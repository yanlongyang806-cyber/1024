// VEHGuardian.cpp
// x64 DLL: VEH + UnhandledExceptionFilter + watchdog + dump + logging
// Build: Visual Studio x64 / MT or MD (Release recommended)
// NOTE: This code is intended for debugging / resilience in controlled envs only.

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "dbghelp.lib")

static std::atomic<bool> g_running(false);
static PVOID g_vehHandle = nullptr;
static std::thread g_watchdogThread;
static HANDLE g_mainThreadHandle = NULL;
static DWORD g_mainThreadId = 0;
static const wchar_t* g_logPath = L"C:\\temp\\VEH_guard.log";
static const wchar_t* g_dumpFolder = L"C:\\CrashDumps";

// simple logging (append)
static void Log(const wchar_t* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    FILE* f = nullptr;
    _wfopen_s(&f, g_logPath, L"a");
    if (f) {
        wchar_t buf[1024];
        vswprintf_s(buf, _countof(buf), fmt, ap);
        std::fwprintf(f, L"%s: %s\n", [&](void)->const wchar_t* {
            static wchar_t timebuf[64];
            std::time_t t = std::time(nullptr);
            struct tm tmv;
            localtime_s(&tmv, &t);
            wcsftime(timebuf, sizeof(timebuf)/sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &tmv);
            return timebuf;
        }(), buf);
        fclose(f);
    }
    va_end(ap);
}

// write full minidump (with memory)
static void WriteMiniDump(EXCEPTION_POINTERS* pep, const wchar_t* suffix)
{
    // make folder if needed
    CreateDirectoryW(g_dumpFolder, NULL);

    wchar_t path[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    swprintf_s(path, L"%s\\VEHDump_%04d%02d%02d_%02d%02d%02d_%s.dmp",
               g_dumpFolder, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, suffix ? suffix : L"");
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        Log(L"WriteMiniDump: CreateFile failed %u", GetLastError());
        return;
    }

    MINIDUMP_EXCEPTION_INFORMATION mei;
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = pep;
    mei.ClientPointers = FALSE;

    BOOL ok = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                                MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithThreadInfo,
                                (pep ? &mei : nullptr), nullptr, nullptr);
    if (!ok) {
        Log(L"MiniDumpWriteDump failed: %u", GetLastError());
    } else {
        Log(L"Wrote dump: %s", path);
    }
    CloseHandle(hFile);
}

// Heuristic: try to advance instruction pointer to skip faulty instruction.
// VERY RISKY and extremely heuristic. We only attempt for simple x64 AVs.
static bool TryRecoverFromAccessViolation(CONTEXT* ctx)
{
#ifdef _M_X64
    // Advance RIP by 1..8 bytes fallible heuristic.
    // Safer approach would be to disassemble; omitted for simplicity.
    ULONG64 rip = ctx->Rip;
    // try skipping 1 and 2 bytes as a conservative attempt
    ctx->Rip = rip + 1;
    Log(L"TryRecoverFromAccessViolation: advanced RIP +1 (0x%llx -> 0x%llx)", rip, ctx->Rip);
    return true;
#else
    return false;
#endif
}

// VEH handler
static LONG WINAPI GuardianVEH(PEXCEPTION_POINTERS ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    Log(L"VEH invoked: code=0x%08X addr=0x%p", code, ep->ExceptionRecord->ExceptionAddress);

    // Always attempt to write a dump (best-effort). If exception pointers null, write without.
    __try {
        WriteMiniDump(ep, L"veh");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // ignore
    }

    // If stack cookie / failfast: do NOT attempt to continue
    if (code == 0xC0000409 /*STATUS_STACK_BUFFER_OVERRUN*/ || code == 0xDEADDEAD) {
        Log(L"VEH: failfast-like exception (0x%08X) - cannot recover", code);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Access violation: attempt recovery
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        CONTEXT* ctx = ep->ContextRecord;
        if (TryRecoverFromAccessViolation(ctx)) {
            Log(L"VEH: recovery attempt succeeded (continue execution).");
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Illegal instruction: attempt skip
    if (code == EXCEPTION_ILLEGAL_INSTRUCTION) {
#ifdef _M_X64
        CONTEXT* ctx = ep->ContextRecord;
        ctx->Rip += 1; // heuristic
        Log(L"VEH: illegal instruction - advanced RIP");
        return EXCEPTION_CONTINUE_EXECUTION;
#else
        return EXCEPTION_CONTINUE_SEARCH;
#endif
    }

    // Fallback: log and continue search (let system handle)
    Log(L"VEH: unhandled exception code=0x%08X -> CONTINUE_SEARCH", code);
    return EXCEPTION_CONTINUE_SEARCH;
}

// Unhandled exception filter (backup)
static LONG WINAPI GuardianUnhandledFilter(EXCEPTION_POINTERS* ep)
{
    Log(L"UnhandledExceptionFilter invoked: code=0x%08X", ep->ExceptionRecord->ExceptionCode);
    __try { WriteMiniDump(ep, L"unhandled"); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    // Try to allow process continuation? Returning EXCEPTION_EXECUTE_HANDLER will terminate.
    // Best is to return EXCEPTION_CONTINUE_SEARCH to let default handler run.
    return EXCEPTION_CONTINUE_SEARCH;
}

// watchdog: monitors process health and tries to restart key routines if possible.
// Here: simple periodic heartbeat log; user can extend to restart threads/services.
static void WatchdogLoop()
{
    Log(L"Watchdog thread started");
    int tick = 0;
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        tick++;
        // write heartbeat
        Log(L"Watchdog heartbeat %d", tick);
        // Optionally: check main thread liveness (cooperative)
        if (g_mainThreadId != 0) {
            // get thread handle if not present
            if (!g_mainThreadHandle) {
                HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, g_mainThreadId);
                if (th) {
                    g_mainThreadHandle = th;
                }
            }
            // we could QueryThreadCycleTime or similar; for now just log existence
            if (g_mainThreadHandle) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(g_mainThreadHandle, &exitCode)) {
                    if (exitCode != STILL_ACTIVE) {
                        Log(L"Watchdog: main thread not active (exit code=%u)", exitCode);
                        // option: attempt action
                    }
                }
            }
        }
    }
    Log(L"Watchdog thread exiting");
}

// helper to get a thread id likely to be main thread: enumerate threads and pick one owning the main module's entry region.
// This is heuristic and optional.
static DWORD FindLikelyMainThreadId()
{
    // naive: use current thread (the injection thread assumed run inside loader)
    return GetCurrentThreadId();
}

extern "C" __declspec(dllexport) void VG_EnableLogging()
{
    Log(L"VG_EnableLogging called");
}

// Start/stop
static void StartGuardian()
{
    if (g_running.load()) return;
    g_running.store(true);
    // register VEH (first)
    g_vehHandle = AddVectoredExceptionHandler(1, GuardianVEH);
    SetUnhandledExceptionFilter(GuardianUnhandledFilter);
    Log(L"Registered VEH & UnhandledExceptionFilter (handle=%p)", g_vehHandle);
    // find likely main thread
    g_mainThreadId = FindLikelyMainThreadId();
    Log(L"Likely main thread id: %u", g_mainThreadId);

    // start watchdog
    g_watchdogThread = std::thread(WatchdogLoop);
}

static void StopGuardian()
{
    if (!g_running.load()) return;
    g_running.store(false);
    if (g_watchdogThread.joinable()) g_watchdogThread.join();
    if (g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
    }
    Log(L"Guardian stopped");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        // ensure directories
        CreateDirectoryW(L"C:\\temp", NULL);
        CreateDirectoryW(g_dumpFolder, NULL);
        Log(L"VEHGuardian DLL loaded");
        StartGuardian();
        break;
    case DLL_PROCESS_DETACH:
        StopGuardian();
        Log(L"VEHGuardian DLL unloaded");
        break;
    }
    return TRUE;
}
