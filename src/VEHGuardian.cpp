// VEHGuardian.cpp (最终版，整合)
// Place under src/ and build with CMake as provided.

#include "VEHGuardian.h"
#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <sstream>
#include <fstream>

#pragma comment(lib, "dbghelp.lib")

static std::atomic<bool> g_running(false);
static PVOID g_vehHandle = nullptr;
static std::thread g_watchdogThread;
static HANDLE g_mainThreadHandle = NULL;
static DWORD g_mainThreadId = 0;
static const wchar_t* g_logPath = L"C:\\temp\\VEH_guard.log";
static const wchar_t* g_dumpFolder = L"C:\\CrashDumps";

static std::mutex g_logMutex;
static std::string g_lastException;

// 简单记录函数（线程安全）
static void SimpleLog(const wchar_t* fmt, ...)
{
    std::lock_guard<std::mutex> lk(g_logMutex);
    va_list ap;
    va_start(ap, fmt);
    FILE* f = nullptr;
    _wfopen_s(&f, g_logPath, L"a");
    if (f) {
        wchar_t buf[1024];
        vswprintf_s(buf, _countof(buf), fmt, ap);
        // 时间戳
        wchar_t timebuf[64];
        std::time_t t = std::time(nullptr);
        struct tm tmv;
        localtime_s(&tmv, &t);
        wcsftime(timebuf, sizeof(timebuf)/sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &tmv);
        std::fwprintf(f, L"%s: %s\n", timebuf, buf);
        fclose(f);
    }
    va_end(ap);
}

// 写 dump（尽量写）
static void WriteMiniDumpInternal(EXCEPTION_POINTERS* pep, const wchar_t* suffix)
{
    // 创建目录
    CreateDirectoryW(g_dumpFolder, NULL);

    wchar_t path[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    swprintf_s(path, L"%s\\VEHDump_%04d%02d%02d_%02d%02d%02d_%s.dmp",
               g_dumpFolder, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
               suffix ? suffix : L"");
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SimpleLog(L"WriteMiniDump: CreateFile failed %u", GetLastError());
        return;
    }

    MINIDUMP_EXCEPTION_INFORMATION mei;
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = pep;
    mei.ClientPointers = FALSE;

    BOOL ok = MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        static_cast<MINIDUMP_TYPE>(MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithThreadInfo),
        (pep ? &mei : nullptr),
        nullptr,
        nullptr
    );

    if (!ok) {
        SimpleLog(L"MiniDumpWriteDump failed: %u", GetLastError());
    } else {
        SimpleLog(L"Wrote dump: %s", path);
    }
    CloseHandle(hFile);
}

// 简单尝试跳过一条指令（非常保守）
static bool TryRecoverFromAccessViolation(CONTEXT* ctx)
{
#ifdef _M_X64
    ULONG64 rip = ctx->Rip;
    ctx->Rip = rip + 1; // 跳过 1 字节指令（非常保守）
    SimpleLog(L"TryRecoverFromAccessViolation: advanced RIP +1 (0x%llx -> 0x%llx)", rip, ctx->Rip);
    return true;
#else
    return false;
#endif
}

// VEH 处理函数
static LONG WINAPI GuardianVEH(PEXCEPTION_POINTERS ep)
{
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    SimpleLog(L"VEH invoked: code=0x%08X addr=0x%p", code, ep->ExceptionRecord->ExceptionAddress);

    // 尝试写 dump（尽量）
    __try { WriteMiniDumpInternal(ep, L"veh"); } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // 对于 failfast / stack cookie 类型，不尝试恢复
    if (code == 0xC0000409 /*STATUS_STACK_BUFFER_OVERRUN*/ || code == 0xDEADDEAD) {
        SimpleLog(L"VEH: failfast-like exception (0x%08X) - cannot recover", code);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXCEPTION_ACCESS_VIOLATION) {
        CONTEXT* ctx = ep->ContextRecord;
        if (ctx && TryRecoverFromAccessViolation(ctx)) {
            SimpleLog(L"VEH: recovery attempt succeeded (continue execution).");
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    if (code == EXCEPTION_ILLEGAL_INSTRUCTION) {
#ifdef _M_X64
        CONTEXT* ctx = ep->ContextRecord;
        if (ctx) {
            ctx->Rip += 1;
            SimpleLog(L"VEH: illegal instruction - advanced RIP");
            return EXCEPTION_CONTINUE_EXECUTION;
        }
#endif
        return EXCEPTION_CONTINUE_SEARCH;
    }

    SimpleLog(L"VEH: unhandled exception code=0x%08X -> CONTINUE_SEARCH", code);
    return EXCEPTION_CONTINUE_SEARCH;
}

// 未捕获异常过滤（做个备份）
static LONG WINAPI GuardianUnhandledFilter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    SimpleLog(L"UnhandledExceptionFilter invoked: code=0x%08X", ep->ExceptionRecord->ExceptionCode);
    __try { WriteMiniDumpInternal(ep, L"unhandled"); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return EXCEPTION_CONTINUE_SEARCH;
}

// 看门狗线程（写心跳）
static void WatchdogLoop()
{
    SimpleLog(L"Watchdog thread started");
    int tick = 0;
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        tick++;
        SimpleLog(L"Watchdog heartbeat %d", tick);
        if (g_mainThreadId != 0 && !g_mainThreadHandle) {
            HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, g_mainThreadId);
            if (th) g_mainThreadHandle = th;
        }
    }
    SimpleLog(L"Watchdog thread exiting");
}

static DWORD FindLikelyMainThreadId()
{
    return GetCurrentThreadId();
}

extern "C" __declspec(dllexport) void VG_EnableLogging()
{
    SimpleLog(L"VG_EnableLogging called");
}

// Exports for simple control and status
extern "C" __declspec(dllexport) BOOL InitVEH()
{
    if (g_running.load()) return TRUE;
    g_running.store(true);
    g_vehHandle = AddVectoredExceptionHandler(1, GuardianVEH);
    SetUnhandledExceptionFilter(GuardianUnhandledFilter);
    g_mainThreadId = FindLikelyMainThreadId();
    g_watchdogThread = std::thread(WatchdogLoop);
    SimpleLog(L"InitVEH: started, handle=%p mainThread=%u", g_vehHandle, g_mainThreadId);
    return TRUE;
}

extern "C" __declspec(dllexport) VOID CleanupVEH()
{
    if (!g_running.load()) return;
    g_running.store(false);
    if (g_watchdogThread.joinable()) g_watchdogThread.join();
    if (g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
    }
    if (g_mainThreadHandle) {
        CloseHandle(g_mainThreadHandle);
        g_mainThreadHandle = NULL;
    }
    SimpleLog(L"CleanupVEH: stopped");
}

extern "C" __declspec(dllexport) BOOL IsVEHActive()
{
    return g_running.load();
}

extern "C" __declspec(dllexport) const char* GetLastExceptionInfo()
{
    return g_lastException.c_str();
}

// DllMain
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateDirectoryW(L"C:\\temp", NULL);
        CreateDirectoryW(g_dumpFolder, NULL);
        SimpleLog(L"VEHGuardian DLL loaded");
        // auto-start
        InitVEH();
        break;
    case DLL_PROCESS_DETACH:
        CleanupVEH();
        SimpleLog(L"VEHGuardian DLL unloaded");
        break;
    }
    return TRUE;
}
