#include <windows.h>
#include <unordered_set>
#include <sstream>
#include <fstream>
#include <ctime>
#include <string>

static thread_local std::unordered_set<DWORD64> threadCrashAddresses;

static void WriteLog(const std::string& msg) {
    std::ofstream log("error_log.txt", std::ios::app);
    if (!log.is_open()) return;
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &now);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    log << "[" << buf << "] " << msg << std::endl;
}

LONG CALLBACK SmartVehHandler(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD64 addr = reinterpret_cast<DWORD64>(ep->ExceptionRecord->ExceptionAddress);

    std::ostringstream oss;
    oss << "Exception caught at 0x" << std::hex << addr;
    WriteLog(oss.str());

    if (threadCrashAddresses.count(addr)) {
        WriteLog("Repeated exception at same address, skipping.");
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    threadCrashAddresses.insert(addr);

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        ep->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
#if defined(_M_X64)
        ep->ContextRecord->Rip += 2;
#elif defined(_M_IX86)
        ep->ContextRecord->Eip += 2;
#endif
        WriteLog("Advanced instruction pointer by 2 bytes.");
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        AddVectoredExceptionHandler(1, SmartVehHandler);
        WriteLog("Smart VEH handler installed.");
    }
    return TRUE;
}
