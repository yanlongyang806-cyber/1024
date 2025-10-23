#include <windows.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <sstream>
#include <mutex>
#include <thread>

static std::mutex logMutex;  // 保证多线程日志安全
static std::unordered_map<DWORD, std::unordered_set<DWORD64>> threadCrashMap; // 每线程独立记录崩溃地址

// 🧠 获取时间字符串
std::string GetTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &now);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}

// ✍️ 线程安全写日志
void WriteLog(const std::string& message) {
    std::lock_guard<std::mutex> guard(logMutex);
    std::ofstream log("error_log.txt", std::ios::app);
    if (log.is_open()) {
        log << "[" << GetTimestamp() << "] [TID:" << GetCurrentThreadId() << "] " << message << std::endl;
    }
}

// 🚨 智能异常处理程序
LONG CALLBACK SmartVehHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (!ExceptionInfo || !ExceptionInfo->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;

    DWORD64 crashAddr = reinterpret_cast<DWORD64>(ExceptionInfo->ExceptionRecord->ExceptionAddress);
    DWORD threadId = GetCurrentThreadId();

    auto& crashSet = threadCrashMap[threadId];
    std::ostringstream oss;
    oss << "⚠️ Exception 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode
        << " at address 0x" << crashAddr;
    WriteLog(oss.str());

    // 防止重复处理同一线程相同异常
    if (crashSet.count(crashAddr)) {
        WriteLog("🔁 Repeated crash detected. Skipping this instruction.");
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    crashSet.insert(crashAddr);

    // 智能修复逻辑
    switch (ExceptionInfo->ExceptionRecord->ExceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            WriteLog("💡 Attempting instruction pointer skip (2 bytes forward).");
        #if defined(_M_X64)
            ExceptionInfo->ContextRecord->Rip += 2;
        #elif defined(_M_IX86)
            ExceptionInfo->ContextRecord->Eip += 2;
        #endif
            return EXCEPTION_CONTINUE_EXECUTION;

        case EXCEPTION_STACK_OVERFLOW:
            WriteLog("❗ Stack overflow detected. Cannot safely recover.");
            return EXCEPTION_CONTINUE_SEARCH;

        default:
            WriteLog("❔ Unhandled exception. Forwarding to next handler.");
            return EXCEPTION_CONTINUE_SEARCH;
    }
}

// 🧩 DLL 初始化与卸载
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            AddVectoredExceptionHandler(1, SmartVehHandler);
            WriteLog("✅ SmartExceptionHandler initialized.");
            break;

        case DLL_THREAD_DETACH:
            threadCrashMap.erase(GetCurrentThreadId());
            break;

        case DLL_PROCESS_DETACH:
            WriteLog("🔚 SmartExceptionHandler shutting down.");
            break;
    }
    return TRUE;
}
