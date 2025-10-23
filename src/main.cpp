#include <windows.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <unordered_set>
#include <vector>
#include <string>
#include <sstream>
#include <mutex>

// 线程安全日志
static std::mutex g_log_mutex;
static void WriteLog(const std::string& message) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::ofstream log("error_log.txt", std::ios::app);
    if (!log.is_open()) return;

    // 获取当前时间
    std::time_t now = std::time(nullptr);
    std::tm localtm;
    localtime_s(&localtm, &now);

    char timebuf[64];
    std::snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02d %02d:%02d:%02d",
                  localtm.tm_year + 1900, localtm.tm_mon + 1, localtm.tm_mday,
                  localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    log << "[" << timebuf << "] " << message << std::endl;
}

// 存储已知崩溃地址（进程级）
static std::unordered_set<uint64_t> knownCrashAddresses;
static std::mutex g_known_mutex; // 保护 knownCrashAddresses

// 辅助：把地址/数字格式化为十六进制字符串
static std::string ToHex(uint64_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << v;
    return oss.str();
}

// VEH 异常处理程序（更安全的实现）
LONG CALLBACK SmartVehHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (!ExceptionInfo || !ExceptionInfo->ExceptionRecord || !ExceptionInfo->ContextRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;
    const uint64_t crashAddr = reinterpret_cast<uint64_t>(ExceptionInfo->ExceptionRecord->ExceptionAddress);

    // 记录异常地址（用十六进制）
    WriteLog(std::string("Exception caught at address: ") + ToHex(crashAddr));

    {
        std::lock_guard<std::mutex> lk(g_known_mutex);
        if (knownCrashAddresses.find(crashAddr) != knownCrashAddresses.end()) {
            WriteLog(std::string("Crash address ") + ToHex(crashAddr) + " already encountered, skipping...");
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // 首次记录
        knownCrashAddresses.insert(crashAddr);
    }

    // 处理不同类型的异常
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
            WriteLog("Access Violation occurred, attempting to skip...");
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            WriteLog("Illegal Instruction encountered, attempting to skip...");
            break;
        case EXCEPTION_STACK_OVERFLOW:
            WriteLog("Stack Overflow encountered.");
            return EXCEPTION_CONTINUE_SEARCH; // 不尝试跳过
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            WriteLog("Array Bounds Exceeded encountered.");
            return EXCEPTION_CONTINUE_SEARCH;
        default: {
            std::ostringstream oss;
            oss << "Unhandled exception encountered. Code: 0x" << std::hex << code;
            WriteLog(oss.str());
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    // 尝试跳过出错指令：默认跳过 2 字节（可在配置里调整）
#if defined(_M_X64) || defined(__x86_64__)
    CONTEXT& ctx = *ExceptionInfo->ContextRecord;
    uint64_t oldRip = ctx.Rip;
    const uint32_t advance = 2; // 默认前进字节数，若需精确请用配置表按地址设置
    ctx.Rip += advance;
    {
        std::ostringstream oss;
        oss << "Advancing RIP from 0x" << std::hex << oldRip << " to 0x" << std::hex << ctx.Rip
            << " (advance=" << std::dec << advance << ")";
        WriteLog(oss.str());
    }
#else
    // x86
    CONTEXT& ctx = *ExceptionInfo->ContextRecord;
    #if defined(_M_IX86)
        uint32_t oldEip = ctx.Eip;
        const uint32_t advance = 2;
        ctx.Eip += advance;
        WriteLog("Advanced EIP to continue");
    #else
        WriteLog("Unsupported architecture for automatic RIP/EIP advance");
        return EXCEPTION_CONTINUE_SEARCH;
    #endif
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}

// DLL 初始化（更安全：也处理卸载）
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    static PVOID vehHandle = nullptr;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule); // 性能优化
        vehHandle = AddVectoredExceptionHandler(1, SmartVehHandler);
        if (vehHandle) {
            WriteLog("SmartExceptionHandler DLL injected successfully. VEH installed.");
        } else {
            WriteLog("SmartExceptionHandler DLL injected but VEH installation failed.");
        }
        break;
    case DLL_PROCESS_DETACH:
        if (vehHandle) {
            RemoveVectoredExceptionHandler(vehHandle);
            vehHandle = nullptr;
            WriteLog("VEH removed on DLL detach.");
        } else {
            WriteLog("DLL detach: no VEH to remove.");
        }
        break;
    }
    return TRUE;
}
