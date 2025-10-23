#include <windows.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <unordered_set>
#include <vector>

// 声明日志写入函数
void WriteLog(const std::string& message) {
    std::ofstream log("error_log.txt", std::ios::app);
    if (log.is_open()) {
        // 获取当前时间
        std::time_t now = std::time(0);
        std::tm* localtm = std::localtime(&now);
        log << "[" << 1900 + localtm->tm_year << "-"
            << 1 + localtm->tm_mon << "-"
            << localtm->tm_mday << " "
            << 1 + localtm->tm_hour << ":"
            << 1 + localtm->tm_min << ":"
            << 1 + localtm->tm_sec << "] "
            << message << std::endl;
    }
}

// 存储已知崩溃地址
std::unordered_set<DWORD64> knownCrashAddresses;

// VEH 异常处理程序
LONG CALLBACK SmartVehHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    const DWORD64 crashAddr = reinterpret_cast<DWORD64>(ExceptionInfo->ExceptionRecord->ExceptionAddress);
    
    // 记录异常信息
    WriteLog("Exception caught at address: 0x" + std::to_string(crashAddr));

    // 智能跳过：如果地址已经发生过崩溃，跳过
    if (knownCrashAddresses.find(crashAddr) != knownCrashAddresses.end()) {
        WriteLog("Crash address 0x" + std::to_string(crashAddr) + " already encountered, skipping...");
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // 记录第一次出现的崩溃地址
    knownCrashAddresses.insert(crashAddr);

    // 处理不同类型的异常
    switch (ExceptionInfo->ExceptionRecord->ExceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
            WriteLog("Access Violation occurred, attempting to skip...");
            return EXCEPTION_CONTINUE_EXECUTION;  // 跳过当前错误，继续执行

        case EXCEPTION_ILLEGAL_INSTRUCTION:
            WriteLog("Illegal Instruction encountered, attempting to skip...");
            return EXCEPTION_CONTINUE_EXECUTION;  // 跳过非法指令

        case EXCEPTION_STACK_OVERFLOW:
            WriteLog("Stack Overflow encountered.");
            // 在此可以根据需要做更多的处理
            return EXCEPTION_CONTINUE_SEARCH;  // 不跳过，继续寻找其他处理方法

        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            WriteLog("Array Bounds Exceeded encountered.");
            return EXCEPTION_CONTINUE_SEARCH;  // 同样不跳过

        default:
            WriteLog("Unhandled exception encountered. Code: " + std::to_string(ExceptionInfo->ExceptionRecord->ExceptionCode));
            return EXCEPTION_CONTINUE_SEARCH;  // 如果异常无法处理，继续抛出
    }
}

// DLL 初始化
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // 安装 VEH 异常处理程序
        AddVectoredExceptionHandler(1, SmartVehHandler);
        WriteLog("SmartExceptionHandler DLL injected successfully.");
    }
    return TRUE;
}
