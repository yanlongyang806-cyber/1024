#ifndef THREAD_EXCEPTION_HANDLER_H
#define THREAD_EXCEPTION_HANDLER_H

#include <windows.h>
#include <unordered_set>
#include <string>

// 线程本地存储，存储每个线程遇到的崩溃地址
__declspec(thread) extern std::unordered_set<DWORD64> threadCrashAddresses;

// 声明异常处理程序
LONG CALLBACK SmartVehHandler(EXCEPTION_POINTERS* ExceptionInfo);

// 用于记录日志的函数
void WriteLog(const std::string& message);

#endif // THREAD_EXCEPTION_HANDLER_H
