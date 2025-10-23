__declspec(thread) stdunordered_setDWORD64 threadCrashAddresses;   线程本地存储

LONG CALLBACK SmartVehHandler(EXCEPTION_POINTERS ExceptionInfo) {
    const DWORD64 crashAddr = reinterpret_castDWORD64(ExceptionInfo-ExceptionRecord-ExceptionAddress);

     对当前线程的异常进行处理
    if (threadCrashAddresses.find(crashAddr) != threadCrashAddresses.end()) {
        WriteLog(Crash address 0x + stdto_string(crashAddr) +  already encountered, skipping...);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    threadCrashAddresses.insert(crashAddr);

     处理异常...
}
