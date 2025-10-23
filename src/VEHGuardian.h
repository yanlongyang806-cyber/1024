#pragma once
#include <windows.h>

#ifdef VEHGUARDIAN_EXPORTS
#  define VEH_API extern "C" __declspec(dllexport)
#else
#  define VEH_API extern "C" __declspec(dllimport)
#endif

VEH_API BOOL InitVEH();
VEH_API VOID CleanupVEH();
VEH_API BOOL IsVEHActive();
VEH_API const char* GetLastExceptionInfo();
