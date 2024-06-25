#include "verify_equipment_AntiDebugging.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <time.h>

#define TIME_THRESHOLD 100 // 延时设定，预防调试

void check_time_delay(clock_t start_time) {
    clock_t end_time = clock();
    double elapsed_time = ((double) (end_time - start_time)) / CLOCKS_PER_SEC * 1000;
    if (elapsed_time > TIME_THRESHOLD) {
        exit(1);
    }
}

long getCurrentTimestamp() {
    // 获取当前时间
    time_t currentTime = time(NULL);
    
    // 将 time_t 类型转换为 long 类型
    long currentTimeLong = (long)currentTime;
    
    return currentTimeLong;
}

BOOL IsVirtualPC_LDTCheck() {
    unsigned short ldt_addr = 0;
    unsigned char ldtr[2];

    __asm__ __volatile__ (
        "sldt %0"
        : "=m" (ldtr)
    );

    ldt_addr = *((unsigned short *)&ldtr);
    return ldt_addr != 0x0000;
}

void detectDebugger() {
    if (IsDebuggerPresent()) {
        exit(1);
    }
}

void preventMemoryDump() {
    HANDLE hProcess = GetCurrentProcess();
    DWORD oldProtect;
    VirtualProtectEx(hProcess, NULL, 0, PAGE_NOACCESS, &oldProtect);
}

void preventRemoteDebug() {
    typedef NTSTATUS(WINAPI *pNtSetInformationProcess)(HANDLE, UINT, PVOID, ULONG);
    DWORD debugPort = 0;
    HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(hNtDll, "NtSetInformationProcess");
    NtSetInformationProcess(GetCurrentProcess(), 0x1D, &debugPort, sizeof(debugPort));
}

void preventThreadInjection() {
    HANDLE hProcess = GetCurrentProcess();
    DWORD oldProtect;
    VirtualProtectEx(hProcess, NULL, 0, PAGE_NOACCESS, &oldProtect);
}

JNIEXPORT jlong JNICALL Java_love_LI_LI(JNIEnv *env, jobject obj, jint a, jint b) {
    if(IsVirtualPC_LDTCheck())
        exit(1);
    clock_t start_time = clock();
    detectDebugger(); 
    preventMemoryDump();
    preventRemoteDebug();
    preventThreadInjection(); 
    check_time_delay(start_time);
    jint result = a + b;
    check_time_delay(start_time);
    return getCurrentTimestamp();
}