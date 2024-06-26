#include "example_package_AntiDebugging.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

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

JNIEXPORT jvoid JNICALL Java_love_LI_LI(JNIEnv *env, jobject obj, jint a, jint b) {
    if(IsVirtualPC_LDTCheck())
        exit(1);
    detectDebugger(); 
    preventMemoryDump();
    preventRemoteDebug();
    preventThreadInjection(); 
}
