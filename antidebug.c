#include "example_package_AntiDebugging.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>

/*
 * Function: IsVirtualPC_LDTCheck
 * -------------------------------
 * Uses the SLDT instruction to get the LDT register value. If non-zero,
 * it suggests that the code is running inside a virtual environment.
 */
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

/*
 * Function: detectDebugger
 * ------------------------
 * Checks if a debugger is attached to the current process using the
 * IsDebuggerPresent API. Terminates the process if a debugger is detected.
 */
void detectDebugger() {
    if (IsDebuggerPresent()) {
        exit(1);
    }
}

/*
 * Function: preventMemoryDump
 * ---------------------------
 * Prevents memory dump by changing the protection of the process memory
 * to PAGE_NOACCESS.
 */
void preventMemoryDump() {
    HANDLE hProcess = GetCurrentProcess();
    DWORD oldProtect;
    VirtualProtectEx(hProcess, NULL, 0, PAGE_NOACCESS, &oldProtect);
}

/*
 * Function: preventRemoteDebug
 * ----------------------------
 * Prevents remote debugging by invoking NtSetInformationProcess with
 * a parameter to disable debugging from another process.
 */
void preventRemoteDebug() {
    typedef NTSTATUS(WINAPI *pNtSetInformationProcess)(HANDLE, UINT, PVOID, ULONG);
    DWORD debugPort = 0;
    HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(hNtDll, "NtSetInformationProcess");
    NtSetInformationProcess(GetCurrentProcess(), 0x1D, &debugPort, sizeof(debugPort));
}

/*
 * Function: preventThreadInjection
 * --------------------------------
 * Prevents thread injection protection by changing the process memory
 * protection to PAGE_NOACCESS.
 */
void preventThreadInjection() {
    HANDLE hProcess = GetCurrentProcess();
    DWORD oldProtect;
    VirtualProtectEx(hProcess, NULL, 0, PAGE_NOACCESS, &oldProtect);
}

/*
 * Function: hideThreadFromDebugger
 * --------------------------------
 * Hides the current thread from the debugger by calling NtSetInformationThread.
 */
void hideThreadFromDebugger() {
    typedef NTSTATUS (WINAPI *pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (hNtdll) {
        pNtSetInformationThread NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
        if (NtSetInformationThread) {
            NtSetInformationThread(GetCurrentThread(), 0x11, 0, 0);
        }
    }
}

/*
 * Function: IsJDWPActive
 * ----------------------
 * Scans through process modules to determine if a Java Debug Wire Protocol
 * (JDWP) interface is active by searching for "jdwp" in the module's path.
 */
BOOL IsJDWPActive() {
    HMODULE hMods[1024];
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                // If module name contains "jdwp" (case-insensitive), JDWP is active.
                if (_tcsstr(szModName, _T("jdwp")) != NULL) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/*
 * Function: disableJDWPInterface
 * ------------------------------
 * Disables the JDWP interface by terminating the process if JDWP is active.
 */
void disableJDWPInterface() {
    if (IsJDWPActive()) {
        exit(1);
    }
}

/*
 * Function: disableRemoteAttach
 * -----------------------------
 * Combines hiding the thread from debugger and disabling the JDWP interface
 * to prevent remote attachments.
 */
void disableRemoteAttach() {
    hideThreadFromDebugger();
    disableJDWPInterface();
}

/*
 * Thread Function: MonitorJDWPThread
 * ----------------------------------
 * Constantly monitors for an active JDWP interface and terminates the process 
 * if one is detected.
 */
DWORD WINAPI MonitorJDWPThread(LPVOID lpParam) {
    while (1) {
        if (IsJDWPActive()) {
            exit(1);
        }
        Sleep(100);  
    }
    return 0;
}

/*
 * Function: startJDWPMonitorThread
 * --------------------------------
 * Starts a new thread to continuously monitor for an active JDWP interface.
 */
void startJDWPMonitorThread() {
    HANDLE hThread = CreateThread(NULL, 0, MonitorJDWPThread, NULL, 0, NULL);
    if (hThread != NULL) {
        CloseHandle(hThread);
    }
}

/*
 * JNI Function: Java_example_package_AntiDebugging_antidebug
 * ----------------------------------------------------------
 * Called from Java code. It sequentially invokes various anti-debugging
 * and memory protection functions to secure the process.
 */
JNIEXPORT void JNICALL Java_example_package_AntiDebugging_antidebug(JNIEnv *env, jobject obj, jint a, jint b) {
    if (IsVirtualPC_LDTCheck())
        exit(1);
    detectDebugger();
    preventMemoryDump();
    preventRemoteDebug();
    preventThreadInjection();
    disableRemoteAttach();
    startJDWPMonitorThread();
}
