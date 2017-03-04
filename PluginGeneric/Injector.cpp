#include "Injector.h"
#include <Psapi.h>

#include <Scylla/Logger.h>
#include <Scylla/NtApiLoader.h>
#include <Scylla/OsInfo.h>
#include <Scylla/PebHider.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>

#include "..\InjectorCLI\\ApplyHooking.h"

extern scl::Settings g_settings;
extern scl::Logger g_log;

static LPVOID remoteImageBase = 0;

typedef void(__cdecl * t_SetDebuggerBreakpoint)(DWORD_PTR address);
t_SetDebuggerBreakpoint _SetDebuggerBreakpoint = 0;

//anti-attach vars
DWORD ExitThread_addr;
BYTE* DbgUiIssueRemoteBreakin_addr;
DWORD jmpback;
DWORD DbgUiRemoteBreakin_addr;
BYTE* RemoteBreakinPatch;
BYTE code[8];
HANDLE hDebuggee;

void ReadNtApiInformation(const wchar_t *file, HOOK_DLL_DATA *hde)
{
    scl::NtApiLoader api_loader;
    auto res = api_loader.Load(file);
    if (!res.first)
    {
        g_log.LogError(L"Failed to load NT API addresses: %s", res.second);
        return;
    }

    hde->NtUserQueryWindowRVA = (DWORD)api_loader.get_fun(L"user32.dll", L"NtUserQueryWindow");
    hde->NtUserBuildHwndListRVA = (DWORD)api_loader.get_fun(L"user32.dll", L"NtUserBuildHwndList");
    hde->NtUserFindWindowExRVA = (DWORD)api_loader.get_fun(L"user32.dll", L"NtUserFindWindowEx");

    g_log.LogInfo(L"Loaded RVA for user32.dll!NtUserQueryWindow = 0x%p", hde->NtUserQueryWindowRVA);
    g_log.LogInfo(L"Loaded RVA for user32.dll!NtUserBuildHwndList = 0x%p", hde->NtUserBuildHwndListRVA);
    g_log.LogInfo(L"Loaded RVA for user32.dll!NtUserFindWindowEx = 0x%p", hde->NtUserFindWindowExRVA);

    if (!hde->NtUserQueryWindowRVA || !hde->NtUserBuildHwndListRVA || !hde->NtUserFindWindowExRVA)
    {
        g_log.LogError(
            L"NtUser* API Addresses are missing!\n"
            L"File: %s\n"
            L"Section: %s\n"
            L"Please read the documentation to fix this problem!",
            file, api_loader.GetOsId().c_str()
        );
    }
}

#ifndef _WIN64
void __declspec(naked) handleAntiAttach()
{
    _asm {
        push ebp //stolen bytes
        mov ebp, esp //stolen bytes
        pushad
        mov eax, dword ptr[ebp + 0x8]
        mov hDebuggee, eax
    }

    //write our RemoteBreakIn patch to target memory
    RemoteBreakinPatch = (BYTE*)VirtualAllocEx(hDebuggee, 0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hDebuggee, (LPVOID)RemoteBreakinPatch, code, sizeof(code), NULL);

    //find push ntdll.DbgUiRemoteBreakin and patch our patch function addr there
    while (*(DWORD*)DbgUiIssueRemoteBreakin_addr != DbgUiRemoteBreakin_addr) {
        DbgUiIssueRemoteBreakin_addr++;
    }
    WriteProcessMemory(GetCurrentProcess(), DbgUiIssueRemoteBreakin_addr, &RemoteBreakinPatch, 4, NULL);

    _asm {
        popad
        mov eax, jmpback
        jmp eax
    }
}
#endif

void InstallAntiAttachHook()
{
#ifndef _WIN64
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);

    DbgUiIssueRemoteBreakin_addr = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgUiIssueRemoteBreakin");
    DbgUiRemoteBreakin_addr = (DWORD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgUiRemoteBreakin");
    ExitThread_addr = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    jmpback = (DWORD)DbgUiIssueRemoteBreakin_addr;
    jmpback += 5;

    BYTE jmp[1] = { 0xE9 };
    WriteProcessMemory(hOlly, DbgUiIssueRemoteBreakin_addr, &jmp, sizeof(jmp), NULL);
    DWORD patch = (DWORD)handleAntiAttach;
    patch -= (DWORD)DbgUiIssueRemoteBreakin_addr;
    patch -= 5;
    WriteProcessMemory(hOlly, DbgUiIssueRemoteBreakin_addr + 1, &patch, 4, NULL);

    //init our remote breakin patch
    BYTE* p = &code[0];
    *p = 0xCC;  //int3
    p++;
    *p = 0x68;  //push
    p++;
    *(DWORD*)(p) = ExitThread_addr;
    p += 4;
    *p = 0xC3; //retn
#endif
}

bool StartFixBeingDebugged(DWORD targetPid, bool setToNull)
{
    scl::Handle hProcess(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid));
    if (!hProcess.get())
        return false;

    auto peb = scl::GetPeb(hProcess.get());
    if (!peb)
        return false;

    peb->BeingDebugged = setToNull ? FALSE : TRUE;
    if (!scl::SetPeb(hProcess.get(), peb.get()))
        return false;

    if (scl::IsWow64Process(hProcess.get()))
    {
        auto peb64 = scl::Wow64GetPeb64(hProcess.get());
        if (!peb64)
            return false;

        peb->BeingDebugged = setToNull ? FALSE : TRUE;
        if (!scl::Wow64SetPeb64(hProcess.get(), peb64.get()))
            return false;
    }

    return true;
}

bool StartHooking(HANDLE hProcess, HOOK_DLL_DATA *hdd, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hdd->dwProtectedProcessId = GetCurrentProcessId(); //for olly plugins
    hdd->EnableProtectProcessId = TRUE;

    DWORD peb_flags = 0;
    if (g_settings.opts().fixPebBeingDebugged) peb_flags |= PEB_PATCH_BeingDebugged;
    if (g_settings.opts().fixPebHeapFlags) peb_flags |= PEB_PATCH_HeapFlags;
    if (g_settings.opts().fixPebNtGlobalFlag) peb_flags |= PEB_PATCH_NtGlobalFlag;
    if (g_settings.opts().fixPebStartupInfo) peb_flags |= PEB_PATCH_ProcessParameters;

    ApplyPEBPatch(hProcess, peb_flags);

    return ApplyHook(hdd, hProcess, dllMemory, imageBase);
}

void startInjectionProcess(HANDLE hProcess, HOOK_DLL_DATA *hdd, BYTE * dllMemory, bool newProcess)
{
    DWORD initDllFuncAddressRva = GetDllFunctionAddressRVA(dllMemory, "InitDll");
    DWORD hookDllDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "HookDllData");

    if (newProcess == false)
    {
        //g_log.Log(L"Apply hooks again");
        if (StartHooking(hProcess, hdd, dllMemory, (DWORD_PTR)remoteImageBase))
        {
            WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hookDllDataAddressRva + (DWORD_PTR)remoteImageBase), hdd, sizeof(HOOK_DLL_DATA), 0);
        }
    }
    else
    {
        if (g_settings.opts().removeDebugPrivileges)
        {
            RemoveDebugPrivileges(hProcess);
        }

        RestoreHooks(hdd, hProcess);

        remoteImageBase = MapModuleToProcess(hProcess, dllMemory);
        if (remoteImageBase)
        {
            FillHookDllData(hProcess, hdd);


            StartHooking(hProcess, hdd, dllMemory, (DWORD_PTR)remoteImageBase);

            if (WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hookDllDataAddressRva + (DWORD_PTR)remoteImageBase), hdd, sizeof(HOOK_DLL_DATA), 0))
            {
                g_log.LogInfo(L"Hook Injection successful, Imagebase %p", remoteImageBase);
            }
            else
            {
                g_log.LogInfo(L"Failed to write hook dll data");
            }
        }
        else
        {
            g_log.LogInfo(L"Failed to map image!");
        }
    }
}

void startInjection(DWORD targetPid, HOOK_DLL_DATA *hdd, const WCHAR * dllPath, bool newProcess)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
    if (hProcess)
    {
        BYTE * dllMemory = ReadFileToMemory(dllPath);
        if (dllMemory)
        {
            startInjectionProcess(hProcess, hdd, dllMemory, newProcess);
            free(dllMemory);
        }
        else
        {
            g_log.LogError(L"Cannot find %s", dllPath);
        }
        CloseHandle(hProcess);
    }
    else
    {
        g_log.LogError(L"Cannot open process handle %d", targetPid);
    }
}

void DoThreadMagic(HANDLE hThread)
{
    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
    NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);
    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);
}

LPVOID NormalDllInjection(HANDLE hProcess, const WCHAR * dllPath)
{
    SIZE_T memorySize = (wcslen(dllPath) + 1) * sizeof(WCHAR);

    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, memorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD hModule = 0;

    if (!remoteMemory)
    {
        g_log.LogInfo(L"DLL INJECTION: VirtualAllocEx failed!");
        return 0;
    }

    if (WriteProcessMemory(hProcess, remoteMemory, dllPath, memorySize, 0))
    {
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryW, remoteMemory, CREATE_SUSPENDED, 0);
        if (hThread)
        {
            DoThreadMagic(hThread);

            GetExitCodeThread(hThread, &hModule);

            if (!hModule)
            {
                g_log.LogInfo(L"DLL INJECTION: Failed load library!");
            }

            CloseHandle(hThread);
        }
        else
        {
            g_log.LogInfo(L"DLL INJECTION: Failed to start thread %d!", GetLastError());
        }
    }
    else
    {
        g_log.LogInfo(L"DLL INJECTION: Failed WriteProcessMemory!");
    }

    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);



    return (LPVOID)hModule;
}

DWORD_PTR GetAddressOfEntryPoint(BYTE * dllMemory)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dllMemory;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);
    return pNt->OptionalHeader.AddressOfEntryPoint;
}

LPVOID StealthDllInjection(HANDLE hProcess, const WCHAR * dllPath, BYTE * dllMemory)
{
    LPVOID remoteImageBaseOfInjectedDll = 0;

    if (dllMemory)
    {
        remoteImageBaseOfInjectedDll = MapModuleToProcess(hProcess, dllMemory);
        if (remoteImageBaseOfInjectedDll)
        {

            DWORD_PTR entryPoint = GetAddressOfEntryPoint(dllMemory);

            if (entryPoint)
            {
                DWORD_PTR dllMain = entryPoint + (DWORD_PTR)remoteImageBaseOfInjectedDll;

                g_log.LogInfo(L"DLL INJECTION: Starting thread at RVA %p VA %p!", entryPoint, dllMain);

                HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)dllMain, remoteImageBaseOfInjectedDll, CREATE_SUSPENDED, 0);
                if (hThread)
                {
                    DoThreadMagic(hThread);

                    CloseHandle(hThread);
                }
                else
                {
                    g_log.LogInfo(L"DLL INJECTION: Failed to start thread %d!", GetLastError());
                }
            }
        }
        else
        {
            g_log.LogInfo(L"DLL INJECTION: Failed to map image of %s!", dllPath);
        }
        free(dllMemory);
    }

    return remoteImageBaseOfInjectedDll;
}

void injectDll(DWORD targetPid, const WCHAR * dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
    BYTE * dllMemory = ReadFileToMemory(dllPath);

    if (hProcess && dllMemory)
    {
        LPVOID remoteImage = 0;

        DWORD entryPoint = (DWORD)GetAddressOfEntryPoint(dllMemory);

        if (entryPoint) g_log.LogInfo(L"DLL entry point (DllMain) RVA %X!", entryPoint);

        if (g_settings.opts().dllStealth)
        {
            g_log.LogInfo(L"Starting Stealth DLL Injection!");
            remoteImage = StealthDllInjection(hProcess, dllPath, dllMemory);
        }
        else if (g_settings.opts().dllNormal)
        {
            g_log.LogInfo(L"Starting Normal DLL Injection!");
            remoteImage = NormalDllInjection(hProcess, dllPath);
        }
        else
        {
            g_log.LogInfo(L"DLL INJECTION: No injection type selected!");
        }

        if (remoteImage)
        {
            g_log.LogInfo(L"DLL INJECTION: Injection of %s successful, Imagebase %p", dllPath, remoteImage);

            if (g_settings.opts().dllUnload)
            {
                g_log.LogInfo(L"DLL INJECTION: Unloading Imagebase %p", remoteImage);

                if (g_settings.opts().dllNormal)
                {
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)FreeLibrary, remoteImage, CREATE_SUSPENDED, 0);
                    if (hThread)
                    {
                        DoThreadMagic(hThread);
                        CloseHandle(hThread);
                        g_log.LogInfo(L"DLL INJECTION: Unloading Imagebase %p successful", remoteImage);
                    }
                    else
                    {
                        g_log.LogInfo(L"DLL INJECTION: Unloading Imagebase %p FAILED", remoteImage);
                    }
                }
                else if (g_settings.opts().dllStealth)
                {
                    VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
                    g_log.LogInfo(L"DLL INJECTION: Unloading Imagebase %p successful", remoteImage);
                }
            }
        }

        free(dllMemory);
        CloseHandle(hProcess);
    }
    else
    {
        if (!hProcess) g_log.LogInfo(L"DLL INJECTION: Cannot open process handle %d", targetPid);
        if (!dllMemory) g_log.LogInfo(L"DLL INJECTION: Failed to read file %s!", dllPath);
    }
}

BYTE * ReadFileToMemory(const WCHAR * targetFilePath)
{
    HANDLE hFile;
    DWORD dwBytesRead;
    DWORD FileSize;
    BYTE* FilePtr = 0;

    hFile = CreateFileW(targetFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        FileSize = GetFileSize(hFile, NULL);
        if (FileSize > 0)
        {
            FilePtr = (BYTE*)calloc(FileSize + 1, 1);
            if (FilePtr)
            {
                if (!ReadFile(hFile, (LPVOID)FilePtr, FileSize, &dwBytesRead, NULL))
                {
                    free(FilePtr);
                    FilePtr = 0;
                }

            }
        }
        CloseHandle(hFile);
    }

    return FilePtr;
}

void FillHookDllData(HANDLE hProcess, HOOK_DLL_DATA *hdd)
{
    HMODULE localKernel = GetModuleHandleW(L"kernel32.dll");
    HMODULE localKernelbase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");

    hdd->hNtdll = GetModuleBaseRemote(hProcess, L"ntdll.dll");
    hdd->hkernel32 = GetModuleBaseRemote(hProcess, L"kernel32.dll");
    hdd->hkernelBase = GetModuleBaseRemote(hProcess, L"kernelbase.dll");
    hdd->hUser32 = GetModuleBaseRemote(hProcess, L"user32.dll");

    hdd->EnablePebBeingDebugged = g_settings.opts().fixPebBeingDebugged;
    hdd->EnablePebHeapFlags = g_settings.opts().fixPebHeapFlags;
    hdd->EnablePebNtGlobalFlag = g_settings.opts().fixPebNtGlobalFlag;
    hdd->EnablePebStartupInfo = g_settings.opts().fixPebStartupInfo;
    hdd->EnableBlockInputHook = g_settings.opts().hookBlockInput;
    hdd->EnableOutputDebugStringHook = g_settings.opts().hookOutputDebugStringA;
    hdd->EnableNtSetInformationThreadHook = g_settings.opts().hookNtSetInformationThread;
    hdd->EnableNtQueryInformationProcessHook = g_settings.opts().hookNtQueryInformationProcess;
    hdd->EnableNtQuerySystemInformationHook = g_settings.opts().hookNtQuerySystemInformation;
    hdd->EnableNtQueryObjectHook = g_settings.opts().hookNtQueryObject;
    hdd->EnableNtYieldExecutionHook = g_settings.opts().hookNtYieldExecution;
    hdd->EnableNtCloseHook = g_settings.opts().hookNtClose;
    hdd->EnableNtCreateThreadExHook = g_settings.opts().hookNtCreateThreadEx;
    hdd->EnablePreventThreadCreation = g_settings.opts().preventThreadCreation;
    hdd->EnableNtUserFindWindowExHook = g_settings.opts().hookNtUserFindWindowEx;
    hdd->EnableNtUserBuildHwndListHook = g_settings.opts().hookNtUserBuildHwndList;
    hdd->EnableNtUserQueryWindowHook = g_settings.opts().hookNtUserQueryWindow;
    hdd->EnableNtSetDebugFilterStateHook = g_settings.opts().hookNtSetDebugFilterState;
    hdd->EnableGetTickCountHook = g_settings.opts().hookGetTickCount;
    hdd->EnableGetTickCount64Hook = g_settings.opts().hookGetTickCount64;
    hdd->EnableGetLocalTimeHook = g_settings.opts().hookGetLocalTime;
    hdd->EnableGetSystemTimeHook = g_settings.opts().hookGetSystemTime;
    hdd->EnableNtQuerySystemTimeHook = g_settings.opts().hookNtQuerySystemTime;
    hdd->EnableNtQueryPerformanceCounterHook = g_settings.opts().hookNtQueryPerformanceCounter;
    hdd->EnableNtSetInformationProcessHook = g_settings.opts().hookNtSetInformationProcess;

    hdd->EnableNtGetContextThreadHook = g_settings.opts().hookNtGetContextThread;
    hdd->EnableNtSetContextThreadHook = g_settings.opts().hookNtSetContextThread;
    hdd->EnableNtContinueHook = g_settings.opts().hookNtContinue | g_settings.opts().killAntiAttach;
    hdd->EnableKiUserExceptionDispatcherHook = g_settings.opts().hookKiUserExceptionDispatcher;
    hdd->EnableMalwareRunPeUnpacker = g_settings.opts().malwareRunpeUnpacker;

    hdd->isKernel32Hooked = FALSE;
    hdd->isNtdllHooked = FALSE;
    hdd->isUser32Hooked = FALSE;
}

bool RemoveDebugPrivileges(HANDLE hProcess)
{
    TOKEN_PRIVILEGES Debug_Privileges;

    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
    {
        HANDLE hToken = 0;
        if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            Debug_Privileges.Privileges[0].Attributes = 0;
            Debug_Privileges.PrivilegeCount = 1;

            AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, NULL, NULL);
            CloseHandle(hToken);
            return true;
        }
    }

    return false;
}

#define DbgBreakPoint_FUNC_SIZE         0x02
#ifdef _WIN64
#define DbgUiRemoteBreakin_FUNC_SIZE    0x42
#define NtContinue_FUNC_SIZE            0x0b
#else
#define DbgUiRemoteBreakin_FUNC_SIZE    0x54
#define NtContinue_FUNC_SIZE            0x18
#endif

void ApplyAntiAntiAttach(DWORD pid)
{
    static const struct {
        const wchar_t *module;
        const char *name;
        size_t size;
    } patch_funcs[] = {
        { L"ntdll.dll", "DbgBreakPoint", DbgBreakPoint_FUNC_SIZE },
        { L"ntdll.dll", "DbgUiRemoteBreakin", DbgUiRemoteBreakin_FUNC_SIZE },
        { L"ntdll.dll", "NtContinue", NtContinue_FUNC_SIZE }
    };

    scl::Handle hProcess(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, pid));
    if (!hProcess.get())
    {
        g_log.LogError(L"Anti-Anti-Attach: Failed to open process (pid=%d): %s", pid, scl::FormatMessageW(GetLastError()).c_str());
        return;
    }

    for (size_t i = 0; i < _countof(patch_funcs); i++)
    {
        auto hLocalModule = GetModuleHandleW(patch_funcs[i].module);
        if (!hLocalModule)
        {
            g_log.LogError(L"Anti-Anti-Attach: Failed to get module handle (%s). %s!%s will remain unpatched!",
                scl::FormatMessageW(GetLastError()).c_str(), patch_funcs[i].module, scl::wstr_conv().from_bytes(patch_funcs[i].name).c_str());
            continue;
        }

        auto hRemoteModule = scl::GetRemoteModuleHandleW(hProcess.get(), patch_funcs[i].module);
        if (!hRemoteModule)
        {
            g_log.LogError(L"Anti-Anti-Attach: Failed to get remote module handle (%s). %s!%s will remain unpatched!",
                scl::FormatMessageW(GetLastError()).c_str(), patch_funcs[i].module, scl::wstr_conv().from_bytes(patch_funcs[i].name).c_str());
            continue;
        }

        // TODO: need more checks on hRemoteModule.

        auto proc_addr = GetProcAddress(hLocalModule, patch_funcs[i].name);
        if (!proc_addr)
        {
            g_log.LogError(L"Anti-Anti-Attach: Failed to get proc address (%s). %s!%s will remain unpatched!",
                scl::FormatMessageW(GetLastError()).c_str(), patch_funcs[i].module, scl::wstr_conv().from_bytes(patch_funcs[i].name).c_str());
            continue;
        }

        auto proc_addr_rva = (DWORD_PTR)proc_addr - (DWORD_PTR)hLocalModule;

        if (WriteProcessMemory(hProcess.get(), (PVOID)((DWORD_PTR)hRemoteModule + proc_addr_rva), proc_addr, patch_funcs[i].size, nullptr))
        {
            g_log.LogError(L"Anti-Anti-Attach: Failed to patch process (%s). %s!%s will remain unpatched!",
                scl::FormatMessageW(GetLastError()).c_str(), patch_funcs[i].module, scl::wstr_conv().from_bytes(patch_funcs[i].name).c_str());
            continue;
        }
    }
}
