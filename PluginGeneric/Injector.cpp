#include "Injector.h"

#include <Scylla/DynamicMapping.h>
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
    DWORD hookDllDataAddressRva = scl::GetDllFunctionAddressRva(dllMemory, "HookDllData");

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

        remoteImageBase = scl::MapModuleToProcess(hProcess, dllMemory).first;
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
        std::basic_string<BYTE> dllMemory;
        if (scl::ReadFileContents(dllPath, dllMemory))
        {
            startInjectionProcess(hProcess, hdd, &dllMemory[0], newProcess);
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

void FillHookDllData(HANDLE hProcess, HOOK_DLL_DATA *hdd)
{
    HMODULE localKernel = GetModuleHandleW(L"kernel32.dll");
    HMODULE localKernelbase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");

    hdd->hNtdll = scl::GetRemoteModuleHandleW(hProcess, L"ntdll.dll");
    hdd->hkernel32 = scl::GetRemoteModuleHandleW(hProcess, L"kernel32.dll");
    hdd->hkernelBase = scl::GetRemoteModuleHandleW(hProcess, L"kernelbase.dll");
    hdd->hUser32 = scl::GetRemoteModuleHandleW(hProcess, L"user32.dll");

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
