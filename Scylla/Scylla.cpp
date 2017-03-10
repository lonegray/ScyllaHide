#include "Scylla.h"

#include "DllInject.h"
#include "Logger.h"
#include "NtApiLoader.h"
#include "OsInfo.h"
#include "Peb.h"
#include "Util.h"

extern scl::Logger g_log;

void scl::ReadNtApiInformation(const wchar_t *file, HOOK_DLL_DATA *hde)
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

void scl::InjectDll(DWORD pid, const wchar_t *dll_path, bool stealth, bool unload)
{
    Handle hProcess(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, pid));
    if (!hProcess.get())
    {
        g_log.LogInfo(L"Dll-Inject: Failed to open PID %d: %s", pid, scl::FormatMessageW(GetLastError()).c_str());
        return;
    }

    auto ret = stealth ? InjectDllStealth(hProcess.get(), dll_path) : InjectDllNormal(hProcess.get(), dll_path);
    if (!ret.first)
    {
        g_log.LogError(L"Dll-Inject: %s", ret.second.c_str());
        return;
    }

    auto hRemoteModule = ret.first;
    g_log.LogInfo(L"Dll-Inject: Successful injected %s, ImageBase %p", dll_path, hRemoteModule);

    if (unload)
    {
        if (stealth)
        {
            VirtualFreeEx(hProcess.get(), hRemoteModule, 0, MEM_RELEASE);
        }
        else
        {
            scl::Handle hThread(CreateRemoteThread(hProcess.get(), nullptr, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, hRemoteModule, CREATE_SUSPENDED, nullptr));
            if (!hThread.get())
            {
                g_log.LogError(L"Dll-Inject: Failed to unload %s", dll_path);
                return;
            }

            WaitThreadEnd(hThread.get());
        }
    }

    g_log.LogInfo(L"Dll-Inject: Successful unloaded %s", dll_path);
}

#define DbgBreakPoint_FUNC_SIZE         0x02
#ifdef _WIN64
#define DbgUiRemoteBreakin_FUNC_SIZE    0x42
#define NtContinue_FUNC_SIZE            0x0b
#else
#define DbgUiRemoteBreakin_FUNC_SIZE    0x54
#define NtContinue_FUNC_SIZE            0x18
#endif

void scl::KillAntiAttach(DWORD pid)
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
        g_log.LogError(L"Kill-Anti-Attach: Failed to open process (pid=%d): %s", pid, scl::FormatMessageW(GetLastError()).c_str());
        return;
    }

    for (size_t i = 0; i < _countof(patch_funcs); i++)
    {
        auto hLocalModule = GetModuleHandleW(patch_funcs[i].module);
        if (!hLocalModule)
        {
            g_log.LogError(L"Kill-Anti-Attach: Failed to get module handle (%s). %s!%s will remain unpatched!",
                scl::FormatMessageW(GetLastError()).c_str(), patch_funcs[i].module, scl::wstr_conv().from_bytes(patch_funcs[i].name).c_str());
            continue;
        }

        auto hRemoteModule = scl::GetRemoteModuleHandleW(hProcess.get(), patch_funcs[i].module);
        if (!hRemoteModule)
        {
            g_log.LogError(L"Kill-Anti-Attach: Failed to get remote module handle (%s). %s!%s will remain unpatched!",
                scl::FormatMessageW(GetLastError()).c_str(), patch_funcs[i].module, scl::wstr_conv().from_bytes(patch_funcs[i].name).c_str());
            continue;
        }

        // TODO: need more checks on hRemoteModule.

        auto proc_addr = GetProcAddress(hLocalModule, patch_funcs[i].name);
        if (!proc_addr)
        {
            g_log.LogError(L"Kill-Anti-Attach: Failed to get proc address (%s). %s!%s will remain unpatched!",
                scl::FormatMessageW(GetLastError()).c_str(), patch_funcs[i].module, scl::wstr_conv().from_bytes(patch_funcs[i].name).c_str());
            continue;
        }

        auto proc_addr_rva = (DWORD_PTR)proc_addr - (DWORD_PTR)hLocalModule;

        if (WriteProcessMemory(hProcess.get(), (PVOID)((DWORD_PTR)hRemoteModule + proc_addr_rva), proc_addr, patch_funcs[i].size, nullptr))
        {
            g_log.LogError(L"Kill-Anti-Attach: Failed to patch process (%s). %s!%s will remain unpatched!",
                scl::FormatMessageW(GetLastError()).c_str(), patch_funcs[i].module, scl::wstr_conv().from_bytes(patch_funcs[i].name).c_str());
            continue;
        }
    }
}

void scl::InitHookDllData(HOOK_DLL_DATA *hdd, HANDLE hProcess, const Settings &settings)
{
    // TODO: inspect this function.

    hdd->hNtdll = GetRemoteModuleHandleW(hProcess, L"ntdll.dll");
    hdd->hkernel32 = GetRemoteModuleHandleW(hProcess, L"kernel32.dll");
    hdd->hkernelBase = GetRemoteModuleHandleW(hProcess, L"kernelbase.dll");
    hdd->hUser32 = GetRemoteModuleHandleW(hProcess, L"user32.dll");

    hdd->EnablePebBeingDebugged = settings.opts().fixPebBeingDebugged;
    hdd->EnablePebHeapFlags = settings.opts().fixPebHeapFlags;
    hdd->EnablePebNtGlobalFlag = settings.opts().fixPebNtGlobalFlag;
    hdd->EnablePebStartupInfo = settings.opts().fixPebStartupInfo;
    hdd->EnableBlockInputHook = settings.opts().hookBlockInput;
    hdd->EnableOutputDebugStringHook = settings.opts().hookOutputDebugStringA;
    hdd->EnableNtSetInformationThreadHook = settings.opts().hookNtSetInformationThread;
    hdd->EnableNtQueryInformationProcessHook = settings.opts().hookNtQueryInformationProcess;
    hdd->EnableNtQuerySystemInformationHook = settings.opts().hookNtQuerySystemInformation;
    hdd->EnableNtQueryObjectHook = settings.opts().hookNtQueryObject;
    hdd->EnableNtYieldExecutionHook = settings.opts().hookNtYieldExecution;
    hdd->EnableNtCloseHook = settings.opts().hookNtClose;
    hdd->EnableNtCreateThreadExHook = settings.opts().hookNtCreateThreadEx;
    hdd->EnablePreventThreadCreation = settings.opts().preventThreadCreation;
    hdd->EnableNtUserFindWindowExHook = settings.opts().hookNtUserFindWindowEx;
    hdd->EnableNtUserBuildHwndListHook = settings.opts().hookNtUserBuildHwndList;
    hdd->EnableNtUserQueryWindowHook = settings.opts().hookNtUserQueryWindow;
    hdd->EnableNtSetDebugFilterStateHook = settings.opts().hookNtSetDebugFilterState;
    hdd->EnableGetTickCountHook = settings.opts().hookGetTickCount;
    hdd->EnableGetTickCount64Hook = settings.opts().hookGetTickCount64;
    hdd->EnableGetLocalTimeHook = settings.opts().hookGetLocalTime;
    hdd->EnableGetSystemTimeHook = settings.opts().hookGetSystemTime;
    hdd->EnableNtQuerySystemTimeHook = settings.opts().hookNtQuerySystemTime;
    hdd->EnableNtQueryPerformanceCounterHook = settings.opts().hookNtQueryPerformanceCounter;
    hdd->EnableNtSetInformationProcessHook = settings.opts().hookNtSetInformationProcess;

    hdd->EnableNtGetContextThreadHook = settings.opts().hookNtGetContextThread;
    hdd->EnableNtSetContextThreadHook = settings.opts().hookNtSetContextThread;
    hdd->EnableNtContinueHook = settings.opts().hookNtContinue | settings.opts().killAntiAttach;
    hdd->EnableKiUserExceptionDispatcherHook = settings.opts().hookKiUserExceptionDispatcher;
    hdd->EnableMalwareRunPeUnpacker = settings.opts().malwareRunpeUnpacker;

    hdd->isKernel32Hooked = FALSE;
    hdd->isNtdllHooked = FALSE;
    hdd->isUser32Hooked = FALSE;
}

bool scl::SetPebBeingDebugged(DWORD pid, bool being_debugged)
{
    // TODO: need logging?
    Handle hProcess(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, pid));
    if (!hProcess.get())
        return false;

    auto peb = GetPeb(hProcess.get());
    if (!peb)
        return false;

    peb->BeingDebugged = being_debugged ? TRUE : FALSE;
    if (!scl::SetPeb(hProcess.get(), peb.get()))
        return false;

    if (IsWow64Process(hProcess.get()))
    {
        auto peb64 = scl::Wow64GetPeb64(hProcess.get());
        if (!peb64)
            return false;

        peb->BeingDebugged = being_debugged ? TRUE : FALSE;
        if (!scl::Wow64SetPeb64(hProcess.get(), peb64.get()))
            return false;
    }

    return true;
}

bool scl::RemoveDebugPrivileges(HANDLE hProcess)
{
    TOKEN_PRIVILEGES privs;

    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privs.Privileges[0].Luid))
        return false;

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
        return false;

    privs.Privileges[0].Attributes = 0;
    privs.PrivilegeCount = 1;

    AdjustTokenPrivileges(hToken, FALSE, &privs, 0, nullptr, nullptr);
    CloseHandle(hToken);

    return true;
}

