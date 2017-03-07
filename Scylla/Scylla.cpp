#include "Scylla.h"

#include "DllInject.h"
#include "Logger.h"
#include "Util.h"

extern scl::Logger g_log;

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
