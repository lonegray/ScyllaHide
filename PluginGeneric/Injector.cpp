#include "Injector.h"

#include <Scylla/DynamicMapping.h>
#include <Scylla/Logger.h>
#include <Scylla/OsInfo.h>
#include <Scylla/PebHider.h>
#include <Scylla/Scylla.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>

#include "..\InjectorCLI\\ApplyHooking.h"

extern scl::Settings g_settings;
extern scl::Logger g_log;

static LPVOID remoteImageBase = 0;

typedef void(__cdecl * t_SetDebuggerBreakpoint)(DWORD_PTR address);
t_SetDebuggerBreakpoint _SetDebuggerBreakpoint = 0;

//anti-attach vars
static DWORD ExitThread_addr;
static BYTE *DbgUiIssueRemoteBreakin_addr;
static DWORD jmpback;
static DWORD DbgUiRemoteBreakin_addr;
static BYTE *RemoteBreakinPatch;
static BYTE code[8];
static HANDLE hDebuggee;

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

void ApplyPEBPatch(HANDLE hProcess, DWORD flags)
{
    auto peb = scl::GetPeb(hProcess);
    if (!peb) {
        g_log.LogError(L"Failed to read PEB from remote process");
    }
    else
    {
        if (flags & PEB_PATCH_BeingDebugged)
            peb->BeingDebugged = FALSE;
        if (flags & PEB_PATCH_NtGlobalFlag)
            peb->NtGlobalFlag &= ~0x70;

        if (flags & PEB_PATCH_ProcessParameters) {
            if (!scl::PebPatchProcessParameters(peb.get(), hProcess))
                g_log.LogError(L"Failed to patch PEB!ProcessParameters");
        }

        if (flags & PEB_PATCH_HeapFlags)
        {
            if (!scl::PebPatchHeapFlags(peb.get(), hProcess))
                g_log.LogError(L"Failed to patch flags in PEB!ProcessHeaps");
        }

        if (!scl::SetPeb(hProcess, peb.get()))
            g_log.LogError(L"Failed to write PEB to remote process");

    }

#ifndef _WIN64
    if (!scl::IsWow64Process(hProcess))
        return;

    auto peb64 = scl::Wow64GetPeb64(hProcess);
    if (!peb64) {
        g_log.LogError(L"Failed to read PEB64 from remote process");
    }
    else
    {
        if (flags & PEB_PATCH_BeingDebugged)
            peb64->BeingDebugged = FALSE;
        if (flags & PEB_PATCH_NtGlobalFlag)
            peb64->NtGlobalFlag &= ~0x70;

        if (flags & PEB_PATCH_ProcessParameters) {
            if (!scl::Wow64Peb64PatchProcessParameters(peb64.get(), hProcess))
                g_log.LogError(L"Failed to patch PEB64!ProcessParameters");
        }

        if (flags & PEB_PATCH_HeapFlags)
        {
            if (!scl::Wow64Peb64PatchHeapFlags(peb64.get(), hProcess))
                g_log.LogError(L"Failed to patch flags in PEB64!ProcessHeaps");
        }

        if (!scl::Wow64SetPeb64(hProcess, peb64.get()))
            g_log.LogError(L"Failed to write PEB64 to remote process");
    }
#endif
}

void startInjection(DWORD pid, HOOK_DLL_DATA *hdd, const wchar_t* dll_path, bool new_process)
{
    scl::Handle hProcess(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, pid));
    if (!hProcess.get())
    {
        g_log.LogError(L"Failed to open process PID %d: %s", pid, scl::FormatMessageW(GetLastError()).c_str());
        return;
    }

    std::basic_string<BYTE> dll_mem;
    if (!scl::ReadFileContents(dll_path, dll_mem))
    {
        g_log.LogError(L"Failed to read file %s: %s", dll_path, scl::FormatMessageW(GetLastError()).c_str());
        return;
    }

    auto remote_hdd_rva = scl::GetDllFunctionAddressRva(dll_mem.data(), "HookDllData");
    if (!remote_hdd_rva)
    {
        g_log.LogError(L"Failed to get RVA for %s!HookDllData", dll_path);
        return;
    }

    if (new_process)
    {
        scl::InitHookDllData(hdd, hProcess.get(), g_settings);

        if (g_settings.opts().removeDebugPrivileges)
        {
            if (!scl::RemoveDebugPrivileges(hProcess.get()))
            {
                g_log.LogError(L"Failed to remove debug privileges PID %d: %s", pid, scl::FormatMessageW(GetLastError()).c_str());
            }
        }

        RestoreHooks(hdd, hProcess.get());

        auto ret = scl::MapModuleToProcess(hProcess.get(), &dll_mem[0]);
        if (!ret.first)
        {
            g_log.LogError(L"Failed to load %s into remote process: %s", dll_path, ret.second.c_str());
        }
        remoteImageBase = ret.first;

        g_log.LogInfo(L"Hook Injection successful, Imagebase %p", remoteImageBase);
    }

    // For olly plugins
    hdd->dwProtectedProcessId = GetCurrentProcessId();
    hdd->EnableProtectProcessId = TRUE;

    if (!ApplyHook(hdd, hProcess.get(), &dll_mem[0], (DWORD_PTR)remoteImageBase))
    {
        g_log.LogError(L"Failed to apply hooks, sorry...");
    }

    if (!WriteProcessMemory(hProcess.get(), (LPVOID)((DWORD_PTR)remoteImageBase + remote_hdd_rva), hdd, sizeof(HOOK_DLL_DATA), 0))
    {
        g_log.LogError(L"Failed to write updated hook data into remote process: %s", scl::FormatMessageW(GetLastError()).c_str());
    }

    DWORD peb_flags = 0;
    if (g_settings.opts().fixPebBeingDebugged) peb_flags |= PEB_PATCH_BeingDebugged;
    if (g_settings.opts().fixPebHeapFlags) peb_flags |= PEB_PATCH_HeapFlags;
    if (g_settings.opts().fixPebNtGlobalFlag) peb_flags |= PEB_PATCH_NtGlobalFlag;
    if (g_settings.opts().fixPebStartupInfo) peb_flags |= PEB_PATCH_ProcessParameters;

    ApplyPEBPatch(hProcess.get(), peb_flags);
}
