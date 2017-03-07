#pragma once

#include <Windows.h>
#include <Scylla/Hook.h>
#include <Scylla/Settings.h>

namespace scl
{
    void ReadNtApiInformation(const wchar_t *file, HOOK_DLL_DATA *hdd);

    void InjectDll(DWORD pid, const wchar_t *dll_path, bool stealth, bool unload);

    void KillAntiAttach(DWORD pid);

    void InitHookDllData(HOOK_DLL_DATA *hdd, HANDLE hProcess, const Settings &settings);
}
