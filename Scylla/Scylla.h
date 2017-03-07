#pragma once

#include <Windows.h>
#include <string>

namespace scl
{
    void InjectDll(DWORD pid, const wchar_t *dll_path, bool stealth, bool unload);
    void KillAntiAttach(DWORD pid);
}
