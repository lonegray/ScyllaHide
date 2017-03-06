#pragma once

#include <Windows.h>
#include <string>
#include <utility>

namespace scl
{
    std::pair<HMODULE, std::wstring> MapModuleToProcess(HANDLE hProcess, const BYTE *dll_mem);
    DWORD GetDllFunctionAddressRva(const BYTE *dll_mem, const char *func_name);
}
