#pragma once

#include <Windows.h>
#include <string>

namespace scl
{
    std::pair<HMODULE, std::wstring> InjectDllNormal(HANDLE hProcess, const wchar_t *dll_path);
    std::pair<HMODULE, std::wstring> InjectDllStealth(HANDLE hProcess, const wchar_t *dll_path);
}
