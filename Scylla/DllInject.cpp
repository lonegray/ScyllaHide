#include "DllInject.h"

#include "DynamicMapping.h"
#include "Util.h"

std::pair<HMODULE, std::wstring> scl::InjectDllNormal(HANDLE hProcess, const wchar_t *dll_path)
{
    auto mem_size = (wcslen(dll_path) + 1) * sizeof(WCHAR);

    VirtualMemoryHandle remote_mem(hProcess, VirtualAllocEx(hProcess, nullptr, mem_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!remote_mem.get())
        return std::make_pair(nullptr, fmtw(L"Failed to allocate remote memory (%s)", FormatMessageW(GetLastError())));

    if (!WriteProcessMemory(hProcess, remote_mem.get(), dll_path, mem_size, nullptr))
        return std::make_pair(nullptr, fmtw(L"Failed to write to remote process (%s)", scl::FormatMessageW(GetLastError())));

    // TODO: Calculate remote LoadLibraryW address?

    Handle hThread(CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, remote_mem.get(), CREATE_SUSPENDED, nullptr));
    if (!hThread.get())
        return std::make_pair(nullptr, fmtw(L"Failed to execute remote LoadLibraryW (%s)", scl::FormatMessageW(GetLastError())));

    WaitThreadEnd(hThread.get());

    // TODO: On x64 LoadLibraryW can return address bigger than DWORD can hold.
    DWORD hModule = 0;
    GetExitCodeThread(hThread.get(), &hModule);

    return std::make_pair((HMODULE)hModule, std::wstring());
}

std::pair<HMODULE, std::wstring> scl::InjectDllStealth(HANDLE hProcess, const wchar_t *dll_path)
{
    std::basic_string<BYTE> dll_mem;
    if (!scl::ReadFileContents(dll_path, dll_mem))
        return std::make_pair(nullptr, fmtw(L"Failed to read file %s: %s", dll_path, scl::FormatMessageW(GetLastError())));

    auto ret = MapModuleToProcess(hProcess, &dll_mem[0]);
    if (!ret.first)
        return std::make_pair(nullptr, fmtw(L"Failed to map DLL into remote process: %s", dll_path, ret.second.c_str()));

    auto hModule = (HMODULE)ret.first;

    auto dos_headers = (PIMAGE_DOS_HEADER)&dll_mem[0];
    auto nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_headers + dos_headers->e_lfanew);
    auto entryPoint = nt_headers->OptionalHeader.AddressOfEntryPoint;
    if (!entryPoint)
        return std::make_pair(nullptr, L"Invalid entry point of injected DLL");

    auto dllMain = (DWORD_PTR)hModule + entryPoint;

    scl::Handle hThread(CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)dllMain, hModule, CREATE_SUSPENDED, nullptr));
    if (!hThread.get())
        return std::make_pair(nullptr, fmtw(L"Failed to execute DllMain in remote process: %s", scl::FormatMessageW(GetLastError())));

    scl::WaitThreadEnd(hThread.get());

    return std::make_pair(hModule, std::wstring());
}
