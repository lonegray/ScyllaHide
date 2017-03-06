#include "DynamicMapping.h"
#include <ntdll/ntdll.h>

#include "Util.h"

static DWORD RvaToOffset(const PIMAGE_NT_HEADERS nt_headers, DWORD rva)
{
    auto section = IMAGE_FIRST_SECTION(nt_headers);

    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
            return rva - section->VirtualAddress + section->PointerToRawData;
        section++;
    }

    return 0;
}

static void ResolveRelocations(PIMAGE_BASE_RELOCATION relocation, DWORD_PTR module, DWORD_PTR delta)
{
    while (relocation->VirtualAddress)
    {
        auto dest = (BYTE *)(module + relocation->VirtualAddress);
        DWORD reloc_count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto reloc_info = (WORD *)((DWORD_PTR)relocation + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < reloc_count; i++)
        {
            WORD type = reloc_info[i] >> 12;
            WORD offset = reloc_info[i] & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
            case IMAGE_REL_BASED_DIR64: {
                auto *patchAddress = (DWORD_PTR *)(dest + offset);
                *patchAddress += delta;
                break;
            }
            default:
                break;
            }
        }

        relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocation + relocation->SizeOfBlock);
    }
}

static std::pair<bool, std::wstring> ResolveImports(PIMAGE_IMPORT_DESCRIPTOR import_descr, DWORD_PTR module)
{
    while (import_descr->FirstThunk)
    {
        auto module_name = (char *)(module + import_descr->Name);
        auto module_name_w = scl::wstr_conv().from_bytes(module_name);
        auto hModule = GetModuleHandleA(module_name);

        if (!hModule)
        {
            hModule = LoadLibraryA(module_name);
            if (!hModule)
            {
                auto error_str = scl::fmtw(L"Failed to load library %s (%s)",
                    module_name_w.c_str(), scl::FormatMessageW(GetLastError()).c_str());
                return std::make_pair(false, error_str);
            }
        }

        auto func_ref = (PIMAGE_THUNK_DATA)(module + import_descr->FirstThunk);
        PIMAGE_THUNK_DATA thunk_ref;
        if (import_descr->OriginalFirstThunk)
        {
            thunk_ref = (PIMAGE_THUNK_DATA)(module + import_descr->OriginalFirstThunk);
        }
        else
        {
            thunk_ref = (PIMAGE_THUNK_DATA)(module + import_descr->FirstThunk);
        }

        while (thunk_ref->u1.Function)
        {
            std::wstring func_name;

            if (IMAGE_SNAP_BY_ORDINAL(thunk_ref->u1.Function))
            {
                func_ref->u1.Function = (DWORD_PTR)GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(thunk_ref->u1.Ordinal));
                func_name = scl::fmtw(L"`ordinal %u`", IMAGE_ORDINAL(thunk_ref->u1.Ordinal));
            }
            else
            {
                auto thunk_data = (PIMAGE_IMPORT_BY_NAME)(module + thunk_ref->u1.AddressOfData);
                func_ref->u1.Function = (DWORD_PTR)GetProcAddress(hModule, (LPCSTR)thunk_data->Name);
                func_name = scl::wstr_conv().from_bytes((LPCSTR)thunk_data->Name);
            }

            if (!func_ref->u1.Function)
            {
                auto error_str = scl::fmtw(L"Failed to resolve %s!%s (%s)",
                    module_name_w.c_str(), func_name.c_str(), scl::FormatMessageW(GetLastError()).c_str());
                return std::make_pair(false, error_str);
            }

            thunk_ref++;
            func_ref++;
        }

        import_descr++;
    }

    return std::make_pair(true, std::wstring());
}

std::pair<HMODULE, std::wstring> scl::MapModuleToProcess(HANDLE hProcess, const BYTE *dll_mem)
{
    auto dos_header = (PIMAGE_DOS_HEADER)dll_mem;
    auto nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);

    if ((dos_header->e_magic != IMAGE_DOS_SIGNATURE) || (nt_headers->Signature != IMAGE_NT_SIGNATURE))
        return std::make_pair(nullptr, L"Invalid DOS/NT header");

    if (!nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        return std::make_pair(nullptr, L"Missing relocation section");

    VirtualMemoryHandle hModuleRemote(hProcess, VirtualAllocEx(hProcess, nullptr, nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!hModuleRemote.get())
        return std::make_pair(nullptr, fmtw(L"Failed to allocate remote memory (%s)", FormatMessageW(GetLastError())).c_str());

    std::basic_string<BYTE> hModuleLocal;
    hModuleLocal.resize(nt_headers->OptionalHeader.SizeOfHeaders);

    memcpy(&hModuleLocal[0], dos_header, nt_headers->OptionalHeader.SizeOfHeaders);

    auto section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        memcpy((LPVOID)((DWORD_PTR)hModuleLocal.data() + section->VirtualAddress), (LPVOID)((DWORD_PTR)dos_header + section->PointerToRawData), section->SizeOfRawData);
        section++;
    }

    auto delta = (DWORD_PTR)hModuleRemote.get() - nt_headers->OptionalHeader.ImageBase;
    ResolveRelocations(
        (PIMAGE_BASE_RELOCATION)((DWORD_PTR)hModuleLocal.data() + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
        (DWORD_PTR)hModuleLocal.data(),
        delta);

    auto ret = ResolveImports(
        (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModuleLocal.data() + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
        (DWORD_PTR)hModuleLocal.data()
        );

    if (!ret.first)
        return std::make_pair(nullptr, ret.second);

    if (!WriteProcessMemory(hProcess, hModuleRemote.get(), hModuleLocal.data(), nt_headers->OptionalHeader.SizeOfImage, nullptr))
        return std::make_pair(nullptr, fmtw(L"Failed to write to remote process (%s)", FormatMessageW(GetLastError()).c_str()));

    return std::make_pair((HMODULE)hModuleRemote.reset(nullptr, nullptr).second, std::wstring());
}

DWORD scl::GetDllFunctionAddressRva(const BYTE *dll_mem, const char *func_name)
{
    auto dos_header = (PIMAGE_DOS_HEADER)dll_mem;
    auto nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);

    auto export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto export_dir_offset = RvaToOffset(nt_headers, export_dir_rva);

    auto export_dir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dll_mem + export_dir_offset);

    auto funcs = (DWORD *)((DWORD_PTR)export_dir + export_dir->AddressOfFunctions - export_dir_rva);
    auto names = (DWORD *)((DWORD_PTR)export_dir + export_dir->AddressOfNames - export_dir_rva);
    auto ordinals = (WORD *)((DWORD_PTR)export_dir + export_dir->AddressOfNameOrdinals - export_dir_rva);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++)
    {
        auto fn_name = (char *)((DWORD_PTR)export_dir + names[i] - export_dir_rva);
        if (!_stricmp(fn_name, func_name))
            return funcs[ordinals[i]];
    }

    return 0;
}
