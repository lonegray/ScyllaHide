#include <windows.h>
#include "..\HookLibrary\HookMain.h"

void ReadNtApiInformation(const wchar_t *file, HOOK_DLL_DATA *hde);

void InstallAntiAttachHook();
void startInjectionProcess(HANDLE hProcess, HOOK_DLL_DATA *hdd, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, HOOK_DLL_DATA *hdd, const WCHAR * dllPath, bool newProcess);
void InjectDll(DWORD pid, const wchar_t *dll_path);
void FillHookDllData(HANDLE hProcess, HOOK_DLL_DATA * data);
bool StartFixBeingDebugged(DWORD targetPid, bool setToNull);
void ApplyAntiAntiAttach(DWORD pid);

bool RemoveDebugPrivileges(HANDLE hProcess);
