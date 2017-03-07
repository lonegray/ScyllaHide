#include <windows.h>
#include <Scylla/Hook.h>

void ReadNtApiInformation(const wchar_t *file, HOOK_DLL_DATA *hde);

void InstallAntiAttachHook();
void startInjectionProcess(HANDLE hProcess, HOOK_DLL_DATA *hdd, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, HOOK_DLL_DATA *hdd, const WCHAR * dllPath, bool newProcess);
void FillHookDllData(HANDLE hProcess, HOOK_DLL_DATA * data);
bool StartFixBeingDebugged(DWORD targetPid, bool setToNull);

bool RemoveDebugPrivileges(HANDLE hProcess);
