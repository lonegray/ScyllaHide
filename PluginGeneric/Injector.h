#pragma once

#include <windows.h>
#include "Scylla/Hook.h"

void InstallAntiAttachHook();
void startInjection(DWORD targetPid, HOOK_DLL_DATA *hdd, const WCHAR * dllPath, bool newProcess);
bool StartFixBeingDebugged(DWORD targetPid, bool setToNull);

bool RemoveDebugPrivileges(HANDLE hProcess);
