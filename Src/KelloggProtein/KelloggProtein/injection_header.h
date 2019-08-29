#pragma once
#ifndef _INJECTION_HEADER_H__
#define _INJECTION_HEADER_H__
#include "windows.h"
#include "stdio.h"
#include "tlhelp32.h"

typedef DWORD(WINAPI* PFNTCREATETHREADEX)
(
	PHANDLE                 ThreadHandle,
	ACCESS_MASK             DesiredAccess,
	LPVOID                  ObjectAttributes,
	HANDLE                  ProcessHandle,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	BOOL	                CreateSuspended,
	DWORD                   dwStackSize,
	DWORD                   dw1,
	DWORD                   dw2,
	LPVOID                  Unknown
);

enum { INJECTION_MODE = 0, EJECTION_MODE };

BOOL SetPrivilege(LPCTSTR, BOOL);
BOOL InjectDll(DWORD, LPCTSTR);
BOOL EjectDll(DWORD);
BOOL InjectAllProcess(int, LPCTSTR);
#endif