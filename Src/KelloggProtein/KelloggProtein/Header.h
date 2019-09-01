#pragma once
#ifndef _INJECTION_HEADER_H__
#define _INJECTION_HEADER_H__
#include "windows.h"
#include "stdio.h"
#include "tlhelp32.h"
#define MAX_PROCESS_NAME_LENGTH 260

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
enum { BY_PID = 0, BY_NAME };

BOOL SetPrivilege(LPCTSTR, BOOL);
BOOL InjectDll(DWORD, LPCTSTR);
BOOL EjectDll(DWORD);
BOOL InjectAllProcess(int, LPCTSTR);
BOOL SearchProcess(int, DWORD, const char*,DWORD*);
#endif