#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#include <tchar.h>

#pragma warning(disable: 4996)
#define STR_MODULE_NAME					    L"KeyBoardHook.dll"
#define STATUS_SUCCESS						(0x00000000L)

#pragma data_seg(".share")
char whatNowKeyDown = 0;
BOOL isNewKeyHit = FALSE;
#pragma data_seg()
#pragma comment(linker,"/SECTION:.share,RWS")

typedef LONG NTSTATUS;
typedef struct _CLIENT_ID 
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef struct _THREAD_BASIC_INFORMATION 
{
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION;
typedef NTSTATUS(WINAPI* PFZWRESUMETHREAD)
(
	HANDLE ThreadHandle,
	PULONG SuspendCount
	);

typedef NTSTATUS(WINAPI* PFZWQUERYINFORMATIONTHREAD)
(
	HANDLE ThreadHandle,
	ULONG ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
);

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
HHOOK g_hook = NULL;
HINSTANCE g_hInstance = NULL;

BYTE g_pZWRT[5] = { 0, };

BOOL IsVistaLater()
{
	OSVERSIONINFO osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	GetVersionExW(&osvi);

	if (osvi.dwMajorVersion >= 6)
		return TRUE;

	return FALSE;
}

void DebugLog(const char* format, ...)
{
	va_list vl;
	FILE* pf = NULL;
	char szLog[512] = { 0, };

	va_start(vl, format);
	wsprintfA(szLog, format, vl);
	va_end(vl);

	OutputDebugStringA(szLog);
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE                  hProcess = NULL;
	HANDLE                  hThread = NULL;
	LPVOID                  pRemoteBuf = NULL;
	DWORD                   dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE  pThreadProc = NULL;
	BOOL                    bRet = FALSE;
	HMODULE                 hMod = NULL;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		DebugLog("InjectDll() : OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		goto INJECTDLL_EXIT;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
		MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		DebugLog("InjectDll() : VirtualAllocEx() failed!!! [%d]\n", GetLastError());
		goto INJECTDLL_EXIT;
	}

	if (!WriteProcessMemory(hProcess, pRemoteBuf,
		(LPVOID)szDllPath, dwBufSize, NULL))
	{
		DebugLog("InjectDll() : WriteProcessMemory() failed!!! [%d]\n", GetLastError());
		goto INJECTDLL_EXIT;
	}

	hMod = GetModuleHandle(L"kernel32.dll");
	if (hMod == NULL)
	{
		DebugLog("InjectDll() : GetModuleHandle() failed!!! [%d]\n", GetLastError());
		goto INJECTDLL_EXIT;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
	if (pThreadProc == NULL)
	{
		DebugLog("InjectDll() : GetProcAddress() failed!!! [%d]\n", GetLastError());
		goto INJECTDLL_EXIT;
	}

	if (!MyCreateRemoteThread(hProcess, pThreadProc, pRemoteBuf))
	{
		DebugLog("InjectDll() : MyCreateRemoteThread() failed!!!\n");
		goto INJECTDLL_EXIT;
	}

	bRet = TRUE;

INJECTDLL_EXIT:

	if (pRemoteBuf)
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	if (hThread)
		CloseHandle(hThread);

	if (hProcess)
		CloseHandle(hProcess);

	return bRet;
}

BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	HANDLE      hThread = NULL;
	FARPROC     pFunc = NULL;

	if (IsVistaLater())    // Vista, 7, Server2008
	{
		pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		if (pFunc == NULL)
		{
			DebugLog("MyCreateRemoteThread() : GetProcAddress() failed!!! [%d]\n",
				GetLastError());
			return FALSE;
		}

		((PFNTCREATETHREADEX)pFunc)(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			pRemoteBuf,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);
		if (hThread == NULL)
		{
			DebugLog("MyCreateRemoteThread() : NtCreateThreadEx() failed!!! [%d]\n", GetLastError());
			return FALSE;
		}
	}
	else                    // 2000, XP, Server2003
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0,
			pThreadProc, pRemoteBuf, 0, NULL);
		if (hThread == NULL)
		{
			DebugLog("MyCreateRemoteThread() : CreateRemoteThread() failed!!! [%d]\n", GetLastError());
			return FALSE;
		}
	}

	if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))
	{
		DebugLog("MyCreateRemoteThread() : WaitForSingleObject() failed!!! [%d]\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL hook_by_code(LPCTSTR szDllName, LPCTSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandle(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] == 0xE9)
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pOrgBytes, pFunc, 5);

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pFunc, pBuf, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}



BOOL unhook_by_code(LPCTSTR szDllName, LPCTSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandle(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xE9)
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pFunc, pOrgBytes, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,             // lookup privilege on local system
		lpszPrivilege,    // privilege to lookup 
		&luid))          // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}
NTSTATUS WINAPI NewZwResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
	NTSTATUS status, statusThread;
	FARPROC pFunc = NULL, pFuncThread = NULL;
	DWORD dwPID = 0;
	static DWORD dwPrevPID = 0;
	THREAD_BASIC_INFORMATION tbi;
	HMODULE hMod = NULL;
	char szModPath[MAX_PATH] = { 0, };

	DebugLog("NewZwResumeThread() : start!!!\n");

	MessageBox(NULL, L"ResuemeThread", NULL, MB_OK | MB_TOPMOST);

	hMod = GetModuleHandle(L"ntdll.dll");
	if (hMod == NULL)
	{
		DebugLog("NewZwResumeThread() : GetModuleHandle(%s) failed!!! [%d]\n",
			"\"ntdll.dll\"", GetLastError());
		return NULL;
	}

	// call ntdll!ZwQueryInformationThread()
	pFuncThread = GetProcAddress(hMod, "ZwQueryInformationThread");
	if (pFuncThread == NULL)
	{
		DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
			"\"ZwQueryInformationThread\"", GetLastError());
		return NULL;
	}

	statusThread = ((PFZWQUERYINFORMATIONTHREAD)pFuncThread)
		(ThreadHandle, 0, &tbi, sizeof(tbi), NULL);
	if (statusThread != STATUS_SUCCESS)
	{
		DebugLog("NewZwResumeThread() : pFuncThread() failed!!! [%d]\n",
			GetLastError());
		return NULL;
	}

	dwPID = (DWORD)tbi.ClientId.UniqueProcess;
	if ((dwPID != GetCurrentProcessId()) && (dwPID != dwPrevPID))
	{
		DebugLog("NewZwResumeThread() => call \n");

		dwPrevPID = dwPID;

		// change privilege
		if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
			DebugLog("NewZwResumeThread() : SetPrivilege() failed!!!\n");

		// get injection dll path
		GetModuleFileName(GetModuleHandle(STR_MODULE_NAME),szModPath,MAX_PATH);

		if (!InjectDll(dwPID, szModPath))
			DebugLog("NewZwResumeThread() : InjectDll(%d) failed!!!\n", dwPID);
	}

	// call ntdll!ZwResumeThread()
	if (!unhook_by_code(L"ntdll.dll", L"ZwResumeThread", g_pZWRT))
	{
		DebugLog("NewZwResumeThread() : unhook_by_code() failed!!!\n");
		return NULL;
	}

	pFunc = GetProcAddress(hMod, "ZwResumeThread");
	if (pFunc == NULL)
	{
		DebugLog("NewZwResumeThread() : GetProcAddress(%s) failed!!! [%d]\n",
			"\"ZwResumeThread\"", GetLastError());
		goto __NTRESUMETHREAD_END;
	}

	status = ((PFZWRESUMETHREAD)pFunc)(ThreadHandle, SuspendCount);
	if (status != STATUS_SUCCESS)
	{
		DebugLog("NewZwResumeThread() : pFunc() failed!!! [%d]\n", GetLastError());
		goto __NTRESUMETHREAD_END;
	}

__NTRESUMETHREAD_END:

	if (!hook_by_code(L"ntdll.dll", L"ZwResumeThread",
		(PROC)NewZwResumeThread, g_pZWRT))
	{
		DebugLog("NewZwResumeThread() : hook_by_code() failed!!!\n");
	}

	DebugLog("NewZwResumeThread() : end!!!\n");

	return status;
}

LRESULT CALLBACK KeyBoardLogging(int nCode, WPARAM wParam, LPARAM lParam)
{
	//add process

	if (nCode >= 0)
	{
		if (!(lParam & 0x80000000))
		{
			whatNowKeyDown = wParam;
			isNewKeyHit = TRUE;
		}
	}

	return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	char            szCurProc[MAX_PATH] = { 0, };
	char* p = NULL;


	// change privilege
	SetPrivilege(SE_DEBUG_NAME, TRUE);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// hook
		g_hInstance = hinstDLL;
		hook_by_code(L"ntdll.dll", L"ZwResumeThread",(PROC)NewZwResumeThread, g_pZWRT);
		g_hook = SetWindowsHookEx(WH_KEYBOARD, KeyBoardLogging, g_hInstance, 0);
		break;

	case DLL_PROCESS_DETACH:
		// unhook
		unhook_by_code(L"ntdll.dll", L"ZwResumeThread",g_pZWRT);
		UnhookWindowsHookEx(g_hook);
		break;
	}

	return TRUE;
}
#ifdef __cplusplus
extern "C"
{
	_declspec(dllexport) char GetKeyboardValue()
	{
		isNewKeyHit = FALSE;
		return whatNowKeyDown;
	}

	_declspec(dllexport) BOOL IsNewKeyHit()
	{
		return isNewKeyHit;
	}
}
#endif