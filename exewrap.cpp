#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <tchar.h>

#define DBG 0 && printf

WCHAR* CheckArg(WCHAR *arg)
{
	if (!arg)
		return arg;
	if (wcschr(arg, ' '))
	{
		WCHAR *cpy = new WCHAR[wcslen(arg)+3];
		*cpy = L'"';
		wcscpy(cpy+1, arg);
		wcscat(cpy, L"\"");
		DBG("REPLACE ARG with %ws\n", cpy);
		return cpy;
	}
	return arg;
}

int wmain(int argc, wchar_t *argv[])
{
	WCHAR path[MAX_PATH];
	if (argc > 1 && !wcscmp(argv[1], L"-exec"))
	{
		WCHAR ** newArgs = new WCHAR*[argc+2];
		newArgs[0] = argv[2];
		DBG("\nPASS2: now run %ws\n", newArgs[0]);
		int j=0;
		for(int a=2; a < argc; a++)
		{
			DBG("\tArg[%d]: %ws\n", j, argv[a]);
			newArgs[j++] = CheckArg(argv[a]);
		}
		newArgs[j] = 0;
		int sts = _wspawnv(_P_OVERLAY, newArgs[0], newArgs);
		return(sts);
		//fprintf(stderr, "ERROR: failed to start %ws\n", newArgs[0]);
		//return(1);
	}
	HMODULE hMod = GetModuleHandle(0);
	GetModuleFileName(hMod, path,sizeof(path)-1);
	HANDLE handle = CreateFile( path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);


	DBG("CALLING EXEWRAP %ws - %ws\n", argv[0], path);
	BY_HANDLE_FILE_INFORMATION bhf;
	if (GetFileInformationByHandle(handle, &bhf)) 
	{
		WCHAR redPath[2*MAX_PATH+8];
		DWORD bytesRead;
		DWORD offset = bhf.nFileSizeLow - sizeof(redPath);
		SetFilePointer(handle, offset, NULL, FILE_BEGIN);
		ReadFile(handle, redPath, sizeof(redPath), &bytesRead, NULL);

		WCHAR *p = redPath;
		if (!memcmp(p, L"ABCD", sizeof(WCHAR)*4))
		{
			WCHAR *procName = p+4;
			WCHAR *wrapperPath = p+8+MAX_PATH;
			DBG("WRAP %ws, wrapper=%ws\n", procName, wrapperPath);
			WCHAR ** newArgs = new WCHAR*[argc+4];
			newArgs[0] = wrapperPath;
			newArgs[1] = (wchar_t*) L"-exec";
			newArgs[2] = procName;
			int j=3;
			for(int a=1; a < argc; a++)
			{
				DBG("\tArg[%d]: %ws\n", j, argv[a]);
				newArgs[j++] = CheckArg(argv[a]);
			}
			newArgs[j] = 0;
			DBG("RERUN %ws -exec %ws\n", wrapperPath, procName);
			int sts = _wspawnv(_P_OVERLAY, newArgs[0], newArgs);
			return(sts);
			//fprintf(stderr, "ERROR: failed to wrap %ws\n", wrapperPath);
			//return(1);
#if 0
			//_wexecv((const wchar_t*) argv[0], (const wchar_t* const*)argv);
			PROCESS_INFORMATION pi;
			STARTUPINFO si;
			bool bOK = CreateProcess(
					0,
					procName,
					0,
					0,
					FALSE,
					0, // CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
					0,
					0,
					&si,
					&pi);
			if (!bOK)
				printf("FAILED to create proc: %ws\n", procName);
			else
				printf("started proc: %ws\n", procName);
#endif
		}
	}

	//printf("IN=%s, PROG=%s, myPID=%d\n", argv[0], prog, getpid());
	//argv[0] = prog;
	//spawnv(_P_WAIT, argv[0], argv);
	//printf("failed to exec %s\n", argv[0]);
	return(0);
}
