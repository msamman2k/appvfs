#include <stdio.h>
#include <windows.h>
#include "globals.h"


int main(int argc, char *argv[])
{
	char cmd[1024];

	if (argc < 2)
	{
		return(1);
	}
	DWORD pid = GetCurrentProcessId();

	sprintf(cmd, "%d:%s", pid, argv[1]);
	for(int i=2; i < argc; i++)
	{
		strcat(cmd, " ");
		strcat(cmd, argv[i]);
	}
	MessagePipe rcvPipe;
	char pipeName[1024];
	char res[8*1024];
	sprintf(pipeName, "AppVFSPipe_%d", pid);
	if (!rcvPipe.Create(pipeName))
		return(1);
	DWORD len;
	MessagePipe::WriteTo("AppVFSPipe", cmd, strlen(cmd), &len);
	if (rcvPipe.Read(res, sizeof(res), &len))
	{
		printf("%s\n----------\n", res);
	}

	return(0);
}

