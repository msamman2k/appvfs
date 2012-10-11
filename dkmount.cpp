#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <tchar.h>
#include "globals.h"

BOOL
CreateMountPoint(
	LPCWSTR	MountPoint,
	LPCWSTR	DeviceName)
{
	HANDLE handle;
	PREPARSE_DATA_BUFFER reparseData;
	USHORT	bufferLength;
	USHORT	targetLength;
	BOOL	result;
	ULONG	resultLength;
	//WCHAR	targetDeviceName[MAX_PATH] =  L"\\\\?";
	WCHAR	targetDeviceName[MAX_PATH] =  L"\\??";


	wcscat(targetDeviceName, DeviceName);
	wcscat(targetDeviceName, L"\\");

	Logger::log(0, "Mount: %ws -> %ws\n", targetDeviceName, MountPoint);
	handle = CreateFile(
		MountPoint, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (handle == INVALID_HANDLE_VALUE) 
	{
		Logger::logWinError(GetLastError(), "CreateFile failed: %ws", MountPoint);
		return FALSE;
	}

	targetLength = wcslen(targetDeviceName) * sizeof(WCHAR);
	bufferLength = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) +
		targetLength + sizeof(WCHAR) + sizeof(WCHAR);

	reparseData = (PREPARSE_DATA_BUFFER) malloc(bufferLength);

	ZeroMemory(reparseData, bufferLength);

	reparseData->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	reparseData->ReparseDataLength = bufferLength - REPARSE_DATA_BUFFER_HEADER_SIZE;

	reparseData->MountPointReparseBuffer.SubstituteNameOffset = 0;
	reparseData->MountPointReparseBuffer.SubstituteNameLength = targetLength;
	reparseData->MountPointReparseBuffer.PrintNameOffset = targetLength + sizeof(WCHAR);
	reparseData->MountPointReparseBuffer.PrintNameLength = 0;

	RtlCopyMemory(reparseData->MountPointReparseBuffer.PathBuffer, targetDeviceName, targetLength);

	result = DeviceIoControl(
				handle,
				FSCTL_SET_REPARSE_POINT,
				reparseData,
				bufferLength,
				NULL,
				0,
				&resultLength,
				NULL);
	
	if (result) 
	{
		Logger::log(0,"CreateMountPoint %ws -> %ws success\n",
			MountPoint, targetDeviceName);
	}
	else
	{
		Logger::logWinError(GetLastError(), "CreateMountPoint %ws -> %ws failed", MountPoint, targetDeviceName);
	}
	CloseHandle(handle);
	free(reparseData);

	return result;
}

BOOL
DeleteMountPoint(
	LPCWSTR	MountPoint)
{
	HANDLE	handle;
	BOOL	result;
	ULONG	resultLength;
	REPARSE_GUID_DATA_BUFFER	reparseData = { 0 };

	handle = CreateFile(
		MountPoint, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (handle == INVALID_HANDLE_VALUE) 
	{
		Logger::logWinError(GetLastError(), "CreateFile failed: %ws", MountPoint);
		return FALSE;
	}

	reparseData.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;

	result = DeviceIoControl(
				handle,
				FSCTL_DELETE_REPARSE_POINT,
				&reparseData,
				REPARSE_GUID_DATA_BUFFER_HEADER_SIZE,
				NULL,
				0,
				&resultLength,
				NULL);
	
	CloseHandle(handle);

	if (result) 
		Logger::log(0,"DeleteMountPoint %ws success\n", MountPoint);
	else
		Logger::logWinError(GetLastError(), "DeleteMountPoint %ws failed", MountPoint);
	return result;
}

BOOL
CreateDriveLetter(
	WCHAR		DriveLetter,
	LPCWSTR	DeviceName)
{
	WCHAR   dosDevice[] = L"\\\\.\\C:";
	WCHAR   driveName[] = L"C:";
	WCHAR	rawDeviceName[MAX_PATH] = L"\\Device";
	HANDLE  device;

	dosDevice[4] = DriveLetter;
	driveName[0] = DriveLetter;
	wcscat(rawDeviceName, DeviceName);

	Logger::log(0,"DriveLetter: %wc, DeviceName %ws\n", DriveLetter, dosDevice);

	device = CreateFile(
		dosDevice,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
		);

    if (device != INVALID_HANDLE_VALUE) 
	{
		Logger::logWinError(ERROR_DEVICE_IN_USE, "DokanControl Mount failed for %wc", DriveLetter);
		CloseHandle(device);
        return FALSE;
    }

    if (!DefineDosDevice(DDD_RAW_TARGET_PATH, driveName, rawDeviceName))
	{
		Logger::logWinError(GetLastError(),"DokanControl DefineDosDevice failed");
        return FALSE;
    }

	device = CreateFile(
        dosDevice,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        NULL
        );

    if (device == INVALID_HANDLE_VALUE) 
	{
		Logger::logWinError(GetLastError(), "DokanControl Mount %wc failed", DriveLetter);
        DefineDosDevice(DDD_REMOVE_DEFINITION, dosDevice, NULL);
        return FALSE;
    }

	CloseHandle(device);
	return TRUE;
}

BOOL
DokanControlMount(
	LPCWSTR	MountPoint,
	LPCWSTR	DeviceName)
{
	ULONG length = wcslen(MountPoint);

	if (length == 1 ||
		(length == 2 && MountPoint[1] == L':') ||
		(length == 3 && MountPoint[1] == L':' && MountPoint[2] == L'\\')) {
		return CreateDriveLetter(MountPoint[0], DeviceName);
	} else if (length > 3) {
		return CreateMountPoint(MountPoint, DeviceName);
	}
	return FALSE; 
}

BOOL
DokanControlUnmount(
	LPCWSTR	MountPoint)
{
    
	ULONG	length = wcslen(MountPoint);

	if (length == 1 ||
		(length == 2 && MountPoint[1] == L':') ||
		(length == 3 && MountPoint[1] == L':' && MountPoint[2] == L'\\')) {

		WCHAR   drive[] = L"C:";	
	    drive[0] = MountPoint[0];

		if (!DefineDosDevice(DDD_REMOVE_DEFINITION, drive, NULL)) 
		{
			Logger::logWinError(GetLastError(), "DokanControl DefineDosDevice failed");
			//Logger::log(0,"DriveLetter %wc\n", MountPoint[0]);
			return FALSE;
		}
		else
		{
			Logger::log(0,"DokanControl DD_REMOVE_DEFINITION success\n");
			return TRUE;
		}

	} else if (length > 3 ) {
		return DeleteMountPoint(MountPoint);
	}

	return FALSE;
}

#ifdef MOUNTER_MAIN

int wmain(int argc, WCHAR *argv[])
{
	if (argc < 2)
	{
Usage:
		fprintf(stderr, "Usage: %ws -m mountPoint deviceName\n");
		fprintf(stderr, "Usage: %ws -u mountPoint\n");
		return(1);
	}

	if (!wcscmp(argv[1], L"-m"))
	{
		if (argc < 4)
			goto Usage;
		WCHAR* MountPoint = argv[2];
		WCHAR* DeviceName = argv[3];
		if (!DokanControlMount(MountPoint, DeviceName))
		{
			fprintf(stderr, "failed to mount\n");
			return(1);
		}
		else
			printf("Device mounted\n");
	}
	else if (!wcscmp(argv[1], L"-u"))
	{
		if (argc < 3)
			goto Usage;
		WCHAR* MountPoint = argv[2];
		if (!DokanControlUnmount(MountPoint))
		{
			fprintf(stderr, "failed to unmount\n");
			return(1);
		}
		else
			printf("Device unmounted\n");
	}
	else
		goto Usage;

	return(0);
}

#endif
