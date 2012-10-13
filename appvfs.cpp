#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <io.h>
#include <process.h>
#include <tlhelp32.h>
#include <AccCtrl.h>
#include <AclAPI.h>


#include "dokan.h"

DWORD g_lookupCount;
DWORD g_lookupTime;
DWORD g_fetchTime;
DWORD g_readTime;
WCHAR g_ExeRedirectDir[MAX_PATH];

BOOL  g_archMode = true;
BOOL  g_dokanFailed = false;
static int g_dbgLevel = 0;
static bool g_readOnly = false;
#define SDBG0	Logger::debugEx
#define SDBG1	(g_dbgLevel>=1) && Logger::debugEx
#define SDBG2	(g_dbgLevel>=2) && Logger::debugEx
#define SDBG3	(g_dbgLevel>=3) && Logger::debugEx
#define SDBG4	(g_dbgLevel>=4) && Logger::debugEx
#define DErr(err)	((-1)*(err))

// static WCHAR RootDirectory[MAX_PATH] = L"C:";
static WCHAR g_ArchiveFile[MAX_PATH];
static WCHAR g_MountPoint[MAX_PATH];
static HANDLE g_hArchiveFile;
static bool g_wrapExe;

#include "fsmgr.cpp"
#define ArchiveEntry ReadFileData
static FSMgr g_archiveMgr;
static int g_logFD = 2;

#include "dkmount.cpp"

#define DbgReturn(error)	 (g_dbgLevel>2 || ((error) && (g_dbgLevel>1 || (error) == ERROR_ACCESS_DENIED)))
#define IsBadHandle(h) 		(!(h) || (h) == INVALID_HANDLE_VALUE)

#define XPRC(pDFI) 	((char*) ProcInfoBuf((pDFI)->ProcessId))

struct OSPROC
{
	DWORD pid;
	DWORD ppid;
	WCHAR exeFile[MAX_PATH];
	bool  added;
	OSPROC(DWORD _pid, DWORD _ppid, LPCWSTR  _exeFile)
	{
		this->pid = _pid;
		this->ppid = _ppid;
		this->added = false;
		if (!_exeFile)
			_exeFile = L"unknown";
		wcscpy(this->exeFile, _exeFile);
	}
};

#define op_CreateFile			1
#define op_CreateDirectory		2
#define op_OpenDirectory		3
#define op_CloseFile			4
#define op_Cleanup				5
#define op_ReadFile				6
#define op_WriteFile			7
#define op_FlushFileBuffers		8
#define op_GetFileInfo			9
#define op_FindFiles			10
#define op_DeleteFile			11
#define op_DeleteDirectory		12
#define op_MoveFile				13
#define op_LockFile				14
#define op_UnlockFile			15
#define op_SetEndOfFile			16
#define op_SetAllocationSize	17
#define op_SetFileAttributes	18
#define op_SetFileTime			19
#define op_GetFileSecurity		20
#define op_SetFileSecurity		21

#define MAX_OPS					22

struct OpData
{
	char name[64];
	int   id;
	DWORD totalCalls;
	DWORD totalRedirectCalls;
	DWORD totalExecTime;
	DWORD totalRedirectExecTime;

	OpData()
	{
		Reset();
	}

	OpData(int _id, const char *_name)
	{
		Reset(_id, _name);
	}

	void Reset(int _id, const char *_name)
	{
		id = _id;
		strcpy(name, _name);
		Reset();
	}

	void Reset()
	{
		totalCalls = totalRedirectCalls = totalExecTime = totalRedirectExecTime = 0;
	}

	void Add(OpData &opData)
	{
		totalCalls 			+= opData.totalCalls ;
		totalRedirectCalls 	+= opData.totalRedirectCalls ;
		totalExecTime 		+= opData.totalExecTime ;
		totalRedirectExecTime += opData.totalRedirectExecTime ;
	}

	int AppendHeader(char *out, int off=0)
	{
		int len = sprintf(out+off, "%-20s %10s %10s %10s %10s\n",
					"opName",
					"#Calls",
					"ExeTime",
					"#R-Calls",
					"R-ExeTime");
		len += sprintf(out+off+len, "%-20s %10s %10s %10s %10s\n",
					"-------",
					"-------",
					"--------",
					"--------",
					"--------");
		return(len);
	}
	
	int AppendLine(char *out, int off, const char  *line)
	{
		int len = sprintf(out+off, "%s\n", line);
		return(len);
	}

	int Append(char *out, int off)
	{
		int len = sprintf(out+off, "%-20s %10d %10d %10d %10d\n",
					name,
					totalCalls,
					totalExecTime,
					totalRedirectCalls,
					totalRedirectExecTime);
		return(len);
	}
};

static OpData OpInfo[MAX_OPS];

#define OpName(op)		OpInfo[(op)].name
#define InitOp(func)	OpInfo[op_##func].Reset(op_##func, #func)
void InitOps()
{
	OpInfo[0].Reset(0, "OVERALL:");
	InitOp(CreateFile);
	InitOp(CreateDirectory);
	InitOp(OpenDirectory);
	InitOp(LockFile);
	InitOp(UnlockFile);
	InitOp(CloseFile);
	InitOp(Cleanup);
	InitOp(ReadFile);
	InitOp(WriteFile);
	InitOp(FlushFileBuffers);
	InitOp(GetFileInfo);
	InitOp(FindFiles);
	InitOp(DeleteFile);
	InitOp(DeleteDirectory);
	InitOp(MoveFile);
	InitOp(SetEndOfFile);
	InitOp(SetAllocationSize);
	InitOp(SetFileAttributes);
	InitOp(SetFileTime);
	InitOp(GetFileSecurity);
	InitOp(SetFileSecurity);
};

struct ProcMgr
{
	DList<OSPROC*> i_procList;
	bool disabled;

	ProcMgr()
	{
		disabled = false;
		i_procList.Init(32);
		OSPROC *ourProc = FindProc(GetCurrentProcessId());
		AddProc(ourProc);
	}

	void AddProc(OSPROC *proc)
	{
		if (proc && !proc->added)
		{
			SDBG1("==== ADD NEW PROC %d (%ws)\n", proc->pid, proc->exeFile);
			proc->added = true;
			i_procList.AddEntry(proc);
		}
	}

	void AddProc(DWORD pid)
	{
		OSPROC *proc = FindProc(pid);
		if (proc)
			AddProc(proc);
	}

	OSPROC* FindProcEx(DWORD pid)
	{
		OSPROC *p = FindProc(pid);
		if (p) SDBG1("\tFound %ws(%d), added=%d\n", p->exeFile, p->pid, p->added);
		return(p);
	}

	OSPROC* FindProc(DWORD pid)
	{
		for(int i=0; i< i_procList.count; i++)
		{
			OSPROC *p = i_procList[i];
			if (p->pid == pid)
				return(p);
		}
		HANDLE i_hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		pe.th32ParentProcessID = 0;

		for(BOOL ok=Process32First(i_hSnap,&pe); ok; ok=Process32Next(i_hSnap,&pe))
		{
			if (pid == pe.th32ProcessID)
			{
				OSPROC *p = new OSPROC(pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
				CloseHandle( i_hSnap );
				return(p);
			}
		}
		CloseHandle( i_hSnap );
		return(0);
	}

	bool AllowProc(OSPROC *proc)
	{
		if (!wcscmp(proc->exeFile, L"csrss.exe") || !wcscmp(proc->exeFile, L"svchost.exe"))
			return(true);
		OSPROC *parent = FindProc(proc->ppid);
		if (!parent)
		{
			SDBG3("INFO: parent for %ws (ppid=%d) not found\n", proc->exeFile, proc->ppid);
			return(false);
		}
		if (AllowProc(parent))
		{
			if (!parent->added)
				AddProc(parent);
			return(true);
		}
		return(false);
	}

	bool AllowPID(int op, DWORD pid)
	{
		if (i_procList.count == 1 || disabled)
			return(true);
		OSPROC *newProc = FindProc(pid);
		if (newProc)
		{
			if (newProc->added)
				return(true);
			for(int i=0; i< i_procList.count; i++)
			{
				OSPROC *p = i_procList[i];
				if (newProc->ppid == p->pid)
				{
					AddProc(newProc);
					return(true);
				}
			}
			if (AllowProc(newProc))
			{
				AddProc(newProc);
				return(true);
			}
		//SDBG1("==== DENY(%s) pid=%d, ppid=%d (%ws)\n", OpName(op), newProc->pid, newProc->ppid, newProc->exeFile);
		if (!newProc->added)
			delete newProc;
		}
		//SDBG1("==== DENY(%s) proc pid=%d not found\n", OpName(op), pid);
		return(false);
	}

	void GetProcInfo(DWORD pid, char *buf)
	{
		OSPROC *p = FindProc(pid);
		if (p)
		{
			sprintf(buf, "[%d:%ws]", p->pid, p->exeFile);
			if (!p->added)
				delete p;
		}
		else
			sprintf(buf, "[%d:???]", p->pid);
	}

	void Refresh()
	{
	}

} g_procMgr;

struct ProcInfoBuf
{
	char buf[256];
	ProcInfoBuf(DWORD pid)
	{
		g_procMgr.GetProcInfo(pid, buf);
	}

	operator char*()
	{
		return buf;
	}
};


struct ExeWrapper
{
	BYTE *data;
	DWORD size;
	WCHAR exeWrapperPath[MAX_PATH];

	BOOL Init()
	{
		BY_HANDLE_FILE_INFORMATION bhf;

		GetModuleFileName(GetModuleHandle(0), exeWrapperPath,sizeof(exeWrapperPath)-1);
		WCHAR *p = wcsrchr(exeWrapperPath, L'\\');
		if (!p)
			p = exeWrapperPath;
		else
			++p;
		wcscpy(p, L"exewrap.exe");
		HANDLE handle = CreateFile( exeWrapperPath, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) 
		{
			Logger::logWinError(GetLastError(), "failed to open %ws", exeWrapperPath);
			return(false);
		}
		if (!GetFileInformationByHandle(handle, &bhf)) 
		{
			Logger::logWinError(GetLastError(), "failed to get exewrapper data %ws", exeWrapperPath);
			return(false);
		}
		size = bhf.nFileSizeLow;
		data = new BYTE[bhf.nFileSizeLow];
		DWORD bytesRead;
		if (!ReadFile(handle, data, bhf.nFileSizeLow, &bytesRead, NULL))
		{
			CloseHandle(handle);
			Logger::logWinError(GetLastError(), "failed to read exewrapper data %ws", exeWrapperPath);
			return(false);
		}
		CloseHandle(handle);
		return(true);
	}

	BYTE *CopyData( BYTE *addData, WORD addSize)
	{
		BYTE *newData = new BYTE[size + addSize];
		memcpy(newData, data, size);
		memcpy(newData+size, addData, addSize);
		return(newData);
	}

} g_exeWrapper;

struct FILE_CONTEXT
{
	HANDLE handle;
	ArchiveEntry *pze;

	FILE_CONTEXT(LPCWSTR _FileName, ArchiveEntry *_pze, HANDLE _handle=0)
	{
		this->pze = _pze;
		this->handle = _handle;
	}
};

ULONG64 AllocContext(PDOKAN_FILE_INFO pDFI, LPCWSTR _FileName, ArchiveEntry *_pze, HANDLE _handle=0)
{
#if 0
	if (pDFI->Context)
	{
		SDBG0("WARN: ctx %x in use %ws\n", pDFI->Context, _FileName);
	}
#endif
	FILE_CONTEXT* ctx = new FILE_CONTEXT(_FileName, _pze, _handle);
	return((ULONG64)ctx);
}


ULONG64 FreeContext(ULONG64 &ctxID)
{ 
	if (!ctxID)
		return(0);
	FILE_CONTEXT *ctx = (FILE_CONTEXT*)ctxID;
	if (ctx->handle)
	{
		CloseHandle(ctx->handle);	// if zipMode then the handle is for the tmp lock file
	}
	ctx->handle = 0;
	ctx->pze = 0;
	delete ctx;
	return(0);
}

ArchiveEntry* GetContextArchiveEntry(ULONG64 &ctxID)
{
	if (!ctxID)
		return(0);
	FILE_CONTEXT *ctx = (FILE_CONTEXT*)ctxID;
	return ctx->pze;
}

HANDLE GetContextHandle(ULONG64 &ctxID)
{
	if (!ctxID)
		return(0);
	FILE_CONTEXT *ctx = (FILE_CONTEXT*)ctxID;
	return ctx->handle;
}

void SetContextHandle(ULONG64 &ctxID, HANDLE handle)
{
	if (!ctxID)
		return;
	FILE_CONTEXT *ctx = (FILE_CONTEXT*)ctxID;
	ctx->handle = handle;
}

CriticalSection i_cs;

static RedirectorInfo g_redirector;
static DList<ArchiveEntry *> g_exeList;


class DBGCtx
{
	public:
	int				m_op;
	LPCWSTR 		m_FileName;
	ArchiveEntry 	*pze;
	bool 			redirect;
	DWORD 			startTime;
	PDOKAN_FILE_INFO m_pDFI;
	WCHAR filePath[MAX_PATH];


	inline DBGCtx(PDOKAN_FILE_INFO pDFI, int op, LPCWSTR FileName)
	{
		m_pDFI     = pDFI;
		m_op       = op;
		m_FileName = FileName;
		filePath[0] = 0;
		startTime = ::GetTickCount();
		i_cs.Lock();
		
		pze = 0;
		if (g_archMode)
		{
			if (m_pDFI->Context)
			{
				pze = GetContextArchiveEntry(m_pDFI->Context);
				FILE_CONTEXT *ctx = (FILE_CONTEXT*)m_pDFI->Context;
			}

			if (!pze)
			{
				DWORD delta = ::GetTickCount();
				pze = g_archiveMgr.GetEntry(FileName, &redirect);
				delta = ::GetTickCount() - delta;
				g_lookupTime += delta;
				++g_lookupCount;
				if (pze)
					redirect = pze->redirect;
			}
			else
				redirect = pze->redirect;
		}
		else
			redirect = false;
	}

	ArchiveEntry *GetExecutableEntry(ArchiveEntry *ent, bool bFetch=false)
	{
		if (!g_wrapExe)
			return(ent);
		for(int i=0; i< g_exeList.count; i++)
		{
			ArchiveEntry *e2 = g_exeList[i];
			if (!wcscmp(e2->path, ent->path))
				return e2;
		}
		struct WINFO
		{
			WCHAR sig1[4];
			WCHAR exePath[MAX_PATH];
			WCHAR sig2[4];
			WCHAR exeWrapPath[MAX_PATH];
		} winfo;

		memset(&winfo, 0, sizeof(winfo));
		wcsncpy(winfo.sig1, L"ABCD", 4);
		wcscpy(winfo.exePath, g_ExeRedirectDir);
		wcscat(winfo.exePath, ent->path);
		wcsncpy(winfo.sig2, L"WRAP", 4);
		wcscpy(winfo.exeWrapPath, g_exeWrapper.exeWrapperPath);
		RedirectEntry::Canonicalize(winfo.exePath);
		SDBG0("Clone %ws => %ws\n", ent->path, winfo.exePath);
		// delete old copy first
		DeleteFile(winfo.exePath);
		ArchiveEntry *ent2 = ent->Clone();
		BYTE *data = g_exeWrapper.CopyData( (BYTE*)&winfo, sizeof(winfo) );
		ent2->SetData( data, g_exeWrapper.size + sizeof(winfo));
		g_archiveMgr.Clone(&g_archiveMgr, ent, winfo.exePath);

		g_exeList.AddEntry(ent2);
		return(ent2);
	}

	inline void Fetch(ArchiveEntry *ent)
	{
		if (ent->IsExecutable())
		{
			ent = GetExecutableEntry(ent, true);
		}
		g_archiveMgr.Fetch(ent);
	}

	inline void GetInfo(ArchiveEntry *ent, BY_HANDLE_FILE_INFORMATION &ret, DWORD useVolumeSerialNumber)
	{
		if (ent->IsExecutable())
			ent = GetExecutableEntry(ent);
		ent->GetInfo(ret, useVolumeSerialNumber);
#if 0
		if (ent->IsExecutable())
			ret.dwFileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
			//ret.dwReserved0 = IO_REPARSE_TAG_SYMLINK;
#endif
	}

	inline void GetInfo(ArchiveEntry *ent, WIN32_FIND_DATA &ret, const TCHAR* useName=0, int addAttrs=0)
	{
		if (ent->IsExecutable())
			ent = GetExecutableEntry(ent);
		ent->GetInfo(ret, useName, addAttrs);
#if 0
		if (ent->IsExecutable())
		{
			ret.dwFileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
			ret.dwReserved0 = IO_REPARSE_TAG_MOUNT_POINT;
			//ret.dwReserved0 = IO_REPARSE_TAG_SYMLINK;
		}
#endif
	}

	inline BYTE* GetData(ArchiveEntry *ent)
	{
		if (g_wrapExe && ent->IsExecutable())
			ent = GetExecutableEntry(ent, true);
		else
		{
			DWORD delta = ::GetTickCount();
			Fetch(ent);
			delta = ::GetTickCount() - delta;
			g_fetchTime += delta;
		}
		return ent->GetData();
	}


	inline ~DBGCtx()
	{
		DWORD delta;
		if (redirect)
		{
			delta = ::GetTickCount() - startTime;
			OpInfo[m_op].totalRedirectCalls++;
			OpInfo[m_op].totalRedirectExecTime += delta;
		}
		else
		{
			delta = ::GetTickCount() - startTime;
			OpInfo[m_op].totalExecTime += delta;
			OpInfo[m_op].totalCalls++;
		}
		i_cs.Unlock();
	}

	inline DWORD GetFileError(LPCWSTR FileName)
	{
		bool red;
		ArchiveEntry*parent = g_archiveMgr.GetParentEntry(FileName, &red);
		return(parent?	ERROR_FILE_NOT_FOUND: ERROR_PATH_NOT_FOUND);
	}


	inline void GetFilePath(LPCWSTR FileName)
	{
		GetFilePath(filePath, MAX_PATH, FileName);
	}

	inline void GetFilePath( PWCHAR	_filePath, ULONG	numberOfElements, LPCWSTR FileName)
	{
		if (redirect)
		{
			g_redirector.GetRedirectPath(FileName, _filePath, MAX_PATH);
		}
		else
		{
#if 0
		RtlZeroMemory(_filePath, numberOfElements * sizeof(WCHAR));
		wcsncpy(_filePath, RootDirectory, wcslen(RootDirectory));
		wcsncat(_filePath, FileName, wcslen(FileName));
#endif
		SDBG0("======= ERROR: internal error\n");
		}
	}

	WCHAR* ToUnixPath(WCHAR* path)
	{
		for(WCHAR *p=path; *p; ++p)
			if (*p == L'\\')
				*p = L'/';
		return(path);
	}

	int SetReturn2(DWORD code, HANDLE handle, const char *fmt, ...)
	{
		char 		m_buf[1024];
		int 		m_bufLen;
		LPCWSTR fileName = pze? pze->path: m_FileName;
		FILE_CONTEXT *ctx = (FILE_CONTEXT*)m_pDFI->Context;

		m_bufLen = sprintf(m_buf, "%s::%s(%x) %ws ", redirect? "R-": "--", OpName(m_op), ctx, fileName);
		
		char extra[MAX_PATH];
		va_list args;
		va_start(args, fmt);
		vsprintf(extra, fmt, args);
		va_end(args);

		
		if (!code)
		{
			if (handle)
				m_bufLen += sprintf(m_buf+m_bufLen, "%s => OK (h=%x)\n", extra, handle);
			else
				m_bufLen += sprintf(m_buf+m_bufLen, "%s => OK\n", extra);
		}
		else
			m_bufLen += sprintf(m_buf+m_bufLen, "%s => ERROR(%d) %ws\n", extra, code, (TCHAR*)WINSYSERR_T(code));
		_write(g_logFD, m_buf, m_bufLen);
		if (redirect)
		 	SDBG3("  REDIRECT(%s) %ws ==> %ws\n", OpName(m_op), fileName, ToUnixPath(filePath));
		return DErr(code);
	}

	inline int SetReturn(DWORD code)
	{
		return DErr(code);
	}
};



BOOL EnablePriv(const TCHAR *privName)
{
    HANDLE hToken;
    LUID DebugValue;
    TOKEN_PRIVILEGES tkp;


    //
    // Retrieve a handle of the access token
    //
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
        SDBG0(0, "OpenProcessToken failed\n");
        return FALSE;
    	}

    //
    // Enable the privilege
    //
    if (!LookupPrivilegeValue(NULL, privName, &DebugValue))
		{
        SDBG0("LookupPrivilegeValue failed\n");
        return FALSE;
    	}

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = DebugValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken,
        		FALSE,
        		&tkp,
        		sizeof(TOKEN_PRIVILEGES),
        		(PTOKEN_PRIVILEGES) NULL,
        	(PDWORD) NULL))
	{
		Logger::logWinError(GetLastError(), "AdjustTokenPrivileges failed");
		return(FALSE);
	}
    //
    // The return value of AdjustTokenPrivileges can't be tested
    //
    if (GetLastError() != ERROR_SUCCESS)
	{
		Logger::logWinError(GetLastError(), "AdjustTokenPrivileges failed");
        return FALSE;
    }

    return TRUE;
}


class DokanAccessor
{
	WCHAR accountName[256];

public:
	operator WCHAR*()
	{
		return accountName;
	}

	DokanAccessor(PDOKAN_FILE_INFO	DokanFileInfo)
	{
		WCHAR domainName[256];
		accountName[0] = 0;

		HANDLE	handle;
		UCHAR buffer[1024];
		DWORD returnLength;
		DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
		DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
		PTOKEN_USER tokenUser;
		SID_NAME_USE snu;

		handle = DokanOpenRequestorToken(DokanFileInfo);
		if (handle == INVALID_HANDLE_VALUE) 
		{
			SDBG1("  DokanOpenRequestorToken failed\n");
			return;
		}

		if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer), &returnLength)) 
		{
			SDBG1("  GetTokenInformaiton failed: %d\n", GetLastError());
			CloseHandle(handle);
			return;
		}

		CloseHandle(handle);

		tokenUser = (PTOKEN_USER)buffer;
		if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName,
			&accountLength, domainName, &domainLength, &snu)) 
		{
			SDBG1("  LookupAccountSid failed: %d\n", GetLastError());
			return;
		}

		// SDBG1("  AccountName: %s, DomainName: %s\n", accountName, domainName);
	}
};


#define CheckAccess(dbgCtx) \
		do {\
			if (!g_procMgr.AllowPID(dbgCtx.m_op, dbgCtx.m_pDFI->ProcessId)) \
			{\
				error = ERROR_ACCESS_DENIED;\
				goto end;\
			}\
		} while(0)

#define CheckWriteAccess(dbgCtx) \
		do {\
			if (g_readOnly && !dbgCtx.redirect)\
			{\
				error = ERROR_ACCESS_DENIED;\
				goto end;\
			}\
		} while(0)

static int DOKAN_CALLBACK
AppVFS_LockFile(
	LPCWSTR				FileName,
	LONGLONG			ByteOffset,
	LONGLONG			Length,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE	handle;
	LARGE_INTEGER offset;
	LARGE_INTEGER length;

	handle = GetContextHandle(pDFI->Context);
	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);

	DBGCtx dbgCtx(pDFI, op_LockFile, FileName);

	if (g_archMode && !dbgCtx.redirect)
	{
		/*
		if (true)
		{
			error = ERROR_ACCESS_DENIED;
			goto endLockFile;
		}
		*/
#if 0
		if (IsBadHandle(handle))
		{
			char lockPath[MAX_PATH];
			dbgCtx.pze->Hash(lockPath, "c:/tmp/zfs/");
			handle = CreateFileA(
				lockPath,
				GENERIC_READ|GENERIC_WRITE,
				FILE_SHARE_READ|FILE_SHARE_WRITE,
				NULL,
				OPEN_ALWAYS,
				0,
				NULL);
			if (handle == INVALID_HANDLE_VALUE)
				error = GetLastError();
			else if (error == ERROR_ALREADY_EXISTS)
				error = NOERROR;
			else if (SetFilePointer(handle, dbgCtx.pze->Size(), 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
				error = GetLastError();
			else if (!SetEndOfFile(handle))
				error = GetLastError();
			SetContextHandle(pDFI->Context, handle);
		}
		if (!error && !LockFile(handle, offset.HighPart, offset.LowPart, length.HighPart, length.LowPart)) 
			error = GetLastError();
#endif
		goto endLockFile;
	}

	dbgCtx.GetFilePath(FileName);

	if (IsBadHandle(handle))
	{
		error = ERROR_INVALID_HANDLE;
	}
	else
	{
		if (!LockFile(handle, offset.HighPart, offset.LowPart, length.HighPart, length.LowPart)) 
			error = GetLastError();
	}

end:
endLockFile:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%x, off=%lld, len=%lld", handle, ByteOffset, Length);

	return dbgCtx.SetReturn(error);
}

static int DOKAN_CALLBACK
AppVFS_UnlockFile(
	LPCWSTR				FileName,
	LONGLONG			ByteOffset,
	LONGLONG			Length,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	LARGE_INTEGER	length;
	LARGE_INTEGER	offset;
	HANDLE handle = GetContextHandle(pDFI->Context);
	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);

	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	DBGCtx dbgCtx(pDFI, op_UnlockFile, FileName);

	if (g_archMode && !dbgCtx.redirect)
	{
#if 0
		ArchiveEntry *pze = dbgCtx.pze;
		handle = GetContextHandle(pDFI->Context);
		if (IsBadHandle(handle))
		{
			error = ERROR_INVALID_HANDLE;
			if (Length == -1)
				error = NOERROR;
		}
		else
		{
			if (!UnlockFile(handle, offset.HighPart, offset.LowPart, length.HighPart, length.LowPart)) 
				error = GetLastError();
		}
		//error = NOERROR;	// somehow UnlockFile is called without LockFile with certain CreateFile AccessMode flags
#endif
		goto endUnlockFile;
	}

	dbgCtx.GetFilePath(FileName);

	if (IsBadHandle(handle))
		error = ERROR_INVALID_HANDLE;

	else if (!UnlockFile(handle, offset.HighPart, offset.LowPart, length.HighPart, length.LowPart)) 
	{
			error = GetLastError();
	} 

	if (error == ERROR_NOT_LOCKED && dbgCtx.redirect)
		error = NOERROR;

end:
endUnlockFile:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%x, off=%lld, len=%lld", handle, ByteOffset, Length);

	return dbgCtx.SetReturn(error);
}
int DOKAN_CALLBACK
AppVFS_CreateFile(
	LPCWSTR					FileName,
	DWORD					AccessMode,
	DWORD					ShareMode,
	DWORD					CreationDisposition,
	DWORD					FlagsAndAttributes,
	PDOKAN_FILE_INFO		pDFI)
{


	HANDLE handle = 0;
	DWORD fileAttr;
	DWORD error = NOERROR;

	// if AccessMode & SYNCHRONIZE them must call AppVFS_LockFile
	DBGCtx dbgCtx(pDFI, op_CreateFile, FileName);


	if (CreationDisposition == CREATE_NEW || CreationDisposition == TRUNCATE_EXISTING ||
		(AccessMode & (GENERIC_WRITE|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES)))
		//(AccessMode & (GENERIC_WRITE)))
	{
		if (!dbgCtx.redirect)
			CheckWriteAccess(dbgCtx);
	}
	
	if (g_archMode && !dbgCtx.redirect)
	{
		ArchiveEntry *pze = dbgCtx.pze;
		if (!pze)
		{
			if (CreationDisposition == CREATE_ALWAYS)
				error = ERROR_ACCESS_DENIED;
			else
				error = dbgCtx.GetFileError(FileName);
		}
		/*
		else if (AccessMode & SYNCHRONIZE)
		{
			error = ERROR_ACCESS_DENIED;
			goto endCreateFile;
		}
		*/
		else
		{
			CheckAccess(dbgCtx);
			pDFI->Context = AllocContext(pDFI, FileName, pze, 0);
		}
		goto endCreateFile;
	}
	/*
	if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
		ShareMode = FILE_SHARE_WRITE;
	else if (ShareMode == 0)
		ShareMode = FILE_SHARE_READ;
	*/

	// When filePath is a directory, needs to change the flag so that the file can be opened.
	CheckAccess(dbgCtx);
	dbgCtx.GetFilePath(FileName);

	fileAttr = GetFileAttributes(dbgCtx.filePath);
	if (fileAttr && fileAttr & FILE_ATTRIBUTE_DIRECTORY) 
	{
		FlagsAndAttributes |= FILE_FLAG_BACKUP_SEMANTICS;
		//AccessMode = 0;
	}

	handle = CreateFile(
		dbgCtx.filePath,
		AccessMode,//GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
		ShareMode,
		NULL, // security attribute
		CreationDisposition,
		FlagsAndAttributes,// |FILE_FLAG_NO_BUFFERING,
		NULL); // template file handle

	if (handle == INVALID_HANDLE_VALUE) 
	{
		error = GetLastError();
	}
	else
	{
		// save the file handle in Context
		pDFI->Context = AllocContext(pDFI, FileName, dbgCtx.pze, handle);
	}


end:
endCreateFile:
	int ret;
	if (DbgReturn(error))
	{
		ret = dbgCtx.SetReturn2(error, handle, 
			"(a:%8.8x,d:%x,s:%x,f:%x, by: %s::%ws)", AccessMode, CreationDisposition, ShareMode, FlagsAndAttributes, XPRC(pDFI), (WCHAR*) DokanAccessor(pDFI));
	}
	else
		ret = dbgCtx.SetReturn(error);
	// SYNCHRONIZE 
#if 0
	if (ret == 0 && (AccessMode & SYNCHRONIZE))
	{
		AppVFS_LockFile(FileName, 0, -1, pDFI);
	}
#endif
	return(ret);
}


static int DOKAN_CALLBACK
AppVFS_CreateDirectory(
	LPCWSTR					FileName,
	PDOKAN_FILE_INFO		pDFI)
{
	DWORD error = NOERROR;
	bool redirect = false;

	DBGCtx dbgCtx(pDFI, op_CreateDirectory, FileName);
	CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		if (dbgCtx.pze)
			error = ERROR_ALREADY_EXISTS;
		else
			error = ERROR_ACCESS_DENIED;
		goto endCreateDir;
	}

	CheckWriteAccess(dbgCtx);
	dbgCtx.GetFilePath(FileName);

	if (!CreateDirectory(dbgCtx.filePath, NULL)) 
		error = GetLastError();
	else
		pDFI->Context = AllocContext(pDFI, FileName, dbgCtx.pze, 0);

end:
endCreateDir:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "");

	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_OpenDirectory(
	LPCWSTR					FileName,
	PDOKAN_FILE_INFO		pDFI)
{
	DWORD error = NOERROR;
	HANDLE handle = 0;
	DBGCtx dbgCtx(pDFI, op_OpenDirectory, FileName);
	CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		ArchiveEntry *pze = dbgCtx.pze;
		if (!pze)
			error = dbgCtx.GetFileError(FileName);

		else if (!pze->IsDirectory())
			error = ERROR_DIRECTORY;
		else
			pDFI->Context = AllocContext(pDFI, FileName, pze, 0);
		goto endOpenDir;
	}

	DWORD attr;

	dbgCtx.GetFilePath(FileName);

	attr = GetFileAttributes(dbgCtx.filePath);
	if (attr == INVALID_FILE_ATTRIBUTES) 
	{
		error = GetLastError();
	}
	else if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) 
	{
		error = ERROR_DIRECTORY;
	}
	else
	{
		handle = CreateFile(
			dbgCtx.filePath,
			0,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			NULL);

		if (handle == INVALID_HANDLE_VALUE) 
			error = GetLastError();
	}


	if (!error)
		pDFI->Context = AllocContext(pDFI, FileName, dbgCtx.pze, handle);

end:
endOpenDir:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, handle, "(by: %s)", XPRC(pDFI));

	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_CloseFile(
	LPCWSTR					FileName,
	PDOKAN_FILE_INFO		pDFI)
{

	DWORD error = NOERROR;
	DBGCtx dbgCtx(pDFI, op_CloseFile, FileName);
	HANDLE handle = GetContextHandle(pDFI->Context);

	if (g_archMode && !dbgCtx.redirect)
	{
		ArchiveEntry *pze = dbgCtx.pze;
		if (pDFI->Context) 
		{
			pDFI->Context = FreeContext(pDFI->Context);
		}
		goto endCloseFile;
	}

	if (pDFI->Context) 
	{
		error = ERROR_INVALID_CLEANER;
		pDFI->Context = FreeContext(pDFI->Context);
	}
	else
	{
		//SDBG1("Close: %s\n\tinvalid handle\n\n", dbgCtx.filePath);
		//error = ERROR_INVALID_HANDLE;
	}

end:
endCloseFile:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, handle, "(h=%lx)", handle);

	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_Cleanup(
	LPCWSTR					FileName,
	PDOKAN_FILE_INFO		pDFI)
{
	DWORD error = NOERROR;
	HANDLE handle = GetContextHandle(pDFI->Context);
	
	DBGCtx dbgCtx(pDFI, op_Cleanup, FileName);

	if (g_archMode && !dbgCtx.redirect)
	{
		ArchiveEntry *pze = dbgCtx.pze;
		if (pDFI->Context) 
		{
			pDFI->Context = FreeContext(pDFI->Context);
		}
		else
			error = ERROR_INVALID_HANDLE;
		goto endCleanup;
	}


	if (pDFI->Context) 
	{
		pDFI->Context = FreeContext(pDFI->Context);
		handle = 0;

		if (pDFI->DeleteOnClose) 
		{
			dbgCtx.GetFilePath(FileName);
			SDBG2("Cleanup DeleteOnClose isDir=%d, %ws\n", pDFI->IsDirectory, dbgCtx.filePath);
			if (pDFI->IsDirectory) 
			{
				if (!RemoveDirectory(dbgCtx.filePath)) 
				{
					error = GetLastError();
					if (error == ERROR_FILE_NOT_FOUND)
						error = NOERROR;
				}
			} 
			else
			{
				if (!DeleteFile(dbgCtx.filePath)) 
				{
					error = GetLastError();
					if (error == ERROR_FILE_NOT_FOUND)
						error = NOERROR;
				}
			}
		}
	}
	else
		error = ERROR_INVALID_HANDLE;

end:
endCleanup:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, handle, "(h=%lx)", handle);
	
	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_ReadFile(
	LPCWSTR				FileName,
	LPVOID				Buffer,
	DWORD				BufferLength,
	LPDWORD				pReadLength,
	LONGLONG			Offset,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE	handle = GetContextHandle(pDFI->Context);
	ULONG	offset = (ULONG)Offset;
	BOOL	opened = FALSE;

	DBGCtx dbgCtx(pDFI, op_ReadFile, FileName);
	//CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		ArchiveEntry *pze = dbgCtx.pze;
		if (!pze)
			error = ERROR_INVALID_HANDLE;
		else
		{
			BYTE* data = (BYTE*) dbgCtx.GetData(pze);
			if (Offset > pze->Size())
				error = ERROR_INVALID_DATA;
			else
			{
				data += Offset;
				DWORD avail = pze->Size() - offset;
				if (avail > BufferLength)
					avail = BufferLength;
				*pReadLength = avail;
				memcpy(Buffer, data, avail);
				goto endReadFile;
			}
		}
		goto endReadFile;
	}



	if (IsBadHandle(handle))
	{
		dbgCtx.GetFilePath(FileName);
		//SDBG2("\tinvalid handle, cleanuped?\n");
		handle = CreateFile( dbgCtx.filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) 
		{
			error = GetLastError();
			goto endReadFile;
		}
		opened = TRUE;
	}
	
	if (SetFilePointer(handle, offset, NULL, FILE_BEGIN) == 0xFFFFFFFF) 
		error = GetLastError();
	else if (!ReadFile(handle, Buffer, BufferLength, pReadLength,NULL)) 
		error = GetLastError();

	if (opened)
		CloseHandle(handle);

end:
endReadFile:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%lx, off=%lu, len=%d, retLen=%d) ", handle, offset, BufferLength, *pReadLength);

	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_WriteFile(
	LPCWSTR		FileName,
	LPCVOID		Buffer,
	DWORD		NumberOfBytesToWrite,
	LPDWORD		NumberOfBytesWritten,
	LONGLONG			Offset,
	PDOKAN_FILE_INFO	pDFI)
{

	HANDLE	handle = GetContextHandle(pDFI->Context);
	DWORD error = NOERROR;
	ULONG	offset = (ULONG)Offset;
	BOOL	opened = FALSE;

	DBGCtx dbgCtx(pDFI, op_WriteFile, FileName);

	//CheckAccess(dbgCtx);
	if (g_archMode && !dbgCtx.redirect)
	{
		error = ERROR_ACCESS_DENIED;
		goto endWriteFile;
	}

	CheckWriteAccess(dbgCtx);

	// reopen the file
	if (IsBadHandle(handle))
	{
		dbgCtx.GetFilePath(FileName);

		handle = CreateFile(
			dbgCtx.filePath,
			GENERIC_WRITE,
			FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);
		if (handle == INVALID_HANDLE_VALUE) 
		{
			error = GetLastError();
			goto endWriteFile;
		}
		opened = TRUE;
	}

	if (pDFI->WriteToEndOfFile) 
	{
		if (SetFilePointer(handle, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) 
			error = GetLastError();
	} 
	else if (SetFilePointer(handle, offset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) 
		error = GetLastError();

		
	if (!error && !WriteFile(handle, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, NULL)) 
	{
		error = GetLastError();
	}

	// close the file when it is reopened
	if (opened)
		CloseHandle(handle);

end:
endWriteFile:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%lx, off=%lu, len=%d, retLen=%d) ", handle, offset, NumberOfBytesToWrite, *NumberOfBytesWritten);

	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_FlushFileBuffers(
	LPCWSTR		FileName,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE	handle = GetContextHandle(pDFI->Context);

	DBGCtx dbgCtx(pDFI, op_FlushFileBuffers, FileName);

	if (g_archMode && !dbgCtx.redirect)
	{
		goto endFlushFile;
	}


	if (IsBadHandle(handle))
	{
		error = ERROR_INVALID_HANDLE;
		// error = NOERROR;
	}
	else if (!FlushFileBuffers(handle))
	{
		//SDBG2("\tflush error code = %d\n", GetLastError());
		error =  GetLastError();
	}

end:
endFlushFile:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "");
	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_GetFileInformation(
	LPCWSTR							FileName,
	LPBY_HANDLE_FILE_INFORMATION	pBHFI,
	PDOKAN_FILE_INFO				pDFI)
{
	DWORD error = NOERROR;
	BOOL	opened = FALSE;
	HANDLE	handle = GetContextHandle(pDFI->Context);
	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);

	DBGCtx dbgCtx(pDFI, op_GetFileInfo, FileName);

	//CheckAccess(dbgCtx);
	if (g_archMode && !dbgCtx.redirect)
	{
		pze = dbgCtx.pze;
		if(!pze)
			error = ERROR_INVALID_HANDLE;
		else
		{
			dbgCtx.GetInfo(pze, *pBHFI, 0x19831116);
		}
		//dbgCtx.GetFilePath(FileName);
		goto endGetFileInfo;
	}

	if (IsBadHandle(handle))
	{
		SDBG0("\tGetFileInformationByHandle internal error -- invalid handle\n");
		error = ERROR_INVALID_HANDLE;
		dbgCtx.GetFilePath(FileName);

		// If CreateDirectory returned FILE_ALREADY_EXISTS and 
		// it is called with FILE_OPEN_IF, that handle must be opened.
		handle = CreateFile(dbgCtx.filePath, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (handle == INVALID_HANDLE_VALUE)
		{
			error = GetLastError();
			goto endGetFileInfo;
		}
		else
			error = NOERROR;
		opened = TRUE;
	}

	if (!GetFileInformationByHandle(handle, pBHFI)) 
	{
		SDBG0("\tGetFileInformationByHandle failed: error = %d\n", GetLastError());

		// FileName is a root directory
		// in this case, FindFirstFile can't get directory information
		dbgCtx.GetFilePath(FileName);
		if (wcslen(FileName) == 1)
		{
			//SDBG1("\troot dir\n");
			pBHFI->dwFileAttributes = GetFileAttributes(dbgCtx.filePath);

		}
		else 
		{
			WIN32_FIND_DATAW find;
			ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
			handle = FindFirstFile(dbgCtx.filePath, &find);
			if (handle == INVALID_HANDLE_VALUE) 
			{
				error = GetLastError();
			}
			else
			{
				pBHFI->dwFileAttributes = find.dwFileAttributes;
				pBHFI->ftCreationTime = find.ftCreationTime;
				pBHFI->ftLastAccessTime = find.ftLastAccessTime;
				pBHFI->ftLastWriteTime = find.ftLastWriteTime;
				pBHFI->nFileSizeHigh = find.nFileSizeHigh;
				pBHFI->nFileSizeLow = find.nFileSizeLow;
				//SDBG1("\tFindFiles OK, file size = %d\n", find.nFileSizeLow);
				FindClose(handle);
			}
		}
	} 
	else
	{
		//SDBG1("\tGetFileInformationByHandle success, file size = %d\n", pBHFI->nFileSizeLow);
	}

	if (opened)
		CloseHandle(handle);

end:
endGetFileInfo:
	if (DbgReturn(error))
	{
		return dbgCtx.SetReturn2(error, 0, "(h=%x, pze=%x => iHigh=%u, iLow=%u, vol=%u)", 
				handle, pze, pBHFI->nFileIndexHigh, pBHFI->nFileIndexLow, pBHFI->dwVolumeSerialNumber);
	}
	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_FindFiles(
	LPCWSTR				FileName,
	PFillFindData		FillFindData, // function pointer
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE				hFind;
	WIN32_FIND_DATAW	findData;
	LPCWSTR				yenStar = L"\\*";
	int count = 0;

	DBGCtx dbgCtx(pDFI, op_FindFiles, FileName);

	CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		WIN32_FIND_DATAW	fd;
		ArchiveEntry *pze = dbgCtx.pze;
		if (!pze)
			error = dbgCtx.GetFileError(FileName);
		else if (pze->IsDirectory())
		{
			if (!g_archiveMgr.IsRoot(pze))
			{
				dbgCtx.GetInfo(pze, fd, _TEXT("."));
				FillFindData(&fd, pDFI);
				SDBG4("\t\tEntry: %ws\n", fd.cFileName);
				ArchiveEntry* parent = g_archiveMgr.GetParentOf(pze);
				if (parent)
				{
					dbgCtx.GetInfo(parent, fd, _TEXT(".."));
					FillFindData(&fd, pDFI);
					SDBG4("\t\tEntry: %ws\n", fd.cFileName);
				}
				else
				{
					HANDLE hRoot = FindFirstFile(g_MountPoint, &fd);
					if (hRoot == INVALID_HANDLE_VALUE) 
					{
						Logger::logWinError(GetLastError(), "failed to get root info");
					}
					else
					{
						CloseHandle(hRoot);
						wcscpy(fd.cFileName, _TEXT(".."));
						fd.dwFileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
						fd.dwReserved0 = IO_REPARSE_TAG_MOUNT_POINT;
						FillFindData(&fd, pDFI);
						SDBG4("\t\tEntry: %ws\n", fd.cFileName);
					}
				}
			}

			for(ArchiveEntry*c = g_archiveMgr.GetFirstChild(pze); c; c=g_archiveMgr.GetNextSibling(c))
			{
				dbgCtx.GetInfo(c, fd);
				SDBG4("\t\tEntry: %ws\n", fd.cFileName);
#if 0
				if (cze->redirect)
				{
					fd.dwFileAttributes  |= FILE_ATTRIBUTE_REPARSE_POINT;
					fd.dwReserved0 = IO_REPARSE_TAG_SYMLINK;
				}
#endif
				FillFindData(&fd, pDFI);
			}
		}
		else
		{
			dbgCtx.GetInfo(pze, fd);
		}
		goto endFindFiles;
	}



	dbgCtx.GetFilePath(FileName);

	wcscat(dbgCtx.filePath, yenStar);

	hFind = FindFirstFile(dbgCtx.filePath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) 
	{
		error = GetLastError();
		//SDBG1("\tinvalid file handle. Error is %u\n\n", GetLastError());
		goto endFindFiles;
	}

	SDBG4("\t\tFS: Entry: %ws\n", findData.cFileName);
	FillFindData(&findData, pDFI);
	count++;

	while (FindNextFile(hFind, &findData) != 0) 
	{
 		FillFindData(&findData, pDFI);
		SDBG4("\t\tFS: Entry: %ws\n", findData.cFileName);
		count++;
	}
	
	error = GetLastError();
	FindClose(hFind);

	if (error == ERROR_NO_MORE_FILES) 
		error = NOERROR;

	//SDBG1("\tFindFiles return %d entries in %ws\n\n", count, dbgCtx.filePath);
	
end:
endFindFiles:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "by: %s", XPRC(pDFI));

	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_DeleteFile(
	LPCWSTR				FileName,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE	handle = GetContextHandle(pDFI->Context);
	DBGCtx dbgCtx(pDFI, op_DeleteFile, FileName);
	CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		error = ERROR_ACCESS_DENIED;
		goto endDeleteFile;
	}

	dbgCtx.GetFilePath(FileName);

	if (!DeleteFile(dbgCtx.filePath)) 
		error = GetLastError();


end:
endDeleteFile:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%x)", handle);
	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_DeleteDirectory(
	LPCWSTR				FileName,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE	handle = GetContextHandle(pDFI->Context);
	HANDLE	hFind;
	WIN32_FIND_DATAW	findData;
	ULONG	fileLen;

	DBGCtx dbgCtx(pDFI, op_DeleteDirectory, FileName);
	CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		error = ERROR_ACCESS_DENIED;
		goto endDeleteDir;
	}


	dbgCtx.GetFilePath(FileName);

	WCHAR dirPath[MAX_PATH];
	wcscpy(dirPath, dbgCtx.filePath);
	fileLen = wcslen(dirPath);
	if (dirPath[fileLen-1] != L'\\') 
	{
		dirPath[fileLen++] = L'\\';
	}
	dirPath[fileLen] = L'*';
	dirPath[fileLen+1] = 0;

	hFind = FindFirstFile(dirPath, &findData);
	while (hFind != INVALID_HANDLE_VALUE) 
	{
		if (wcscmp(findData.cFileName, L"..") != 0 &&
			wcscmp(findData.cFileName, L".") != 0) 
		{
			FindClose(hFind);
			error = ERROR_DIR_NOT_EMPTY;
			goto endDeleteDir;
		}
		if (!FindNextFile(hFind, &findData))
			break;
	}

	error = GetLastError();
	FindClose(hFind);
	if (error == ERROR_NO_MORE_FILES) 
		error = NOERROR;
	else
	{
		DWORD dwAttrs = GetFileAttributes(dbgCtx.filePath);
		if (dwAttrs & FILE_ATTRIBUTE_READONLY)
			error = ERROR_ACCESS_DENIED;
		else if (!RemoveDirectory(dbgCtx.filePath)) 
			error = GetLastError();
		SDBG1("DELETE DIR %ws, error=%d, rdOnly=%s\n", dbgCtx.filePath, error, 
			(dwAttrs & FILE_ATTRIBUTE_READONLY)? "Y": "N");
	}

end:
endDeleteDir:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "");
	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_MoveFile(
	LPCWSTR				FileName, // existing file name
	LPCWSTR				NewFileName,
	BOOL				ReplaceIfExisting,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	WCHAR			newFilePath[MAX_PATH];
	BOOL			status;

	DBGCtx dbgCtx(pDFI, op_MoveFile, FileName);
	CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		error = ERROR_ACCESS_DENIED;
		goto endMoveFile;
	}


	dbgCtx.GetFilePath(FileName);
	dbgCtx.GetFilePath(newFilePath, MAX_PATH, NewFileName);

	if (pDFI->Context)
	{
		// should close? or rename at closing?
		pDFI->Context = FreeContext(pDFI->Context);
	}

	if (ReplaceIfExisting)
		status = MoveFileEx(dbgCtx.filePath, newFilePath, MOVEFILE_REPLACE_EXISTING);
	else
		status = MoveFile(dbgCtx.filePath, newFilePath);

	if (status == FALSE)
		error = GetLastError();

end:
endMoveFile:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "");
	return dbgCtx.SetReturn(error);
}



static int DOKAN_CALLBACK
AppVFS_SetEndOfFile(
	LPCWSTR				FileName,
	LONGLONG			ByteOffset,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	LARGE_INTEGER	offset;
	HANDLE handle = GetContextHandle(pDFI->Context);
	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);

	DBGCtx dbgCtx(pDFI, op_SetEndOfFile, FileName);

	if (g_archMode && !dbgCtx.redirect)
	{
		error = NOERROR;
		goto endSetFilePointer;
	}


	if (IsBadHandle(handle))
	{
		error = ERROR_INVALID_HANDLE;
	}
	else
	{
		offset.QuadPart = ByteOffset;
		if (!SetFilePointerEx(handle, offset, NULL, FILE_BEGIN)) 
			error = GetLastError();
		else if (!SetEndOfFile(handle)) 
			error = GetLastError();
	}

end:
endSetFilePointer:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%x, off=%lld)", handle, ByteOffset);

	return dbgCtx.SetReturn(error);
}

extern "C" BOOL WINAPI GetFileSizeEx(HANDLE , PLARGE_INTEGER);


static int DOKAN_CALLBACK
AppVFS_SetAllocationSize(
	LPCWSTR				FileName,
	LONGLONG			AllocSize,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE	handle = GetContextHandle(pDFI->Context);
	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);
	LARGE_INTEGER	fileSize;

	DBGCtx dbgCtx(pDFI, op_SetAllocationSize, FileName);
	if (g_archMode && !dbgCtx.redirect)
	{
		error = ERROR_ACCESS_DENIED;
		goto endSetAllocSize;
	}


	if (IsBadHandle(handle))
	{
		error = ERROR_INVALID_HANDLE;
	}
	else if (GetFileSizeEx(handle, &fileSize)) 
	{
		if (AllocSize < fileSize.QuadPart) 
		{
			fileSize.QuadPart = AllocSize;
			if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) 
			{
				SDBG1("\tSetAllocationSize: SetFilePointer eror: %d, offset = %I64d\n\n", GetLastError(), AllocSize);
				error = GetLastError();
			}
			
			else if (!SetEndOfFile(handle)) 
				error = GetLastError();
		}
	} 
	else
	{
		error = GetLastError();
	}

end:
endSetAllocSize:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "");

	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_SetFileAttributes(
	LPCWSTR				FileName,
	DWORD				FileAttributes,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;

	HANDLE	handle = GetContextHandle(pDFI->Context);
	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);
	
	DBGCtx dbgCtx(pDFI, op_SetFileAttributes, FileName);

	//CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		error = ERROR_ACCESS_DENIED;
		goto endSetFileAttr;
	}

	dbgCtx.GetFilePath(FileName);

	if (!SetFileAttributes(dbgCtx.filePath, FileAttributes))
		error = GetLastError();

end:
endSetFileAttr:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%x)", handle);

	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_SetFileTime(
	LPCWSTR				FileName,
	CONST FILETIME*		CreationTime,
	CONST FILETIME*		LastAccessTime,
	CONST FILETIME*		LastWriteTime,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE	handle = GetContextHandle(pDFI->Context);
	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);

	DBGCtx dbgCtx(pDFI, op_SetFileTime, FileName);

	//CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
		error = ERROR_ACCESS_DENIED;
		goto endSetFileTime;
	}

	if (IsBadHandle(handle))
	{
		error = ERROR_INVALID_HANDLE;
	}
	else if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) 
	{
		error = GetLastError();
	}

end:
endSetFileTime:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%x)", handle);
	return dbgCtx.SetReturn(error);
}



#include "mingw/winext.h"		// missing windows sec stuff from mingw
typedef BOOL (WINAPI *tCreateWellKnownSid)(
        WELL_KNOWN_SID_TYPE WellKnownSidType,
     	PSID DomainSid,
    	PSID pSid,
      	DWORD *cbSid);

static tCreateWellKnownSid pCreateWellKnownSid;

DWORD GetDefaultSecurity(
    PSECURITY_INFORMATION pSecInfo, 
    PSECURITY_DESCRIPTOR  psd,
    ULONG                 BufferLength,
    PULONG                LengthNeeded)
{
    SID_IDENTIFIER_AUTHORITY sid_auth_world = SECURITY_WORLD_SID_AUTHORITY;
    PSID everyone_sid = NULL, self_sid = NULL /*guest_sid = NULL*/;
    DWORD self_sid_size = SECURITY_MAX_SID_SIZE;
    EXPLICIT_ACCESS ea;
    PACL acl = NULL;
    PSECURITY_DESCRIPTOR desc = NULL;
	DWORD error = NOERROR;

    if (*pSecInfo & DACL_SECURITY_INFORMATION)
        SDBG0("      DACL_SECURITY_INFORMATION\n");
    if (*pSecInfo & GROUP_SECURITY_INFORMATION)
        SDBG0("      GROUP_SECURITY_INFORMATION\n");
    if (*pSecInfo & LABEL_SECURITY_INFORMATION)
        SDBG0("      LABEL_SECURITY_INFORMATION\n");
    if (*pSecInfo & OWNER_SECURITY_INFORMATION)
        SDBG0("      OWNER_SECURITY_INFORMATION\n");
    if (*pSecInfo & PROTECTED_DACL_SECURITY_INFORMATION)
        SDBG0("      PROTECTED_DACL_SECURITY_INFORMATION\n");
    if (*pSecInfo & PROTECTED_SACL_SECURITY_INFORMATION)
        SDBG0("      PROTECTED_SACL_SECURITY_INFORMATION\n");
    if (*pSecInfo & SACL_SECURITY_INFORMATION)
        SDBG0("      SACL_SECURITY_INFORMATION\n");
    if (*pSecInfo & UNPROTECTED_DACL_SECURITY_INFORMATION)
        SDBG0("      UNPROTECTED_DACL_SECURITY_INFORMATION\n");
    if (*pSecInfo & UNPROTECTED_SACL_SECURITY_INFORMATION)
        SDBG0("      UNPROTECTED_SACL_SECURITY_INFORMATION\n");
    
    /* TODO: return all access rights for everyone for now */
    
    /* get SID for Everyone group */
    if (!AllocateAndInitializeSid(&sid_auth_world, 1, SECURITY_WORLD_RID,
               0, 0, 0, 0, 0, 0, 0, &everyone_sid))
    {   
		error = GetLastError();
        SDBG0("   Could not allocate SID for Everyone\n");
        goto get_file_security_exit;
    }

    /* get SID for Guest account */
    /*
    if (!AllocateAndInitializeSid(&sid_auth_world, 1, DOMAIN_USER_RID_GUEST,
               0, 0, 0, 0, 0, 0, 0, &guest_sid))
    {
		error = GetLastError();
        SDBG0("   Could not allocate SID for Guest\n");
        goto get_file_security_exit;
    }
    */

    self_sid = LocalAlloc(LMEM_FIXED, self_sid_size);
    if (self_sid == NULL)
    {
		error = GetLastError();
        SDBG0("   Could not allocate SID for self\n");
        goto get_file_security_exit;
    }

    /* get SID for current account */
	if (!pCreateWellKnownSid)
	{
		HMODULE hLib = LoadLibrary(L"Advapi32.dll");
		PROC p = GetProcAddress(hLib, "CreateWellKnownSid");
		pCreateWellKnownSid = (tCreateWellKnownSid) p;
		FreeLibrary(hLib);
	}
    if (!pCreateWellKnownSid(WinSelfSid, NULL, self_sid, &self_sid_size))
    {
		error = GetLastError();
        SDBG0("   Could not create SID for self\n");
        goto get_file_security_exit;
    }

    /* Specify ACE with all rights for everyone */
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR) everyone_sid;

    /* add entry to the ACL */
    if (SetEntriesInAcl(1, &ea, NULL, &acl) != ERROR_SUCCESS)
    {
		error = GetLastError();
        SDBG0("   Could not add ACE to ACL\n");
        goto get_file_security_exit;
    }

    /* initialize the descriptor */
    desc = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!InitializeSecurityDescriptor(desc, SECURITY_DESCRIPTOR_REVISION))
    {
		error = GetLastError();
        SDBG0("   Could not initialize descriptor\n");
        goto get_file_security_exit;
    }

    /* set primary owner to Guest */
    if (*pSecInfo & OWNER_SECURITY_INFORMATION)
    {
        if (!SetSecurityDescriptorOwner(desc, self_sid, FALSE))
        {
			error = GetLastError();
            SDBG0("   Could not set descriptor owner\n");
            goto get_file_security_exit;
        }
    }

    /* set primary group to Everyone group */
    if (*pSecInfo & GROUP_SECURITY_INFORMATION)
    {
        if (!SetSecurityDescriptorGroup(desc, everyone_sid, FALSE))
        {
			error = GetLastError();
            SDBG0("   Could not set descriptor group\n");
            goto get_file_security_exit;
        }
    }

    /* add the ACL to the security descriptor */
    if (*pSecInfo & DACL_SECURITY_INFORMATION)
    {
       if (!SetSecurityDescriptorDacl(desc, TRUE, acl, FALSE))
       {
			error = GetLastError();
           SDBG0("   Could not set descriptor DACL\n");
           goto get_file_security_exit;
       }
    }

    *LengthNeeded = GetSecurityDescriptorLength(desc);

    if (BufferLength >= *LengthNeeded)
    {
        ZeroMemory(psd, BufferLength);
        CopyMemory(psd, desc, *LengthNeeded);
    }
    else
    {
		error = ERROR_INSUFFICIENT_BUFFER;
        SDBG0("   Length Needed: %u\n", *LengthNeeded);
    }

get_file_security_exit:
    
    if (desc)
        LocalFree(desc);
    if (acl)
        LocalFree(acl);
    /*
    if (guest_sid)
        FreeSid(guest_sid);
    */
    if (self_sid)
        FreeSid(self_sid);
    if (everyone_sid)
        FreeSid(everyone_sid);

    SDBG0("GetFileSecurity exit: %d\n", error);

    return error;
}


static int DOKAN_CALLBACK
AppVFS_GetFileSecurity(
	LPCWSTR					FileName,
	PSECURITY_INFORMATION	pSecInfo,
	PSECURITY_DESCRIPTOR	psd,
	ULONG				BufferLength,
	PULONG				LengthNeeded,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE handle = GetContextHandle(pDFI->Context);
	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);

	DBGCtx dbgCtx(pDFI, op_GetFileSecurity, FileName);
	CheckAccess(dbgCtx);

	if (g_archMode && !dbgCtx.redirect)
	{
#if 1
		WCHAR path[MAX_PATH];
		GetModuleFileName(GetModuleHandle(0), path, sizeof(path)-1);
		if (!GetFileSecurity(path, *pSecInfo, psd, BufferLength, LengthNeeded))
		{
			error = GetLastError();
		}
#else
		error = GetDefaultSecurity(pSecInfo, psd, BufferLength, LengthNeeded);
#endif
		goto endGetFileSec;
	}

	dbgCtx.GetFilePath(FileName);

	if (IsBadHandle(handle))
	{
		error = ERROR_INVALID_HANDLE;
	}
	else if (!GetFileSecurity(dbgCtx.filePath, *pSecInfo, psd, BufferLength, LengthNeeded))
	{
		error = GetLastError();
	}

end:
endGetFileSec:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%x, secInfo=0x%x, by: %s)", handle, *pSecInfo, XPRC(pDFI));
	return dbgCtx.SetReturn(error);
}


static int DOKAN_CALLBACK
AppVFS_SetFileSecurity(
	LPCWSTR					FileName,
	PSECURITY_INFORMATION	pSecInfo,
	PSECURITY_DESCRIPTOR	psd,
	ULONG				psdLength,
	PDOKAN_FILE_INFO	pDFI)
{
	DWORD error = NOERROR;
	HANDLE	handle = GetContextHandle(pDFI->Context);
	ArchiveEntry*pze = GetContextArchiveEntry(pDFI->Context);
	DBGCtx dbgCtx(pDFI, op_SetFileSecurity, FileName);

	CheckAccess(dbgCtx);
	if (g_archMode && !dbgCtx.redirect)
	{
		error = ERROR_ACCESS_DENIED;
		goto endSetFileSec;
	}

	if (IsBadHandle(handle))
	{
		error = ERROR_INVALID_HANDLE;
	}

	else if (!SetUserObjectSecurity(handle, pSecInfo, psd)) 
	{
		error = GetLastError();
	}
	
end:
endSetFileSec:
	if (DbgReturn(error))
		return dbgCtx.SetReturn2(error, 0, "(h=%x, secInfo=%d)", handle, *pSecInfo);
	return dbgCtx.SetReturn(error);
}

static int DOKAN_CALLBACK
AppVFS_GetVolumeInformation(
	LPWSTR		VolumeNameBuffer,
	DWORD		VolumeNameSize,
	LPDWORD		VolumeSerialNumber,
	LPDWORD		MaximumComponentLength,
	LPDWORD		FileSystemFlags,
	LPWSTR		FileSystemNameBuffer,
	DWORD		FileSystemNameSize,
	PDOKAN_FILE_INFO	pDFI)
{
	wcscpy(VolumeNameBuffer, L"DOKAN");
	*VolumeSerialNumber = 0x19831116;
	*MaximumComponentLength = 256;
	*FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | 
						FILE_CASE_PRESERVED_NAMES | 
						FILE_READ_ONLY_VOLUME |
						FILE_SUPPORTS_REMOTE_STORAGE |
						FILE_UNICODE_ON_DISK |
						FILE_PERSISTENT_ACLS |
						0;

#if 0
	*FileSystemFlags |= FILE_SUPPORTS_HARD_LINKS;
	*FileSystemFlags |= FILE_SUPPORTS_OPEN_BY_FILE_ID;
#endif
	*FileSystemFlags |= FILE_SUPPORTS_OBJECT_IDS;
	SDBG3("==> GetVolumeInformation: nameBufLen=%d\n", FileSystemNameSize);
	wcscpy(FileSystemNameBuffer, L"Dokan");

	return 0;
}


static int DOKAN_CALLBACK
AppVFS_Unmount(
	PDOKAN_FILE_INFO	pDFI)
{
	SDBG2("==> Unmount\n");
	return 0;
}


static void DOKAN_CALLBACK AppVFS_DebugPrint(const char *fmt, ...)
{
	if (g_dbgLevel < 5)
		return;

	va_list args;
	va_start(args, fmt);
	char out[1024];
	strcpy(out, "DOKAN: ");
	int len = strlen(out);
	int ret = len + vsprintf(out+len, fmt, args);
	va_end(args);

	_write(2, out, ret);
}

static bool g_mountReady;

extern "C" BOOL WINAPI GetVolumeNameForVolumeMountPoint(
  LPCTSTR lpszVolumeMountPoint,
  LPTSTR lpszVolumeName,
  DWORD cchBufferLength
);

extern "C" BOOL WINAPI SetVolumeMountPointW(
  LPCTSTR lpszVolumeMountPoint,
  LPCTSTR lpszVolumeName
);

extern "C" BOOL WINAPI DeleteVolumeMountPointW(LPCTSTR lpszVolumeMountPoint);

bool g_presist = false;

void ListVolumes()
{
	BOOL bFlag;
	TCHAR Buf[MAX_PATH];           // temporary buffer for volume name
	TCHAR Drive[] = TEXT("c:\\"); // template drive specifier
	TCHAR I;                      // generic loop counter
	
	for (I = TEXT('c'); I < TEXT('z');  I++ ) 
	{
    	// Stamp the drive for the appropriate letter.
    	Drive[0] = I;
    	bFlag = GetVolumeNameForVolumeMountPoint(
                Drive,     // input volume mount point or directory
                Buf,       // output volume name buffer
                MAX_PATH ); // size of volume name buffer

    	if (bFlag) 
     	{
      		SDBG2 ("The ID of drive \"%ws\" is \"%ws\"\n", Drive, Buf);
     	}
	}
}

static int DOKAN_CALLBACK AppVFS_SetupMountPoint(LPWSTR mountPoint, LPWSTR DeviceName)
{
	if (g_presist)
	{
		SDBG2("Mount %ws\n", mountPoint);
		WCHAR volumeName[MAX_PATH];
		memset(volumeName, 0, sizeof(volumeName));
		wcscpy(volumeName, L"\\\\?");
		wcscat(volumeName, DeviceName);
		wcscat(volumeName, L"\\");
		SDBG2("Mount %ws => %ws\n", mountPoint, volumeName);  
		if (!SetVolumeMountPointW(mountPoint, DeviceName))
		{
			Logger::logWinError(GetLastError(), "Failed to set volume mountp");
			return(1);
		}
		else
			SDBG2("Volume mountpoint OK\n");
	}
	else if (!DokanControlMount(g_MountPoint, DeviceName))
	{
		return(1);
	}
	//ListVolumes();

	return(0);
}

static int DOKAN_CALLBACK AppVFS_RemoveMountPoint(LPWSTR mountPoint)
{
	if (g_presist)
	{
		if (DeleteVolumeMountPointW(mountPoint))
		{
			Logger::logWinError(GetLastError(), "Failed to delete volume mountp");
		}
	}
	else
		DokanControlUnmount(mountPoint); 
}

static void DOKAN_CALLBACK AppVFS_MountReady(LPCWSTR deviceName, LPCWSTR mountPoint)
{
	WCHAR volumeName[MAX_PATH];
	wcscpy(volumeName, L"\\\\?");
	wcscat(volumeName, deviceName);
	SDBG2("MountPoint is ready: deviceName=%ws, p=%ws\n", deviceName, mountPoint);
	g_mountReady = true;
#if 0
	SDBG0("\t\tVolume=%ws\n", volumeName);
	WCHAR mountPoint2[MAX_PATH];
	wcscpy(mountPoint2, mountPoint);
	wcscat(mountPoint2, L"\\");
	// http://msdn.microsoft.com/en-us/library/windows/desktop/aa363904%28v=vs.85%29.aspx
	// To define a drive letter assignment that is persistent across boots and not a network share, use the SetVolumeMountPoint function. If the volume to be mounted already has a drive letter assigned to it, use the DeleteVolumeMountPoint function to remove the assignment.
	if (!GetVolumeNameForVolumeMountPoint(mountPoint, volumeName, MAX_PATH))
	{
		Logger::logWinError(GetLastError(), "failed to get volume for mount point");
	}
	
#endif
#if 1
	SDBG2("Enable kernel debug: %d\n", (g_dbgLevel >= 6));
	if (g_dbgLevel >= 6)
		DokanSetDebugMode(1);
	else
		DokanSetDebugMode(0);
#endif
}

struct ProcessCtx
{
	WCHAR* cmdLine;
	WCHAR* startDir;
};

DWORD WINAPI StartProgramThread( LPVOID lpParam )
{
	ProcessCtx* procCtx = (ProcessCtx*)lpParam;
	while( !g_mountReady && !g_dokanFailed)
		Sleep(100);
	if (g_dokanFailed)
		return(1);

	PROCESS_INFORMATION pi;
	STARTUPINFO si;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	//WCHAR* oldPath = _wgetenv(L"PATH");
	//SDBG0("PATH=%ws\n", oldPath);
	bool bOK = CreateProcess(
					0,
					procCtx->cmdLine,
					0,
					0,
					TRUE,
					CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
					0,
					procCtx->startDir,
					&si,
					&pi);
	if (!bOK)
	{
		Logger::logWinError(GetLastError(), "failed to create process");
		return(1);
	}
	SDBG1("started '%ws'\n", procCtx->cmdLine);
	SDBG1("started pid=%d\n", pi.dwProcessId);
	g_procMgr.AddProc(pi.dwProcessId);
	ResumeThread(pi.hThread);
	//WaitForSingleObject(pi.hProcess, INFINITE);



#if 0
	while( _taccess(exePath, R_OK) == -1 && !g_dokanFailed)
	{
		Sleep(100);
	}
	if (g_dokanFailed)
		return(1);
	intptr_t hProc = _wspawnl( _P_NOWAIT, exePath, L"A", 0 );
	SDBG0("Found file %ws, hProc=%x\n", exePath, hProc);
#endif
	return(0);
}

char* ProcessCmd(char *line, char *out)
{
	out[0] = 0;
	for(char *p=strtok(line, " \t\n\r"); p; p=strtok(NULL, " \t\n\r"))
	{
		char *cmd = p;
		//SDBG0("run cmd %s\n", cmd);
		if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "/h"))
		{
			strcpy(out, "Commands: \n"
					"\tset debug dbgLev      -- set debug level to 'dbgLev'\n"
					"\tstats                 -- show stats\n"
					"\treset                 -- reset stats\n"
					"\tredirect src des_dir  -- redirect source file/folder to des_dir\n");
		}
		else if (!strcmp(cmd, "set"))
		{
			char *var = strtok(0, " \t\n\r");
			char *val = strtok(0, " \t\n\r");
			g_dbgLevel = atoi(val);
			SDBG1("SET dbgLevel=%d\n", g_dbgLevel);
			return(out);
		}
		else if (!strcmp(cmd, "reset"))
		{
			SDBG1("RESET stats\n");
			for(int i=1; i< MAX_OPS; i++)
			{
				OpData &opData = OpInfo[i];
				opData.Reset();
			}
			g_lookupCount = g_lookupTime = g_fetchTime = 0;
			return(out);
		}
		else if (!strcmp(cmd, "redirect"))
		{
			char *srcPath = strtok(0, " \t\n\r");
			char *desPath = strtok(0, " \t\n\r");
			WCHAR wSrcPath[MAX_PATH];
			WCHAR wDesPath[MAX_PATH];
			mbstowcs(wSrcPath, srcPath, MAX_PATH);
			mbstowcs(wDesPath, desPath, MAX_PATH);

			SDBG3("REDIRECT %ws => %ws\n", wSrcPath, wDesPath);
			RedirectEntry *ent = g_redirector.AddPathMap(wSrcPath, wDesPath);
			g_archiveMgr.AddRedirect(g_redirector, ent);
		}
		else if (!strcmp(cmd, "stats"))
		{
			int len=0;
		
			OpData &overall = OpInfo[0];
			overall.Reset();
			len += overall.AppendHeader(out, len);
			for(int i=1; i< MAX_OPS; i++)
			{
				OpData &opData = OpInfo[i];
				int t = opData.totalCalls+ opData.totalRedirectCalls;
				if (!t)
					continue;
				len += opData.Append(out, len);
				overall.Add(opData);
			}
			len += overall.AppendLine(out, len, "----------------------------------------------------------------");
			len += overall.Append(out, len);
			sprintf(out+len, "\nOverall: LookupCnt=%ld, LookupTime=%ld, FetchTime=%ld\n",
				g_lookupCount,
				g_lookupTime, g_fetchTime);
		}
		else if (!strcmp(cmd, "quit"))
		{
			exit(0);
		}

	}
	return(out);
}

DWORD WINAPI ConsoleThread( LPVOID lpParam )
{

	MessagePipe pipe;
	pipe.Create("AppVFSPipe");
	char buf[1024];
	DWORD len;
	while(pipe.Read(buf, sizeof(buf), &len))
	{
		char *p = buf;
		char *pp = strchr(p, ':');
		if (!pp)
			continue;
		char *cmd = ++pp;
		DWORD pid = atoi(p);
		char res[8*1024];
		SDBG0("Got cmd %s\n", cmd);
		ProcessCmd(cmd, res);
		char clntPipeName[MAX_PATH];
		sprintf(clntPipeName, "AppVFSPipe_%d", pid);
		MessagePipe::WriteTo(clntPipeName, res, strlen(res), &len);
		memset(buf, 0, sizeof(buf));
	}
}

void StartConsoleThread()
{
	DWORD BgThreadID;
	HANDLE hBgThread = CreateThread( 
            0,                   	// default security attributes
            0,                      // use default stack size  
            ConsoleThread,       	// thread function name
            0,          		// argument to thread function 
            0,                      // use default creation flags 
            &BgThreadID);   		// returns the thread identifier 
}

void StartProgram(ProcessCtx *procCtx)
{
	DWORD BgThreadID;
	HANDLE hBgThread = CreateThread( 
            0,                   	// default security attributes
            0,                      // use default stack size  
            StartProgramThread,    	// thread function name
            procCtx,          		// argument to thread function 
            0,                      // use default creation flags 
            &BgThreadID);   		// returns the thread identifier 
}

void ShowUsage(WCHAR *prog)
{
	fprintf(stderr, "appvfs -a archive -m mountPoint [options]\n%s", 
		"  -a*rchive imageFIle     -- specify the VFS archive image file\n"
		"  -m*ountPoint folder     -- specify the VFS mount point/folder\n"
		"  -t*hreads n             -- set number of I/O service threads\n"
		"  -g debugLevel           -- set debug level (1-5)\n"
		"  -r*edirect src dest     -- redirect folder/file 'src' to 'dest' folder\n"
		"  -xdir executableDir     -- executable file directory\n"
		"  -e*xec 'commandLine'    -- start program commandline (must be quoted)\n"
		"                             example: -exec 'c:/myapp/myapp.exe arg1 arg2'\n"
		"     -s*tartDir path      -- specify startup directory (used with -exec option)\n"
		"  -h*elp                  -- for this help\n"
		"\nNotes:\n"
		"1. The VFS image will be mounted read-only. If your VFS contains files/folders\n"
		"   that require write access (e.g. log or db folders), then use the -redirect\n"
		"   option which instructs AppVFS to redirect I/O calls to the destination\n"
		"   folder. A copy of the sources will be made to the destination folder if not\n"
		"   found there. If you change the destination folder in subsequent runs then\n" 
		"   it is your responsibility to copy the old ones from the previous folders\n" 
		"2. The -xdir option will instruct appvfs to create a copy of the executables\n"
		"   and place them under the 'executableDir' which should be outside the.\n"
		"   mountpoint. This is currently needed if the programs executables use sockets.\n" 
		"3. Debug level values (-g opion)\n"
		"        1    -- show access denied errors only\n"
		"        2    -- show access errors only\n"
        "        3    -- show all I/O calls\n" 
        "        4    -- show all I/O calls with additional detail\n"
        "        5    -- show debug from Dokan DLL\n"
		);
}

int wmain(int argc, PWCHAR argv[])
{
	int status;
	bool bValidate = true;
	ProcessCtx procCtx;
	PDOKAN_OPERATIONS dokanOperations =
			(PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
	PDOKAN_OPTIONS dokanOptions =
			(PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));

	procCtx.cmdLine = 0;
	procCtx.startDir = 0;
	Logger::debugLevel = 1;
	InitOps();
	g_exeWrapper.Init();

	ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
	dokanOptions->Version = DOKAN_VERSION;
	dokanOptions->ThreadCount = 0; // use default

	#define OptIs(arg,opt)	(!_wcsnicmp(arg, L##opt, wcslen(arg)))

	int c;
	for (c = 1; c < argc; c++) 
	{
		WCHAR* arg = argv[c];
		if (OptIs(arg, "-archive"))
		{
			g_archMode = true;
			g_readOnly = true;
			wcscpy(g_ArchiveFile, argv[++c]);
		}
#if 0
		else if (OptIs(arg, L"-rootDIr"))
		{
			wcscpy(RootDirectory, argv[++c]);
			SDBG0("RootDirectory: %ls\n", RootDirectory);
			continue;
		}
#endif
		else if (OptIs(arg, "-mountOn"))
		{
			wcscpy(g_MountPoint, argv[++c]);
			dokanOptions->MountPoint = g_MountPoint;
		}
		else if (OptIs(arg, "-redirect"))
		{
			WCHAR *srcPath = argv[++c];
			WCHAR *desPath = argv[++c];
			printf("R srcPath=%ws, desPath=%ws\n", srcPath, desPath);
			g_redirector.AddPathMap(srcPath, desPath);
		}
#if 0
		else if (OptIs(arg, "-allowPID"))
		{
			DWORD pid = _wtoi(argv[++c]);
			g_procMgr.AddProc(pid);
		}
#endif
		else if (OptIs(arg, "-threads"))
		{
			dokanOptions->ThreadCount = (USHORT)_wtoi(argv[++c]);
		}
		else if (OptIs(arg, "-g"))
		{
			g_dbgLevel = _wtoi(argv[++c]);
		}
#if 0
		else if (OptIs(arg, "-network"))
		{
			dokanOptions->Options |= DOKAN_OPTION_NETWORK;
		}
#endif
		else if (OptIs(arg, "-removable"))
		{
			dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
		}
		else if (OptIs(arg, "-exec"))
		{
			procCtx.cmdLine = argv[++c];
		}
		else if (OptIs(arg, "-xdir"))
		{
			g_wrapExe = true;
			wcscpy(g_ExeRedirectDir, argv[++c]);
			int len = wcslen(g_ExeRedirectDir);
			RedirectEntry::Canonicalize(g_ExeRedirectDir);
			if (g_ExeRedirectDir[len-1] != L'\\')
			{
				g_ExeRedirectDir[len]   = L'\\';
				g_ExeRedirectDir[len+1] = 0;
			}
		}
		else if (OptIs(arg, "-startDir"))
		{
			procCtx.startDir = argv[++c];
		}
		else if (OptIs(arg, "-help"))
		{
			ShowUsage(argv[0]);
			return(1);
		}
		else
		{
			ShowUsage(argv[0]);
			return -1;
		}
	}
	
	if (!g_ArchiveFile[0] || !g_MountPoint[0])
	{
		ShowUsage(argv[0]);
		return(1);
	}

	SDBG1("Debug level: %d\n", g_dbgLevel);
	Logger::debugLevel = g_dbgLevel;
	StartConsoleThread();
	if (procCtx.cmdLine)
	{
		StartProgram(&procCtx);
	}
	if (g_archMode)
	{
		EnablePriv(SE_SECURITY_NAME);
		EnablePriv(SE_MANAGE_VOLUME_NAME);
		g_hArchiveFile = CreateFile(g_ArchiveFile, READ_CONTROL| ACCESS_SYSTEM_SECURITY , 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		SECURITY_INFORMATION	SecInfo = 0x0000001F;
		PSECURITY_DESCRIPTOR	psd = (SECURITY_DESCRIPTOR*) malloc(1024);
		DWORD d;
		DWORD error = NOERROR;
		if (!GetUserObjectSecurity(g_hArchiveFile, &SecInfo, psd, 1024, &d))
		{
			error = GetLastError();
		}
		SDBG2("hArchive = %x, secInfo=0x%8.8X, err=%d\n", g_hArchiveFile, SecInfo, error);
		SDBG2("Open archive %ws\n", g_ArchiveFile);
		if (!g_archiveMgr.Open(g_ArchiveFile, g_redirector, bValidate))
		{
			fprintf(stderr, "failed to open archive %ws\n", g_ArchiveFile);
			return(1);
		}

		SDBG2("hArchiveFile = %x\n", g_hArchiveFile);
		//g_archiveMgr.List();
	}
	
	if (g_dbgLevel >= 5)
	{
		dokanOptions->Options |= DOKAN_OPTION_DEBUG;
		dokanOptions->Options |= DOKAN_OPTION_STDERR;
	}

	//dokanOptions->Options |= DOKAN_OPTION_KEEP_ALIVE;
	//dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;

	ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
	dokanOperations->CreateFile = AppVFS_CreateFile;
	dokanOperations->OpenDirectory = AppVFS_OpenDirectory;
	dokanOperations->CreateDirectory = AppVFS_CreateDirectory;
	dokanOperations->Cleanup = AppVFS_Cleanup;
	dokanOperations->CloseFile = AppVFS_CloseFile;
	dokanOperations->ReadFile = AppVFS_ReadFile;
	dokanOperations->WriteFile = AppVFS_WriteFile;
	dokanOperations->FlushFileBuffers = AppVFS_FlushFileBuffers;
	dokanOperations->GetFileInformation = AppVFS_GetFileInformation;
	dokanOperations->FindFiles = AppVFS_FindFiles;
	dokanOperations->FindFilesWithPattern = NULL;
	dokanOperations->SetFileAttributes = AppVFS_SetFileAttributes;
	dokanOperations->SetFileTime = AppVFS_SetFileTime;
	dokanOperations->DeleteFile = AppVFS_DeleteFile;
	dokanOperations->DeleteDirectory = AppVFS_DeleteDirectory;
	dokanOperations->MoveFile = AppVFS_MoveFile;
	dokanOperations->SetEndOfFile = AppVFS_SetEndOfFile;
	dokanOperations->SetAllocationSize = AppVFS_SetAllocationSize;	
	dokanOperations->LockFile = AppVFS_LockFile;
	dokanOperations->UnlockFile = AppVFS_UnlockFile;
	dokanOperations->GetFileSecurity = AppVFS_GetFileSecurity;
	dokanOperations->SetFileSecurity = AppVFS_SetFileSecurity;
	dokanOperations->GetDiskFreeSpace = NULL;
	dokanOperations->GetVolumeInformation = AppVFS_GetVolumeInformation;
	dokanOperations->Unmount = AppVFS_Unmount;

#define CUSTOM_DOKAN_BUILD  // undef this if you don't have the custom built dokan lib
#ifdef CUSTOM_DOKAN_BUILD
	dokanOperations->DebugPrint = AppVFS_DebugPrint;
	dokanOperations->MountReady = AppVFS_MountReady;
	dokanOperations->SetupMountPoint = AppVFS_SetupMountPoint;
	dokanOperations->RemoveMountPoint = AppVFS_RemoveMountPoint;
#endif


	SDBG0("START DokanMain: %ws\n", dokanOptions->MountPoint);
	status = DokanMain(dokanOptions, dokanOperations);
	SDBG0("DokanMain status=%d\n", status);
	switch (status) 
	{
	case DOKAN_SUCCESS:
		fprintf(stderr, "Success\n");
		break;
	case DOKAN_ERROR:
		fprintf(stderr, "Error\n");
		break;
	case DOKAN_DRIVE_LETTER_ERROR:
		fprintf(stderr, "Bad Drive letter\n");
		break;
	case DOKAN_DRIVER_INSTALL_ERROR:
		fprintf(stderr, "Can't install driver\n");
		break;
	case DOKAN_START_ERROR:
		fprintf(stderr, "Driver something wrong\n");
		break;
	case DOKAN_MOUNT_ERROR:
		fprintf(stderr, "Can't assign a drive letter\n");
		break;
	case DOKAN_MOUNT_POINT_ERROR:
		fprintf(stderr, "Mount point error\n");
		break;
	default:
		fprintf(stderr, "Unknown error: %d\n", status);
		break;
	}

	free(dokanOptions);
	free(dokanOperations);
	fprintf(stderr, "DONE MAIN THREAD\n");
	g_dokanFailed = true;
	return (1);
}
