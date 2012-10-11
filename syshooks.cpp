#include <windows.h>
#include <io.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "syshooks.h"

static int dbgLevel;
static int (*g_logger)(const char *fmt, ...);

#define DBG_ERR 0 && 
#define DBG1 (dbgLevel>= 1) && g_logger
#define DBG4 (dbgLevel>= 2) && g_logger

#define KERNEL32DLL "kernel32.dll"
#define MSVCRTDLL "msvcrt.dll"

static char g_origExtPath[MAX_PATH];
static char g_NewExePath[MAX_PATH];
static char *g_CommandLineA;
static WCHAR *g_CommandLineW;

void AddDllHooks(HMODULE hMod, bool cmdLineOnly);

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD)(ptr)+(DWORD)(addValue))

DWORD GetModuleBaseFromWin32sHMod(HMODULE hMod); // Prototype (defined below)

PROC WINAPI HookImportedFunction(
        HMODULE hFromModule,        // Module to intercept calls from
        PSTR    pszFunctionModule,  // Module to intercept calls to
        PSTR    pszFunctionName,    // Function to intercept calls to
        PROC    pfnNewProc          // New function (replaces old function)
        )
{
    PROC pfnOriginalProc;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    PIMAGE_THUNK_DATA pNameThunk;
	BOOL B;
	DWORD dwOld, dw;
//	DWORD *pdw1;

    if ( IsBadCodePtr(pfnNewProc) ) // Verify that a valid pfn was passed
	{
		DBG_ERR("BadCodePtr %x\n", pfnNewProc);
        return 0;
	}
    
    // First, verify the the module and function names passed to use are valid
    pfnOriginalProc = GetProcAddress( GetModuleHandle(pszFunctionModule),
                                      pszFunctionName );

/*	pdw1 = (DWORD*)pfnOriginalProc;
	pfnOriginalProc = (PROC)*pdw1;*/

    if ( !pfnOriginalProc )
	{
		DBG_ERR("Orig function '%s' not found in mod %s\n", pszFunctionName, pszFunctionModule);
        return 0;
	}
    
    if ( (GetVersion() & 0xC0000000) == 0x80000000 )
        pDosHeader = (PIMAGE_DOS_HEADER)GetModuleBaseFromWin32sHMod(hFromModule); // win32
    else
        pDosHeader = (PIMAGE_DOS_HEADER)hFromModule;            // other

    // Tests to make sure we're looking at a module image (the 'MZ' header)
    if ( IsBadReadPtr(pDosHeader, sizeof(IMAGE_DOS_HEADER)) )
        return 0;
    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
        return 0;

    // The MZ header has a pointer to the PE header
    pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);

    // More tests to make sure we're looking at a "PE" image
    if ( IsBadReadPtr(pNTHeader, sizeof(IMAGE_NT_HEADERS)) )
	{
		DBG_ERR("Invalide NTHeader\n");
        return 0;
	}
    if ( pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{
		DBG_ERR("Invalide NTHeader sig\n");
        return 0;
	}

    // We know have a valid pointer to the module's PE header.  Now go
    // get a pointer to its imports section
    pImportDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, pDosHeader, 
                            pNTHeader->OptionalHeader.
                            DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].
                            VirtualAddress);
                        
    // Bail out if the RVA of the imports section is 0 (it doesn't exist)
    if ( pImportDesc == (PIMAGE_IMPORT_DESCRIPTOR)pNTHeader )
	{
		DBG_ERR("Invalide import desc\n");
        return 0;
	}

    // Iterate through the array of imported module descriptors, looking
    // for the module whose name matches the pszFunctionModule parameter

	bool found = false;

TryNext:
    while ( pImportDesc->Name )
    {
        PSTR pszModName = MakePtr(PSTR, pDosHeader, pImportDesc->Name);
        
        if ( stricmp(pszModName, pszFunctionModule) == 0 )
            break;

        pImportDesc++;  // Advance to next imported module descriptor
    }
    
    if ( pImportDesc->Name == 0 )
	{
		if (found)
    		return pfnOriginalProc;
		DBG_ERR("No import desc name\n");
        return 0;
	}

    pThunk     = MakePtr(PIMAGE_THUNK_DATA, pDosHeader, pImportDesc->FirstThunk);
    pNameThunk = MakePtr(PIMAGE_THUNK_DATA, pDosHeader, pImportDesc->OriginalFirstThunk);

	while ( pThunk->u1.Function )
    {
		if ( (DWORD)pThunk->u1.Function == (DWORD)pfnOriginalProc )
        {
            // We found it!  Overwrite the original address with the
            // address of the interception function.  Return the original
            // address to the caller so that they can chain on to it.
            
			//Problem persists in winXP... Not required in win98..
			//DLL will simply unload if an unalowed byte was modified.
			if(IsBadWritePtr(&pThunk->u1.Function, 4))
			{
				B = VirtualProtect(&pThunk->u1.Function, 4, 
					PAGE_EXECUTE_READWRITE, &dwOld);
				pThunk->u1.Function = (DWORD)pfnNewProc;

				B = VirtualProtect(&pThunk->u1.Function, 4, 
					dwOld, &dw);
			}else
				pThunk->u1.Function = (DWORD)pfnNewProc;            			

			//pfnOriginalProc = (PROC)(DWORD)pdw1;
			found = true;
            // return pfnOriginalProc; // we could have multiple sections for the same import DLL
        }
        
        pThunk++;   // Advance to next imported function address
    }

#if 0
	while ( pNameThunk->u1.AddressOfData )
	{
		PIMAGE_IMPORT_BY_NAME pImp = MakePtr(PIMAGE_IMPORT_BY_NAME, pDosHeader, pNameThunk->u1.AddressOfData);
		DBG1(" +Hint=%5d, Name=%s\n", pImp->Hint, pImp->Name);
        pNameThunk++;   // Advance to next imported function address
	}
#endif
    
    pImportDesc++;  
    if ( pImportDesc->Name )
		goto TryNext;
	if (found)
    	return pfnOriginalProc;
	DBG_ERR("function '%s' not found in mod %s\n", pszFunctionName, pszFunctionModule);
    return 0;   // Function not found
}

typedef DWORD (__stdcall *XPROC)(DWORD);

// Converts an HMODULE under Win32s to a base address in memory
DWORD GetModuleBaseFromWin32sHMod(HMODULE hMod)
{
    XPROC ImteFromHModule, BaseAddrFromImte;
    HMODULE hModule;
    DWORD imte;
    
    hModule = GetModuleHandle("W32SKRNL.DLL");
    if( !hModule )
        return 0;
    
    ImteFromHModule = (XPROC)GetProcAddress(hModule, "_ImteFromHModule@4");
    if ( !ImteFromHModule )
        return 0;
    
    BaseAddrFromImte = (XPROC)GetProcAddress(hModule, "_BaseAddrFromImte@4");
    if ( !BaseAddrFromImte )
        return 0;

    imte = ImteFromHModule( (DWORD)hMod);
    if ( !imte )
        return 0;
    
    return BaseAddrFromImte(imte);
}
#define Hook(dllfuncname, proc) HookImportedFunction(GetModuleHandle(0), KERNEL32DLL, dllfuncname, (PROC)proc)
#define IfCantHook(returnV, cast, dllfuncname, proc) if( (returnV = (cast)Hook(dllfuncname, (PROC)proc))==0 )

class HOOKENT_T
{
	const char* i_funcName;
	PROC i_origProc;
	PROC i_currProc;
	public:
		HOOKENT_T(HMODULE hTargetMod, const char* pszModuleName, const char* pszFunctionName, PROC wrapperFunc)
		{
			HMODULE hMod = GetModuleHandle(pszModuleName);
			i_origProc = GetProcAddress(hMod, pszFunctionName);
			if (!i_origProc)
				DBG_ERR("ERROR: orig proc %s not found\n", pszFunctionName);
			i_funcName = pszFunctionName;
			i_currProc = HookImportedFunction(hTargetMod, (CHAR*) pszModuleName, (CHAR*) pszFunctionName, (PROC)wrapperFunc);
			if (HasHook())
				DBG1("Added hook %s:: %s\n", pszModuleName, pszFunctionName);
			else
				DBG_ERR("FAILED to add hook %s:: %s\n", pszModuleName, pszFunctionName);
		}

		bool HasHook()
		{
			return (i_currProc != 0);
		}

		PROC OrigFunction()
		{
			return i_origProc;
		}
};


#define cCreateFileA		0
#define cCreateFileW		1
#define c_open				2
#define c_close				3
#define c_read				4
#define c_write				5
#define c_fstati64			6
#define c_open_osfhandle 	7
#define c_filelengthi64		8
#define cLoadLibraryA		9

#define cFindFirstFileA		10
#define cFindFirstFileW		11

#define cFindNextFileA		12
#define cFindNextFileW		13
#define cFindClose			14
#define c_wopen				15
#define cGetCommandLineA	16
#define cGetCommandLineW	17

static HOOKENT_T* Hooks[32];



typedef int (__cdecl *t_prc)(...);
#define AddHook(hMod,modName,funcName)	Hooks[c##funcName] = new HOOKENT_T(hMod, modName, #funcName, (PROC) w##funcName);
//#define GetHook(funcName)	(t_##funcName) Hooks[c##funcName]->OrigFunction()
#define GetHook(funcName)	(t_prc) Hooks[c##funcName]->OrigFunction()

extern "C" {

HANDLE WINAPI wCreateFileA(
        LPCTSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
    	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
    	HANDLE hTemplateFile)
{
		DBG4("CreateFileA\n");
		t_prc proc = GetHook(CreateFileA);
		return (HANDLE) proc( lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


HANDLE WINAPI wCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
    )
{
		DBG4("CreateFileW\n");
		t_prc proc = GetHook(CreateFileW);
		return (HANDLE) proc( lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}



HANDLE WINAPI wFindFirstFileA( LPCTSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
		t_prc proc = GetHook(FindFirstFileA);
		HANDLE ret = (HANDLE) proc( lpFileName, lpFindFileData);
		DBG4("FindFirstFileA %s, h=%x\n", lpFileName, ret);
		return (ret);
}

HANDLE WINAPI wFindFirstFileW( LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
{
		t_prc proc = GetHook(FindFirstFileW);
		HANDLE ret = (HANDLE) proc( lpFileName, lpFindFileData);
		DBG4("FindFirstFileW %ws, h=%x\n", lpFileName, ret);
		return (ret);
}


BOOL WINAPI wFindNextFileA( HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
		t_prc proc = GetHook(FindNextFileA);
		BOOL ret = (BOOL) proc(hFindFile,  lpFindFileData);
		if (ret)
			DBG4("FindNextFileA: h=%x, ret=%d, file=%s\n", hFindFile, ret, lpFindFileData->cFileName);
		else
			DBG4("FindNextFileA: h=%x, ret=%d\n", hFindFile, ret);

		return(ret);
}

BOOL WINAPI wFindNextFileW( HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
		t_prc proc = GetHook(FindNextFileW);
		BOOL ret = (BOOL) proc(hFindFile,  lpFindFileData);
		if (ret)
			DBG4("FindNextFileW: h=%x, ret=%d, file=%ws\n", hFindFile, ret, lpFindFileData->cFileName);
		else
			DBG4("FindNextFileW: h=%x, ret=%d\n", hFindFile, ret);
		return(ret);
}

BOOL WINAPI wFindClose( HANDLE hFindFile)
{
		t_prc proc = GetHook(FindClose);
		BOOL ret = (BOOL) proc(hFindFile);
		DBG4("FindClose: h=%x, ret=%d\n", hFindFile, ret);
		return(ret);
}


int __cdecl w_open(const char * _Filename, int _Openflag, int _PermissionMode = 0)
{
		t_prc proc = (t_prc) GetHook(_open);
		int fd = proc( _Filename, _Openflag, _PermissionMode );
		if (fd != -1)
			DBG4("_open fd=%d, %s\n", fd, _Filename);
		return(fd);
}

int w_wopen( const wchar_t *_Filename, int _Openflag, int _PermissionMode)
{
		t_prc proc = (t_prc) GetHook(_wopen);
		int fd = proc( _Filename, _Openflag, _PermissionMode );
		if (fd != -1)
			DBG4("_wopen fd=%d, %ws\n", fd, _Filename);
		return(fd);
}

int __cdecl w_fstati64(int fd, struct _stati64 *st)
{
		t_prc proc = GetHook(_fstati64);
		int sts = proc(fd, st);
		DBG4("_fstati64 fd=%d, sts=%d\n", fd, sts);
		return sts;
}

int __cdecl w_close(int fd)
{
		DBG4("close fd=%d\n", fd);
		t_prc proc = GetHook(_close);
		return proc(fd);
}

int __cdecl w_read(int fd, void* buf, unsigned int cnt)
{
		DBG4("read fd=%d, cnt=%d\n", fd, cnt);
		t_prc proc = GetHook(_read);
		return proc(fd, buf, cnt);
}

int  __cdecl w_write(int fd, const void* buf, unsigned int cnt)
{
		DBG4("write fd=%d, cnt=%d\n", fd, cnt);
		t_prc proc = GetHook(_write);
		return proc(fd, buf, cnt);
}

int w_open_osfhandle ( intptr_t osfhandle, int flags  )
{
		DBG4("w_open_osfhandle\n");
		t_prc proc = GetHook(_open_osfhandle);
		return proc(osfhandle, flags );
}

__int64 __cdecl w_filelengthi64(int fd)
{
		DBG4("w_filelengthi64: fd=%d\n", fd);
		t_prc proc = GetHook(_filelengthi64);
		return (__int64) proc(fd );
}

HMODULE WINAPI wLoadLibraryA(LPCTSTR lpFileName)
{
		t_prc proc = GetHook(LoadLibraryA);
		HMODULE hMod = (HMODULE) proc(lpFileName);
		DBG4("wLoadLibraryA: hMod=%x %s\n", hMod, lpFileName);
		if (hMod)
			AddDllHooks(hMod, false);
		return(hMod);
}

LPSTR WINAPI wGetCommandLineA(VOID)
{
	t_prc proc = GetHook(GetCommandLineA);
	LPSTR ret = (LPSTR) proc();
	LPSTR origRet = ret;
	if (g_NewExePath[0])
	{
		if (!g_CommandLineA)
		{
			g_CommandLineA = new char[strlen(ret)+ strlen(g_NewExePath)];
			char *pRet = g_CommandLineA;
			char *pNewPath = g_NewExePath;

			*pRet = 0;
			char *p1=ret, *p2=g_origExtPath;

			for(; *p1 && *p2; ++p1, ++p2)
			{
				if (toupper(*p1) == toupper(*p2))
					*pRet++ = *pNewPath++;
				else
					break;
			}
			*pRet = 0;
			if (*pNewPath)
			{
				//DBG1("Append #%s#\n", pNewPath);
				strcat(g_CommandLineA, pNewPath);
			}
			if (*p1)
			{
				//DBG1("Append #%s#\n", p1);
				strcat(g_CommandLineA, p1);
			}
		}
		ret = g_CommandLineA;
	}
	//DBG1("GetCommandLineA: %s\n", origRet);
	DBG1("GetCommandLineA: %s\n", ret);
	return(ret);
}

LPWSTR WINAPI wGetCommandLineW(VOID)
{
	t_prc proc = GetHook(GetCommandLineW);
	LPWSTR ret = (LPWSTR) proc();
	DBG4("GetCommandLineW: %ws\n", ret);
	return(ret);
}

};



typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;


typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;


typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;


typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;


DWORD NTAPI LdrRegisterDllNotification(
  ULONG Flags,
  void* NotificationFunction,
  PVOID Context,
  PVOID *Cookie
);


VOID CALLBACK LdrDllNotification(
  ULONG NotificationReason,
  PLDR_DLL_NOTIFICATION_DATA NotificationData,
  PVOID Context)
{
	if (NotificationReason == 1 )
	{
		LDR_DLL_LOADED_NOTIFICATION_DATA ld = NotificationData->Loaded;
		HMODULE hMod = GetModuleHandleW(ld.FullDllName->Buffer);
		DBG1("LOADED %ws, hMod=%x\n", ld.FullDllName->Buffer, hMod);
		//AddDllHooks(hMod);
	}
}


void AddDllHooks(HMODULE hMod, bool cmdLineOnly)
{
	if (!cmdLineOnly)
	{
		AddHook(hMod, KERNEL32DLL, CreateFileA);
		AddHook(hMod, KERNEL32DLL, CreateFileW);

		AddHook(hMod, KERNEL32DLL, FindFirstFileA);
		AddHook(hMod, KERNEL32DLL, FindFirstFileW);

		AddHook(hMod, KERNEL32DLL, FindNextFileA);
		AddHook(hMod, KERNEL32DLL, FindNextFileW);
		AddHook(hMod, KERNEL32DLL, FindClose);

		AddHook(hMod, KERNEL32DLL, LoadLibraryA);

		AddHook(hMod, MSVCRTDLL, _open);
		AddHook(hMod, MSVCRTDLL, _wopen);
		AddHook(hMod, MSVCRTDLL, _close);
		AddHook(hMod, MSVCRTDLL, _read);
		AddHook(hMod, MSVCRTDLL, _write);
		AddHook(hMod, MSVCRTDLL, _fstati64);
		AddHook(hMod, MSVCRTDLL, _filelengthi64);
		AddHook(hMod, MSVCRTDLL, _open_osfhandle);
	}
	
	AddHook(hMod, KERNEL32DLL, GetCommandLineA);
	AddHook(hMod, KERNEL32DLL, GetCommandLineW);
}


void SysHooksReplaceCommandLine(char *origExePath, char *NewExePath)
{
	strcpy(g_origExtPath, origExePath);
	strcpy(g_NewExePath, NewExePath);
	for(char *p=g_NewExePath; *p; ++p)
	{
		if (*p == '/')
			*p = '\\';
	}
	DBG4("\nREPLACE %s with %s\n", g_origExtPath, g_NewExePath);
}

void initSystemHooks(BOOL cmdLineOnly, int dbgLev, int (*logger)(const char *fmt, ...))
{
	dbgLevel = dbgLev;
	g_logger = logger;
#ifndef RUBYDLL
#define RUBYDLL 0
#endif
	HMODULE hMod = GetModuleHandle(RUBYDLL);
	//AddDllHooks(GetModuleHandle(0), cmdLineOnle);
	AddDllHooks(hMod, cmdLineOnly);
#if 0
	hMod = LoadLibrary("ntdll.dll");
	typedef DWORD NTAPI (*PPRC)( ULONG Flags, PVOID NotificationFunction, PVOID Context, PVOID *Cookie);
	
	PPRC prc = (PPRC) GetProcAddress(hMod, "LdrRegisterDllNotification");
	void *cookie;
	DWORD sts = prc(
				0,
  				(void*) LdrDllNotification,
  				0, // PVOID Context,
  				&cookie);//     PVOID *Cookie
#endif
}
