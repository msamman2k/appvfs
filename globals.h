#ifndef _INC_GLOBALS_H 
#define _INC_GLOBALS_H

#include <io.h>
#include <ctype.h>
#include <strings.h>
#include <wchar.h>
#include <tchar.h>
#include <fcntl.h>
#include <errno.h>

#define ERR_INDEXOUTOFRANGE	1
#define ERR_AESINIT			2
#define ERR_OPEN			3
#define ERR_FILEWRITE		4
#define ERR_FILESEEK		5

class FMTBuf
{
	public:
	char buf[1024];
	int len;
	FMTBuf()
	{
	}
	FMTBuf(const char *fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		len = vsprintf(buf, fmt, args);
		va_end(args);
	}

	int Format(const char *fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		len = vsprintf(buf, fmt, args);
		va_end(args);
		return(len);
	}

	operator char*()
	{
		return buf;
	}
};

class Exception
{
public:
	int code;
	char msg[1024];
	Exception(int _code, const char *fmt, ...)
	{
		code = _code;
		va_list args;
		va_start(args, fmt);
		vsprintf(msg, fmt, args);
		va_end(args);
	}
};

class CriticalSection
{
	private:
		CRITICAL_SECTION natMutex;
	public:
		CriticalSection()
		{
			memset(&natMutex, 0, sizeof(natMutex));
			InitializeCriticalSection(&natMutex);
		}
		void Lock()
		{
			EnterCriticalSection(&natMutex);
		}
		void Unlock()
		{
			LeaveCriticalSection(&natMutex);
		}
};

class WINSYSERR_T
	{
	const TCHAR* lpErrMsg;
	TCHAR* errBuf;
	DWORD LastErr;
	public:
	WINSYSERR_T(DWORD err)
		{
		LastErr  = err;
		errBuf   = 0;
		lpErrMsg = 0;
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
    				NULL, 
					err, 
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    				(TCHAR*) &errBuf, 
					0, NULL );
		if (errBuf)
			{
			errBuf[_tcslen(errBuf)-1] = 0;
			lpErrMsg = errBuf;
			}
		else
			lpErrMsg = _TEXT("unknown error");
		}

	operator TCHAR*()
	{
		return (TCHAR*) lpErrMsg; 
	}

	~WINSYSERR_T()
		{
		if (LastErr)
			SetLastError(LastErr);
		if (errBuf)
			LocalFree(errBuf);
		}

	TCHAR *ErrMsg()	{ return (TCHAR*) lpErrMsg; }
	DWORD ErrCode()	{ return LastErr;}
	};



class Logger
{
public:
	static char logFile[MAX_PATH];
	static int debugLevel;
	static int numErrors;
	static int logFD;
	static int log(int lev, const char *fmt, ...)
	{
		if (debugLevel < lev)
			return(0);
		va_list args;
		va_start(args, fmt);
		char out[1024];
		int ret = vsprintf(out, fmt, args);
		va_end(args);

		_write(logFD, out, ret);
		return(ret);
	}

	static int debugEx(const char *fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		char out[1024];
		int ret = vsprintf(out, fmt, args);
		va_end(args);

		_write(logFD, out, ret);
		return(ret);
	}

	static int logWinError(DWORD errCode, const char *fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		char out[1024];
		int len = sprintf(out, "ERROR: ", errCode);
		len = len + vsprintf(out+len, fmt, args);
		va_end(args);
		len += sprintf(out+len, " -- (%d) %ws\n", errCode, (TCHAR*)WINSYSERR_T(errCode));

		_write(logFD, out, len);
		++numErrors;
		return(len);
	}

	static int logError(const char *fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		char out[1024];
		strcpy(out, "ERROR: ");
		int len = strlen(out);
		len = len + vsprintf(out+len, fmt, args);
		va_end(args);

		_write(logFD, out, len);
		++numErrors;
		return(len);
	}

	static void InitLog(const char *fileName)
	{
		strcpy(logFile, fileName);
		int fd = _open(logFile, O_WRONLY|O_CREAT|O_TRUNC, 0666);
		if (fd != -1)
			logFD = fd;
		else
			printf("Failed to open log %s -- %s\n", fileName, strerror(errno));
		// unlink(g_logFile);
		// atexit(deleteLog);
	}
};

int Logger::debugLevel = 0;
int Logger::numErrors = 0;
int Logger::logFD = 2;
char Logger::logFile[MAX_PATH];


class MessagePipe
{
	HANDLE m_hPipe;
	char   m_pipeName[MAX_PATH];

	public:
		BOOL Create(const char *name)
		{
			sprintf(m_pipeName, "\\\\.\\pipe\\%s", name); 
			m_hPipe = ::CreateNamedPipeA(m_pipeName,
					PIPE_ACCESS_INBOUND, 
					PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 
					PIPE_UNLIMITED_INSTANCES, 
					8 * 1024, 
					64 * 1024,
 					NMPWAIT_USE_DEFAULT_WAIT, 
					NULL);
			if (m_hPipe == INVALID_HANDLE_VALUE)
			{
				Logger::logWinError(GetLastError(), "failed to create pipe %s", m_pipeName);
				return(FALSE);
			}
			return (TRUE);
		}

		BOOL Read(void *data, DWORD maxLen, DWORD *pDataLength)
		{
			BOOL  bOK = ::ConnectNamedPipe(m_hPipe, 0);
			DWORD error = GetLastError();

			if (bOK || error == ERROR_PIPE_CONNECTED)
			{
				*pDataLength = 0;
				if (!(::ReadFile(m_hPipe, data, maxLen, pDataLength, 0)))
				{
					error = GetLastError();
					bOK = FALSE;
					fprintf(stderr, "ERROR: failed read from pipe %d\n", error);
				}
				::DisconnectNamedPipe(m_hPipe);
			}
			else
			{
				fprintf(stderr, "ERROR: failed to connect pipe %d\n", error);
			}
		return(bOK);
		}

		static BOOL WriteTo(const char* name, void *data, DWORD maxLen, DWORD *pDataLength)
		{
			DWORD  error = NOERROR;
			HANDLE hPipe = INVALID_HANDLE_VALUE;
			char   pipeName[MAX_PATH];
			sprintf(pipeName, "\\\\.\\pipe\\%s", name); 
			while (true) 
			{ 
				hPipe = ::CreateFileA((LPSTR)pipeName, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
				if (hPipe != INVALID_HANDLE_VALUE)
					break;
				error = GetLastError();
					
				// If any error except the ERROR_PIPE_BUSY has occurred, we should return FALSE. 
				if (error != ERROR_PIPE_BUSY) 
				{
					Logger::logWinError(GetLastError(), "failed to access pipe %s", pipeName);
					return FALSE;
				}
				// The named pipe is busy. Let’s wait for 2 seconds. 
				if (!WaitNamedPipeA((LPSTR)pipeName, 2000)) 
				{ 
					error = GetLastError();
					Logger::logWinError(GetLastError(), "failed to wite on pipe %s", pipeName);
					return FALSE;
				} 
			} 
			*pDataLength = 0;
			if (!(WriteFile(hPipe, (LPVOID)data, maxLen, pDataLength, 0)))
			{
				Logger::logWinError(GetLastError(), "failed to write to pipe %s", pipeName);
				CloseHandle(hPipe);
				return FALSE;
			}
			CloseHandle(hPipe);
			return TRUE;
		}

		void Close()
		{
			if (m_hPipe)
				CloseHandle(m_hPipe);
			m_hPipe = 0;
		}
};




template <class T>
class DList
{
	T *i_entries;
	int i_numAlloced; 

public:
	int count;
	DList(int cnt=0)
	{
		i_entries = 0;
		i_numAlloced = 0;
		count = 0;
		Init(cnt);
	}

	bool Init(int cnt)
	{
		i_numAlloced = cnt;
		if (i_entries)
			free(i_entries);
		if (i_numAlloced)
			i_entries = (T*) malloc(sizeof(T) * i_numAlloced);
		else
			i_entries = 0;
		return(i_entries != 0);
	}

	~DList()
	{
		if (i_entries)
			free(i_entries);
		i_entries = 0;
	}

	inline T operator [](const int idx)
	{
		if (idx >= count)
			throw new Exception(ERR_INDEXOUTOFRANGE, "index out of range");
		return i_entries[idx];
	}

	void AddEntry(T ent)
	{
		if (count == i_numAlloced)
		{
			i_numAlloced += 8;
			i_entries = (T*) realloc(i_entries, sizeof(T) * i_numAlloced);
		}
		i_entries[count++] = ent;
	}

	void SetEntryAt(T ent, int idx)
	{
		if (idx >= i_numAlloced)
			throw new Exception(ERR_INDEXOUTOFRANGE, "index out of range");
		i_entries[idx] = ent;
	}

	typedef int (*t_sortFunc)(T *e1, T *e2);
	void Sort(t_sortFunc sortFunc)
	{
		typedef int (*t_comparator) (const void *, const void *); 
		qsort(i_entries, count, sizeof(T), (t_comparator)sortFunc);
	}

	inline int Count()
	{
		return(count);
	}

};

#define IsDirSep(c) ((c) == '/' || (c) == '\\')

struct RedirectEntry
{
	WCHAR m_srcPath[MAX_PATH];
	WCHAR m_desPath[MAX_PATH];
	int   m_srcLen;
	int   m_desLen;


	RedirectEntry(WCHAR* _srcPath, WCHAR* _desPath)
	{
		wcscpy(m_srcPath, Canonicalize(_srcPath));
		wcscpy(m_desPath, Canonicalize(_desPath));
		m_srcLen = wcslen(_srcPath);
		m_desLen = wcslen(_desPath);
		Logger::log(0, "ADD PATH MAP (%8.8x) %ws => %ws\n", this, m_srcPath, m_desPath);
	}
	
	inline bool Contains(LPCWSTR path)
	{
		LPCWSTR s = m_srcPath;
		LPCWSTR p = path;
		for(; *s && *p; ++s, ++p)
		{
			if (_totupper(*s) != _totupper(*p))
			{
				if (IsDirSep(*s) && IsDirSep(*p))
					continue;
				return(false);
			}
		}
		return (!*s);
	}

	static WCHAR* Canonicalize(WCHAR *path)
	{
		for(WCHAR* p=path; *p; ++p)
		{
			if (*p == '/' )
				*p = '\\';
		}
		return path;
	}

};


class RedirectorInfo
{
	DList<RedirectEntry*> i_mapList;
	public:

		RedirectorInfo()
		{
			i_mapList.Init(8);
		}

		int Count()
		{
			return i_mapList.count;
		}

		inline RedirectEntry* operator [](const int idx)
		{
			return i_mapList[idx];
		}

		bool GetRedirectPath(LPCWSTR FileName, WCHAR* retPath, int PathLen)
		{
			for(int i=0; i < i_mapList.count; i++)
			{
				RedirectEntry*ent = i_mapList[i];
				if (ent->Contains(FileName))
				{
					wcsncpy(retPath, ent->m_desPath, ent->m_desLen);
					wcscpy(retPath+ent->m_desLen, FileName);
					return(true);
				}
			}

			return(false);
		}

		static int compareEntries(RedirectEntry **e1, RedirectEntry** e2)
		{
			int ret = (wcslen(e2[0]->m_srcPath) - wcslen(e1[0]->m_srcPath)); 	
			return(ret);
		}

		RedirectEntry* AddPathMap(WCHAR* _srcPath, WCHAR* _desPath)
		{
			RedirectEntry* ent = new RedirectEntry(_srcPath, _desPath);
			i_mapList.AddEntry(ent);
			// sort the entries by longest path so our Contains method works
			i_mapList.Sort(compareEntries);
			return(ent);
		}

		void List(const char *cmnt)
		{
			Logger::log(0, "%s\n", cmnt);
			for(int i=0; i < i_mapList.Count(); i++)
			{
				RedirectEntry* ent = i_mapList[i];
				Logger::log(0, "\tMapEntry #%d  %ws => %ws\n", i+1, ent->m_srcPath, ent->m_desPath);
			}
		}

		bool HasRedirects()
		{
			return (i_mapList.count != 0);
		}

};

#endif // _INC_GLOBALS_H
