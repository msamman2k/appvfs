#include <stdio.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <wchar.h>
#include <tchar.h>
#include "globals.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

#ifdef USE_REGEXP
#include <regex.h>
#endif


extern "C" {
WINBASEAPI BOOL WINAPI CreateHardLinkA(LPCSTR,LPCSTR,LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI CreateHardLinkW(LPCWSTR,LPCWSTR,LPSECURITY_ATTRIBUTES);
};

class FilterHelper
{

public:
	const WCHAR *m_fromExt;
	const WCHAR *m_toExt;
	const WCHAR *m_regExpStr;
	bool  		 m_builtIn;
	WCHAR m_helperApp[MAX_PATH];
	WCHAR* m_helperAppLoader;
#ifdef USE_REGEXP
	regex_t m_regExp;
#endif

	enum FilterAction { ActionKeep=1, ActionReplace=2, ActionExclude=3};
	FilterHelper(WCHAR *option, WCHAR *info, bool bExeclude=false)
	{
		const WCHAR *helperApp;
		WCHAR origFilter[MAX_PATH];

		wcscpy(origFilter, info);
		int sts;
		if (bExeclude)
		{
			m_regExpStr = wcstok(info, L": ");
			m_fromExt = L"*";
			m_toExt   = L"*";
			helperApp = L"@delete";
			m_helperAppLoader = 0; 
		}
		else
		{
			m_fromExt 	= wcstok(info, L"# ");
			m_toExt   	= wcstok(NULL, L"# ");
			m_regExpStr = wcstok(NULL, L"# ");
			helperApp   = wcstok(NULL, L"# ");
			m_helperAppLoader = wcstok(NULL, L"# ");
			if (m_helperAppLoader)
			{
				// in case the remaining chars have separators
				int offset = m_helperAppLoader - info;
				wcscpy(info+offset, origFilter+offset);
			}
		}
		Logger::log(0, "INFO: using filter %ws '%ws'\n", option, origFilter);
		m_builtIn   = false;


		if (!m_fromExt || !m_toExt || !helperApp || !m_regExpStr )
		{
			throw Exception(1, "invalid filter '%ws' syntax: must be .fromExt#.to_ext#regExp#FilterTool#ToolLoader", origFilter); 
		}
		if (*m_fromExt == L'*' && *m_toExt == L'*')
		{
			if (wcscmp(helperApp, L"@delete"))
				throw Exception(1, "invalid filter builtin specifiction: must be *#*#regExp#@delete"); 
			m_builtIn = true;
		}
		else if (*m_fromExt != L'.' || *m_toExt != L'.')
			throw Exception(1, "invalid filter '%ws' syntax: must be .fromExt#.to_ext#rregExp#FilterTool#ToolLoader", origFilter); 

#ifdef USE_REGEXP
		memset(&m_regExp, 0, sizeof(m_regExp));
		char tname[MAX_PATH];
		WideCharToMultiByte(CP_UTF8,0, m_regExpStr,-1, tname, MAX_PATH,0,0);
		if ((sts = regcomp(&m_regExp, tname, REG_EXTENDED)) != 0)
		{
			//regerror(sts, &re, errbuf, 1024);
			throw Exception(5, "invalid regexp -- %ws", m_regExpStr);
		}
#endif

		if (m_builtIn)
			return;

		if (_waccess(helperApp, R_OK) == -1)
			throw Exception(1, "can't access helper %ws", helperApp); 
		WCHAR fullPath[MAX_PATH];
		WCHAR *p;
		GetFullPathName(helperApp, MAX_PATH, m_helperApp, &p);
	}
	
	FilterAction GetAction(WCHAR* path, WCHAR *ext)
	{
		if (m_builtIn || (ext && !_wcsicmp(m_fromExt, ext)))
		{
#ifdef USE_REGEXP
			regmatch_t m;
			m.rm_so = m.rm_eo = -1;
			char tname[MAX_PATH];
			WideCharToMultiByte(CP_UTF8,0, path,-1, tname, MAX_PATH,0,0);
		 	int sts = regexec(&m_regExp, tname, (size_t) 1, &m, 0);
			//printf("\tCHECK %ws %ws (%d:%d) sts=%d\n", path, m_regExpStr, m.rm_so, m.rm_eo, sts);
        	if (sts || m.rm_so == m.rm_eo)
           	 	return(ActionKeep);
			if (m_builtIn)
			{
				return ActionExclude;
			}
#endif
			return ActionReplace;
		}
		return(ActionKeep);
	}
};

class MD5Wrapper
{
	unsigned char md5_hash[MD5_DIGEST_LENGTH];
	char md5_str[(MD5_DIGEST_LENGTH*2)+1];

	const char* hash( unsigned char* data, int len)
	{
		static char hexChar[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

		::MD5((unsigned char*) data, len, md5_hash);
		char *p = md5_str;
    	for(int i=0; i <MD5_DIGEST_LENGTH; i++)
		{
			*p++ = hexChar[ md5_hash[i] >> 4];
			*p++ = hexChar[ md5_hash[i] & 0xf];
		}
		*p = 0;
		return(md5_str);
	}


	public:
	MD5Wrapper(unsigned char *data, int len)
	{
		hash((unsigned char*) data, len);
	}

	MD5Wrapper(const char *data)
	{
		hash((unsigned char*) data, strlen(data));
	}
	MD5Wrapper(const wchar_t *data) 
	{
		hash((unsigned char*) data, wcslen(data)*sizeof(wchar_t));
	}

	operator char*()
	{
		return md5_str;
	}
};



#define FS_VERSION 1.0
#define FS_SIGNATURE	0xaabbaabb

#define F_ENCRYPRED	0x01

struct DBHeader
{
	char 	type[3];
	BYTE	flags;
	float 	version;
	DWORD   signature;
	BYTE	k1[16];
	DWORD   totalFiles;
	BYTE	k2[16];
	DWORD64 encStrTableSize;
	BYTE	k3[16];
	DWORD64 strTableSize;
	off64_t	hashTableOffset;
	off64_t	metadataOffset;
	off64_t	dataOffset;
	DWORD64 totalSize;
	BYTE	k4[64];
	BYTE	key[32];
	BYTE	iv[32];

	DBHeader()
	{
		memset(this, 0, sizeof(*this));
		type[0] = 'F'; type[1] = 'S'; type[2] = 'D';
		version = FS_VERSION;
		signature = FS_SIGNATURE;
	}

	void SetKey(BYTE* k, char *encKey, int from, int to)
	{
		for(int i=from; i <= to; ++i)
		{
			*k++ = encKey[i] - '0';
		}
	}

	bool IsEncrypted()
	{
		return ((flags & F_ENCRYPRED) != 0);
	}

	void SetKey(char *encKey)
	{
		SetKey(k4, encKey, 0,  15);
		SetKey(k1, encKey, 16, 31);
		SetKey(k2, encKey, 32, 47);
		SetKey(k3, encKey, 48, 63);
	}

	void GetKey(BYTE *k, char *encKey, int from, int to)
	{
		for(int i=from; i <= to; ++i)
		{
			encKey[i] = '0' + *k;
			++k;
		}
	}

	void GetKey(char *encKey)
	{
		GetKey(k4, encKey, 0,  15);
		GetKey(k1, encKey, 16, 31);
		GetKey(k2, encKey, 32, 47);
		GetKey(k3, encKey, 48, 63);
		encKey[64] = 0;
	}
};

#define FLAG_EXE	0x0001

struct FileData
{
	WORD     	lev;		// for visual debugging but not needed
	WORD     	fflags;		
	DWORD 		index;
	DWORD 		parentIndex;
	DWORD 		firstChildIndex;
	DWORD 		nextSiblingIndex;
	DWORD 		dwFileAttributes;
	FILETIME 	ftCreationTime;
	FILETIME 	ftLastAccessTime;
	FILETIME 	ftLastWriteTime;
	DWORD64 	size;
	DWORD64 	encSize;
	off64_t 	dataOffset;
	off64_t 	nameOffset;
#undef USE_HASHING
#ifdef USE_HASHING
	DWORD		h_hashIndex;
	DWORD		h_nextHashIndex;
#endif

	inline DWORD64 Size()
	{
		return size;
	}

	inline bool IsDirectory()
	{
		return ((dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
	}

	inline bool IsExecutable()
	{
		return (fflags & FLAG_EXE);
	}
};

struct WriteFileData: public FileData
{
	WCHAR   path[MAX_PATH];
	LPCWSTR rootDir;
	LPCWSTR tmpFile;
	bool  excluded;
	WriteFileData()
	{
		tmpFile = 0;
		rootDir = 0;
		path[0] = 0;
		excluded = false;
	}

	void SetPath(const WCHAR *_path)
	{
		path[0] = L'/';
		wcscpy(path+1, _path);
	}
};

struct ReadFileData
{
	LPCWSTR path;
	FileData* fd;
	BYTE *data;
	LPCWSTR name0;
	bool redirect;
	bool exclude;

	ReadFileData(FileData *_fd, LPCWSTR _path)
	{
		fd       = _fd;
		path     = _path;
		data     = 0;
		redirect = false;
		exclude = false;
		Init();
	}

	ReadFileData *Clone()
	{
		ReadFileData *ent = new ReadFileData(fd, path);
		*ent = *this;
		ent->fd = new FileData();
		*ent->fd = *fd;
		return(ent);
	}

	void Init()
	{
		LPCWSTR pLastSlash = 0;
		for(LPCWSTR p=path; *p; *p++)
		{
			if (*p == '/' && p[1])
				pLastSlash = p;
		}
		if (!pLastSlash)
			name0 = path;
		else
			name0 = pLastSlash+1;
	}

	bool IsDirectory()
	{
		return ((fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
	}

	inline bool IsExecutable()
	{
		return (fd->fflags & FLAG_EXE);
	}

	DWORD64 Size()
	{
		return fd->size;
	}

	void SetData(BYTE *value, DWORD size)
	{
		fd->size = size;
		data = value;
	}

	void SetData(BYTE *value)
	{
		data = value;
	}

	BYTE* GetData()
	{
		return data;
	}

	char* Hash(char* outPath, const char *prefix=0)
	{
		char tname[MAX_PATH];
		WideCharToMultiByte(CP_UTF8,0, this->path,-1, tname, MAX_PATH,0,0);
		if (prefix)
		{
			strcpy(outPath, prefix);
			strcat(outPath, (char*) MD5Wrapper(tname));
		}
		else
			strcpy(outPath, (char*) MD5Wrapper(tname));
		return outPath;
	}

	void GetInfo(BY_HANDLE_FILE_INFORMATION &ret, DWORD useVolumeSerialNumber)
	{
		ret.dwFileAttributes = fd->dwFileAttributes; // | FILE_ATTRIBUTE_READONLY;
		ret.ftCreationTime   = fd->ftCreationTime;
		ret.ftLastAccessTime = fd->ftLastAccessTime;
		ret.ftLastWriteTime  = fd->ftLastWriteTime;
		ret.nFileSizeHigh    = 0;
		ret.nFileSizeLow     = fd->size;
		ret.dwVolumeSerialNumber = 0;
		ret.nNumberOfLinks   = 1;
		ret.nFileIndexHigh   = 0;
		ret.nFileIndexLow    = fd->index-1;
		ret.dwVolumeSerialNumber = useVolumeSerialNumber;
	}

	void GetInfo(WIN32_FIND_DATA &ret, const TCHAR* useName=0, int addAttrs=0)
	{
		ret.dwFileAttributes = fd->dwFileAttributes | addAttrs; // | FILE_ATTRIBUTE_READONLY;
		ret.ftCreationTime   = fd->ftCreationTime;
		ret.ftLastAccessTime = fd->ftLastAccessTime;
		ret.ftLastWriteTime  = fd->ftLastWriteTime;
		ret.nFileSizeHigh    = 0;
		ret.nFileSizeLow     = fd->size;
		ret.dwReserved0      = 0;
		ret.dwReserved1      = 0;
		if (useName)
			_tcscpy(ret.cFileName, useName);
		else
		{
			_tcscpy(ret.cFileName, GetName());
		}
		ret.cAlternateFileName[0] = 0;

		// this is causing real performance issue and probably not needed
		//GetShortPathName(ret.cFileName, ret.cAlternateFileName, 
		//				sizeof(ret.cAlternateFileName) / sizeof(ret.cAlternateFileName[0]));

	}

	inline LPCWSTR GetName()
	{
		return(name0);
	}

};

class FileFilterMgr : public DList<FilterHelper*> 
{
	public:
		WCHAR m_tmpDir[MAX_PATH];
		DList<WCHAR*> m_tmpFiles;
		FileFilterMgr()
		{
			m_tmpDir[0] = 0;
		}

		~FileFilterMgr()
		{
			Cleanup();
		}

		void Init()
		{
			if (m_tmpDir[0])
				return;
			WCHAR *tmp = _wgetenv(L"TEMP");
			if (!tmp)
				tmp = _wgetenv(L"TMP");
			if (!tmp)
				throw Exception(1, "TEMP system variable is not set");
			if (_waccess(tmp, R_OK) == -1)
				throw Exception(1, "can't accesss TEMP directory %ws", tmp);
			wsprintf(m_tmpDir, L"%s/fsmgr%d", tmp, getpid());
			_wmkdir(m_tmpDir);
			wcscat(m_tmpDir, L"/");
		}

		void Cleanup()
		{
			for(int i=0; i< m_tmpFiles.Count(); i++)
			{
				WCHAR *tmpFile = m_tmpFiles[i];
				printf("Deleting %ws\n", tmpFile);
				DeleteFile(tmpFile);
				delete[] tmpFile;
			}
			_wrmdir(m_tmpDir);
		}

		bool ProcessFilter(WriteFileData *fd, WIN32_FIND_DATAW &findData)
		{
			WCHAR *curPath = fd->path+1;
			WCHAR *p = wcsrchr(curPath, L'.');
			for(int i=0; i< count; i++)
			{
				FilterHelper *helper = (*this)[i];
				FilterHelper::FilterAction act = helper->GetAction(curPath, p);

				if (act == FilterHelper::ActionExclude)
				{
					return(false);
				}
				if (act == FilterHelper::ActionReplace)
				{
					//printf("Replace: %ws\n", curPath);
					int off = p - curPath;
					WCHAR newPath[MAX_PATH];
					wcsncpy(newPath, curPath, off);
					wcscpy(newPath+off, helper->m_toExt);
					WCHAR cmd[MAX_PATH*3+3];
					WCHAR *pSlash = wcsrchr(newPath, L'/');
					if (!pSlash)
						pSlash = newPath;
					else
						++pSlash;
					if (helper->m_helperAppLoader)
						wsprintf(cmd, L"%s %s %s %ws/%ws", helper->m_helperAppLoader, helper->m_helperApp, curPath, m_tmpDir, pSlash);
					else
						wsprintf(cmd, L"%s %s %ws/%ws", helper->m_helperApp, curPath, m_tmpDir, pSlash);
					Logger::log(0, "Run %ws\n", cmd);
					int sts = _wsystem(cmd);
					// printf("Run: %ws : sts=%d\n", cmd, sts);
					if (sts != 0)
						throw Exception(0, "failed to generate %ws", newPath);
					else
					{
						WCHAR* tmpFile = new WCHAR[wcslen(m_tmpDir) + wcslen(pSlash)+1];
						wcscpy(tmpFile, m_tmpDir);
						wcscat(tmpFile, pSlash);
						WIN32_FIND_DATAW findData2;
						HANDLE hFindFile = FindFirstFile(tmpFile, &findData2);
						if (hFindFile == INVALID_HANDLE_VALUE)
						{
							throw Exception(0, "failed to generate %ws", tmpFile);
						}
						else
						{
							fd->SetPath(newPath);
							findData.nFileSizeHigh    = findData2.nFileSizeHigh;
							findData.nFileSizeLow     = findData2.nFileSizeLow;
							_tcscpy(findData.cFileName, findData2.cFileName);
							m_tmpFiles.AddEntry(tmpFile);
							fd->tmpFile = tmpFile;
							CloseHandle(hFindFile);
						}
					}
					break;
				}
			}
			return(true);
		}
};

FileFilterMgr g_filterMgr;

class FSMgr
{
	DList<FileData*> 	m_outFileList;
	DList<FileData*> 	m_inFileList;
	LPCWSTR				m_outFileName;
	int       		 	m_outFileFD;
	off64_t				m_outFilePos;
	DBHeader* 		 	m_pHdr; 
	BYTE* 				m_strTable;
	EVP_CIPHER_CTX 		m_encCipher;
	EVP_CIPHER_CTX 		m_decCipher;

	HANDLE 				m_hArchiveFile;
	HANDLE 				m_hArchiveMemMap;
	BYTE*				m_archiveBaseAddr;
	ReadFileData*		i_rootDir;
	bool				m_writingFiles;
	DWORD				m_totalFiles;
	DWORD				m_excludeCount;
	DWORD64				m_excludeSize;
	DWORD64				m_totalSize;
	DWORD64				m_includeSize;
#ifdef USE_HASHING
#	define InitialFNV  2166136261U
#	define FNVMultiple 16777619
#	define PRIME		997
	DWORD				*m_hashTable;
	DWORD				*m_hashCounts;


	/* Fowler / Noll / Vo (FNV) Hash */
	int HashString(const WCHAR *str)
	{
    	size_t hash = InitialFNV;
    	for(const WCHAR *p=str; *p; ++p)
    	{
			WCHAR c = *p;
			if (c == L'\\')
				c = L'/';
			else
				c = _totupper(c);
			hash = hash ^ (c);       	/* xor  the low 8 bits */
			hash = hash * FNVMultiple;  /* multiply by the magic number */
		}
    	return (hash % PRIME);
	}
#endif

	void HashEntry(WriteFileData* fd)
	{
#ifdef USE_HASHING
		int bucket = fd->h_hashIndex = HashString(fd->path);
		DWORD *list = m_hashTable+bucket;

		fd->h_nextHashIndex = 0;
		++m_hashCounts[bucket];
		if (!*list)
			*list = fd->index;
		else
		{
			FileData *item = m_outFileList[*list];
			while(item->h_nextHashIndex)
			{
				item = m_outFileList[item->h_nextHashIndex];
			}
			item->h_nextHashIndex = fd->index;
		}
#endif
	}
	
	void InitHash()
	{
#ifdef USE_HASHING
		m_hashTable  = new DWORD[PRIME];
		m_hashCounts = new DWORD[PRIME];
		memset(m_hashTable,  0, sizeof(DWORD)*PRIME);
		memset(m_hashCounts, 0, sizeof(DWORD)*PRIME);
#endif
	}

	void DumpHashInfo()
	{
#ifdef USE_HASHING
		DWORD *list = m_hashTable;
		for(int bucket=0; bucket < PRIME; ++bucket)
		{
			if (*list)
			{
				printf("HashBucket# %d: cnt=%d -- ", bucket, m_hashCounts[bucket]);
				DWORD index = m_hashTable[bucket];
				while(index)
				{
					WriteFileData *item = (WriteFileData*) m_outFileList[index];
					printf("%ws ", item->path);
					index=item->h_nextHashIndex;
				}
				printf("\n");
			}
			++list;
		}

#endif
	}

	WriteFileData* AddFileEntry(int lev, LPCWSTR path, LPCWSTR rootDir, WIN32_FIND_DATAW &findData, WriteFileData *parentFD)
	{
		WriteFileData *fd = new WriteFileData();
		memset(fd, 0, sizeof(*fd));
		fd->SetPath(path);
		PWCHAR p; 
		for(p=fd->path; *p; *p++)
		{
			if (*p == L'\\')
				*p = L'/';
		}

		m_totalSize += findData.nFileSizeLow;
		m_totalFiles += 1;
		if (g_filterMgr.Count())
		{
			if (!g_filterMgr.ProcessFilter(fd, findData))
			{
				if (!parentFD || !parentFD->excluded)
					printf("Exclude: %ws\n", fd->path);
				m_excludeSize += findData.nFileSizeLow;
				m_excludeCount += 1;
				fd->excluded = true;
				return(fd);
			}
		}

		m_includeSize += findData.nFileSizeLow; 

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
#ifndef USE_HASHING
			// *p++ = '/';
			// *p = 0;
#endif
		}
		else
		{
			if ( ((p - fd->path) > 4) && !wcsicmp(p-4, L".exe"))
				fd->fflags |= FLAG_EXE;
		}

		fd->lev              = lev;
		fd->rootDir          = rootDir;
		fd->index            = m_outFileList.Count();
		fd->parentIndex		 = parentFD? parentFD->index: 0;
		fd->firstChildIndex  = 0;
		fd->nextSiblingIndex = 0;
		fd->dwFileAttributes = findData.dwFileAttributes;
		fd->ftCreationTime   = findData.ftCreationTime;
		fd->ftLastAccessTime = findData.ftLastAccessTime;
		fd->ftLastWriteTime  = findData.ftLastWriteTime;
		fd->size             = findData.nFileSizeLow;
		fd->dataOffset		 = 0;
		fd->nameOffset       = 0;
		HashEntry(fd);
		m_outFileList.AddEntry(fd);
		return(fd);
	}

public:
	FSMgr()
	{
		m_writingFiles = false;
		m_excludeSize = 0;
		m_excludeCount = 0;
		m_totalSize = 0;
		m_includeSize = 0;
		m_totalFiles = 0;
	}
	~FSMgr()
	{
		if (m_writingFiles || Logger::numErrors)
		{
			Cleanup();
		}
	}
	void Cleanup()
	{
		if (m_outFileFD != -1)
			close(m_outFileFD);
		m_outFileFD = -1;
		if (m_outFileName)
		{
			printf("Deleting %ws\n", m_outFileName);
			DeleteFile(m_outFileName);
		}
	}

	bool AddDir(int lev, LPCWSTR fileName, LPCWSTR rootDir, WriteFileData *fdData)
	{
		DWORD error;
		WIN32_FIND_DATAW	findData;
		WCHAR pattern[MAX_PATH];
		WCHAR path[MAX_PATH];

		wcscpy(pattern, fileName);
		wcscat(pattern, L"\\*.*");
		HANDLE hFindFile  = FindFirstFile(pattern, &findData);

		// printf(">> l=%d ADD Dir %ws\n", lev, fileName);

		if (hFindFile == INVALID_HANDLE_VALUE)
		{
			throw Exception(ERR_OPEN, "file not found %ws", fileName);
			return(false);
		}

		FileData *last = 0;
		do 
		{
			LPCWSTR cName = findData.cFileName;
			if (cName[0] == L'.' && (cName[1] == 0 || (cName[1] == L'.' && cName[2] == 0)))
			{
				continue;
			}
			wcscpy(path, fileName);
			wcscat(path, L"\\");
			wcscat(path, cName);
			WriteFileData *fd = AddFile(lev+1, path, rootDir, fdData);
			if (fd && !fd->excluded)
			{
				if (last)
					last->nextSiblingIndex  = fd->index;
				else
					fdData->firstChildIndex = fd->index;		
				last = fd;
			}
		}
		while (FindNextFile(hFindFile, &findData));


		error = GetLastError();
		FindClose(hFindFile);
		if (error == ERROR_NO_MORE_FILES) 
			error = NOERROR;
		return(error != NOERROR);
	}

	WriteFileData* AddFile(int lev, LPCWSTR fileName, LPCWSTR rootDir, WriteFileData *parentFD=0)
	{
		DWORD error;
		WIN32_FIND_DATAW	findData;
		HANDLE hFindFile;

		hFindFile  = FindFirstFile(fileName, &findData);


		if (hFindFile == INVALID_HANDLE_VALUE)
		{
			throw Exception(ERR_OPEN, "file not found %ws", fileName);
			return(0);
		}

		WriteFileData *fd = AddFileEntry(lev, fileName, rootDir, findData, parentFD);
		if (!fd)
		{
			return(fd);
		}

		do 
		{
			LPCWSTR cName = findData.cFileName;
			if (cName[0] == L'.' && (cName[1] == 0 || (cName[1] == L'.' && cName[2] == 0)))
			{
				continue;
			}

			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				AddDir(lev, fileName, rootDir, fd);
			}
			else
			{
				// printf(">> l=%d ADD File %ws\n", lev, fileName);
			}
		}
		while (FindNextFile(hFindFile, &findData));


		error = GetLastError();
		FindClose(hFindFile);
		if (error != ERROR_NO_MORE_FILES) 
			return(0);
		return(fd);
	}

	inline LPCWSTR ToUnixPath(PWCHAR path)
	{
		for(PWCHAR p=path; *p; ++p)
		{
			if (*p == L'\\')
				*p = L'/';
		}
		return(path);
	}


	void GetRelativePath(LPCWSTR fileName, PWCHAR relPath, PWCHAR parentDir)
	{
		PWCHAR p;
		GetFullPathName(fileName, MAX_PATH, relPath, &p);
		//wcscpy(relPath, fileName);
		for(p=relPath; *p; ++p)
		{
			if (*p == L'/')
				*p = L'\\';
		}

		// remove trailing slashes
		for(--p; *p == L'\\'; --p)		
			*p = 0;

		p = relPath;
		if (*p == L'.' && p[1] == '.' || p[1] == L':')
		{
			PWCHAR pp = wcsrchr(p, L'\\');
			int len = pp - p;
			++len;
			wcsncpy(parentDir, p, len);
			parentDir[len] = 0;
			wcscpy(relPath, ++pp);
		}
		else
		{
			wcscpy(parentDir, L".");
		}
	}

	/**
 	 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 	 * Fills in the encryption and decryption ctx objects and returns 0 on success
 	 **/
	bool aes_init(BYTE *key_data, int key_data_len, BYTE *salt)
	{
		int nrounds = 5;
  		BYTE key[32], iv[32];
  
  		/*
   		* Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   		* nrounds is the number of times the we hash the material. More rounds are more secure but
   		* slower.
   		*/
  		int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  		if (i != 32) 
  		{
   			 printf("Key size is %d bits - should be 256 bits\n", i);
   			 return(false);
  		}

  		EVP_CIPHER_CTX_init(&m_encCipher);
  		EVP_EncryptInit_ex(&m_encCipher, EVP_aes_256_cbc(), NULL, key, iv);
  		EVP_CIPHER_CTX_init(&m_decCipher);
  		EVP_DecryptInit_ex(&m_decCipher, EVP_aes_256_cbc(), NULL, key, iv);

  		return (true);
	}

	BYTE *aes_encrypt(BYTE *rawdata, int *pDataLen)
	{
  		/* max cipherdata len for a n bytes of rawdata is n + AES_BLOCK_SIZE -1 bytes */
  		int c_len = *pDataLen + AES_BLOCK_SIZE, f_len = 0;
  		BYTE *cipherdata = new BYTE[c_len];

  		/* allows reusing of 'e' for multiple encryption cycles */
  		EVP_EncryptInit_ex(&m_encCipher, NULL, NULL, NULL, NULL);

  		/* update cipherdata, c_len is filled with the length of cipherdata generated,
   		 *len is the size of rawdata in bytes */
  		EVP_EncryptUpdate(&m_encCipher, cipherdata, &c_len, rawdata, *pDataLen);

  		/* update cipherdata with the final remaining bytes */
  		EVP_EncryptFinal_ex(&m_encCipher, cipherdata+c_len, &f_len);

  		*pDataLen = c_len + f_len;
  		return cipherdata;
	}

	/*
 	* Decrypt *len bytes of cipherdata
 	*/
	BYTE *aes_decrypt(BYTE *cipherdata, int *pOrigDataLen)
	{
  		/* because we have padding ON, we must allocate an extra cipher block size of memory */
  		int p_len = *pOrigDataLen, f_len = 0;
  		BYTE *origData = new BYTE[p_len + AES_BLOCK_SIZE];
  
  		EVP_DecryptInit_ex (&m_decCipher, NULL, NULL, NULL, NULL);
  		EVP_DecryptUpdate  (&m_decCipher, origData, &p_len, cipherdata, *pOrigDataLen);
  		EVP_DecryptFinal_ex(&m_decCipher, origData+p_len, &f_len);

  		*pOrigDataLen = p_len + f_len;
  		return origData;
	}

	void EncryptInit(bool forWrite, const char *keyData=0)
	{
		if (forWrite)
		{
			if (keyData && *keyData)
			{
				/**
 	 			* Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 	 			* Fills in the encryption and decryption ctx objects and returns 0 on success
 	 			**/
				m_pHdr->flags |= F_ENCRYPRED;
  				/*
   				* Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   				* nrounds is the number of times the we hash the material. More rounds are more secure but
   				* slower.
   				*/
				const unsigned int salt[] = {12345, 54321};
				int nrounds = 5;
  				int nBytes = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), 
						(BYTE*) salt, (BYTE*) keyData, strlen(keyData), nrounds, m_pHdr->key, m_pHdr->iv);
  				if (nBytes != 32) 
  				{
   			 		printf("Key size is %d bits - should be 256 bits\n", nBytes);
  				}
			}
		}

		if (m_pHdr->IsEncrypted())
		{
  			EVP_CIPHER_CTX_init(&m_encCipher);
  			EVP_EncryptInit_ex(&m_encCipher, EVP_aes_256_cbc(), NULL, m_pHdr->key, m_pHdr->iv);
  			EVP_CIPHER_CTX_init(&m_decCipher);
  			EVP_DecryptInit_ex(&m_decCipher, EVP_aes_256_cbc(), NULL, m_pHdr->key, m_pHdr->iv);
		}
	}

	BYTE *Encrypt(BYTE *rawdata, int rawDataLen, int *pRetEncDataLen, bool validate=false)
	{
		*pRetEncDataLen= rawDataLen;
		BYTE* cipherData = aes_encrypt(rawdata, pRetEncDataLen);
		if (validate)
		{
			int decLen = *pRetEncDataLen;
			BYTE* origData   = (BYTE*) aes_decrypt(cipherData, &decLen);
			if (decLen !=  rawDataLen || memcmp(rawdata, origData, decLen))
			{
				printf("ENC/DEC failed\n");
			}
			delete[] origData;
		}
		return cipherData;
	}

	BYTE *Decrypt(BYTE *encData, int encDataSize, int *pRetOrigDataLen)
	{
		int decLen = encDataSize;
		BYTE* origData   = (BYTE*) aes_decrypt(encData, &decLen);
		*pRetOrigDataLen = decLen;
		return(origData);
	}


	int Align(DWORD size)
	{
		DWORD sig = FS_SIGNATURE;
		DWORD delta = size % sizeof(DWORD64);
		BYTE tmp[sizeof(DWORD64)];
		if (delta)
		{
			memset(tmp, 0, sizeof(tmp));
			Write(tmp, delta);
		}
		Write( &sig, sizeof(sig));
		delta += sizeof(sig);
		return(delta);
	}

	bool Write(void *buf, int size)
	{
		int b = _write(m_outFileFD, buf, size);
		if (b > 0)
		{
			m_outFilePos += b;
			return(true);
		}
		char *errMsg = strerror(errno);
		throw Exception(ERR_FILEWRITE, "error writing to '%ws' -- %s", m_outFileName, errMsg);
		return(false);
	}

	void Rewind()
	{
		Seek(SEEK_SET, 0);
	}

	off64_t Seek(int whence, off64_t pos)
	{
		off64_t res = lseek64(m_outFileFD, pos, whence);
		if (res == -1)
		{
			throw Exception(ERR_FILESEEK, "seek error to pos=%lld '%ws' -- %s", pos, m_outFileName, strerror(errno));
		}
		else
			m_outFilePos = res;
		return(res);
	}


	bool SaveData(char *keyData, PWCHAR outFile)
	{
		WriteFileData *fileData = (WriteFileData*) m_outFileList[1];
		DBHeader hdr;
		m_pHdr = &hdr;
		m_outFileName = outFile;
		bool validate = true;
		DWORD64 totalDataSize = 0;
		DWORD64 encTotalDataSize = 0;

		m_pHdr->totalFiles = m_outFileList.Count() - 1;
		EncryptInit(true, keyData);
		bool bOK = true;
		bool encrypt = m_pHdr->IsEncrypted();
		m_outFilePos = 0;
		m_outFileFD =  _wopen(outFile, O_RDWR | O_BINARY | O_CREAT | O_EXCL, 0666);
		if (m_outFileFD == -1)
		{
			throw Exception(ERR_OPEN, "can't open output file %ws -- %s", outFile, strerror(errno));
			return(false);
		}
		Write( &hdr, sizeof(hdr));
		// write the string table (file paths)
		WriteStringTable(validate);
		WriteHashTable();

		m_pHdr->metadataOffset = m_outFilePos;
		// seek pass metadata size 
		m_pHdr->dataOffset = Seek(SEEK_CUR, m_pHdr->totalFiles * sizeof(FileData)); 


		for (int i=1; i < m_outFileList.Count(); i++) 
		{
			WriteFileData *fileData = (WriteFileData*) m_outFileList[i];
			if (fileData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;
			if (!AppendFileData(fileData, validate))
			{
				bOK = false;
				break;
			}
		}

		Seek(SEEK_SET, m_pHdr->metadataOffset); 
		WriteFileMetadata();
		hdr.totalSize = Seek(SEEK_END, 0); 

		Rewind();
		Write(&hdr, sizeof(hdr));

		close(m_outFileFD);
		m_outFileFD = 0;
		return(bOK);
	}

	void WriteStringTable(bool validate)
	{
		DWORD64 nameOffset = 0;
		int strTableSize = 0;
		int encStrTableSize = 0;

		bool encrypt = m_pHdr->IsEncrypted();

		for (int i=1; i < m_outFileList.Count(); i++) 
		{
			WriteFileData *fileData = (WriteFileData*) m_outFileList[i];
			int len = sizeof(WCHAR) * (wcslen(fileData->path) + 1); // include null terminator
			if (!encrypt)
				Write( fileData->path, len);
			strTableSize += len;
			fileData->nameOffset = nameOffset;
			nameOffset += len;
		}

		if (!encrypt)
			Align(strTableSize);
		else
		{
			// printf("strTableSize = %d\n", strTableSize);
			BYTE* strTable = new BYTE[strTableSize];
			DWORD64 offset = 0;
			for (int i=1; i < m_outFileList.Count(); i++) 
			{
				WriteFileData *fileData = (WriteFileData*) m_outFileList[i];
				int len = sizeof(WCHAR) * (wcslen(fileData->path) + 1); // include null terminator
				memcpy(strTable+offset, fileData->path, len);
				offset += len;
			}
			BYTE* encStrTable = Encrypt(strTable, strTableSize, &encStrTableSize, validate);
			Write(encStrTable, encStrTableSize);

			Align(encStrTableSize);
			delete[] encStrTable;
			delete[] strTable;
		}

		m_pHdr->strTableSize    = strTableSize;
		m_pHdr->encStrTableSize = encStrTableSize;
	}

	void WriteHashTable()
	{
#ifdef USE_HASHING
		m_pHdr->hashTableOffset = m_outFilePos;
		Write(m_hashTable, sizeof(*m_hashTable)*PRIME);
#else
		m_pHdr->hashTableOffset = 0;
#endif
	}

	void WriteFileMetadata()
	{
		for (int i=1; i < m_outFileList.Count(); i++) 
		{
			FileData *fileData = (FileData*) m_outFileList[i];
			Write(fileData, sizeof(FileData));
		}
	}

	bool AppendFileData(WriteFileData *fileData, bool validate)
	{
		const WCHAR* pInPath;
		WCHAR inPath[MAX_PATH];

		if (fileData->tmpFile)
			pInPath = fileData->tmpFile;
		else
		{
			wcscpy(inPath, fileData->rootDir);
			wcscat(inPath, L"/");
			wcscat(inPath, fileData->path);
			pInPath = inPath;
		}

		printf("Adding %ws (%d)\n", fileData->path, fileData->Size());
		int inFD =  _wopen(pInPath, O_RDONLY | O_BINARY, 0666);
		if (inFD == -1)
		{
			fprintf(stderr, "can't open input file %ws -- %s\n", pInPath, strerror(errno));
			return(false);
		}
		int n;
		BYTE buf[4096];
		BYTE* fileBuf = 0;
		bool bOK = true;
		bool encrypt = m_pHdr->IsEncrypted();
		DWORD fileSize = fileData->Size();
		if (encrypt)
		{
			fileBuf = new BYTE[fileSize];
		}

		fileData->dataOffset = m_outFilePos;

		DWORD offset=0;
		DWORD total=0;
		while( (n = read(inFD, buf, sizeof(buf))) > 0)
		{
			if (!encrypt)
			{
				if (Write(buf, n) == -1)
				{
					bOK = false;
					fprintf(stderr, "can't write data for %ws -- %s\n", pInPath, strerror(errno));
					break;
				}
			}
			else
			{
				memcpy(fileBuf+offset, buf, n);
				offset += n;
			}
			total += n;
		}
		if (total != fileSize)
		{
			printf("ERROR: Reading more than file size %d != %d\n", offset, fileData->Size());
		}

		if (encrypt)
		{
			int encDataSize=0;
			BYTE* encData = Encrypt(fileBuf, fileSize, &encDataSize, validate);
			Write(encData, encDataSize);
			fileData->encSize = encDataSize;
			delete[] fileBuf;
		}
		close(inFD);
		return(bOK);
	}

	void InitRoot()
	{
		FileData *fd = new FileData();
		memset(fd, 0, sizeof(*fd));
		i_rootDir = new ReadFileData(fd, L"/");
		i_rootDir->fd->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
		i_rootDir->fd->firstChildIndex = 1;
		m_inFileList.Init(256);
		m_inFileList.AddEntry((FileData*) i_rootDir);
	}

	void LoadArchive()
	{
		InitRoot();
		DBHeader *pHdr = m_pHdr = (DBHeader*) m_archiveBaseAddr;
		FileData *fileData   = (FileData*) (m_archiveBaseAddr + m_pHdr->metadataOffset); 

		//printf("Total files: %d\n", pHdr->totalFiles);
		if (!pHdr->IsEncrypted())
		{
			m_strTable = (BYTE*) (m_archiveBaseAddr + sizeof(*pHdr));
		}
		else
		{
			int origStrTableLen=0;
			EncryptInit(false);
			BYTE* encStrTable = (BYTE*) (m_archiveBaseAddr + sizeof(*pHdr));
			m_strTable = Decrypt(encStrTable, pHdr->encStrTableSize, &origStrTableLen);
			if (origStrTableLen != pHdr->strTableSize)
			{
				printf("ERROR: strtable incorrect sz=%d, orig=%d\n", origStrTableLen , pHdr->strTableSize);
				return;
			}
			//printf("strtable sz=%d, orig=%d\n", origStrTableLen , pHdr->strTableSize);
		}

#ifdef USE_HASHING
		m_hashTable = (DWORD*) (m_archiveBaseAddr + m_pHdr->hashTableOffset);
#endif

		for(int i=0; i < pHdr->totalFiles; ++i)
		{
			LPCWSTR path = (LPCWSTR)(m_strTable + fileData->nameOffset);

			ReadFileData *rdFileData = new ReadFileData(fileData++, path);
			//printf("Reading %ws\n", rdFileData->path);
			m_inFileList.AddEntry((FileData*)rdFileData);
		}
	}

	void ValidateArchive()
	{
		for(int i=0; i < m_inFileList.Count(); i++)
		{

			ReadFileData* ent = (ReadFileData*) m_inFileList[i];
			bool red;
			ReadFileData*pze = GetEntry(ent->path, &red);
			if (!pze || wcscmp(ent->path, pze->path))
			{
				Logger::log(0, "INVALID %ws, pze=%x\n", ent->path, pze);
			}
			else if (pze->IsDirectory())
			{
				for(ReadFileData *c = GetFirstChild(pze); c; c=GetNextSibling(c))
				{
					ReadFileData* p = GetParentEntry(c->path, &red, L'/');
					if (!p && c->fd->parentIndex)
						Logger::log(0, "INVALID no parent for %ws\n", ent->path);
					break;
				}
			}
			//else Logger::log(0, "valid %ws\n", ent->path);

		}
	}

	bool WriteFiles(char *keyData, PWCHAR outFile, DList<LPCWSTR> &fileList)
	{
		InitHash();
		WCHAR curDir[MAX_PATH];
		GetCurrentDirectory(MAX_PATH, curDir);
		// add null entry to reserve index 0
		m_outFileList.AddEntry(0);

		for(int pass=1; pass <= 2; ++pass)
		{
			WriteFileData *last = 0;
			for (int i=0; i < fileList.Count(); i++) 
			{
				LPCWSTR fileName = fileList[i];
				WCHAR relPath[MAX_PATH], parentDir[MAX_PATH];
				WCHAR newDir[MAX_PATH];
	
				GetRelativePath(fileName, relPath, parentDir);
				if (!SetCurrentDirectory(parentDir))
				{
					fprintf(stderr, "ERROR: invalid path %ws\n", parentDir);
					return(false);
				}
				GetCurrentDirectory(MAX_PATH, newDir);
				if (pass == 2)
				{
					printf("==> in %ws\n", newDir);
					//printf("relPath=%ws, parent=%ws\n", relPath, parentDir);
					printf("====> process %ws\n", relPath);
					int len = wcslen(newDir);
					PWCHAR rootDir = new WCHAR[len+1];
					wcscpy(rootDir, ToUnixPath(newDir));
					if (rootDir[len-1] == '/')
						rootDir[len-1] = 0;
					WriteFileData* fd = AddFile(0, relPath, rootDir);
					if (fd && !fd->excluded)
					{
						if (last)
							last->nextSiblingIndex = fd->index;
						last = fd;
					}
				}
				SetCurrentDirectory(curDir);
			}
		}
		m_writingFiles = true;
		SaveData(keyData, outFile);
		m_writingFiles = false;
		//Dump(true);
		printf("Total files: (%d / %d), size (%llu / %llu) excluded files %d (size %lld)\n", 
					m_outFileList.Count(), m_totalFiles, m_includeSize, m_totalSize, m_excludeCount, m_excludeSize);
		DumpHashInfo();
		return(true);
	}

	bool Open(const PWCHAR filePath, RedirectorInfo &redictorInfo, bool bValidate)
	{
		if (!OpenArchive(filePath))
			return(false);
		bool bOK = true;
		if (redictorInfo.HasRedirects())
		{
			for(int i=0; i < redictorInfo.Count(); i++)
			{
				RedirectEntry*ent = redictorInfo[i];
				if (!AddRedirect(redictorInfo, ent))
					bOK = false;
				
			}
		}
		if (bValidate)
			ValidateArchive();
		return(bOK);
	}

	bool AddRedirect(RedirectorInfo &redictorInfo, RedirectEntry*ent)
	{
		bool red;
		ReadFileData*pze = GetEntry(ent->m_srcPath, &red);
		if (pze)
		{
			Logger::log(1, "==> Found redirected file/folder %ws\n", pze->path);
			return InitRedirect(redictorInfo, pze);
		}
		else
		{
			Logger::logError("no redirected path found for file/folder %ws\n", ent->m_srcPath);
		}
		return(false);
	}

	static bool Clone(FSMgr *fsMgr, ReadFileData *pze, WCHAR *destPath, bool useHardLink = false)
	{
		WCHAR *p = wcschr(destPath, L'\\');
		bool bOK = true;

		while (p)
		{
			p = wcschr(p+1, L'\\');
			if (!p)
				break;
			*p = '\0';
			BOOL bOK2 = CreateDirectory(destPath, NULL);
			DWORD error = GetLastError();
			if (bOK2)
				Logger::log(1, "\t\tcreate dir %ws\n", destPath);
			*p = '\\';
			if (!bOK2 && error != ERROR_ALREADY_EXISTS)
			{
				bOK = false;
				break;
			}
		}
		if (pze->IsDirectory())
		{
			if (CreateDirectory(destPath, NULL))
				Logger::log(1, "\t\tcreate dir %ws\n", destPath);
			else if (GetLastError() != ERROR_ALREADY_EXISTS)
			{
				bOK = false;
				Logger::logWinError(GetLastError(), "Failed to create directory %ws", destPath);
			}
		}
		else
		{
			WCHAR destPathActual[MAX_PATH];
			WCHAR *pPath;
			if (useHardLink)
			{
				wcscpy(destPathActual, destPath);
				wcscat(destPathActual, L".Local");
				pPath = destPathActual;
			}
			else
			{
				pPath = destPath;
			}
			HANDLE handle = CreateFile(
				pPath,
				GENERIC_WRITE | GENERIC_READ ,
				FILE_SHARE_WRITE | FILE_SHARE_READ,
				NULL,
				CREATE_NEW,
				0,
				NULL);
			if (!handle || handle == INVALID_HANDLE_VALUE) 
			{
				if (GetLastError() !=  ERROR_FILE_EXISTS)
				{
					Logger::logWinError(GetLastError(), "failed to clone file %ws", pPath);
					bOK = false;	
				}
			}
			else
			{
				Logger::log(1, "\t\tcreate file %ws\n", destPath);
				DWORD nb;
				fsMgr->Fetch(pze);
				BYTE* data = pze->GetData();
				WriteFile(handle, data, pze->Size(), &nb, NULL);
				SetFileTime(handle, 
						&pze->fd->ftCreationTime,
						&pze->fd->ftLastAccessTime,
						&pze->fd->ftLastWriteTime);
				CloseHandle(handle);
				SetFileAttributes(pPath, pze->fd->dwFileAttributes);
				if (useHardLink)
				{
					BOOL fCreatedLink = CreateHardLinkW( destPath, destPathActual, NULL );
				}
			}
		}

		return(bOK);
	}

	bool InitRedirect(RedirectorInfo &redictorInfo, ReadFileData *pze)
		{
		pze->redirect= true;
		WCHAR dest[MAX_PATH];
		WCHAR src[MAX_PATH];
		memset(dest, 0, MAX_PATH);
		wcscpy(src, pze->path);
		for(WCHAR *p=src; *p; ++p)
			if (*p == L'/')
				*p = L'\\';
		bool bOK = true;
		if (redictorInfo.GetRedirectPath(src, dest, MAX_PATH))
		{
			Logger::log(1, "\t==> redirect %s %ws -> %ws\n", pze->IsDirectory()? "DIR ": "FILE", src, dest);
			if (!Clone(this, pze, dest))
				bOK = false;
		}
		else
			Logger::logError("no redirected path found for file/folder %ws\n", src);

		for(ReadFileData *c = GetFirstChild(pze); c; c=GetNextSibling(c))
		{
			if (!InitRedirect(redictorInfo, c))
				bOK = false;
		}
		return(bOK);
	}

	bool OpenArchive(PWCHAR ArchiveFile)
	{
		m_hArchiveFile = CreateFile(ArchiveFile, 
			GENERIC_READ, 
			FILE_SHARE_READ,		
			0,
			OPEN_EXISTING,
			0,
			0);
		if (!m_hArchiveFile || m_hArchiveFile == INVALID_HANDLE_VALUE)
		{
			fprintf(stderr, "failed to open archive %ws -- %ws\n", ArchiveFile, (TCHAR*)WINSYSERR_T(GetLastError()));
			return(false);
		}

		m_hArchiveMemMap = CreateFileMapping(m_hArchiveFile, 0, PAGE_READONLY, 0, 0, 0);
		if (!m_hArchiveMemMap)
		{
			CloseHandle(m_hArchiveFile);
			fprintf(stderr, "failed to map archive %ws\n", ArchiveFile);
			return(false);
		}
		m_archiveBaseAddr = (BYTE*) MapViewOfFile(m_hArchiveMemMap, FILE_MAP_READ, 0, 0, 0);
		if (!m_archiveBaseAddr)
		{
		}

		LoadArchive();
		return(true);
	}


	void CloseArchive()
	{
		if (m_archiveBaseAddr)
			UnmapViewOfFile(m_archiveBaseAddr);
		if (m_hArchiveMemMap)
			CloseHandle(m_hArchiveMemMap);
		if (m_hArchiveFile && m_hArchiveFile != INVALID_HANDLE_VALUE)
			CloseHandle(m_hArchiveFile);
	}

	void Fetch(ReadFileData* pze)
	{
		if (m_pHdr->IsEncrypted())
		{
			BYTE* data = pze->GetData();
			if (!data)
			{
				BYTE *encData = (BYTE*)m_archiveBaseAddr + pze->fd->dataOffset;
				int origDataLen = 0;
				Logger::log(2, "\t==> DEC file %ws\n", pze->path);
				data = Decrypt(encData, pze->fd->encSize, &origDataLen);
				if (origDataLen != pze->fd->Size())
				{
					Logger::logError("decyrption file %ws\n", pze->path);
				}
				pze->SetData(data);
			}
		}
		else if (pze->fd->dataOffset)
			pze->SetData( (BYTE*)m_archiveBaseAddr + pze->fd->dataOffset);
	}

	inline bool IsRoot(ReadFileData* pze)
	{
		return (pze == i_rootDir);
	}

	inline ReadFileData*  GetParentOf(ReadFileData* pze)
	{
		return (pze->fd->parentIndex? (ReadFileData*)m_inFileList[pze->fd->parentIndex]: 0);
	}

	inline ReadFileData*  GetFirstChild(ReadFileData* pze)
	{
		if (pze->fd->firstChildIndex)
			return (ReadFileData*)m_inFileList[pze->fd->firstChildIndex];
		return(0);
	}

	inline ReadFileData* GetNextSibling(ReadFileData* pze)
	{
		if (pze->fd->nextSiblingIndex)
			return (ReadFileData*) m_inFileList[pze->fd->nextSiblingIndex];
		return(0);
	}

	inline bool Equal(const TCHAR *str1, const TCHAR *str2)
	{
		const TCHAR *p1;
		const TCHAR *p2;
		for(p1=str1, p2=str2; *p1 && *p2; ++p1, ++p2)
		{
			TCHAR c1 = *p1, c2 = *p2;
			if (_totupper(c1) == _totupper(c2))
				continue;
			if (c1 == '\\') c1 = '/';
			if (c2 == '\\') c2 = '/';
			if (c1 == c2)
				continue;
			return(false);
		}
		if (IsDirSep(*p1))
			++p1;
		if (IsDirSep(*p2))
			++p2;
		return(!*p1 && !*p2);
	}


	inline ReadFileData* GetChildByName(ReadFileData* parent, LPCWSTR cName)
	{
		for(ReadFileData*c = GetFirstChild(parent); c; c=GetNextSibling(c))
		{
			if (Equal(c->name0, cName))
				return(c);
		}
		return(0);
	}

	ReadFileData* GetParentEntry(const WCHAR *name, bool *pInRedirectPath, WCHAR sep= L'\\')
	{
		WCHAR *p = wcsrchr(name+1, sep);
		if (!p)
			return(0);

		WCHAR tmp[MAX_PATH];
		int len = p - name;
		for(int j=0; j < len; j++)
			tmp[j] = name[j];
		tmp[len] = 0;
		return GetEntry(tmp, pInRedirectPath);
	}

#ifdef USE_HASHING
	ReadFileData* GetEntry(const WCHAR *name, bool *pInRedirectPath)
	{
		*pInRedirectPath = false;

		if (name[1] == 0)
			return i_rootDir;

		int bucket = HashString(name);
		DWORD index = m_hashTable[bucket];
		//Logger::log(0, "GetEntry: %ws, b=%d, index=%d\n", name, bucket, index);

		while(index)
		{
			ReadFileData *item = (ReadFileData*) m_inFileList[index];
			// Logger::log(0, "\tCheck: %ws == %ws\n", item->path, name);

			if (Equal(item->path, name))
			{
				if (!(*pInRedirectPath = item->redirect))
				{
					for(ReadFileData*p = GetParentOf(item); p; p = GetParentOf(p))
					{
						if (p->redirect)
						{
						*pInRedirectPath = true;
						break;
						}
					}
				}
				return(item);
			}
			index=item->fd->h_nextHashIndex;
		}
		return(0);
	}

#else

	ReadFileData* GetEntry(const WCHAR *name, bool *pInRedirectPath)
	{
		*pInRedirectPath = false;
		++name;
		if (*name == 0)
			return i_rootDir;

		ReadFileData* parent = i_rootDir;
		while(parent)
		{
			TCHAR *p;
			for(p=(TCHAR*) name; *p && !IsDirSep(*p); ++p)
				;
			if (IsDirSep(*p))
			{
				TCHAR tmp[MAX_PATH];
				int len = p -name;
				for(int j=0; j < len; j++)
					tmp[j] = name[j];
				tmp[len] = 0;
				parent = GetChildByName(parent, tmp);
				if (parent)
					*pInRedirectPath = parent->redirect;
				name = p+1;
				continue;
			}
			ReadFileData *ent = GetChildByName(parent, name);
			if (ent)
			{
				*pInRedirectPath = ent->redirect;
				//if (ent->exclude) return(0);
			}
			return(ent);
		}
		return(0);
	}
#endif


	
	void Dump(bool bOutput=false)
	{
		printf("%7s %5s %8.8s %10s %5s %5s %5s %s\n", "perm",  "index", " ATTRS  ", "Size", "p-idx", "1st-c", "n-sib", "       Path");
		printf("%7s %5s %5s %10s %5s %5s %s\n", "-------", "-----", "--------", "----------", "-----", "-----", "-----", " -----------");
		DList<FileData*> &fileList = (bOutput)?  m_outFileList: m_inFileList;

		for (int i=1; i < fileList.Count(); i++) 
		{
			FileData *fd = fileList[i];
			LPCWSTR path;
			if (bOutput)
				path = ((WriteFileData*) fd)->path;
			else
			{
				path = ((ReadFileData*) fd)->path;
				fd = ((ReadFileData*) fd)->fd;
			}
			char perm[8];

			perm[0] = (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)? 'd': '-';
			if (fd->dwFileAttributes & FILE_ATTRIBUTE_READONLY)
			{
				perm[1] = 'r';
				perm[2] = '-';
			}
			else
			{
				perm[1] = 'r';
				perm[2] = 'w';
			}

			perm[3] = (fd->fflags & FLAG_EXE)? 'x': '-';
			perm[4] = (fd->dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)? 'H': '-';
			perm[5] = (fd->dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED)? 'C': '-';
			perm[6] = (fd->dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED)? 'E': '-';
			perm[7] = 0;


			printf("%7s %5d %8.8x %10d ", perm, fd->index, fd->dwFileAttributes, fd->Size() );
			//printf("%5d ", fd->index);
			if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				printf("%5d %5d %5d ", fd->parentIndex, fd->firstChildIndex, fd->nextSiblingIndex);
			else
				printf("%5d ----- %5d ", fd->parentIndex, fd->nextSiblingIndex);
			for(int j=0; j < fd->lev; j++)
				printf("  ");
			printf("%ws\n", path);
		}
		printf("Total files: %d\n", fileList.Count()-1);
	}
};


#ifdef FS_MAIN

void ShowUsage(WCHAR *prog, bool bShowDetail=false)
{
	WCHAR *p = wcsrchr(prog, '/');
	if (!p)
		p = wcsrchr(prog, '\\');
	if (p)
		prog = ++p;

	printf("Usage: %ws -l inputImage\n", prog);
	printf("Usage: -h [detail]\n", prog);
	printf("Usage: %ws -o outputImage [-k password] [-r filter] [-e filter] dirOrFile+\n", prog);
	printf("Where: \n");
	printf("   -o ouptutImage -- specify the output image file name\n");
	printf("   -k password    -- specify encryption password. If specified, the image\n");
	printf("                     will be encrypted using AES 256 encyption alogrithm.\n");
	printf("                     Otherwise, he archive image will be unencrypted.\n");
	printf("   -l inputImage  -- list image content\n");
	printf("   -e regExp      -- specify file exclusion filter\n");
	printf("   -r filter      -- specify file replacement/renaming/preprocessing filter\n");
	printf("                     filter syntax: \n");
	printf("                        .FromExt#.toExt#RegExp#FilterTool[#ToolLoader]\n");
	printf("   -h [detail]    -- show this help. More info provided if detail is specified\n");
	if (!bShowDetail)
		return;
	printf("\nNotes: \n");
	printf("  With the '-r' option (and for each file the regular expression 'RegExp'), \n");
	printf("  the tool 'FilterTool' will be passed two arguments and input file name \n");
	printf("  and an output file name. The tool is expected to generate the output file \n");
	printf("  which will replace the input file in the generated archive image.\n");
	printf("  The output file name in this case with have the extension specified in\n");
	printf("  'toExt'.\n");

	printf("\nExamples: \n");
	printf("   \n");
	printf("   %ws -o archive.img c:/testing/app c:/testing/data \\\n", prog);
	printf("       -r '.rb#.rb#^(app|data)#preproc.rb#ruby.exe'  \\\n");
	printf("       -r '.o#.obj#^(app|data)#rename.sh#sh.exe'  \\\n");
	printf("       -e '[/]doc([/]|$)' \\\n");
	printf("       -e '[/]tmp/'\n");

}

static FSMgr fsMgr;
int wmain(int argc, PWCHAR argv[])
{
	PWCHAR outFile = 0;	
	PWCHAR inpFile = 0;	
	DList<LPCWSTR> fileList; 
	bool showDetailHelp = false;

	bool listOnly = false;
	char keyData[512] = {0};

	if (argc < 2)
	{
		ShowUsage(argv[0]);
		return(1);
	}

	g_filterMgr.Init();

	for (int i=1; i < argc; i++) 
	{
		PWCHAR arg = argv[i];
		if (arg[0] == L'-')
		{
			switch (arg[1])
			{
				case L'k':
					arg = argv[++i];
					WideCharToMultiByte(CP_UTF8,0, arg, -1, keyData, sizeof(keyData),0,0);
					break;

				case L'o':
					outFile = argv[++i];
					break;
				case L'l':
					listOnly = true;
				case L'i':
					inpFile = argv[++i];
					break;
				case L'e':	
				case L'r':	
					try
					{
						g_filterMgr.AddEntry(new FilterHelper(arg, argv[++i], arg[1] == L'e'));
					}
					catch(Exception &e)
					{
						fprintf(stderr, "ERROR(%d): %s\n", e.code, e.msg);
						return(1);
					}
					break;
				case L'h':
				case L'H':
					showDetailHelp = (i+1 < argc && !wcscmp(argv[i+1], L"detail"));
					ShowUsage(argv[0], showDetailHelp);
					return(1);
				default:
						fprintf(stderr, "ERROR: invalid option %ws\n", arg);
						ShowUsage(argv[0], showDetailHelp);
						return(1);
			}
		}
		else
			fileList.AddEntry(argv[i]);
	}

	if (inpFile)
	{
		fsMgr.OpenArchive(inpFile);
		if (listOnly)
			fsMgr.Dump();
	}
	else if (outFile)
	{
		if (!fileList.Count())
		{
			ShowUsage(argv[0]);
			return(1);
		}
		try
		{
			if (_waccess(outFile, R_OK) == 0)
			{
				fprintf(stderr, "ERROR: %ws already exists\n", outFile);
				return(1);
			}
			for (int i=0; i < fileList.Count(); i++) 
			{
				LPCWSTR fileName = fileList[i];
				if (_waccess(fileName, R_OK) == -1)
					throw Exception(ERR_OPEN, "file not found %ws", fileName);
			}
			fsMgr.WriteFiles(keyData, outFile, fileList);
			if (Logger::numErrors)
			{
				return(1);
			}
		} 
		catch(Exception &e)
		{
			Logger::logError("%s\n", e.msg);
			return(1);
		}
		catch(... )
		{
			fprintf(stderr, "ERROR: Unknown error\n");
			return(1);
		}
	}
	else
		{
			ShowUsage(argv[0]);
			return(1);
		}

	return(0);
}

#endif
