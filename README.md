
Notes:
======
	1. Please contact me (Maher Samman) at mahersamman2000@yahoo.com for help and inquires.
	2. This is an initial release just to get the project going and get more feedback. There
	   are few commercial products out there that do the same thing but are very expensive. 

About AppVFS:
=============

	AppVFS is a set of tools that allow you to to package and run your applications 
	from a virtual file system (VFS) that can be made accessible to your applications
	only. The VFS is based on the Dokan library (http://dokan-dev.net), a great package
	created by Hiroki Asakawa that provides a simple application-level API which allows
	developers to implement file system services easily and without the need to write
	complex kernel derivers.

About Dokan:
============
	(extract from http://dokan-dev.net/en/about/ )
	When you want to create a new file system on Windows, for example to improve FAT or NTFS, you 
	need to develop a file system driver. Developing a device driver that works in kernel mode on 
	windows is extremely difficult. By using Dokan library, you can create your own file systems 
	very easily without writing device driver. Dokan Library is similar to FUSE(Linux user mode 
	file system) but works on Windows.

	Dokan means ‘clay pipe’ in Japanese. The Dokan library works as a proxy and looks like a ‘pipe’.
	

Usage Scenario:
===============

	Say that you/your company are/is building a product that uses Java, Ruby, or ActionScripts.
	And you want to make sure that people (or really hackers) don't try to reverse-engineer or
	peek into your code to steal your technology. If that's your case, then AppVFS is what 
	you need. 
	
Why/How, and what else do I need to do:
=======================================

	1. AppVFS can encrypt your VFS image so hackers can't dump the content of your files
	2. AppVFS limts access and I/O calls to processes (and their sub procs) started by 
	   AppVFS only. Therefore, no other processes on the system  (e.g. debuggers or Explorer) 
	   can open/read your files.

	Well, there is a catch here. Anyone can start AppVFS and pass it an any application to 
	start and get access to the files in the image. This is actually your responsibility, at
	least in this initial release of AppVFS. That is, you need to change appvfs.cpp code
	yourself to control its startup. Along the way you can check licensing and other stuff
	that you need to start your main (or bootstrap) application. From there on, only your
	main app and its subprocesses will have access to the VFS in the image.

	If you're really concerned about those hard working and relentless hackers, 
	then you may also need to implement some kind of anti-debugging in your application(s) 
	code/memory. Just google up "windows anti-debugging" and find one that suites your needs 
	and can implement yourself. This is also another feature that should probably be provided
	by AppVFS in the future.

	Finally, I am not saying that you can close the door completely on hackers. AppVFS is just 
	an attempt to make it extremely more difficult and more time consuming to hack your applications.
	You have to remember (and admit) that regardless of what you do, it is still possible 
	for some with administrative rights to access your process memory outside of debuggers. 
	However, if such people get to that low level then they have to spend alot of time trying 
	to figure out things in your application.

AppVFS Components:
==================

	AppVFS has three main basic tools: mkvfs, appvfs, and vfsctl. 
	
	Mkvfs is used to generate an image (optionally with encryption) from a set of files and 
	directories you specify. You can then use the generated image to mount your VFS using appvfs. 

	Run mkvfs -h (shown below) for other cool options that you can use to build your VFS image with 
	encryption, file exclusion and file replacement options on the fly.

	Run appvfs -h to see options for file redirection and restricted/protected application
	startup.

	Run vfsctl -h for options to get stats and set debug levels.

Supported Platforms:
====================
	In this initial release, only Windows is supported. The build environment is 
	based on MINGW.
	AppVFS supports AES 256 encryption only.

Performance:
============

	Given that this is an application-level VFS, performance will surely be affected.  However, performance may still be within acceptable range for you because the VFS is actually loaded into memory by AppVFS. It all depends on the number of files and the overall size of VFS image you generate with mkvfs. I have ran a rails app from a VFS which includes both of the rails app and the ruby installation (total of 198MB) and performance was acceptable. If I leave the ruby installation out of the image then the performance is comparable to real environment running off of hard disk.  Therefore, when you package your application, you may want to split into two parts.  Your Senitive data, code and even binaries (that you do not want hackers to get access to) go into the image and common stuff go into hard disk.


Issues:
=======

	1. There is an issue with applications that you sockets. I can't figure out the issue
	   but it seems to be related to mounted virtual file systems. The workaround is to use
	   the -xdir option in appvfs (run appvfs -h for detail).

	2. There is a bug in the Dokan library which passes incomplete file info data back to the
	   Windows kernel. The fix is to add the following in DokanFillFilePositionInfo (dokan/fileinfo.c):
	   	DokanFillFileAllInfo()
	   {
	   // right after call to DokanFillFilePositionInfo(), add:
	   DokanFillInternalInfo(&AllInfo->InternalInformation, FileInfo, RemainingLength);
	   }
	   This means that the Dokan DLL will be changed and you have to replace the one
	   under %WINDIR%\system32\dokan.dll with the one you build.

       This bug affects ruby/rails.

	   I built my own Dokan library with the fix and a few other Dokan API callbacks
	   but need to submit those back into the Dokan code stream.

	   See Building the Dokan Library for detail.

	3. For Ruby/Rails, you need to use build and use rubyMain.exe if you decide to
	   package ruby installation in your VFS image. You can then use mkvfs with the
	   -r option to replace the ruby.exe. The file ruby_pkg.sh is an example of how
	   to package a ruby installation. Note that you also need to use the -xdir option
	   with appvfs in order to get rails (or networking ruby apps) working.

Building AppVFS:
================
	
1.  Download and install the Dokan Library
	http://dokan-dev.net/wp-content/uploads/DokanInstall_0.6.0.exe
2. Download and build OpenSLL (see below)
3. Download and extract Mingw regexp package from:
	http://sourceforge.net/projects/mingw/files/Other/UserContributed/regex/mingw-regex-2.5.1/
	Note: No need to build it. The Makefile for AppVFS builds it.

3. Edit the Makefile and set the following (use your own folder locations):
	OPENSSLDIR=c:/openSSL 
	DOKANLIBDIR=c:\Program Files\dokan\DokanLibrary
	REGEXPDIR=./mingw-libgnurx-2.5.1

4. % make

2. cd %WINDIR%\system32
	replace dokan.dll with the one provided by Maher


BUILDING OpenSSL:
=================

Get sources from http://www.openssl.org/source/openssl-1.0.1c.tar.gz

For 32 bits:
    perl Configure mingw no-shared no-asm --prefix=c:/OpenSSL
For 64 bits:
    perl Configure mingw64 no-shared no-asm --prefix=C:/OpenSSL-x64

Then:

    make depend
    # make (fails to build tests) so
	make build_libs build_apps build_tools
	make openssl.pc libssl.pc libcrypto.pc
    # make install (make install_sw to skip installing many man pages)
	make install_sw

see https://github.com/freelan-developers/freelan-buildtools/blob/master/INSTALL.md


Building DOKAN Library:
=======================

	1. Get the Dokan Library sources:
		svn checkout http://dokan.googlecode.com/svn/trunk/ dokan-read-only

		if you do not have svn, you can download it from http://sourceforge.net/projects/win32svn/

		Dokan is also on github  https://github.com/clone/dokan

	2.  You need the Windows Driver Kit Version 7.1.0 (earlier version might work) which
	    you can get from:
		http://www.microsoft.com/en-us/download/confirmation.aspx?id=11800
	
		Install it under c:\WinDDK
		start a command prompt
		run:
			c:\WinDDK\7600.16385.1\bin\setenv.bat c:\WinDDK\7600.16385.1 chk
			For usage and other targets, run:
			c:\WinDDK\7600.16385.1\bin\setenv.bat

	3. Go to your dokan source directory:
		cd dokan
		build

		This will generate the dokan.dll and dokan.lib under the .obj directory


Mkvfs Usage:
============

<pre>
Usage: mkvfs.exe -l inputImage
Usage: -h [detail]
Usage: mkvfs.exe -o outputImage [-k password] [-r filter] [-e filter] dirOrFile+
Where:
   -o ouptutImage -- specify the output image file name
   -k password    -- specify encryption password. If specified, the image
                     will be encrypted using AES 256 encyption alogrithm.
                     Otherwise, he archive image will be unencrypted.
   -l inputImage  -- list image content
   -e regExp      -- specify file exclusion filter
   -r filter      -- specify file replacement/renaming/preprocessing filter
                     filter syntax:
                        .FromExt#.toExt#RegExp#FilterTool[#ToolLoader]
   -h [detail]    -- show this help. More info provided if detail is specified

Notes:
  With the '-r' option (and for each file the regular expression 'RegExp'),
  the tool 'FilterTool' will be passed two arguments and input file name
  and an output file name. The tool is expected to generate the output file
  which will replace the input file in the generated archive image.
  The output file name in this case with have the extension specified in
  'toExt'.

Examples:

   mkvfs.exe -o archive.img c:/testing/app c:/testing/data \
       -r '.rb#.rb#^(app|data)#preproc.rb#ruby.exe'  \
       -r '.o#.obj#^(app|data)#rename.sh#sh.exe'  \
       -e '[/]doc([/]|$)' \
       -e '[/]tmp/'
</pre>

AppVFS Help:
============

<pre>
appvfs -a archive -m mountPoint [options]
  -a*rchive imageFIle     -- specify the VFS archive image file
  -m*ountPoint folder     -- specify the VFS mount point/folder
  -t*hreads n             -- set number of I/O service threads
  -g debugLevel           -- set debug level (1-5)
  -r*edirect src dest     -- redirect folder/file 'src' to 'dest' folder
  -xdir executableDir     -- executable file directory
  -e*xec 'commandLine'    -- start program commandline (must be quoted)
                             example: -exec 'c:/myapp/myapp.exe arg1 arg2'
     -s*tartDir path      -- specify startup directory (used with -exec option)
  -h*elp                  -- for this help

Notes:
1. The VFS image will be mounted read-only. If your VFS contains files/folders
   that require write access (e.g. log or db folders), then use the -redirect
   option which instructs AppVFS to redirect I/O calls to the destination
   folder. A copy of the sources will be made to the destination folder if not
   found there. If you change the destination folder in subsequent runs then
   it is your responsibility to copy the old ones from the previous folders
2. The -xdir option will instruct appvfs to create a copy of the executables
   and place them under the 'executableDir' which should be outside the.
   mountpoint. This is currently needed if the programs executables use sockets.

3. Debug level values (-g opion)
        1    -- show access denied errors only
        2    -- show access errors only
        3    -- show all I/O calls
        4    -- show all I/O calls with additional detail
        5    -- show debug from Dokan DLL
</pre>


Vfsctl Help:
============

<pre>
	./vfsctl.exe -h
	Cmmands:
	      set debug dbgLev      -- set AppVFS debug level to 'dbgLev'
	      stats                 -- show stats
	      reset                 -- reset stats
	      redirect src des_dir  -- redirect source file/folder to des_dir
	
	Example:
		vfsctl.exe set debug 3
		vfsctl.exe stats
	

Sample output vfsctl.exe stats:
===============================

opName                   #Calls    ExeTime   #R-Calls  R-ExeTime
-------                 -------   --------   --------   --------
CreateFile                34635        969          1          0
CreateDirectory               1          0          4          0
OpenDirectory            162833       1947          6          0
CloseFile                139251       1216          6          0
Cleanup                  139285         31          6          0
ReadFile                   3323        483          0          0
GetFileInfo                3263          0          2          0
FindFiles                137130       1175          6          0
UnlockFile                 1862          0          0          0
GetFileSecurity               4          0          0          0
*OVERALL*:               621587       5821         31          0

Overall: LookupCnt=336740, LookupTime=3276, FetchTime=437

----------
</pre>

