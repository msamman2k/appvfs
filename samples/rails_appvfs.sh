#!/bin/sh

if [ ! -d samples/testData ]; then
	echo "You should run this script from the main source directory" 2>&1
	exit 1
fi

CURDIR=$(echo $(pwd) | sed 's;^/\([a-zA-Z]\);\1:;')

TEST_ENV=c:/tmp/rails_test

mkdir -p $TEST_ENV

if [ ! -d $TEST_ENV ]; then
	echo "ERROR: can't create directory $_TEST_ENV" 1>&2
fi

VFS_MOUNT_FOLDER="$TEST_ENV/mt"
EXE_REDIRECT_DIR="$TEST_ENV/exeRedirect"
WRT_REDIRECT_DIR="$TEST_ENV/writeData"

mkdir -p $VFS_MOUNT_FOLDER
mkdir -p $EXE_REDIRECT_DIR
mkdir -p $WRT_REDIRECT_DIR

IMAGE_ARCHIVE=archive.img
# number of I/O service threads
nthreads=3		
###########################################################
# REDIRECTS: specify files & directories that should have write access
WRT_REDIRECTS="-r \\blog\\tmp $WRT_REDIRECT_DIR 
			   -r \\blog\\log $WRT_REDIRECT_DIR 
			   -r \\blog\\db  $WRT_REDIRECT_DIR"

##############################################################
# EXEC_COMMAND: specify program startup and the start directory
EXEC_COMMAND='-exec c:/tmp/runrails_folder.bat -startDir d:/tmp/mt/blog'
EXEC_COMMAND=""
##############################################################
# EXE_REDIRECT_OPT: specify directory location where executables
# will be copied to. This is important in order to workaround
# an issue with sockets
EXE_REDIRECT_OPT="-xdir $EXE_REDIRECT_DIR"
##############################################################
# DEBUG_LEVEL: set the debug level
# 		DBG_LEVEL=1    show access denied errors only
# 		DBG_LEVEL=2    show access errors only
# 		DBG_LEVEL=3    show all I/O calls 
# 		DBG_LEVEL=4    show all I/O calls with additional detail
# 		DBG_LEVEL=5    show debug from Dokan DLL
# 		DBG_LEVEL=5    enable dokan driver debug
DBG_LEVEL="1"
##############################################################

# removable: treat the mounted FS as removable
#removable="-removable"
removable=""
args="-m $VFS_MOUNT_FOLDER -a $IMAGE_ARCHIVE -t $nthreads -g $DBG_LEVEL $EXE_REDIRECT_OPT $WRT_REDIRECTS $EXEC_COMMAND"

echo "Run: $args"

(../source/appvfs.exe $args 2>&1) | tee rails_appvfs.log
