#!/bin/sh

# Note that you need to run this script from MINGW shell
# You need to start samples/rails_appvfs.sh before running this script

TEST_ENV=/c/tmp/rails_test
mkdir -p $TEST_ENV

if [ ! -d $TEST_ENV ]; then
	echo "ERROR: can't create directory $_TEST_ENV" 1>&2
fi

VFS_MOUNT_FOLDER="$TEST_ENV/mt"
RUBYDIR=$VFS_MOUNT_FOLDER/ruby193

export PATH=${RUBYDIR}/bin:.:/usr/local/bin:/mingw/bin:/bin:/c/Windows/system32:/c/Windows



# thse RA_ variables are used by rubyMain.exe (renamed to ruby.exe)
#export RA_RBC_SUPPRT=1		// load rbc files instead or rb files whenever needed
export RA_DEBUG=3
export RA_LOGDIR=c:/tmp/ra_dbg
# RA_RYBY_EXE_PATH is used to fake ruby (via rubyMain.exe) to think that it is running ruby.exe 
# from ruby install dir. This is to workaround an issue with rails and rubygems that expect 
# ruby.exe to be under the ruby install dir
export RA_RYBY_EXE_PATH=${RUBYDIR}/bin/ruby.exe

function runTest()
{
	# Test ruby marshaling or rb -> rbc files (ruby byte code)
	cd $VFS_MOUNT_FOLDER
	env RA_RBC_SUPPRT=1 ruby -I. start.rb
}

echo "======== start test at: $(date) ============"
runTest
#(runTest 2>&1) | tee test.log
