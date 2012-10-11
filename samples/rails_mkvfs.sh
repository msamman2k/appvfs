#!/bin/sh

# Sample file to generate an image with ruby/rails application

if [ ! -d samples/testData ]; then
	echo "You should run this script from the main source directory" 2>&1
	exit 1
fi

RUBY_INSTALLDIR="c:/ruby193"

if [ ! -d $RUBY_INSTALLDIR ]; then
	echo "You need to edit $0 and set RUBY_INSTALLDIR to point to the ruby install directory" 1>&2
	exit 1
fi

SRCLIST="
	samples/testData/start.rb 
	samples/testData/app 
	samples/testData/data 
	samples/testData/rails_apps/blog
	$RUBY_INSTALLDIR
	"

# use the marshal filter to compile .rb files into .rbc files
# or ruby byte code

marshal="-r .rb#.rbc#^(app|data)#filters/marshal.rb#ruby.exe"

# replace ruby.exe with a copy of rubyMain.exe
# rubyMain.exe works around an issue with ruby paths. It also
# overload rb_load to capture load/require ops and use .rbc files
# whenever needed.
replaceRuby='-r .exe#.exe#ruby.exe#filters/replaceRuby.rb#ruby.exe'

# exclude the docs folders to limit space 
excludeDocs='-e [/]doc([/]|$)'
excludeTmps='-e ^[a-z]*[/]tmp/' 

(
mkvfs.exe -o archive.img \
		-k bluefish \
		$excludeTmps \
		$marshal \
		$excludeDocs \
		$replaceRuby \
		$SRCLIST
 2>&1) | tee rails_mkvfs.log
