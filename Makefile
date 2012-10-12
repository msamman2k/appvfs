
CC=g++
CFLAGS=-g
CFLAGS=-O3
OPENSSLDIR=c:/openSSL
DOKANLIBDIR=dokan
build_rubyMain = 1

REGEXPDIR=mingw-libgnurx-2.5.1
REGEXPCFLAGS = -D USE_REGEXP -I $(REGEXPDIR)
REGEXPLIB = /usr/local/lib/libregex.a
REGEXPSRC = $(REGEXPDIR)/regex.c

REGEXPSOBJS=$(REGEXPSRC:.c=.o)  


ifeq ($(build_rubyMain), 1)

RUBY_MAIN=checkRuby rubyMain.exe

endif


all: $(RUBY_MAIN) appvfs.exe mkvfs.exe vfsctl.exe exewrap.exe
	@echo ruby_libs = $(ruby_libs)
	@echo building $@ for $(ruby_arch)
	@echo all done


ifeq ($(build_rubyMain), 1)

RUBY = $(shell which ruby 2>/dev/null | sed 's;\\;/;g' | sed 's;/bin/.*;;')

checkRuby:
	@if [[ "$(RUBY)" = "" ]]; then \
		echo "ERROR: no ruby installation detected." 1>&2;\
		echo "If you don't need to build rubyMain.exe then edit the Makefile and set build_rubyMain = 0";\
		exit 1;\
	fi
	
RUBYINC = $(shell ruby -r mkmf -e "print RbConfig::CONFIG['includedir']")
ruby_h_dir=$(shell ruby -r mkmf -e 'print RbConfig::CONFIG["rubyhdrdir"]')
ruby_arch=$(shell  ruby -r mkmf -e 'print RbConfig::CONFIG["arch"]')
ruby_libs=$(shell  ruby -r mkmf -e 'print RbConfig::CONFIG["LIBS"]')

RUBYLIB=$(shell ruby -r mkmf -e "print RbConfig::CONFIG['LIBRUBY']")
RUBYDLL=$(shell echo $(RUBYLIB) | sed 's;^lib;;' | sed 's;\.a;;')
RUBYDLLDEF= -DRUBYDLL="\"$(RUBYDLL)\""
RUBY_CFLAGS=-I$(ruby_h_dir)/$(ruby_arch) -I$(ruby_h_dir) -I/usr/local/include
rubyMain.exe: rubyMain.cpp globals.h syshooks.o $(REGEXPSOBJS)
	$(CC) $(CFLAGS) -o $@ $(RUBYDLLDEF) -I. $(RUBY_CFLAGS) $(REGEXPCFLAGS) rubyMain.cpp syshooks.o $(RUBY)/lib/$(RUBYLIB) $(REGEXPSOBJS) -L/usr/local/lib $(ruby_libs)

endif
	
syshooks.o: %.o: %.cpp globals.h syshooks.h
	$(CC) $(CFLAGS) -c $(RUBYDLLDEF) -I. -o $@  $(@:.o=.cpp)

appvfs.exe: appvfs.cpp mingwMain.o globals.h fsmgr.cpp dkmount.cpp
	 $(CC) $(CFLAGS) -o $@ -I$(DOKANLIBDIR) -IZipUtil -I$(OPENSSLDIR)/include -DUNICODE -D_UNICODE  mingwMain.o appvfs.cpp $(DOKANLIBDIR)/dokan.lib $(OPENSSLDIR)/lib/libcrypto.a -luser32 -lgdi32 -ladvapi32 -lws2_32

mkvfs.exe: fsmgr.cpp globals.h mingwMain.o $(REGEXPSOBJS)
	 $(CC) $(CFLAGS) -o $@ -DFS_MAIN -DUNICODE -D_UNICODE  $(REGEXPCFLAGS) -I$(OPENSSLDIR)/include mingwMain.o fsmgr.cpp $(OPENSSLDIR)/lib/libcrypto.a $(REGEXPSOBJS) -luser32 -lgdi32 -ladvapi32

mingwMain.o: %.o: %.cpp
	$(CC) $(CFLAGS) -c -DUNICODE -D_UNICODE  -o $@  $(@:.o=.cpp)

vfsctl.exe: vfsctl.cpp globals.h
	 $(CC) $(CFLAGS) -o $@ vfsctl.cpp -luser32 -lgdi32 -lws2_32

dkmount.exe: dkmount.cpp mingwMain.o
	$(CC) $(CFLAGS) -DMOUNTER_MAIN -DUNICODE -D_UNICODE -o $@  dkmount.cpp mingwMain.o

exewrap.exe: exewrap.cpp mingwMain.o
	$(CC) $(CFLAGS) -DUNICODE -D_UNICODE -o $@  exewrap.cpp mingwMain.o

$(REGEXPSOBJS): %.o: %.c
	gcc -I$(REGEXPDIR) -c -o $@ $(@:.o=.c)

clean:
	rm -f *.o *.exe $(REGEXPSOBJS)
