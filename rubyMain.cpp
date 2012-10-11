#include <windows.h>
#include <stdio.h>
#include "ruby.h"
#include "globals.h"
#include <io.h>
#include <sys/fcntl.h>
#include "syshooks.h"

static int dbgLevel;

void InitDebug(char *logDir)
{
	char logFile[MAX_PATH];
	printf("InitDebug %s\n", logDir);
	sprintf(logFile, "%s/rubylog_%d.log", logDir, getpid());
	Logger::InitLog(logFile);
}


#define DBG1 (dbgLevel>= 1) && Logger::debugEx
#define DBG2 (dbgLevel>= 2) && Logger::debugEx

extern "C" {
typedef VALUE (*PROCTYPE)(ANYARGS);
RUBY_EXTERN VALUE rb_mKernel;
RUBY_EXTERN VALUE rb_cISeq;
RUBY_EXTERN VALUE rb_iseq_load(VALUE data, VALUE parent, VALUE opt);
typedef void* NODE;
extern void rb_enc_init();
VALUE rb_parser_new(void);
NODE *rb_parser_compile_cstr(volatile VALUE, const char*, const char*, int, int);
NODE *rb_parser_compile_string(volatile VALUE, const char*, VALUE, int);
NODE *rb_parser_compile_file(volatile VALUE, const char*, VALUE, int);
int ruby_run_node(void *n);
VALUE rb_iseq_disasm(VALUE self);
VALUE rb_iseq_new_top(NODE *node, VALUE name, VALUE path, VALUE absolute_path, VALUE parent);
VALUE rb_iseq_eval(VALUE iseqval);
};

#if 0
#include "rbRedef.h"

PROCTYPE RbVars[MAX_RBVARS];
HMODULE hRubyDLL;

PROCTYPE getRbVar(int id)
{
	PROCTYPE var = RbVars[id];
	if (var)
		return var;
	if (!hRubyDLL)
	{
		DBG1("Load %s\n", RUBYDLL);
		hRubyDLL = LoadLibrary(RUBYDLL);
		if (!hRubyDLL)
		{
			DBG1("ERROR: failed to load RubyDLL\n");
			exit(1);
		}
		var = (PROCTYPE) GetProcAddress(hRubyDLL, RbVarNames[id]);
		RbVars[id] = var;
		if (!var)
		{
			DBG1("ERROR: failed to get %s::%s \n", RbVarNames[id], RUBYDLL);
			exit(1);
		}
		DBG1("@@@ GOT %s\n", RbVarNames[id]);
		return(var);
	}
}
#endif

class DFilePath
{
	char i_str[MAX_PATH];
	public:
	DFilePath(char *path)
	{
		strcpy(i_str, path);
	}
	DFilePath()
	{
		*i_str = 0;
	}
	bool BuildPath(const char *path, bool bExact, const char *oldExt, const char *newExt)
	{
		*i_str = 0;
		char *p = strrchr(path, '.');
		if (p && strcmp(p, oldExt))
			return(false);
		else if (!p && bExact)	// extension is expected
			return(false);
		int len = strlen(path) + strlen(newExt) + 1;
		if (!p)
			strcpy(i_str, path);
		else
			{
			strncpy(i_str, path, (p - path));
			i_str[p-path] = 0;
			}
		strcat(i_str, newExt);
		return(true);
	}

	char*Str()	{return i_str;}
	void operator=(char *str)
	{
		strcpy(i_str, str);
	}

	bool operator==(const char *path)
	{
		const char *p1, *p2;
		for(p1=i_str, p2=path; *p1 && *p2; ++p1, ++p2)
		{
			if (tolower(*p1) != tolower(*p2))
				return(false);
		}
		return (!*p1 && !*p2);
	}
};

DList<DFilePath*> g_reqFileList;

void rbx_load(VALUE fname, int wrap)
{
	DBG2("Calling our rb_load\n");
	rb_load(fname, wrap);
}

static VALUE
iseq_s_load(int argc, VALUE *argv, VALUE self)
{
	rb_eval_string("puts 'calling iseq_s_load'");
    VALUE data, opt=Qnil;
    rb_scan_args(argc, argv, "11", &data, &opt);

    return rb_iseq_load(data, 0, opt);
}

#define RBVM_EXT ".rbc"
void rbx_resolve(int argc, VALUE *argv, VALUE self)
{
	VALUE v_fname=Qnil;
	VALUE v_wrap=0, v_require=0;
	rb_scan_args(argc, argv, "30", &v_fname, &v_wrap, &v_require);
	char* filename = RSTRING_PTR(v_fname);
	DFilePath tmpFilename;
	int wrap = FIX2INT(v_wrap);
	int require = FIX2INT(v_require);
#if 1
	bool isRB = tmpFilename.BuildPath(filename, !require, ".rb", RBVM_EXT);
	if (isRB)
	{
		char *rbcFileName = tmpFilename.Str();
		VALUE v_newPath = rb_str_new(rbcFileName, strlen(rbcFileName));
		VALUE v_tmp = rb_find_file(FilePathValue(v_newPath));
		if (v_tmp)
		{
			char *newPath = RSTRING_PTR(v_newPath);
			if (require)
			{
				for(int i=0; i < g_reqFileList.Count(); i++)
				{
					if (*g_reqFileList[i] == newPath)
					{
					DBG1("++++ ARLEAY LOAD RBC FILE %s (require=%d, loaded=%d)\n", rbcFileName, require);
					return;
					}
				}
				g_reqFileList.AddEntry(new DFilePath(newPath)); 
			}
			DBG1("++++ LOAD RBC FILE %s (require=%d, loaded=%d)\n", rbcFileName, require);
			struct stat sts;
			stat(newPath, &sts);
			int fd = open(newPath, O_RDONLY | O_BINARY, 0666);
			char *buf = new char[sts.st_size+1];
			read(fd, buf, sts.st_size);
			buf[sts.st_size] = 0;

			VALUE str = rb_str_new(buf, sts.st_size);
			VALUE mar = rb_const_get(rb_cObject, rb_intern("Marshal"));
			VALUE code = rb_funcall(mar, rb_intern("restore"), 1, str);
    		code = rb_iseq_load(code, 0, Qnil);
			rb_secure(1);
			rb_iseq_eval(code);
			return;
		}
	}
#endif
	VALUE v_tmp = rb_find_file(FilePathValue(v_fname));
	const char *absPath = v_tmp? RSTRING_PTR(v_tmp): "n/a";

	if (!require)
	{
#if 0
		ZipEntry *pze = zipManager.GetEntry(filename);
		if (pze)
		{
			DBG2("++++ LOAD FROM ZIP FILE %s\n", filename);
			char *buf = pze->Data();
		 	VALUE parser = rb_parser_new();
			VALUE str = rb_str_new(buf, strlen(buf));
			NODE *node = rb_parser_compile_string(parser, filename, str, 1);
			VALUE iseq = rb_iseq_new_top(node, rb_str_new("<top (required)>"), v_fname, v_tmp, Qfalse);
			rb_iseq_eval(iseq);
			return;
		}
#endif
		DBG2("resolve: rbLoad filename=%s, wrap=%d => %s\n", filename, wrap, absPath);
		rb_load(v_fname, wrap);
	}
	else
	{
		DBG2("resolve: rbRequire filename=%s, wrap=%d => %s\n", filename, wrap, absPath);
		rb_require(filename);
	}
}

static const char *kerInitStr = "\
#require \"zlib\"\n\
module Kernel\n\
  alias_method :old_load, :load\n\
  alias_method :old_require, :require\n\
  def load filename, wrap = false\n\
	# puts \"LOAD -> #{filename}\"\n\
	Kernel.resolve filename, wrap, 0\n\
    #old_load filename, wrap\n\
  end\n\
  def require filename = false\n\
	# puts \"REQUIRE -> #{filename}\"\n\
	Kernel.resolve filename, 0, 1\n\
    #old_require filename\n\
  end\n\
end\n";

void initHooks()
{
	rb_eval_string(kerInitStr);
	rb_define_singleton_method(rb_mKernel, "load", (VALUE(*)(ANYARGS))rbx_load, -1);
	rb_define_singleton_method(rb_mKernel, "resolve", (VALUE(*)(ANYARGS))rbx_resolve, -1);
	rb_define_singleton_method(rb_cISeq, "load", (PROCTYPE) iseq_s_load, -1);


#ifndef RUBYDLL
	// built statically
#if 0
	DBG2("Set load path\n");
	VALUE load_path = rb_gv_get("$:");
	
	rb_ary_push(load_path, rb_str_new("D:/Amoria/dev/rubyProject/rubyApp/testing"));
	rb_ary_push(load_path, rb_str_new("C:/ruby193/lib/ruby/site_ruby/1.9.1"));
	rb_ary_push(load_path, rb_str_new("C:/ruby193/lib/ruby/site_ruby/1.9.1/i386-msvcrt"));
	rb_ary_push(load_path, rb_str_new("C:/ruby193/lib/ruby/site_ruby"));
	rb_ary_push(load_path, rb_str_new("C:/ruby193/lib/ruby/vendor_ruby/1.9.1"));
	rb_ary_push(load_path, rb_str_new("C:/ruby193/lib/ruby/vendor_ruby/1.9.1/i386-msvcrt"));
	rb_ary_push(load_path, rb_str_new("C:/ruby193/lib/ruby/vendor_ruby"));
	rb_ary_push(load_path, rb_str_new("C:/ruby193/lib/ruby/1.9.1"));
	rb_ary_push(load_path, rb_str_new("C:/ruby193/lib/ruby/1.9.1/i386-mingw32"));
	//rb_eval_string("puts \"Search path:\" +  $:");
	DBG2("Set load path - OK\n");
#endif
#endif
	
}

/*
 * see http://ruby-doc.org/core-1.8.7/Kernel.html#method-i-load
 * load:
 * Loads and executes the Ruby program in the file filename. If the filename does not resolve to an absolute path, the file is searched for in the library directories listed in $:. If the optional wrap parameter is true, the loaded script will be executed under an anonymous module, protecting the calling program’s global namespace. In no circumstance will any local variables in the loaded file be propagated to the loading environment.
 *
 *
 * require:
 * Ruby tries to load the library named string, returning true if successful. If the filename does not resolve to an absolute path, it will be searched for in the directories listed in $:. If the file has the extension “.rb”, it is loaded as a source file; if the extension is “.so”, “.o”, or “.dll”, or whatever the default shared library extension is on the current platform, Ruby loads the shared library as a Ruby extension. Otherwise, Ruby tries adding “.rb”, “.so”, and so on to the name. The name of the loaded feature is added to the array in $". A feature will not be loaded if it’s name already appears in $". However, the file name is not converted to an absolute path, so that “require 'a';require './a'” will load a.rb twice.
 */

void testStuff()
{
	//rb_eval_string("require \"zlib\"");
	if (true)
		return;
	rb_require("zlib");
	ID mar = rb_intern("Marshal");
	printf("mar = %x\n", mar);
	VALUE myclass = rb_const_get(rb_cObject, rb_intern("Marshal"));
	printf("mar = %x\n", myclass);
	VALUE myclass2 = rb_const_get(rb_cObject, rb_intern("Zlib"));
	printf("zlib = %x\n", myclass2);
}


int main(int argc, char *argv[])
{
	char *dbgStr      = getenv("RA_DEBUG");			// enable debugging
	char *rubyExePath = getenv("RA_RYBY_EXE_PATH"); // will rename ruby.exe path to this
	char *overloadEnv = getenv("RA_RBC_SUPPRT");

	if (dbgStr)
	{
		char *dbgLogDir = getenv("RA_LOGDIR");
		dbgLevel = atoi(dbgStr);
		if (!dbgLogDir)
			dbgLogDir = getenv("TEMP");
		if (!dbgLogDir)
			dbgLogDir = getenv("TMP");
		InitDebug(dbgLogDir);
	}
	//for(int i=0; i < argc; i++) { DBG2("RUBYMAIN: arg[%d] = %s\n", i, argv[i]); }
	initSystemHooks(TRUE, dbgLevel, Logger::debugEx);
	if (rubyExePath)
	{
		// this is to workaround an issue with rails and rubygems that
		// expect the ruby.exe to be under the ruby install directory and generates
		// gem's paths based on it.
		// The hack fakes ruby to think that the running exe is under the install directory
		SysHooksReplaceCommandLine(argv[0], rubyExePath);
	}

	ruby_sysinit(&argc, &argv);
	ruby_init();
	if (overloadEnv)
		initHooks();
	int sts = ruby_run_node(ruby_options(argc, argv));
	return(sts);
}
