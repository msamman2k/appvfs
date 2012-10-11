#ifndef SYSHOOKS_H
#define SYSHOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

void initSystemHooks(BOOL cmdLineOnly, int dbgLev, int(*logger)(const char *fmt, ...));
void SysHooksReplaceCommandLine(char *origExePath, char *NewExePath);
#ifdef __cplusplus
}
#endif


#endif
