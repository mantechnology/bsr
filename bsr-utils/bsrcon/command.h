#ifdef _WIN
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "mvol.h"
#include "log_manager.h"
// DW-2166
#include <setupapi.h>
#include <stdlib.h>
#include <Shlwapi.h>
#include <Wincrypt.h>
#else // _LIN
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mvol.h"
#endif

#ifdef _WIN
#define BUFSIZE 1024
#define MD5LEN  16

const TCHAR gBsrRegistryPath[] = _T("System\\CurrentControlSet\\Services\\bsrvflt\\volumes");
const TCHAR gBsrRegistry[] = _T("System\\CurrentControlSet\\Services\\bsrvflt");

int get_handler_timeout();
DWORD delete_volume_reg(TCHAR letter);

int generating_md5(char* fullPath);
int driver_Install_Inf(wchar_t* session, char* fullPath);
DWORD RunProcess(char* command, char* workingDirectory, char **out);
#endif

BOOLEAN get_engine_log_file_max_count(int *max);
BOOLEAN get_cli_log_file_max_count(int *max);
DWORD set_cli_log_file_max_count(int cli_type, int max);
DWORD get_fast_sync();
DWORD set_fast_sync(DWORD fast_sync);
BOOLEAN get_log_level(int *sys_evtlog_lv, int *dbglog_lv);
BOOLEAN get_handler_use();
BOOLEAN get_debug_log_enable_category(int *dbg_ctgr);
DWORD set_statuscmd_logging(DWORD logging);
DWORD get_statuscmd_logging();
DWORD set_log_path(char *newPath);
DWORD get_log_path();
