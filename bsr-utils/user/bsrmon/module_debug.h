#ifdef _WIN
#include <windows.h>
#include "ioctl.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <set>
#include <iostream>

#ifdef _LIN
#include <dirent.h>
#define DEBUGFS_ROOT "/sys/kernel/debug/bsr"
#endif

#define MAX_DEBUG_BUF_SIZE 4096
#define MAX_PATH 260

#define DEFAULT_FILE_ROLLING_SIZE 50
#define DEFAULT_FILE_ROLLONG_CNT 3

#ifdef _WIN
#define _SEPARATOR_ "\\"
#else // _LIN
#define _SEPARATOR_ "/"
#endif

enum set_option_type
{
	PERIOD,
	FILE_ROLLING_SIZE,
	FILE_ROLLING_CNT,
};

enum get_info_type
{
	RESOURCE,
	CONNECTION,
	VOLUME,
};

enum get_debug_type
{
	IO_STAT,
	IO_COMPLETE,
	REQUEST,
	NETWORK_SPEED,
	SEND_BUF,
	MEMORY,
};

struct volume {
	int vnr;
	struct volume* next;
};

struct connection {
	char name[2][20];
	int node_id[2];
};

struct resource {
	char name[10];
	struct connection *conn;
	struct volume *vol;
	struct resource* next;
};

#ifdef _LIN
#define fopen_s(pFile, filename, mode) ((*pFile=fopen(filename, mode)) == NULL)
#define sprintf_s sprintf
#endif

#ifdef _WIN
HANDLE OpenDevice(PCHAR devicename);
DWORD GetBsrDebugInfo(PBSR_DEBUG_INFO pDebugInfo);
// BSR-37
enum BSR_DEBUG_FLAGS ConvertToBsrDebugFlags(char *str);
#endif

void* exec_pipe(enum get_info_type info_type, char *res_name);
void freeResource(struct resource* res);
struct resource* GetResourceInfo();
int CheckResourceInfo(char* resname, int node_id, int vnr);

#ifdef _WIN
PBSR_DEBUG_INFO GetDebugInfo(enum BSR_DEBUG_FLAGS flag, struct resource* res, int val);
#endif
char* GetDebugToBuf(enum get_debug_type debug_type, struct resource *res);
int GetDebugToFile(enum get_debug_type debug_type, struct resource *res, char * respath, char * currtime);
int GetMemInfoToFile(char *path, char * currtime);

extern long GetOptionValue(enum set_option_type option_type);