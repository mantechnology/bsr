#ifdef _WIN
#include <windows.h>
#include "ioctl.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _LIN
#define DEBUGFS_ROOT "/sys/kernel/debug/bsr"
#endif

#define MAX_DEBUG_BUF_SIZE 4096

enum get_info_type
{
	RESOURCE,
	CONNECTION,
	VOLUME,
};

enum get_debug_type
{
	IO,
	NETWORK_SPEED,
	SEND_BUF,
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

#ifdef _WIN
HANDLE OpenDevice(PCHAR devicename);
DWORD GetBsrDebugInfo(PBSR_DEBUG_INFO pDebugInfo);
// BSR-37
enum BSR_DEBUG_FLAGS ConvertToBsrDebugFlags(char *str);
#endif

void* exec_pipe(enum get_info_type info_type, char *res_name);
void freeResource(struct resource* res);
struct resource* GetResourceInfo();

#ifdef _WIN
PBSR_DEBUG_INFO GetDebugInfo(enum BSR_DEBUG_FLAGS flag, struct resource* res, int val);
#endif
char* GetDebugToBuf(enum get_debug_type debug_type, struct resource *res);