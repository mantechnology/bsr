#include <sys/stat.h>
#include <set>
#include <iostream>

#ifdef _LIN
#include <dirent.h>
#define DEBUGFS_ROOT "/sys/kernel/debug/bsr"
#endif

#define MAX_DEBUG_BUF_SIZE 4096


enum get_info_type
{
	RESOURCE,
	CONNECTION,
	VOLUME,
};


#define RESOURCE_NAME_MAX 128
#define CONNECTION_NAME_MAX 64

struct volume {
	int vnr;
	struct volume* next;
};

struct connection {
	char name[CONNECTION_NAME_MAX];
	int node_id;
	struct connection* next;
};

struct resource {
	char name[RESOURCE_NAME_MAX];
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

// BSR-940
void* exec_pipe(enum get_info_type info_type, char *res_name);
void freeResource(struct resource* res);
struct resource* GetResourceInfo(char * name);
int CheckResourceInfo(char* resname, int node_id, int vnr);

#ifdef _WIN
PBSR_DEBUG_INFO GetDebugInfo(enum BSR_DEBUG_FLAGS flag, struct resource* res, int vnr, int peer_node_id);
#endif
char* GetDebugToBuf(enum bsrmon_type debug_type, struct resource *res);
int GetDebugToFile(enum bsrmon_type debug_type, struct resource *res, char * respath, char * currtime);
int GetMemInfoToFile(char *path, char * currtime);

// BSR-740
int InitPerfType(enum bsrmon_type debug_type, struct resource *res);
