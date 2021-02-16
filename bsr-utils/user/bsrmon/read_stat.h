#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bsrmon.h"


struct perf_stat {
	unsigned long priv;
	unsigned long min;
	unsigned long max;
	unsigned long cnt;
	ULONG_PTR sum;
	bool duplicate;
};

#ifdef _WIN
struct kmem_perf_stat {
	/* bytes */
	struct perf_stat total; /* TotalUsed */ 
	struct perf_stat npused; /* NonPagedUsed */ 
	struct perf_stat pused; /* PagedUsed */ 
};

struct umem_perf_stat {
	/* bytes */
	struct perf_stat wss;  /* WorkingSetSize */ 
	struct perf_stat qpp;  /* QuotaPagedPoolUsage */ 
	struct perf_stat qnpp; /* QuotaNonPagedPoolUsage */ 
	struct perf_stat pfu;  /* PagefileUsage */
};
#else // _LIN
struct kmem_perf_stat {
	/* bytes */
	struct perf_stat req; /* BSR_REQ */ 
	struct perf_stat al;  /* BSR_AL */ 
	struct perf_stat bm;  /* BSR_BM */ 
	struct perf_stat ee;  /* BSR_EE */ 
};

struct umem_perf_stat {
	/* kbytes */
	struct perf_stat rsz;
	struct perf_stat vsz;
};
#endif

// for report
void read_io_stat_work(char *path);
void read_io_complete_work(char *path);
void read_req_stat_work(char *path);
void read_req_peer_stat_work(char *path, char *peer_name);
void read_network_speed_work(char *path, char *peer_name, bool);
void read_sendbuf_work(char *path, char *peer_name, bool);
void read_memory_work(char *path);

// for watch
void watch_io_stat(char *cmd);
void watch_io_complete(char *cmd);
void watch_req_stat(char *cmd);
void watch_network_speed(char *cmd);
void watch_sendbuf(char *cmd);
void watch_memory(char *cmd);