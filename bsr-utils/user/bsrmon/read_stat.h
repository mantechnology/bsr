#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COLLECTION_TIME_LENGTH 23

struct perf_stat {
	unsigned long long priv;
	unsigned long long min;
	unsigned long long max;
	unsigned long long sum;
	unsigned long cnt;
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


struct io_perf_stat {
	struct perf_stat iops;
	struct perf_stat kbs;
	ULONG_PTR ios;
	ULONG_PTR kb;
};

struct req_perf_stat {
	struct perf_stat before_queue;
	struct perf_stat before_al_begin;
	struct perf_stat in_actlog;
	struct perf_stat submit;
	struct perf_stat bio_endio;
	struct perf_stat destroy;
	struct perf_stat before_bm_write;
	struct perf_stat after_bm_write;
	struct perf_stat after_sync_page;
};


// BSR-765 add AL performance aggregation
struct al_perf_stat {
	unsigned long cnt;
	unsigned long max;
	ULONG_PTR sum;
};

struct al_stat {
	unsigned int nr_elements;
	struct al_perf_stat used;
	ULONG_PTR hits;
	ULONG_PTR misses;
	ULONG_PTR starving;
	ULONG_PTR locked;
	ULONG_PTR changed;
	struct al_perf_stat wait;
	struct al_perf_stat pending;
	unsigned int e_starving;
	unsigned int e_pending;
	unsigned int e_used;
	unsigned int e_busy;
	unsigned int e_wouldblock;
};

// for report
void read_io_stat_work(char *path, struct time_filter *tf);
void read_io_complete_work(char *path, struct time_filter *tf);
void read_req_stat_work(char *path, char *resname, struct time_filter *tf);
void read_memory_work(char *path, struct time_filter *tf);
// BSR-764
void read_peer_stat_work(char *path, char *resname, int type, struct time_filter *tf);
// BSR-765
void read_al_stat_work(char *path, struct time_filter *tf);

// for watch
void watch_io_stat(char *path, bool scroll);
void watch_io_complete(char *path, bool scroll);
void watch_req_stat(char *path, bool scroll);
void watch_network_speed(char *path, bool scroll);
void watch_sendbuf(char *path, bool scroll);
void watch_memory(char *path, bool scroll);
// BSR-764
void watch_peer_req_stat(char *path, bool scroll);
// BSR-765
void watch_al_stat(char *path, bool scroll);
// BSR-838
void watch_peer_resync_ratio(char *path, bool scroll);

