#ifndef __BSR_IOCTL_H__
#define __BSR_IOCTL_H__

#include "bsr_log.h"
#ifdef _WIN
#include "windows/ioctl.h"
#else // _LIN
#include "linux/bsr_linux_ioctl.h"
#endif

// BSR-764 add I/O performance degradation simulation
#define SIMUL_PERF_DEGR_FLAG0		0 // disable
#define SIMUL_PERF_DEGR_FLAG1		1 // enable

#define SIMUL_PERF_DELAY_TYPE0		0 // write I/O occurrence
#define SIMUL_PERF_DELAY_TYPE1		1 // Master I/O completion
#define SIMUL_PERF_DELAY_TYPE2		2 // Active log commit
#define SIMUL_PERF_DELAY_TYPE3		3 // bio submit
#define SIMUL_PERF_DELAY_TYPE4		4 // socket send
#define SIMUL_PERF_DELAY_TYPE5		5 // socket receive
#define SIMUL_PERF_DELAY_TYPE6		6 // peer request submit


typedef struct _SIMULATION_PERF_DEGR {
	ULONG 		flag;		    // 0: disable, 1: enable
	ULONG		type;		    // delay Type
	ULONG		delay_time;     // delay time
} SIMULATION_PERF_DEGR, *PSIMULATION_PERF_DEGR;

typedef struct _HANDLER_INFO {
	bool				use;
} HANDLER_INFO, *PHANDLER_INFO;

// BSR-1048
typedef struct _WRITE_KERNEL_LOG {
	int level;
	int length;
	char message[MAX_BSRLOG_BUF];
} WRITE_KERNEL_LOG, *PWRITE_KERNEL_LOG;

// BSR-1072
typedef struct _KERNEL_PANIC_INFO {
	int enable;
	int occurrence_time;
	// BSR-1072 as soon as force is set, it causes a system panic. 
	int force;
} KERNEL_PANIC_INFO, *PKERNEL_PANIC_INFO;

#endif