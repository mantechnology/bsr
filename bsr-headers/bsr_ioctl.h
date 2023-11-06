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

#define MAX_PANIC_CERT_BUF			40

typedef struct _SIMULATION_PERF_DEGR {
	ULONG 		flag;		    // 0: disable, 1: enable
	ULONG		type;		    // delay Type
	ULONG		delay_time;     // delay time
} SIMULATION_PERF_DEGR, *PSIMULATION_PERF_DEGR;

typedef struct _HANDLER_INFO {
	bool				use;
} HANDLER_INFO, *PHANDLER_INFO;

// BSR-1060
typedef struct _HANDLER_TIMEOUT_INFO {
	int				timeout;
} HANDLER_TIMEOUT_INFO, *PHANDLER_TIMEOUT_INFO;

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
	// BSR-1073 saves a string for confirmation in the event of an arbitrary panic.
	char cert[MAX_PANIC_CERT_BUF];
} KERNEL_PANIC_INFO, *PKERNEL_PANIC_INFO;

// BSR-1039
#define HOLD_STATE_TYPE_UNKNOWN		0
#define HOLD_STATE_TYPE_CONNECT		1
#define HOLD_STATE_TYPE_REPL		2
#define HOLD_STATE_TYPE_DISK		3

typedef struct _HOLD_STATE {
	int type; 
	int state;
} HOLD_STATE, *PHOLD_STATE;

enum bsrmon_type
{
	BSRMON_IO_STAT,
	BSRMON_IO_COMPLETE,
	BSRMON_IO_PENDING,  // BSR-1054
	BSRMON_AL_STAT,
	BSRMON_PEER_REQUEST,
	BSRMON_REQUEST,
	BSRMON_RESYNC_RATIO,
	BSRMON_NETWORK_SPEED,
	BSRMON_SEND_BUF,
	BSRMON_MEMORY,
	BSRMON_ALL_STAT,
};

// BSR-1138
#define DEFAULT_BSRMON_TYPES ((1 << BSRMON_ALL_STAT) - 1)
#endif