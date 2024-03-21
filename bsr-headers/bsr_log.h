#ifndef __LOGGING_H__
#define __LOGGING_H__


#if defined(_LIN) && !defined(__KERNEL__)

#ifndef min
#define min(x,y) ((x) < (y) ? (x) : (y))
#endif

#define ERROR_INVALID_PARAMETER 1
#define ERROR_SUCCESS 	0
#define ERROR_INVALID_DATA	-1
#define MAX_PATH        260
#define BOOLEAN			bool
#define DWORD			unsigned int
#define UCHAR			unsigned char
#define LPCTSTR			const char * 
#define LPCSTR			const char *
#define ULONG			unsigned int
#define GetLastError()  errno
#define ERROR_FILE_NOT_FOUND	2/*ENOENT*/
#endif


typedef struct _LOGGING_MIN_LV {
	int			nType;
	int			nErrLvMin;
}LOGGING_MIN_LV, *PLOGGING_MIN_LV;

// BSR-654
typedef struct _DEBUG_LOG_CATEGORY {
	int			nType; // 0 : enable, 1 : disable
	unsigned int			nCategory;
}DEBUG_LOG_CATEGORY, *PDEBUG_LOG_CATEGORY;

typedef struct _CLI_LOG_MAX_COUNT {
	int			nType;
	int			nMaxCount;
}CLI_LOG_MAX_COUNT, *PCLI_LOG_MAX_COUNT;

// DW-1153 debug oos.
#define _DEBUG_OOS

#define LOGGING_TYPE_SYSLOG		0
#define LOGGING_TYPE_DBGLOG		1

// DW-2008 log level,type string
static const char * const g_default_lv_str[] = { "emerg", "alert", "criti", "err", "warning", "notice", "info", "debug" };
#ifdef __KERNEL__
static const char * const g_log_type_str[] = { "sys", "dbg" };
#endif
// DW-2099
#ifndef __KERNEL__
static const char * const g_log_category_str[] = { 
	"VOLUME", "IO", "IO_ERROR", "BITMAP",
	"LRU", "REQUEST", "PEER_REQUEST", "RESYNC_OV", "REPLICATION", 
	"CONNECTION", "UUID", "TWOPC", "THREAD", "SEND_BUFFER", "STATE", 
	"SOCKET", "DRIVER", "NETLINK", "GENL", "PROTOCOL", "MEMORY", "LOG", 
	"LATENCY", "VERIFY", "OUT_OF_SYNC", "ETC" };
#endif

#define LOG_DEFAULT_MAX_LEVEL 8
#define LOG_CATEGORY_MAX 26


// DW-2008 move here from bsr_window.h
enum
{
	KERN_EMERG_NUM = 0,
	KERN_ALERT_NUM,
	KERN_CRIT_NUM,
	KERN_ERR_NUM,
	KERN_WARNING_NUM,
	KERN_NOTICE_NUM,
	KERN_INFO_NUM,
	KERN_DEBUG_NUM,
	KERN_NUM_END
};


/* Log level value is 32-bit integer
00000000 00000000 00000000 00000000
||| 3 bit between 0 ~ 2 indicates system event log level (0 ~ 7)
|||	   3 bit between 3 ~ 5 indicates debug print log level (0 ~ 7)
*/
#define LOG_LV_BIT_POS_EVENTLOG		(0)
#define LOG_LV_BIT_POS_DBG			(LOG_LV_BIT_POS_EVENTLOG + 3)

// Default values are used when log_level value doesn't exist.
#define LOG_LV_DEFAULT_EVENTLOG	KERN_ERR_NUM
#define LOG_LV_DEFAULT_DBG		KERN_INFO_NUM
#define LOG_LV_DEFAULT			(LOG_LV_DEFAULT_EVENTLOG << LOG_LV_BIT_POS_EVENTLOG) | (LOG_LV_DEFAULT_DBG << LOG_LV_BIT_POS_DBG) 

// BSR-579
#define LOG_FILE_COUNT_DEFAULT	15

#define LOG_LV_MASK			0x7


// BSR-648
enum BSR_LOG_CATEGORY
{
	BSR_LC_VOLUME = 0,
	BSR_LC_IO,
	BSR_LC_IO_ERROR,
	BSR_LC_BITMAP,
	BSR_LC_LRU,
	BSR_LC_REQUEST,
	BSR_LC_PEER_REQUEST,
	BSR_LC_RESYNC_OV,
	BSR_LC_REPLICATION,
	BSR_LC_CONNECTION,
	BSR_LC_UUID,
	BSR_LC_TWOPC,
	BSR_LC_THREAD,
	BSR_LC_SEND_BUFFER,
	BSR_LC_STATE,
	BSR_LC_SOCKET,
	BSR_LC_DRIVER,
	BSR_LC_NETLINK,
	BSR_LC_GENL,
	BSR_LC_PROTOCOL,
	BSR_LC_MEMORY,
	BSR_LC_LOG,
	BSR_LC_LATENCY,
	BSR_LC_VERIFY,
	BSR_LC_OUT_OF_SYNC,
	BSR_LC_ETC,
};

// BSR-654 The default values are those excluding latency, verifi, and out of sync.
#define DEBUG_LOG_OUT_PUT_CATEGORY_DEFAULT ((1 << BSR_LC_VOLUME) | (1 << BSR_LC_IO) | (1 << BSR_LC_IO_ERROR) | \
									(1 << BSR_LC_BITMAP) | (1 << BSR_LC_LRU) | (1 << BSR_LC_REQUEST) | \
									(1 << BSR_LC_PEER_REQUEST) | (1 << BSR_LC_RESYNC_OV) | (1 << BSR_LC_REPLICATION) | \
									(1 << BSR_LC_CONNECTION) | (1 << BSR_LC_UUID) | (1 << BSR_LC_TWOPC) | \
									(1 << BSR_LC_THREAD) | (1 << BSR_LC_SEND_BUFFER) | (1 << BSR_LC_STATE) | \
									(1 << BSR_LC_SOCKET) | (1 << BSR_LC_DRIVER) | (1 << BSR_LC_NETLINK) | \
									(1 << BSR_LC_GENL) | (1 << BSR_LC_PROTOCOL) | (1 << BSR_LC_MEMORY) | \
									(1 << BSR_LC_LOG) | (1 << BSR_LC_ETC))
// | (1 << BSR_LC_LATENCY) | (1 << BSR_LC_VERIFY) | (1 << BSR_LC_OUT_OF_SYNC) 


#ifdef _DEBUG_OOS
#define FRAME_DELIMITER		"@"
#define OOS_TRACE_STRING	"oos_trace"
#define STACK_FRAME_CAPTURE_COUNT	(10)
#define MAX_FUNC_NAME_LEN		(50)
#define MAX_FUNCS_STR_LEN		(MAX_FUNC_NAME_LEN * (STACK_FRAME_CAPTURE_COUNT + 1))
#define MAX_FUNC_ADDR_LEN		(20)
#endif

// BSR-577
#define IDX_OPTION_LENGTH			0x01
#define MAX_BSRLOG_BUF				512
#define LOGBUF_MAXCNT				100000
#define MAX_BSR_MISSING_BUF			128

#ifdef _LIN 
#ifndef LONGLONG
#define LONGLONG		long long int
#endif
#endif

typedef struct _BSR_LOG {
	LONGLONG 	totalcnt;
	char		LogBuf[1]; // LOGBUF_MAXCNT*MAX_BSRLOG_BUF
}BSR_LOG, *PBSR_LOG;

#define BSR_LOG_SIZE				((LOGBUF_MAXCNT*(MAX_BSRLOG_BUF + IDX_OPTION_LENGTH)) + sizeof(LONGLONG))


#ifdef __KERNEL__

#define Set_log_lv(log_level) \
	atomic_set(&g_eventlog_lv_min, (log_level >> LOG_LV_BIT_POS_EVENTLOG) & LOG_LV_MASK);	\
	atomic_set(&g_dbglog_lv_min, (log_level >> LOG_LV_BIT_POS_DBG) & LOG_LV_MASK);	


#define Get_log_lv() \
	(atomic_read(&g_eventlog_lv_min) << LOG_LV_BIT_POS_EVENTLOG) | (atomic_read(&g_dbglog_lv_min) << LOG_LV_BIT_POS_DBG)

#endif

// BSR-605
#define CLI_LOG_FILE_MAX_SIZE (1024 * 1024 * 5)
#define CLI_LOG_FILE_MAX_COUNT_DEFAULT 3

// BSR-605 the type of cli is determined by the offset position per bit.
#define BSR_ADM_LOG_FILE_MAX_COUNT 0
#define BSR_SETUP_LOG_FILE_MAX_COUNT 8
#define BSR_META_LOG_FILE_MAX_COUNT 16

#define BSR_LOG_MAX_FILE_COUNT_MASK 255
#define BSR_CLI_LOG_FILE_MAX_COUT_VALUE_REG "cli_log_file_max_count"

#ifdef _LIN
// BSR-605
#define BSR_CLI_LOG_FILE_MAXCNT_REG	"/etc/bsr.d/.cli_log_file_max_count"

// BSR-973
#define BSR_FAST_SYNC_REG	"/etc/bsr.d/.use_fast_sync"

// BSR-584
#define BSR_LOG_LEVEL_REG		"/etc/bsr.d/.log_level"
#define BSR_LOG_FILE_MAXCNT_REG	"/etc/bsr.d/.log_file_max_count"

// BSR-654
#define BSR_DEBUG_LOG_CATEGORY_REG	"/etc/bsr.d/.debuglog_category"

// BSR-1031
#define BSR_STATUSCMD_LOGGING_REG "/etc/bsr.d/.statuscmd_logging"

// BSR-1112
#define BSR_LOG_PATH_REG "/etc/bsr.d/.log_path"
// BSR-597
#define BSR_LOG_FILE_PATH "/var/log/bsr"
#define BSR_LOG_FILE_NAME "bsr.log"
#define BSR_LOG_ROLLING_FILE_NAME "bsr.log_"
#endif

#endif