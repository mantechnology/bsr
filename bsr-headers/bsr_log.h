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

typedef struct _CLI_LOG_MAX_COUNT {
	int			nType;
	int			nMaxCount;
}CLI_LOG_MAX_COUNT, *PCLI_LOG_MAX_COUNT;

// DW-1153 debug oos.
#define _DEBUG_OOS

#define LOGGING_TYPE_SYSLOG		0
#define LOGGING_TYPE_DBGLOG		1
// DW-1961 add logging type
#define LOGGING_TYPE_FEATURELOG 2

// DW-2008 log level,type string
static const char * const g_default_lv_str[] = { "emerg", "alert", "criti", "err", "warning", "notice", "info", "debug" };
#ifdef __KERNEL__
static const char * const g_log_type_str[] = { "sys", "dbg", "feature" };
#endif
// DW-2099
#ifndef __KERNEL__
static const char * const g_feature_lv_str[] = { "none", "oos", "latency", "verify" };
#endif

#define LOG_DEFAULT_MAX_LEVEL 8
#define LOG_FEATURE_MAX_LEVEL (1 << 3)


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
	KERN_OOS_NUM,
	KERN_LATENCY_NUM,
	KERN_NUM_END
};


/* Log level value is 32-bit integer
00000000 00000000 00000000 00000000
||| 3 bit between 0 ~ 2 indicates system event log level (0 ~ 7)
|||	   3 bit between 3 ~ 5 indicates debug print log level (0 ~ 7)
||	   2 bit indicates feature log flag (0x01: oos trace, 0x02: latency)
*/
#define LOG_LV_BIT_POS_EVENTLOG		(0)
#define LOG_LV_BIT_POS_DBG			(LOG_LV_BIT_POS_EVENTLOG + 3)
#define LOG_LV_BIT_POS_FEATURELOG	(LOG_LV_BIT_POS_DBG + 3)

// Default values are used when log_level value doesn't exist.
#define LOG_LV_DEFAULT_EVENTLOG	KERN_ERR_NUM
#define LOG_LV_DEFAULT_DBG		KERN_INFO_NUM
#define LOG_LV_DEFAULT_FEATURE		0
#define LOG_LV_DEFAULT			(LOG_LV_DEFAULT_EVENTLOG << LOG_LV_BIT_POS_EVENTLOG) | (LOG_LV_DEFAULT_DBG << LOG_LV_BIT_POS_DBG) 

// BSR-579
#define LOG_FILE_COUNT_DEFAULT	15

#define LOG_LV_MASK			0x7


//

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
	atomic_set(&g_dbglog_lv_min, (log_level >> LOG_LV_BIT_POS_DBG) & LOG_LV_MASK);	\
	atomic_set(&g_featurelog_flag, (log_level >> LOG_LV_BIT_POS_FEATURELOG) & LOG_LV_MASK);


#define Get_log_lv() \
	(atomic_read(&g_eventlog_lv_min) << LOG_LV_BIT_POS_EVENTLOG) | (atomic_read(&g_dbglog_lv_min) << LOG_LV_BIT_POS_DBG) | (atomic_read(&g_featurelog_flag) << LOG_LV_BIT_POS_FEATURELOG)

#endif

// BSR-605
#define CLI_LOG_FILE_MAX_SIZE (1024 * 1024 * 5)
#define CLI_LOG_FILE_MAX_DEFAULT_COUNT 2

// BSR-605 the type of cli is determined by the offset position per bit.
#define BSR_ADM_LOG_FILE_MAX_COUNT 0
#define BSR_SETUP_LOG_FILE_MAX_COUNT 8
#define BSR_META_LOG_FILE_MAX_COUNT 16

#define LOG_MAX_FILE_COUNT_MASK 255
#define BSR_CLI_LOG_FILE_MAX_COUT_VALUE_REG "cli_log_file_max_count"

#ifdef _LIN
// BSR-605
#define BSR_CLI_LOG_FILE_MAXCNT_REG	"/etc/bsr.d/.cli_log_file_max_count"

// BSR-584
#define BSR_LOG_LEVEL_REG		"/etc/bsr.d/.log_level"
#define BSR_LOG_FILE_MAXCNT_REG	"/etc/bsr.d/.log_file_max_count"
// BSR-597
#define BSR_LOG_FILE_PATH "/var/log/bsr"
#define BSR_LOG_FILE_NAME "bsrlog.txt"
#define BSR_LOG_ROLLING_FILE_NAME "bsrlog.txt_"
#endif

#endif