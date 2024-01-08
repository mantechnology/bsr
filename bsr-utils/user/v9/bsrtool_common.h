#ifndef BSRTOOL_COMMON_H
#define BSRTOOL_COMMON_H

#include "bsr_endian.h"
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#ifdef _LIN 
#include <linux/major.h>
#else
// BSR-1109
#include <sys/cygwin.h>
#endif
#include "shared_tool.h"

#define LANANA_BSR_MAJOR 147	/* we should get this into linux/major.h */
#ifndef BSR_MAJOR
#define BSR_MAJOR LANANA_BSR_MAJOR
#elif (BSR_MAJOR != LANANA_BSR_MAJOR)
# error "FIXME unexpected BSR_MAJOR"
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(A) (sizeof(A)/sizeof(A[0]))
#endif

/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 *
 * The implementation uses gcc's reluctance to create a negative array, but
 * gcc (as of 4.4) only emits that error for obvious cases (eg. not arguments
 * to inline functions).  So as a fallback we use the optimizer; if it can't
 * prove the condition is false, it will cause a link error on the undefined
 * "__build_bug_on_failed".  This error message can be harder to track down
 * though, hence the two different methods.
 */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#else
extern int __build_bug_on_failed;
#define BUILD_BUG_ON(condition)                                 \
	do {                                                    \
		((void)sizeof(char[1 - 2*!!(condition)]));      \
		if (condition) __build_bug_on_failed = 1;       \
		} while(false)
#endif

/* Flags which used to be in enum mdf_flag before version 09 */
enum mdf_flag_08 {
	MDF_CONNECTED_IND =  1 << 2,
	MDF_FULL_SYNC =      1 << 3,
	MDF_PEER_OUT_DATED = 1 << 5,
	MDF_FENCING_IND =    1 << 8,
};

struct option;

extern void dt_release_lockfile(int bsr_fd);
extern unsigned long long m_strtoll(const char* s,const char def_unit);
extern void dt_print_uuids(const uint64_t* uuid, unsigned int flags);
extern void dt_pretty_print_uuids(const uint64_t* uuid, unsigned int flags);

void dt_print_v9_uuids(const uint64_t*, unsigned int, unsigned int);
void dt_pretty_print_v9_uuids(const uint64_t*, unsigned int, unsigned int);

const char *get_hostname(void);

#define GIT_HASH_BYTE   20
#define SRCVERSION_BYTE 12     /* actually 11 and a half. */
#define SRCVERSION_PAD (GIT_HASH_BYTE - SRCVERSION_BYTE)
#define SVN_STYLE_OD  16

struct version {
	uint32_t svn_revision;
	char git_hash[GIT_HASH_BYTE];
	struct {
		unsigned major, minor, sublvl, patch;
	} version;
	unsigned version_code;
};

enum driver_version_policy {
    _STRICT,
	FALLBACK_TO_UTILS
};
extern const struct version *bsr_driver_version(enum driver_version_policy fallback);
extern const struct version *bsr_utils_version(void);
extern const char *escaped_version_code_kernel(void);
extern int version_code_kernel(void);
extern int version_code_userland(void);
extern int version_equal(const struct version *rev1, const struct version *rev2);
extern void config_help_legacy(const char * const tool, const struct version * const driver_version);
extern void add_lib_bsr_to_path(void);
extern uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length);

#ifdef _WIN
#define UTRACE(format, arg...) fprintf(stderr, "[%s|%d] "format, __FUNCTION__, __LINE__, ##arg)
#endif

// BSR-604
#define LEVEL_OFFSET 9

enum cli_log_level {
	ERROR_LEVEL,
	WARNING_LEVEL,
	INFO_LEVEL,
	TRACE_LEVEL
};

// BSR-604 the executable name used as the log file name.
extern char *lprogram;
extern char *lcmd;
// BSR-1031
extern int lstatus; // is status cmd
extern char execution_log[512]; // command execution startup log
// BSR-1112
extern char lpath[256];

// BSR-604 write log files
extern void bsr_write_log(const char* func, int line, enum cli_log_level level, bool write_continued, bool line_break, const char* fmt, ...);
extern void bsr_write_vlog(const char* func, int line, enum cli_log_level level, const char *fmt, va_list args);

// BSR-614 default log level is info
extern int llevel;

// BSR-1112
extern void get_log_path();
// BSR-1031
extern void set_exec_log(int argc, char** argv);
extern void bsr_exec_log();
extern void bsr_done_log(int rv);


FILE *bsr_open_log();

#define CLI_ERRO_LOG(continued, linebreak, format, arg...) bsr_write_log(__FUNCTION__, __LINE__, ERROR_LEVEL, continued, linebreak, format, ##arg) 
#define CLI_WRAN_LOG(continued, format, arg...) bsr_write_log(__FUNCTION__, __LINE__, WARNING_LEVEL, continued, true, format, ##arg)
#define CLI_INFO_LOG(continued, format, arg...) bsr_write_log(__FUNCTION__, __LINE__, INFO_LEVEL, continued, true, format, ##arg)
#define CLI_TRAC_LOG(continued, format, arg...) bsr_write_log(__FUNCTION__, __LINE__, TRACE_LEVEL, continued, true, format, ##arg)

#define CLI_ERRO_VLOG(format, arg...) bsr_write_vlog(__FUNCTION__, __LINE__, ERROR_LEVEL, format, arg) 


#define CLI_ERRO_LOG_PEEROR(continued, msg) \
		{	\
			CLI_ERRO_LOG(continued, true, msg); \
			perror(msg); \
			fprintf(stderr, "\n"); \
		} while(false)

#define CLI_INFO_LOG_PRINT(continued, format, arg...) \
		{	\
			CLI_INFO_LOG(continued, format, ##arg); \
			printf(format, ##arg); \
			printf("\n"); \
		} while(false)

#define CLI_WRAN_LOG_PRINT(continued, format, arg...) \
		{	\
			CLI_WRAN_LOG(continued, format, ##arg); \
			printf(format, ##arg); \
			printf("\n"); \
		} while(false)

#define CLI_ERRO_LOG_STDERR_NO_LINE_BREAK(continued, format, arg...) \
		{	\
			CLI_ERRO_LOG(continued, false, format, ##arg); \
			fprintf(stderr, format, ##arg); \
		} while(false)

#define CLI_ERRO_LOG_STDERR(continued, format, arg...) \
		{	\
			CLI_ERRO_LOG(continued, true, format, ##arg); \
			fprintf(stderr, format, ##arg); \
			fprintf(stderr, "\n"); \
		} while(false)

#define CLI_ERRO_VLOG_STDERR(format, arg)  \
		{	\
			CLI_ERRO_VLOG(format, arg); \
			va_end(arg);	\
			va_start(arg, format); \
			vfprintf(stderr, format, arg); \
		} while(false)

#endif

