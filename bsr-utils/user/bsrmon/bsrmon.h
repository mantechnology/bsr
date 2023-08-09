#ifdef _WIN
#include <windows.h>
#include "bsr_ioctl.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_BUF_SIZE 4096
#define MAX_PATH 260

#ifdef _WIN
#define _SEPARATOR_ "\\"
#else // _LIN
#define _SEPARATOR_ "/"
#endif


#ifdef _LIN
#define PERIOD_OPTION_PATH "/etc/bsr.d/.bsrmon_period"
#define FILE_SIZE_OPTION_PATH "/etc/bsr.d/.bsrmon_file_size"
#define FILE_CNT_OPTION_PATH "/etc/bsr.d/.bsrmon_file_cnt"
// BSR-1112
#define PERFMON_FILE_PATH "/etc/bsr.d/.log_path"
#define DEFAULT_PERFMON_FILE_PATH "/var/log/bsr/perfmon/"
#endif

#ifdef _WIN
#define popen _popen
#define pclose _pclose
#define fscanf_str fscanf_s
#define fscanf_ex fscanf_s
#define sprintf_ex sprintf_s
#define strtok_r strtok_s
#else // _LIN
#ifndef ULONG_PTR
#define ULONG_PTR unsigned long
#endif
#define fopen_s(pFile, filename, mode) ((*pFile=fopen(filename, mode)) == NULL)
#define sprintf_ex sprintf
#define fscanf_str(fp, format, buf) fscanf(fp, format, buf)
#define fscanf_ex fscanf
#endif

struct time_stamp {
	int t_sec;
	int t_min;
	int t_hour;
	int use;
};

// BSR-771
struct time_filter {
	char start_date[11];
	char end_date[11];
	struct time_stamp start_time;
	struct time_stamp end_time;
};


enum get_debug_type
{
	IO_STAT,
	IO_COMPLETE,
	IO_PENDING, // BSR-1054
	AL_STAT,
	PEER_REQUEST,
	REQUEST,
	RESYNC_RATIO,
	NETWORK_SPEED,
	SEND_BUF,
	MEMORY,
	ALL_STAT
};

static inline void clear_screen()
{
#ifdef _WIN
	system("cls");
#else // _LIN
	system("clear");
#endif
}


// BSR-771
int parse_timestamp(char *str, char *date, struct time_stamp *ts);
int datecmp(char *curr, struct time_stamp *ts);
void get_perf_path();

// BSR-940
extern struct type_names perf_type_names;
extern void init_perf_type_str();
extern const char *perf_type_str(enum get_debug_type t);