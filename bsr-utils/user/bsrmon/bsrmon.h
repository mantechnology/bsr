#ifdef _WIN
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <set>
#include <iostream>
#include "../../../bsr-headers/bsr_ioctl.h"

#define MAX_BUF_SIZE 4096
#define MAX_PATH 260

#define DEFAULT_BSRMON_PERIOD 1
#define DEFAULT_BSRMON_FILE_SIZE 50
#define DEFAULT_FILE_CNT 4

#ifdef _WIN
#define _SEPARATOR_ "\\"
#else // _LIN
#define _SEPARATOR_ "/"
#endif


#ifdef _LIN
#define PERIOD_OPTION_PATH "/etc/bsr.d/.bsrmon_period"
#define FILE_SIZE_OPTION_PATH "/etc/bsr.d/.bsrmon_file_size"
#define FILE_CNT_OPTION_PATH "/etc/bsr.d/.bsrmon_file_cnt"
// BSR-1112 BSR-1215
#define FILE_PATH_OPTION_PATH "/etc/bsr.d/.bsrmon_file_path"
#define DEFAULT_PERFMON_FILE_PATH "/var/log/bsr/perfmon/"
#endif

#ifdef _WIN
#define popen _popen
#define pclose _pclose
#define fscanf_str fscanf_s
#define fscanf_ex fscanf_s
#define sprintf_ex sprintf_s
#define strtok_r strtok_s
#define pid_t DWORD
#else // _LIN
#ifndef ULONG_PTR
#define ULONG_PTR unsigned long
#endif
#define fopen_s(pFile, filename, mode) ((*pFile=fopen(filename, mode)) == NULL)
#define sprintf_ex sprintf
#define fscanf_str(fp, format, buf) fscanf(fp, format, buf)
#define fscanf_ex fscanf
#endif

// BSR-1138
#define DEFAULT_BSRMON_LOG_BACKUP_SIZE 1 // 1M

enum set_option_type
{
	BSRMON_PERIOD,
	BSRMON_FILE_SIZE,
	BSRMON_FILE_CNT,
	BSRMON_RUN,
	// BSR-1138
	BSRMON_TYPES,
	BSRMON_PID,
	BSRMON_STOP_SIGNAL,
};

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
void eliminate(char *str, char ch);
void get_filelist(char * dir_path, char * find_file, std::set<std::string> *file_list, bool copy);
FILE *perf_fileopen(char * filename, char * currtime);

// BSR-940
extern struct type_names perf_type_names;
extern void init_perf_type_str();
extern const char *perf_type_str(enum bsrmon_type t);
extern void SetOptionValue(enum set_option_type option_type, long value);
extern long GetOptionValue(enum set_option_type option_type);

extern bool write_log;

// BSR-1138
extern void _bsrmon_log(const char * func, int line, const char * fmt, ...);
#ifdef _WIN
#define bsrmon_log(std_io, fmt, ...)	\
		{	\
			if (write_log) \
				_bsrmon_log(__FUNCTION__, __LINE__, fmt, __VA_ARGS__); \
			else {	\
				fprintf(std_io, fmt, __VA_ARGS__); \
			}	\
		} while(false)

#else // _LIN
#define bsrmon_log(std_io, fmt, arg...)	\
		{	\
			if (write_log) \
				_bsrmon_log(__FUNCTION__, __LINE__, fmt, ##arg); \
			else {	\
				fprintf(std_io, fmt, ##arg); \
			}	\
		} while(false)

#endif
