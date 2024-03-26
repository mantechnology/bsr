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
#define DEFAULT_BSRMON_FILE_CNT 4
// BSR-1239 
#define DEFAULT_BSRMON_TOTAL_SIZE_LIMIT 2002 // MB

#ifdef _WIN
#define _SEPARATOR_ "\\"
#else // _LIN
#define _SEPARATOR_ "/"
#endif


#ifdef _LIN
// BSR-1112 BSR-1215
#define FILE_PATH_OPTION_PATH "/etc/bsr.d/.bsrmon_file_path"
#define BSRMON_PERIOD_OPTION_PATH "/etc/bsr.d/.bsrmon_period"
#define BSRMON_FILE_SIZE_OPTION_PATH "/etc/bsr.d/.bsrmon_file_size"
#define BSRMON_FILE_COUNT_OPTION_PATH "/etc/bsr.d/.bsrmon_file_cnt"
// BSR-1239
#define BSRMON_TOTAL_SIZE_LIMIT_OPTION_PATH "/etc/bsr.d/.bsrmon_total_size_limit"
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
	// BSR-1239
	BSRMON_TOTAL_SIZE_LIMIT,
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

// must be same as enum bsrmon_type order
static const char * const total_types_str[] = {
	"iostat", "ioclat", "io_pending", "alstat", "peer_reqstat", "reqstat", "resync_ratio",
	"network", "sendbuf", "memstat", "all",
};

// BSR-1236 separate items for capacity calculation based on resource and volume count.
// BSR-1236 The type of collection that is independent of the number of resources and volumes.
static const char * const global_types_str[] = {
	"memstat",
};

// BSR-1236 The type of collection that is related to the number of resources.
static const char * const res_types_str[] = {
	"network", "sendbuf",
};

// BSR-1236 The type of collection that is related to the number of volume.
static const char * const vol_types_str[] = {
	"iostat", "ioclat", "io_pending", "alstat", "peer_reqstat", "reqstat", "resync_ratio",
};

struct bsrmon_type_counts {
	int total;
	int global;
	int resource;
	int volume;
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
FILE *perf_fileopen(char * filename, char * currtime, void *param);

// BSR-940
extern struct type_names perf_type_names;
extern void init_perf_type_str();
extern const char *perf_type_str(enum bsrmon_type t);
extern long SetOptionValue(enum set_option_type option_type, long value);
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

static void GetCurrentlySetTypeCount(struct bsrmon_type_counts *type_counts, bool print)
{
	long type = GetOptionValue(BSRMON_TYPES);

	type_counts->global = 0;
	type_counts->resource = 0;
	type_counts->volume = 0;

	if (type <= 0)
		type = DEFAULT_BSRMON_TYPES;

	for (int i = 0; i <= BSRMON_ALL_STAT; i++) {
		if (type & (1 << i)) {
			for (int j = 0; j < sizeof(global_types_str) / sizeof(global_types_str[0]); j++) {
				if (strcmp(global_types_str[j], total_types_str[i]) == 0) {
					type_counts->global++;
					if (print)
						printf("%s ", global_types_str[j]);
				}
			}

			for (int j = 0; j < sizeof(res_types_str) / sizeof(res_types_str[0]); j++) {
				if (strcmp(res_types_str[j], total_types_str[i]) == 0) {
					type_counts->resource++;
					if (print)
						printf("%s ", res_types_str[j]);
				}
			}

			for (int j = 0; j < sizeof(vol_types_str) / sizeof(vol_types_str[0]); j++) {
				if (strcmp(vol_types_str[j], total_types_str[i]) == 0) {
					type_counts->volume++;
					if (print)
						printf("%s ", vol_types_str[j]);
				}
			}
		}
	}

	type_counts->total = type_counts->global + type_counts->resource + type_counts->volume;
}
