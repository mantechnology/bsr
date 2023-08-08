#ifdef _WIN
#include <tchar.h>
#endif
#include "bsrmon.h"

char g_perf_path[MAX_PATH];


struct type_names {
	const char * const *names;
	unsigned int size;
};


// BSR-940 must be same as enum get_debug_type order
static const char * const __type_names[] = {
	"IO_STAT", 
	"IO_COMPLETE",
	"IO_PENDING", // BSR-1054
	"al_stat", 
	"peer_request",
	"request",
	"resync_ratio",
	"network",
	"send_buffer",
	"memory",
	"all",
};

struct type_names perf_type_names;

void init_perf_type_str()
{
	perf_type_names.names = __type_names;
	perf_type_names.size = sizeof __type_names / sizeof __type_names[0];
}

const char *perf_type_str(enum get_debug_type t)
{
	return (t < 0 || (unsigned int)t >= perf_type_names.size ||
	        !perf_type_names.names[t]) ?
	       "?" : perf_type_names.names[t];
}

static int decode_timestamp(char timestamp[], struct time_stamp *ts)
{
	timestamp[2] = timestamp[5] = '\0';
	ts->t_sec  = atoi(&timestamp[6]);
	ts->t_min  = atoi(&timestamp[3]);
	ts->t_hour = atoi(timestamp);

	if ((ts->t_sec < 0) || (ts->t_sec > 59) ||
	    (ts->t_min < 0) || (ts->t_min > 59) ||
	    (ts->t_hour < 0) || (ts->t_hour > 23))
		return 1;

	ts->use = true;

	return 0;
}

int parse_timestamp(char *str, char *date, struct time_stamp *ts)
{
	char timestamp[9];
	char * ptr;
	if (str) {
		// BSR-940 parse date
		if (strstr(str, "_")) {
			ptr = strtok_r(str, "_", &str);
#ifdef _WIN
			strcpy_s(date, strlen(ptr) + 1, ptr);
#else // _LIN
			strcpy(date, ptr);
#endif	
		} 
		else if (strstr(str, "-")) {
#ifdef _WIN
			strcpy_s(date, strlen(str) + 1, str);
#else // _LIN
			strcpy(date, str);
#endif	
		}

		// BSR-940 parse time
		if (strstr(str, ":")) {
			switch (strlen(str)) {
			case 5:
				// ex) 00:00
#ifdef _WIN
				strncpy_s(timestamp, str, 5);
#else // _LIN
				strncpy(timestamp, str, 5);
#endif
				timestamp[5] = '\0';
#ifdef _WIN
				strcat_s(timestamp, ":00");
#else // _LIN
				strcat(timestamp, ":00");
#endif
				break;

			case 8:
				// ex) 00:00:00
#ifdef _WIN
				strncpy_s(timestamp, str, 8);
#else // _LIN
				strncpy(timestamp, str, 8);
#endif
				break;

			default:
				break;
			}
			timestamp[8] = '\0';

			return decode_timestamp(timestamp, ts);
		}
	}

	return 0;
	
}

/*
 * Compare two timestamps.
 *
 * RETURNS:
 * A positive value if @curr is greater than @ts,
 * a negative one otherwise.
 */
int datecmp(char *curr, struct time_stamp *ts)
{
    struct time_stamp curr_ts;
	char timestamp[9];

#ifdef _WIN
	strncpy_s(timestamp, curr, 8);
#else // _LIN
	strncpy(timestamp, curr, 8);
#endif
    decode_timestamp(timestamp, &curr_ts);

	if (curr_ts.t_hour == ts->t_hour) {
		if (curr_ts.t_min == ts->t_min)
			return (curr_ts.t_sec - ts->t_sec);
		else
			return (curr_ts.t_min - ts->t_min);
	}
	else
		return (curr_ts.t_hour - ts->t_hour);
}

void get_perf_path()
{
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsrvflt");
	DWORD type = REG_SZ;
	DWORD size = MAX_PATH;
	DWORD lResult = ERROR_SUCCESS;
	TCHAR buf[MAX_PATH] = { 0, };

	memset(g_perf_path, 0, sizeof(g_perf_path));
	
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		goto out;
	}

	lResult = RegQueryValueEx(hKey, _T("log_path"), NULL, &type, (PBYTE)&buf, &size);
	RegCloseKey(hKey);

out:
	if (ERROR_SUCCESS == lResult) {
		sprintf_s(g_perf_path, "%ws\\perfmon\\", buf);
	} else {
		char bsr_path[MAX_PATH] = {0,};
		size_t path_size;
		errno_t result;
		result = getenv_s(&path_size, bsr_path, MAX_PATH, "BSR_PATH");
		if (result) {
			strcpy_s(bsr_path, "c:\\Program Files\\bsr\\log\\perfmon\\");
		} else {
			strncpy_s(g_perf_path, (char *)bsr_path, strlen(bsr_path) - strlen("bin"));
			strcat_s(g_perf_path, "log\\perfmon\\");
		}
	}

#else // _LIN
	FILE *fp;
	char buf[MAX_PATH] = {0,};

	fp = fopen(PERFMON_FILE_PATH, "r");

	memset(g_perf_path, 0, sizeof(g_perf_path));
	if (fp == NULL) {
		sprintf(g_perf_path, "%s", DEFAULT_PERFMON_FILE_PATH);
	} else {
		if (fgets(buf, sizeof(buf), fp) != NULL)
			sprintf(g_perf_path, "%s/perfmon/", buf);
		else
			sprintf(g_perf_path, "%s", DEFAULT_PERFMON_FILE_PATH);
		fclose(fp);
	}
#endif
}