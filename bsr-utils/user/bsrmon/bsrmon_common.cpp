#ifdef _WIN
#include <tchar.h>
#else // _LIN
#include <dirent.h>
#endif
#include <stdarg.h>
#include <time.h>
#include <sys/timeb.h>
#include "bsrmon.h"
#include "../../../bsr-headers/bsr_ioctl.h"

char g_perf_path[MAX_PATH];
bool write_log = false;

// BSR-1138
#define DEFAULT_BSRMON_LOG_ROLLING_SIZE 1 // 1M

struct type_names {
	const char * const *names;
	unsigned int size;
};


// BSR-940 must be same as enum bsrmon_type order
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

const char *perf_type_str(enum bsrmon_type t)
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
		if (result || (bsr_path == NULL) || !strlen(bsr_path)) {
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

/*
* character removal
*/
void eliminate(char *str, char ch)
{
	size_t len = strlen(str) + 1;
	for (; *str != '\0'; str++, len--) {
		if (*str == ch) {
#ifdef _WIN	
			strcpy_s(str, len, str + 1);
#else
			strcpy(str, str + 1);
#endif
			str--;
		}
	}
}

// BSR-940 get list of performance data files
void get_filelist(char * dir_path, char * find_file, std::set<std::string> *file_list, bool copy)
{
	char filename[MAX_PATH + 20] = { 0, };
	std::set<std::string>::iterator iter;
#ifdef _WIN
	WCHAR dir_path_w[MAX_PATH] = { 0, };
	WCHAR find_file_w[MAX_PATH] = { 0, };
	HANDLE hFind;
	WIN32_FIND_DATA FindFileData;

	wsprintf(dir_path_w, L"%S%S%S*", dir_path, _SEPARATOR_, find_file);
	wsprintf(find_file_w, L"%S", find_file);

	hFind = FindFirstFile(dir_path_w, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
		return;

	do{
		if (!wcsstr(FindFileData.cFileName, L"tmp_") && wcsstr(FindFileData.cFileName, find_file_w)) {
			sprintf_s(filename, "%s%s%ws", dir_path, _SEPARATOR_, FindFileData.cFileName);
			if (copy) {
				// BSR-940 copy to tmp_* files
				char copy_file[MAX_PATH + 25] = { 0, };
				WCHAR filename_w[MAX_PATH + 20] = { 0, };
				WCHAR copyfile_w[MAX_PATH + 25] = { 0, };
				printf("file %s\n", filename);
				sprintf_ex(copy_file, "%s%stmp_%ws", dir_path, _SEPARATOR_, FindFileData.cFileName);
				wsprintf(filename_w, L"%S", filename);
				wsprintf(copyfile_w, L"%S", copy_file);

				if (CopyFile(filename_w, copyfile_w, false))
					file_list->insert(copy_file);
			}
			else {
				file_list->insert(filename);
			}
		}
	} while (FindNextFile(hFind, &FindFileData));
	FindClose(hFind);
#else // _LIN
	DIR *dir_p = NULL;
	struct dirent* entry = NULL;

	if ((dir_p = opendir(dir_path)) == NULL)
		return;

	while ((entry = readdir(dir_p)) != NULL) {
		if (!strstr(entry->d_name, "tmp_") && strstr(entry->d_name, find_file)) {
			sprintf_ex(filename, "%s%s%s", dir_path, _SEPARATOR_, entry->d_name);
			if (copy) {
				// BSR-940 copy to tmp_* files
				char copy_file[MAX_PATH + 25] = { 0, };
				char cmd[MAX_PATH + 28] = { 0, };
				int ret = 0;

				printf("file %s\n", filename);

				sprintf_ex(copy_file, "%s%stmp_%s", dir_path, _SEPARATOR_, entry->d_name);
				sprintf_ex(cmd, "cp -f %s %s > /dev/null 2>&1", filename, copy_file);

				ret = system(cmd);
				if (!ret)
					file_list->insert(copy_file);
			}
			else {
				file_list->insert(filename);
			}
		}
	}
	closedir(dir_p);
#endif
}

FILE *_fileopen(char * filename, char * currtime, bool logfile)
{
	FILE *fp;
	char new_filename[512];
	int rename_err = 0;
	off_t size;
	long file_rolling_size;
#ifdef _WIN
	fp = _fsopen(filename, "a", _SH_DENYNO);
#else // _LIN
	fp = fopen(filename, "a");
#endif
	if (fp == NULL) {
		fprintf(stderr, "Failed to open %s\n", filename);
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	
	if (logfile) {
		file_rolling_size = DEFAULT_BSRMON_LOG_ROLLING_SIZE;
	}
	else {
		file_rolling_size = GetOptionValue(FILE_ROLLING_SIZE);
		if (file_rolling_size <= 0)
			file_rolling_size = DEFAULT_FILE_ROLLING_SIZE;
	}

	if ((1024 * 1024 * file_rolling_size) < size) {
		char dir_path[MAX_PATH] = { 0, };
		char find_file[MAX_PATH] = { 0, };
		char r_time[64] = { 0, };
		char* ptr;
		std::set<std::string> listFileName;
		std::set<std::string>::reverse_iterator iter;

		int file_cnt = 0, rolling_cnt = 0;

		fclose(fp);

		if (logfile) {
			rolling_cnt = 1;
		}
		else {
			int rolling_cnt = GetOptionValue(FILE_ROLLING_CNT);
			if (rolling_cnt <= 0)
				rolling_cnt = DEFAULT_FILE_ROLLONG_CNT;
		}

#ifdef _WIN
		ptr = strrchr(filename, '\\');
		memcpy(dir_path, filename, (ptr - filename));
		_snprintf_s(find_file, strlen(ptr) + 1, "%s_", ptr + 1);
#else
		ptr = strrchr(filename, '/');
		memcpy(dir_path, filename, (ptr - filename));
		snprintf(find_file, strlen(ptr) + 1, "%s_", ptr + 1);
#endif
		get_filelist(dir_path, find_file, &listFileName, false);
		if (listFileName.size() != 0) {
			for (iter = listFileName.rbegin(); iter != listFileName.rend(); iter++) {
				file_cnt++;
				if (file_cnt >= rolling_cnt)
					remove(iter->c_str());
			}
		}

		memcpy(r_time, currtime, strlen(currtime));
		eliminate(r_time, ':');
		sprintf_ex(new_filename, "%s_%s", filename, r_time);
		rename_err = rename(filename, new_filename);
		if (rename_err == -1) {
			fprintf(stderr, "Failed to log file rename %s => %s\n", filename, new_filename);
			return NULL;
		}
#ifdef _WIN
		fp = _fsopen(filename, "a", _SH_DENYNO);
#else // _LIN
		fp = fopen(filename, "a");
#endif
		if (fp == NULL) {
			fprintf(stderr, "Failed to open %s\n", filename);
			return NULL;
		}
	}

	return fp;

}
FILE *perf_fileopen(char * filename, char * currtime)
{
	return _fileopen(filename, currtime, false);
}

static FILE * log_fileopen(char * filename, char * currtime) {
	return _fileopen(filename, currtime, true);
}

// BSR-1138
void _bsrmon_log(const char * func, int line, const char * fmt, ...) {
	char b[514];
	long offset = 0;
	va_list args;
	struct tm local_tm;
	struct timeb timer_msec;
	FILE *f_out;
	char bsrmon_log_path[MAX_PATH+10];
	char curr_time[64] = { 0, };

	get_perf_path();
	sprintf_ex(bsrmon_log_path, "%sbsrmon.log", g_perf_path);
	ftime(&timer_msec);
#ifdef _WIN
	localtime_s(&local_tm, &timer_msec.time);
#else
	local_tm = *localtime(&timer_msec.time);
#endif

	sprintf_ex(curr_time, "%04d-%02d-%02d_%02d:%02d:%02d.%03d",
		local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday,
		local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec, timer_msec.millitm);
	
#ifdef _WIN
	offset = _snprintf_s(b, 512, "%s [func:%s][line:%d] ", curr_time, func, line);
#else // _LIN
	offset = snprintf(b, 512, "%s [func:%s][line:%d] ", curr_time, func, line);
#endif

	f_out = log_fileopen(bsrmon_log_path, curr_time);

	va_start(args, fmt);

#ifdef _WIN
	vsnprintf_s(b + offset, 512 - offset, 512 - offset, fmt, args);
#else // _LIN
	vsnprintf(b + offset, 512 - offset, fmt, args);
#endif
	va_end(args);

	fprintf(f_out, "%s", b);		
	fclose(f_out);
}