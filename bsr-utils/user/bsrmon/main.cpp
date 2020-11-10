#ifdef _WIN
#include <windows.h>
#include "ioctl.h"
#include <tchar.h>
#else // _LIN
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "../../../bsr-headers/linux/bsr_ioctl.h"
#endif
#include <stdio.h>
#include <time.h>
#include <sys/timeb.h>
#include "module_debug.h"
#include "monitor_collect.h"

#ifdef _LIN
#define PERIOD_OPTION_PATH "/etc/bsr.d/.bsrmon_period"
#define FILE_SIZE_OPTION_PATH "/etc/bsr.d/.bsrmon_file_size"
#define FILE_CNT_OPTION_PATH "/etc/bsr.d/.bsrmon_file_cnt"
#endif

#ifdef _WIN
void debug_usage()
{
	printf("usage: bsrmon /debug cmds options \n\n"
		"cmds:\n");
	printf(
		"   version\n"
		"   in_flight_summary {resource}\n"
		"   state_twopc {resource}\n"
		"   callback_history {resource} {peer_node_id}\n"
		"   debug {resource} {peer_node_id}\n"
		"   conn_oldest_requests {resource} {peer_node_id}\n"
		"   transport {resource} {peer_node_id}\n"
		"   transport_speed {resource} {peer_node_id}\n"
		"   send_buf {resource} {peer_node_id}\n"
		"   proc_bsr {resource} {peer_node_id} {volume}\n"
		"   resync_extents {resource} {peer_node_id} {volume}\n"
		"   act_log_extents {resource} {volume}\n"
		"   data_gen_id {resource} {volume}\n"
		"   ed_gen_id {resource} {volume}\n"
		"   io_frozen {resource} {volume}\n"
		"   dev_oldest_requests {resource} {volume}\n"
		"   dev_io_stat {resource} {volume}\n"
		"   dev_io_complete {resource} {volume}\n"
		"   dev_req_timing {resource} {volume}\n"
		);
	printf("\n");

	printf(
		"\n\n"
		"examples:\n"
		"bsrmon /debug version \n"
		"bsrmon /debug in_flight_summary r1 \n"
		"bsrmon /debug transport r1 1\n"
		"bsrmon /debug proc_bsr r1 1 0 \n"
		"bsrmon /debug io_frozen r1 0 \n"
		);

	exit(ERROR_INVALID_PARAMETER);
}
#endif

void usage()
{
	printf("usage: bsrmon cmds options \n\n"
		"cmds:\n");
#ifdef _WIN
	printf(
		"   /debug\n"
		);
#endif
	printf(
		"   /start\n"
		"   /stop\n"
		"   /print\n"
		"   /file\n"
		"   /watch [resource] [type : 0~4] [vnr]\n"
		"\t type info, IO_STAT(0) IO_COMPLETE(1) REQUEST(2) NETWORK_SPEED(3) SEND_BUF(4)\n"
		"\t vnr info, it is used only when type value is 0 or 1\n"
		"   /watchmem\n"
		"   /set [period, file_size, file_cnt] [value]\n"
		);

	printf(
		"\n\n"
		"examples:\n"
		"bsrmon /watch r0\n"
		"bsrmon /watch r0 0 0\n"
		"bsrcon /watch r0 2\n"
		);
	exit(ERROR_INVALID_PARAMETER);
}

#ifdef _WIN
// BSR-37 debugfs porting
int BsrDebug(int argc, char* argv[])
{
	DWORD ret = ERROR_SUCCESS;
	int argIndex = 0;
	PBSR_DEBUG_INFO debugInfo = NULL;
	int size = MAX_SEQ_BUF;
	enum BSR_DEBUG_FLAGS flag;

	flag = ConvertToBsrDebugFlags(argv[argIndex]);

	if (!flag)
		debug_usage();

	if (flag == DBG_DEV_ACT_LOG_EXTENTS)
		size <<= 10;  // 4M

	debugInfo = (PBSR_DEBUG_INFO)malloc(sizeof(BSR_DEBUG_INFO) + size);
	if (!debugInfo) {
		fprintf(stderr, "DEBUG_ERROR: Failed to malloc BSR_DEBUG_INFO\n");
		return  ERROR_NOT_ENOUGH_MEMORY;
	}

	memset(debugInfo, 0, sizeof(BSR_DEBUG_INFO) + size);
	debugInfo->peer_node_id = -1;
	debugInfo->vnr = -1;
	debugInfo->buf_size = size;
	debugInfo->flags = flag;

	if (debugInfo->flags != DBG_BSR_VERSION) {
		argIndex++;
		if (argIndex < argc)
			strcpy_s(debugInfo->res_name, argv[argIndex]);
		else
			debug_usage();
		argIndex++;
		switch (debugInfo->flags) {
		case DBG_RES_IN_FLIGHT_SUMMARY:
		case DBG_RES_STATE_TWOPC:
			break;
		case DBG_CONN_CALLBACK_HISTORY:
		case DBG_CONN_DEBUG:
		case DBG_CONN_OLDEST_REQUESTS:
		case DBG_CONN_TRANSPORT:
		case DBG_CONN_TRANSPORT_SPEED:
		case DBG_CONN_SEND_BUF:
			if (argIndex < argc)
				debugInfo->peer_node_id = atoi(argv[argIndex]);
			else
				debug_usage();
			break;
		case DBG_PEER_PROC_BSR:
		case DBG_PEER_RESYNC_EXTENTS:
			if (argIndex < argc)
				debugInfo->peer_node_id = atoi(argv[argIndex]);
			else
				debug_usage();
			argIndex++;
			if (argIndex < argc)
				debugInfo->vnr = atoi(argv[argIndex]);
			else
				debug_usage();
			break;
		case DBG_DEV_ACT_LOG_EXTENTS:
		case DBG_DEV_DATA_GEN_ID:
		case DBG_DEV_ED_GEN_ID:
		case DBG_DEV_IO_FROZEN:
		case DBG_DEV_OLDEST_REQUESTS:
		case DBG_DEV_IO_STAT:
		case DBG_DEV_IO_COMPLETE:
		case DBG_DEV_REQ_TIMING:
			if (argIndex < argc)
				debugInfo->vnr = atoi(argv[argIndex]);
			else
				debug_usage();
			break;
		default:
			break;
		}
	}


	while ((ret = GetBsrDebugInfo(debugInfo)) != ERROR_SUCCESS) {
		if (ret == ERROR_MORE_DATA) {
			size <<= 1;

			if (size > MAX_SEQ_BUF << 10) { // 4M
				fprintf(stderr, "DEBUG_ERROR: Failed to get bsr debuginfo. (Err=%u)\n", ret);
				fprintf(stderr, "buffer overflow.\n");
				break;
			}

			// reallocate when buffer is insufficient
			debugInfo = (PBSR_DEBUG_INFO)realloc(debugInfo, sizeof(BSR_DEBUG_INFO) + size);
			if (!debugInfo) {
				fprintf(stderr, "DEBUG_ERROR: Failed to realloc BSR_DEBUG_INFO\n");
				break;
			}
			debugInfo->buf_size = size;
		}
		else {
			fprintf(stderr, "DEBUG_ERROR: Failed to get bsr debuginfo. (Err=%u)\n", ret);
			break;
		}
	}

	if (ret == ERROR_SUCCESS) {
		fprintf(stdout, "%s\n", debugInfo->buf);
	}
	else if (ret == ERROR_INVALID_PARAMETER) {
		fprintf(stderr, "invalid paramter.\n");
	}

	if (debugInfo) {
		free(debugInfo);
		debugInfo = NULL;
	}

	return ret;
}
#endif

void PrintMonitor()
{	
	char *buf = NULL;
	struct resource* res;
	
	res = GetResourceInfo();
	if (!res) {
		fprintf(stderr, "failed GetResourceInfo\n");
		return;
	}

	// print I/O monitoring status
	printf("IO_STAT:\n");
	buf = GetDebugToBuf(IO_STAT, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	printf("IO_COMPLETE:\n");
	buf = GetDebugToBuf(IO_COMPLETE, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	printf("REQUEST:\n");
	buf = GetDebugToBuf(REQUEST, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	// print memory monitoring status
	printf("Memory:\n");
	buf = GetBsrMemoryUsage();
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}
	buf = GetBsrUserMemoryUsage();
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	// print network monitoring status
	printf("Network:\n");
	buf = GetDebugToBuf(NETWORK_SPEED, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}
	buf = GetDebugToBuf(SEND_BUF, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	freeResource(res);
}

// BSR-688 save aggregated data to file
void MonitorToFile()
{
#ifdef _WIN
	size_t path_size;
	errno_t result;
	char bsr_path[MAX_PATH] = {0,};
#endif
	char perfpath[MAX_PATH] = {0,};
	struct resource* res;
	struct tm base_date_local;
	struct timeb timer_msec;
	char curr_time[64] = {0,};
	char mempath[MAX_PATH] = {0,};
	FILE * mem_fp;

	res = GetResourceInfo();
	if (!res) {
		fprintf(stderr, "failed GetResourceInfo\n");
		return;
	}
#ifdef _WIN
	result = getenv_s(&path_size, bsr_path, MAX_PATH, "BSR_PATH");
	if (result) {
		strcpy_s(bsr_path, "c:\\Program Files\\bsr\\bin");
	}
	strncpy_s(perfpath, bsr_path, strlen(bsr_path) - strlen("bin"));
	strcat_s(perfpath, "log\\perfmon\\");

	ftime(&timer_msec);
	localtime_s(&base_date_local, &timer_msec.time);
#else
	sprintf(perfpath, "/var/log/bsr/perfmon/");

	ftime(&timer_msec);
	base_date_local = *localtime(&timer_msec.time);
#endif	
	sprintf_s(curr_time, "%04d-%02d-%02d_%02d:%02d:%02d.%d",
		base_date_local.tm_year + 1900, base_date_local.tm_mon + 1, base_date_local.tm_mday,
		base_date_local.tm_hour, base_date_local.tm_min, base_date_local.tm_sec, timer_msec.millitm);


	while (res) {
		char respath[MAX_PATH] = {0,};
		char lastfile[MAX_PATH] = { 0, };
		FILE *last_fp;

		sprintf_s(respath, "%s%s", perfpath, res->name);
#ifdef _WIN
		CreateDirectoryA(respath, NULL);
#else // _LIN
		
		mkdir(respath, 0777);
#endif

		sprintf_s(lastfile, "%s"_SEPARATOR_"last", respath);
		
		if (fopen_s(&last_fp, lastfile, "w") != 0)
			return;

		fprintf(last_fp, "==> Resource %s <==\n\n", res->name);
		fclose(last_fp);

		// save monitoring status
		GetDebugToFile(IO_STAT, res, respath, curr_time);
		GetDebugToFile(IO_COMPLETE, res, respath, curr_time);
		GetDebugToFile(REQUEST, res, respath, curr_time);
		GetDebugToFile(NETWORK_SPEED, res, respath, curr_time);
		GetDebugToFile(SEND_BUF, res, respath, curr_time);
		res = res->next;
	}

	// save memory monitoring status
	sprintf_s(mempath, "%slast", perfpath);
	if (fopen_s(&mem_fp, mempath, "w") != 0)
		return;
	fprintf(mem_fp, "Memory:\n");
	fclose(mem_fp);
	GetMemInfoToFile(perfpath, curr_time);

	freeResource(res);
}

// BSR-688 watching last file
void Watch(char *resname, int type = -1, int vnr = 0)
{
	char cmd[MAX_PATH];
	bool watch_all_type = false;
#ifdef _WIN
	char bsr_path[MAX_PATH] = {0,};
	char perf_path[MAX_PATH] = {0,};
	size_t path_size;
	errno_t result;
	result = getenv_s(&path_size, bsr_path, MAX_PATH, "BSR_PATH");
	if (result) {
		strcpy_s(bsr_path, "c:\\Program Files\\bsr\\bin");
	}
	strncpy_s(perf_path, bsr_path, strlen(bsr_path) - strlen("bin"));
	strcat_s(perf_path, "log\\perfmon\\");
#endif

	if (resname == NULL)
#ifdef _WIN
		sprintf_s(cmd, "Powershell.exe -command \"Get-Content '%smemory' -Wait -Tail 100\"", perf_path);
#else // _LIN
		sprintf(cmd, "tail --follow=name /var/log/bsr/perfmon/memory");
#endif
	else {
		int err = CheckResourceInfo(resname, 0, vnr);
		if (err) {
			fprintf(stderr, "Failed CheckResourceInfo, err=%d\n", err);
			return;
		}

		if (type != -1) {
			switch (type) {
			case IO_STAT:
#ifdef _WIN
				sprintf_s(cmd, "Powershell.exe -command \"Get-Content '%s%s\\vnr%d_IO_STAT' -Wait -Tail 100\"", perf_path, resname, vnr);
#else // _LIN
				sprintf(cmd, "tail --follow=name /var/log/bsr/perfmon/%s/vnr%d_IO_STAT", resname, vnr);
#endif
				break;
			case IO_COMPLETE:
#ifdef _WIN
				sprintf_s(cmd, "Powershell.exe -command \"Get-Content '%s%s\\vnr%d_IO_COMPLETE' -Wait -Tail 100\"", perf_path, resname, vnr);
#else // _LIN
				sprintf(cmd, "tail --follow=name /var/log/bsr/perfmon/%s/vnr%d_IO_COMPLETE", resname, vnr);
#endif
				break;
			case REQUEST:
#ifdef _WIN
				sprintf_s(cmd, "Powershell.exe -command \"Get-Content '%s%s\\request' -Wait -Tail 100\"", perf_path, resname);
#else // _LIN
				sprintf(cmd, "tail --follow=name /var/log/bsr/perfmon/%s/request", resname);
#endif
				break;
			case NETWORK_SPEED:
#ifdef _WIN
				sprintf_s(cmd, "Powershell.exe -command \"Get-Content '%s%s\\network' -Wait -Tail 100\"", perf_path, resname);
#else // _LIN
				sprintf(cmd, "tail --follow=name /var/log/bsr/perfmon/%s/network", resname);
#endif
				break;
			case SEND_BUF:
#ifdef _WIN
				sprintf_s(cmd, "Powershell.exe -command \"Get-Content '%s%s\\send_buffer' -Wait -Tail 100\"", perf_path, resname);
#else // _LIN
				sprintf(cmd, "tail --follow=name /var/log/bsr/perfmon/%s/send_buffer", resname);
#endif
				break;
			default:
				usage();
			}
		}
		else {
#ifdef _WIN
			sprintf_s(cmd, "type \"%s%s\\last\" & type \"%slast\" ", perf_path, resname, perf_path);
#else // _LIN
			sprintf(cmd, "cat /var/log/bsr/perfmon/%s/last; cat /var/log/bsr/perfmon/last; ", resname);
#endif
			watch_all_type = true;
		}
	}
#ifdef _WIN
	system("cls");
#else // _LIN
	system("clear");
#endif

	while (1) {
		system(cmd);
		if (!watch_all_type)
			break;
#ifdef _WIN
		Sleep(1000);
		system("cls");
#else // _LIN
		sleep(1);
		system("clear");
#endif
	}
}

// BSR-694
void SetOptionValue(enum set_option_type option_type, long value)
{
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsr");
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);
	DWORD lResult = ERROR_SUCCESS;
	DWORD option_value = value;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		fprintf(stderr, "Failed to RegOpenValueEx status(0x%x)\n", lResult);
		return;
	}
#else // _LIN
	FILE *fp;
#endif

	if (option_type == PERIOD && value > 0)
#ifdef _WIN
		lResult = RegSetValueEx(hKey, _T("bsrmon_period"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#else // _LIN
		fp = fopen(PERIOD_OPTION_PATH, "w");
#endif
	else if (option_type == FILE_ROLLING_SIZE && value > 0)
#ifdef _WIN
		lResult = RegSetValueEx(hKey, _T("bsrmon_file_size"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#else // _LIN
		fp = fopen(FILE_SIZE_OPTION_PATH, "w");
#endif
	else if (option_type == FILE_ROLLING_CNT && value > 0)
#ifdef _WIN
		lResult = RegSetValueEx(hKey, _T("bsrmon_file_cnt"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#else // _LIN
		fp = fopen(FILE_CNT_OPTION_PATH, "w");
#endif
	else {
#ifdef _WIN
		RegCloseKey(hKey);
#endif
		usage();
	}

#ifdef _WIN
	if (ERROR_SUCCESS != lResult)
		fprintf(stderr, "Failed to RegSetValueEx status(0x%x)\n", lResult);

	RegCloseKey(hKey);
#else // _LIN
	if (fp != NULL) {
		fprintf(fp, "%ld", value);
		fclose(fp);
	}
	else {
		fprintf(stderr, "Failed open file(%d)\n", option_type);
	}
#endif
}

long GetOptionValue(enum set_option_type option_type)
{
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsr");
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);
	DWORD lResult = ERROR_SUCCESS;
	DWORD value;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		fprintf(stderr, "Failed to RegOpenValueEx status(0x%x)\n", lResult);
		return -1;
	}
#else // _LIN
	FILE *fp;
	long value;
#endif

	if (option_type == PERIOD)
#ifdef _WIN
		lResult = RegQueryValueEx(hKey, _T("bsrmon_period"), NULL, &type, (LPBYTE)&value, &size);
#else // _LIN
		fp = fopen(PERIOD_OPTION_PATH, "r");
#endif
	else if (option_type == FILE_ROLLING_SIZE)
#ifdef _WIN
		lResult = RegQueryValueEx(hKey, _T("bsrmon_file_size"), NULL, &type, (LPBYTE)&value, &size);
#else // _LIN
		fp = fopen(FILE_SIZE_OPTION_PATH, "r");
#endif
	else if (option_type == FILE_ROLLING_CNT)
#ifdef _WIN
		lResult = RegQueryValueEx(hKey, _T("bsrmon_file_cnt"), NULL, &type, (LPBYTE)&value, &size);
#else // _LIN
		fp = fopen(FILE_CNT_OPTION_PATH, "r");
#endif
	else {
#ifdef _WIN
		RegCloseKey(hKey);
#endif
		return -1;
	}

#ifdef _WIN
	if (ERROR_SUCCESS != lResult) {
		RegCloseKey(hKey);
		return lResult;
	}
	RegCloseKey(hKey);
	return value;
#else // _LIN
	if (fp != NULL) {
		fscanf(fp, "%ld", &value);
		fclose(fp);
		return value;
	}
	return -1;
#endif
}

// BSR-695
static void save_bsrmon_run_reg(unsigned int run)
{
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsr");
	DWORD lResult = ERROR_SUCCESS;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		fprintf(stderr, "Failed to RegOpenValueEx status(0x%x)\n", lResult);
		return;
	}
	lResult = RegSetValueEx(hKey, _T("bsrmon_run"), 0, REG_DWORD, (LPBYTE)&run, sizeof(run));
	if (ERROR_SUCCESS != lResult)
		fprintf(stderr, "Failed to RegSetValueEx status(0x%x)\n", lResult);

	RegCloseKey(hKey);
#else
	int fd = 0;
	FILE * fp;
	// write /etc/bsr.d/.bsrmon_run
	fp = fopen(BSR_MON_RUN_REG, "w");
	if (fp != NULL) {
		fprintf(fp, "%d", run);
		fclose(fp);
	} 
	else 
		fprintf(stderr, "Failed open %s file\n", BSR_MON_RUN_REG);
#endif
	
}

#ifdef _LIN
static pid_t get_running_pid() {
	char buf[10] = {0,};
	pid_t pid;
	FILE *cmd_pipe = popen("pgrep -f bsrmon-run", "r");

	fgets(buf, MAX_PATH, cmd_pipe);
	pid = strtoul(buf, NULL, 10);
	pclose(cmd_pipe);
	return pid;
}
#endif

static void start_mon()
{
	char buf[MAX_PATH] = {0,};
#ifdef _LIN
	pid_t pid = get_running_pid();
	
	if (pid > 0) {
		fprintf(stderr, "Aleady running (pid=%d)\n", pid);
		return;
	}
	sprintf(buf, "nohup /lib/bsr/bsrmon-run >/dev/null 2>&1 &");

	if (system(buf) !=0) {
		fprintf(stderr, "Failed \"%s\"\n", buf);
		return;
	}
#endif

	save_bsrmon_run_reg(1);

}

static void stop_mon()
{
	char buf[MAX_PATH] = {0,};
#ifdef _LIN
	pid_t pid = get_running_pid();

	if (pid <= 0) 
		fprintf(stderr, "bsrmon-run is not running\n");
	
	sprintf(buf, "kill -TERM %d >/dev/null 2>&1", pid);

	if (system(buf) !=0) {
		fprintf(stderr, "Failed \"%s\"\n", buf);
	}
#endif

	save_bsrmon_run_reg(0);

}

#ifdef _WIN
int main(int argc, char* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	int	res = ERROR_SUCCESS;
	int  	argIndex = 0;

	if (argc < 2)
		usage();

	for (argIndex = 1; argIndex < argc; argIndex++) {
		if (!strcmp(argv[argIndex], "/print")) {
			argIndex++;
			if (argIndex <= argc)
				PrintMonitor();
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/file")) {
			argIndex++;
			if (argIndex <= argc) {
				MonitorToFile();
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/watch")) {
			argIndex++;
			if (argIndex < argc) {
				char *res_name = argv[argIndex++];
				if (argIndex < argc) {
					int type = atoi(argv[argIndex]);
					argIndex++;
					if (argIndex < argc)
						Watch(res_name, type, atoi(argv[argIndex]));
					else
						Watch(res_name, type);
				}
				else
					Watch(res_name);
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/watchmem")) {
			argIndex++;
			if (argIndex <= argc) {
				Watch(NULL);
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/set")) {
			argIndex++;

			if (argIndex < argc) {
				if (strcmp(argv[argIndex], "period") == 0) {
					argIndex++;
					if (argIndex < argc)
						SetOptionValue(PERIOD, atoi(argv[argIndex]));
					else
						usage();
				}
				else if (strcmp(argv[argIndex], "file_size") == 0) {
					argIndex++;
					if (argIndex < argc)
						SetOptionValue(FILE_ROLLING_SIZE, atoi(argv[argIndex]));
					else
						usage();
				}
				else if (strcmp(argv[argIndex], "file_cnt") == 0) {
					argIndex++;
					if (argIndex < argc)
						SetOptionValue(FILE_ROLLING_CNT, atoi(argv[argIndex]));
					else
						usage();
				}
				else
					usage();
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/start")) {
			argIndex++;
			if (argIndex <= argc) {
				start_mon();
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/stop")) {
			argIndex++;
			if (argIndex <= argc) {
				stop_mon();
			}
			else
				usage();
		}
#ifdef _WIN
		// BSR-37
		else if (!_stricmp(argv[argIndex], "/debug")) {
			argIndex++;
			if (argIndex < argc)
				res = BsrDebug(argc - argIndex, &argv[argIndex]);
			else
				debug_usage();
			break;
		}
#endif
		else {
			printf("Please check undefined arg[%d]=(%s)\n", argIndex, argv[argIndex]);
		}
	}

	return res;
}