#ifdef _WIN
#include <tchar.h>
#else // _LIN
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "../../../bsr-headers/bsr_ioctl.h"
#endif
#include <time.h>
#include <sys/timeb.h>
#include "bsrmon.h"
#include "module_debug.h"
#include "monitor_collect.h"
#include "read_stat.h"


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
		"   resync_ratio {resource} {peer_node_id} {volume}\n"
		"   act_log_extents {resource} {volume}\n"
		"   act_log_stat {resource} {volume}\n"
		"   data_gen_id {resource} {volume}\n"
		"   ed_gen_id {resource} {volume}\n"
		"   io_frozen {resource} {volume}\n"
		"   dev_oldest_requests {resource} {volume}\n"
		"   dev_io_stat {resource} {volume}\n"
		"   dev_io_complete {resource} {volume}\n"
		"   dev_req_timing {resource} {volume}\n"
		"   dev_peer_req_timing {resource} {volume}\n"
		);
	printf("\n");

	printf(
		"\n\n"
		"examples:\n"
		"bsrmon /debug version \n"
		"bsrmon /debug in_flight_summary r1 \n"
		"bsrmon /debug transport r1 1\n"
		"bsrmon /debug proc_bsr r1 1 0\n"
		"bsrmon /debug io_frozen r1 0\n"
		"bsrmon /debug resync_ratio r1 1\n"
		);

	exit(ERROR_INVALID_PARAMETER);
}
#endif

void perf_test_usage()
{
	printf("I/O performance degradation simulation. Absolutely only for testing purposes!\n"
		"usage: bsrmon /io_delay_test {flag} {delay point} {delay time} \n\n"
		"flag:\n"
		"   0: disable\n"
		"   1: enable\n"
		"\n\n"

		"delay point:\n"
		"   0: write I/O occurrence\n"
		"   1: master I/O completion\n"
		"   2: active log commit\n"
		"   3: submit\n"
		"   4: socket send\n"
		"   5: socket receive\n"
		"   6: peer request submit\n"
		"\n\n"

		"delay time:\n"
		"   0 ~ 500 ms\n"

		);
	exit(ERROR_INVALID_PARAMETER);
}

void usage()
{
	printf("usage: bsrmon cmds options \n\n"
		"cmds:\n");

	printf(
		"   /start\n"
		"   /stop\n"
		"   /status\n"
		//"   /print\n"
		//"   /file\n"
		"   /show [/t {types[,...]|all}] [/r {resource[,...]|all}] [/j|/json] [/c|/continue]\n"
		"   /watch {types} [/scroll]\n"
		"   /report {types} [/f {filename}] [/p {peer_name[,...]}]\n"
		"                                   [/d {YYYY-MM-DD}]\n"
		"                                   [/s {YYYY-MM-DD|hh:mm[:ss]|YYYY-MM-DD_hh:mm[:ss]}]\n"
		"                                   [/e {YYYY-MM-DD|hh:mm[:ss]|YYYY-MM-DD_hh:mm[:ss]}]\n"
		"   /set {period, file_size, file_cnt} {value}\n"
		"   /get {all, period, file_size, file_cnt}\n"
		"   /io_delay_test {flag} {delay point} {delay time}\n"
		);
#ifdef _WIN
	printf(
		"   /debug cmds options\n"
		);
#endif
	printf(
		"\n\n"
		"Types:\n"
		"   iostat {resource} {vnr}\n"
		"   ioclat {resource} {vnr}\n"
		"   io_pending {resource} {vnr}\n"
		"   reqstat {resource} {vnr}\n"
		"   peer_reqstat {resource} {vnr}\n"
		"   alstat {resource} {vnr}\n"
		"   resync_ratio {resource} {vnr}\n"
		"   network {resource}\n"
		"   sendbuf {resource}\n"
		"   memstat \n"
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
		case DBG_PEER_RESYNC_RATIO:
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
		case DBG_DEV_ACT_LOG_STAT:
		case DBG_DEV_DATA_GEN_ID:
		case DBG_DEV_ED_GEN_ID:
		case DBG_DEV_IO_FROZEN:
		case DBG_DEV_OLDEST_REQUESTS:
		case DBG_DEV_IO_STAT:
		case DBG_DEV_IO_COMPLETE:
		case DBG_DEV_IO_PENDING: // BSR-1054
		case DBG_DEV_REQ_TIMING:
		case DBG_DEV_PEER_REQ_TIMING:
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

void PrintMonitor(char* res_name)
{	
	char *buf = NULL;
	struct resource* res;
	
	res = GetResourceInfo(res_name);
	if (!res) {
		fprintf(stderr, "Failed to get resource info.\n");
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
	// BSR-1054
	printf("IO_PENDING:\n");
	buf = GetDebugToBuf(IO_PENDING, res);
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

	printf("PEER_REQUEST:\n");
	buf = GetDebugToBuf(PEER_REQUEST, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	printf("AL_STAT:\n");
	buf = GetDebugToBuf(AL_STAT, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	// BSR-838
	printf("RESYNC_RATIO:\n");
	buf = GetDebugToBuf(RESYNC_RATIO, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	// print memory monitoring status
	printf("Memory:\n");
#ifdef _LIN
	// BSR-875 
	buf = GetSysMemoryUsage();
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}
#endif
	buf = GetBsrMemoryUsage(false);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}
#ifdef _LIN
	// BSR-875
	buf = GetBsrModuleMemoryUsage();
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}
#endif
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

// BSR-740 init performance data
void InitMonitor()
{
	struct resource *res, *res_head;

	res = GetResourceInfo(NULL);
	if (!res) {
		fprintf(stderr, "Failed to get resource info.\n");
		return;
	}

	res_head = res;
	while (res) {
		if (InitPerfType(IO_STAT, res) != 0)
			goto next;
		if (InitPerfType(IO_COMPLETE, res) != 0)
			goto next;
		if (InitPerfType(REQUEST, res) != 0)
			goto next;
		if (InitPerfType(PEER_REQUEST, res) != 0)
			goto next;
		if (InitPerfType(AL_STAT, res) != 0)
			goto next;
		if (InitPerfType(NETWORK_SPEED, res) != 0)
			goto next;
		if (InitPerfType(RESYNC_RATIO, res) != 0)
			goto next;
next:
		res = res->next;
	}

	freeResource(res_head);
}


// BSR-688 save aggregated data to file
void MonitorToFile()
{
	struct resource *res, *res_head;
	struct tm base_date_local;
	struct timeb timer_msec;
	char curr_time[64] = {0,};
	
	res = GetResourceInfo(NULL);
	if (!res) {
		fprintf(stderr, "Failed to get resource info.\n");
		return;
	}

	get_perf_path();

	ftime(&timer_msec);
#ifdef _WIN
	localtime_s(&base_date_local, &timer_msec.time);
#else
	base_date_local = *localtime(&timer_msec.time);
#endif	
	sprintf_ex(curr_time, "%04d-%02d-%02d_%02d:%02d:%02d.%03d",
		base_date_local.tm_year + 1900, base_date_local.tm_mon + 1, base_date_local.tm_mday,
		base_date_local.tm_hour, base_date_local.tm_min, base_date_local.tm_sec, timer_msec.millitm);

	res_head = res;
	while (res) {
		char respath[MAX_PATH+RESOURCE_NAME_MAX] = {0,};

		sprintf_ex(respath, "%s%s", g_perf_path, res->name);
#ifdef _WIN
		CreateDirectoryA(respath, NULL);
#else // _LIN
		
		mkdir(respath, 0777);
#endif
		// save monitoring status
		if (GetDebugToFile(IO_STAT, res, respath, curr_time) != 0)
			goto next;
		if (GetDebugToFile(IO_COMPLETE, res, respath, curr_time) != 0)
			goto next;
		if (GetDebugToFile(IO_PENDING, res, respath, curr_time) != 0)
			goto next;
		if (GetDebugToFile(REQUEST, res, respath, curr_time) != 0)
			goto next;
		if (GetDebugToFile(PEER_REQUEST, res, respath, curr_time) != 0)
			goto next;
		if (GetDebugToFile(AL_STAT, res, respath, curr_time) != 0)
			goto next;
		if (GetDebugToFile(NETWORK_SPEED, res, respath, curr_time) != 0)
			goto next;
		if (GetDebugToFile(SEND_BUF, res, respath, curr_time) != 0)
			goto next;
		if (GetDebugToFile(RESYNC_RATIO, res, respath, curr_time) != 0)
			goto next;
next:
		res = res->next;
	}

	// save memory monitoring status
	GetMemInfoToFile(g_perf_path, curr_time);
	freeResource(res_head);
}

// BSR-741 checking the performance monitor status
static bool is_running(bool print_log)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
#else // _LIN
	int fd = 0;
#endif
	unsigned int run = 0;
	int err = 0;

#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		if (print_log)
			fprintf(stderr, "Failed to open bsr\n");
		return false;
	}
	
	if (DeviceIoControl(hDevice, IOCTL_MVOL_GET_BSRMON_RUN, NULL, 0, &run, sizeof(unsigned int), &dwReturned, NULL) == FALSE)
		err = 1;
	
	if (hDevice != INVALID_HANDLE_VALUE)
		CloseHandle(hDevice);

#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		if (print_log)
			fprintf(stderr, "Can not open /dev/bsr-control\n");
		return false;
	}
	if (ioctl(fd, IOCTL_MVOL_GET_BSRMON_RUN, &run) != 0)
		err = 1;

	if (fd)
		close(fd);

#endif

	if (err){
		if (print_log)
			fprintf(stderr, "Failed to IOCTL_MVOL_GET_BSRMON_RUN\n");
		return false;
	} else if (run) {
		if (print_log)
			fprintf(stdout, "bsr performance monitor is enabled.\n");
		return true;
	} else {
		if (print_log)
			fprintf(stdout, "bsr performance monitor is disabled.\n");
		return false;
	}

}


#ifdef _LIN
static pid_t GetRunningPid() {
	char buf[10] = {0,};
	pid_t pid;
	FILE *cmd_pipe = popen("pgrep bsrmon-run", "r");

	if (!cmd_pipe)
		return 0;
	fgets(buf, MAX_PATH, cmd_pipe);
	pid = strtoul(buf, NULL, 10);
	pclose(cmd_pipe);
	return pid;
}
#endif

// BSR-688 watching perf file
void Watch(char *resname, enum get_debug_type type, int vnr, bool scroll)
{
	char watch_path[512] = {0,};

	get_perf_path();

#ifdef _WIN
	if (!is_running(true))
		return;
#else
	pid_t pid = GetRunningPid();
	if (pid <= 0) {
		fprintf(stderr, "bsrmon-run script is not running\n");
		return;
	}
#endif

	if (resname != NULL) {
		int err = CheckResourceInfo(resname, 0, vnr);
		if (err) 
			return;
		
	}

	clear_screen();

	if (vnr != -1)
		sprintf_ex(watch_path, "%s%s%svnr%d_", g_perf_path, resname, _SEPARATOR_, vnr);
	else if (resname)
		sprintf_ex(watch_path, "%s%s%s", g_perf_path, resname, _SEPARATOR_);
	else // memory
		sprintf_ex(watch_path, "%s", g_perf_path);


	sprintf_ex(watch_path, "%s%s", watch_path, perf_type_str(type));

	if (type != -1) {
		switch (type) {
		case IO_STAT:
			watch_io_stat(watch_path, scroll);
			break;
		case IO_COMPLETE:
			watch_io_complete(watch_path, scroll);
			break;
		case IO_PENDING:
			watch_io_pending(watch_path, scroll);
			break;
		case REQUEST:
			watch_req_stat(watch_path, scroll);
			break;
		case PEER_REQUEST:
			watch_peer_req_stat(watch_path, scroll);
			break;
		case AL_STAT:
			watch_al_stat(watch_path, scroll);
			break;
		case NETWORK_SPEED:
			watch_network_speed(watch_path, scroll);
			break;
		case SEND_BUF:
			watch_sendbuf(watch_path, scroll);
			break;
		case MEMORY:
			watch_memory(watch_path, scroll);
			break;
		case RESYNC_RATIO:
			watch_peer_resync_ratio(watch_path, scroll);
			break;

		default:
			usage();
		}
	}
}


void Report(char *resname, char *rfile, enum get_debug_type type, int vnr, struct time_filter *tf, struct peer_stat *peer_list)
{
	char dirpath[512] = {0,};
	char filename[32] = {0,};
	std::set<std::string> filelist;
	std::set<std::string>::iterator iter;

	get_perf_path();

	printf("Report %s ", resname ? resname : "");
	
	if (rfile) {
		printf("[%s]\n", rfile);
		filelist.insert(rfile);
	} else {
		if (resname) {
			sprintf_ex(dirpath, "%s%s", g_perf_path, resname);
		}
		else {
			sprintf_ex(dirpath, "%s", g_perf_path);
		}
		if (vnr != -1) {
			printf("[%s - vnr%u]\n", perf_type_str(type), vnr);
			sprintf_ex(filename, "vnr%d_%s", vnr, perf_type_str(type));	
		}
		else {
			printf("[%s]\n", perf_type_str(type));
			sprintf_ex(filename, "%s", perf_type_str(type));
		}

		// BSR-940 copy to performance data file tmp_* and get list
		get_filelist(dirpath, filename, &filelist, true);

		if (filelist.size() == 0) {
			fprintf(stderr, "Fail to get bsr performance file list.\n");
			return;
		}
	}

	switch (type) {
	case IO_STAT:
		read_io_stat_work(filelist, tf);
		break;
	case IO_COMPLETE:
		read_io_complete_work(filelist, tf);
		break;
	case IO_PENDING:
		read_io_pending_work(filelist, tf);
		break;
	case REQUEST:
		read_req_stat_work(filelist, resname, peer_list, tf);
		break;
	case PEER_REQUEST:
		read_peer_req_stat_work(filelist, resname, peer_list, tf);
		break;
	case AL_STAT:
		read_al_stat_work(filelist, tf);
		break;
	case RESYNC_RATIO:
		read_resync_ratio_work(filelist, resname, peer_list, tf);
		break;
	case NETWORK_SPEED:
		read_network_stat_work(filelist, resname, peer_list, tf);
		break;
	case SEND_BUF:
		read_sendbuf_stat_work(filelist, resname, peer_list, tf);
		break;
	case MEMORY:
		read_memory_work(filelist, tf);
		break;
	
	default:
		usage();
	}

	// BSR-940 remove tmp_* file
	if (!rfile) {
		for (iter = filelist.begin(); iter != filelist.end(); iter++)
			remove(iter->c_str());
	}

}


// BSR-694
void SetOptionValue(enum set_option_type option_type, long value)
{
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsrvflt");
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);
	DWORD lResult = ERROR_SUCCESS;
	DWORD option_value = value;
#else // _LIN
	FILE *fp;
#endif


	if (value <= 0) {
		fprintf(stderr, "Failed to set option value %ld\n", value);
		return;
	}

#ifdef _WIN
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		fprintf(stderr, "Failed to RegOpenValueEx status(0x%x)\n", lResult);
		return;
	}
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
		fprintf(stderr, "Failed to open file(%d)\n", option_type);
	}
#endif
}

long GetOptionValue(enum set_option_type option_type)
{
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsrvflt");
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
	if (ERROR_SUCCESS != lResult)
		value = -1;

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

// BSR-788 print bsrmon options value
static void PrintOptionValue(char * option)
{
	bool print_all = false;
	long value = 0;
	if (strcmp(option, "all") == 0) {
		print_all = true;
	} 
	
	if (print_all || strcmp(option, "period") == 0) {
		value = GetOptionValue(PERIOD);
		if (value <= 0)
			value = DEFAULT_BSRMON_PERIOD;
		printf("period : %ld sec\n", value);
	}
	if (print_all || strcmp(option, "file_size") == 0) {
		value = GetOptionValue(FILE_ROLLING_SIZE);
		if (value <= 0)
			value = DEFAULT_FILE_ROLLING_SIZE;
		printf("file_size : %ld MB\n", value);
	}
	if (print_all || strcmp(option, "file_cnt") == 0) {
		value = GetOptionValue(FILE_ROLLING_CNT);
		if (value <= 0)
			value = DEFAULT_FILE_ROLLONG_CNT;
		printf("file_cnt : %ld\n", value);
	}

	if (!value)
		usage();
}

// BSR-695
static void SetBsrmonRun(unsigned int run)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	unsigned int pre_value;
#else // _LIN
	FILE * fp;
	int fd = 0;
#endif

#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Failed to open bsr\n");
		return;
	}

	// BSR-740 send to bsr engine
	if (DeviceIoControl(hDevice, IOCTL_MVOL_SET_BSRMON_RUN, &run, sizeof(unsigned int), &pre_value, sizeof(unsigned int), &dwReturned, NULL) == FALSE) {
		fprintf(stderr, "Failed to IOCTL_MVOL_SET_BSRMON_RUN\n");
	}

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}

	// BSR-801 if it is the same as the previous value, an error is output
	if (pre_value == run) {
		if (run)
			fprintf(stderr, "Already running\n");
		else
			fprintf(stderr, "bsrmon is not running\n");
	}

#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		fprintf(stderr, "Can not open /dev/bsr-control\n");
		return;
	}
	// BSR-740 send to bsr engine
 	if (ioctl(fd, IOCTL_MVOL_SET_BSRMON_RUN, &run) != 0) {
		fprintf(stderr, "Failed to IOCTL_MVOL_SET_BSRMON_RUN\n");
	}
	if (fd)
		close(fd);

	// write /etc/bsr.d/.bsrmon_run
	fp = fopen(BSR_MON_RUN_REG, "w");
	if (fp != NULL) {
		fprintf(fp, "%d", run);
		fclose(fp);
	} 
	else 
		fprintf(stderr, "Failed to open %s file\n", BSR_MON_RUN_REG);
#endif
	
}

static void StartMonitor()
{
	
#ifdef _LIN
	char buf[MAX_PATH] = {0,};
	pid_t pid;
#endif

	InitMonitor();
	SetBsrmonRun(1);

#ifdef _LIN
	pid = GetRunningPid();
	
	if (pid > 0) {
		fprintf(stderr, "Already running (pid=%d)\n", pid);
		return;
	}
	sprintf(buf, "nohup bsrmon-run >/dev/null 2>&1 &");

	if (system(buf) !=0) {
		fprintf(stderr, "Failed \"%s\"\n", buf);
		return;
	}
#endif

}

static void StopMonitor()
{
#ifdef _LIN
	char buf[MAX_PATH] = {0,};
	pid_t pid = GetRunningPid();

	if (pid <= 0) {
		fprintf(stdout, "bsrmon-run is not running\n");
	} else {
		sprintf(buf, "kill -TERM %d >/dev/null 2>&1", pid);

		if (system(buf) !=0)
			fprintf(stderr, "Failed \"%s\"\n", buf);
	}
#endif

	SetBsrmonRun(0);
}

// BSR-764
static int SetPerfSimulFlag(SIMULATION_PERF_DEGR* pt)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	DWORD       dwReturned = 0;
	BOOL        ret = FALSE;
#else // _LIN
	int fd = 0;
#endif

	int err = 0;

	if (pt == NULL) {
		fprintf(stderr, "LOG_ERROR: %s: Invalid parameter\n", __FUNCTION__);
		return -1;
	}
#ifdef _WIN
	// 1. Open MVOL_DEVICE
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Failed to open bsr\n");
		return -1;
	}

	ret = DeviceIoControl(hDevice, IOCTL_MVOL_SET_SIMUL_PERF_DEGR,
		pt, sizeof(SIMULATION_PERF_DEGR), pt, sizeof(SIMULATION_PERF_DEGR), &dwReturned, NULL);
	if (ret == FALSE) {
		fprintf(stderr, "Failed to IOCTL_MVOL_SET_SIMUL_PERF_DEGR\n");
		err = -1;
	}

	// 3. CloseHandle MVOL_DEVICE
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		fprintf(stderr, "Can not open /dev/bsr-control\n");
		return -1;
	}
	if (ioctl(fd, IOCTL_MVOL_SET_SIMUL_PERF_DEGR, pt) != 0)
		err = 1;

	if (fd)
		close(fd);

#endif

	return err;
}

int ConvertType(char * type_name) 
{
	if (strcmp(type_name, "iostat") == 0)
		return IO_STAT;
	else if (strcmp(type_name, "ioclat") == 0)
		return IO_COMPLETE;
	else if (strcmp(type_name, "io_pending") == 0)
		return IO_PENDING;
	else if (strcmp(type_name, "reqstat") == 0)
		return REQUEST;
	else if (strcmp(type_name, "peer_reqstat") == 0)
		return PEER_REQUEST;
	else if (strcmp(type_name, "alstat") == 0)
		return AL_STAT;
	else if (strcmp(type_name, "network") == 0)
		return NETWORK_SPEED;
	else if (strcmp(type_name, "sendbuf") == 0)
		return SEND_BUF;
	else if (strcmp(type_name, "memstat") == 0)
		return MEMORY;
	// BSR-838
	else if (strcmp(type_name, "resync_ratio") == 0)
		return RESYNC_RATIO;
	else if (strcmp(type_name, "all") == 0)
		return ALL_STAT;
	
	return -1;
}

// BSR-948
void show_current(struct resource *res, int type_flags, bool json, bool now)
{
	int interval = 0;
#ifdef _WIN
	if (!is_running(false))
		return;
#else
	pid_t pid = GetRunningPid();
	if (pid <= 0) {
		fprintf(stderr, "bsrmon-run script is not running\n");
		return;
	}
#endif

	get_perf_path();

	if (!res)
		res = GetResourceInfo(NULL);
	if (!type_flags)
		type_flags = (1 << ALL_STAT) -1;

	if (!res) {
		fprintf(stderr, "Failed to get resource info.\n");
		return;
	}

	if (!now) {
		interval = GetOptionValue(PERIOD);
		if (interval <= 0)
			interval = DEFAULT_BSRMON_PERIOD;
	}
	
	while (1) {
		print_current(res, type_flags, json);
		
		if (!interval)
			break;
		
#ifdef _WIN
		Sleep(interval * 1000);
#else // _LIN
		sleep(interval);
#endif
	}
}

// BSR-948
int get_types(char * types) {
	int type_flags = 0;

	char *ptr, *save_ptr;
	ptr = strtok_r(types, ",", &save_ptr);
	while (ptr) {
		int type = ConvertType(ptr);
		if (type == -1) {
			fprintf(stderr, "bsrmon: Unknown types '%s'\n", ptr);
			return type;
		}
		if (strcmp(ptr, "all") == 0)
			type_flags = (1 << type) - 1;
		else
			type_flags |= 1 << type;

		ptr = strtok_r(NULL, ",", &save_ptr);
	}

	return type_flags;
}

// BSR-948
struct resource * get_res_list(char * res_list)
{
	char *ptr, *save_ptr;
	struct resource *res_head = NULL, *res = NULL, *res_temp = NULL; 
	ptr = strtok_r(res_list, ",", &save_ptr);
	while (ptr) {
		if (strcmp(ptr, "all") == 0) {
			res_head = GetResourceInfo(NULL);
			if (!res_head) {
				fprintf(stderr, "Failed to get resource info.\n");
			}
			return res_head;
		} else {
			res = GetResourceInfo(ptr);
			if (!res) {
				fprintf(stderr, "Failed to get resource info.\n");
				if (res_head)
					free(res_head);
				return NULL;
			}
			if (!res_temp)
				res_head = res;
			else
				res_temp->next = res;
			
			res_temp = res;
		}
		
		ptr = strtok_r(NULL, ",", &save_ptr);
		
	}
	return res_head;
}

// BSR-940 parse peer name list
struct peer_stat * get_conn_list(char * conn_list)
{
	char *ptr, *save_ptr;
	struct peer_stat *peer_head = NULL, *peer_cur = NULL, *peer_end = NULL;
	ptr = strtok_r(conn_list, ",", &save_ptr);
	while (ptr) {
		peer_cur = (struct peer_stat *)malloc(sizeof(struct peer_stat));
		if (!peer_cur) {
			fprintf(stderr, "Failed to malloc peer_stat, size : %lu\n", sizeof(struct peer_stat));
			return NULL;
		}
		memset(peer_cur, 0, sizeof(struct peer_stat));
#ifdef _WIN
		strcpy_s(peer_cur->name, ptr);
#else // _LIN
		strcpy(peer_cur->name, ptr);
#endif		
		peer_cur->next = NULL;
		if (peer_head == NULL) {
			peer_head = peer_end = peer_cur;
		}
		else {
			peer_end->next = peer_cur;
			peer_end = peer_cur;
		}
		
		ptr = strtok_r(NULL, ",", &save_ptr);
		
	}
	return peer_head;
}


#ifdef _WIN
int main(int argc, char* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	int res = ERROR_SUCCESS;
	int argIndex = 0;

	if (argc < 2)
		usage();

	init_perf_type_str();

	for (argIndex = 1; argIndex < argc; argIndex++) {
		if (!strcmp(argv[argIndex], "/print")) {
			argIndex++;
#ifdef _WIN
			// BSR-1102
			if (argIndex < argc) {
				if (!strcmp(argv[argIndex], "tag")) {
					GetBsrMemoryUsage(true);
				}
				else {
					PrintMonitor(argv[argIndex]);
				}
			}
			else {
				usage();
			}
#else
			if (argIndex < argc) {
				PrintMonitor(argv[argIndex]);
			}
			else {
				usage();
			}
#endif
		}
		else if (!strcmp(argv[argIndex], "/file")) {
			argIndex++;
			if (argIndex <= argc) {
				MonitorToFile();
			}
			else
				usage();
		}
		// BSR-772 when the /scroll option is used, the output is scrolled.
		//		default is fixed screen output.
		else if (!strcmp(argv[argIndex], "/watch")) {
			int type = -1;
			char *res_name = NULL;
			bool b_scroll = false;
			int vnr = -1;

			if (++argIndex < argc) {
				type = ConvertType(argv[argIndex]);

				if (type < 0) 
					usage();
			
				if (++argIndex >= argc) {
					if (type != MEMORY)
						usage();
				}

				if (type == MEMORY) {
					if (argIndex < argc) {
						if (!strcmp(argv[argIndex], "/scroll"))
							b_scroll = true;
						else
						usage();
					}
					Watch(NULL, MEMORY, -1, b_scroll);
					break;
				}

				if (argIndex >= argc) 
					usage();
				res_name = argv[argIndex];
				if (type <= RESYNC_RATIO) {
					if (++argIndex < argc)
						vnr = atoi(argv[argIndex]);
					else
						usage();
				} 

				if (++argIndex < argc) {
					if (!strcmp(argv[argIndex], "/scroll"))
						b_scroll = true;
					else
						usage();
				}

				Watch(res_name, (enum get_debug_type)type, vnr, b_scroll);
				break;
			} else
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
		// BSR-788
		else if (!strcmp(argv[argIndex], "/get")) {
			argIndex++;

			if (argIndex < argc) {
				PrintOptionValue(argv[argIndex]);
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/start")) {
			argIndex++;
			if (argIndex <= argc) {
				StartMonitor();
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/stop")) {
			argIndex++;
			if (argIndex <= argc) {
				StopMonitor();
			}
			else
				usage();
		}
		// BSR-741
		else if (!strcmp(argv[argIndex], "/status")) {
			argIndex++;
			if (argIndex <= argc) {
				if (is_running(true)) {
#ifdef _LIN
					// BSR-796 print whether the bsrmon-run script is running
					pid_t pid = GetRunningPid();
					if (pid > 0)
						fprintf(stderr, "bsrmon-run script is running (pid=%d)\n", pid);
					else
						fprintf(stdout, "bsrmon-run script is not running\n");

#endif					
				}
			}
			else
				usage();
		}
		// BSR-709
		else if (!strcmp(argv[argIndex], "/report")) {
			int type = -1;
			char *res_name = NULL;
			char *file_name = NULL;
			int vol_num = -1;
			struct time_filter tf;
			struct peer_stat *peer_list = NULL;

			memset(&tf, 0, sizeof(struct time_filter));

			if (++argIndex < argc) {
				type = ConvertType(argv[argIndex]);

				if (type < 0) {
					usage();
				}
			
				if (type != MEMORY) {
					if (++argIndex >= argc) {
						usage();
					}
					res_name = argv[argIndex];
					if (type <= RESYNC_RATIO) {
						// IO_STAT, IO_COMPLETE, IO_PENDING, AL_STAT, PEER_REQUEST, REQUEST need vnr
						if (++argIndex < argc) {
							vol_num = atoi(argv[argIndex]);
						} else {
							usage();
						}
					}
				}

				// BSR-771 add date and time option to /report command
				for (argIndex++; argIndex < argc; argIndex++) {
					if (!strncmp(argv[argIndex], "/", 1)) {
						int c = *(argv[argIndex] + 1);
						if (++argIndex >= argc) {
							usage();
						}
						switch (c) {
						case 'f':
							file_name = argv[argIndex];
							break;
						case 'p': // BSR-940 peer_name list
							peer_list = get_conn_list(argv[argIndex]);
							break;
						case 'd':
#ifdef _WIN
							strcpy_s(tf.start_date, argv[argIndex]);
							strcpy_s(tf.end_date, argv[argIndex]);
#else
							strcpy(tf.start_date, argv[argIndex]);
							strcpy(tf.end_date, argv[argIndex]);
#endif
							break;
						case 's':
							parse_timestamp(argv[argIndex], tf.start_date, &tf.start_time);
							break;
						case 'e':
							parse_timestamp(argv[argIndex], tf.end_date, &tf.end_time);
							break;
						default:
							usage();
						}
					} else {
						usage();
					}
				}

				if (!(strlen(tf.start_date) && strlen(tf.end_date))) {
					if (strlen(tf.start_date) || strlen(tf.end_date))
						goto report_fail;
				}

				if (!(tf.start_time.t_hour && tf.end_time.t_hour)) {
					if (tf.start_time.t_hour || tf.end_time.t_hour)
						goto report_fail;
				}


				Report(res_name, file_name, (enum get_debug_type)type, vol_num, &tf, peer_list);

				break;

			report_fail:
				printf("invalid parameters.\n"
					"usage examples: \n"
					"/s hh:mm[:ss] /e hh:mm[:ss] \n"
					"/s YYYY-MM-DD /e YYYY-MM-DD \n"
					"/s YYYY-MM-DD_hh:mm[:ss] /e YYYY-MM-DD_hh:mm[:ss] \n"
					);
				printf("\n");
				exit(ERROR_INVALID_PARAMETER);
				
			}
			else {
				usage();
			}
		}
		// BSR-764 add I/O performance degradation simulation
		else if (!strcmp(argv[argIndex], "/io_delay_test"))
		{
			SIMULATION_PERF_DEGR pt;
			argIndex++;
			// get parameter 1 (flag)
			if (argIndex < argc) {
				pt.flag = atoi(argv[argIndex]);
				argIndex++;
				// get parameter 2 (type)
				if (argIndex < argc) {
					pt.type = atoi(argv[argIndex]);
					argIndex++;
					// get parameter 3 (time)
					if (argIndex < argc) {
						pt.delay_time = atoi(argv[argIndex]);
						if (pt.delay_time >= 0) 
							SetPerfSimulFlag(&pt);
					}
					else {
						perf_test_usage();
					}
				}
				else if (pt.flag == 0) {
					SetPerfSimulFlag(&pt);
				}
				else {
					perf_test_usage();
				}
			}
			else {
				perf_test_usage();
			}

		}
		// BSR-948 print all last collected performance data for all resources
		else if (!strcmp(argv[argIndex], "/show"))
		{
			int type_flags = 0;
			bool json = false;
			bool now = true;
			struct resource *res_head = NULL;
			for (argIndex++; argIndex < argc; argIndex++) {
				if (!strcmp(argv[argIndex], "/j") || !strcmp(argv[argIndex], "/json"))
					json = true;
				else if (!strcmp(argv[argIndex], "/c") || !strcmp(argv[argIndex], "/continue"))
					now = false;
				else if (!strncmp(argv[argIndex], "/", 1)) {
					int c = *(argv[argIndex] + 1);
					if (++argIndex >= argc) {
						usage();
					}
					switch (c) {
					case 't':
						// types
						type_flags = get_types(argv[argIndex]);
						break;
					case 'r':
						//resource
						res_head = get_res_list(argv[argIndex]);
						if (!res_head)
							exit(ERROR_INVALID_PARAMETER);
						break;
					default:
						usage();
					}
				} else {
					usage();
				}
			}
			if (type_flags != -1)
				show_current(res_head, type_flags, json, now);
			
			freeResource(res_head);
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