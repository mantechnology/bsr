#ifdef _WIN
#include <tchar.h>
#else // _LIN
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#endif
#include <time.h>
#include <sys/timeb.h>
#include <string.h>
#include "bsrmon.h"
#include "module_debug.h"
#include "monitor_collect.h"
#include "read_stat.h"
#include "../../../bsr-headers/bsr_ioctl.h"

#ifdef _LIN
bool receive_signal;
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
		"bsrmon /debug resync_ratio r1 1 0\n"
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
		"   /start {types[,...]|all}\n"
		"   /stop\n"
		"   /status\n"
		//"   /print\n"
		"   /show [/t {types[,...]|all}] [/r {resource[,...]|all}] [/j|/json] [/c|/continue]\n"
		"   /watch {types} [/scroll]\n"
		"   /report {types} [/f {filename}] [/p {peer_name[,...]}]\n"
		"                                   [/d {YYYY-MM-DD}]\n"
		"                                   [/s {YYYY-MM-DD|hh:mm[:ss]|YYYY-MM-DD_hh:mm[:ss]}]\n"
		"                                   [/e {YYYY-MM-DD|hh:mm[:ss]|YYYY-MM-DD_hh:mm[:ss]}]\n"
		"   /set {period, file_size, file_cnt } {value}\n"
		// BSR-1236
		"   /set {total_file_size} {totcal resource count} {total volume count} {total capacity}\n"
		"   /get {all, period, file_size, file_cnt, types}\n"
		// BSR-1236
		"   /get {total_file_size} {totcal resource count} {total volume count}\n"
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
		bsrmon_log(stderr, "DEBUG_ERROR: Failed to malloc BSR_DEBUG_INFO\n");
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
				bsrmon_log(stderr, "DEBUG_ERROR: Failed to get bsr debuginfo. (Err=%u)\n", ret);
				bsrmon_log(stderr, "buffer overflow.\n");
				break;
			}

			// reallocate when buffer is insufficient
			debugInfo = (PBSR_DEBUG_INFO)realloc(debugInfo, sizeof(BSR_DEBUG_INFO) + size);
			if (!debugInfo) {
				bsrmon_log(stderr, "DEBUG_ERROR: Failed to realloc BSR_DEBUG_INFO\n");
				break;
			}
			debugInfo->buf_size = size;
		}
		else {
			bsrmon_log(stderr, "DEBUG_ERROR: Failed to get bsr debuginfo. (Err=%u)\n", ret);
			break;
		}
	}

	if (ret == ERROR_SUCCESS) {
		bsrmon_log(stdout, "%s\n", debugInfo->buf);
	}
	else if (ret == ERROR_INVALID_PARAMETER) {
		bsrmon_log(stderr, "invalid paramter.\n");
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
	buf = GetDebugToBuf(BSRMON_IO_STAT, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	printf("IO_COMPLETE:\n");
	buf = GetDebugToBuf(BSRMON_IO_COMPLETE, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}
	// BSR-1054
	printf("IO_PENDING:\n");
	buf = GetDebugToBuf(BSRMON_IO_PENDING, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	printf("REQUEST:\n");
	buf = GetDebugToBuf(BSRMON_REQUEST, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	printf("PEER_REQUEST:\n");
	buf = GetDebugToBuf(BSRMON_PEER_REQUEST, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	printf("AL_STAT:\n");
	buf = GetDebugToBuf(BSRMON_AL_STAT, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}

	// BSR-838
	printf("RESYNC_RATIO:\n");
	buf = GetDebugToBuf(BSRMON_RESYNC_RATIO, res);
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
	buf = GetDebugToBuf(BSRMON_NETWORK_SPEED, res);
	if (buf) {
		printf("%s\n", buf);
		free(buf);
		buf = NULL;
	}
	buf = GetDebugToBuf(BSRMON_SEND_BUF, res);
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
		bsrmon_log(stderr, "Failed to get resource info.\n");
		return;
	}

	res_head = res;
	while (res) {
		if (InitPerfType(BSRMON_IO_STAT, res) != 0)
			goto next;
		if (InitPerfType(BSRMON_IO_COMPLETE, res) != 0)
			goto next;
		if (InitPerfType(BSRMON_REQUEST, res) != 0)
			goto next;
		if (InitPerfType(BSRMON_PEER_REQUEST, res) != 0)
			goto next;
		if (InitPerfType(BSRMON_AL_STAT, res) != 0)
			goto next;
		if (InitPerfType(BSRMON_NETWORK_SPEED, res) != 0)
			goto next;
		if (InitPerfType(BSRMON_RESYNC_RATIO, res) != 0)
			goto next;
next:
		res = res->next;
	}

	freeResource(res_head);
}


// BSR-688 save aggregated data to file
void MonitorToFile(int type_flags)
{
	struct resource *res, *res_head;
	struct tm base_date_local;
	struct timeb timer_msec;
	char curr_time[64] = {0,};
	
	res = GetResourceInfo(NULL);
	if (!res) {
		bsrmon_log(stderr, "Failed to get resource info.\n");
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
		if ((type_flags & (1 << BSRMON_IO_STAT)) && (GetDebugToFile(BSRMON_IO_STAT, res, respath, curr_time) != 0))
			goto next;
		if ((type_flags & (1 << BSRMON_IO_COMPLETE)) && (GetDebugToFile(BSRMON_IO_COMPLETE, res, respath, curr_time) != 0))
			goto next;
		if ((type_flags & (1 << BSRMON_IO_PENDING)) && (GetDebugToFile(BSRMON_IO_PENDING, res, respath, curr_time) != 0))
			goto next;
		if ((type_flags & (1 << BSRMON_REQUEST)) && (GetDebugToFile(BSRMON_REQUEST, res, respath, curr_time) != 0))
			goto next;
		if ((type_flags & (1 << BSRMON_PEER_REQUEST)) && (GetDebugToFile(BSRMON_PEER_REQUEST, res, respath, curr_time) != 0))
			goto next;
		if ((type_flags & (1 << BSRMON_AL_STAT)) && (GetDebugToFile(BSRMON_AL_STAT, res, respath, curr_time) != 0))
			goto next;
		if ((type_flags & (1 << BSRMON_NETWORK_SPEED)) && (GetDebugToFile(BSRMON_NETWORK_SPEED, res, respath, curr_time) != 0))
			goto next;
		if ((type_flags & (1 << BSRMON_SEND_BUF)) && (GetDebugToFile(BSRMON_SEND_BUF, res, respath, curr_time) != 0))
			goto next;
		if ((type_flags & (1 << BSRMON_RESYNC_RATIO)) && (GetDebugToFile(BSRMON_RESYNC_RATIO, res, respath, curr_time) != 0))
			goto next;
next:
		res = res->next;
	}

	// save memory monitoring status
	if (type_flags & (1 << BSRMON_MEMORY))
		GetMemInfoToFile(g_perf_path, curr_time);
	freeResource(res_head);
}

static pid_t GetRunningPid() 
{
#ifdef _WIN
	DWORD error = 0;
	HANDLE hProc = NULL;
	DWORD pid = GetOptionValue(BSRMON_PID);

	if (pid > 0) {
		if (hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)) {
			TCHAR p_path[MAX_PATH]={0,};
			TCHAR p_name[MAX_PATH]={0,};
			DWORD len = sizeof(p_path);
			// BSR-1138 get process name from full path
			QueryFullProcessImageName(hProc, 0, p_path, &len);
			_wsplitpath_s(p_path, NULL, 0, NULL, 0, p_name, len, NULL, 0);
			CloseHandle(hProc);

			if (!wcsncmp(p_name, L"bsrmon", 6)) {
				// bsrmon running
				return pid;
			}
		}
		pid = 0;
		SetOptionValue(BSRMON_PID, 0);
		SetOptionValue(BSRMON_STOP_SIGNAL, 0);
	}
#else // _LIN
	char buf[10] = {0,};
	pid_t pid = 0;
	pid_t c_pid = 0;
	FILE *cmd_pipe = popen("pgrep -fa \"bsrmon /start\" | grep -v pgrep | awk '{print $1}'", "r");
	if (!cmd_pipe)
		return 0;
	
	// current pid
	c_pid = getpid();

	while (fgets(buf, MAX_PATH, cmd_pipe) != NULL) {
		pid = strtoul(buf, NULL, 10);
		if (pid == c_pid)
			pid = 0;
		else if (pid > 0)
			break;
	}
	pclose(cmd_pipe);
#endif

	return pid;
}


// BSR-688 watching perf file
void Watch(char *resname, enum bsrmon_type type, int vnr, bool scroll)
{
	char watch_path[512] = {0,};
	pid_t pid = 0;

	get_perf_path();

	pid = GetRunningPid();
	if (pid <= 0) {
		fprintf(stderr, "bsrmon is not running\n");
		return;
	}

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
		case BSRMON_IO_STAT:
			watch_io_stat(watch_path, scroll);
			break;
		case BSRMON_IO_COMPLETE:
			watch_io_complete(watch_path, scroll);
			break;
		case BSRMON_IO_PENDING:
			watch_io_pending(watch_path, scroll);
			break;
		case BSRMON_REQUEST:
			watch_req_stat(watch_path, scroll);
			break;
		case BSRMON_PEER_REQUEST:
			watch_peer_req_stat(watch_path, scroll);
			break;
		case BSRMON_AL_STAT:
			watch_al_stat(watch_path, scroll);
			break;
		case BSRMON_NETWORK_SPEED:
			watch_network_speed(watch_path, scroll);
			break;
		case BSRMON_SEND_BUF:
			watch_sendbuf(watch_path, scroll);
			break;
		case BSRMON_MEMORY:
			watch_memory(watch_path, scroll);
			break;
		case BSRMON_RESYNC_RATIO:
			watch_peer_resync_ratio(watch_path, scroll);
			break;

		default:
			usage();
		}
	}
}


void Report(char *resname, char *rfile, enum bsrmon_type type, int vnr, struct time_filter *tf, struct peer_stat *peer_list)
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
	case BSRMON_IO_STAT:
		read_io_stat_work(filelist, tf);
		break;
	case BSRMON_IO_COMPLETE:
		read_io_complete_work(filelist, tf);
		break;
	case BSRMON_IO_PENDING:
		read_io_pending_work(filelist, tf);
		break;
	case BSRMON_REQUEST:
		read_req_stat_work(filelist, resname, peer_list, tf);
		break;
	case BSRMON_PEER_REQUEST:
		read_peer_req_stat_work(filelist, resname, peer_list, tf);
		break;
	case BSRMON_AL_STAT:
		read_al_stat_work(filelist, tf);
		break;
	case BSRMON_RESYNC_RATIO:
		read_resync_ratio_work(filelist, resname, peer_list, tf);
		break;
	case BSRMON_NETWORK_SPEED:
		read_network_stat_work(filelist, resname, peer_list, tf);
		break;
	case BSRMON_SEND_BUF:
		read_sendbuf_stat_work(filelist, resname, peer_list, tf);
		break;
	case BSRMON_MEMORY:
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

	if ((option_type != BSRMON_RUN) && 
		(option_type != BSRMON_STOP_SIGNAL) &&
		(option_type != BSRMON_PID) &&
		(value <= 0)) {
		bsrmon_log(stderr, "Failed to set option value %ld\n", value);
		return;
	}

#ifdef _WIN
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		bsrmon_log(stderr, "Failed to RegOpenValueEx status(0x%x)\n", lResult);
		return;
	}
#endif

	if (option_type == BSRMON_PERIOD && value > 0)
#ifdef _WIN
		lResult = RegSetValueEx(hKey, _T("bsrmon_period"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#else // _LIN
		fp = fopen(PERIOD_OPTION_PATH, "w");
#endif
	else if (option_type == BSRMON_FILE_SIZE && value > 0)
#ifdef _WIN
		lResult = RegSetValueEx(hKey, _T("bsrmon_file_size"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#else // _LIN
		fp = fopen(FILE_SIZE_OPTION_PATH, "w");
#endif
	else if (option_type == BSRMON_FILE_CNT && value > 0)
#ifdef _WIN
		lResult = RegSetValueEx(hKey, _T("bsrmon_file_cnt"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#else // _LIN
		fp = fopen(FILE_CNT_OPTION_PATH, "w");
#endif
	else if (option_type == BSRMON_RUN)
#ifdef _WIN
		lResult = RegSetValueEx(hKey, _T("bsrmon_run"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#else // _LIN
		fp = fopen(BSRMON_RUN_REG, "w");
#endif
	// BSR-1138 save bsrmon collection types
	else if (option_type == BSRMON_TYPES && value > 0)
#ifdef _WIN
		lResult = RegSetValueEx(hKey, _T("bsrmon_types"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#else // _LIN
		fp = fopen(BSRMON_TYPES_REG, "w");
#endif
#ifdef _WIN
	else if (option_type == BSRMON_PID && value >= 0)
		lResult = RegSetValueEx(hKey, _T("bsrmon_pid"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
	else if (option_type == BSRMON_STOP_SIGNAL && value >= 0)
		lResult = RegSetValueEx(hKey, _T("bsrmon_stop_signal"), 0, REG_DWORD, (LPBYTE)&option_value, sizeof(option_value));
#endif
	else {
#ifdef _WIN
		RegCloseKey(hKey);
#endif
		usage();
	}

#ifdef _WIN
	if (ERROR_SUCCESS != lResult)
		bsrmon_log(stderr, "Failed to RegSetValueEx status(0x%x)\n", lResult);

	RegCloseKey(hKey);
#else // _LIN
	if (fp != NULL) {
		fprintf(fp, "%ld", value);
		fclose(fp);
	}
	else {
		bsrmon_log(stderr, "Failed to open file(%d)\n", option_type);
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
		bsrmon_log(stderr, "Failed to RegOpenValueEx status(0x%x)\n", lResult);
		return -1;
	}
#else // _LIN
	FILE *fp;
	long value;
#endif

	if (option_type == BSRMON_PERIOD)
#ifdef _WIN
		lResult = RegQueryValueEx(hKey, _T("bsrmon_period"), NULL, &type, (LPBYTE)&value, &size);
#else // _LIN
		fp = fopen(PERIOD_OPTION_PATH, "r");
#endif
	else if (option_type == BSRMON_FILE_SIZE)
#ifdef _WIN
		lResult = RegQueryValueEx(hKey, _T("bsrmon_file_size"), NULL, &type, (LPBYTE)&value, &size);
#else // _LIN
		fp = fopen(FILE_SIZE_OPTION_PATH, "r");
#endif
	else if (option_type == BSRMON_FILE_CNT)
#ifdef _WIN
		lResult = RegQueryValueEx(hKey, _T("bsrmon_file_cnt"), NULL, &type, (LPBYTE)&value, &size);
#else // _LIN
		fp = fopen(FILE_CNT_OPTION_PATH, "r");
#endif
	else if (option_type == BSRMON_RUN)
#ifdef _WIN
		lResult = RegQueryValueEx(hKey, _T("bsrmon_run"), NULL, &type, (LPBYTE)&value, &size);
#else // _LIN
		fp = fopen(BSRMON_RUN_REG, "r");
#endif
	else if (option_type == BSRMON_TYPES)
#ifdef _WIN
		lResult = RegQueryValueEx(hKey, _T("bsrmon_types"), NULL, &type, (LPBYTE)&value, &size);
#else // _LIN
		fp = fopen(BSRMON_TYPES_REG, "r");
#endif
#ifdef _WIN
	else if (option_type == BSRMON_STOP_SIGNAL)
		lResult = RegQueryValueEx(hKey, _T("bsrmon_stop_signal"), NULL, &type, (LPBYTE)&value, &size);
	else if (option_type == BSRMON_PID)
		lResult = RegQueryValueEx(hKey, _T("bsrmon_pid"), NULL, &type, (LPBYTE)&value, &size);
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

static void GetCurrentlySetTypeCount(long *gt_cnt, long *rt_cnt, long *vt_cnt, bool print)
{
	long type = GetOptionValue(BSRMON_TYPES);

	*gt_cnt = *rt_cnt = *vt_cnt = 0;

	if (type <= 0)
		type = DEFAULT_BSRMON_TYPES;

	for (int i = 0; i <= BSRMON_ALL_STAT; i++) {
		if (type & (1 << i)) {
			for (int j = 0; j < sizeof(global_types_str) / sizeof(global_types_str[0]); j++) {
				if (strcmp(global_types_str[j], total_types_str[i]) == 0) {
					(*gt_cnt)++;
					if (print)
						printf("%s ", global_types_str[j]);
				}
			}

			for (int j = 0; j < sizeof(res_types_str) / sizeof(res_types_str[0]); j++) {
				if (strcmp(res_types_str[j], total_types_str[i]) == 0) {
					(*rt_cnt)++;
					if (print)
						printf("%s ", res_types_str[j]);
				}
			}

			for (int j = 0; j < sizeof(vol_types_str) / sizeof(vol_types_str[0]); j++) {
				if (strcmp(vol_types_str[j], total_types_str[i]) == 0) {
					(*vt_cnt)++;
					if (print)
						printf("%s ", vol_types_str[j]);
				}
			}
		}
	}
}

// BSR-788 print bsrmon options value
static void PrintOptionValue(char * option, char *param1, char *param2)
{
	bool print_all = false;
	// BSR-1236
	bool print_total_file_size = false;
	long value = 0;
	long type = 0, period = 0, file_size = 0, file_cnt = 0;
	// BSR-1236
	long tt_cnt = 0, gt_cnt = 0, rt_cnt = 0, vt_cnt = 0;

	// BSR-1138
	if (strcmp(option, "run") == 0) {
		value = GetOptionValue(BSRMON_RUN);
		if (value < 0)
			value = 1;
		printf("%ld\n", value);
		return;
	}
#ifdef _WIN
	if (strcmp(option, "pid") == 0) {
		value = GetOptionValue(BSRMON_PID);
		if (value < 0)
			value = 1;
		printf("%ld\n", value);
		return;
	}
#endif
	if (strcmp(option, "all") == 0) {
		print_all = true;
	}
	// BSR-1236
	else if (strcmp(option, "total_file_size") == 0) {
		print_all = true;
		print_total_file_size = true;
	}
	
	if (print_all || strcmp(option, "period") == 0) {
		period = GetOptionValue(BSRMON_PERIOD);
		if (period <= 0)
			period = DEFAULT_BSRMON_PERIOD;
		if (!print_total_file_size) {
			printf("The collection period is as follows.\n");
			printf("\tperiod : %ldseconds\n\n", period);
		}
	}
	if (print_all || strcmp(option, "file_size") == 0) {
		file_size = GetOptionValue(BSRMON_FILE_SIZE);
		if (file_size <= 0)
			file_size = DEFAULT_BSRMON_FILE_SIZE;
		if (!print_total_file_size) {
			printf("The maximum size for each type of collected file is as follows, and if the maximum file size is exceeded, it is backed up and saved according to the file_cnt setting.\n");
			printf("\tMaximum file size by type : %ldMB\n\n", file_size);
		}
	}
	if (print_all || strcmp(option, "file_cnt") == 0) {
		file_cnt = GetOptionValue(BSRMON_FILE_CNT);
		if (file_cnt <= 0)
			file_cnt = DEFAULT_FILE_CNT;
		if (!print_total_file_size) {
			printf("The maximum number of files stored per type is as follows.\n");
			printf("\tMaximum number of files per type : %ld\n\n", file_cnt);
		}
	}

	// BSR-1138
	if (print_all || strcmp(option, "types") == 0) {
		int print_sep = 0;

		if (!print_total_file_size) {
			printf("The types to be collected are as follows.\n");
			printf("\t");
		}

		GetCurrentlySetTypeCount(&gt_cnt, &rt_cnt, &vt_cnt, print_total_file_size ? false : true);
		tt_cnt = gt_cnt + rt_cnt + vt_cnt;

		if (!print_total_file_size)
			printf("\n\n");
	}

	if (print_all) {
		// BSR-1236 add capacity for bsrmon logs as well. ((DEFAULT_BSRMON_LOG_ROLLING_SIZE * 2))
		int bsrmon_log_cap = DEFAULT_BSRMON_LOG_ROLLING_SIZE * 2;

		if (!print_total_file_size) {
			printf("The current setting requires a maximum of \"%ldMB\" to store the collected data of one resource of one volume.\n", file_size * file_cnt * tt_cnt + bsrmon_log_cap);
			printf("\tThe command \"/get total_file_size\" tells you the maximum storage space you need based on the count of resources and volumes.\n");
		} else {
			int res_cnt, vol_cnt;

			res_cnt = atoi(param1);
			vol_cnt = atoi(param2);

			if (res_cnt > vol_cnt)
				printf("The number of volumes (%d) cannot be less than the number of resources (%d). Please check again.\n", vol_cnt, res_cnt);
			else 
				printf("%d resource of %d volumes require up to \"%ldMB\" of storage space in the current settings.\n", vol_cnt, res_cnt,
				((file_size * file_cnt * tt_cnt) * res_cnt) + (file_size * file_cnt * vt_cnt * ((vol_cnt - res_cnt))) + bsrmon_log_cap);
		}
	}

	if (!value && !type && !file_cnt && !file_size && !period)
		usage();
}

// BSR-741 checking the performance monitor status
static int is_running(bool print_log)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
#endif
	int run = 0;

	run = GetOptionValue(BSRMON_RUN);
	if (run < 0)
		run = 1;

#ifdef _WIN
	if (GetOptionValue(BSRMON_STOP_SIGNAL) == 1) {
		if (print_log)
			fprintf(stdout, "bsrmon : stopping.\n");
		return run;
	}
#endif

	if (run > 0) {
		if (print_log) {
			// BSR-796 print whether the bsrmon is running
			pid_t pid = GetRunningPid();
			if (pid > 0) {
				fprintf(stdout, "bsrmon : running\n");
				fprintf(stdout, "%6s : %d\n", "pid", pid);
				PrintOptionValue((char *)"types", NULL, NULL);
			}
			else
				fprintf(stdout, "bsrmon : stopped\n");

		}
	} else {
		if (print_log)
			fprintf(stdout, "bsrmon : disabled\n");
	}

	return run;
}


// BSR-695
static void SetBsrmonRun(unsigned int run, int flags)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	unsigned int pre_value;
#else // _LIN
	int fd = 0;
#endif

	if (run && (GetOptionValue(BSRMON_RUN) < 1))
		bsrmon_log(stdout, "bsrmon enabled.\n");

	SetOptionValue(BSRMON_RUN, run);

	if (flags) {
		char types[128] = {0,};
		for (int i = 0; i <= BSRMON_ALL_STAT; i++) {
			if (flags & (1 << i)) {
#ifdef _WIN
				strcat_s(types, total_types_str[i]);
				strcat_s(types," ");
#else
				strcat(types, total_types_str[i]);
				strcat(types," ");
#endif
			}
		}
		bsrmon_log(stdout, "collection types : %s\n", types);
	}

#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		bsrmon_log(stderr, "Failed to open bsr\n");
		return;
	}

	// BSR-740 send to bsr engine
	if (DeviceIoControl(hDevice, IOCTL_MVOL_SET_BSRMON_RUN, &flags, sizeof(unsigned int), &pre_value, sizeof(unsigned int), &dwReturned, NULL) == FALSE) {
		bsrmon_log(stderr, "Failed to IOCTL_MVOL_SET_BSRMON_RUN\n");
	}

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}

	// BSR-801 if it is the same as the previous value, an error is output
	if (pre_value == flags) {
		if (flags)
			fprintf(stderr, "bsrmon already running\n");
		else
			fprintf(stderr, "bsrmon is not running\n");
	}

#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		//fprintf(stderr, "Can not open /dev/bsr-control\n");
		return;
	}
	// BSR-740 send to bsr engine
 	if (ioctl(fd, IOCTL_MVOL_SET_BSRMON_RUN, &flags) != 0) {
		bsrmon_log(stderr, "Failed to IOCTL_MVOL_SET_BSRMON_RUN\n");
	}
	if (fd)
		close(fd);
#endif
	
}

#ifdef _LIN
// BSR-1138 bsrmon kill signal handler
void sig_handler(int signo)
{
	bsrmon_log(stdout, "receive bsrmon stop signal.\n");
	receive_signal = true;
}
#endif

// BSR-1138
static void BsrmonRun(int flags)
{
	int interval = 0;
	pid_t processId = 0;
	
	write_log = true;

#ifdef _WIN
	processId = GetCurrentProcessId();
	bsrmon_log(stdout, "bsrmon start. (pid=%d)\n", processId);

	SetOptionValue(BSRMON_PID, processId);
	InitMonitor();
	SetBsrmonRun(1, flags);

	// terminates when BSRMON_STOP_SIGNAL is set
	while (GetOptionValue(BSRMON_STOP_SIGNAL) == 0) {
		interval = GetOptionValue(BSRMON_PERIOD);
		if (interval <= 0)
			interval = DEFAULT_BSRMON_PERIOD;
		MonitorToFile(flags);
		Sleep(interval * 1000);
	}

	// stop done
	SetOptionValue(BSRMON_STOP_SIGNAL, 0);
	SetOptionValue(BSRMON_PID, 0);

	bsrmon_log(stdout, "bsrmon stop. (pid=%d)\n", processId);
#else // _LIN
	processId = getpid();
	bsrmon_log(stdout, "bsrmon start. (pid=%d)\n", processId);

	receive_signal = false;
	signal(SIGUSR1, sig_handler);

	InitMonitor();
	SetBsrmonRun(1, flags);

	// terminates when SIGUSR1 is received
	while (!receive_signal) {
		interval = GetOptionValue(BSRMON_PERIOD);
		if (interval <= 0)
			interval = DEFAULT_BSRMON_PERIOD;
		MonitorToFile(flags);
		sleep(interval);
	}
	
	bsrmon_log(stdout, "bsrmon stop. (pid=%d)\n", processId);
#endif

}


static void StartMonitor(int flags)
{
#ifdef _WIN
	WCHAR systemDirPath[MAX_PATH];
	WCHAR appName[MAX_PATH];
	WCHAR cmd[MAX_PATH];

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	DWORD pid = GetRunningPid();

	if (GetOptionValue(BSRMON_STOP_SIGNAL) == 1) {
		fprintf(stdout, "bsrmon is stopping. please try again in a moment.\n");
		return;
	}

	if (pid > 0) {
		fprintf(stdout, "bsrmon already running (pid=%d)\n", pid);
		return;
	}

	if (flags)
		SetOptionValue(BSRMON_TYPES, flags);
	else {
		flags = GetOptionValue(BSRMON_TYPES);
		if (flags <= 0)
			flags = DEFAULT_BSRMON_TYPES; // all
	}


    GetSystemDirectory(systemDirPath, sizeof(systemDirPath) / sizeof(WCHAR));
    swprintf_s(appName, MAX_PATH, L"%s\\cmd.exe", systemDirPath);
	swprintf_s(cmd, MAX_PATH, L"powershell.exe -Command \"start-process bsrmon -ArgumentList \"/start_ex\", \"%d\" -WindowStyle Hidden\"", flags);
	ZeroMemory(&si, sizeof(STARTUPINFO));

	si.cb = sizeof(STARTUPINFO);

	// BSR-1138 bsrmon /start_ex runs in background
	if (CreateProcess(NULL, cmd, NULL,
		NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	} 
	else {
		fprintf(stderr, "Failed to start bsrmon.\n");
	}
#else // _LIN
	pid_t pid;

	pid = GetRunningPid();
	
	if (pid > 0) {
		fprintf(stdout, "bsrmon already running (pid=%d)\n", pid);
		return;
	}

	// BSR-1138 fork() bsrmon /start
	pid = fork();

	if (pid < 0) {
		bsrmon_log(stderr, "Failed to start bsrmon.\n");
		return;
	} else if (pid == 0) {
		if (flags)
			SetOptionValue(BSRMON_TYPES, flags);
		else {
			flags = GetOptionValue(BSRMON_TYPES);
			if (flags <= 0)
				flags = DEFAULT_BSRMON_TYPES; // all
		}
		BsrmonRun(flags);
	} else 
		return;
#endif
}




static void StopMonitor(int disable)
{
	int run = 0;
	pid_t pid = 0;
	
	pid = GetRunningPid();
#ifdef _WIN
	if (GetOptionValue(BSRMON_STOP_SIGNAL) == 1) {
		fprintf(stdout, "bsrmon is already stopping.\n");
		return;
	}
#endif
	run = is_running(false);
	if (!run) {
		fprintf(stdout, "bsrmon is not running\n");
		return;
	}
#ifdef _WIN
	if (pid > 0) {
		SetOptionValue(BSRMON_STOP_SIGNAL, 1);
		_bsrmon_log(__FUNCTION__, __LINE__, "set BSRMON_STOP_SIGNAL\n");
	}
	if (disable) {
		SetBsrmonRun(0, 0);
		_bsrmon_log(__FUNCTION__, __LINE__, "bsrmon disabled.\n");
	} 
#else // _LIN
	if (pid > 0) {
		if (kill(pid, SIGUSR1) != 0)
			fprintf(stderr, "Failed to stop bsrmon\n");
		else
			_bsrmon_log(__FUNCTION__, __LINE__, "send bsrmon stop signal.\n");
	}
	SetBsrmonRun(0, 0);
	_bsrmon_log(__FUNCTION__, __LINE__, "bsrmon disabled.\n");
#endif
}

static int SetFileSizeForUserSettings(long res_cnt, long vol_cnt, long total_file_size)
{
	if (res_cnt > vol_cnt) {
		printf("The number of resources(%d) cannot be more than the number of volumes(%d). Please check again.\n", res_cnt, vol_cnt);
		return -1;
	}
	else {
		long total_cnt = 0, file_cnt = 0;
		int bsrmon_log_size = DEFAULT_BSRMON_LOG_ROLLING_SIZE * 2;
		float file_size = 0;
		long gt_cnt = 0, rt_cnt = 0, vt_cnt = 0;

		file_cnt = GetOptionValue(BSRMON_FILE_CNT);
		if (file_cnt <= 0)
			file_cnt = DEFAULT_FILE_CNT;

		GetCurrentlySetTypeCount(&gt_cnt, &rt_cnt, &vt_cnt, false);

		// global "memstat"
		total_cnt = total_cnt + gt_cnt;
		// res "network", "sendbuf"
		total_cnt = total_cnt + (rt_cnt * res_cnt);
		// vol "iostat", "ioclat", "io_pending", "alstat", "peer_reqstat", "reqstat", "resync_ratio",
		total_cnt = total_cnt + (vt_cnt * vol_cnt);

		if (total_cnt)
			file_size = (float)((total_file_size - bsrmon_log_size) / total_cnt) / file_cnt;
		else
			file_size = (float)(total_file_size - bsrmon_log_size) / file_cnt;

		if (file_size < 1) {
			printf("Resource %d, volume %d requires a minimum %ldMB capacity. Please check again.\n", res_cnt, vol_cnt, (total_cnt * file_cnt) + bsrmon_log_size);
			return -1;
		}
		else {
			SetOptionValue(BSRMON_FILE_SIZE, (long)file_size);
			printf("The file size is set to %ldMB. The file count is %ld, so the total required capacity is %ldMB.\n", (long)file_size, file_cnt, ((total_cnt * file_cnt) * (long)file_size) + bsrmon_log_size);
		}
	}

	return 0;
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
		return BSRMON_IO_STAT;
	else if (strcmp(type_name, "ioclat") == 0)
		return BSRMON_IO_COMPLETE;
	else if (strcmp(type_name, "io_pending") == 0)
		return BSRMON_IO_PENDING;
	else if (strcmp(type_name, "reqstat") == 0)
		return BSRMON_REQUEST;
	else if (strcmp(type_name, "peer_reqstat") == 0)
		return BSRMON_PEER_REQUEST;
	else if (strcmp(type_name, "alstat") == 0)
		return BSRMON_AL_STAT;
	else if (strcmp(type_name, "network") == 0)
		return BSRMON_NETWORK_SPEED;
	else if (strcmp(type_name, "sendbuf") == 0)
		return BSRMON_SEND_BUF;
	else if (strcmp(type_name, "memstat") == 0)
		return BSRMON_MEMORY;
	// BSR-838
	else if (strcmp(type_name, "resync_ratio") == 0)
		return BSRMON_RESYNC_RATIO;
	else if (strcmp(type_name, "all") == 0)
		return BSRMON_ALL_STAT;
	
	return -1;
}

// BSR-948
void show_current(struct resource *res, int type_flags, bool json, bool now)
{
	int interval = 0;
	pid_t pid = GetRunningPid();
	if (pid <= 0) {
		fprintf(stderr, "bsrmon is not running\n");
		return;
	}

	if (!res)
		res = GetResourceInfo(NULL);
	if (!type_flags)
		type_flags = (1 << BSRMON_ALL_STAT) -1;

	if (!res) {
		fprintf(stderr, "Failed to get resource info.\n");
		return;
	}

	if (!now) {
		interval = GetOptionValue(BSRMON_PERIOD);
		if (interval <= 0)
			interval = DEFAULT_BSRMON_PERIOD;
	}
	
	while (1) {		
		get_perf_path();
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
			bsrmon_log(stderr, "bsrmon: Unknown types '%s'\n", ptr);
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
				bsrmon_log(stderr, "Failed to get resource info.\n");
			}
			return res_head;
		} else {
			res = GetResourceInfo(ptr);
			if (!res) {
				bsrmon_log(stderr, "Failed to get resource info.\n");
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
			bsrmon_log(stderr, "Failed to malloc peer_stat, size : %lu\n", sizeof(struct peer_stat));
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

void bsrmon_exec_log(int argc, char** argv)
{
	char exec_log[512];
	size_t offset = 0;

	if (!strcmp(argv[1], "/file"))
		return;

	memset(exec_log, 0, sizeof(exec_log));

	for (int i = 0; i < argc; i++)
#ifdef _WIN
		offset += _snprintf_s(exec_log + offset, (512 - offset), (512 - offset) - 1, " %s", argv[i]);
#else 

		offset += snprintf(exec_log + offset, (512 - offset), " %s", argv[i]);
#endif
	_bsrmon_log(__FUNCTION__, __LINE__, "execution command,%s\n", exec_log);
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

	bsrmon_exec_log(argc, argv);

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
		// BSR-772 when the /scroll option is used, the output is scrolled.
		//		default is fixed screen output.
		else if (!strcmp(argv[argIndex], "/watch")) {
			int type = -1;
			char *res_name = NULL;
			bool b_scroll = false;
			int vnr = -1;
			int type_flags = 0;

			if (++argIndex < argc) {
				type = ConvertType(argv[argIndex]);

				if (type < 0) 
					usage();

				type_flags = GetOptionValue(BSRMON_TYPES);
				if (type_flags <= 0)
					type_flags = DEFAULT_BSRMON_TYPES; // all

				if (!(type_flags & (1 << type))) {
					printf("'%s' performance monitor is disabled\n", argv[argIndex]);
					break;
				}
			
				if (++argIndex >= argc) {
					if (type != BSRMON_MEMORY)
						usage();
				}

				if (type == BSRMON_MEMORY) {
					if (argIndex < argc) {
						if (!strcmp(argv[argIndex], "/scroll"))
							b_scroll = true;
						else
						usage();
					}
					Watch(NULL, BSRMON_MEMORY, -1, b_scroll);
					break;
				}

				if (argIndex >= argc) 
					usage();
				res_name = argv[argIndex];
				if (type <= BSRMON_RESYNC_RATIO) {
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

				Watch(res_name, (enum bsrmon_type)type, vnr, b_scroll);
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
						SetOptionValue(BSRMON_PERIOD, atoi(argv[argIndex]));
					else
						usage();
				}
				else if (strcmp(argv[argIndex], "file_size") == 0) {
					argIndex++;
					if (argIndex < argc)
						SetOptionValue(BSRMON_FILE_SIZE, atoi(argv[argIndex]));
					else
						usage();
				}
				else if (strcmp(argv[argIndex], "file_cnt") == 0) {
					argIndex++;
					if (argIndex < argc)
						SetOptionValue(BSRMON_FILE_CNT, atoi(argv[argIndex]));
					else
						usage();
				}
				// BSR-1236
				else if (strcmp(argv[argIndex], "total_file_size") == 0) {
					argIndex++;
					if (argIndex + 2 < argc) {
						long res_cnt = atoi(argv[argIndex++]);
						long vol_cnt = atoi(argv[argIndex++]);
						long total_file_size = atoi(argv[argIndex++]);

						SetFileSizeForUserSettings(res_cnt, vol_cnt, total_file_size);
					} else 
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
				// BSR-1236 outputs the currently set collection file settings to the maximum amount of storage required, depending on the resource and volume.
				if (!strcmp(argv[argIndex], "total_file_size")) {
					if (argIndex + 2 < argc) {
						PrintOptionValue(argv[argIndex], argv[argIndex + 1], argv[argIndex + 2]);
						argIndex += 2;
					}
				} else {
					PrintOptionValue(argv[argIndex], NULL, NULL);
				}
			}
			else
				usage();
		}
#ifdef _WIN
		// BSR-1138
		else if (!strcmp(argv[argIndex], "/start_ex")) {
			if (argc > 3)
				usage();
			if (++argIndex <= argc) {
				int type_flags = 0;
				type_flags = atoi(argv[argIndex]);
				BsrmonRun(type_flags);
			}
			else
				usage();
		}
#endif
		else if (!strcmp(argv[argIndex], "/start")) {
			if (argc > 3)
				usage();
			if (++argIndex <= argc) {
				int type_flags = 0;
				if (argIndex < argc) 
					type_flags = get_types(argv[argIndex]);
				if (type_flags == -1)
					exit(ERROR_INVALID_PARAMETER);
				StartMonitor(type_flags);
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/stop")) {
#ifdef _WIN
			if (argc > 3)
				usage();
			if (++argIndex <= argc) {
				int disable = 1;
				if (argIndex < argc) {
					if (!strcmp(argv[argIndex], "running")) {
						disable = 0;
					}
					else
						usage();
				}
				StopMonitor(disable);
			} else
				usage();
#else // _LIN
			if (argc > 2)
				usage();
			StopMonitor(1);
#endif
		}
		// BSR-741
		else if (!strcmp(argv[argIndex], "/status")) {
			argIndex++;
			if (argIndex <= argc) {
				is_running(true);
			} else
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
			
				if (type != BSRMON_MEMORY) {
					if (++argIndex >= argc) {
						usage();
					}
					res_name = argv[argIndex];
					if (type <= BSRMON_RESYNC_RATIO) {
						// BSRMON_IO_STAT, BSRMON_IO_COMPLETE, BSRMON_IO_PENDING, BSRMON_AL_STAT, BSRMON_PEER_REQUEST, BSRMON_REQUEST need vnr
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


				Report(res_name, file_name, (enum bsrmon_type)type, vol_num, &tf, peer_list);

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