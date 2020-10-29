#ifdef _WIN
#include <windows.h>
#include "ioctl.h"
#else // _LIN
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../../bsr-headers/linux/bsr_ioctl.h"
#endif
#include <stdio.h>
#include <time.h>
#include "module_debug.h"
#include "monitor_collect.h"

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
		"   /print\n"
		"   /file\n"
		"   /watch [all|resource]\n"
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
	printf("IO:\n");
	buf = GetDebugToBuf(IO, res);
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
	time_t now = time(NULL);
	struct tm base_date_local;
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

	localtime_s(&base_date_local, &now);
#else
	sprintf(perfpath, "/var/log/bsr/perfmon/");

	base_date_local = *localtime(&now);
#endif	
	sprintf_s(curr_time, "%04d-%02d-%02d_%02d:%02d:%02d",
		base_date_local.tm_year + 1900, base_date_local.tm_mon + 1, base_date_local.tm_mday,
		base_date_local.tm_hour, base_date_local.tm_min, base_date_local.tm_sec);


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
		GetDebugToFile(IO, res, respath, curr_time);
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
void Watch(char *resname)
{
	char cmd[MAX_PATH];
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

	if (_stricmp(resname, "all") == 0)
		return; // TODO watch all
	else
		sprintf_s(cmd, "type \"%s%s\\last\" & type \"%slast\" ", perf_path, resname, perf_path);
	
	system("cls");
#else
	if (strcasecmp(resname, "all") == 0)
		sprintf(cmd, "cat /var/log/bsr/perfmon/*/last; cat /var/log/bsr/perfmon/last; ");
	else
		sprintf(cmd, "cat /var/log/bsr/perfmon/%s/last; cat /var/log/bsr/perfmon/last; ", resname);

	system("clear");
#endif
	while (1) {
		system(cmd);
#ifdef _WIN
		Sleep(1000);
		system("cls");
#else // _LIN
		sleep(1);
		system("clear");
#endif

	}
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
			if (argIndex < argc)
				Watch(argv[argIndex]);
			else if (argIndex == argc)
				Watch((char*)"all");
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