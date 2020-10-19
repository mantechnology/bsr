#ifdef _WIN
#include <windows.h>
#include <stdio.h>
#include "ioctl.h"
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
	exit(ERROR_INVALID_PARAMETER);
}

#ifdef _WIN
HANDLE
OpenDevice(PCHAR devicename)
{
	HANDLE		handle = INVALID_HANDLE_VALUE;

	handle = CreateFileA(devicename, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		printf("LOG_ERROR: OpenDevice: cannot open %s\n", devicename);
	}

	return handle;
}

DWORD GetBsrDebugInfo(PBSR_DEBUG_INFO pDebugInfo)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	DWORD       dwReturned = 0;
	BOOL        ret = FALSE;

	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "DEBUG_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
	ret = DeviceIoControl(hDevice, IOCTL_MVOL_GET_DEBUG_INFO,
		pDebugInfo, sizeof(BSR_DEBUG_INFO) + pDebugInfo->buf_size, pDebugInfo, sizeof(BSR_DEBUG_INFO) + pDebugInfo->buf_size, &dwReturned, NULL);
	if (ret == FALSE) {
		retVal = GetLastError();
	}

	if (hDevice != INVALID_HANDLE_VALUE)
		CloseHandle(hDevice);

	return retVal;
}

// BSR-37
enum BSR_DEBUG_FLAGS ConvertToBsrDebugFlags(char *str)
{
	if (!_strcmpi(str, "version")) return DBG_BSR_VERSION;
	else if (!_strcmpi(str, "in_flight_summary")) return DBG_RES_IN_FLIGHT_SUMMARY;
	else if (!_strcmpi(str, "state_twopc")) return DBG_RES_STATE_TWOPC;
	else if (!_strcmpi(str, "callback_history")) return DBG_CONN_CALLBACK_HISTORY;
	else if (!_strcmpi(str, "debug")) return DBG_CONN_DEBUG;
	else if (!_strcmpi(str, "conn_oldest_requests")) return DBG_CONN_OLDEST_REQUESTS;
	else if (!_strcmpi(str, "transport")) return DBG_CONN_TRANSPORT;
	else if (!_strcmpi(str, "transport_speed")) return DBG_CONN_TRANSPORT_SPEED;
	else if (!_strcmpi(str, "send_buf")) return DBG_CONN_SEND_BUF;
	else if (!_strcmpi(str, "proc_bsr")) return DBG_PEER_PROC_BSR;
	else if (!_strcmpi(str, "resync_extents")) return DBG_PEER_RESYNC_EXTENTS;
	else if (!_strcmpi(str, "act_log_extents")) return DBG_DEV_ACT_LOG_EXTENTS;
	else if (!_strcmpi(str, "data_gen_id")) return DBG_DEV_DATA_GEN_ID;
	else if (!_strcmpi(str, "ed_gen_id")) return DBG_DEV_ED_GEN_ID;
	else if (!_strcmpi(str, "io_frozen")) return DBG_DEV_IO_FROZEN;
	else if (!_strcmpi(str, "dev_oldest_requests")) return DBG_DEV_OLDEST_REQUESTS;
	else if (!_strcmpi(str, "dev_req_timing")) return DBG_DEV_REQ_TIMING;
	return DBG_NO_FLAGS;
}

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
		case DBG_DEV_REQ_TIMING: // BSR-682 TODO move to bsrmon?
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

#ifdef _WIN
int main(int argc, char* argv [])
#else
int main(int argc, char* argv [])
#endif
{
	int	res = ERROR_SUCCESS;
	int  	argIndex = 0;

	if (argc < 2)
		usage();

	for (argIndex = 1; argIndex < argc; argIndex++) {
#ifdef _WIN
		// BSR-37
		if (!_stricmp(argv[argIndex], "/debug")) {
			argIndex++;
			if (argIndex < argc)
				res = BsrDebug(argc - argIndex, &argv[argIndex]);
			else
				debug_usage();
			break;
		}
		else {
			printf("Please check undefined arg[%d]=(%s)\n", argIndex, argv[argIndex]);
		}
#endif
	}

	return res;
}