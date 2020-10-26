#include "module_debug.h"

#ifdef _WIN
HANDLE
OpenDevice(PCHAR devicename)
{
	HANDLE		handle = INVALID_HANDLE_VALUE;

	handle = CreateFileA(devicename, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "LOG_ERROR: OpenDevice: cannot open %s\n", devicename);
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
#endif

void* exec_pipe(enum get_info_type info_type, char *res_name)
{
	char command[128], command2[128];
	char buf[128] = { 0, };
	struct resource *res_head = NULL, *res = NULL, *res_temp = NULL;
	struct connection* conn = NULL;
	struct volume *vol_head = NULL, *vol = NULL, *vol_temp = NULL;
	int idx = 0;
	FILE *pipe;

	if (info_type == RESOURCE) {
#ifdef _WIN
		sprintf_s(command, "bsradm sh-resources-list");
#else // _LIN
		sprintf(command, "bsradm sh-resources-list");
#endif
	}
	else if (info_type == CONNECTION) {
#ifdef _WIN
		sprintf_s(command, "bsradm sh-peer-node-name %s", res_name);
#else // _LIN
		sprintf(command, "bsradm sh-peer-node-name %s", res_name);
#endif
		conn = (struct connection*)malloc(sizeof(struct connection));
		if (!conn) {
			fprintf(stderr, "conn malloc failed, size : %lu\n", sizeof(struct connection));
			return NULL;
		}
		memset(conn, 0, sizeof(struct connection));
	}
	else if (info_type == VOLUME) {
#ifdef _WIN
		sprintf_s(command, "bsradm sh-dev-vnr %s", res_name);
#else // _LIN
		sprintf(command, "bsradm sh-dev-vnr %s", res_name);
#endif
	}
	else {
		fprintf(stderr, "Invalid get_info_type value\n");
		return NULL;
	}

#ifdef _WIN
	pipe = _popen(command, "r");
#else // _LIN
	pipe = popen(command, "r");
#endif
	if (!pipe) {
		fprintf(stderr, "popen failed, command : %s\n", command);
		return NULL;
	}
	while (!feof(pipe)) {
		if (fgets(buf, 128, pipe) != NULL) {
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;

			if (info_type == RESOURCE) {
#ifdef _WIN
				sprintf_s(command2, "bsradm status %s >nul 2>&1", buf);
#else // _LIN
				sprintf(command2, "bsradm status %s &>/dev/null", buf);
#endif
				// check if resource up
				if (!system(command2)) {
					res = (struct resource*)malloc(sizeof(struct resource));
					if (!res) {
						fprintf(stderr, "res malloc failed, size : %lu\n", sizeof(struct resource));
						return NULL;
					}
					res->conn = NULL;
					res->vol = NULL;
#ifdef _WIN
					strcpy_s(res->name, buf);
#else // _LIN
					strcpy(res->name, buf);
#endif
					res->next = NULL;

					if (!res_temp)
						res_head = res;
					else
						res_temp->next = res;
					res_temp = res;
				}
			}
			else if (info_type == CONNECTION) {
#ifdef _WIN
				strcpy_s(conn->name[idx++], buf);
#else // _LIN
				strcpy(conn->name[idx++], buf);
#endif
			}
			else if (info_type == VOLUME) {
				vol = (struct volume*)malloc(sizeof(struct volume));
				if (!vol) {
					fprintf(stderr, "vol malloc failed, size : %lu\n", sizeof(struct volume));
					return NULL;
				}
				vol->vnr = atoi(buf);
				vol->next = NULL;

				if (!vol_temp)
					vol_head = vol;
				else
					vol_temp->next = vol;
				vol_temp = vol;
			}
		}
		else if (*buf == 0) {
			fprintf(stderr, "exec failed, command : %s\n", command);
			return NULL;
		}
	}
#ifdef _WIN
	_pclose(pipe);
#else // _LIN
	pclose(pipe);
#endif

	if (info_type == RESOURCE) {
		return res_head;
	}
	else if (info_type == CONNECTION) {
		idx = 0;
#ifdef _WIN
		sprintf_s(command, "bsradm sh-peer-node-id %s", res_name);
		pipe = _popen(command, "r");
#else // _LIN
		sprintf(command, "bsradm sh-peer-node-id %s", res_name);
		pipe = popen(command, "r");
#endif
		if (!pipe) {
			fprintf(stderr, "popen failed, command : %s\n", command);
			return NULL;
		}
		while (!feof(pipe)) {
			if (fgets(buf, 128, pipe) != NULL) {
				// remove EOL
				*(buf + (strlen(buf) - 1)) = 0;

				conn->node_id[idx++] = atoi(buf);
			}
			else if (*buf == 0) {
				fprintf(stderr, "exec failed, command : %s\n", command);
				return NULL;
			}
		}
#ifdef _WIN
		_pclose(pipe);
#else // _LIN
		pclose(pipe);
#endif

		return conn;
	}
	else if (info_type == VOLUME) {
		return vol_head;
	}
	else {
		return NULL;
	}
}

void freeResource(struct resource* res)
{
	struct resource* res_temp;
	struct volume* vol_temp;

	while (res) {
		if (res->conn) {
			free(res->conn);
			res->conn = NULL;
		}

		while (res->vol) {
			vol_temp = res->vol;
			res->vol = res->vol->next;

			free(vol_temp);
			vol_temp = NULL;
		}

		res_temp = res;
		res = res->next;

		free(res_temp);
		res_temp = NULL;
	}
}

struct resource* GetResourceInfo()
{
	struct resource *res_head = NULL, *res = NULL;

	res = (struct resource*)exec_pipe(RESOURCE, NULL);
	res_head = res;
	while (res) {
		res->conn = (struct connection*)exec_pipe(CONNECTION, res->name);
		if (!res->conn) {
			freeResource(res);
			return NULL;
		}

		res->vol = (struct volume*)exec_pipe(VOLUME, res->name);
		if (!res->vol) {
			freeResource(res);
			return NULL;
		}

		res = res->next;
	}

	return res_head;
}

#ifdef _WIN
PBSR_DEBUG_INFO GetDebugInfo(enum BSR_DEBUG_FLAGS flag, struct resource* res, int val)
{
	PBSR_DEBUG_INFO debugInfo;
	int size = MAX_DEBUG_BUF_SIZE;
	int ret = 0;

	debugInfo = (PBSR_DEBUG_INFO)malloc(sizeof(BSR_DEBUG_INFO) + size);
	if (!debugInfo) {
		fprintf(stderr, "DEBUG_ERROR: Failed to malloc BSR_DEBUG_INFO\n");
		return NULL;
	}
	memset(debugInfo, 0, sizeof(BSR_DEBUG_INFO) + size);
	debugInfo->peer_node_id = -1;
	debugInfo->vnr = -1;
	debugInfo->buf_size = size;
	debugInfo->flags = flag;

	strcpy_s(debugInfo->res_name, res->name);
	if (flag == DBG_DEV_REQ_TIMING)
		debugInfo->vnr = val;
	else if (flag == DBG_CONN_TRANSPORT_SPEED || flag == DBG_CONN_SEND_BUF)
		debugInfo->peer_node_id = val;

	while ((ret = GetBsrDebugInfo(debugInfo)) != ERROR_SUCCESS) {
		if (ret == ERROR_MORE_DATA) {
			size <<= 1;

			if (size > MAX_DEBUG_BUF_SIZE << 10) { // 4M
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
		return debugInfo;
	}
	else if (ret == ERROR_INVALID_PARAMETER) {
		fprintf(stderr, "invalid paramter.\n");
	}

	if (debugInfo) {
		free(debugInfo);
		debugInfo = NULL;
	}

	return NULL;
}
#endif

char* GetDebugToBuf(enum get_debug_type debug_type, struct resource *res) {
#ifdef _WIN
	PBSR_DEBUG_INFO debugInfo = NULL;
	enum BSR_DEBUG_FLAGS flag;
#else // _LIN
	char path[128];
	FILE *fp;
#endif
	char *buffer;

	if (!res) {
		fprintf(stderr, "Invalid res object\n");
		return NULL;
	}

	buffer = (char*)malloc(MAX_DEBUG_BUF_SIZE);
	if (!buffer) {
		fprintf(stderr, "Failed to malloc debug buffer\n");
		return NULL;
	}
	memset(buffer, 0, MAX_DEBUG_BUF_SIZE);

	if (debug_type == IO) {
		struct volume *vol = res->vol;
		if (!res->vol) {
			fprintf(stderr, "Invalid res->vol object\n");
			goto fail;
		}

		while (vol) {
#ifdef _WIN		
			flag = ConvertToBsrDebugFlags("dev_req_timing");

			sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "vnr(%d):\n", vol->vnr);

			debugInfo = GetDebugInfo(flag, res, vol->vnr);
			if (!debugInfo)
				goto fail;

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;
#else // _LIN
			sprintf(path, "%s/resources/%s/volumes/%d/req_timing", DEBUGFS_ROOT, res->name, vol->vnr);

			sprintf(buffer + strlen(buffer), "vnr(%d):\n", vol->vnr);
			
			fp = fopen(path, "r");
			if (!fp) {
				fprintf(stderr, "fopen failed, path : %s\n", path);
				goto fail;
			}

			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);
#endif
			vol = vol->next;
		}
	}
	else if (debug_type == NETWORK_SPEED) {
		if (!res->conn) {
			fprintf(stderr, "Invalid res->conn object\n");
			return NULL;
		}
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("transport_speed");

		sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s:\n", res->conn->name[0]);
		debugInfo = GetDebugInfo(flag, res, res->conn->node_id[0]);
		if (!debugInfo)
			goto fail;

		memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
		free(debugInfo);
		debugInfo = NULL;

		sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s:\n", res->conn->name[1]);
		debugInfo = GetDebugInfo(flag, res, res->conn->node_id[1]);
		if (!debugInfo)
			goto fail;
			
		memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
		free(debugInfo);
		debugInfo = NULL;
#else // _LIN
		sprintf(path, "%s/resources/%s/connections/%s/transport_speed", DEBUGFS_ROOT, res->name, res->conn->name[0]);

		sprintf(buffer + strlen(buffer), "%s:\n", res->conn->name[0]);
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			goto fail;
		}

		fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
		fclose(fp);

		sprintf(path, "%s/resources/%s/connections/%s/transport_speed", DEBUGFS_ROOT, res->name, res->conn->name[1]);

		sprintf(buffer + strlen(buffer), "%s:\n", res->conn->name[1]);
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			goto fail;
		}

		fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
		fclose(fp);
#endif
	}
	else if (debug_type == SEND_BUF) {
		if (!res->conn) {
			fprintf(stderr, "Invalid res->conn object\n");
			return NULL;
		}
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("send_buf");

		sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s:\n", res->conn->name[0]);
		debugInfo = GetDebugInfo(flag, res, res->conn->node_id[0]);
		if (!debugInfo)
			goto fail;

		memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
		free(debugInfo);
		debugInfo = NULL;

		sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s:\n", res->conn->name[1]);
		debugInfo = GetDebugInfo(flag, res, res->conn->node_id[1]);
		if (!debugInfo)
			goto fail;
			
		memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
		free(debugInfo);
		debugInfo = NULL;
#else // _LIN
		sprintf(path, "%s/resources/%s/connections/%s/send_buf", DEBUGFS_ROOT, res->name, res->conn->name[0]);

		sprintf(buffer + strlen(buffer), "%s:\n", res->conn->name[0]);	
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			goto fail;
		}

		fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
		fclose(fp);

		sprintf(path, "%s/resources/%s/connections/%s/send_buf", DEBUGFS_ROOT, res->name, res->conn->name[1]);

		sprintf(buffer + strlen(buffer), "%s:\n", res->conn->name[1]);	
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			goto fail;
		}

		fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
		fclose(fp);
#endif
	} else {
		fprintf(stderr, "Invalid debug_type value\n");
		goto fail;
	}

	return buffer;

fail:
	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
	return NULL;
}