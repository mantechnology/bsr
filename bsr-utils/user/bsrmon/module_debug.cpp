#include "module_debug.h"
#include "monitor_collect.h"

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
	else if (!_strcmpi(str, "dev_io_stat")) return DBG_DEV_IO_STAT;
	else if (!_strcmpi(str, "dev_io_complete")) return DBG_DEV_IO_COMPLETE;
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
	if (flag == DBG_DEV_IO_STAT || flag == DBG_DEV_IO_COMPLETE || flag == DBG_DEV_REQ_TIMING)
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

	if (debug_type <= REQUEST) {
		struct volume *vol = res->vol;
		if (!res->vol) {
			fprintf(stderr, "Invalid res->vol object\n");
			goto fail;
		}

		while (vol) {
#ifdef _WIN		
			if (debug_type == IO)
				flag = ConvertToBsrDebugFlags("dev_io_stat");
			else if (debug_type == IO_COMPLETE)
				flag = ConvertToBsrDebugFlags("dev_io_complete");
			else if (debug_type == REQUEST)
				flag = ConvertToBsrDebugFlags("dev_req_timing");

			//sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "vnr(%d):\n", vol->vnr);

			debugInfo = GetDebugInfo(flag, res, vol->vnr);
			if (!debugInfo)
				goto fail;

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;
#else // _LIN
			if (debug_type == IO)
				sprintf(path, "%s/resources/%s/volumes/%d/io_stat", DEBUGFS_ROOT, res->name, vol->vnr);
			if (debug_type == IO_COMPLETE)
				sprintf(path, "%s/resources/%s/volumes/%d/io_complete", DEBUGFS_ROOT, res->name, vol->vnr);
			else if (debug_type == REQUEST) 
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

FILE *perf_fileopen(char * filename, char * currtime)
{
	FILE *fp;
	char new_filename[512];
	int err;
	off_t size;

	if (fopen_s(&fp, filename, "a") != 0) {
		fprintf(stderr, "Failed to open %s\n", filename);
		return NULL;
	}
	
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);

	// TODO rolling size
	if ((1024 * 1024 * 50) < size) {
#ifdef _WIN
		HANDLE hFind;
		WIN32_FIND_DATA FindFileData;
		WCHAR dir_path[512] = { 0, };
		WCHAR find_file[512] = { 0, };
#else //_LIN
		DIR *dir_p = NULL;
		struct dirent* entry = NULL;
		char dir_path[512] = { 0, }; 
		char find_file[512] = { 0, };
#endif
		char remove_file[512] = { 0, };
		char r_time[64] = { 0, };
		char* ptr;

		fclose(fp);

#ifdef _WIN
		wsprintf(dir_path, L"%S*", filename);
		ptr = strrchr(filename, '\\');
		memcpy(remove_file, filename, (ptr - filename));
		wsprintf(find_file, L"%S_", ptr + 1);
		hFind = FindFirstFile(dir_path, &FindFileData);
		if (hFind == INVALID_HANDLE_VALUE){
			fprintf(stderr, "failed to open %s\n", dir_path);
			return NULL;
		}
		
		do{
			// TODO rolling cnt
			if (wcsstr(FindFileData.cFileName, find_file)) {
				sprintf_s(remove_file, "%s"_SEPARATOR_"%ws", remove_file, FindFileData.cFileName);
				remove(remove_file);
			}
		} while (FindNextFile(hFind, &FindFileData));

		FindClose(hFind);
#else // _LIN
		ptr = strrchr(filename, '/');
		memcpy(dir_path, filename, (ptr - filename));
		snprintf(find_file, strlen(ptr) + 1, "%s_", ptr + 1);

		if ((dir_p = opendir(dir_path)) == NULL) {
			fprintf(stderr, "failed to open %s\n", dir_path);
			return NULL;
		}
		// TODO rolling cnt
		while ((entry = readdir(dir_p)) != NULL) {
			if (strstr(entry->d_name, find_file)) {
				sprintf_s(remove_file, "%s"_SEPARATOR_"%s", dir_path, entry->d_name);
				remove(remove_file);
			}
		}
		
		closedir(dir_p);
#endif
		memcpy(r_time, currtime, strlen(currtime));
		eliminate(r_time, ':');
		printf("%s\n", r_time);
		sprintf_s(new_filename, "%s_%s", filename, r_time);
		err = rename(filename, new_filename);
		if (err == -1) {
			fprintf(stderr, "failed to log file rename %s => %s\n", filename, new_filename);
			return NULL;
		}
		if (fopen_s(&fp, filename, "a") != 0) {
			fprintf(stderr, "Failed to open %s\n", filename);
			return NULL;
		}
	}

	
	return fp;

}

// BSR-688 save aggregated debugfs data to file
int GetDebugToFile(enum get_debug_type debug_type, struct resource *res, char *respath, char * currtime)
{
#ifdef _WIN
	PBSR_DEBUG_INFO debugInfo = NULL;
	enum BSR_DEBUG_FLAGS flag;
#else // _LIN
	char path[128];
#endif

	FILE *fp;
	FILE *last_fp;
	char lastfile[MAX_PATH];
	char outfile[MAX_PATH];
	
	char *buffer;

	int ret = -1;

	if (!res) {
		fprintf(stderr, "Invalid res object\n");
		return -1;
	}

	sprintf_s(lastfile, "%s"_SEPARATOR_"last", respath);

	if (fopen_s(&last_fp, lastfile, "a") != 0) {
		fprintf(stderr, "Failed to open %s\n", respath);
		return -1;
	}

	buffer = (char*)malloc(MAX_DEBUG_BUF_SIZE);
	if (!buffer) {
		fprintf(stderr, "Failed to malloc debug buffer\n");
		return -1;
	}
	memset(buffer, 0, MAX_DEBUG_BUF_SIZE);

	if (debug_type <= REQUEST) {
		struct volume *vol = res->vol;
		if (!res->vol) {
			fprintf(stderr, "Invalid res->vol object\n");
			goto fail;
		}

		while (vol) {

			if (debug_type == IO) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("dev_io_stat");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/io_stat", DEBUGFS_ROOT, res->name, vol->vnr);
#endif
				sprintf_s(outfile, "%s"_SEPARATOR_"vnr%d_IO", respath, vol->vnr);
				fprintf(last_fp, "IO (vnr%d):\n", vol->vnr);
			} else if (debug_type == IO_COMPLETE) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("dev_io_complete");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/io_complete", DEBUGFS_ROOT, res->name, vol->vnr);
#endif
				fprintf(last_fp, "IO complete latency (vnr%d):\n", vol->vnr);
				sprintf_s(outfile, "%s"_SEPARATOR_"vnr%d_IO_COMPLETE", respath, vol->vnr);
			} else if (debug_type == REQUEST) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("dev_req_timing");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/req_timing", DEBUGFS_ROOT, res->name, vol->vnr);
#endif
				fprintf(last_fp, "Request latency (vnr%d):\n", vol->vnr);
				sprintf_s(outfile, "%s"_SEPARATOR_"request", respath);
			}

#ifdef _WIN
			debugInfo = GetDebugInfo(flag, res, vol->vnr);
			if (!debugInfo)
				goto fail;

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;
#else // _LIN
			fp = fopen(path, "r");

			if (!fp) {
				fprintf(stderr, "fopen failed, path : %s\n", path);
				goto fail;
			}

			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);
#endif

			fp = perf_fileopen(outfile, currtime);
			if (fp == NULL) 
				goto fail;

			fprintf(fp, "%s\n", currtime);	
			fprintf(fp, "%s", buffer);
			fclose(fp);
			
			fprintf(last_fp, "%s\n", buffer);
			memset(buffer, 0, MAX_DEBUG_BUF_SIZE);

			vol = vol->next;
		}
	}
	else if (debug_type == NETWORK_SPEED) {
		if (!res->conn) {
			fprintf(stderr, "Invalid res->conn object\n");
			return -1;
		}
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("transport_speed");

		sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "  %s (byte/s): ", res->conn->name[0]);
		debugInfo = GetDebugInfo(flag, res, res->conn->node_id[0]);
		if (!debugInfo)
			goto fail;

		memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
		free(debugInfo);
		debugInfo = NULL;

		sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "  %s (byte/s): ", res->conn->name[1]);
		debugInfo = GetDebugInfo(flag, res, res->conn->node_id[1]);
		if (!debugInfo)
			goto fail;
			
		memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
		free(debugInfo);
		debugInfo = NULL;
#else // _LIN
		sprintf(path, "%s/resources/%s/connections/%s/transport_speed", DEBUGFS_ROOT, res->name, res->conn->name[0]);

		sprintf(buffer + strlen(buffer), "  %s (byte/s): ", res->conn->name[0]);
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			goto fail;
		}

		fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
		fclose(fp);

		sprintf(path, "%s/resources/%s/connections/%s/transport_speed", DEBUGFS_ROOT, res->name, res->conn->name[1]);

		sprintf(buffer + strlen(buffer), "  %s (byte/s): ", res->conn->name[1]);
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			goto fail;
		}

		fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
		fclose(fp);
#endif
		sprintf_s(outfile, "%s"_SEPARATOR_"network", respath);
		
		fp = perf_fileopen(outfile, currtime);
		if (fp == NULL)
			goto fail;

		fprintf(fp, "%s\n", currtime);	
		fprintf(fp, "%s", buffer);
		fclose(fp);

		fprintf(last_fp, "Network:\n%s\n", buffer);
	}
	else if (debug_type == SEND_BUF) {
		if (!res->conn) {
			fprintf(stderr, "Invalid res->conn object\n");
			return -1;
		}
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("send_buf");

		sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "  %s:\n", res->conn->name[0]);
		debugInfo = GetDebugInfo(flag, res, res->conn->node_id[0]);
		if (!debugInfo)
			goto fail;

		memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
		free(debugInfo);
		debugInfo = NULL;

		sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "  %s:\n", res->conn->name[1]);
		debugInfo = GetDebugInfo(flag, res, res->conn->node_id[1]);
		if (!debugInfo)
			goto fail;

		memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
		free(debugInfo);
		debugInfo = NULL;
#else // _LIN
		sprintf(path, "%s/resources/%s/connections/%s/send_buf", DEBUGFS_ROOT, res->name, res->conn->name[0]);

		sprintf(buffer + strlen(buffer), "  %s:\n", res->conn->name[0]);
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			goto fail;
		}

		fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
		fclose(fp);

		sprintf(path, "%s/resources/%s/connections/%s/send_buf", DEBUGFS_ROOT, res->name, res->conn->name[1]);

		sprintf(buffer + strlen(buffer), "  %s:\n", res->conn->name[1]);
		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			goto fail;
		}

		fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
		fclose(fp);
#endif
		sprintf_s(outfile, "%s"_SEPARATOR_"send_buffer", respath);

		fp = perf_fileopen(outfile, currtime);
		if (fp == NULL)
			goto fail;

		fprintf(fp, "%s\n", currtime);
		fprintf(fp, "%s", buffer);
		fclose(fp);

		fprintf(last_fp, "Send buffer:\n%s\n", buffer);

	}
	else {
		fprintf(stderr, "Invalid debug_type value\n");
		goto fail;
	}

	ret = 0;

fail:

	if (last_fp) {
		fclose(last_fp);
	}
	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
	return ret;
}

// BSR-688 save memory info to file
int GetMemInfoToFile(char *path, char * currtime)
{
	FILE *fp;
	FILE *last_fp;
	char lastfile[MAX_PATH] = {0,};
	char outfile[MAX_PATH] = {0,};
	char *buffer = NULL;
	int ret = -1;

	sprintf_s(lastfile, "%s"_SEPARATOR_"last", path);

	if (fopen_s(&last_fp, lastfile, "a") != 0) {
		fprintf(stderr, "Failed to open %s\n", path);
		return -1;
	}

	sprintf_s(outfile, "%s"_SEPARATOR_"memory", path);

	fp = perf_fileopen(outfile, currtime);
	if (fp == NULL)
		goto fail;

	fprintf(fp, "%s\n", currtime);

	buffer = GetBsrMemoryUsage();
	if (buffer) {
		fprintf(fp, "%s", buffer);
		fprintf(last_fp, "%s\n", buffer);
		free(buffer);
		buffer = NULL;
	}

	buffer = GetBsrUserMemoryUsage();
	if (buffer) {
		fprintf(fp, "%s", buffer);
		fprintf(last_fp, "%s\n", buffer);
		free(buffer);
		buffer = NULL;
	}
	
	fclose(fp);

	ret = 0;

fail:

	if (last_fp) {
		fclose(last_fp);
	}
	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
	return ret;
}