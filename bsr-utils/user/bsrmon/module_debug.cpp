#include <errno.h>
#include "bsrmon.h"
#include "module_debug.h"
#include "monitor_collect.h"
#ifdef _WIN
#include <tchar.h>
#else
#include <unistd.h>
#endif
#ifdef _WIN
HANDLE
OpenDevice(PCHAR devicename)
{
	HANDLE		handle = INVALID_HANDLE_VALUE;

	handle = CreateFileA(devicename, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		bsrmon_log(stderr, "LOG_ERROR: OpenDevice: cannot open %s\n", devicename);
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
		bsrmon_log(stderr, "DEBUG_ERROR: %s: Failed open bsr. Err=%u\n",
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
	else if (!_strcmpi(str, "act_log_stat")) return DBG_DEV_ACT_LOG_STAT;
	else if (!_strcmpi(str, "data_gen_id")) return DBG_DEV_DATA_GEN_ID;
	else if (!_strcmpi(str, "ed_gen_id")) return DBG_DEV_ED_GEN_ID;
	else if (!_strcmpi(str, "io_frozen")) return DBG_DEV_IO_FROZEN;
	else if (!_strcmpi(str, "dev_oldest_requests")) return DBG_DEV_OLDEST_REQUESTS;
	else if (!_strcmpi(str, "dev_io_stat")) return DBG_DEV_IO_STAT;
	else if (!_strcmpi(str, "dev_io_complete")) return DBG_DEV_IO_COMPLETE;
	else if (!_strcmpi(str, "dev_io_pending")) return DBG_DEV_IO_PENDING;
	else if (!_strcmpi(str, "dev_req_timing")) return DBG_DEV_REQ_TIMING;
	else if (!_strcmpi(str, "dev_peer_req_timing")) return DBG_DEV_PEER_REQ_TIMING;
	else if (!_strcmpi(str, "resync_ratio")) return DBG_PEER_RESYNC_RATIO;
	return DBG_NO_FLAGS;
}
#endif

void* exec_pipe(enum get_info_type info_type, char *res_name)
{
	char command[256];
	char buf[256] = { 0, };
	struct resource *res_head = NULL, *res = NULL, *res_temp = NULL;
	struct connection* conn = NULL, *conn_head = NULL, *conn_temp = NULL;
	struct volume *vol_head = NULL, *vol = NULL, *vol_temp = NULL;
	FILE *pipe;

	if (info_type == RESOURCE)
		sprintf_ex(command, "bsradm sh-resources-list");
	else if (info_type == CONNECTION)
		sprintf_ex(command, "bsradm sh-peer-nodes %s", res_name);
	else if (info_type == VOLUME)
		sprintf_ex(command, "bsradm sh-dev-vnr %s", res_name);
	else {
		bsrmon_log(stderr, "Invalid get_info_type value\n");
		return NULL;
	}

#ifdef _WIN
	pipe = _popen(command, "r");
#else // _LIN
	pipe = popen(command, "r");
#endif
	if (!pipe) {
		bsrmon_log(stderr, "Failed to execute command : %s\n", command);
		return NULL;
	}

	while (!feof(pipe)) {
		if (fgets(buf, 256, pipe) != NULL) {
			// remove EOL
			*(buf + (strlen(buf) - 1)) = 0;

			if (info_type == RESOURCE) {
				res = (struct resource*)malloc(sizeof(struct resource));
				if (!res) {
					bsrmon_log(stderr, "Failed to malloc resource, size : %lu\n", sizeof(struct resource));
					return NULL;
				}
				res->conn = NULL;
				res->vol = NULL;
				eliminate(buf, '"');
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
			else if (info_type == CONNECTION) {
				char *id_ptr = NULL, *name_ptr = NULL;
				conn = (struct connection*)malloc(sizeof(struct connection));
				if (!conn) {
					bsrmon_log(stderr, "Failed to malloc connection, size : %lu\n", sizeof(struct connection));
					return NULL;
				}
				memset(conn, 0, sizeof(struct connection));
				
				// BSR-1032 peer name parsing (including ipv6)
				id_ptr = strtok_r(buf, " ", &name_ptr);
				conn->node_id = atoi(id_ptr);
#ifdef _WIN
				strcpy_s(conn->name, name_ptr);
#else // _LIN
				strcpy(conn->name, name_ptr);
#endif		
				conn->next = NULL;
				if (!conn_temp)
					conn_head = conn;
				else
					conn_temp->next = conn;
				conn_temp = conn;

			}
			else if (info_type == VOLUME) {
				vol = (struct volume*)malloc(sizeof(struct volume));
				if (!vol) {
					bsrmon_log(stderr, "Failed to malloc volume, size : %lu\n", sizeof(struct volume));
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
			bsrmon_log(stderr, "Failed to execute command : %s\n", command);
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
		return conn_head;
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
	struct connection* conn_temp;

	while (res) {
		while (res->conn) {
			conn_temp = res->conn;
			res->conn = res->conn->next;

			free(conn_temp);
			conn_temp = NULL;
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

struct resource* GetResourceInfo(char * name)
{
	struct resource *res_head = NULL, *res = NULL;

	if (!name) {
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
	else {
		res = (struct resource*)malloc(sizeof(struct resource));
		if (!res) {
			bsrmon_log(stderr, "Failed to malloc resource, size : %lu\n", sizeof(struct resource));
			return NULL;
		}
		res->conn = NULL;
		res->vol = NULL;
#ifdef _WIN
		strcpy_s(res->name, name);
#else // _LIN
		strcpy(res->name, name);
#endif
		res->next = NULL;

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

		return res;
	}
	
}

int CheckResourceInfo(char* resname, int node_id, int vnr)
{
	struct resource *res, *res_temp;
	struct volume *vol;
	struct connection *conn;
	int err = 0;

	res = GetResourceInfo(NULL);
	if (!res) {
		bsrmon_log(stderr, "Failed in CheckResourceInfo(), not found resource %s\n", resname);
		return -1;
	}

	res_temp = res;
	while (res_temp) {
		// check resname
		if (!strcmp(resname, res_temp->name)) {
			// check node_id
			if (node_id != 0) {
				bool find_id = false;
				conn = res_temp->conn;
				while (conn) {
					if (node_id == conn->node_id) {
						find_id = true;
						break;
					} else
						conn = conn->next;
				}
				if (!find_id) {
					err = -1;
					bsrmon_log(stderr, "Failed in CheckResourceInfo(), not found node-id:%d\n", node_id);
					goto ret;
				}
			}
			
			// check vnr
			if (vnr >= 0) {
				vol = res_temp->vol;
				while (vol) {
					if (vnr == vol->vnr)
						goto ret;
					else
						vol = vol->next;
				}
				bsrmon_log(stderr, "Failed in CheckResourceInfo(), not found vnr:%d\n", vnr);
				err = -1;
			}
			
			goto ret;
		}
		else
			res_temp = res_temp->next;	
	}

	bsrmon_log(stderr, "Failed in CheckResourceInfo(), not found resource %s\n", resname);
	err = -1;
ret:
	freeResource(res);
	return err;
}

#ifdef _WIN
PBSR_DEBUG_INFO GetDebugInfo(enum BSR_DEBUG_FLAGS flag, struct resource* res, int vnr, int peer_node_id)
{
	PBSR_DEBUG_INFO debugInfo;
	int size = MAX_DEBUG_BUF_SIZE;
	int ret = 0;

	debugInfo = (PBSR_DEBUG_INFO)malloc(sizeof(BSR_DEBUG_INFO) + size);
	if (!debugInfo) {
		bsrmon_log(stderr, "DEBUG_ERROR: Failed to malloc BSR_DEBUG_INFO\n");
		return NULL;
	}
	memset(debugInfo, 0, sizeof(BSR_DEBUG_INFO) + size);
	debugInfo->peer_node_id = peer_node_id;
	debugInfo->vnr = vnr;
	debugInfo->buf_size = size;
	debugInfo->flags = flag;

	strcpy_s(debugInfo->res_name, res->name);
	while ((ret = GetBsrDebugInfo(debugInfo)) != ERROR_SUCCESS) {
		if (ret == ERROR_MORE_DATA) {
			size <<= 1;

			if (size > MAX_DEBUG_BUF_SIZE << 10) { // 4M
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
			break;
		}
	}

	if ((ret == ERROR_SUCCESS) && (strlen(debugInfo->buf) > 0)) {
		return debugInfo;
	}

	if (debugInfo) {
		free(debugInfo);
		debugInfo = NULL;
	}

	return NULL;
}
#endif

char* GetDebugToBuf(enum bsrmon_type debug_type, struct resource *res) {
#ifdef _WIN
	PBSR_DEBUG_INFO debugInfo = NULL;
	enum BSR_DEBUG_FLAGS flag;
#else // _LIN
	char path[MAX_PATH];
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

	if (debug_type <= BSRMON_REQUEST) {
		struct volume *vol = res->vol;
		if (!res->vol) {
			fprintf(stderr, "Invalid res->vol object\n");
			goto fail;
		}

		while (vol) {
#ifdef _WIN		
			if (debug_type == BSRMON_IO_STAT)
				flag = ConvertToBsrDebugFlags("dev_io_stat");
			else if (debug_type == BSRMON_IO_COMPLETE)
				flag = ConvertToBsrDebugFlags("dev_io_complete");
			else if (debug_type == BSRMON_IO_PENDING)
				flag = ConvertToBsrDebugFlags("dev_io_pending");
			else if (debug_type == BSRMON_REQUEST)
				flag = ConvertToBsrDebugFlags("dev_req_timing");
			else if (debug_type == BSRMON_PEER_REQUEST)
				flag = ConvertToBsrDebugFlags("dev_peer_req_timing");
			else if (debug_type == BSRMON_AL_STAT)
				flag = ConvertToBsrDebugFlags("act_log_stat");

			//sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "vnr(%d):\n", vol->vnr);

			debugInfo = GetDebugInfo(flag, res, vol->vnr, -1);
			if (!debugInfo) {
				fprintf(stderr, "Failed to get bsr debuginfo(%d).\n", flag);
				goto fail;
			}

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;
#else // _LIN
			if (debug_type == BSRMON_IO_STAT)
				sprintf(path, "%s/resources/%s/volumes/%d/io_stat", DEBUGFS_ROOT, res->name, vol->vnr);
			if (debug_type == BSRMON_IO_COMPLETE)
				sprintf(path, "%s/resources/%s/volumes/%d/io_complete", DEBUGFS_ROOT, res->name, vol->vnr);
			if (debug_type == BSRMON_IO_PENDING)
				sprintf(path, "%s/resources/%s/volumes/%d/io_pending", DEBUGFS_ROOT, res->name, vol->vnr);
			else if (debug_type == BSRMON_REQUEST) 
				sprintf(path, "%s/resources/%s/volumes/%d/req_timing", DEBUGFS_ROOT, res->name, vol->vnr);
			else if (debug_type == BSRMON_PEER_REQUEST) 
				sprintf(path, "%s/resources/%s/volumes/%d/peer_req_timing", DEBUGFS_ROOT, res->name, vol->vnr);
			else if (debug_type == BSRMON_AL_STAT) 
				sprintf(path, "%s/resources/%s/volumes/%d/act_log_stat", DEBUGFS_ROOT, res->name, vol->vnr);

			sprintf(buffer + strlen(buffer), "vnr(%d):\n", vol->vnr);
			
			fp = fopen(path, "r");
			if (!fp) {
				fprintf(stderr, "Failed to open file, path : %s\n", path);
				goto fail;
			}

			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);
#endif
			vol = vol->next;
		}
	}
	else if (debug_type == BSRMON_NETWORK_SPEED) {
		struct connection *conn = res->conn;
		if (!res->conn) {
			fprintf(stderr, "Invalid res->conn object\n");
			return NULL;
		}
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("transport_speed");

		while (conn) {
			sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s:\n", conn->name);
			debugInfo = GetDebugInfo(flag, res, -1, conn->node_id);
			if (!debugInfo) {
				fprintf(stderr, "Failed to get bsr debuginfo(%d).\n", flag);
				goto fail;
			}

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;

			conn = conn->next;
		}
		
#else // _LIN
		while (conn) {
			sprintf(path, "%s/resources/%s/connections/%s/transport_speed", DEBUGFS_ROOT, res->name, conn->name);

			sprintf(buffer + strlen(buffer), "%s:\n", conn->name);
			fp = fopen(path, "r");
			if (!fp) {
				fprintf(stderr, "Failed to open file, path : %s\n", path);
				goto fail;
			}

			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);

			conn = conn->next;
		}
		
#endif
	}
	else if (debug_type == BSRMON_SEND_BUF) {
		struct connection *conn = res->conn;
		if (!res->conn) {
			fprintf(stderr, "Invalid res->conn object\n");
			return NULL;
		}
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("send_buf");

		while (conn) {
			sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s:\n", conn->name);
			
			debugInfo = GetDebugInfo(flag, res, -1, conn->node_id);
			if (!debugInfo) {
				fprintf(stderr, "Failed to get bsr debuginfo(%d).\n", flag);
				goto fail;
			}

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;
			conn = conn->next;
		}
#else // _LIN
		while (conn) {
			sprintf(path, "%s/resources/%s/connections/%s/send_buf", DEBUGFS_ROOT, res->name, conn->name);

			sprintf(buffer + strlen(buffer), "%s:\n", conn->name);	
			fp = fopen(path, "r");
			if (!fp) {
				fprintf(stderr, "Failed to open file, path : %s\n", path);
				goto fail;
			}

			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);
			conn = conn->next;
		}
#endif
	}
	// BSR-838
	else if (debug_type == BSRMON_RESYNC_RATIO) {
		struct volume *vol = res->vol;
		if (!res->vol) {
			fprintf(stderr, "Invalid res->vol object\n");
			goto fail;
		}

		while (vol) {
			struct connection *conn = res->conn;
			if (!res->conn) {
				fprintf(stderr, "Invalid res->conn object\n");
				return NULL;
			}
#ifdef _WIN
			flag = ConvertToBsrDebugFlags("resync_ratio");

			while (conn) {
				sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s ", conn->name);

				debugInfo = GetDebugInfo(flag, res, vol->vnr, conn->node_id);
				if (!debugInfo) {
					fprintf(stderr, "Failed to get bsr debuginfo(%d).\n", flag);
					goto fail;
				}

				memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
				free(debugInfo);
				debugInfo = NULL;
				conn = conn->next;
			}
#else // _LIN
			sprintf(buffer + strlen(buffer), "vnr(%d): ", vol->vnr);

			while (conn) {
				sprintf(path, "%s/resources/%s/connections/%s/%d/resync_ratio", 
						DEBUGFS_ROOT, res->name, conn->name, vol->vnr);

				sprintf(buffer + strlen(buffer), "%s ", conn->name);
				fp = fopen(path, "r");
				if (!fp) {
					fprintf(stderr, "Failed to open file, path : %s\n", path);
					goto fail;
				}

				fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
				fclose(fp);
				conn = conn->next;
			}
#endif
			vol = vol->next;
		}
		
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

// BSR-740 before enable bsrmon_run, read the debugfs file once and initialize it.
int InitPerfType(enum bsrmon_type debug_type, struct resource *res)
{
#ifdef _WIN
	PBSR_DEBUG_INFO debugInfo = NULL;
	enum BSR_DEBUG_FLAGS flag;
#else // _LIN
	char path[MAX_PATH];
	FILE *fp;
#endif	
	int ret = -1;
	char *buffer;

	buffer = (char*)malloc(MAX_DEBUG_BUF_SIZE);
	if (!buffer) {
		bsrmon_log(stderr, "Failed to malloc debug buffer\n");
		return -1;
	}
	memset(buffer, 0, MAX_DEBUG_BUF_SIZE);

	if (debug_type <= BSRMON_REQUEST) {
		struct volume *vol = res->vol;
		if (!res->vol)
			goto fail;

		while (vol) {
#ifdef _WIN
			if (debug_type == BSRMON_IO_STAT)
				flag = ConvertToBsrDebugFlags("dev_io_stat");
			else if (debug_type == BSRMON_IO_COMPLETE)
				flag = ConvertToBsrDebugFlags("dev_io_complete");
			else if (debug_type == BSRMON_REQUEST)
				flag = ConvertToBsrDebugFlags("dev_req_timing");
			else if (debug_type == BSRMON_PEER_REQUEST)
				flag = ConvertToBsrDebugFlags("dev_peer_req_timing");
			else if (debug_type == BSRMON_AL_STAT)
				flag = ConvertToBsrDebugFlags("act_log_stat");
#else // _LIN 
			if (debug_type == BSRMON_IO_STAT)
				sprintf(path, "%s/resources/%s/volumes/%d/io_stat", DEBUGFS_ROOT, res->name, vol->vnr);
			else if (debug_type == BSRMON_IO_COMPLETE)
				sprintf(path, "%s/resources/%s/volumes/%d/io_complete", DEBUGFS_ROOT, res->name, vol->vnr);
			else if (debug_type == BSRMON_REQUEST)
				sprintf(path, "%s/resources/%s/volumes/%d/req_timing", DEBUGFS_ROOT, res->name, vol->vnr);
			else if (debug_type == BSRMON_PEER_REQUEST)
				sprintf(path, "%s/resources/%s/volumes/%d/peer_req_timing", DEBUGFS_ROOT, res->name, vol->vnr);
			else if (debug_type == BSRMON_AL_STAT)
				sprintf(path, "%s/resources/%s/volumes/%d/act_log_stat", DEBUGFS_ROOT, res->name, vol->vnr);
#endif

			

#ifdef _WIN
			debugInfo = GetDebugInfo(flag, res, vol->vnr, -1);
			if (!debugInfo)
				goto fail;
			free(debugInfo);
			debugInfo = NULL;
#else // _LIN
			fp = fopen(path, "r");
			if (!fp) 
				goto fail;
			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);
#endif
			vol = vol->next;
		}
	} else if (debug_type == BSRMON_NETWORK_SPEED) {
		struct connection *conn = res->conn;
		if (!res->conn) 
			return -1;
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("transport_speed");

		while (conn) {
			debugInfo = GetDebugInfo(flag, res, -1, conn->node_id);
			if (!debugInfo) 
				goto fail;

			free(debugInfo);
			debugInfo = NULL;
			conn = conn->next;
		}
#else // _LIN
		while (conn) {
			sprintf(path, "%s/resources/%s/connections/%s/transport_speed", DEBUGFS_ROOT, res->name, conn->name);

			fp = fopen(path, "r");
			if (!fp) {
				goto fail;
			}
			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);
			conn = conn->next;
		}
#endif
	}
	// BSR-838 
	else if (debug_type == BSRMON_RESYNC_RATIO) {
		struct volume *vol = res->vol;
		if (!res->vol) 
			return -1;

		while (vol) {
			
			struct connection *conn = res->conn;
			if (!res->conn)
				return -1;
#ifdef _WIN
			flag = ConvertToBsrDebugFlags("resync_ratio");

			while (conn) {
				debugInfo = GetDebugInfo(flag, res, vol->vnr, conn->node_id);
				if (!debugInfo)
					goto fail;

				free(debugInfo);
				debugInfo = NULL;
				conn = conn->next;
			}
#else // _LIN
			while (conn) {
				sprintf(path, "%s/resources/%s/connections/%s/%d/resync_ratio", DEBUGFS_ROOT, res->name, conn->name, vol->vnr);

				fp = fopen(path, "r");
				if (!fp) {
					goto fail;
				}
				fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
				fclose(fp);
				conn = conn->next;
			}
#endif
			memset(buffer, 0, MAX_DEBUG_BUF_SIZE);
			vol = vol->next;
		}
	} else {
		goto fail;
	}

	ret = 0;

fail:
	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
	return ret;
}

// BSR-688 save aggregated debugfs data to file
int GetDebugToFile(enum bsrmon_type debug_type, struct resource *res, char *respath, char * currtime)
{
#ifdef _WIN
	PBSR_DEBUG_INFO debugInfo = NULL;
	enum BSR_DEBUG_FLAGS flag;
#else // _LIN
	char path[MAX_PATH];
#endif

	FILE *fp;
	char outfile[MAX_PATH];
	
	char *buffer;
	int ret = -1;

	if (!res) {
		bsrmon_log(stderr, "Invalid res object\n");
		return -1;
	}


	buffer = (char*)malloc(MAX_DEBUG_BUF_SIZE);
	if (!buffer) {
		bsrmon_log(stderr, "Failed to malloc debug buffer\n");
		return -1;
	}
	memset(buffer, 0, MAX_DEBUG_BUF_SIZE);

	if (debug_type <= BSRMON_REQUEST) {
		struct volume *vol = res->vol;
		if (!res->vol) {
			bsrmon_log(stderr, "Invalid %s res->vol object\n", res->name);
			goto fail;
		}

		while (vol) {

			sprintf_ex(outfile, "%s%svnr%d_%s", respath, _SEPARATOR_, vol->vnr, perf_type_str(debug_type));

			if (debug_type == BSRMON_IO_STAT) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("dev_io_stat");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/io_stat", DEBUGFS_ROOT, res->name, vol->vnr);
#endif				
			} else if (debug_type == BSRMON_IO_COMPLETE) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("dev_io_complete");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/io_complete", DEBUGFS_ROOT, res->name, vol->vnr);
#endif
			} else if (debug_type == BSRMON_IO_PENDING) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("dev_io_pending");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/io_pending", DEBUGFS_ROOT, res->name, vol->vnr);
#endif
			} else if (debug_type == BSRMON_REQUEST) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("dev_req_timing");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/req_timing", DEBUGFS_ROOT, res->name, vol->vnr);
#endif
			} else if (debug_type == BSRMON_PEER_REQUEST) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("dev_peer_req_timing");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/peer_req_timing", DEBUGFS_ROOT, res->name, vol->vnr);
#endif
			} else if (debug_type == BSRMON_AL_STAT) {
#ifdef _WIN
				flag = ConvertToBsrDebugFlags("act_log_stat");
#else // _LIN
				sprintf(path, "%s/resources/%s/volumes/%d/act_log_stat", DEBUGFS_ROOT, res->name, vol->vnr);
#endif
			}


#ifdef _WIN
			debugInfo = GetDebugInfo(flag, res, vol->vnr, -1);
			if (!debugInfo) {
				bsrmon_log(stderr, "Failed to get %s(vnr:%d) %s debuginfo(%d).\n",
						res->name, vol->vnr, perf_type_str(debug_type), flag);
				goto fail;
			}

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;
#else // _LIN
			fp = fopen(path, "r");

			if (!fp) {
				bsrmon_log(stderr, "Failed to open file, path : %s\n", path);
				goto fail;
			}

			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			
			ret = errno;

			fclose(fp);

			if (ret == ENODEV)
				goto fail;
#endif
			// BSR-776 do not write error messages to the performance file.
			if (!strncmp(buffer, "err reading", 11))
				goto fail;

			fp = perf_fileopen(outfile, currtime);
			if (fp == NULL) 
				goto fail;

			fprintf(fp, "%s %s", currtime, buffer);	
			fclose(fp);
			
			memset(buffer, 0, MAX_DEBUG_BUF_SIZE);

			vol = vol->next;
		}
	}
	else if (debug_type == BSRMON_NETWORK_SPEED) {
		struct connection *conn = res->conn;
		if (!res->conn) {
			bsrmon_log(stderr, "Invalid %s res->conn object\n", res->name);
			return -1;
		}
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("transport_speed");

		while (conn) {
			sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s ", conn->name);
			debugInfo = GetDebugInfo(flag, res, -1, conn->node_id);
			if (!debugInfo) {
				bsrmon_log(stderr, "Failed to get %s(conn->node_id:%d) %s debuginfo(%d).\n", 
						res->name, conn->node_id, perf_type_str(debug_type), flag);
				goto fail;
			}

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;
			conn = conn->next;
		}
#else // _LIN
		while (conn) {
			sprintf(path, "%s/resources/%s/connections/%s/transport_speed", DEBUGFS_ROOT, res->name, conn->name);

			sprintf(buffer + strlen(buffer), "%s ", conn->name);
			fp = fopen(path, "r");
			if (!fp) {
				bsrmon_log(stderr, "Failed to open file, path : %s\n", path);
				goto fail;
			}

			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);
			conn = conn->next;
		}
#endif
		// BSR-776 do not write error messages to the performance file.
		if (!strncmp(buffer, "err reading", 11))
			goto fail;

		sprintf_ex(outfile, "%s%s%s", respath, _SEPARATOR_, perf_type_str(debug_type));
		
		fp = perf_fileopen(outfile, currtime);
		if (fp == NULL)
			goto fail;

		fprintf(fp, "%s %s\n", currtime, buffer);	
		fclose(fp);

	}
	else if (debug_type == BSRMON_SEND_BUF) {
		struct connection *conn = res->conn;
		if (!res->conn) {
			bsrmon_log(stderr, "Invalid %s res->conn object\n", res->name);
			return -1;
		}
#ifdef _WIN
		flag = ConvertToBsrDebugFlags("send_buf");
		
		while (conn) {
			sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s ", conn->name);
			debugInfo = GetDebugInfo(flag, res, -1, conn->node_id);
			if (!debugInfo) {
				bsrmon_log(stderr, "Failed to get %s(conn->node_id:%d) %s debuginfo(%d).\n", 
						res->name, conn->node_id, perf_type_str(debug_type), flag);
				goto fail;
			}

			memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
			free(debugInfo);
			debugInfo = NULL;
			conn = conn->next;

		}
#else // _LIN
		while (conn) {
			sprintf(path, "%s/resources/%s/connections/%s/send_buf", DEBUGFS_ROOT, res->name, conn->name);

			sprintf(buffer + strlen(buffer), "%s ", conn->name);
			fp = fopen(path, "r");
			if (!fp) {
				bsrmon_log(stderr, "Failed to open file, path : %s\n", path);
				goto fail;
			}

			fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
			fclose(fp);
			conn = conn->next;
		}
#endif
		// BSR-776 do not write error messages to the performance file.
		if (!strncmp(buffer, "err reading", 11))
			goto fail;
		sprintf_ex(outfile, "%s%s%s", respath, _SEPARATOR_, perf_type_str(debug_type));

		fp = perf_fileopen(outfile, currtime);
		if (fp == NULL)
			goto fail;

		fprintf(fp, "%s %s\n", currtime, buffer);
		fclose(fp);
	}
	// BSR-838 
	else if (debug_type == BSRMON_RESYNC_RATIO) {
		struct volume *vol = res->vol;
		if (!res->vol) {
			bsrmon_log(stderr, "Invalid %s res->vol object\n", res->name);
			goto fail;
		}

		while (vol) {
			struct connection *conn = res->conn;
			if (!res->conn) {
				bsrmon_log(stderr, "Invalid %s res->conn object\n", res->name);
				return -1;
			}
#ifdef _WIN
			flag = ConvertToBsrDebugFlags("resync_ratio");

			while (conn) {
				sprintf_s(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), "%s ", conn->name);
				debugInfo = GetDebugInfo(flag, res, vol->vnr, conn->node_id);
				if (!debugInfo) {
					bsrmon_log(stderr, "Failed to get %s(vnr:%d,conn->node_id:%d) %s debuginfo(%d).\n", 
						res->name, vol->vnr, conn->node_id, perf_type_str(debug_type), flag);
					goto fail;
				}

				memcpy(buffer + strlen(buffer), debugInfo->buf, strlen(debugInfo->buf));
				free(debugInfo);
				debugInfo = NULL;
				conn = conn->next;

			}
#else // _LIN
			while (conn) {
				sprintf(path, "%s/resources/%s/connections/%s/%d/resync_ratio", DEBUGFS_ROOT, res->name, conn->name, vol->vnr);

				sprintf(buffer + strlen(buffer), "%s ", conn->name);
				fp = fopen(path, "r");
				if (!fp) {
					bsrmon_log(stderr, "Failed to open file, path : %s\n", path);
					goto fail;
				}

				fread(buffer + strlen(buffer), MAX_DEBUG_BUF_SIZE - strlen(buffer), 1, fp);
				fclose(fp);
				conn = conn->next;
			}
#endif	
			// BSR-776 do not write error messages to the performance file.
			if (!strncmp(buffer, "err reading", 11))
				goto fail;

			sprintf_ex(outfile, "%s%svnr%d_%s", respath, _SEPARATOR_, vol->vnr, perf_type_str(debug_type));

			fp = perf_fileopen(outfile, currtime);
			if (fp == NULL)
				goto fail;

			fprintf(fp, "%s %s\n", currtime, buffer);
			fclose(fp);
			memset(buffer, 0, MAX_DEBUG_BUF_SIZE);
			vol = vol->next;
		}
	} else {
		bsrmon_log(stderr, "Invalid debug_type value\n");
		goto fail;
	}

	ret = 0;

fail:

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
	char outfile[MAX_PATH] = {0,};
	char *buffer = NULL;
	int ret = -1;


	sprintf_ex(outfile, "%s%s", path, perf_type_str(BSRMON_MEMORY));

	fp = perf_fileopen(outfile, currtime);
	if (fp == NULL)
		goto fail;

	fprintf(fp, "%s ", currtime);

#ifdef _LIN
	// BSR-875
	buffer = GetSysMemoryUsage();
	if (buffer) {
		fprintf(fp, "%s", buffer);
		free(buffer);
		buffer = NULL;
	}
#endif
	buffer = GetBsrMemoryUsage(false);
	if (buffer) {
		fprintf(fp, "%s", buffer);
		free(buffer);
		buffer = NULL;
	}
#ifdef _LIN
	// BSR-875
	buffer = GetBsrModuleMemoryUsage();
	if (buffer) {
		fprintf(fp, "%s", buffer);
		free(buffer);
		buffer = NULL;
	} else {
		// BSR-881
		fprintf(fp, "0 0 0 0 ");
	}
#endif

	buffer = GetBsrUserMemoryUsage();
	if (buffer) {
		fprintf(fp, "%s", buffer);
		free(buffer);
		buffer = NULL;
	}
	fprintf(fp, "\n");
	fclose(fp);

	ret = 0;

fail:
	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
	return ret;
}