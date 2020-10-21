#include <stdio.h>
#include <stdlib.h>

enum get_info_type
{
	RESOURCE,
	CONNECTION,
	VOLUME,
};

struct volume {
	int vnr;
	struct volume* next;
};

struct connection {
	char name[2][20];
	int node_id[2];
};

struct resource {
	char name[10];
	struct connection *conn;
	struct volume *vol;
	struct resource* next;
};

void* exec_pipe(enum get_info_type info_type, char *res_name)
{
	char command[128], command2[128]; 
	char buf[128] = {0,};
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
	} else if (info_type == CONNECTION) {
#ifdef _WIN
		sprintf_s(command, "bsradm sh-peer-node-name %s", res_name);
#else // _LIN
		sprintf(command, "bsradm sh-peer-node-name %s", res_name);
#endif
		conn = (struct connection*)malloc(sizeof(struct connection));
		if (!conn) {
			printf("conn malloc failed, size : %d\n", sizeof(struct connection));
			return NULL;
		}
		memset(conn, 0, sizeof(conn));
	} else if (info_type == VOLUME) {
#ifdef _WIN
		sprintf_s(command, "bsradm sh-dev-vnr %s", res_name);
#else // _LIN
		sprintf(command, "bsradm sh-dev-vnr %s", res_name);
#endif
	} else {
		printf("invalid get_info_type value\n");
		return NULL;
	}

#ifdef _WIN
	pipe = _popen(command, "r");
#else // _LIN
	pipe = popen(command, "r");
#endif
	if (!pipe) {
		printf("popen failed, command : %s\n", command);
		return NULL;
	}
	while (!feof(pipe)) {
		if (fgets(buf, 128, pipe) != NULL) {
			// remove EOL
			*(buf+(strlen(buf)-1)) = 0;

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
						printf("res malloc failed, size : %d\n", sizeof(struct resource));
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
			} else if (info_type == CONNECTION) {
#ifdef _WIN
				strcpy_s(conn->name[idx++], buf);
#else // _LIN
				strcpy(conn->name[idx++], buf);
#endif
			} else if (info_type == VOLUME) {
				vol = (struct volume*)malloc(sizeof(struct volume));
				if (!vol) {
					printf("vol malloc failed, size : %d\n", sizeof(struct volume));
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
		} else if (*buf == 0) {
			printf("exec failed, command : %s\n", command);
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
	} else if (info_type == CONNECTION) {
		idx = 0;
#ifdef _WIN
		sprintf_s(command, "bsradm sh-peer-node-id %s", res_name);
		pipe = _popen(command, "r");
#else // _LIN
		sprintf(command, "bsradm sh-peer-node-id %s", res_name);
		pipe = popen(command, "r");
#endif
		if (!pipe) {
			printf("popen failed, command : %s\n", command);
			return NULL;
		}
		while (!feof(pipe)) {
			if (fgets(buf, 128, pipe) != NULL) {
				// remove EOL
				*(buf+(strlen(buf)-1)) = 0;

				conn->node_id[idx++] = atoi(buf);
			} else if (*buf == 0) {
				printf("exec failed, command : %s\n", command);
				return NULL;
			}
		}
#ifdef _WIN
		_pclose(pipe);
#else // _LIN
		pclose(pipe);
#endif

		return conn;
	} else if (info_type == VOLUME) {
		return vol_head;
	} else {
		return NULL;
	}
}

void freeResource(struct resource* res)
{
	struct resource* res_temp;
	struct volume* vol_temp;

	while(res) {
		if (res->conn) {
			free(res->conn);
			res->conn = NULL;
		}

		while(res->vol) {
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
	while(res) {
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