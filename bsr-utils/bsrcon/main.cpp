#include "command.h"

static void usage(bool all_cmd);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#ifdef _WIN
void disk_error_usage()
{
	printf("disk error simulation. Absolutely only for testing purposes!\n"
		"usage: bsrcon /disk_error <errorflag> <errortype> <errorcount>\n\n"
		"errorflag:\n"
		"   0: no disk error, disable error simulation\n"
        "   1: continuous disk error\n"
        "   2: temporary disk error\n"
        "\n\n"

		"errortype:\n"		
		"   0: Errors before Disk I/O request, generic_make_request fail\n"
		"   1: Local Disk I/O complete with error\n"
		"   2: Peer Disk I/O complete with error\n"
		"   3: Meta Data I/O complete with error\n"
		"   4: Bitmap I/O complete with error\n"
		"\n\n"

		"errorcount:\n"
        "   0 ~ 4294967295, unsigned integer\n"
	);
	exit(ERROR_INVALID_PARAMETER);
}
#endif

#ifdef _WIN
// BSR-1051
static int confirmed(const char *text, bool force)
{
	const char yes[] = "yes";
	const size_t N = sizeof(yes);
	char answer[32] = { 0, };
	size_t n = 0;
	int ok = 0;

	fprintf(stderr, "\n%s\n", text);

	if (force) {
		fprintf(stderr, "*** confirmation forced via --force option ***\n");
		ok = 1;
	}
	else {
		fprintf(stderr, "[need to type '%s' to confirm] ", yes);
		scanf_s("%s", answer);
		if (strlen(answer) == (N - 1) &&
			!strncmp(answer, yes, N - 1)) {
			ok = 1;
		}
		fprintf(stderr, "\n");
	}

	return ok;
}
#endif

UCHAR letter = 'C';
int verbose = 0;
// BSR-1112
int cmd_get_log_path(int *index, int argc, char* argv[])
{
	return get_log_path();
}

// BSR-1052
// BSR-973
int cmd_get_log(int *index, int argc, char* argv[])
{
	char *providerName = NULL;
	char *resourceName = NULL;
	int oosTrace = 0;

	(*index)++;

	if (*index < argc)
		providerName = argv[*index];
	else
		usage(false);
	(*index)++;

	// DW-1629
	for (int num = 0; num < 2; num++) {
		if (*index < argc) {

#ifdef _DEBUG_OOS
			if (strcmp(argv[*index], "oos") == 0)
				oosTrace++;
			else if (!resourceName) {
#else
			if (!resourceName) {
#endif
				resourceName = argv[*index];
				//6 additional parsing data length (">bsr ")
				if (strlen(resourceName) > MAX_PATH - 6)
					usage(false);
			}
			else
				usage(false);

			(*index)++;
		}
		else
			break;
	}

	return MVOL_GetBsrLog(providerName, resourceName, oosTrace);
}

int cmd_minlog_lv(int *index, int argc, char* argv[])
{
	LOGGING_MIN_LV lml = { 0, };
	
	(*index)++;

	// first argument indicates logging type.
	if (*index < argc) {
		if (strcmp(argv[*index], "sys") == 0) {
			lml.nType = LOGGING_TYPE_SYSLOG;
		}
		else if (strcmp(argv[*index], "dbg") == 0) {
			lml.nType = LOGGING_TYPE_DBGLOG;
		}
		else
			usage(false);
	}

	// second argument indicates minimum logging level.
	(*index)++;
	if (*index < argc) {
		lml.nErrLvMin = atoi(argv[*index]);
	}
	else
		usage(false);

	return MVOL_SetMinimumLogLevel(&lml);
}

// BSR-1031
int cmd_statuscmd_logging(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc) {
		if ((strcmp(argv[*index], "1") == 0) ||
			(strcmp(argv[*index], "0") == 0))
			return set_statuscmd_logging(atoi(argv[*index]));
		else usage(false);
	}
	else
		usage(false);

	return 0;
}

// BSR-605
int cmd_climaxlogfile_cnt(int *index, int argc, char* argv[])
{
	CLI_LOG_MAX_COUNT lmc = { 0, };
	
	(*index)++;
	if (*index < argc) {
		if (strcmp(argv[*index], "adm") == 0) {
			lmc.nType = BSR_ADM_LOG_FILE_MAX_COUNT;
		}
		else if (strcmp(argv[*index], "setup") == 0) {
			lmc.nType = BSR_SETUP_LOG_FILE_MAX_COUNT;
		}
		else if (strcmp(argv[*index], "meta") == 0) {
			lmc.nType = BSR_META_LOG_FILE_MAX_COUNT;
		}
		else
			usage(false);
	}

	(*index)++;

	if (*index < argc) {
		if (atoi(argv[*index]) == 0) {
			printf("You must enter a value greater than 1. Please enter again.\n");
			return -1;
		}
		lmc.nMaxCount = atoi(argv[*index]);
	}
	else
		usage(false);

	return set_cli_log_file_max_count(lmc.nType, lmc.nMaxCount);
}

// BSR-579
int cmd_maxlogfile_cnt(int *index, int argc, char* argv[])
{
	(*index)++;
	// BSR-618
	if (*index >= argc)
		usage(false);

	// BSR-1238
	if (atoi(argv[*index]) == 0) {
		printf("You must enter a value greater than 1. Please enter again.\n");
		return -1;
	}

	// BSR-579
	return MVOL_SetLogFileMaxCount(atoi(argv[*index]));
}

// BSR-654
int cmd_dbglog_ctgr(int *index, int argc, char* argv[])
{
	DEBUG_LOG_CATEGORY dlc = { 0, };
	int i;

	(*index)++;
	if ((*index + 1) < argc) {
		if (!strcmp(argv[*index], "enable"))
		{
			dlc.nType = 0;
		}
		else if (!strcmp(argv[*index], "disable"))
		{
			dlc.nType = 1;
		}
		else
			usage(false);

		for (; *index < argc; (*index)++) {
			for (i = 0; i < (int)ARRAY_SIZE(g_log_category_str); i++) {
#ifdef _WIN
				if (_strcmpi(argv[*index], g_log_category_str[i]) == 0) {
#else
				if (strcasecmp(argv[*index], g_log_category_str[i]) == 0) {
#endif
					dlc.nCategory += 1 << i;
					break;
				}
#ifdef _WIN
				else if (_strcmpi(argv[*index], "all") == 0) {
#else
				else if (strcasecmp(argv[*index], "all") == 0) {
#endif
					dlc.nCategory = -1;
					break;
				}
			}
		}
		return MVOL_SetDebugLogCategory(&dlc);
	}
	else
		usage(false);

	return 0;
}

#define BToM(x) (x / 1024 / 1024)

int cmd_get_log_info(int *index, int argc, char* argv[])
{
	// DW-1921
	int sys_evt_lv = 0;
	int dbglog_lv = 0;
	int log_max_count = 0;
	int cli_log_max_count = 0;
	int dbg_ctgr = 0;
	int log_backup_size = 0;

	// DW-2008
	if (get_log_level(&sys_evt_lv, &dbglog_lv)) {
		printf("Current log storage path.\n");
		printf("    ");
		get_log_path();
		printf("\n");

		printf("Current log level.\n");
		printf("    system-lv : %s(%d)\n    debug-lv : %s(%d)\n",
			g_default_lv_str[sys_evt_lv], sys_evt_lv, g_default_lv_str[dbglog_lv], dbglog_lv);
		printf("\n");

		printf("Maximum log file capacity\n");
		log_backup_size = BToM(CLI_LOG_FILE_MAX_SIZE);

		// BSR-605
		if (get_cli_log_file_max_count(&cli_log_max_count)) {
			int adm_cnt, setup_cnt, meta_cnt;

			adm_cnt = ((cli_log_max_count >> BSR_ADM_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK);
			setup_cnt = ((cli_log_max_count >> BSR_SETUP_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK);
			meta_cnt = ((cli_log_max_count >> BSR_META_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK);

			printf("    bsradm : size %dMB, count %d, total size %dMB\n", log_backup_size, adm_cnt, adm_cnt * log_backup_size);
			printf("    bsrsetup : size %dMB, count %d, total size %dMB\n", log_backup_size, setup_cnt, setup_cnt * log_backup_size);
			printf("    bsrmeta : size %dMB, count %d, total size %dMB\n", log_backup_size, meta_cnt, meta_cnt * log_backup_size);
		}
		else
			printf("Failed to get cli log file max count\n");

		log_backup_size = BToM(BSR_LOG_SIZE);
		// BSR-579
		if (get_engine_log_file_max_count(&log_max_count))
			printf("    bsrdriver : size %dMB, count %d, total size %dMB\n", log_backup_size, log_max_count, log_max_count * log_backup_size);
		else
			printf("Failed to get log file max count\n");

		printf("\n");

		if (get_debug_log_enable_category(&dbg_ctgr)) {
			printf("Output category during debug log.\n");
			printf("    category :");
			for (int i = 0; i < LOG_CATEGORY_MAX; i++) {
				if (dbg_ctgr & (1 << i)) {
					printf(" %s", g_log_category_str[i]);
				}
			}
			printf("\n");
		}
		else
			printf("Failed to get debug log enable category\n");
	}
	else
		printf("Failed to get log level.\n");
	printf("\n");
	// BSR-1031
	get_statuscmd_logging();

	return 0;
}

// BSR-1060 gets the set handler information.
int cmd_get_handler_info(int *index, int argc, char* argv[])
{
	printf("Current handler.\n");
	printf("    state : %s\n", get_handler_use() ? "enable" : "disable");
#ifdef _WIN
	printf("    timeout : %d\n", get_handler_timeout());
#endif
	return 0;
}
// BSR-1060 sets the handler wait time. the unit is seconds.
#ifdef _WIN
int cmd_handler_timeout(int *index, int argc, char* argv[])
{
	HANDLER_TIMEOUT_INFO hInfo = { 0, };

	(*index)++;
	if (*index < argc) {
		int timeout = atoi(argv[*index]);
		if (timeout < 0) {
			fprintf(stderr, "HANDLER_TIMEOUT_ERROR: %s: Invalid parameter\n", __FUNCTION__);
			usage(false);
		}
		else {
			hInfo.timeout = timeout;
		}
	}
	else
		usage(false);

	return  MVOL_SetHandlerTimeout(&hInfo);
}
#endif

int cmd_handler_use(int *index, int argc, char* argv[])
{
	HANDLER_INFO hInfo = { 0, };

	(*index)++;
	if (*index < argc) {
		int use = atoi(argv[*index]);
		if (use < 0 || use > 1) {
			fprintf(stderr, "HANDLER_USE_ERROR: %s: Invalid parameter\n", __FUNCTION__);
			usage(false);
		}
		else {
			if (use)
				hInfo.use = true;
		}
	}
	else
		usage(false);

	return  MVOL_SetHandlerUse(&hInfo);
}
#ifdef _WIN
#ifdef _DEBUG_OOS
int cmd_convert_oos_log(int *index, int argc, char* argv[])
{
	(*index)++;

	// Get oos log path
	if (*index < argc)
		return MVOL_ConvertOosLog((LPCTSTR)argv[*index]);
	else
		usage(false);
}


int cmd_serch_oos_log(int *index, int argc, char* argv[])
{
	char *srcPath = NULL;
	char *sector = NULL;

	(*index)++;

	// Get oos log path
	if (*index < argc)
		srcPath = argv[*index];
	else
		usage(false);

	// Get oos search sector
	(*index)++;
	if (*index < argc)
		sector = argv[*index];
	else
		usage(false);

	return MVOL_SearchOosLog((LPCTSTR)srcPath, (LPCTSTR)sector);
}
#endif

// BSR-71
int cmd_bsrlock_use(int *index, int argc, char* argv[])
{
	int bBsrLock = 0;
	
	(*index)++;
	if (*index < argc) {
		bBsrLock = atoi(argv[*index]);
		if (bBsrLock < 0 || bBsrLock > 1) {
			fprintf(stderr, "BSRLOCK_USE_ERROR: %s: Invalid parameter\n", __FUNCTION__);
			usage(false);
		}
	}
	else
		usage(false);

	return MVOL_BsrlockUse(bBsrLock);
}

int cmd_write_log(int *index, int argc, char* argv[])
{
	char *providerName = NULL;
	char *loggingData = NULL;

	(*index)++;
	// Get eventlog provider name.
	if (*index < argc)
		providerName = argv[*index];
	else
		usage(false);

	// Get eventlog data to be written.
	(*index)++;
	if (*index < argc)
		loggingData = argv[*index];
	else
		usage(false);

	return WriteEventLog((LPCSTR)providerName, (LPCSTR)loggingData);
}

int cmd_get_volume_size(int *index, int argc, char* argv[])
{
	MVOL_VOLUME_INFO	srcVolumeInfo;
	LARGE_INTEGER		volumeSize;
	int res;

	printf("GET VOLUME SIZE\n");

	memset(&srcVolumeInfo, 0, sizeof(MVOL_VOLUME_INFO));

	res = MVOL_GetVolumeInfo(letter, &srcVolumeInfo);
	if (res) {
		printf("cannot get src volume info, Drive=%c:, err=%d\n",
			letter, GetLastError());
		return res;
	}

	volumeSize.QuadPart = 0;
	res = MVOL_GetVolumeSize(srcVolumeInfo.PhysicalDeviceName, &volumeSize);
	if (res) {
		printf("cannot MVOL_GetVolumeSize, err=%d\n", res);
		return res;
	}
	else
		printf("VolumeSize = %I64d\n", volumeSize.QuadPart);

	return res;
}

int cmd_delaydack_enable(int *index, int argc, char* argv[])
{
	char *addr = NULL;
	int res;

	(*index)++;
	if (*index < argc)
		addr = argv[*index];
	else
		usage(false);

	res = MVOL_SetDelayedAck(addr, "enable");
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Cannot enable DelayedAck. Err=%u\n", res);
	}

	return res;
}

int cmd_nodelayedack(int *index, int argc, char* argv[])
{
	int res = 0;
	char *addr;

	(*index)++;
	if (*index < argc)
		addr = argv[*index];
	else
		usage(false);

	res = MVOL_SetDelayedAck(addr, "disable");
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Cannot disable DelayedAck. Err=%u\n", res);
	}

	return res;
}

int cmd_letter(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc)
		letter = (UCHAR)*argv[*index];
	else
		usage(false);

	return 0;
}


int cmd_proc(int *index, int argc, char* argv[])
{
	MVOL_VOLUME_INFO VolumeInfo = { 0, };
	int res;

	res = MVOL_GetStatus(&VolumeInfo);
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Failed MVOL_GetStatus. Err=%u\n", res);
	}
	else {
		fprintf(stdout, "%s\n", VolumeInfo.Seq);
	}

	return res;
}

int cmd_status(int *index, int argc, char* argv[])
{
	MVOL_VOLUME_INFO VolumeInfo = { 0, };
	CHAR tmpSeq[sizeof(VolumeInfo.Seq)] = { NULL };
	CHAR *line, *cline;
	CHAR *context = NULL;
	CHAR buffer[2] = { NULL };
	int res;

	res = MVOL_GetStatus(&VolumeInfo);
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Failed MVOL_GetStatus. Err=%u\n", res);
	}
	else {
		int lineCount = 1;
		line = strtok_s(VolumeInfo.Seq, "\n", &context);
		while (line) {
			if (strstr(line, ": cs:")) {
				cline = (char *)malloc(strlen(line) + 1);
				strcpy_s(cline, strlen(line) + 1, line);
				buffer[0] = atoi(strtok_s(NULL, ":", &cline)) + 67;
				buffer[1] = '\0';
				strcat_s(tmpSeq, buffer);
			}

			strcat_s(tmpSeq, line);
			strcat_s(tmpSeq, "\n");
			line = strtok_s(NULL, "\n", &context);
			if (lineCount == 2) strcat_s(tmpSeq, "\n");
			lineCount++;
		}
		fprintf(stdout, "%s\n", tmpSeq);
	}

	return res;
}

int cmd_dismount(int *index, int argc, char* argv[])
{
	int force = 0;
	int res;

	(*index)++;
	if (*index < argc)
		letter = (UCHAR)*argv[*index];
	else
		usage(false);

	res = MVOL_DismountVolume(letter, force);

	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Failed MVOL_DismountVolume. Err=%u\n", res);
	}

	return res;
}

int cmd_release_vol(int *index, int argc, char* argv[])
{
	int ret = ERROR_SUCCESS;
	char* resName = NULL;
	bool force = false;

	(*index)++;
	if (((*index) + 1) < argc) {
		// BSR-1051 
		if (!strcmp(argv[*index], "--force")) {
			force = true;
			(*index)++;
		}
		resName = argv[(*index)++];
		letter = (UCHAR)*argv[(*index)++];
	} else 
		usage(false);

	printf(" ==> Destroys the meta data of volume letter %c! <==\n", letter);
	if (!confirmed("The volume release unlocks the volume and destroy the meta data.\nDo you really want to release volume?\n", force))
		return ret;

	ret = MVOL_MountVolume(letter);
	if (ERROR_SUCCESS == ret) {
		char cl[MAX_PATH] = { 0, };
		char *wd = NULL, *buf = NULL;
		size_t len;

		printf("Mounted volume.\n");
		ret = delete_volume_reg(letter);
		if (ERROR_SUCCESS == ret)
			printf("Deleted registry key.\n");
		else
			printf("Failed to remove volume lock registry key. Please remove registry key.\n");

		if (!_dupenv_s(&wd, &len, "BSR_PATH")) {
			bool wm = false;
			char *token, *ptr;
			char str[MAX_PATH] = { 0, };

			// BSR-1051 run dry-run to find the target volume in case of multiple volumes.
			sprintf_s(cl, "bsradm --dry-run wipe-md %s", resName);
			ret = RunProcess(cl, wd, &buf);
			if (ERROR_SUCCESS == ret) {
				sprintf_s(str, "bsrmeta %d", letter > 'a' ? letter - 'c' : letter - 'C');
				token = strtok_s(buf, "\n", &ptr);
				while (token != NULL) {
					if (!strncmp(token, str, strlen(str))) {
						// BSR-1051 destroys the metadata of the volume.
						sprintf_s(str, "%s--force", token);
						ret = RunProcess(str, wd, NULL);
						if (ERROR_SUCCESS == ret)
							printf("Destroyed meta data.\n");
						else
							printf("Failed to destroy meta data. Please destroy meta data(wipe-md).\n");
						wm = true;
						break;
					}
					token = strtok_s(ptr, "\n", &ptr);
				}
				if (wd)
					free(wd);
				if (buf)
					free(buf);
				if (!wm)
					printf("Failed to destroy meta data. Please destroy meta data(wipe-md).\n");
			} else
				printf("Failed to destroy meta data. Please destroy meta data(wipe-md).\n");
		} else
			printf("Failed to get BSR installation path during volume release. Please destroy meta data(wipe-md).\n");
	}

	return ret;
}

int cmd_disk_error(int *index, int argc, char* argv[])
{
	SIMULATION_DISK_IO_ERROR sdie = { 0, };

	(*index)++;
	// get parameter 1 (DiskI/O error flag)
	if (*index < argc) {
		sdie.ErrorFlag = atoi(argv[*index]);
		(*index)++;
		// get parameter 2 (DiskI/O error Type)
		if (*index < argc) {
			sdie.ErrorType = atoi(argv[*index]);
			(*index)++;
			// get parameter 3 (DiskI/O error count)
			if (*index < argc) {
				sdie.ErrorCount = atoi(argv[*index]);
			}
			else {
				disk_error_usage();
			}
		}
		else {
			disk_error_usage();
		}
	}
	else {
		disk_error_usage();
	}
	return MVOL_SimulDiskIoError(&sdie);
}

int cmd_bsrlock_status(int *index, int argc, char* argv[])
{
	return GetBsrlockStatus();
}

int cmd_info(int *index, int argc, char* argv[])
{
	int res = 0;

	(*index)++;
	if (*index < argc && !strcmp(argv[*index], "--verbose"))
		verbose++;

	res = MVOL_GetVolumesInfo(verbose);
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Failed MVOL_InitThread. Err=%u\n", res);

	}
	return res;
}

int cmd_driver_install(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc) // BSR-1030 apply the primary driver section to the inf file
		return driver_Install_Inf(L"DefaultInstall.NTamd64", argv[*index]);
	else
		usage(false);
}

int cmd_driver_uninstall(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc) // BSR-1030
		return driver_Install_Inf(L"DefaultUninstall.NTamd64", argv[*index]);
	else
		usage(false);
}

int cmd_md5(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc)
		return generating_md5(argv[*index]);
	else
		usage(false);
}
#endif

int cmd_set_fast_sync(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc)
		return set_fast_sync(atoi(argv[*index]));
	else
		usage(false);

	return 0;
}

int cmd_get_fast_sync(int *index, int argc, char* argv[])
{
	return get_fast_sync();
}

int cmd_write_kernel_log(int *index, int argc, char* argv[])
{
	int level = 0;
	(*index)++;
	if (*index < argc) {
		level = atoi(argv[(*index)++]);
		return MVOL_WriteBsrKernelLog(level, argv[*index]);
	}
	else
		usage(false);

	return 0;
}


// BSR-1072 a system panic will occur immediately.
int cmd_forced_panic(int *index, int argc, char* argv[])
{
	char cert[MAX_PANIC_CERT_BUF];

	(*index)++;

	memset(cert, 0, MAX_PANIC_CERT_BUF);
	fgets(cert, MAX_PANIC_CERT_BUF, stdin);

	return MVOL_BsrPanic(0, 0, 1, cert);
}

// BSR-1072 generates a system panic based on the time specified.
int cmd_bsr_panic(int *index, int argc, char* argv[])
{
	int panic_enable = 0;
	int occurrence_time = 0;

	(*index)++;
	if ((*index + 1) < argc) {
		panic_enable = atoi(argv[(*index)++]);
		occurrence_time = atoi(argv[(*index)++]);
		return MVOL_BsrPanic(panic_enable, occurrence_time, 0, NULL);
	}
	else
		usage(false);

	return 0;
}

// BSR-1039 holds or releases the specified state. (currently only supports L_AHEAD status.)
int cmd_bsr_hold_state(int *index, int argc, char* argv[])
{
	int type = 0;
	int state = 0;

	(*index)++;
	if ((*index + 1) < argc) {
		type = atoi(argv[(*index)++]);
		state = atoi(argv[(*index)++]);
		return MVOL_HoldState(type, state);
	}
	else
		usage(false);

	return 0;
}

// BSR-1039 sets the number of fake slots used by AL.
int cmd_bsr_fake_al_used(int *index, int argc, char* argv[])
{
	int al_used_count = 0;

	(*index)++;
	if (*index < argc) {
		al_used_count = atoi(argv[(*index)++]);
		return MVOL_FakeALUsed(al_used_count);
	}
	else
		usage(false);

	return 0;
}


// BSR-1112 add commands to change log path
int cmd_set_log_path(int *index, int argc, char* argv[])
{
	char *newPath;

	(*index)++;

	if (*index < argc) {
#ifdef _WIN
		char *ptr;
		newPath = strtok_s(argv[*index], "\"", &ptr);
#else
		newPath = argv[*index];
#endif
		return set_log_path(newPath);
	}
	else
		usage(false);
	
	return 0;
}

int cmd_all_cmd_usage(int *index, int argc, char* argv[])
{
	usage(true);
}

struct cmd_struct {
	const char *cmd;
	int(*fn) (int *, int, char **);
	const char *options;
	const char *desc;
	const char *example;
	// BSR-1073 set whether to hide commands.
	bool hide;
};

static struct cmd_struct commands[] = {
	{ "/all_usage", cmd_all_cmd_usage, "", "", "", false },
	// BSR-1052 added /get_log command again
	// BSR-973
	{ "/get_log", cmd_get_log, "{save log file name}\n", "", "\"bsrsave.txt\" or \"C:\\Program Files\\bsr\\log\\bsrsave.txt\"", true },
	{ "/minlog_lv", cmd_minlog_lv, "{log type} {log level}", "", "\"dbg 7\" or \"sys 7\"", false },
	{ "/statuscmd_logging", cmd_statuscmd_logging, "{status cmd logging}", "", "\"1\" or \"0\"", true },
	{ "/climaxlogfile_cnt", cmd_climaxlogfile_cnt, "{file type} {max file count}", "", "\"adm 10\" or \"setup 10\" or \"meta 10\"", false },
	{ "/maxlogfile_cnt", cmd_maxlogfile_cnt, "{max file count}", "", "10" },
	{ "/dbglog_ctgr", cmd_dbglog_ctgr, "{category use} {category}", "", "\"enable VOLUME SOKET ETC\" or \"disable VOLUME PROTOCOL\"", true },
	{ "/get_log_info", cmd_get_log_info, "", "", "", false },
	{ "/handler_use", cmd_handler_use, "{handler use}", "", "\"1\" or \"0\"", false },
	{ "/get_handler_info", cmd_get_handler_info, "", "", "", false },
#ifdef _WIN
	// BSR-1060
	{ "/handler_timeout", cmd_handler_timeout, "{handler timeout(seconds)}", "", "1", false },
#ifdef _DEBUG_OOS
	{ "/convert_oos_log", cmd_convert_oos_log, "{source file path}", "", "C:\\Program Files\\bsr\\log", true },
	{ "/serch_oos_log", cmd_serch_oos_log, "{source file path} {sector}", "", "\"C:\\Program Files\\bsr\\log\" 10240000", true },
#endif
	{ "/bsrlock_use", cmd_bsrlock_use, "{bsrlock use}", "", "\"1\" or \"0\"", false },
	{ "/write_log", cmd_write_log, "{provider name} {logging data}", "", "bsr data", true },
	{ "/get_volume_size", cmd_get_volume_size, "", "", "", false },
	{ "/delaydack_enable", cmd_delaydack_enable, "{address}", "", "10.10.1.10", false },
	{ "/nodelayedack", cmd_nodelayedack, "{address}", "", "10.10.1.10", false },
	{ "/letter", cmd_letter, "{letter}", "", "E", true },
	{ "/l", cmd_letter, "{letter}", "", "E", true },
	{ "/proc/bsr", cmd_proc, "", "", "", true },
	{ "/status", cmd_status, "", "", "", false },
	{ "/s", cmd_status, "", "", "", true },
	{ "/dismount", cmd_dismount, "{letter}", "", "E", false },
	// BSR-1051
	{ "/release_vol", cmd_release_vol, "{resource name} {letter}", "", "\"r0 E\", \"--force r0 E\"", false },
	{ "/disk_error", cmd_disk_error, "{error flag} {error type} {error count}", "", "1 2 100", false },
	{ "/bsrlock_status", cmd_bsrlock_status, "", "", "", true },
	{ "/info", cmd_info, "", "", "", false },
	{ "/driver_install", cmd_driver_install, "{driver file path}", "", "\"C:\\Program Files\\bsr\\bin\\bsrfsflt.inf\"", false },
	{ "/driver_uninstall", cmd_driver_uninstall, "{driver file path}", "", "\"C:\\Program Files\\bsr\\bin\\bsrfsflt.inf\"", false },
	{ "/md5", cmd_md5, "{file path}", "", "\"C:\\Program Files\\bsr\\bin\\md5\"", false },
#endif
	{ "/set_fast_sync", cmd_set_fast_sync, "{fast sync use}", "", "\"1\" or \"0\"", false },
	{ "/get_fast_sync", cmd_get_fast_sync, "", "", "", false },
	{ "/write_kernel_log", cmd_write_kernel_log, "", "", "", true },
	// BSR-1072
	{ "/forced_panic", cmd_forced_panic, "", "", "", true },
	{ "/bsr_panic", cmd_bsr_panic, "", "", "", true },
	// BSR-1039
	{ "/hold_state", cmd_bsr_hold_state, "type state", "only supports turning on and off congestion", "2 22 or 0 0", true },
	// BSR-1039
	{ "/fake_al_used", cmd_bsr_fake_al_used, "{fake al used count}", "", "6001", true },
	// BSR-1112
	{ "/set_log_path", cmd_set_log_path, "{log file path}", "", 
#ifdef _WIN
		"\"C:\\Program Files\\bsr\\log\"", 
#else // _LIN
		"/var/log/bsr", 
#endif
		false },
	{ "/get_log_path", cmd_get_log_path, "", "", "", false },

};

static void usage(bool all_cmd)
{
	int i;
	printf("usage: bsrcon cmds options \n\n"
		"cmds:\n");

	for (i = 0; i < (int)ARRAY_SIZE(commands); i++) {
		if (!all_cmd) {
			if (commands[i].hide)
				continue;
		}
		printf("\t%s %s\n", commands[i].cmd, commands[i].options);
		if (!strcmp(commands[i].cmd, "/minlog_lv")) {
			printf("\t\tlevel info,");
			for (int i = 0; i < LOG_DEFAULT_MAX_LEVEL; i++) {
				printf(" %s(%d)", g_default_lv_str[i], i);
			}
			printf("\n");
		}
		else if (!strcmp(commands[i].cmd, "/dbglog_ctgr")) {
			printf("\t\tcategory info,");
			for (int i = 0; i < LOG_CATEGORY_MAX; i++) {
				printf(" %s", g_log_category_str[i]);
			}
			printf("\n");
		}
	}

	printf("examples:\n");
	for (i = 0; i < (int)ARRAY_SIZE(commands); i++) {
		if (commands[i].hide)
			continue;
		printf("\tbsrcon %s %s\n", commands[i].cmd, commands[i].example);
	}

	exit(ERROR_INVALID_PARAMETER);
}

#ifdef _WIN
DWORD main(int argc, char* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	DWORD res = ERROR_SUCCESS;
	int argIndex = 0, commandIndex = 0;

	if (argc < 2)
		usage(false);

	struct cmd_struct *cmd = NULL;

	for (argIndex = 1; argIndex < argc; argIndex++) {
		for (commandIndex = 0; commandIndex < (int)ARRAY_SIZE(commands); commandIndex++) {
			if (!strcmp(commands[commandIndex].cmd, argv[argIndex])) {
				cmd = &commands[commandIndex];
				if (cmd) {
					res = cmd->fn(&argIndex, argc, argv);
					if (res)
						return res;
					break;
				}
			}
		}

		if (!cmd) {
			printf("Please check undefined arg[%d]=(%s)\n", argIndex, argv[argIndex]);
			break;
		}

		cmd = NULL;
	}

	return res;
}

