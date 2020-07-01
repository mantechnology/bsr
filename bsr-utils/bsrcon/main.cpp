#ifdef _WIN
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "mvol.h"
#include "LogManager.h"
#else // _LIN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mvol.h"
#endif

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

void usage()
{
	printf("usage: bsrcon cmds options \n\n"
		"cmds:\n");
#ifdef _WIN
	printf(
		"   /nodelayedack [ip|guid]\n"
        "   /delayedack_enable [ip|guid]\n"
        "   /m [letter] : mount\n"
		"   /bsrlock_status\n"
		"   /info\n"
		"   /status : bsr version\n"
		"   /write_log [ProviderName] \"[LogData]\" \n"
);
#endif
	printf(
		"   /handler_use [0,1]\n"
		"   /get_log [ProviderName]\n"
		// DW-1629
		"   /get_log [ProviderName] [ResourceName : Max Length 250|oos]\n"
		"   /get_log [ProviderName] [ResourceName : Max Length 250][oos]\n"
		"   /get_log_info\n"
		"   /maxlogfile_cnt [LogFileMaxCount : 0 ~ 1000]\n"
		"   /climaxlogfile_cnt [adm, setup, meta] [LogFileMaxCount : 0 ~ 255]\n"
		"   /minlog_lv [sys, dbg] [Level : 0~7]\n");
	// DW-2008
	printf("\t level info,");
	for (int i = 0; i < LOG_DEFAULT_MAX_LEVEL; i++) {
		printf(" %s(%d)", g_default_lv_str[i], i);
	}
	printf("\n");

	printf("   /minlog_lv feature [flag : 0,1,2,4]\n");
	printf("\t level info,");
	for (int i = 0; (1 << (i - 1)) < LOG_FEATURE_MAX_LEVEL; i++) {
		printf(" %s(%d)", g_feature_lv_str[i], i == 0 ? 0 : 1 << (i - 1));
	}
	printf("\n");
		
	printf(
		"\n\n"
#ifdef _WIN
		"options:\n"
		"   /letter or /l : drive letter \n"
		"\n\n"
		"examples:\n"
        "bsrcon /nodelayedack 10.10.0.1 \n"
        "bsrcon /m F \n"
		"bsrcon /write_log bsrService \"Logging start\" \n"	
#else
		"examples:\n"
#endif
		"bsrcon /handler_use 1 \n"	
		"bsrcon /get_log bsrService \n"
		"bsrcon /get_log bsrService r0\n"
		"bsrcon /get_log_info \n"
		"bsrcon /minlog_lv dbg 6 \n"
		"bsrcon /minlog_lv sys 3 \n"
		"bsrcon /maxlogfile_cnt 5\n"
		"bsrcon /climaxlogfile_cnt adm 2\n"
		"bsrcon /minlog_lv feature 2\n"
	);

	exit(ERROR_INVALID_PARAMETER);
}

#ifdef _WIN
const TCHAR gBsrRegistryPath[] = _T("System\\CurrentControlSet\\Services\\bsr\\volumes");

static
DWORD DeleteVolumeReg(TCHAR letter)
{
	HKEY hKey = NULL;
	DWORD dwIndex = 0;
	const int MAX_VALUE_NAME = 16;
	const int MAX_VOLUME_GUID = 256;

	TCHAR szSrcLetter[2] = { letter, 0 };
	TCHAR szRegLetter[MAX_VALUE_NAME] = { 0, };
	DWORD cbRegLetter = MAX_VALUE_NAME;
	UCHAR volGuid[MAX_VOLUME_GUID] = { 0, };
	DWORD cbVolGuid = MAX_VOLUME_GUID;

	LONG lResult = ERROR_SUCCESS;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, gBsrRegistryPath, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		if (lResult == ERROR_FILE_NOT_FOUND) {
			fprintf(stderr, "Key not found\n");
		}
		else {
			fprintf(stderr, "Error opening key\n");
		}
		return lResult;
	}

	while (ERROR_SUCCESS == RegEnumValue(hKey, dwIndex++, szRegLetter, &cbRegLetter,
		NULL, NULL, (LPBYTE)volGuid, &cbVolGuid)) {

		if (!_tcsicmp(szRegLetter, szSrcLetter)) {
			lResult = RegDeleteValue(hKey, szRegLetter);
			if (ERROR_SUCCESS != lResult) {
				fprintf(stderr, "Error deleting value. code(0x%x)\n", lResult);
			}
			RegCloseKey(hKey);
			return lResult;
		}

		memset(szRegLetter, 0, MAX_VALUE_NAME * sizeof(TCHAR));
		memset(volGuid, 0, MAX_VOLUME_GUID * sizeof(UCHAR));
		cbRegLetter = MAX_VALUE_NAME;
		cbVolGuid = MAX_VOLUME_GUID;
	}

	RegCloseKey(hKey);

	return lResult;
}
#endif

// BSR-579
BOOLEAN GetLogFileMaxCount(int *max)
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD log_file_max_count = 0;
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsr");
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		return FALSE;
	}

	lResult = RegQueryValueEx(hKey, _T("log_file_max_count"), NULL, &type, (LPBYTE)&log_file_max_count, &size);
	RegCloseKey(hKey);

#else // _LIN
	// BSR-597 get log_file_max_count
	FILE *fp;
	fp = fopen(BSR_LOG_FILE_MAXCNT_REG, "r");
	if(fp != NULL) {
		char buf[10] = {0};
		if (fgets(buf, sizeof(buf), fp) != NULL)
			log_file_max_count = atoi(buf);
		fclose(fp);
	} else {
		lResult = ERROR_FILE_NOT_FOUND;
	}
#endif

	if (lResult == ERROR_FILE_NOT_FOUND || lResult != ERROR_SUCCESS || log_file_max_count == 0)
		log_file_max_count = LOG_FILE_COUNT_DEFAULT;

	*max = log_file_max_count;

	return true;
}


// BSR-605
BOOLEAN GetCliLogFileMaxCount(int *max)
{
	DWORD cli_log_file_max_count = 0;
#ifdef _WIN
	DWORD lResult = ERROR_SUCCESS;
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsr");
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		return FALSE;
	}

	lResult = RegQueryValueEx(hKey, _T(BSR_CLI_LOG_FILE_MAX_COUT_VALUE_REG), NULL, &type, (LPBYTE)&cli_log_file_max_count, &size);
	RegCloseKey(hKey);

	if (lResult == ERROR_FILE_NOT_FOUND || lResult != ERROR_SUCCESS || cli_log_file_max_count == 0) {
		cli_log_file_max_count = (2 << BSR_ADM_LOG_FILE_MAX_COUNT);
		cli_log_file_max_count += (2 << BSR_SETUP_LOG_FILE_MAX_COUNT);
		cli_log_file_max_count += (2 << BSR_META_LOG_FILE_MAX_COUNT);
	}
#else // _LIN
	// BSR-605 displays the default value in case of open or read failure.
	cli_log_file_max_count = (2 << BSR_ADM_LOG_FILE_MAX_COUNT);
	cli_log_file_max_count += (2 << BSR_SETUP_LOG_FILE_MAX_COUNT);
	cli_log_file_max_count += (2 << BSR_META_LOG_FILE_MAX_COUNT);

	// /etc/bsr.d/.cli_log_file_max_count
	FILE *fp = fopen(BSR_CLI_LOG_FILE_MAXCNT_REG, "r");
	if (fp != NULL) {
		char buf[10] = { 0 };
		if (fgets(buf, sizeof(buf), fp) != NULL) 
			cli_log_file_max_count = atoi(buf);
		fclose(fp);
	}
#endif
	*max = cli_log_file_max_count;

	return true;
}


// BSR-605 cli log maximum file count settings 
BOOLEAN CLI_SetLogFileMaxCount(int cli_type, int max)
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD cli_log_file_max_count = 0;
	DWORD adm_max, setup_max, meta_max;
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsr");
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		return FALSE;
	}

	lResult = RegQueryValueEx(hKey, _T("cli_log_file_max_count"), NULL, &type, (LPBYTE)&cli_log_file_max_count, &size);
#else // _LIN
	// /etc/bsr.d/.cli_log_file_max_count
	FILE *fp = fopen(BSR_CLI_LOG_FILE_MAXCNT_REG, "r");
	if (fp != NULL) {
		char buf[10] = { 0 };
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			cli_log_file_max_count = atoi(buf);
		}
		else {
			// BSR-605 set the default value if the file fails to open or read.
			lResult = (DWORD)ERROR_FILE_NOT_FOUND;
		}
		fclose(fp);
	}
	else {
		// BSR-605 set the default value if the file fails to open or read.
		lResult = (DWORD)ERROR_FILE_NOT_FOUND;
	}
#endif
	if (lResult == (DWORD)ERROR_FILE_NOT_FOUND) {
		adm_max = setup_max = meta_max = 2;
	}
	else if (lResult != ERROR_SUCCESS) {
#ifdef _WIN
		RegCloseKey(hKey);
#endif
		return false;
	}
	else { 
		adm_max = ((cli_log_file_max_count >> BSR_ADM_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK);
		setup_max = ((cli_log_file_max_count >> BSR_SETUP_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK);
		meta_max = ((cli_log_file_max_count >> BSR_META_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK);
	}

	if (cli_type == BSR_ADM_LOG_FILE_MAX_COUNT) {
		adm_max = max;
	}
	else if (cli_type == BSR_SETUP_LOG_FILE_MAX_COUNT) {
		setup_max = max;
	}
	else if (cli_type == BSR_META_LOG_FILE_MAX_COUNT) {
		meta_max = max;
	}

	cli_log_file_max_count = ((adm_max << BSR_ADM_LOG_FILE_MAX_COUNT) | (setup_max << BSR_SETUP_LOG_FILE_MAX_COUNT) | (meta_max << BSR_META_LOG_FILE_MAX_COUNT));
#ifdef _WIN
	lResult = RegSetValueEx(hKey, _T("cli_log_file_max_count"), 0, REG_DWORD, (LPBYTE)&cli_log_file_max_count, sizeof(cli_log_file_max_count));
#else // _LIN
	// /etc/bsr.d/.cli_log_file_max_count
	fp = fopen(BSR_CLI_LOG_FILE_MAXCNT_REG, "w+");
	if (fp != NULL) {
		char buf[10] = { 0 } ;
		sprintf(buf, "%u", cli_log_file_max_count);
		if (!fputs(buf, fp)) 
			return false;
		fclose(fp);
	}
	else
		return false;

#endif
	if (ERROR_SUCCESS != lResult)
		return false;

#ifdef _WIN
	RegCloseKey(hKey);
#endif

	return true;
}

// DW-1921
//Print log_level through the current registry value.
BOOLEAN GetLogLevel(int *sys_evtlog_lv, int *dbglog_lv, int *feature_lv)
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD logLevel = 0;
#ifdef _WIN
	HKEY hKey = NULL;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsr");
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);
#else
	FILE *fp;
#endif

#ifdef _WIN
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		return FALSE;
	}

	lResult = RegQueryValueEx(hKey, _T("log_level"), NULL, &type, (LPBYTE)&logLevel, &size);
	RegCloseKey(hKey);
#else // _LIN
	// BSR-584 read /etc/bsr.d/.log_level
	fp = fopen(BSR_LOG_LEVEL_REG, "r");
	if(fp != NULL) {
		char buf[10] = {0};
		if (fgets(buf, sizeof(buf), fp) != NULL)
			logLevel = atoi(buf);
		fclose(fp);
	} else {
		lResult = ERROR_FILE_NOT_FOUND;
	}
#endif

	if (lResult == ERROR_FILE_NOT_FOUND || logLevel == 0) {
		// DW-1921
		//It is not an error that no key exists.Just set it to the default value.
		*sys_evtlog_lv = LOG_LV_DEFAULT_EVENTLOG;
		*dbglog_lv = LOG_LV_DEFAULT_DBG;
		*feature_lv = LOG_LV_DEFAULT_FEATURE;

		return true;
	} else if (lResult != ERROR_SUCCESS)
		return true;


	*sys_evtlog_lv = (logLevel >> LOG_LV_BIT_POS_EVENTLOG) & LOG_LV_MASK;
	*dbglog_lv = (logLevel >> LOG_LV_BIT_POS_DBG) & LOG_LV_MASK;
	*feature_lv = (logLevel >> LOG_LV_BIT_POS_FEATURELOG) & LOG_LV_MASK;

	return true;

}


#ifdef _WIN
DWORD main(int argc, char* argv [])
#else
int main(int argc, char* argv [])
#endif
{
	DWORD	res = ERROR_SUCCESS;
	int  	argIndex = 0;
	char	GetLog = 0;
	char	OosTrace = 0;
	char	*ProviderName = NULL;
	char	*resourceName = NULL;
	// DW-1921
	char	GetLogInfo = 0;
	char	SetMinLogLv = 0;
	char	SetCliLogFileMaxCount = 0;
	char	SetLogFileMaxCount = 0;
	LOGGING_MIN_LV lml = { 0, };
	CLI_LOG_MAX_COUNT lmc = { 0, };
	int LogFileCount = 0;
	char	HandlerUseFlag = 0;
	HANDLER_INFO hInfo = { 0, };
#ifdef _WIN
	UCHAR	Letter = 'C';
	char	GetVolumeSizeFlag = 0;
	char	ProcBsrFlag = 0;
	char	ProcBsrFlagWithLetter = 0;
    char    DelayedAckEnableFlag = 0;
    char    DelayedAckDisableFlag = 0;
    char    MountFlag = 0, DismountFlag = 0;
	char	SimulDiskIoErrorFlag = 0;
    char    *addr = NULL;
	char	WriteLog = 0;
	char	*LoggingData = NULL;
	char	VolumesInfoFlag = 0;
	char	Bsrlock_status = 0;
	char	Verbose = 0;
	int     Force = 0;
	SIMULATION_DISK_IO_ERROR sdie = { 0, };
#endif
#ifdef _DEBUG_OOS
	char	ConvertOosLog = 0;
	char	*pSrcFilePath = NULL;	
	char	SearchOosLog = 0;
	char	*sector = NULL;
#endif

	if (argc < 2)
		usage();

	for (argIndex = 1; argIndex < argc; argIndex++) {
		if (strcmp(argv[argIndex], "/get_log") == 0) {
			argIndex++;
			GetLog++;

			if (argIndex < argc)
				ProviderName = argv[argIndex];
			else
				usage();
			argIndex++;

			// DW-1629
			for (int num = 0; num < 2; num++) {
				if (argIndex < argc) {

#ifdef _DEBUG_OOS
					if (strcmp(argv[argIndex], "oos") == 0)
						OosTrace++;
					else if (!resourceName) {
#else
					if (!resourceName) {
#endif
						resourceName = argv[argIndex];
						//6 additional parsing data length (">bsr ")
						if (strlen(resourceName) > MAX_PATH - 6)
							usage();
					}
					else
						usage();

					argIndex++;
				}
				else
					break;
			}

		}
#ifdef _DEBUG_OOS
		else if (strcmp(argv[argIndex], "/convert_oos_log") == 0) {
			argIndex++;
			ConvertOosLog++;

			// Get oos log path
			if (argIndex < argc)
				pSrcFilePath = argv[argIndex];
			else
				usage();
		}
		else if (strcmp(argv[argIndex], "/search_oos_log") == 0) {
			argIndex++;
			SearchOosLog++;

			// Get oos log path
			if (argIndex < argc)
				pSrcFilePath = argv[argIndex];
			else
				usage();

			// Get oos search sector
			argIndex++;
			if (argIndex < argc)
				sector = argv[argIndex];
			else
				usage();
		}
#endif
		else if (strcmp(argv[argIndex], "/minlog_lv") == 0) {
			argIndex++;
			SetMinLogLv++;

			// first argument indicates logging type.
			if (argIndex < argc) {
				if (strcmp(argv[argIndex], "sys") == 0) {
					lml.nType = LOGGING_TYPE_SYSLOG;
				}
				else if (strcmp(argv[argIndex], "dbg") == 0) {
					lml.nType = LOGGING_TYPE_DBGLOG;
				}
				else if (strcmp(argv[argIndex], "feature") == 0) {
					lml.nType = LOGGING_TYPE_FEATURELOG;
				}
				else
					usage();				
			}

			// second argument indicates minimum logging level.
			argIndex++;
			if (argIndex < argc) {
				lml.nErrLvMin = atoi(argv[argIndex]);
			}
			else
				usage();
		}
		// BSR-605
		else if (strcmp(argv[argIndex], "/climaxlogfile_cnt") == 0) {
			argIndex++;
			SetCliLogFileMaxCount++;
			if (argIndex < argc) {
				if (strcmp(argv[argIndex], "adm") == 0) {
					lmc.nType = BSR_ADM_LOG_FILE_MAX_COUNT;
				}
				else if (strcmp(argv[argIndex], "setup") == 0) {
					lmc.nType = BSR_SETUP_LOG_FILE_MAX_COUNT;
				}
				else if (strcmp(argv[argIndex], "meta") == 0) {
					lmc.nType = BSR_META_LOG_FILE_MAX_COUNT;
				}
				else
					usage();
			}

			argIndex++;
			if (argIndex < argc) {
				lmc.nMaxCount = atoi(argv[argIndex]);
			}
			else
				usage();
		}

		// BSR-579
		else if (strcmp(argv[argIndex], "/maxlogfile_cnt") == 0) {
			SetLogFileMaxCount++;
			argIndex++;
			// BSR-618
			if (argIndex < argc) {
				LogFileCount = atoi(argv[argIndex]);
			}
			else
				usage();
		}
		else if (!strcmp(argv[argIndex], "/get_log_info")) {
			GetLogInfo++;
		}
		else if (strcmp(argv[argIndex], "/handler_use") == 0) {
			HandlerUseFlag++;
			argIndex++;

			if (argIndex < argc)
				hInfo.use = atoi(argv[argIndex]);
			else
				usage();
		}
#ifdef _WIN
		else if (strcmp(argv[argIndex], "/write_log") == 0) {
			argIndex++;
			WriteLog++;
			
			// Get eventlog provider name.
			if (argIndex < argc)
				ProviderName = argv[argIndex];
			else
				usage();

			// Get eventlog data to be written.
			argIndex++;
			if (argIndex < argc)
				LoggingData = argv[argIndex];
			else
				usage();
		}
		else if (strcmp(argv[argIndex], "/get_volume_size") == 0) {
			GetVolumeSizeFlag++;
		}
		else if (strcmp(argv[argIndex], "/delayedack_enable") == 0) {
			DelayedAckEnableFlag++;
			argIndex++;

			if (argIndex < argc)
				addr = argv[argIndex];
			else
				usage();
		}
		else if (strcmp(argv[argIndex], "/nodelayedack") == 0) {
			DelayedAckDisableFlag++;
			argIndex++;

			if (argIndex < argc)
				addr = argv[argIndex];
			else
				usage();
		}
		else if (!_stricmp(argv[argIndex], "/letter") || !_stricmp(argv[argIndex], "/l")) {
			argIndex++;

			if (argIndex < argc)
				Letter = (UCHAR) *argv[argIndex];
			else
				usage();
		}
		
		else if (!strcmp(argv[argIndex], "/proc/bsr")) {
			ProcBsrFlag++;
		}
		else if (!strcmp(argv[argIndex], "/status") || !strcmp(argv[argIndex], "/s")) {
			ProcBsrFlagWithLetter++;
		}
		else if (!_stricmp(argv[argIndex], "/d")) {
            DismountFlag++;
            argIndex++;

            if (argIndex < argc)
                Letter = (UCHAR)*argv[argIndex];
            else
                usage();
        }

		/*
		else if (!_stricmp(argv[argIndex], "/fd") || !_stricmp(argv[argIndex], "/df")) {
            Force = 1;
            DismountFlag++;
            argIndex++;

            if (argIndex < argc)
                Letter = (UCHAR)*argv[argIndex];
            else
                usage();
        }
		*/
        else if (!_stricmp(argv[argIndex], "/m")) {
            MountFlag++;
            argIndex++;

            if (argIndex < argc)
                Letter = (UCHAR)*argv[argIndex];
            else
                usage();
        }
		else if (!_stricmp(argv[argIndex], "/disk_error")) // Simulate Disk I/O Error
		{
			SimulDiskIoErrorFlag++;
			argIndex++;
			// get parameter 1 (DiskI/O error flag)
			if (argIndex < argc) {
				sdie.ErrorFlag = atoi(argv[argIndex]);
				argIndex++;
				// get parameter 2 (DiskI/O error Type)
				if (argIndex < argc) {
					sdie.ErrorType = atoi(argv[argIndex]);
					argIndex++;
					// get parameter 3 (DiskI/O error count)
					if (argIndex < argc) {
						sdie.ErrorCount = atoi(argv[argIndex]);
					} else {
						disk_error_usage();					
					}
				} else {
					disk_error_usage();
				}
			} else {
				disk_error_usage();
			}
			
		}
		else if (!strcmp(argv[argIndex], "/bsrlock_status")) {
			Bsrlock_status++;
		}
		else if (!strcmp(argv[argIndex], "/info")) {
			VolumesInfoFlag++;
		}
		else if (!strcmp(argv[argIndex], "--verbose")) {
			Verbose++;
		}
#endif
		else {
			printf("Please check undefined arg[%d]=(%s)\n", argIndex, argv[argIndex]);
		}
	}


	if (SetMinLogLv) {
		res = MVOL_SetMinimumLogLevel(&lml);
	}

	if (GetLog) {
		res = MVOL_GetBsrLog(ProviderName, resourceName, OosTrace);
	}
	
	// BSR-579
	if (SetLogFileMaxCount) {
		res = MVOL_SetLogFileMaxCount(LogFileCount);
	}

	// BSR-605
	if (SetCliLogFileMaxCount) {
		res = CLI_SetLogFileMaxCount(lmc.nType, lmc.nMaxCount);
	}

	// DW-1921
	if (GetLogInfo) {
		int sys_evt_lv = 0;
		int dbglog_lv = 0;
		int feature_lv = 0;
		int log_max_count = 0;
		int cli_log_max_count = 0;

		// DW-2008
		if (GetLogLevel(&sys_evt_lv, &dbglog_lv, &feature_lv)) {
			printf("Current log level.\n");
			printf("    system-lv : %s(%d)\n    debug-lv : %s(%d)\n    feature-lv : %d\n",
				g_default_lv_str[sys_evt_lv], sys_evt_lv, g_default_lv_str[dbglog_lv], dbglog_lv, feature_lv);

			printf("Number of log files that can be saved.\n");
			printf("Maximum size of one log file is 50M.\n"); 
			// BSR-579
			if (GetLogFileMaxCount(&log_max_count))
				printf("    bsrdriver : %d\n", log_max_count);
			else
				printf("Failed to get log file max count\n");

			// BSR-605
			if (GetCliLogFileMaxCount(&cli_log_max_count)) {
				printf("    bsradm : %d\n", ((cli_log_max_count >> BSR_ADM_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK));
				printf("    bsrsetup : %d\n", ((cli_log_max_count >> BSR_SETUP_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK));
				printf("    bsrmeta : %d\n", ((cli_log_max_count >> BSR_META_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK));
			}
			else
				printf("Failed to get cli log file max count\n");
		}
		else
			printf("Failed to get log level.\n");
	}


#ifdef _DEBUG_OOS
	if (SearchOosLog) {
		res = MVOL_SearchOosLog((LPCTSTR)pSrcFilePath, (LPCTSTR)sector);
	}
#endif

	if (HandlerUseFlag) {
		res = MVOL_SetHandlerUse(&hInfo);
	}

#ifdef _WIN
	if (GetVolumeSizeFlag) {
		MVOL_VOLUME_INFO	srcVolumeInfo;
		LARGE_INTEGER		volumeSize;

		printf("GET VOLUME SIZE\n");

		memset(&srcVolumeInfo, 0, sizeof(MVOL_VOLUME_INFO));

		res = MVOL_GetVolumeInfo(Letter, &srcVolumeInfo);
		if (res) {
			printf("cannot get src volume info, Drive=%c:, err=%d\n",
				Letter, GetLastError());
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

	if (ProcBsrFlag) {
		MVOL_VOLUME_INFO VolumeInfo = {0,};

		res = MVOL_GetStatus( &VolumeInfo );
		if( res != ERROR_SUCCESS ) {
			fprintf( stderr, "Failed MVOL_GetStatus. Err=%u\n", res );
		}
		else {
			fprintf( stdout, "%s\n", VolumeInfo.Seq );
		}

		return res;
	}

	if (ProcBsrFlagWithLetter) {
		MVOL_VOLUME_INFO VolumeInfo = { 0, };
		CHAR tmpSeq[sizeof(VolumeInfo.Seq)] = { NULL };
		CHAR *line, *cline;
		CHAR *context = NULL;
		CHAR buffer[2] = { NULL };

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

    if (DelayedAckEnableFlag) {	
		res = MVOL_SetDelayedAck(addr, "enable");
        if (res != ERROR_SUCCESS) {
            fprintf(stderr, "Cannot enable DelayedAck. Err=%u\n", res);
        }

        return res;
    }

    if (DelayedAckDisableFlag) {
        res = MVOL_SetDelayedAck(addr, "disable");
        if (res != ERROR_SUCCESS) {
            fprintf(stderr, "Cannot disable DelayedAck. Err=%u\n", res);
        }

        return res;
    }

    if (DismountFlag) {
        res = MVOL_DismountVolume(Letter, Force);

        if (res != ERROR_SUCCESS) {
            fprintf(stderr, "Failed MVOL_DismountVolume. Err=%u\n", res);
        }
    }

	if (MountFlag) {
		res = MVOL_MountVolume(Letter);
		if (ERROR_SUCCESS == res) {
			if (ERROR_SUCCESS == DeleteVolumeReg(Letter)) {
				fprintf(stderr, "%c: is Mounted, not any more bsr volume.\nRequire to delete a resource file.\n", Letter);
			}
		}
	}
	if (SimulDiskIoErrorFlag) {
		res = MVOL_SimulDiskIoError(&sdie);
	}

#ifdef _DEBUG_OOS
	if (ConvertOosLog) {
		res = MVOL_ConvertOosLog((LPCTSTR)pSrcFilePath);
	}
#endif

	if (WriteLog) {
		res = WriteEventLog((LPCSTR)ProviderName, (LPCSTR)LoggingData);
	}


	if (VolumesInfoFlag) {
		res = MVOL_GetVolumesInfo(Verbose);
		if( res != ERROR_SUCCESS ) {
			fprintf( stderr, "Failed MVOL_InitThread. Err=%u\n", res );
		}

		return res;
	}

	if (Bsrlock_status) {
		res = GetBsrlockStatus();
	}

#endif
	return res;
}

