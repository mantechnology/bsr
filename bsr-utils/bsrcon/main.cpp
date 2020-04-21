#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "mvol.h"
#include "LogManager.h"

void
disk_error_usage()
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


void
usage()
{
	printf("usage: bsrcon cmds options \n\n"
		"cmds:\n"
		/*"   /proc/bsr \n"*/
		/*"   /get_volume_size \n"*/
		"   /nodelayedack [ip|guid]\n"
        "   /delayedack_enable [ip|guid]\n"
        "   /m [letter] : mount\n"
        /*"   /d[f] : dismount[force] \n"*/
		"   /get_log [ProviderName]\n"
		// DW-1629
		"   /get_log [ProviderName] [ResourceName : Max Length 250|oos]\n"
		"   /get_log [ProviderName] [ResourceName : Max Length 250][oos]\n"
		"   /minlog_lv [sys, dbg] [Level : 0~7]\n");
	// DW-2008
	printf("\t level info,");
	for (int i = 0; i < LOG_DEFAULT_MAX_LEVEL; i++) {
		printf(" %s(%d)", g_default_lv_str[i], i);
	}
	printf("\n");

	printf("   /minlog_lv feature [flag : 0,1,2,4]\n");
	printf("\t level info,");
	for (int i = 0; i < LOG_FEATURE_MAX_LEVEL; i++) {
		printf(" %s(%d)", g_feature_lv_str[i], i == 0 ? 0 : 1 << (i - 1));
	}
	printf("\n");
		
	printf("   /write_log [ProviderName] \"[LogData]\" \n"
		"   /handler_use [0,1]\n"
		"	/bsrlock_status\n"
		"   /info\n"
		"   /status : bsr version\n"
		"	/get_log_lv\n"

		"\n\n"

		"options:\n"
		"   /letter or /l : drive letter \n"
		"\n\n"

		"examples:\n"
/*		"bsrcon /proc/bsr\n"*/
/*		"bsrcon /status\n"*/
/*		"bsrcon /s\n"*/
        "bsrcon /nodelayedack 10.10.0.1 \n"
        /*"bsrcon /d F \n"*/
        "bsrcon /m F \n"
		"bsrcon /get_log bsrService \n"
		"bsrcon /get_log bsrService r0\n"
		"bsrcon /minlog_lv dbg 6 \n"
		"bsrcon /minlog_lv sys 3 \n"
		"bsrcon /minlog_lv feature 2\n"
		"bsrcon /write_log bsrService \"Logging start\" \n"
		"bsrcon /handler_use 1 \n"		
		"bsrcon /get_log_lv \n"
	);

	exit(ERROR_INVALID_PARAMETER);
}

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

// DW-1921

//Print log_level through the current registry value.
BOOL GetLogLevel(int *sys_evtlog_lv, int *dbglog_lv, int *feature_lv)
{
	HKEY hKey = NULL;
	LONG lResult = ERROR_SUCCESS;
	const TCHAR bsrRegistry[] = _T("SYSTEM\\CurrentControlSet\\Services\\bsr");
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);
	DWORD logLevel = 0;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, bsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		return FALSE;
	}

	lResult = RegQueryValueEx(hKey, _T("log_level"), NULL, &type, (LPBYTE)&logLevel, &size);
	RegCloseKey(hKey);

	if (ERROR_SUCCESS != lResult) {
		if (lResult == ERROR_FILE_NOT_FOUND) {
			// DW-1921
			//It is not an error that no key exists.Just set it to the default value.
			*sys_evtlog_lv = LOG_LV_DEFAULT_EVENTLOG;
			*dbglog_lv = LOG_LV_DEFAULT_DBG;
			*feature_lv = LOG_LV_DEFAULT_FEATURE;

			return TRUE;
		}
		else
			return TRUE;
	}

	*sys_evtlog_lv = (logLevel >> LOG_LV_BIT_POS_EVENTLOG) & LOG_LV_MASK;
	*dbglog_lv = (logLevel >> LOG_LV_BIT_POS_DBG) & LOG_LV_MASK;
	*feature_lv = (logLevel >> LOG_LV_BIT_POS_FEATURELOG) & LOG_LV_MASK;

	return TRUE;
}

DWORD
main(int argc, char* argv [])
{
	DWORD	res = ERROR_SUCCESS;
	int  	argIndex = 0;
	UCHAR	Letter = 'C';
	char	GetVolumeSizeFlag = 0;
	char	ProcBsrFlag = 0;
	char	ProcBsrFlagWithLetter = 0;
    char    DelayedAckEnableFlag = 0;
    char    DelayedAckDisableFlag = 0;
	char	HandlerUseFlag = 0;
    char    MountFlag = 0, DismountFlag = 0;
	char	SimulDiskIoErrorFlag = 0;
    char    *addr = NULL;
	char	GetLog = 0;
	char	OosTrace = 0;
#ifdef _WIN_DEBUG_OOS
	char	ConvertOosLog = 0;
	char	*pSrcFilePath = NULL;	
	char	SearchOosLog = 0;
	char	*sector = NULL;
#endif
	char	WriteLog = 0;
	char	SetMinLogLv = 0;
	char	*ProviderName = NULL;
	char	*LoggingData = NULL;
	char	VolumesInfoFlag = 0;
	char	Bsrlock_status = 0;
	char	Verbose = 0;
	char	*resourceName = NULL;
	int     Force = 0;
	// DW-1921
	char	GetLogLv = 0;

	LARGE_INTEGER Offset = {0,};
	ULONG	BlockSize = 0;
	ULONG	Count = 0;
	SIMULATION_DISK_IO_ERROR sdie = { 0, };
	LOGGING_MIN_LV lml = { 0, };
	HANDLER_INFO hInfo = { 0, };

	if (argc < 2)
		usage();

	for (argIndex = 1; argIndex < argc; argIndex++) {
		if (strcmp(argv[argIndex], "/get_volume_size") == 0) {
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
		else if (strcmp(argv[argIndex], "/get_log") == 0) {
			argIndex++;
			GetLog++;

			if (argIndex < argc)
				ProviderName = argv[argIndex];
			else
				usage();
#ifdef _WIN_DEBUG_OOS
			argIndex++;

			// DW-1629
			for (int num = 0; num < 2; num++) {
				if (argIndex < argc) {
					if (strcmp(argv[argIndex], "oos") == 0)
						OosTrace++;
					else if (!resourceName) {
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
#endif
		}
#ifdef _WIN_DEBUG_OOS
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
		else if (strcmp(argv[argIndex], "/handler_use") == 0) {
			HandlerUseFlag++;
			argIndex++;

			if (argIndex < argc)
				hInfo.use = atoi(argv[argIndex]);
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
		else if (!strcmp(argv[argIndex], "/bsrlock_status")) {
			Bsrlock_status++;
		}
		else if (!strcmp(argv[argIndex], "/info")) {
			VolumesInfoFlag++;
		}
		else if (!strcmp(argv[argIndex], "--verbose")) {
			Verbose++;
		}
		else if (!strcmp(argv[argIndex], "/get_log_lv")) {
			GetLogLv++;
		}
		else {
			printf("Please check undefined arg[%d]=(%s)\n", argIndex, argv[argIndex]);
		}
	}

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

	if (SetMinLogLv) {
		res = MVOL_SetMinimumLogLevel(&lml);
	}

	if (GetLog) {
		//res = CreateLogFromEventLog( (LPCSTR)ProviderName );
		res = MVOL_GetBsrLog(ProviderName, resourceName, OosTrace);
	}
#ifdef _WIN_DEBUG_OOS
	if (ConvertOosLog) {
		res = MVOL_ConvertOosLog((LPCTSTR)pSrcFilePath);
	}

	if (SearchOosLog) {
		res = MVOL_SearchOosLog((LPCTSTR)pSrcFilePath, (LPCTSTR)sector);
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

	if (HandlerUseFlag) {
		res = MVOL_SetHandlerUse(&hInfo);
	}

	// DW-1921
	if (GetLogLv) {
		int sys_evt_lv = 0;
		int dbglog_lv = 0;
		int feature_lv = 0;

		// DW-2008
		if (GetLogLevel(&sys_evt_lv, &dbglog_lv, &feature_lv)) {
			printf("system-lv : %s(%d)\ndebug-lv : %s(%d)\nfeature-lv : %d\n",
				g_default_lv_str[sys_evt_lv], sys_evt_lv, g_default_lv_str[dbglog_lv], dbglog_lv, feature_lv);
		}
		else
			printf("Failed to get log level.\n");
	}

	return res;
}

