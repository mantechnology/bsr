#ifdef _WIN
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "mvol.h"
#include "LogManager.h"
// DW-2166
#include <setupapi.h>
#include <stdlib.h>
#include <Shlwapi.h>
#else // _LIN
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mvol.h"
#endif

static void usage();

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
const TCHAR gBsrRegistryPath[] = _T("System\\CurrentControlSet\\Services\\bsrvflt\\volumes");
const TCHAR gBsrRegistry[] = _T("System\\CurrentControlSet\\Services\\bsrvflt");
#endif

#ifdef _WIN
DWORD get_value_of_vflt(TCHAR *target, DWORD *value)
#else
DWORD get_value_of_vflt(const char *target, DWORD *value)
#endif
{
	DWORD lResult = ERROR_SUCCESS;
#ifdef _WIN
	HKEY hKey = NULL;
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);
#else
	FILE *fp;
#endif

#ifdef _WIN
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, gBsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		return lResult;
	}

	lResult = RegQueryValueEx(hKey, target, NULL, &type, (LPBYTE)value, &size);
	RegCloseKey(hKey);
#else // _LIN
	fp = fopen(target, "r");
	if (fp != NULL) {
		char buf[11] = { 0 };
		if (fgets(buf, sizeof(buf), fp) != NULL)
			*value = atoi(buf);
		fclose(fp);
	}
	else {
		lResult = ERROR_FILE_NOT_FOUND;
	}
#endif

	return lResult;
}

#ifdef _WIN
DWORD set_value_of_vflt(TCHAR *target, DWORD *value)
#else
DWORD set_value_of_vflt(const char *target, DWORD *value)
#endif
{
	DWORD lResult = ERROR_SUCCESS;
#ifdef _WIN
	HKEY hKey = NULL;
	DWORD type = REG_DWORD;
	DWORD size = sizeof(DWORD);
#else
	FILE *fp;
#endif

#ifdef _WIN
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, gBsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		return lResult;
	}

	lResult = RegSetValueEx(hKey, target, 0, REG_DWORD, (LPBYTE)value, sizeof(*value));
	RegCloseKey(hKey);
#else // _LIN
	fp = fopen(target, "w+");
	if (fp != NULL) {
		char buf[11] = { 0 };
		sprintf(buf, "%u", *value);
		if (!fputs(buf, fp))
			lResult = ERROR_INVALID_DATA;
		fclose(fp);
	}
#endif

	return lResult;
}

#ifdef _WIN
static DWORD delete_volume_reg(TCHAR letter)
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
BOOLEAN get_log_file_max_count(int *max)
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD log_file_max_count = 0;
#ifdef _WIN
	lResult = get_value_of_vflt(_T("log_file_max_count"), &log_file_max_count);
#else // _LIN
	// BSR-597 get log_file_max_count
	lResult = get_value_of_vflt(BSR_LOG_FILE_MAXCNT_REG, &log_file_max_count);
#endif

	if (lResult == ERROR_FILE_NOT_FOUND || lResult != ERROR_SUCCESS || log_file_max_count == 0)
		log_file_max_count = LOG_FILE_COUNT_DEFAULT;

	*max = log_file_max_count;

	return true;
}


// BSR-605
BOOLEAN get_cli_log_file_max_count(int *max)
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD cli_log_file_max_count = 0;
#ifdef _WIN

	lResult = get_value_of_vflt(_T(BSR_CLI_LOG_FILE_MAX_COUT_VALUE_REG), &cli_log_file_max_count);
#else // _LIN
	// /etc/bsr.d/.cli_log_file_max_count
	lResult = get_value_of_vflt(BSR_CLI_LOG_FILE_MAXCNT_REG, &cli_log_file_max_count);
#endif
	if (lResult == ERROR_FILE_NOT_FOUND || lResult != ERROR_SUCCESS || cli_log_file_max_count == 0) {
		// BSR-605 displays the default value in case of open or read failure.
		cli_log_file_max_count = (2 << BSR_ADM_LOG_FILE_MAX_COUNT);
		cli_log_file_max_count += (2 << BSR_SETUP_LOG_FILE_MAX_COUNT);
		cli_log_file_max_count += (2 << BSR_META_LOG_FILE_MAX_COUNT);
	}

	*max = cli_log_file_max_count;

	return true;
}

// BSR-973
DWORD get_fast_sync()
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD fast_sync = 1;

#ifdef _WIN
	lResult = get_value_of_vflt(_T("use_fast_sync"), &fast_sync);
#else // _LIN
	// /etc/bsr.d/.use_fast_sync
	lResult = get_value_of_vflt(BSR_FAST_SYNC_REG, &fast_sync);
#endif
	if (ERROR_SUCCESS != lResult && ERROR_FILE_NOT_FOUND != lResult) {
		printf("failed to get fast sync settings (%d)\n", lResult);
		return lResult;
	}

	printf("current fast sync %s (%d)\n", fast_sync ? "enable" : "disable", fast_sync);

	return lResult;
}


// BSR-973
DWORD set_fast_sync(DWORD fast_sync)
{
	DWORD lResult = ERROR_SUCCESS;

#ifdef _WIN
	lResult = set_value_of_vflt(_T("use_fast_sync"), &fast_sync);
#else // _LIN
	// /etc/bsr.d/.use_fast_sync
	lResult = set_value_of_vflt(BSR_FAST_SYNC_REG, &fast_sync);
#endif
	if (ERROR_SUCCESS != lResult) {
		printf("fast sync setup failed.\n");
		return lResult;
	}

	printf("fast sync setup success.\n");
	return lResult;
}

// BSR-605 cli log maximum file count settings 
DWORD cli_set_log_file_max_count(int cli_type, int max)
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD cli_log_file_max_count = 0;
	DWORD adm_max, setup_max, meta_max;
#ifdef _WIN
	lResult = get_value_of_vflt(_T(BSR_CLI_LOG_FILE_MAX_COUT_VALUE_REG), &cli_log_file_max_count);
#else // _LIN
	// /etc/bsr.d/.cli_log_file_max_count
	lResult = get_value_of_vflt(BSR_CLI_LOG_FILE_MAXCNT_REG, &cli_log_file_max_count);
#endif
	if (lResult == (DWORD)ERROR_FILE_NOT_FOUND) {
		adm_max = setup_max = meta_max = 2;
	}
	else if (lResult != ERROR_SUCCESS) {
		printf("cli log file max count setup failed (%d)\n", lResult);
		return lResult;
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
	lResult = set_value_of_vflt(_T("cli_log_file_max_count"), &cli_log_file_max_count);
#else // _LIN
	// /etc/bsr.d/.cli_log_file_max_count
	lResult = set_value_of_vflt(BSR_CLI_LOG_FILE_MAXCNT_REG, &cli_log_file_max_count);
#endif
	if (ERROR_SUCCESS != lResult) {
		printf("cli log file max count setup failed (%d)\n", lResult);
	}

	return lResult;
}

// DW-1921
//Print log_level through the current registry value.
BOOLEAN get_log_level(int *sys_evtlog_lv, int *dbglog_lv)
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD logLevel = 0;

#ifdef _WIN
	lResult = get_value_of_vflt(_T("log_level"), &logLevel);
#else // _LIN
	// BSR-584 read /etc/bsr.d/.log_level
	lResult = get_value_of_vflt(BSR_LOG_LEVEL_REG, &logLevel);
#endif

	if (lResult == ERROR_FILE_NOT_FOUND) {
		// DW-1921
		//It is not an error that no key exists.Just set it to the default value.
		*sys_evtlog_lv = LOG_LV_DEFAULT_EVENTLOG;
		*dbglog_lv = LOG_LV_DEFAULT_DBG;
		return true;
	} else if (lResult != ERROR_SUCCESS)
		return false;

	*sys_evtlog_lv = (logLevel >> LOG_LV_BIT_POS_EVENTLOG) & LOG_LV_MASK;
	*dbglog_lv = (logLevel >> LOG_LV_BIT_POS_DBG) & LOG_LV_MASK;

	return true;
}

// BSR-1060
BOOLEAN get_handler_use()
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD use = 0;

#ifdef _WIN
	lResult = get_value_of_vflt(_T("handler_use"), &use);
#else // _LIN
	lResult = get_value_of_vflt(BSR_HANDLER_USE_REG, &use);
#endif

	if (lResult == ERROR_FILE_NOT_FOUND) {
		return false;
	}

	return use;
}

#ifdef _WIN
int get_handler_timeout()
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD timeout = 5; // BSR_TIMEOUT_DEF 

	lResult = get_value_of_vflt(_T("handler_timeout"), &timeout);

	if (lResult == ERROR_FILE_NOT_FOUND) {
		return timeout;
	}

	return timeout;
}
#endif

// BSR-654
BOOLEAN get_debug_log_enable_category(int *dbg_ctgr)
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD ctgr = 0;

#ifdef _WIN
	lResult = get_value_of_vflt(_T("debuglog_category"), &ctgr);
#else // _LIN
	// BSR-584 read /etc/bsr.d/.debuglog_category
	lResult = get_value_of_vflt(BSR_DEBUG_LOG_CATEGORY_REG, &ctgr);
#endif

	if (lResult == ERROR_FILE_NOT_FOUND) {
		*dbg_ctgr = DEBUG_LOG_OUT_PUT_CATEGORY_DEFAULT;
		return true;
	}
	else if (lResult != ERROR_SUCCESS)
		return false;

	*dbg_ctgr = ctgr;

	return true;
}

#ifdef _WIN
struct cb_ctx {
	PVOID cb_default_ctx;
	bool need_reboot;
	wchar_t err[255];
};

UINT queue_callback(PVOID Context, UINT Notification, UINT_PTR Param1, UINT_PTR Param2)
{
	struct cb_ctx *ctx = (struct cb_ctx *)Context;
	PFILEPATHS_W p;
	PSOURCE_MEDIA_W m;
	wchar_t path[255];

	switch (Notification)
	{
	case SPFILENOTIFY_RENAMEERROR:
		p = (PFILEPATHS_W)Param1;
		swprintf_s(ctx->err, L"Failed to reanme from %ws to %ws. err(%d)\n", p->Source, p->Target, p->Win32Error);
		return FILEOP_ABORT;
	case SPFILENOTIFY_COPYERROR:
		p = (PFILEPATHS_W)Param1;
		swprintf_s(ctx->err, L"Failed to copy from %ws to %ws. err(%d)\n", p->Source, p->Target, p->Win32Error);
		return FILEOP_ABORT;
	case SPFILENOTIFY_DELETEERROR:
		p = (PFILEPATHS_W)Param1;
		swprintf_s(ctx->err, L"Failed to delete %ws. err(%x)\n", p->Target, p->Win32Error);
		return FILEOP_SKIP;
	case SPFILENOTIFY_NEEDMEDIA:
		m = (PSOURCE_MEDIA_W)Param1;
		swprintf_s(path, L"%ws\\%ws", m->SourcePath, m->SourceFile);
		if (!PathFileExistsW(path)) {
			swprintf_s(ctx->err, L"The copy destination file(%ws) does not exist.\n", path);
			return FILEOP_ABORT;
		}
		return FILEOP_DOIT;
	case SPFILENOTIFY_FILEOPDELAYED:
		ctx->need_reboot = true;
		break;
	case SPFILENOTIFY_TARGETEXISTS:
	case SPFILENOTIFY_TARGETNEWER:
		return FILEOP_SKIP;
	case SPFILENOTIFY_STARTCOPY:
	case SPFILENOTIFY_ENDCOPY:
	case SPFILENOTIFY_STARTDELETE:
	case SPFILENOTIFY_ENDDELETE:
	default:
		return SetupDefaultQueueCallbackW(ctx->cb_default_ctx, Notification, Param1, Param2);
	}

	return 0;
}

// DW-2166 Run the driver install/uninstall via the inf file full path.
int driver_Install_Inf(wchar_t* session, char* fullPath)
{
	HANDLE handle;
	struct cb_ctx ctx;
	wchar_t service[32] = L"";
	wchar_t fullPath16[255] = L"";
	PSP_FILE_CALLBACK cb;

	memset(service, 0, sizeof(wchar_t) * 32);
	memset(fullPath16, 0, sizeof(wchar_t) * 255);
	memset(ctx.err, 0, sizeof(wchar_t) * 255);

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, fullPath, (int)strlen(fullPath), fullPath16, 255);

	// open inf file
	handle = SetupOpenInfFileW(fullPath16, 0, INF_STYLE_WIN4, 0);

	if (handle == NULL) {
		wprintf(L"Failed to open. error(%d)\n", GetLastError());
		return -1;
	}

	cb = (PSP_FILE_CALLBACK)queue_callback;

	ctx.cb_default_ctx = SetupInitDefaultQueueCallback(NULL);
	ctx.need_reboot = false;

	// install session
	if (!SetupInstallFromInfSectionW(NULL, handle, session, SPINST_ALL, 0, 0, SP_COPY_NEWER, cb, (PVOID)&ctx, 0, 0)) {
		SetupCloseInfFile(handle);
		wprintf(L"Failed to %ws. %ws, error(%d)\n", session, ctx.err, GetLastError());
		return -1;
	}

	swprintf_s(service, L"%ws.Services", session);

	// install service
	int res = SetupInstallServicesFromInfSectionW(handle, service, 0);
	if (!res) {
		SetupCloseInfFile(handle);
		wprintf(L"Failed to create service. error(%ld)\n", GetLastError());
		return -1;
	}

	if (res == ERROR_SUCCESS_REBOOT_REQUIRED)
		ctx.need_reboot = true;

	if (ctx.need_reboot) {
		// need reboot
		wprintf(L"Reboot is required to complete the driver installation.\n");
		return 1;
	}

	SetupCloseInfFile(handle);

	return 0;
}

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

#define BUFSIZE 1024
#define MD5LEN  16

int generating_md5(char* fullPath)
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[BUFSIZE];
	DWORD cbRead = 0;
	BYTE rgbHash[MD5LEN];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	wchar_t fullpath16[512];

	memset(fullpath16, 0, sizeof(wchar_t) * 512);

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, fullPath, (int)strlen(fullPath), fullpath16, 255);

	// Logic to check usage goes here.
	hFile = CreateFileW(fullpath16,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		printf("Error opening file %s\nError: %d\n", fullPath, dwStatus);
		return -1;
	}

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		return -1;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return -1;
	}

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			printf("CryptHashData failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return -1;
		}
	}

	if (!bResult)
	{
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return -1;
	}

	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			printf("%c%c", rgbDigits[rgbHash[i] >> 4],
				rgbDigits[rgbHash[i] & 0xf]);
		}
		printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
		return -1;
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	return 0;
}
#endif


UCHAR letter = 'C';
int verbose = 0;

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
		usage();
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
					usage();
			}
			else
				usage();

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
			usage();
	}

	// second argument indicates minimum logging level.
	(*index)++;
	if (*index < argc) {
		lml.nErrLvMin = atoi(argv[*index]);
	}
	else
		usage();

	return MVOL_SetMinimumLogLevel(&lml);
}

// BSR-1031
DWORD set_statuscmd_logging(DWORD logging)
{
	DWORD lResult = ERROR_SUCCESS;

#ifdef _WIN
	lResult = set_value_of_vflt(_T("statuscmd_logging"), &logging);
#else // _LIN
	// /etc/bsr.d/.statuscmd_logging
	lResult = set_value_of_vflt(BSR_STATUSCMD_LOGGING_REG, &logging);
#endif
	if (ERROR_SUCCESS != lResult) {
		printf("status cmd logging setup failed.\n");
		return lResult;
	}

	printf("status cmd logging setup success.\n");
	return lResult;
}

DWORD get_statuscmd_logging()
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD logging = 0;

#ifdef _WIN
	lResult = get_value_of_vflt(_T("statuscmd_logging"), &logging);
#else // _LIN
	// /etc/bsr.d/.statuscmd_logging
	lResult = get_value_of_vflt(BSR_STATUSCMD_LOGGING_REG, &logging);
#endif
	if (ERROR_SUCCESS != lResult && ERROR_FILE_NOT_FOUND != lResult) {
		printf("failed to get statuscmd_logging settings (%d)\n", lResult);
		return lResult;
	}

	printf("Logging status command to the CLI log : %s (%d)\n", logging ? "enable" : "disable", logging);

	return lResult;
}

// BSR-1031
int cmd_statuscmd_logging(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc) {
		if ((strcmp(argv[*index], "1") == 0) ||
			(strcmp(argv[*index], "0") == 0))
			return set_statuscmd_logging(atoi(argv[*index]));
		else usage();
	}
	else
		usage();

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
			usage();
	}

	(*index)++;
	if (*index < argc) {
		lmc.nMaxCount = atoi(argv[*index]);
	}
	else
		usage();

	return cli_set_log_file_max_count(lmc.nType, lmc.nMaxCount);
}

// BSR-579
int cmd_maxlogfile_cnt(int *index, int argc, char* argv[])
{
	(*index)++;
	// BSR-618
	if (*index >= argc)
		usage();

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
			usage();

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
		usage();

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

	// DW-2008
	if (get_log_level(&sys_evt_lv, &dbglog_lv)) {
		printf("Current log level.\n");
		printf("    system-lv : %s(%d)\n    debug-lv : %s(%d)\n",
			g_default_lv_str[sys_evt_lv], sys_evt_lv, g_default_lv_str[dbglog_lv], dbglog_lv);

		printf("\n");
		printf("The maximum size of cli log file is %dM.\n", BToM(CLI_LOG_FILE_MAX_SIZE));
		printf("Number of log files that can be saved.\n");

		// BSR-605
		if (get_cli_log_file_max_count(&cli_log_max_count)) {
			printf("    bsradm : %d\n", ((cli_log_max_count >> BSR_ADM_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK));
			printf("    bsrsetup : %d\n", ((cli_log_max_count >> BSR_SETUP_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK));
			printf("    bsrmeta : %d\n", ((cli_log_max_count >> BSR_META_LOG_FILE_MAX_COUNT) & BSR_LOG_MAX_FILE_COUNT_MASK));
		}
		else
			printf("Failed to get cli log file max count\n");
		printf("\n");
		printf("The maximum size of driver log file is %dM or %d log count.\n", BToM(BSR_LOG_SIZE), LOGBUF_MAXCNT);
		printf("Number of log files that can be saved.\n");

		// BSR-579
		if (get_log_file_max_count(&log_max_count))
			printf("    bsrdriver : %d\n", log_max_count);
		else
			printf("Failed to get log file max count\n");

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
			usage();
		}
		else {
			hInfo.timeout = timeout;
		}
	}
	else
		usage();

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
			usage();
		}
		else {
			if (use)
				hInfo.use = true;
		}
	}
	else
		usage();

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
		usage();
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
		usage();

	// Get oos search sector
	(*index)++;
	if (*index < argc)
		sector = argv[*index];
	else
		usage();

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
			usage();
		}
	}
	else
		usage();

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
		usage();

	// Get eventlog data to be written.
	(*index)++;
	if (*index < argc)
		loggingData = argv[*index];
	else
		usage();

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
		usage();

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
		usage();

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
		usage();

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
		usage();

	res = MVOL_DismountVolume(letter, force);

	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Failed MVOL_DismountVolume. Err=%u\n", res);
	}

	return res;
}

#define RUN_PROCESS_TIMEOUT 10000

// BSR-1051
DWORD RunProcess(char* command, char* workingDirectory, char **out)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char *appName = NULL;
	DWORD res = 0;
	HANDLE stdOutRd = INVALID_HANDLE_VALUE, stdOutWd = INVALID_HANDLE_VALUE;
	SECURITY_ATTRIBUTES saAttr;

	ZeroMemory(&saAttr, sizeof(saAttr));
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (out) {
		if (!CreatePipe(&stdOutRd, &stdOutWd, &saAttr, 0)) {
			res = GetLastError();
			fprintf(stderr, "CreatePipe faild: GetLastError %d\n", res);
			goto out;
		}

		if (!SetHandleInformation(stdOutRd, HANDLE_FLAG_INHERIT, 0)) {
			res = GetLastError();
			fprintf(stderr, "SetHandleInformation faild: GetLastError %d\n", res);
			goto out;
		}
		si.hStdOutput = stdOutWd;
	}

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;;
	si.wShowWindow = SW_HIDE;

	if (!CreateProcessA(appName,
		command,					// Command line
		NULL,							// Process handle not inheritable. 
		NULL,							// Thread handle not inheritable. 
		TRUE,							// Set handle inheritance to FALSE. 
		CREATE_NEW_CONSOLE,								// creation flags. 
		NULL,							// Use parent's environment block. 
		workingDirectory,			// Use parent's starting directory. 
		&si,							// Pointer to STARTUPINFO structure.
		&pi)							// Pointer to PROCESS_INFORMATION structure.
		) {
		res = GetLastError();
		fprintf(stderr, "CreateProcess faild: GetLastError %d\n", res);
		goto out;
	} else {
		if (pi.dwProcessId > 0) {
			res = WaitForSingleObject(pi.hProcess, RUN_PROCESS_TIMEOUT);
			if (res != WAIT_OBJECT_0) {
				if (res == WAIT_FAILED)
					res = GetLastError();
				fprintf(stderr, "CreateProcess WaitForSingleObject faild: Error %d\n", res);
				goto out_all;
			} else 
				res = 0;
		}
		if (stdOutRd != INVALID_HANDLE_VALUE && stdOutWd != INVALID_HANDLE_VALUE) {
			unsigned long dwRead;
			unsigned long avail;

			PeekNamedPipe(stdOutRd, *out, BUFSIZE, &dwRead, &avail, NULL);

			if (dwRead > 0) {
				*out = (char*)malloc(dwRead + 1);
				if (*out) {
					if (!ReadFile(stdOutRd, *out, BUFSIZE, &dwRead, NULL))
						res = ERROR_INVALID_DATA;
				} else
					res = ERROR_OUTOFMEMORY;
			} else
				res = ERROR_INVALID_DATA;
			
		}
	}

out_all:
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

out:
	if (stdOutRd != INVALID_HANDLE_VALUE)
		CloseHandle(stdOutRd);
	if (stdOutWd != INVALID_HANDLE_VALUE)
		CloseHandle(stdOutWd);

	return res;
}

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
	} else {
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
		usage();

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
		usage();
}

int cmd_driver_uninstall(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc) // BSR-1030
		return driver_Install_Inf(L"DefaultUninstall.NTamd64", argv[*index]);
	else
		usage();
}

int cmd_md5(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc)
		return generating_md5(argv[*index]);
	else
		usage();
}
#endif

int cmd_set_fast_sync(int *index, int argc, char* argv[])
{
	(*index)++;
	if (*index < argc)
		return set_fast_sync(atoi(argv[*index]));
	else
		usage();

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
		usage();

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
		usage();

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
		usage();

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
		usage();

	return 0;
}

int create_dir(char* path)
{
	char dirName[MAX_PATH] = { 0, };
	char* pDir = dirName;
	DWORD ret = ERROR_SUCCESS;
#ifdef _WIN
	char* p = path;

	while(*p) {
		// create sub dir
		if ('\\' == *p) {
			if (':' != *(p-1)) {
				if (!CreateDirectoryA(dirName, NULL)) {
					ret = GetLastError();
					if (ret != ERROR_ALREADY_EXISTS) {
						fprintf(stderr, "LOG_PATH_ERROR: %s: Failed create %s. Err=%u\n",
							__FUNCTION__, dirName, ret);
						return ret;
					}
				}
			}
		}
				
		*pDir++ = *p++;
		*pDir = '\0';
	}

	// create log dir
	if (!CreateDirectoryA(dirName, NULL)) {
		ret = GetLastError();
		if (ret == ERROR_ALREADY_EXISTS) {
			ret = ERROR_SUCCESS;
		} else {
			fprintf(stderr, "LOG_PATH_ERROR: %s: Failed create %s. Err=%u\n",
				__FUNCTION__, dirName, ret);
		}
	}
#else
	strcpy(dirName, path);
	dirName[MAX_PATH-1] = '\0';
	pDir++;
	while(*pDir) {
		// create sub dir
		if ('/' == *pDir) {
			*pDir = '\0';
			ret = mkdir(dirName, 0777);
			if (ret != 0 && errno != EEXIST) {
				fprintf(stderr, "LOG_PATH_ERROR: %s: Failed create %s. Err=%d\n", __FUNCTION__, dirName, ret);
				return ret;
			}
			*pDir = '/';
		}
		pDir++;
	}
	// create log dir
	ret = mkdir(dirName, 0777);
	if (ret != 0) {
		if (errno == EEXIST)
			ret = ERROR_SUCCESS;
		else
			fprintf(stderr, "LOG_PATH_ERROR: %s: Failed create %s. Err=%d\n", __FUNCTION__, dirName, ret);
	}
#endif		

	return ret;
}

// BSR-1112
int cmd_set_log_path(int *index, int argc, char* argv[])
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	HKEY hKey = NULL;
	TCHAR logPath[MAX_PATH] = { 0, };
#else // _LIN
	FILE *fp;
#endif
	char *newPath;
	char fullPath[MAX_PATH] = { 0, };
	DWORD retVal = ERROR_SUCCESS;

	(*index)++;

	if (*index < argc) {
#ifdef _WIN
		char *ptr;
		newPath = strtok_s(argv[*index], "\"", &ptr);
#else
		newPath = argv[*index];
#endif
	}
	else
		usage();
	
#ifdef _WIN
	// create log dir with perfmon dir
	sprintf_s(fullPath, "%s\\perfmon", newPath);
	retVal = create_dir(fullPath);
	if (retVal != ERROR_SUCCESS)
		return retVal;

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, newPath, (int)strlen(newPath), logPath, MAX_PATH);

	retVal = RegOpenKeyEx(HKEY_LOCAL_MACHINE, gBsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != retVal) {
		fprintf(stderr, "LOG_PATH_ERROR: %s: Failed RegOpenKeyEx %s. Err=%u\n",
				__FUNCTION__, gBsrRegistry, retVal);
		return retVal;
	}

	retVal = RegSetValueEx(hKey, _T("log_path"), 0, REG_SZ, (PBYTE)logPath, 
					(DWORD)(_tcslen(logPath) + 1) * sizeof(TCHAR));
	RegCloseKey(hKey);
#else // _LIN
	// create log dir with perfmon dir
	sprintf(fullPath, "%s/perfmon", newPath);
	retVal = create_dir(fullPath);
	if (retVal != 0)
		return retVal;

	// write /etc/bsr.d/.log_path
	fp = fopen(BSR_LOG_PATH_REG, "w");
	if (fp != NULL) {
		fprintf(fp, "%s", newPath);
		fclose(fp);
	} else {
		retVal = GetLastError();
		fprintf(stderr, "LOG_PATH_ERROR: %s: Failed open %s file. Err=%u\n",
				__FUNCTION__, BSR_LOG_PATH_REG, retVal);
		return retVal;
	}

#endif

	return MVOL_BsrLogPathChange();
}

// BSR-1112
int cmd_get_log_path(int *index, int argc, char* argv[])
{
#ifdef _WIN
	DWORD lResult = ERROR_SUCCESS;
	HKEY hKey = NULL;
	DWORD type = REG_SZ;
	DWORD size = MAX_PATH;	
	TCHAR buf[MAX_PATH] = { 0, };
	
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, gBsrRegistry, 0, KEY_ALL_ACCESS, &hKey);
	if (ERROR_SUCCESS != lResult) {
		return lResult;
	}

	lResult = RegQueryValueEx(hKey, _T("log_path"), NULL, &type, (PBYTE)&buf, &size);
	RegCloseKey(hKey);
	if (ERROR_SUCCESS == lResult) {
		printf("%ws\n", buf);
	}
	else {
		TCHAR bsr_path[MAX_PATH] = {0,};
		size_t path_size;
		errno_t result;
		result = _wgetenv_s(&path_size, bsr_path, MAX_PATH, L"BSR_PATH");
		if (result) {
			printf("c:\\Program Files\\bsr\\log\\");
		} else {
			wcsncpy_s(buf, bsr_path, wcslen(bsr_path) - wcslen(L"bin"));
			printf("%ws\\log", buf);
		}
	}
#else // _LIN
	FILE *fp;
	char buf[MAX_PATH] = { 0, };

	fp = fopen(BSR_LOG_PATH_REG, "r");

	if (fp == NULL) {
		printf("%s\n", BSR_LOG_FILE_PATH);
		return 0;
	}

	if (fgets(buf, sizeof(buf), fp) != NULL)
		printf("%s\n", buf);
	else 
		printf("%s\n", BSR_LOG_FILE_PATH);
	fclose(fp);
#endif

	return 0;
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
	// BSR-1052 added /get_log command again
	// BSR-973
	{ "/get_log", cmd_get_log, "{save log file name}\n", "", "\"bsrsave.txt\" or \"C:\\Program Files\\bsr\\log\\bsrsave.txt\"", false },
	{ "/minlog_lv", cmd_minlog_lv, "{log type} {log level}", "", "\"dbg 7\" or \"sys 7\"", false },
	{ "/statuscmd_logging", cmd_statuscmd_logging, "{status cmd logging}", "", "\"1\" or \"0\"", false },
	{ "/climaxlogfile_cnt", cmd_climaxlogfile_cnt, "{file type} {max file count}", "", "\"adm 10\" or \"setup 10\" or \"meta 10\"", false },
	{ "/maxlogfile_cnt", cmd_maxlogfile_cnt, "{max file count}", "", "10" },
	{ "/dbglog_ctgr", cmd_dbglog_ctgr, "{category use} {category}", "", "\"enable VOLUME SOKET ETC\" or \"disable VOLUME PROTOCOL\"", false },
	{ "/get_log_info", cmd_get_log_info, "", "", "", false },
	{ "/handler_use", cmd_handler_use, "{handler use}", "", "\"1\" or \"0\"", false },
	{ "/get_handler_info", cmd_get_handler_info, "", "", "", false },
#ifdef _WIN
	// BSR-1060
	{ "/handler_timeout", cmd_handler_timeout, "{handler timeout(seconds)}", "", "1", false },
#ifdef _DEBUG_OOS
	{ "/convert_oos_log", cmd_convert_oos_log, "{source file path}", "", "C:\\Program Files\\bsr\\log", false },
	{ "/serch_oos_log", cmd_serch_oos_log, "{source file path} {sector}", "", "\"C:\\Program Files\\bsr\\log\" 10240000", false },
#endif
	{ "/bsrlock_use", cmd_bsrlock_use, "{bsrlock use}", "", "\"1\" or \"0\"", false },
	{ "/write_log", cmd_write_log, "{provider name} {logging data}", "", "bsr data", true },
	{ "/get_volume_size", cmd_get_volume_size, "", "", "", false },
	{ "/delaydack_enable", cmd_delaydack_enable, "{address}", "", "10.10.1.10", false },
	{ "/nodelayedack", cmd_nodelayedack, "{address}", "", "10.10.1.10", false },
	{ "/letter", cmd_letter, "{letter}", "", "E", false },
	{ "/l", cmd_letter, "{letter}", "", "E", false },
	{ "/proc/bsr", cmd_proc, "", "", "", false },
	{ "/status", cmd_status, "", "", "", false },
	{ "/s", cmd_status, "", "", "", false },
	{ "/dismount", cmd_dismount, "{letter}", "", "E", false },
	// BSR-1051
	{ "/release_vol", cmd_release_vol, "{resource name} {letter}", "", "\"r0 E\", \"--force r0 E\"", false },
	{ "/disk_error", cmd_disk_error, "{error flag} {error type} {error count}", "", "1 2 100", false },
	{ "/bsrlock_status", cmd_bsrlock_status, "", "", "", false },
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
	{ "/hold_state", cmd_bsr_hold_state, "type state", "only supports turning on and off congestion", "2 22 or 0 0", false },
	// BSR-1039
	{ "/fake_al_used", cmd_bsr_fake_al_used, "{fake al used count}", "", "6001", false },
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

static void usage()
{
	int i;
	printf("usage: bsrcon cmds options \n\n"
		"cmds:\n");

	for (i = 0; i < (int)ARRAY_SIZE(commands); i++) {
		if (commands[i].hide)
			continue;
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
		usage();

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

