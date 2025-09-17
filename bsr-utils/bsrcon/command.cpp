#include "command.h"

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
#define MAX_VALUE_NAME 16
#define MAX_VOLUME_GUID 256

DWORD delete_volume_reg(TCHAR letter)
{
	HKEY hKey = NULL;
	DWORD dwIndex = 0;

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
BOOLEAN get_engine_log_file_max_count(int *max)
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
DWORD set_cli_log_file_max_count(int cli_type, int max)
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
	}
	else if (lResult != ERROR_SUCCESS)
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

	return (use == 1) ? true : false;
}

#ifdef _WIN
int get_handler_timeout()
{
	DWORD lResult = ERROR_SUCCESS;
	DWORD timeout = BSR_TIMEOUT_DEF; 

	lResult = get_value_of_vflt(_T("handler_timeout"), &timeout);

	if (lResult == ERROR_FILE_NOT_FOUND) {
		return timeout * 100;
	}

	if(timeout < BSR_HANDLER_TIMEOUT_MIN) // BSR-1564
			timeout = BSR_HANDLER_TIMEOUT_MIN;
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
		swprintf_s(ctx->err, 255, L"Failed to reanme from %ws to %ws. err(%d)\n", p->Source, p->Target, p->Win32Error);
		return FILEOP_ABORT;
	case SPFILENOTIFY_COPYERROR:
		p = (PFILEPATHS_W)Param1;
		swprintf_s(ctx->err, 255, L"Failed to copy from %ws to %ws. err(%d)\n", p->Source, p->Target, p->Win32Error);
		return FILEOP_ABORT;
	case SPFILENOTIFY_DELETEERROR:
		p = (PFILEPATHS_W)Param1;
		swprintf_s(ctx->err, 255, L"Failed to delete %ws. err(%x)\n", p->Target, p->Win32Error);
		return FILEOP_SKIP;
	case SPFILENOTIFY_NEEDMEDIA:
		m = (PSOURCE_MEDIA_W)Param1;
		swprintf_s(path, 255, L"%ws\\%ws", m->SourcePath, m->SourceFile);
		if (!PathFileExistsW(path)) {
			swprintf_s(ctx->err, 255, L"The copy destination file(%ws) does not exist.\n", path);
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
	// BSR-1183 The maximum size of the service is 32("DefaultInstall.NTamd64.Services") or 33("DefaultUninstall.NTamd64.Services").
	wchar_t service[64] = L"";
	wchar_t fullPath16[255] = L"";
	PSP_FILE_CALLBACK cb;

	memset(service, 0, sizeof(wchar_t) * 64);
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

	swprintf_s(service, 64, L"%ws.Services", session);

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
			fprintf(stderr, "CreatePipe failed: GetLastError %d\n", res);
			goto out;
		}

		if (!SetHandleInformation(stdOutRd, HANDLE_FLAG_INHERIT, 0)) {
			res = GetLastError();
			fprintf(stderr, "SetHandleInformation failed: GetLastError %d\n", res);
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
		fprintf(stderr, "CreateProcess failed: GetLastError %d\n", res);
		goto out;
	}
	else {
		if (pi.dwProcessId > 0) {
			res = WaitForSingleObject(pi.hProcess, RUN_PROCESS_TIMEOUT);
			if (res != WAIT_OBJECT_0) {
				if (res == WAIT_FAILED)
					res = GetLastError();
				fprintf(stderr, "CreateProcess WaitForSingleObject failed: Error %d\n", res);
				goto out_all;
			}
			else
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
				}
				else
					res = ERROR_OUTOFMEMORY;
			}
			else
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
#endif

int create_dir(char* path)
{
	char dirName[MAX_PATH] = { 0, };
	char* pDir = dirName;
	DWORD ret = ERROR_SUCCESS;
#ifdef _WIN
	char* p = path;

	while (*p) {
		// create sub dir
		if (('\\' == *p) && (':' != *(p - 1))) {
			if (!CreateDirectoryA(dirName, NULL)) {
				ret = GetLastError();
				if (ret != ERROR_ALREADY_EXISTS) {
					fprintf(stderr, "LOG_PATH_ERROR: %s: Failed create %s. Err=%u\n",
						__FUNCTION__, dirName, ret);
					return ret;
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
		}
		else {
			fprintf(stderr, "LOG_PATH_ERROR: %s: Failed create %s. Err=%u\n",
				__FUNCTION__, dirName, ret);
		}
	} else
		ret = ERROR_SUCCESS;
#else
	strcpy(dirName, path);
	dirName[MAX_PATH - 1] = '\0';
	pDir++;
	while (*pDir) {
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


DWORD set_log_path(char *newPath) 
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	HKEY hKey = NULL;
	TCHAR logPath[MAX_PATH] = { 0, };
#else // _LIN
	FILE *fp;
#endif
	char fullPath[MAX_PATH] = { 0, };
	DWORD retVal = ERROR_SUCCESS;
#ifdef _WIN
	// BSR-1270
	// create log dir
	retVal = create_dir(newPath);
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
	// BSR-1270
	// create log dir 
	retVal = create_dir(newPath);
	if (retVal != 0)
		return retVal;

	// write /etc/bsr.d/.log_path
	fp = fopen(BSR_LOG_PATH_REG, "w");
	if (fp != NULL) {
		fprintf(fp, "%s", newPath);
		fclose(fp);
	}
	else {
		retVal = GetLastError();
		fprintf(stderr, "LOG_PATH_ERROR: %s: Failed open %s file. Err=%u\n",
			__FUNCTION__, BSR_LOG_PATH_REG, retVal);
		return retVal;
	}

#endif

	return MVOL_BsrLogPathChange();
}


DWORD get_log_path()
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
		TCHAR bsr_path[MAX_PATH] = { 0, };
		size_t path_size;
		errno_t result;
		result = _wgetenv_s(&path_size, bsr_path, MAX_PATH, L"BSR_PATH");
		if (result || (bsr_path == NULL) || !wcslen(bsr_path)) {
			printf("c:\\Program Files\\bsr\\log\\\n");
		}
		else {
			wcsncpy_s(buf, bsr_path, wcslen(bsr_path) - wcslen(L"bin"));
			printf("%wslog\n", buf);
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