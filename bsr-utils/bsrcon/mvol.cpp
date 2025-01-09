/*
	Copyright(C) 2007-2016, ManTechnology Co., LTD.
	Copyright(C) 2007-2016, bsr@mantech.co.kr

	Windows BSR is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	Windows BSR is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Windows BSR; see the file COPYING. If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifdef _WIN
#include <windows.h>
#include <winioctl.h>
#include <tchar.h>
#include <strsafe.h>
#include <stdio.h>
#include "log_manager.h"
#include "../../bsr-platform/windows/bsrsvc/bsrService.h"
#include "../../bsr-platform/windows/bsrfsflt/bsrfsflt_comm.h"
#else // _LIN
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#endif
#include "mvol.h"

#ifdef _WIN
#ifdef _DEBUG_OOS
#include "oos_trace.h"
#endif
#endif



#ifdef _WIN
HANDLE
OpenDevice( PCHAR devicename )
{
    HANDLE		handle = INVALID_HANDLE_VALUE;

    handle = CreateFileA( devicename, GENERIC_READ, FILE_SHARE_READ, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if( handle == INVALID_HANDLE_VALUE ) {
        printf("LOG_ERROR: OpenDevice: cannot open %s\n", devicename);	
    }

    return handle;
}

DWORD
MVOL_GetVolumeInfo( CHAR DriveLetter, PMVOL_VOLUME_INFO pVolumeInfo )
{
    HANDLE		driveHandle = INVALID_HANDLE_VALUE;
    DWORD		res = ERROR_SUCCESS;
    ULONG		iolen;
    ULONG		len;
    CHAR		letter[] = "\\\\.\\ :";

    if( pVolumeInfo == NULL ) {
        printf("LOG_ERROR: MVOL_GetVolumeInfo: invalid parameter\n");
        return ERROR_INVALID_PARAMETER;
    }

    letter[4] = DriveLetter;
    driveHandle = CreateFileA( letter, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if( driveHandle == INVALID_HANDLE_VALUE ) {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_GetVolumeInfo: cannot open Drive (%c:), err=%u\n",
            DriveLetter, res);
        return res;
    }

    len = sizeof(MVOL_VOLUME_INFO);
    if( !DeviceIoControl(driveHandle, IOCTL_MVOL_GET_VOLUME_INFO,
        pVolumeInfo, len, pVolumeInfo, len, &iolen, NULL) )
    {
        res = GetLastError();
        printf("LOG_ERROR: MVOL_GetVolumeInfo: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if( driveHandle != INVALID_HANDLE_VALUE )
        CloseHandle(driveHandle);

    return res;
}

DWORD
MVOL_GetVolumesInfo(BOOLEAN verbose)
{
    DWORD res = ERROR_SUCCESS;

	HANDLE handle = OpenDevice(MVOL_DEVICE);
	if (INVALID_HANDLE_VALUE == handle)	{
		res = GetLastError();
		fprintf(stderr, "%s: cannot open root device, err=%u\n", __FUNCTION__, res);
		return res;
	}

	DWORD mem_size = 1 << 13;
	DWORD dwReturned;
	PVOID buffer = malloc(mem_size);
	memset(buffer, 0, mem_size);

	while (!DeviceIoControl(handle, IOCTL_MVOL_GET_VOLUMES_INFO, NULL, 0, buffer, mem_size, &dwReturned, NULL)) {
		res = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == res) {
			mem_size <<= 1;
			free(buffer);
			buffer = malloc(mem_size);
			memset(buffer, 0, mem_size);
		} else {
			fprintf(stderr, "%s: ioctl err. GetLastError(%d)\n", __FUNCTION__, res);
			goto out;
		}
	}

	res = ERROR_SUCCESS;
	int count = dwReturned / sizeof(BSR_VOLUME_ENTRY);
	//printf("size(%d) count(%d) sizeof(BSR_VOLUME_ENTRY)(%d)\n", dwReturned, count, sizeof(BSR_VOLUME_ENTRY));

	for (int i = 0; i < count; ++i) {
		PBSR_VOLUME_ENTRY pEntry = ((PBSR_VOLUME_ENTRY)buffer) + i;
		printf("--------------------------------------------------------------------------------------\n");
		printf( "   Physical Device Name| %ws\n"
				"                  Minor| %d\n"
				"            Mount Point| %ws\n"
				"     Replication Volume| %d\n"
				"    Disk Partition Size| %llu bytes (%llu kibytes)\n"
				"       Replication Size| %llu bytes (%llu kibytes)\n"
#ifndef _WIN_MULTIVOL_THREAD
				"           ThreadActive| %d\n"
				"             ThreadExit| %d\n"
#endif
				"            Volume GUID| %ws\n",
				pEntry->PhysicalDeviceName,
				pEntry->Minor,
				pEntry->MountPoint,
				pEntry->ExtensionActive,
				pEntry->Size, (pEntry->Size/1024),
				pEntry->AgreedSize, (pEntry->AgreedSize/1024),
#ifndef _WIN_MULTIVOL_THREAD
				pEntry->ThreadActive,
				pEntry->ThreadExit,
#endif
				pEntry->VolumeGuid
		);
		printf("--------------------------------------------------------------------------------------\n\n");

	}
out:
	if (INVALID_HANDLE_VALUE != handle) {
		CloseHandle(handle);
	}

	if (buffer) {
		free(buffer);
	}

	return res;
}

DWORD
MVOL_GetVolumeSize( PWCHAR PhysicalVolume, PLARGE_INTEGER pVolumeSize )
{
    HANDLE			handle = INVALID_HANDLE_VALUE;
    DWORD			res = ERROR_SUCCESS;
    ULONG			iolen;
    ULONG			len;
    MVOL_VOLUME_INFO	volumeInfo = {0,};

    if( PhysicalVolume == NULL || pVolumeSize == NULL ) {
        printf("LOG_ERROR: MVOL_GetVolumeSize: invalid parameter\n");
        return ERROR_INVALID_PARAMETER;
    }

    if( wcslen(PhysicalVolume) > MAXDEVICENAME ) {
        printf("LOG_ERROR: MVOL_GetVolumeSize: invalid parameter\n");
        return ERROR_INVALID_PARAMETER;
    }

    handle = OpenDevice( MVOL_DEVICE );
    if( handle == INVALID_HANDLE_VALUE ) {
        res = GetLastError();
        printf("MVOL_GetVolumeSize: cannot open root device, err=%u\n", res);
        return res;
    }

    wcscpy_s( volumeInfo.PhysicalDeviceName, PhysicalVolume );
    len = sizeof(MVOL_VOLUME_INFO);
    if( !DeviceIoControl(handle, IOCTL_MVOL_GET_VOLUME_SIZE,
        &volumeInfo, len, pVolumeSize, sizeof(LARGE_INTEGER), &iolen, NULL) )
    {
        res = GetLastError();
        printf("MVOL_GetVolumeSize: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if( handle != INVALID_HANDLE_VALUE )
        CloseHandle(handle);

    return res;
}

DWORD MVOL_GetStatus( PMVOL_VOLUME_INFO VolumeInfo )
{
    HANDLE      hDevice = INVALID_HANDLE_VALUE;
    DWORD       retVal = ERROR_SUCCESS;
    DWORD       dwReturned = 0;
    BOOL        ret = FALSE;

    if( VolumeInfo == NULL ) {
        fprintf( stderr, "LOG_ERROR: %s: Invalid parameter\n", __FUNCTION__ );
        return ERROR_INVALID_PARAMETER;
    }

    hDevice = OpenDevice( MVOL_DEVICE );
    if( hDevice == INVALID_HANDLE_VALUE ) {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed open bsr. Err=%u\n",
            __FUNCTION__, retVal );
        return retVal;
    }

    ret = DeviceIoControl( hDevice, IOCTL_MVOL_GET_PROC_BSR,
        NULL, 0, VolumeInfo, sizeof(MVOL_VOLUME_INFO), &dwReturned, NULL );
    if( ret == FALSE ) {
        retVal = GetLastError();
        fprintf( stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_GET_PROC_BSR. Err=%u\n",
            __FUNCTION__, retVal );
    }

    if( hDevice != INVALID_HANDLE_VALUE )   CloseHandle( hDevice );
    return retVal;
}

DWORD MVOL_SetDelayedAck(CHAR *addr, CHAR *arg)
{   
    DWORD       retVal = ERROR_SUCCESS;
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi;
    
    WCHAR systemDirPath[MAX_PATH];
    WCHAR appName[MAX_PATH];
    WCHAR cmd[MAX_PATH];

    GetSystemDirectory(systemDirPath, sizeof(systemDirPath) / sizeof(WCHAR));
    swprintf_s(appName, MAX_PATH, L"%s\\cmd.exe", systemDirPath);
    swprintf_s(cmd, MAX_PATH, L"/C delayedack.bat %hs %hs %hs", arg, addr, "1");

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    if (!CreateProcess(appName, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        retVal = GetLastError();
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return retVal;
}

DWORD
MVOL_set_ioctl(PWCHAR PhysicalVolume, DWORD code, MVOL_VOLUME_INFO *pVolumeInfo)
{
    HANDLE			handle = INVALID_HANDLE_VALUE;
    DWORD			res = ERROR_SUCCESS;
    ULONG			iolen;
    ULONG			len;
    MVOL_VOLUME_INFO	volumeInfo = {0,};

    if (PhysicalVolume == NULL) {
        printf("LOG_ERROR: MVOL_set_ioctl: invalid parameter\n");
        return ERROR_INVALID_PARAMETER;
    }

    if (wcslen(PhysicalVolume) > MAXDEVICENAME) {
        printf("LOG_ERROR: MVOL_set_ioctl: invalid parameter\n");
        return ERROR_INVALID_PARAMETER;
    }

    handle = OpenDevice(MVOL_DEVICE);
    if (handle == INVALID_HANDLE_VALUE) {
        res = GetLastError();
        printf("MVOL_set_ioctl: cannot open root device, err=%u\n", res);
        return res;
    }

    volumeInfo = *pVolumeInfo;
    wcscpy_s(volumeInfo.PhysicalDeviceName, PhysicalVolume);
    len = sizeof(MVOL_VOLUME_INFO);
    if (!DeviceIoControl(handle, code,
        &volumeInfo, len, pVolumeInfo, sizeof(MVOL_VOLUME_INFO), &iolen, NULL))
    {
        res = GetLastError();
        printf("MVOL_set_ioctl: ioctl err=%d\n", res);
        goto out;
    }

    res = ERROR_SUCCESS;
out:
    if (handle != INVALID_HANDLE_VALUE)
        CloseHandle(handle);

    return res;
}


BOOL LockVolume(HANDLE handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

BOOL UnlockVolume(HANDLE handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(handle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

BOOL IsVolumeMounted(HANDLE handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(handle, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

BOOL Dismount(HANDLE handle)
{
    DWORD dwBytesReturned;
    return DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
}

DWORD MVOL_MountVolume(char drive_letter)
{
    HANDLE			hDrive = INVALID_HANDLE_VALUE;
    char            letter[] = "\\\\.\\ :";
    DWORD			retVal = ERROR_SUCCESS;
    DWORD           dwReturned = 0;
	char			MsgBuff[MAX_PATH] = { 0, };
    BOOL            ok = FALSE;

    letter[4] = drive_letter;
    hDrive = CreateFileA(letter, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, 0, NULL);

    if (INVALID_HANDLE_VALUE == hDrive) {
        retVal = GetLastError();
        fprintf(stderr, "%s: Failed open %c: drive. Error Code=%u\n",
            __FUNCTION__, drive_letter, retVal);
        return retVal;
    }

    ok = DeviceIoControl(hDrive, IOCTL_MVOL_MOUNT_VOLUME,
		NULL, 0, MsgBuff, MAX_PATH, &dwReturned, NULL);
    if (!ok) {
        retVal = GetLastError();
        fprintf(stderr, "%s: Failed IOCTL_MVOL_MOUNT_VOLUME. ErrorCode(%u)\n",
            __FUNCTION__, retVal);
        goto out;
    }

	if (dwReturned) {
		fprintf(stderr, MsgBuff);
		retVal = 1;
		goto out;
	}
	
    retVal = ERROR_SUCCESS;
out:
    if (INVALID_HANDLE_VALUE != hDrive) {
        CloseHandle(hDrive);
    }

    return retVal;
}

DWORD MVOL_DismountVolume(CHAR DriveLetter, int Force)
{
    HANDLE      handle = NULL;
    CHAR        letter[] = "\\\\.\\ :";

    letter[4] = DriveLetter;
    
    __try
    {
        handle = CreateFileA(letter, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        
        if (INVALID_HANDLE_VALUE == handle) {
            DWORD dwErr = GetLastError();
            if (ERROR_FILE_NOT_FOUND != dwErr) {
                printf("LOG_ERROR: Failed to create vol(%S)'s handle. GetLastError(0x%x)\n"
                    , letter, GetLastError());
            }

            return GetLastError();
        }

        if (!IsVolumeMounted(handle)) {
            printf("LOG_ERROR: %c: is already dismounted\n", DriveLetter);
            return ERROR_SUCCESS;
        }
         
        if (!Force) {
            if (!LockVolume(handle)) {
                printf("LOG_ERROR: %c: in use\n", DriveLetter);
                return GetLastError();
            }
        }
        
        
        if (!Dismount(handle)) {
            printf("LOG_ERROR: FSCTL_DISMOUNT_VOLUME fail. GetLastError(%d)\n", GetLastError());
            return GetLastError();
        }

        if (!Force) {
            if (!UnlockVolume(handle)) {
                printf("LOG_ERROR: FSCTL_UNLOCK_VOLUME fail. GetLastError(%d)\n", GetLastError());
                return GetLastError();
            }
        }


        if (IsVolumeMounted(handle)) {
            int duration = 10000, delay = 500;
            int i, count = duration / delay;
            for (i = 0; i < count; ++i) {
                Sleep(delay);
                printf("LOG_ERROR: vol(%s) is not dismounted yet. %d count delay. GetLastError(0x%x)\n", letter, i, GetLastError());
                if (!IsVolumeMounted(handle)) {
                    return ERROR_SUCCESS;
                }
            }

            return GetLastError();
        }
    }
    __finally
    {
        if (handle) {
            CloseHandle(handle);
        }
    }
	printf("%c: Volume Dismount Success\n", DriveLetter);
    return ERROR_SUCCESS;
}

DWORD CreateLogFromEventLog(LPCSTR pszProviderName)
{
	HANDLE hEventLog = NULL;
	DWORD dwStatus = ERROR_SUCCESS;
	DWORD dwBytesToRead = 0;
	DWORD dwBytesRead = 0;
	DWORD dwMinBytesToRead = 0;
	PBYTE pBuffer = NULL;
	PBYTE pTemp = NULL;
	TCHAR tszProviderName[MAX_PATH];
	TCHAR szLogFilePath[MAX_PATH] = _T("");
	HANDLE hLogFile = INVALID_HANDLE_VALUE;
		

#ifdef _UNICODE
	if (0 == MultiByteToWideChar(CP_ACP, 0, (LPSTR)pszProviderName, -1, tszProviderName, MAX_PATH)) {
		dwStatus = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwStatus);
		goto cleanup;
	}
#else
	strcpy(tszProviderName, pszProviderName);
#endif

	_tcscat_s(tszProviderName, MAX_PATH, LOG_FILE_EXT);

	// Get log file full path( [current process path]\[provider name].log )
	dwStatus = GetCurrentFilePath(tszProviderName, szLogFilePath);
	if (ERROR_SUCCESS != dwStatus) {
		_tprintf(_T("could not get log file path, err : %d\n"), dwStatus);
		return dwStatus;
	}

	// Create log file and overwrite if exists.
	hLogFile = CreateFile(szLogFilePath, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hLogFile) {
		dwStatus = GetLastError();
		_tprintf(_T("could not create file, err : %d\n"), dwStatus);
		return dwStatus;
	}
	
	// Provider name must exist as a subkey of Application.
	hEventLog = OpenEventLog(NULL, tszProviderName);
	if (NULL == hEventLog) {
		dwStatus = GetLastError();
		_tprintf(_T("could not open event log, err : %d\n"), dwStatus);
		goto cleanup;
	}

	// Buffer size will be increased if not enough.
	dwBytesToRead = MAX_RECORD_BUFFER_SIZE;
	pBuffer = (PBYTE)malloc(dwBytesToRead);
	if (NULL == pBuffer) {
		_tprintf(_T("allocate memory for record buffer failed\n"));
		dwStatus = ERROR_NOT_ENOUGH_MEMORY;
		goto cleanup;
	}

	while (ERROR_SUCCESS == dwStatus) {
		// read event log in chronological(old -> new) order.
		if (!ReadEventLog(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ, 0, pBuffer, dwBytesToRead, &dwBytesRead, &dwMinBytesToRead)) {
			dwStatus = GetLastError();

			if (ERROR_INSUFFICIENT_BUFFER == dwStatus) {
				dwStatus = ERROR_SUCCESS;

				// Increase buffer size and re-try it.
				pTemp = (PBYTE)realloc(pBuffer, dwMinBytesToRead);
				if (NULL == pTemp) {
					_tprintf(_T("reallocate memory(%d bytes) for record buffer failed\n"), dwMinBytesToRead);
					goto cleanup;
				}

				pBuffer = pTemp;
				dwBytesToRead = dwMinBytesToRead;
			}
			else {
				if (ERROR_HANDLE_EOF != dwStatus) {
					_tprintf(_T("ReadEventLog failed, err : %d\n"), dwStatus);
				}
				else {
					// done.
					dwStatus = ERROR_SUCCESS;					
				}
					goto cleanup;
			}
		}
		else {
			dwStatus = WriteLogWithRecordBuf(hLogFile, tszProviderName, pBuffer, dwBytesRead);

			if (ERROR_SUCCESS != dwStatus) {
				_tprintf(_T("Write Log Failed, err : %d\n"), dwStatus);
			}
		}
	}
	
cleanup:

	if (INVALID_HANDLE_VALUE != hLogFile) {
		CloseHandle(hLogFile);
		hLogFile = INVALID_HANDLE_VALUE;
	}

	if (NULL != hEventLog) {
		CloseEventLog(hEventLog);
		hEventLog = NULL;
	}

	if (NULL != pBuffer) {
		free(pBuffer);
		pBuffer = NULL;
	}

	return dwStatus;
}

DWORD WriteLogWithRecordBuf(HANDLE hLogFile, LPCTSTR pszProviderName, PBYTE pBuffer, DWORD dwBytesRead)
{
	DWORD dwStatus = ERROR_SUCCESS;
	PBYTE pRecord = pBuffer;
	PBYTE pEndOfRecords = pBuffer + dwBytesRead;	
	
	while (pRecord < pEndOfRecords) {
		// Write event log data only when provider name matches.
		if (0 == _tcsicmp(pszProviderName, (LPCTSTR)(pRecord + sizeof(EVENTLOGRECORD)))) {
			// Some data doesn't have data length if writer didn't provide data size.
			if (((PEVENTLOGRECORD)pRecord)->DataLength > 0) {
				PBYTE pData = NULL;
				TCHAR szTimeStamp[MAX_TIMESTAMP_LEN] = _T("");

				// Get time string (format : mm/dd/yyyy hh:mm:ss )
				GetTimestamp(((PEVENTLOGRECORD)pRecord)->TimeGenerated, szTimeStamp);

				pData = (PBYTE)malloc(((PEVENTLOGRECORD)pRecord)->DataLength);
				if (NULL == pData) {
					_tprintf(_T("malloc failed\n"));
					dwStatus = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}

				memcpy(pData, (PBYTE)(pRecord + ((PEVENTLOGRECORD)pRecord)->DataOffset), ((PEVENTLOGRECORD)pRecord)->DataLength);
				
				dwStatus = WriteLogToFile(hLogFile, szTimeStamp, pData);
				if (ERROR_SUCCESS != dwStatus) {
					_tprintf(_T("WriteLogToFile failed, err : %d\n"), dwStatus);
					// Do not finish. Write next data.
				}

				if (NULL != pData) {
					free(pData);
					pData = NULL;
				}
			}			
		}

		pRecord += ((PEVENTLOGRECORD)pRecord)->Length;
	}	

	return dwStatus;
}

DWORD GetCurrentFilePath(LPCTSTR pszCurrentFileName, PTSTR pszCurrentFileFullPath)
{
	DWORD dwStatus = ERROR_SUCCESS;
	TCHAR szLogFilePath[MAX_PATH] = _T("");
	PTCHAR pTemp = NULL;

	// Get current module path. (it includes [processname].[ext])
	if (0 == GetModuleFileName(NULL, szLogFilePath, MAX_PATH)) {
		dwStatus = GetLastError();
		_tprintf(_T("could not get module path, err : %d\n"), dwStatus);
		return dwStatus;
	}

	// Find last back slash.
	pTemp = _tcsrchr(szLogFilePath, _T('\\'));
	if (NULL == pTemp) {
		dwStatus = ERROR_PATH_NOT_FOUND;
		_tprintf(_T("invalid path format : %s\n"), szLogFilePath);
		return dwStatus;
	}

	// Remove process name.
	pTemp++;
	*pTemp = _T('\0');

	// Concatenate [filename].[ext]
	StringCchCat(szLogFilePath, MAX_PATH, pszCurrentFileName);

	StringCchCopy(pszCurrentFileFullPath, MAX_PATH, szLogFilePath);

	return dwStatus;
}

void GetTimestamp(const DWORD Time, TCHAR DisplayString[])
{
	ULONGLONG ullTimeStamp = 0;
	ULONGLONG SecsTo1970 = 116444736000000000;
	SYSTEMTIME st;
	FILETIME ft, ftLocal;

	ullTimeStamp = Int32x32To64(Time, 10000000) + SecsTo1970;
	ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
	ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

	FileTimeToLocalFileTime(&ft, &ftLocal);
	FileTimeToSystemTime(&ftLocal, &st);
	StringCchPrintf(DisplayString, MAX_TIMESTAMP_LEN, L"%d/%d/%d %.2d:%.2d:%.2d",
		st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
}

DWORD WriteLogToFile(HANDLE hLogFile, LPCTSTR pszTimeStamp, PBYTE pszData)
{
	DWORD dwStatus = ERROR_SUCCESS;
	TCHAR szLogData[MAX_LOGDATA_LEN] = _T("");
	CHAR szAnsiLogData[MAX_LOGDATA_LEN] = "";
	DWORD dwBytesToWrite = 0;
	DWORD dwBytesWritten = 0;

	// delete \r and \n if log contains them.
	for (int i = 1; i <= 2; i++) {
		PTCHAR pTemp = (PTCHAR)pszData;
		pTemp += (_tcslen(pTemp) - i);
		if (*pTemp == _T('\n') ||
			*pTemp == _T('\r'))
		{
			*pTemp = _T('\0');
		}
	}	
	
	// Log data format : mm/dd/yyyy hh:mm:ss [log data]
	if (S_OK != StringCchPrintf(szLogData, MAX_LOGDATA_LEN, _T("%s %s\r\n"), pszTimeStamp, pszData)) {
		_tprintf(_T("making log data failed\n"));
		dwStatus = ERROR_INVALID_DATA;
		goto exit;
	}

#ifdef _UNICODE
	if (0 == WideCharToMultiByte(CP_ACP, 0, szLogData, -1, (LPSTR)szAnsiLogData, MAX_LOGDATA_LEN, NULL, NULL)) {
		dwStatus = GetLastError();
		_tprintf(_T("WideChartoMultiByte failed, err : %d\n"), dwStatus);
		goto exit;
	}
#else
	strcpy(szAnsiLogData, szLogData);
#endif

	dwBytesToWrite = (DWORD)strlen(szAnsiLogData);
	if (!WriteFile(hLogFile, szAnsiLogData, dwBytesToWrite, &dwBytesWritten, NULL)) {
		dwStatus = GetLastError();
		_tprintf(_T("write log data failed, err : %d\n"), dwStatus);
		goto exit;
	}

exit:
	return dwStatus;
}

DWORD WriteEventLog(LPCSTR pszProviderName, LPCSTR pszData)
{
	HANDLE hEventLog = NULL;	
	PWSTR pwszLogData = NULL;
	DWORD dwStatus = ERROR_SUCCESS;
	DWORD dwDataSize = 0;
	
	hEventLog = RegisterEventSourceA(NULL, pszProviderName);

	if (NULL == hEventLog) {
		dwStatus = GetLastError();
		_tprintf(_T("RegisterEventSource failed, err : %d\n"), dwStatus);
		goto cleanup;
	}

	dwDataSize = (DWORD)((strlen(pszData) + 1) * sizeof(WCHAR));

	pwszLogData = (PWSTR)malloc(dwDataSize);

	if (0 == MultiByteToWideChar(CP_ACP, 0, pszData, -1, pwszLogData, dwDataSize)) {
		dwStatus = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwStatus);
		goto cleanup;
	}

	PCWSTR aInsertions[] = { pwszLogData };

	if (!ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, ONELINE_INFO, NULL, 1, dwDataSize, aInsertions, (PVOID)pwszLogData)) {
		dwStatus = GetLastError();
		_tprintf(_T("ReportEvent failed, err : %d\n"), dwStatus);
		goto cleanup;
	}

	printf("Log data has been written (%s : %s)\n", pszProviderName, pszData);

cleanup:

	if (NULL != pwszLogData) {
		free(pwszLogData);
		pwszLogData = NULL;
	}

	if (NULL != hEventLog) {
		CloseHandle(hEventLog);
		hEventLog = NULL;
	}

	return dwStatus;
}

// Simulate Disk I/O Error 
DWORD MVOL_SimulDiskIoError(SIMULATION_DISK_IO_ERROR* pSdie)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	DWORD       dwReturned = 0;
	BOOL        ret = FALSE;

	if (pSdie == NULL) {
		fprintf(stderr, "LOG_ERROR: %s: Invalid parameter\n", __FUNCTION__);
		return ERROR_INVALID_PARAMETER;
	}

	// 1. Open MVOL_DEVICE
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}

	// 2. DeviceIoControl with SIMULATION_DISK_IO_ERROR parameter (DW-841, mvol.h)
	ret = DeviceIoControl(hDevice, IOCTL_MVOL_SET_SIMUL_DISKIO_ERROR,
		pSdie, sizeof(SIMULATION_DISK_IO_ERROR), pSdie, sizeof(SIMULATION_DISK_IO_ERROR), &dwReturned, NULL);
	if (ret == FALSE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_GET_PROC_BSR. Err=%u\n",
			__FUNCTION__, retVal);
	}

	// 3. CloseHandle MVOL_DEVICE
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
	return retVal;
}


#ifdef _DEBUG_OOS
// DW-1153
PVOID g_pBsrBaseAddr;		// base address of loaded bsrvflt.sys
ULONG g_ulBsrImageSize;		// image size of loaded bsrvflt.sys
DWORD64 g_ModuleBase;			// base address of loaded bsrvflt.pdb

// get base address and image size of loaded bsr.sys
BOOLEAN queryBsrBase(VOID)
{
	DWORD dwSize = 0;
	NTSTATUS status;
	PVOID pBsrAddr = NULL;
	BOOLEAN bRet = FALSE;
	PRTL_PROCESS_MODULES ModuleInfo = NULL;

	do {
		status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &dwSize);

		if (status != STATUS_INFO_LENGTH_MISMATCH) {
			break;
		}

		ModuleInfo = (PRTL_PROCESS_MODULES)malloc(dwSize);

		if (NULL == ModuleInfo) {
			break;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, dwSize, &dwSize);

		if (status != STATUS_SUCCESS) {
			break;
		}

		// found all loaded system modules.

		for (ULONG i = 0; i<ModuleInfo->NumberOfModules; i++) {
			PCHAR pFileName = (PCHAR)(ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);
			if (strcmp(pFileName, BSR_DRIVER_NAME) == 0) {
				// found loaded bsr.sys
				g_pBsrBaseAddr = ModuleInfo->Modules[i].ImageBase;
				g_ulBsrImageSize = ModuleInfo->Modules[i].ImageSize;
				bRet = TRUE;

				break;
			}
		}

	} while (false);
			
	if (NULL != ModuleInfo) {
		free(ModuleInfo);
		ModuleInfo = NULL;
	}

	return bRet;
}

BOOLEAN GetSymbolFileSize(const TCHAR* pFileName, DWORD& FileSize)
{
	BOOLEAN bRet = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	if (pFileName == NULL) {
		_tprintf(_T("filePath is NULL\n"));
		return FALSE;	
	}

	do {
		hFile = CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (hFile == INVALID_HANDLE_VALUE) {
			_tprintf(_T("CreateFile failed, %d \n"), GetLastError());
			break;
		}

		FileSize = GetFileSize(hFile, NULL);
		if (FileSize == INVALID_FILE_SIZE) {
			_tprintf(_T("GetFileSize failed, %d \n"), GetLastError());
			break;
		}
		
		bRet = TRUE;

	} while (false);

	if (INVALID_HANDLE_VALUE != hFile) {
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	return bRet;
}

// 
BOOLEAN GetFuncNameWithOffset(ULONG ulOffset, PCHAR pszFuncName)
{
	BOOLEAN bRet = FALSE;
	DWORD64 SymAddr = g_ModuleBase + ulOffset;
	CSymbolInfoPackage sip;
	DWORD64 Displacement = 0;

	do {
		bRet = SymFromAddr(GetCurrentProcess(), SymAddr, &Displacement, &sip.si);
		if (!bRet) {
			_tprintf(_T("SymFromAddr fail : %d, offset(%Ix)\n"), GetLastError(), ulOffset);
			break;
		}

		if (sip.si.Tag != SymTagFunction) {
			break;
		}

		sprintf_s(pszFuncName, 50, "%s+0x%x", sip.si.Name, SymAddr - sip.si.Address);

		bRet = TRUE;

	} while (false);

	return bRet;
}

BOOLEAN GetFuncNameWithAddr(PVOID pAddr, PCHAR pszFuncName)
{
	BOOLEAN bRet = FALSE;
	ULONG_PTR ulOffset = 0;

	ulOffset = (ULONG_PTR)((DWORD64)pAddr - (DWORD64)g_pBsrBaseAddr);
	
	if (ulOffset > g_ulBsrImageSize) {
		// address is not in bsr range.
		return FALSE;
	}

	bRet = GetFuncNameWithOffset((ULONG)ulOffset, pszFuncName);

	return bRet;
}

// Convert call stack frame into readable function name.
VOID ConvertCallStack(PCHAR LogLine)
{
	CHAR szDelimiter[2] = FRAME_DELIMITER;
	PCHAR pTemp = LogLine;
	CHAR szStackFramesName[MAX_FUNCS_STR_LEN] = "";

	if (LogLine == NULL ||
		strstr(LogLine, OOS_TRACE_STRING) == NULL ||
		NULL == strchr(LogLine, szDelimiter[0]))
	{
		return;
	}
	
	while ((pTemp = strchr(pTemp, szDelimiter[0])) != NULL) {
		CHAR szAddr[MAX_FUNC_ADDR_LEN] = "";
		PVOID dwAddr = 0;
		CHAR szFuncName[MAX_FUNC_NAME_LEN] = "";
		pTemp++;
		PCHAR pEnd = strchr(pTemp, szDelimiter[0]);
		if (NULL == pEnd) {
			pEnd = strchr(pTemp, '\0');
			if (NULL == pEnd) {
				_tprintf(_T("invalid string!!\n"));
				continue;
			}
		}

		ULONG ulAddrLen = (ULONG)(pEnd - pTemp);

		strncpy_s(szAddr, pTemp, ulAddrLen);
		sscanf_s(szAddr, "%Ix", &dwAddr);

		strcat_s(szStackFramesName, MAX_FUNCS_STR_LEN, FRAME_DELIMITER);
		
		if (TRUE == GetFuncNameWithAddr(dwAddr, szFuncName))
			strcat_s(szStackFramesName, MAX_FUNCS_STR_LEN, szFuncName);
		else
			strcat_s(szStackFramesName, MAX_FUNCS_STR_LEN, szAddr);
	}

	pTemp = strchr(LogLine, szDelimiter[0]);
	if (NULL == pTemp) {
		_tprintf(_T("could not find delimiter from %s\n"), LogLine);
		return;
	}
	
	*pTemp = '\0';
	strcat_s(LogLine, MAX_BSRLOG_BUF, szStackFramesName);	
}

// initialize out-of-sync trace.
// 1. get loaded bsr driver address, image size.
// 2. initialize and load bsr symbol
BOOLEAN InitOosTrace()
{
	BOOLEAN bRet = FALSE;
	DWORD dwFileSize = 0;
	DWORD64 BaseAddr = 0x10000000;
	TCHAR tszBsrSymbolPath[MAX_PATH] = _T("");
#ifdef _UNICODE
	CHAR szBsrSymbolPath[MAX_PATH] = "";
#endif

	GetCurrentFilePath(BSR_SYMBOL_NAME, tszBsrSymbolPath);
	
	do {
		if (g_pBsrBaseAddr == NULL &&
			FALSE == queryBsrBase())
		{
			_tprintf(_T("Failed to initialize bsr base\n"));
			break;			
		}

		_tprintf(_T("bsrvflt.sys(%p), imageSize(%x)\n"), g_pBsrBaseAddr, g_ulBsrImageSize);

		DWORD Options = 0;

		Options = SymGetOptions();
		Options |= SYMOPT_DEBUG;
		Options |= SYMOPT_LOAD_LINES;

		SymSetOptions(Options);
		
		if (FALSE == SymInitialize(GetCurrentProcess(), NULL, FALSE)) {
			_tprintf(_T("SymInitialize failed : %d\n"), GetLastError());
			break;
		}

		GetSymbolFileSize(tszBsrSymbolPath, dwFileSize);

		if (0 == dwFileSize) {
			_tprintf(_T("Symbol file size is zero\n"));
			break;
		}

#ifdef _UNICODE
		if (0 == WideCharToMultiByte(CP_ACP, 0, tszBsrSymbolPath, -1, (LPSTR)szBsrSymbolPath, MAX_PATH, NULL, NULL)) {
			_tprintf(_T("Failed to convert wchar to char : %d\n"), GetLastError());
			break;
		}

		g_ModuleBase = SymLoadModule64(GetCurrentProcess(), NULL, szBsrSymbolPath, NULL, BaseAddr, dwFileSize);
#else
		g_ModuleBase = SymLoadModule64(GetCurrentProcess(), NULL, tszBsrSymbolPath, NULL, BaseAddr, dwFileSize);
#endif
		if (0 == g_ModuleBase) {
			_tprintf(_T("SymLoadModule64 failed : %d\n"), GetLastError());
			break;
		}

		bRet = TRUE;

	} while (false);

	return bRet;
}

// initialize out-of-sync trace.
// 1. unload and clean up bsr symbol
VOID CleanupOosTrace()
{
	::SymUnloadModule64(GetCurrentProcess, g_ModuleBase);
	::SymCleanup(GetCurrentProcess());
}
#endif	// _DEBUG_OOS

#ifdef _DEBUG_OOS

DWORD MVOL_ConvertOosLog(LPCTSTR pSrcFilePath)
{
	DWORD dwRet = ERROR_SUCCESS;
	BOOLEAN bRet = FALSE;
	DWORD dwRead = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hConverted = INVALID_HANDLE_VALUE;
	TCHAR ptSrcFilePath[MAX_PATH] = _T("");
	TCHAR ptOrgRenamedFilePath[MAX_PATH] = _T("");
	char *buff = NULL;
	
#ifdef _UNICODE
	if (0 == MultiByteToWideChar(CP_ACP, 0, (LPSTR)pSrcFilePath, -1, ptSrcFilePath, MAX_PATH)) {
		dwRet = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwRet);
		return dwRet;
	}
#else
	strcpy(ptSrcFilePath, pSrcFilePath);
#endif

	do {
		bRet = InitOosTrace();
		if (!bRet) {
			_tprintf(_T("InitOosTrace failed, %d \n"), GetLastError());
			break;
		}

		_tcscpy_s(ptOrgRenamedFilePath, ptSrcFilePath);
		_tcscat_s(ptOrgRenamedFilePath, _T("_org"));

		if (!MoveFile(ptSrcFilePath, ptOrgRenamedFilePath)) {
			dwRet = GetLastError();
			_tprintf(_T("MoveFile for (%s -> %s) failed, %d \n"), ptSrcFilePath, ptOrgRenamedFilePath, dwRet);
			break;
		}

		hFile = CreateFile(ptOrgRenamedFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			dwRet = GetLastError();
			_tprintf(_T("CreateFile for %s failed, %d \n"), ptSrcFilePath, dwRet);
			break;
		}

		LARGE_INTEGER liFileSize = { 0, };

		if (!GetFileSizeEx(hFile, &liFileSize) ||
			!liFileSize.QuadPart)
		{
			dwRet = GetLastError();
			_tprintf(_T("GetFileSizeEx failed, %d \n"), dwRet);
			break;
		}

		buff = new char[liFileSize.QuadPart];
		if (!buff) {
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
			printf("failed to alloc buff\n");
			break;
		}

		if (!ReadFile(hFile, buff, (DWORD)liFileSize.QuadPart, &dwRead, NULL)) {
			dwRet = GetLastError();
			_tprintf(_T("ReadFile failed, %d \n"), dwRet);
			break;
		}

		hConverted = CreateFile(ptSrcFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			dwRet = GetLastError();
			_tprintf(_T("CreateFile for %s failed, %d \n"), ptSrcFilePath, dwRet);
			break;
		}

		char *pLine = buff, *pTemp = buff;
		while (pTemp = strstr(pLine, "\r\n")) {
			CHAR szLineBuf[1024] = "";
			*pTemp = '\0';
			strcpy_s(szLineBuf, pLine);
			// convert callstack by line
			ConvertCallStack(szLineBuf);
			WriteFile(hConverted, szLineBuf, (DWORD)strlen(szLineBuf), &dwRead, NULL);
			WriteFile(hConverted, "\r\n", 2, &dwRead, NULL);

			// go next
			pLine = pTemp+2;
		}

		_tprintf(_T("Converted Log Path : %s\n"), ptSrcFilePath);

	} while (false);

	
	if (buff)
		delete(buff);

	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	if (hConverted != INVALID_HANDLE_VALUE)
		CloseHandle(hConverted);

	if (bRet)
		CleanupOosTrace();

	return dwRet;
}
#endif

VOID getVolumeBsrlockInfo(HANDLE hBsrlock, PWCHAR pszVolumeName)
{
	
	DWORD dwErr = 0;
	DWORD dwRet = 0;

	// to be printed.
	WCHAR szLetter[10] = L"";				// C:
	WCHAR szDevName[MAX_PATH] = L"";		// \Device\HarddiskVolume1
	BOOLEAN bProtected = FALSE;				// Protected, Not protected
	PWCHAR pTemp = NULL;					// Volume{11111111-2222-3333-4444-555555555555}
		
	if (pszVolumeName == NULL) {
		printf("invalid parameter\n");
		return;
	}

	GetVolumePathNamesForVolumeNameW(pszVolumeName, szLetter, 10, &dwRet);

	pTemp = wcsstr(pszVolumeName, L"Volume");
	if (pTemp == NULL) {
		printf("err2\n");
		return;
	}

	pTemp[wcslen(pTemp) - 1] = L'\0';
	
	if (QueryDosDevice(pTemp, szDevName, 260)) {
		if (wcsstr(szDevName, L"Floppy") ||
			wcsstr(szDevName, L"CdRom"))
		{
			return;
		}

		if (!DeviceIoControl(hBsrlock, IOCTL_BSRLOCK_GET_STATUS, szDevName, (DWORD)(wcslen(szDevName) + 1) * sizeof(WCHAR), &bProtected, (DWORD)sizeof(bProtected), &dwRet, NULL)) {
			dwErr = GetLastError();
			printf("DeviceIoControl Failed for device(%ws), err(%d)\n", szDevName, dwErr);
			return;
		}

		bProtected;
	}
	else {
		printf("err3\n");
	}

//print_info:
	printf("Mount point: %ws\n", wcslen(szLetter) >= 1 ? szLetter : L"None");
	printf("Volume Guid: %ws\n", pTemp);
	printf("Device Name: %ws\n", szDevName);
	printf("    Locking: %s\n", bProtected ? "On" : "Off");
	printf("\n");
}

DWORD GetBsrlockStatus()
{	
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	PWCHAR pTemp = NULL;
	DWORD dwErr = ERROR_SUCCESS;
	DWORD dwRet = 0;
	int bBsrlock;
	
	do {
		hDevice = OpenDevice(BSRLOCK_DEVICE_NAME_USER);

		if (hDevice == INVALID_HANDLE_VALUE) {
			dwErr = GetLastError();
			printf("Failed to open device(%s), err(%d)\n", BSRLOCK_DEVICE_NAME_USER, dwErr);
			break;
		}

		HANDLE FindHandle = INVALID_HANDLE_VALUE;
		WCHAR VolumeName[MAX_PATH] = L"";
		WCHAR DevName[MAX_PATH] = L"";

		FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));

		if (FindHandle == INVALID_HANDLE_VALUE) {
			printf("Failed to find volume, err(%d)\n", GetLastError());
			break;
		}
		
		getVolumeBsrlockInfo(hDevice, VolumeName);

		while (FindNextVolume(FindHandle, VolumeName, ARRAYSIZE(VolumeName))) {
			getVolumeBsrlockInfo(hDevice, VolumeName);
		}
		
		if (DeviceIoControl(hDevice, IOCTL_GET_BSRLOCK_USE, NULL, 0,  &bBsrlock, sizeof(int), &dwRet, NULL) == FALSE) {
			dwErr = GetLastError();
			printf("Failed IOCTL_GET_BSRLOCK_USE. err(%d)\n", dwErr);
		}
		if (!bBsrlock) {
			printf("\n# bsrlock is disabled\n");
		}

	} while (false);	
	
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		hDevice = INVALID_HANDLE_VALUE;
	}

	return dwErr;
}

// BSR-71 add bsrlock bypass setting for testing and debugging
DWORD MVOL_BsrlockUse(int bBsrlock) {
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
	DWORD       retVal = ERROR_SUCCESS;

	hDevice = OpenDevice(BSRLOCK_DEVICE_NAME_USER);\
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "BSRLOCK_USE_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}

	if (DeviceIoControl(hDevice, IOCTL_SET_BSRLOCK_USE, &bBsrlock, sizeof(int), NULL, 0, &dwReturned, NULL) == FALSE) {
		retVal = GetLastError();
		fprintf(stderr, "BSRLOCK_USE_ERROR: %s: Failed IOCTL_SET_BSRLOCK_USE. Err=%u\n",
			__FUNCTION__, retVal);
	}

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
	return retVal;
}

#endif


DWORD MVOL_SetHandlerUse(PHANDLER_INFO pHandler)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
	FILE *fp;
#endif
	DWORD       retVal = ERROR_SUCCESS;

	if (pHandler == NULL) {
		fprintf(stderr, "HANDLER_USE_ERROR: %s: Invalid parameter\n", __FUNCTION__);
		return ERROR_INVALID_PARAMETER;
	}

	// 1. Open MVOL_DEVICE
#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "HANDLER_USE_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR))==-1) {
		fprintf(stderr, "HANDLER_USE_ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

	// 2. DeviceIoControl with HANDLER_USE parameter
#ifdef _WIN
	if (DeviceIoControl(hDevice, IOCTL_MVOL_SET_HANDLER_USE, pHandler, sizeof(HANDLER_INFO), NULL, 0, &dwReturned, NULL) == FALSE) {
#else
	if (ioctl(fd, IOCTL_MVOL_SET_HANDLER_USE, pHandler) != 0) {
#endif
		retVal = GetLastError();
		fprintf(stderr, "HANDLER_USE_ERROR: %s: Failed IOCTL_MVOL_SET_HANDLER_USE. Err=%u\n",
			__FUNCTION__, retVal);
	}

	// 3. CloseHandle MVOL_DEVICE
#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);

	// BSR-626 write /etc/bsr.d/.handler_use
	fp = fopen(BSR_HANDLER_USE_REG, "w");
	if (fp != NULL) {
		fprintf(fp, "%d", pHandler->use);
		fclose(fp);
	} else {
		retVal = GetLastError();
		fprintf(stderr, "HANDLER_USE_ERROR: %s: Failed open %s file. Err=%u\n",
				__FUNCTION__, BSR_HANDLER_USE_REG, retVal);
	}
#endif
	return retVal;
}


// BSR-1060
#ifdef _WIN
DWORD MVOL_SetHandlerTimeout(PHANDLER_TIMEOUT_INFO pHandler)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
	DWORD       retVal = ERROR_SUCCESS;

	if (pHandler == NULL) {
		fprintf(stderr, "HANDLER_TIMEOUT_ERROR: %s: Invalid parameter\n", __FUNCTION__);
		return ERROR_INVALID_PARAMETER;
	}

	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "HANDLER_TIMEOUT_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	} 

	if (DeviceIoControl(hDevice, IOCTL_MVOL_SET_HANDLER_TIMEOUT, pHandler, sizeof(HANDLER_TIMEOUT_INFO), NULL, 0, &dwReturned, NULL) == FALSE) {
		retVal = GetLastError();
		fprintf(stderr, "HANDLER_TIMEOUT_ERROR: %s: Failed IOCTL_MVOL_SET_HANDLER_TIMEOUT. Err=%u\n",
			__FUNCTION__, retVal);
	}

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}

	return retVal;
}
#endif

// DW-1629
BOOLEAN logfindstr(char* target, char *msg)
{
	if (target == NULL)
		return false;

	char* ptr = strstr(msg, target);

	if (ptr == NULL)
		return false;

	return true;
}

// BSR-654
DWORD MVOL_SetDebugLogCategory(PDEBUG_LOG_CATEGORY pDlcE)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
	FILE *fp;
#endif
	DWORD       retVal = ERROR_SUCCESS;

	// 1. Open MVOL_DEVICE
#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "DEBUG_CATEGORY_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		fprintf(stderr, "DEBUG_CATEGORY_ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

	// 2. DeviceIoControl with LOGGING_MIN_LV parameter (DW-858)
#ifdef _WIN
	if (DeviceIoControl(hDevice, IOCTL_MVOL_SET_DEBUG_LOG_CATEGORY, pDlcE, sizeof(DEBUG_LOG_CATEGORY), NULL, 0, &dwReturned, NULL) == FALSE) {
#else // _LIN
	if ((ioctl(fd, IOCTL_MVOL_SET_DEBUG_LOG_CATEGORY, pDlcE)) < 0) {
#endif
		retVal = GetLastError();
		fprintf(stderr, "DEBUG_CATEGORY_ERROR: %s: Failed IOCTL_MVOL_SET_DEBUG_LOG_CATEGORY. Err=%u\n",
			__FUNCTION__, retVal);
	}

	// 3. CloseHandle MVOL_DEVICE
#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);

	// write /etc/bsr.d/.debuglog_category
	fp = fopen(BSR_DEBUG_LOG_CATEGORY_REG, "w");
	if (fp != NULL) {
		fprintf(fp, "%u", pDlcE->nCategory);
		fclose(fp);
	}
	else {
		retVal = GetLastError();
		fprintf(stderr, "DEBUG_CATEGORY_ERROR: %s: Failed open %s file. Err=%u\n",
			__FUNCTION__, BSR_DEBUG_LOG_CATEGORY_REG, retVal);
	}
#endif
	return retVal;
}

DWORD MVOL_SetMinimumLogLevel(PLOGGING_MIN_LV pLml)
{	
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
	FILE *fp;
	long log_level=0;
#endif
	DWORD       retVal = ERROR_SUCCESS;


	if (pLml == NULL || pLml->nType < LOGGING_TYPE_SYSLOG ||
		((pLml->nType == LOGGING_TYPE_SYSLOG || pLml->nType == LOGGING_TYPE_DBGLOG) && 
		(pLml->nErrLvMin < 0 || pLml->nErrLvMin >= LOG_DEFAULT_MAX_LEVEL)) || pLml->nErrLvMin < 0)
	{
		fprintf(stderr, "LOG_ERROR: %s: Invalid parameter(%d)\n", __FUNCTION__, pLml->nErrLvMin);
		return ERROR_INVALID_PARAMETER;
	}


	// 1. Open MVOL_DEVICE
#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR))==-1) {
		fprintf(stderr, "LOG_ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

	// 2. DeviceIoControl with LOGGING_MIN_LV parameter (DW-858)
#ifdef _WIN
	if (DeviceIoControl(hDevice, IOCTL_MVOL_SET_LOGLV_MIN, pLml, sizeof(LOGGING_MIN_LV), NULL, 0, &dwReturned, NULL) == FALSE) {
#else // _LIN
	if ((log_level = ioctl(fd, IOCTL_MVOL_SET_LOGLV_MIN, pLml)) < 0) {
#endif
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_SET_LOGLV_MIN. Err=%u\n",
			__FUNCTION__, retVal);
	}

	// 3. CloseHandle MVOL_DEVICE
#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);

	// BSR-584 write /etc/bsr.d/.log_level
	fp = fopen(BSR_LOG_LEVEL_REG, "w");
	if(fp != NULL) {
		fprintf(fp, "%ld", log_level);
		fclose(fp);
	} else {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open %s file. Err=%u\n",
				__FUNCTION__, BSR_LOG_LEVEL_REG, retVal);
	}
#endif
	return retVal;
}

// BSR-579
DWORD MVOL_SetLogFileMaxCount(ULONG limit)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	// BSR-597
	int fd;
	FILE *fp;
#endif
	DWORD       retVal = ERROR_SUCCESS;


	if (limit <= 0 ||limit > 1000)
	{
		fprintf(stderr, "LOG_FILE_MAX_COUNT_ERROR: %s: Invalid parameter(%d)\n", __FUNCTION__, limit);
		return ERROR_INVALID_PARAMETER;
	}


	// 1. Open MVOL_DEVICE
#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_FILE_MAX_COUNT_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	// BSR-597
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR))==-1) {
		fprintf(stderr, "LOG_FILE_MAX_COUNT_ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

	// 2. DeviceIoControl with LOGGING_MIN_LV parameter (DW-858)
#ifdef _WIN
	if (DeviceIoControl(hDevice, IOCTL_MVOL_SET_LOG_FILE_MAX_COUNT, &limit, sizeof(ULONG), NULL, 0, &dwReturned, NULL) == FALSE) {
#else // _LIN
	// BSR-579
	if (ioctl(fd, IOCTL_MVOL_SET_LOG_FILE_MAX_COUNT, &limit) != 0) {
#endif
		retVal = GetLastError();
		fprintf(stderr, "LOG_FILE_MAX_COUNT_ERROR: %s: Failed IOCTL_MVOL_SET_LOG_FILE_MAX_COUNT. Err=%u\n",
			__FUNCTION__, retVal);
	}

	// 3. CloseHandle MVOL_DEVICE
#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	// BSR-597
	if (fd)
		close(fd);

	// BSR-597 write /etc/bsr.d/.log_file_max_count
	fp = fopen(BSR_LOG_FILE_MAXCNT_REG, "w");
	if(fp != NULL) {
		fprintf(fp, "%u", limit);
		fclose(fp);
	} else {
		retVal = GetLastError();
		fprintf(stderr, "LOG_FILE_MAX_COUNT_ERROR: %s: Failed open %s file. Err=%u\n",
				__FUNCTION__, BSR_LOG_FILE_MAXCNT_REG, retVal);
	}
#endif
	return retVal;
}

// BSR-1048
DWORD MVOL_WriteBsrKernelLog(int level, char *message)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
#endif
	DWORD       retVal = ERROR_SUCCESS;
	WRITE_KERNEL_LOG writeLog;

#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		fprintf(stderr, "LOG_ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

	writeLog.level = level;
	writeLog.length = strlen(message);
	if (writeLog.length >= MAX_BSRLOG_BUF) {
#ifdef _WIN
		retVal = ERROR_BAD_FORMAT;
#else
		retVal = -1;
#endif
		fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_WRITE_LOG. Err=%u, length(%d)\n",
			__FUNCTION__, retVal, writeLog.length);
	}
	else {
		memset(writeLog.message, 0, sizeof(writeLog.message));
		memcpy(writeLog.message, message, strlen(message));

#ifdef _WIN
		if (DeviceIoControl(hDevice, IOCTL_MVOL_WRITE_LOG, &writeLog, sizeof(WRITE_KERNEL_LOG), NULL, 0, &dwReturned, NULL) == FALSE) {
#else // _LIN
		if (ioctl(fd, IOCTL_MVOL_WRITE_LOG, &writeLog) != 0) {
#endif
			retVal = GetLastError();
			fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_WRITE_LOG. Err=%u\n",
				__FUNCTION__, retVal);
		}
	}

#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);
#endif

	return retVal;
}

// BSR-1039
DWORD MVOL_HoldState(int type, int state)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
#endif
	DWORD       retVal = ERROR_SUCCESS;
	HOLD_STATE in;

#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "HOLD_STATE_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		fprintf(stderr, "HOLD_STATE_ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

	in.type = type;
	in.state = state;

#ifdef _WIN
	if (DeviceIoControl(hDevice, IOCTL_MVOL_HOLD_STATE, &in, sizeof(HOLD_STATE), NULL, 0, &dwReturned, NULL) == FALSE) {
#else // _LIN
	if (ioctl(fd, IOCTL_MVOL_HOLD_STATE, &in) != 0) {
#endif
		retVal = GetLastError();
		fprintf(stderr, "HOLD_STATE_ERROR: %s: Failed IOCTL_MVOL_HOLD_STATE. Err=%u\n",
			__FUNCTION__, retVal);
	}

#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);
#endif

	return retVal;
}

DWORD MVOL_FakeALUsed(int al_used_count)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
#endif
	DWORD       retVal = ERROR_SUCCESS;

#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "FAKE_AL_USED_COUNT__ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		fprintf(stderr, "FAKE_AL_USED_COUNT__ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

#ifdef _WIN
	if (DeviceIoControl(hDevice, IOCTL_MVOL_FAKE_AL_USED, &al_used_count, sizeof(al_used_count), NULL, 0, &dwReturned, NULL) == FALSE) {
#else // _LIN
	if (ioctl(fd, IOCTL_MVOL_FAKE_AL_USED, &al_used_count) != 0) {
#endif
		retVal = GetLastError();
		fprintf(stderr, "FAKE_AL_USED_COUNT__ERROR: %s: Failed IOCTL_MVOL_FAKE_AL_USED. Err=%u\n",
			__FUNCTION__, retVal);
	}

#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);
#endif

	return retVal;
}

// BSR-1444
#ifdef _WIN
DWORD MVOL_ReleaseReadonly(int minor)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
	DWORD       retVal = ERROR_SUCCESS;

	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "RELEASE_READONLY__ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}

	if (DeviceIoControl(hDevice, IOCTL_MVOL_RELEASE_READONLY, &minor, sizeof(minor), NULL, 0, &dwReturned, NULL) == FALSE) {
		retVal = GetLastError();
		fprintf(stderr, "RELEASE_READONLY__ERROR: %s: Failed IOCTL_MVOL_RELEASE_READONLY. Err=%u\n",
			__FUNCTION__, retVal);
	}

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
	return retVal;
}
#endif

// BSR-1072
DWORD MVOL_BsrPanic(int panic_enable, int occurrence_time, int force, char* cert)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
#endif
	DWORD       retVal = ERROR_SUCCESS;
	KERNEL_PANIC_INFO in;

#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "PANIC_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1) {
		fprintf(stderr, "PANIC_ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

	if (cert && strlen(cert) >= MAX_PANIC_CERT_BUF) {
#ifdef _WIN
		retVal = ERROR_BAD_FORMAT;
#else
		retVal = -1;
#endif
		fprintf(stderr, "PANIC_ERROR: %s: Failed IOCTL_MVOL_WRITE_LOG. Err=%u, length(%d)\n",
			__FUNCTION__, retVal, strlen(cert));
	} else {
		in.enable = panic_enable;
		in.occurrence_time = occurrence_time;
		in.force = force;

		if (cert) {
			memset(in.cert, 0, sizeof(in.cert));
			// BSR-1073 remove the opening character of fgets()
			memcpy(in.cert, cert, (strlen(cert) - 1));
		}
#ifdef _WIN
		if (DeviceIoControl(hDevice, IOCTL_MVOL_BSR_PANIC, &in, sizeof(KERNEL_PANIC_INFO), NULL, 0, &dwReturned, NULL) == FALSE) {
#else // _LIN
		if (ioctl(fd, IOCTL_MVOL_BSR_PANIC, &in) != 0) {
#endif
			retVal = GetLastError();
			fprintf(stderr, "PANIC_ERROR: %s: Failed IOCTL_MVOL_BSR_PANIC. Err=%u\n",
				__FUNCTION__, retVal);
		}
	}
#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);
#endif

	return retVal;
}

// BSR-1052 If an exception occurs while saving the real-time log, add the command again because you need another way to save the log.
// BSR-973 Add real-time log file logging to disable function MVOL_GetBsrLog. also, the log format has changed, so modifications are required to use the function MVOL_GetBsrLog.
DWORD MVOL_GetBsrLog(char* pszProviderName, char* resName, BOOLEAN oosTrace)
{
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
	FILE *fp; 
#endif
	DWORD       retVal = ERROR_SUCCESS;
	PBSR_LOG	pBsrLog = NULL;
	// DW-1629
	char tstr[MAX_PATH] = { 0, };

#ifdef _WIN
#ifdef _DEBUG_OOS
	if (oosTrace)
		oosTrace = InitOosTrace();	
#endif
#endif

	if (resName != NULL) {
		memset(tstr, 0, MAX_PATH);

		// DW-1629 check logs for resource name and additional parsing data
		//#define __bsr_printk_device ...
		//#define __bsr_printk_peer_device ...
		//#define __bsr_printk_resource ...
		//#define __bsr_printk_connection ...
#ifdef _WIN
		sprintf_s(tstr, "> bsr %s", resName);
#else // _LIN
		sprintf(tstr, "> bsr %s", resName);
#endif
	}
	
	// 1. Open MVOL_DEVICE
#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR))==-1) {
		fprintf(stderr, "LOG_ERROR: Can not open /dev/bsr-control\n");
		return -1;
	}
#endif

	pBsrLog = (PBSR_LOG)malloc(BSR_LOG_SIZE);
	if (!pBsrLog) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed malloc. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
		//fprintf(stderr, "Failed malloc\n");
		//exit(1);

	}

	// 2. DeviceIoControl with BSR_LOG_SIZE parameter (DW-1054)
#ifdef _WIN
	if (DeviceIoControl(hDevice, IOCTL_MVOL_GET_BSR_LOG, pBsrLog, BSR_LOG_SIZE, pBsrLog, BSR_LOG_SIZE, &dwReturned, NULL) == FALSE) {
#else // _LIN
	if (ioctl(fd, IOCTL_MVOL_GET_BSR_LOG, pBsrLog) != 0) {
#endif
		retVal = GetLastError();
		fprintf(stderr, "LOG_ERROR: %s: Failed IOCTL_MVOL_GET_BSR_LOG. Err=%u\n",
			__FUNCTION__, retVal);
	}	
	else {
#ifdef _WIN
		HANDLE hLogFile = INVALID_HANDLE_VALUE;
		hLogFile = CreateFileA(pszProviderName, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hLogFile != INVALID_HANDLE_VALUE) {
#else // _LIN
		fp = fopen(pszProviderName ,"w");
		if(fp != NULL) {
#endif
			unsigned int loopcnt = (unsigned int)min(pBsrLog->totalcnt, LOGBUF_MAXCNT);
			if (pBsrLog->totalcnt <= LOGBUF_MAXCNT) {
				for (unsigned int i = 0; i < (loopcnt*(MAX_BSRLOG_BUF + IDX_OPTION_LENGTH)); i += (MAX_BSRLOG_BUF + IDX_OPTION_LENGTH)) {
					// DW-1629
					if (resName != NULL && !logfindstr(tstr, ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH)))
						continue;

#ifdef _DEBUG_OOS
					if (oosTrace) {
#ifdef _WIN
						ConvertCallStack(((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
#else // _LIN
						// skip
#endif
					} else if (logfindstr(OOS_TRACE_STRING, ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH))) {
						// DW-1153 don't write out-of-sync trace log since user doesn't want to see..
						continue;
					}
#endif

#ifdef _WIN
					DWORD dwWritten;
					DWORD len = (DWORD)strlen(((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
					WriteFile(hLogFile, ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH), len - 1, &dwWritten, NULL);
#else // _LIN
					fprintf(fp, "%s", ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
#endif
				}
			}
			else { // pBsrLog->totalcnt > LOGBUF_MAXCNT
				pBsrLog->totalcnt = pBsrLog->totalcnt%LOGBUF_MAXCNT;
				// BSR-578 log start point is calculated based on zero.
				for (unsigned int i = (unsigned int)pBsrLog->totalcnt*(MAX_BSRLOG_BUF + IDX_OPTION_LENGTH); i < (LOGBUF_MAXCNT*(MAX_BSRLOG_BUF + IDX_OPTION_LENGTH)); i += (MAX_BSRLOG_BUF + IDX_OPTION_LENGTH)) {
					// DW-1629
					if (resName != NULL && !logfindstr(tstr, ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH)))
						continue;

#ifdef _DEBUG_OOS
					if (oosTrace) {
#ifdef _WIN
						ConvertCallStack(((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
#else // _LIN
						// skip
#endif
					} else if (logfindstr(OOS_TRACE_STRING, ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH))) {
						// DW-1153 don't write out-of-sync trace log since user doesn't want to see..
						continue;
					}
#endif

#ifdef _WIN
					DWORD dwWritten;
					DWORD len = (DWORD)strlen(((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
					WriteFile(hLogFile, ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH), len - 1, &dwWritten, NULL);
					WriteFile(hLogFile, "\r\n", 2, &dwWritten, NULL);
#else // _LIN
					fprintf(fp, "%s", ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
#endif
				}

				for (unsigned int i = 0; i < pBsrLog->totalcnt*(MAX_BSRLOG_BUF + IDX_OPTION_LENGTH); i += (MAX_BSRLOG_BUF + IDX_OPTION_LENGTH)) {
					// DW-1629
					if (resName != NULL && !logfindstr(tstr, ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH)))
						continue;

#ifdef _DEBUG_OOS
					if (oosTrace) {
#ifdef _WIN
						ConvertCallStack(((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
#else // _LIN
						// skip
#endif
					} else if (NULL != strstr(((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH), OOS_TRACE_STRING)) {
						// DW-1153 don't write out-of-sync trace log since user doesn't want to see..
						continue;
					}
#endif
#ifdef _WIN
					DWORD dwWritten;
					DWORD len = (DWORD)strlen(((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
					WriteFile(hLogFile, ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH), len - 1, &dwWritten, NULL);
					WriteFile(hLogFile, "\r\n", 2, &dwWritten, NULL);
#else // _LIN
					fprintf(fp, "%s", ((&pBsrLog->LogBuf[i]) + IDX_OPTION_LENGTH));
#endif
				}
			}
#ifdef _WIN
			CloseHandle(hLogFile);
#else // _LIN
			fclose(fp);
#endif
		}
		else {
			retVal = GetLastError();
			fprintf(stderr, "LOG_ERROR: %s: Failed CreateFile. Err=%u\n",
				__FUNCTION__, retVal);
		}
	}
	// 3. CloseHandle MVOL_DEVICE
#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);
#endif

	if (pBsrLog) {
		free(pBsrLog);
	}
#ifdef _WIN
#ifdef _DEBUG_OOS
	if (oosTrace){
		CleanupOosTrace();
	}
#endif
#endif	

	return retVal;

}


#ifdef _WIN
DWORD WriteSearchLogIfMatch(HANDLE hResFile, PCHAR pszLine, unsigned long long ullSearchSector)
#else // _LIN
int WriteSearchLogIfMatch(FILE *hResFile, char * pszLine, unsigned long long ullSearchSector)
#endif
{
	DWORD dwRet = ERROR_SUCCESS;
#ifdef _WIN
	DWORD dwRead = 0;
#endif
	unsigned long long startSector = -1, endSector = -1;
	char szSector[1024] = "";
	char *pSector = NULL;
	
	do {
		pSector = strstr(pszLine, "sector(") + strlen("sector(");
		if (NULL == pSector) {
			dwRet = ERROR_INVALID_DATA;
#ifdef _WIN
			_tprintf(_T("could not find sector string\n"));
#else
			fprintf(stderr, "could not find sector string\n");
#endif
			break;
		}

#ifdef _WIN	
		strcpy_s(szSector, pSector);
#else
		strcpy(szSector, pSector);
#endif
		char *pSectorEnd = strchr(szSector, ')');
		if (NULL == pSectorEnd) {
			dwRet = ERROR_INVALID_DATA;
#ifdef _WIN
			_tprintf(_T("could not find sector string2\n"));
#else
			fprintf(stderr, "could not find sector string2\n");
#endif
			break;
		}
		
		*pSectorEnd = '\0';
		
#define SECTOR_DELIMITER " ~ "

		pSectorEnd = strstr(szSector, SECTOR_DELIMITER);
		if (NULL == pSectorEnd) {
			dwRet = ERROR_INVALID_DATA;
#ifdef _WIN
			_tprintf(_T("could not find sector delimiter\n"));
#else
			fprintf(stderr, "could not find sector delimiter\n");
#endif
			break;
		}
		
		pSector = szSector;
		*pSectorEnd = '\0';

		startSector = atoll(pSector);
		pSector = pSectorEnd + strlen(SECTOR_DELIMITER);
		endSector = atoll(pSector);

		if (startSector < 0 || endSector < 0) {
			dwRet = ERROR_INVALID_DATA;
#ifdef _WIN
			_tprintf(_T("we got invalid sector(%llu ~ %llu)\n"), startSector, endSector);
#else
			fprintf(stderr, "we got invalid sector(%llu ~ %llu)\n", startSector, endSector);
#endif
			break;
		}
		
		// check if ullSearchSector is between startSector and endSector
		if (ullSearchSector < startSector ||
			ullSearchSector > endSector)
		{
			// we are not interested in this sector, just return success.
			dwRet = ERROR_SUCCESS;
			break;
		}
		
		// write res file.
#ifdef _WIN
		if (!WriteFile(hResFile, pszLine, (DWORD)strlen(pszLine), &dwRead, NULL)) {
			dwRet = GetLastError();

			_tprintf(_T("WriteFile1 failed, err : %d\n"), dwRet);
			break;
		}
		if (!WriteFile(hResFile, "\r\n", 2, &dwRead, NULL)) {
			dwRet = GetLastError();
			_tprintf(_T("WriteFile1 failed, err : %d\n"), dwRet);
			break;
		}
#else // _LIN
		fprintf(hResFile, "%s", pszLine);
#endif
		dwRet = ERROR_SUCCESS;
	} while (false);

	return dwRet;
}

DWORD MVOL_SearchOosLog(LPCTSTR pSrcFilePath, LPCTSTR szSector)
{	
	DWORD dwRet = ERROR_SUCCESS;
#ifdef _WIN
	DWORD dwRead = 0;
	HANDLE hSrcFile = INVALID_HANDLE_VALUE;
	HANDLE hSearchedResFile = INVALID_HANDLE_VALUE;
	TCHAR ptSrcFilePath[MAX_PATH] = _T("");
	TCHAR ptResFilePath[MAX_PATH] = _T("");
	TCHAR ptSector[128] = _T("");
	unsigned long long ullSector = atoll((const char*)szSector);

	char *buff = NULL;

#ifdef _UNICODE
	if (0 == MultiByteToWideChar(CP_ACP, 0, (LPSTR)pSrcFilePath, -1, ptSrcFilePath, MAX_PATH)) {
		dwRet = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwRet);
		return dwRet;
	}
	if (0 == MultiByteToWideChar(CP_ACP, 0, (LPSTR)szSector, -1, ptSector, 128)) {
		dwRet = GetLastError();
		_tprintf(_T("MultiByteToWideChar failed, err : %d\n"), dwRet);
		return dwRet;
}
#else
	strcpy(ptSrcFilePath, pSrcFilePath);
	strcpy(ptSector, szSector);
#endif


	do {
		hSrcFile = CreateFile(ptSrcFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hSrcFile == INVALID_HANDLE_VALUE) {
			dwRet = GetLastError();
			_tprintf(_T("CreateFile for %s failed, %d \n"), ptSrcFilePath, dwRet);
			break;
		}

		LARGE_INTEGER liFileSize = { 0, };

		if (!GetFileSizeEx(hSrcFile, &liFileSize) ||
			!liFileSize.QuadPart)
		{
			dwRet = GetLastError();
			_tprintf(_T("GetFileSizeEx failed, %d \n"), dwRet);
			break;
		}

		buff = new char[liFileSize.QuadPart];
		if (!buff) {
			dwRet = ERROR_NOT_ENOUGH_MEMORY;
			printf("failed to alloc buff\n");
			break;
		}

		if (!ReadFile(hSrcFile, buff, (DWORD)liFileSize.QuadPart, &dwRead, NULL)) {
			dwRet = GetLastError();
			_tprintf(_T("ReadFile failed, %d \n"), dwRet);
			break;
		}

		_stprintf_s(ptResFilePath, _T("%s_sector%s"), ptSrcFilePath, ptSector);
		_tprintf(_T("resfile : %s\n"), ptResFilePath);
				
		hSearchedResFile = CreateFile(ptResFilePath, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hSearchedResFile == INVALID_HANDLE_VALUE) {
			dwRet = GetLastError();
			_tprintf(_T("CreateFile for %s failed, %d \n"), ptResFilePath, dwRet);
			break;
		}

		char *pLine = buff, *pTemp = buff;
		pTemp = strstr(pLine, "\0");		
		while (pTemp = strstr(pLine, "\r\n")) {
			CHAR szLineBuf[1024] = "";
			*pTemp = '\0';
			strcpy_s(szLineBuf, pLine);	

			// skip unless it's oos log.
			if (strstr(szLineBuf, OOS_TRACE_STRING) == NULL) {
				pLine = pTemp + 2;
				continue;
			}
			
			// write log if given sector is accessed
			dwRet = WriteSearchLogIfMatch(hSearchedResFile, szLineBuf, ullSector);
			if (ERROR_SUCCESS != dwRet) {
				break;
			}
			
			// go next
			pLine = pTemp + 2;
		}

		if (ERROR_SUCCESS != dwRet) {
			break;
		}
				
		if (strchr(pLine, '\0') != NULL) {
			CHAR szLineBuf[1024] = "";			
			strcpy_s(szLineBuf, pLine);
			
			// skip unless it's oos log.
			if (strstr(szLineBuf, OOS_TRACE_STRING) != NULL) {
				// check if given sector is accessed
				WriteSearchLogIfMatch(hSearchedResFile, szLineBuf, ullSector);
			}
		}

	} while (false);

	if (buff) {
		delete(buff);
		buff = NULL;
	}

	if (INVALID_HANDLE_VALUE != hSearchedResFile) {
		CloseHandle(hSearchedResFile);
		hSearchedResFile = INVALID_HANDLE_VALUE;
	}

	if (INVALID_HANDLE_VALUE != hSrcFile) {
		CloseHandle(hSrcFile);
		hSrcFile = INVALID_HANDLE_VALUE;
	}

#else // _LIN
	FILE *src_file;
	FILE *searched_file;
	char result_path[MAX_PATH];
	char sector[128];
	unsigned long long ullSector = atoll((const char*)szSector);

	
	// open log file
	src_file = fopen(pSrcFilePath, "r");
	if(src_file != NULL) {
		char strTemp[MAX_BSRLOG_BUF];
		char *pStr;
		
		strcpy(sector, szSector);
		sprintf(result_path, "%s_sector%s", pSrcFilePath, sector);
		searched_file = fopen(result_path, "w");
		if(searched_file != NULL) {

			// read log file
			while( !feof(src_file) )
			{
				pStr = fgets(strTemp, sizeof(strTemp), src_file);
				if (ferror(src_file)) {
					fprintf(stderr, "failed to read log file.\n");
				}

				if (pStr == NULL)
					break;
				// skip unless it's oos log.
				if (pStr != NULL && strstr(pStr, OOS_TRACE_STRING) == NULL) {
					continue;
				}
				// write log if given sector is accessed
				dwRet = WriteSearchLogIfMatch(searched_file, pStr, ullSector);
				if (ERROR_SUCCESS != dwRet) {
					fprintf(stderr, "failed to write search file.\n");
					break;
				}
			}

			fclose(searched_file);
		} else {
			fprintf(stderr, "failed to create search file.\n");
			dwRet = GetLastError();
		}

		fclose(src_file);
	} else {
		fprintf(stderr, "failed to open log file.\n");
		dwRet = ERROR_FILE_NOT_FOUND;
	}
#endif

	return dwRet;
}

// BSR-1112
DWORD MVOL_BsrLogPathChange()
{
	DWORD retVal = ERROR_SUCCESS;
#ifdef _WIN
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       dwReturned = 0;
	DWORD		dwControlCode = 0;
#else // _LIN
	int fd;
#endif
#ifdef _WIN
	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		fprintf(stderr, "LOG_PATH_ERROR: %s: Failed open bsr. Err=%u\n",
			__FUNCTION__, retVal);
		return retVal;
	}
#else // _LIN
	if ((fd = open(BSR_CONTROL_DEV, O_RDWR)) == -1)
		return 0;
#endif

#ifdef _WIN
	if (DeviceIoControl(hDevice, IOCTL_MVOL_LOG_PATH_CHANGED, NULL, 0, NULL, 0, &dwReturned, NULL) == FALSE) {
#else
	if (ioctl(fd, IOCTL_MVOL_LOG_PATH_CHANGED) != 0) {
#endif
		retVal = GetLastError();
		fprintf(stderr, "LOG_PATH_ERROR: %s: Failed IOCTL_MVOL_LOG_PATH_CHANGED. Err=%u\n",
			__FUNCTION__, retVal);
	}

#ifdef _WIN
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
	}
#else // _LIN
	if (fd)
		close(fd);
#endif
	return retVal;
}