#include "bsrmon.h"
#include "monitor_collect.h"
#ifdef _WIN
#include <Psapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#endif

#ifdef _LIN
unsigned long long GetSlabMemoryUsage(enum slab_type slab)
{
	char buff[512];
	FILE *fp;
	char path[128];
	int i = 0;
	unsigned long long object_size = 0, total_objects = 0;

	fp = popen("cat /proc/slabinfo", "r");
	if(NULL == fp) {
		bsrmon_log(stderr, "popen 'cat /proc/slabinfo' error\n");
		return 0;
	}

	while(fgets(buff, 1024, fp)) {
		char *ptr = strtok(buff, " "); 
		int index;

		if (ptr != NULL) {
			if (slab == BSR_REQ) {
				if(strcmp(ptr, "bsr_req") != 0)
					continue;
			} else if (slab == BSR_AL) {
				if(strcmp(ptr, "bsr_al") != 0)
					continue;
			} else if (slab == BSR_BM) {
				if(strcmp(ptr, "bsr_bm") != 0)
					continue;
			} else if (slab == BSR_EE) {
				if(strcmp(ptr, "bsr_ee") != 0)
					continue;
			} else {
				bsrmon_log(stderr, "Invalid slab type\n");
				pclose(fp); // BSR-1138 fix handle leak
				return 0;
			}

			index = 0;

			while (ptr != NULL)              
			{ 
				if (index == 2) {
					total_objects = atoi(ptr); 
				}
				else if (index == 3) {
					object_size = atoi(ptr); 
					pclose(fp); // BSR-1138 fix handle leak
					return total_objects * object_size / 1024;
				}   
				ptr = strtok(NULL, " ");     
				index++;
			}
		}
	}

	pclose(fp); // BSR-1138 fix handle leak

	for (i = 0; i < 2; i++) {
		if (slab == BSR_REQ) {
			if (i == 0)
				sprintf(path, "%s/bsr_req/object_size", SLAB_ROOT);
			else
				sprintf(path, "%s/bsr_req/total_objects", SLAB_ROOT);
		}
		else if (slab == BSR_AL) {
			if (i == 0)
				sprintf(path, "%s/bsr_al/object_size", SLAB_ROOT);
			else
				sprintf(path, "%s/bsr_al/total_objects", SLAB_ROOT);
		}
		else if (slab == BSR_BM) {
			if (i == 0)
				sprintf(path, "%s/bsr_bm/object_size", SLAB_ROOT);
			else
				sprintf(path, "%s/bsr_bm/total_objects", SLAB_ROOT);
		}
		else if (slab == BSR_EE) {
			if (i == 0)
				sprintf(path, "%s/bsr_ee/object_size", SLAB_ROOT);
			else
				sprintf(path, "%s/bsr_ee/total_objects", SLAB_ROOT);
		}
		else {
			bsrmon_log(stderr, "Invalid slab type\n");
			return 0;
		}

		fp = fopen(path, "r");
		if (!fp) {
			bsrmon_log(stderr, "Failed to open file, path : %s\n", path);
			return 0;
		}
		fread(buff, 128, 1, fp);
		fclose(fp);

		if (i == 0)
			object_size = atoi(buff);
		else
			total_objects = atoi(buff);
	}

	return object_size * total_objects / 1024;
}
#endif

#ifdef _LIN
// BSR-875 collect system memory usage
char* GetSysMemoryUsage(void)
{
	unsigned long long mem_total = 0, mem_free = 0, mem_buff_cache = 0, mem_used = 0;
	char *buffer;
	FILE *fp;
	char line[128];

	buffer = (char*)malloc(MAX_BUF_SIZE);
	if (!buffer) {
		bsrmon_log(stderr, "Failed to malloc buffer\n");
		return NULL;
	}
	memset(buffer, 0, MAX_BUF_SIZE);
	
	fp = popen("cat /proc/meminfo | awk '{print $1 $2}'", "r");

	if(NULL == fp) {
		bsrmon_log(stderr, "popen 'cat /proc/meminfo' error\n");
		return NULL;
	}

	while (fgets(line, sizeof(line), fp) != NULL){
		char *name_ptr, *val_ptr;
		name_ptr = strtok(line, ":");
		val_ptr = strtok(NULL, " ");

		if (strncmp(name_ptr, "MemTotal", 8) == 0)
			mem_total = atoi(val_ptr);
		else if (strncmp(name_ptr, "MemFree", 7) == 0)
			mem_free = atoi(val_ptr);
		else if (strncmp(name_ptr, "Buffer", 6) == 0)
			mem_buff_cache += atoi(val_ptr);
		else if (strncmp(name_ptr, "Cached", 6) == 0)
			mem_buff_cache += atoi(val_ptr);
		// cache : Memory used by the page cache and slabs (Cached and SReclaimable in /proc/meminfo)
		else if (strncmp(name_ptr, "SReclaimable", 12) == 0)
			mem_buff_cache += atoi(val_ptr);
//		else if (strncmp(name_ptr, "Slab", 4) == 0)
//			total_slab = atoi(val_ptr);
	}
	pclose(fp); // BSR-1138 fix handle leak

	mem_used = mem_total - mem_free - mem_buff_cache;

	/* MemTotal MemUsed MemFree buff/cache (kbytes) */
	sprintf(buffer, "%llu %llu %llu %llu ", 
			mem_total, mem_used, mem_free, mem_buff_cache);


	return buffer;
}
#endif

#ifdef _WIN
#include "module_debug.h"
#include "../../../bsr-headers/windows/ioctl.h"

DWORD MVOL_GetUntagMemoryUsage(LONGLONG *untagMemUsage)
{
	HANDLE      hDevice = INVALID_HANDLE_VALUE;
	DWORD       retVal = ERROR_SUCCESS;
	BOOL        ret = FALSE;
	DWORD       dwReturned = 0;

	hDevice = OpenDevice(MVOL_DEVICE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		retVal = GetLastError();
		return retVal;
	}

	ret = DeviceIoControl(hDevice, IOCTL_MVOL_GET_UNTAG_MEM_USAGE, NULL, 0, untagMemUsage, sizeof(*untagMemUsage), &dwReturned, NULL);
	if (ret == FALSE) {
		retVal = GetLastError();
	}

	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice); // BSR-1138 fix handle leak
	}

	return retVal;
}

#endif
char* GetBsrMemoryUsage(bool printTag)
{
#ifdef _WIN
	DWORD dwSize = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PSYSTEM_POOLTAG_INFORMATION pSysPoolTagInfo = NULL;
	PSYSTEM_POOLTAG psysPoolTag = NULL;
	ULONG_PTR NonPagedUsed = 0, PagedUsed = 0, TotalUsed = 0;
	MEMORYSTATUSEX global;
	int try_cnt = 0;
#else // _LIN
	unsigned long long req_usage = 0, al_usage = 0, bm_usage = 0, ee_usage = 0;
#endif
	char *buffer = NULL;

	if (!printTag) {
		buffer = (char*)malloc(MAX_BUF_SIZE);
		if (!buffer) {
			bsrmon_log(stderr, "Failed to malloc buffer\n");
			return buffer;
		}
		memset(buffer, 0, MAX_BUF_SIZE);
	}
#ifdef _WIN
	do{
		status = ZwQuerySystemInformation(SystemPoolTagInformation, pSysPoolTagInfo, dwSize, &dwSize);
		try_cnt++;

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			if (pSysPoolTagInfo != NULL)
			{
				free(pSysPoolTagInfo);
				pSysPoolTagInfo = NULL;
			}

			pSysPoolTagInfo = (PSYSTEM_POOLTAG_INFORMATION)malloc(dwSize);

			if (pSysPoolTagInfo != NULL)
				memset(pSysPoolTagInfo, 0, dwSize);
			else {
				bsrmon_log(stderr, "Failed to malloc pSysPoolTagInfo\n");
				goto fail;
			}
		}

	} while (status != STATUS_SUCCESS && try_cnt < 3);

	if (status != STATUS_SUCCESS) {
		bsrmon_log(stderr, "Failed to ZwQuerySystemInformation, status: %ld\n", status);
		goto fail;
	}

	// found all Pool tag.
	psysPoolTag = (PSYSTEM_POOLTAG)&pSysPoolTagInfo->TagInfo->Tag;
	ULONG count = pSysPoolTagInfo->Count;

	for (ULONG i = 0; i < count; i++)
	{
		// tag check if "BSxx"
		if (psysPoolTag->Tag[0] != 'B' || psysPoolTag->Tag[1] != 'S') {
			psysPoolTag++;
			continue;
		}

		if (psysPoolTag->NonPagedUsed != 0)
		{
			NonPagedUsed += psysPoolTag->NonPagedUsed;
			TotalUsed += psysPoolTag->NonPagedUsed;
			if (printTag)
				printf("nonPaged:%s, allocate %lu, used %llu, free %lu\n", psysPoolTag->Tag, psysPoolTag->NonPagedAllocs, psysPoolTag->NonPagedUsed, psysPoolTag->NonPagedFrees);
		}
		
		if (psysPoolTag->PagedUsed != 0)
		{
			PagedUsed += psysPoolTag->PagedUsed;
			TotalUsed += psysPoolTag->PagedUsed;
			if (printTag)
				printf("paged:%s, allocate %lu, used %llu, free %lu\n", psysPoolTag->Tag, psysPoolTag->PagedAllocs, psysPoolTag->PagedUsed, psysPoolTag->PagedFrees);
		}

		psysPoolTag++;
	}

	LONGLONG UntagNonPagedUsed = 0;
	DWORD ret;

	ret = MVOL_GetUntagMemoryUsage(&UntagNonPagedUsed);
	if (ret != ERROR_SUCCESS) {
		bsrmon_log(stderr, "Failed to get untag memory usage, ret: %x\n", ret);
		goto fail;
	}

	TotalUsed += UntagNonPagedUsed;

	global.dwLength = sizeof(MEMORYSTATUSEX);
	if (0 == GlobalMemoryStatusEx(&global)) {
		bsrmon_log(stderr, "Failed to global memory status\n");
		goto fail;
	}

	if (!printTag) {
		// total memory, total memory usage
		sprintf_s(buffer, MAX_BUF_SIZE, "%lld %lld ", global.ullTotalPhys, global.ullTotalPhys - global.ullAvailPhys);

		/* TotalUsed(bytes) NonPagedUsed(bytes) PagedUsed(bytes) */
		sprintf_s(buffer + strlen(buffer), MAX_BUF_SIZE - strlen(buffer), "%llu %llu %llu %lld ", TotalUsed, NonPagedUsed, PagedUsed, UntagNonPagedUsed);
	} else {
		printf("total %llu, total nonpaged %llu, total paged %llu, total untaged %llu\n", TotalUsed, NonPagedUsed, PagedUsed, UntagNonPagedUsed);
	}

	if (NULL != pSysPoolTagInfo) {
		free(pSysPoolTagInfo);
		pSysPoolTagInfo = NULL;
	}

	return buffer;

fail:
	if (pSysPoolTagInfo)
	{
		free(pSysPoolTagInfo);
		pSysPoolTagInfo = NULL;
	}

	if (!printTag) {
		if (buffer) {
			free(buffer);
			buffer = NULL;
		}
	}
	return NULL;
#else // _LIN
	req_usage = GetSlabMemoryUsage(BSR_REQ);
	al_usage = GetSlabMemoryUsage(BSR_AL);
	bm_usage = GetSlabMemoryUsage(BSR_BM);
	ee_usage = GetSlabMemoryUsage(BSR_EE);

	/* BSR_REQ BSR_AL BSR_BM BSR_EE (kbytes) */
	sprintf(buffer, "%llu %llu %llu %llu ", req_usage, al_usage, bm_usage, ee_usage);


	return buffer;
#endif
}

#ifdef _LIN
// BSR-875
char* GetBsrModuleMemoryUsage(void)
{
	char *buffer;
	char path[128] = {0,};
	FILE *fp;

	buffer = (char*)malloc(MAX_BUF_SIZE);
	if (!buffer) {
		bsrmon_log(stderr, "Failed to malloc buffer\n");
		return NULL;
	}
	memset(buffer, 0, MAX_BUF_SIZE);
		
	sprintf(path, "%s/alloc_mem", DEBUGFS_ROOT);
	fp = fopen(path, "r");
	if (!fp) {
		bsrmon_log(stderr, "Failed to open file, path : %s\n", path);
		return NULL;
	}
	fread(buffer, 128, 1, fp);
	fclose(fp);
	// remove EOL
	*(buffer + (strlen(buffer) - 1)) = ' ';
	return buffer;

}
#endif

#ifdef _LIN
void read_top_mem_usage_process(FILE *pipe, char *buf, char *buffer) {
	if (buf[strlen(buf) - 1] == '\n' || buf[strlen(buf) - 1] == ' ')
		buf[strlen(buf) - 1] = 0;

	/* name pid rsz(kbytes) vsz(kbytes) */
	sprintf(buffer + strlen(buffer), "%s ", buf);
} 

void read_bsr_process(FILE *pipe, char *buf, char *buffer) {
	unsigned int pid, rsz, vsz;
	char *ptr, *save_ptr;
	int idx = 0;

	ptr = strtok_r(buf, " ", &save_ptr);

	while(ptr) {
		if (idx == 0)
			pid = atoi(ptr);
		else if (idx == 1)
			rsz = atoi(ptr);
		else if (idx == 2)
			vsz = atoi(ptr);
		else
			break;
		idx++;

		ptr = strtok_r(NULL, " ", &save_ptr);
	}

	if (strncmp(ptr, "bsr", 3))
		return;

	if (ptr[strlen(ptr) - 1] == '\n' || ptr[strlen(ptr) - 1] == ' ')
		ptr[strlen(ptr) - 1] = 0;

	/* name pid rsz(kbytes) vsz(kbytes) */
	sprintf(buffer + strlen(buffer), "%s %d %u %u ", ptr, pid, rsz, vsz);
		
}

bool pipe_run(const char* command, char* buffer, void(*pp_read)(FILE *, char *, char *))
{
	FILE *pipe = popen(command, "r");
	bool remained = false;
	char buf[128] = { 0, };

	if (!pipe) {
		bsrmon_log(stderr, "Failed to execute command : %s\n", command);
		return false;
	}

	while (!feof(pipe)) {
		if (remained) {
			if (fgets(buf, sizeof(buf), pipe) != NULL) {
				if (buf[strlen(buf) - 1] == '\n') {
					remained = false;
				}
				continue;
			}
		}

		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), pipe) != NULL) {
			if (buf[strlen(buf) - 1] != '\n') {
				remained = true;
			}
			pp_read(pipe, buf, buffer);
		}
	}
	pclose(pipe);

	return true;
}
#endif 

char* GetBsrUserMemoryUsage(void)
{
#ifdef _WIN
	HANDLE process;
	PROCESS_MEMORY_COUNTERS info = { 0 };
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	TCHAR szProcessName[1024] = { 0, };
	TCHAR fileName[128];
	DWORD dwLen = 0;
	SIZE_T usage = 0;
	TCHAR szName[1024] = { 0, };
	char topProcess[256] = { 0, };
#endif
	char *buffer;

	buffer = (char*)malloc(MAX_BUF_SIZE);
	if (!buffer) {
		bsrmon_log(stderr, "Failed to malloc buffer\n");
		return NULL;
	}
	memset(buffer, 0, MAX_BUF_SIZE);

#ifdef _WIN
	info.cb = sizeof(info);
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)){
		bsrmon_log(stderr, "Failed to get processid list\n");
		goto fail;
	}
	cProcesses = cbNeeded / sizeof(DWORD);

	for (unsigned int i = 0; i < cProcesses; i++) {
		process = OpenProcess(MAXIMUM_ALLOWED, false, aProcesses[i]);
		if (NULL != process) {
			dwLen = sizeof(szProcessName) / sizeof(TCHAR);
			if (QueryFullProcessImageName(process, 0, szProcessName, &dwLen)) {
				// Get file name from full path
				_wsplitpath_s(szProcessName, NULL, 0, NULL, 0, fileName, 128, NULL, 0);
			}
		}

		GetProcessMemoryInfo(process, &info, sizeof(info));

		if (usage < info.WorkingSetSize) {
			usage = info.WorkingSetSize;
			_tcsncpy_s(szName, _countof(szName), fileName, _countof(szName) - 1);
		}

		if (wcsncmp(fileName, L"bsr", 3)) {
			CloseHandle(process); // BSR-1138 fix handle leak
			continue;
		}
		/* name pid WorkingSetSize QuotaPagedPoolUsage QuotaNonPagedPoolUsage PagefileUsage (bytes)*/
		sprintf_s(buffer + strlen(buffer), MAX_BUF_SIZE - strlen(buffer),
			"%ws %wu %llu %llu %llu %llu ",
			fileName, aProcesses[i], info.WorkingSetSize, info.QuotaPagedPoolUsage, info.QuotaNonPagedPoolUsage, info.PagefileUsage);

		CloseHandle(process);
	}
	// top process name, top process memory usage
	sprintf_s(topProcess, sizeof(topProcess), "%ws %llu ", szName, usage);
	memmove(buffer + strlen(topProcess), buffer, strlen(buffer));
	memcpy(buffer, topProcess, strlen(topProcess));

	return buffer;
#else // _LIN

	// BSR-875 get top process
	if (!pipe_run("ps -eo comm,pid,rsz,vsz --sort -rsz --no-headers | head -1 | awk '{ gsub(/[ ]+/,\" \"); print }'", buffer, read_top_mem_usage_process))
		goto fail;

	if (!pipe_run("ps -eo pid,rsz,vsz,cmd | grep bsr", buffer, read_bsr_process))
		goto fail;

	return buffer;
#endif
fail:
	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
	return NULL;
}