#include "monitor_collect.h"

#ifdef _LIN
unsigned long long GetSlabMemoryUsage(enum slab_type slab)
{
	char path[128];
	unsigned long long object_size, total_objects;
	FILE *fp;
	char file_buf[128];
	int i = 0;

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
			fprintf(stderr, "Invalid slab type\n");
			return -1;
		}

		fp = fopen(path, "r");
		if (!fp) {
			fprintf(stderr, "fopen failed, path : %s\n", path);
			return -1;
		}
		fread(file_buf, 128, 1, fp);
		fclose(fp);

		if (i == 0)
			object_size = atoi(file_buf);
		else
			total_objects = atoi(file_buf);
	}

	return object_size * total_objects;
}
#endif

char* GetBsrMemoryUsage(void)
{
#ifdef _WIN
	DWORD dwSize = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PSYSTEM_POOLTAG_INFORMATION pSysPoolTagInfo = NULL;
	PSYSTEM_POOLTAG psysPoolTag = NULL;
	ULONG_PTR NonPagedUsed = 0, PagedUsed = 0, TotalUsed = 0;
	int try_cnt = 0;
#else // _LIN
	unsigned long long req_usage = 0, al_usage = 0, bm_usage = 0, ee_usage = 0;
#endif
	char *buffer;

	buffer = (char*)malloc(MAX_BUF_SIZE);
	if (!buffer) {
		fprintf(stderr, "Failed to malloc buffer\n");
		return NULL;
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
				fprintf(stderr, "Failed to malloc pSysPoolTagInfo\n");
				goto fail;
			}
		}

	} while (status != STATUS_SUCCESS && try_cnt < 3);

	if (status != STATUS_SUCCESS) {
		fprintf(stderr, "Failed to ZwQuerySystemInformation, status: %ld\n", status);
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

		if (psysPoolTag->NonPagedAllocs != 0)
		{
			NonPagedUsed += psysPoolTag->NonPagedUsed;
			TotalUsed += psysPoolTag->NonPagedUsed;
		}
		else
		{
			PagedUsed += psysPoolTag->PagedUsed;
			TotalUsed += psysPoolTag->PagedUsed;
		}

		psysPoolTag++;
	}

	sprintf_s(buffer, MAX_BUF_SIZE, "TotalUsed: %13llu bytes\nNonPagedUsed: %10llu bytes\nPagedUsed: %13llu bytes\n", TotalUsed, NonPagedUsed, PagedUsed);

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

	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
	return NULL;
#else // _LIN
	req_usage = GetSlabMemoryUsage(BSR_REQ);
	al_usage = GetSlabMemoryUsage(BSR_AL);
	bm_usage = GetSlabMemoryUsage(BSR_BM);
	ee_usage = GetSlabMemoryUsage(BSR_EE);

	sprintf(buffer, "BSR_REQ: %10llu bytes\nBSR_AL: %11llu bytes\nBSR_BM: %11llu bytes\nBSR_EE: %11llu bytes\n", req_usage, al_usage, bm_usage, ee_usage);

	return buffer;
#endif
}