#ifdef _WIN
#include <Shlwapi.h>
#endif

#ifdef _WIN
#define SystemPoolTagInformation (DWORD)0x16
#define STATUS_SUCCESS 0
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#else // _LIN
enum slab_type
{
	BSR_REQ,
	BSR_AL,
	BSR_BM,
	BSR_EE,
};
#define SLAB_ROOT "/sys/kernel/slab"
#define DEBUGFS_ROOT "/sys/kernel/debug/bsr"
#endif


#ifdef _WIN
typedef struct _SYSTEM_POOLTAG
{
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
	};
	ULONG PagedAllocs;
	ULONG PagedFrees;
	SIZE_T PagedUsed;
	ULONG NonPagedAllocs;
	ULONG NonPagedFrees;
	SIZE_T NonPagedUsed;

}SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
	ULONG Count;
	SYSTEM_POOLTAG TagInfo[ANYSIZE_ARRAY];

}SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

#pragma comment( lib, "ntdll.lib" )

extern "C" NTSYSAPI NTSTATUS WINAPI ZwQuerySystemInformation(
	_In_      ULONG		SystemInformationClass,
	_Inout_   PVOID     SystemInformation,
	_In_      ULONG     SystemInformationLength,
	_Out_opt_ PULONG    ReturnLength);
#endif

#ifdef _LIN
unsigned long long GetSlabMemoryUsage(enum slab_type slab);
char* GetSysMemoryUsage(void);
char* GetBsrModuleMemoryUsage(void);
#endif
char* GetBsrMemoryUsage(void);
char* GetBsrUserMemoryUsage(void);