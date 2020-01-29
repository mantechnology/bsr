#include "bsrfsflt_struct.h"

#define BSRLOCK_DEVICE_OBJECT_NAME	L"\\Device\\bsrfsflt"
#define BSRLOCK_SYMLINK_NAME		L"\\DosDevices\\bsrfsflt"
#define BSRLOCK_CALLBACK_NAME		L"\\Callback\\bsrfsflt"

#define BSR_CALLBACK_NAME		L"\\Callback\\bsr"

#define BSRLOCK_DEVICE_NAME_USER	"\\\\.\\bsrfsflt"

#define	BSRLOCK_TYPE		0x9801

#define IOCTL_BSRLOCK_GET_STATUS CTL_CODE(BSRLOCK_TYPE, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _BSRLOCK_VOLUME_CONTROL
{
	BSRLOCK_VOLUME volume;
	BOOLEAN bBlock;
}BSRLOCK_VOLUME_CONTROL, *PBSRLOCK_VOLUME_CONTROL;


typedef struct _BSR_VOLUME_CONTROL
{
	PVOID pVolumeObject;
}BSR_VOLUME_CONTROL, *PBSR_VOLUME_CONTROL;