#pragma warning (disable : 4127)

VOID
InitVolBlock(
	VOID
	);

VOID
CleanupVolBlock(
	VOID
	);

BOOLEAN
AddProtectedVolume(
	PVOID pVolumeObject
	);

BOOLEAN
DeleteProtectedVolume(
	PVOID pVolumeObject
	);

BOOLEAN
isProtectedVolume(
	IN PVOID pVolume
	);

NTSTATUS
ConvertVolume(
	IN PBSRLOCK_VOLUME pVolumeInfo,
	OUT PDEVICE_OBJECT *pConverted
	);
