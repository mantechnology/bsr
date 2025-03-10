

NTSTATUS
bsrlockCreateControlDeviceObject(
	IN PDRIVER_OBJECT pDrvObj
	);

VOID
bsrlockDeleteControlDeviceObject(
	VOID
	);

VOID
bsrlockCallbackFunc(
	IN PVOID Context,
	IN PVOID Argument1,
	IN PVOID Argument2
	);

NTSTATUS
bsrlockStartupCallback(
	VOID
	);

VOID
bsrlockCleanupCallback(
	VOID
	);

NTSTATUS
DefaultIrpDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	);

NTSTATUS
DeviceIoControlDispatch(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
	);

NTSTATUS 
ResizeBsrVolume(
	PDEVICE_OBJECT pDeviceObject
	);

NTSTATUS 
	CustomBsrLog(
	const char * format, 
	...
)	;