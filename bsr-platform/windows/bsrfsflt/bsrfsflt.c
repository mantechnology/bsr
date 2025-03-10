/*++

Module Name:

    bsrlock.c

Abstract:

    This is the main module of the bsrlock miniFilter driver.

Environment:

    Kernel mode

--*/

#include "pch.h"

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;



/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
bsrlockInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
bsrlockInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
bsrlockInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
bsrlockUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
bsrlockInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
bsrlockPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
bsrlockPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
bsrlockPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

		{ IRP_MJ_CREATE,
		0,
		bsrlockPreOperation,
		bsrlockPostOperation },

		{ IRP_MJ_CLOSE,
		0,
		bsrlockPreOperation,
		bsrlockPostOperation },

		{ IRP_MJ_READ,
		FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO | FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		bsrlockPreOperation,
		bsrlockPostOperation },

		{ IRP_MJ_WRITE,
		FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO | FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
		bsrlockPreOperation,
		bsrlockPostOperation },

		{ IRP_MJ_FILE_SYSTEM_CONTROL,
		0,
		bsrlockPreOperation,
		bsrlockPostOperation },

		// BSR-1152
#if 0
		// DW-1868
		{ IRP_MJ_QUERY_VOLUME_INFORMATION,
		0,
		bsrlockPreOperation,
		bsrlockPostOperation },
#endif
#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_CLOSE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_READ,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_WRITE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_SET_EA,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      bsrlockPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_PNP,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      bsrlockPreOperation,
      bsrlockPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    bsrlockUnload,                           //  MiniFilterUnload

    bsrlockInstanceSetup,                    //  InstanceSetup
    bsrlockInstanceQueryTeardown,            //  InstanceQueryTeardown
    bsrlockInstanceTeardownStart,            //  InstanceTeardownStart
    bsrlockInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
bsrlockInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );
	
    return STATUS_SUCCESS;
}


NTSTATUS
bsrlockInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    return STATUS_SUCCESS;
}


VOID
bsrlockInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
}


VOID
bsrlockInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
}

extern PULONG InitSafeBootMode;

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

	// BSR-511 failure handling in safe mode
	if (*InitSafeBootMode > 0) {
		//1 :SAFEBOOT_MINIMAL
		//2 :SAFEBOOT_NETWORK
		//3 :SAFEBOOT_DSREPAIR
		return STATUS_UNSUCCESSFUL;
	}

	bsrlock_print_log("DriverEntry\n");
	
    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

	if (!NT_SUCCESS(status)) {
		bsrlock_print_log("FltRegisterFilter failed, status : 0x%x\n", status);
		return status;
	}

	status = bsrlockCreateControlDeviceObject(DriverObject);
	if (!NT_SUCCESS(status)) {
		bsrlock_print_log("bsrlockCreateControlDeviceObject failed, status : 0x%x\n", status);
		FltUnregisterFilter(gFilterHandle);
		return status;
	}			

	bsrlockStartupCallback();

	InitVolBlock();

    //
    //  Start filtering i/o
    //
    status = FltStartFiltering( gFilterHandle );

    if (!NT_SUCCESS( status )) {
		bsrlock_print_log("FltStartFiltering failed, status : 0x%x\n", status);
        FltUnregisterFilter( gFilterHandle );
    }   

    return status;
}

NTSTATUS
bsrlockUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );
	
	bsrlock_print_log("Unloading\n");

    FltUnregisterFilter( gFilterHandle );

	CleanupVolBlock();

	bsrlockCleanupCallback();

	bsrlockDeleteControlDeviceObject();

    return STATUS_SUCCESS;
}

#include <ntddk.h>
#include <fltkernel.h>
#include <ntdddisk.h>  

// BSR-1468
NTSTATUS GetPartitionSizeFromVolume(
    _In_ PFLT_VOLUME Volume,
    _Out_ ULONGLONG *PartitionSize
    )
{
    NTSTATUS status;
    PDEVICE_OBJECT diskDeviceObject = NULL;
    IO_STATUS_BLOCK ioStatus;
    KEVENT event;
    PIRP irp = NULL;
    PARTITION_INFORMATION_EX partInfo = {0};  

    status = FltGetDiskDeviceObject(Volume, &diskDeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_DISK_GET_PARTITION_INFO_EX,  
        diskDeviceObject,
        NULL,
        0,
        &partInfo,
        sizeof(partInfo),
        FALSE,
        &event,
        &ioStatus);
    if (irp == NULL) {
        ObDereferenceObject(diskDeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(diskDeviceObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatus.Status;
    }

    if (NT_SUCCESS(status)) {
        *PartitionSize = partInfo.PartitionLength.QuadPart; 
    }

    ObDereferenceObject(diskDeviceObject);
    return status;
}

// BSR-1468
NTSTATUS GetSectorSizeFromVolume(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, ULONG *SectorSize) 
{
  NTSTATUS status;
  DISK_GEOMETRY diskGeometry;
  ULONG bytesReturned;

  status = FltDeviceIoControlFile(Instance, 
                                  FileObject, 
                                  IOCTL_DISK_GET_DRIVE_GEOMETRY, 
                                  NULL, 0, 
                                  &diskGeometry, sizeof(DISK_GEOMETRY), 
                                  &bytesReturned);

  if (NT_SUCCESS(status)) {
      *SectorSize = diskGeometry.BytesPerSector;
      return STATUS_SUCCESS;
  }

  return status;
}


NTSTATUS GetFileSystemSize(PFLT_INSTANCE Instance, ULONGLONG *fsSize) {
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    FILE_FS_SIZE_INFORMATION fsSizeInfo;
    
    status = FltQueryVolumeInformation( Instance,
                                        &ioStatus,             
                                        &fsSizeInfo,            
                                        sizeof(fsSizeInfo),     
                                        FileFsSizeInformation);

    if (NT_SUCCESS(status)) {
       *fsSize = fsSizeInfo.TotalAllocationUnits.QuadPart * fsSizeInfo.SectorsPerAllocationUnit;
        // *fsSize = fsSizeInfo.TotalAllocationUnits.QuadPart * fsSizeInfo.SectorsPerAllocationUnit * fsSizeInfo.BytesPerSector;
        // *freeSpace = fsSizeInfo.AvailableAllocationUnits.QuadPart * fsSizeInfo.SectorsPerAllocationUnit * fsSizeInfo.BytesPerSector;
    } 

    return status;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
bsrlockPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( CompletionContext );

	// DW-1461 fsctl lock requested by bsr may fail due to bsrlock. make bypass operation executed in kernel mode.
	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;

	switch (Data->Iopb->MajorFunction) {
		case IRP_MJ_READ:
		case IRP_MJ_WRITE:
		{			
			NTSTATUS status = STATUS_UNSUCCESSFUL;
			PDEVICE_OBJECT pDiskDev = NULL;

			status = FltGetDiskDeviceObject(FltObjects->Volume, &pDiskDev);
						
			if (NT_SUCCESS(status) &&
				isProtectedVolume(pDiskDev))
			{
				// protect volume
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;

				return FLT_PREOP_COMPLETE;
			}
		}
		case IRP_MJ_FILE_SYSTEM_CONTROL:
		{
			if (Data->Iopb->Parameters.FileSystemControl.Direct.FsControlCode == FSCTL_EXTEND_VOLUME) {
				NTSTATUS status = STATUS_UNSUCCESSFUL;
				PDEVICE_OBJECT pDiskDev = NULL;

				status = FltGetDiskDeviceObject(FltObjects->Volume, &pDiskDev);

				if (NT_SUCCESS(status)) {
          ULONGLONG partitionSize = 0;
          ULONG sectorSize = 0;
          ULONGLONG partitionPerSector = 0;
          NTSTATUS callBsrResize = STATUS_UNSUCCESSFUL;
          ULONGLONG extendSize = 0;
          ULONGLONG currentFsSize = 0;

          if(Data->Iopb->Parameters.FileSystemControl.Direct.InputSystemBuffer != NULL) {
            extendSize = *(ULONGLONG*)Data->Iopb->Parameters.FileSystemControl.Direct.InputSystemBuffer;
            status = GetPartitionSizeFromVolume(FltObjects->Volume, &partitionSize);
            if(NT_SUCCESS(status)) {
              status = GetSectorSizeFromVolume(FltObjects->Instance, Data->Iopb->TargetFileObject, &sectorSize);
              if(NT_SUCCESS(status)) {
                status = GetFileSystemSize(FltObjects->Instance, &currentFsSize);
                if(NT_SUCCESS(status)) {
                  partitionPerSector = partitionSize / sectorSize;
                  CustomBsrLog("%s, current fs size : %llus, extend size : %llus, partition size : %llus, sector size : %u", 
                    __FUNCTION__ , currentFsSize, extendSize, partitionPerSector, sectorSize);
                  if(partitionPerSector != 0 && extendSize == partitionPerSector && currentFsSize != extendSize) {
                    // BSR-1468 resize bsr only when the file system size is equal to the partition size.
                    callBsrResize = STATUS_SUCCESS;
                  }
                } else {
                  CustomBsrLog("%s, Failed to current file system size %x, %llus, %llu, %u", __FUNCTION__, status, extendSize, partitionSize, sectorSize);
                  partitionPerSector = partitionSize / sectorSize;
                  if(extendSize == partitionPerSector)
                   callBsrResize = STATUS_SUCCESS;
                }
              } else {
                CustomBsrLog("%s, Failed to partition size %x, %llus, %llu", __FUNCTION__, status, extendSize, partitionSize);
                callBsrResize = STATUS_SUCCESS;
              }
            } else {
              CustomBsrLog("%s, Failed to volume sector size %x, %llus", __FUNCTION__, status, extendSize);
              callBsrResize = STATUS_SUCCESS;
            }
            if(NT_SUCCESS(callBsrResize))
              ResizeBsrVolume(pDiskDev);
          } else 
           CustomBsrLog("%s, Input buffer empty", __FUNCTION__);
				} else {
          CustomBsrLog("%s, Failed to obtain device object from disk %x", __FUNCTION__, status);
        }
			}
			break;
		}
		// BSR-1152 restore because the VSS operates abnormally due to modifications that prevent volume expansion/shrinkage. 
#if 0
		case IRP_MJ_QUERY_VOLUME_INFORMATION:
		{
			NTSTATUS status = STATUS_UNSUCCESSFUL;
			PDEVICE_OBJECT pDiskDev = NULL;

			status = FltGetDiskDeviceObject(FltObjects->Volume, &pDiskDev);

			if (NT_SUCCESS(status) &&
				isProtectedVolume(pDiskDev))
			{
				// DW-1868 set up STAUS_ACCESS_DENIED for the IRP_MJ_QUERY_VOLUME_INFORMATION code to prevent the use of volume expansion/shrinkage 
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;

				return FLT_PREOP_COMPLETE;
			}
			break;
		}
#endif
	}

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
bsrlockPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );
	    
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
bsrlockPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

void bsrlock_print_log(const char * format, ...)
/*++

Routine Description:

	appends bsrlock prefix and print log.

Arguments:

	format - print format for log.

Return Value:

	None

--*/
{
	char szTemp[BSRLOCK_LOG_MAXLEN] = BSRLOCK_LOG_PREFIX;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	va_list args;
	va_start(args, format);
	status = RtlStringCchVPrintfA(szTemp + strlen(BSRLOCK_LOG_PREFIX), BSRLOCK_LOG_MAXLEN, format, args);
	va_end(args);

	if (NT_SUCCESS(status))
		KdPrint((szTemp));
}