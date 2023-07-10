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

#include "../../../bsr/bsr_int.h"
#include <wdm.h>
#include <ntstrsafe.h>
#include <ntddk.h>
#include <ntddvol.h>
#include "../../../bsr/bsr-kernel-compat/windows/bsr_windows.h"
#include "../../../bsr/bsr-kernel-compat/windows/bsr_wingenl.h"	
#include "disp.h"
#include "bsrvfltmsg.h"
#include "proto.h"

#include "../../../bsr/bsr_debugfs.h"
#include "../../../bsr/bsr-kernel-compat/bsr_wrappers.h"

#ifdef _WIN_WPP
#include "disp.tmh"
#endif


DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD mvolUnload;
DRIVER_ADD_DEVICE mvolAddDevice;


_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH mvolCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH mvolClose;
_Dispatch_type_(IRP_MJ_SHUTDOWN) DRIVER_DISPATCH mvolShutdown;
_Dispatch_type_(IRP_MJ_FLUSH_BUFFERS) DRIVER_DISPATCH mvolFlush;
_Dispatch_type_(IRP_MJ_POWER) DRIVER_DISPATCH mvolDispatchPower;
_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL) DRIVER_DISPATCH mvolSystemControl;
_Dispatch_type_(IRP_MJ_READ) DRIVER_DISPATCH mvolRead;
_Dispatch_type_(IRP_MJ_WRITE) DRIVER_DISPATCH mvolWrite;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH mvolDeviceControl;
_Dispatch_type_(IRP_MJ_PNP) DRIVER_DISPATCH mvolDispatchPnp;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, _QueryVolumeNameRegistry)
#endif


NTSTATUS
mvolRunIrpSynchronous(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

extern PULONG InitSafeBootMode;
atomic_t64 g_untagged_mem_usage = 0;

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS            		status;
    PDEVICE_OBJECT      		deviceObject;
    PROOT_EXTENSION			RootExtension = NULL;
    UNICODE_STRING      		nameUnicode, linkUnicode;
    ULONG				i;

	// BSR-579 change location because it is used by log_consumer_thread()
	KeInitializeMutex(&mvolMutex, 0);

	// DW-1961 The frequency of the performance counter is fixed at system boot and is consistent across all processors. 
	// Therefore, driver cache the frequency of the performance counter during initialization.
	KeQueryPerformanceCounter(&g_frequency);

	atomic_set64(&g_untagged_mem_usage, 0);

	init_logging();
	// init logging system first
	bsr_logger_init();
	

    bsr_debug(99, BSR_LC_DRIVER, NO_OBJECT,"MVF Driver Loading...");

    initRegistry(RegistryPath);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = mvolSendToNextDriver;


	// BSR-511 call mvolSendToNextdriver in safe mode
	if (*InitSafeBootMode > 0) {
		bsr_info(82, BSR_LC_DRIVER, NO_OBJECT, "Booted to safe mode %u", *InitSafeBootMode);
	}
	else {
		DriverObject->MajorFunction[IRP_MJ_CREATE] = mvolCreate;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = mvolClose;
		DriverObject->MajorFunction[IRP_MJ_READ] = mvolRead;
		DriverObject->MajorFunction[IRP_MJ_WRITE] = mvolWrite;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = mvolDeviceControl;
		DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = mvolShutdown;
		DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = mvolFlush;
		DriverObject->MajorFunction[IRP_MJ_PNP] = mvolDispatchPnp;
		DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = mvolSystemControl;
		DriverObject->MajorFunction[IRP_MJ_POWER] = mvolDispatchPower;
	}

    DriverObject->DriverExtension->AddDevice = mvolAddDevice;
    DriverObject->DriverUnload = mvolUnload;

	gbShutdown = FALSE;
		
    RtlInitUnicodeString(&nameUnicode, L"\\Device\\mvolBsrCtrl");
    status = IoCreateDevice(DriverObject, sizeof(ROOT_EXTENSION),
        &nameUnicode, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
		bsr_err(2, BSR_LC_DRIVER, NO_OBJECT, "Failed to initialization bsr driver due to can't create root device, err(%x)", status);
        return status;
    }

    RtlInitUnicodeString(&linkUnicode, L"\\DosDevices\\mvolBsrCtrl");
    status = IoCreateSymbolicLink(&linkUnicode, &nameUnicode);
    if (!NT_SUCCESS(status)) {
		bsr_err(3, BSR_LC_DRIVER, NO_OBJECT, "Failed to initialization bsr driver due to can't create symbolic link, err(%x)", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    mvolDriverObject = DriverObject;
    mvolRootDeviceObject = deviceObject;

    RootExtension = deviceObject->DeviceExtension;
    RootExtension->Magic = MVOL_MAGIC;
    RootExtension->Head = NULL;
    RootExtension->Count = 0;
	ucsdup(&RootExtension->RegistryPath, RegistryPath->Buffer, RegistryPath->Length);
    RootExtension->PhysicalDeviceNameLength = nameUnicode.Length * sizeof(WCHAR);
    RtlCopyMemory(RootExtension->PhysicalDeviceName, nameUnicode.Buffer, nameUnicode.Length);

    KeInitializeSpinLock(&mvolVolumeLock);
    KeInitializeMutex(&eventlogMutex, 0);
	downup_rwlock_init(&transport_classes_lock); //init spinlock for transport 
	
#ifdef _WIN_WPP
	WPP_INIT_TRACING(DriverObject, RegistryPath);
	DoTraceMessage(TRCINFO, "BSR V9(1:1) MVF Driver loaded.");
#endif

	bsrStartupCallback();
    // Init BSR engine
    bsr_init();

	bsr_info(4, BSR_LC_DRIVER, NO_OBJECT, "BSR MVF Driver loaded.");

    return STATUS_SUCCESS;
}

VOID
mvolUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
#ifdef _WIN_WPP
	WPP_CLEANUP(DriverObject);
#endif
	bsr_logger_cleanup();
	bsrCleanupCallback();
	clean_logging();
	WskPutNPI();
}

NTSTATUS _QueryVolumeNameRegistry(
	_In_ PMOUNTDEV_UNIQUE_ID pmuid,
	_Out_ PVOLUME_EXTENSION pvext)
{
	OBJECT_ATTRIBUTES           attributes;
	PKEY_FULL_INFORMATION       keyInfo = NULL;
	PKEY_VALUE_FULL_INFORMATION valueInfo = NULL;
	size_t                      valueInfoSize = sizeof(KEY_VALUE_FULL_INFORMATION) + 1024 + sizeof(ULONGLONG);

	UNICODE_STRING mm_reg_path;
	NTSTATUS status;
	HANDLE hKey = NULL;
	ULONG size;
	int Count;

	PAGED_CODE();

	RtlUnicodeStringInit(&mm_reg_path, L"\\Registry\\Machine\\System\\MountedDevices");

	InitializeObjectAttributes(&attributes,
		&mm_reg_path,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenKey(&hKey, KEY_READ, &attributes);
	if (!NT_SUCCESS(status)) {
		goto cleanup;
	}

	status = ZwQueryKey(hKey, KeyFullInformation, NULL, 0, &size);
	if (status != STATUS_BUFFER_TOO_SMALL) {
		ASSERT(!NT_SUCCESS(status));
		goto cleanup;
	}

	keyInfo = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, size, '00SB');
	if (!keyInfo) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}

	status = ZwQueryKey(hKey, KeyFullInformation, keyInfo, size, &size);
	if (!NT_SUCCESS(status)) {
		goto cleanup;
	}

	Count = keyInfo->Values;

	valueInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoSize, '10SB');
	if (!valueInfo) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}

	for (int i = 0; i < Count; ++i) {
		RtlZeroMemory(valueInfo, valueInfoSize);

		status = ZwEnumerateValueKey(hKey, i, KeyValueFullInformation, valueInfo, (ULONG)valueInfoSize, &size);
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
				goto cleanup;
			}
		}

		if (REG_BINARY == valueInfo->Type && pmuid->UniqueIdLength == valueInfo->DataLength) {
			PWCHAR key = ExAllocatePoolWithTag(PagedPool, valueInfo->NameLength + sizeof(WCHAR), '20SB');
			if (!key) {
				goto cleanup;
			}
			RtlZeroMemory(key, valueInfo->NameLength + sizeof(WCHAR));
			RtlCopyMemory(key, valueInfo->Name, valueInfo->NameLength);

			if (((SIZE_T)pmuid->UniqueIdLength == RtlCompareMemory(pmuid->UniqueId, (PCHAR)valueInfo + valueInfo->DataOffset, pmuid->UniqueIdLength))) {
				if (wcsstr(key, L"\\DosDevices\\")) {
					// BSR-109
					memset(pvext->MountPoint, 0, sizeof(pvext->MountPoint));
					memcpy(pvext->MountPoint, L" :", 4);
					pvext->MountPoint[0] = (WCHAR)toupper((CHAR)(*(key + wcslen(L"\\DosDevices\\"))));
					// BSR-763 set minor value
					pvext->Minor = (UCHAR)(pvext->MountPoint[0] - 'C');
				}
				else if (wcsstr(key, L"\\??\\Volume")) {	// registry's style
					// BSR-109
					memset(pvext->VolumeGuid, 0, sizeof(pvext->VolumeGuid));
					memcpy(pvext->VolumeGuid, key, valueInfo->NameLength);
				}
			}

			kfree(key);
		}
	}

cleanup:
	kfree(keyInfo);
	kfree(valueInfo);

	if (hKey) {
		ZwClose(hKey);
	}

	return status;
}

NTSTATUS
mvolAddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS            status;
    PDEVICE_OBJECT      AttachedDeviceObject = NULL;
    PDEVICE_OBJECT      ReferenceDeviceObject = NULL;
    PVOLUME_EXTENSION   VolumeExtension = NULL;
    ULONG               deviceType = 0;
	static volatile LONG      IsEngineStart = FALSE;

	// BSR-511 failure handling in safe mode
	if (*InitSafeBootMode > 0) {
		//1 :SAFEBOOT_MINIMAL
		//2 :SAFEBOOT_NETWORK
		//3 :SAFEBOOT_DSREPAIR
		bsr_info(5, BSR_LC_DRIVER, NO_OBJECT, "Safe boot mode %u", *InitSafeBootMode);
		return STATUS_UNSUCCESSFUL;
	}

    if (FALSE == InterlockedCompareExchange(&IsEngineStart, TRUE, FALSE)) {
        HANDLE		hNetLinkThread = NULL;
        NTSTATUS	Status = STATUS_UNSUCCESSFUL;

        // Init WSK and StartNetLinkServer
		Status = PsCreateSystemThread(&hNetLinkThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, InitWskNetlink, NULL);
        if (!NT_SUCCESS(Status)) {
			bsr_err(36, BSR_LC_THREAD, NO_OBJECT, "Failed to add device due to failure to create thread. status(0x%08X)", Status);
            return Status;
        }

		//Status = ObReferenceObjectByHandle(hNetLinkThread, THREAD_ALL_ACCESS, NULL, KernelMode, &g_NetlinkServerThread, NULL);
		ZwClose(hNetLinkThread);

        //if (!NT_SUCCESS(Status)) {
		//	bsr_err(7, BSR_LC_DRIVER, NO_OBJECT, "Failed to add device due to failure to create thread handle. status(0x%08X)", Status);
        //    return Status;
        //}
    }

    ReferenceDeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);
    deviceType = ReferenceDeviceObject->DeviceType; //deviceType = 0x7 = FILE_DEVICE_DISK 
    ObDereferenceObject(ReferenceDeviceObject);

    status = IoCreateDevice(mvolDriverObject, sizeof(VOLUME_EXTENSION), NULL,
        deviceType, FILE_DEVICE_SECURE_OPEN, FALSE, &AttachedDeviceObject);
    if (!NT_SUCCESS(status)) {
        mvolLogError(mvolRootDeviceObject, 102, MSG_ADD_DEVICE_ERROR, status);
		bsr_err(72, BSR_LC_VOLUME, NO_OBJECT, "Failed to add volume due to can't create device, err(0x%x)", status);
        return status;
    }

    AttachedDeviceObject->Flags |= (DO_DIRECT_IO | DO_POWER_PAGABLE);
    AttachedDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    VolumeExtension = AttachedDeviceObject->DeviceExtension;
    RtlZeroMemory(VolumeExtension, sizeof(VOLUME_EXTENSION));
    VolumeExtension->DeviceObject = AttachedDeviceObject;
    VolumeExtension->PhysicalDeviceObject = PhysicalDeviceObject;
    VolumeExtension->Magic = MVOL_MAGIC;
    VolumeExtension->Flag = 0;
    VolumeExtension->IrpCount = 0;
    VolumeExtension->TargetDeviceObject =
        IoAttachDeviceToDeviceStack(AttachedDeviceObject, PhysicalDeviceObject);
    if (VolumeExtension->TargetDeviceObject == NULL) {
        mvolLogError(mvolRootDeviceObject, 103, MSG_ADD_DEVICE_ERROR, STATUS_NO_SUCH_DEVICE);
        IoDeleteDevice(AttachedDeviceObject);
        return STATUS_NO_SUCH_DEVICE;
	}
	// BSR-958
	VolumeExtension->bPreviouslyResynced = TRUE;

	IoInitializeRemoveLock(&VolumeExtension->RemoveLock, '00FS', 0, 0);
	KeInitializeMutex(&VolumeExtension->CountMutex, 0);

    status = GetDeviceName(PhysicalDeviceObject,
        VolumeExtension->PhysicalDeviceName, MAXDEVICENAME * sizeof(WCHAR)); // -> \Device\HarddiskVolumeXX
    if (!NT_SUCCESS(status)) {
        mvolLogError(mvolRootDeviceObject, 101, MSG_ADD_DEVICE_ERROR, status);
		IoDeleteDevice(AttachedDeviceObject);
        return status;
    }

	BUG_ON_UINT16_OVER(wcslen(VolumeExtension->PhysicalDeviceName) * sizeof(WCHAR));
    VolumeExtension->PhysicalDeviceNameLength = (USHORT)(wcslen(VolumeExtension->PhysicalDeviceName) * sizeof(WCHAR));

	PMOUNTDEV_UNIQUE_ID pmuid = QueryMountDUID(PhysicalDeviceObject);
	if (pmuid) {
		_QueryVolumeNameRegistry(pmuid, VolumeExtension);
		ExFreePool(pmuid);
	}

    MVOL_LOCK();
    mvolAddDeviceList(VolumeExtension);
    MVOL_UNLOCK();
    
#ifdef _WIN_MVFL
    if (do_add_minor(VolumeExtension->Minor)) {
#ifndef _WIN_MULTIVOL_THREAD
        status = mvolInitializeThread(VolumeExtension, &VolumeExtension->WorkThreadInfo, mvolWorkThread);
        if (!NT_SUCCESS(status)) {
			bsr_err(9, BSR_LC_DRIVER, NO_OBJECT,"Failed to initialize WorkThread. status(0x%x)", status);
            //return status;
        }
#endif
        VolumeExtension->Active = TRUE;
		// DW-1327 to block I/O by bsrlock.
		SetBsrlockIoBlock(VolumeExtension, TRUE);
    }
#endif

	// DW-1109 create block device in add device routine, it won't be destroyed at least we put ref in remove device routine.
	VolumeExtension->dev = create_bsr_block_device(VolumeExtension);

	bsr_info(41, BSR_LC_VOLUME, NO_OBJECT,"VolumeExt(0x%p) Device(%ws) minor(%d) Active(%d) MountPoint(%ws) VolumeGUID(%ws)",
		VolumeExtension,
		VolumeExtension->PhysicalDeviceName,
		VolumeExtension->Minor,
		VolumeExtension->Active,
		VolumeExtension->MountPoint,
		VolumeExtension->VolumeGuid);

    return STATUS_SUCCESS;
}

NTSTATUS
mvolSendToNextDriver(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
	NTSTATUS 	status = STATUS_SUCCESS;
	
    if (DeviceObject == mvolRootDeviceObject) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		status = IoAcquireRemoveLock(&VolumeExtension->RemoveLock, NULL);
		if (!NT_SUCCESS(status)) {
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return status;
		}
	}
		
    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		IoReleaseRemoveLock(&VolumeExtension->RemoveLock, NULL);
	}

	return status;
}

NTSTATUS
mvolCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
#if 0 // DW-1380
    if (DeviceObject == mvolRootDeviceObject) {
        bsr_debug(99, BSR_LC_DRIVER, NO_OBJECT,"mvolRootDevice Request");

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

#ifdef _WIN_MVFL
    if (VolumeExtension->Active) 
	{
		// DW-1300 get device and get reference.
		struct bsr_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
		// DW-1300 prevent mounting volume when device went diskless.
		if (device && ((R_PRIMARY != device->resource->role[NOW]) || (device->resource->bPreDismountLock == TRUE) || device->disk_state[NOW] == D_DISKLESS))   // V9
		{
			//PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
			//bsr_debug(100, BSR_LC_DRIVER, NO_OBJECT,"DeviceObject(0x%x), MinorFunction(0x%x) STATUS_INVALID_DEVICE_REQUEST", DeviceObject, irpSp->MinorFunction);
			// DW-1300 put device reference count when no longer use.
			kref_put(&device->kref, bsr_destroy_device);

			Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);

			return STATUS_INVALID_DEVICE_REQUEST;
		}
		// DW-1300 put device reference count when no longer use.
		else if (device)
			kref_put(&device->kref, bsr_destroy_device);
    }
#endif
#endif

    return mvolSendToNextDriver(DeviceObject, Irp);
}

NTSTATUS
mvolClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
#if 0 // DW-1380
    if (DeviceObject == mvolRootDeviceObject) {
		bsr_debug(101, BSR_LC_DRIVER, NO_OBJECT,"mvolRootDevice Request");

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
#endif
    return mvolSendToNextDriver(DeviceObject, Irp);
}

void bsr_cleanup_by_win_shutdown(PVOLUME_EXTENSION VolumeExtension);

NTSTATUS
mvolShutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

	bsr_cleanup_by_win_shutdown(VolumeExtension);

    return mvolSendToNextDriver(DeviceObject, Irp);
    //status = mvolRunIrpSynchronous(DeviceObject, Irp); // DW-1146 disable cleaunup logic. for some case, hang occurred while shutdown
	//return status;
}

NTSTATUS
mvolFlush(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS	status = STATUS_SUCCESS;
	PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
	 
	if (g_mj_flush_buffers_filter && VolumeExtension->Active) {
		// DW-1300 get device and get reference.
		struct bsr_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
        if (device) {
#ifdef _WIN_MULTIVOL_THREAD
			IoMarkIrpPending(Irp);
			mvolQueueWork(VolumeExtension->WorkThreadInfo, DeviceObject, Irp, 0); 
#else
			PMVOL_THREAD				pThreadInfo;
			pThreadInfo = &VolumeExtension->WorkThreadInfo;
            IoMarkIrpPending(Irp);
            ExInterlockedInsertTailList(&pThreadInfo->ListHead,
                &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);
            IO_THREAD_SIG(pThreadInfo);
#endif
			// DW-1300 put device reference count when no longer use.
			kref_put(&device->kref, bsr_destroy_device);
			return STATUS_PENDING;
        } else {
        	Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);

            return STATUS_INVALID_DEVICE_REQUEST;
        }
	}
		
	status = mvolSendToNextDriver(DeviceObject, Irp);

	return status;
}

_Use_decl_annotations_
NTSTATUS
mvolSystemControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION irpSp = NULL;
    if (DeviceObject == mvolRootDeviceObject) {
		bsr_debug(102, BSR_LC_DRIVER, NO_OBJECT, "mvolRootDevice Request");

        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

#ifdef _WIN_MVFL
    if (VolumeExtension->Active) {
		// DW-1300 get device and get reference.
		struct bsr_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
		// DW-1300 prevent mounting volume when device is failed or below.
		if (device && device->resource->bTempAllowMount == FALSE && ((R_PRIMARY != device->resource->role[NOW]) || (device->resource->bPreDismountLock == TRUE) || device->disk_state[NOW] <= D_FAILED))   // V9
		{
			//PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
			//bsr_debug(103, BSR_LC_DRIVER, NO_OBJECT,"DeviceObject(0x%x), MinorFunction(0x%x) STATUS_INVALID_DEVICE_REQUEST", DeviceObject, irpSp->MinorFunction);
			// DW-1300 put device reference count when no longer use.
			kref_put(&device->kref, bsr_destroy_device);

			// DW-1883
			//Driver Verifier generates a BSOD if IRP_MJ_SYSTEM_CONTROL is not passed to the lower stack driver.
			//Modify the minor function to be changed to a value that is not currently defined. It will probably return STATUS_NOT_SUPPORTED.
			irpSp = IoGetCurrentIrpStackLocation(Irp);
			irpSp->MinorFunction = 0xFF;
		}
		// DW-1300 put device reference count when no longer use.
		else if (device)
			kref_put(&device->kref, bsr_destroy_device);
    }
#endif
    IoSkipCurrentIrpStackLocation(Irp);

    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
}

NTSTATUS
mvolDispatchPower(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    return mvolSendToNextDriver(DeviceObject, Irp);
}

_Use_decl_annotations_
NTSTATUS
mvolRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS 	status = STATUS_SUCCESS;
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;

    if (DeviceObject == mvolRootDeviceObject) {
        goto invalid_device;
    }

    if (VolumeExtension->Active) {
		// DW-1300 get device and get reference.
		struct bsr_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
		// DW-1363 prevent mounting volume when device is failed or below.
		if (device && ((R_PRIMARY == device->resource->role[0]) && (device->resource->bPreDismountLock == FALSE) && device->disk_state[NOW] > D_FAILED || device->resource->bTempAllowMount == TRUE)) {
			// BSR-687 aggregate I/O throughput and latency
			if (atomic_read(&g_bsrmon_run)) {
				PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
				atomic_inc(&device->io_cnt[READ]);
				atomic_add(irpSp->Parameters.Read.Length >> 10, &device->io_size[READ]);
			}
			// DW-1300 put device reference count when no longer use.
			kref_put(&device->kref, bsr_destroy_device);
            if (g_read_filter) {
                goto async_read_filter;
            }
        }
        else {
			// DW-1300 put device reference count when no longer use.
			if (device)
				kref_put(&device->kref, bsr_destroy_device);
            goto invalid_device;
        }
    }

	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		status = IoAcquireRemoveLock(&VolumeExtension->RemoveLock, NULL);
		if (!NT_SUCCESS(status)) {
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return status;
		}
	} 
	
    IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		IoReleaseRemoveLock(&VolumeExtension->RemoveLock, NULL);
	}
	return status;

async_read_filter:
    {
#ifdef BSR_TRACE
        PIO_STACK_LOCATION readIrpSp = IoGetCurrentIrpStackLocation(Irp);
		bsr_debug(104, BSR_LC_DRIVER, NO_OBJECT,"\n\nupper driver READ request start! vol:%c: sect:0x%llx sz:%d --------------------------------!",
            VolumeExtension->Letter, (readIrpSp->Parameters.Read.ByteOffset.QuadPart / 512), readIrpSp->Parameters.Read.Length);
#endif

#ifdef _WIN_MULTIVOL_THREAD
		IoMarkIrpPending(Irp);
		mvolQueueWork(VolumeExtension->WorkThreadInfo, DeviceObject, Irp, 0);
#else
        PMVOL_THREAD pThreadInfo = &VolumeExtension->WorkThreadInfo;

        IoMarkIrpPending(Irp);

        ExInterlockedInsertTailList(&pThreadInfo->ListHead, &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);
        IO_THREAD_SIG(pThreadInfo);
#endif
    }
    return STATUS_PENDING;

invalid_device:
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS
mvolWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
    PVOLUME_EXTENSION VolumeExtension = DeviceObject->DeviceExtension;
	ktime_t start_kt;

	// BSR-764 delay write I/O occurrence
	if (g_simul_perf.flag && g_simul_perf.type == SIMUL_PERF_DELAY_TYPE0) 
		force_delay(g_simul_perf.delay_time);
	start_kt = ktime_get();

    if (DeviceObject == mvolRootDeviceObject) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (VolumeExtension->Active) {
		// DW-1300 get device and get reference.
		struct bsr_device *device = get_device_with_vol_ext(VolumeExtension, TRUE);
		// DW-1363 prevent writing when device is failed or below.
		if (device && device->resource && (device->resource->role[NOW] == R_PRIMARY) && (device->resource->bPreSecondaryLock == FALSE) && (device->disk_state[NOW] > D_FAILED)) {
        	
			PIO_STACK_LOCATION pisl = IoGetCurrentIrpStackLocation(Irp);
			ULONGLONG offset_sector = (ULONGLONG)(pisl->Parameters.Write.ByteOffset.QuadPart) >> 9;
			ULONG size_sector = pisl->Parameters.Write.Length >> 9;
			sector_t vol_size_sector = bsr_get_capacity(device->this_bdev);

			// if io offset is larger than volume size oacassionally,
			// then allow to lower device, so not try to send to peer
			if (offset_sector + size_sector > vol_size_sector) {

				bsr_debug(105, BSR_LC_DRIVER, NO_OBJECT, "Upper driver WRITE vol(%ws) sect(0x%llx+%u) VolumeExtension->IrpCount(%d) ......................Skipped Irp:%p Irp->Flags:%x",
					VolumeExtension->MountPoint, offset_sector, size_sector, VolumeExtension->IrpCount, Irp, Irp->Flags);	

				unsigned long long saved_size = VolumeExtension->dev->bd_contains->d_size;
				unsigned long long real_size = get_targetdev_volsize(VolumeExtension); 	

				if (offset_sector + size_sector > saved_size && real_size > saved_size) {
					bsr_debug(106, BSR_LC_DRIVER, NO_OBJECT, "saved_size (%llu), real_size (%llu) vol_sector(%llu) off_sector(%llu)", saved_size >> 9, real_size >> 9, vol_size_sector, offset_sector + size_sector);
					bsr_debug(107, BSR_LC_DRIVER, NO_OBJECT, "need to temporary bm write");
				}				
				
				// DW-1300 put device reference count when no longer use.
				kref_put(&device->kref, bsr_destroy_device);
				goto skip;
			}


#ifdef BSR_TRACE
			bsr_debug(108, BSR_LC_DRIVER, NO_OBJECT,"Upper driver WRITE vol(%ws) sect(0x%llx+%u) ................Queuing(%d)!",
				VolumeExtension->MountPoint, offset_sector, size_sector, VolumeExtension->IrpCount);
#endif

#ifdef _WIN_MULTIVOL_THREAD
			// DW-1999 If the completion routine is called before status_pending is returned to the filesystem, the verifier causes a bugcheck.
			// Therefore, change the calling position of IoMarkIrpPending to set it in advance.
			IoMarkIrpPending(Irp);

			//It is processed in 2 passes according to IRQL.
			//1. If IRQL is greater than or equal to DISPATCH LEVEL, Queue write I/O.
			//2. Otherwise, Directly call mvolwritedispatch
			if(KeGetCurrentIrql() < DISPATCH_LEVEL) {
				// BSR-687 aggregate I/O throughput and latency
				if (atomic_read(&g_bsrmon_run)) {
					PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
					atomic_inc(&device->io_cnt[WRITE]);
					atomic_add(irpSp->Parameters.Write.Length >> 10, &device->io_size[WRITE]);
				}
				status = mvolReadWriteDevice(VolumeExtension, Irp, IRP_MJ_WRITE, start_kt);
				if (status != STATUS_SUCCESS) {
                	mvolLogError(VolumeExtension->DeviceObject, 111, MSG_WRITE_ERROR, status);

                	Irp->IoStatus.Information = 0;
                	Irp->IoStatus.Status = status;
                	IoCompleteRequest(Irp, (CCHAR)(NT_SUCCESS(Irp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT));
                	return status;
            	}	
			} else {
				// BSR-687 aggregate I/O throughput and latency
				if (atomic_read(&g_bsrmon_run)) {
					PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
					atomic_inc(&device->io_cnt[WRITE]);
					atomic_add(irpSp->Parameters.Write.Length >> 10, &device->io_size[WRITE]);
				}
				mvolQueueWork(VolumeExtension->WorkThreadInfo, DeviceObject, Irp, start_kt);
			}
			
#else
			PMVOL_THREAD	pThreadInfo = &VolumeExtension->WorkThreadInfo;

            IoMarkIrpPending(Irp);

            ExInterlockedInsertTailList(&pThreadInfo->ListHead,
                &Irp->Tail.Overlay.ListEntry, &pThreadInfo->ListLock);
            IO_THREAD_SIG(pThreadInfo);
#endif

			// DW-1300 put device reference count when no longer use.
			kref_put(&device->kref, bsr_destroy_device);
            return STATUS_PENDING;
        }
        else {
			// DW-1300 put device reference count when no longer use.
			if (device)
				kref_put(&device->kref, bsr_destroy_device);

			// BSR-958 
			if (VolumeExtension->bPreviouslyResynced) {
				bsr_debug(109, BSR_LC_DRIVER, NO_OBJECT, "Upper driver WRITE vol(%ws) VolumeExtension->IrpCount(%d) STATUS_INVALID_DEVICE_REQUEST return Irp:%p Irp->Flags:%x",
					VolumeExtension->MountPoint, VolumeExtension->IrpCount, Irp, Irp->Flags);

				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);

				return STATUS_INVALID_DEVICE_REQUEST;
			}
        }
    }

skip:
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		status = IoAcquireRemoveLock(&VolumeExtension->RemoveLock, NULL);
		if (!NT_SUCCESS(status)) {
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return status;
		}
	}

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		IoReleaseRemoveLock(&VolumeExtension->RemoveLock, NULL);
	}
	return status;
}

extern int bsr_seq_show(struct seq_file *seq, void *v);

NTSTATUS
mvolDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS		status;
    PIO_STACK_LOCATION	irpSp = NULL;
    PVOLUME_EXTENSION	VolumeExtension = DeviceObject->DeviceExtension;

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
		// BSR-109 updated mount information as soon as IOCTL_MOUNTDEV_LINK_CREATED, IOCTL_MOUNTDEV_LINK_DELETED control code is received
		case IOCTL_MOUNTDEV_LINK_CREATED:
		{
			PMOUNTDEV_NAME name = (PMOUNTDEV_NAME)Irp->AssociatedIrp.SystemBuffer;
			UNICODE_STRING d;

			if (!name || name->NameLength == 0) 
				break;

			d.Buffer = name->Name;
			d.Length = name->NameLength;

			MVOL_LOCK();
			if (MOUNTMGR_IS_DRIVE_LETTER(&d)) {
				memset(VolumeExtension->MountPoint, 0, sizeof(VolumeExtension->MountPoint));
				VolumeExtension->Minor = (UCHAR)(name->Name[strlen("\\DosDevices\\")] - 'C');
				memcpy(VolumeExtension->MountPoint, (name->Name + strlen("\\DosDevices\\")), (USHORT)(strlen(" :") * sizeof(WCHAR)));
				bsr_debug(110, BSR_LC_DRIVER, NO_OBJECT, "IOCTL_MOUNTDEV_LINK_CREATED %ws, minor %d", VolumeExtension->MountPoint, VolumeExtension->Minor);
			}
			else if (MOUNTMGR_IS_VOLUME_NAME(&d)) {
				memset(VolumeExtension->VolumeGuid, 0, sizeof(VolumeExtension->VolumeGuid));
				memcpy(VolumeExtension->VolumeGuid, name->Name, name->NameLength);
				bsr_debug(111, BSR_LC_DRIVER, NO_OBJECT, "IOCTL_MOUNTDEV_LINK_CREATED %ws", VolumeExtension->VolumeGuid);
			}

			MVOL_UNLOCK();


			MVOL_IOCOMPLETE_REQ(Irp, STATUS_SUCCESS, 0);
		}
		case IOCTL_MOUNTDEV_LINK_DELETED:
		{
			PMOUNTDEV_NAME name = (PMOUNTDEV_NAME)Irp->AssociatedIrp.SystemBuffer;
			UNICODE_STRING d;

			if (!name || name->NameLength == 0)
				break;

			d.Buffer = name->Name;
			d.Length = name->NameLength;

			MVOL_LOCK();
			if (MOUNTMGR_IS_DRIVE_LETTER(&d)) {
				bsr_debug(112, BSR_LC_DRIVER, NO_OBJECT, "IOCTL_MOUNTDEV_LINK_DELETED %ws", VolumeExtension->MountPoint);
				memset(VolumeExtension->MountPoint, 0, sizeof(VolumeExtension->MountPoint));
				VolumeExtension->Minor = 0;
			}
			else if (MOUNTMGR_IS_DRIVE_LETTER(&d)) {
				bsr_debug(113, BSR_LC_DRIVER, NO_OBJECT, "IOCTL_MOUNTDEV_LINK_DELETED %ws", VolumeExtension->VolumeGuid);
				memset(VolumeExtension->VolumeGuid, 0, sizeof(VolumeExtension->VolumeGuid));
			}
			MVOL_UNLOCK();

			MVOL_IOCOMPLETE_REQ(Irp, STATUS_SUCCESS, 0);
		}

        case IOCTL_MVOL_GET_PROC_BSR:
        {
			PMVOL_VOLUME_INFO p = NULL;
			struct seq_file seq = {0,};
			PIO_STACK_LOCATION	irpSp = IoGetCurrentIrpStackLocation(Irp);

			if (!Irp->AssociatedIrp.SystemBuffer)
				return STATUS_INVALID_PARAMETER;

			if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MVOL_VOLUME_INFO))
				return STATUS_BUFFER_TOO_SMALL;

			p = (PMVOL_VOLUME_INFO)Irp->AssociatedIrp.SystemBuffer;
			seq_alloc(&seq, MAX_SEQ_BUF);

			MVOL_LOCK();
			bsr_seq_show((struct seq_file *)&seq, 0);
			MVOL_UNLOCK();
			
			RtlCopyMemory(p->Seq, seq.buf, seq.size);
			seq_free(&seq);

			irpSp->Parameters.DeviceIoControl.OutputBufferLength = sizeof(MVOL_VOLUME_INFO);
			MVOL_IOCOMPLETE_REQ(Irp, STATUS_SUCCESS, sizeof(MVOL_VOLUME_INFO));
        }

        case IOCTL_MVOL_GET_VOLUME_COUNT:
        {
            PROOT_EXTENSION RootExtension = mvolRootDeviceObject->DeviceExtension;

            *(PULONG)(Irp->AssociatedIrp.SystemBuffer) = RootExtension->Count;
            MVOL_IOCOMPLETE_REQ(Irp, STATUS_SUCCESS, sizeof(ULONG));
        }

        case IOCTL_MVOL_GET_VOLUMES_INFO:
        {
            ULONG size = 0;

            status = IOCTL_GetAllVolumeInfo(Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

        case IOCTL_MVOL_GET_VOLUME_INFO:
        {
            ULONG size = 0;

            status = IOCTL_GetVolumeInfo(DeviceObject, Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

        case IOCTL_MVOL_GET_VOLUME_SIZE:
        {
            status = IOCTL_GetVolumeSize(DeviceObject, Irp);
            MVOL_IOCOMPLETE_REQ(Irp, status, sizeof(LARGE_INTEGER));
        }

        case IOCTL_MVOL_GET_COUNT_INFO:
        {
            ULONG			size = 0;

            status = IOCTL_GetCountInfo(DeviceObject, Irp, &size);
            MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

		// BSR-1066
		case IOCTL_MVOL_TEMP_MOUNT_VOLUME:
		{
			ULONG size = 0;
			status = IOCTL_MountVolume(DeviceObject, Irp, &size, true);
			MVOL_IOCOMPLETE_REQ(Irp, status, size);
		}
		case IOCTL_MVOL_DISMOUNT_VOLUME:
		{
			status = IOCTL_DismountVolume(DeviceObject);
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}

        case IOCTL_MVOL_MOUNT_VOLUME:
        {
			ULONG size = 0;

            status = IOCTL_MountVolume(DeviceObject, Irp, &size, false);
			if (!NT_SUCCESS(status)) {
				bsr_warn(84, BSR_LC_DRIVER, NO_OBJECT, "IOCTL_MVOL_MOUNT_VOLUME failed. Volume(%ws) status(0x%x)",
					VolumeExtension->MountPoint, status);
			}
			else if (!size) {	// ok
				bsr_info(10, BSR_LC_DRIVER, NO_OBJECT, "IOCTL_MVOL_MOUNT_VOLUME. %ws Volume is mounted",
					VolumeExtension->MountPoint);
			}

			MVOL_IOCOMPLETE_REQ(Irp, status, size);
        }

		case IOCTL_MVOL_SET_SIMUL_DISKIO_ERROR: 
		{
			status = IOCTL_SetSimulDiskIoError(DeviceObject, Irp); // Simulate Disk I/O Error IOCTL Handler
            MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}
		// BSR-764
		case IOCTL_MVOL_SET_SIMUL_PERF_DEGR:
		{
			status = IOCTL_SetSimulPerfDegr(DeviceObject, Irp); // Simulate Performance Degradation Handler
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}
		case IOCTL_MVOL_SET_LOGLV_MIN:
		{
			status = IOCTL_SetMinimumLogLevel(DeviceObject, Irp); // Set minimum level of logging (system event log, service log)
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}
		case IOCTL_MVOL_SET_LOG_FILE_MAX_COUNT:
		{
			status = IOCTL_SetLogFileMaxCount(DeviceObject, Irp); // Set log file max count
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}
		// BSR-649
		case IOCTL_MVOL_SET_DEBUG_LOG_CATEGORY:
		{
			status = IOCTL_SetDebugLogCategory(DeviceObject, Irp); // Set debug log filter
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}
		// BSR-1048
		case IOCTL_MVOL_WRITE_LOG:
		{
			status = IOCTL_WriteLog(DeviceObject, Irp);
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);

		}
		// BSR-1072
		case IOCTL_MVOL_BSR_PANIC:
		{
			status = IOCTL_Panic(DeviceObject, Irp);
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);

		}
		// BSR-1039
		case IOCTL_MVOL_HOLD_STATE:
		{
			status = IOCTL_HoldState(DeviceObject, Irp);
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);

		}
		// BSR-1039
		case IOCTL_MVOL_FAKE_AL_USED:
		{
			status = IOCTL_FakeALUsed(DeviceObject, Irp);
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);

		}
		case IOCTL_MVOL_GET_BSR_LOG:
		{
			ULONG size = 0;
			status = IOCTL_GetBsrLog(DeviceObject, Irp, &size);
			if(status == STATUS_SUCCESS) {
				MVOL_IOCOMPLETE_REQ(Irp, status, size);
			} else {
				MVOL_IOCOMPLETE_REQ(Irp, status, 0);
			}
		}

		case IOCTL_MVOL_SET_HANDLER_USE:
		{
			status = IOCTL_SetHandlerUse(DeviceObject, Irp); // Set handler_use value.
			MVOL_IOCOMPLETE_REQ(Irp, status, 0);
		}		
		case IOCTL_MVOL_GET_UNTAG_MEM_USAGE:
		{
			ULONG size = 0;

			status = IOCTL_GetUntagMemoryUsage(DeviceObject, Irp, &size);
			MVOL_IOCOMPLETE_REQ(Irp, status, size);
		}
		case IOCTL_VOLUME_ONLINE:
		{
			// DW-1700
			//Update the volume size when the disk is online.
			//After the IOCTL_VOLUME_ONLINE command completes, you can get the size of the volume.
			// DW-1917
			LONGLONG size;
			struct block_device *bdev = VolumeExtension->dev;

			status = mvolRunIrpSynchronous(DeviceObject, Irp);

			if (bdev && bdev->bd_contains) {
				size = get_targetdev_volsize(VolumeExtension);
				bdev->bd_contains->d_size = size;
				// DW-1917 max_hw_sectors value must be set.
				bdev->bd_disk->queue->max_hw_sectors = size ? (size >> 9) : BSR_MAX_BIO_SIZE;
			}

			Irp->IoStatus.Status = status;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return status;
		}
		// BSR-37 debugfs porting
		case IOCTL_MVOL_GET_DEBUG_INFO:
		{
			ULONG size = 0;
			
			status = IOCTL_GetDebugInfo(Irp, &size);
			if (status == STATUS_SUCCESS) {
				MVOL_IOCOMPLETE_REQ(Irp, status, sizeof(BSR_DEBUG_INFO) + size);
			}
			else {
				MVOL_IOCOMPLETE_REQ(Irp, status, 0);
			}
			
		}
		// BSR-740
		case IOCTL_MVOL_SET_BSRMON_RUN:
		{
			status = IOCTL_SetBsrmonRun(DeviceObject, Irp);
			MVOL_IOCOMPLETE_REQ(Irp, status, sizeof(unsigned int));
		}
		// BSR-741
		case IOCTL_MVOL_GET_BSRMON_RUN:
		{
			status = IOCTL_GetBsrmonRun(DeviceObject, Irp);
			MVOL_IOCOMPLETE_REQ(Irp, status, sizeof(unsigned int));
		}
    }

    if (DeviceObject == mvolRootDeviceObject ||
        VolumeExtension->TargetDeviceObject == NULL)
    {
        status = STATUS_UNSUCCESSFUL;
        MVOL_IOCOMPLETE_REQ(Irp, status, 0);
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(VolumeExtension->TargetDeviceObject, Irp);
}

NTSTATUS
mvolDispatchPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS		status;
    PIO_STACK_LOCATION	irpSp;

    if (DeviceObject == mvolRootDeviceObject) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    switch (irpSp->MinorFunction) {
        case IRP_MN_START_DEVICE:
        {
            status = mvolStartDevice(DeviceObject, Irp);
            break;
        }
		case IRP_MN_SURPRISE_REMOVAL:
        case IRP_MN_REMOVE_DEVICE:
        {
            status = mvolRemoveDevice(DeviceObject, Irp);
            break;
        }
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        {
            status = mvolDeviceUsage(DeviceObject, Irp);
            break;
        }

        default:
            return mvolSendToNextDriver(DeviceObject, Irp);
    }

    return status;
}
