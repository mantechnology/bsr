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

#include <Ntifs.h>
#include <ntddk.h>
#include <stdlib.h>
#include <Mountmgr.h> 
#include <ntddvol.h>
#include <ntdddisk.h>
#include <ntstrsafe.h>

#include "../../../bsr/bsr-kernel-compat/windows/bsr_windows.h"
#include "../../../bsr/bsr-kernel-compat/windows/bsr_wingenl.h"
#include "proto.h"
#include "../../../bsr/bsr_int.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, QueryMountDUID)
#pragma alloc_text(PAGE, DeleteRegistryValueKey)
#ifdef _WIN_MVFL
//#pragma alloc_text(PAGE, FsctlFlsuhDismountVolume)
#pragma alloc_text(PAGE, FsctlLockVolume)
#pragma alloc_text(PAGE, FsctlUnlockVolume)
#pragma alloc_text(PAGE, FsctlCreateVolume)
#pragma alloc_text(PAGE, FsctlFlushDismountVolume)
#pragma alloc_text(PAGE, FsctlFlushVolume)
#endif
#endif

//#define _WIN32_CHECK_PARTITION_STYLE // DW-1495

NTSTATUS
GetDeviceName( PDEVICE_OBJECT DeviceObject, PWCHAR Buffer, ULONG BufferLength )
{
	NTSTATUS					status;
	POBJECT_NAME_INFORMATION	nameInfo=NULL;
	ULONG						size;

	nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag( NonPagedPool, MAXDEVICENAME*sizeof(WCHAR), '26SB' );
	if( !nameInfo ) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory( nameInfo, MAXDEVICENAME * sizeof(WCHAR) );
	status = ObQueryNameString( DeviceObject, nameInfo, MAXDEVICENAME, &size );
	if( !NT_SUCCESS(status) ) {
		bsr_err(96, BSR_LC_DRIVER, NO_OBJECT, "Failed to get device name, err=0x%x", status);
		ExFreePool( nameInfo );
		return status;
	}

	if( BufferLength > nameInfo->Name.Length ) {
		memcpy( Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length );
	}
	else {
		memcpy( Buffer, nameInfo->Name.Buffer, BufferLength-4 );
	}

	ExFreePool( nameInfo );
	return STATUS_SUCCESS;
}

#ifdef _WIN_MVFL
/**
* @brief    do FSCTL_DISMOUNT_VOLUME in kernel.
*           advised to use this function in next sequence
*			lock - dismount - unlock
*			because this function can process regardless of using volume
*           reference to http://msdn.microsoft.com/en-us/library/windows/desktop/aa364562(v=vs.85).aspx 
*           using sequence is FsctlLockVolume() - FsctlFlushDismountVolume() - FsctlUnlockVolume() 
*           Opened volume's HANDLE value is in VOLUME_EXTENSION.
*           if you need, can be used Independently. 
*/
NTSTATUS FsctlFlushDismountVolume(unsigned int minor, bool bFlush)
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
#if 0
	PFILE_OBJECT pVolumeFileObject = NULL;
#endif
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor, FALSE);
    if (!pvext) {
        return STATUS_UNSUCCESSFUL;
    }

	RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);
	
	// DW-1587
	// there is no other way to check if there is volume mounted.
	// So 28175 warning disabled.
#pragma warning (disable: 28175)
	// DW-1303 No dismount for already dismounted volume
	if (pvext->PhysicalDeviceObject && pvext->PhysicalDeviceObject->Vpb) {
		if (!(pvext->PhysicalDeviceObject->Vpb->Flags & VPB_MOUNTED)) {
			bsr_info(15, BSR_LC_VOLUME, NO_OBJECT,"No dismount. volume(%wZ) already dismounted", &device_name);
			return STATUS_SUCCESS;
		}
	}
#pragma warning (default: 28175)
    __try
    {
        if (!pvext->LockHandle) {
            InitializeObjectAttributes(&ObjectAttributes,
                &device_name,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                NULL,
                NULL);

            status = ZwCreateFile(&hFile,
                GENERIC_READ | GENERIC_WRITE,
                &ObjectAttributes,
                &StatusBlock,
                NULL,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0);
            if (!NT_SUCCESS(status)) {
                bsr_info(16, BSR_LC_VOLUME, NO_OBJECT,"Failed to open volume. status(0x%x)", status);
                __leave;
            }
        }
        else {
            hFile = pvext->LockHandle;
        }

#if 0
        status = ObReferenceObjectByHandle(hFile,
            FILE_READ_DATA,
            *IoFileObjectType,
            KernelMode,
            &pVolumeFileObject,
            NULL);
        if (!NT_SUCCESS(status)) {
			bsr_err(53, BSR_LC_ETC, NO_OBJECT,"ObReferenceObjectByHandle Failed. status(0x%x)", status);
            __leave;
        }
#endif
		if (bFlush) {
			bsr_info(62, BSR_LC_VOLUME, NO_OBJECT, "try flush volume(%wZ)", &device_name);

			status = ZwFlushBuffersFile(hFile, &StatusBlock);
			if (!NT_SUCCESS(status)) {
				bsr_info(17, BSR_LC_VOLUME, NO_OBJECT,"Failed to flush volume. status(0x%x)", status);
			}
			bsr_info(63, BSR_LC_VOLUME, NO_OBJECT, "volume(%wZ) flushed", &device_name);
		}

		bsr_info(64, BSR_LC_VOLUME, NO_OBJECT, "try dismount volume(%wZ)", &device_name);

        status = ZwFsControlFile(hFile, 0, 0, 0, &StatusBlock, FSCTL_DISMOUNT_VOLUME, 0, 0, 0, 0);
        if (!NT_SUCCESS(status)) {
            bsr_info(18, BSR_LC_VOLUME, NO_OBJECT,"Failed to volume dismount(FSCTL_DISMOUNT_VOLUME). status(0x%x)", status);
            __leave;
        }
        bsr_info(19, BSR_LC_VOLUME, NO_OBJECT,"volume(%wZ) dismounted", &device_name);
    }
    __finally
    {
        if (!pvext->LockHandle && hFile)    // case of dismount Independently
        {
            ZwClose(hFile);
        }
#if 0
        if (pVolumeFileObject) {
            ObDereferenceObject(pVolumeFileObject);
        }
#endif
    }

    return status;
}

/**
* @brief    do FSCTL_LOCK_VOLUME in kernel.
*           If acuiring lock is success, volume's HANDLE value is in VOLUME_EXTENSION.
*           this handle must be closed by FsctlUnlockVolume()-ZwClose()
*           If volume is referenced by somewhere, aquiring lock will be failed.
*/
NTSTATUS FsctlLockVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor, FALSE);
    if (!pvext) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

	// DW-1587
	// there is no other way to check if there is volume mounted.
	// So 28175 warning disabled.
#pragma warning (disable: 28175)
	// DW-1303 No lock for already dismounted volume
	if (pvext->PhysicalDeviceObject && pvext->PhysicalDeviceObject->Vpb) {
		if (!(pvext->PhysicalDeviceObject->Vpb->Flags & VPB_MOUNTED)) {
			bsr_info(20, BSR_LC_VOLUME, NO_OBJECT,"No lock. volume(%wZ) already dismounted", &device_name);
			return STATUS_UNSUCCESSFUL;
		}
	}
#pragma warning (default: 28175)
    __try
    {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);
        if (!NT_SUCCESS(status)) {
            bsr_info(21, BSR_LC_VOLUME, NO_OBJECT,"Failed to acquire volume handle. status(0x%x)", status);
            __leave;
        }

		bsr_info(65, BSR_LC_VOLUME, NO_OBJECT, "try lock volume(%wZ)", &device_name);
		// DW-2149 only one attempt to acquire volume lock is made only once.
        status = ZwFsControlFile(hFile, 0, 0, 0, &StatusBlock, FSCTL_LOCK_VOLUME, 0, 0, 0, 0);            

        if (!NT_SUCCESS(status)) {
            //printk(KERN_ERR "ZwFsControlFile Failed. status(0x%x)\n", status);
            bsr_info(22, BSR_LC_VOLUME, NO_OBJECT,"Failed to acquire volume lock(FSCTL_LOCK_VOLUME). status(0x%x) &ObjectAttributes(0x%p) hFile(0x%p)", status, &ObjectAttributes, hFile);
            __leave;
        }
        
        pvext->LockHandle = hFile;
        hFile = NULL;

        bsr_info(23, BSR_LC_VOLUME, NO_OBJECT,"volume(%wZ) locked. handle(0x%p)", &device_name, pvext->LockHandle);

    }
    __finally
    {
        if (hFile) {
            ZwClose(hFile);
        }
    }

    return status;
}

/**
* @brief    do FSCTL_UNLOCK_VOLUME in kernel.
*/
NTSTATUS FsctlUnlockVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor, FALSE);
    if (!pvext) {
        return STATUS_UNSUCCESSFUL;
    }

    if (!pvext->LockHandle) {
        bsr_info(24, BSR_LC_VOLUME, NO_OBJECT,"volume(%ws) not locked", pvext->PhysicalDeviceName);
        return STATUS_NOT_LOCKED;
    }

    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK StatusBlock;

    __try
    {
		bsr_info(61, BSR_LC_VOLUME, NO_OBJECT, "unlock volume(%ws)", pvext->PhysicalDeviceName);
        status = ZwFsControlFile(pvext->LockHandle, 0, 0, 0, &StatusBlock, FSCTL_UNLOCK_VOLUME, 0, 0, 0, 0);
        if (!NT_SUCCESS(status)) {
            bsr_info(25, BSR_LC_VOLUME, NO_OBJECT,"Failed to unlock volume(FSCTL_UNLOCK_VOLUME). status(0x%x)", status);
            __leave;
        }

        bsr_info(26, BSR_LC_VOLUME, NO_OBJECT,"volume(%ws) unlocked", pvext->PhysicalDeviceName);
    }
    __finally
    {
        ZwClose(pvext->LockHandle);
        pvext->LockHandle = NULL;
    }

    return status;
}

/**
*/
NTSTATUS FsctlFlushVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor, FALSE);
    if (!pvext) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

    __try
    {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        if (!NT_SUCCESS(status)) {
            bsr_info(27, BSR_LC_VOLUME, NO_OBJECT,"Failed to acquire volume handle. status(0x%x)", status);
            __leave;
        }

        status = ZwFlushBuffersFile(hFile, &StatusBlock);
    }
    __finally
    {
        if (hFile) {
            ZwClose(hFile);
        }
    }

    return status;
}

/**
*/
NTSTATUS FsctlCreateVolume(unsigned int minor)
{
    PAGED_CODE();

    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor, TRUE);
    if (!pvext) {
        return STATUS_UNSUCCESSFUL;
    }

    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE hFile = NULL;
    UNICODE_STRING device_name;

    RtlUnicodeStringInit(&device_name, pvext->PhysicalDeviceName);

    __try {
        InitializeObjectAttributes(&ObjectAttributes,
            &device_name,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL);

        status = ZwCreateFile(&hFile,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &ObjectAttributes,
            &StatusBlock,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            0);

        if (!NT_SUCCESS(status)) {
            bsr_err(28, BSR_LC_VOLUME, NO_OBJECT,"Failed to create volume due to create file for %wZ. status(0x%x)", &device_name, status);
            __leave;
        }
    }
    __finally {
        if (hFile) {
            ZwClose(hFile);
        }
    }

    return status;
}

HANDLE GetVolumeHandleFromDeviceMinor(unsigned int minor)
{
	PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor, FALSE);
	if (!pvext) {
		bsr_err(29, BSR_LC_VOLUME, NO_OBJECT,"Failed to get volume handle from device minor(%u) due to could not get volume extension", minor);
		return NULL;
	}

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hVolume = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0, };
	IO_STATUS_BLOCK ioStatus = { 0, };	
	UNICODE_STRING usPath = { 0, };
		
	do {
		RtlUnicodeStringInit(&usPath, pvext->PhysicalDeviceName);
		InitializeObjectAttributes(&ObjectAttributes,
			&usPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		status = ZwCreateFile(&hVolume,
			FILE_WRITE_DATA | FILE_READ_ATTRIBUTES,
			&ObjectAttributes,
			&ioStatus,
			NULL,
			0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE,
			NULL,
			0);

		if (!NT_SUCCESS(status)) {
			// BSR-1045
			bsr_err(30, BSR_LC_VOLUME, NO_OBJECT, "Failed to get volume handle from device minor(%u) due to failue to create file for %wZ. status(0x%x)", minor, &usPath, status);
			return NULL;
		}
		
	} while (false);
			
	return hVolume;
}

// returns file system type, NTFS(1), FAT(2), EXFAT(3), REFS(4)
USHORT GetFileSystemTypeWithHandle(HANDLE hVolume, bool *retry)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK iostatus = { 0, };
	FILESYSTEM_STATISTICS fss = { 0, };
	
    *retry = false;

	if (NULL == hVolume) {
		bsr_err(84, BSR_LC_VOLUME, NO_OBJECT, "Failed to get file system type with handle due to volume is not allocate");
		return 0;
	}
	
	status = ZwFsControlFile(hVolume, NULL, NULL, NULL, &iostatus, FSCTL_FILESYSTEM_GET_STATISTICS, NULL, 0, &fss, sizeof(fss));

    // DW-2015 set the retry when STATUS_INVALID_PARAMETER.
	if (iostatus.Status == STATUS_INVALID_PARAMETER) {
		*retry = true;
	}

	// retrieved status might indicate there's more data, never mind this as long as the only thing we need is file system type.
	if (fss.FileSystemType == 0 &&
		!NT_SUCCESS(status))
	{
		bsr_err(85, BSR_LC_VOLUME, NO_OBJECT, "Failed to get file system type with handle due to failure to command FSCTL_FILESYSTEM_GET_STATISTICS. status(0x%x)", status);
		return 0;
	}
	else
		return fss.FileSystemType;
}

// retrieves file system specified cluster information ( total cluster count, number of bytes per cluster )
int GetClusterInfoWithVolumeHandle(HANDLE hVolume, PULONGLONG pullTotalCluster, PULONG pulBytesPerCluster)
{
	int bRet = -EINVAL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK ioStatus = { 0, };
	USHORT usFileSystemType = 0;
	ULONGLONG ullTotalCluster = 0;
	ULONG ulBytesPerCluster = 0;
	HANDLE hEvent = NULL;
    bool retry = false;

	if (NULL == hVolume ||
		NULL == pullTotalCluster ||
		NULL == pulBytesPerCluster)
	{
		bsr_err(86, BSR_LC_VOLUME, NO_OBJECT, "Failed to get cluster info with volume handle due to invalid parameter. volume handle(%p), total cluster(%p), bytes per cluster(%p)", hVolume, pullTotalCluster, pulBytesPerCluster);
		return bRet;
	}

	do {
		usFileSystemType = GetFileSystemTypeWithHandle(hVolume, &retry);
		if (usFileSystemType == 0) {
            if (retry) 
				bRet = -EAGAIN;
			else
				bsr_err(87, BSR_LC_VOLUME, NO_OBJECT, "Failed to get cluster info with volume handle due to failure to get file system type. %d", usFileSystemType);

			break;		
		}

		// getting fs volume data sometimes gets pended when it coincides with another peer's, need to wait until the operation's done.
		status = ZwCreateEvent(&hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
		if (!NT_SUCCESS(status)) {
			bsr_err(88, BSR_LC_VOLUME, NO_OBJECT, "Failed to get cluster info with volume handle due to failure to create event. status(0x%x)", status);
			break;
		}
		
		// supported file systems
		// 1. NTFS
		// 2. REFS
		switch (usFileSystemType) {
		case FILESYSTEM_STATISTICS_TYPE_NTFS:
		{
			NTFS_VOLUME_DATA_BUFFER nvdb = { 0, };

			status = ZwFsControlFile(hVolume, hEvent, NULL, NULL, &ioStatus, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &nvdb, sizeof(nvdb));
			if (!NT_SUCCESS(status)) {
				bsr_err(89, BSR_LC_VOLUME, NO_OBJECT, "Failed to get cluster info with volume handle due to failure to fsctl code FSCTL_GET_NTFS_VOLUME_DATA. status(0x%x)", status);
				break;
			}

			ZwWaitForSingleObject(hEvent, FALSE, NULL);
			ullTotalCluster = nvdb.TotalClusters.QuadPart;
			ulBytesPerCluster = nvdb.BytesPerCluster;
			break;

		}
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
		case FILESYSTEM_STATISTICS_TYPE_REFS:
		{
			REFS_VOLUME_DATA_BUFFER rvdb = { 0, };

			status = ZwFsControlFile(hVolume, hEvent, NULL, NULL, &ioStatus, FSCTL_GET_REFS_VOLUME_DATA, NULL, 0, &rvdb, sizeof(rvdb));
			if (!NT_SUCCESS(status)) {
				bsr_err(90, BSR_LC_VOLUME, NO_OBJECT, "Failed to get cluster info with volume handle due to failure to fsctl code FSCTL_GET_REFS_VOLUME_DATA. status(0x%x)", status); 
				break;
			}

			ZwWaitForSingleObject(hEvent, FALSE, NULL);
			ullTotalCluster = rvdb.TotalClusters.QuadPart;
			ulBytesPerCluster = rvdb.BytesPerCluster;
			break;
		}
#endif
		default:
			bsr_warn(92, BSR_LC_VOLUME, NO_OBJECT, "The file system %u is not supported", usFileSystemType);
			break;
		}

		if (0 == ullTotalCluster ||
			0 == ulBytesPerCluster)
		{
			bsr_err(91, BSR_LC_VOLUME, NO_OBJECT, "Failed to get cluster info with volume handle due to cluster information is invalid, total cluster(%llu), bytes per cluster(%u)", ullTotalCluster, ulBytesPerCluster);
			break;
		}

		bRet = 0;

	} while (false);

	if (bRet == 0) {
		*pullTotalCluster = ALIGN(ullTotalCluster, BITS_PER_BYTE);
		*pulBytesPerCluster = ulBytesPerCluster;
	}

	if (NULL != hEvent) {
		ZwClose(hEvent);
		hEvent = NULL;
	}
	
	return bRet;
}

// DW-1317
/*   makes volume to be read-only. there will be no write at all when mounted, also any write operation to this volume will be failed. (0xC00000A2 : STATUS_MEDIA_WRITE_PROTECTED)
   be sure that bsr must not go sync target before clearing read-only attribute.
   for mounted read-only volume, write operation would come up as soon as read-only attribute is cleared.
*/
#define GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY          (0x1000000000000000)
bool ChangeVolumeReadonly(unsigned int minor, bool set)
{
	HANDLE hVolume = NULL;
	bool bRet = FALSE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK iosb = { 0, };

	do {
		hVolume = GetVolumeHandleFromDeviceMinor(minor);
		if (NULL == hVolume) {
			bsr_err(73, BSR_LC_VOLUME, NO_OBJECT, "Failed to change volume read only due to could not get volume handle from minor(%u)", minor);
			break;
		}
		
		//VOLUME_GET_GPT_ATTRIBUTES_INFORMATION IOCTL_VOLUME_GET_GPT_ATTRIBUTES
		VOLUME_GET_GPT_ATTRIBUTES_INFORMATION vggai = { 0, };		

		status = ZwDeviceIoControlFile(hVolume, NULL, NULL, NULL, &iosb, IOCTL_VOLUME_GET_GPT_ATTRIBUTES, NULL, 0, &vggai, sizeof(vggai));
		if (status != STATUS_SUCCESS) {
			bsr_err(74, BSR_LC_VOLUME, NO_OBJECT, "Failed to change volume read only due to failure to ioctl code IOCTL_VOLUME_GET_GPT_ATTRIBUTES. status(0x%x)", status);
			break;
		}

		if (vggai.GptAttributes & GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY) {
			if (set) {
				// No additional setting attribute is required.
				bsr_info(46, BSR_LC_DRIVER, NO_OBJECT, "Specified volume is read-only already.");
				bRet = true;
				break;
			}
			else {
				// clear read-only attribute.
				vggai.GptAttributes &= ~GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY;
			}
		}
		else {
			if (!set) {
				// No additional setting attribute is required.
				bsr_info(47, BSR_LC_DRIVER, NO_OBJECT, "Specified volume is writable already");
				bRet = true;
				break;
			}
			else {
				// set read-only attribute.
				vggai.GptAttributes |= GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY;
			}
		}

		VOLUME_SET_GPT_ATTRIBUTES_INFORMATION vsgai = { 0, };
		vsgai.GptAttributes = vggai.GptAttributes;
		
#ifdef  _WIN32_CHECK_PARTITION_STYLE
		// DW-1495 Make sure the disk is the disk is MBR and GPT and specify another argument. 
		 * If you are using only GPT disks, att_mod_mutex is not required and can be removed later. 
		 */ 
		PARTITION_INFORMATION_EX	partInfoEx;
		
		status = ZwDeviceIoControlFile(hVolume, NULL, NULL, NULL, &iosb, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &partInfoEx, sizeof(partInfoEx));
		if (status != STATUS_SUCCESS) {
			bsr_err(75, BSR_LC_VOLUME, NO_OBJECT,"ZwDeviceIoControlFile with IOCTL_DISK_GET_PARTITION_INFO_EX failed, status(0x%x)", status);
			break;
		}
		else {
			bsr_debug(118, BSR_LC_DRIVER, NO_OBJECT,"success to get PARTITION_FORMATION_EX for volume(minor: %d) PartitionStyle = %d", minor, partInfoEx.PartitionStyle);
		}
		
		// documentation says that ApplyToAllConnectedVolumes is required to support MBR disk.
		// PARTITION_STYLE_MBR = 0, PARTITION_STYLE_GPT = 1, PARTITION_STYLE_RAW = 2
		if (partInfoEx.PartitionStyle == 0){ 
			vsgai.ApplyToAllConnectedVolumes = TRUE;
		}
		else if(partInfoEx.PartitionStyle == 1){
			vsgai.ApplyToAllConnectedVolumes = FALSE; 
		} 
		else {
			bsr_err(76, BSR_LC_VOLUME, NO_OBJECT,"This PartitionStyle is Raw (minor: %d)", minor);
		}
#else
		// documentation says that ApplyToAllConnectedVolumes is required to support MBR disk.
		vsgai.ApplyToAllConnectedVolumes = TRUE;
#endif
		status = ZwDeviceIoControlFile(hVolume, NULL, NULL, NULL, &iosb, IOCTL_VOLUME_SET_GPT_ATTRIBUTES, &vsgai, sizeof(vsgai), NULL, 0);
		if (status != STATUS_SUCCESS) {
			bsr_err(77, BSR_LC_VOLUME, NO_OBJECT, "Failed to change volume read only due to failure to ioctl code IOCTL_VOLUME_SET_GPT_ATTRIBUTES. status(0x%x)", status);
			break;
		}
		else {
			bsr_info(51, BSR_LC_DRIVER, NO_OBJECT, "Read-only attribute for volume(minor: %d) has been %s", minor, set ? "set" : "cleared");
		}
		
		bRet = true;

	} while (false);
	
	if (hVolume != NULL) {
		ZwClose(hVolume);
		hVolume = NULL;
	}

	return bRet;
}

#define RETRY_MAX_COUNT 10

// returns volume bitmap and cluster information.
PVOID GetVolumeBitmap(struct bsr_device *device, PULONGLONG pullTotalCluster, PULONG pulBytesPerCluster)
{
	PVOLUME_BITMAP_BUFFER pVbb = NULL;
	HANDLE hVolume = NULL;
	IO_STATUS_BLOCK ioStatus = { 0, };
	STARTING_LCN_INPUT_BUFFER slib = { 0, };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BOOLEAN bRet = FALSE;
    int ret = 0;

	if (NULL == pullTotalCluster ||
		NULL == pulBytesPerCluster)
	{
		bsr_err(78, BSR_LC_VOLUME, device, "Failed to get volume bitmap due to invalid parameter, total cluster(%p), bytes per cluster(%p)", pullTotalCluster, pulBytesPerCluster);
		return NULL;
	}

	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		bsr_err(79, BSR_LC_VOLUME, device, "Failed to get volume bitmap due to could not get volume bitmap because of high irql(%d)", KeGetCurrentIrql());
		return NULL;
	}

	do {
        int rtc = 0;

retry:
		hVolume = GetVolumeHandleFromDeviceMinor(device->minor);
		if (NULL == hVolume) {
			bsr_err(80, BSR_LC_VOLUME, device, "Failed to get volume bitmap due to could not get volume handle from minor(%u)", device->minor);
			break;
		}
				
		ret =  GetClusterInfoWithVolumeHandle(hVolume, pullTotalCluster, pulBytesPerCluster);
        if (0 != ret) {
            // DW-2015 if the STATUS_INVALID_PARAMETER condition is received when using the handle, retries up to RETRY_MAX_COUNT(10).
			if (ret == -EAGAIN && rtc < RETRY_MAX_COUNT) {
				if (NULL != hVolume){
					ZwClose(hVolume);
					hVolume = NULL;
				}
				rtc++;
				bsr_info(55, BSR_LC_DRIVER, device, "Retry to get volume handle (%d/%d), minor(%u)", rtc, RETRY_MAX_COUNT, device->minor);
				goto retry;
			}
			bsr_err(81, BSR_LC_VOLUME, device, "Could not get cluster information");
			break;
		}

		ULONG ulBitmapSize = sizeof(VOLUME_BITMAP_BUFFER) + (ULONG)(*pullTotalCluster / BITS_PER_BYTE);
		
		pVbb = (PVOLUME_BITMAP_BUFFER)ExAllocatePoolWithTag(NonPagedPool, ulBitmapSize, '16SB');
		if (NULL == pVbb) {
			bsr_err(64, BSR_LC_MEMORY, device, "Failed to get volume bitmap due to failure to allocate %d size memory for bitmap buffer", ulBitmapSize);
			break;
		}
				
		slib.StartingLcn.QuadPart = 0;
		status = ZwFsControlFile(hVolume, NULL, NULL, NULL, &ioStatus, FSCTL_GET_VOLUME_BITMAP, &slib, sizeof(slib), pVbb, ulBitmapSize);
		if (!NT_SUCCESS(status)) {
			bsr_err(82, BSR_LC_VOLUME, device, "Failed to get volume bitmap due to failure to ioctl code FSCTL_GET_VOLUME_BITMAP. status(%0x%x)", status);
			break;
		}
				
		bRet = TRUE;

	} while (false);

	if (NULL != hVolume) {
		ZwClose(hVolume);
		hVolume = NULL;
	}

	if (!bRet) {
		*pullTotalCluster = 0;
		*pulBytesPerCluster = 0;

		if (NULL != pVbb) {
			ExFreePool(pVbb);
			pVbb = NULL;
		}
	}

	return (PVOLUME_BITMAP_BUFFER)pVbb;
}
#endif

PVOLUME_EXTENSION
mvolSearchDevice( PWCHAR PhysicalDeviceName )
{
	PROOT_EXTENSION		RootExtension = NULL;
	PVOLUME_EXTENSION	VolumeExtension = NULL;

	RootExtension = mvolRootDeviceObject->DeviceExtension;
	VolumeExtension = RootExtension->Head;
	while( VolumeExtension != NULL ) {
		if( !_wcsicmp(VolumeExtension->PhysicalDeviceName, PhysicalDeviceName) ) {
			return VolumeExtension;
		}

		VolumeExtension = VolumeExtension->Next;
	}
	
	return NULL;
}

PVOLUME_EXTENSION
mvolSearchVolExtention(PDEVICE_OBJECT PhysicalDevice)
{
	PROOT_EXTENSION		RootExtension = NULL;
	PVOLUME_EXTENSION	VolumeExtension = NULL;

	RootExtension = mvolRootDeviceObject->DeviceExtension;
	VolumeExtension = RootExtension->Head;
	while(VolumeExtension != NULL) {
		if(VolumeExtension->PhysicalDeviceObject == PhysicalDevice) {
			return VolumeExtension;
		}

		VolumeExtension = VolumeExtension->Next;
	}
	
	return NULL;
}

VOID
mvolAddDeviceList( PVOLUME_EXTENSION pEntry )
{
	PROOT_EXTENSION		RootExtension = mvolRootDeviceObject->DeviceExtension;
	PVOLUME_EXTENSION	pList = RootExtension->Head;

	if( pList == NULL ) {
		RootExtension->Head = pEntry;
		InterlockedIncrement16( (SHORT*)&RootExtension->Count );
		return ;
	}

	while( pList->Next != NULL ) {
		pList = pList->Next;
	}

	pList->Next = pEntry;
	InterlockedIncrement16((SHORT*)&RootExtension->Count);
	return ;
}

VOID
mvolDeleteDeviceList( PVOLUME_EXTENSION pEntry )
{
	PROOT_EXTENSION		RootExtension = mvolRootDeviceObject->DeviceExtension;
	PVOLUME_EXTENSION	pList = RootExtension->Head;
	PVOLUME_EXTENSION	pTemp = NULL;

	if( pList == NULL )	return ;
	
    if (pList == pEntry) {
		RootExtension->Head = pList->Next;
		InterlockedDecrement16((SHORT*)&RootExtension->Count);
		return ;
	}

    while (pList->Next && pList->Next != pEntry) {
		pList = pList->Next;
	}

	if( pList->Next == NULL )	return ;

	pTemp = pList->Next;
	pList->Next = pTemp->Next;
	InterlockedDecrement16((SHORT*)&RootExtension->Count);
}

ULONG
mvolGetDeviceCount()
{
	PROOT_EXTENSION		RootExtension = NULL;
	PVOLUME_EXTENSION	VolumeExtension = NULL;
	ULONG			count = 0;
	
	RootExtension = mvolRootDeviceObject->DeviceExtension;
	VolumeExtension = RootExtension->Head;
	while( VolumeExtension != NULL ) {
		count++;
		VolumeExtension = VolumeExtension->Next;
	}

	bsr_debug(119, BSR_LC_DRIVER, NO_OBJECT, "DeviceCount=%d", count);

	return count;
}

VOID
MVOL_LOCK()
{
	NTSTATUS					status;
	
	status = KeWaitForMutexObject( &mvolMutex, Executive, KernelMode, FALSE, NULL );
	if( !NT_SUCCESS(status) ) {
		bsr_err(59, BSR_LC_DRIVER, NO_OBJECT, "Failed to lock due to failure to wait. status(%x)", status);
	}
}

VOID
MVOL_UNLOCK()
{
	KeReleaseMutex( &mvolMutex, FALSE );
}

VOID
COUNT_LOCK( PVOLUME_EXTENSION VolumeExtension )
{
	NTSTATUS	status;

	status = KeWaitForMutexObject( &VolumeExtension->CountMutex, Executive, KernelMode, FALSE, NULL );
	if( !NT_SUCCESS(status) ) {
		bsr_err(60, BSR_LC_DRIVER, NO_OBJECT, "Failed to lock due to failure to wait. status(%x)", status);
	}
}

VOID
COUNT_UNLOCK( PVOLUME_EXTENSION VolumeExtension )
{
	KeReleaseMutex( &VolumeExtension->CountMutex, FALSE );
}

// Inputs:
//   MountPoint - this is the buffer containing the mountpoint structure used for the query
//   MountPointLength - this is the total size of the MountPoint buffer
//   MountPointInfoLength - the size of the mount point Info structure
//
// Outputs:
//   MountPointInfo - this is the returned mount point information
//   MountPointInfoLength - the # of bytes actually needed
//
// Returns:
//   Results of the underlying operation
//
// Notes:
//   Re-opening the mount manager could be optimized if that were an important goal;
//   We avoid it to minimize handle context problems.
//   http://www.osronline.com/article.cfm?name=mountmgr.zip&id=107
//
NTSTATUS QueryMountPoint(
	_In_ PVOID MountPoint,
	_In_ ULONG MountPointLength,
	_Inout_ PVOID MountPointInfo,
	_Out_  PULONG MountPointInfoLength)
{
	OBJECT_ATTRIBUTES mmgrObjectAttributes;
	UNICODE_STRING mmgrObjectName;
	NTSTATUS status;
	HANDLE mmgrHandle;
	IO_STATUS_BLOCK iosb;
	HANDLE testEvent;

	//
	// First, we need to obtain a handle to the mount manager, so we must:
	//
	//  - Initialize the unicode string with the mount manager name
	//  - Build an object attributes structure
	//  - Open the mount manager
	//
	// This should yield a valid handle for calling the mount manager
	//

	//
	// Initialize the unicode string with the mount manager's name
	//
	RtlInitUnicodeString(&mmgrObjectName, MOUNTMGR_DEVICE_NAME);

	//
	// Initialize object attributes.
	//
	mmgrObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	mmgrObjectAttributes.RootDirectory = NULL;
	mmgrObjectAttributes.ObjectName = &mmgrObjectName;

	//
	// Note: in a kernel driver, we'd add OBJ_KERNEL_HANDLE
	// as another attribute.
	//
	mmgrObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
	mmgrObjectAttributes.SecurityDescriptor = NULL;
	mmgrObjectAttributes.SecurityQualityOfService = NULL;

	//
	// Open the mount manager
	//
	status = ZwCreateFile(&mmgrHandle,
		FILE_READ_DATA | FILE_WRITE_DATA,
		&mmgrObjectAttributes,
		&iosb,
		0, // allocation is meaningless
		0, // no attributes specified
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // we're willing to share
		FILE_OPEN, // must already exist
		FILE_NON_DIRECTORY_FILE, // must NOT be a directory
		NULL, // no EA buffer
		0); // no EA buffer size...
	if (!NT_SUCCESS(status) ||
		!NT_SUCCESS(iosb.Status)) {
		bsr_warn(88, BSR_LC_DRIVER, NO_OBJECT, "Unable to open %wZ, error = 0x%x", &mmgrObjectName, status);
		return status;
	}

	//
	// If we get to here, we assume it was successful.  We need an event object
	// for monitoring the completion of I/O operations.
	//
	status = ZwCreateEvent(&testEvent,
		GENERIC_ALL,
		0, // no object attributes
		NotificationEvent,
		FALSE);
	if (!NT_SUCCESS(status)) {
		bsr_warn(89, BSR_LC_DRIVER, NO_OBJECT, "Failed to create event (0x%x)", status);
		return status;
	}

	status = ZwDeviceIoControlFile(
		mmgrHandle,
		testEvent,
		0, // no apc
		0, // no apc context
		&iosb,
		IOCTL_MOUNTMGR_QUERY_POINTS,
		MountPoint, // input buffer
		MountPointLength, // size of input buffer
		MountPointInfo, // output buffer
		*MountPointInfoLength); // size of output buffer
	if (STATUS_PENDING == status) {
		//
		// Must wait for the I/O operation to complete
		//
		status = ZwWaitForSingleObject(testEvent, TRUE, 0);
		if (NT_SUCCESS(status)) {
			status = iosb.Status;
		}
	}

	//
	// Regardless of the results, we are done with the mount manager and event
	// handles so discard them.
	//
	(void)ZwClose(testEvent);
	(void)ZwClose(mmgrHandle);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	*MountPointInfoLength = (ULONG)iosb.Information;

	return STATUS_SUCCESS;
}

/**
* @brief
*   get volume's unique id
*   this id is in MOUNTDEV_UNIQUE_ID structure, you must free memory after using this
*   reference to <http://msdn.microsoft.com/en-us/library/windows/hardware/ff567603(v=vs.85).aspx> 
* @param
*   volmgr - driver's instance object pointer
* @return
*   volume's unique id type of PMOUNTDEV_UNIQUE_ID
*/
PMOUNTDEV_UNIQUE_ID QueryMountDUID(PDEVICE_OBJECT devObj)
{
    PMOUNTDEV_UNIQUE_ID guid = NULL;
    NTSTATUS result = STATUS_SUCCESS;
    SIZE_T cbBuf = sizeof(MOUNTDEV_UNIQUE_ID) + 256;

    PAGED_CODE();
    for (;;) {
        PIRP req = NULL;
        IO_STATUS_BLOCK ioStatus;
        KEVENT evnt;

        KeInitializeEvent(&evnt, NotificationEvent, FALSE);

        guid = (PMOUNTDEV_UNIQUE_ID)ExAllocatePoolWithTag(PagedPool, cbBuf, '08SB');
        if (NULL == guid) {
			bsr_debug(55, BSR_LC_VOLUME, NO_OBJECT, "Out of memory.");
            return NULL;
        }

        req = IoBuildDeviceIoControlRequest(IOCTL_MOUNTDEV_QUERY_UNIQUE_ID
            , devObj, NULL, 0, guid, (ULONG)cbBuf, FALSE, &evnt, &ioStatus);
        if (NULL == req) {
            goto Finally;
        }

        result = IoCallDriver(devObj, req);
        if (STATUS_PENDING == result) {
            KeWaitForSingleObject(&evnt, Executive, KernelMode, FALSE, NULL);
        }

        if (!NT_SUCCESS(ioStatus.Status)) {
            if (STATUS_BUFFER_OVERFLOW == ioStatus.Status) {
                // Buffer is too small to store unique id information. We re-allocate memory for
                // bigger size. If the desired buffer size is smaller than we created, something is
                // wrong. We don't retry.
                if (sizeof(guid->UniqueId) + guid->UniqueIdLength > cbBuf) {
                    cbBuf = sizeof(guid->UniqueIdLength) + guid->UniqueIdLength;
                    ExFreePool(guid);
                    guid = NULL;
                    continue;
                }
            }

            result = ioStatus.Status;
            goto Finally;
        }

        break;
    }

Finally:
    {
        if (!NT_SUCCESS(result)) {
			bsr_debug(56, BSR_LC_VOLUME, NO_OBJECT, "Failed to retrieve a GUID: 0x%lx", result);
            ExFreePool(guid);
            guid = NULL;
        }

        return guid;
    }
}

/**
* @brief
*/
void PrintVolumeDuid(PDEVICE_OBJECT devObj)
{
	PMOUNTDEV_UNIQUE_ID guid = QueryMountDUID(devObj);

    if (NULL == guid) {
		bsr_warn(45, BSR_LC_VOLUME, NO_OBJECT, "Volume GUID: NULL", 0);
        return;
    }

    int i;
    char pguid_text[128] = {0, };
    char temp[8] = {0, };

    for (i = 0; i < guid->UniqueIdLength; ++i) {
        _itoa_s(guid->UniqueId[i], temp, 8, 16);
		strncat(pguid_text, temp, sizeof(pguid_text)- strlen(pguid_text) - 1);
		strncat(pguid_text, " ", sizeof(pguid_text) - strlen(pguid_text) - 1);
    }

	bsr_debug(57, BSR_LC_VOLUME, NO_OBJECT, "device object(0x%x), Volume GUID(%s)", devObj, pguid_text);

    ExFreePool(guid);
}

NTSTATUS
GetDriverLetterByDeviceName(IN PUNICODE_STRING pDeviceName, OUT PUNICODE_STRING pDriveLetter)
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK StatusBlock;
	PFILE_OBJECT pVolumeFileObject = NULL;
	HANDLE FileHandle;

	InitializeObjectAttributes(&ObjectAttributes,
		pDeviceName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	Status = ZwCreateFile(&FileHandle,
		SYNCHRONIZE | FILE_READ_DATA,
		&ObjectAttributes,
		&StatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (Status != STATUS_SUCCESS) {
		return Status;
	}
	Status = ObReferenceObjectByHandle(FileHandle,
		FILE_READ_DATA,
		*IoFileObjectType,
		KernelMode,
		&pVolumeFileObject,
		NULL);
	if (Status != STATUS_SUCCESS) {
		ZwClose(FileHandle);
		bsr_err(61, BSR_LC_DRIVER, NO_OBJECT, "Failed to get driver letter by device name due to failed to reference object file handle. status(0x%08X)", Status);
		return Status;
	}

	Status = IoVolumeDeviceToDosName(pVolumeFileObject->DeviceObject, pDriveLetter);
	if (Status != STATUS_SUCCESS) {
		bsr_err(62, BSR_LC_DRIVER, NO_OBJECT, "Failed to get driver letter by device name due to failure to volume device dos name. status(%x)", Status);
		// return Status;
	}
	ObDereferenceObject(pVolumeFileObject);
	ZwClose(FileHandle);
	return Status;
}

/**
* @brief
*   delete registry's value
* @param
*   preg_path - UNICODE_STRING type's path ex)"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\bsrvflt\\volumes"
*   pvalue_name - UNICODE_STRING type's value
* @return
*   success : STATUS_SUCCESS 
*   fail : api's return value
*/
NTSTATUS DeleteRegistryValueKey(__in PUNICODE_STRING preg_path, __in PUNICODE_STRING pvalue_name)
{
    PAGED_CODE();

    OBJECT_ATTRIBUTES   attributes;
    NTSTATUS            status;
    HANDLE              hKey = NULL;

    InitializeObjectAttributes(&attributes,
        preg_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&hKey, DELETE, &attributes);
    if (!NT_SUCCESS(status)) {
        bsr_warn(90, BSR_LC_DRIVER, NO_OBJECT, "Failed to open registry key. status(0x%x)", status);
        goto cleanup;
    }

    status = ZwDeleteValueKey(hKey, pvalue_name);
    if (!NT_SUCCESS(status)) {
		bsr_warn(91, BSR_LC_DRIVER, NO_OBJECT, "Failed to delete registry key. status(0x%x)", status);
        goto cleanup;
    }

cleanup:
    if (hKey) {
        ZwClose(hKey);
    }

    return status;
}

NTSTATUS GetRegistryValue(PCWSTR pwcsValueName, ULONG *pReturnLength, UCHAR *pucReturnBuffer, PUNICODE_STRING pRegistryPath)
{
    HANDLE hKey;
    ULONG ulLength;
    NTSTATUS status;
    OBJECT_ATTRIBUTES stObjAttr;
    UNICODE_STRING valueName;
    KEY_VALUE_PARTIAL_INFORMATION stKeyInfo;
    PKEY_VALUE_PARTIAL_INFORMATION pstKeyInfo;

    RtlInitUnicodeString(&valueName, pwcsValueName);

    InitializeObjectAttributes(&stObjAttr, pRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &stObjAttr);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ulLength = 0;
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, &stKeyInfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &ulLength);
    if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW) && (status != STATUS_BUFFER_TOO_SMALL)) {
        ZwClose(hKey);
        return status;
    }

    pstKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulLength, '36SB');
    if (pstKeyInfo == NULL) {
        ZwClose(hKey);
        return status;
    }

    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pstKeyInfo, ulLength, &ulLength);
    if (NT_SUCCESS(status)) {
        *pReturnLength = pstKeyInfo->DataLength;
        RtlCopyMemory(pucReturnBuffer, pstKeyInfo->Data, pstKeyInfo->DataLength);
    }
    ExFreePool(pstKeyInfo);
    ZwClose(hKey);
    return status;
}

int initRegistry(__in PUNICODE_STRING RegPath_unicode)
{
	ULONG ulLength;
	UCHAR aucTemp[255] = { 0 };
	NTSTATUS status;

#ifndef _WIN32
	// set proc_details
	status = GetRegistryValue(L"proc_details", &ulLength, &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		proc_details = *(int*) aucTemp;
	}
	else {
		proc_details = 1;
	}
#endif

	// set bypass_level
	status = GetRegistryValue(L"bypass_level", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_bypass_level = *(int*) aucTemp;
	}
	else {
		g_bypass_level = 0;
	}

	// set read_filter
#if 0	
	status = GetRegistryValue(L"read_filter", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_read_filter = *(int*) aucTemp;
	}
	else {
		g_read_filter = 0;
	}
#endif
	g_read_filter = 0;

	//set g_mj_flush_buffers_filter
	status = GetRegistryValue(L"flush_filter", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS) {
		g_mj_flush_buffers_filter = *(int*) aucTemp;
	}
	else {
		g_mj_flush_buffers_filter = 0;
	}
	
	// set use_volume_lock
	status = GetRegistryValue(L"use_volume_lock", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_use_volume_lock = *(int*) aucTemp;
	}
	else {
		g_use_volume_lock = 0;
	}

	// set log level
	int log_level = LOG_LV_DEFAULT;	
	status = GetRegistryValue(LOG_LV_REG_VALUE_NAME, &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		log_level = *(int*)aucTemp;
	}
	Set_log_lv(log_level);

	// BSR-654 set debug log out put category
	int debug_log_category_enable = DEBUG_LOG_OUT_PUT_CATEGORY_DEFAULT;
	status = GetRegistryValue(DEBUG_LOG_CATEGORY_REG_VALUE_NAME, &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		debug_log_category_enable = *(int*)aucTemp;
	}
	atomic_set(&g_debug_output_category, debug_log_category_enable);

	// set g_netlink_tcp_port
	status = GetRegistryValue(L"netlink_tcp_port", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_netlink_tcp_port = *(int*) aucTemp;
	}
	else {
		g_netlink_tcp_port = NETLINK_PORT;
	}

	// set daemon_tcp_port
	status = GetRegistryValue(L"daemon_tcp_port", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_daemon_tcp_port = *(int*) aucTemp;
	}
	else {
		g_daemon_tcp_port = 5679;
	}

#ifdef _WIN_HANDLER_TIMEOUT
	status = GetRegistryValue(L"handler_use", &ulLength, (UCHAR*) &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_handler_use = *(int*) aucTemp;
	}
	else {
		g_handler_use = 0;
	}
	
	status = GetRegistryValue(L"handler_timeout", &ulLength, (UCHAR*) &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_handler_timeout = *(int*) aucTemp;
		if (g_handler_timeout < 0) {
			g_handler_timeout = BSR_TIMEOUT_DEF;
		}
	} else {
		g_handler_timeout = BSR_TIMEOUT_DEF/10;
	}	
	g_handler_timeout = g_handler_timeout * 1000; // change to ms
	
	status = GetRegistryValue(L"handler_retry", &ulLength, (UCHAR*) &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS) {
		g_handler_retry = *(int*) aucTemp;
		if (g_handler_retry < 0) {
			g_handler_retry = 0;
		}
	} else {
		g_handler_retry = 0;
	}
#endif

    status = GetRegistryValue(L"bsrmon_run", &ulLength, (UCHAR*) &aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		g_bsrmon_run = *(int*) aucTemp;
	}
	else {
		g_bsrmon_run = 1;
	}

	// set ver
    // BSR_DOC: not used
	status = GetRegistryValue(L"ver", &ulLength, (UCHAR*)&aucTemp, RegPath_unicode);
	if (status == STATUS_SUCCESS){
		RtlCopyMemory(g_ver, aucTemp, ulLength * 2);
	}
	else {
		RtlCopyMemory(g_ver, L"BSR", 4 * 2); 
	}
	// _WIN32_V9: proc_details is removed. 
	bsr_info(63, BSR_LC_DRIVER, NO_OBJECT, "registry_path[%wZ]", RegPath_unicode);
	bsr_info(64, BSR_LC_DRIVER, NO_OBJECT, "bypass_level=%d, read_filter=%d, use_volume_lock=%d, netlink_tcp_port=%d, daemon_tcp_port=%d, ver=%ws", g_bypass_level, g_read_filter,
																																	g_use_volume_lock, g_netlink_tcp_port,
																																	g_daemon_tcp_port, g_ver);

	return 0;
}

// DW-1327 notifies callback object with given name and parameter.
NTSTATUS NotifyCallbackObject(PWSTR pszCallbackName, PVOID pParam)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES cboa = { 0, };
	UNICODE_STRING usCbName;
	PCALLBACK_OBJECT pCallbackObj;

	if (pszCallbackName == NULL) {
		return STATUS_INVALID_PARAMETER;
	}
	
	RtlInitUnicodeString(&usCbName, pszCallbackName);
	InitializeObjectAttributes(&cboa, &usCbName, OBJ_CASE_INSENSITIVE, 0, 0);

	status = ExCreateCallback(&pCallbackObj, &cboa, FALSE, TRUE);

	if (NT_SUCCESS(status)) {
		ExNotifyCallback(pCallbackObj, pParam, NULL);
		ObDereferenceObject(pCallbackObj);
	}
	else
		bsr_err(65, BSR_LC_DRIVER, NO_OBJECT, "Failed to notify callback object due to open callback object for %ws. status : 0x%x", pszCallbackName, status);

	return status;
}

// DW-1327 notifies callback object of bsrlock, this routine is used to block or allow I/O by bsrlock.
NTSTATUS SetBsrlockIoBlock(PVOLUME_EXTENSION pVolumeExtension, bool bBlock)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BSRLOCK_VOLUME_CONTROL volumeControl = { 0, };
	
	volumeControl.volume.volumeType = VOLUME_TYPE_DEVICE_OBJECT;
	volumeControl.volume.volumeID.pVolumeObject = pVolumeExtension->PhysicalDeviceObject;
	volumeControl.bBlock = bBlock;

	status = NotifyCallbackObject(BSRLOCK_CALLBACK_NAME, &volumeControl);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	return status;
}

/**
 * @brief
 *	caller should release unicode's buffer(in bytes)
 */
ULONG ucsdup(_Out_ UNICODE_STRING * dst, _In_ WCHAR * src, ULONG size)
{
	if (!dst || !src) {
		return 0;
	}

    dst->Buffer = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, size + sizeof(UNICODE_NULL), '46SB');
	if (dst->Buffer) {
		dst->Length = (USHORT)size;
		dst->MaximumLength = (USHORT)(size + sizeof(UNICODE_NULL));
		RtlCopyMemory(dst->Buffer, src, size);
		return size;
	}

	return 0;
}

// GetIrpName
// from:https://github.com/iocellnetworks/ndas4windows/blob/master/fremont/3.20-stable/src/drivers/ndasfat/ndasfat.c

#ifdef IRP_TEST
#define OPERATION_NAME_BUFFER_SIZE  256
CHAR UnknownIrpMinor [] = "Unknown Irp minor code (%u)";

VOID
GetIrpName(
IN UCHAR MajorCode,
IN UCHAR MinorCode,
IN ULONG FsctlCode,
OUT PCHAR MajorCodeName,
OUT PCHAR MinorCodeName
)
/*++

Routine Description:

This routine translates the given Irp codes into printable strings which
are returned.  This guarantees to routine valid strings in each buffer.
The MinorCode string may be a NULL string (not a null pointer).

Arguments:

MajorCode - the IRP Major code of the operation
MinorCode - the IRP Minor code of the operation
FsctlCode - if this is an IRP_MJ_FILE_SYSTEM_CONTROL/IRP_MN_USER_FS_REQUEST
operation then this is the FSCTL code whose name is also
translated.  This name is returned as part of the MinorCode
string.
MajorCodeName - a string buffer at least OPERATION_NAME_BUFFER_SIZE
characters long that receives the major code name.
MinorCodeName - a string buffer at least OPERATION_NAME_BUFFER_SIZE
characters long that receives the minor/fsctl code name.

Return Value:

None.

--*/
{
    PCHAR irpMajorString;
    PCHAR irpMinorString = "";
    CHAR nameBuf[OPERATION_NAME_BUFFER_SIZE];

    switch (MajorCode) {
    case IRP_MJ_CREATE:
        irpMajorString = "IRP_MJ_CREATE";
        break;
    case IRP_MJ_CREATE_NAMED_PIPE:
        irpMajorString = "IRP_MJ_CREATE_NAMED_PIPE";
        break;
    case IRP_MJ_CLOSE:
        irpMajorString = "IRP_MJ_CLOSE";
        break;
    case IRP_MJ_READ:
        irpMajorString = "IRP_MJ_READ";
        switch (MinorCode) {
        case IRP_MN_NORMAL:
            irpMinorString = "IRP_MN_NORMAL";
            break;
        case IRP_MN_DPC:
            irpMinorString = "IRP_MN_DPC";
            break;
        case IRP_MN_MDL:
            irpMinorString = "IRP_MN_MDL";
            break;
        case IRP_MN_COMPLETE:
            irpMinorString = "IRP_MN_COMPLETE";
            break;
        case IRP_MN_COMPRESSED:
            irpMinorString = "IRP_MN_COMPRESSED";
            break;
        case IRP_MN_MDL_DPC:
            irpMinorString = "IRP_MN_MDL_DPC";
            break;
        case IRP_MN_COMPLETE_MDL:
            irpMinorString = "IRP_MN_COMPLETE_MDL";
            break;
        case IRP_MN_COMPLETE_MDL_DPC:
            irpMinorString = "IRP_MN_COMPLETE_MDL_DPC";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_WRITE:
        irpMajorString = "IRP_MJ_WRITE";
        switch (MinorCode) {
        case IRP_MN_NORMAL:
            irpMinorString = "IRP_MN_NORMAL";
            break;
        case IRP_MN_DPC:
            irpMinorString = "IRP_MN_DPC";
            break;
        case IRP_MN_MDL:
            irpMinorString = "IRP_MN_MDL";
            break;
        case IRP_MN_COMPLETE:
            irpMinorString = "IRP_MN_COMPLETE";
            break;
        case IRP_MN_COMPRESSED:
            irpMinorString = "IRP_MN_COMPRESSED";
            break;
        case IRP_MN_MDL_DPC:
            irpMinorString = "IRP_MN_MDL_DPC";
            break;
        case IRP_MN_COMPLETE_MDL:
            irpMinorString = "IRP_MN_COMPLETE_MDL";
            break;
        case IRP_MN_COMPLETE_MDL_DPC:
            irpMinorString = "IRP_MN_COMPLETE_MDL_DPC";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_QUERY_INFORMATION:
        irpMajorString = "IRP_MJ_QUERY_INFORMATION";
        break;
    case IRP_MJ_SET_INFORMATION:
        irpMajorString = "IRP_MJ_SET_INFORMATION";
        break;
    case IRP_MJ_QUERY_EA:
        irpMajorString = "IRP_MJ_QUERY_EA";
        break;
    case IRP_MJ_SET_EA:
        irpMajorString = "IRP_MJ_SET_EA";
        break;
    case IRP_MJ_FLUSH_BUFFERS:
        irpMajorString = "IRP_MJ_FLUSH_BUFFERS";
        break;
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        irpMajorString = "IRP_MJ_QUERY_VOLUME_INFORMATION";
        break;
    case IRP_MJ_SET_VOLUME_INFORMATION:
        irpMajorString = "IRP_MJ_SET_VOLUME_INFORMATION";
        break;
    case IRP_MJ_DIRECTORY_CONTROL:
        irpMajorString = "IRP_MJ_DIRECTORY_CONTROL";
        switch (MinorCode) {
        case IRP_MN_QUERY_DIRECTORY:
            irpMinorString = "IRP_MN_QUERY_DIRECTORY";
            break;
        case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
            irpMinorString = "IRP_MN_NOTIFY_CHANGE_DIRECTORY";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_FILE_SYSTEM_CONTROL:
        irpMajorString = "IRP_MJ_FILE_SYSTEM_CONTROL";
        switch (MinorCode) {
        case IRP_MN_USER_FS_REQUEST:
            switch (FsctlCode) {
            case FSCTL_REQUEST_OPLOCK_LEVEL_1:
                irpMinorString = "FSCTL_REQUEST_OPLOCK_LEVEL_1";
                break;
            case FSCTL_REQUEST_OPLOCK_LEVEL_2:
                irpMinorString = "FSCTL_REQUEST_OPLOCK_LEVEL_2";
                break;
            case FSCTL_REQUEST_BATCH_OPLOCK:
                irpMinorString = "FSCTL_REQUEST_BATCH_OPLOCK";
                break;
            case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
                irpMinorString = "FSCTL_OPLOCK_BREAK_ACKNOWLEDGE";
                break;
            case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
                irpMinorString = "FSCTL_OPBATCH_ACK_CLOSE_PENDING";
                break;
            case FSCTL_OPLOCK_BREAK_NOTIFY:
                irpMinorString = "FSCTL_OPLOCK_BREAK_NOTIFY";
                break;
            case FSCTL_LOCK_VOLUME:
                irpMinorString = "FSCTL_LOCK_VOLUME";
                break;
            case FSCTL_UNLOCK_VOLUME:
                irpMinorString = "FSCTL_UNLOCK_VOLUME";
                break;
            case FSCTL_DISMOUNT_VOLUME:
                irpMinorString = "FSCTL_DISMOUNT_VOLUME";
                break;
            case FSCTL_IS_VOLUME_MOUNTED:
                irpMinorString = "FSCTL_IS_VOLUME_MOUNTED";
                break;
            case FSCTL_IS_PATHNAME_VALID:
                irpMinorString = "FSCTL_IS_PATHNAME_VALID";
                break;
            case FSCTL_MARK_VOLUME_DIRTY:
                irpMinorString = "FSCTL_MARK_VOLUME_DIRTY";
                break;
            case FSCTL_QUERY_RETRIEVAL_POINTERS:
                irpMinorString = "FSCTL_QUERY_RETRIEVAL_POINTERS";
                break;
            case FSCTL_GET_COMPRESSION:
                irpMinorString = "FSCTL_GET_COMPRESSION";
                break;
            case FSCTL_SET_COMPRESSION:
                irpMinorString = "FSCTL_SET_COMPRESSION";
                break;
            case FSCTL_MARK_AS_SYSTEM_HIVE:
                irpMinorString = "FSCTL_MARK_AS_SYSTEM_HIVE";
                break;
            case FSCTL_OPLOCK_BREAK_ACK_NO_2:
                irpMinorString = "FSCTL_OPLOCK_BREAK_ACK_NO_2";
                break;
            case FSCTL_INVALIDATE_VOLUMES:
                irpMinorString = "FSCTL_INVALIDATE_VOLUMES";
                break;
            case FSCTL_QUERY_FAT_BPB:
                irpMinorString = "FSCTL_QUERY_FAT_BPB";
                break;
            case FSCTL_REQUEST_FILTER_OPLOCK:
                irpMinorString = "FSCTL_REQUEST_FILTER_OPLOCK";
                break;
            case FSCTL_FILESYSTEM_GET_STATISTICS:
                irpMinorString = "FSCTL_FILESYSTEM_GET_STATISTICS";
                break;
            case FSCTL_GET_NTFS_VOLUME_DATA:
                irpMinorString = "FSCTL_GET_NTFS_VOLUME_DATA";
                break;
            case FSCTL_GET_NTFS_FILE_RECORD:
                irpMinorString = "FSCTL_GET_NTFS_FILE_RECORD";
                break;
            case FSCTL_GET_VOLUME_BITMAP:
                irpMinorString = "FSCTL_GET_VOLUME_BITMAP";
                break;
            case FSCTL_GET_RETRIEVAL_POINTERS:
                irpMinorString = "FSCTL_GET_RETRIEVAL_POINTERS";
                break;
            case FSCTL_MOVE_FILE:
                irpMinorString = "FSCTL_MOVE_FILE";
                break;
            case FSCTL_IS_VOLUME_DIRTY:
                irpMinorString = "FSCTL_IS_VOLUME_DIRTY";
                break;
            case FSCTL_ALLOW_EXTENDED_DASD_IO:
                irpMinorString = "FSCTL_ALLOW_EXTENDED_DASD_IO";
                break;
            case FSCTL_FIND_FILES_BY_SID:
                irpMinorString = "FSCTL_FIND_FILES_BY_SID";
                break;
            case FSCTL_SET_OBJECT_ID:
                irpMinorString = "FSCTL_SET_OBJECT_ID";
                break;
            case FSCTL_GET_OBJECT_ID:
                irpMinorString = "FSCTL_GET_OBJECT_ID";
                break;
            case FSCTL_DELETE_OBJECT_ID:
                irpMinorString = "FSCTL_DELETE_OBJECT_ID";
                break;
            case FSCTL_SET_REPARSE_POINT:
                irpMinorString = "FSCTL_SET_REPARSE_POINT";
                break;
            case FSCTL_GET_REPARSE_POINT:
                irpMinorString = "FSCTL_GET_REPARSE_POINT";
                break;
            case FSCTL_DELETE_REPARSE_POINT:
                irpMinorString = "FSCTL_DELETE_REPARSE_POINT";
                break;
            case FSCTL_ENUM_USN_DATA:
                irpMinorString = "FSCTL_ENUM_USN_DATA";
                break;
            case FSCTL_SECURITY_ID_CHECK:
                irpMinorString = "FSCTL_SECURITY_ID_CHECK";
                break;
            case FSCTL_READ_USN_JOURNAL:
                irpMinorString = "FSCTL_READ_USN_JOURNAL";
                break;
            case FSCTL_SET_OBJECT_ID_EXTENDED:
                irpMinorString = "FSCTL_SET_OBJECT_ID_EXTENDED";
                break;
            case FSCTL_CREATE_OR_GET_OBJECT_ID:
                irpMinorString = "FSCTL_CREATE_OR_GET_OBJECT_ID";
                break;
            case FSCTL_SET_SPARSE:
                irpMinorString = "FSCTL_SET_SPARSE";
                break;
            case FSCTL_SET_ZERO_DATA:
                irpMinorString = "FSCTL_SET_ZERO_DATA";
                break;
            case FSCTL_QUERY_ALLOCATED_RANGES:
                irpMinorString = "FSCTL_QUERY_ALLOCATED_RANGES";
                break;
            case FSCTL_SET_ENCRYPTION:
                irpMinorString = "FSCTL_SET_ENCRYPTION";
                break;
            case FSCTL_ENCRYPTION_FSCTL_IO:
                irpMinorString = "FSCTL_ENCRYPTION_FSCTL_IO";
                break;
            case FSCTL_WRITE_RAW_ENCRYPTED:
                irpMinorString = "FSCTL_WRITE_RAW_ENCRYPTED";
                break;
            case FSCTL_READ_RAW_ENCRYPTED:
                irpMinorString = "FSCTL_READ_RAW_ENCRYPTED";
                break;
            case FSCTL_CREATE_USN_JOURNAL:
                irpMinorString = "FSCTL_CREATE_USN_JOURNAL";
                break;
            case FSCTL_READ_FILE_USN_DATA:
                irpMinorString = "FSCTL_READ_FILE_USN_DATA";
                break;
            case FSCTL_WRITE_USN_CLOSE_RECORD:
                irpMinorString = "FSCTL_WRITE_USN_CLOSE_RECORD";
                break;
            case FSCTL_EXTEND_VOLUME:
                irpMinorString = "FSCTL_EXTEND_VOLUME";
                break;
            case FSCTL_QUERY_USN_JOURNAL:
                irpMinorString = "FSCTL_QUERY_USN_JOURNAL";
                break;
            case FSCTL_DELETE_USN_JOURNAL:
                irpMinorString = "FSCTL_DELETE_USN_JOURNAL";
                break;
            case FSCTL_MARK_HANDLE:
                irpMinorString = "FSCTL_MARK_HANDLE";
                break;
            case FSCTL_SIS_COPYFILE:
                irpMinorString = "FSCTL_SIS_COPYFILE";
                break;
            case FSCTL_SIS_LINK_FILES:
                irpMinorString = "FSCTL_SIS_LINK_FILES";
                break;
                //case FSCTL_HSM_MSG:
                //     irpMinorString = "FSCTL_HSM_MSG";
                //    break;
                //case FSCTL_HSM_DATA:
                //    irpMinorString = "FSCTL_HSM_DATA";
                //    break;
            case FSCTL_RECALL_FILE:
                irpMinorString = "FSCTL_RECALL_FILE";
                break;
#if WINVER >= 0x0501                            
            case FSCTL_READ_FROM_PLEX:
                irpMinorString = "FSCTL_READ_FROM_PLEX";
                break;
            case FSCTL_FILE_PREFETCH:
                irpMinorString = "FSCTL_FILE_PREFETCH";
                break;
#endif                            
            default:
                sprintf(nameBuf, "Unknown FSCTL (%u)", MinorCode);
                irpMinorString = nameBuf;
                break;
            }

            sprintf(nameBuf, "%s (USER)", irpMinorString);
            irpMinorString = nameBuf;
            break;

        case IRP_MN_MOUNT_VOLUME:
            irpMinorString = "IRP_MN_MOUNT_VOLUME";
            break;
        case IRP_MN_VERIFY_VOLUME:
            irpMinorString = "IRP_MN_VERIFY_VOLUME";
            break;
        case IRP_MN_LOAD_FILE_SYSTEM:
            irpMinorString = "IRP_MN_LOAD_FILE_SYSTEM";
            break;
        case IRP_MN_TRACK_LINK:
            irpMinorString = "IRP_MN_TRACK_LINK";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_DEVICE_CONTROL:
        irpMajorString = "IRP_MJ_DEVICE_CONTROL";
        switch (MinorCode) {
        case 0:
            irpMinorString = "User request";
            break;
        case IRP_MN_SCSI_CLASS:
            irpMinorString = "IRP_MN_SCSI_CLASS";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        irpMajorString = "IRP_MJ_INTERNAL_DEVICE_CONTROL";
        break;
    case IRP_MJ_SHUTDOWN:
        irpMajorString = "IRP_MJ_SHUTDOWN";
        break;
    case IRP_MJ_LOCK_CONTROL:
        irpMajorString = "IRP_MJ_LOCK_CONTROL";
        switch (MinorCode) {
        case IRP_MN_LOCK:
            irpMinorString = "IRP_MN_LOCK";
            break;
        case IRP_MN_UNLOCK_SINGLE:
            irpMinorString = "IRP_MN_UNLOCK_SINGLE";
            break;
        case IRP_MN_UNLOCK_ALL:
            irpMinorString = "IRP_MN_UNLOCK_ALL";
            break;
        case IRP_MN_UNLOCK_ALL_BY_KEY:
            irpMinorString = "IRP_MN_UNLOCK_ALL_BY_KEY";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_CLEANUP:
        irpMajorString = "IRP_MJ_CLEANUP";
        break;
    case IRP_MJ_CREATE_MAILSLOT:
        irpMajorString = "IRP_MJ_CREATE_MAILSLOT";
        break;
    case IRP_MJ_QUERY_SECURITY:
        irpMajorString = "IRP_MJ_QUERY_SECURITY";
        break;
    case IRP_MJ_SET_SECURITY:
        irpMajorString = "IRP_MJ_SET_SECURITY";
        break;
    case IRP_MJ_POWER:
        irpMajorString = "IRP_MJ_POWER";
        switch (MinorCode) {
        case IRP_MN_WAIT_WAKE:
            irpMinorString = "IRP_MN_WAIT_WAKE";
            break;
        case IRP_MN_POWER_SEQUENCE:
            irpMinorString = "IRP_MN_POWER_SEQUENCE";
            break;
        case IRP_MN_SET_POWER:
            irpMinorString = "IRP_MN_SET_POWER";
            break;
        case IRP_MN_QUERY_POWER:
            irpMinorString = "IRP_MN_QUERY_POWER";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_SYSTEM_CONTROL:
        irpMajorString = "IRP_MJ_SYSTEM_CONTROL";
        switch (MinorCode) {
        case IRP_MN_QUERY_ALL_DATA:
            irpMinorString = "IRP_MN_QUERY_ALL_DATA";
            break;
        case IRP_MN_QUERY_SINGLE_INSTANCE:
            irpMinorString = "IRP_MN_QUERY_SINGLE_INSTANCE";
            break;
        case IRP_MN_CHANGE_SINGLE_INSTANCE:
            irpMinorString = "IRP_MN_CHANGE_SINGLE_INSTANCE";
            break;
        case IRP_MN_CHANGE_SINGLE_ITEM:
            irpMinorString = "IRP_MN_CHANGE_SINGLE_ITEM";
            break;
        case IRP_MN_ENABLE_EVENTS:
            irpMinorString = "IRP_MN_ENABLE_EVENTS";
            break;
        case IRP_MN_DISABLE_EVENTS:
            irpMinorString = "IRP_MN_DISABLE_EVENTS";
            break;
        case IRP_MN_ENABLE_COLLECTION:
            irpMinorString = "IRP_MN_ENABLE_COLLECTION";
            break;
        case IRP_MN_DISABLE_COLLECTION:
            irpMinorString = "IRP_MN_DISABLE_COLLECTION";
            break;
        case IRP_MN_REGINFO:
            irpMinorString = "IRP_MN_REGINFO";
            break;
        case IRP_MN_EXECUTE_METHOD:
            irpMinorString = "IRP_MN_EXECUTE_METHOD";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    case IRP_MJ_DEVICE_CHANGE:
        irpMajorString = "IRP_MJ_DEVICE_CHANGE";
        break;
    case IRP_MJ_QUERY_QUOTA:
        irpMajorString = "IRP_MJ_QUERY_QUOTA";
        break;
    case IRP_MJ_SET_QUOTA:
        irpMajorString = "IRP_MJ_SET_QUOTA";
        break;
    case IRP_MJ_PNP:
        irpMajorString = "IRP_MJ_PNP";
        switch (MinorCode) {
        case IRP_MN_START_DEVICE:
            irpMinorString = "IRP_MN_START_DEVICE";
            break;
        case IRP_MN_QUERY_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_QUERY_REMOVE_DEVICE";
            break;
        case IRP_MN_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_REMOVE_DEVICE";
            break;
        case IRP_MN_CANCEL_REMOVE_DEVICE:
            irpMinorString = "IRP_MN_CANCEL_REMOVE_DEVICE";
            break;
        case IRP_MN_STOP_DEVICE:
            irpMinorString = "IRP_MN_STOP_DEVICE";
            break;
        case IRP_MN_QUERY_STOP_DEVICE:
            irpMinorString = "IRP_MN_QUERY_STOP_DEVICE";
            break;
        case IRP_MN_CANCEL_STOP_DEVICE:
            irpMinorString = "IRP_MN_CANCEL_STOP_DEVICE";
            break;
        case IRP_MN_QUERY_DEVICE_RELATIONS:
            irpMinorString = "IRP_MN_QUERY_DEVICE_RELATIONS";
            break;
        case IRP_MN_QUERY_INTERFACE:
            irpMinorString = "IRP_MN_QUERY_INTERFACE";
            break;
        case IRP_MN_QUERY_CAPABILITIES:
            irpMinorString = "IRP_MN_QUERY_CAPABILITIES";
            break;
        case IRP_MN_QUERY_RESOURCES:
            irpMinorString = "IRP_MN_QUERY_RESOURCES";
            break;
        case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
            irpMinorString = "IRP_MN_QUERY_RESOURCE_REQUIREMENTS";
            break;
        case IRP_MN_QUERY_DEVICE_TEXT:
            irpMinorString = "IRP_MN_QUERY_DEVICE_TEXT";
            break;
        case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
            irpMinorString = "IRP_MN_FILTER_RESOURCE_REQUIREMENTS";
            break;
        case IRP_MN_READ_CONFIG:
            irpMinorString = "IRP_MN_READ_CONFIG";
            break;
        case IRP_MN_WRITE_CONFIG:
            irpMinorString = "IRP_MN_WRITE_CONFIG";
            break;
        case IRP_MN_EJECT:
            irpMinorString = "IRP_MN_EJECT";
            break;
        case IRP_MN_SET_LOCK:
            irpMinorString = "IRP_MN_SET_LOCK";
            break;
        case IRP_MN_QUERY_ID:
            irpMinorString = "IRP_MN_QUERY_ID";
            break;
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            irpMinorString = "IRP_MN_QUERY_PNP_DEVICE_STATE";
            break;
        case IRP_MN_QUERY_BUS_INFORMATION:
            irpMinorString = "IRP_MN_QUERY_BUS_INFORMATION";
            break;
        case IRP_MN_DEVICE_USAGE_NOTIFICATION:
            irpMinorString = "IRP_MN_DEVICE_USAGE_NOTIFICATION";
            break;
        case IRP_MN_SURPRISE_REMOVAL:
            irpMinorString = "IRP_MN_SURPRISE_REMOVAL";
            break;
        case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
            irpMinorString = "IRP_MN_QUERY_LEGACY_BUS_INFORMATION";
            break;
        default:
            sprintf(nameBuf, UnknownIrpMinor, MinorCode);
            irpMinorString = nameBuf;
        }
        break;

    default:
        sprintf(nameBuf, "Unknown Irp major code (%u)", MajorCode);
        irpMajorString = nameBuf;
    }

    strcpy(MajorCodeName, irpMajorString);
    strcpy(MinorCodeName, irpMinorString);
}

VOID
PrintIrp(
PCHAR					Where,
PVOID					VolDo,
PIRP					Irp
)
{
#if 1 // DBG

    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT		fileObject = irpSp->FileObject;
    UNICODE_STRING		nullName;
    UCHAR				minorFunction;
    CHAR				irpMajorString[OPERATION_NAME_BUFFER_SIZE];
    CHAR				irpMinorString[OPERATION_NAME_BUFFER_SIZE];

    GetIrpName(
        irpSp->MajorFunction,
        irpSp->MinorFunction,
        irpSp->Parameters.FileSystemControl.FsControlCode,
        irpMajorString,
        irpMinorString
        );

    RtlInitUnicodeString(&nullName, L"fileObject == NULL");

    if (irpSp->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL && irpSp->MinorFunction == IRP_MN_USER_FS_REQUEST)
        minorFunction = (UCHAR) ((irpSp->Parameters.FileSystemControl.FsControlCode & 0x00003FFC) >> 2);
    else if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL && irpSp->MinorFunction == 0)
        minorFunction = (UCHAR) ((irpSp->Parameters.DeviceIoControl.IoControlCode & 0x00003FFC) >> 2);
    else
        minorFunction = irpSp->MinorFunction;

    ASSERT(Irp->RequestorMode == KernelMode || Irp->RequestorMode == UserMode);

    if (KeGetCurrentIrql() < DISPATCH_LEVEL) {

        DbgPrint
            ("%s %p Irql:%d Irp:%p %s %s (%u:%u) %08x %02x ",
            (Where) ? Where : "", VolDo,
            KeGetCurrentIrql(),
            Irp, irpMajorString, irpMinorString, irpSp->MajorFunction, minorFunction,
            Irp->Flags, irpSp->Flags);

        /*"%s %c%c%c%c%c ", */
        /*(Irp->RequestorMode == KernelMode) ? "KernelMode" : "UserMode",
        (Irp->Flags & IRP_PAGING_IO) ? '*' : ' ',
        (Irp->Flags & IRP_SYNCHRONOUS_PAGING_IO) ? '+' : ' ',
        (Irp->Flags & IRP_SYNCHRONOUS_API) ? 'A' : ' ',
        BooleanFlagOn(Irp->Flags,IRP_NOCACHE) ? 'N' : ' ',
        (fileObject && fileObject->Flags & FO_SYNCHRONOUS_IO) ? '&':' ',*/

        DbgPrint
            ("file: %p  %08x %p %wZ %d\n",
            fileObject,
            fileObject ? fileObject->Flags : 0,
            fileObject ? fileObject->RelatedFileObject : NULL,
            fileObject ? &fileObject->FileName : &nullName,
            fileObject ? fileObject->FileName.Length : 0
            );
    }

#else

    UNREFERENCED_PARAMETER(DebugLevel);
    UNREFERENCED_PARAMETER(Where);
    UNREFERENCED_PARAMETER(VolDo);
    UNREFERENCED_PARAMETER(Irp);

#endif

    return;
}
#endif
