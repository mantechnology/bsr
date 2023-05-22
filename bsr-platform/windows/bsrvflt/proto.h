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

#ifndef __PROTO_H__
#define __PROTO_H__
#include <mountdev.h>

//
// disp.c
//
_Dispatch_type_(IRP_MJ_OTHER)
DRIVER_DISPATCH mvolSendToNextDriver;
//
// sub.c
//
NTSTATUS
mvolStartDevice( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolRemoveDevice( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolDeviceUsage( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS
mvolReadWriteDevice( IN PVOLUME_EXTENSION VolumeExtension, IN PIRP Irp, IN ULONG Io, ktime_t);
NTSTATUS
mvolGetVolumeSize( PDEVICE_OBJECT TargetDeviceObject, PLARGE_INTEGER pVolumeSize );
extern NTSTATUS
mvolUpdateMountPointInfoByExtension(PVOLUME_EXTENSION pvext);
VOID
mvolLogError( PDEVICE_OBJECT DeviceObject, ULONG UniqID,
	NTSTATUS ErrorCode, NTSTATUS Status );

NTSTATUS
IOCTL_SetIOFlag(PDEVICE_OBJECT DeviceObject, PIRP Irp, ULONG Val, BOOLEAN On);

IO_COMPLETION_ROUTINE mvolIrpCompletion;

//
// util.c
//
NTSTATUS
GetDeviceName( PDEVICE_OBJECT DeviceObject, PWCHAR Buffer, ULONG BufferLength );

PVOLUME_EXTENSION
mvolSearchDevice( PWCHAR PhysicalDeviceName );

PVOLUME_EXTENSION
mvolSearchVolExtention( PDEVICE_OBJECT PhysicalDevice );


VOID
mvolAddDeviceList( PVOLUME_EXTENSION VolumeExtension );
VOID
mvolDeleteDeviceList( PVOLUME_EXTENSION VolumeExtension );
ULONG
mvolGetDeviceCount();

VOID
MVOL_LOCK();
VOID
MVOL_UNLOCK();
VOID
COUNT_LOCK( PVOLUME_EXTENSION VolumeExtension );
VOID
COUNT_UNLOCK( PVOLUME_EXTENSION VolumeExtension );

//
// ops.c
//
NTSTATUS
IOCTL_GetAllVolumeInfo( PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_GetVolumeInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_GetVolumeSize( PDEVICE_OBJECT DeviceObject, PIRP Irp );
NTSTATUS
IOCTL_VolumeReadOff( PDEVICE_OBJECT DeviceObject, PIRP Irp, BOOLEAN ReadEnable );
NTSTATUS
IOCTL_VolumeWriteOff( PDEVICE_OBJECT DeviceObject, PIRP Irp, BOOLEAN WriteEnable );
NTSTATUS
IOCTL_GetCountInfo( PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength );
NTSTATUS
IOCTL_MountVolume(PDEVICE_OBJECT DeviceObject, PIRP Irp, PULONG ReturnLength);
NTSTATUS
IOCTL_SetSimulDiskIoError( PDEVICE_OBJECT DeviceObject, PIRP Irp);
// BSR-764
NTSTATUS
IOCTL_SetSimulPerfDegr(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS
IOCTL_SetMinimumLogLevel(PDEVICE_OBJECT DeviceObject, PIRP Irp);
// BSR-579
NTSTATUS
IOCTL_SetLogFileMaxCount(PDEVICE_OBJECT DeviceObject, PIRP Irp);
// BSR-649
NTSTATUS
IOCTL_SetDebugLogCategory(PDEVICE_OBJECT DeviceObject, PIRP Irp);
// BSR-1048
NTSTATUS
IOCTL_WriteLog(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// BSR-1072
NTSTATUS
IOCTL_Panic(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// BSR-1039
NTSTATUS
IOCTL_HoldState(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS
IOCTL_FakeALUsed(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS
IOCTL_GetBsrLog(PDEVICE_OBJECT DeviceObject, PIRP Irp, ULONG* size);

NTSTATUS
IOCTL_SetHandlerUse(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// BSR-37
NTSTATUS
IOCTL_GetDebugInfo(PIRP Irp, ULONG * size);

// BSR-740
NTSTATUS
IOCTL_SetBsrmonRun(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// BSR-741
NTSTATUS
IOCTL_GetBsrmonRun(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// BSR-874
NTSTATUS
IOCTL_GetUntagMemoryUsage(PDEVICE_OBJECT DeviceObject, PIRP Irp, ULONG *size);

NTSTATUS 
bsrStartupCallback();
VOID
bsrCleanupCallback();

//
// thread.c
//
#ifdef _WIN_MULTIVOL_THREAD
NTSTATUS
mvolInitializeThread( PMVOL_THREAD pThreadInfo, PKSTART_ROUTINE ThreadRoutine );
#else
NTSTATUS
mvolInitializeThread( PVOLUME_EXTENSION DeviceExtension,
	PMVOL_THREAD pThreadInfo, PKSTART_ROUTINE ThreadRoutine );
#endif
VOID
mvolTerminateThread( PMVOL_THREAD pThreadInfo );
KSTART_ROUTINE mvolWorkThread;
#ifdef _WIN_MULTIVOL_THREAD
VOID
mvolQueueWork(PMVOL_THREAD pThreadInfo, PDEVICE_OBJECT DeviceObject, PIRP irp, ktime_t);
#endif
#endif __PROTO_H__
