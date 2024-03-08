/*
   bsr_sender.c

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>.

   bsr is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   bsr is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with bsr; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

*/
#include "bsr_int.h"
#include "../bsr-headers/bsr.h"
#ifdef _WIN
#include "./bsr-kernel-compat/windows/sched.h"
#include "./bsr-kernel-compat/windows/wait.h"
#include "./bsr-kernel-compat/windows/bsr_windows.h"
#else // _LIN
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#endif
#include "../bsr-headers/bsr_protocol.h"
#include "bsr_req.h"


static int make_ov_request(struct bsr_peer_device *, int);
static int make_resync_request(struct bsr_peer_device *, int);
static void maybe_send_barrier(struct bsr_connection *, int);

// DW-1755 DW-1966
static void process_io_error(sector_t sector, unsigned int size, bool write, struct bsr_device *device, unsigned char disk_type, int error);

/* endio handlers:
 *   bsr_md_endio (defined here)
 *   bsr_request_endio (defined here)
 *   bsr_peer_request_endio (defined here)
 *   bsr_bm_endio (defined in bsr_bitmap.c)
 *
 * For all these callbacks, note the following:
 * The callbacks will be called in irq context by the IDE drivers,
 * and in Softirqs/Tasklets/BH context by the SCSI drivers.
 * Try to get the locking right :)
 *
 */

struct mutex resources_mutex;
spinlock_t g_inactive_lock; // BSR-438
spinlock_t g_unacked_lock; // BSR-1036

/* used for synchronous meta data and bitmap IO
 * submitted by bsr_md_sync_page_io()
 */
#ifdef _WIN
NTSTATUS bsr_md_endio(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
#else // _LIN
BIO_ENDIO_TYPE bsr_md_endio BIO_ENDIO_ARGS(struct bio *bio)
#endif
{
	struct bsr_device *device;
#ifdef _WIN
    struct bio *bio = NULL;
    int error = 0;
	static int md_endio_cnt = 0;
    
	bsr_debug(14, BSR_LC_IO, NO_OBJECT,"BIO_ENDIO_FN_START:Thread(%s) bsr_md_io_complete IRQL(%d) .............", current->comm, KeGetCurrentIrql());

	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
        error = Irp->IoStatus.Status;
		bio = (struct bio *)Context;
		//
		//	Simulation Local Disk I/O Error Point. disk error simluation type 3
		//
		if(gSimulDiskIoError.ErrorFlag && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE3) {
			if(IsDiskError()) {
				bsr_err(38, BSR_LC_IO, NO_OBJECT,"SimulDiskIoError: Meta Data I/O Error type3.....ErrorFlag:%d ErrorCount:%d", gSimulDiskIoError.ErrorFlag, gSimulDiskIoError.ErrorCount);
				error = STATUS_UNSUCCESSFUL;
			}
		}
    } else {
        error = (int)Context;
        bio = (struct bio *)Irp;
    }

	if (!bio) {
		bsr_debug(49, BSR_LC_IO, NO_OBJECT, "null bio");
		BIO_ENDIO_FN_RETURN;
	}

	// DW-1822
	 /* The generic_make_request calls IoAcquireRemoveLock before the IRP is created
	 * and is freed from the completion routine functions.
	 * However, retry I/O operations are performed without RemoveLock,
	 * because the retry routine will work after the release.
	 * IoReleaseRemoveLock must be moved so that it is released after the retry.
	 */
	// DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
	if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk) {
		if (bio->bi_bdev->bd_disk->pDeviceExtension != NULL) {
			IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		}
	}
#endif
	BIO_ENDIO_FN_START;

	device = bio->bi_private;
	device->md_io.error = error;

	/* We grabbed an extra reference in _bsr_md_sync_page_io() to be able
	* to timeout on the lower level device, and eventually detach from it.
	* If this io completion runs after that timeout expired, this
	* bsr_md_put_buffer() may allow us to finally try and re-attach.
	* During normal operation, this only puts that extra reference
	* down to 1 again.
	* Make sure we first drop the reference, and only then signal
	* completion, or we may (in bsr_al_read_log()) cycle so fast into the
	* next bsr_md_sync_page_io(), that we trigger the
	* ASSERT(atomic_read(&mdev->md_io_in_use) == 1) there.
	*/
#ifdef _WIN
	if (NT_ERROR(error)) {
#else // _LIN
	if (error) {
#endif
		// DW-1755 DW-1966
		process_io_error(BSR_BIO_BI_SECTOR(bio), BSR_BIO_BI_SIZE(bio), (bio->bi_opf & WRITE), device, VOLUME_TYPE_META, error);
	}

#ifdef _WIN
	if (device->ldev) /* special case: bsr_md_read() during bsr_adm_attach() */
		put_ldev(__FUNCTION__, device);
	else
		bsr_debug(50, BSR_LC_IO, device, "ldev null");
	
	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		PVOID buffer = NULL;

		if (Irp->MdlAddress != NULL) {
			PMDL mdl, nextMdl;
			for (mdl = Irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
				nextMdl = mdl->Next;
				MmUnlockPages(mdl);
				IoFreeMdl(mdl); // This function will also unmap pages.
			}
			Irp->MdlAddress = NULL;
		}
		IoFreeIrp(Irp);

		if (bio->bi_rw != WRITE_FLUSH) {
			if (bio->bio_databuf) {
				buffer = bio->bio_databuf;
			}
			else {
				if (bio->bi_max_vecs > 1) {
					BUG(); 
				}
				buffer = (PVOID)bio->bi_io_vec[0].bv_page->addr;
			}
		}

		sub_untagged_mdl_mem_usage(buffer, bio->bi_size);
		sub_untagged_mem_usage(IoSizeOfIrp(bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject->StackSize));
	}

	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		bio_put(bio);
	}
#else // _LIN
	bio_put(bio);
	if (device->ldev) /* special case: bsr_md_read() during bsr_adm_attach() */
		put_ldev(__FUNCTION__, device);
#endif	
	/* We grabbed an extra reference in _bsr_md_sync_page_io() to be able
		* to timeout on the lower level device, and eventually detach from it.
		* If this io completion runs after that timeout expired, this
		* bsr_md_put_buffer() may allow us to finally try and re-attach.
		* During normal operation, this only puts that extra reference
		* down to 1 again.
		* Make sure we first drop the reference, and only then signal
		* completion, or we may (in bsr_al_read_log()) cycle so fast into the
		* next bsr_md_sync_page_io(), that we trigger the
		* ASSERT(atomic_read(&mdev->md_io_in_use) == 1) there.
		*/
	bsr_md_put_buffer(device);
	device->md_io.done = 1;
	// BSR-1068 wake_up should be called at the end. (also call wake_up inside the bsr_md_put_buffer() above)
	wake_up(&device->misc_wait);

	BIO_ENDIO_FN_RETURN;
}

/* reads on behalf of the partner,
 * "submitted" by the receiver
 */
static void bsr_endio_read_sec_final(struct bsr_peer_request *peer_req) __releases(local)
{
	unsigned long flags = 0;
	struct bsr_peer_device *peer_device; 
	struct bsr_device *device; 
	struct bsr_connection *connection;

	// BSR-930
#ifdef _WIN
	// BSR-438
	spin_lock_irqsave(&g_inactive_lock, flags);
	if (test_bit(__EE_WAS_INACTIVE_REQ, &peer_req->flags)) {
		if (!test_bit(__EE_WAS_LOST_REQ, &peer_req->flags)) {
			struct bsr_peer_request *p_req, *t_inative;

			peer_device = peer_req->peer_device;
			device = peer_device->device;
			connection = peer_device->connection;

			//DW-1735 In case of the same peer_request, destroy it in inactive_ee and exit the function.
			list_for_each_entry_safe_ex(struct bsr_peer_request, p_req, t_inative, &connection->inactive_ee, w.list) {
				if (peer_req == p_req) {
					bsr_info(21, BSR_LC_PEER_REQUEST, device, "Inactive peer request completed. request(%p), sector(%llu), size(%u)", peer_req, (unsigned long long)peer_req->i.sector, peer_req->i.size);

					//DW-1965 apply an I/O error when it is not __EE_WAS_LOST_REQ.
					if (peer_req->flags & EE_WAS_ERROR) {
						// DW-1966
						process_io_error(peer_req->i.sector, peer_req->i.size, false, device, VOLUME_TYPE_REPL, peer_req->error);
						atomic_inc(&device->io_error_count);
						bsr_md_set_flag(device, MDF_IO_ERROR);
						if (device->resource->role[NOW] == R_PRIMARY) {
							bsr_md_set_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR);
						}
						__bsr_chk_io_error(device, BSR_READ_ERROR);
					}
					atomic_dec(&connection->inacitve_ee_cnt);
					list_del(&peer_req->w.list);
					break;
				}
			}
			// BSR-930
			put_ldev(__FUNCTION__, device);
		}
		else {
			bsr_info(20, BSR_LC_PEER_REQUEST, NO_OBJECT, "Inactive peer request completed but lost read request. request(%p), sector(%llu), size(%u)", peer_req, (unsigned long long)peer_req->i.sector, peer_req->i.size);
			
		}
		bsr_free_peer_req(peer_req);
		spin_unlock_irqrestore(&g_inactive_lock, flags);

		return;
	}
	spin_unlock_irqrestore(&g_inactive_lock, flags);
#endif

	peer_device = peer_req->peer_device;
	device = peer_device->device;
	connection = peer_device->connection;

	// DW-1961
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY)) {
		bsr_debug(5, BSR_LC_LATENCY, device, "peer_req(%p) IO latency : in_act(%d) minor(%u) ds(%s) type(read) sector(%llu) size(%u) prepare(%lldus) disk io(%lldus)",
			peer_req, peer_req->do_submit, device->minor, bsr_disk_str(device->disk_state[NOW]), peer_req->i.sector, peer_req->i.size,
			timestamp_elapse(__FUNCTION__, peer_req->created_ts, peer_req->io_request_ts), timestamp_elapse(__FUNCTION__, peer_req->io_request_ts, peer_req->io_complete_ts));
	}

	spin_lock_irqsave(&device->resource->req_lock, flags);
	device->read_cnt += peer_req->i.size >> 9;
	list_del(&peer_req->w.list);
	if (list_empty(&connection->read_ee))
		wake_up(&connection->ee_wait);
	if (test_bit(__EE_WAS_ERROR, &peer_req->flags)) {
		// DW-1966
		process_io_error(peer_req->i.sector, peer_req->i.size, false, device, VOLUME_TYPE_REPL, peer_req->error);

		atomic_inc(&device->io_error_count);
		bsr_md_set_flag(device, MDF_IO_ERROR);
		// DW-1843 set MDF_PRIMARY_IO_ERROR flag when reading IO error at primary.
		if (device->resource->role[NOW] == R_PRIMARY) {
			bsr_md_set_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR);
		}
		__bsr_chk_io_error(device, BSR_READ_ERROR);
	}
	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	bsr_queue_work(&connection->sender_work, &peer_req->w);
	put_ldev(__FUNCTION__, device);
}

static int is_failed_barrier(int ee_flags)
{
	return (ee_flags & (EE_IS_BARRIER|EE_WAS_ERROR|EE_RESUBMITTED|EE_TRIM|EE_ZEROOUT))
		== (EE_IS_BARRIER|EE_WAS_ERROR);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver, final stage.  */
void bsr_endio_write_sec_final(struct bsr_peer_request *peer_req) __releases(local)
{
	unsigned long flags = 0;
	ULONG_PTR peer_flags = 0;
	struct bsr_peer_device *peer_device;
	struct bsr_device *device;
	struct bsr_connection *connection;
	sector_t sector;
	int do_wake = 0;
	u64 block_id;
	unsigned int size;

	// BSR-930
#ifdef _WIN
	// DW-1696 In case of the same peer_request, destroy it in inactive_ee and exit the function.
	// BSR-438
	spin_lock_irqsave(&g_inactive_lock, flags);
	if (test_bit(__EE_WAS_INACTIVE_REQ, &peer_req->flags)) {
		if (!test_bit(__EE_WAS_LOST_REQ, &peer_req->flags)) {
			struct bsr_peer_request *p_req, *t_inative;

			peer_device = peer_req->peer_device;
			device = peer_device->device;
			connection = peer_device->connection;

			list_for_each_entry_safe_ex(struct bsr_peer_request, p_req, t_inative, &connection->inactive_ee, w.list) {
				if (peer_req == p_req) {
					if (peer_req->block_id != ID_SYNCER) {
						//DW-1920 in inactive_ee, the replication data calls bsr_al_complete_io() upon completion of the write.
						bsr_al_complete_io(__FUNCTION__, device, &peer_req->i);
						bsr_info(23, BSR_LC_PEER_REQUEST, device, "Inactive replication peer request completed. peer request(%p) completed. sector(%llu), size(%u)", peer_req, (unsigned long long)peer_req->i.sector, peer_req->i.size);
					}
					else {
						//DW-1965 in inactive_ee, the resync data calls bsr_rs_complete_io() upon completion of the write.
						if (!(peer_req->flags & EE_SPLIT_REQ)) 
							bsr_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
						bsr_info(24, BSR_LC_PEER_REQUEST, device, "Inactive resync peer request completed. peer request(%p) completed. sector(%llu), size(%u)", peer_req, (unsigned long long)peer_req->i.sector, peer_req->i.size);
					}

					//DW-1965 apply an I/O error when it is not __EE_WAS_LOST_REQ.
					if (peer_req->flags & EE_WAS_ERROR) {
						// DW-1966
						process_io_error(peer_req->i.sector, peer_req->i.size, true, device, VOLUME_TYPE_REPL, peer_req->error);
						bsr_set_all_out_of_sync(device, peer_req->i.sector, peer_req->i.size);
						atomic_inc(&device->io_error_count);
						bsr_md_set_flag(device, MDF_IO_ERROR);
					}

					atomic_dec(&connection->inacitve_ee_cnt);
					list_del(&peer_req->w.list);
					break;
				}
			}
			// BSR-930
			if (!(peer_req->flags & EE_SPLIT_REQ))
				put_ldev(__FUNCTION__, device);
		}
		else {
			bsr_info(22, BSR_LC_PEER_REQUEST, NO_OBJECT, "Inactive peer request completed but lost write request. inactive_ee(%p), sector(%llu), size(%u)", peer_req, (unsigned long long)peer_req->i.sector, peer_req->i.size);
		}			 

		bsr_free_peer_req(peer_req);
		spin_unlock_irqrestore(&g_inactive_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&g_inactive_lock, flags);
#endif

	peer_device = peer_req->peer_device;
	device = peer_device->device;
	connection = peer_device->connection;

	// DW-1961
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY)) {
		bsr_debug(6, BSR_LC_LATENCY, device, "peer_req(%p) IO latency : in_act(%d) minor(%u) ds(%s) type(write) sector(%llu) size(%u) prepare(%lldus) disk io(%lldus)",
			peer_req, peer_req->do_submit, device->minor, bsr_disk_str(device->disk_state[NOW]), peer_req->i.sector, peer_req->i.size,
			timestamp_elapse(__FUNCTION__, peer_req->created_ts, peer_req->io_request_ts), timestamp_elapse(__FUNCTION__, peer_req->io_request_ts, peer_req->io_complete_ts));
	}
	/* if this is a failed barrier request, disable use of barriers,
	 * and schedule for resubmission */
#ifdef _WIN64
	BUG_ON_UINT32_OVER(peer_req->flags);
#endif
	if (is_failed_barrier((int)peer_req->flags)) {
		bsr_bump_write_ordering(device->resource, device->ldev, WO_BDEV_FLUSH);
		spin_lock_irqsave(&device->resource->req_lock, flags);
		list_del(&peer_req->w.list);
		peer_req->flags = (peer_req->flags & ~EE_WAS_ERROR) | EE_RESUBMITTED;
		peer_req->w.cb = w_e_reissue;
		/* put_ldev actually happens below, once we come here again. */
		__release(local);
		spin_unlock_irqrestore(&device->resource->req_lock, flags);
		bsr_queue_work(&connection->sender_work, &peer_req->w);
		return;
	}

	/* after we moved peer_req to done_ee,
	 * we may no longer access it,
	 * it may be freed/reused already!
	 * (as soon as we release the req_lock) */

	// DW-1601 the last split uses the sector of the first bit for resync_lru matching.
#ifdef SPLIT_REQUEST_RESYNC
	if (peer_req->flags & EE_SPLIT_LAST_REQ)
		sector = BM_BIT_TO_SECT(peer_req->sbb.start);
	else
#endif
		sector = peer_req->i.sector;

	block_id = peer_req->block_id;
	peer_flags = peer_req->flags;

	if (peer_flags & EE_WAS_ERROR) {
		// DW-1966
		process_io_error(peer_req->i.sector, peer_req->i.size, true, device, VOLUME_TYPE_REPL, peer_req->error);

		// DW-1842 __EE_SEND_WRITE_ACK should be used only for replication.
		if (block_id != ID_SYNCER) {
			/* In protocol != C, we usually do not send write acks.
			* In case of a write error, send the neg ack anyways. */
			if (!__test_and_set_bit(__EE_SEND_WRITE_ACK, &peer_req->flags))
				inc_unacked(peer_device);
		}

		// DW-1810
		/* There is no case where this flag is set because of WRITE SAME, TRIM. 
		Therefore, the flag EE_WAS_ERROR means that an IO ERROR occurred. 
		In order to synchronize the Secondaries at the time of primary failure, 
		OOS for IO error is recorded for all nodes.
		*/
		bsr_set_all_out_of_sync(device, peer_req->i.sector, peer_req->i.size);
		atomic_inc(&device->io_error_count);
		bsr_md_set_flag(device, MDF_IO_ERROR);
    }

	// DW-1859
	check_and_clear_io_error_in_secondary(peer_device);

	spin_lock_irqsave(&device->resource->req_lock, flags);

	device->writ_cnt += peer_req->i.size >> 9;
	atomic_inc(&connection->done_ee_cnt);
	size = peer_req->i.size;
	list_move_tail(&peer_req->w.list, &connection->done_ee);

	/*
	 * Do not remove from the write_requests tree here: we did not send the
	 * Ack yet and did not wake possibly waiting conflicting requests.
	 * Removed from the tree from "bsr_process_done_ee" within the
	 * appropriate callback (e_end_block/e_end_resync_block) or from
	 * _bsr_clear_done_ee.
	 */

	if (block_id == ID_SYNCER)
		do_wake = list_empty(&connection->sync_ee);
	else
		do_wake = list_empty(&connection->active_ee);

	/* FIXME do we want to detach for failed REQ_DISCARD?
	* ((peer_req->flags & (EE_WAS_ERROR|EE_TRIM)) == EE_WAS_ERROR) */
	if (peer_flags & EE_WAS_ERROR)
		__bsr_chk_io_error(device, BSR_WRITE_ERROR);

	if (connection->cstate[NOW] == C_CONNECTED)
		queue_work(connection->ack_sender, &connection->send_acks_work);

	spin_unlock_irqrestore(&device->resource->req_lock, flags);
	
	// DW-1601 calls bsr_rs_complete_io() after all data is complete.
	// DW-1886
	if (block_id == ID_SYNCER) {
		if (!(peer_flags & EE_SPLIT_REQ))
			bsr_rs_complete_io(peer_device, sector, __FUNCTION__);
		atomic_add64(size, &peer_device->rs_written);

	}

	if (do_wake) 
		wake_up(&connection->ee_wait);

	// DW-1903 EE_SPLIT_REQ is a duplicate request and does not call put_ldev().
	if (!(peer_flags & EE_SPLIT_REQ))
		put_ldev(__FUNCTION__, device);
}

/* writes on behalf of the partner, or resync writes,
 * "submitted" by the receiver.
 */
#ifdef _WIN
BIO_ENDIO_TYPE bsr_peer_request_endio(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
#else // _LIN
BIO_ENDIO_TYPE bsr_peer_request_endio BIO_ENDIO_ARGS(struct bio *bio)
#endif
{
#ifdef _WIN
	struct bio *bio = NULL;
	int error = 0;
	static int peer_request_endio_cnt = 0;
	//bsr_debug(51, BSR_LC_IO, NO_OBJECT,"BIO_ENDIO_FN_START:Thread(%s) bsr_peer_request_endio: IRQL(%d) ..............",  current->comm, KeGetCurrentIrql());

	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		error = Irp->IoStatus.Status;
		bio = (struct bio *)Context;
		//
		//	Simulation Local Disk I/O Error Point. disk error simluation type 2
		//
		if(gSimulDiskIoError.ErrorFlag && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE2) {
			if(IsDiskError()) {
				bsr_err(8, BSR_LC_IO, NO_OBJECT,"SimulDiskIoError: Peer Request I/O Error type2.....ErrorFlag:%d ErrorCount:%d", gSimulDiskIoError.ErrorFlag, gSimulDiskIoError.ErrorCount);
				error = STATUS_UNSUCCESSFUL;
			}
		}
	} else {
		error = (int)Context;
		bio = (struct bio *)Irp;
	}

	if (!bio)
		BIO_ENDIO_FN_RETURN;

	// DW-1822
	 /* The generic_make_request calls IoAcquireRemoveLock before the IRP is created
 	 * and is freed from the completion routine functions.
	 * However, retry I/O operations are performed without RemoveLock,
	 * because the retry routine will work after the release.
	 * IoReleaseRemoveLock must be moved so that it is released after the retry.
	 */
	// DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
	if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk) {
		if (bio->bi_bdev->bd_disk->pDeviceExtension != NULL) {
			IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		}
	}
#endif

	struct bsr_peer_request *peer_req = bio->bi_private;

	bool is_write = bio_data_dir(bio) == WRITE;
	bool is_discard = bio_op(bio) == REQ_OP_WRITE_ZEROES || bio_op(bio) == REQ_OP_DISCARD;

	BIO_ENDIO_FN_START;
	// BSR-779
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_PEER_REQUEST))
		ktime_get_accounting(peer_req->p_bio_endio_kt);
	// DW-1961 Save timestamp for IO latency measuremen
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
		peer_req->io_complete_ts = timestamp();

#ifdef _WIN
	if (NT_ERROR(error) && bsr_ratelimit())
#else // _LIN
	if (error && bsr_ratelimit())
#endif
		bsr_warn(30, BSR_LC_PEER_REQUEST, NO_OBJECT, "Failed to %s: error=0x%08X sec=%llus size:%d",
		is_write ? (is_discard ? "discard" : "write")
		: "read", error,
		(unsigned long long)peer_req->i.sector, peer_req->i.size);
#ifdef _WIN
	if (NT_ERROR(error)) {
#else // _LIN 
	if (error) {
#endif
		set_bit(__EE_WAS_ERROR, &peer_req->flags);
		// DW-1755
		// DW-1966 "process_io_error()" it is called by "bsr_endio_write_sec_final()", "bsr_endio_read_sec_final()".
		// set I/O error
		peer_req->error = error;
	}
#ifdef _WIN
	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		PVOID buffer = NULL;

		if (Irp->MdlAddress != NULL) {
			PMDL mdl, nextMdl;
			for (mdl = Irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
				nextMdl = mdl->Next;
				MmUnlockPages(mdl);
				IoFreeMdl(mdl); // This function will also unmap pages.
			}
			Irp->MdlAddress = NULL;
		}
		IoFreeIrp(Irp); 
		
		if (bio->bi_rw != WRITE_FLUSH) {
			if (bio->bio_databuf) {
				buffer = bio->bio_databuf;
			}
			else {
				if (bio->bi_max_vecs > 1) {
					BUG(); 
				}
				buffer = (PVOID)bio->bi_io_vec[0].bv_page->addr;
			}
		}

		sub_untagged_mdl_mem_usage(buffer, bio->bi_size);
		sub_untagged_mem_usage(IoSizeOfIrp(bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject->StackSize));
	}
#endif

	bio_put(bio); /* no need for the bio anymore */

	if (atomic_dec_and_test(&peer_req->pending_bios)) {
		if (is_write)
			bsr_endio_write_sec_final(peer_req);
		else
			bsr_endio_read_sec_final(peer_req);
	}

	//bsr_debug(52, BSR_LC_IO, NO_OBJECT,"bsr_peer_request_endio done.(%d).............!!!", peer_request_endio_cnt++);

	BIO_ENDIO_FN_RETURN;
}

void bsr_panic_after_delayed_completion_of_aborted_request(struct bsr_device *device)
{
#ifdef _WIN
	bsr_err(9, BSR_LC_IO, NO_OBJECT,"bsr minor:%u resource:%s / vnr:%u", device->minor, device->resource->name, device->vnr);
	panic("potential random memory corruption caused by delayed completion of aborted local request");
#else // _LIN
	panic("bsr%u %s/%u potential random memory corruption caused by delayed completion of aborted local request",
		device->minor, device->resource->name, device->vnr);
#endif
}


/* read, readA or write requests on R_PRIMARY coming from bsr_make_request
 */
#ifdef _WIN
NTSTATUS bsr_request_endio(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
#else // _LIN
BIO_ENDIO_TYPE bsr_request_endio BIO_ENDIO_ARGS(struct bio *bio)
#endif
{
	unsigned long flags;
	struct bsr_request *req = NULL;
	struct bsr_device *device = NULL;
	struct bio_and_error m;
	enum bsr_req_event what;
	struct bsr_peer_device* peer_device;
#ifdef _WIN
	struct bio *bio = NULL;
	int error = 0;

	//bsr_debug(53, BSR_LC_IO, NO_OBJECT,"BIO_ENDIO_FN_START:Thread(%s) bsr_request_endio: IRQL(%d) ................", current->comm, KeGetCurrentIrql());

	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		bio = (struct bio *)Context;
		error = Irp->IoStatus.Status;
		//
		//	Simulation Local Disk I/O Error Point. disk error simluation type 1
		//
		if(gSimulDiskIoError.ErrorFlag && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE1) {
			if(IsDiskError()) {
				bsr_err(10, BSR_LC_IO, NO_OBJECT,"SimulDiskIoError: Local I/O Error type1.....ErrorFlag:%d ErrorCount:%d",gSimulDiskIoError.ErrorFlag,gSimulDiskIoError.ErrorCount);
				error = STATUS_UNSUCCESSFUL;
			}
		}
	} else {
		error = (int)Context;
		bio = (struct bio *)Irp;
	}

	if (!bio) {
		bsr_debug(54, BSR_LC_IO, NO_OBJECT, "null bio");
		BIO_ENDIO_FN_RETURN;
	}

	// DW-1822
	 /* The generic_make_request calls IoAcquireRemoveLock before the IRP is created
	 * and is freed from the completion routine functions.
	 * However, retry I/O operations are performed without RemoveLock,
	 * because the retry routine will work after the release.
	 * IoReleaseRemoveLock must be moved so that it is released after the retry.
	 */
	// DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
	if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk) {
		if (bio->bi_bdev->bd_disk->pDeviceExtension != NULL) {
			IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		}
	}
#endif
	BIO_ENDIO_FN_START;
	req = bio->bi_private;
	device = req->device;

	// BSR-779 change req->post_submit_kt to req->bio_endio_kt
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
		ktime_get_accounting(req->bio_endio_kt);

	if (bio_data_dir(bio) & WRITE) {
		bsr_debug(15, BSR_LC_VERIFY, device, "%s, req %p, sector(%llu), size(%u), bitmap(%llu ~ %llu)", __FUNCTION__, 
				req,
				(unsigned long long)req->i.sector, 
				req->i.size, 
				(unsigned long long)BM_SECT_TO_BIT(req->i.sector), 
				(unsigned long long)BM_SECT_TO_BIT(req->i.sector + (req->i.size >> 9)));
	}

	// DW-1961 Calculate and Log IO Latency
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
		req->io_complete_ts = timestamp();

	/* If this request was aborted locally before,
	* but now was completed "successfully",
	* chances are that this caused arbitrary data corruption.
	*
	* "aborting" requests, or force-detaching the disk, is intended for
	* completely blocked/hung local backing devices which do no longer
	* complete requests at all, not even do error completions.  In this
	* situation, usually a hard-reset and failover is the only way out.
	*
	* By "aborting", basically faking a local error-completion,
	* we allow for a more graceful swichover by cleanly migrating services.
	* Still the affected node has to be rebooted "soon".
	*
	* By completing these requests, we allow the upper layers to re-use
	* the associated data pages.
	*
	* If later the local backing device "recovers", and now DMAs some data
	* from disk into the original request pages, in the best case it will
	* just put random data into unused pages; but typically it will corrupt
	* meanwhile completely unrelated data, causing all sorts of damage.
	*
	* Which means delayed successful completion,
	* especially for READ requests,
	* is a reason to panic().
	*
	* We assume that a delayed *error* completion is OK,
	* though we still will complain noisily about it.
	*/
	if (unlikely(req->rq_state[0] & RQ_LOCAL_ABORTED)) {
		if (bsr_ratelimit())
			bsr_emerg(11, BSR_LC_IO, device, "Delayed completion of aborted local request; disk-timeout may be too aggressive");

		if (!error)
			bsr_panic_after_delayed_completion_of_aborted_request(device);
	}

	/* to avoid recursion in __req_mod */
	// DW-1706 By NT_ERROR(), reduce the error sensitivity to I/O.
#ifdef _WIN
	if (NT_ERROR(error)) {
#else // _LIN
	if (unlikely(error)) {
#endif
		switch (bio_op(bio)) {
		case REQ_OP_WRITE_ZEROES:
		case REQ_OP_DISCARD:
			if (error == -EOPNOTSUPP)
				what = DISCARD_COMPLETED_NOTSUPP;
			else
				what = DISCARD_COMPLETED_WITH_ERROR;
			break;
		case REQ_OP_READ:
			if (bio->bi_opf & REQ_RAHEAD)
				what = READ_AHEAD_COMPLETED_WITH_ERROR;
			else
				what = READ_COMPLETED_WITH_ERROR;
			break;
		default:
			what = WRITE_COMPLETED_WITH_ERROR;
			break;
		}

		// DW-1755 DW-1966
		process_io_error(BSR_BIO_BI_SECTOR(bio), BSR_BIO_BI_SIZE(bio), (bio->bi_opf & WRITE), device, VOLUME_TYPE_REPL, error);
	}
	else {
		what = COMPLETED_OK;
	}

#ifdef _WIN
	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		PVOID buffer = NULL;

		if (Irp->MdlAddress != NULL) {
			PMDL mdl, nextMdl;
			for (mdl = Irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
				nextMdl = mdl->Next;
				MmUnlockPages(mdl);
				IoFreeMdl(mdl); // This function will also unmap pages.
			}
			Irp->MdlAddress = NULL;
		}
		IoFreeIrp(Irp);

		if (bio->bi_rw != WRITE_FLUSH) {
			if (bio->bio_databuf) {
				buffer = bio->bio_databuf;
			}
			else {
				if (bio->bi_max_vecs > 1) {
					BUG();
				}
				buffer = (PVOID)bio->bi_io_vec[0].bv_page->addr;
			}
		}

		sub_untagged_mdl_mem_usage(buffer, bio->bi_size);
		sub_untagged_mem_usage(IoSizeOfIrp(bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject->StackSize));
	}

#ifdef BSR_TRACE	
	{
		static int cnt = 0;
		bsr_debug(55, BSR_LC_IO, NO_OBJECT,"bsr_request_endio done.(%d).................IRQL(%d)!!!", cnt++, KeGetCurrentIrql());
	}
#endif
#endif
	bio_put(req->private_bio);

	// BSR-687
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_COMPLETE)) {
		atomic_inc(&device->local_complete_kt.cnt);
		ktime_aggregate_delta(device, req->start_kt, local_complete_kt);
	}

	req->private_bio = ERR_PTR(error);

	/* not req_mod(), we need irqsave here! */
	spin_lock_irqsave(&device->resource->req_lock, flags);
	// DW-2042
#ifdef SPLIT_REQUEST_RESYNC
	for_each_peer_device(peer_device, device) {
		struct bsr_connection *connection = peer_device->connection;
		int idx = peer_device ? 1 + peer_device->node_id : 0;
		if (req->rq_state[idx] & RQ_OOS_PENDING) {
			// DW-2058 set out of sync again before sending.
			bsr_set_out_of_sync(peer_device, req->i.sector, req->i.size);
			_req_mod(req, QUEUE_FOR_SEND_OOS, peer_device);
			// BSR-541
			wake_up(&connection->sender_work.q_wait);
		}
	}
#endif

#ifdef _WIN
#ifdef BSR_TRACE	
	bsr_debug(56, BSR_LC_IO, NO_OBJECT,"(%s) bsr_request_endio: before __req_mod! IRQL(%d) ", current->comm, KeGetCurrentIrql());
#endif
#endif
	__req_mod(req, what, NULL, &m);

	// BSR-1116 asynchronous replication improves local write performance by completing local writes from write-complete-callback, whether or not data is transferred.
	if (what == COMPLETED_OK) {
		if (!m.bio && req->req_databuf) {
			m.bio = req->master_bio;
			m.error = 0;
			req->i.completed = true;
			_bsr_end_io_acct(device, req);

			if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
				req->local_complete_ts = timestamp();
		}
	}

	spin_unlock_irqrestore(&device->resource->req_lock, flags);
	put_ldev(__FUNCTION__, device);

	if (m.bio)
		complete_master_bio(device, &m);

	BIO_ENDIO_FN_RETURN;
}

void bsr_csum_pages(struct crypto_shash *tfm, struct bsr_peer_request *peer_req, void *digest)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(tfm);
	*(uint32_t *)digest = crc32c(0, peer_req->peer_req_databuf, peer_req->i.size);
#else // _LIN 
	SHASH_DESC_ON_STACK(desc, tfm);
	struct page *page = peer_req->page_chain.head;

	desc->tfm = tfm;

	crypto_shash_init(desc);

	page_chain_for_each(page) {
		unsigned off = page_chain_offset(page);
		unsigned len = page_chain_size(page);
		u8 *src;
        src = bsr_kmap_atomic(page, KM_USER0);
        crypto_shash_update(desc, src + off, len);
        bsr_kunmap_atomic(src, KM_USER0);
	}
	crypto_shash_final(desc, digest);
    shash_desc_zero(desc);
#endif
}


void bsr_csum_bio(struct crypto_shash *tfm, struct bsr_request *request, void *digest)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(tfm);
	struct hash_desc desc;
#else // _LIN
	BSR_BIO_VEC_TYPE bvec;
	BSR_ITER_TYPE iter;
	SHASH_DESC_ON_STACK(desc, tfm);
	struct bio *bio = request->master_bio;
#endif

#ifdef _WIN 
	if (request->req_databuf)
		crypto_hash_update(&desc, (struct scatterlist *)request->req_databuf, request->i.size);
	crypto_hash_final(&desc, digest);
#else // _LIN 
    desc->tfm = tfm;

    crypto_shash_init(desc);

	bio_for_each_segment(bvec, bio, iter) {
        u8 *src;
        src = bsr_kmap_atomic(bvec BVD bv_page, KM_USER0);
        crypto_shash_update(desc, src + bvec BVD bv_offset, bvec BVD bv_len);
        bsr_kunmap_atomic(src, KM_USER0);
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
		/* WRITE_SAME has only one segment,
		 * checksum the payload only once. */
		if (bio_op(bio) == REQ_OP_WRITE_SAME)
			break;
#endif
	}
    crypto_shash_final(desc, digest);
    shash_desc_zero(desc);
#endif
}

/* MAYBE merge common code with w_e_end_ov_req */
static int w_e_send_csum(struct bsr_work *w, int cancel)
{
	struct bsr_peer_request *peer_req = container_of(w, struct bsr_peer_request, w);
	struct bsr_peer_device *peer_device = peer_req->peer_device;
	int digest_size;
	void *digest;
	int err = 0;

	if (unlikely(cancel))
		goto out;

	if (unlikely((peer_req->flags & EE_WAS_ERROR) != 0)) {
		// BSR-448 fix bug that checksum synchronization stops when SyncTarget io-error occurs continuously.
		// Send the packet with block_id set to ID_CSUM_SYNC_IO_ERROR.
		atomic_add(peer_req->i.size >> 9, &peer_device->rs_sect_in);
		bsr_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
		bsr_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
		peer_req->block_id = ID_CSUM_SYNC_IO_ERROR;
		if (peer_device->connection->agreed_pro_version < 113)
			goto out;
	}

	digest_size = crypto_shash_digestsize(peer_device->connection->csums_tfm);
	digest = bsr_prepare_drequest_csum(peer_req, digest_size);
	if (digest) {
		bsr_csum_pages(peer_device->connection->csums_tfm, peer_req, digest);
		// BSR-448 Do not receive ack if send io fail notification packet.
		if (likely((peer_req->flags & EE_WAS_ERROR) == 0))
			inc_rs_pending(peer_device);
		/* Free peer_req and pages before send.
		 * In case we block on congestion, we could otherwise run into
		 * some distributed deadlock, if the other side blocks on
		 * congestion as well, because our receiver blocks in
		 * bsr_alloc_pages due to pp_in_use > max_buffers. */
		bsr_free_peer_req(peer_req);
		peer_req = NULL;
		err = bsr_send_command(peer_device, P_CSUM_RS_REQUEST, DATA_STREAM);
	} else {
		bsr_err(38, BSR_LC_MEMORY, peer_device, "Failed to send csum checksum to failure to allocate memory for digest");
		err = -ENOMEM;
	}

out:
	if (peer_req)
		bsr_free_peer_req(peer_req);

	if (unlikely(err))
		bsr_err(155, BSR_LC_RESYNC_OV, peer_device, "Failed to checksum or send. err(%d)", err);
	return err;
}

static int read_for_csum(struct bsr_peer_device *peer_device, sector_t sector, int size)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_request *peer_req;

	if (!get_ldev(device))
		return -EIO;

	/* Do not wait if no memory is immediately available.  */
	peer_req = bsr_alloc_peer_req(peer_device, GFP_TRY & ~__GFP_RECLAIM);
	if (!peer_req) {
		bsr_err(39, BSR_LC_MEMORY, peer_device, "Failed to read checksum due to failure to allocate memory for peer request");
		goto defer;
	}

	if (size) {
		bsr_alloc_page_chain(&peer_device->connection->transport,
			&peer_req->page_chain, DIV_ROUND_UP(size, PAGE_SIZE), GFP_TRY);
		if (!peer_req->page_chain.head) {
			bsr_err(40, BSR_LC_MEMORY, peer_device, "Failed to read checksum due to failure to allocate memory for page chain");
			goto defer2;
		}
#ifdef _WIN
		peer_req->peer_req_databuf = peer_req->page_chain.head;
	} else {
		peer_req->peer_req_databuf = NULL;
#endif
	}

	peer_req->i.size = size;
	peer_req->i.sector = sector;
	peer_req->block_id = ID_SYNCER; /* unused */

	peer_req->w.cb = w_e_send_csum;
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&peer_req->w.list, &peer_device->connection->read_ee);
	spin_unlock_irq(&device->resource->req_lock);

	atomic_add(size >> 9, &device->rs_sect_ev);
	if (bsr_submit_peer_request(device, peer_req, REQ_OP_READ, 0,
		BSR_FAULT_RS_RD) == 0)
		return 0;

	bsr_err(27, BSR_LC_PEER_REQUEST, peer_device, "Failed to read checksum due to failure to submit peer request");
	/* If it failed because of ENOMEM, retry should help.  If it failed
	 * because bio_add_page failed (probably broken lower level driver),
	 * retry may or may not help.
	 * If it does not, you may need to force disconnect. */
	spin_lock_irq(&device->resource->req_lock);
	list_del(&peer_req->w.list);
	spin_unlock_irq(&device->resource->req_lock);

defer2:
	bsr_free_peer_req(peer_req);
defer:
	put_ldev(__FUNCTION__, device);
	return -EAGAIN;
}

int w_resync_timer(struct bsr_work *w, int cancel)
{
	struct bsr_peer_device *peer_device =
		container_of(w, struct bsr_peer_device, resync_work);
	struct bsr_device *device = peer_device->device;
	LONGLONG ts = timestamp();
	mutex_lock(&device->bm_resync_and_resync_timer_fo_mutex);

	switch (peer_device->repl_state[NOW]) {
	case L_VERIFY_S:
		// BSR-118
		if (test_bit(OV_FAST_BM_SET_PENDING, &peer_device->flags)) {
			ULONG_PTR now = jiffies;
			int i;

			for (i = 0; i < BSR_SYNC_MARKS; i++) {
				peer_device->rs_mark_left[i] = peer_device->ov_left;
				peer_device->rs_mark_time[i] = now;
			}
			clear_bit(OV_FAST_BM_SET_PENDING, &peer_device->flags);
		}
		make_ov_request(peer_device, cancel);
		break;
	case L_SYNC_TARGET:
		// DW-1317 try to get volume control mutex, reset timer if failed.
		if (mutex_trylock(&device->resource->vol_ctl_mutex)) {
			mutex_unlock(&device->resource->vol_ctl_mutex);
			make_resync_request(peer_device, cancel);
			// DW-1977
			ts = timestamp_elapse(__FUNCTION__, ts, timestamp());
			if (ts > ((3 * 1000) * HZ)) {
				bsr_warn(170, BSR_LC_RESYNC_OV, peer_device, "resync request takes a long time(%lldus)", ts);
			}
		}
		else		
			mod_timer(&peer_device->resync_timer, jiffies);	
		break;
	default:
		// DW-1977
		bsr_info(105, BSR_LC_RESYNC_OV, peer_device, "Stop the resync or verify request because the replication status is %s, not sync target or verify source.", bsr_repl_str(peer_device->repl_state[NOW]));
		break;
	}

	mutex_unlock(&device->bm_resync_and_resync_timer_fo_mutex);

	return 0;
}

int w_send_uuids(struct bsr_work *w, int cancel)
{
	struct bsr_peer_device *peer_device =
		container_of(w, struct bsr_peer_device, propagate_uuids_work);

	UNREFERENCED_PARAMETER(cancel);

	if (peer_device->repl_state[NOW] < L_ESTABLISHED ||
	    !test_bit(INITIAL_STATE_SENT, &peer_device->flags))
		return 0;

	bsr_send_uuids(peer_device, 0, 0, NOW);

	return 0;
}

#ifdef _WIN
void resync_timer_fn(PKDPC Dpc, PVOID data, PVOID SystemArgument1, PVOID SystemArgument2)
#else // _LIN
void resync_timer_fn(BSR_TIMER_FN_ARG)
#endif
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Dpc);
	struct bsr_peer_device *peer_device = (struct bsr_peer_device *) data;
#else // _LIN
	struct bsr_peer_device *peer_device = BSR_TIMER_ARG2OBJ(peer_device, resync_timer);
#endif

	if (peer_device == NULL)
		return;

	bsr_queue_work_if_unqueued(
		&peer_device->connection->sender_work,
		&peer_device->resync_work);

}

static void fifo_set(struct fifo_buffer *fb, int value)
{
	unsigned int i;

	for (i = 0; i < fb->size; i++)
		fb->values[i] = value;
}

static int fifo_push(struct fifo_buffer *fb, int value)
{
	int ov;

	ov = fb->values[fb->head_index];
	fb->values[fb->head_index++] = value;

	if (fb->head_index >= fb->size)
		fb->head_index = 0;

	return ov;
}

static void fifo_add_val(struct fifo_buffer *fb, int value)
{
	unsigned int i;

	for (i = 0; i < fb->size; i++)
		fb->values[i] += value;
}
#ifdef _WIN
struct fifo_buffer *fifo_alloc(int fifo_size, ULONG Tag)
#else // _LIN
struct fifo_buffer *fifo_alloc(int fifo_size)
#endif
{
	struct fifo_buffer *fb;
	fb = bsr_kzalloc(sizeof(struct fifo_buffer) + sizeof(int) * fifo_size, GFP_NOIO, Tag);
	if (!fb)
		return NULL;

	fb->head_index = 0;
	fb->size = fifo_size;
	fb->total = 0;

	return fb;
}

static int bsr_rs_controller(struct bsr_peer_device *peer_device, unsigned int sect_in)
{
	struct peer_device_conf *pdc;
	unsigned int want;     /* The number of sectors we want in-flight */
	int req_sect; /* Number of sectors to request in this turn */
	int correction; /* Number of sectors more we need in-flight */
	int cps; /* correction per invocation of bsr_rs_controller() */
	int steps; /* Number of time steps to plan ahead */
	int curr_corr;
	int max_sect, min_sect;
	struct fifo_buffer *plan;

	pdc = rcu_dereference(peer_device->conf);
	plan = rcu_dereference(peer_device->rs_plan_s);

	steps = plan->size; /* (pdc->c_plan_ahead * 10 * SLEEP_TIME) / HZ; */

	if (peer_device->rs_in_flight + sect_in == 0) { /* At start of resync */
		want = ((pdc->resync_rate * 2 * SLEEP_TIME) / HZ) * steps;
	} else { /* normal path */
		want = pdc->c_fill_target ? pdc->c_fill_target :
			sect_in * pdc->c_delay_target * HZ / (SLEEP_TIME * 10);
	}

	correction = want - peer_device->rs_in_flight - plan->total;

	/* Plan ahead */
	cps = correction / steps;
	fifo_add_val(plan, cps);
	plan->total += cps * steps;

	/* What we do in this step */
	curr_corr = fifo_push(plan, 0);
	curr_corr = max_t(int, curr_corr, 8);	// minimum 8

	plan->total -= curr_corr;
	req_sect = sect_in + curr_corr;
	if (req_sect < 0)
		req_sect = 0;

	max_sect = (pdc->c_max_rate * 2 * SLEEP_TIME) / HZ;
	min_sect = (pdc->c_min_rate * 2 * SLEEP_TIME) / HZ;
	if (req_sect > max_sect) {
		req_sect = max_sect;
	} else if (peer_device->connection->agreed_pro_version >= 115) {
		// BSR-838 set the minimum resync size to c-min-rate.
		if (req_sect < min_sect)
			req_sect = min_sect;
	}

#ifdef _WIN
    bsr_debug_tr("sect_in=%5u, %5d, corr(%d) cps(%d) curr_c(%d) rs(%d)",
         sect_in, peer_device->rs_in_flight, correction, cps, curr_corr, req_sect);
#endif
	/*
	bsr_warn(78, BSR_LC_ETC, device, "si=%u if=%d wa=%u co=%d st=%d cps=%d pl=%d cc=%d rs=%d",
		 sect_in, peer_device->rs_in_flight, want, correction,
		 steps, cps, peer_device->rs_planed, curr_corr, req_sect);
	*/

	return req_sect;
}

static int bsr_rs_number_requests(struct bsr_peer_device *peer_device)
{
	struct net_conf *nc;
	unsigned int sect_in;  /* Number of sectors that came in since the last turn */
	int number;
	ULONG_PTR now = jiffies;

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);

	// BSR-838
	if (time_after_eq(now, peer_device->rs_in_flight_mark_time + HZ)) {
		peer_device->rs_in_flight = 0;
		peer_device->rs_in_flight_mark_time = now;
	}

	if (rcu_dereference(peer_device->rs_plan_s)->size) {
		sect_in = atomic_xchg(&peer_device->rs_sect_in, 0);
		number = bsr_rs_controller(peer_device, sect_in) >> (BM_BLOCK_SHIFT - 9);
		peer_device->c_sync_rate = number * HZ * (BM_BLOCK_SIZE / 1024) / SLEEP_TIME;
	}
	else {
		peer_device->c_sync_rate = rcu_dereference(peer_device->conf)->resync_rate;
		number = SLEEP_TIME * peer_device->c_sync_rate  / ((BM_BLOCK_SIZE / 1024) * HZ);
	}
	rcu_read_unlock();

	/* Don't have more than "max-buffers"/2 in-flight.
	 * Otherwise we may cause the remote site to stall on bsr_alloc_pages(),
	 * potentially causing a distributed deadlock on congestion during
	 * online-verify or (checksum-based) resync, if max-buffers,
	 * socket buffer sizes and resync rate settings are mis-configured. */
	/* note that "number" is in units of "BM_BLOCK_SIZE" (which is 4k),
	 * mxb (as used here, and in bsr_alloc_pages on the peer) is
	 * "number of pages" (typically also 4k),
	 * but "rs_in_flight" is in "sectors" (512 Byte). */

	// BSR-838 remove the max-buffers limit. request resync at resync-rate or c-min-rate per second.
	if (peer_device->connection->agreed_pro_version < 115) {
		int mxb = nc ? nc->max_buffers : 0;
		if (mxb - peer_device->rs_in_flight / 8 < number) {
			number = mxb - peer_device->rs_in_flight / 8;
		}
	}

	return number;
}

// DW-1978 25000000 is 100 Gbyte (1bit = 4k)
#define RANGE_FIND_NEXT_BIT 25000000

static int make_resync_request(struct bsr_peer_device *peer_device, int cancel)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_transport *transport = &peer_device->connection->transport;
	ULONG_PTR bit;
	sector_t sector;
	const sector_t capacity = bsr_get_vdisk_capacity(device);
	unsigned int max_bio_size, size;
	int number, rollback_i;
	int align, requeue = 0;
	int i = 0;
	int discard_granularity = 0;
#ifdef _WIN
	bsr_debug_tm("timer callback jiffies(%llu)", jiffies);
#endif

	if (unlikely(cancel)) {
		bsr_info(106, BSR_LC_RESYNC_OV, peer_device, "Resync Stop is set to stop.");
		return 0;
	}

	if (peer_device->rs_total == 0) {
		/* empty resync? */
		bsr_info(107, BSR_LC_RESYNC_OV, peer_device, "Finished the resync. resync target area does not exist.");
		bsr_resync_finished(__FUNCTION__, peer_device, D_MASK);
		return 0;
	}

	if (!get_ldev(device)) {
		/* Since we only need to access device->rsync a
		   get_ldev_if_state(device,D_FAILED) would be sufficient, but
		   to continue resync with a broken disk makes no sense at
		   all */
		bsr_err(108, BSR_LC_RESYNC_OV, device, "Failed to make resync request due to disk broke down(%s)\n", bsr_disk_str(device->disk_state[NOW]));
		return 0;
	}

#ifdef SPLIT_REQUEST_RESYNC
	if (peer_device->connection->agreed_pro_version >= 113) {
		// DW-2082 if the bitmap exchange was not completed and the resync request was sent once, the next resync request is not sent.
		if (atomic_read(&peer_device->wait_for_bitmp_exchange_complete)) {
			bsr_debug(16, BSR_LC_VERIFY, peer_device, "waiting for syncsource to bitmap exchange status");
			goto requeue;
		}
	}
#endif

	if (peer_device->connection->agreed_features & BSR_FF_THIN_RESYNC) {
		rcu_read_lock();
		discard_granularity = rcu_dereference(device->ldev->disk_conf)->rs_discard_granularity;
		rcu_read_unlock();
	}

	max_bio_size = (unsigned int)(min((queue_max_hw_sectors(device->rq_queue) << 9), BSR_MAX_BIO_SIZE));
	number = bsr_rs_number_requests(peer_device);
#ifdef _WIN
    bsr_debug_tr("number(%d)", number);
#endif
	if (number <= 0)
		goto requeue;

	for (i = 0; i < number; i++) {
		/* Stop generating RS requests, when half of the send buffer is filled */
		mutex_lock(&peer_device->connection->mutex[DATA_STREAM]);
		if (transport->ops->stream_ok(transport, DATA_STREAM)) {
			struct bsr_transport_stats transport_stats;
#ifdef _WIN
			signed long long queued, sndbuf;
#else // _LIN
			int queued, sndbuf;
#endif
			transport->ops->stats(transport, &transport_stats);
			queued = transport_stats.send_buffer_used;
			sndbuf = transport_stats.send_buffer_size;
#ifdef _WIN
			bsr_debug_tr("make_resync_request: %d/%d: queued=%lld sndbuf=%lld", i, number, queued, sndbuf);
#endif
			if (queued > sndbuf / 2) {
				requeue = 1;
				transport->ops->hint(transport, DATA_STREAM, NOSPACE);
			}
		}
		else
			requeue = 1;
		mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);
		if (requeue)
			goto requeue;

next_sector:
		size = BM_BLOCK_SIZE;
		for (;;) {
			// DW-1978
			bit = bsr_bm_range_find_next(peer_device, device->bm_resync_fo, device->bm_resync_fo + RANGE_FIND_NEXT_BIT);
			if (bit < (device->bm_resync_fo + RANGE_FIND_NEXT_BIT + 1)) {
				break;
			}

			if (bit >= bsr_bm_bits(device)) {
				device->bm_resync_fo = bsr_bm_bits(device);
				bsr_info(109, BSR_LC_RESYNC_OV, peer_device, "All resync requests have been sent. BSR_END_OF_BITMAP(%llu), device->bm_resync_fo : %llu, bm_set : %llu",
						(unsigned long long)bit, (unsigned long long)device->bm_resync_fo, (unsigned long long)bsr_bm_total_weight(peer_device));
				put_ldev(__FUNCTION__, device);
				return 0;
			}

			// DW-1978 it may have been completed with replication or the connection may have been terminated.
			if (peer_device->rs_total == 0)
				goto requeue;

			device->bm_resync_fo = bit;
			// BSR-1083
			cond_resched();
		}

		sector = BM_BIT_TO_SECT(bit);

		if (bsr_try_rs_begin_io(peer_device, sector, true)) {
			device->bm_resync_fo = bit;
			goto requeue;
		}
		device->bm_resync_fo = bit + 1;

		if (unlikely(bsr_bm_test_bit(peer_device, bit) == 0)) {
			bsr_rs_complete_io(peer_device, sector, __FUNCTION__);
			goto next_sector;
		}

#if BSR_MAX_BIO_SIZE > BM_BLOCK_SIZE
		/* try to find some adjacent bits.
		 * we stop if we have already the maximum req size.
		 *
		 * Additionally always align bigger requests, in order to
		 * be prepared for all stripe sizes of software RAIDs.
		 */
		align = 1;
		rollback_i = i;
		while (i < number) {
			if (size + BM_BLOCK_SIZE > max_bio_size)
				break;

			/* Be always aligned */
			if (sector & ((1<<(align+3))-1))
				break;

			if (discard_granularity && size == (unsigned int)discard_granularity)
				break;

			/* do not cross extent boundaries */
			if (((bit+1) & BM_BLOCKS_PER_BM_EXT_MASK) == 0)
				break;
			/* now, is it actually dirty, after all?
			 * caution, bsr_bm_test_bit is tri-state for some
			 * obscure reason; ( b == 0 ) would get the out-of-band
			 * only accidentally right because of the "oddly sized"
			 * adjustment below */
			if (bsr_bm_test_bit(peer_device, bit + 1) != 1)
				break;
			bit++;
			size += BM_BLOCK_SIZE;
			if ((unsigned int)(BM_BLOCK_SIZE << align) <= size)
				align++;
			i++;
		}
		/* if we merged some,
		 * reset the offset to start the next bsr_bm_find_next from */
		if (size > BM_BLOCK_SIZE)
			device->bm_resync_fo = bit + 1;
#endif

#ifdef SPLIT_REQUEST_RESYNC
		// DW-2082
		if ((ULONG_PTR)atomic_read64(&peer_device->e_resync_bb) < device->bm_resync_fo) {
			// DW-2065
			atomic_set64(&peer_device->e_resync_bb, device->bm_resync_fo);
		}
#endif
		/* adjust very last sectors, in case we are oddly sized */
		if (sector + (size>>9) > capacity)
			size = (unsigned int)(capacity-sector)<<9;

		if (peer_device->use_csums) {
			switch (read_for_csum(peer_device, sector, size)) {
			case -EIO: /* Disk failure */
				put_ldev(__FUNCTION__, device);
				return -EIO;
			case -EAGAIN: /* allocation failed, or ldev busy */
				bsr_rs_complete_io(peer_device, sector, __FUNCTION__);
				device->bm_resync_fo = (ULONG_PTR)BM_SECT_TO_BIT(sector);
				i = rollback_i;
				goto requeue;
			case 0:
				/* everything ok */
				break;
			default:
				BUG();
			}
		} else {
			int err;

			inc_rs_pending(peer_device);
			err = bsr_send_drequest(peer_device,
						(size == (unsigned int)discard_granularity) ? P_RS_THIN_REQ : P_RS_DATA_REQUEST,
						 sector, size, ID_SYNCER);
			if (err) {
				bsr_err(110, BSR_LC_RESYNC_OV, peer_device, "Failed to make resync request due to failure send, aborting...");
				dec_rs_pending(peer_device);
				put_ldev(__FUNCTION__, device);
				return err;
			}			
			// DW-1886
			peer_device->rs_send_req += size;
		}
	}

	if (device->bm_resync_fo >= bsr_bm_bits(device)) {
		/* last syncer _request_ was sent,
		 * but the P_RS_DATA_REPLY not yet received.  sync will end (and
		 * next sync group will resume), as soon as we receive the last
		 * resync data block, and the last bit is cleared.
		 * until then resync "work" is "inactive" ...
		 */
		bsr_info(111, BSR_LC_RESYNC_OV, peer_device, "All resync requests have been sent, but no resync response has been received yet.  device->bm_resync_fo : %llu, bm_set : %llu", (unsigned long long)device->bm_resync_fo, (unsigned long long)bsr_bm_total_weight(peer_device));
		put_ldev(__FUNCTION__, device);
		return 0;
	}

requeue:
	peer_device->rs_in_flight += (i << (BM_BLOCK_SHIFT - 9));
	mod_timer(&peer_device->resync_timer, jiffies + SLEEP_TIME);
	put_ldev(__FUNCTION__, device);
	return 0;
}

static int make_ov_request(struct bsr_peer_device *peer_device, int cancel)
{
	struct bsr_device *device = peer_device->device;
	int number, i, size;
	ULONG_PTR bit;
	sector_t sector;
	const sector_t capacity = bsr_get_vdisk_capacity(device);
	bool stop_sector_reached = false;
	struct peer_device_conf *pdc;
	struct bsr_request *req, *tmp;
	sector_t offset = 0;

	if (unlikely(cancel))
		return 1;

	// BSR-587 optional ov request size and interval
	rcu_read_lock();
	pdc = rcu_dereference(peer_device->conf);
	rcu_read_unlock();

	number = bsr_rs_number_requests(peer_device);

	sector = peer_device->ov_position;
	for (i = 0; i < number; i++) {
		if (sector >= capacity)
			return 1;

		/* We check for "finished" only in the reply path:
		 * w_e_end_ov_reply().
		 * We need to send at least one request out. */
		stop_sector_reached = i > 0
			&& verify_can_do_stop_sector(peer_device)
			&& sector >= peer_device->ov_stop_sector;
		if (stop_sector_reached)
			break;

#if 0 	
		// V8 style code. performace: decrease P_OV_REQUEST count, increase network thoughput per 1 time
		size = 1024*1024; 
		//size =  1024*256;  // for flowcontrol
#endif
		// BSR-997 set split ov size and sectors
		if (peer_device->ov_split_position) {
			offset = (peer_device->ov_split_position - BM_BIT_TO_SECT(BM_SECT_TO_BIT(peer_device->ov_split_position)));
			if (offset == 0)
				size = BM_BLOCK_SIZE;
			else
				size = BM_BLOCK_SIZE - (int)(offset << 9);

			bit = peer_device->ov_bm_position;
			sector = peer_device->ov_split_position;
		}
		else {
			size = BM_BLOCK_SIZE;

			// BSR-118 bitmap operation to use fast ov
			for (;;) {
				bit = bsr_ov_bm_range_find_next(peer_device, peer_device->ov_bm_position, peer_device->ov_bm_position + RANGE_FIND_NEXT_BIT);
				if (bit < bsr_ov_bm_bits(peer_device) && bit < (peer_device->ov_bm_position + RANGE_FIND_NEXT_BIT)) {
					break;
				}

				if (bit >= bsr_ov_bm_bits(peer_device)) {
					bsr_info(112, BSR_LC_RESYNC_OV, peer_device, "All verify requests have been sent. BSR_END_OF_OV_BITMAP(%llu), peer_device->ov_bm_position : %llu left %llu",
							(unsigned long long)bit, (unsigned long long)peer_device->ov_bm_position, (unsigned long long)peer_device->ov_left);
					peer_device->ov_bm_position = bsr_ov_bm_bits(peer_device);
					peer_device->ov_position = BM_BIT_TO_SECT(peer_device->ov_bm_position);
					return 0;
				}

				peer_device->ov_bm_position = bit;
				// BSR-1083
				cond_resched();
			}

			sector = BM_BIT_TO_SECT(bit);

		}

		if (bsr_try_rs_begin_io(peer_device, sector, true)) {
			peer_device->ov_position = sector;
			goto requeue;
		}

		peer_device->ov_bm_position = bit + 1;
		peer_device->ov_split_position = 0; // BSR-997

		// BSR-119 verify in OV_REQUEST_NUM_BLOCK unit to reduce disk I/O load.
		while (i+1 < number) {
			if (bsr_ov_bm_test_bit(peer_device, bit + 1) != 1)
				break;

			if(size < ((int)pdc->ov_req_num * BM_BLOCK_SIZE)) {
				size += BM_BLOCK_SIZE;
				i++;
				bit++;
			}
			else
				break;
		}

		if (sector + (size >> 9) > capacity)
			size = (unsigned int)(capacity - sector) << 9;

		// BSR-997 check if the ov request range overlaps with an incomplete write request
		spin_lock_irq(&device->resource->req_lock);
		list_for_each_entry_safe_ex(struct bsr_request, req, tmp, &device->pending_master_completion[1], req_pending_master_completion) {			
			if (req->i.sector > (sector + (size >> 9) - 1))
				continue;
			if ((req->i.sector + (req->i.size >> 9)) - 1 < sector)
				continue;
			
			bsr_debug(219, BSR_LC_RESYNC_OV, peer_device, "pending IO, ov sector (%llu) size (%d) position (%d) bit (%d), req sector (%llu) size (%d)", 
					sector, size >> 9, peer_device->ov_bm_position, bit, req->i.sector, req->i.size >> 9);
			
			// skipped all ov request sector
			if ((req->i.sector <= sector) && (req->i.sector + (req->i.size >> 9) >= sector + (size >> 9)))
				goto skipped;

			// write request sector is larger than ov sector, 
			// reduce ov request size
			if ((req->i.sector > sector) && (req->i.sector < sector + (size >> 9))) {
				if ((peer_device->ov_split_position == 0) || peer_device->ov_split_position > req->i.sector) {
					size = (int)((req->i.sector - sector) << 9);
					peer_device->ov_split_position = req->i.sector;			
					bsr_debug(220, BSR_LC_RESYNC_OV, peer_device, "ov sector (%llu) reduce size (%d)", sector, size);
				}
				continue;
			}

			// ov sector is larger than the write request sector, 
			// ov request start sector reset
			if ((req->i.sector <= sector) && (req->i.sector + (req->i.size >> 9) > sector)) {
				size = (int)(((req->i.sector + (req->i.size >> 9)) - sector) << 9);
				peer_device->ov_split_position = req->i.sector + (req->i.size >> 9);
				goto skipped;
			}
		}

		atomic_set64(&peer_device->ov_req_sector, sector + (size >> 9) - 1);
		spin_unlock_irq(&device->resource->req_lock);

		inc_rs_pending(peer_device);
		if (bsr_send_ov_request(peer_device, sector, size)) {
			dec_rs_pending(peer_device);
			return 0;
		}
		goto next_sector;

skipped:
		// BSR-997 set skipped block
		spin_unlock_irq(&device->resource->req_lock);
		bsr_rs_complete_io(peer_device, sector, __FUNCTION__);
		bsr_debug(221, BSR_LC_RESYNC_OV, peer_device, "skipped sector %llu size(%d)", sector, size >> 9);
		verify_skipped_block(peer_device, sector, size, false);
next_sector:
		if (peer_device->ov_split_position) {			
			peer_device->ov_position = peer_device->ov_split_position;
			bit = BM_SECT_TO_BIT(peer_device->ov_split_position);
			peer_device->ov_bm_position = bit;
			bsr_debug(224, BSR_LC_RESYNC_OV, peer_device, "next sector (%llu) bm_position (%d)", 
					peer_device->ov_split_position, peer_device->ov_bm_position);
		} else {
			sector += (size >> 9);
			if (size > BM_BLOCK_SIZE) {
				peer_device->ov_bm_position = bit + 1;
			}
		}
	}
	peer_device->ov_position = sector;

 requeue:
	peer_device->rs_in_flight += (i << (BM_BLOCK_SHIFT - 9));
	if (i == 0 || !stop_sector_reached)
		mod_timer(&peer_device->resync_timer, jiffies + pdc->ov_req_interval);
	return 1;
}

struct resync_finished_work {
	struct bsr_peer_device_work pdw;
	enum bsr_disk_state new_peer_disk_state;
};

static int w_resync_finished(struct bsr_work *w, int cancel)
{
	struct resync_finished_work *rfw = container_of(
		container_of(w, struct bsr_peer_device_work, w),
		struct resync_finished_work, pdw);

	UNREFERENCED_PARAMETER(cancel);

	bsr_resync_finished(__FUNCTION__, rfw->pdw.peer_device, rfw->new_peer_disk_state);
	bsr_kfree(rfw);

	return 0;
}

// BSR-863
void bsr_uuid_peer(struct bsr_peer_device *peer_device)
{
	clear_bit(GOT_UUID_ACK, &peer_device->connection->flags);
	bsr_send_uuids(peer_device, 0, 0, NOW);
	wait_event(peer_device->connection->uuid_wait,
		test_bit(GOT_UUID_ACK, &peer_device->connection->flags) ||
		peer_device->connection->cstate[NOW] < C_CONNECTED);
}

void bsr_ping_peer(struct bsr_connection *connection)
{
	clear_bit(GOT_PING_ACK, &connection->flags);
	request_ping(connection);
	wait_event(connection->ping_wait,
		   test_bit(GOT_PING_ACK, &connection->flags) ||
		   connection->cstate[NOW] < C_CONNECTED);
}

/* caller needs to hold rcu_read_lock, req_lock, adm_mutex or conf_update */
struct bsr_peer_device *peer_device_by_node_id(struct bsr_device *device, int node_id)
{
	struct bsr_peer_device *peer_device;

	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->node_id == node_id)
			return peer_device;
	}

	return NULL;
}

static void __outdate_peer_disk_by_mask(struct bsr_device *device, u64 nodes)
{
	struct bsr_peer_device *peer_device;
	int node_id;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		if (!(nodes & NODE_MASK(node_id)))
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device && peer_device->disk_state[NEW] >= D_CONSISTENT)
			__change_peer_disk_state(peer_device, D_OUTDATED, __FUNCTION__);
	}
}

/* An annoying corner case is if we are resync target towards a bunch
   of nodes. One of the resyncs finished as STABLE_RESYNC, the others
   as UNSTABLE_RESYNC. */
static bool was_resync_stable(struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;

	if (test_bit(UNSTABLE_RESYNC, &peer_device->flags) &&
	    !test_bit(STABLE_RESYNC, &device->flags))
		return false;

	// DW-1113 clear UNSTABLE_RESYNC flag for all peers that I'm getting synced with and have set primary as authoritative node since I have consistent disk with primary.
	if (peer_device->connection->peer_role[NOW] == R_PRIMARY) {
		struct bsr_peer_device *found_peer = NULL;
		for_each_peer_device_rcu(found_peer, device) {
			enum bsr_repl_state repl_state = found_peer->repl_state[NOW];
			u64 authoritative_nodes = found_peer->uuid_authoritative_nodes;

			if (found_peer == peer_device)
				continue;

			if (test_bit(UNSTABLE_RESYNC, &found_peer->flags) &&
				(repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
				authoritative_nodes & NODE_MASK(peer_device->node_id))
				clear_bit(UNSTABLE_RESYNC, &found_peer->flags);
		}
	}

	set_bit(STABLE_RESYNC, &device->flags);
	/* that STABLE_RESYNC bit gets reset if in any other ongoing resync
	   we receive something from a resync source that is marked with
	   UNSTABLE RESYNC. */

	return true;
}

// DW-955 need to upgrade disk state after unstable resync.
static void sanitize_state_after_unstable_resync(struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_device *found_peer = NULL;
	
	// unstable resync's done, does mean primary node exists. try to find it.
	for_each_peer_device_rcu(found_peer, device) {
		// my disk is consistent with primary's, adopt it's disk state.
		if (found_peer->connection->peer_role[NOW] == R_PRIMARY &&
			bsr_bm_total_weight(found_peer) == 0)
		{
			__change_disk_state(device, found_peer->disk_state[NOW], __FUNCTION__);
			return;
		}
	}

	// I have no connection with primary, but disk is consistent with unstable node. I may be outdated.
	if (bsr_bm_total_weight(peer_device) == 0 &&
		device->disk_state[NOW] < D_OUTDATED &&
		peer_device->disk_state[NOW] >= D_OUTDATED)
		__change_disk_state(device, D_OUTDATED, __FUNCTION__);
}

static void __cancel_other_resyncs(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NEW] == L_PAUSED_SYNC_T) {
			// DW-955 canceling other resync may causes out-oof-sync remained, clear the bitmap since no need.
			struct bsr_peer_md *peer_md = device->ldev->md.peers;
			int peer_node_id = 0;
			u64 peer_bm_uuid = 0;

			spin_lock_irq(&device->ldev->md.uuid_lock);
			peer_node_id = peer_device->node_id;
			peer_bm_uuid = peer_md[peer_node_id].bitmap_uuid;

			if (peer_bm_uuid)
				_bsr_uuid_push_history(device, peer_bm_uuid, NULL);
			if (peer_md[peer_node_id].bitmap_index != -1
			 && !bsr_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR)) {
				bsr_info(113, BSR_LC_RESYNC_OV, peer_device, "Bitmap will be cleared due to resync cancelation");
				forget_bitmap(device, peer_node_id);
			}
			bsr_md_mark_dirty(device);
			spin_unlock_irq(&device->ldev->md.uuid_lock);

			__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED, __FUNCTION__);
		}
	}
}

static void init_resync_stable_bits(struct bsr_peer_device *first_target_pd)
{
	struct bsr_device *device = first_target_pd->device;
	struct bsr_peer_device *peer_device;

	clear_bit(UNSTABLE_RESYNC, &first_target_pd->flags);

	/* Clear the device wide STABLE_RESYNC flag when becoming
	   resync target on the first peer_device. */
	for_each_peer_device(peer_device, device) {
		enum bsr_repl_state repl_state = peer_device->repl_state[NOW];
		if (peer_device == first_target_pd)
			continue;
		if (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T)
			return;
	}
	clear_bit(STABLE_RESYNC, &device->flags);
}

int bsr_resync_finished(const char *caller, struct bsr_peer_device *peer_device,
			 enum bsr_disk_state new_peer_disk_state)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_connection *connection = peer_device->connection;
	enum bsr_repl_state *repl_state = peer_device->repl_state;
	enum bsr_repl_state old_repl_state = L_ESTABLISHED;
	ULONG_PTR db, dt, dbdt;
	ULONG_PTR n_oos;
	char *khelper_cmd = NULL;
	int verify_done = 0;

	bool uuid_updated = false;
	bool stable_resync = false;
	bool uuid_resync_finished = false;
	u64 newer = 0;

	struct bsr_peer_md old_peers_md[BSR_NODE_ID_MAX];
	u64 removed_history = 0, before_uuid = 0;

	if (repl_state[NOW] == L_SYNC_SOURCE || repl_state[NOW] == L_PAUSED_SYNC_S) {
		/* Make sure all queued w_update_peers()/consider_sending_peers_in_sync()
		   executed before killing the resync_lru with bsr_rs_del_all() */
		if (current == device->resource->worker.task)
			goto queue_on_sender_workq;
		else
			bsr_flush_workqueue(device->resource, &device->resource->work);
	}

	/* Remove all elements from the resync LRU. Since future actions
	 * might set bits in the (main) bitmap, then the entries in the
	 * resync LRU would be wrong. */
	if (bsr_rs_del_all(peer_device)) {
		struct resync_finished_work *rfw;

		/* In case this is not possible now, most probably because
		 * there are P_RS_DATA_REPLY Packets lingering on the sender's
		 * queue (or even the read operations for those packets
		 * is not finished by now).   Retry in 100ms. */

		bsr_kick_lo(device);
		schedule_timeout_interruptible(HZ / 10);
	queue_on_sender_workq:
		rfw = bsr_kmalloc(sizeof(*rfw), GFP_ATOMIC, '13SB');
		if (rfw) {
			rfw->pdw.w.cb = w_resync_finished;
			rfw->pdw.peer_device = peer_device;
			rfw->new_peer_disk_state = new_peer_disk_state;
			bsr_queue_work(&connection->sender_work, &rfw->pdw.w);
			return 1;
		}
		bsr_err(41, BSR_LC_MEMORY, peer_device, "resync finished, but failure to allocate memory for work item(resync finished)");
	}

	dt = (jiffies - peer_device->rs_start - peer_device->rs_paused) / HZ;
	if (dt <= 0)
		dt = 1;
	db = peer_device->rs_total;
	/* adjust for verify start and stop sectors, respective reached position */
	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T)
		db -= peer_device->ov_left;

	dbdt = Bit2KB(db/dt);
	peer_device->rs_paused /= HZ;

	if (!get_ldev(device))
		goto out;

	bsr_ping_peer(connection);

	// BSR-863
	if ((repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T)) {

		stable_resync = was_resync_stable(peer_device);
		if (!peer_device->rs_failed) {
			// DW-1034 we've already had the newest one.
			if (stable_resync) {
				if (((bsr_current_uuid(device) & ~UUID_PRIMARY) != (peer_device->current_uuid & ~UUID_PRIMARY)) &&
					peer_device->uuids_received) {
					newer = bsr_uuid_resync_finished(peer_device, old_peers_md, &removed_history, &before_uuid);
					uuid_resync_finished = true;
				}
			}

			if (connection->agreed_pro_version >= 115) {
				// BSR-863 sync target sends the uuid to the sync source during the synchronization completion process and updates the uuid when it receives a response.
				bsr_uuid_peer(peer_device);
			}
		}
	}

	spin_lock_irq(&device->resource->req_lock);

	// BSR-1065 checked congestion in req_lock area for synchronization with congestion setting and resynchronization completion
	// DW-1198 If repl_state is L_AHEAD, do not finish resync. Keep the L_AHEAD.
	if (repl_state[NOW] == L_AHEAD) {
		bsr_info(115, BSR_LC_RESYNC_OV, peer_device, "Resync does not finished because the replication status is Ahead."); // DW-1518
		put_ldev(__FUNCTION__, device); 
		spin_unlock_irq(&device->resource->req_lock);
		return 1;
	}

	// BSR-1085 when the resync is completed in a congested state(L_BEHIND), only the source node completes resync on the next resync.
	if (peer_device->repl_state[NOW] == L_BEHIND) {
		put_ldev(__FUNCTION__, device);
		spin_unlock_irq(&device->resource->req_lock);
		return 1;
	}

	begin_state_change_locked(device->resource, CS_VERBOSE);
	old_repl_state = repl_state[NOW];

	verify_done = (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T);

	/* This protects us against multiple calls (that can happen in the presence
	   of application IO), and against connectivity loss just before we arrive here. */
	if (peer_device->repl_state[NOW] <= L_ESTABLISHED) {
		// BSR-863
		if (connection->agreed_pro_version >= 115 && uuid_resync_finished) {
			bsr_uuid_resync_finished_rollback(peer_device, newer, before_uuid, old_peers_md, removed_history);
		}
		goto out_unlock;
	}
	__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED, __FUNCTION__);

	// BSR-595
	{
	char tmp[sizeof(" but 01234567890123456789 sectors skipped")] = "";
	if (verify_done && peer_device->ov_skipped) {
		snprintf(tmp, sizeof(tmp), " but %llu sectors skipped", (unsigned long long)peer_device->ov_skipped);
	}
#ifdef SPLIT_REQUEST_RESYNC
	bsr_info(116, BSR_LC_RESYNC_OV, peer_device, "%s => %s done%s (total %llu sec; paused %llu sec; %llu K/sec), hit bit (in sync %llu; marked rl %llu)",
		caller, verify_done ? "Online verify" : "Resync", tmp,
		(unsigned long long)dt + peer_device->rs_paused, 
		(unsigned long long)peer_device->rs_paused, (unsigned long long)dbdt, 
		(unsigned long long)device->h_insync_bb, 
		(unsigned long long)device->h_marked_bb);
#else // _LIN
	bsr_info(117, BSR_LC_RESYNC_OV, peer_device, "%s done (total %llu sec; paused %llu sec; %llu K/sec)",
		verify_done ? "Online verify" : "Resync", (unsigned long long)dt + peer_device->rs_paused, (unsigned long long)peer_device->rs_paused, (unsigned long long)dbdt);
#endif
	}
	n_oos = bsr_bm_total_weight(peer_device);

	if (repl_state[NOW] == L_VERIFY_S || repl_state[NOW] == L_VERIFY_T) {
		// BSR-118
		// ov done
		if (NULL != peer_device->fast_ov_bitmap) {
			// BSR-835
			kref_put(&peer_device->ov_bm_ref, bsr_free_ov_bm);
		}

		if (n_oos) {
			bsr_alert(118, BSR_LC_RESYNC_OV, peer_device, "Online verify found %lu %dk block out of sync",
			      n_oos, Bit2KB(1));
			khelper_cmd = "out-of-sync";
		}
	} else {
#ifdef _WIN
		if (!((n_oos - peer_device->rs_failed) == 0)) {
			DbgPrint("_WIN32_v9_CHECK: n_oos=%Iu rs_failed=%Iu. Ignore assert ##########", n_oos, peer_device->rs_failed);
		}
#else // _LIN
		D_ASSERT(peer_device, (n_oos - peer_device->rs_failed) == 0);
#endif

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T)
			khelper_cmd = "after-resync-target";

		if (peer_device->use_csums && peer_device->rs_total) {
			const ULONG_PTR s = peer_device->rs_same_csum;
			const ULONG_PTR t = peer_device->rs_total;
			const ULONG_PTR ratio =
				(t == 0)     ? 0 :
			(t < 100000) ? ((s*100)/t) : (s/(t/100));
			bsr_info(119, BSR_LC_RESYNC_OV, peer_device, "%llu %% had equal checksums, eliminated: %lluK; "
			     "transferred %lluK total %lluK",
			     (unsigned long long)ratio,
			     (unsigned long long)Bit2KB(peer_device->rs_same_csum),
			     (unsigned long long)Bit2KB(peer_device->rs_total - peer_device->rs_same_csum),
			     (unsigned long long)Bit2KB(peer_device->rs_total));
		}
	}

	if (peer_device->rs_failed) {
		bsr_info(120, BSR_LC_RESYNC_OV, peer_device, "            %llu failed blocks (out of sync :%llu)", (unsigned long long)peer_device->rs_failed, (unsigned long long)n_oos);

		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T) {
			__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
			__change_peer_disk_state(peer_device, D_UP_TO_DATE, __FUNCTION__);
		} else {
			__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);
			__change_peer_disk_state(peer_device, D_INCONSISTENT, __FUNCTION__);
		}
		peer_device->resync_again = true;
	}
	else {
		if (repl_state[NOW] == L_SYNC_TARGET || repl_state[NOW] == L_PAUSED_SYNC_T) {
			bool stable_resync = was_resync_stable(peer_device);
			if (stable_resync)
				__change_disk_state(device, peer_device->disk_state[NOW], __FUNCTION__);
			// DW-955 need to upgrade disk state after unstable resync.
			else
				sanitize_state_after_unstable_resync(peer_device);

			if (device->disk_state[NEW] == D_UP_TO_DATE)
				__cancel_other_resyncs(device);

			if (stable_resync &&
				// DW-1034 we've already had the newest one.
				((bsr_current_uuid(device) & ~UUID_PRIMARY) != (peer_device->current_uuid & ~UUID_PRIMARY)) &&
			    peer_device->uuids_received) {

				// DW-1216 no downgrade if uuid flags contains belows because
				// 1. receiver updates newly created uuid unless it is being gotten sync, downgrading shouldn't(or might not) affect.
				if (peer_device->uuid_flags & UUID_FLAG_NEW_DATAGEN)
					newer = 0;

				__outdate_peer_disk_by_mask(device, newer);
			} else {
				if (!peer_device->uuids_received)
					bsr_err(121, BSR_LC_RESYNC_OV, peer_device, "resync finished, but uuids were not received. maybe BUG");

				if (test_bit(UNSTABLE_RESYNC, &peer_device->flags))
					bsr_info(122, BSR_LC_RESYNC_OV, peer_device, "Peer was unstable during resync");
			}

			if (peer_device->uuids_received) {
				/* Now the two UUID sets are equal, update what we
				* know of the peer. */
				const int node_id = device->resource->res_opts.node_id;
				int i;

				// BSR-1017 renew if you received the uuid again during the end of resync.
				if ((bsr_current_uuid(device) & ~UUID_PRIMARY) != (peer_device->current_uuid & ~UUID_PRIMARY)) {
					// BSR-1017 notify if the uuid has been updated during resync completion.
					if (uuid_resync_finished)
						bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
					bsr_uuid_resync_finished(peer_device, NULL, NULL, NULL);
				}

				bsr_print_uuids(peer_device, "updated UUIDs", __FUNCTION__);
				peer_device->current_uuid = bsr_current_uuid(device);
				peer_device->bitmap_uuids[node_id] = bsr_bitmap_uuid(peer_device);
				for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids); i++)
					peer_device->history_uuids[i] =
					bsr_history_uuid(device, i);

				// BSR-676 notify uuid
				bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
				// DW-2160
				uuid_updated = true;
			}
		} else if (repl_state[NOW] == L_SYNC_SOURCE || repl_state[NOW] == L_PAUSED_SYNC_S) {
			struct bsr_peer_device *p;

			if (new_peer_disk_state != D_MASK)
				__change_peer_disk_state(peer_device, new_peer_disk_state, __FUNCTION__);
			if (peer_device->connection->agreed_pro_version < 110) {
				bsr_uuid_set_bitmap(peer_device, 0UL);
				bsr_print_uuids(peer_device, "updated UUIDs", __FUNCTION__);
				// BSR-676 notify uuid
				bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
			}

			// BSR-1171
			for_each_peer_device(p, device) {
				if (p == peer_device)
					continue;

				// BSR-1171 
				if (p->repl_state[NOW] != L_ESTABLISHED) {
					// BSR-1171 resync is complete and it is the latest data. If replication occurs at the end of the connection after excluding it from the bitmap merge target of another node, set it as a merge target.
					p->merged_nodes |= NODE_MASK(peer_device->node_id);
					p->latest_nodes |= NODE_MASK(peer_device->node_id); 
					bsr_info(18, BSR_LC_VERIFY, NO_OBJECT, "clear bitmap merge target %d in %d.", peer_device->node_id, p->node_id);
				}
			}

			peer_device->latest_nodes = 0;
#ifdef _WIN64
			peer_device->merged_nodes = UINT64_MAX;
#else
			peer_device->merged_nodes = ~0UL;
#endif
			bsr_md_clear_peer_flag(peer_device, MDF_NEED_TO_MERGE_BITMAP);
		}
	}

	// DW-955 clear resync aborted flag when just resync is done.
	clear_bit(RESYNC_ABORTED, &peer_device->flags);

	// BSR-431 clear MDF_PEER_INIT_SYNCT_BEGIN flag when just resync is done.
	if (bsr_md_test_peer_flag(peer_device, MDF_PEER_INIT_SYNCT_BEGIN)) {
		struct bsr_peer_device *other_peer_device = NULL;
		bsr_md_clear_peer_flag(peer_device, MDF_PEER_INIT_SYNCT_BEGIN);

		// BSR-1213 clear MDF_PEER_INIT_SYNCT_BEGIN on other peer nodes as well.
		for_each_peer_device(other_peer_device, device) {
			if (other_peer_device == peer_device)
				continue;
			bsr_md_clear_peer_flag(other_peer_device, MDF_PEER_INIT_SYNCT_BEGIN);
		}
	}

#ifdef _WIN
	// BSR-1066 when resync finished, clear MDF_PEER_DISKLESS_OR_CRASHED_PRIMARY flag
	if (bsr_md_test_peer_flag(peer_device, MDF_PEER_DISKLESS_OR_CRASHED_PRIMARY)) {
		bsr_md_clear_peer_flag(peer_device, MDF_PEER_DISKLESS_OR_CRASHED_PRIMARY);
	}
#endif

out_unlock:
	end_state_change_locked(device->resource, false, __FUNCTION__);

	// DW-2160 If the peer device and the current uuid of the device differ by receiving the UUID during synchronization completion, update it again.
	if (uuid_updated && ((bsr_current_uuid(device) & ~UUID_PRIMARY) != (peer_device->current_uuid & ~UUID_PRIMARY))) {
		int i;

		bsr_uuid_resync_finished(peer_device, NULL, NULL, NULL);
		peer_device->current_uuid = bsr_current_uuid(device);
		peer_device->bitmap_uuids[device->resource->res_opts.node_id] = bsr_bitmap_uuid(peer_device);
		for (i = 0; i < ARRAY_SIZE(peer_device->history_uuids); i++)
			peer_device->history_uuids[i] = bsr_history_uuid(device, i);

		bsr_print_uuids(peer_device, "again updated UUIDs", __FUNCTION__);

		// BSR-1017
		bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
		bsr_md_mark_dirty(device);
	}

	put_ldev(__FUNCTION__, device);

	peer_device->rs_total  = 0;
	peer_device->rs_failed = 0;
	peer_device->rs_paused = 0;
	atomic_set(&peer_device->wait_for_bitmp_exchange_complete, 0);

	if (peer_device->resync_again) {
		enum bsr_repl_state new_repl_state =
			old_repl_state == L_SYNC_TARGET || old_repl_state == L_PAUSED_SYNC_T ?
			L_WF_BITMAP_T :
			old_repl_state == L_SYNC_SOURCE || old_repl_state == L_PAUSED_SYNC_S ?
			L_WF_BITMAP_S : L_ESTABLISHED;

		// DW-2062 set resync_again to true/false because it cannot be duplicated.
		// if resync is started and completed in the future, it is not necessary to try again, so set it to false.
		peer_device->resync_again = false;
		if (new_repl_state != L_ESTABLISHED) {
			begin_state_change_locked(device->resource, CS_VERBOSE);
			__change_repl_state_and_auto_cstate(peer_device, new_repl_state, __FUNCTION__);
			end_state_change_locked(device->resource, false, __FUNCTION__);
		}
	}
	spin_unlock_irq(&device->resource->req_lock);

out:
	/* reset start sector, if we reached end of device */
	if (verify_done && peer_device->ov_left_sectors == 0)
		peer_device->ov_start_sector = 0;

	// DW-2088
	bsr_md_clear_peer_flag(peer_device, MDF_PEER_INCOMP_SYNC_WITH_SAME_UUID);

	if (old_repl_state == L_SYNC_SOURCE || old_repl_state == L_PAUSED_SYNC_S) {
		// DW-1874
		bsr_md_clear_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC);
	}

	bsr_md_sync_if_dirty(device);

	if (khelper_cmd)
		bsr_khelper(device, connection, khelper_cmd);

	/* If we have been sync source, and have an effective fencing-policy,
	 * once *all* volumes are back in sync, call "unfence". */
	if (old_repl_state == L_SYNC_SOURCE || old_repl_state == L_PAUSED_SYNC_S) {
		enum bsr_disk_state disk_state = D_MASK;
		enum bsr_disk_state pdsk_state = D_MASK;
		enum bsr_fencing_policy fencing_policy = FP_DONT_CARE;

		rcu_read_lock();
		fencing_policy = connection->fencing_policy;
		if (fencing_policy != FP_DONT_CARE) {
			struct bsr_peer_device *peer_device;
			int vnr;
			idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
				struct bsr_device *device = peer_device->device;
				disk_state = min_t(enum bsr_disk_state, disk_state, device->disk_state[NOW]);
				pdsk_state = min_t(enum bsr_disk_state, pdsk_state, peer_device->disk_state[NOW]);
			}
		}
		rcu_read_unlock();
		if (disk_state == D_UP_TO_DATE && pdsk_state == D_UP_TO_DATE)
			bsr_khelper(NULL, connection, "unfence-peer");
	}

	// BSR-1001
	if (old_repl_state == L_SYNC_TARGET)
		check_remaining_out_of_sync(device);

	return 1;
}

/* helper */
static void move_to_net_ee_or_free(struct bsr_connection *connection, struct bsr_peer_request *peer_req)
{
	if (bsr_peer_req_has_active_page(peer_req)) {
		/* This might happen if sendpage() has not finished */
		int i = DIV_ROUND_UP(peer_req->i.size, PAGE_SIZE);
		atomic_add(i, &connection->pp_in_use_by_net);
		atomic_sub(i, &connection->pp_in_use);
		spin_lock_irq(&connection->resource->req_lock);
		list_add_tail(&peer_req->w.list, &peer_req->peer_device->connection->net_ee);
		spin_unlock_irq(&connection->resource->req_lock);
		wake_up(&bsr_pp_wait);
	} else
		bsr_free_peer_req(peer_req);
}

/**
 * w_e_end_data_req() - Worker callback, to send a P_DATA_REPLY packet in response to a P_DATA_REQUEST
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_e_end_data_req(struct bsr_work *w, int cancel)
{
	struct bsr_peer_request *peer_req = container_of(w, struct bsr_peer_request, w);
	struct bsr_peer_device *peer_device = peer_req->peer_device;
	int err;

	if (unlikely(cancel)) {
		bsr_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		err = bsr_send_block(peer_device, P_DATA_REPLY, 0, peer_req);
	} else {
		if (bsr_ratelimit())
			bsr_err(21, BSR_LC_REPLICATION, peer_device, "Failed to response for request data due to failure read. sector(%llus).",
			    (unsigned long long)peer_req->i.sector);

		err = bsr_send_ack(peer_device, P_NEG_DREPLY, peer_req);
	}

	dec_unacked(peer_device);

	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		bsr_err(22, BSR_LC_REPLICATION, peer_device, "Failed to response for request data due send. err(%d)", err);
	return err;
}

static bool all_zero(struct bsr_peer_request *peer_req)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(peer_req);
	return false;
#else // _LIN
	struct page *page = peer_req->page_chain.head;
	unsigned int len = peer_req->i.size;

	page_chain_for_each(page) {
		unsigned int l = min_t(unsigned int, len, PAGE_SIZE);
		unsigned int i, words = l / sizeof(long);
		unsigned long *d;

		d = bsr_kmap_atomic(page, KM_USER1);
		for (i = 0; i < words; i++) {
			if (d[i]) {
				bsr_kunmap_atomic(d, KM_USER1);
				return false;
			}
		}
		bsr_kunmap_atomic(d, KM_USER1);
		len -= l;
	}

	return true;
#endif
}

/**
 * w_e_end_rsdata_req() - Worker callback to send a P_RS_DATA_REPLY packet in response to a P_RS_DATA_REQUEST
 * @w:		work object.
 * @cancel:	The connection will be closed anyways
 */
int w_e_end_rsdata_req(struct bsr_work *w, int cancel)
{
	struct bsr_peer_request *peer_req = container_of(w, struct bsr_peer_request, w);
	struct bsr_peer_device *peer_device = peer_req->peer_device;
	struct bsr_device *device = peer_device->device;
	int err = 0;

	if (unlikely(cancel)) {
		bsr_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (get_ldev_if_state(device, D_DETACHING)) {
		bsr_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
		put_ldev(__FUNCTION__, device);
	}

	if (peer_device->repl_state[NOW] == L_AHEAD) {
		err = bsr_send_ack(peer_device, P_RS_CANCEL, peer_req);
	}
	else if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		// DW-1807 send P_RS_CANCEL if resync is not in progress
		// DW-1846 The request should also be processed when the resync is stopped.
		// DW-2055 primary is always the syncsource of resync, so send the resync data.
		if (!is_sync_source(peer_device) && device->resource->role[NOW] != R_PRIMARY) {
			err = bsr_send_ack(peer_device, P_RS_CANCEL, peer_req);
		}
		else {
			if (likely(peer_device->disk_state[NOW] >= D_INCONSISTENT)) {

				// BSR-428 fix potential rs_in_flight incorrect calculation
				inc_rs_pending(peer_device);
				// DW-1817
				//Add the data size to rs_in_flight before sending the resync data.
				// BSR-839
				add_rs_in_flight(peer_req->i.size, peer_device->connection);

				bsr_debug(17, BSR_LC_VERIFY, peer_device, "%s, sector(%llu), size(%u), bitmap(%llu ~ %llu)", __FUNCTION__, 
																												(unsigned long long)peer_req->i.sector, 
																												peer_req->i.size, 
																												(unsigned long long)BM_SECT_TO_BIT(peer_req->i.sector), 
																												(unsigned long long)BM_SECT_TO_BIT(peer_req->i.sector + (peer_req->i.size >> 9)));

				if (peer_req->flags & EE_RS_THIN_REQ && all_zero(peer_req)) {
					err = bsr_send_rs_deallocated(peer_device, peer_req);
				} else {
					err = bsr_send_block(peer_device, P_RS_DATA_REPLY, atomic_read(&peer_device->resync_seq), peer_req);
					// BSR-838
					atomic_add64(peer_req->i.size, &peer_device->cur_resync_sended);
				}

				// BSR-428 fix potential rs_in_flight incorrect calculation
				if (err) {
					dec_rs_pending(peer_device);
					// BSR-839
					sub_rs_in_flight(peer_req->i.size, peer_device->connection, true);
				}

			}
			else {
				if (bsr_ratelimit())
					bsr_err(123, BSR_LC_RESYNC_OV, peer_device, "No response sent for resync request data due to peer disk status %s.", bsr_disk_str(peer_device->disk_state[NOW]));
				err = 0;
			}
		}
	} else {
		if (bsr_ratelimit())
			bsr_err(124, BSR_LC_RESYNC_OV, peer_device, "Failed to response for request resync data due to failure write. sector(%llus).",
			    (unsigned long long)peer_req->i.sector);

		err = bsr_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);

		/* update resync data with failure */
		bsr_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
	}

	dec_unacked(peer_device);

	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		bsr_err(125, BSR_LC_RESYNC_OV, peer_device, "Failed to response for request resync data due send. err(%d)", err);
	return err;
}

int w_e_end_csum_rs_req(struct bsr_work *w, int cancel)
{
	struct bsr_peer_request *peer_req = container_of(w, struct bsr_peer_request, w);
	struct bsr_peer_device *peer_device = peer_req->peer_device;
	struct bsr_device *device = peer_device->device;
	struct digest_info *di;
	int digest_size = 0; 
	
	void *digest = NULL;
	int err, eq = 0;

	if (unlikely(cancel)) {
		bsr_info(126, BSR_LC_RESYNC_OV, peer_device, "Cancels the checksum synchronization request response. sector : %llu", (unsigned long long)peer_req->i.sector);
		bsr_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	if (get_ldev(device)) {
		bsr_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
		put_ldev(__FUNCTION__, device);
	}

	di = peer_req->digest;

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		/* quick hack to try to avoid a race against reconfiguration.
		 * a real fix would be much more involved,
		 * introducing more locking mechanisms */
		if (peer_device->connection->csums_tfm) {
			digest_size = crypto_shash_digestsize(peer_device->connection->csums_tfm);
			D_ASSERT(device, digest_size == di->digest_size);

			digest = bsr_kmalloc(digest_size, GFP_NOIO, '23SB');
			if (digest) {
				bsr_csum_pages(peer_device->connection->csums_tfm, peer_req, digest);
				eq = !memcmp(digest, di->digest, digest_size);
				bsr_kfree(digest);
			}
		}

		if (eq) {
			bsr_set_in_sync(peer_device, peer_req->i.sector, peer_req->i.size);
			/* rs_same_csums unit is BM_BLOCK_SIZE */
			peer_device->rs_same_csum += peer_req->i.size >> BM_BLOCK_SHIFT;
			err = bsr_send_ack(peer_device, P_RS_IS_IN_SYNC, peer_req);
			// BSR-448 applied to release io-error value.
			check_and_clear_io_error_in_primary(device);
		} else {
			inc_rs_pending(peer_device);
			peer_req->block_id = ID_SYNCER; /* By setting block_id, digest pointer becomes invalid! */
			peer_req->flags &= ~EE_HAS_DIGEST; /* This peer request no longer has a digest pointer */
			bsr_kfree(di);
			err = bsr_send_block(peer_device, P_RS_DATA_REPLY, atomic_read(&peer_device->resync_seq), peer_req);
			// BSR-1102 aggregation on sending resync data during hash resync
			atomic_add64(peer_req->i.size, &peer_device->cur_resync_sended);
		}
	} else {
		err = bsr_send_ack(peer_device, P_NEG_RS_DREPLY, peer_req);
		if (bsr_ratelimit())
			bsr_err(127, BSR_LC_RESYNC_OV, device, "Failed to response for request checksum resync data due to failure write.");
		// BSR-448 fix bug that checksum synchronization stops when SyncSource io-error occurs continuously.
		bsr_rs_failed_io(peer_device, peer_req->i.sector, peer_req->i.size);
	}

	dec_unacked(peer_device);
	move_to_net_ee_or_free(peer_device->connection, peer_req);

	if (unlikely(err))
		bsr_err(128, BSR_LC_RESYNC_OV, device, "Failed to response for request checksum resync data due send. err(%d)", err);
	return err;
}

int w_e_end_ov_req(struct bsr_work *w, int cancel)
{
	struct bsr_peer_request *peer_req = container_of(w, struct bsr_peer_request, w);
	struct bsr_peer_device *peer_device = peer_req->peer_device;
	int digest_size;
	void *digest;
	int err = 0;

	if (unlikely(cancel))
		goto out;

	digest_size = crypto_shash_digestsize(peer_device->connection->verify_tfm);
	/* FIXME if this allocation fails, online verify will not terminate! */
	digest = bsr_prepare_drequest_csum(peer_req, digest_size);
	if (!digest) {
		err = -ENOMEM;
		goto out;
	}

	if (!(peer_req->flags & EE_WAS_ERROR))
		bsr_csum_pages(peer_device->connection->verify_tfm, peer_req, digest);
	else
		memset(digest, 0, digest_size);

	/* Free peer_req and pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * bsr_alloc_pages due to pp_in_use > max_buffers. */
	bsr_free_peer_req(peer_req);
	peer_req = NULL;

	inc_rs_pending(peer_device);
	err = bsr_send_command(peer_device, P_OV_REPLY, DATA_STREAM);
	if (err)
		dec_rs_pending(peer_device);

out:
	if (peer_req)
		bsr_free_peer_req(peer_req);
	dec_unacked(peer_device);
	return err;
}

void bsr_ov_out_of_sync_found(struct bsr_peer_device *peer_device, sector_t sector, int size)
{
	if (peer_device->ov_last_oos_start + peer_device->ov_last_oos_size == sector) {
		peer_device->ov_last_oos_size += size>>9;
	} else {
		peer_device->ov_last_oos_start = sector;
		peer_device->ov_last_oos_size = size>>9;
	}
	bsr_set_out_of_sync(peer_device, sector, size);
}

void verify_progress(struct bsr_peer_device *peer_device,
        sector_t sector, int size, bool acked)
{
	bool stop_sector_reached =
		(peer_device->repl_state[NOW] == L_VERIFY_S) &&
		verify_can_do_stop_sector(peer_device) &&
		(sector + (size>>9)) >= peer_device->ov_stop_sector;
	
	// BSR-119 	
	// BSR-997 store ov_left as sectors
	//peer_device->ov_left -= (size >> BM_BLOCK_SHIFT);
	peer_device->ov_left_sectors -= (size >> 9);
	peer_device->ov_left = BM_SECT_TO_BIT(peer_device->ov_left_sectors);

	// BSR-835 set last acked sector
	if (acked)
		peer_device->ov_acked_sector = sector;

	/* let's advance progress step marks only for every other megabyte */
	if ((peer_device->ov_left & 0x1ff) == 0)
		bsr_advance_rs_marks(peer_device, peer_device->ov_left);
		
	// BSR-997 set RS_DONE if ov_left_sectors is 0 instead of ov_left
	if (peer_device->ov_left_sectors == 0 || stop_sector_reached) {
		bsr_peer_device_post_work(peer_device, RS_DONE);
	}
}

// BSR-997
static bool is_skipped_sectors(struct bsr_scope_sector *skipped, sector_t sst, sector_t est)
{
	if ((skipped->start >= sst && skipped->end <= est) ||
		(skipped->start <= est && skipped->end >= est) ||
		(skipped->start <= sst && skipped->end >= sst)) {
		return true;
	}

	return false;
}

// BSR-997
static int bsr_send_split_ov_request(struct bsr_peer_device *peer_device, sector_t sector, int size) 
{
	if (bsr_try_rs_begin_io(peer_device, sector, true)) {
		return -1;
	}

	inc_rs_pending(peer_device);
	if (bsr_send_ov_request(peer_device, sector, size)) {
		dec_rs_pending(peer_device);
		return -1;
	}

	return 0;
}

// BSR-997 resend ov request except for skipped sectors
static sector_t make_split_ov_request(struct bsr_peer_device *peer_device, 
	struct bsr_scope_sector *skipped, sector_t sst, sector_t est, bool done)
{
	sector_t skip_sst = 0, skip_est = 0;
	struct bsr_scope_sector *split_list;

	spin_lock_irq(&peer_device->ov_lock);
	if (skipped->start >= sst) {
		skip_sst = skipped->start > sst ? skipped->start : sst;
		skip_est = skipped->end < est ? skipped->end : est;

		if (skipped->end <= est) {
			list_del(&skipped->sector_list);
			kfree2(skipped);
		} else {
			// skipped->est > est
			skipped->start = est;
		}				
	} 
	else if (skipped->end <= est) {
		// skipped->sst < sst
		skip_sst = sst;
		skip_est = skipped->end < est ? skipped->end : est;
		skipped->end = sst;
	} 
	else {
		// skipped->est > est
		skip_sst = sst;
		skip_est = est;

#ifdef _WIN
		split_list = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct bsr_scope_sector), 'AASB');
#else // _LIN
		split_list = (struct bsr_scope_sector *)bsr_kmalloc(sizeof(struct bsr_scope_sector), GFP_ATOMIC|__GFP_NOWARN, '');
#endif
		if (!split_list) {
			bsr_err(97, BSR_LC_MEMORY, peer_device, "Failed to add ov skipped due to failure to allocate memory. sector(%llu ~ %llu)", 
				(unsigned long long)skip_sst, (unsigned long long)skip_est);
			spin_unlock_irq(&peer_device->ov_lock);
			goto skip_sector;
		}

		split_list->start = skip_est;
		split_list->end = skipped->end;
		skipped->end = skip_sst;
		list_add(&split_list->sector_list, &peer_device->ov_skip_sectors_list);
	}
	

	// send ov request sst ~ skip_sst
	if (sst < skip_sst) {
		atomic_set64(&peer_device->ov_split_req_sector, skip_sst - 1);
		if (atomic_read64(&peer_device->ov_split_reply_sector) == 0) {
			atomic_set64(&peer_device->ov_split_reply_sector, sst);
		}
		spin_unlock_irq(&peer_device->ov_lock);
		bsr_debug(225, BSR_LC_RESYNC_OV, peer_device, "make split ov request sector %llu size(%d)", sst, skip_sst - sst);
		if (bsr_send_split_ov_request(peer_device, sst, (int)((skip_sst - sst) << 9)))
			goto skip_sector;
	}
	else
		spin_unlock_irq(&peer_device->ov_lock);
	// check next skip list skip_est ~ est
	if (skip_est <= est)
		goto skip_sector;
	return sst;

skip_sector:
	bsr_debug(222, BSR_LC_RESYNC_OV, peer_device, "skipped sector %llu size(%d)", skip_sst, skip_est - skip_sst);
	verify_skipped_block(peer_device, skip_sst, (int)((skip_est - skip_sst) << 9), true);
	return skip_est;
}


// BSR-997 check sectors in ov_skip_sectors_list
static bool check_ov_skip_sectors(struct bsr_peer_device *peer_device, sector_t sst, sector_t est)
{
	struct bsr_scope_sector *skipped, *tmp;
	sector_t ret_sst = sst;	
	bool is_skipped = false;
	bool split_ov_done = false;

	spin_lock_irq(&peer_device->ov_lock);
	if (list_empty(&peer_device->ov_skip_sectors_list)) {
		spin_unlock_irq(&peer_device->ov_lock);
		return false;
	}

	list_for_each_entry_safe_ex(struct bsr_scope_sector, skipped, tmp, &peer_device->ov_skip_sectors_list, sector_list) 
	{
		if (is_skipped_sectors(skipped, sst, est)) {
			if (!is_skipped) {
				is_skipped = true;
				bsr_debug(226, BSR_LC_RESYNC_OV, peer_device, "ov reply sector %llu size(%d)", sst, est - sst);
			}
			spin_unlock_irq(&peer_device->ov_lock);
			ret_sst = make_split_ov_request(peer_device, skipped, sst, est, split_ov_done);
			spin_lock_irq(&peer_device->ov_lock);
			if ((ret_sst == sst) || (ret_sst == est)) {
				split_ov_done = true;
				break;
			}
			sst = ret_sst;

		}
	}
	
	if (is_skipped && !split_ov_done) {
		atomic_set64(&peer_device->ov_split_req_sector, est - 1);
		if (atomic_read64(&peer_device->ov_split_reply_sector) == 0) {
			atomic_set64(&peer_device->ov_split_reply_sector, sst);
		}

		spin_unlock_irq(&peer_device->ov_lock);
		bsr_debug(225, BSR_LC_RESYNC_OV, peer_device, "make split ov request sector %llu size(%d)", sst, est - sst);
		if (bsr_send_split_ov_request(peer_device, sst, (int)((est - sst) << 9))) {
			// send split failed
			verify_skipped_block(peer_device, sst, (int)((est - sst) << 9), true);
		}
	}
	else
		spin_unlock_irq(&peer_device->ov_lock);

	return is_skipped;
}

int w_e_end_ov_reply(struct bsr_work *w, int cancel)
{
	struct bsr_peer_request *peer_req = container_of(w, struct bsr_peer_request, w);
	struct bsr_peer_device *peer_device = peer_req->peer_device;
	struct bsr_device *device = peer_device->device;
	struct digest_info *di;
	void *digest;
	sector_t sector = peer_req->i.sector;
	unsigned int size = peer_req->i.size;
	int digest_size;
	int err = 0, eq = 0;
	bool is_skipped = false;

	if (unlikely(cancel)) {
		bsr_free_peer_req(peer_req);
		dec_unacked(peer_device);
		return 0;
	}

	/* after "cancel", because after bsr_disconnect/bsr_rs_cancel_all
	 * the resync lru has been cleaned up already */
	if (get_ldev(device)) {
		bsr_rs_complete_io(peer_device, peer_req->i.sector, __FUNCTION__);
		put_ldev(__FUNCTION__, device);
	}

	di = peer_req->digest;

	if (likely((peer_req->flags & EE_WAS_ERROR) == 0)) {
		digest_size = crypto_shash_digestsize(peer_device->connection->verify_tfm);
		digest = bsr_kmalloc(digest_size, GFP_NOIO, '33SB');
		if (digest) {
			bsr_csum_pages(peer_device->connection->verify_tfm, peer_req, digest);
			D_ASSERT(device, digest_size == di->digest_size);
			eq = !memcmp(digest, di->digest, digest_size);
			bsr_kfree(digest);
		}
	}


	// BSR-997 in case of inconsistent, check whether it is an ov skipped sector.
	if (!eq) {
		is_skipped = check_ov_skip_sectors(peer_device, sector, sector + (size >> 9));
	}

	/* Free peer_req and pages before send.
	 * In case we block on congestion, we could otherwise run into
	 * some distributed deadlock, if the other side blocks on
	 * congestion as well, because our receiver blocks in
	 * bsr_alloc_pages due to pp_in_use > max_buffers. */
	bsr_free_peer_req(peer_req);
	peer_req = NULL;

	// BSR-997
	if (!is_skipped) {
		if (!eq)
			bsr_ov_out_of_sync_found(peer_device, sector, size);
		else
			ov_out_of_sync_print(peer_device, false);

		verify_progress(peer_device, sector, size, true);
		err = bsr_send_ack_ex(peer_device, P_OV_RESULT, sector, size,
				eq ? ID_IN_SYNC : ID_OUT_OF_SYNC);
		
		
		if ((atomic_read64(&peer_device->ov_split_req_sector) != 0) &&
			(sector >= (sector_t)atomic_read64(&peer_device->ov_split_reply_sector)) &&
			(sector < (sector_t)atomic_read64(&peer_device->ov_split_req_sector))) {

			atomic_set64(&peer_device->ov_split_reply_sector, sector + (size >> 9) - 1);
			
		}
		else {
			atomic_set64(&peer_device->ov_reply_sector, sector + (size >> 9) - 1);
		}
	

	}
	else {
		// peer needs to receive ack to execute bsr_rs_complete_io()
		// send P_OV_RESULT for sector, set size to 0
		err = bsr_send_ack_ex(peer_device, P_OV_RESULT, sector, 0, ID_IN_SYNC);
	}

	dec_unacked(peer_device);

	return err;
}

/* FIXME
 * We need to track the number of pending barrier acks,
 * and to be able to wait for them.
 * See also comment in bsr_adm_attach before bsr_suspend_io.
 */
static int bsr_send_barrier(struct bsr_connection *connection)
{
	struct p_barrier *p;
	int err;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->barrier = connection->send.current_epoch_nr;
	p->pad = 0;
	connection->send.last_sent_epoch_nr = connection->send.current_epoch_nr;
	connection->send.current_epoch_writes = 0;
	connection->send.last_sent_barrier_jif = jiffies;

	set_bit(BARRIER_ACK_PENDING, &connection->flags);
	err = send_command(connection, -1, P_BARRIER, DATA_STREAM);
	if (err) {
		clear_bit(BARRIER_ACK_PENDING, &connection->flags);
		wake_up(&connection->resource->barrier_wait);
	}
	return err;
}

static bool need_unplug(struct bsr_connection *connection)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(connection);
	return FALSE;
#else // _LIN
	unsigned i = connection->todo.unplug_slot;
	return dagtag_newer_eq(connection->send.current_dagtag_sector,
			connection->todo.unplug_dagtag_sector[i]);
#endif
}

static void maybe_send_unplug_remote(struct bsr_connection *connection, bool send_anyways)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(connection);
	UNREFERENCED_PARAMETER(send_anyways);

#else // _LIN
	if (need_unplug(connection)) {
		/* Yes, this is non-atomic wrt. its use in bsr_unplug_fn.
		 * We save a spin_lock_irq, and worst case
		 * we occasionally miss an unplug event. */

		/* Paranoia: to avoid a continuous stream of unplug-hints,
		 * in case we never get any unplug events */
		connection->todo.unplug_dagtag_sector[connection->todo.unplug_slot] =
			connection->send.current_dagtag_sector + (1ULL << 63);
		/* advance the current unplug slot */
		connection->todo.unplug_slot ^= 1;
	} else if (!send_anyways)
		return;
 
	if (connection->cstate[NOW] < C_CONNECTED)
		return;

	if (!conn_prepare_command(connection, 0, DATA_STREAM))
		return;

	send_command(connection, -1, P_UNPLUG_REMOTE, DATA_STREAM);
#endif
}
 
static bool __bsr_may_sync_now(struct bsr_peer_device *peer_device)
{
	struct bsr_device *other_device = peer_device->device;
	int ret = true;
#ifdef _LIN // DW-900 to avoid the recursive lock
	rcu_read_lock();
#endif
	while (1) {
		struct bsr_peer_device *other_peer_device;
		int resync_after;

		if (!other_device->ldev || other_device->disk_state[NOW] == D_DISKLESS)
			break;
		resync_after = rcu_dereference(other_device->ldev->disk_conf)->resync_after;
		if (resync_after == -1)
			break;
		other_device = minor_to_device(resync_after);
		if (!other_device)
			break;
		other_peer_device = conn_peer_device(peer_device->connection, other_device->vnr);
		if ((other_peer_device->repl_state[NOW] >= L_SYNC_SOURCE &&
		     other_peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T) ||
		    other_peer_device->resync_susp_dependency[NOW] ||
		    other_peer_device->resync_susp_peer[NOW] ||
		    other_peer_device->resync_susp_user[NOW]) {
			bsr_info(129, BSR_LC_RESYNC_OV, peer_device, "Another(node_id:%d) peer device is in progress for resync", other_peer_device->node_id);
			ret = false;
			break;
		}
	}
#ifdef _LIN // DW-900 to avoid the recursive lock
	rcu_read_unlock();
#endif

	return ret;
}

/**
 * bsr_pause_after() - Pause resync on all devices that may not resync now
 * @device:	BSR device.
 *
 * Called from process context only (admin command and after_state_ch).
 */

static bool bsr_pause_after(struct bsr_device *device)
{
	struct bsr_device *other_device;
	bool changed = false;
	int vnr;

	UNREFERENCED_PARAMETER(device);

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &bsr_devices, other_device, vnr) {
		struct bsr_peer_device *other_peer_device;

		begin_state_change_locked(other_device->resource, CS_HARD);
		if (other_device->disk_state[NOW] == D_DISKLESS) {
			abort_state_change_locked(other_device->resource, true, __FUNCTION__);
			continue;
		}
		for_each_peer_device(other_peer_device, other_device) {
			if (other_peer_device->repl_state[NOW] == L_OFF)
				continue;
			if (!__bsr_may_sync_now(other_peer_device))
				__change_resync_susp_dependency(other_peer_device, true, __FUNCTION__);
		}
		if (end_state_change_locked(other_device->resource, true, __FUNCTION__) != SS_NOTHING_TO_DO)
			changed = true;
	}
	rcu_read_unlock();
	return changed;
}

/**
 * bsr_resume_next() - Resume resync on all devices that may resync now
 * @device:	BSR device.
 *
 * Called from process context only (admin command and sender).
 */
static bool bsr_resume_next(struct bsr_device *device)
{
	struct bsr_device *other_device;
	bool changed = false;
	int vnr;

	UNREFERENCED_PARAMETER(device);

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &bsr_devices, other_device, vnr) {
		struct bsr_peer_device *other_peer_device;

		begin_state_change_locked(other_device->resource, CS_HARD);
		if (other_device->disk_state[NOW] == D_DISKLESS) {
			abort_state_change_locked(other_device->resource, true, __FUNCTION__);
			continue;
		}
		for_each_peer_device(other_peer_device, other_device) {
			if (other_peer_device->repl_state[NOW] == L_OFF)
				continue;
			if (other_peer_device->resync_susp_dependency[NOW] &&
			    __bsr_may_sync_now(other_peer_device))
				__change_resync_susp_dependency(other_peer_device, false, __FUNCTION__);
		}
		if (end_state_change_locked(other_device->resource, true, __FUNCTION__) != SS_NOTHING_TO_DO)
			changed = true;
	}
	rcu_read_unlock();
	return changed;
}

void resume_next_sg(struct bsr_device *device)
{
	lock_all_resources();
	bsr_resume_next(device);
	unlock_all_resources();
}

void suspend_other_sg(struct bsr_device *device)
{
	lock_all_resources();
	bsr_pause_after(device);
	unlock_all_resources();
}

/* caller must hold resources_mutex */
enum bsr_ret_code bsr_resync_after_valid(struct bsr_device *device, int resync_after)
{
	struct bsr_device *other_device;
	int rv = ERR_NO;

	if (resync_after == -1)
		return ERR_NO;
	if (resync_after < -1)
		return ERR_RESYNC_AFTER;
	other_device = minor_to_device(resync_after);
	if (!other_device)
		return ERR_RESYNC_AFTER;

	/* check for loops */
	rcu_read_lock();
	while (1) {
		if (other_device == device) {
			rv = ERR_RESYNC_AFTER_CYCLE;
			break;
		}

		/* You are free to depend on diskless, non-existing,
		 * or not yet/no longer existing minors.
		 * We only reject dependency loops.
		 * We cannot follow the dependency chain beyond a detached or
		 * missing minor.
		 */
		if (!other_device)
			break;

		if (!get_ldev_if_state(other_device, D_NEGOTIATING))
			break;
		resync_after = rcu_dereference(other_device->ldev->disk_conf)->resync_after;
		put_ldev(__FUNCTION__, other_device);

		/* dependency chain ends here, no cycles. */
		if (resync_after == -1)
			break;

		/* follow the dependency chain */
		other_device = minor_to_device(resync_after);
	}
	rcu_read_unlock();

	return rv;
}

/* caller must hold resources_mutex */
void bsr_resync_after_changed(struct bsr_device *device)
{
	while (bsr_pause_after(device) || bsr_resume_next(device))
		/* do nothing */ ;
}

void bsr_rs_controller_reset(struct bsr_peer_device *peer_device)
{
	struct fifo_buffer *plan;

	atomic_set(&peer_device->rs_sect_in, 0);
	atomic_set(&peer_device->device->rs_sect_ev, 0);  /* FIXME: ??? */
	peer_device->rs_in_flight = 0;
#ifdef _WIN	
	peer_device->rs_last_events =
		bsr_backing_bdev_events(peer_device->device);
#else // _LIN
	peer_device->rs_last_events =
		bsr_backing_bdev_events(peer_device->device->ldev->backing_bdev->bd_disk);
#endif

	/* Updating the RCU protected object in place is necessary since
	   this function gets called from atomic context.
	   It is valid since all other updates also lead to an completely
	   empty fifo */
	rcu_read_lock();
	plan = rcu_dereference(peer_device->rs_plan_s);
	plan->total = 0;
	fifo_set(plan, 0);
	rcu_read_unlock();
}

#ifdef _WIN
void start_resync_timer_fn(PKDPC Dpc, PVOID data, PVOID SystemArgument1, PVOID SystemArgument2)
#else // _LIN
void start_resync_timer_fn(BSR_TIMER_FN_ARG)
#endif
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Dpc);
	struct bsr_peer_device *peer_device = (struct bsr_peer_device *) data;
#else
	struct bsr_peer_device *peer_device = BSR_TIMER_ARG2OBJ(peer_device, start_resync_timer);
#endif

	if (peer_device == NULL)
		return;

	bsr_info(130, BSR_LC_RESYNC_OV, peer_device, "post RS_START to the peer_device work"); // DW-1518
	bsr_peer_device_post_work(peer_device, RS_START);
}

bool bsr_stable_sync_source_present(struct bsr_peer_device *except_peer_device, enum which_state which)
{
	u64 authoritative_nodes = except_peer_device->uuid_authoritative_nodes;
	struct bsr_device *device = except_peer_device->device;
	struct bsr_peer_device *peer_device;
	bool rv = false;

	/* If a peer considers himself as unstable and sees me as an authoritative
	   node, then we have a stable resync source! */
	if (authoritative_nodes & NODE_MASK(device->resource->res_opts.node_id))
		return true;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum bsr_repl_state repl_state;
		struct net_conf *nc;

		if (peer_device == except_peer_device)
			continue;

		repl_state = peer_device->repl_state[which];

		if (repl_state >= L_ESTABLISHED && repl_state < L_AHEAD) {
			if (authoritative_nodes & NODE_MASK(peer_device->node_id)) {
				rv = true;
				break;
			}

			nc = rcu_dereference(peer_device->connection->transport.net_conf);
			/* Restricting the clause the two_primaries not allowed, otherwise
			   we need to ensure here that we are neighbor of all primaries,
			   and that is a lot more challenging. */

			if ((!nc->two_primaries &&
			     peer_device->connection->peer_role[which] == R_PRIMARY) ||
			    ((repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
			     peer_device->uuid_flags & UUID_FLAG_STABLE)) {
				rv = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	return rv;
}

static void do_start_resync(struct bsr_peer_device *peer_device)
{
	bool retry_resync = false;

	// BSR-853 fix stuck in SyncSource/Established state
	if (peer_device->repl_state[NOW] == L_SYNC_SOURCE) {
		bsr_info(214, BSR_LC_RESYNC_OV, peer_device, "resync is already running. stop the resync timer.");
		if (test_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags))
			clear_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags);
		return;
	}

	if (atomic_read(&peer_device->unacked_cnt) || 
		atomic_read(&peer_device->rs_pending_cnt) ||
		// DW-1979
		atomic_read(&peer_device->wait_for_recv_bitmap)) {
		bsr_warn(171, BSR_LC_RESYNC_OV, peer_device, "postponing start_resync ... unacked : %d, pending : %d, bitmap : %d", atomic_read(&peer_device->unacked_cnt), atomic_read(&peer_device->rs_pending_cnt),
			atomic_read(&peer_device->wait_for_recv_bitmap));
		retry_resync = true;
	}

#ifdef SPLIT_REQUEST_RESYNC
	// BSR-842
	if (peer_device && peer_device->connection->agreed_pro_version < 115) {
		// DW-2076
		if (test_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags) && atomic_read(&peer_device->rq_pending_oos_cnt)) {
			bsr_debug(187, BSR_LC_RESYNC_OV, peer_device, "postponing start_resync ... pending oos : %d", atomic_read(&peer_device->rq_pending_oos_cnt));
			retry_resync = true;
		}
	}
#endif

	if (retry_resync) {
		// BSR-634 changed to mod_timer() due to potential kernel panic caused by duplicate calls to add_timer().
		mod_timer(&peer_device->start_resync_timer, jiffies + HZ / 10);
		return;
	}


	bsr_info(131, BSR_LC_RESYNC_OV, peer_device, "Starting resync."); // DW-1518
	bsr_start_resync(peer_device, peer_device->start_resync_side);
}

static bool use_checksum_based_resync(struct bsr_connection *connection, struct bsr_device *device)
{
	bool csums_after_crash_only;
	rcu_read_lock();
	csums_after_crash_only = rcu_dereference(connection->transport.net_conf)->csums_after_crash_only;
	rcu_read_unlock();
	return connection->agreed_pro_version >= 89 &&		/* supported? */
		connection->csums_tfm &&			/* configured? */
		(csums_after_crash_only == false		/* use for each resync? */
		 || test_bit(CRASHED_PRIMARY, &device->flags));	/* or only after Primary crash? */
}

/**	DW-1314
* bsr_inspect_resync_side() - Check stability if resync can be started.
* rule for resync - Sync source must be stable and authoritative of sync target if sync target is unstable.
* DW-1315 need to also inspect if I will be able to be resync side. (state[NEW])
*/
bool bsr_inspect_resync_side(struct bsr_peer_device *peer_device, enum bsr_repl_state replState, enum which_state which, bool locked)
{
	struct bsr_device *device = peer_device->device;
	enum bsr_repl_state side = 0;
	u64 authoritative = 0;

	// no start resync if I haven't received uuid from peer.	
	if (!peer_device->uuids_received) {
		bsr_info(132, BSR_LC_RESYNC_OV, peer_device, "Not yet received UUID from peer and cannot be %s", bsr_repl_str(replState));
		return false;
	}

	switch (replState) {
		case L_STARTING_SYNC_T:
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			side = L_SYNC_TARGET;
			break;
		case L_STARTING_SYNC_S:
		case L_WF_BITMAP_S:
		case L_SYNC_SOURCE:
		case L_PAUSED_SYNC_S:
			side = L_SYNC_SOURCE;
			break;
		case L_VERIFY_S:    // need to deal with verification state.
			side = L_VERIFY_S;
			break;
		case L_VERIFY_T:
			side = L_VERIFY_T;
			break;
		default:
			bsr_info(133, BSR_LC_RESYNC_OV, peer_device, "Unexpected replication state (%s)", bsr_repl_str(replState));
			return false;
	}
	
	if (side == L_SYNC_TARGET || side == L_VERIFY_T) {
		if (!(peer_device->uuid_flags & UUID_FLAG_STABLE)) {
			bsr_info(134, BSR_LC_RESYNC_OV, peer_device, "SyncSource is unstable, can not be %s, uuid_flags(%llx), authoritative(%llx)",
				bsr_repl_str(replState), peer_device->uuid_flags, peer_device->uuid_authoritative_nodes);
			return false;
		}

		if (!bsr_device_stable_ex(device, &authoritative, which, locked) &&
			!(NODE_MASK(peer_device->node_id) & authoritative)) {
			bsr_info(135, BSR_LC_RESYNC_OV, peer_device, "Unstable and SyncSource is not an authorized node, can not be %s, authoritative(%llx)",
				bsr_repl_str(replState), authoritative);
			return false;
		}
	}
	else if (side == L_SYNC_SOURCE || side == L_VERIFY_S) {
		if (!bsr_device_stable_ex(device, &authoritative, which, locked)) {
			bsr_info(136, BSR_LC_RESYNC_OV, peer_device, "Local is an unstable node, can not be %s, authoritative(%llx)", bsr_repl_str(replState), authoritative);
			return false;
		}

		if (!(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
			!(NODE_MASK(device->resource->res_opts.node_id) & peer_device->uuid_authoritative_nodes)) {
			bsr_info(137, BSR_LC_RESYNC_OV, peer_device, "SyncTarget is unstable and not authorized node, can not be %s, uuid_flags(%llx), authoritative(%llx)",
				bsr_repl_str(replState), peer_device->uuid_flags, peer_device->uuid_authoritative_nodes);
			return false;			
		}
	}

	return true;
}

/**
 * bsr_start_resync() - Start the resync process
 * @side:	Either L_SYNC_SOURCE or L_SYNC_TARGET
 *
 * This function might bring you directly into one of the
 * C_PAUSED_SYNC_* states.
 */
void bsr_start_resync(struct bsr_peer_device *peer_device, enum bsr_repl_state side)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_connection *connection = peer_device->connection;
	enum bsr_disk_state finished_resync_pdsk = D_UNKNOWN;
	enum bsr_repl_state repl_state;
	int r;
	ULONG_PTR last_reconnect_jif = 0;

	spin_lock_irq(&device->resource->req_lock);
	repl_state = peer_device->repl_state[NOW];
	spin_unlock_irq(&device->resource->req_lock);
	if (repl_state < L_ESTABLISHED) {
		/* Connection closed meanwhile. */
		bsr_err(138, BSR_LC_RESYNC_OV, peer_device, "Failed to start resync due to not connected"); // DW-1518
		goto clear_flag;
	}
	if (repl_state >= L_SYNC_SOURCE && repl_state < L_AHEAD) {
		bsr_err(139, BSR_LC_RESYNC_OV, peer_device, "Failed to start resync due to resync already running!");
		goto clear_flag;
	}

	// BSR-842
#ifdef SPLIT_REQUEST_RESYNC
	if (peer_device && peer_device->connection->agreed_pro_version >= 115) {
		if (side == L_SYNC_TARGET && atomic_read(&peer_device->wait_for_out_of_sync)) {
			bsr_info(215, BSR_LC_RESYNC_OV, peer_device, "resync will not start because out of sync has not been received completely");
			goto clear_flag;
		}
	}
#endif

	// DW-955 clear resync aborted flag when just starting resync.
	clear_bit(RESYNC_ABORTED, &peer_device->flags);

	// BSR-1015
	last_reconnect_jif = connection->last_reconnect_jif;

	if (!test_bit(B_RS_H_DONE, &peer_device->flags)) {
		if (side == L_SYNC_TARGET) {
			/* Since application IO was locked out during L_WF_BITMAP_T and
			   L_WF_SYNC_UUID we are still unmodified. Before going to L_SYNC_TARGET
			   we check that we might make the data inconsistent. */
			r = bsr_khelper(device, connection, "before-resync-target");

			// DW-798, BSR-399
#ifdef _WIN
			r = r & 0xff;
#else // _LIN
			r = (r >> 8) & 0xff;
#endif
			if (r > 0) {
				bsr_info(140, BSR_LC_RESYNC_OV, device, "before-resync-target handler returned %d, "
					 "dropping connection.", r);
				change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
				goto clear_flag;
			}
		} else /* L_SYNC_SOURCE */ {
			r = bsr_khelper(device, connection, "before-resync-source");
			// DW-798, BSR-25
#ifdef _WIN
			r = r & 0xff;
#else // _LIN
			r = (r >> 8) & 0xff;
#endif
			if (r > 0) {
				if (r == 3) {
					bsr_info(141, BSR_LC_RESYNC_OV, device, "before-resync-source handler returned %d, "
						 "ignoring. Old userland tools?", r);
				} else {
					bsr_info(142, BSR_LC_RESYNC_OV, device, "before-resync-source handler returned %d, "
						 "dropping connection.", r);
					change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
					goto clear_flag;
				}
			}
		}
	}

	// BSR-969
	if (down_trylock(&device->resource->state_sem)) {
		mutex_lock(&peer_device->device->bm_resync_and_resync_timer_fo_mutex);
		/* Retry later and let the worker make progress in the
		 * meantime; two-phase commits depend on that.  */
		bsr_info(143, BSR_LC_RESYNC_OV, peer_device, "The resync will resume later because another task is running."); // DW-1518
		// BSR-969 sets the resync timer only in the connected state.
		if (connection->cstate[NOW] == C_CONNECTED) {
			set_bit(B_RS_H_DONE, &peer_device->flags);
			peer_device->start_resync_side = side;
			// BSR-634 changed to mod_timer() due to potential kernel panic caused by duplicate calls to add_timer().
			mod_timer(&peer_device->start_resync_timer, jiffies + HZ / 5);
		}
		mutex_unlock(&peer_device->device->bm_resync_and_resync_timer_fo_mutex);
		goto clear_flag;
	}

	// BSR-1015 to stop bsr_start_resync() when reconnection occurs during handler operation
	if (!connection->last_reconnect_jif ||
		(connection->last_reconnect_jif != last_reconnect_jif)) {
			bsr_info(227, BSR_LC_RESYNC_OV, connection, "The resync will resume later because reconnected");
			up(&device->resource->state_sem);
			goto clear_flag;
	}

	// DW-2058
#ifdef SPLIT_REQUEST_RESYNC
	//DW-2042
	if (peer_device->connection->agreed_pro_version >= 113) {
		//DW-1911
		struct bsr_marked_replicate *marked_rl, *mrt;
		struct bsr_scope_sector *pending_st, *rpt;
		ULONG_PTR offset = 0;

		mutex_lock(&device->resync_pending_fo_mutex);
		list_for_each_entry_safe_ex(struct bsr_scope_sector, pending_st, rpt, &(device->resync_pending_sectors), sector_list) {
			list_del(&pending_st->sector_list);
			kfree2(pending_st);
		}
		mutex_unlock(&device->resync_pending_fo_mutex);

		//DW-1908
		device->h_marked_bb = 0;
		device->h_insync_bb = 0;
		
		list_for_each_entry_safe_ex(struct bsr_marked_replicate, marked_rl, mrt, &(device->marked_rl_list), marked_rl_list) {
			list_del(&marked_rl->marked_rl_list);
			kfree2(marked_rl);
		}

#ifdef _WIN
		device->s_rl_bb = UINT64_MAX;
#else	// _LIN
		device->s_rl_bb = -1;
#endif
		device->e_rl_bb = 0;

		// DW-2065
		atomic_set64(&peer_device->s_resync_bb, 0);
		atomic_set64(&peer_device->e_resync_bb, 0);

		// DW-2050
		if (side == L_SYNC_TARGET) {
			// DW-1908 set start out of sync bit
			// DW-2050 fix temporary hang caused by req_lock and bm_lock
			for (;;) {
				ULONG_PTR tmp = bsr_bm_range_find_next(peer_device, offset, offset + RANGE_FIND_NEXT_BIT);

				if (tmp < (offset + RANGE_FIND_NEXT_BIT + 1)) {
					atomic_set64(&peer_device->s_resync_bb, tmp);
					break;
				}

				if (tmp >= bsr_bm_bits(device)) {
					atomic_set64(&peer_device->s_resync_bb, BSR_END_OF_BITMAP);
					break;
				}

				offset = tmp;
				// BSR-1083
				cond_resched();
			}

			// DW-2065
			atomic_set64(&peer_device->e_resync_bb, atomic_read64(&peer_device->s_resync_bb));
		}
	}
#endif

	lock_all_resources();
	clear_bit(B_RS_H_DONE, &peer_device->flags);
	if (connection->cstate[NOW] < C_CONNECTED ||
	    !get_ldev_if_state(device, D_NEGOTIATING)) {
		unlock_all_resources();
		goto out;
	}

	// DW-1314 check stable sync source rules.
	if (!bsr_inspect_resync_side(peer_device, side, NOW, false)) {
		bsr_warn(172, BSR_LC_RESYNC_OV, peer_device, "could not start resync.");

		// turn back the replication state to L_ESTABLISHED
		if (peer_device->repl_state[NOW] > L_ESTABLISHED) {
			begin_state_change_locked(device->resource, CS_VERBOSE);
			__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED, __FUNCTION__);
			end_state_change_locked(device->resource, false, __FUNCTION__);
		}
		unlock_all_resources();
		// DW-2031 add put_ldev() due to ldev leak occurrence
		put_ldev(__FUNCTION__, device);
		goto out;
	}

	begin_state_change_locked(device->resource, CS_VERBOSE);
#ifdef _WIN // DW-900 to avoid the recursive lock
	rcu_read_lock();
#endif
	__change_resync_susp_dependency(peer_device, !__bsr_may_sync_now(peer_device), __FUNCTION__);
#ifdef _WIN // DW-900 to avoid the recursive lock
	rcu_read_unlock();
#endif
	__change_repl_state_and_auto_cstate(peer_device, side, __FUNCTION__);
	if (side == L_SYNC_TARGET) {
		__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
		init_resync_stable_bits(peer_device);
	} else /* side == L_SYNC_SOURCE */ {
		__change_peer_disk_state(peer_device, D_INCONSISTENT, __FUNCTION__);
		// BSR-838
		if (peer_device->connection->agreed_pro_version >= 115) {
			mod_timer(&peer_device->sended_timer, jiffies);
		}
	}
	finished_resync_pdsk = peer_device->resync_finished_pdsk;
	peer_device->resync_finished_pdsk = D_UNKNOWN;
	r = end_state_change_locked(device->resource, false, __FUNCTION__);
	repl_state = peer_device->repl_state[NOW];

	if (repl_state < L_ESTABLISHED)
		r = SS_UNKNOWN_ERROR;

	if (r == SS_SUCCESS) {
		bsr_pause_after(device);
		/* Forget potentially stale cached per resync extent bit-counts.
		 * Open coded bsr_rs_cancel_all(device), we already have IRQs
		 * disabled, and know the disk state is ok. */
		spin_lock(&device->al_lock);
		lc_reset(peer_device->resync_lru);
		peer_device->resync_locked = 0;
		peer_device->resync_wenr = LC_FREE;
		spin_unlock(&device->al_lock);
	}

	unlock_all_resources();


	if (r == SS_SUCCESS) {
		// DW-1285 set MDF_PEER_INIT_SYNCT_BEGIN 
		// BSR-1213 set even when start_init_sync is 1
		if( (side == L_SYNC_TARGET) 
			&& ((peer_device->device->ldev->md.current_uuid == UUID_JUST_CREATED) 
			|| atomic_read(&peer_device->start_init_sync))) { 
			bsr_md_set_peer_flag (peer_device, MDF_PEER_INIT_SYNCT_BEGIN);
			atomic_set(&peer_device->start_init_sync, 0);
		}
		
		// BSR-842
#ifdef SPLIT_REQUEST_RESYNC
		if (peer_device && peer_device->connection->agreed_pro_version >= 115) {
			if (repl_state == L_SYNC_SOURCE && atomic_read(&peer_device->rq_pending_oos_cnt) == 0) {
				struct bsr_oos_no_req* send_oos = bsr_kmalloc(sizeof(struct bsr_oos_no_req), 0, 'OSSB');
				unsigned long flags;

				if (send_oos) {
					INIT_LIST_HEAD(&send_oos->oos_list_head);
					send_oos->sector = ID_OUT_OF_SYNC_FINISHED;
					// BSR-1162 ID_OUT_OF_SYNC_FINISHED size set to 0
					send_oos->size = 0;
					spin_lock_irqsave(&peer_device->send_oos_lock, flags);
					list_add_tail(&send_oos->oos_list_head, &peer_device->send_oos_list);
					spin_unlock_irqrestore(&peer_device->send_oos_lock, flags);
					queue_work(peer_device->connection->ack_sender, &peer_device->send_oos_work);
				}
				else {
					bsr_err(95, BSR_LC_MEMORY, peer_device, "Failed to send out of sync due to failure to allocate memory so dropping connection.");
					change_cstate_ex(peer_device->connection, C_DISCONNECTING, CS_HARD);
				}
			}
		}
#endif

		bsr_info(144, BSR_LC_RESYNC_OV, peer_device, "Began resync as %s (will sync %llu KB [%llu bits set]).",
		     bsr_repl_str(repl_state),
		     (unsigned long long) peer_device->rs_total << (BM_BLOCK_SHIFT-10),
		     (unsigned long long) peer_device->rs_total);
		if (side == L_SYNC_TARGET) {
			// DW-1846 bm_resync_fo must be locked and set.
			mutex_lock(&device->bm_resync_and_resync_timer_fo_mutex);
			device->bm_resync_fo = 0;
			mutex_unlock(&device->bm_resync_and_resync_timer_fo_mutex);
			peer_device->use_csums = use_checksum_based_resync(connection, device);

			// BSR-838
			peer_device->rs_in_flight_mark_time = jiffies;
		} else {
			peer_device->use_csums = false;
			// DW-1874
			bsr_md_set_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC);
		}

		if ((side == L_SYNC_TARGET || side == L_PAUSED_SYNC_T) &&
		    !(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
		    !bsr_stable_sync_source_present(peer_device, NOW))
			set_bit(UNSTABLE_RESYNC, &peer_device->flags);

		/* Since protocol 96, we must serialize bsr_gen_and_send_sync_uuid
		 * with w_send_oos, or the sync target will get confused as to
		 * how much bits to resync.  We cannot do that always, because for an
		 * empty resync and protocol < 95, we need to do it here, as we call
		 * bsr_resync_finished from here in that case.
		 * We bsr_gen_and_send_sync_uuid here for protocol < 96,
		 * and from after_state_ch otherwise. */
		if (side == L_SYNC_SOURCE && connection->agreed_pro_version < 96)
			bsr_gen_and_send_sync_uuid(peer_device);

		if (connection->agreed_pro_version < 95 && peer_device->rs_total == 0) {
			/* This still has a race (about when exactly the peers
			 * detect connection loss) that can lead to a full sync
			 * on next handshake. In 8.3.9 we fixed this with explicit
			 * resync-finished notifications, but the fix
			 * introduces a protocol change.  Sleeping for some
			 * time longer than the ping interval + timeout on the
			 * SyncSource, to give the SyncTarget the chance to
			 * detect connection loss, then waiting for a ping
			 * response (implicit in bsr_resync_finished) reduces
			 * the race considerably, but does not solve it. */
			if (side == L_SYNC_SOURCE) {
				struct net_conf *nc;
				int timeo;

				rcu_read_lock();
				nc = rcu_dereference(connection->transport.net_conf);
				timeo = nc->ping_int * HZ + nc->ping_timeo * HZ / 9;
				rcu_read_unlock();
				schedule_timeout_interruptible(timeo);
			}
			bsr_resync_finished(__FUNCTION__, peer_device, D_MASK);
		}

		/* ns.conn may already be != peer_device->repl_state[NOW],
		 * we may have been paused in between, or become paused until
		 * the timer triggers.
		 * No matter, that is handled in resync_timer_fn() */
		if (repl_state == L_SYNC_TARGET)
			mod_timer(&peer_device->resync_timer, jiffies);

		bsr_md_sync_if_dirty(device);
	}
	else {
		bsr_err(145, BSR_LC_RESYNC_OV, peer_device, "Failed to start resync due to error. %s (err = %d)", bsr_repl_str(repl_state), r); // DW-1518
	}

	put_ldev(__FUNCTION__, device);
out:
	up(&device->resource->state_sem);
	if (finished_resync_pdsk != D_UNKNOWN)
		bsr_resync_finished(__FUNCTION__, peer_device, finished_resync_pdsk);

clear_flag:
	// DW-1619 clear AHEAD_TO_SYNC_SOURCE bit when start resync.
	// BSR-998 fix stuck in SyncSource/Established state
	// clear AHEAD_TO_SYNC_SOURCE bit after state change
	clear_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags);

}

static void update_on_disk_bitmap(struct bsr_peer_device *peer_device, bool resync_done)
{
	struct bsr_device *device = peer_device->device;
	peer_device->rs_last_writeout = jiffies;

	if (!get_ldev(device))
		return;

	bsr_bm_write_lazy(device, 0);

	if (resync_done) {
		if (is_verify_state(peer_device, NOW)) {
			ov_out_of_sync_print(peer_device, true);
			ov_skipped_print(peer_device, true);
		} else 
			resync_done = is_sync_state(peer_device, NOW);
	}
	if (resync_done)
		bsr_resync_finished(__FUNCTION__, peer_device, D_MASK);

	/* update timestamp, in case it took a while to write out stuff */
	peer_device->rs_last_writeout = jiffies;
	put_ldev(__FUNCTION__, device);
}

static void bsr_ldev_destroy(struct bsr_device *device)
{
    struct bsr_peer_device *peer_device;

    rcu_read_lock();
    for_each_peer_device_rcu(peer_device, device) {
            lc_destroy(peer_device->resync_lru);
            peer_device->resync_lru = NULL;
	}
    rcu_read_unlock();

    lc_destroy(device->act_log);
    device->act_log = NULL;
	__acquire(local);
	bsr_backing_dev_free(device, device->ldev);
	device->ldev = NULL;
	__release(local);

        clear_bit(GOING_DISKLESS, &device->flags);
	wake_up(&device->misc_wait);
}

static void go_diskless(struct bsr_device *device)
{
	D_ASSERT(device, device->disk_state[NOW] == D_FAILED ||
			 device->disk_state[NOW] == D_DETACHING);
	/* we cannot assert local_cnt == 0 here, as get_ldev_if_state will
	 * inc/dec it frequently. Once we are D_DISKLESS, no one will touch
	 * the protected members anymore, though, so once put_ldev reaches zero
	 * again, it will be safe to free them. */

	/* Try to write changed bitmap pages, read errors may have just
	 * set some bits outside the area covered by the activity log.
	 *
	 * If we have an IO error during the bitmap writeout,
	 * we will want a full sync next time, just in case.
	 * (Do we want a specific meta data flag for this?)
	 *
	 * If that does not make it to stable storage either,
	 * we cannot do anything about that anymore.
	 *
	 * We still need to check if both bitmap and ldev are present, we may
	 * end up here after a failed attach, before ldev was even assigned.
	 */
	if (device->bitmap && device->ldev) {
		if (bsr_bitmap_io_from_worker(device, bsr_bm_write,
					       "detach",
					       BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,
					       NULL)) {
			if (test_bit(CRASHED_PRIMARY, &device->flags)) {
				struct bsr_peer_device *peer_device;

				rcu_read_lock();
				for_each_peer_device_rcu(peer_device, device)
					bsr_md_set_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
				rcu_read_unlock();
				bsr_md_sync_if_dirty(device);
			}
		}
	}

	change_disk_state(device, D_DISKLESS, CS_HARD, NULL);
}

static int do_md_sync(struct bsr_device *device)
{
	bsr_warn(39, BSR_LC_STATE, device, "metadata sync timer expired! Worker calls bsr_md_sync().");
#ifdef BSR_DEBUG_MD_SYNC
	bsr_warn(43, BSR_LC_STATE, device, "last md_mark_dirty: %s:%u",
		device->last_md_mark_dirty.func, device->last_md_mark_dirty.line);
#endif
	bsr_md_sync(device);
	return 0;
}

#ifdef _WIN
void repost_up_to_date_fn(PKDPC Dpc, PVOID data, PVOID arg1, PVOID arg2)
#else // _LIN
void repost_up_to_date_fn(BSR_TIMER_FN_ARG)
#endif 
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(arg1);
	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(Dpc);
	struct bsr_resource *resource = (struct bsr_resource *) data;
#else // _LIN
	struct bsr_resource *resource = BSR_TIMER_ARG2OBJ(resource, repost_up_to_date_timer);
#endif
	bsr_post_work(resource, TRY_BECOME_UP_TO_DATE);
}

static int try_become_up_to_date(struct bsr_resource *resource)
{
	enum bsr_state_rv rv;

	/* Doing a two_phase_commit from worker context is only possible
	 * if twopc_work is not queued. Let it get executed first.
	 *
	 * Avoid deadlock on state_sem, in case someone holds it while
	 * waiting for the completion of some after-state-change work.
	 */

	if (list_empty(&resource->twopc_work.list)) {
		if (down_trylock(&resource->state_sem))
			goto repost;
		rv = change_from_consistent(resource, CS_ALREADY_SERIALIZED |
			CS_VERBOSE | CS_SERIALIZE | CS_DONT_RETRY);
		up(&resource->state_sem);
		if (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG)
			goto repost;
	} else {
	repost:
		mod_timer(&resource->repost_up_to_date_timer, jiffies + HZ / 10);
	}

	return 0;
}

/* only called from bsr_worker thread, no locking */
void __update_timing_details(
		struct bsr_thread_timing_details *tdp,
		unsigned int *cb_nr,
		void *cb,
		const char *fn, const unsigned int line)
{
	unsigned int i = *cb_nr % BSR_THREAD_DETAILS_HIST;
	struct bsr_thread_timing_details *td = tdp + i;

	td->start_jif = jiffies;
	td->cb_addr = cb;
	td->caller_fn = fn;
	td->line = line;
	td->cb_nr = *cb_nr;

	i = (i+1) % BSR_THREAD_DETAILS_HIST;
	td = tdp + i;
	memset(td, 0, sizeof(*td));

	++(*cb_nr);
}

static void do_device_work(struct bsr_device *device, const ULONG_PTR todo)
{
	if (test_bit(MD_SYNC, &todo))
		do_md_sync(device);
	if (test_bit(GO_DISKLESS, &todo))
		go_diskless(device);
	if (test_bit(DESTROY_DISK, &todo))
		bsr_ldev_destroy(device);
}

static void do_peer_device_work(struct bsr_peer_device *peer_device, const ULONG_PTR todo, bool connected)
{
	// BSR-1125
	if (test_bit(RS_PROGRESS_NOTIFY, &todo))
		bsr_broadcast_peer_device_state(peer_device);

	if (test_bit(RS_DONE, &todo) ||
	    test_bit(RS_PROGRESS, &todo))
		update_on_disk_bitmap(peer_device, test_bit(RS_DONE, &todo));		
	// BSR-926 callback for resync is invoked, so it is not called if it is not connected.
	if (test_bit(RS_START, &todo) && connected)
		do_start_resync(peer_device);
}

#define BSR_RESOURCE_WORK_MASK	\
	(1UL << TRY_BECOME_UP_TO_DATE)

#define BSR_DEVICE_WORK_MASK	\
	((1UL << GO_DISKLESS)	\
	|(1UL << DESTROY_DISK)	\
	|(1UL << MD_SYNC)	\
	)

#define BSR_PEER_DEVICE_WORK_MASK	\
	((1UL << RS_START)		\
	|(1UL << RS_PROGRESS)		\
	|(1UL << RS_PROGRESS_NOTIFY)		\
	|(1UL << RS_DONE)		\
	)

static ULONG_PTR get_work_bits(const ULONG_PTR mask, ULONG_PTR* flags)
{

	ULONG_PTR old, new;
	do {
		old = *flags;
		new = old & ~mask;
#ifdef _WIN64
		BUG_ON_UINT32_OVER(old);
		BUG_ON_UINT32_OVER(new);
#endif
#ifdef _WIN
	} while (atomic_cmpxchg((atomic_t *)flags, (int)old, (int)new) != (int)old);
#else // _LIN
	} while (cmpxchg(flags, old, new) != old);
#endif
	return old & mask;
}

static void __do_unqueued_peer_device_work(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		struct bsr_device *device = peer_device->device;
		ULONG_PTR todo = get_work_bits(BSR_PEER_DEVICE_WORK_MASK, &peer_device->flags);
		
		if (!todo)
			continue;

		kref_get(&device->kref);
		rcu_read_unlock();
		do_peer_device_work(peer_device, todo, (connection->cstate[NOW] == C_CONNECTED));
		kref_put(&device->kref, bsr_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void do_unqueued_peer_device_work(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	u64 im;

	for_each_connection_ref(connection, im, resource) 
		__do_unqueued_peer_device_work(connection);
}

static void do_unqueued_device_work(struct bsr_resource *resource)
{
	struct bsr_device *device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		ULONG_PTR todo = get_work_bits(BSR_DEVICE_WORK_MASK, &device->flags);

		if (!todo)
			continue;

		kref_get(&device->kref);
		rcu_read_unlock();
		do_device_work(device, todo);
		kref_put(&device->kref, bsr_destroy_device);
		rcu_read_lock();
	}
	rcu_read_unlock();
}

static void do_unqueued_resource_work(struct bsr_resource *resource)
{
	ULONG_PTR todo = get_work_bits(BSR_RESOURCE_WORK_MASK, &resource->flags);
	
	if (test_bit(TRY_BECOME_UP_TO_DATE, &todo))
		try_become_up_to_date(resource);
}

static bool dequeue_work_batch(struct bsr_work_queue *queue, struct list_head *work_list)
{
	spin_lock_irq(&queue->q_lock);
	list_splice_tail_init(&queue->q, work_list);
	spin_unlock_irq(&queue->q_lock);
	return !list_empty(work_list);
}

static struct bsr_request *__next_request_for_connection(
		struct bsr_connection *connection, struct bsr_request *r)
{
#ifdef NETQUEUED_LOG
	r = list_prepare_entry_ex(struct bsr_request, r, &connection->resource->net_queued_log, nq_requests);
#else
	r = list_prepare_entry_ex(struct bsr_request, r, &connection->resource->transfer_log, tl_requests);
#endif

#ifdef NETQUEUED_LOG
	list_for_each_entry_continue_ex(struct bsr_request, r, &connection->resource->net_queued_log, nq_requests) {
#else
	list_for_each_entry_continue_ex(struct bsr_request, r, &connection->resource->transfer_log, tl_requests) {
#endif
		int vnr = r->device->vnr;
		struct bsr_peer_device *peer_device = conn_peer_device(connection, vnr);
		unsigned s = bsr_req_state_by_peer_device(r, peer_device);
		if (!(s & RQ_NET_QUEUED))
			continue;
		return r;
	}
	return NULL;
}

/* holds req_lock on entry, may give up and reaquire temporarily */
static struct bsr_request *tl_mark_for_resend_by_connection(struct bsr_connection *connection)
{
	struct bio_and_error m;
	struct bsr_request *req = NULL;
	struct bsr_request *req_oldest = NULL;
	struct bsr_request *tmp = NULL;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device;
	unsigned s;

	/* In the unlikely case that we need to give up the spinlock
	 * temporarily below, we need to restart the loop, as the request
	 * pointer, or any next pointers, may become invalid meanwhile.
	 *
	 * We can restart from a known safe position, though:
	 * the last request we successfully marked for resend,
	 * without it disappearing.
	 */
restart:
	req = list_prepare_entry_ex(struct bsr_request, tmp, &connection->resource->transfer_log, tl_requests);

	list_for_each_entry_continue_ex(struct bsr_request, req, &connection->resource->transfer_log, tl_requests) {
		/* potentially needed in complete_master_bio below */
		device = req->device;
		peer_device = conn_peer_device(connection, device->vnr);
		s = bsr_req_state_by_peer_device(req, peer_device);

		if (!(s & RQ_NET_MASK))
			continue;

		/* if it is marked QUEUED, it can not be an old one,
		 * so we can stop marking for RESEND here. */
		if (s & RQ_NET_QUEUED)
			break;

		/* Skip old requests which are uninteresting for this connection.
		 * Could happen, if this connection was restarted,
		 * while some other connection was lagging seriously. */
		if (s & RQ_NET_DONE)
			continue;

		/* FIXME what about QUEUE_FOR_SEND_OOS?
		 * Is it even possible to encounter those here?
		 * It should not.
		 */
		if (bsr_req_is_write(req))
			expect(peer_device, s & RQ_EXP_BARR_ACK);

		__req_mod(req, RESEND, peer_device, &m);

		/* If this is now RQ_NET_PENDING (it should), it won't
		 * disappear, even if we give up the spinlock below. */
		if (bsr_req_state_by_peer_device(req, peer_device) & RQ_NET_PENDING)
			tmp = req;

		/* We crunch through a potentially very long list, so be nice
		 * and eventually temporarily give up the spinlock/re-enable
		 * interrupts.
		 *
		 * Also, in the very unlikely case that trying to mark it for
		 * RESEND actually caused this request to be finished off, we
		 * complete the master bio, outside of the lock. */
		if (m.bio || need_resched()) {
			spin_unlock_irq(&connection->resource->req_lock);
			if (m.bio)
				complete_master_bio(device, &m);
			cond_resched();
			spin_lock_irq(&connection->resource->req_lock);
			goto restart;
		}
		if (!req_oldest)
			req_oldest = req;
	}
	return req_oldest;
}

static struct bsr_request *tl_next_request_for_connection(struct bsr_connection *connection)
{
	if (connection->todo.req_next == TL_NEXT_REQUEST_RESEND)
		connection->todo.req_next = tl_mark_for_resend_by_connection(connection);

	else if (connection->todo.req_next == NULL)
		connection->todo.req_next = __next_request_for_connection(connection, NULL);

	connection->todo.req = connection->todo.req_next;

	/* advancement of todo.req_next happens in advance_conn_req_next(),
	 * called from mod_rq_state() */

	return connection->todo.req;
}

static void maybe_send_state_afer_ahead(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if (test_and_clear_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags)) {
			peer_device->todo.was_ahead = false;
			rcu_read_unlock();
			bsr_send_current_state(peer_device);
			rcu_read_lock();
		}
	}
	rcu_read_unlock();
}

/* This finds the next not yet processed request from
 * connection->resource->transfer_log.
 * It also moves all currently queued connection->sender_work
 * to connection->todo.work_list.
 */
static bool check_sender_todo(struct bsr_connection *connection)
{
	tl_next_request_for_connection(connection);

	/* we did lock_irq above already. */
	/* FIXME can we get rid of this additional lock? */
	spin_lock(&connection->sender_work.q_lock);
	list_splice_tail_init(&connection->sender_work.q, &connection->todo.work_list);
	spin_unlock(&connection->sender_work.q_lock);

	return connection->todo.req
#ifdef _LIN
		|| need_unplug(connection)
#endif		
		|| !list_empty(&connection->todo.work_list);
}

static void wait_for_sender_todo(struct bsr_connection *connection)
{
#ifdef _LIN
	DEFINE_WAIT(wait);
#endif
	struct net_conf *nc;
	int uncork, cork;
	bool got_something = 0;

	spin_lock_irq(&connection->resource->req_lock);
	got_something = check_sender_todo(connection);
	spin_unlock_irq(&connection->resource->req_lock);
	if (got_something)
		return;

	/* Still nothing to do?
	 * Maybe we still need to close the current epoch,
	 * even if no new requests are queued yet.
	 *
	 * Also, poke TCP, just in case.
	 * Then wait for new work (or signal). */
	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	uncork = nc ? nc->tcp_cork : 0;
	rcu_read_unlock();
	if (uncork)
		bsr_uncork(connection, DATA_STREAM);

	for (;;) {
		int send_barrier;
#ifdef _LIN
		prepare_to_wait(&connection->sender_work.q_wait, &wait,
				TASK_INTERRUPTIBLE);
#endif
		spin_lock_irq(&connection->resource->req_lock);
		if (check_sender_todo(connection) || signal_pending(current)) {
			spin_unlock_irq(&connection->resource->req_lock);
			break;
		}

		/* We found nothing new to do, no to-be-communicated request,
		 * no other work item.  We may still need to close the last
		 * epoch.  Next incoming request epoch will be connection ->
		 * current transfer log epoch number.  If that is different
		 * from the epoch of the last request we communicated, it is
		 * safe to send the epoch separating barrier now.
		 */
		send_barrier =
			atomic_read(&connection->resource->current_tle_nr) !=
			connection->send.current_epoch_nr;
		spin_unlock_irq(&connection->resource->req_lock);

		if (send_barrier)
			maybe_send_barrier(connection,
					connection->send.current_epoch_nr + 1);

		if (test_and_clear_bit(SEND_STATE_AFTER_AHEAD_C, &connection->flags))
			maybe_send_state_afer_ahead(connection);

		/* bsr_send() may have called flush_signals() */
		if (get_t_state(&connection->sender) != RUNNING)
			break;

#ifdef _WIN
		schedule(&connection->sender_work.q_wait, SENDER_SCHEDULE_TIMEOUT, __FUNCTION__, __LINE__); 
#else // _LIN
		schedule();
#endif
		/* may be woken up for other things but new work, too,
		 * e.g. if the current epoch got closed.
		 * In which case we send the barrier above. */
	}
#ifdef _LIN
	finish_wait(&connection->sender_work.q_wait, &wait);
#endif

	/* someone may have changed the config while we have been waiting above. */
#ifdef _WIN
	rcu_read_lock_w32_inner();
#else // _LIN
	rcu_read_lock();
#endif
	nc = rcu_dereference(connection->transport.net_conf);
	cork = nc ? nc->tcp_cork : 0;
	rcu_read_unlock();

	if (cork)
		bsr_cork(connection, DATA_STREAM);
	else if (!uncork)
		bsr_uncork(connection, DATA_STREAM);
}

static void re_init_if_first_write(struct bsr_connection *connection, int epoch)
{
	if (!connection->send.seen_any_write_yet) {
		connection->send.seen_any_write_yet = true;
		connection->send.current_epoch_nr = epoch;
		connection->send.current_epoch_writes = 0;
		connection->send.last_sent_barrier_jif = jiffies;
		connection->send.current_dagtag_sector =
			connection->resource->dagtag_sector - ((BIO_MAX_VECS << PAGE_SHIFT) >> 9) - 1;
	}
}

static void maybe_send_barrier(struct bsr_connection *connection, int epoch)
{
	/* re-init if first write on this connection */
	if (!connection->send.seen_any_write_yet)
		return;
	if (connection->send.current_epoch_nr != epoch) {
		if (connection->send.current_epoch_writes)
			bsr_send_barrier(connection);
		connection->send.current_epoch_nr = epoch;
	}
}

// BSR-838
#ifdef _WIN
void sended_timer_fn(PKDPC Dpc, PVOID data, PVOID SystemArgument1, PVOID SystemArgument2)
#else // _LIN
void sended_timer_fn(BSR_TIMER_FN_ARG)
#endif
{
	LONGLONG cur_repl, last_repl, cur_resync, last_resync;
#ifdef _WIN
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Dpc);
	struct bsr_peer_device *peer_device = (struct bsr_peer_device *) data;
#else
	struct bsr_peer_device *peer_device = BSR_TIMER_ARG2OBJ(peer_device, sended_timer);
#endif

	if (peer_device == NULL)
		return;

	cur_repl = atomic_read64(&peer_device->cur_repl_sended);
	last_repl = atomic_read64(&peer_device->last_repl_sended);
	cur_resync = atomic_read64(&peer_device->cur_resync_sended);
	last_resync = atomic_read64(&peer_device->last_resync_sended);

	atomic_set64(&peer_device->repl_sended, cur_repl - last_repl);
	atomic_set64(&peer_device->resync_sended, cur_resync - last_resync);

	atomic_set64(&peer_device->last_repl_sended, atomic_read64(&peer_device->cur_repl_sended));
	atomic_set64(&peer_device->last_resync_sended, atomic_read64(&peer_device->cur_resync_sended));

	atomic_set64(&peer_device->last_resync_received, atomic_read64(&peer_device->cur_resync_received));

	if (peer_device->repl_state[NOW] == L_SYNC_SOURCE) {
		mod_timer(&peer_device->sended_timer, jiffies + HZ);
	} else {
		atomic_set64(&peer_device->cur_repl_sended, 0);
		atomic_set64(&peer_device->last_repl_sended, 0);
		atomic_set64(&peer_device->cur_resync_sended, 0);
		atomic_set64(&peer_device->last_resync_sended, 0);

		atomic_set64(&peer_device->cur_resync_received, 0);
		atomic_set64(&peer_device->last_resync_received, 0);

		atomic_set64(&peer_device->repl_sended, 0);
		atomic_set64(&peer_device->resync_sended, 0);
	}
}

static int process_one_request(struct bsr_connection *connection)
{
	struct bio_and_error m;
	struct bsr_request *req = connection->todo.req;
	struct bsr_device *device = req->device;
	struct bsr_peer_device *peer_device =
			conn_peer_device(connection, device->vnr);
	unsigned s = bsr_req_state_by_peer_device(req, peer_device);
#ifdef _LIN
	bool do_send_unplug = req->rq_state[0] & RQ_UNPLUG;
#endif
	int err;
	enum bsr_req_event what;

	req->pre_send_jif[peer_device->node_id] = jiffies;
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
		ktime_get_accounting(req->pre_send_kt[peer_device->node_id]);
	if (bsr_req_is_write(req)) {
		/* If a WRITE does not expect a barrier ack,
		 * we are supposed to only send an "out of sync" info packet */
		if (s & RQ_EXP_BARR_ACK) {
			u64 current_dagtag_sector =
				req->dagtag_sector - (req->i.size >> 9);

			re_init_if_first_write(connection, req->epoch);
			maybe_send_barrier(connection, req->epoch);
			if (current_dagtag_sector != connection->send.current_dagtag_sector)
				bsr_send_dagtag(connection, current_dagtag_sector);

			connection->send.current_epoch_writes++;
			connection->send.current_dagtag_sector = req->dagtag_sector;

			if (peer_device->todo.was_ahead) {
				clear_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags);
				peer_device->todo.was_ahead = false;
				bsr_send_current_state(peer_device);
			}

			err = bsr_send_dblock(peer_device, req);
			what = err ? SEND_FAILED : HANDED_OVER_TO_NETWORK;

			// BSR-838
			atomic_add64(req->i.size, &peer_device->cur_repl_sended);
			// BSR-1145 bsr_free_accelbuf() needs to be called from req_lock due to an internal call function.
			spin_lock_irq(&connection->resource->req_lock);
			// DW-1237 data block has been sent(or failed), put request databuf ref.
			if (req->req_databuf && (0 == atomic_dec_return(&req->req_databuf_ref))) {
				if (req->rq_state[0] & RQ_LOCAL_COMPLETED) {
					bsr_free_accelbuf(req->device, req->req_databuf, req->bio_status.size);
					req->req_databuf = NULL;
				}
			}
			spin_unlock_irq(&connection->resource->req_lock);
		} else {
			/* this time, no connection->send.current_epoch_writes++;
			 * If it was sent, it was the closing barrier for the last
			 * replicated epoch, before we went into AHEAD mode.
			 * No more barriers will be sent, until we leave AHEAD mode again. */

			// BSR-901 execute maybe_send_barrier() only in Ahead state when sending oos
			// otherwise, if oos req from another epoch is sent during replication epoch processing, 
			// current_epoch_nr will change and same barrier_nr may be sent duplicated.
			if (peer_device->repl_state[NOW] == L_AHEAD)
				maybe_send_barrier(connection, req->epoch);

			if (!peer_device->todo.was_ahead) {
				peer_device->todo.was_ahead = true;
				bsr_send_current_state(peer_device);
			}
			err = bsr_send_out_of_sync(peer_device, &req->i);

#ifdef SPLIT_REQUEST_RESYNC
			// DW-2058 if all request(pending out of sync) is sent when the current status is L_ESTABLISHED and out of sync remains, start resync.
			if (peer_device->connection->agreed_pro_version >= 113) {
				if (atomic_read(&peer_device->rq_pending_oos_cnt) == 0 &&
					peer_device->repl_state[NOW] == L_ESTABLISHED &&
					bsr_bm_total_weight(peer_device)) {

					bsr_info(146, BSR_LC_RESYNC_OV, peer_device, "Start resync again because there is out of sync(%llu) in L_ESTABLISHED state", (unsigned long long)bsr_bm_total_weight(peer_device));
					peer_device->start_resync_side = L_SYNC_SOURCE;
					// BSR-634 changed to mod_timer() due to potential kernel panic caused by duplicate calls to add_timer().
					mod_timer(&peer_device->start_resync_timer, jiffies + HZ);
				}
			}
#endif
			what = OOS_HANDED_TO_NETWORK;
		}
	} else {
		maybe_send_barrier(connection, req->epoch);
        err = bsr_send_drequest(peer_device, P_DATA_REQUEST,
            req->i.sector, req->i.size, (ULONG_PTR)req);
		what = err ? SEND_FAILED : HANDED_OVER_TO_NETWORK;
	}

	spin_lock_irq(&connection->resource->req_lock);
	__req_mod(req, what, peer_device, &m);

	/* As we hold the request lock anyways here,
	 * this is a convenient place to check for new things to do. */
	check_sender_todo(connection);
	spin_unlock_irq(&connection->resource->req_lock);

	if (m.bio)
		complete_master_bio(device, &m);

#ifdef _LIN
	do_send_unplug = do_send_unplug && what == HANDED_OVER_TO_NETWORK;
	maybe_send_unplug_remote(connection, do_send_unplug);
#endif
	return err;
}

static int process_sender_todo(struct bsr_connection *connection)
{
	struct bsr_work *w = NULL;

	/* Process all currently pending work items,
	 * or requests from the transfer log.
	 *
	 * Right now, work items do not require any strict ordering wrt. the
	 * request stream, so lets just do simple interleaved processing.
	 *
	 * Stop processing as soon as an error is encountered.
	 */

	if (!connection->todo.req) {
#ifdef _LIN
		update_sender_timing_details(connection, maybe_send_unplug_remote);
		maybe_send_unplug_remote(connection, false);
#endif
	}

	else if (list_empty(&connection->todo.work_list)) {
		int ret = 0;
		ret = process_one_request(connection);
		update_sender_timing_details(connection, process_one_request);
		return ret;
	}

	while (!list_empty(&connection->todo.work_list)) {
		int err;

		w = list_first_entry(&connection->todo.work_list, struct bsr_work, list);
		list_del_init(&w->list);
		update_sender_timing_details(connection, w->cb);
		err = w->cb(w, connection->cstate[NOW] < C_CONNECTED);
		if (err)
			return err;

		/* If we would need strict ordering for work items, we could
		 * add a dagtag member to struct bsr_work, and serialize based on that.
		 * && !dagtag_newer(connection->todo.req->dagtag_sector, w->dagtag_sector))
		 * to the following condition. */
		if (connection->todo.req) {
			update_sender_timing_details(connection, process_one_request);
			err = process_one_request(connection);
		}
		if (err)
			return err;
	}

	return 0;
}

int bsr_sender(struct bsr_thread *thi)
{
	struct bsr_connection *connection = thi->connection;
	struct bsr_work *w;
	struct bsr_peer_device *peer_device;
	int vnr;
	int err;

	/* Should we drop this? Or reset even more stuff? */
	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		peer_device->send_cnt = 0;
		peer_device->recv_cnt = 0;
	}
	rcu_read_unlock();

	while (get_t_state(thi) == RUNNING) {
		bsr_thread_current_set_cpu(thi);
		if (list_empty(&connection->todo.work_list) &&
		    connection->todo.req == NULL) {
			update_sender_timing_details(connection, wait_for_sender_todo);
			wait_for_sender_todo(connection);
		}

		if (signal_pending(current)) {
			flush_signals(current);
			if (get_t_state(thi) == RUNNING) {
				bsr_warn(29, BSR_LC_THREAD, connection, "Sender got an unexpected signal");
				continue;
			}
			break;
		}

		if (get_t_state(thi) != RUNNING)
			break;

		err = process_sender_todo(connection);
		// BSR-819 Fix to change to NetworkFailure only in connected state
		if (err && connection->cstate[NOW] == C_CONNECTED) {
			change_cstate_ex(connection, C_NETWORK_FAILURE, CS_HARD);
		}
	}

	/* cleanup all currently unprocessed requests */
	if (!connection->todo.req) {
		spin_lock_irq(&connection->resource->req_lock);
		tl_next_request_for_connection(connection);
		spin_unlock_irq(&connection->resource->req_lock);
	}
	while (connection->todo.req) {
		struct bio_and_error m;
		struct bsr_request *req = connection->todo.req;
		struct bsr_device *device = req->device;
		peer_device = conn_peer_device(connection, device->vnr);

		spin_lock_irq(&connection->resource->req_lock);
		tl_next_request_for_connection(connection);
		__req_mod(req, SEND_CANCELED, peer_device, &m);
		spin_unlock_irq(&connection->resource->req_lock);
		if (m.bio)
			complete_master_bio(device, &m);
	}

	/* cancel all still pending works */
	do {
		while (!list_empty(&connection->todo.work_list)) {
			w = list_first_entry(&connection->todo.work_list, struct bsr_work, list);
			list_del_init(&w->list);
			w->cb(w, 1);
		}
		dequeue_work_batch(&connection->sender_work, &connection->todo.work_list);
	} while (!list_empty(&connection->todo.work_list));

	return 0;
}

int bsr_worker(struct bsr_thread *thi)
{
	LIST_HEAD(work_list);
	struct bsr_resource *resource = thi->resource;
	struct bsr_work *w;
	bool is_null_callback_print = false;

	while (get_t_state(thi) == RUNNING) {
		bsr_thread_current_set_cpu(thi);

		if (list_empty(&work_list)) {
			bool w = false, r = false, d = false, p = false;
			int sig = 0;

			update_worker_timing_details(resource, dequeue_work_batch);

			wait_event_interruptible_ex(resource->work.q_wait,
				(w = dequeue_work_batch(&resource->work, &work_list),
				 r = test_and_clear_bit(RESOURCE_WORK_PENDING, &resource->flags),
				 d = test_and_clear_bit(DEVICE_WORK_PENDING, &resource->flags),
				 p = test_and_clear_bit(PEER_DEVICE_WORK_PENDING, &resource->flags),
				 w || r || d || p), sig);

			if (p) {
				update_worker_timing_details(resource, do_unqueued_peer_device_work);
				do_unqueued_peer_device_work(resource);
			}

			if (d) {
				update_worker_timing_details(resource, do_unqueued_device_work);
				do_unqueued_device_work(resource);
			}
			if (r) {
				update_worker_timing_details(resource, do_unqueued_resource_work);
				do_unqueued_resource_work(resource);
			}
		}

		if (signal_pending(current)) {
			flush_signals(current);
			if (get_t_state(thi) == RUNNING) {
				bsr_warn(30, BSR_LC_THREAD, resource, "Worker got an unexpected signal");
				continue;
			}
			break;
		}

		if (get_t_state(thi) != RUNNING)
			break;

		// DW-1953
		is_null_callback_print = false;

		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct bsr_work, list);
			list_del_init(&w->list);
			update_worker_timing_details(resource, w->cb);

			// DW-938 fix callback pointer's NULL case
			if (w->cb != NULL) {
				w->cb(w, 0);
			} 
			else {
				// DW-1953 logs are printed only once per work_list.
				if (is_null_callback_print == false) {
					// DW-1953 do not use "break" because you must call a non-null callback.
					bsr_warn(31, BSR_LC_THREAD, resource, "worker got an null-callback list. resource name (%s), twopc_work(%p) : w(%p)", resource->name, &(resource->twopc_work), w);
					is_null_callback_print = true;
				}
			}
		}
	}

	do {
		if (test_and_clear_bit(RESOURCE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_resource_work);
			do_unqueued_resource_work(resource);
		}
		if (test_and_clear_bit(DEVICE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_device_work);
			do_unqueued_device_work(resource);
		}
		if (test_and_clear_bit(PEER_DEVICE_WORK_PENDING, &resource->flags)) {
			update_worker_timing_details(resource, do_unqueued_peer_device_work);
			do_unqueued_peer_device_work(resource);
		}
		while (!list_empty(&work_list)) {
			w = list_first_entry(&work_list, struct bsr_work, list);
			list_del_init(&w->list);
			update_worker_timing_details(resource, w->cb);
			w->cb(w, 1);
		}
		dequeue_work_batch(&resource->work, &work_list);
	} while (!list_empty(&work_list) ||
		 test_bit(DEVICE_WORK_PENDING, &resource->flags) ||
		 test_bit(PEER_DEVICE_WORK_PENDING, &resource->flags));

	// BSR-1064
	atomic_set(&resource->will_be_used_vol_ctl_mutex, 0);

	return 0;
}

// DW-1755 When a disk error occurs, 
 /* transfers the event to the work thread queue.
 */
static void process_io_error(sector_t sector, unsigned int size, bool write, struct bsr_device *device, unsigned char disk_type, int error)
{
	bsr_queue_notify_io_error_occurred(device, disk_type, (write == true) ? WRITE : READ, error, sector, size);
}


