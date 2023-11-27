/*
   bsr_req.c

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
#ifdef _LIN
#include <linux/module.h>
#include <linux/slab.h>
#endif
#include "bsr_req.h"

static bool bsr_may_do_local_read(struct bsr_device *device, sector_t sector, int size);

/* Update disk stats at start of I/O request */
static void _bsr_start_io_acct(struct bsr_device *device, struct bsr_request *req)
{
#ifdef COMPAT_HAVE_BIO_START_IO_ACCT
	req->start_jif = bio_start_io_acct(req->master_bio);
#else
	struct request_queue *q = device->rq_queue;
	generic_start_io_acct(q, bio_data_dir(req->master_bio), req->i.size >> 9,
		(struct hd_struct*)&device->vdisk->part0);
#endif
}

static struct bsr_request *bsr_req_new(struct bsr_device *device, struct bio *bio_src)
{
	struct bsr_request *req;
	int i;

	req = mempool_alloc(bsr_request_mempool, GFP_NOIO);
	if (!req)
		return NULL;

	memset(req, 0, sizeof(*req));

#ifdef COMPAT_HAVE_BIO_ALLOC_CLONE
	if (bsr_req_make_private_bio(device, req, bio_src) == false) {
#else
    if (bsr_req_make_private_bio(req, bio_src) == false) {
#endif
		mempool_free(req, bsr_request_mempool);
		return NULL;
    }

	// DW-1925 improvement req-buf-size
	atomic_inc(&device->resource->req_write_cnt);

#ifdef _WIN
	// DW-776 (private bio's buffer is invalid when memory-overflow occured)
	req->private_bio->bio_databuf = bio_src->bio_databuf;
#endif

	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 6);

	req->device = device;
	req->master_bio = bio_src;

	// BSR-1116
	req->bio_status.op = bio_op(req->master_bio);
	req->bio_status.opf = req->master_bio->bi_opf;
	req->bio_status.data_dir = bio_data_dir(req->master_bio);
#ifdef _LIN
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
	if (req->bio_status.op == REQ_OP_WRITE_SAME)
		req->bio_status.bv_len = bio_iovec(req->master_bio) BVD bv_len;
#endif
#endif

	req->epoch = 0;

	bsr_clear_interval(&req->i);
	req->i.sector = BSR_BIO_BI_SECTOR(bio_src);
	req->i.size = BSR_BIO_BI_SIZE(bio_src);
	req->i.local = true;
	req->i.waiting = false;

	INIT_LIST_HEAD(&req->tl_requests);

#ifdef NETQUEUED_LOG	
	INIT_LIST_HEAD(&req->nq_requests);
	atomic_set(&req->nq_ref, 0);
#endif
	
	INIT_LIST_HEAD(&req->req_pending_master_completion);
	INIT_LIST_HEAD(&req->req_pending_local);

	/* one reference to be put by __bsr_make_request */
	atomic_set(&req->completion_ref, 1);
	/* one kref as long as completion_ref > 0 */
	kref_init(&req->kref);

	req->rq_state[0] = (bio_data_dir(bio_src) == WRITE ? RQ_WRITE : 0)
		// | (bio_op(bio_src) == REQ_OP_WRITE_SAME ? RQ_WSAME : 0)
		| (bio_op(bio_src) == REQ_OP_WRITE_ZEROES ? RQ_ZEROES : 0)
		| (bio_op(bio_src) == REQ_OP_DISCARD ? RQ_UNMAP : 0);

	for (i = 1; i < ARRAY_SIZE(req->rq_state); i++)
		req->rq_state[i] = 0;

	return req;
}

void bsr_free_accelbuf(struct bsr_device *device, char *buf, int size)
{
	int hsize = sizeof(struct bsr_offset_ring_header);

	bsr_offset_ring_dispose(&device->accelbuf, (int)(buf - device->accelbuf.buf - hsize));
	atomic_sub64(hsize + size, &device->accelbuf.used_size);
}

void bsr_queue_peer_ack(struct bsr_resource *resource, struct bsr_request *req)
{
	struct bsr_connection *connection;
	bool queued = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		unsigned int node_id = connection->peer_node_id;
		if (connection->agreed_pro_version < 110 ||
		    connection->cstate[NOW] != C_CONNECTED ||
		    !(req->rq_state[1 + node_id] & RQ_NET_SENT))
			continue;
		// BSR-827 fix bsr_req memory leak (kernel >= v5.4)
		if (!kref_get_unless_zero(&req->kref))
			refcount_set(&req->kref.refcount, 1); /* was 0, instead of kref_get() */
		req->rq_state[1 + node_id] |= RQ_PEER_ACK;
		if (!queued) {
			list_add_tail(&req->tl_requests, &resource->peer_ack_list);
			queued = true;
		}
		queue_work(connection->ack_sender, &connection->peer_ack_work);
	}
	rcu_read_unlock();

	if (!queued) {
		if (req->req_databuf) {
			// DW-596 required to verify to free req_databuf at this point
			bsr_free_accelbuf(req->device, req->req_databuf, req->bio_status.size);
			req->req_databuf = NULL;
		}
		// DW-1925 improvement req-buf-size
		atomic_dec(&resource->req_write_cnt);
		mempool_free(req, bsr_request_mempool);
	}

}

static bool peer_ack_differs(struct bsr_request *req1, struct bsr_request *req2)
{
	unsigned int max_node_id = req1->device->resource->max_node_id;
	unsigned int node_id;

	for (node_id = 0; node_id <= max_node_id; node_id++)
		if ((req1->rq_state[1 + node_id] & RQ_NET_OK) !=
		    (req2->rq_state[1 + node_id] & RQ_NET_OK))
			return true;
	return false;
}

static bool peer_ack_window_full(struct bsr_request *req)
{
	struct bsr_resource *resource = req->device->resource;
	u32 peer_ack_window = resource->res_opts.peer_ack_window;
	u64 last_dagtag = resource->last_peer_acked_dagtag + peer_ack_window;

	return dagtag_newer_eq(req->dagtag_sector, last_dagtag);
}

static void bsr_remove_request_interval(struct rb_root *root,
					 struct bsr_request *req)
{
	struct bsr_device *device = req->device;
	struct bsr_interval *i = &req->i;

	bsr_remove_interval(root, i);

	/* Wake up any processes waiting for this request to complete.  */
	if (i->waiting)
		wake_up(&device->misc_wait);
}

/* must_hold resource->req_lock */
void bsr_req_destroy(struct kref *kref)
{
	struct bsr_request *req = container_of(kref, struct bsr_request, kref);
	struct bsr_request *destroy_next;
	struct bsr_device *device = NULL;
	struct bsr_peer_device *peer_device;
	unsigned int s, device_refs = 0;
	bool was_last_ref = false;
	unsigned long flags;

 tail_recursion:
	if (device_refs > 0 && device != req->device) {
		/* We accumulate device refs to put, it is very likely that we
		 * destroy a number of requests for the same volume in a row.
		 * But if the tail-recursed request happens to be for a
		 * different volume, we need to put the accumulated device refs
		 * now, while we still know the corresponding device,
		 * and start accumulating for the other device.
		 */
		kref_debug_sub(&device->kref_debug, device_refs, 6);
		kref_sub(&device->kref, device_refs, bsr_destroy_device);
		device_refs = 0;
	}
	device = req->device;
	s = req->rq_state[0];
	destroy_next = req->destroy_next;
	if ((atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST)) && (s & RQ_WRITE)) {
		spin_lock(&device->timing_lock); /* local irq already disabled */
		device->reqs++;
		ktime_aggregate_delta(device, req->start_kt, req_destroy_kt);
		
		ktime_aggregate(device, req, in_actlog_kt);
		ktime_aggregate(device, req, before_queue_kt);
		ktime_aggregate(device, req, before_al_begin_io_kt);
		ktime_aggregate(device, req, submit_kt);
		ktime_aggregate(device, req, bio_endio_kt);

		for_each_peer_device(peer_device, device) {
			int node_id = peer_device->node_id;
			unsigned ns = bsr_req_state_by_peer_device(req, peer_device);
			if (!(ns & RQ_NET_MASK))
				continue;
			peer_device->reqs++;
			ktime_aggregate_pd(peer_device, node_id, req, pre_send_kt);
			ktime_aggregate_pd(peer_device, node_id, req, acked_kt);
			ktime_aggregate_pd(peer_device, node_id, req, net_done_kt);
		}
		spin_unlock(&device->timing_lock);
	} 
	/* paranoia */
	for_each_peer_device(peer_device, device) {
		unsigned ns = bsr_req_state_by_peer_device(req, peer_device);
		if (!(ns & RQ_NET_MASK))
			continue;
		if (ns & RQ_NET_DONE)
			continue;

		bsr_err(7, BSR_LC_REQUEST, device,
			"request destroy Logic BUG. request state(0:%x, %d:%x), completion reference(%d)",
			s, 1 + peer_device->node_id, ns, atomic_read(&req->completion_ref));
		goto out;
	}

	/* more paranoia */
	if ((req->master_bio && !(s & RQ_POSTPONED)) ||
		atomic_read(&req->completion_ref) || (s & RQ_LOCAL_PENDING)) {
		bsr_err(8, BSR_LC_REQUEST, device, "request destroy Logic BUG. request state(%x), completion reference(%d)",
				s, atomic_read(&req->completion_ref));
		goto out;
	}

#ifdef NETQUEUED_LOG
	atomic_set(&req->nq_ref, 0);
	list_del_init(&req->nq_requests);
#endif
	
	list_del_init(&req->tl_requests);

	/* finally remove the request from the conflict detection
	 * respective block_id verification interval tree. */
	if (!bsr_interval_empty(&req->i)) {
		struct rb_root *root;

		if (s & RQ_WRITE)
			root = &device->write_requests;
		else
			root = &device->read_requests;
		bsr_remove_request_interval(root, req);
	} else if (s & (RQ_NET_MASK & ~RQ_NET_DONE) && req->i.size != 0)
		bsr_err(9, BSR_LC_REQUEST, device, "request destroy Logic BUG. interval empty, but request state(0x%x), sect(%llu), size(%u)",
			s, (unsigned long long)req->i.sector, req->i.size);

	if (s & RQ_WRITE) {
		/* There is a special case:
		 * we may notice late that IO was suspended,
		 * and postpone, or schedule for retry, a write,
		 * before it even was submitted or sent.
		 * In that case we do not want to touch the bitmap at all.
		 */
		if ((s & (RQ_POSTPONED|RQ_LOCAL_MASK|RQ_NET_MASK)) != RQ_POSTPONED &&
		    req->i.size && get_ldev_if_state(device, D_DETACHING)) {
			struct bsr_peer_md *peer_md = device->ldev->md.peers;
			ULONG_PTR bits = UINTPTR_MAX, mask = UINTPTR_MAX;
			int node_id, max_node_id = device->resource->max_node_id;
			// DW-1191
			ULONG_PTR set_bits = 0;

			for (node_id = 0; node_id <= max_node_id; node_id++) {
				unsigned int rq_state;

				rq_state = req->rq_state[1 + node_id];
				// Dw-2091 clear the peer index that sent out of sync (rq_state & RQ_NET_DONE && rq_state & RQ_OOS_NET_QUEUED).
				if (rq_state & RQ_NET_OK || ((rq_state & RQ_NET_DONE) && (rq_state & RQ_OOS_NET_QUEUED))
					// BSR-1021 exclude from the destination bitmap because it has not been connected before and has already set out of sync.
					|| rq_state & RQ_OOS_LOCAL_DONE) {
					int bitmap_index = peer_md[node_id].bitmap_index;

					if (bitmap_index == -1)
						continue;

					if (rq_state & RQ_NET_SIS)
						clear_bit(bitmap_index, &bits);
					else
						clear_bit(bitmap_index, &mask);
				}
			}

			// DW-1191 this req needs to go into bitmap, and notify peer if possible.
			set_bits = bsr_set_sync(device, req->i.sector, req->i.size, bits, mask);			
			if (set_bits) {
				for_each_peer_device(peer_device, device) {
					int bitmap_index = peer_device->bitmap_index;

					if (test_bit(bitmap_index, &set_bits) &&
						peer_device->connection->cstate[NOW] >= C_CONNECTED)
					{
						// DW-1191 sending out-of-sync isn't available since we need to acquire mutex to prepare command and caller acquired spin lock.
						//		 queueing sending out-of-sync into connection ack sender here guarantees that oos will be sent before peer ack does.
						struct bsr_oos_no_req* send_oos = NULL;

						// BSR-934
						if (peer_device->disk_state[NOW] != D_DISKLESS)
							bsr_info(10, BSR_LC_REQUEST, peer_device, "Found disappeared out-of-sync, need to send new one(sector(%llu), size(%u))", (unsigned long long)req->i.sector, req->i.size);

						send_oos = bsr_kmalloc(sizeof(struct bsr_oos_no_req), 0, 'OSSB');
						if (send_oos) {
							INIT_LIST_HEAD(&send_oos->oos_list_head);
							send_oos->sector = req->i.sector;
							send_oos->size = req->i.size;
							
							spin_lock_irqsave(&peer_device->send_oos_lock, flags);
							list_add_tail(&send_oos->oos_list_head, &peer_device->send_oos_list);
							spin_unlock_irqrestore(&peer_device->send_oos_lock, flags);
							queue_work(peer_device->connection->ack_sender, &peer_device->send_oos_work);
						}
						else {
							bsr_err(35, BSR_LC_MEMORY, peer_device, "Failed to send out of sync due to failure to allocate memory so dropping connection. sector(%llu), size(%u)",
								(unsigned long long)req->i.sector, req->i.size);
							change_cstate_ex(peer_device->connection, C_DISCONNECTING, CS_HARD);
						}
					}
				}
			}

			put_ldev(__FUNCTION__, device);
		}

		/* one might be tempted to move the bsr_al_complete_io
		 * to the local io completion callback bsr_request_endio.
		 * but, if this was a mirror write, we may only
		 * bsr_al_complete_io after this is RQ_NET_DONE,
		 * otherwise the extent could be dropped from the al
		 * before it has actually been written on the peer.
		 * if we crash before our peer knows about the request,
		 * but after the extent has been dropped from the al,
		 * we would forget to resync the corresponding extent.
		 */
		if (s & RQ_IN_ACT_LOG) {
			if (get_ldev_if_state(device, D_DETACHING)) {
				was_last_ref = bsr_al_complete_io(__FUNCTION__, device, &req->i);
				put_ldev(__FUNCTION__, device);
			} else if (bsr_ratelimit()) {
				bsr_warn(26, BSR_LC_LRU, device, "Should have called bsr_al_complete_io(, %llu, %u), "
					  "but my Disk seems to have failed :(",
					  (unsigned long long) req->i.sector, req->i.size);
			}
		}
	}

	// DW-1961
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY)) {
		bsr_debug(3, BSR_LC_LATENCY, device, "req(%p) IO latency : in_act(%d) minor(%u) ds(%s) type(%s) sector(%llu) size(%u) prepare(%lldus) disk_io(%lldus) local_io(%lldus) total(%lldus) io_depth(%d)",
			req, req->do_submit, device->minor, bsr_disk_str(device->disk_state[NOW]), "write", req->i.sector, req->i.size,
			timestamp_elapse(__FUNCTION__, req->created_ts, req->io_request_ts), 
			timestamp_elapse(__FUNCTION__, req->io_request_ts, req->io_complete_ts), 
			timestamp_elapse(__FUNCTION__, req->created_ts, req->local_complete_ts), 
			timestamp_elapse(__FUNCTION__, req->created_ts, timestamp()), 
			atomic_read(&device->ap_bio_cnt[WRITE]));
	}

	device_refs++; /* In both branches of the if the reference to device gets released */
	if (s & RQ_WRITE && req->i.size) {
		struct bsr_resource *resource = device->resource;
		struct bsr_request *peer_ack_req = resource->peer_ack_req;

		if (peer_ack_req) {
			if (peer_ack_differs(req, peer_ack_req) ||
				(was_last_ref && atomic_read(&device->ap_actlog_cnt)) ||
			    peer_ack_window_full(req)) {
				bsr_queue_peer_ack(resource, peer_ack_req);
				peer_ack_req = NULL;
			} else {
				if (peer_ack_req->req_databuf) {
					bsr_free_accelbuf(peer_ack_req->device, peer_ack_req->req_databuf, peer_ack_req->bio_status.size);
					peer_ack_req->req_databuf = NULL;
				}
				// DW-1925 improvement req-buf-size
				atomic_dec(&resource->req_write_cnt);
				mempool_free(peer_ack_req, bsr_request_mempool);
				peer_ack_req = NULL;
			}
		}

		resource->peer_ack_req = req;
		mod_timer(&resource->peer_ack_timer,
			  jiffies + resource->res_opts.peer_ack_delay * HZ / 1000);

		if (!peer_ack_req)
			resource->last_peer_acked_dagtag = req->dagtag_sector;
	} else {
		if (req->req_databuf) {
			bsr_free_accelbuf(req->device, req->req_databuf, req->bio_status.size);
			req->req_databuf = NULL;
		}
		// DW-1925 improvement req-buf-size
		atomic_dec(&req->device->resource->req_write_cnt);
		mempool_free(req, bsr_request_mempool);
	}

	/*
	 * Do the equivalent of:
	 *   kref_put(&req->kref, bsr_req_destroy)
	 * without recursing into the destructor.
	 */
	if (destroy_next) {
		req = destroy_next;
		if (refcount_dec_and_test(&req->kref.refcount))
			goto tail_recursion;
	}
	

out:
	kref_debug_sub(&device->kref_debug, device_refs, 6);
	kref_sub(&device->kref, device_refs, bsr_destroy_device);
}

static void wake_all_senders(struct bsr_resource *resource) {
	struct bsr_connection *connection;
	/* We need make sure any update is visible before we wake up the
	 * threads that may check the values in their wait_event() condition.
	 * Do we need smp_mb here? Or rather switch to atomic_t? */
	rcu_read_lock();
	for_each_connection_rcu(connection, resource)
		wake_up(&connection->sender_work.q_wait);
	rcu_read_unlock();
}

/* must hold resource->req_lock */
bool start_new_tl_epoch(struct bsr_resource *resource)
{
	/* no point closing an epoch, if it is empty, anyways. */
	if (resource->current_tle_writes == 0)
		return false;

	resource->current_tle_writes = 0;
	atomic_inc(&resource->current_tle_nr);
	wake_all_senders(resource);
	return true;
}

// DW-1755
int w_notify_io_error(struct bsr_work *w, int cancel)
{
	int ret = 0;
	struct bsr_io_error_work *dw =
		container_of(w, struct bsr_io_error_work, w);
	UNREFERENCED_PARAMETER(cancel);

	if (dw && dw->io_error) {
		notify_io_error(dw->device, dw->io_error);
		bsr_kfree(dw->io_error);
		bsr_kfree(dw);
	}

	return ret;
}

// DW-676 
int w_notify_updated_gi(struct bsr_work *w, int cancel)
{
	int ret = 0;
	struct bsr_updated_gi_work *dw =
		container_of(w, struct bsr_updated_gi_work, w);
	UNREFERENCED_PARAMETER(cancel);

	if (dw) {
		struct bsr_device *device;
		struct bsr_peer_device *peer_device;

		mutex_lock(&notification_mutex);
		if (dw->type == BSR_GI_NOTI_UUID) {
			device = dw->device;
			for_each_peer_device(peer_device, device) {
				notify_gi_uuid_state(NULL, 0, peer_device, NOTIFY_CHANGE);
			}
		}
		else if (dw->type == BSR_GI_NOTI_DEVICE_FLAG) {
			notify_gi_device_mdf_flag_state(NULL, 0, dw->device, NOTIFY_CHANGE);
		}
		else if (dw->type == BSR_GI_NOTI_PEER_DEVICE_FLAG) {
			notify_gi_peer_device_mdf_flag_state(NULL, 0, dw->peer_device, NOTIFY_CHANGE);
		}
		mutex_unlock(&notification_mutex);
		bsr_kfree(dw);
	}

	return ret;
}

void complete_master_bio(struct bsr_device *device,
struct bio_and_error *m)
{
#ifdef _WIN
	struct bio* master_bio = NULL;
#endif
	struct bsr_peer_device *peer_device;

	int rw = bio_data_dir(m->bio);

	// BSR-658 get bi sector, size before bio free
	sector_t bi_sector = BSR_BIO_BI_SECTOR(m->bio);
	int bi_size = BSR_BIO_BI_SIZE(m->bio);
	struct io_pending_info *io_pending = NULL, *tmp = NULL;
	unsigned long flags;

	// BSR-1054
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_PENDING)) {
		spin_lock_irqsave(&device->io_pending_list_lock, flags);
		// calculate the latency as the first item in the list, otherwise just remove it.
		// as long as the first item is still in the list, the latency continues to increase. This can be considered as IO pending.
		io_pending = list_first_entry_or_null(&device->io_pending_list, struct io_pending_info, list);
		if (io_pending) {
			if ((io_pending->bio != m->bio) || io_pending->complete_pending) {
				device->io_pending_latency = ns_to_ktime(0);
				list_for_each_entry_safe_ex(struct io_pending_info, io_pending, tmp, &device->io_pending_list, list) {
					if ((io_pending->bio == m->bio) && !io_pending->complete_pending) {
						list_del(&io_pending->list);
						kfree2(io_pending);
						break;
					}
				}
				io_pending = NULL;
			} else {
				io_pending->complete_pending = 1;
			}
		}
		spin_unlock_irqrestore(&device->io_pending_list_lock, flags);
	}

#ifdef _WIN
	ASSERT(m->bio->bi_end_io == NULL); //at this point, if bi_end_io_cb is not NULL, occurred to recusively call.(bio_endio -> bsr_request_endio -> complete_master_bio -> bio_endio)
#else // _LIN
	bsr_bio_endio(m->bio, m->error);
	// BSR-764 delay master I/O completion
	if(g_simul_perf.flag && (g_simul_perf.type == SIMUL_PERF_DELAY_TYPE1)) 
		force_delay(g_simul_perf.delay_time);
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_COMPLETE)) {
		atomic_inc(&device->master_complete_kt.cnt);
		ktime_aggregate_delta(device, m->io_start_kt, master_complete_kt);
	}

#endif
	peer_device = NULL;
#ifdef _WIN
	// if bio has pMasterIrp, process to complete master bio.
	if (m->bio->pMasterIrp) {
		NTSTATUS status = m->error;
		master_bio = m->bio; // if pMasterIrp is exist, bio is master bio.
#endif
		// In diskless mode, if irp was sent to peer,
		// then would be completed success,
		// The others should be converted to the Windows error status.
		if (m->error) {
#ifdef _WIN
			if (D_DISKLESS == device->disk_state[NOW]) {
				status = STATUS_SUCCESS;
			}
#endif

			// DW-1755 In the passthrough policy, 
			/* when a disk error occurs on the primary node,
			* write out_of_sync for all nodes.
			*/
			for_each_peer_device(peer_device, device) {
				if (peer_device) {
					bsr_set_out_of_sync(peer_device, bi_sector, bi_size);
					if (peer_device->connection->cstate[NOW] == C_CONNECTED)
						bsr_md_set_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR);
				}
			}

			bsr_md_set_flag(device, MDF_IO_ERROR);
		}
		// DW-1859
		check_and_clear_io_error_in_primary(device);

#ifdef _WIN
		if (!master_bio->splitInfo) {
			if (master_bio->bi_size <= 0 || master_bio->bi_size > (1024 * 1024)) {
				bsr_err(58, BSR_LC_IO, NO_OBJECT, "Failed to complete I/O due to block I/O size is invalid. size(%d)", master_bio->bi_size);
				BUG();
			}

			if (NT_ERROR(status)) {
				master_bio->pMasterIrp->IoStatus.Status = status;
				master_bio->pMasterIrp->IoStatus.Information = 0;
			}
			else {
				master_bio->pMasterIrp->IoStatus.Status = 0;
				master_bio->pMasterIrp->IoStatus.Information = master_bio->bi_size;
			}

#ifdef _WIN_TMP_Win8_BUG_0x1a_61946
			if (NT_SUCCESS(status) && (bio_rw(master_bio) == READ) && master_bio->bio_databuf) {
				PVOID	buffer = NULL;
				buffer = MmGetSystemAddressForMdlSafe(master_bio->pMasterIrp->MdlAddress, NormalPagePriority);
				if (buffer == NULL) {
					bsr_err(59, BSR_LC_IO, NO_OBJECT, "Failed to complete I/O due to failure to get MDL for not split block I/o buffer");
					BUG();
				}
				if (buffer) {
					memcpy(buffer, master_bio->bio_databuf, master_bio->pMasterIrp->IoStatus.Information);
				}
			}
#endif
			IoCompleteRequest(master_bio->pMasterIrp, NT_SUCCESS(master_bio->pMasterIrp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
			// BSR-764 delay master I/O completion
			if (g_simul_perf.flag && g_simul_perf.type == SIMUL_PERF_DELAY_TYPE1) 
				force_delay(g_simul_perf.delay_time);
			// BSR-687
			if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_COMPLETE)) {
				atomic_inc(&device->master_complete_kt.cnt);
				ktime_aggregate_delta(device, m->bio->io_start_kt, master_complete_kt);
			}
			// DW-1300 put reference when completing master irp.
			kref_put(&device->kref, bsr_destroy_device);
		}
		else {

#ifdef _WIN_TMP_Win8_BUG_0x1a_61946
			if (NT_SUCCESS(status) && (bio_rw(master_bio) == READ) && master_bio->bio_databuf) {
				PVOID	buffer = NULL;
				buffer = MmGetSystemAddressForMdlSafe(master_bio->pMasterIrp->MdlAddress, NormalPagePriority);
				if (buffer == NULL) {
					bsr_err(60, BSR_LC_IO, NO_OBJECT, "Failed to complete I/O due to failure to get MDL for split block I/o buffer");
					BUG();
				}
				else {
					// get offset and copy
					memcpy((char *)buffer + (master_bio->split_id * MAX_SPILT_BLOCK_SZ), master_bio->bio_databuf, master_bio->pMasterIrp->IoStatus.Information);
				}

				master_bio->pMasterIrp->IoStatus.Information = master_bio->bi_size;
			}
#endif
			if (!NT_SUCCESS(status)) {
				master_bio->splitInfo->LastError = status;
			}

			if (atomic_inc_return((volatile LONG *)&master_bio->splitInfo->finished) == (long)master_bio->split_total_id) {

				if (master_bio->splitInfo->LastError == STATUS_SUCCESS) {
					master_bio->pMasterIrp->IoStatus.Status = STATUS_SUCCESS;
					master_bio->pMasterIrp->IoStatus.Information = master_bio->split_total_length;
				}
				else {
					master_bio->pMasterIrp->IoStatus.Status = master_bio->splitInfo->LastError;
					master_bio->pMasterIrp->IoStatus.Information = 0;
				}

				IoCompleteRequest(master_bio->pMasterIrp, NT_SUCCESS(master_bio->pMasterIrp->IoStatus.Status) ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
				// BSR-764 delay master I/O completion
				if (g_simul_perf.flag && g_simul_perf.type == SIMUL_PERF_DELAY_TYPE1) 
					force_delay(g_simul_perf.delay_time);
				// BSR-687
				if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_COMPLETE)) {
					atomic_inc(&device->master_complete_kt.cnt);
					ktime_aggregate_delta(device, m->bio->io_start_kt, master_complete_kt);
				}

				kfree(master_bio->splitInfo);
				// DW-1300 put reference when completing master irp.
				kref_put(&device->kref, bsr_destroy_device);
			}
		}

#ifdef _WIN_TMP_Win8_BUG_0x1a_61946
		if ((bio_rw(master_bio) == READ) && master_bio->bio_databuf) {
			kfree(master_bio->bio_databuf);
		}
#endif
		kfree(master_bio);
	}
	else {
		panic("complete_master_bio ERRROR! pMasterIrp is NULL");
	}
#endif
	// BSR-1054 calculate io_pending_latency if bio is complete
	if (io_pending) {
		spin_lock_irqsave(&device->io_pending_list_lock, flags);
		device->io_pending_latency = ktime_sub(ktime_get(), io_pending->io_start_kt);
		list_del(&io_pending->list);
		kfree2(io_pending);
		spin_unlock_irqrestore(&device->io_pending_list_lock, flags);
	}
	dec_ap_bio(device, rw);
}


/* Helper for __req_mod().
 * Set m->bio to the master bio, if it is fit to be completed,
 * or leave it alone (it is initialized to NULL in __req_mod),
 * if it has already been completed, or cannot be completed yet.
 * If m->bio is set, the error status to be returned is placed in m->error.
 */
static
void bsr_req_complete(struct bsr_request *req, struct bio_and_error *m)
{
	const unsigned s = req->rq_state[0];
	struct bsr_device *device = req->device;
	struct bsr_peer_device *peer_device;
	int error, ok = 0;

	/*
	 * figure out whether to report success or failure.
	 *
	 * report success when at least one of the operations succeeded.
	 * or, to put the other way,
	 * only report failure, when both operations failed.
	 *
	 * what to do about the failures is handled elsewhere.
	 * what we need to do here is just: complete the master_bio.
	 *
	 * local completion error, if any, has been stored as ERR_PTR
	 * in private_bio within bsr_request_endio.
	 */
	if (s & RQ_LOCAL_OK)
		++ok;
	error = PTR_ERR(req->private_bio);

	for_each_peer_device(peer_device, device) {
		unsigned ns = bsr_req_state_by_peer_device(req, peer_device);
		/* any net ok ok local ok is good enough to complete this bio as OK */
		if (ns & RQ_NET_OK)
			++ok;
		/* paranoia */
		/* we must not complete the master bio, while it is
		 *	still being processed by _bsr_send_zc_bio (bsr_send_dblock),
		 *	respectively still needed for the second bsr_csum_bio() there.
		 *	not yet acknowledged by the peer
		 *	not yet completed by the local io subsystem
		 * these flags may get cleared in any order by
		 *	the worker,
		 *	the sender,
		 *	the receiver,
		 *	the bio_endio completion callbacks.
		 */
		if (!(ns & RQ_NET_MASK))
			continue;
		if (!(ns & (RQ_NET_PENDING|RQ_NET_QUEUED)))
			continue;

		bsr_err(15, BSR_LC_REQUEST, device,
			"Failed to complete request due to logic bug. request state(0:%x, %d:%x), completion reference (%d)",
			s, 1 + peer_device->node_id, ns, atomic_read(&req->completion_ref));
		return;
	}

	/* more paranoia */
	if (atomic_read(&req->completion_ref) ||
	    ((s & RQ_LOCAL_PENDING) && !(s & RQ_LOCAL_ABORTED))) {
		bsr_err(16, BSR_LC_REQUEST, device, "Failed to complete request due to logic bug. request state(%x), completion reference(%d)",
				s, atomic_read(&req->completion_ref));
		return;
	}

	// BSR-1116 add the following conditions because master_bio exists but writing may complete
	if (!req->i.completed && !req->master_bio) {
		bsr_err(17, BSR_LC_REQUEST, device, "Failed to complete request due to logic bug, master block I/O is NULL.");
		return;
	}


	/* Before we can signal completion to the upper layers,
	 * we may need to close the current transfer log epoch.
	 * We are within the request lock, so we can simply compare
	 * the request epoch number with the current transfer log
	 * epoch number.  If they match, increase the current_tle_nr,
	 * and reset the transfer log epoch write_cnt.
	 */

	// BSR-1116
	if (req->bio_status.data_dir == WRITE &&
	    req->epoch == atomic_read(&device->resource->current_tle_nr))
		start_new_tl_epoch(device->resource);

	if (!req->i.completed) {
		/* Update disk stats */
		_bsr_end_io_acct(device, req);
	}

	/* If READ failed,
	 * have it be pushed back to the retry work queue,
	 * so it will re-enter __bsr_make_request(),
	 * and be re-assigned to a suitable local or remote path,
	 * or failed if we do not have access to good data anymore.
	 *
	 * Unless it was failed early by __bsr_make_request(),
	 * because no path was available, in which case
	 * it was not even added to the transfer_log.
	 *
	 * read-ahead may fail, and will not be retried.
	 *
	 * WRITE should have used all available paths already.
	 */
	if (!ok &&
		// BSR-1116
		req->bio_status.op == REQ_OP_READ &&
		!(req->bio_status.op & REQ_RAHEAD) &&
		!list_empty(&req->tl_requests))
		req->rq_state[0] |= RQ_POSTPONED;
	
	if (!(req->rq_state[0] & RQ_POSTPONED)) {
		// BSR-1116
		if (!req->i.completed) {
			// DW-1755 
			// for the "passthrough" policy, all local errors are returned to the file system.
			enum bsr_io_error_p eh = EP_PASSTHROUGH;

			// DW-1837
			//If the disk is detached, device-> ldev can be null.
			if (device->ldev) {
				rcu_read_lock();
				eh = rcu_dereference(device->ldev->disk_conf)->on_io_error;
				rcu_read_unlock();
			}

			if (eh == EP_PASSTHROUGH)
				m->error = error;
			else
				m->error = ok ? 0 : (error ? error : -EIO);

			m->bio = req->master_bio;
#ifdef _LIN
			if (atomic_read(&g_bsrmon_run))
				m->io_start_kt = req->start_kt;
#endif
			/* We leave it in the tree, to be able to verify later
			* write-acks in protocol != C during resync.
			* But we mark it as "complete", so it won't be counted as
			* conflict in a multi-primary setup. */
			req->i.completed = true;

			if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
				req->local_complete_ts = timestamp();
		}
		req->master_bio = NULL;
	}

	if (req->i.waiting)
		wake_up(&device->misc_wait);

	/* Either we are about to complete to upper layers,
	 * or we will restart this request.
	 * In either case, the request object will be destroyed soon,
	 * so better remove it from all lists. */
	list_del_init(&req->req_pending_master_completion);
}

/* still holds resource->req_lock */
static int bsr_req_put_completion_ref(struct bsr_request *req, struct bio_and_error *m, int put)
{
	D_ASSERT(req->device, m || (req->rq_state[0] & RQ_POSTPONED));
#ifdef BSR_TRACE
	if (put > 1) {
        bsr_debug(31, BSR_LC_REQUEST, NO_OBJECT,"(%s) completion_ref: put=%d !!!", current->comm, put);
	}
#endif
	if (!atomic_sub_and_test(put, &req->completion_ref))
	{
		// BSR-1072 log output if req->completion_ref is negative
		if (atomic_read(&req->completion_ref) < 0) {
			bsr_warn(32, BSR_LC_REQUEST, NO_OBJECT, "ASSERTION req->completion_ref (%d) < 0", atomic_read(&req->completion_ref));
		}
#ifdef BSR_TRACE
		bsr_debug(32, BSR_LC_REQUEST, NO_OBJECT,"(%s) completion_ref=%d. No complete req yet! sect=0x%llx sz=%d", current->comm, req->completion_ref, req->i.sector, req->i.size);
#endif
		return 0;
	}

	bsr_req_complete(req, m);

	if (req->rq_state[0] & RQ_POSTPONED) {
		/* don't destroy the req object just yet,
		 * but queue it for retry */
		bsr_restart_request(req);
		return 0;
	}
#ifdef BSR_TRACE
	bsr_debug(33, BSR_LC_REQUEST, NO_OBJECT,"sect=0x%llx sz=%d done!!!", req->i.sector, req->i.size);
#endif
	return 1;
}

static void set_if_null_req_next(struct bsr_peer_device *peer_device, struct bsr_request *req)
{
	struct bsr_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->todo.req_next == NULL)
		connection->todo.req_next = req;
}

static void advance_conn_req_next(struct bsr_peer_device *peer_device, struct bsr_request *req)
{
	struct bsr_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->todo.req_next != req)
		return;
	list_for_each_entry_continue_ex(struct bsr_request, req, &connection->resource->transfer_log, tl_requests) {
		const unsigned s = bsr_req_state_by_peer_device(req, peer_device);
		if (s & RQ_NET_QUEUED)
			break;
	}
	if (&req->tl_requests == &connection->resource->transfer_log)
		req = NULL;
	connection->todo.req_next = req;
}

static void set_if_null_req_ack_pending(struct bsr_peer_device *peer_device, struct bsr_request *req)
{
	struct bsr_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->req_ack_pending == NULL)
		connection->req_ack_pending = req;
}

static void advance_conn_req_ack_pending(struct bsr_peer_device *peer_device, struct bsr_request *req)
{
	struct bsr_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->req_ack_pending != req)
		return;
	list_for_each_entry_continue_ex(struct bsr_request, req, &connection->resource->transfer_log, tl_requests) {
		const unsigned s = bsr_req_state_by_peer_device(req, peer_device);
		if ((s & RQ_NET_SENT) && (s & RQ_NET_PENDING))
			break;
	}
	if (&req->tl_requests == &connection->resource->transfer_log)
		req = NULL;
	connection->req_ack_pending = req;
}

static void set_if_null_req_not_net_done(struct bsr_peer_device *peer_device, struct bsr_request *req)
{
	struct bsr_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->req_not_net_done == NULL)
		connection->req_not_net_done = req;
}

static void advance_conn_req_not_net_done(struct bsr_peer_device *peer_device, struct bsr_request *req)
{
	struct bsr_connection *connection = peer_device ? peer_device->connection : NULL;
	if (!connection)
		return;
	if (connection->req_not_net_done != req)
		return;
	list_for_each_entry_continue_ex(struct bsr_request, req, &connection->resource->transfer_log, tl_requests) {
		const unsigned s = bsr_req_state_by_peer_device(req, peer_device);
		if ((s & RQ_NET_SENT) && !(s & RQ_NET_DONE))
			break;
	}
	if (&req->tl_requests == &connection->resource->transfer_log)
		req = NULL;
	connection->req_not_net_done = req;
}

/* I'd like this to be the only place that manipulates
 * req->completion_ref and req->kref. */
static void mod_rq_state(struct bsr_request *req, struct bio_and_error *m,
		struct bsr_peer_device *peer_device,
		int clear, int set)
{
	unsigned old_net;
	unsigned old_local = req->rq_state[0];
	unsigned set_local = set & RQ_STATE_0_MASK;
	unsigned clear_local = clear & RQ_STATE_0_MASK;
	int c_put = 0;
	int k_put = 0;
	const int idx = peer_device ? 1 + peer_device->node_id : 0;
    struct bsr_device * device = req->device;

	/* FIXME n_connections, when this request was created/scheduled. */
	BUG_ON(idx > BSR_NODE_ID_MAX);
	BUG_ON(idx < 0);

	old_net = req->rq_state[idx];

	set &= ~RQ_STATE_0_MASK;
	clear &= ~RQ_STATE_0_MASK;

	// BSR-1021 exclude from local settings because only the peer node is set.
	set_local &= ~RQ_OOS_LOCAL_DONE;

	if (!idx) {
		/* do not try to manipulate net state bits
		 * without an associated state slot! */
		BUG_ON(set);
		BUG_ON(clear);
	}

	// DW-2042 When setting RQ_OOS_NET_QUEUED, RQ_OOS_PENDING shall be set.
#ifdef SPLIT_REQUEST_RESYNC
	if (peer_device && peer_device->connection->agreed_pro_version >= 113) {
		if ((set & RQ_OOS_NET_QUEUED) && !(req->rq_state[idx] & RQ_OOS_PENDING)) {
			return;
		}
	}
#endif

	if (bsr_suspended(req->device) && !((old_local | clear_local) & RQ_COMPLETION_SUSP))
		set_local |= RQ_COMPLETION_SUSP;

	/* apply */

	req->rq_state[0] &= ~clear_local;
	req->rq_state[0] |= set_local;

	req->rq_state[idx] &= ~clear;
	req->rq_state[idx] |= set;

	/* no change? */
	if (req->rq_state[0] == old_local && req->rq_state[idx] == old_net)
		return;

	// BSR-1021 
	if (!(old_net & RQ_OOS_LOCAL_DONE) && (set & RQ_OOS_LOCAL_DONE)) {
		bsr_set_out_of_sync(peer_device, req->i.sector, req->i.size);
		return;
	}

	/* intent: get references */

	if (!(old_local & RQ_LOCAL_PENDING) && (set_local & RQ_LOCAL_PENDING))
		atomic_inc(&req->completion_ref);

	if (!(old_net & RQ_NET_PENDING) && (set & RQ_NET_PENDING)) {
		// DW-2058 inc rq_pending_oos_cnt
#ifdef SPLIT_REQUEST_RESYNC
		if (peer_device->connection->agreed_pro_version >= 113) {
			if (set & RQ_OOS_PENDING) {
				atomic_inc(&peer_device->rq_pending_oos_cnt);
			}
		}
#endif
		inc_ap_pending(peer_device);
		atomic_inc(&req->completion_ref);
	}

	if (!(old_net & RQ_NET_QUEUED) && (set & RQ_NET_QUEUED)) {
		atomic_inc(&req->completion_ref);
		
#ifdef NETQUEUED_LOG
		if(atomic_inc_return(&req->nq_ref) == 1) {
			list_add_tail(&req->nq_requests, &req->device->resource->net_queued_log);
		}
#endif
		set_if_null_req_next(peer_device, req);
	}

	if (!(old_net & RQ_EXP_BARR_ACK) && (set & RQ_EXP_BARR_ACK))
		kref_get(&req->kref); /* wait for the DONE */

	if (!(old_net & RQ_NET_SENT) && (set & RQ_NET_SENT)) {
		/* potentially already completed in the ack_receiver thread */
		if (!(old_net & RQ_NET_DONE)) {
			// BSR-839
			add_ap_in_flight(req->i.size, peer_device->connection);
			
			set_if_null_req_not_net_done(peer_device, req);

			// DW-1961
			if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
				req->net_sent_ts[peer_device->node_id] = timestamp();
		}
		if (req->rq_state[idx] & RQ_NET_PENDING)
			set_if_null_req_ack_pending(peer_device, req);
	}

	if (!(old_local & RQ_COMPLETION_SUSP) && (set_local & RQ_COMPLETION_SUSP))
		atomic_inc(&req->completion_ref);

	/* progress: put references */

	if ((old_local & RQ_COMPLETION_SUSP) && (clear_local & RQ_COMPLETION_SUSP))
		++c_put;

	if (!(old_local & RQ_LOCAL_ABORTED) && (set_local & RQ_LOCAL_ABORTED)) {
		D_ASSERT(device, req->rq_state[0] & RQ_LOCAL_PENDING);
		/* local completion may still come in later,
		 * we need to keep the req object around. */
		kref_get(&req->kref);
		++c_put;
	}

	if ((old_local & RQ_LOCAL_PENDING) && (clear_local & RQ_LOCAL_PENDING)) {
		if (req->rq_state[0] & RQ_LOCAL_ABORTED)
			++k_put;
		else
			++c_put;
		list_del_init(&req->req_pending_local);
	}

	// DW-1237 Local I/O has been completed, put request databuf ref. 
	if (!(old_local & RQ_LOCAL_COMPLETED) && (set_local & RQ_LOCAL_COMPLETED)) {
		if (0 == atomic_dec_return(&req->req_databuf_ref) && req->req_databuf) {
			bsr_free_accelbuf(req->device, req->req_databuf, req->bio_status.size);
			req->req_databuf = NULL;
		}
	}

	if ((old_net & RQ_NET_PENDING) && (clear & RQ_NET_PENDING)) {
		dec_ap_pending(peer_device);
		++c_put;
		if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
			ktime_get_accounting(req->acked_kt[peer_device->node_id]);
		advance_conn_req_ack_pending(peer_device, req);
	}

	if ((old_net & RQ_NET_QUEUED) && (clear & RQ_NET_QUEUED)) {
		++c_put;

#ifdef NETQUEUED_LOG
		if (atomic_dec_return(&req->nq_ref) == 0) {
			list_del_init(&req->nq_requests);
		}
#endif
		advance_conn_req_next(peer_device, req);
	}

	if (!(old_net & RQ_NET_DONE) && (set & RQ_NET_DONE)) {
#ifdef SPLIT_REQUEST_RESYNC
		if (peer_device && peer_device->connection->agreed_pro_version >= 113) {
			if (old_net & (RQ_OOS_NET_QUEUED | RQ_OOS_PENDING)) {
				// DW-2076 
				atomic_dec(&peer_device->rq_pending_oos_cnt);
				// BSR-842
				if (peer_device && peer_device->connection->agreed_pro_version >= 115) {
					if (peer_device->repl_state[NOW] == L_SYNC_SOURCE && atomic_read(&peer_device->rq_pending_oos_cnt) == 0) {
						struct bsr_oos_no_req* send_oos = bsr_kmalloc(sizeof(struct bsr_oos_no_req), 0, 'OSSB');
						unsigned long flags;

						if (send_oos) {
							INIT_LIST_HEAD(&send_oos->oos_list_head);
							send_oos->sector = ID_OUT_OF_SYNC_FINISHED;
							spin_lock_irqsave(&peer_device->send_oos_lock, flags);
							list_add_tail(&send_oos->oos_list_head, &peer_device->send_oos_list);
							spin_unlock_irqrestore(&peer_device->send_oos_lock, flags);
							queue_work(peer_device->connection->ack_sender, &peer_device->send_oos_work);
						}
						else {
							bsr_err(94, BSR_LC_MEMORY, peer_device, "Failed to send out of sync due to failure to allocate memory so dropping connection.");
							change_cstate_ex(peer_device->connection, C_DISCONNECTING, CS_HARD);
						}
					}
				}
			}
		}
#endif
		if (old_net & RQ_NET_SENT) {
			// BSR-839
			sub_ap_in_flight(req->i.size, peer_device->connection);

			// DW-1961 Calculate and Log IO Latency
			if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY)) {
				req->net_done_ts[peer_device->node_id] = timestamp();
				bsr_debug(4, BSR_LC_LATENCY, peer_device, "req(%p) NET latency : in_act(%d) node_id(%u) prpl(%s) type(%s) sector(%llu) size(%u) net(%lldus)",
					req, req->do_submit, peer_device->node_id, bsr_repl_str((peer_device)->repl_state[NOW]), (req->rq_state[0] & RQ_WRITE) ? "write" : "read",
					req->i.sector, req->i.size, timestamp_elapse(__FUNCTION__, req->net_sent_ts[peer_device->node_id], req->net_done_ts[peer_device->node_id]));
			}
		}

		if (old_net & RQ_EXP_BARR_ACK)
			++k_put;

		if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
			ktime_get_accounting(req->net_done_kt[peer_device->node_id]);

		/* in ahead/behind mode, or just in case,
		 * before we finally destroy this request,
		 * the caching pointers must not reference it anymore */
		advance_conn_req_next(peer_device, req);
		advance_conn_req_ack_pending(peer_device, req);
		advance_conn_req_not_net_done(peer_device, req);
	}

	/* potentially complete and destroy */

	if (k_put || c_put) {
		/* Completion does it's own kref_put.  If we are going to
		 * kref_sub below, we need req to be still around then. */
		int at_least = k_put + !!c_put;
		int refcount = refcount_read(&req->kref.refcount);
		
		if (refcount < at_least)
			bsr_err(18, BSR_LC_REQUEST, device,
            "request state modify Logic BUG. 0: state(%x -> %x), idx %d state(%x -> %x), refcount = %d, should be >= %d",
            old_local, req->rq_state[0],
            idx, old_net, req->rq_state[idx],
            refcount, at_least);
	}

	/* If we made progress, retry conflicting peer requests, if any. */
	if (req->i.waiting)
		wake_up(&req->device->misc_wait);

	if (c_put)
		k_put += bsr_req_put_completion_ref(req, m, c_put);
	if (k_put)
		kref_sub(&req->kref, k_put, bsr_req_destroy);
}

static void bsr_report_io_error(struct bsr_device *device, struct bsr_request *req)
{
#ifdef COMPAT_HAVE_BDEVNAME
	char b[BDEVNAME_SIZE];
#endif
	// DW-1755 Counts the error value only when it is a passthrough policy.
	// Only the first error is logged.
	bool write_log = true;

	if (atomic_read(&device->io_error_count) < INT32_MAX) {
		if (atomic_inc_return(&device->io_error_count) > 1)
			write_log = true;
	}
	if (!bsr_ratelimit())
		write_log = false;

	if (write_log) {
#if defined(_WIN) || defined(COMPAT_HAVE_BDEVNAME) 
		bsr_warn(10, BSR_LC_IO_ERROR, device, "local %s IO error sector %llu+%u on %s",
			(req->rq_state[0] & RQ_WRITE) ? "WRITE" : "READ",
			(unsigned long long)req->i.sector,
			req->i.size >> 9,
			bdevname(device->ldev->backing_bdev, b));
#else
		bsr_warn(10, BSR_LC_IO_ERROR, device, "local %s IO error sector %llu+%u on %pg",
			(req->rq_state[0] & RQ_WRITE) ? "WRITE" : "READ",
			(unsigned long long)req->i.sector,
			req->i.size >> 9,
			device->ldev->backing_bdev);
#endif

	}
}

/* Helper for HANDED_OVER_TO_NETWORK.
 * Is this a protocol A write (neither WRITE_ACK nor RECEIVE_ACK expected)?
 * Is it also still "PENDING"?
 * --> If so, clear PENDING and set NET_OK below.
 * If it is a protocol A write, but not RQ_PENDING anymore, neg-ack was faster
 * (and we must not set RQ_NET_OK) */
static inline bool is_pending_write_protocol_A(struct bsr_request *req, int idx)
{
	return (req->rq_state[0] & RQ_WRITE) == 0 ? 0 :
		(req->rq_state[idx] &
		   (RQ_NET_PENDING|RQ_EXP_WRITE_ACK|RQ_EXP_RECEIVE_ACK))
		==  RQ_NET_PENDING;
}

/* obviously this could be coded as many single functions
 * instead of one huge switch,
 * or by putting the code directly in the respective locations
 * (as it has been before).
 *
 * but having it this way
 *  enforces that it is all in this one place, where it is easier to audit,
 *  it makes it obvious that whatever "event" "happens" to a request should
 *  happen "atomically" within the req_lock,
 *  and it enforces that we have to think in a very structured manner
 *  about the "events" that may happen to a request during its life time ...
 *
 *
 * peer_device == NULL means local disk
 */
int __req_mod(struct bsr_request *req, enum bsr_req_event what,
		struct bsr_peer_device *peer_device,
		struct bio_and_error *m)
{
	struct bsr_device *device = req->device;
	struct net_conf *nc;
	unsigned int p = 0;
	int idx, rv = 0;

	if (m)
		m->bio = NULL;

	idx = peer_device ? 1 + peer_device->node_id : 0;

	switch (what) {
	default:
		bsr_err(19, BSR_LC_REQUEST, device, "Failed to modify requst status due to logic bug. event(%d)", what);
		break;

	/* does not happen...
	 * initialization done in bsr_req_new
	case CREATED:
		break;
		*/

	case TO_BE_SENT: /* via network */
		/* reached via __bsr_make_request
		 * and from w_read_retry_remote */
		D_ASSERT(device, idx && !(req->rq_state[idx] & RQ_NET_MASK));
		rcu_read_lock();
		if (peer_device && peer_device->connection) {
			nc = rcu_dereference(peer_device->connection->transport.net_conf);
			p = nc->wire_protocol;
		}
		rcu_read_unlock();
		
		req->rq_state[idx] |=
			p == BSR_PROT_C ? RQ_EXP_WRITE_ACK :
			p == BSR_PROT_B ? RQ_EXP_RECEIVE_ACK : 0;
		mod_rq_state(req, m, peer_device, 0, RQ_NET_PENDING);
		break;

	case TO_BE_SUBMITTED: /* locally */
		/* reached via __bsr_make_request */
		D_ASSERT(device, !(req->rq_state[0] & RQ_LOCAL_MASK));
		mod_rq_state(req, m, peer_device, 0, RQ_LOCAL_PENDING);
		break;

	case COMPLETED_OK:
		if (req->rq_state[0] & RQ_WRITE)
			device->writ_cnt += req->i.size >> 9;
		else
			device->read_cnt += req->i.size >> 9;

		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING,
				RQ_LOCAL_COMPLETED|RQ_LOCAL_OK);
		break;

	case ABORT_DISK_IO:
		mod_rq_state(req, m, peer_device, 0, RQ_LOCAL_ABORTED);
		break;

	case WRITE_COMPLETED_WITH_ERROR:
		bsr_report_io_error(device, req);
		__bsr_chk_io_error(device, BSR_WRITE_ERROR);
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case READ_COMPLETED_WITH_ERROR:
		bsr_set_all_out_of_sync(device, req->i.sector, req->i.size);
		bsr_report_io_error(device, req);
		__bsr_chk_io_error(device, BSR_READ_ERROR);
		/* Fall through */
	case READ_AHEAD_COMPLETED_WITH_ERROR:
		/* it is legal to fail read-ahead, no __bsr_chk_io_error in that case. */
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case DISCARD_COMPLETED_NOTSUPP:
	case DISCARD_COMPLETED_WITH_ERROR:
		/* I'd rather not detach from local disk just because it
		 * failed a REQ_DISCARD. */
		mod_rq_state(req, m, peer_device, RQ_LOCAL_PENDING, RQ_LOCAL_COMPLETED);
		break;

	case QUEUE_FOR_NET_READ:
		/* READ, and
		 * no local disk,
		 * or target area marked as invalid,
		 * or just got an io-error. */
		/* from __bsr_make_request
		 * or from bio_endio during read io-error recovery */

		/* So we can verify the handle in the answer packet.
		 * Corresponding bsr_remove_request_interval is in
		 * bsr_req_complete() */
		D_ASSERT(device, bsr_interval_empty(&req->i));
		bsr_insert_interval(&device->read_requests, &req->i);

		set_bit(UNPLUG_REMOTE, &device->flags);

		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		D_ASSERT(device, (req->rq_state[0] & RQ_LOCAL_MASK) == 0);
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED);
		break;

	case QUEUE_FOR_NET_WRITE:
		/* assert something? */
		/* from __bsr_make_request only */

		/* NOTE
		 * In case the req ended up on the transfer log before being
		 * queued on the worker, it could lead to this request being
		 * missed during cleanup after connection loss.
		 * So we have to do both operations here,
		 * within the same lock that protects the transfer log.
		 *
		 * _req_add_to_epoch(req); this has to be after the
		 * _maybe_start_new_epoch(req); which happened in
		 * __bsr_make_request, because we now may set the bit
		 * again ourselves to close the current epoch.
		 *
		 * Add req to the (now) current epoch (barrier). */

		/* otherwise we may lose an unplug, which may cause some remote
		 * io-scheduler timeout to expire, increasing maximum latency,
		 * hurting performance. */
		set_bit(UNPLUG_REMOTE, &device->flags);

		/* queue work item to send data */
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED|RQ_EXP_BARR_ACK);

		/* close the epoch, in case it outgrew the limit */
#ifdef _WIN
		rcu_read_lock_w32_inner();
#else // LIN
		rcu_read_lock();
#endif
		if (peer_device && peer_device->connection) {
			nc = rcu_dereference(peer_device->connection->transport.net_conf);
			p = nc->max_epoch_size;
		}
		rcu_read_unlock();
		if (device->resource->current_tle_writes >= p)
			start_new_tl_epoch(device->resource);
		break;

#ifdef SPLIT_REQUEST_RESYNC
	case QUEUE_FOR_PENDING_OOS:
		mod_rq_state(req, m, peer_device, 0, RQ_OOS_PENDING|RQ_NET_PENDING);
		break;
#endif

	case QUEUE_FOR_SEND_OOS:
#ifdef SPLIT_REQUEST_RESYNC
		mod_rq_state(req, m, peer_device, RQ_OOS_PENDING|RQ_NET_PENDING, RQ_OOS_NET_QUEUED | RQ_NET_QUEUED);
#else
		mod_rq_state(req, m, peer_device, 0, RQ_NET_QUEUED);
#endif
		break;

	case READ_RETRY_REMOTE_CANCELED:
	case SEND_CANCELED:
	case SEND_FAILED:
		/* real cleanup will be done from tl_clear.  just update flags
		 * so it is no longer marked as on the sender queue */
		mod_rq_state(req, m, peer_device, RQ_NET_QUEUED, 0);
		break;

	case HANDED_OVER_TO_NETWORK:
		/* assert something? */
		if (is_pending_write_protocol_A(req, idx))
			/* this is what is dangerous about protocol A:
			 * pretend it was successfully written on the peer. */
			mod_rq_state(req, m, peer_device, RQ_NET_QUEUED|RQ_NET_PENDING,
				     RQ_NET_SENT|RQ_NET_OK);
		else
			mod_rq_state(req, m, peer_device, RQ_NET_QUEUED, RQ_NET_SENT);
		/* It is still not yet RQ_NET_DONE until the
		 * corresponding epoch barrier got acked as well,
		 * so we know what to dirty on connection loss. */
		break;

	case OOS_HANDED_TO_NETWORK:
		/* Was not set PENDING, no longer QUEUED, so is now DONE
		 * as far as this connection is concerned. */
		mod_rq_state(req, m, peer_device, RQ_NET_QUEUED, RQ_NET_DONE);
		break;

	case CONNECTION_LOST_WHILE_PENDING:
		/* transfer log cleanup after connection loss */
		mod_rq_state(req, m, peer_device,
				RQ_NET_OK|RQ_NET_PENDING|RQ_COMPLETION_SUSP,
				RQ_NET_DONE);
		break;

	case DISCARD_WRITE:
		/* for discarded conflicting writes of multiple primaries,
		 * there is no need to keep anything in the tl, potential
		 * node crashes are covered by the activity log.
		 *
		 * If this request had been marked as RQ_POSTPONED before,
		 * it will actually not be discarded, but "restarted",
		 * resubmitted from the retry worker context. */
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		D_ASSERT(device, req->rq_state[idx] & RQ_EXP_WRITE_ACK);
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_DONE|RQ_NET_OK);
		break;

	case WRITE_ACKED_BY_PEER_AND_SIS:
		req->rq_state[idx] |= RQ_NET_SIS;
	case WRITE_ACKED_BY_PEER:
		/* Normal operation protocol C: successfully written on peer.
		 * During resync, even in protocol != C,
		 * we requested an explicit write ack anyways.
		 * Which means we cannot even assert anything here.
		 * Nothing more to do here.
		 * We want to keep the tl in place for all protocols, to cater
		 * for volatile write-back caches on lower level devices. */
		goto ack_common;
	case RECV_ACKED_BY_PEER:
		D_ASSERT(device, req->rq_state[idx] & RQ_EXP_RECEIVE_ACK);
		/* protocol B; pretends to be successfully written on peer.
		 * see also notes above in HANDED_OVER_TO_NETWORK about
		 * protocol != C */
	ack_common:
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK);
		break;

	case POSTPONE_WRITE:
		D_ASSERT(device, req->rq_state[idx] & RQ_EXP_WRITE_ACK);
		/* If this node has already detected the write conflict, the
		 * worker will be waiting on misc_wait.  Wake it up once this
		 * request has completed locally.
		 */
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		req->rq_state[0] |= RQ_POSTPONED;
		if (req->i.waiting)
			wake_up(&req->device->misc_wait);
		/* Do not clear RQ_NET_PENDING. This request will make further
		 * progress via restart_conflicting_writes() or
		 * fail_postponed_requests(). Hopefully. */
		break;

	case NEG_ACKED:
		mod_rq_state(req, m, peer_device, RQ_NET_OK|RQ_NET_PENDING, RQ_NET_DONE);
		break;

	case FAIL_FROZEN_DISK_IO:
		if (!(req->rq_state[0] & RQ_LOCAL_COMPLETED))
			break;
		mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP, 0);
		break;

	case RESTART_FROZEN_DISK_IO:
#if 0
		/* FIXME; do we need a (temporary) dedicated thread for this? */
		if (!(req->rq_state[0] & RQ_LOCAL_COMPLETED))
			break;

		mod_rq_state(req, m, peer_device,
				RQ_COMPLETION_SUSP|RQ_LOCAL_COMPLETED,
				RQ_LOCAL_PENDING);

		rv = MR_READ;
		if (bio_data_dir(req->master_bio) == WRITE)
			rv = MR_WRITE;

		get_ldev(device); /* always succeeds in this call path */
		req->w.cb = w_restart_disk_io;
		bsr_queue_work(&device->resource->work, &req->w);
		break;
#else
		BUG(); /* FIXME */
		break;
#endif

	case RESEND:
		/* Simply complete (local only) READs. */
		if (!(req->rq_state[0] & RQ_WRITE) && !(req->rq_state[idx] & RQ_NET_MASK)) {
			mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP, 0);
			break;
		}

		/* If RQ_NET_OK is already set, we got a P_WRITE_ACK or P_RECV_ACK
		   before the connection loss (B&C only); only P_BARRIER_ACK
		   (or the local completion?) was missing when we suspended.
		   Throwing them out of the TL here by pretending we got a BARRIER_ACK.
		   During connection handshake, we ensure that the peer was not rebooted.

		   Resending is only allowed on synchronous connections,
		   where all requests not yet completed to upper layers whould
		   be in the same "reorder-domain", there can not possibly be
		   any dependency between incomplete requests, and we are
		   allowed to complete this one "out-of-sequence".
		 */
		if (!(req->rq_state[idx] & RQ_NET_OK)) {
			mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP,
					RQ_NET_QUEUED|RQ_NET_PENDING);
			break;
		}
		/* else, fall through to BARRIER_ACKED */
		/* Fall through */
	case BARRIER_ACKED:
		/* barrier ack for READ requests does not make sense */
		if (!(req->rq_state[0] & RQ_WRITE))
			break;

		if (req->rq_state[idx] & RQ_NET_PENDING) {
			/* barrier came in before all requests were acked.
			 * this is bad, because if the connection is lost now,
			 * we won't be able to clean them up... */
			bsr_err(20, BSR_LC_REQUEST, device, "FIXME, barrier came in before all requests were acked.");
			mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK);
		}
		/* Allowed to complete requests, even while suspended.
		 * As this is called for all requests within a matching epoch,
		 * we need to filter, and only set RQ_NET_DONE for those that
		 * have actually been on the wire. */
		mod_rq_state(req, m, peer_device, RQ_COMPLETION_SUSP,
				(req->rq_state[idx] & RQ_NET_MASK) ? RQ_NET_DONE : 0);
		break;

	case DATA_RECEIVED:
		D_ASSERT(device, req->rq_state[idx] & RQ_NET_PENDING);
		mod_rq_state(req, m, peer_device, RQ_NET_PENDING, RQ_NET_OK|RQ_NET_DONE);
		break;

	case QUEUE_AS_BSR_BARRIER:
		start_new_tl_epoch(device->resource);
		for_each_peer_device(peer_device, device)
			mod_rq_state(req, m, peer_device, 0, RQ_NET_OK|RQ_NET_DONE);
		break;

		// BSR-1021
	case OOS_SET_TO_LOCAL:
		mod_rq_state(req, m, peer_device, 0, RQ_OOS_LOCAL_DONE);
		break;
	};

	return rv;
}

/* we may do a local read if:
 * - we are consistent (of course),
 * - or we are generally inconsistent,
 *   BUT we are still/already IN SYNC with all peers for this area.
 *   since size may be bigger than BM_BLOCK_SIZE,
 *   we may need to check several bits.
 */
static bool bsr_may_do_local_read(struct bsr_device *device, sector_t sector, int size)
{
	struct bsr_md *md = &device->ldev->md;
	unsigned int node_id;
    ULONG_PTR sbnr, ebnr;
	sector_t esector, nr_sectors;

	if (device->disk_state[NOW] == D_UP_TO_DATE)
		return true;
#ifdef _WIN // DW-643 FsctlLockVolume fail problem.
	else if (device->disk_state[NOW] == D_OUTDATED)
		return true;
#endif
	if (device->disk_state[NOW] != D_INCONSISTENT)
		return false;
	esector = sector + (size >> 9) - 1;
	nr_sectors = bsr_get_vdisk_capacity(device);
	D_ASSERT(device, sector  < nr_sectors);
	D_ASSERT(device, esector < nr_sectors);

	sbnr = (ULONG_PTR)BM_SECT_TO_BIT(sector);
	ebnr = (ULONG_PTR)BM_SECT_TO_BIT(esector);

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		struct bsr_peer_md *peer_md = &md->peers[node_id];

		/* Skip bitmap indexes which are not assigned to a peer. */
		if (peer_md->bitmap_index == -1)
			continue;

		if (bsr_bm_count_bits(device, peer_md->bitmap_index, sbnr, ebnr))
			return false;
	}
	return true;
}

/* TODO improve for more than one peer.
 * also take into account the bsr protocol. */
static bool remote_due_to_read_balancing(struct bsr_device *device,
		struct bsr_peer_device *peer_device, sector_t sector,
		enum bsr_read_balancing rbm)
{
#ifdef _LIN
#ifdef COMPAT_HAVE_BDI_CONGESTED_FN
	struct backing_dev_info *bdi;
#endif
#endif
	int stripe_shift;

	switch (rbm) {
	case RB_CONGESTED_REMOTE:
#ifdef _WIN
		// not support
		return false;
#else // _LIN
// BSR-1095
#ifdef COMPAT_HAVE_BDI_CONGESTED_FN
#ifdef COMPAT_STRUCT_GENDISK_HAS_BACKING_DEV_INFO
		return bdi_read_congested(device->ldev->backing_bdev->bd_disk->bdi);
#else 
		bdi = bdi_from_device(device);
		return bdi_read_congested(bdi);
#endif
#else
		return false;
#endif
#endif
	case RB_LEAST_PENDING:
		return atomic_read(&device->local_cnt) >
			atomic_read(&peer_device->ap_pending_cnt) + atomic_read(&peer_device->rs_pending_cnt);
	case RB_32K_STRIPING:  /* stripe_shift = 15 */
	case RB_64K_STRIPING:
	case RB_128K_STRIPING:
	case RB_256K_STRIPING:
	case RB_512K_STRIPING:
	case RB_1M_STRIPING:   /* stripe_shift = 20 */
		stripe_shift = (rbm - RB_32K_STRIPING + 15);
		return (sector >> (stripe_shift - 9)) & 1;
	case RB_ROUND_ROBIN:
		return test_and_change_bit(READ_BALANCE_RR, &device->flags);
	case RB_PREFER_REMOTE:
		return true;
	case RB_PREFER_LOCAL:
	default:
		return false;
	}
}

/*
 * complete_conflicting_writes  -  wait for any conflicting write requests
 *
 * The write_requests tree contains all active write requests which we
 * currently know about.  Wait for any requests to complete which conflict with
 * the new one.
 *
 * Only way out: remove the conflicting intervals from the tree.
 */
static void complete_conflicting_writes(struct bsr_request *req)
{
	DEFINE_WAIT(wait);
	struct bsr_device *device = req->device;
	struct bsr_interval *i;
	sector_t sector = req->i.sector;
	int size = req->i.size;

	for (;;) {
		bsr_for_each_overlap(i, &device->write_requests, sector, size) {
			/* Ignore, if already completed to upper layers. */
			if (i->completed)
				continue;
			/* Handle the first found overlap.  After the schedule
			 * we have to restart the tree walk. */
			break;
		}
		if (!i)	/* if any */
			break;

		/* Indicate to wake up device->misc_wait on progress.  */
		prepare_to_wait(&device->misc_wait, &wait, TASK_UNINTERRUPTIBLE);
		i->waiting = true;
		spin_unlock_irq(&device->resource->req_lock);
#ifdef _WIN
		schedule(&device->misc_wait, MAX_SCHEDULE_TIMEOUT, __FUNCTION__, __LINE__);
#else // _LIN
		schedule();
#endif
		spin_lock_irq(&device->resource->req_lock);
	}
	finish_wait(&device->misc_wait, &wait);
}

extern atomic_t g_fake_al_used;

/* called within req_lock and rcu_read_lock() */
static void __maybe_pull_ahead(struct bsr_device *device, struct bsr_connection *connection)
{
	struct net_conf *nc;
	bool congested = false;
	enum bsr_on_congestion on_congestion;
	struct bsr_peer_device *peer_device = conn_peer_device(connection, device->vnr);

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	on_congestion = nc ? nc->on_congestion : OC_BLOCK;
	rcu_read_unlock();
	if (on_congestion == OC_BLOCK ||
		// DW-1204 peer is already disconnected, no pull ahead
		connection->cstate[NOW] < C_CONNECTED ||
	    connection->agreed_pro_version < 96)
		return;

	if (on_congestion == OC_PULL_AHEAD && peer_device->repl_state[NOW] == L_AHEAD)
		return; /* nothing to do ... */

	/* If I don't even have good local storage, we can not reasonably try
	 * to pull ahead of the peer. We also need the local reference to make
	 * sure device->act_log is there.
	 */
	if (!get_ldev_if_state(device, D_UP_TO_DATE))
		return;

	if (nc->cong_fill) {
		// DW-1817 
		//To accurately check when to enter AHEAD mode, you should consider the size of the synchronization data in the send buffer.
		__u64 total_in_flight = atomic_read64(&connection->ap_in_flight) + atomic_read64(&connection->rs_in_flight);
		if (total_in_flight >= nc->cong_fill) {
			bsr_info(20, BSR_LC_REPLICATION, device, "Congestion-fill threshold reached %lluKB", total_in_flight >> 10);
			congested = true;
		}
	}

	// BSR-839 implement congestion-highwater
	// congestion detection based on the number of in_flight data
	if (nc->cong_highwater) {
		unsigned int total_in_flight_cnt = atomic_read(&connection->ap_in_flight_cnt) + atomic_read(&connection->rs_in_flight_cnt);
		if (total_in_flight_cnt >= nc->cong_highwater) {
			bsr_info(32, BSR_LC_REPLICATION, device, "Congestion-highwater threshold reached %u", total_in_flight_cnt);
			congested = true;
		}
	}


	if ((device->act_log->used + atomic_read(&g_fake_al_used)) >= nc->cong_extents) {
		bsr_info(13, BSR_LC_LRU, device, "Congestion-extents threshold reached");
		congested = true;
	}

	if (congested) {
		struct bsr_resource *resource = device->resource;

		/* start a new epoch for non-mirrored writes */
		start_new_tl_epoch(resource);
		begin_state_change_locked(resource, CS_VERBOSE | CS_HARD);
		if (on_congestion == OC_PULL_AHEAD) {
			// BSR-1041 clear AHEAD_TO_SYNC_SOURCE that may have been set in the previous congestion before setting the congestion state.
			if (peer_device->repl_state[NOW] == L_SYNC_SOURCE) 
				clear_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags);
			__change_repl_state_and_auto_cstate(peer_device, L_AHEAD, __FUNCTION__);
		}
		else			/* on_congestion == OC_DISCONNECT */
			__change_cstate(peer_device->connection, C_DISCONNECTING);
		end_state_change_locked(resource, false, __FUNCTION__);
	}
	put_ldev(__FUNCTION__, device);
}

/* called within req_lock */
static void maybe_pull_ahead(struct bsr_device *device)
{
	struct bsr_connection *connection;

	for_each_connection(connection, device->resource)
		__maybe_pull_ahead(device, connection);
}

bool bsr_should_do_remote(struct bsr_peer_device *peer_device, enum which_state which)
{
	enum bsr_disk_state peer_disk_state = peer_device->disk_state[which];
	enum bsr_repl_state repl_state = peer_device->repl_state[which];

	return peer_disk_state == D_UP_TO_DATE ||	
		// BSR-660
		repl_state == L_STARTING_SYNC_S ||
		// DW-1979 add bsr_should_do-remote() allowed state
		repl_state == L_WF_BITMAP_S ||
		(peer_disk_state == D_INCONSISTENT &&
		(repl_state == L_ESTABLISHED ||
		(repl_state >= L_WF_BITMAP_T && repl_state < L_AHEAD)));
	/* Before proto 96 that was >= CONNECTED instead of >= L_WF_BITMAP_T.
	That is equivalent since before 96 IO was frozen in the L_WF_BITMAP*
	states. */
}

static bool bsr_should_send_out_of_sync(struct bsr_peer_device *peer_device)
{
	return peer_device->repl_state[NOW] == L_AHEAD;
	// DW-2058 modify DW-1979 to remove the L_WF_BITMAPS_S condition
	// || peer_device->repl_state[NOW] == L_WF_BITMAP_S;
	/* pdsk = D_INCONSISTENT as a consequence. Protocol 96 check not necessary
	   since we enter state L_AHEAD only if proto >= 96 */
}

/* If this returns NULL, and req->private_bio is still set,
 * the request should be submitted locally.
 *
 * If it returns NULL, but req->private_bio is not set,
 * we do not have access to good data :(
 *
 * Otherwise, this destroys req->private_bio, if any,
 * and returns the peer device which should be asked for data.
 */
static struct bsr_peer_device *find_peer_device_for_read(struct bsr_request *req)
{
	struct bsr_peer_device *peer_device;
	struct bsr_device *device = req->device;
	enum bsr_read_balancing rbm = RB_PREFER_REMOTE;

	if (req->private_bio) {
		if (!bsr_may_do_local_read(device,
					req->i.sector, req->i.size)) {
			bio_put(req->private_bio);
			req->private_bio = NULL;
			put_ldev(__FUNCTION__, device);
		}
	}

	if (device->disk_state[NOW] > D_DISKLESS) {
		rcu_read_lock();
		rbm = rcu_dereference(device->ldev->disk_conf)->read_balancing;
		rcu_read_unlock();
		if (rbm == RB_PREFER_LOCAL && req->private_bio) {
			return NULL; /* submit locally */
		}
	}

	/* TODO: improve read balancing decisions, take into account bsr
	 * protocol, all peers, pending requests etc. */

	for_each_peer_device(peer_device, device) {
		if (peer_device->disk_state[NOW] != D_UP_TO_DATE)
			continue;
		if (req->private_bio == NULL ||
		    remote_due_to_read_balancing(device, peer_device,
						 req->i.sector, rbm)) {
			goto found;
		}
	}
	peer_device = NULL;

    found:
	if (peer_device && req->private_bio) {
		bio_put(req->private_bio);
		req->private_bio = NULL;
		put_ldev(__FUNCTION__, device);
	}
	return peer_device;
}

/* returns the number of connections expected to actually write this data,
 * which does NOT include those that we are L_AHEAD for. */
static int bsr_process_write_request(struct bsr_request *req, bool *all_prot_a)
{
	struct bsr_device *device = req->device;
	struct bsr_peer_device *peer_device;
	bool in_tree = false;
	int remote, send_oos;
	int count = 0;

	*all_prot_a = true;

	for_each_peer_device(peer_device, device) {
		remote = bsr_should_do_remote(peer_device, NOW);
		send_oos = bsr_should_send_out_of_sync(peer_device);

#ifdef _DEBUG_OOS
		// DW-1153 Write log when process I/O
		bsr_debug(6, BSR_LC_OUT_OF_SYNC, NO_OBJECT, "["OOS_TRACE_STRING"] pnode-id(%d), bitmap_index(%d) req(%p), remote(%d), send_oos(%d), sector(%lu ~ %lu)",
			peer_device->node_id, peer_device->bitmap_index, req, remote, send_oos, req->i.sector, req->i.sector + (req->i.size / 512));
#endif
		if (!remote && !send_oos) {
			// BSR-1021 unconnected nodes set out of sync for the request area.
			// BSR-1046 set OOS only when peer_device->bitmap_index is set.
			if ((peer_device->bitmap_index != -1) &&
				(peer_device->connection->cstate[NOW] != C_CONNECTED))
				_req_mod(req, OOS_SET_TO_LOCAL, peer_device);
			continue;
		}

		D_ASSERT(device, !(remote && send_oos));

		if (remote) {
			u32 prot;
			rcu_read_lock();
			prot = rcu_dereference(peer_device->connection->transport.net_conf)->wire_protocol;
			rcu_read_unlock();

			if (prot != BSR_PROT_A)
				*all_prot_a = false;

			++count;
			// DW-1237 get request databuf ref to send data block.
			atomic_inc(&req->req_databuf_ref);
			_req_mod(req, TO_BE_SENT, peer_device);
			if (!in_tree) {
				/* Corresponding bsr_remove_request_interval is in
				 * bsr_req_complete() */
				bsr_insert_interval(&device->write_requests, &req->i);
				in_tree = true;
			}
			_req_mod(req, QUEUE_FOR_NET_WRITE, peer_device);
		}
#ifdef SPLIT_REQUEST_RESYNC
		else {
			ULONG_PTR c = bsr_set_out_of_sync(peer_device, req->i.sector, req->i.size);

			if (peer_device->connection->agreed_pro_version >= 113) {
				// DW-2091 send all out of snyc regardless of redundancy.
				// the downside is that if out of sync continues to occur in the same area, it will transmit more than before.
				// out of sync is sent after the writing is complete and the consistency issues are resolved by separating old and new oos from synctarget to resync_pending.

				// DW-2042 set QUEUE_FOR_SEND_OOS after completion of writing and send QUEUE_FOR_PENDING_OOS. For transmission, QUEUE_FOR_PENDING_OOS must be set before setting QUEUE_FOR_SEND_OOS.
				_req_mod(req, QUEUE_FOR_PENDING_OOS, peer_device);
			}
			else {
				// BSR-1039 send OOS to the node to be set up on AL OOS.
				if (c || (req->rq_state[peer_device->node_id + 1] & RQ_IN_AL_OOS)) {
					_req_mod(req, QUEUE_FOR_SEND_OOS, peer_device);
				}
			}
		}
#else
		else if (bsr_set_out_of_sync(peer_device, req->i.sector, req->i.size)) {
			_req_mod(req, QUEUE_FOR_SEND_OOS, peer_device);
		}
#endif
	}

	return count;
}

static void bsr_process_discard_or_zeroes_req(struct bsr_request *req, int flags)
{
	int err = bsr_issue_discard_or_zero_out(req->device,
				req->i.sector, req->i.size >> 9, flags);
	bsr_bio_endio(req->private_bio, err ? -EIO : 0);
}

static void
bsr_submit_req_private_bio(struct bsr_request *req)
{
	struct bsr_device *device = req->device;
	struct bio *bio = req->private_bio;
	unsigned int type;

	if (bio_op(bio) != REQ_OP_READ)
		type = BSR_FAULT_DT_WR;
	else if (bio->bi_opf & REQ_RAHEAD)
		type = BSR_FAULT_DT_RA;
	else
		type = BSR_FAULT_DT_RD;

	bio_set_dev(bio, device->ldev->backing_bdev);

	/* State may have changed since we grabbed our reference on the
	 * device->ldev member. Double check, and short-circuit to endio.
	 * In case the last activity log transaction failed to get on
	 * stable storage, and this is a WRITE, we may not even submit
	 * this bio. */
	if (get_ldev(device)) {
		if (bsr_insert_fault(device, type))
			bsr_bio_endio(bio, -EIO);
		else if (bio_op(bio) == REQ_OP_WRITE_ZEROES) {
			bsr_process_discard_or_zeroes_req(req, EE_ZEROOUT |
			    ((bio->bi_opf & REQ_NOUNMAP) ? 0 : EE_TRIM));
		} else if (bio_op(bio) == REQ_OP_DISCARD)
			bsr_process_discard_or_zeroes_req(req, EE_TRIM);
		else {
			// DW-1961 Save timestamp for IO latency measuremen
			if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
				req->io_request_ts = timestamp();

#ifdef _WIN
			if (generic_make_request(bio)) {
				bio_endio(bio, -EIO);
			}
#else // _LIN
			generic_make_request(bio);
#endif
		}
		put_ldev(__FUNCTION__, device);
	} else
		bsr_bio_endio(bio, -EIO);
}

static void bsr_queue_write(struct bsr_device *device, struct bsr_request *req)
{
	atomic_inc(&device->ap_actlog_cnt);
	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&req->tl_requests, &device->submit.writes);
	list_add_tail(&req->req_pending_master_completion,
			&device->pending_master_completion[1 /* WRITE */]);
	spin_unlock_irq(&device->resource->req_lock);
	queue_work(device->submit.wq, &device->submit.worker);
	/* do_submit() may sleep internally on al_wait, too */
	wake_up(&device->al_wait);
}

static void bsr_req_in_actlog(struct bsr_request *req)
{
	req->rq_state[0] |= RQ_IN_ACT_LOG;
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
		ktime_get_accounting(req->in_actlog_kt);
}

/* returns the new bsr_request pointer, if the caller is expected to
 * bsr_send_and_submit() it (to save latency), or NULL if we queued the
 * request on the submitter thread.
 * Returns ERR_PTR(-ENOMEM) if we cannot allocate a bsr_request.
 */
static struct bsr_request *
bsr_request_prepare(struct bsr_device *device, struct bio *bio, ktime_t start_kt, ULONG_PTR start_jif)
{
	const int rw = bio_data_dir(bio);
	struct bsr_request *req;

	/* allocate outside of all locks; */
	req = bsr_req_new(device, bio);
	if (!req) {
		// BSR-1054
		if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_PENDING)) {
			struct io_pending_info *io_pending, *tmp;
			spin_lock_irq(&device->io_pending_list_lock);
			list_for_each_entry_safe_ex(struct io_pending_info, io_pending, tmp, &device->io_pending_list, list) {
				if (io_pending->bio == bio) {
					list_del(&io_pending->list);
					kfree2(io_pending);
					break;
				}
			}
			spin_unlock_irq(&device->io_pending_list_lock);
		}
		dec_ap_bio(device, rw);
		/* only pass the error to the upper layers.
		 * if user cannot handle io errors, that's not our business. */
		bsr_err(36, BSR_LC_MEMORY, device, "Failed to prepare request due to failure to allocate memory for request");
		bsr_bio_endio(bio, -ENOMEM);
		return ERR_PTR(-ENOMEM);
	}

	// DW-1961 Save timestamp for IO latency measuremen
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
		req->created_ts = timestamp();

	req->start_jif = start_jif;
	ktime_get_accounting_assign(req->start_kt, start_kt);

	if (!get_ldev(device)) {
		bio_put(req->private_bio);
		req->private_bio = NULL;
	}

	/* Update disk stats */
	_bsr_start_io_acct(device, req);

	/* process discards always from our submitter thread */
	if ((bio_op(bio) == REQ_OP_WRITE_ZEROES) ||
		(bio_op(bio) == REQ_OP_DISCARD))
		goto queue_for_submitter_thread;

	if (rw == WRITE && req->i.size) {
		/* Unconditionally defer to worker,
		 * if we still need to bumpt our data generation id */
		if (test_bit(NEW_CUR_UUID, &device->flags))
			goto queue_for_submitter_thread;

		if (req->private_bio && !test_bit(AL_SUSPENDED, &device->flags)) {
			if (!bsr_al_begin_io_fastpath(device, &req->i))
				goto queue_for_submitter_thread;
			bsr_req_in_actlog(req);
		}
	}
	return req;

queue_for_submitter_thread:
	req->do_submit = true;
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
		ktime_get_accounting(req->before_queue_kt);
	bsr_queue_write(device, req);
	return NULL;
}

/* Require at least one path to current data.
 * We don't want to allow writes on C_STANDALONE D_INCONSISTENT:
 * We would not allow to read what was written,
 * we would not have bumped the data generation uuids,
 * we would cause data divergence for all the wrong reasons.
 *
 * If we don't see at least one D_UP_TO_DATE, we will fail this request,
 * which either returns EIO, or, if OND_SUSPEND_IO is set, suspends IO,
 * and queues for retry later.
 */
static bool may_do_writes(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;

	if (device->disk_state[NOW] == D_UP_TO_DATE)
		return true;

	for_each_peer_device(peer_device, device) {
		if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
		    return true;
	}

	return false;
}
#ifndef blk_queue_plugged
//#ifdef COMPAT_HAVE_BLK_CHECK_PLUGGED //skip 597b214 commit

#ifdef _LIN
struct bsr_plug_cb {
	struct blk_plug_cb cb;
	struct bsr_request *most_recent_req;
	/* do we need more? */
};
#endif
static void bsr_unplug(struct blk_plug_cb *cb, bool from_schedule)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(cb);
	UNREFERENCED_PARAMETER(from_schedule);
#else // _LIN
	struct bsr_plug_cb *plug = container_of(cb, struct bsr_plug_cb, cb);
	struct bsr_resource *resource = plug->cb.data;
	struct bsr_request *req = plug->most_recent_req;

	bsr_kfree(cb);
	if (!req)
		return;

	spin_lock_irq(&resource->req_lock);
	/* In case the sender did not process it yet, raise the flag to
	 * have it followed with P_UNPLUG_REMOTE just after. */
	req->rq_state[0] |= RQ_UNPLUG;
	/* but also queue a generic unplug */
	bsr_queue_unplug(req->device);
	kref_put(&req->kref, bsr_req_destroy);
	spin_unlock_irq(&resource->req_lock);
#endif    
}

static struct bsr_plug_cb* bsr_check_plugged(struct bsr_resource *resource)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(resource);
#else // _LIN
	/* A lot of text to say
	 * return (struct bsr_plug_cb*)blk_check_plugged(); */
	struct bsr_plug_cb *plug;
	struct blk_plug_cb *cb;

	bool new_plug_alloc = true;

	// BSR-881 fix incorrect kmalloc memory usage collection
	if (current->plug) {		
		list_for_each_entry(cb, &current->plug->cb_list, list)
			if (cb->callback == bsr_unplug && cb->data == (void *)resource) {
				new_plug_alloc = false;
			}
	}
	
	cb = blk_check_plugged(bsr_unplug, resource, sizeof(*plug));

	if (cb) {
		plug = container_of(cb, struct bsr_plug_cb, cb);

		// BSR-875
		if (new_plug_alloc) // BSR-881 not currently on the callback list
			atomic_add64(ksize(cb), &mem_usage.kmalloc);
	}
	else
		plug = NULL;
	return plug;
#endif    
}

static void bsr_update_plug(struct bsr_plug_cb *plug, struct bsr_request *req)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(req);
	UNREFERENCED_PARAMETER(plug);
#else // _LIN
	struct bsr_request *tmp = plug->most_recent_req;
	/* Will be sent to some peer.
	 * Remember to tag it with UNPLUG_REMOTE on unplug */
	kref_get(&req->kref);
	plug->most_recent_req = req;
	if (tmp)
		kref_put(&tmp->kref, bsr_req_destroy);
#endif    
}
#else
struct bsr_plug_cb { };
static void * bsr_check_plugged(struct bsr_resource *resource) { return NULL; };
static void bsr_update_plug(struct bsr_plug_cb *plug, struct bsr_request *req) { };
#endif

// BSR-838 calculate the resync ratio and wait if it is lower than the set ratio.
static void check_resync_ratio_and_wait(struct bsr_peer_device *peer_device)
{
	LONG_PTR repl_sended, resync_sended, resync_received, repl_ratio, resync_ratio;
	LONG_PTR resync_sended_percent, resync_percent;
	int c_min_rate;

	rcu_read_lock();
	c_min_rate = rcu_dereference(peer_device->conf)->c_min_rate;
	rcu_read_unlock();

	repl_ratio = atomic_read64(&peer_device->repl_ratio);
	resync_ratio = atomic_read64(&peer_device->resync_ratio);

	while (peer_device->repl_state[NOW] == L_SYNC_SOURCE && repl_ratio && resync_ratio) {
		resync_received = atomic_read64(&peer_device->cur_resync_received) - atomic_read64(&peer_device->last_resync_received);
		resync_sended = atomic_read64(&peer_device->cur_resync_sended) - atomic_read64(&peer_device->last_resync_sended);
		if (resync_received > resync_sended) {
			repl_sended = atomic_read64(&peer_device->cur_repl_sended) - atomic_read64(&peer_device->last_repl_sended);
			resync_sended_percent = 0;

			if (resync_sended > 0 && repl_sended > 0) {
				if ((resync_sended * 100) < repl_sended)
					resync_sended_percent = 100 - (repl_sended * 100 / (repl_sended + resync_sended));
				else
					resync_sended_percent = resync_sended * 100 / (repl_sended + resync_sended);

				if ((resync_ratio * 100) < repl_ratio)
					resync_percent = 100 - (repl_ratio * 100 / (repl_ratio + resync_ratio));
				else
					resync_percent = resync_ratio * 100 / (repl_ratio + resync_ratio);

				if ((resync_sended_percent < resync_percent) ||
					(c_min_rate && resync_sended < c_min_rate)) {
					msleep(1);
					continue;
				}
			}
		}
		break;
	}
}

// BSR-997 validate that range is already (null return if not already)
// similar to resync_pending_check_and_expand_dup()
static struct bsr_ov_skip_sectors *ov_check_and_expand_dup(struct bsr_peer_device *peer_device, sector_t sst, sector_t est)
{
	struct bsr_ov_skip_sectors *ov_st = NULL;

	if (list_empty(&peer_device->ov_skip_sectors_list))
		return NULL;

	list_for_each_entry_ex(struct bsr_ov_skip_sectors, ov_st, &peer_device->ov_skip_sectors_list, sector_list) {
		if (sst >= ov_st->sst && sst <= ov_st->est && est <= ov_st->est) {
			// ignore them because they already have the all rangs.
			return ov_st;
		}

		if (sst <= ov_st->sst && est >= ov_st->sst && est > ov_st->est) {
			// update sst and est because it contains a larger range that already exists.
			ov_st->sst = sst;
			ov_st->est = est;
			return ov_st;
		}

		if (sst >= ov_st->sst && sst <= ov_st->est && est > ov_st->est) {
			// existing ranges include start ranges, but end ranges are larger, so update the est values.
			ov_st->est = est;
			return ov_st;
		}

		if (sst < ov_st->sst && est >= ov_st->sst && est <= ov_st->est) {
			// existing ranges include end ranges, but start ranges are small, so update the sst values.
			ov_st->sst = sst;
			return ov_st;
		}
	}
	// there is no equal range.
	return NULL;
}

// BSR-997 if you already have a range, remove the duplicate entry. (all list item)
// similar to resync_pending_list_all_check_and_dedup()
static void ov_list_all_check_and_dedup(struct bsr_peer_device *peer_device, struct bsr_ov_skip_sectors *ov_st)
{
	struct bsr_ov_skip_sectors *target, *tmp;

	list_for_each_entry_safe_ex(struct bsr_ov_skip_sectors, target, tmp, &peer_device->ov_skip_sectors_list, sector_list) {
		if (ov_st == target)
			continue;

		if (ov_st->sst <= target->sst && ov_st->est >= target->est) {
			// remove all ranges as they are included.
			list_del(&target->sector_list);
			kfree2(target);
			continue;
		}
		if (ov_st->sst > target->sst && ov_st->sst <= target->est) {
			// the end range is included, so update the est.
			target->est = ov_st->sst;
		}

		if (ov_st->sst <= target->sst && ov_st->est > target->sst) {
			// the start range is included, so update the sst.
			target->sst = ov_st->est;
		}
	}
}

// BSR-997 check whether the sector is within the ov progress range
static bool is_ov_in_progress(struct bsr_peer_device *peer_device, sector_t sst, sector_t est)
{
	sector_t s_ov_sector = (sector_t)atomic_read64(&peer_device->ov_reply_sector);
	sector_t e_ov_sector = (sector_t)atomic_read64(&peer_device->ov_req_sector);
	sector_t s_ov_split = (sector_t)atomic_read64(&peer_device->ov_split_reply_sector);
	sector_t e_ov_split = (sector_t)atomic_read64(&peer_device->ov_split_req_sector);

	if (e_ov_sector == 0)
		return false;
	// check ov in progress range
	if ((s_ov_sector >= sst && e_ov_sector <= est) ||
		(s_ov_sector <= est && e_ov_sector >= est) ||
		(s_ov_sector <= sst && e_ov_sector >= sst))
		return true;
	if (e_ov_split == 0)
		return false;
	// check split ov in progress range
	if ((s_ov_split >= sst && e_ov_split <= est) ||
		(s_ov_split <= est && e_ov_split >= est) ||
		(s_ov_split <= sst && e_ov_split >= sst))
		return true;

	return false;
}

// BSR-997 add ov skipped only when the range is not included. (sort and add)
// simuilar to list_add_resync_pending()
static int list_add_ov_skip_sectors(struct bsr_peer_device *peer_device, sector_t sst, sector_t est)
{
	struct bsr_ov_skip_sectors *ov_st = NULL;
	struct bsr_ov_skip_sectors *target = NULL;

	int i = 0;

	spin_lock_irq(&peer_device->ov_lock);
	if (is_ov_in_progress(peer_device, sst, est - 1)) {
		// remove duplicates from items you want to add.
		ov_st = ov_check_and_expand_dup(peer_device, sst, est);
		if (ov_st) {
			ov_list_all_check_and_dedup(peer_device, ov_st);
		}
		else {
			struct bsr_ov_skip_sectors *target;
#ifdef _WIN
				ov_st = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct bsr_ov_skip_sectors), '9ASB');
#else // _LIN
				ov_st = (struct bsr_ov_skip_sectors *)bsr_kmalloc(sizeof(struct bsr_ov_skip_sectors), GFP_ATOMIC|__GFP_NOWARN, '');
#endif

			if (!ov_st) {
				bsr_err(96, BSR_LC_MEMORY, peer_device, "Failed to add ov skipped due to failure to allocate memory. sector(%llu ~ %llu)", (unsigned long long)sst, (unsigned long long)est);
				spin_unlock_irq(&peer_device->ov_lock);
				return -ENOMEM;
			}

			ov_st->sst = sst;
			ov_st->est = est;

			// add to the list in sequential sort.
			if (list_empty(&peer_device->ov_skip_sectors_list)) {
				list_add(&ov_st->sector_list, &peer_device->ov_skip_sectors_list);
			}
			else {
				list_for_each_entry_ex(struct bsr_ov_skip_sectors, target, &peer_device->ov_skip_sectors_list, sector_list) {
					if (ov_st->sst < target->sst) {
						if (peer_device->ov_skip_sectors_list.next == &target->sector_list)
							list_add(&ov_st->sector_list, &peer_device->ov_skip_sectors_list);
						else
							list_add_tail(&ov_st->sector_list, &target->sector_list);

						goto eof;
					}
				}
				list_add_tail(&ov_st->sector_list, &peer_device->ov_skip_sectors_list);
			}
		}
eof:
		list_for_each_entry_ex(struct bsr_ov_skip_sectors, target, &peer_device->ov_skip_sectors_list, sector_list) 
		{
			bsr_debug(218, BSR_LC_RESYNC_OV, peer_device, "%d. ov skipped sector sst %llu est %llu  list %llu ~ %llu", 
				i++, sst, est, (unsigned long long)target->sst, (unsigned long long)target->est);
		}

	}
	spin_unlock_irq(&peer_device->ov_lock);

	return 0;
}

char* bsr_alloc_accelbuf(struct bsr_device *device, int size)
{
	char* accelbuf = NULL;
	int offset;
	int total_size;

	// BSR-1145 allocate accelbuf only when it is less than or equal to the specified size.
	// the purpose of accelbuf is to improve the local write performance of small-sized writes.
	if (size <= device->resource->res_opts.max_accelbuf_blk_size) {
		if (bsr_offset_ring_adjust(&device->accelbuf, device->resource->res_opts.accelbuf_size, "accelbuf")) {
			int hsize = sizeof(struct bsr_offset_ring_header);

			total_size = hsize + size;
			// BSR-1116 buffering write data to improve local write performance for asynchronous replication
			if (bsr_offset_ring_acquire(&device->accelbuf, &offset, total_size)) {
				accelbuf = device->accelbuf.buf + offset + hsize;
				atomic_add64(total_size, &device->accelbuf.used_size);
			}
		}
	}

	return accelbuf;
}

static void bsr_send_and_submit(struct bsr_device *device, struct bsr_request *req)
{
	struct bsr_resource *resource = device->resource;
	struct bsr_peer_device *peer_device = NULL; /* for read */
	const int rw = bio_data_dir(req->master_bio);
	struct bio_and_error m = { NULL, };
	bool no_remote = false;
	bool submit_private_bio = false;


	for_each_peer_device(peer_device, device) {
		bool remote = bsr_should_do_remote(peer_device, NOW);
		if (peer_device->connection->agreed_pro_version >= 115 && remote) {
			check_resync_ratio_and_wait(peer_device);
		}
	}

	// BSR-997 add sectors overlapping write request and ov progress range to ov_skip_sectors_list
	if (rw == WRITE && req->i.size) {
		for_each_peer_device(peer_device, device) {
			if (peer_device->repl_state[NOW] == L_VERIFY_S) {
				list_add_ov_skip_sectors(peer_device, req->i.sector, req->i.sector + (req->i.size >> 9));
			}
		}
	}

	spin_lock_irq(&resource->req_lock);
	if (rw == WRITE) {
		/* This may temporarily give up the req_lock,
		 * but will re-aquire it before it returns here.
		 * Needs to be before the check on bsr_suspended() */
		complete_conflicting_writes(req);
		/* no more giving up req_lock from now on! */

		/* check for congestion, and potentially stop sending
		 * full data updates, but start sending "dirty bits" only. */
		maybe_pull_ahead(device);
	}


	if (bsr_suspended(device)) {
		/* push back and retry: */
		req->rq_state[0] |= RQ_POSTPONED;
		if (req->private_bio) {
			bio_put(req->private_bio);
			req->private_bio = NULL;
			put_ldev(__FUNCTION__, device);
		}
		goto out;
	}

	/* We fail READ early, if we can not serve it.
	 * We must do this before req is registered on any lists.
	 * Otherwise, bsr_req_complete() will queue failed READ for retry. */
	if (rw != WRITE) {
		peer_device = find_peer_device_for_read(req);
		if (!peer_device && !req->private_bio)
			goto nodata;
	}

	/* which transfer log epoch does this belong to? */
	req->epoch = atomic_read(&resource->current_tle_nr);

	if (rw == WRITE)
		resource->dagtag_sector += req->i.size >> 9;
	req->dagtag_sector = resource->dagtag_sector;
	/* no point in adding empty flushes to the transfer log,
	 * they are mapped to bsr barriers already. */
	if (likely(req->i.size != 0)) {
		if (rw == WRITE) {
			struct bsr_request *req2;

			resource->current_tle_writes++;
			list_for_each_entry_reverse_ex(struct bsr_request, req2, &resource->transfer_log, tl_requests) {
				if (req2->rq_state[0] & RQ_WRITE) {
					/* Make the new write request depend on
					 * the previous one. */
					BUG_ON(req2->destroy_next);
					req2->destroy_next = req;
					kref_get(&req->kref);
					break;
				}
			}
		}
		list_add_tail(&req->tl_requests, &resource->transfer_log);
	}

	if (rw == WRITE) {
		bool all_prot_a = true;
		if (req->private_bio && !may_do_writes(device)) {
			bio_put(req->private_bio);
			req->private_bio = NULL;
			put_ldev(__FUNCTION__, device);
			goto nodata;
		}
		/* Need to replicate writes.  Unless it is an empty flush,
		 * which is better mapped to a BSR P_BARRIER packet,
		 * also for bsr wire protocol compatibility reasons.
		 * If this was a flush, just start a new epoch.
		 * Unless the current epoch was empty anyways, or we are not currently
		 * replicating, in which case there is no point. */
		if (unlikely(req->i.size == 0)) {
			/* The only size==0 bios we expect are empty flushes. */
			D_ASSERT(device, req->master_bio->bi_opf & BSR_REQ_PREFLUSH);
			_req_mod(req, QUEUE_AS_BSR_BARRIER, NULL);
		} else if (!bsr_process_write_request(req, &all_prot_a)) {
			no_remote = true;
		}
		// BSR-1145 check the status of the connected node and allocate it. 
		// accelbuf is only used when all connected nodes use asynchronous replication.
		else if (all_prot_a) {
			int size;
			size = BSR_BIO_BI_SIZE(req->private_bio);
			req->req_databuf = bsr_alloc_accelbuf(device, size);

			if (req->req_databuf) {
#ifdef _WIN
				memcpy(req->req_databuf, req->private_bio->bio_databuf, size);
				req->bio_status.size = size;
#else
#ifdef _LIN_SEND_BUF
				BSR_BIO_VEC_TYPE bvec;
				BSR_ITER_TYPE iter;
				unsigned char *d;
				int len = 0;

				req->bio_status.size = size;
				bio_for_each_segment(bvec, req->private_bio, iter) {
					d = bsr_kmap_atomic(bvec BVD bv_page, KM_USER0);
					memcpy(req->req_databuf + len, d + bvec BVD bv_offset, bvec BVD bv_len);
					bsr_kunmap_atomic(d, KM_USER0);
					len += bvec BVD bv_len;
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
					if (bio_op(req->private_bio) == REQ_OP_WRITE_SAME) {
						break;
					}
#endif
				}
#endif
#endif
				// DW-1237 set request data buffer ref to 1 for local I/O.
				atomic_inc(&req->req_databuf_ref);
#ifdef _WIN
				req->private_bio->bio_databuf = req->req_databuf;
#endif
			}
		}
		wake_all_senders(resource);
	} else {
		if (peer_device) {
			_req_mod(req, TO_BE_SENT, peer_device);
			_req_mod(req, QUEUE_FOR_NET_READ, peer_device);
			wake_up(&peer_device->connection->sender_work.q_wait);
		} else
			no_remote = true;
	}

#ifdef _LIN
	if (no_remote == false) {
		struct bsr_plug_cb *plug = bsr_check_plugged(resource);
		if (plug)
			bsr_update_plug(plug, req);
	}
#endif

	/* If it took the fast path in bsr_request_prepare, add it here.
	 * The slow path has added it already. */
	if (list_empty(&req->req_pending_master_completion))
		list_add_tail(&req->req_pending_master_completion,
			&device->pending_master_completion[rw == WRITE]);
	if (req->private_bio) {
		/* needs to be marked within the same spinlock */
		req->pre_submit_jif = jiffies;
		if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
			ktime_get_accounting(req->submit_kt);
		list_add_tail(&req->req_pending_local,
			&device->pending_completion[rw == WRITE]);
		_req_mod(req, TO_BE_SUBMITTED, NULL);
		/* but we need to give up the spinlock to submit */
		submit_private_bio = true;
	} else if (no_remote) {
nodata:
		if (bsr_ratelimit()) {
			struct bsr_device * device = req->device;
			bsr_err(7, BSR_LC_IO, device, "IO ERROR: neither local nor remote data, sector %llu+%u",
				(unsigned long long)req->i.sector, req->i.size >> 9);
		}
		/* A write may have been queued for send_oos, however.
		 * So we can not simply free it, we must go through bsr_req_put_completion_ref() */
	}

out:
	if (bsr_req_put_completion_ref(req, &m, 1))
		kref_put(&req->kref, bsr_req_destroy);
	spin_unlock_irq(&resource->req_lock);

	/* Even though above is a kref_put(), this is safe.
	 * As long as we still need to submit our private bio,
	 * we hold a completion ref, and the request cannot disappear.
	 * If however this request did not even have a private bio to submit
	 * (e.g. remote read), req may already be invalid now.
	 * That's why we cannot check on req->private_bio. */
	if (submit_private_bio) {
		bsr_debug(14, BSR_LC_VERIFY, device, "%s, sector(%llu), size(%u), bitmap(%llu ~ %llu)", __FUNCTION__, 
																									(unsigned long long)req->i.sector,
																									req->i.size, 
																									(unsigned long long)BM_SECT_TO_BIT(req->i.sector),
																									(unsigned long long)BM_SECT_TO_BIT(req->i.sector + (req->i.size >> 9)));
		// BSR-764 delay bio Submit
		if (g_simul_perf.flag && g_simul_perf.type == SIMUL_PERF_DELAY_TYPE3)
			force_delay(g_simul_perf.delay_time);

		bsr_submit_req_private_bio(req);
	}
#ifdef _LIN
	/* we need to plug ALWAYS since we possibly need to kick lo_dev.
	 * we plug after submit, so we won't miss an unplug event */
	bsr_plug_device(device->vdisk->queue);
#endif
	if (m.bio)
		complete_master_bio(device, &m);
}

#ifdef _WIN
NTSTATUS __bsr_make_request(struct bsr_device *device, struct bio *bio, ktime_t start_kt, ULONG_PTR start_jif)
#else // _LIN
void __bsr_make_request(struct bsr_device *device, struct bio *bio, ktime_t start_kt,
		unsigned long start_jif)
#endif
{
	struct bsr_request *req = bsr_request_prepare(device, bio, start_kt, start_jif);
#ifdef _WIN
	//only memory allocation fail case
	if ((LONG_PTR)req == -ENOMEM)
		return STATUS_UNSUCCESSFUL;
	//retry case in bsr_request_prepare. don't retrun STATUS_UNSUCCESSFUL.
	if (IS_ERR_OR_NULL(req)) {
		if (req)
			bsr_err(51, BSR_LC_MEMORY, device, "FIXME, Failed to local request prepare, block I/O(%p), sector(%llu), size(%u)", bio, bio->bi_sector, bio->bi_size);
		return STATUS_SUCCESS;
	}
#else // _LIN
	if (IS_ERR_OR_NULL(req))
		return;
#endif
	
	bsr_send_and_submit(device, req);

#ifdef _WIN
	return STATUS_SUCCESS;
#endif
}

/* helpers for do_submit */

struct incoming_pending_later {
	/* from bsr_make_request() or receive_Data() */
	struct list_head incoming;
	/* for non-blocking fill-up # of updates in the transaction */
	struct list_head more_incoming;
	/* to be submitted after next AL-transaction commit */
	struct list_head pending;
	/* currently blocked e.g. by concurrent resync requests */
	struct list_head later;
};

struct waiting_for_act_log {
	struct incoming_pending_later requests;
	struct incoming_pending_later peer_requests;
};

static void ipb_init(struct incoming_pending_later *ipb)
{
	INIT_LIST_HEAD(&ipb->incoming);
	INIT_LIST_HEAD(&ipb->more_incoming);
	INIT_LIST_HEAD(&ipb->pending);
	INIT_LIST_HEAD(&ipb->later);
}

static void wfa_init(struct waiting_for_act_log *wfa)
{
	ipb_init(&wfa->requests);
	ipb_init(&wfa->peer_requests);
}

#define wfa_lists_empty(_wfa, name)	\
	(list_empty(&(_wfa)->requests.name) && list_empty(&(_wfa)->peer_requests.name))
#define wfa_splice_init(_wfa, from, to) do { \
	list_splice_init(&(_wfa)->requests.from, &(_wfa)->requests.to); \
	list_splice_init(&(_wfa)->peer_requests.from, &(_wfa)->peer_requests.to); \
	} while (false)
#define wfa_splice_tail_init(_wfa, from, to) do { \
	list_splice_tail_init(&(_wfa)->requests.from, &(_wfa)->requests.to); \
	list_splice_tail_init(&(_wfa)->peer_requests.from, &(_wfa)->peer_requests.to); \
	} while (false)

static void __bsr_submit_peer_request(struct bsr_peer_request *peer_req)
{
	struct bsr_peer_device *peer_device = peer_req->peer_device;
	struct bsr_device *device = peer_device->device;
	int err;

	peer_req->flags |= EE_IN_ACTLOG;
	atomic_dec(&peer_req->peer_device->wait_for_actlog);
	list_del_init(&peer_req->wait_for_actlog);

	err = bsr_submit_peer_request(device, peer_req,
		REQ_OP_WRITE, peer_req->op_flags, BSR_FAULT_DT_WR);

	if (err)
		bsr_cleanup_after_failed_submit_peer_request(peer_req);
}

static void submit_fast_path(struct bsr_device *device, struct waiting_for_act_log *wfa)
{
#ifdef _LIN
	struct blk_plug plug;
#endif
	struct bsr_request *req, *tmp;
	struct bsr_peer_request *pr, *pr_tmp;

#ifdef _LIN
	blk_start_plug(&plug);
#endif

	list_for_each_entry_safe_ex(struct bsr_peer_request, pr, pr_tmp, &wfa->peer_requests.incoming, wait_for_actlog) {
		if (!bsr_al_begin_io_fastpath(pr->peer_device->device, &pr->i))
			continue;

		__bsr_submit_peer_request(pr);
	}

	list_for_each_entry_safe_ex(struct bsr_request, req, tmp, &wfa->requests.incoming, tl_requests) {
		const int rw = bio_data_dir(req->master_bio);

		if (rw == WRITE && req->private_bio && req->i.size
		&& !test_bit(AL_SUSPENDED, &device->flags)) {
			if (!bsr_al_begin_io_fastpath(device, &req->i))
				continue;
			bsr_req_in_actlog(req);
			atomic_dec(&device->ap_actlog_cnt);
		}

		list_del_init(&req->tl_requests);
		bsr_send_and_submit(device, req);
	}
#ifdef _LIN
	blk_finish_plug(&plug);
#endif
}

static struct bsr_request *wfa_next_request(struct waiting_for_act_log *wfa)
{
	struct list_head *lh = !list_empty(&wfa->requests.more_incoming) ?
		&wfa->requests.more_incoming : &wfa->requests.incoming;
	return list_first_entry_or_null(lh, struct bsr_request, tl_requests);
}

static struct bsr_peer_request *wfa_next_peer_request(struct waiting_for_act_log *wfa)
{
	struct list_head *lh = !list_empty(&wfa->peer_requests.more_incoming) ?
		&wfa->peer_requests.more_incoming : &wfa->peer_requests.incoming;
	return list_first_entry_or_null(lh, struct bsr_peer_request, wait_for_actlog);
}

extern atomic_t g_fake_al_used;

// BSR-1039
static int bsr_al_oos_io_nonblock(struct bsr_device* device, struct bsr_request *req)
{
	struct bsr_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->cstate[NOW] == C_CONNECTED) {
			if (peer_device->connection->agreed_pro_version >= 116) {
				if (peer_device->repl_state[NOW] == L_AHEAD) {
					req->rq_state[peer_device->node_id + 1] |= RQ_IN_AL_OOS;
					bsr_set_out_of_sync(peer_device, req->i.sector, req->i.size);
				}
				else {
					return -ENOBUFS;
				}
			}
			else {
				return -ENOBUFS;
			}
		}
	}

	req->rq_state[0] |= RQ_IN_AL_OOS;

	for_each_peer_device(peer_device, device) {
		if (req->rq_state[peer_device->node_id + 1] & RQ_IN_AL_OOS) {
			atomic_inc(&peer_device->al_oos_cnt);
		}
	}

	return 0;
}

static bool prepare_al_transaction_nonblock(struct bsr_device *device,
						struct waiting_for_act_log *wfa)
{
	struct bsr_peer_request *peer_req;
	struct bsr_request *req = NULL;
	bool made_progress = false;
	bool wake = false;
	int err;

	spin_lock_irq(&device->al_lock);

	/* Don't even try, if someone has it locked right now. */
	if (test_bit(__LC_LOCKED, &device->act_log->flags))
		goto out_unlock;
	
	peer_req = wfa_next_peer_request(wfa);
	while (peer_req) {
		err = bsr_al_begin_io_nonblock(device, &peer_req->i);
		if (err == -ENOBUFS)
			break;
		if (err == -EBUSY)
			wake = true;
		if (err)
			list_move_tail(&peer_req->wait_for_actlog, &wfa->peer_requests.later);
		else {
			list_move_tail(&peer_req->wait_for_actlog, &wfa->peer_requests.pending);
			made_progress = true;
		}
		peer_req = wfa_next_peer_request(wfa);
	}

	req = wfa_next_request(wfa);
	while (req) {
		if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
			ktime_get_accounting(req->before_al_begin_io_kt);
		
		err = bsr_al_begin_io_nonblock(device, &req->i);
		if (err == -ENOBUFS) {
			// BSR-1039 set AL OOS because no AL is available in congestion.
			spin_unlock_irq(&device->al_lock);
			err = bsr_al_oos_io_nonblock(device, req);
			if (!err) {
				list_move_tail(&req->tl_requests, &wfa->requests.pending);
				made_progress = true;
			}
			goto out;
		}
		if (err == -EBUSY)
			wake = true;
		if (err)
			list_move_tail(&req->tl_requests, &wfa->requests.later);
		else {
			list_move_tail(&req->tl_requests, &wfa->requests.pending);
			made_progress = true;
		}
		req = wfa_next_request(wfa);
	}
out_unlock:
	spin_unlock_irq(&device->al_lock);
out:
	if (wake)
		wake_up(&device->al_wait);
	return made_progress;
}

static void send_and_submit_pending(struct bsr_device *device, struct waiting_for_act_log *wfa)
{
#ifdef _LIN
	struct blk_plug plug;
#endif
	struct bsr_request *req, *tmp;
	struct bsr_peer_request *pr, *pr_tmp;
	struct bsr_peer_device *peer_device;
	bool is_bm_wrtie = false;
#ifdef _LIN
	blk_start_plug(&plug);
#endif
	list_for_each_entry_safe_ex(struct bsr_peer_request, pr, pr_tmp, &wfa->peer_requests.pending, wait_for_actlog) {
		__bsr_submit_peer_request(pr);
	}

	list_for_each_entry_safe_ex(struct bsr_request, req, tmp, &wfa->requests.pending, tl_requests) {
		// BSR-1039 write the bitmap of node with AL OOS set in the meta.
		if (req->rq_state[0] & RQ_IN_AL_OOS) {
			if (!is_bm_wrtie) {
				for_each_peer_device(peer_device, device) {
					if (req->rq_state[peer_device->node_id + 1] & RQ_IN_AL_OOS)
						bsr_bm_write(device, peer_device);
				}
				is_bm_wrtie = true;
			}
		} else {
			bsr_req_in_actlog(req);
		}
		atomic_dec(&device->ap_actlog_cnt);
		list_del_init(&req->tl_requests);
		bsr_send_and_submit(device, req);
	}
#ifdef _LIN
	blk_finish_plug(&plug);
#endif
}


static void ensure_current_uuid(struct bsr_device *device)
{
	if (test_and_clear_bit(NEW_CUR_UUID, &device->flags)) {
		bsr_info(35, BSR_LC_UUID, device, "clear the UUID creation flag with the current UUID verification and attempt to create a UUID");
		// DW-2004 the function ensure_current_uuid() updates the uuid during replication, 
		// so if uuid update is required in D_FAILED state, please update with other function.
		if (device->disk_state[NOW] != D_FAILED) {
			struct bsr_resource *resource = device->resource;
			mutex_lock(&resource->conf_update);
			bsr_uuid_new_current(device, false, false, false, __FUNCTION__);
			mutex_unlock(&resource->conf_update);
		}
	}
}

/* more: for non-blocking fill-up # of updates in the transaction */
static bool grab_new_incoming_requests(struct bsr_device *device, struct waiting_for_act_log *wfa, bool more)
{
	/* grab new incoming requests */
	struct list_head *reqs = more ? &wfa->requests.more_incoming : &wfa->requests.incoming;
	struct list_head *peer_reqs = more ? &wfa->peer_requests.more_incoming : &wfa->peer_requests.incoming;
	bool found_new = false;

	spin_lock_irq(&device->resource->req_lock);
	found_new = !list_empty(&device->submit.writes);
	list_splice_tail_init(&device->submit.writes, reqs);
	found_new |= !list_empty(&device->submit.peer_writes);
	list_splice_tail_init(&device->submit.peer_writes, peer_reqs);
	spin_unlock_irq(&device->resource->req_lock);

	return found_new;
}

void do_submit(struct work_struct *ws)
{
	struct bsr_device *device = container_of(ws, struct bsr_device, submit.worker);
	struct waiting_for_act_log wfa;
	// DW-1780 retry the same request with al_timeout
	ULONG_PTR al_wait_count = 0;
	LONGLONG ts = 0; 
	wfa_init(&wfa);

	grab_new_incoming_requests(device, &wfa, false);

	for (;;) {
		DEFINE_WAIT(wait);

		ensure_current_uuid(device);

		/* move used-to-be-postponed back to front of incoming */
		wfa_splice_init(&wfa, later, incoming);
		submit_fast_path(device, &wfa);
		if (wfa_lists_empty(&wfa, incoming))
			break;

		for (;;) {
			/*
			* We put ourselves on device->al_wait, then check if
			* we can need to actually sleep and wait for someone
			* else to make progress.
			*
			* We need to sleep if we cannot activate enough
			* activity log extents for even one single request.
			* That would mean that all (peer-)requests in our incoming lists
			* either target "cold" activity log extent, all
			* activity log extent slots are have on-going
			* in-flight IO (are "hot"), and no idle or free slot
			* is available, or the target regions are busy doing resync,
			* and lock out application requests for that reason.
			*
			* prepare_to_wait() can internally cause a wake_up()
			* as well, though, so this may appear to busy-loop
			* a couple times, but should settle down quickly.
			*
			* When resync and/or application requests make
			* sufficient progress, some refcount on some extent
			* will eventually drop to zero, we will be woken up,
			* and can try to move that now idle extent to "cold",
			* and recycle it's slot for one of the extents we'd
			* like to become hot.
			*/
			prepare_to_wait(&device->al_wait, &wait, TASK_UNINTERRUPTIBLE);

			wfa_splice_init(&wfa, later, incoming);
			prepare_al_transaction_nonblock(device, &wfa);
			if (!wfa_lists_empty(&wfa, pending)) {
				if(al_wait_count)
					bsr_debug(29, BSR_LC_LRU, device, "al_wait retry count : %llu", (unsigned long long)al_wait_count);
				al_wait_count = 0;
				if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_AL_STAT))
					device->al_wait_retry_cnt = 0;
				break;
			}
			al_wait_count += 1;
			if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_AL_STAT)) {
				device->al_wait_retry_cnt++;
				device->al_wait_retry_total++;
				device->al_wait_retry_max = max(device->al_wait_retry_max, device->al_wait_retry_cnt);
			}
			
#ifdef _LIN 
			// DW-691 windows skipped 3d552f8 commit(linux bsr)
			bsr_kick_lo(device);
#endif

#ifdef _WIN // DW-1513, DW-1546, DW-1761 If al_wait event is not received during AL_WAIT_TIMEOUT, disconnect.
			if(!schedule(&device->al_wait, AL_WAIT_TIMEOUT, __FUNCTION__, __LINE__)) {
#else // _LIN
			if(!schedule_timeout(AL_WAIT_TIMEOUT)) {
#endif
				struct bsr_peer_device *peer_device;
				bsr_err(14, BSR_LC_LRU, device, "Reconnect to activity log acquisition wait timeout. retry(%llu)", (unsigned long long)al_wait_count);
				for_each_peer_device_rcu(peer_device, device) {
					change_cstate_ex(peer_device->connection, C_NETWORK_FAILURE, CS_HARD);
				}
				
				continue;
			}

			/* If all currently "hot" activity log extents are kept busy by
			 * incoming requests, we still must not totally starve new
			 * requests to "cold" extents.
			 * Something left on &incoming means there had not been
			 * enough update slots available, and the activity log
			 * has been marked as "starving".
			 *
			 * Try again now, without looking for new requests,
			 * effectively blocking all new requests until we made
			 * at least _some_ progress with what we currently have.
			 */
			if (!wfa_lists_empty(&wfa, incoming))
				continue;

			/* Nothing moved to pending, but nothing left
			 * on incoming: all moved to "later"!
			 * Grab new and iterate. */
			grab_new_incoming_requests(device, &wfa, false);
		}
		finish_wait(&device->al_wait, &wait);

		/* If the transaction was full, before all incoming requests
		 * had been processed, skip ahead to commit, and iterate
		 * without splicing in more incoming requests from upper layers.
		 *
		 * Else, if all incoming have been processed,
		 * they have become either "pending" (to be submitted after
		 * next transaction commit) or "busy" (blocked by resync).
		 *
		 * Maybe more was queued, while we prepared the transaction?
		 * Try to stuff those into this transaction as well.
		 * Be strictly non-blocking here,
		 * we already have something to commit.
		 *
		 * Commit as soon as we don't make any more progres.
		 */

		while (wfa_lists_empty(&wfa, incoming)) {
			bool made_progress;

			/* It is ok to look outside the lock,
			* it's only an optimization anyways */
			if (list_empty(&device->submit.writes) &&
				list_empty(&device->submit.peer_writes))
				break;

			if (!grab_new_incoming_requests(device, &wfa, true))
				break;

			made_progress = prepare_al_transaction_nonblock(device, &wfa);

			wfa_splice_tail_init(&wfa, more_incoming, incoming);
			if (!made_progress)
				break;
		}

		if (device->resource->role[NOW] == R_SECONDARY)
			ts = timestamp();
		else
			ts = 0;

		bsr_al_begin_io_commit(device);

		// DW-1977
		if (device->resource->role[NOW] == R_SECONDARY && ts != 0) {
			ts = timestamp_elapse(__FUNCTION__, ts, timestamp());
			if (ts > ((3 * 1000) * HZ)) {
				bsr_warn(27, BSR_LC_LRU, device, "Activity log commit takes a long time(%lldus)", ts);
			}
		}

		ensure_current_uuid(device);

		send_and_submit_pending(device, &wfa);
	}
#ifdef _LIN
	// DW-691 windows skipped 3d552f8 commit(linux bsr)
	bsr_kick_lo(device);
#endif
}

// BSR-723 add compat code for blk_queue_split

#ifndef COMPAT_HAVE_BLK_QUEUE_SPLIT_Q_BIO
#if defined(COMPAT_HAVE_BLK_QUEUE_SPLIT_BIO)
	/* version (>=5.9) with only 1 argument. nothing to do */
	#define blk_queue_split(q, bio) blk_queue_split(bio)
#elif defined(COMPAT_HAVE_BLK_QUEUE_SPLIT_Q_BIO_BIOSET)
#define blk_queue_split(q, bio) blk_queue_split(q, bio, q->bio_split)
#else
#define blk_queue_split(q, bio) do { } while (0)
#endif
#endif

#ifdef COMPAT_HAVE_SUBMIT_BIO
MAKE_REQUEST_TYPE bsr_submit_bio(struct bio *bio)
#else
MAKE_REQUEST_TYPE bsr_make_request(struct request_queue *q, struct bio *bio)
#endif
{
#if defined(COMPAT_HAVE_BIO_BI_BDEV)
	struct bsr_device *device = bio->bi_bdev->bd_disk->private_data;
#elif defined(_WIN)
	struct bsr_device *device = (struct bsr_device *) q->queuedata;
#else
	struct bsr_device *device = bio->bi_disk->private_data;
#endif
	ktime_t start_kt;
	ULONG_PTR start_jif;
#ifdef _WIN
	NTSTATUS	status;
	start_kt = ktime_get();
#else // _LIN
	const int rw = bio_data_dir(bio);
	// BSR-620 If the meta-disk err, device->ldev can be null.
	if (rw == READ && device->ldev) {
		// BSR-746 modify to bypass after checking with get_ldev() when read io occurs
		if (!get_ldev(device)) {
			bsr_bio_endio(bio, -ENODEV);
			MAKE_REQUEST_RETURN;
		}

		if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_STAT)) {
			atomic_inc(&device->io_cnt[READ]);
			atomic_add(BSR_BIO_BI_SIZE(bio) >> 10, &device->io_size[READ]);
		}
// BSR-458
#ifdef READ_BYPASS_TO_BACKING_BDEV
		bio_set_dev(bio, device->ldev->backing_bdev);
		generic_make_request(bio);
		put_ldev(__FUNCTION__, device);
		MAKE_REQUEST_RETURN;
#endif
	}

	// BSR-764 delay write I/O occurrence
	if (g_simul_perf.flag && (g_simul_perf.type == SIMUL_PERF_DELAY_TYPE0)) 
		force_delay(g_simul_perf.delay_time);

	start_kt = ktime_get();

	if ((atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_STAT)) && (rw == WRITE) && device->ldev) {
		atomic_inc(&device->io_cnt[WRITE]);
		atomic_add(BSR_BIO_BI_SIZE(bio) >> 10, &device->io_size[WRITE]);
	}
	/* We never supported BIO_RW_BARRIER.
	 * We don't need to, anymore, either: starting with kernel 2.6.36,
	 * we have REQ_FUA and REQ_PREFLUSH, which will be handled transparently
	 * by the block layer. */
	if (unlikely(bio->bi_opf & BSR_REQ_HARDBARRIER)) {
		bsr_bio_endio(bio, -EOPNOTSUPP);
		MAKE_REQUEST_RETURN;
	}
#endif

#ifdef _LIN
	// BSR-730 prevent writing when device is failed or below.
	if (device->disk_state[NOW] <= D_FAILED) {
		bsr_bio_endio(bio, -ENODEV);
		MAKE_REQUEST_RETURN;
	}

/* 54efd50 block: make generic_make_request handle arbitrarily sized bios
 * introduced blk_queue_split(), which is supposed to split (and put on the
 * current->bio_list bio chain) any bio that is violating the queue limits.
 * Before that, any user was supposed to go through bio_add_page(), which
 * would call our merge bvec function, and that should already be sufficient
 * to not violate queue limits.
 */

#ifdef COMPAT_HAVE_BIO_SPLIT_TO_LIMITS
	// BSR-1114 add compat code for bio_split_to_limits()
	bio = bio_split_to_limits(bio);
	if (!bio) {
		MAKE_REQUEST_RETURN;
	}
#else
	// BSR-723
	blk_queue_split(q, &bio);
#endif
#endif
	start_jif = jiffies;

	// BSR-1054 add bio to io_pending_list
	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_IO_PENDING)) {
		struct io_pending_info* io_pending = bsr_kmalloc(sizeof(struct io_pending_info), GFP_ATOMIC|__GFP_NOWARN, 'BASB');
		INIT_LIST_HEAD(&io_pending->list);
		spin_lock_irq(&device->io_pending_list_lock);
		list_add_tail(&io_pending->list, &device->io_pending_list);
		io_pending->bio = bio;
		io_pending->io_start_kt = start_kt;
		io_pending->complete_pending = 0;
		spin_unlock_irq(&device->io_pending_list_lock);
	}

	inc_ap_bio(device, bio_data_dir(bio));

#ifdef _WIN
	status = __bsr_make_request(device, bio, start_kt, start_jif);
	return status;
#else // _LIN
	__bsr_make_request(device, bio, start_kt, start_jif);
	MAKE_REQUEST_RETURN;
#endif
}

/* This is called by bio_add_page().
 *
 * q->max_hw_sectors and other global limits are already enforced there.
 *
 * We need to call down to our lower level device,
 * in case it has special restrictions.
 *
 * As long as the BIO is empty we have to allow at least one bvec,
 * regardless of size and offset, so no need to ask lower levels.
 */
#ifdef COMPAT_HAVE_BLK_QUEUE_MERGE_BVEC
int bsr_merge_bvec(struct request_queue *q,
		struct bvec_merge_data *bvm,
		struct bio_vec *bvec)
{
	struct bsr_device *device = (struct bsr_device *) q->queuedata;
	unsigned int bio_size = bvm->bi_size;
	int limit = BSR_MAX_BIO_SIZE;
	int backing_limit;

	if (bio_size && get_ldev(device)) {
		unsigned int max_hw_sectors = queue_max_hw_sectors(q);
		struct request_queue * const b =
			device->ldev->backing_bdev->bd_disk->queue;
		if (b->merge_bvec_fn) {
			bvm->bi_bdev = device->ldev->backing_bdev;
			backing_limit = b->merge_bvec_fn(b, bvm, bvec);
			limit = min(limit, backing_limit);
		}
		put_ldev(__FUNCTION__, device);
		if ((limit >> 9) > max_hw_sectors)
			limit = max_hw_sectors << 9;
	}
	return limit;
}
#endif

static ULONG_PTR time_min_in_future(ULONG_PTR now,
		ULONG_PTR t1, ULONG_PTR t2)
{
	t1 = time_after(now, t1) ? now : t1;
	t2 = time_after(now, t2) ? now : t2;

	// BSR-408 return the nearest future time
	if (t1 == now && t2 == now)
		return now;
	if (t1 == now)
		return t2;
	if (t2 == now)
		return t1;

	return time_after(t1, t2) ? t2 : t1;
}

extern atomic_t g_forced_kernel_panic;
extern atomic_t g_panic_occurrence_time;

#define SECONDS_TO_MILLISECONDS(x)	(x * 1000)

static bool net_timeout_reached(struct bsr_request *net_req,
		struct bsr_connection *connection,
		ULONG_PTR now, ULONG_PTR ent,
		unsigned int ko_count, unsigned int timeout)
{
	struct bsr_device *device = net_req->device;
	struct bsr_peer_device *peer_device = conn_peer_device(connection, device->vnr);
	int peer_node_id = peer_device->node_id;

	if (!time_after(now, net_req->pre_send_jif[peer_node_id] + ent))
		return false;

	if (time_in_range(now, connection->last_reconnect_jif, connection->last_reconnect_jif + ent))
		return false;

	if (net_req->rq_state[1 + peer_node_id] & RQ_NET_PENDING) {
		bsr_warn(25, BSR_LC_REQUEST, device, "Remote failed to finish a request within %ums > ko-count (%u) * timeout (%u * 0.1s)",
			jiffies_to_msecs(now - net_req->pre_send_jif[peer_node_id]), ko_count, timeout);
		return true;
	}

	/* We received an ACK already (or are using protocol A),
	 * but are waiting for the epoch closing barrier ack.
	 * Check if we sent the barrier already.  We should not blame the peer
	 * for being unresponsive, if we did not even ask it yet. */
	if (net_req->epoch == connection->send.current_epoch_nr) {
		unsigned int msecs = jiffies_to_msecs(now - net_req->pre_send_jif[peer_node_id]);

 		bsr_warn(26, BSR_LC_REQUEST, device,
			"We did not send a P_BARRIER for %ums > ko-count (%u) * timeout (%u * 0.1s); bsr kernel thread blocked?", msecs, ko_count, timeout);

		if (atomic_read(&g_forced_kernel_panic)) {
			// BSR-1072 depending on the call cycle of net_timeout_reached(), the condition can be satisfied after the set time.
			if (msecs > (unsigned int)SECONDS_TO_MILLISECONDS(atomic_read(&g_panic_occurrence_time))) {
#ifdef _WIN
				KeBugCheckEx(MANUALLY_INITIATED_CRASH1, (ULONG_PTR)connection->resource, (ULONG_PTR)connection, (ULONG_PTR)net_req, (ULONG_PTR)msecs);
#else	// _LIN
				panic("Panic due to did not send a P_BARRIER, resource %p, connection %p, request %p, time %d => %u", connection->resource, connection, net_req, atomic_read(&g_panic_occurrence_time), msecs);
#endif
			}
		}

		return false;
	}

	/* Worst case: we may have been blocked for whatever reason, then
	 * suddenly are able to send a lot of requests (and epoch separating
	 * barriers) in quick succession.
	 * The timestamp of the net_req may be much too old and not correspond
	 * to the sending time of the relevant unack'ed barrier packet, so
	 * would trigger a spurious timeout.  The latest barrier packet may
	 * have a too recent timestamp to trigger the timeout, potentially miss
	 * a timeout.  Right now we don't have a place to conveniently store
	 * these timestamps.
	 * But in this particular situation, the application requests are still
	 * completed to upper layers, BSR should still "feel" responsive.
	 * No need yet to kill this connection, it may still recover.
	 * If not, eventually we will have queued enough into the network for
	 * us to block. From that point of view, the timestamp of the last sent
	 * barrier packet is relevant enough.
	 */
	if (time_after(now, connection->send.last_sent_barrier_jif + ent)) {
		bsr_warn(27, BSR_LC_REQUEST, device, "Remote failed to answer a P_BARRIER (sent at %lu jif; now=%lu jif) within %ums > ko-count (%u) * timeout (%u * 0.1s)",
			connection->send.last_sent_barrier_jif, now,
			jiffies_to_msecs(now - connection->send.last_sent_barrier_jif), ko_count, timeout);
		return true;
	}
	return false;
}

/* A request is considered timed out, if
 * - we have some effective timeout from the configuration,
 *   with some state restrictions applied,
 * - the oldest request is waiting for a response from the network
 *   resp. the local disk,
 * - the oldest request is in fact older than the effective timeout,
 * - the connection was established (resp. disk was attached)
 *   for longer than the timeout already.
 * Note that for 32bit jiffies and very stable connections/disks,
 * we may have a wrap around, which is catched by
 *   !time_in_range(now, last_..._jif, last_..._jif + timeout).
 *
 * Side effect: once per 32bit wrap-around interval, which means every
 * ~198 days with 250 HZ, we have a window where the timeout would need
 * to expire twice (worst case) to become effective. Good enough.
 */
#ifdef _WIN
void request_timer_fn(PKDPC Dpc, PVOID data, PVOID SystemArgument1, PVOID SystemArgument2)
#else // _LIN
void request_timer_fn(BSR_TIMER_FN_ARG)
#endif
{
	struct bsr_connection *connection;
	struct bsr_request *req_read, *req_write;
	
#ifdef _WIN
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	struct bsr_device *device = (struct bsr_device *) data;
#else // _LIN
	struct bsr_device *device = BSR_TIMER_ARG2OBJ(device, request_timer);
#endif
	ULONG_PTR oldest_submit_jif;
	ULONG_PTR dt = 0;
	ULONG_PTR et = 0;
	ULONG_PTR now = jiffies;
	ULONG_PTR next_trigger_time = now;
	bool restart_timer = false;

	if (device == NULL)
		return;

	rcu_read_lock();
	if (get_ldev(device)) { /* implicit state.disk >= D_INCONSISTENT */
		dt = rcu_dereference(device->ldev->disk_conf)->disk_timeout * HZ / 10;
		put_ldev(__FUNCTION__, device);
	}
	rcu_read_unlock();

	/* FIXME right now, this basically does a full transfer log walk *every time* */
	spin_lock_irq(&device->resource->req_lock);
	if (dt) {
		req_read = list_first_entry_or_null(&device->pending_completion[0], struct bsr_request, req_pending_local);
		req_write = list_first_entry_or_null(&device->pending_completion[1], struct bsr_request, req_pending_local);

		// BSR-1160
		if (!req_write)
			wake_up(&device->wt_wait);

		oldest_submit_jif =
			(req_write && req_read)
			? ( time_before(req_write->pre_submit_jif, req_read->pre_submit_jif)
			  ? req_write->pre_submit_jif : req_read->pre_submit_jif )
			: req_write ? req_write->pre_submit_jif
			: req_read ? req_read->pre_submit_jif : now;

		if (device->disk_state[NOW] > D_FAILED) {
			et = min_not_zero(et, dt);
			next_trigger_time = time_min_in_future(now,
					next_trigger_time, oldest_submit_jif + dt);
			restart_timer = true;
		}

		if (time_after(now, oldest_submit_jif + dt) &&
		    !time_in_range(now, device->last_reattach_jif, device->last_reattach_jif + dt)) {
			bsr_warn(28, BSR_LC_REQUEST, device, "Local backing device failed to meet the disk-timeout");
			__bsr_chk_io_error(device, BSR_FORCE_DETACH);
		}
	}
	for_each_connection(connection, device->resource) {
		struct net_conf *nc;
		struct bsr_request *req;
        ULONG_PTR ent = 0;
        ULONG_PTR pre_send_jif = 0;
		unsigned int ko_count = 0, timeout = 0;

		rcu_read_lock();
		nc = rcu_dereference(connection->transport.net_conf);
		if (nc) {
			/* effective timeout = ko_count * timeout */
			if (connection->cstate[NOW] == C_CONNECTED) {
				ko_count = nc->ko_count;
				timeout = nc->timeout;
				ent = timeout * HZ/10 * ko_count;
			}
		}
		rcu_read_unlock();

		// BSR-975
		if (!ent)
			continue;

		/* maybe the oldest request waiting for the peer is in fact still
		 * blocking in tcp sendmsg.  That's ok, though, that's handled via the
		 * socket send timeout, requesting a ping, and bumping ko-count in
		 * we_should_drop_the_connection().
		 */

		/* check the oldest request we did successfully sent,
		 * but which is still waiting for an ACK. */
		req = connection->req_ack_pending;

		/* if we don't have such request (e.g. protocoll A)
		 * check the oldest requests which is still waiting on its epoch
		 * closing barrier ack. */
		if (!req)
			req = connection->req_not_net_done;
		if (req)
			pre_send_jif = req->pre_send_jif[connection->peer_node_id];

		
		et = min_not_zero(et, ent);
		next_trigger_time = time_min_in_future(now,
				next_trigger_time, pre_send_jif + ent);
		restart_timer = true;

		// BSR-975 reschedule the request timer even if there are no pending req
		/* evaluate the oldest peer request only in one timer! */
		if (req && req->device != device)
			req = NULL;
		if (!req)
			continue;

		if (net_timeout_reached(req, connection, now, ent, ko_count, timeout)) {
			begin_state_change_locked(device->resource, CS_VERBOSE | CS_HARD);
			__change_cstate(connection, C_TIMEOUT);
			end_state_change_locked(device->resource, false, __FUNCTION__);
		}
	}
	spin_unlock_irq(&device->resource->req_lock);

	if (restart_timer) {
		next_trigger_time = time_min_in_future(now, next_trigger_time, now + et);
		mod_timer(&device->request_timer, next_trigger_time);
	}
}
