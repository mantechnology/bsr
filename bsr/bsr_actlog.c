/*
   bsr_actlog.c

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
#ifdef _WIN
#include "./bsr-kernel-compat/windows/bsr_windows.h"
#include "./bsr-kernel-compat/windows/bsr_wingenl.h"
#include "./bsr-kernel-compat/windows/bsr_endian.h"
#include "./bsr-kernel-compat/windows/idr.h"
#else	// _LIN
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/bsr_limits.h>
#include <linux/dynamic_debug.h>
#endif
#include "./bsr-kernel-compat/bsr_wrappers.h"
#include "../bsr-headers/bsr.h"

enum al_transaction_types {
	AL_TR_UPDATE = 0,
	AL_TR_INITIALIZED = 0xffff
};
/* all fields on disc in big endian */
#ifdef _WIN
#pragma pack (push, 1)
#define __packed
#endif
struct __packed al_transaction_on_disk {
	/* don't we all like magic */
	__be32	magic;

	/* to identify the most recent transaction block
	 * in the on disk ring buffer */
	__be32	tr_number;

	/* checksum on the full 4k block, with this field set to 0. */
	__be32	crc32c;

	/* type of transaction, special transaction types like:
	 * purge-all, set-all-idle, set-all-active, ... to-be-defined
	 * see also enum al_transaction_types */
	__be16	transaction_type;

	/* we currently allow only a few thousand extents,
	 * so 16bit will be enough for the slot number. */

	/* how many updates in this transaction */
	__be16	n_updates;

	/* maximum slot number, "al-extents" in bsr.conf speak.
	 * Having this in each transaction should make reconfiguration
	 * of that parameter easier. */
	__be16	context_size;

	/* slot number the context starts with */
	__be16	context_start_slot_nr;

	/* Some reserved bytes.  Expected usage is a 64bit counter of
	 * sectors-written since device creation, and other data generation tag
	 * supporting usage */
#ifdef _WIN
	__be32	__reserved_win[4];
#else // _LIN
	__be32	__reserved[4];
#endif

	/* --- 36 byte used --- */

	/* Reserve space for up to AL_UPDATES_PER_TRANSACTION changes
	 * in one transaction, then use the remaining byte in the 4k block for
	 * context information.  "Flexible" number of updates per transaction
	 * does not help, as we have to account for the case when all update
	 * slots are used anyways, so it would only complicate code without
	 * additional benefit.
	 */
	__be16	update_slot_nr[AL_UPDATES_PER_TRANSACTION];

	/* but the extent number is 32bit, which at an extent size of 4 MiB
	 * allows to cover device sizes of up to 2**54 Byte (16 PiB) */
	__be32	update_extent_nr[AL_UPDATES_PER_TRANSACTION];

	/* --- 420 bytes used (36 + 64*6) --- */

	/* 4096 - 420 = 3676 = 919 * 4 */
	__be32	context[AL_CONTEXT_PER_TRANSACTION];
};

#ifdef _WIN 
#pragma pack (pop)
#undef __packed
#endif

struct update_peers_work {
       struct bsr_work w;
       struct bsr_peer_device *peer_device;
       unsigned int enr;
};

void *bsr_md_get_buffer(struct bsr_device *device, const char *intent)
{
	int r;
	long t = 0;

	// DW-1961 Measure how long the metadisk waits for use
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
		device->md_io.prepare_ts = timestamp();

	wait_event_timeout_ex(device->misc_wait,
							(r = atomic_cmpxchg(&device->md_io.in_use, 0, 1)) == 0 ||
							device->disk_state[NOW] <= D_FAILED,
							HZ * 10, t);

	if (t == 0)
		bsr_err(15, BSR_LC_IO, device, "Failed to get meta buffer in 10 seconds, %s", intent);

	if (r)
		return NULL;

	device->md_io.current_use = intent;
#ifdef _LIN
	device->md_io.start_jif = jiffies;
	device->md_io.submit_jif = device->md_io.start_jif - 1;
#endif
	return page_address(device->md_io.page);
}

void bsr_md_put_buffer(struct bsr_device *device)
{
	if (atomic_dec_and_test(&device->md_io.in_use))
		wake_up(&device->misc_wait);
}

void wait_until_done_or_force_detached(struct bsr_device *device, struct bsr_backing_dev *bdev,
				       unsigned int *done)
{
	long dt;

	rcu_read_lock();
	dt = rcu_dereference(bdev->disk_conf)->disk_timeout;
	rcu_read_unlock();
	dt = dt * HZ / 10;
	if (dt == 0)
		dt = MAX_SCHEDULE_TIMEOUT;

	wait_event_timeout_ex(device->misc_wait, 
		*done || test_bit(FORCE_DETACH, &device->flags), dt, dt);

	if (dt == 0) {
		bsr_err(16, BSR_LC_IO, device, "The meta-disk I/O timeout sets the detach state.");
		bsr_chk_io_error(device, 1, BSR_FORCE_DETACH);
	}
}

static int _bsr_md_sync_page_io(struct bsr_device *device,
				 struct bsr_backing_dev *bdev,
				 sector_t sector, int op)
{
	struct bio *bio;
	/* we do all our meta data IO in aligned 4k blocks. */
	const int size = 4096;
	int err, op_flags = 0;

	if ((op == REQ_OP_WRITE) && !test_bit(MD_NO_FUA, &device->flags))
		op_flags |= BSR_REQ_FUA | BSR_REQ_PREFLUSH;
	op_flags |= BSR_REQ_UNPLUG | BSR_REQ_SYNC | REQ_NOIDLE;

#ifdef COMPAT_MAYBE_RETRY_HARDBARRIER
	/* < 2.6.36, "barrier" semantic may fail with EOPNOTSUPP */
 retry:
#endif
	device->md_io.done = 0;
	device->md_io.error = -ENODEV;
#ifdef _WIN 
	bio = bio_alloc_bsr(GFP_NOIO, '30SB');
#else	// _LIN
	bio = bio_alloc_bsr(bdev->md_bdev, GFP_NOIO, op | op_flags);
#endif
    if (!bio) {
        return -ENODEV;
    }

#ifndef COMPAT_BIO_ALLOC_HAS_4_PARAMS
	bio_set_dev(bio, bdev->md_bdev);
#endif
	BSR_BIO_BI_SECTOR(bio) = sector;
	err = -EIO;
	if (bio_add_page(bio, device->md_io.page, size, 0) != size)
		goto out;
	bio->bi_private = device;
	bio->bi_end_io = bsr_md_endio;
#ifndef COMPAT_BIO_ALLOC_HAS_4_PARAMS
	bio_set_op_attrs(bio, op, op_flags);
#endif

	if (op != REQ_OP_WRITE && device->disk_state[NOW] == D_DISKLESS && device->ldev == NULL)
		/* special case, bsr_md_read() during bsr_adm_attach(): no get_ldev */
		;
	else if (!get_ldev_if_state(device, D_ATTACHING)) {
		/* Corresponding put_ldev in bsr_md_endio() */
		bsr_err(17, BSR_LC_IO, device, "Meta-disk I/O cannot be performed in %s state.", bsr_disk_str(device->disk_state[NOW]));
		err = -ENODEV;
		goto out;
	}

	bio_get(bio); /* one bio_put() is in the completion handler */
	atomic_inc(&device->md_io.in_use); /* bsr_md_put_buffer() is in the completion handler */

	// DW-1961 Save timestamp for IO latency measurement
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
		device->md_io.io_request_ts = timestamp();

#ifdef _LIN
	device->md_io.submit_jif = jiffies;
#endif

	if (bsr_insert_fault(device, (op == REQ_OP_WRITE) ? BSR_FAULT_MD_WR : BSR_FAULT_MD_RD))
		bsr_bio_endio(bio, -EIO);
#ifdef _WIN
	else {
		if (submit_bio(bio)) {
			bio_endio(bio, -EIO);
		}
	}
#else // _LIN
	else
		submit_bio(bio);
#endif

	wait_until_done_or_force_detached(device, bdev, &device->md_io.done);

	// DW-1961 Calculate and Log IO Latency
	if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY)) {
		device->md_io.io_complete_ts = timestamp();
		bsr_debug(1, BSR_LC_LATENCY, device, "md IO latency : type(%s) prepare(%lldus) disk io(%lldus)",
				(op == REQ_OP_WRITE) ? "write" : "read",
				timestamp_elapse(__FUNCTION__, device->md_io.prepare_ts, device->md_io.io_request_ts), 
				timestamp_elapse(__FUNCTION__, device->md_io.io_request_ts, device->md_io.io_complete_ts));
	}

	err = device->md_io.error;
#ifdef _WIN
    if(err == STATUS_NO_SUCH_DEVICE) {
		// DW-1396 referencing bio causes BSOD as long as bio has already been freed once it's been submitted, we don't need volume device name which is already removed also.
        bsr_err(18, BSR_LC_IO, device, "Failed to I/O due to the meta volume could not be found");
        return err;
    }
#endif

#ifdef COMPAT_MAYBE_RETRY_HARDBARRIER
	/* check for unsupported barrier op.
	 * would rather check on EOPNOTSUPP, but that is not reliable.
	 * don't try again for ANY return value != 0 */
	if (err && device->md_io.done && (bio->bi_opf & BSR_REQ_HARDBARRIER)) {
		/* Try again with no barrier */
		bsr_warn(74, BSR_LC_ETC, device, "Barriers not supported on meta data device - disabling");
		set_bit(MD_NO_FUA, &device->flags);
		op_flags &= ~BSR_REQ_HARDBARRIER;
		bio_put(bio);
		goto retry;
	}
#endif
#ifdef _WIN
	return err;
#endif
 out:
	bio_put(bio);
	return err;
}

int bsr_md_sync_page_io(struct bsr_device *device, struct bsr_backing_dev *bdev,
			 sector_t sector, int op)
{
	int err;
	D_ASSERT(device, atomic_read(&device->md_io.in_use) == 1);

	if (!bdev->md_bdev) {
		if (bsr_ratelimit())
			bsr_err(19, BSR_LC_IO, device, "Failed to I/O due to meta disk device information does not exist. md_dev(NULL)");
		return -EIO;
	}

	bsr_dbg(device, "meta_data io: %s [%d]:%s(,%llus,%s) %pS",
	     current->comm, current->pid, __func__,
		 (unsigned long long)sector, (op == REQ_OP_WRITE) ? "WRITE" : "READ",
	     (void*)_RET_IP_ );

	if (sector < bsr_md_first_sector(bdev) ||
	    sector + 7 > bsr_md_last_sector(bdev))
		bsr_alert(20, BSR_LC_IO, device, "%s [%d]:%s(,%llus,%s) out of range meta disk access",
		     current->comm, current->pid, __func__,
		     (unsigned long long)sector, 
			 (op == REQ_OP_WRITE) ? "WRITE" : "READ");

	err = _bsr_md_sync_page_io(device, bdev, sector, op);
	if (err) {
		bsr_err(21, BSR_LC_IO, device, "Failed to %s meta disk sector(%llus). error(%d)",
			(op == REQ_OP_WRITE) ? "WRITE" : "READ",
		    (unsigned long long)sector, err);
	}
	return err;
}

struct get_activity_log_ref_ctx {
	/* in: which extent on which device? */
	struct bsr_device *device;
	unsigned int enr;
	bool nonblock;

	/* out: do we need to wake_up(&device->al_wait)? */
	bool wake_up;
};
static struct bm_extent*
find_active_resync_extent(struct get_activity_log_ref_ctx *al_ctx)
{
	struct bsr_peer_device *peer_device;
	struct lc_element *tmp;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, al_ctx->device) {
		if (peer_device == NULL)
			goto out;
		// DW-1601 If greater than 112, remove act_log and resync_lru associations
#ifdef SPLIT_REQUEST_RESYNC
		if (peer_device->connection->agreed_pro_version <= 112) 
#endif
		{
			tmp = lc_find(peer_device->resync_lru, al_ctx->enr / AL_EXT_PER_BM_SECT);
			if (unlikely(tmp != NULL)) {
				struct bm_extent  *bm_ext = lc_entry(tmp, struct bm_extent, lce);
				if (test_bit(BME_NO_WRITES, &bm_ext->flags)) {
					if (peer_device->resync_wenr == tmp->lc_number) {
						int lc_put_result;						
						peer_device->resync_wenr = LC_FREE;
						lc_put_result = lc_put(__FUNCTION__, peer_device->resync_lru, &bm_ext->lce);
						if (lc_put_result == 0) {
							bm_ext->flags = 0;
							al_ctx->wake_up = true;
							peer_device->resync_locked--;
							continue;
						}
						else if (lc_put_result < 0) {
							bsr_err(1, BSR_LC_LRU, peer_device, "Failed to reduce lru cache reference count. enr(%u)", (al_ctx->enr / AL_EXT_PER_BM_SECT));
							continue;
						}
					}
					rcu_read_unlock();
					bsr_debug_al("return bm_ext, bm_ext->lce.lc_number = %u, bm_ext->lce.refcnt = %u", bm_ext->lce.lc_number, bm_ext->lce.refcnt);
					return bm_ext;
				}
			}
		}
	}
out:
	rcu_read_unlock();
	bsr_debug_al("return NULL");
	return NULL;
}

static void
set_bme_priority(struct get_activity_log_ref_ctx *al_ctx)
{
	struct bsr_peer_device *peer_device;
	struct lc_element *tmp;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, al_ctx->device) {
		// DW-1601 If greater than 112, remove act_log and resync_lru associations
#ifdef SPLIT_REQUEST_RESYNC
		if (peer_device->connection->agreed_pro_version <= 112)
#endif
		{
			tmp = lc_find(peer_device->resync_lru, al_ctx->enr / AL_EXT_PER_BM_SECT);
			if (tmp) {
				struct bm_extent  *bm_ext = lc_entry(tmp, struct bm_extent, lce);
				if (test_bit(BME_NO_WRITES, &bm_ext->flags)
					&& !test_and_set_bit(BME_PRIORITY, &bm_ext->flags))
					al_ctx->wake_up = true;
			}
		}
	}
	rcu_read_unlock();
}

static
struct lc_element *__al_get(const char* caller, struct get_activity_log_ref_ctx *al_ctx)
{
	struct bsr_device *device = al_ctx->device;
	struct lc_element *al_ext = NULL;
	struct bm_extent *bm_ext;

	spin_lock_irq(&device->al_lock);
	bm_ext = find_active_resync_extent(al_ctx);
	if (bm_ext) {
		set_bme_priority(al_ctx);
		goto out;
	}

	if (al_ctx->nonblock)
		al_ext = lc_try_get(caller, device->act_log, al_ctx->enr);
	else
		al_ext = lc_get(caller, device->act_log, al_ctx->enr);
out: 
	spin_unlock_irq(&device->al_lock);
	if (al_ctx->wake_up)
		wake_up(&device->al_wait);
	return al_ext;
}

static
struct lc_element *_al_get_nonblock(const char* caller, struct bsr_device *device, unsigned int enr)
{
	struct get_activity_log_ref_ctx al_ctx =
	{ .device = device, .enr = enr, .nonblock = true };
	return __al_get(caller, &al_ctx);
}

static
struct lc_element *_al_get(const char* caller, struct bsr_device *device, unsigned int enr)
{
	struct get_activity_log_ref_ctx al_ctx =
	{ .device = device, .enr = enr, .nonblock = false };
	return __al_get(caller, &al_ctx);
}

bool bsr_al_begin_io_fastpath(struct bsr_device *device, struct bsr_interval *i)
{
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	ULONG_PTR first = (ULONG_PTR)i->sector >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR last = i->size == 0 ? first : (ULONG_PTR)(i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT - 9);
	
	D_ASSERT(device, first <= last);
	D_ASSERT(device, atomic_read(&device->local_cnt) > 0);

	/* FIXME figure out a fast path for bios crossing AL extent boundaries */
	if (first != last)
		return false;
#ifdef _WIN64
	BUG_ON_UINT32_OVER(first);
#endif
	return _al_get_nonblock(__FUNCTION__, device, (unsigned int)first) != NULL;
}


#if (PAGE_SHIFT + 3) < (AL_EXTENT_SHIFT - BM_BLOCK_SHIFT)
/* Currently BM_BLOCK_SHIFT, BM_EXT_SHIFT and AL_EXTENT_SHIFT
 * are still coupled, or assume too much about their relation.
 * Code below will not work if this is violated.
 * Will be cleaned up with some followup patch.
 */
# error FIXME
#endif

static ULONG_PTR al_extent_to_bm_bit(unsigned int al_enr)
{
	return (ULONG_PTR)al_enr << (AL_EXTENT_SHIFT - BM_BLOCK_SHIFT);
}

static sector_t al_tr_number_to_on_disk_sector(struct bsr_device *device)
{
	const unsigned int stripes = device->ldev->md.al_stripes;
	const unsigned int stripe_size_4kB = device->ldev->md.al_stripe_size_4k;

	/* transaction number, modulo on-disk ring buffer wrap around */
	unsigned int t = device->al_tr_number % (device->ldev->md.al_size_4k);

	/* ... to aligned 4k on disk block */
	t = ((t % stripes) * stripe_size_4kB) + t/stripes;

	/* ... to 512 byte sector in activity log */
	t *= 8;

	/* ... plus offset to the on disk position */
	return device->ldev->md.md_offset + device->ldev->md.al_offset + t;
}

static int __al_write_transaction(struct bsr_device *device, struct al_transaction_on_disk *buffer)
{
	struct lc_element *e;
	sector_t sector;
	int mx;
	unsigned extent_nr;
	unsigned crc = 0;
	int err = 0;
	unsigned short i;
	ktime_t start_kt = ns_to_ktime(0);

	if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_REQUEST))
		start_kt = ktime_get();

	memset(buffer, 0, sizeof(*buffer));
	buffer->magic = cpu_to_be32(BSR_AL_MAGIC);
	buffer->tr_number = cpu_to_be32(device->al_tr_number);

	i = 0;

	bsr_bm_reset_al_hints(device);

	/* Even though no one can start to change this list
	 * once we set the LC_LOCKED -- from bsr_al_begin_io(),
	 * lc_try_lock_for_transaction() --, someone may still
	 * be in the process of changing it. */
	spin_lock_irq(&device->al_lock);

	list_for_each_entry_ex(struct lc_element, e, &device->act_log->to_be_changed, list) {
		if (i == AL_UPDATES_PER_TRANSACTION) {
			i++;
			break;
		}
#ifdef _WIN
	BUG_ON_UINT16_OVER(e->lc_index);
#endif
#ifdef _WIN64
	// DW-1918 the value of lc_new_number MAX should be verified by UINT32.
	BUG_ON_UINT32_OVER(e->lc_new_number);
#endif
		buffer->update_slot_nr[i] = cpu_to_be16((u16)e->lc_index);
		buffer->update_extent_nr[i] = cpu_to_be32((u32)e->lc_new_number);
		if (e->lc_number != LC_FREE) {
			ULONG_PTR start, end;

			start = al_extent_to_bm_bit(e->lc_number);
			end = al_extent_to_bm_bit(e->lc_number + 1) - 1;
			bsr_bm_mark_range_for_writeout(device, start, end);
		}
		i++;
	}
	spin_unlock_irq(&device->al_lock);
	BUG_ON(i > AL_UPDATES_PER_TRANSACTION);

	buffer->n_updates = cpu_to_be16(i);
	for ( ; i < AL_UPDATES_PER_TRANSACTION; i++) {
		buffer->update_slot_nr[i] = cpu_to_be16(UINT16_MAX);
		buffer->update_extent_nr[i] = cpu_to_be32(LC_FREE);
	}
#ifdef _WIN
	BUG_ON_UINT16_OVER(device->act_log->nr_elements);
	BUG_ON_UINT16_OVER(device->al_tr_cycle);
#endif
	buffer->context_size = cpu_to_be16((u16)device->act_log->nr_elements);
	buffer->context_start_slot_nr = cpu_to_be16((u16)device->al_tr_cycle);

	mx = min_t(int, AL_CONTEXT_PER_TRANSACTION,
		   device->act_log->nr_elements - device->al_tr_cycle);
	for (i = 0; i < mx; i++) {
		unsigned idx = device->al_tr_cycle + i;
		extent_nr = lc_element_by_index(device->act_log, idx)->lc_number;
		buffer->context[i] = cpu_to_be32(extent_nr);
	}
	for (; i < AL_CONTEXT_PER_TRANSACTION; i++)
		buffer->context[i] = cpu_to_be32(LC_FREE);

	device->al_tr_cycle += AL_CONTEXT_PER_TRANSACTION;
	if (device->al_tr_cycle >= device->act_log->nr_elements)
		device->al_tr_cycle = 0;

	sector = al_tr_number_to_on_disk_sector(device);
#ifdef _WIN
	crc = crc32c(0, (uint8_t*)buffer, 4096);
#else // _LIN
	crc = crc32c(0, buffer, 4096);
#endif
	buffer->crc32c = cpu_to_be32(crc);
	if (ktime_to_ms(start_kt))
		ktime_aggregate_delta(device, start_kt, al_before_bm_write_hinted_kt);
	if (bsr_bm_write_hinted(device))
		err = -EIO;
	else {
		bool write_al_updates;
		rcu_read_lock();
		write_al_updates = rcu_dereference(device->ldev->disk_conf)->al_updates;
		rcu_read_unlock();
		if (write_al_updates) {
			if (ktime_to_ms(start_kt))
				ktime_aggregate_delta(device, start_kt, al_after_bm_write_hinted_kt);
			if (bsr_md_sync_page_io(device, device->ldev, sector, REQ_OP_WRITE)) {
				err = -EIO;
				bsr_chk_io_error(device, 1, BSR_META_IO_ERROR);
			} else {
				device->al_tr_number++;
				device->al_writ_cnt++;
				if (ktime_to_ms(start_kt))
					atomic_inc(&device->al_updates_cnt);
			}
			// BSR-764 delay active log commit
			if (g_simul_perf.flag && g_simul_perf.type == SIMUL_PERF_DELAY_TYPE2)
				force_delay(g_simul_perf.delay_time);
			
			if (ktime_to_ms(start_kt))
				ktime_aggregate_delta(device, start_kt, al_after_sync_page_kt);
		}
	}

	return err;
}

static int al_write_transaction(struct bsr_device *device)
{
	struct al_transaction_on_disk *buffer;
	int err;

	if (!get_ldev(device)) {
		bsr_err(2, BSR_LC_LRU, device, "Failed to write activity log due to cannot start transaction because it is in the state %s",
			bsr_disk_str(device->disk_state[NOW]));
		return -EIO;
	}

	/* The bitmap write may have failed, causing a state change. */
	if (device->disk_state[NOW] < D_INCONSISTENT) {
		bsr_err(3, BSR_LC_LRU, device,
			"Failed to write activity log due to it is in the state %s",
			bsr_disk_str(device->disk_state[NOW]));
		put_ldev(__FUNCTION__, device);
		return -EIO;
	}

	/* protects md_io_buffer, al_tr_cycle, ... */
	buffer = bsr_md_get_buffer(device, __func__);
	if (!buffer) {
		bsr_err(22, BSR_LC_IO, device, "Failed to write activity log due to failure to get meta I/O buffer.");
		put_ldev(__FUNCTION__, device);
		return -ENODEV;
	}

	err = __al_write_transaction(device, buffer);

	bsr_md_put_buffer(device);
	put_ldev(__FUNCTION__, device);

	return err;
}

static int bm_e_weight(struct bsr_peer_device *peer_device, ULONG_PTR enr);

bool bsr_al_try_lock(struct bsr_device *device)
{
	bool locked;

	spin_lock_irq(&device->al_lock);
	locked = lc_try_lock(device->act_log);
	spin_unlock_irq(&device->al_lock);

	return locked;
}

bool bsr_al_try_lock_for_transaction(struct bsr_device *device)
{
	bool locked;

	spin_lock_irq(&device->al_lock);
	locked = lc_try_lock_for_transaction(device->act_log);
	spin_unlock_irq(&device->al_lock);

	return locked;
}


void bsr_al_begin_io_commit(struct bsr_device *device)
{
	bool locked = bsr_al_try_lock_for_transaction(device);

	wait_event(device->al_wait,
		device->act_log->pending_changes == 0 || locked);

	if (locked) {
		/* Double check: it may have been committed by someone else
		 * while we were waiting for the lock. */
		if (device->act_log->pending_changes) {
			bool write_al_updates;

			rcu_read_lock();
			write_al_updates = rcu_dereference(device->ldev->disk_conf)->al_updates;
			rcu_read_unlock();

			if (write_al_updates)
				al_write_transaction(device);
			spin_lock_irq(&device->al_lock);
			/* FIXME
			if (err)
				we need an "lc_cancel" here;
			*/
			lc_committed(device->act_log);
			spin_unlock_irq(&device->al_lock);
		}
		lc_unlock(device->act_log);
		wake_up(&device->al_wait);
	}
}

static bool put_actlog(const char* caller, struct bsr_device *device, unsigned int first, unsigned int last)
{
	struct lc_element *extent;
	unsigned long flags;
	unsigned int enr;
	bool wake = false;

	D_ASSERT(device, first <= last);
	spin_lock_irqsave(&device->al_lock, flags);
	for (enr = first; enr <= last; enr++) {
		int lc_put_result;		
		extent = lc_find(device->act_log, enr);
		if (!extent || extent->refcnt <= 0) {
			bsr_err(4, BSR_LC_LRU, device, "%s => Failed to put Activity log due to inactive extent %u", caller, enr);
			continue;
		}
		bsr_debug_al("called lc_put extent->lc_number= %u, extent->refcnt = %u", extent->lc_number, extent->refcnt); 
		lc_put_result = lc_put(caller, device->act_log, extent);
		if (lc_put_result == 0)
			wake = true;
	}
	spin_unlock_irqrestore(&device->al_lock, flags);
	if (wake)
		wake_up(&device->al_wait);

	return wake;
}

/**
* bsr_al_begin_io_for_peer() - Gets (a) reference(s) to AL extent(s)
* @peer_device:	BSR peer device to be targeted
* @i:			interval to check and register
*
* Ensures that the extents covered by the interval @i are hot in the
* activity log. This function makes sure the area is not active by any
* resync operation on any connection.
*/
int bsr_al_begin_io_for_peer(const char* caller, struct bsr_peer_device *peer_device, struct bsr_interval *i)
{
	struct bsr_device *device = peer_device->device;
	ULONG_PTR first = (ULONG_PTR)i->sector >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR last = i->size == 0 ? first : (ULONG_PTR)(i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR enr;
	bool need_transaction = false;

	D_ASSERT(peer_device, first <= last);
	D_ASSERT(peer_device, atomic_read(&device->local_cnt) > 0);

#ifdef _WIN64
	BUG_ON_UINT32_OVER(first);
	BUG_ON_UINT32_OVER(last);
#endif
	for (enr = first; enr <= last; enr++) {
		struct lc_element *al_ext;
		wait_event(device->al_wait,
				(al_ext = _al_get(__FUNCTION__, device, (unsigned int)enr)) != NULL ||
				peer_device->connection->cstate[NOW] < C_CONNECTED);
		if (al_ext == NULL) {
			if (enr > first)
				put_actlog(caller, device, (unsigned int)first, (unsigned int)(enr - 1));
			return -ECONNABORTED;
		}
		if (al_ext->lc_number != enr)
			need_transaction = true;
	}

	if (need_transaction)
		bsr_al_begin_io_commit(device);
	return 0;

}

extern atomic_t g_fake_al_used;

int bsr_al_begin_io_nonblock(struct bsr_device *device, struct bsr_interval *i)
{
	struct lru_cache *al = device->act_log;
	struct bm_extent *bm_ext;
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	ULONG_PTR first = (ULONG_PTR)i->sector >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR last = i->size == 0 ? first : (ULONG_PTR)(i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR nr_al_extents;
	unsigned int available_update_slots;
	struct get_activity_log_ref_ctx al_ctx = { .device = device, };
	ULONG_PTR enr;

	D_ASSERT(device, first <= last);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(first);
	BUG_ON_UINT32_OVER(last);
#endif
	nr_al_extents = 1 + last - first; /* worst case: all touched extends are cold. */

	// DW-1513 If the used value is greater than nr_elements, set available_update_slots to 0.
	if (al->nr_elements < (al->used + atomic_read(&g_fake_al_used)))	{
		available_update_slots = 0;
		bsr_warn(19, BSR_LC_LRU, device, "No update slot is available");
	} else {
		available_update_slots = min(al->nr_elements - (al->used + atomic_read(&g_fake_al_used)),
					al->max_pending_changes - al->pending_changes);
	}

	/* We want all necessary updates for a given request within the same transaction
	 * We could first check how many updates are *actually* needed,
	 * and use that instead of the worst-case nr_al_extents */
	if (available_update_slots < nr_al_extents) {
		/* Too many activity log extents are currently "hot".
		 *
		 * If we have accumulated pending changes already,
		 * we made progress.
		 *
		 * If we cannot get even a single pending change through,
		 * stop the fast path until we made some progress,
		 * or requests to "cold" extents could be starved. */
		if (!al->pending_changes) {
			set_bit(__LC_STARVING, &device->act_log->flags);
			if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_AL_STAT))
				device->e_al_starving++;
		}

		// DW-1945 fixup that Log debug logs when pending_changes are insufficient.
		// because insufficient of slots for pending_changes can occur frequently.
		if (al->max_pending_changes - al->pending_changes < nr_al_extents) {
			if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_AL_STAT))
				device->e_al_pending++;
			bsr_dbg(device, "insufficient al_extent slots for 'pending_changes' nr_al_extents:%llu pending:%u", (unsigned long long)nr_al_extents, al->pending_changes);
		} 
		else {
			if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_AL_STAT))
				device->e_al_used++;

			bsr_debug(5, BSR_LC_LRU, device, "Insufficient activity log extent slots for used slot. slot(%llu) used(%u)", (unsigned long long)nr_al_extents, (al->used + atomic_read(&g_fake_al_used)));
		}
		return -ENOBUFS;
	}

	/* Is resync active in this area? */
	for (enr = first; enr <= last; enr++) {
		al_ctx.enr = (unsigned int)enr;
		bm_ext = find_active_resync_extent(&al_ctx);
		if (unlikely(bm_ext != NULL)) {
			set_bme_priority(&al_ctx);
			bsr_debug(28, BSR_LC_LRU, device, "active resync extent enr : %llu", (unsigned long long)enr);
			if (al_ctx.wake_up) {
				if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_AL_STAT))
					device->e_al_busy++;
				return -EBUSY;
			}
			if (atomic_read(&g_bsrmon_run) & (1 << BSRMON_AL_STAT))
				device->e_al_wouldblock++;
			return -EWOULDBLOCK;
		}
	}


	// DW-1513 At this point, LC_STARVING flag should be cleared. Otherwise, LOGIC BUG occurs.
	if (test_bit(__LC_STARVING, &device->act_log->flags)) {
		clear_bit(__LC_STARVING, &device->act_log->flags);
	}

	/* Checkout the refcounts.
	 * Given that we checked for available elements and update slots above,
	 * this has to be successful. */
	for (enr = first; enr <= last; enr++) {
		struct lc_element *al_ext;
		al_ext = lc_get_cumulative(__FUNCTION__, device->act_log, (unsigned int)enr);
		if (!al_ext)
			bsr_err(6, BSR_LC_LRU, device, "LOGIC BUG, Failed to get activity log due to not exist. enr=%llu (LC_STARVING=%d LC_LOCKED=%d used=%u pending_changes=%u lc->free=%d lc->lru=%d)",
			(unsigned long long)enr,
			test_bit(__LC_STARVING, &device->act_log->flags),
			test_bit(__LC_LOCKED, &device->act_log->flags),
			device->act_log->used + atomic_read(&g_fake_al_used),
			device->act_log->pending_changes,
			!list_empty(&device->act_log->free),
			!list_empty(&device->act_log->lru)
			);
	}
	return 0;
}

/* put activity log extent references corresponding to interval i, return true
 * if at least one extent is now unreferenced. */
bool bsr_al_complete_io(const char* caller, struct bsr_device *device, struct bsr_interval *i)
{
	/* for bios crossing activity log extent boundaries,
	 * we may need to activate two extents in one go */
	ULONG_PTR first = (ULONG_PTR)i->sector >> (AL_EXTENT_SHIFT - 9);
	ULONG_PTR last = i->size == 0 ? first : (ULONG_PTR)(i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT - 9);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(first);
	BUG_ON_UINT32_OVER(last);
#endif
	bsr_debug_al("first = %llu last = %llu i->size = %u", (unsigned long long)first, (unsigned long long)last, i->size);

	return put_actlog(caller, device, (unsigned int)first, (unsigned int)last);
}

static int _try_lc_del(struct bsr_device *device, struct lc_element *al_ext)
{
	int rv;

	spin_lock_irq(&device->al_lock);
	rv = (al_ext->refcnt == 0);
	if (likely(rv))
		lc_del(device->act_log, al_ext);
	spin_unlock_irq(&device->al_lock);

	return rv;
}

/**
 * bsr_al_shrink() - Removes all active extents form the activity log
 * @device:	BSR device.
 *
 * Removes all active extents form the activity log, waiting until
 * the reference count of each entry dropped to 0 first, of course.
 *
 * You need to lock device->act_log with lc_try_lock() / lc_unlock()
 */
void bsr_al_shrink(struct bsr_device *device)
{
	struct lc_element *al_ext;
	unsigned int i;

	D_ASSERT(device, test_bit(__LC_LOCKED, &device->act_log->flags));

	for (i = 0; i < device->act_log->nr_elements; i++) {
		al_ext = lc_element_by_index(device->act_log, i);
		if (al_ext->lc_number == LC_FREE)
			continue;
		wait_event(device->al_wait, _try_lc_del(device, al_ext));
	}

	wake_up(&device->al_wait);
}

static bool extent_in_sync(struct bsr_peer_device *peer_device, unsigned int rs_enr)
{
	// DW-2096 send peer_in_sync to Ahead node.
	if (peer_device->repl_state[NOW] == L_ESTABLISHED || peer_device->repl_state[NOW] == L_AHEAD) {
		if (bsr_bm_total_weight(peer_device) == 0)
			return true;
		if (bm_e_weight(peer_device, rs_enr) == 0)
			return true;
	} else if (peer_device->repl_state[NOW] == L_SYNC_SOURCE ||
		peer_device->repl_state[NOW] == L_SYNC_TARGET) {
		bool rv = false;

		if (!bsr_try_rs_begin_io(peer_device, BM_EXT_TO_SECT(rs_enr), false)) {
			struct bm_extent *bm_ext;
			struct lc_element *e;

			e = lc_find(peer_device->resync_lru, rs_enr);
			bm_ext = lc_entry(e, struct bm_extent, lce);
			rv = (bm_ext->rs_left == 0);
			bsr_rs_complete_io(peer_device, BM_EXT_TO_SECT(rs_enr), __FUNCTION__);
		}

		return rv;
	}
	// DW-955 Need to send peer_in_sync to PausedSyncTarget and UpToDate node.
	else if (peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
		if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
			return true;
	}

	return false;
}

static void
consider_sending_peers_in_sync(struct bsr_peer_device *peer_device, unsigned int rs_enr)
{
	struct bsr_device *device = peer_device->device;
	u64 mask = NODE_MASK(peer_device->node_id), im;
	struct bsr_peer_device *p;
	int size_sect;

	if (peer_device->connection->agreed_pro_version < 110)
		return;

	for_each_peer_device_ref(p, im, device) {
		if (p == peer_device)
			continue;
		if (extent_in_sync(p, rs_enr))
			mask |= NODE_MASK(p->node_id);
	}

	size_sect = (int)(min(BM_SECT_PER_EXT,
			bsr_get_vdisk_capacity(device) - BM_EXT_TO_SECT(rs_enr)));

	for_each_peer_device_ref(p, im, device) {
		if (mask & NODE_MASK(p->node_id)) {
			bsr_send_peers_in_sync(p, mask, BM_EXT_TO_SECT(rs_enr), size_sect << 9);
		}
	}
}

int bsr_al_initialize(struct bsr_device *device, void *buffer)
{
	struct al_transaction_on_disk *al = buffer;
	struct bsr_md *md = &device->ldev->md;
	int al_size_4k = md->al_stripes * md->al_stripe_size_4k;
	int i;

	__al_write_transaction(device, al);
	/* There may or may not have been a pending transaction. */
	spin_lock_irq(&device->al_lock);
	lc_committed(device->act_log);
	spin_unlock_irq(&device->al_lock);

	/* The rest of the transactions will have an empty "updates" list, and
	 * are written out only to provide the context, and to initialize the
	 * on-disk ring buffer. */
	for (i = 1; i < al_size_4k; i++) {
		int err = __al_write_transaction(device, al);
		if (err)
			return err;
	}
	return 0;
}

static int w_update_peers(struct bsr_work *w, int unused)
{
	struct update_peers_work *upw = container_of(w, struct update_peers_work, w);
	struct bsr_peer_device *peer_device = upw->peer_device;
	struct bsr_device *device = peer_device->device;
	struct bsr_connection *connection = peer_device->connection;

	UNREFERENCED_PARAMETER(unused);

	consider_sending_peers_in_sync(peer_device, upw->enr);

	bsr_kfree(upw);

	kref_debug_put(&device->kref_debug, 5);
	kref_put(&device->kref, bsr_destroy_device);

	kref_debug_put(&connection->kref_debug, 14);
	kref_put(&connection->kref, bsr_destroy_connection);

	return 0;
}

/* inherently racy...
 * return value may be already out-of-date when this function returns.
 * but the general usage is that this is only use during a cstate when bits are
 * only cleared, not set, and typically only care for the case when the return
 * value is zero, or we already "locked" this "bitmap extent" by other means.
 *
 * enr is bm-extent number, since we chose to name one sector (512 bytes)
 * worth of the bitmap a "bitmap extent".
 *
 * TODO
 * I think since we use it like a reference count, we should use the real
 * reference count of some bitmap extent element from some lru instead...
 *
 */
static int bm_e_weight(struct bsr_peer_device *peer_device, ULONG_PTR enr)
{
	ULONG_PTR start, end;
	int count;

	start = enr << (BM_EXT_SHIFT - BM_BLOCK_SHIFT);
	end = ((enr + 1) << (BM_EXT_SHIFT - BM_BLOCK_SHIFT)) - 1;
	count = (unsigned int)bsr_bm_count_bits(peer_device->device, peer_device->bitmap_index, start, end);
#if DUMP_MD >= 3
	bsr_info(7, BSR_LC_LRU, peer_device, "enr=%lu weight=%d", enr, count);
#endif
	return count;
}

static const char *bsr_change_sync_fname[] = {
	[RECORD_RS_FAILED] = "bsr_rs_failed_io",
	[SET_IN_SYNC] = "bsr_set_in_sync",
	[SET_OUT_OF_SYNC] = "bsr_set_out_of_sync"
};


/* ATTENTION. The AL's extents are 4MB each, while the extents in the
 * resync LRU-cache are 128MB each.
 * The caller of this function has to hold an get_ldev() reference.
 *
 * Adjusts the caching members ->rs_left (success) or ->rs_failed (!success),
 * potentially pulling in (and recounting the corresponding bits)
 * this resync extent into the resync extent lru cache.
 *
 * Returns whether all bits have been cleared for this resync extent,
 * precisely: (rs_left <= rs_failed)
 *
 * TODO will be obsoleted once we have a caching lru of the on disk bitmap
 */
static bool update_rs_extent(struct bsr_peer_device *peer_device,
		unsigned int enr, int count, update_sync_bits_mode mode)
{
	struct bsr_device *device = peer_device->device;
	struct lc_element *e;

	D_ASSERT(device, atomic_read(&device->local_cnt));

	/* When setting out-of-sync bits,
	 * we don't need it cached (lc_find).
	 * But if it is present in the cache,
	 * we should update the cached bit count.
	 * Otherwise, that extent should be in the resync extent lru cache
	 * already -- or we want to pull it in if necessary -- (lc_get),
	 * then update and check rs_left and rs_failed. */
	if (mode == SET_OUT_OF_SYNC)
		e = lc_find(peer_device->resync_lru, enr);
	else
		e = lc_get(__FUNCTION__, peer_device->resync_lru, enr);
	if (e) {
		struct bm_extent *ext = lc_entry(e, struct bm_extent, lce);
		if (ext->lce.lc_number == enr) {
			if (mode == SET_IN_SYNC)
				ext->rs_left -= count;
			else if (mode == SET_OUT_OF_SYNC)
				ext->rs_left += count;
			else
				ext->rs_failed += count;
			if (ext->rs_left < ext->rs_failed) {
				struct bsr_connection *connection = peer_device->connection;
				bsr_warn(20, BSR_LC_LRU, peer_device, "BAD! There are more sync failures than out of sync set to sync. "
					"(enr=%u rs_left=%d rs_failed=%d count=%d cstate=%s %s)",
				     ext->lce.lc_number, ext->rs_left,
				     ext->rs_failed, count,
				     bsr_conn_str(connection->cstate[NOW]),
				     bsr_repl_str(peer_device->repl_state[NOW]));

				/* We don't expect to be able to clear more bits
				 * than have been set when we originally counted
				 * the set bits to cache that value in ext->rs_left.
				 * Whatever the reason (disconnect during resync,
				 * delayed local completion of an application write),
				 * try to fix it up by recounting here. */
				ext->rs_left = bm_e_weight(peer_device, enr);
			}
		} else {
			/* Normally this element should be in the cache,
			 * since bsr_rs_begin_io() pulled it already in.
			 *
			 * But maybe an application write finished, and we set
			 * something outside the resync lru_cache in sync.
			 */
			int rs_left = bm_e_weight(peer_device, enr);
			if (ext->flags != 0) {
				bsr_warn(21, BSR_LC_LRU, device, "changing resync lce: %u[%d;%02lx]"
				     " -> %u[%d;00]",
				     ext->lce.lc_number, ext->rs_left,
				     ext->flags, enr, rs_left);
				ext->flags = 0;
			}
			if (ext->rs_failed) {
				bsr_warn(38, BSR_LC_LRU, device, "Kicking resync_lru element enr=%u "
				     "out with rs_failed=%d",
				     ext->lce.lc_number, ext->rs_failed);
			}
			ext->rs_left = rs_left;
			ext->rs_failed = (mode == RECORD_RS_FAILED) ? count : 0;
			/* we don't keep a persistent log of the resync lru,
			 * we can commit any change right away. */
			lc_committed(peer_device->resync_lru);
		}
		if (mode != SET_OUT_OF_SYNC)
			lc_put(__FUNCTION__, peer_device->resync_lru, &ext->lce);
		/* no race, we are within the al_lock! */

		if (ext->rs_left <= ext->rs_failed) {
			// DW-1640 Node that are not synctarget or syncsource send P_PEERS_IN_SYNC packtet to synctarget, causing a disk inconsistency. 
			// Only sync source can send P_PEERS_IN_SYNC to peers. In BSR, it can be guaranteed that only primary is sync source. 
			if (device->resource->role[NOW] == R_PRIMARY ||
				// DW-1873 change P_PEERS_IN_SYNC send conditions
				is_sync_source(peer_device)) { //peer_device->repl_state[NOW] == L_SYNC_SOURCE){	
				struct update_peers_work *upw;
				upw = bsr_kmalloc(sizeof(*upw), GFP_ATOMIC | __GFP_NOWARN, '40SB');

				if (upw) {
					upw->enr = ext->lce.lc_number;
					upw->w.cb = w_update_peers;

					kref_get(&peer_device->device->kref);
					kref_debug_get(&peer_device->device->kref_debug, 5);

					kref_get(&peer_device->connection->kref);
					kref_debug_get(&peer_device->connection->kref_debug, 14);

					upw->peer_device = peer_device;
					bsr_queue_work(&device->resource->work, &upw->w);
				}
				else {
					if (bsr_ratelimit())
						bsr_warn(88, BSR_LC_MEMORY, peer_device, "Failed to allocate %d size memory for send peer in sync", sizeof(struct update_peers_work));
				}

				ext->rs_failed = 0;
				return true;
			// DW-1640
			}
			else {
				return true;
			}
		}
	} else if (mode != SET_OUT_OF_SYNC) {
		/* be quiet if lc_find() did not find it. */
		bsr_err(8, BSR_LC_LRU, device, "Failed to get resync extent. enr(%u), locked(%u/%u) flags(%llu)",
			enr,
		    peer_device->resync_locked,
		    peer_device->resync_lru->nr_elements,
		    (unsigned long long)peer_device->resync_lru->flags);
	}
	return false;
}

void bsr_advance_rs_marks(struct bsr_peer_device *peer_device, ULONG_PTR still_to_go)
{
    ULONG_PTR now = jiffies;
    ULONG_PTR last = peer_device->rs_mark_time[peer_device->rs_last_mark];

	int next = (peer_device->rs_last_mark + 1) % BSR_SYNC_MARKS;
	if (time_after_eq(now, last + BSR_SYNC_MARK_STEP)) {
		if (peer_device->rs_mark_left[peer_device->rs_last_mark] != still_to_go &&
		    peer_device->repl_state[NOW] != L_PAUSED_SYNC_T &&
		    peer_device->repl_state[NOW] != L_PAUSED_SYNC_S) {
			peer_device->rs_mark_time[next] = now;
			peer_device->rs_mark_left[next] = still_to_go;
			peer_device->rs_last_mark = next;
		}
		// BSR-1125 notify sync progress
		bsr_peer_device_post_work(peer_device, RS_PROGRESS_NOTIFY);
	}
}

/* It is called lazy update, so don't do write-out too often. */
static bool lazy_bitmap_update_due(struct bsr_peer_device *peer_device)
{
	return time_after(jiffies, peer_device->rs_last_writeout + 2*HZ);
}

static void maybe_schedule_on_disk_bitmap_update(struct bsr_peer_device *peer_device,
						 bool rs_done)
{
	if (rs_done) {
		if (peer_device->connection->agreed_pro_version <= 95 ||
			is_sync_target_state(peer_device, NOW)) {
			// DW-1908 check for duplicate completion
			if (test_bit(RS_DONE, &peer_device->flags))
				return;
			set_bit(RS_DONE, &peer_device->flags);
		}
			/* and also set RS_PROGRESS below */

		/* Else: rather wait for explicit notification via receive_state,
		 * to avoid uuids-rotated-too-fast causing full resync
		 * in next handshake, in case the replication link breaks
		 * at the most unfortunate time... */
	} else if (!lazy_bitmap_update_due(peer_device))
		return;

	bsr_peer_device_post_work(peer_device, RS_PROGRESS);
}

// BSR-1547
static int w_notify_oos_if_a_zero_or_not(struct bsr_work *w, int cancel) 
{
	struct peer_device_info peer_device_info;
	struct bsr_peer_device_work *pw =
		container_of(w, struct bsr_peer_device_work, w);

	if(pw) {
		// set the NEW information in the peer_device state to prevent redundant state output.
		mutex_lock(&notification_mutex);
		// NOTIFY_OOS does not initialize because it does not use peer_device_info.
		notify_peer_device_state(NULL, 0, pw->peer_device, &peer_device_info, NOTIFY_OOS);
		mutex_unlock(&notification_mutex);
		bsr_kfree(pw);
	}

	return 0;
}

// DW-844
ULONG_PTR update_sync_bits(const char* caller, struct bsr_peer_device *peer_device,
		ULONG_PTR sbnr, ULONG_PTR ebnr,
		update_sync_bits_mode mode, bool locked)
{
	/*
	 * We keep a count of set bits per resync-extent in the ->rs_left
	 * caching member, so we need to loop and work within the resync extent
	 * alignment. Typically this loop will execute exactly once.
	 */
	struct bsr_device *device = peer_device->device;
	unsigned long flags = 0;
	ULONG_PTR count = 0;
	unsigned int cleared = 0;
	// BSR-1470
	ULONG_PTR bm_total = bsr_bm_total_weight(peer_device);
	while (sbnr <= ebnr) {
		/* set temporary boundary bit number to last bit number within
		 * the resync extent of the current start bit number,
		 * but cap at provided end bit number */
		ULONG_PTR tbnr = min(ebnr, sbnr | BM_BLOCKS_PER_BM_EXT_MASK);
		int c;
		int bmi = peer_device->bitmap_index;

		if (mode == RECORD_RS_FAILED)
			/* Only called from bsr_rs_failed_io(), bits
			 * supposedly still set.  Recount, maybe some
			 * of the bits have been successfully cleared
			 * by application IO meanwhile.
			 */
			c = (int)bsr_bm_count_bits(device, bmi, sbnr, tbnr);
		else if (mode == SET_IN_SYNC)
			c = (int)bsr_bm_clear_bits(device, bmi, sbnr, tbnr);
		else /* if (mode == SET_OUT_OF_SYNC) */
			c = (int)bsr_bm_set_bits(device, bmi, sbnr, tbnr);

		if (c) {
#ifdef _WIN // DW-2174 if not locked, it acquires al_lock.
			if (!locked)
#endif
				spin_lock_irqsave(&device->al_lock, flags);
			cleared += update_rs_extent(peer_device, (unsigned int)BM_BIT_TO_EXT(sbnr), c, mode);
#ifdef _WIN // DW-2174
			if (!locked)
#endif
				spin_unlock_irqrestore(&device->al_lock, flags);
			count += c;
		}
		sbnr = tbnr + 1;
	}

	if (count) {
		// DW-1775 If not SET_OUT_OF_SYNC, check resync completion.
		if (mode != SET_OUT_OF_SYNC) {
			ULONG_PTR still_to_go; bool rs_is_done;
			if (mode == RECORD_RS_FAILED)
				peer_device->rs_failed += count;

			still_to_go = bsr_bm_total_weight(peer_device);
			rs_is_done = (still_to_go <= peer_device->rs_failed);

#ifdef SPLIT_REQUEST_RESYNC
			if (peer_device->connection->agreed_pro_version >= 113) {
				// DW-2076 resync completion must be done on the only synctarget otherwise retry resync may not proceed.
				if (rs_is_done && peer_device->repl_state[NOW] == L_SYNC_SOURCE) {
					rs_is_done = false;
				}
			}
#endif
			if (mode == SET_IN_SYNC) 
				bsr_advance_rs_marks(peer_device, still_to_go);

			if ((mode == SET_IN_SYNC && cleared) || rs_is_done) {
				maybe_schedule_on_disk_bitmap_update(peer_device, rs_is_done);
			}
		} 

		// BSR-1470 forward "change peer-device" event in case of OOS trigger (new/release).
		if((mode == SET_OUT_OF_SYNC && 0 == bm_total && bsr_bm_total_weight(peer_device)) ||
			(mode == SET_IN_SYNC && bm_total && 0 == bsr_bm_total_weight(peer_device))) {
			// BSR-1547
			struct bsr_peer_device_work *w;
			w = bsr_kmalloc(sizeof(*w), GFP_ATOMIC, 'W1SB');
			if (w) {
				w->peer_device = peer_device;
				w->w.cb = w_notify_oos_if_a_zero_or_not;
				bsr_queue_work(&device->resource->work, &w->w);
			}
		}

		wake_up(&device->al_wait);
	}
	else {
		// DW-1761 calls wake_up() to resolve the al_wait timeout when duplicate "SET_OUT_OF_SYNC"
		if (peer_device->repl_state[NOW] == L_AHEAD && mode == SET_OUT_OF_SYNC) {
			struct net_conf *nc;

		// BSR-444
#ifdef _WIN
			unsigned char oldIrql_rLock = 0;

			if (!locked)
				rcu_read_lock_w32_inner();
#else // _LIN
			rcu_read_lock();
#endif

			nc = rcu_dereference(peer_device->connection->transport.net_conf);

#ifdef _WIN
			if (!locked)
#endif
				rcu_read_unlock();

			if ((device->act_log->used + atomic_read(&g_fake_al_used)) < nc->cong_extents)
				wake_up(&device->al_wait);
		}
	}
	return count;
}

static bool plausible_request_size(int size)
{
	return size > 0
		&& size <= BSR_MAX_BATCH_BIO_SIZE
		&& IS_ALIGNED(size, 512);
}

/* clear the bit corresponding to the piece of storage in question:
 * size byte of data starting from sector.  Only clear a bits of the affected
 * one ore more _aligned_ BM_BLOCK_SIZE blocks.
 *
 * called by worker on L_SYNC_TARGET and receiver on SyncSource.
 *
 */
ULONG_PTR __bsr_change_sync(struct bsr_peer_device *peer_device, sector_t sector, int size,
		update_sync_bits_mode mode, const char* caller)
{
	/* Is called from worker and receiver context _only_ */
	struct bsr_device *device = peer_device->device;
	ULONG_PTR sbnr, ebnr, lbnr;
	ULONG_PTR count = 0;
	sector_t esector, nr_sectors;

	/* This would be an empty REQ_OP_FLUSH, be silent. */
	// BSR-1162 fix unnecessary error log output when receiving ID_OUT_OF_SYNC_FINISHED
	if ((mode == SET_OUT_OF_SYNC) && ((sector == ID_OUT_OF_SYNC_FINISHED) || (size == 0)))
		return 0;

	if (!plausible_request_size(size)) {
		bsr_info(1, BSR_LC_BITMAP, device, "%s => Skipped to setup sync mode(%d) due to request size is invalid. %s: sector(%llus) size(%u) nonsense!",
				caller,
				mode,
				bsr_change_sync_fname[mode],
				(unsigned long long)sector, 
				size);
		return 0;
	}

	if (!get_ldev(device)) {
#ifdef _DEBUG_OOS // DW-1153 add error log
	if (bsr_ratelimit())
		bsr_info(2, BSR_LC_BITMAP, device, "%s => Skipped to setup sync due to in %s state, sector(%llu), mode(%u)", caller, bsr_disk_str(device->disk_state[NOW]), sector, mode);
#endif
		return 0; /* no disk, no metadata, no bitmap to manipulate bits in */
	}

	nr_sectors = bsr_get_vdisk_capacity(device);
	esector = sector + (size >> 9) - 1;

	if (!expect(peer_device, sector < nr_sectors)) {
#ifdef _DEBUG_OOS // DW-1153 add error log
		bsr_info(3, BSR_LC_BITMAP, peer_device, "%s => Skipped to setup sync mode(%d) due to unexpected error, The sector(%llu) is larger than the capacity(%llu).", caller, mode, sector, nr_sectors);
#endif
		goto out;
	}
	if (!expect(peer_device, esector < nr_sectors))
		esector = nr_sectors - 1;

	lbnr = (ULONG_PTR)BM_SECT_TO_BIT(nr_sectors - 1);

	if (mode == SET_IN_SYNC) {
		/* Round up start sector, round down end sector.  We make sure
		 * we only clear full, aligned, BM_BLOCK_SIZE blocks. */
		if (unlikely(esector < BM_SECT_PER_BIT-1)) {
			// DW-1153 add error log
#ifdef _DEBUG_OOS
			// DW-1992 it is a normal operation, not an error, so it is output at the info level.
			bsr_debug(4, BSR_LC_BITMAP, peer_device, "%s => Skipped to setup sync due to smaller than bitmap bit size, sector(%llu) ~ sector(%llu)", caller, sector, esector);
#endif
			goto out;
		}

		if (unlikely(esector == (nr_sectors-1)))
			ebnr = lbnr;
		else
			ebnr = (ULONG_PTR)BM_SECT_TO_BIT(esector - (BM_SECT_PER_BIT - 1));
		sbnr = (ULONG_PTR)BM_SECT_TO_BIT(sector + BM_SECT_PER_BIT - 1);
	} else {
		/* We set it out of sync, or record resync failure.
		 * Should not round anything here. */
		sbnr = (ULONG_PTR)BM_SECT_TO_BIT(sector);
		ebnr = (ULONG_PTR)BM_SECT_TO_BIT(esector);
	}

#ifdef _WIN
	BUG_ON_UINT32_OVER(sbnr);
	BUG_ON_UINT32_OVER(ebnr);
#endif

	count = update_sync_bits(caller , peer_device, sbnr, ebnr, mode, false);
out:
	put_ldev(__FUNCTION__, device);
	return count;
}

bool bsr_set_all_out_of_sync(struct bsr_device *device, sector_t sector, int size)
{
	return bsr_set_sync(__FUNCTION__, device, sector, size, BSR_END_OF_BITMAP, BSR_END_OF_BITMAP);
}

/**
 * bsr_set_sync  -  Set a disk range in or out of sync
 * @device:	BSR device
 * @sector:	start sector of disk range
 * @size:	size of disk range in bytes
 * @bits:	bit values to use by bitmap index
 * @mask:	bitmap indexes to modify (mask set)
 */
// DW-1191 caller needs to determine the peers that oos has been set.
unsigned long bsr_set_sync(const char* caller, struct bsr_device *device, sector_t sector, int size,
		   ULONG_PTR bits, ULONG_PTR mask)
{
	ULONG_PTR set_start, set_end, clear_start, clear_end;
	sector_t esector, nr_sectors;

	// DW-1191
	unsigned long set_bits = 0;
#ifdef _WIN
	signed long flags;
#endif
	struct bsr_peer_device *peer_device;
	// DW-1871
	bool skip_clear = false;

	if (size <= 0 || !IS_ALIGNED(size, 512)) {
		bsr_info(7, BSR_LC_BITMAP, device, "%s => Skipped to setup sync due to size is invalid. sector(%llus), size(%d)",
			 __func__, (unsigned long long)sector, size);
		return false;
	}

	if (!get_ldev(device)) {
		// DW-1153 add error log
#ifdef _DEBUG_OOS
		if (bsr_ratelimit())
			bsr_info(5, BSR_LC_BITMAP, device, "Skipped to setup sync due to in %s state. sector(%llu)", bsr_disk_str(device->disk_state[NOW]), sector);
#endif
		return false; /* no disk, no metadata, no bitmap to set bits in */
	}

	mask &= (1 << device->bitmap->bm_max_peers) - 1;

	nr_sectors = bsr_get_vdisk_capacity(device);
	esector = sector + (size >> 9) - 1;

	if (!expect(device, sector < nr_sectors)) {
		// DW-1153 add error log
#ifdef _DEBUG_OOS
		bsr_info(6, BSR_LC_BITMAP, device, "Skipped to setup sync due to unexpected error, The sector(%llu) is larger than the capacity sector(%llu).", sector, nr_sectors);
#endif
		goto out;
	}

	if (!expect(device, esector < nr_sectors))
		esector = nr_sectors - 1;

	/* For marking sectors as out of sync, we need to round up. */
	set_start = (ULONG_PTR)BM_SECT_TO_BIT(sector);
	set_end = (ULONG_PTR)BM_SECT_TO_BIT(esector);


	/* For marking sectors as in sync, we need to round down except when we
	 * reach the end of the device: The last bit in the bitmap does not
	 * account for sectors past the end of the device.
	 * CLEAR_END can become negative here. */
	clear_start = (ULONG_PTR)BM_SECT_TO_BIT(sector + BM_SECT_PER_BIT - 1);
	if (esector == nr_sectors - 1)
		clear_end = (ULONG_PTR)BM_SECT_TO_BIT(esector);
	else {
		clear_end = (ULONG_PTR)BM_SECT_TO_BIT(esector + 1);
		// DW-1871 if clear_end is zero, you do not need to call it. update_sync_bits(), bsr_bm_clear_bits()
		if (clear_end == 0)
			skip_clear = true;
		else
			clear_end -= 1;
	}
#ifdef _WIN
	// DW-2174 acquire al_lock before rcu_read_lock() to avoid deadlock.
	spin_lock_irqsave(&device->al_lock, flags);
#endif
	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		int bitmap_index = peer_device->bitmap_index;

		if (bitmap_index == -1)
			continue;

		if (!test_and_clear_bit(bitmap_index, &mask))
			continue;

		if (test_bit(bitmap_index, &bits)) {
			// DW-1191 caller needs to know if the bits has been set at least.
			if (update_sync_bits(caller, peer_device, set_start, set_end, SET_OUT_OF_SYNC, true) > 0)
				set_bits |= (1 << bitmap_index);
		}

		// DW-1871
		else if (clear_start <= clear_end && !skip_clear)
			update_sync_bits(caller, peer_device, clear_start, clear_end, SET_IN_SYNC, true);
	}
	rcu_read_unlock();
#ifdef _WIN32 // DW-2174
	spin_unlock_irqrestore(&device->al_lock, flags);
#endif

	if (mask) {
		ULONG_PTR bitmap_index;
		for_each_set_bit(bitmap_index, (ULONG_PTR*)&mask, BITS_PER_LONG) {
#ifdef _WIN64
			BUG_ON_UINT32_OVER(bitmap_index);
#endif
			if (test_bit((unsigned int)bitmap_index, &bits))
				bsr_bm_set_bits(device, (unsigned int)bitmap_index, set_start, set_end);
			// DW-1871
			else if (clear_start <= clear_end && !skip_clear)
				bsr_bm_clear_bits(device, (unsigned int)bitmap_index, clear_start, clear_end);
		}
	}

out:
	put_ldev(__FUNCTION__, device);

	// DW-1191
	return set_bits;
}

static
struct bm_extent *_bme_get(struct bsr_peer_device *peer_device, unsigned int enr)
{
	struct bsr_device *device = peer_device->device;
	struct lc_element *e;
	struct bm_extent *bm_ext;
	int wakeup = 0;
	ULONG_PTR rs_flags;

	spin_lock_irq(&device->al_lock);
	if (peer_device->resync_locked > peer_device->resync_lru->nr_elements/2) {
		spin_unlock_irq(&device->al_lock);
		return NULL;
	}
	e = lc_get(__FUNCTION__, peer_device->resync_lru, enr);
	bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
	if (bm_ext) {
		if (bm_ext->lce.lc_number != enr) {
			bm_ext->rs_left = bm_e_weight(peer_device, enr);
			bm_ext->rs_failed = 0;
			lc_committed(peer_device->resync_lru);
			wakeup = 1;
		}
		if (bm_ext->lce.refcnt == 1)
			peer_device->resync_locked++;
		set_bit(BME_NO_WRITES, &bm_ext->flags);
	}
	rs_flags = peer_device->resync_lru->flags;
	spin_unlock_irq(&device->al_lock);
	if (wakeup)
		wake_up(&device->al_wait);

	if (!bm_ext) {
		if (rs_flags & LC_STARVING)
			bsr_warn(24, BSR_LC_LRU, peer_device, "Have to wait for element"
			     " (resync LRU too small?)");
		BUG_ON(rs_flags & LC_LOCKED);
	}

	return bm_ext;
}

static int _is_in_al(struct bsr_device *device, unsigned int enr)
{
	int rv;

	spin_lock_irq(&device->al_lock);
	rv = lc_is_used(device->act_log, enr);
	spin_unlock_irq(&device->al_lock);

	return rv;
}

/**
 * bsr_rs_begin_io() - Gets an extent in the resync LRU cache and sets it to BME_LOCKED
 *
 * This functions sleeps on al_wait. Returns 0 on success, -EINTR if interrupted.
 */
int bsr_rs_begin_io(struct bsr_peer_device *peer_device, sector_t sector)
{
	struct bsr_device *device = peer_device->device;
	ULONG_PTR enr = (ULONG_PTR)BM_SECT_TO_EXT(sector);
	struct bm_extent *bm_ext;
	int i, sig = 0;
	// BSR-838
	bool sa = false;
#ifdef _WIN64
	BUG_ON_UINT32_OVER((enr * AL_EXT_PER_BM_SECT + AL_EXT_PER_BM_SECT));
#endif

retry:
	wait_event_interruptible_ex(device->al_wait,
		(bm_ext = _bme_get(peer_device, (unsigned int)enr)), sig);

	if (sig)
		return -EINTR;

	if (test_bit(BME_LOCKED, &bm_ext->flags))
		return 0;

	if (peer_device->connection->agreed_pro_version < 115) {
		/* step aside only while we are above c-min-rate; unless disabled. */
		sa = bsr_rs_c_min_rate_throttle(peer_device);
	}

	for (i = 0; i < AL_EXT_PER_BM_SECT; i++) {
		wait_event_interruptible_ex(device->al_wait,
							!_is_in_al(device, (unsigned int)enr * AL_EXT_PER_BM_SECT + i) ||
							(sa && test_bit(BME_PRIORITY, &bm_ext->flags)), sig);

		if (sig || (sa && test_bit(BME_PRIORITY, &bm_ext->flags))) {
			int lc_put_result;			
			spin_lock_irq(&device->al_lock);
			lc_put_result = lc_put(__FUNCTION__, peer_device->resync_lru, &bm_ext->lce);
			if (lc_put_result == 0) {
				bm_ext->flags = 0; /* clears BME_NO_WRITES and eventually BME_PRIORITY */
				peer_device->resync_locked--;
				wake_up(&device->al_wait);
			}
			else if (lc_put_result < 0) {
				bsr_err(9, BSR_LC_LRU, device, "Failed to get resync LRU of enr(%u) because reference count(%d) was wrong.", enr, lc_put_result);
				spin_unlock_irq(&device->al_lock);
				return -EINTR;
			}
			spin_unlock_irq(&device->al_lock);
			if (sig)
				return -EINTR;
			if (schedule_timeout_interruptible(HZ/10))
				return -EINTR;
			goto retry;
		}
	}
	set_bit(BME_LOCKED, &bm_ext->flags);
	return 0;
}

/**
 * bsr_try_rs_begin_io() - Gets an extent in the resync LRU cache, does not sleep
 *
 * Gets an extent in the resync LRU cache, sets it to BME_NO_WRITES, then
 * tries to set it to BME_LOCKED. Returns 0 upon success, and -EAGAIN
 * if there is still application IO going on in this area.
 */
int bsr_try_rs_begin_io(struct bsr_peer_device *peer_device, sector_t sector, bool throttle)
{
	struct bsr_device *device = peer_device->device;
	ULONG_PTR enr = (ULONG_PTR)BM_SECT_TO_EXT(sector);
	const ULONG_PTR al_enr = enr * AL_EXT_PER_BM_SECT;
	struct lc_element *e;
	struct bm_extent *bm_ext;
	int i;


	if (throttle)
		throttle = bsr_rs_should_slow_down(peer_device, sector, true);

	/* If we need to throttle, a half-locked (only marked BME_NO_WRITES,
	 * not yet BME_LOCKED) extent needs to be kicked out explicitly if we
	 * need to throttle. There is at most one such half-locked extent,
	 * which is remembered in resync_wenr. */

	if (throttle && peer_device->resync_wenr != enr)
		return -EAGAIN;
#ifdef _WIN64
	BUG_ON_UINT32_OVER(enr);
	BUG_ON_UINT32_OVER(al_enr);
#endif

	spin_lock_irq(&device->al_lock);
	if (peer_device->resync_wenr != LC_FREE && peer_device->resync_wenr != enr) {
		/* in case you have very heavy scattered io, it may
		 * stall the syncer undefined if we give up the ref count
		 * when we try again and requeue.
		 *
		 * if we don't give up the refcount, but the next time
		 * we are scheduled this extent has been "synced" by new
		 * application writes, we'd miss the lc_put on the
		 * extent we keep the refcount on.
		 * so we remembered which extent we had to try again, and
		 * if the next requested one is something else, we do
		 * the lc_put here...
		 * we also have to wake_up
		 */

		e = lc_find(peer_device->resync_lru, peer_device->resync_wenr);
		bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
		if (bm_ext) {
			int lc_put_result;
			D_ASSERT(device, !test_bit(BME_LOCKED, &bm_ext->flags));
			D_ASSERT(device, test_bit(BME_NO_WRITES, &bm_ext->flags));
			clear_bit(BME_NO_WRITES, &bm_ext->flags);
			peer_device->resync_wenr = LC_FREE;
			lc_put_result = lc_put(__FUNCTION__, peer_device->resync_lru, &bm_ext->lce);
			if (lc_put_result == 0) {
				bm_ext->flags = 0;
				peer_device->resync_locked--;
			}
			else if (lc_put_result < 0) {
				bsr_err(10, BSR_LC_LRU, device, "Failed to get resync LRU because reference count(%d) was wrong.", lc_put_result);
				goto out;
			}
			 
			wake_up(&device->al_wait);
		} else {
			bsr_alert(11, BSR_LC_LRU, device, "LOGIC BUG, Failed to find bitmap extent information. resync_wenr(%d)", peer_device->resync_wenr);
		}
	}
	/* TRY. */
	e = lc_try_get(__FUNCTION__, peer_device->resync_lru, (unsigned int)enr);
	bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
	if (bm_ext) {
		if (test_bit(BME_LOCKED, &bm_ext->flags))
			goto proceed;
		if (!test_and_set_bit(BME_NO_WRITES, &bm_ext->flags)) {
			peer_device->resync_locked++;
		} else {
			/* we did set the BME_NO_WRITES,
			 * but then could not set BME_LOCKED,
			 * so we tried again.
			 * drop the extra reference. */
			bm_ext->lce.refcnt--;
			D_ASSERT(device, bm_ext->lce.refcnt > 0);
		}
		goto check_al;
	} else {
		/* do we rather want to try later? */
		if (peer_device->resync_locked > peer_device->resync_lru->nr_elements-3)
			goto try_again;
		/* Do or do not. There is no try. -- Yoda */
		e = lc_get(__FUNCTION__, peer_device->resync_lru, (unsigned int)enr);
		bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
		if (!bm_ext) {
			const ULONG_PTR rs_flags = peer_device->resync_lru->flags;
			if (rs_flags & LC_STARVING)
				bsr_warn(25, BSR_LC_LRU, device, "Have to wait for element"
				     " (resync LRU too small?)");
			BUG_ON(rs_flags & LC_LOCKED);
			goto try_again;
		}
		if (bm_ext->lce.lc_number != enr) {
			bm_ext->rs_left = bm_e_weight(peer_device, (unsigned int)enr);
			bm_ext->rs_failed = 0;
			lc_committed(peer_device->resync_lru);
			wake_up(&device->al_wait);
			D_ASSERT(device, test_bit(BME_LOCKED, &bm_ext->flags) == 0);
		}
		set_bit(BME_NO_WRITES, &bm_ext->flags);
		D_ASSERT(device, bm_ext->lce.refcnt == 1);
		peer_device->resync_locked++;
		goto check_al;
	}
check_al:
	// DW-1601 If greater than 112, remove act_log and resync_lru associations
#ifdef SPLIT_REQUEST_RESYNC
	if (peer_device->connection->agreed_pro_version <= 112) 
#endif
	{
		for (i = 0; i < AL_EXT_PER_BM_SECT; i++) {
			if (lc_is_used(device->act_log, (unsigned int)(al_enr + i))){
				bsr_debug_al("check_al sector = %llu, enr = %llu, al_enr + 1 = %llu and goto try_again", sector, (unsigned long long)enr, (unsigned long long)al_enr + i);
				goto try_again;
			}
		}
	}
	set_bit(BME_LOCKED, &bm_ext->flags);
proceed:
	bsr_debug_al("proceed sector = %llu, enr = %llu", sector, (unsigned long long)enr);
	peer_device->resync_wenr = LC_FREE;
	spin_unlock_irq(&device->al_lock);
	return 0;

try_again:
	if (bm_ext) {
		if (throttle ||
		    (test_bit(BME_PRIORITY, &bm_ext->flags) && bm_ext->lce.refcnt == 1)) {
			int lc_put_result;
			D_ASSERT(peer_device, !test_bit(BME_LOCKED, &bm_ext->flags));
			D_ASSERT(peer_device, test_bit(BME_NO_WRITES, &bm_ext->flags));
			clear_bit(BME_NO_WRITES, &bm_ext->flags);
			clear_bit(BME_PRIORITY, &bm_ext->flags);
			peer_device->resync_wenr = LC_FREE;
			lc_put_result = lc_put(__FUNCTION__, peer_device->resync_lru, &bm_ext->lce);
			if (lc_put_result == 0) {
				bm_ext->flags = 0;
				peer_device->resync_locked--;
			}
			else if (lc_put_result < 0){
				goto out;
			}
			wake_up(&device->al_wait);
		}
		else
			peer_device->resync_wenr = (unsigned int)enr;
	}
out:
	spin_unlock_irq(&device->al_lock);
	return -EAGAIN;
}

void bsr_rs_complete_io(struct bsr_peer_device *peer_device, sector_t sector, const char *caller)
{
	struct bsr_device *device = peer_device->device;
	ULONG_PTR enr = (ULONG_PTR)BM_SECT_TO_EXT(sector);
	struct lc_element *e;
	struct bm_extent *bm_ext;
	unsigned long flags;

#ifdef _WIN64
	BUG_ON_UINT32_OVER(enr);
#endif
	spin_lock_irqsave(&device->al_lock, flags);
	e = lc_find(peer_device->resync_lru, (unsigned int)enr);
	bm_ext = e ? lc_entry(e, struct bm_extent, lce) : NULL;
	if (!bm_ext) {
		spin_unlock_irqrestore(&device->al_lock, flags);
		if (bsr_ratelimit())
			bsr_err(31, BSR_LC_LRU, device, "%s => Failed to put resync LRU of enr(%u) was not found.", caller, enr);
		return;
	}

	if (bm_ext->lce.refcnt == 0) {
		spin_unlock_irqrestore(&device->al_lock, flags);
		bsr_err(32, BSR_LC_LRU, device, "%s => Failed to put resync LRU because reference count is 0, reference count of resync LRU cannot be reduced. enr(%u), sector(%llu), BM_BIT(%llu)",
			caller, (unsigned long long)enr, (unsigned long long)sector, (unsigned long long)BM_SECT_TO_BIT(sector));
		return;
	}

	if (lc_put(__FUNCTION__, peer_device->resync_lru, &bm_ext->lce) == 0) {
		bm_ext->flags = 0; /* clear BME_LOCKED, BME_NO_WRITES and BME_PRIORITY */
		peer_device->resync_locked--;
		wake_up(&device->al_wait);
	}

	spin_unlock_irqrestore(&device->al_lock, flags);
}

/**
 * bsr_rs_cancel_all() - Removes all extents from the resync LRU (even BME_LOCKED)
 */
void bsr_rs_cancel_all(struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
	spin_lock_irq(&device->al_lock);

	if (get_ldev_if_state(device, D_DETACHING)) { /* Makes sure ->resync is there. */
		lc_reset(peer_device->resync_lru);
		put_ldev(__FUNCTION__, device);
	}
	peer_device->resync_locked = 0;
	peer_device->resync_wenr = LC_FREE;
	spin_unlock_irq(&device->al_lock);
	wake_up(&device->al_wait);
}

/**
 * bsr_rs_del_all() - Gracefully remove all extents from the resync LRU
 *
 * Returns 0 upon success, -EAGAIN if at least one reference count was
 * not zero.
 */
int bsr_rs_del_all(struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
	struct lc_element *e;
	struct bm_extent *bm_ext;
	unsigned int i;

	spin_lock_irq(&device->al_lock);

	if (get_ldev_if_state(device, D_DETACHING)) {
		/* ok, ->resync is there. */
		for (i = 0; i < peer_device->resync_lru->nr_elements; i++) {
			e = lc_element_by_index(peer_device->resync_lru, i);
			bm_ext = lc_entry(e, struct bm_extent, lce);
			if (bm_ext->lce.lc_number == LC_FREE)
				continue;
			if (bm_ext->lce.lc_number == peer_device->resync_wenr) {
				bsr_info(39, BSR_LC_LRU, peer_device, "Dropping %u in resync lru delete all, apparently"
				     " got 'synced' by application io",
				     peer_device->resync_wenr);
				D_ASSERT(peer_device, !test_bit(BME_LOCKED, &bm_ext->flags));
				D_ASSERT(peer_device, test_bit(BME_NO_WRITES, &bm_ext->flags));
				clear_bit(BME_NO_WRITES, &bm_ext->flags);
				peer_device->resync_wenr = LC_FREE;
				lc_put(__FUNCTION__, peer_device->resync_lru, &bm_ext->lce);
			}
			if (bm_ext->lce.refcnt != 0) {
				bsr_info(40, BSR_LC_LRU, peer_device, "Retrying resync lru delete all later. number=%u, "
				     "refcnt=%u", bm_ext->lce.lc_number, bm_ext->lce.refcnt);
				put_ldev(__FUNCTION__, device);
				spin_unlock_irq(&device->al_lock);
				return -EAGAIN;
			}
			D_ASSERT(peer_device, !test_bit(BME_LOCKED, &bm_ext->flags));
			D_ASSERT(peer_device, !test_bit(BME_NO_WRITES, &bm_ext->flags));
			lc_del(peer_device->resync_lru, &bm_ext->lce);
		}
		D_ASSERT(peer_device, peer_device->resync_lru->used == 0);
		put_ldev(__FUNCTION__, device);
	}
	spin_unlock_irq(&device->al_lock);
	wake_up(&device->al_wait);

	return 0;
}

bool bsr_sector_has_priority(struct bsr_peer_device *peer_device, sector_t sector)
{
	struct bsr_device *device = peer_device->device;
	struct lc_element *tmp;
	bool has_priority = false;
#ifdef _WIN64
	BUG_ON_UINT32_OVER(BM_SECT_TO_EXT(sector));
#endif
	spin_lock_irq(&device->al_lock);
	tmp = lc_find(peer_device->resync_lru, (unsigned int)BM_SECT_TO_EXT(sector));
	if (tmp) {
		struct bm_extent *bm_ext = lc_entry(tmp, struct bm_extent, lce);
		has_priority = test_bit(BME_PRIORITY, &bm_ext->flags);
	}
	spin_unlock_irq(&device->al_lock);
	return has_priority;
}
