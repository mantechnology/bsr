/*
   bsr_main.c

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>.

   Thanks to Carter Burden, Bart Grantham and Gennadiy Nerubayev
   from Logicworks, Inc. for making SDP replication support possible.

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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#ifdef _WIN
// DW-1587 
 /* Turns off the C6319 warning caused by code analysis.
 * The use of comma does not cause any performance problems or bugs, 
 * but keep the code as it is written.
 */
#include <ntifs.h>
#include "./bsr-kernel-compat/windows/bsr_endian.h"
#include "./bsr-kernel-compat/windows/kernel.h"


#else // _LIN
#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <asm/types.h>
#include <net/sock.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/dynamic_debug.h>

#include <linux/list_sort.h>
#endif
#include "../bsr-headers/bsr.h"
#include "../bsr-headers/linux/bsr_limits.h"
#include "bsr_int.h"
#include "../bsr-headers/bsr_protocol.h"
#include "bsr_req.h" /* only for _req_mod in tl_release and tl_clear */
#include "bsr_vli.h"


#ifdef _WIN_SEND_BUF
#include "bsr_send_buf.h"
#endif
#include "bsr_debugfs.h"
#include "../bsr-headers/bsr_meta_data.h"
#ifdef _LIN 
#ifdef COMPAT_HAVE_LINUX_BYTEORDER_SWABB_H
#include <linux/byteorder/swabb.h>
#else
#include <linux/swab.h>
#endif
#endif
#ifdef _WIN_MULTIVOL_THREAD
#include "Proto.h"
#endif


#ifdef COMPAT_BSR_RELEASE_RETURNS_VOID
#define BSR_RELEASE_RETURN void
#else
#define BSR_RELEASE_RETURN int
#endif

#ifdef _WIN
#define BSR_LOG_FILE_NAME L"bsrlog.txt"
// rolling file format, ex) bsrlog.txt_2020-06-02T104543.745 
#define BSR_LOG_ROLLING_FILE_NAME L"bsrlog.txt_"
#endif
#define BSR_LOG_FILE_COUNT 0x00
#define BSR_LOG_FILE_DELETE 0x01

#define MAX_PATH 260

#ifdef _WIN
static int bsr_open(struct block_device *bdev, fmode_t mode);
static BSR_RELEASE_RETURN bsr_release(struct gendisk *gd, fmode_t mode);
#else // _LIN
int bsr_open(struct block_device *bdev, fmode_t mode);
BSR_RELEASE_RETURN bsr_release(struct gendisk *gd, fmode_t mode);
#endif

#ifdef _WIN
static KDEFERRED_ROUTINE md_sync_timer_fn;
static KDEFERRED_ROUTINE peer_ack_timer_fn;
KSTART_ROUTINE bsr_thread_setup;
extern void nl_policy_init_by_manual(void);
extern KDEFERRED_ROUTINE sended_timer_fn;
#else // _LIN
static void md_sync_timer_fn(BSR_TIMER_FN_ARG);
extern void sended_timer_fn(BSR_TIMER_FN_ARG);
#endif
static int w_bitmap_io(struct bsr_work *w, int unused);
static int flush_send_buffer(struct bsr_connection *connection, enum bsr_stream bsr_stream);
#ifdef _LIN
MODULE_AUTHOR("Man Technology Inc. <bsr@mantech.co.kr>");
MODULE_DESCRIPTION("bsr - Block Sync and Replication v" REL_VERSION);
MODULE_VERSION(REL_VERSION);
MODULE_LICENSE("GPL");
MODULE_PARM_DESC(minor_count, "Approximate number of bsr devices ("
		 __stringify(BSR_MINOR_COUNT_MIN) "-" __stringify(BSR_MINOR_COUNT_MAX) ")");
MODULE_ALIAS_BLOCKDEV_MAJOR(BSR_MAJOR);

#include <linux/moduleparam.h>
/* allow_open_on_secondary */
MODULE_PARM_DESC(allow_oos, "DONT USE!");
/* thanks to these macros, if compiled into the kernel (not-module),
 * this becomes the boot parameter bsr.minor_count */
module_param(minor_count, uint, 0444);
module_param(disable_sendpage, bool, 0644);
module_param(allow_oos, bool, 0);
#ifdef _LIN_FAST_SYNC
module_param(debug_fast_sync, bool, 0644);
#endif
#endif

#ifdef CONFIG_BSR_FAULT_INJECTION

//Example: Simulate data write errors on / dev / bsr0 with a probability of 5 % .
//		echo 16 > /sys/module/bsr/parameters/enable_faults
//		echo 1 > /sys/module/bsr/parameters/fault_devs
//		echo 5 > /sys/module/bsr/parameters/fault_rate

int enable_faults = 0;  // 0xFFFF;
int fault_rate = 0;     // test on lower than 5%
int fault_devs = 0;     // minor number for test target
static int fault_count = 0;
int two_phase_commit_fail;
extern spinlock_t g_inactive_lock;
extern spinlock_t g_unacked_lock;

#ifdef _LIN
/* bitmap of enabled faults */
module_param(enable_faults, int, 0664);
/* fault rate % value - applies to all enabled faults */
module_param(fault_rate, int, 0664);
/* count of faults inserted */
module_param(fault_count, int, 0664);
/* bitmap of devices to insert faults on */
module_param(fault_devs, int, 0644);
module_param(two_phase_commit_fail, int, 0644);
#endif
#endif

// BSR-578
struct log_idx_ring_buffer_t gLogBuf;
atomic_t64 gLogCnt;

enum bsr_thread_state g_consumer_state;
#ifdef _WIN
PVOID g_consumer_thread;
#else // _LIN
struct task_struct *g_consumer_thread;
#endif

/* module parameter, defined */
unsigned int minor_count = BSR_MINOR_COUNT_DEF;
#ifdef _WIN 
// if not initialized, it means error.
bool disable_sendpage = true;      // not support page I/O
#else // _LIN
bool disable_sendpage;
#endif
bool allow_oos = false;
#ifdef _LIN_FAST_SYNC
bool debug_fast_sync = false;
#endif
/* Module parameter for setting the user mode helper program
 * to run. Default is /sbin/bsradm */
#ifdef _WIN
char usermode_helper[80] = "bsradm.exe";
#else // _LIN
char usermode_helper[80] = "/sbin/bsradm";
// BSR-626 default value of handler_use is disable
int g_handler_use = 0;
#endif

// BSR-654
atomic_t g_debug_output_category = ATOMIC_INIT(0);
// BSR-740 default value of bsrmon_run is enable
atomic_t g_bsrmon_run = ATOMIC_INIT(1);

// BSR-764
SIMULATION_PERF_DEGR g_simul_perf = {0,};

#ifdef _LIN
module_param_string(usermode_helper, usermode_helper, sizeof(usermode_helper), 0644);
#endif
/* in 2.6.x, our device mapping and config info contains our virtual gendisks
 * as member "struct gendisk *vdisk;"
 */
struct idr bsr_devices;
struct list_head bsr_resources;

#ifdef _WIN
NPAGED_LOOKASIDE_LIST bsr_al_ext_cache;	/* bitmap extents */
NPAGED_LOOKASIDE_LIST bsr_bm_ext_cache;	/* activity log extents */
#else // _LIN
struct kmem_cache *bsr_request_cache;
struct kmem_cache *bsr_ee_cache;	/* peer requests */
struct kmem_cache *bsr_bm_ext_cache;	/* bitmap extents */
struct kmem_cache *bsr_al_ext_cache;	/* activity log extents */
#endif
mempool_t *bsr_request_mempool;
mempool_t *bsr_ee_mempool;
mempool_t *bsr_md_io_page_pool;
struct BSR_BIO_SET bsr_md_io_bio_set;
struct BSR_BIO_SET bsr_io_bio_set;

/* I do not use a standard mempool, because:
   1) I want to hand out the pre-allocated objects first.
   2) I want to be able to interrupt sleeping allocation with a signal.
   Note: This is a single linked list, the next pointer is the private
	 member of struct page.
 */
#ifdef _LIN
struct page *bsr_pp_pool;
#endif
spinlock_t   bsr_pp_lock;
int          bsr_pp_vacant;
wait_queue_head_t bsr_pp_wait;

#ifdef _LIN
// BSR-875
struct bsr_mem_usage mem_usage = {ATOMIC_INIT(0),};
#endif

#ifdef _LIN
static const struct file_operations bsr_ctl_fops = {
		.unlocked_ioctl = bsr_control_ioctl,
};

#define BSR_CTRL_MINOR MISC_DYNAMIC_MINOR
static struct miscdevice bsr_misc = {
	.minor		= BSR_CTRL_MINOR,
	.name		= "bsr-control",
	.fops		= &bsr_ctl_fops,
};

#endif

#ifdef _WIN
struct ratelimit_state bsr_ratelimit_state;	// need to initialize before use.

static inline void ratelimit_state_init(struct ratelimit_state *state, int interval_init, int burst_init)
{
	if (NULL != state) {
		state->interval = interval_init;
		state->burst = burst_init;
		spin_lock_init(&state->lock);
	}
}

#else // _LIN
DEFINE_RATELIMIT_STATE(bsr_ratelimit_state, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);
#endif

// DW-1130 check if peer's replication state is ok to forget it's bitmap.
static inline bool isForgettableReplState(enum bsr_repl_state repl_state)
{
	if (repl_state < L_ESTABLISHED ||
		repl_state == L_SYNC_SOURCE ||
		repl_state == L_AHEAD ||
		repl_state == L_WF_BITMAP_S ||
		// DW-1369 do not clear bitmap when STARTING_SYNC_X state.
		repl_state == L_STARTING_SYNC_S ||
		repl_state == L_STARTING_SYNC_T
		)
		return false;

	return true;
}

#ifdef _WIN
EX_SPIN_LOCK g_rcuLock; //rcu lock is ported with spinlock
struct mutex g_genl_mutex;
// DW-1495 change att_mod_mutex(DW-1293) to global mutex because it can be a problem if IO also occurs on othere resouces on the same disk. 
struct mutex att_mod_mutex; 
// DW-1998
u8 g_genl_run_cmd;
struct mutex g_genl_run_cmd_mutex;
// BSR-822
struct mutex handler_mutex;
#endif

#ifdef _WIN
static const struct block_device_operations bsr_ops = {
	.open =    bsr_open,
	.release = bsr_release,
};
#else // _LIN
extern const struct block_device_operations bsr_ops;
#endif


#ifdef COMPAT_HAVE_BIO_FREE
static void bio_destructor_bsr(struct bio *bio)
{
	bio_free(bio, bsr_md_io_bio_set);
}
#endif

#ifdef _WIN
struct bio *bio_alloc_bsr(gfp_t gfp_mask, ULONG Tag)
#else // _LIN
struct bio *bio_alloc_bsr(struct block_device *bdev, gfp_t gfp_mask, int op)
#endif
{
#ifdef _WIN
	return bio_alloc(gfp_mask, 1, Tag);
#else // _LIN
	struct bio *bio;

 	if (!bioset_initialized(&bsr_md_io_bio_set)) {
#ifdef COMPAT_BIO_ALLOC_HAS_4_PARAMS
 		return bio_alloc(bdev, 1, op, gfp_mask);
#else
 		return bio_alloc(gfp_mask, 1);
#endif
 	}
#ifdef COMPAT_BIO_ALLOC_HAS_4_PARAMS
	bio = bio_alloc_bioset(bdev, 1, op, gfp_mask, &bsr_md_io_bio_set);
#else
	bio = bio_alloc_bioset(gfp_mask, 1, &bsr_md_io_bio_set);
#endif
	if (!bio)
		return NULL;
#ifdef COMPAT_HAVE_BIO_FREE
	bio->bi_destructor = bio_destructor_bsr;
#endif
	return bio;
#endif
}

#ifdef __CHECKER__
/* When checking with sparse, and this is an inline function, sparse will
   give tons of false positives. When this is a real functions sparse works.
 */
int _get_ldev_if_state(struct bsr_device *device, enum bsr_disk_state mins)
{
	int io_allowed;

	atomic_inc(&device->local_cnt);
	io_allowed = (device->disk_state[NOW] >= mins);
	if (!io_allowed) {
		if (atomic_dec_and_test(&device->local_cnt))
			wake_up(&device->misc_wait);
	}
	return io_allowed;
}

#endif

struct bsr_connection *__bsr_next_connection_ref(u64 *visited,
						   struct bsr_connection *connection,
						   struct bsr_resource *resource)
{
	int node_id;

	rcu_read_lock();
	if (!connection) {
        list_first_or_null_rcu_ex(connection, &resource->connections, struct bsr_connection, connections);
		*visited = 0;
	} else {
		struct list_head *pos;
		bool previous_visible; /* on the resources connections list */

		pos = list_next_rcu(&connection->connections);
		/* follow the pointer first, then check if the previous element was
		   still an element on the list of visible connections. */
		smp_rmb();
		previous_visible = !test_bit(C_UNREGISTERED, &connection->flags);

		kref_debug_put(&connection->kref_debug, 13);
		kref_put(&connection->kref, bsr_destroy_connection);

		if (pos == &resource->connections) {
			connection = NULL;
		} else if (previous_visible) {	/* visible -> we are now on a vital element */
			connection = list_entry_rcu(pos, struct bsr_connection, connections);
		} else { /* not visible -> pos might point to a dead element now */
			for_each_connection_rcu(connection, resource) {
				node_id = connection->peer_node_id;
				if (!(*visited & NODE_MASK(node_id)))
					goto found;
			}
			connection = NULL;
		}
	}

	if (connection) {
	found:
		node_id = connection->peer_node_id;
		*visited |= NODE_MASK(node_id);

		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 13);
	}

	rcu_read_unlock();
	return connection;
}


struct bsr_peer_device *__bsr_next_peer_device_ref(u64 *visited,
						     struct bsr_peer_device *peer_device,
						     struct bsr_device *device)
{
	rcu_read_lock();
	if (!peer_device) {
        list_first_or_null_rcu_ex(peer_device, &device->peer_devices, struct bsr_peer_device, peer_devices);
		*visited = 0;
	} else {
		struct list_head *pos;
		bool previous_visible;

		pos = list_next_rcu(&peer_device->peer_devices);
		smp_rmb();
		previous_visible = !test_bit(C_UNREGISTERED, &peer_device->connection->flags);

		kref_debug_put(&peer_device->connection->kref_debug, 15);
		kref_put(&peer_device->connection->kref, bsr_destroy_connection);

		if (pos == &device->peer_devices) {
			peer_device = NULL;
		} else if (previous_visible) {
			peer_device = list_entry_rcu(pos, struct bsr_peer_device, peer_devices);
		} else {
			for_each_peer_device_rcu(peer_device, device) {
				if (!(*visited & NODE_MASK(peer_device->node_id)))
					goto found;
			}
			peer_device = NULL;
		}
	}

	if (peer_device) {
	found:
		*visited |= NODE_MASK(peer_device->node_id);

		kref_get(&peer_device->connection->kref);
		kref_debug_get(&peer_device->connection->kref_debug, 15);
	}

	rcu_read_unlock();
	return peer_device;
}

/* This is a list walk that holds a reference on the next element! The
   reason for that is that one of the requests might hold a reference to a
   following request. A _req_mod() that destroys the current req might drop
   the references on the next request as well! I.e. the "save" of a
   list_for_each_entry_safe() element gets destroyed! -- With holding a
   reference that destroy gets delayed as necessary */

#define tl_for_each_req_ref_from(req, next, tl)		\
	for (req = __tl_first_req_ref(&next, req, tl);	\
	     req;					\
	     req = __tl_next_req_ref(&next, req, tl))

#define tl_for_each_req_ref(req, next, tl)				\
	for (req = __tl_first_req_ref(&next,				\
	list_first_entry_or_null(tl, struct bsr_request, tl_requests), \
				      tl);				\
	     req;							\
	     req = __tl_next_req_ref(&next, req, tl))

static struct bsr_request *__tl_first_req_ref(struct bsr_request **pnext,
					       struct bsr_request *req,
					       struct list_head *transfer_log)
{
	if (req) {
		struct bsr_request *next = list_next_entry_ex(struct bsr_request, req, tl_requests);
		
		if (&next->tl_requests != transfer_log)
			kref_get(&next->kref);
		*pnext = next;
	}
	return req;
}

static struct bsr_request *__tl_next_req_ref(struct bsr_request **pnext,
					      struct bsr_request *req,
					      struct list_head *transfer_log)
{
	struct bsr_request *next = *pnext;
	bool next_is_head = (&next->tl_requests == transfer_log);

	do {
		if (next_is_head)
			return NULL;
		req = next;
		next = list_next_entry_ex(struct bsr_request, req, tl_requests);
		
		next_is_head = (&next->tl_requests == transfer_log);
		if (!next_is_head)
			kref_get(&next->kref);
	} while (kref_put(&req->kref, bsr_req_destroy));
	*pnext = next;
	return req;
}

static void tl_abort_for_each_req_ref(struct bsr_request *next, struct list_head *transfer_log)
{
	if (&next->tl_requests != transfer_log)
		kref_put(&next->kref, bsr_req_destroy);
}

/**
 * tl_release() - mark as BARRIER_ACKED all requests in the corresponding transfer log epoch
 * @device:	BSR device.
 * @barrier_nr:	Expected identifier of the BSR write barrier packet.
 * @set_size:	Expected number of requests before that barrier.
 *
 * In case the passed barrier_nr or set_size does not match the oldest
 * epoch of not yet barrier-acked requests, this function will cause a
 * termination of the connection.
 */
void tl_release(struct bsr_connection *connection, int barrier_nr,
		unsigned int set_size)
{
	struct bsr_resource *resource = connection->resource;
	struct bsr_request *r;
	struct bsr_request *req = NULL;
	int expect_epoch = 0;
	unsigned int expect_size = 0;

	spin_lock_irq(&connection->resource->req_lock);

	/* find oldest not yet barrier-acked write request,
	 * count writes in its epoch. */
	list_for_each_entry_ex(struct bsr_request, r, &resource->transfer_log, tl_requests) {
		struct bsr_peer_device *peer_device;
		int idx;
		peer_device = conn_peer_device(connection, r->device->vnr);
		idx = 1 + peer_device->node_id;

		if (!req) {
			if (!(r->rq_state[0] & RQ_WRITE))
				continue;
			if (!(r->rq_state[idx] & RQ_NET_MASK))
				continue;
			if (r->rq_state[idx] & RQ_NET_DONE)
				continue;
			
			// BSR-901 requests for which RQ_EXP_BARR_ACK is not set are skipped
			// when find oldest not yet barrier-acked write request.
			if (!(r->rq_state[idx] & RQ_EXP_BARR_ACK))
				continue;

			req = r;
			expect_epoch = req->epoch;
			expect_size ++;
		} else {
			if (r->epoch != expect_epoch)
				break;
			if (!(r->rq_state[0] & RQ_WRITE))
				continue;
			// _WIN_MULTI_VOLUME
			// DW-1166 Check RQ_NET_DONE for multi-volume
			if (!(r->rq_state[idx] & RQ_NET_MASK))
				continue;
			if (r->rq_state[idx] & RQ_NET_DONE)
				continue;

			// BSR-901 requests for which RQ_EXP_BARR_ACK is not set are skipped
			// when find oldest not yet barrier-acked write request.
			if (!(r->rq_state[idx] & RQ_EXP_BARR_ACK))
				continue;

			expect_size++;
		}
	}

	/* first some paranoia code */
	if (req == NULL) {
		bsr_err(1, BSR_LC_REPLICATION, connection, "BAD! BarrierAck #%u received, but no epoch in transfer log!?",
			 (unsigned int)barrier_nr);
		goto bail;
	}
	if (expect_epoch != barrier_nr) {
		bsr_err(2, BSR_LC_REPLICATION, connection, "BAD! BarrierAck #%u received, expected #%u!",
			(unsigned int)barrier_nr, (unsigned int)expect_epoch);
		goto bail;
	}

	if (expect_size != set_size) {
		bsr_err(3, BSR_LC_REPLICATION, connection, "BAD! BarrierAck #%u received with n_writes=%u, expected n_writes=%u!",
			(unsigned int)barrier_nr, set_size, expect_size);
		goto bail;
	}

	/* Clean up list of requests processed during current epoch. */
	/* this extra list walk restart is paranoia,
	 * to catch requests being barrier-acked "unexpectedly".
	 * It usually should find the same req again, or some READ preceding it. */
	list_for_each_entry_ex(struct bsr_request, req, &resource->transfer_log, tl_requests)
		if (req->epoch == expect_epoch)
			break;
	tl_for_each_req_ref_from(req, r, &resource->transfer_log) {
		struct bsr_peer_device *peer_device;
		if (req->epoch != expect_epoch) {
			tl_abort_for_each_req_ref(r, &resource->transfer_log);
			break;
		}
		peer_device = conn_peer_device(connection, req->device->vnr);
		_req_mod(req, BARRIER_ACKED, peer_device);
	}
	spin_unlock_irq(&connection->resource->req_lock);

	if (barrier_nr == connection->send.last_sent_epoch_nr) {
		clear_bit(BARRIER_ACK_PENDING, &connection->flags);
		wake_up(&resource->barrier_wait);
	}

	return;

bail:
	spin_unlock_irq(&connection->resource->req_lock);
	change_cstate_ex(connection, C_PROTOCOL_ERROR, CS_HARD);
}


/**
 * _tl_restart() - Walks the transfer log, and applies an action to all requests
 * @connection:	BSR connection to operate on.
 * @what:       The action/event to perform with all request objects
 *
 * @what might be one of CONNECTION_LOST_WHILE_PENDING, RESEND, FAIL_FROZEN_DISK_IO,
 * RESTART_FROZEN_DISK_IO.
 */
/* must hold resource->req_lock */
void _tl_restart(struct bsr_connection *connection, enum bsr_req_event what)
{
	struct bsr_resource *resource = connection->resource;
	struct bsr_peer_device *peer_device;
	struct bsr_request *req, *r;

	tl_for_each_req_ref(req, r, &resource->transfer_log) {
		// DW-689 temporary patch
		if (NULL == req->device) {
			bsr_err(2, BSR_LC_REQUEST, NO_OBJECT, "Ignore restart transfer because of no device assigned in request.");
			break; 
		}
		peer_device = conn_peer_device(connection, req->device->vnr);

		// DW-689 temporary patch
		if (NULL == peer_device) {
			bsr_err(37, BSR_LC_REQUEST, NO_OBJECT, "Ignore restart transfer because of no peer device assigned");
			break; 
		}
		_req_mod(req, what, peer_device);
	}
}

void tl_restart(struct bsr_connection *connection, enum bsr_req_event what)
{
	struct bsr_resource *resource = connection->resource;

	del_timer_sync(&resource->peer_ack_timer);
	spin_lock_irq(&resource->req_lock);
	_tl_restart(connection, what);
	spin_unlock_irq(&resource->req_lock);
}


/**
 * tl_clear() - Clears all requests and &struct bsr_tl_epoch objects out of the TL
 * @device:	BSR device.
 *
 * This is called after the connection to the peer was lost. The storage covered
 * by the requests on the transfer gets marked as our of sync. Called from the
 * receiver thread and the sender thread.
 */
void tl_clear(struct bsr_connection *connection)
{
	tl_restart(connection, CONNECTION_LOST_WHILE_PENDING);
}

/**
 * tl_abort_disk_io() - Abort disk I/O for all requests for a certain device in the TL
 * @device:     BSR device.
 */
void tl_abort_disk_io(struct bsr_device *device)
{
        struct bsr_resource *resource = device->resource;
        struct bsr_request *req, *r;

        spin_lock_irq(&resource->req_lock);
		tl_for_each_req_ref(req, r, &resource->transfer_log) {
                if (!(req->rq_state[0] & RQ_LOCAL_PENDING))
                        continue;
                if (req->device != device)
                        continue;
                _req_mod(req, ABORT_DISK_IO, NULL);
        }
        spin_unlock_irq(&resource->req_lock);
}

#ifdef _WIN
VOID NTAPI bsr_thread_setup(void *arg)
#else // _LIN
static int bsr_thread_setup(void *arg)
#endif
{
	struct bsr_thread *thi = (struct bsr_thread *) arg;
	struct bsr_resource *resource = thi->resource;
	struct bsr_connection *connection = thi->connection;
	unsigned long flags;
	int retval;
#ifdef _WIN
	thi->nt = ct_add_thread((int)PsGetCurrentThreadId(), thi->name, TRUE, 'B0SB');
	if (!thi->nt) {
		bsr_err(6, BSR_LC_THREAD, NO_OBJECT, "Failed to create %s thread.", thi->name);
		PsTerminateSystemThread(STATUS_SUCCESS);
	}

	KeSetEvent(&thi->start_event, 0, FALSE);
	KeWaitForSingleObject(&thi->wait_event, Executive, KernelMode, FALSE, NULL);
#else // _LIN
	// BSR-793 at the start of the thread to explicitly allow the desired signals
	allow_kernel_signal(BSR_SIGKILL);
	allow_kernel_signal(SIGXCPU);
#endif

restart:
	retval = thi->function(thi);

	spin_lock_irqsave(&thi->t_lock, flags);

	/* if the receiver has been "EXITING", the last thing it did
	 * was set the conn state to "StandAlone",
	 * if now a re-connect request comes in, conn state goes C_UNCONNECTED,
	 * and receiver thread will be "started".
	 * bsr_thread_start needs to set "RESTARTING" in that case.
	 * t_state check and assignment needs to be within the same spinlock,
	 * so either thread_start sees EXITING, and can remap to RESTARTING,
	 * or thread_start see NONE, and can proceed as normal.
	 */

	if (thi->t_state == RESTARTING) {
		if (connection)
			bsr_info(7, BSR_LC_THREAD, connection, "Restarting %s thread", thi->name);
		else
			bsr_info(8, BSR_LC_THREAD, resource, "Restarting %s thread", thi->name);
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
#ifdef _LIN
		// BSR-721
		flush_signals(current); /* likely it got a signal to look at t_state... */
#endif
		goto restart;
	}
#ifdef _WIN
	ct_delete_thread(thi->task->pid);
#endif
	thi->task = NULL;
	thi->t_state = NONE;
	smp_mb();

	if (connection)
		bsr_info(9, BSR_LC_THREAD, connection, "Terminating %s thread", thi->name);
	else
		bsr_info(10, BSR_LC_THREAD, resource, "Terminating %s thread", thi->name);

	complete(&thi->stop);
	spin_unlock_irqrestore(&thi->t_lock, flags);

#ifdef _WIN
	PsTerminateSystemThread(STATUS_SUCCESS); 
	// not reached here
#else // _LIN
	return retval;
#endif
}

static void bsr_thread_init(struct bsr_resource *resource, struct bsr_thread *thi,
			     int (*func) (struct bsr_thread *), const char *name)
{
	spin_lock_init(&thi->t_lock);
	thi->task    = NULL;
	thi->t_state = NONE;
	thi->function = func;
	thi->resource = resource;
	thi->connection = NULL;
	thi->name = name;
}

int bsr_thread_start(struct bsr_thread *thi)
{
	struct bsr_resource *resource = thi->resource;
	struct bsr_connection *connection = thi->connection;
#ifdef _LIN
	struct task_struct *nt;
#endif
	unsigned long flags;

	/* is used from state engine doing bsr_thread_stop_nowait,
	 * while holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	switch (thi->t_state) {
	case NONE:
		if (connection)
			bsr_info(11, BSR_LC_THREAD, connection, "Starting %s thread (from %s [%d])",
				 thi->name, current->comm, current->pid);
		else
			bsr_info(12, BSR_LC_THREAD, resource, "Starting %s thread (from %s [%d])",
				 thi->name, current->comm, current->pid);
		init_completion(&thi->stop);
		D_ASSERT(resource, thi->task == NULL);
		thi->reset_cpu_mask = 1;
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		flush_signals(current); /* otherw. may get -ERESTARTNOINTR */
#ifdef _WIN
		thi->nt = NULL;
		{
			HANDLE		hThread = NULL;
			NTSTATUS	Status = STATUS_UNSUCCESSFUL;

			KeInitializeEvent(&thi->start_event, SynchronizationEvent, FALSE);
			KeInitializeEvent(&thi->wait_event, SynchronizationEvent, FALSE);
			Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, bsr_thread_setup, (void *) thi);
			if (!NT_SUCCESS(Status)) {
				// BSR-986 set the status to NONE because thread create failed.
				thi->t_state = NONE;
				return false;
			}
			ZwClose(hThread);
		}

		KeWaitForSingleObject(&thi->start_event, Executive, KernelMode, FALSE, NULL);
		if (!thi->nt) {
			return false;
		}
#else // _LIN
		nt = kthread_create(bsr_thread_setup, (void *) thi,
				    "bsr_%c_%s", thi->name[0], resource->name);

		if (IS_ERR(nt)) {
			if (connection)
				bsr_err(13, BSR_LC_THREAD, connection, "Couldn't start thread");
			else
				bsr_err(14, BSR_LC_THREAD, resource, "Couldn't start thread");

			return false;
		}
#endif
		spin_lock_irqsave(&thi->t_lock, flags);
#ifdef _WIN
		thi->task = thi->nt;
#else // _LIN
		thi->task = nt;
#endif
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
#ifdef _WIN
		wake_up_process(thi);
#else // _LIN
		wake_up_process(nt);
#endif
		break;
	case EXITING:
		thi->t_state = RESTARTING;
		if (connection)
			bsr_info(15, BSR_LC_THREAD, connection, "Restarting %s thread (from %s [%d])",
					thi->name, current->comm, current->pid);
		else
			bsr_info(16, BSR_LC_THREAD, resource, "Restarting %s thread (from %s [%d])",
					thi->name, current->comm, current->pid);
		/* fall through */
	case RUNNING:
	case RESTARTING:
	default:
		spin_unlock_irqrestore(&thi->t_lock, flags);
		break;
	}

	return true;
}


void _bsr_thread_stop(struct bsr_thread *thi, int restart, int wait)
{
	unsigned long flags;

	enum bsr_thread_state ns = restart ? RESTARTING : EXITING;

	/* may be called from state engine, holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	//bsr_info(21, BSR_LC_ETC, NO_OBJECT,"thi(%s) ns(%s) state(%d) waitflag(%d) event(%d)-------------------!", 
	//	thi->name, (ns == RESTARTING) ? "RESTARTING" : "EXITING", thi->t_state, wait, KeReadStateEvent(&thi->stop.wait.wqh_event));

	if (thi->t_state == NONE) {
		spin_unlock_irqrestore(&thi->t_lock, flags);
		if (restart)
			bsr_thread_start(thi);
		return;
	}

	if (thi->t_state == EXITING && ns == RESTARTING) {
		/* Do not abort a stop request, otherwise a waiter might never wake up */
		spin_unlock_irqrestore(&thi->t_lock, flags);
		return;
	}

	if (thi->t_state != ns) {
		if (thi->task == NULL) {
			spin_unlock_irqrestore(&thi->t_lock, flags);
			return;
		}

		thi->t_state = ns;
		smp_mb();
		init_completion(&thi->stop);
		if (thi->task != current)
			send_sig(BSR_SIGKILL, thi->task, 1); // BSR-793 use send_sig not force_sig
		else {
		//	bsr_info(22, BSR_LC_ETC, NO_OBJECT,"cur=(%s) thi=(%s) stop myself", current->comm, thi->name ); 
		}
	}
	spin_unlock_irqrestore(&thi->t_lock, flags);

	if (wait) {
#ifdef _WIN
		// bsr_info(23, BSR_LC_ETC, NO_OBJECT,"(%s) wait_for_completion. signaled(%d)", current->comm, KeReadStateEvent(&thi->stop.wait.wqh_event));

		while (wait_for_completion(&thi->stop) == -BSR_SIGKILL) {
			// bsr_info(24, BSR_LC_ETC, NO_OBJECT,"BSR_SIGKILL occurs. Ignore and wait for real event"); // not happened.
		}
#else // _LIN
		wait_for_completion(&thi->stop);
#endif
	}

	// bsr_info(25, BSR_LC_ETC, NO_OBJECT,"waitflag(%d) signaled(%d). sent stop sig done.", wait, KeReadStateEvent(&thi->stop.wait.wqh_event));

}

int conn_lowest_minor(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int vnr = 0, minor = -1;

	rcu_read_lock();
	peer_device = idr_get_next(&connection->peer_devices, &vnr);
	if (peer_device)
		minor = device_to_minor(peer_device->device);
	rcu_read_unlock();

	return minor;
}

#ifdef CONFIG_SMP
/**
 * bsr_calc_cpu_mask() - Generate CPU masks, spread over all CPUs
 *
 * Forces all threads of a resource onto the same CPU. This is beneficial for
 * BSR's performance. May be overwritten by user's configuration.
 */
static void bsr_calc_cpu_mask(cpumask_var_t *cpu_mask)
{
	unsigned int *resources_per_cpu, min_index = ~0;

	resources_per_cpu = bsr_kzalloc(nr_cpu_ids * sizeof(*resources_per_cpu), GFP_KERNEL, '');
	if (resources_per_cpu) {
		struct bsr_resource *resource;
		unsigned int cpu, min = ~0;

		rcu_read_lock();
		for_each_resource_rcu(resource, &bsr_resources) {
			for_each_cpu(cpu, resource->cpu_mask)
				resources_per_cpu[cpu]++;
		}
		rcu_read_unlock();
		for_each_online_cpu(cpu) {
			if (resources_per_cpu[cpu] < min) {
				min = resources_per_cpu[cpu];
				min_index = cpu;
			}
		}
		bsr_kfree(resources_per_cpu);
	}
	if (min_index == ~0) {
		cpumask_setall(*cpu_mask);
		return;
	}
	cpumask_set_cpu(min_index, *cpu_mask);
}

/**
 * bsr_thread_current_set_cpu() - modifies the cpu mask of the _current_ thread
 * @device:	BSR device.
 * @thi:	bsr_thread object
 *
 * call in the "main loop" of _all_ threads, no need for any mutex, current won't die
 * prematurely.
 */
void bsr_thread_current_set_cpu(struct bsr_thread *thi)
{
	struct bsr_resource *resource = thi->resource;
	struct task_struct *p = current;

	if (!thi->reset_cpu_mask)
		return;
	thi->reset_cpu_mask = 0;
	set_cpus_allowed_ptr(p, resource->cpu_mask);
}
#else
#define bsr_calc_cpu_mask(A) ({})
#endif

static bool bsr_all_neighbor_secondary(struct bsr_resource *resource, u64 *authoritative_ptr)
{
	struct bsr_connection *connection;
	bool all_secondary = true;
	u64 authoritative = 0;
	int id;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] >= C_CONNECTED &&
		    connection->peer_role[NOW] == R_PRIMARY) {
			all_secondary = false;
			id = connection->peer_node_id;
			authoritative |= NODE_MASK(id);
		}
	}
	rcu_read_unlock();

	if (authoritative_ptr)
		*authoritative_ptr = authoritative;

	return all_secondary;
}

/* This function is supposed to have the same semantics as calc_device_stable() in bsr_state.c
   A primary is stable since it is authoritative.
   Unstable are neighbors of a primary and resync target nodes.
   Nodes further away from a primary are stable! */
bool bsr_device_stable(struct bsr_device *device, u64 *authoritative_ptr)
{
	struct bsr_resource *resource = device->resource;
	struct bsr_connection *connection;
	struct bsr_peer_device *peer_device;
	u64 authoritative = 0;
	bool device_stable = true;

	if (resource->role[NOW] == R_PRIMARY)
		return true;

	if (!bsr_all_neighbor_secondary(resource, authoritative_ptr))
		return false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		peer_device = conn_peer_device(connection, device->vnr);
		switch (peer_device->repl_state[NOW]) {
			// BSR-905 if the resync start is delayed in congestion when the relative node is demoted, it may be L_BEHIND.
		case L_BEHIND:
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			device_stable = false;
			authoritative |= NODE_MASK(peer_device->node_id);
			goto out;
		default:
			continue;
		}
	}

out:
	rcu_read_unlock();
	if (authoritative_ptr)
		*authoritative_ptr = authoritative;
	return device_stable;
}


// DW-1315 check if I have primary neighbor, it has same semantics as bsr_all_neighbor_secondary and is also able to check the role to be changed.
static bool bsr_all_neighbor_secondary_ex(struct bsr_resource *resource, u64 *authoritative, enum which_state which, bool locked)
{
	struct bsr_connection *connection;
	bool all_secondary = true;
	int id;

	// DW-1477 avoid the recursive lock (for windows)
	rcu_read_lock_check(locked);
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[which] >= C_CONNECTED &&
			connection->peer_role[which] == R_PRIMARY) {
			all_secondary = false;
			if (authoritative) {
				id = connection->peer_node_id;
				*authoritative |= NODE_MASK(id);
			}
			else {
				break;
			}
		}
	}
	// DW-1477 avoid the recursive lock (for windows)
	rcu_read_unlock_check(locked);

	return all_secondary;
}

// DW-1315 check the stability and authoritative node(if unstable), it has same semantics as bsr_device_stable and is also able to check the state to be changed.
bool bsr_device_stable_ex(struct bsr_device *device, u64 *authoritative, enum which_state which, bool locked)
{
	struct bsr_resource *resource = device->resource;
	struct bsr_connection *connection;
	struct bsr_peer_device *peer_device;
	bool device_stable = true;

	if (resource->role[which] == R_PRIMARY)
		return true;

	if (!bsr_all_neighbor_secondary_ex(resource, authoritative, which, locked))
		return false;

	// DW-1477 avoid the recursive lock (for windows)
	rcu_read_lock_check(locked);

	for_each_connection_rcu(connection, resource) {
		peer_device = conn_peer_device(connection, device->vnr);
		switch (peer_device->repl_state[which]) {
			// BSR-905 if the resync start is delayed in congestion when the relative node is demoted, it may be L_BEHIND.
		case L_BEHIND:
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			device_stable = false;
			if (authoritative)
				*authoritative |= NODE_MASK(peer_device->node_id);
			goto out;
		default:
			continue;
		}
	}

out:
	// DW-1477 avoid the recursive lock (for windows)
	rcu_read_unlock_check(locked);
	return device_stable;
}


// DW-1145 it returns true if my disk is consistent with primary's
bool is_consistent_with_primary(struct bsr_device *device, enum which_state which)
{
	struct bsr_peer_device *peer_device = NULL;
	int node_id = -1;

	if (device->disk_state[which] != D_UP_TO_DATE)
		return false;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++){
		peer_device = peer_device_by_node_id(device, node_id);
		if (!peer_device)
			continue;
		if (peer_device->connection->peer_role[which] == R_PRIMARY &&
			peer_device->repl_state[which] >= L_ESTABLISHED &&
			peer_device->uuids_received &&
			bsr_bm_total_weight(peer_device) == 0)
			return true;
	}
	return false;
}

/**
 * bsr_header_size  -  size of a packet header
 *
 * The header size is a multiple of 8, so any payload following the header is
 * word aligned on 64-bit architectures.  (The bitmap send and receive code
 * relies on this.)
 */
unsigned int bsr_header_size(struct bsr_connection *connection)
{
	if (connection->agreed_pro_version >= 100) {
		BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct p_header100), 8));
		return sizeof(struct p_header100);
	} else {
		BUILD_BUG_ON(sizeof(struct p_header80) !=
			     sizeof(struct p_header95));
		BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct p_header80), 8));
		return sizeof(struct p_header80);
	}
}

static void prepare_header80(struct p_header80 *h, enum bsr_packet cmd, int size)
{
	h->magic   = cpu_to_be32(BSR_MAGIC);
	h->command = cpu_to_be16(cmd);
#ifdef _WIN
	BUG_ON_UINT16_OVER((__be16)size - sizeof(struct p_header80));
#endif
	h->length  = cpu_to_be16((__be16)size - sizeof(struct p_header80));
}

static void prepare_header95(struct p_header95 *h, enum bsr_packet cmd, int size)
{
	h->magic   = cpu_to_be16(BSR_MAGIC_BIG);
	h->command = cpu_to_be16(cmd);
	h->length = cpu_to_be32(size - sizeof(struct p_header95));
}

static void prepare_header100(struct p_header100 *h, enum bsr_packet cmd,
				      int size, int vnr)
{
	h->magic = cpu_to_be32(BSR_MAGIC_100);
#ifdef _WIN	
	BUG_ON_UINT16_OVER(vnr);
#endif
	h->volume = cpu_to_be16((uint16_t)vnr);
	h->command = cpu_to_be16(cmd);
	h->length = cpu_to_be32(size - sizeof(struct p_header100));
	h->pad = 0;
}

static void prepare_header(struct bsr_connection *connection, int vnr,
			   void *buffer, enum bsr_packet cmd, int size)
{
	if (connection->agreed_pro_version >= 100)
		prepare_header100(buffer, cmd, size, vnr);
	else if (connection->agreed_pro_version >= 95 &&
		 size > BSR_MAX_SIZE_H80_PACKET)
		prepare_header95(buffer, cmd, size);
	else
		prepare_header80(buffer, cmd, size);
}

static void new_or_recycle_send_buffer_page(struct bsr_send_buffer *sbuf)
{
	while (1) {

		struct page *page;
		int count = page_count(sbuf->page);

		BUG_ON(count == 0);
		if (count == 1)
			goto have_page;

		page = alloc_page(GFP_KERNEL);
		if (page) {
#ifdef _LIN
			put_page(sbuf->page);
#endif
			sbuf->page = page;
			goto have_page;
		}

		schedule_timeout(HZ / 10);
	}
have_page:
	sbuf->unsent =
	sbuf->pos = page_address(sbuf->page);
}

static char *alloc_send_buffer(struct bsr_connection *connection, int size,
			      enum bsr_stream bsr_stream)
{
	struct bsr_send_buffer *sbuf = &connection->send_buffer[bsr_stream];
	char *page_start = page_address(sbuf->page);
	
	if (sbuf->pos - page_start + size > PAGE_SIZE) {
		bsr_debug_rs("(%s) stream(%d)! unsent(%ld) pos(%ld) size(%d)", current->comm, bsr_stream, (long)sbuf->unsent, (long)sbuf->pos, size);
		flush_send_buffer(connection, bsr_stream);
		new_or_recycle_send_buffer_page(sbuf);
	}

	sbuf->allocated_size = size;
	sbuf->additional_size = 0;

	return sbuf->pos;
}

/* Only used the shrink the previously allocated size. */
static void resize_prepared_command(struct bsr_connection *connection,
				    enum bsr_stream bsr_stream,
				    int size)
{
	connection->send_buffer[bsr_stream].allocated_size =
		size + bsr_header_size(connection);
}

static void additional_size_command(struct bsr_connection *connection,
				    enum bsr_stream bsr_stream,
				    int additional_size)
{
	connection->send_buffer[bsr_stream].additional_size = additional_size;
}

void *__conn_prepare_command(struct bsr_connection *connection, int size,
				    enum bsr_stream bsr_stream)
{
	struct bsr_transport *transport = &connection->transport;
	int header_size;

	if (!transport->ops->stream_ok(transport, bsr_stream)) {
		if (bsr_ratelimit())
			bsr_err(13, BSR_LC_SOCKET, connection, "Failed to prepare send due to socket is not allocate, stream(%s)", (bsr_stream == DATA_STREAM) ? "DATA_STREAM" : "CONTROL_STREAM");
		return NULL;
	}

	header_size = bsr_header_size(connection);
#ifdef _WIN
	void *p = (char *)alloc_send_buffer(connection, header_size + size, bsr_stream) + header_size;
	if(!p) {
		bsr_err(35, BSR_LC_SEND_BUFFER, connection, "Failed to add send buffer for send data. size(%d), stream(%s)", (header_size + size, bsr_stream), (bsr_stream == DATA_STREAM) ? "DATA_STREAM" : "CONTROL_STREAM");
	}
	return p;
#else // _LIN
	return alloc_send_buffer(connection, header_size + size, bsr_stream) + header_size;
#endif
}

/**
 * conn_prepare_command() - Allocate a send buffer for a packet/command
 * @conneciton:	the connections the packet will be sent through
 * @size:	number of bytes to allocate
 * @stream:	DATA_STREAM or CONTROL_STREAM
 *
 * This allocates a buffer with capacity to hold the header, and
 * the requested size. Upon success is return a pointer that points
 * to the first byte behind the header. The caller is expected to
 * call xxx_send_command() soon.
 */
void *conn_prepare_command(struct bsr_connection *connection, int size,
			   enum bsr_stream bsr_stream)
{
	void *p;

	mutex_lock(&connection->mutex[bsr_stream]);
	p = __conn_prepare_command(connection, size, bsr_stream);
	if (!p)
		mutex_unlock(&connection->mutex[bsr_stream]);

	return p;
}

/**
 * bsr_prepare_command() - Allocate a send buffer for a packet/command
 * @conneciton:	the connections the packet will be sent through
 * @size:	number of bytes to allocate
 * @stream:	DATA_STREAM or CONTROL_STREAM
 *
 * This allocates a buffer with capacity to hold the header, and
 * the requested size. Upon success is return a pointer that points
 * to the first byte behind the header. The caller is expected to
 * call xxx_send_command() soon.
 */
void *bsr_prepare_command(struct bsr_peer_device *peer_device, int size, enum bsr_stream bsr_stream)
{
	return conn_prepare_command(peer_device->connection, size, bsr_stream);
}

static int flush_send_buffer(struct bsr_connection *connection, enum bsr_stream bsr_stream)
{
	struct bsr_send_buffer *sbuf = &connection->send_buffer[bsr_stream];
	struct bsr_transport *transport = &connection->transport;
	struct bsr_transport_ops *tr_ops = transport->ops;
	int msg_flags, err;
	ULONG_PTR size;
	ULONG_PTR offset;

	size = sbuf->pos - sbuf->unsent + sbuf->allocated_size;
	if (size == 0)
		return 0;

	msg_flags = sbuf->additional_size ? MSG_MORE : 0;
#ifdef _LIN
	// BSR-819 during disconnection, use MSG_DONTWAIT 
	// to avoid delaying state changes due to socket timeouts.
	msg_flags |= connection->cstate[NOW] < C_CONNECTING ? MSG_DONTWAIT : 0;
#endif
	offset = sbuf->unsent - (char *)page_address(sbuf->page);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(offset);
#endif
#ifdef _WIN
    err = tr_ops->send_page(transport, bsr_stream, sbuf->page->addr, (int)offset, (size_t)size, msg_flags);
#else // _LIN
	err = tr_ops->send_page(transport, bsr_stream, sbuf->page, offset, size, msg_flags);
#endif
	if (!err) {
		sbuf->unsent =
		sbuf->pos += sbuf->allocated_size;      /* send buffer submitted! */
	}

	sbuf->allocated_size = 0;

	return err;
}

int __send_command(struct bsr_connection *connection, int vnr,
			  enum bsr_packet cmd, enum bsr_stream bsr_stream)
{
	struct bsr_send_buffer *sbuf = &connection->send_buffer[bsr_stream];
	struct bsr_transport *transport = &connection->transport;
	struct bsr_transport_ops *tr_ops = transport->ops;
	bool corked = test_bit(CORKED + bsr_stream, &connection->flags);
	bool flush = (cmd == P_PING || cmd == P_PING_ACK || cmd == P_TWOPC_PREPARE);
	int err;

	/* send P_PING and P_PING_ACK immediately, they need to be delivered as
	   fast as possible.
	   P_TWOPC_PREPARE might be used from the worker context while corked.
	   The work item (connect_work) calls change_cluster_wide_state() which
	   in turn waits for reply packets. -> Need to send it regardless of
	   corking.  */

	if (connection->cstate[NOW] < C_CONNECTING)
		return -EIO;
	prepare_header(connection, vnr, sbuf->pos, cmd,
		       sbuf->allocated_size + sbuf->additional_size);

	if (corked && !flush) {
		bsr_debug(32, BSR_LC_SEND_BUFFER, connection, "send buff %s, size: %d vnr: %d, stream : %s", bsr_packet_name(cmd), (sbuf->allocated_size + sbuf->additional_size), vnr, bsr_stream == DATA_STREAM ? "DATA" : "CONTROL");
		sbuf->pos += sbuf->allocated_size;
		sbuf->allocated_size = 0;
		err = 0;
	} else {
		bsr_debug(33, BSR_LC_SEND_BUFFER, connection, "sending %s, size: %d vnr: %d, stream : %s", bsr_packet_name(cmd), (sbuf->pos - sbuf->unsent + sbuf->allocated_size), vnr, bsr_stream == DATA_STREAM ? "DATA" : "CONTROL");
		err = flush_send_buffer(connection, bsr_stream);

		/* BSR protocol "pings" are latency critical.
		 * This is supposed to trigger tcp_push_pending_frames() */
		if (!err && flush)
			tr_ops->hint(transport, bsr_stream, NODELAY);
			
		if (bsr_stream == DATA_STREAM) {
			if (!err)
				connection->last_send_packet = cmd;
			// DW-1977 last successful protocol may not be correct because it is a transfer to the buffer
			else
				bsr_info(1, BSR_LC_PROTOCOL, connection, "The last successful protocol is %s", bsr_packet_name(cmd));
		}
	}

	return err;
}

void bsr_drop_unsent(struct bsr_connection* connection)
{
	int i;

	clear_bit(DATA_CORKED, &connection->flags);
	clear_bit(CONTROL_CORKED, &connection->flags);

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct bsr_send_buffer *sbuf = &connection->send_buffer[i];
		sbuf->unsent =
		sbuf->pos = page_address(sbuf->page);
		sbuf->allocated_size = 0;
		sbuf->additional_size = 0;
	}
}

void bsr_cork(struct bsr_connection *connection, enum bsr_stream stream)
{
	struct bsr_transport *transport = &connection->transport;
	struct bsr_transport_ops *tr_ops = transport->ops;

	mutex_lock(&connection->mutex[stream]);
	set_bit(CORKED + stream, &connection->flags);
	tr_ops->hint(transport, stream, CORK);
	mutex_unlock(&connection->mutex[stream]);
}

void bsr_uncork(struct bsr_connection *connection, enum bsr_stream stream)
{
	struct bsr_transport *transport = &connection->transport;
	struct bsr_transport_ops *tr_ops = transport->ops;


	mutex_lock(&connection->mutex[stream]);
	flush_send_buffer(connection, stream);

	clear_bit(CORKED + stream, &connection->flags);
	tr_ops->hint(transport, stream, UNCORK);
	mutex_unlock(&connection->mutex[stream]);
}

int send_command(struct bsr_connection *connection, int vnr,
		 enum bsr_packet cmd, enum bsr_stream bsr_stream)
{
	int err;

	err = __send_command(connection, vnr, cmd, bsr_stream);
	mutex_unlock(&connection->mutex[bsr_stream]);
	return err;
}

int bsr_send_command(struct bsr_peer_device *peer_device,
		      enum bsr_packet cmd, enum bsr_stream bsr_stream)
{
	return send_command(peer_device->connection, peer_device->device->vnr,
			    cmd, bsr_stream);
}

int bsr_send_ping(struct bsr_connection *connection)
{
	if (!conn_prepare_command(connection, 0, CONTROL_STREAM))
		return -EIO;
	return send_command(connection, -1, P_PING, CONTROL_STREAM);
}

int bsr_send_ping_ack(struct bsr_connection *connection)
{
	if (!conn_prepare_command(connection, 0, CONTROL_STREAM))
		return -EIO;
	return send_command(connection, -1, P_PING_ACK, CONTROL_STREAM);
}

// BSR-863
int bsr_send_uuid_ack(struct bsr_connection *connection)
{
	if (!conn_prepare_command(connection, 0, CONTROL_STREAM))
		return -EIO;
	return send_command(connection, -1, P_UUID_ACK, CONTROL_STREAM);
}


int bsr_send_peer_ack(struct bsr_connection *connection,
			      struct bsr_request *req)
{
	struct bsr_resource *resource = connection->resource;
	struct bsr_connection *c;
	struct p_peer_ack *p;
	u64 mask = 0;


#if 0 // DW-1099 masking my node id causes peers to improper in-sync.
	if (req->rq_state[0] & RQ_LOCAL_OK)
		mask |= NODE_MASK(resource->res_opts.node_id);
#endif

	rcu_read_lock();
	for_each_connection_rcu(c, resource) {
		int node_id = c->peer_node_id;
		int idx = 1 + node_id;

		if (req->rq_state[idx] & RQ_NET_OK)
			mask |= NODE_MASK(node_id);
	}
	rcu_read_unlock();

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return -EIO;
	p->mask = cpu_to_be64(mask);
	p->dagtag = cpu_to_be64(req->dagtag_sector);

	return send_command(connection, -1, P_PEER_ACK, CONTROL_STREAM);
}

int bsr_send_sync_param(struct bsr_peer_device *peer_device)
{
	struct p_rs_param_114 *p;
	int size;
	const int apv = peer_device->connection->agreed_pro_version;
	enum bsr_packet cmd;
	struct net_conf *nc;
	struct peer_device_conf *pdc;

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);

	size = apv <= 87 ? (int)sizeof(struct p_rs_param)
		: apv == 88 ? (int)sizeof(struct p_rs_param)
		+ (int)(strlen(nc->verify_alg) + 1)
			: apv <= 94 ? (int)sizeof(struct p_rs_param_89)
		: apv <= 113 ? (int)sizeof(struct p_rs_param_95)
		: /* apv >= 114 */ (int)sizeof(struct p_rs_param_114);

	cmd = apv >= 89 ? P_SYNC_PARAM89 : P_SYNC_PARAM;
	rcu_read_unlock();

	p = bsr_prepare_command(peer_device, size, DATA_STREAM);
	if (!p)
		return -EIO;

	/* initialize verify_alg and csums_alg */
	memset(p->verify_alg, 0, SHARED_SECRET_MAX);
	memset(p->csums_alg, 0, SHARED_SECRET_MAX);
#ifdef _WIN
    rcu_read_lock_w32_inner();
#else // _LIN
	rcu_read_lock();
#endif
	nc = rcu_dereference(peer_device->connection->transport.net_conf);

	// DW-2023 fix incorrect resync-rate setting
	pdc = rcu_dereference(peer_device->conf);
	p->resync_rate = cpu_to_be32(pdc->resync_rate);
	p->c_plan_ahead = cpu_to_be32(pdc->c_plan_ahead);
	p->c_delay_target = cpu_to_be32(pdc->c_delay_target);
	p->c_fill_target = cpu_to_be32(pdc->c_fill_target);
	p->c_max_rate = cpu_to_be32(pdc->c_max_rate);
	p->ov_req_num = cpu_to_be32(pdc->ov_req_num);
	p->ov_req_interval = cpu_to_be32(pdc->ov_req_interval);

	if (apv >= 88)
		strncpy(p->verify_alg, nc->verify_alg, sizeof(p->verify_alg) - 1);
	if (apv >= 89)
		strncpy(p->csums_alg, nc->csums_alg, sizeof(p->csums_alg) - 1);
	rcu_read_unlock();

	return bsr_send_command(peer_device, cmd, DATA_STREAM);
}

int __bsr_send_protocol(struct bsr_connection *connection, enum bsr_packet cmd)
{
	struct p_protocol *p;
	struct net_conf *nc;
	int size, cf;

	if (test_bit(CONN_DRY_RUN, &connection->flags) && connection->agreed_pro_version < 92) {
		clear_bit(CONN_DRY_RUN, &connection->flags);
		bsr_err(2, BSR_LC_PROTOCOL, connection, "Failed to send protocol due to  --dry-run is not supported by peer");
		return -EOPNOTSUPP;
	}

	size = sizeof(*p);
	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	if (connection->agreed_pro_version >= 87) {
		size += (int)(strlen(nc->integrity_alg) + 1);
	}
	rcu_read_unlock();

	p = __conn_prepare_command(connection, size, DATA_STREAM);
	if (!p)
		return -EIO;
#ifdef _WIN
    rcu_read_lock_w32_inner();
#else // _LIN
	rcu_read_lock();
#endif
	nc = rcu_dereference(connection->transport.net_conf);

	p->protocol      = cpu_to_be32(nc->wire_protocol);
	p->after_sb_0p   = cpu_to_be32(nc->after_sb_0p);
	p->after_sb_1p   = cpu_to_be32(nc->after_sb_1p);
	p->after_sb_2p   = cpu_to_be32(nc->after_sb_2p);
	p->two_primaries = cpu_to_be32(nc->two_primaries);
	cf = 0;
	if (test_bit(CONN_DISCARD_MY_DATA, &connection->flags))
		cf |= CF_DISCARD_MY_DATA;
	if (test_bit(CONN_DRY_RUN, &connection->flags))
		cf |= CF_DRY_RUN;
	p->conn_flags    = cpu_to_be32(cf);

	if (connection->agreed_pro_version >= 87)
		strncpy(p->integrity_alg, nc->integrity_alg, SHARED_SECRET_MAX-1);
	rcu_read_unlock();

	return __send_command(connection, -1, cmd, DATA_STREAM);
}

int bsr_send_protocol(struct bsr_connection *connection)
{
	int err;

	mutex_lock(&connection->mutex[DATA_STREAM]);
	err = __bsr_send_protocol(connection, P_PROTOCOL);
	mutex_unlock(&connection->mutex[DATA_STREAM]);

	return err;
}

static int _bsr_send_uuids(struct bsr_peer_device *peer_device, u64 uuid_flags)
{
	struct bsr_device *device = peer_device->device;
	struct p_uuids *p;
	int i;

	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return 0;

	p = bsr_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p) {
		put_ldev(device);
		return -EIO;
	}

	spin_lock_irq(&device->ldev->md.uuid_lock);
	p->current_uuid = cpu_to_be64(bsr_current_uuid(device));
	p->bitmap_uuid = cpu_to_be64(bsr_bitmap_uuid(peer_device));
	for (i = 0; i < ARRAY_SIZE(p->history_uuids); i++)
		p->history_uuids[i] = cpu_to_be64(bsr_history_uuid(device, i));
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	peer_device->comm_bm_set = bsr_bm_total_weight(peer_device);
	p->dirty_bits = cpu_to_be64(peer_device->comm_bm_set);

	if (test_bit(DISCARD_MY_DATA, &peer_device->flags))
		uuid_flags |= UUID_FLAG_DISCARD_MY_DATA;
	// BSR-175
	if (test_bit(CRASHED_PRIMARY, &device->flags) &&
		bsr_md_test_peer_flag(peer_device, MDF_CRASHED_PRIMARY_WORK_PENDING))
		uuid_flags |= UUID_FLAG_CRASHED_PRIMARY;
	if (!bsr_md_test_flag(device, MDF_CONSISTENT))
		uuid_flags |= UUID_FLAG_INCONSISTENT;	
	if (bsr_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
		uuid_flags |= UUID_FLAG_PRIMARY_IO_ERROR;
	// DW-1874
	if (bsr_md_test_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC))
		uuid_flags |= UUID_FLAG_IN_PROGRESS_SYNC;
	p->uuid_flags = cpu_to_be64(uuid_flags);

	put_ldev(device);

	return bsr_send_command(peer_device, P_UUIDS, DATA_STREAM);
}

static u64 __bitmap_uuid(struct bsr_device *device, int node_id) __must_hold(local)
{
	struct bsr_peer_device *peer_device;
	struct bsr_peer_md *peer_md = device->ldev->md.peers;
	u64 bitmap_uuid = peer_md[node_id].bitmap_uuid;

	/* Sending a bitmap_uuid of 0 means that we are in sync with that peer.
	   The recipient of this message might use this assumption to throw away it's
	   bitmap to that peer.

	   Send -1 instead if we are (resync target from that peer) not at the same
	   current uuid.
	   This corner case is relevant if we finish resync from an UpToDate peer first,
	   and the second resync (which was paused first) is from an Outdated node.
	   And that second resync gets canceled by the resync target due to the first
	   resync finished successfully.

	   Exceptions to the above are when the peer's UUID is not known yet
	 */

	rcu_read_lock();
	peer_device = peer_device_by_node_id(device, node_id);

	if (bitmap_uuid == 0 && peer_device &&
		peer_device->current_uuid != 0 &&
		(peer_device->current_uuid & ~UUID_PRIMARY) !=
		(bsr_current_uuid(device) & ~UUID_PRIMARY))

	{
		// DW-978 Set MDF_PEER_DIFF_CUR_UUID flag so that we're able to recognize -1 is sent.
		// DW-1415 Set MDF_PEER_DIFF_CUR_UUID flag when only peer is in connected state to avoid exchanging uuid unlimitedly on the ring topology with flawed connection.
		if (peer_device->connection->cstate[NOW] == C_CONNECTED)
			peer_md[node_id].flags |= MDF_PEER_DIFF_CUR_UUID;

#ifdef _WIN
		bitmap_uuid = UINT64_MAX;
#else	// _LIN
		bitmap_uuid = -1;
#endif
	}


	rcu_read_unlock();

	return bitmap_uuid;
}

static int _bsr_send_uuids110(struct bsr_peer_device *peer_device, u64 uuid_flags, u64 node_mask, enum which_state which)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_md *peer_md;
	struct p_uuids110 *p;
	ULONG_PTR pos = 0;
	ULONG_PTR i, bitmap_uuids_mask = 0;
	u64 authoritative_mask = 0;
	int p_size = sizeof(*p);

	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return bsr_send_current_uuid(peer_device, device->exposed_data_uuid,
		bsr_weak_nodes_device(device));

	peer_md = device->ldev->md.peers;

	p_size += (BSR_PEERS_MAX + HISTORY_UUIDS) * sizeof(p->other_uuids[0]);
	p = bsr_prepare_command(peer_device, p_size, DATA_STREAM);
	if (!p) {
		put_ldev(device);
		return -EIO;
	}

	spin_lock_irq(&device->ldev->md.uuid_lock);
	p->current_uuid = cpu_to_be64(bsr_current_uuid(device));

	for (i = 0; i < BSR_NODE_ID_MAX; i++) {
		if (peer_md[i].bitmap_index != -1 || peer_md[i].flags & MDF_NODE_EXISTS)
			bitmap_uuids_mask |= NODE_MASK(i);
	}

	// DW-1253 sizeof(bitmap_uuids_mask) is 8, it cannot be found all nodes. so, change it to BSR_NODE_ID_MAX. 
	for_each_set_bit(i, (ULONG_PTR *)&bitmap_uuids_mask, BSR_NODE_ID_MAX) {
#ifdef _WIN64
		BUG_ON_INT32_OVER(i);
#endif
		p->other_uuids[pos++] = cpu_to_be64(__bitmap_uuid(device, (int)i));
	}

	for (i = 0; i < HISTORY_UUIDS; i++)
		p->other_uuids[pos++] = cpu_to_be64(bsr_history_uuid(device, (int)i));
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	p->bitmap_uuids_mask = cpu_to_be64(bitmap_uuids_mask);

	peer_device->comm_bm_set = bsr_bm_total_weight(peer_device);
	p->dirty_bits = cpu_to_be64(peer_device->comm_bm_set);
	if (test_bit(DISCARD_MY_DATA, &peer_device->flags))
		uuid_flags |= UUID_FLAG_DISCARD_MY_DATA;

	// BSR-175
	if (test_bit(CRASHED_PRIMARY, &device->flags) && 
		bsr_md_test_peer_flag(peer_device, MDF_CRASHED_PRIMARY_WORK_PENDING))
		uuid_flags |= UUID_FLAG_CRASHED_PRIMARY;

	if (!bsr_md_test_flag(device, MDF_CONSISTENT))
		uuid_flags |= UUID_FLAG_INCONSISTENT;
	if (test_bit(RECONNECT, &peer_device->connection->flags))
		uuid_flags |= UUID_FLAG_RECONNECT;
	if (bsr_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR))
		uuid_flags |= UUID_FLAG_PRIMARY_IO_ERROR;
	// BSR-936
	if (bsr_device_stable_ex(device, &authoritative_mask, which, false)) {
		uuid_flags |= UUID_FLAG_STABLE;
		p->node_mask = cpu_to_be64(node_mask);
	} else {
		D_ASSERT(peer_device, node_mask == 0);
		p->node_mask = cpu_to_be64(authoritative_mask);
	}
	// DW-1874
	if (bsr_md_test_peer_flag(peer_device, MDF_PEER_IN_PROGRESS_SYNC))
		uuid_flags |= UUID_FLAG_IN_PROGRESS_SYNC;

	// DW-1145 set UUID_FLAG_CONSISTENT_WITH_PRI if my disk is consistent with primary's
	// BSR-936
	if (is_consistent_with_primary(device, which))
		uuid_flags |= UUID_FLAG_CONSISTENT_WITH_PRI;

	// DW-1285 If MDF_PEER_INIT_SYNCT_BEGIN is on, send UUID_FLAG_INIT_SYNCT_BEGIN flag.
	if(bsr_md_test_peer_flag(peer_device, MDF_PEER_INIT_SYNCT_BEGIN))
		uuid_flags |= UUID_FLAG_INIT_SYNCT_BEGIN;

	p->uuid_flags = cpu_to_be64(uuid_flags);

	put_ldev(device);
#ifdef _WIN64
	BUG_ON_INT32_OVER(sizeof(*p) + (hweight64(bitmap_uuids_mask) + HISTORY_UUIDS) * sizeof(p->other_uuids[0]));
#endif
	p_size = (int)(sizeof(*p) + (hweight64(bitmap_uuids_mask) + HISTORY_UUIDS) * sizeof(p->other_uuids[0]));
	resize_prepared_command(peer_device->connection, DATA_STREAM, p_size);
	return bsr_send_command(peer_device, P_UUIDS110, DATA_STREAM);
}

int bsr_send_uuids(struct bsr_peer_device *peer_device, u64 uuid_flags, u64 node_mask, enum which_state which)
{
	if (peer_device->connection->agreed_pro_version >= 110)
		return _bsr_send_uuids110(peer_device, uuid_flags, node_mask, which);
	else
		return _bsr_send_uuids(peer_device, uuid_flags);
}

void bsr_print_uuids(struct bsr_peer_device *peer_device, const char *text, const char *caller)
{
	struct bsr_device *device = peer_device->device;

	if (get_ldev_if_state(device, D_NEGOTIATING)) {
		bsr_info(1, BSR_LC_UUID, peer_device, "%s, %s %016llX:%016llX:%016llX:%016llX",
			caller, text,
			  (unsigned long long)bsr_current_uuid(device),
			  (unsigned long long)bsr_bitmap_uuid(peer_device),
			  (unsigned long long)bsr_history_uuid(device, 0),
			  (unsigned long long)bsr_history_uuid(device, 1));
		put_ldev(device);
	} else {
		bsr_info(2, BSR_LC_UUID, device, "%s, %s effective data uuid: %016llX",
			caller, text, 
			(unsigned long long)device->exposed_data_uuid);
	}
}

int bsr_send_current_uuid(struct bsr_peer_device *peer_device, u64 current_uuid, u64 weak_nodes)
{
	struct p_current_uuid *p;

	p = bsr_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->uuid = cpu_to_be64(current_uuid);
	p->weak_nodes = cpu_to_be64(weak_nodes);
	return bsr_send_command(peer_device, P_CURRENT_UUID, DATA_STREAM);
}

void bsr_gen_and_send_sync_uuid(struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
	struct p_uuid *p;
	u64 uuid;

	D_ASSERT(device, device->disk_state[NOW] == D_UP_TO_DATE);

	uuid = bsr_bitmap_uuid(peer_device);
	if (uuid && uuid != UUID_JUST_CREATED)
		uuid = uuid + UUID_NEW_BM_OFFSET;
	else
		get_random_bytes(&uuid, sizeof(u64));
	bsr_uuid_set_bitmap(peer_device, uuid);
	bsr_print_uuids(peer_device, "updated sync UUID", __FUNCTION__);
	// BSR-676 notify uuid
	bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
	bsr_md_sync(device);

	p = bsr_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (p) {
		p->uuid = cpu_to_be64(uuid);
		bsr_send_command(peer_device, P_SYNC_UUID, DATA_STREAM);
	}
}

/* All callers hold resource->conf_update */
int bsr_attach_peer_device(struct bsr_peer_device *peer_device) __must_hold(local)
{
	struct peer_device_conf *pdc;
	struct fifo_buffer *resync_plan = NULL;
	struct lru_cache *resync_lru = NULL;
	int err = -ENOMEM;

	pdc = rcu_dereference_protected(peer_device->conf,
		lockdep_is_held(&peer_device->device->resource->conf_update));
#ifdef _WIN
    if (peer_device->rs_plan_s)
        resync_plan = peer_device->rs_plan_s;
    else
    	resync_plan = fifo_alloc((pdc->c_plan_ahead * 10 * SLEEP_TIME) / HZ, '88SB');
#else // _LIN
	// BSR-180
	resync_plan = rcu_dereference_protected(peer_device->rs_plan_s,
		lockdep_is_held(&peer_device->device->resource->conf_update));
	if(!resync_plan)
		resync_plan = fifo_alloc((pdc->c_plan_ahead * 10 * SLEEP_TIME) / HZ);
#endif
	if (!resync_plan)
		goto out;
#ifdef _WIN
	resync_lru = lc_create("resync", &bsr_bm_ext_cache,
			       1, 61, sizeof(struct bm_extent),
			       offsetof(struct bm_extent, lce));
#else // _LIN
	resync_lru = lc_create("resync", bsr_bm_ext_cache,
			       1, 61, sizeof(struct bm_extent),
			       offsetof(struct bm_extent, lce));
#endif
	if (!resync_lru)
		goto out;
	rcu_assign_pointer(peer_device->rs_plan_s, resync_plan);
	peer_device->resync_lru = resync_lru;
	err = 0;

out:
	if (err) {
		bsr_kfree(resync_lru);
		bsr_kfree(resync_plan);
	}
	return err;
}

#ifdef _LIN
/* communicated if (agreed_features & BSR_FF_WSAME) */
void assign_p_sizes_qlim(struct bsr_device *device, struct p_sizes *p, struct request_queue *q)
{
#ifndef COMPAT_HAVE_QUEUE_ALIGMENT_OFFSET
	struct block_device *bdev = device->ldev->backing_bdev;
#endif
	if (q) {
#ifdef COMPAT_HAVE_QUEUE_ALIGMENT_OFFSET
		p->qlim->physical_block_size = cpu_to_be32(queue_physical_block_size(q));
		p->qlim->logical_block_size = cpu_to_be32(queue_logical_block_size(q));
		p->qlim->alignment_offset = cpu_to_be32(queue_alignment_offset(q));
#else
		p->qlim->physical_block_size = cpu_to_be32(bdev_physical_block_size(bdev));
		p->qlim->logical_block_size = cpu_to_be32(bdev_logical_block_size(bdev));
		p->qlim->alignment_offset = cpu_to_be32(bdev_alignment_offset(bdev));
#endif
		p->qlim->io_min = cpu_to_be32(queue_io_min(q));
		p->qlim->io_opt = cpu_to_be32(queue_io_opt(q));
		p->qlim->discard_enabled = blk_queue_discard(q);
		p->qlim->discard_zeroes_data = queue_discard_zeroes_data(q);
#ifdef COMPAT_WRITE_SAME_CAPABLE
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
		p->qlim->write_same_capable = !!q->limits.max_write_same_sectors;
#endif
#else
		p->qlim->write_same_capable = 0;
#endif
	} else {
		q = device->rq_queue;
#ifdef COMPAT_HAVE_QUEUE_ALIGMENT_OFFSET
		p->qlim->physical_block_size = cpu_to_be32(queue_physical_block_size(q));
		p->qlim->logical_block_size = cpu_to_be32(queue_logical_block_size(q));
#else
		p->qlim->physical_block_size = cpu_to_be32(bdev_physical_block_size(bdev));
		p->qlim->logical_block_size = cpu_to_be32(bdev_logical_block_size(bdev));
#endif
		p->qlim->alignment_offset = 0;
		p->qlim->io_min = cpu_to_be32(queue_io_min(q));
		p->qlim->io_opt = cpu_to_be32(queue_io_opt(q));
		p->qlim->discard_enabled = 0;
		p->qlim->discard_zeroes_data = 0;
		p->qlim->write_same_capable = 0;
	}
}
#endif

int bsr_send_sizes(struct bsr_peer_device *peer_device,
			uint64_t u_size_diskless, enum dds_flags flags)
{
	struct bsr_device *device = peer_device->device;
	struct p_sizes *p;
	sector_t d_size, u_size;
	int q_order_type;
	unsigned int max_bio_size;
	unsigned int packet_size;

	packet_size = sizeof(*p);
	if (peer_device->connection->agreed_features & BSR_FF_WSAME)
		packet_size += sizeof(p->qlim[0]);

	p = bsr_prepare_command(peer_device, packet_size, DATA_STREAM);
	if (!p)
		return -EIO;

	memset(p, 0, packet_size);
	if (get_ldev_if_state(device, D_NEGOTIATING)) {
#ifdef _LIN
		struct request_queue *q = bdev_get_queue(device->ldev->backing_bdev);
#endif
		d_size = bsr_get_max_capacity(device->ldev);
		rcu_read_lock();
		u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
		rcu_read_unlock();
		q_order_type = bsr_queue_order_type(device);
#ifdef _WIN
		// DW-1497 Fix max bio size to default 1MB, because we don't need to variable max bio config on Windows.
		// Since max_bio_size is an integer type, an overflow has occurred for the value of max_hw_sectors.
		// DW-1763 set to BSR_MAX_BIO_SIZE if larger than BSR_MAX_BIO_SIZE.
		max_bio_size = (unsigned int)(min((queue_max_hw_sectors(device->ldev->backing_bdev->bd_disk->queue) << 9), 
											BSR_MAX_BIO_SIZE));
#else // _LIN
		max_bio_size = queue_max_hw_sectors(q) << 9;
		max_bio_size = min(max_bio_size, BSR_MAX_BIO_SIZE);
#endif
#ifdef _LIN
		assign_p_sizes_qlim(device, p, q);
#endif
		put_ldev(device);
	} else {
		d_size = 0;
		u_size = u_size_diskless;
		q_order_type = QUEUE_ORDERED_NONE;
		max_bio_size = BSR_MAX_BIO_SIZE; /* ... multiple BIOs per peer_request */
#ifdef _LIN
		assign_p_sizes_qlim(device, p, NULL);
#endif
	}

	if (peer_device->connection->agreed_pro_version <= 94)
		max_bio_size = min(max_bio_size, BSR_MAX_SIZE_H80_PACKET);
	else if (peer_device->connection->agreed_pro_version < 100)
		max_bio_size = min(max_bio_size, BSR_MAX_BIO_SIZE_P95);

	p->d_size = cpu_to_be64(d_size);
	p->u_size = cpu_to_be64(u_size);
	/*
	TODO verify: this may be needed for v8 compatibility still.
	p->c_size = cpu_to_be64(trigger_reply ? 0 : bsr_get_capacity(device->this_bdev));
	*/

	// DW-1469 For initial sync, set c_size to 0.
	if (bsr_current_uuid(device) == UUID_JUST_CREATED) {
		p->c_size = 0;	
	} 	
	else {
		p->c_size = cpu_to_be64(bsr_get_vdisk_capacity(device));
	}
	
	p->max_bio_size = cpu_to_be32(max_bio_size);
#ifdef _WIN
	BUG_ON_UINT16_OVER(q_order_type);
#endif
	p->queue_order_type = cpu_to_be16((uint16_t)q_order_type);
	p->dds_flags = cpu_to_be16(flags);

	return bsr_send_command(peer_device, P_SIZES, DATA_STREAM);
}

int bsr_send_current_state(struct bsr_peer_device *peer_device)
{
	return bsr_send_state(peer_device, bsr_get_peer_device_state(peer_device, NOW));
}

static int send_state(struct bsr_connection *connection, int vnr, union bsr_state state)
{
	struct p_state *p;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	if (connection->agreed_pro_version < 110) {
		/* D_DETACHING was introduced with bsr-9.0 */
		if (state.disk > D_DETACHING)
			state.disk--;
		if (state.pdsk > D_DETACHING)
			state.pdsk--;
	}

	p->state = cpu_to_be32(state.i); /* Within the send mutex */
	return send_command(connection, vnr, P_STATE, DATA_STREAM);
}

int conn_send_state(struct bsr_connection *connection, union bsr_state state)
{
	BUG_ON(connection->agreed_pro_version < 100);
	return send_state(connection, -1, state);
}

/**
 * bsr_send_state() - Sends the bsr state to the peer
 * @device:	BSR device.
 * @state:	state to send
 */
int bsr_send_state(struct bsr_peer_device *peer_device, union bsr_state state)
{
	return send_state(peer_device->connection, peer_device->device->vnr, state);
}

int conn_send_state_req(struct bsr_connection *connection, int vnr, enum bsr_packet cmd,
			union bsr_state mask, union bsr_state val)
{
	struct p_req_state *p;

	/* Protocols before version 100 only support one volume and connection.
	 * All state change requests are via P_STATE_CHG_REQ. */
	if (connection->agreed_pro_version < 100)
		cmd = P_STATE_CHG_REQ;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->mask = cpu_to_be32(mask.i);
	p->val = cpu_to_be32(val.i);

	return send_command(connection, vnr, cmd, DATA_STREAM);
}

int conn_send_twopc_request(struct bsr_connection *connection, int vnr, enum bsr_packet cmd,
			    struct p_twopc_request *request)
{
	struct p_twopc_request *p;

	bsr_debug(50, BSR_LC_TWOPC, connection, "Sending %s request for state change %u",
		   bsr_packet_name(cmd),
		   be32_to_cpu(request->tid));

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	memcpy(p, request, sizeof(*request));

	return send_command(connection, vnr, cmd, DATA_STREAM);
}

void bsr_send_sr_reply(struct bsr_connection *connection, int vnr, enum bsr_state_rv retcode)
{
	struct p_req_state_reply *p;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (p) {
		enum bsr_packet cmd = P_STATE_CHG_REPLY;

		if (connection->agreed_pro_version >= 100 && vnr < 0)
			cmd = P_CONN_ST_CHG_REPLY;

		p->retcode = cpu_to_be32(retcode);
		send_command(connection, vnr, cmd, CONTROL_STREAM);
	}
}

void bsr_send_twopc_reply(struct bsr_connection *connection,
			   enum bsr_packet cmd, struct twopc_reply *reply)
{
	struct p_twopc_reply *p;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (p) {
		p->tid = cpu_to_be32(reply->tid);
		p->initiator_node_id = cpu_to_be32(reply->initiator_node_id);
		p->reachable_nodes = cpu_to_be64(reply->reachable_nodes);
		switch (connection->resource->twopc_type) {
		case TWOPC_STATE_CHANGE:
			p->primary_nodes = cpu_to_be64(reply->primary_nodes);
			p->weak_nodes = cpu_to_be64(reply->weak_nodes);
			break;
		case TWOPC_RESIZE:
			p->diskful_primary_nodes = cpu_to_be64(reply->diskful_primary_nodes);
			p->max_possible_size = cpu_to_be64(reply->max_possible_size);
			break;
		}
		send_command(connection, reply->vnr, cmd, CONTROL_STREAM);
	}
}

void bsr_send_peers_in_sync(struct bsr_peer_device *peer_device, u64 mask, sector_t sector, int size)
{
	struct p_peer_block_desc *p;

	p = bsr_prepare_command(peer_device, sizeof(*p), CONTROL_STREAM);
	if (p) {
		p->sector = cpu_to_be64(sector);
		p->mask = cpu_to_be64(mask);
		p->size = cpu_to_be32(size);
		p->pad = 0;
		bsr_send_command(peer_device, P_PEERS_IN_SYNC, CONTROL_STREAM);
	}
}

int bsr_send_peer_dagtag(struct bsr_connection *connection, struct bsr_connection *lost_peer)
{
	struct p_peer_dagtag *p;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->dagtag = cpu_to_be64(lost_peer->last_dagtag_sector);
	p->node_id = cpu_to_be32(lost_peer->peer_node_id);
#ifdef _TRACE_PEER_DAGTAG
	bsr_info(26, BSR_LC_ETC, NO_OBJECT,"bsr_send_peer_dagtag lost_peer:%p lost_peer->last_dagtag_sector:%llx lost_peer->peer_node_id:%d",lost_peer,lost_peer->last_dagtag_sector,lost_peer->peer_node_id);
#endif	
	return send_command(connection, -1, P_PEER_DAGTAG, DATA_STREAM);
}

static void dcbp_set_code(struct p_compressed_bm *p, enum bsr_bitmap_code code)
{
	BUG_ON(code & ~0xf);
	p->encoding = (uint8_t)((p->encoding & ~0xf) | code);
}

static void dcbp_set_start(struct p_compressed_bm *p, int set)
{
	p->encoding = (p->encoding & ~0x80) | (set ? 0x80 : 0);
}

static void dcbp_set_pad_bits(struct p_compressed_bm *p, int n)
{
	BUG_ON(n & ~0x7);
	p->encoding = (uint8_t)((p->encoding & (~0x7 << 4)) | (n << 4));
}

static int fill_bitmap_rle_bits(struct bsr_peer_device *peer_device,
				struct p_compressed_bm *p,
				unsigned int size,
				struct bm_xfer_ctx *c)
{
	struct bitstream bs;
	ULONG_PTR plain_bits;
	ULONG_PTR tmp;
	ULONG_PTR rl;
	ULONG_PTR offset;
	unsigned len;
	unsigned toggle;
	int bits, use_rle;

	/* may we use this feature? */
	rcu_read_lock();
	use_rle = rcu_dereference(peer_device->connection->transport.net_conf)->use_rle;
	rcu_read_unlock();
	if (!use_rle || peer_device->connection->agreed_pro_version < 90)
		return 0;

	if (c->bit_offset >= c->bm_bits)
		return 0; /* nothing to do. */

	/* use at most thus many bytes */
	bitstream_init(&bs, p->code, size, 0);
	memset(p->code, 0, size);
	/* plain bits covered in this code string */
	plain_bits = 0;

	/* p->encoding & 0x80 stores whether the first run length is set.
	 * bit offset is implicit.
	 * start with toggle == 2 to be able to tell the first iteration */
	toggle = 2;

	/* see how much plain bits we can stuff into one packet
	 * using RLE and VLI. */
	do {
		// DW-1979 to avoid lock occupancy, divide and find.
		offset = c->bit_offset;
		for (;;) {
			tmp = (toggle == 0) ? bsr_bm_range_find_next_zero(peer_device, offset, offset + RANGE_FIND_NEXT_BIT) :
				bsr_bm_range_find_next(peer_device, offset, offset + RANGE_FIND_NEXT_BIT);
			if (tmp >= c->bm_bits || tmp < (offset + RANGE_FIND_NEXT_BIT + 1))
				break;
			offset = tmp;
		}
		if (tmp > c->bm_bits)
			tmp = c->bm_bits;

		rl = tmp - c->bit_offset;
		if (toggle == 2) { /* first iteration */
			if (rl == 0) {
				/* the first checked bit was set,
				 * store start value, */
				dcbp_set_start(p, 1);
				/* but skip encoding of zero run length */
				toggle = !toggle;
				continue;
			}
			dcbp_set_start(p, 0);
		}

		/* paranoia: catch zero runlength.
		 * can only happen if bitmap is modified while we scan it. */
		if (rl == 0) {
			bsr_warn(61, BSR_LC_BITMAP, peer_device, "Unexpected zero runlength while encoding bitmap "
			    "t:%u bo:%llu", toggle, (unsigned long long)c->bit_offset);
			// DW-2037 replication I/O can cause bitmap changes, in which case this code will restore.
			if (toggle == 0) {
				update_sync_bits(peer_device, offset, offset, SET_OUT_OF_SYNC, false);
				continue;
			}
			else {
				bsr_err(30, BSR_LC_BITMAP, peer_device, "Failed to fill bitmap due to unexpected out-of-sync has occurred");
				return -1;
			}
		}

		bits = vli_encode_bits(&bs, rl);
		if (bits == -ENOBUFS) /* buffer full */
			break;
		if (bits <= 0) {
			bsr_err(31, BSR_LC_BITMAP, peer_device, "Failed to fill bitmap due to error while encoding bitmap. bits(%d)", bits);
			return 0;
		}

		toggle = !toggle;
		plain_bits += rl;
		c->bit_offset = tmp;
	} while (c->bit_offset < c->bm_bits);

	BUG_ON(UINT_MAX < bs.cur.b - p->code + !!bs.cur.bit);
	len = (unsigned int)(bs.cur.b - p->code + !!bs.cur.bit);

	if (plain_bits < ((ULONG_PTR)len << 3)) {
		/* incompressible with this method.
		 * we need to rewind both word and bit position. */
		c->bit_offset -= plain_bits;
		bm_xfer_ctx_bit_to_word_offset(c);
		c->bit_offset = c->word_offset * BITS_PER_LONG;
		return 0;
	}

	/* RLE + VLI was able to compress it just fine.
	 * update c->word_offset. */
	bm_xfer_ctx_bit_to_word_offset(c);

	/* store pad_bits */
	dcbp_set_pad_bits(p, (8 - bs.cur.bit) & 0x7);

	return len;
}

/**
 * send_bitmap_rle_or_plain
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
send_bitmap_rle_or_plain(struct bsr_peer_device *peer_device, struct bm_xfer_ctx *c)
{
	struct bsr_device *device = peer_device->device;
	unsigned int header_size = bsr_header_size(peer_device->connection);
	struct p_compressed_bm *pc, *tpc;
	int len, err;

	tpc = (struct p_compressed_bm *)bsr_kzalloc(BSR_SOCKET_BUFFER_SIZE, GFP_NOIO | __GFP_NOWARN, 'F8SB');

	if (!tpc) {
		bsr_err(49, BSR_LC_MEMORY, peer_device, "Failed to send bitmap due to failure to allocate %d size memory in kzalloc", BSR_SOCKET_BUFFER_SIZE);
		return -ENOMEM;
	}

	len = fill_bitmap_rle_bits(peer_device, tpc,
			BSR_SOCKET_BUFFER_SIZE - header_size - sizeof(*tpc), c);
	if (len < 0) {
		bsr_err(33, BSR_LC_BITMAP, peer_device, "Failed to send bitmap due to bitmap length is invalid. len(%d) ", len);
		return -EIO;
	}

	// DW-1979
	mutex_lock(&peer_device->connection->mutex[DATA_STREAM]);

	pc = (struct p_compressed_bm *)
		(alloc_send_buffer(peer_device->connection, BSR_SOCKET_BUFFER_SIZE, DATA_STREAM) + header_size);

	pc->encoding = tpc->encoding;
	memcpy(pc->code, tpc->code, BSR_SOCKET_BUFFER_SIZE - header_size - sizeof(*pc));
	bsr_kfree(tpc);

	if (len) {
		dcbp_set_code(pc, RLE_VLI_Bits);
		resize_prepared_command(peer_device->connection, DATA_STREAM, sizeof(*pc) + len);
		err = __send_command(peer_device->connection, device->vnr,
				     P_COMPRESSED_BITMAP, DATA_STREAM);

		if (err) {
			bsr_err(106, BSR_LC_BITMAP, peer_device, "Failed to send compressed bitmap. err(%d)", err);
		}
		
		c->packets[0]++;
		c->bytes[0] += header_size + sizeof(*pc) + len;

		if (c->bit_offset >= c->bm_bits)
			len = 0; /* DONE */
	} else {
		/* was not compressible.
		 * send a buffer full of plain text bits instead. */
		unsigned int data_size;
		ULONG_PTR num_words;
		ULONG_PTR *pu = (ULONG_PTR *)pc;
		data_size = BSR_SOCKET_BUFFER_SIZE - header_size;
		num_words = min_t(size_t, data_size / sizeof(*pu),
				  c->bm_words - c->word_offset);
		len = (int)(num_words * sizeof(*pu));
		if (len)
			bsr_bm_get_lel(peer_device, c->word_offset, num_words, pu);

		resize_prepared_command(peer_device->connection, DATA_STREAM, len);
		err = __send_command(peer_device->connection, device->vnr, P_BITMAP, DATA_STREAM);

		if (err) {
			bsr_err(107, BSR_LC_BITMAP, peer_device, "Failed to send bitmap. err(%d)", err);
		}		

		c->word_offset += num_words;
		c->bit_offset = c->word_offset * BITS_PER_LONG;

		c->packets[1]++;
		c->bytes[1] += header_size + len;

		if (c->bit_offset > c->bm_bits)
			c->bit_offset = c->bm_bits;
	}

	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	if (!err) {
		if (len == 0) {
			INFO_bm_xfer_stats(peer_device, "send", c);
			return 0;
		} else
			return 1;
	}
	return -EIO;
}

void bsr_send_bitmap_source_complete(struct bsr_device *device, struct bsr_peer_device *peer_device, int err)
{
	UNREFERENCED_PARAMETER(device);

	// DW-2037 reconnect if the bitmap cannot be restored.
	if (err) {
		bsr_err(64, BSR_LC_BITMAP, peer_device, "Failed to send bitmap from sync source. err(%d)", err);
		change_cstate_ex(peer_device->connection, C_NETWORK_FAILURE, CS_HARD);
	}
}

// DW-1979
void bsr_send_bitmap_target_complete(struct bsr_device *device, struct bsr_peer_device *peer_device, int err)
{
	if (err) {
		bsr_err(65, BSR_LC_BITMAP, peer_device, "Failed to send bitmap from sync target. err(%d)", err);
		change_cstate_ex(peer_device->connection, C_NETWORK_FAILURE, CS_HARD);
	}

	/* Omit CS_WAIT_COMPLETE and CS_SERIALIZE with this state
	* transition to avoid deadlocks. */

	if (peer_device->connection->agreed_pro_version < 110) {
		enum bsr_state_rv rv;
		rv = stable_change_repl_state(peer_device, L_WF_SYNC_UUID, CS_VERBOSE);
		D_ASSERT(device, rv == SS_SUCCESS);
	}
	else {
		// DW-2088 set the MDF_PEER_INCOMP_SYNC_WITH_SAME_UUID to the peer_device that is syncsource in the synctarget at the start of resync
		bsr_md_set_peer_flag(peer_device, MDF_PEER_INCOMP_SYNC_WITH_SAME_UUID);
		bsr_md_sync(device);

		bsr_start_resync(peer_device, L_SYNC_TARGET);
	}
}


/* See the comment at receive_bitmap() */
static int _bsr_send_bitmap(struct bsr_device *device,
			     struct bsr_peer_device *peer_device)
{
	struct bm_xfer_ctx c;
	int err;

	if (!expect(device, device->bitmap)) {
		bsr_err(66, BSR_LC_BITMAP, peer_device, "Failed to send bitmap because bitmap is not set");
		return false;
	}

	if (get_ldev(device)) {
		if (bsr_md_test_peer_flag(peer_device, MDF_PEER_FULL_SYNC)) {
			bsr_info(28, BSR_LC_IO, device, "Set all bitmap bit to out of sync because the peer has a full sync flag set.");
			bsr_bm_set_many_bits(peer_device, 0, BSR_END_OF_BITMAP);
			if (bsr_bm_write(device, NULL)) {
				/* write_bm did fail! Leave full sync flag set in Meta P_DATA
				 * but otherwise process as per normal - need to tell other
				 * side that a full resync is required! */
				bsr_err(29, BSR_LC_IO, device, "Peer full sync setting failed to write to disk");
			} else {
				bsr_md_clear_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
				bsr_md_sync(device);
			}
		}
		put_ldev(device);
	}

	memset(&c, 0, sizeof(struct bm_xfer_ctx));

	c = (struct bm_xfer_ctx) {
		.bm_bits = bsr_bm_bits(device),
		.bm_words = bsr_bm_words(device),
	};

	do {
		err = send_bitmap_rle_or_plain(peer_device, &c);
	} while (err > 0);

	return err == 0;
}

int bsr_send_bitmap(struct bsr_device *device, struct bsr_peer_device *peer_device)
{
	struct bsr_transport *peer_transport = &peer_device->connection->transport;
	int err = -1;
	struct bsr_peer_device* incomp_sync_source = NULL;
	bool incomp_sync = false;;

	if (peer_device->bitmap_index == -1) {
		bsr_err(67, BSR_LC_BITMAP, peer_device, "Failed to send bitmap due to bitmap index is not assigned to peer device.");
		return -EIO;
	}

	// DW-2088 apply out of sync to the previous syncosurce when changing sync sources with the same uuid.
	for_each_peer_device(incomp_sync_source, device) {
		if (bsr_md_test_peer_flag(incomp_sync_source, MDF_PEER_INCOMP_SYNC_WITH_SAME_UUID)) {
			incomp_sync = true;
			break;
		}
	}

	if (incomp_sync) {
		if (incomp_sync_source != peer_device &&
			peer_device->repl_state[NOW] == L_WF_BITMAP_T) {

			// DW-1815 merge the peer_device bitmap into the same current_uuid.
			ULONG_PTR offset, current_offset;

			int allow_size = 512;
#ifdef _WIN
			ULONG_PTR *bb = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG_PTR) * allow_size, '8ESB');
#else // _LIN
			ULONG_PTR *bb = bsr_kmalloc(sizeof(ULONG_PTR) * allow_size, GFP_ATOMIC|__GFP_NOWARN, '');
#endif
			ULONG_PTR word_offset;

			if (bb == NULL) {
				bsr_err(50, BSR_LC_MEMORY, peer_device, "Failed to send bitmap due to failure to allocate %d size memory for copy bitmap", (sizeof(ULONG_PTR) * allow_size));
				change_cstate_ex(peer_device->connection, C_NETWORK_FAILURE, CS_HARD);
			}
			else {
				memset(bb, 0, sizeof(ULONG_PTR) * allow_size);

				bsr_info(35, BSR_LC_BITMAP, peer_device, "Proceed with bitmap merge for bitmap send, from bitmap index(%d) out of sync(%llu), to bitmap index(%d) out of sync (%llu)",
					incomp_sync_source->bitmap_index, (unsigned long long)bsr_bm_total_weight(incomp_sync_source),
					peer_device->bitmap_index, (unsigned long long)bsr_bm_total_weight(peer_device));

				word_offset = current_offset = offset = 0;
				for (;;) {
					offset = bsr_bm_range_find_next(incomp_sync_source, current_offset, current_offset + RANGE_FIND_NEXT_BIT);
					 // DW-2088 word that is not a bit should be used for merging
					if (offset < (current_offset + RANGE_FIND_NEXT_BIT + 1)) {
						word_offset = (offset / BITS_PER_LONG);
						for (; (word_offset * BITS_PER_LONG) < bsr_bm_bits(device); word_offset += allow_size) {
							bsr_bm_get_lel(incomp_sync_source, word_offset, allow_size, bb);
							bsr_bm_merge_lel(peer_device, word_offset, allow_size, bb);
						}
						break;
					}
					if (offset >= bsr_bm_bits(device)) {
						break;
					}
					current_offset = offset;
				}

				bsr_info(36, BSR_LC_BITMAP, peer_device, "Bitmap merge completed successfully. to bitmap index(%d) out of sync (%llu)", peer_device->bitmap_index, (unsigned long long)bsr_bm_total_weight(peer_device));
				kfree2(bb);
				
			}
		}
		else {
			bsr_md_clear_peer_flag(peer_device, MDF_PEER_INCOMP_SYNC_WITH_SAME_UUID);
		}
	}

	mutex_lock(&peer_device->connection->mutex[DATA_STREAM]);
	// DW-1979
	if (peer_transport->ops->stream_ok(peer_transport, DATA_STREAM)) {
		mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);
		// DW-1988 in synctarget, wait_for_recv_bitmap should not be used, so it has been modified to be set only under certain conditions.
		// DW-1979
		if (peer_device->repl_state[NOW] == L_WF_BITMAP_S ||
			peer_device->repl_state[NOW] == L_AHEAD)
			atomic_set(&peer_device->wait_for_recv_bitmap, 1);
		err = !_bsr_send_bitmap(device, peer_device);
	}
	else
		mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

void bsr_send_b_ack(struct bsr_connection *connection, s32 barrier_nr, u32 set_size)
{
	struct p_barrier_ack *p;

	if (connection->cstate[NOW] < C_CONNECTED)
		return;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return;
	p->barrier = barrier_nr;
	p->set_size = cpu_to_be32(set_size);
	send_command(connection, -1, P_BARRIER_ACK, CONTROL_STREAM);
}

int bsr_send_rs_deallocated(struct bsr_peer_device *peer_device,
			     struct bsr_peer_request *peer_req)
{
	struct p_block_desc *p;

	p = bsr_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(peer_req->i.sector);
	p->blksize = cpu_to_be32(peer_req->i.size);
	p->pad = 0;
	return bsr_send_command(peer_device, P_RS_DEALLOCATED, DATA_STREAM);
}

/**
* _bsr_send_ack() - Sends an ack packet
* @device:	BSR device.
* @cmd:	Packet command code.
* @sector:	sector, needs to be in big endian byte order
* @blksize:	size in byte, needs to be in big endian byte order
* @block_id:	Id, big endian byte order
*/
int _bsr_send_ack(struct bsr_peer_device *peer_device, enum bsr_packet cmd,
	u64 sector, u32 blksize, u64 block_id)
{
	struct p_block_ack *p;

	if (peer_device->repl_state[NOW] < L_ESTABLISHED)
		return -EIO;

	p = bsr_prepare_command(peer_device, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return -EIO;
	p->sector = sector;
	p->block_id = block_id;
	p->blksize = blksize;
	p->seq_num = cpu_to_be32(atomic_inc_return(&peer_device->packet_seq));
	return bsr_send_command(peer_device, cmd, CONTROL_STREAM);
}

// DW-2124
int _bsr_send_bitmap_exchange_state(struct bsr_peer_device *peer_device, enum bsr_packet cmd, u32 state)
{
	struct p_bm_exchange_state *p;

	p = bsr_prepare_command(peer_device, sizeof(*p), DATA_STREAM);

	if (!p)
		return -EIO;

	p->state = cpu_to_be32(state);

	return bsr_send_command(peer_device, cmd, DATA_STREAM);

}

int bsr_send_drequest(struct bsr_peer_device *peer_device, int cmd,
		       sector_t sector, int size, u64 block_id)
{
	struct p_block_req *p;

#ifdef BSR_TRACE
	bsr_debug(175, BSR_LC_RESYNC_OV, NO_OBJECT,"sz=%d sector=%lld", size, sector);
#endif
	p = bsr_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(sector);
	p->block_id = block_id;
	p->pad = 0;
	p->blksize = cpu_to_be32(size);
    bsr_debug_rs("size(%d) cmd(%d) sector(0x%llx) block_id(%llu)", size, cmd, (u64)sector, block_id);
	return bsr_send_command(peer_device, cmd, DATA_STREAM);
}

void *bsr_prepare_drequest_csum(struct bsr_peer_request *peer_req, int digest_size)
{
	struct bsr_peer_device *peer_device = peer_req->peer_device;
	struct p_block_req *p;

	p = bsr_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);
	if (!p)
		return NULL;

	p->sector = cpu_to_be64(peer_req->i.sector);
	p->block_id = peer_req->block_id; // BSR-448 used to notify source of io failure.
	p->blksize = cpu_to_be32(peer_req->i.size);

	return p + 1; /* digest should be placed behind the struct */
}

int bsr_send_ov_request(struct bsr_peer_device *peer_device, sector_t sector, int size)
{
	struct p_block_req *p;

	p = bsr_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(sector);
	p->block_id = peer_device->ov_left; // BSR-118 initially send bitmap_total_weight of fast ov to the target
	p->blksize = cpu_to_be32(size);
	return bsr_send_command(peer_device, P_OV_REQUEST, DATA_STREAM);
}

/* The idea of sendpage seems to be to put some kind of reference
 * to the page into the skb, and to hand it over to the NIC. In
 * this process get_page() gets called.
 *
 * As soon as the page was really sent over the network put_page()
 * gets called by some part of the network layer. [ NIC driver? ]
 *
 * [ get_page() / put_page() increment/decrement the count. If count
 *   reaches 0 the page will be freed. ]
 *
 * This works nicely with pages from FSs.
 * But this means that in protocol A we might signal IO completion too early!
 *
 * In order not to corrupt data during a resync we must make sure
 * that we do not reuse our own buffer pages (EEs) to early, therefore
 * we have the net_ee list.
 *
 * XFS seems to have problems, still, it submits pages with page_count == 0!
 * As a workaround, we disable sendpage on pages
 * with page_count == 0 or PageSlab.
 */

static int _bsr_send_page(struct bsr_peer_device *peer_device, struct page *page,
			    int offset, size_t size, unsigned msg_flags)
{
	struct bsr_connection *connection = peer_device->connection;
	struct bsr_transport *transport = &connection->transport;
	struct bsr_transport_ops *tr_ops = transport->ops;
	int err;

#ifdef _WIN
	err = tr_ops->send_page(transport, DATA_STREAM, page->addr, offset, size, msg_flags);
#else // _LIN
	err = tr_ops->send_page(transport, DATA_STREAM, page, offset, size, msg_flags);
#endif
	if (!err) {
		peer_device->send_cnt += (unsigned int)(size >> 9);
	}

	return err;
}
#ifdef _WIN
//we don't need to consider page, care to only buffer in no_send_page
int _bsr_no_send_page(struct bsr_peer_device *peer_device, void * buffer,
			      int offset, size_t size, unsigned msg_flags)
{
	struct bsr_connection *connection = peer_device->connection;
	struct bsr_transport *transport = &connection->transport;
	struct bsr_transport_ops *tr_ops = transport->ops;
	int err;

	bsr_debug_rs("offset(%d) size(%d)", offset, size);
	flush_send_buffer(connection, DATA_STREAM); 
	err = tr_ops->send_page(transport, DATA_STREAM, buffer, offset, size, msg_flags);
	if (!err) {
		peer_device->send_cnt += (unsigned int)(size >> 9);
	}
	return err;
}
#else // _LIN
int _bsr_no_send_page(struct bsr_peer_device *peer_device, struct page *page,
			      int offset, size_t size, unsigned msg_flags)
{
	struct bsr_connection *connection = peer_device->connection;
	struct bsr_send_buffer *sbuf = &connection->send_buffer[DATA_STREAM];
	char *from_base;
	void *buffer2;
	int err;

	buffer2 = alloc_send_buffer(connection, size, DATA_STREAM);
	from_base = bsr_kmap_atomic(page, KM_USER0);
	memcpy(buffer2, from_base + offset, size);
	bsr_kunmap_atomic(from_base, KM_USER0);

	if (msg_flags & MSG_MORE) {
		sbuf->pos += sbuf->allocated_size;
		sbuf->allocated_size = 0;
		err = 0;
	} else {
		err = flush_send_buffer(connection, DATA_STREAM);
	}

	return err;
}
#endif

static int _bsr_send_bio(struct bsr_peer_device *peer_device, struct bio *bio)
{
	struct bsr_connection *connection = peer_device->connection;
#ifdef _LIN
	BSR_BIO_VEC_TYPE bvec;
	BSR_ITER_TYPE iter;
#endif
	/* Flush send buffer and make sure PAGE_SIZE is available... */
	alloc_send_buffer(connection, PAGE_SIZE, DATA_STREAM);
	connection->send_buffer[DATA_STREAM].allocated_size = 0;

#ifdef _WIN
	int err;
	err = _bsr_no_send_page(peer_device, bio->bio_databuf, 0, bio->bi_size, 0);
	if (err)
		return err;

	peer_device->send_cnt += (bio->bi_size) >> 9;
#else // _LIN
	/* hint all but last page with MSG_MORE */
	bio_for_each_segment(bvec, bio, iter) {
		int err;

		err = _bsr_no_send_page(peer_device, bvec BVD bv_page,
					 bvec BVD bv_offset, bvec BVD bv_len,
					 bio_iter_last(bvec, iter) ? 0 : MSG_MORE);
		if (err)
			return err;
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
		/* WRITE_SAME has only one segment */
		if (bio_op(bio) == REQ_OP_WRITE_SAME)
			break;
#endif
		peer_device->send_cnt += (bvec BVD bv_len) >> 9;
	}
#endif
	return 0;
}

static int _bsr_send_zc_bio(struct bsr_peer_device *peer_device, struct bio *bio)
{

	/* e.g. XFS meta- & log-data is in slab pages, which have a
	 * page_count of 0 and/or have PageSlab() set.
	 * we cannot use send_page for those, as that does get_page();
	 * put_page(); and would cause either a VM_BUG directly, or
	 * __page_cache_release a page that would actually still be referenced
	 * by someone, leading to some obscure delayed Oops somewhere else. */
#ifdef _WIN
	int err;
	err = _bsr_no_send_page(peer_device, bio->bio_databuf, 0, bio->bi_size, 0);
	if (err)
		return err;
	return 0;
#else // _LIN
	BSR_BIO_VEC_TYPE bvec;
	BSR_ITER_TYPE iter;
	bool no_zc = disable_sendpage;

	if (!no_zc)
		bio_for_each_segment(bvec, bio, iter) {
			struct page *page = bvec BVD bv_page;

			if (page_count(page) < 1 || PageSlab(page)) {
				no_zc = true;
				break;
			}
		}

	if (no_zc) {
		return _bsr_send_bio(peer_device, bio);
	} else {
		struct bsr_connection *connection = peer_device->connection;
		struct bsr_transport *transport = &connection->transport;
		struct bsr_transport_ops *tr_ops = transport->ops;
		int err;

		flush_send_buffer(connection, DATA_STREAM);

		err = tr_ops->send_zc_bio(transport, bio);
		if (!err)
			peer_device->send_cnt += BSR_BIO_BI_SIZE(bio) >> 9;

		return err;
	}
#endif
}

static int _bsr_send_zc_ee(struct bsr_peer_device *peer_device,
			    struct bsr_peer_request *peer_req)
{
#ifdef _LIN
	struct page *page = peer_req->page_chain.head;
#endif
	unsigned len = peer_req->i.size;
	int err;

	flush_send_buffer(peer_device->connection, DATA_STREAM);

#ifdef _WIN
	// add bio-linked pointer to bsr_peer_request structure
	// bio-linked pointer(peer_req_databuf) is used to replace with page structure buffers
	err = _bsr_no_send_page(peer_device, peer_req->peer_req_databuf, 0, len, 0);
	if (err)
		return err;
#else // _LIN
	/* hint all but last page with MSG_MORE */
	page_chain_for_each(page) {
		unsigned l = min_t(unsigned, len, PAGE_SIZE);
		if (page_chain_offset(page) != 0 ||
		    page_chain_size(page) != l) {
			bsr_err(78, BSR_LC_SOCKET, peer_device, "FIXME, page %p offset %u len %u",
				page, page_chain_offset(page), page_chain_size(page));
		}

		err = _bsr_send_page(peer_device, page, 0, l,
				      page_chain_next(page) ? MSG_MORE : 0);
		if (err)
			return err;
		len -= l;
	}
#endif
	return 0;
}

/* see also wire_flags_to_bio()
 * BSR_REQ_*, because we need to semantically map the flags to data packet
 * flags and back. We may replicate to other kernel versions. */
static u32 bio_flags_to_wire(struct bsr_connection *connection, struct bio *bio)
{
	if (connection->agreed_pro_version >= 95)
		return  (bio->bi_opf & BSR_REQ_SYNC ? DP_RW_SYNC : 0) |
			(bio->bi_opf & BSR_REQ_UNPLUG ? DP_UNPLUG : 0) |
			(bio->bi_opf & BSR_REQ_FUA ? DP_FUA : 0) |
			(bio->bi_opf & BSR_REQ_PREFLUSH ? DP_FLUSH : 0) |
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
			(bio_op(bio) == REQ_OP_WRITE_SAME ? DP_WSAME : 0) |
#endif
			(bio_op(bio) == REQ_OP_DISCARD ? DP_DISCARD : 0) |
			(bio_op(bio) == REQ_OP_WRITE_ZEROES ?
				((connection->agreed_features & BSR_FF_WZEROES) ?
				(DP_ZEROES |(!(bio->bi_opf & REQ_NOUNMAP) ? DP_DISCARD : 0))
				: DP_DISCARD)
				: 0);
		

	/* else: we used to communicate one bit only in older BSR */
	return bio->bi_opf & (BSR_REQ_SYNC | BSR_REQ_UNPLUG) ? DP_RW_SYNC : 0;
}

/* Used to send write or TRIM aka REQ_DISCARD requests
 * R_PRIMARY -> Peer	(P_DATA, P_TRIM)
 */
int bsr_send_dblock(struct bsr_peer_device *peer_device, struct bsr_request *req)
{
	struct bsr_device *device = peer_device->device;
	struct p_trim *trim = NULL;
	struct p_data *p;
	struct p_wsame *wsame = NULL;
	void *digest_out = NULL;
	unsigned int dp_flags = 0;
	int digest_size = 0;
	int err = 0;
	const int op = bio_op(req->master_bio);
	
	const unsigned s = bsr_req_state_by_peer_device(req, peer_device);

	if (op == REQ_OP_DISCARD || op == REQ_OP_WRITE_ZEROES) {
		trim = bsr_prepare_command(peer_device, sizeof(*trim), DATA_STREAM);
		if (!trim)
			return -EIO;
		p = &trim->p_data;
		trim->size = cpu_to_be32(req->i.size);
	} else {
		if (peer_device->connection->integrity_tfm)
			digest_size = crypto_shash_digestsize(peer_device->connection->integrity_tfm);

#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
		if (op == REQ_OP_WRITE_SAME) {
			wsame = bsr_prepare_command(peer_device, sizeof(*wsame) + digest_size, DATA_STREAM);
			if (!wsame)
				return -EIO;
			p = &wsame->p_data;
			wsame->size = cpu_to_be32(req->i.size);
			digest_out = wsame + 1;
		} else {
#endif
			p = bsr_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);
			if (!p)
				return -EIO;
			digest_out = p + 1;
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
		}
#endif
	}

	p->sector = cpu_to_be64(req->i.sector);
	p->block_id = (ULONG_PTR)req;
	p->seq_num = cpu_to_be32(atomic_inc_return(&peer_device->packet_seq));
	
	dp_flags = bio_flags_to_wire(peer_device->connection, req->master_bio);
	if (peer_device->repl_state[NOW] >= L_SYNC_SOURCE && peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T)
		dp_flags |= DP_MAY_SET_IN_SYNC;
	if (peer_device->connection->agreed_pro_version >= 100) {
		if (s & RQ_EXP_RECEIVE_ACK)
			dp_flags |= DP_SEND_RECEIVE_ACK;
		if (s & RQ_EXP_WRITE_ACK || dp_flags & DP_MAY_SET_IN_SYNC)
			dp_flags |= DP_SEND_WRITE_ACK;
	}
	p->dp_flags = cpu_to_be32(dp_flags);

	if (trim) {
		err = __send_command(peer_device->connection, device->vnr,
				(dp_flags & DP_ZEROES) ? P_ZEROES : P_TRIM, DATA_STREAM);
				
		// BSR-782 apply DW-1012 (Remove out of sync when data is sent, this is the newest one.)
		// also remove oos when P_TRIM or P_ZEROES is sent.
		if (!err)
			bsr_set_in_sync(peer_device, req->i.sector, req->i.size);

		goto out;
	}

	if (digest_size && digest_out)
		bsr_csum_bio(peer_device->connection->integrity_tfm, req, digest_out);

	if (wsame) {
#ifdef _LIN
		additional_size_command(peer_device->connection, DATA_STREAM,
					bio_iovec(req->master_bio) BVD bv_len);
		err = __send_command(peer_device->connection, device->vnr, P_WSAME, DATA_STREAM);
#endif
	} else {
		additional_size_command(peer_device->connection, DATA_STREAM, req->i.size);
		err = __send_command(peer_device->connection, device->vnr, P_DATA, DATA_STREAM);
	}
	if (!err) {
		/* For protocol A, we have to memcpy the payload into
		 * socket buffers, as we may complete right away
		 * as soon as we handed it over to tcp, at which point the data
		 * pages may become invalid.
		 *
		 * For data-integrity enabled, we copy it as well, so we can be
		 * sure that even if the bio pages may still be modified, it
		 * won't change the data on the wire, thus if the digest checks
		 * out ok after sending on this side, but does not fit on the
		 * receiving side, we sure have detected corruption elsewhere.
		 */
		if (!(s & (RQ_EXP_RECEIVE_ACK | RQ_EXP_WRITE_ACK)) || digest_size)
#ifdef _WIN
			err = _bsr_no_send_page(peer_device, req->req_databuf, 0, req->i.size, 0);
#else // _LIN
			err = _bsr_send_bio(peer_device, req->master_bio);
#endif
		else
#ifdef _WIN
			err = _bsr_no_send_page(peer_device, req->req_databuf, 0, req->i.size, 0);
#else // _LIN
			err = _bsr_send_zc_bio(peer_device, req->master_bio);
#endif

		// DW-1012 Remove out of sync when data is sent, this is the newest one.
		if (!err)
			bsr_set_in_sync(peer_device, req->i.sector, req->i.size);

		/* double check digest, sometimes buffers have been modified in flight. */
		if (digest_size > 0 && digest_size <= 64) {
			/* 64 byte, 512 bit, is the largest digest size
			 * currently supported in kernel crypto. */
			unsigned char digest[64];
			bsr_csum_bio(peer_device->connection->integrity_tfm, req, digest);
			if (memcmp(p + 1, digest, digest_size)) {
				bsr_warn(24, BSR_LC_REQUEST, device,
					"Digest mismatch, buffer modified by upper layers during write: %llus +%u",
					(unsigned long long)req->i.sector, req->i.size);
			}
		} /* else if (digest_size > 64) {
		     ... Be noisy about digest too large ...
		} */
	}
out:
	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

/* answer packet, used to send data back for read requests:
 *  Peer       -> (diskless) R_PRIMARY   (P_DATA_REPLY)
 *  L_SYNC_SOURCE -> L_SYNC_TARGET         (P_RS_DATA_REPLY)
 */
int bsr_send_block(struct bsr_peer_device *peer_device, enum bsr_packet cmd,
		    struct bsr_peer_request *peer_req)
{
	struct p_data *p;
	int err;
	int digest_size;

	digest_size = peer_device->connection->integrity_tfm ?
		      crypto_shash_digestsize(peer_device->connection->integrity_tfm) : 0;

	p = bsr_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);

	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(peer_req->i.sector);
	p->block_id = peer_req->block_id;
	p->seq_num = 0;  /* unused */
	p->dp_flags = 0;
	if (digest_size)
		bsr_csum_pages(peer_device->connection->integrity_tfm, peer_req, p + 1);
	additional_size_command(peer_device->connection, DATA_STREAM, peer_req->i.size);

	err = __send_command(peer_device->connection,
			     peer_device->device->vnr, cmd, DATA_STREAM);
	if (!err)
		err = _bsr_send_zc_ee(peer_device, peer_req);
	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

int bsr_send_out_of_sync(struct bsr_peer_device *peer_device, struct bsr_interval *i)
{
	struct p_block_desc *p;

	p = bsr_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(i->sector);
	p->blksize = cpu_to_be32(i->size);
	return bsr_send_command(peer_device, P_OUT_OF_SYNC, DATA_STREAM);
}

int bsr_send_dagtag(struct bsr_connection *connection, u64 dagtag)
{
	struct p_dagtag *p;

	if (connection->agreed_pro_version < 110)
		return 0;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->dagtag = cpu_to_be64(dagtag);
	return send_command(connection, -1, P_DAGTAG, DATA_STREAM);
}

/* primary_peer_present_and_not_two_primaries_allowed() */
static bool primary_peer_present(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	struct net_conf *nc;
	bool two_primaries, rv = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		nc = rcu_dereference(connection->transport.net_conf);
		two_primaries = nc ? nc->two_primaries : false;

		if (connection->peer_role[NOW] == R_PRIMARY && !two_primaries) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static bool any_disk_is_uptodate(struct bsr_device *device)
{
	bool ret = false;

	rcu_read_lock();
	if (device->disk_state[NOW] == D_UP_TO_DATE)
		ret = true;
	else {
		struct bsr_peer_device *peer_device;

		for_each_peer_device_rcu(peer_device, device) {
			if (peer_device->disk_state[NOW] == D_UP_TO_DATE) {
				ret = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	return ret;
}

static int try_to_promote(struct bsr_device *device)
{
	struct bsr_resource *resource = device->resource;
	long timeout = resource->res_opts.auto_promote_timeout * HZ / 10;
	int rv, retry = timeout / (HZ / 5); /* One try every 200ms */
	do {
		rv = bsr_set_role(resource, R_PRIMARY, false, NULL);
		if (rv >= SS_SUCCESS || timeout == 0) {
#ifdef _WIN		
			resource->bPreSecondaryLock = FALSE;
#endif
			return rv;
		} else if (rv == SS_CW_FAILED_BY_PEER) {
			/* Probably udev has it open read-only on one of the peers */
			long t = schedule_timeout_interruptible(HZ / 5);
			if (t < 0)
				break;
			timeout -= HZ / 5;
		} else if (rv == SS_TWO_PRIMARIES) {
			/* Wait till the peer demoted itself */
			 wait_event_interruptible_timeout_ex(resource->state_wait,
				resource->role[NOW] == R_PRIMARY ||
				(!primary_peer_present(resource) && any_disk_is_uptodate(device)),
				timeout, timeout);

			if (timeout <= 0)
				break;
		} else if (rv == SS_NO_UP_TO_DATE_DISK) {
			/* Wait until we get a connection established */
			wait_event_interruptible_timeout_ex(resource->state_wait,
				 any_disk_is_uptodate(device), timeout, timeout);

			if (timeout <= 0)
				break;	
		} else {
			return rv;
		}
	} while (--retry);
	return rv;
}

static int ro_open_cond(struct bsr_device *device)
{
	struct bsr_resource *resource = device->resource;

	if (resource->role[NOW] != R_PRIMARY && primary_peer_present(resource) && !allow_oos)
		return -EMEDIUMTYPE;
	else if (any_disk_is_uptodate(device))
		return 0;
	else
		return -EAGAIN;
}

#ifdef _WIN
static int bsr_open(struct block_device *bdev, fmode_t mode)
#else // _LIN
int bsr_open(struct block_device *bdev, fmode_t mode)
#endif
{
	struct bsr_device *device = bdev->bd_disk->private_data;
	struct bsr_resource *resource = device->resource;
	unsigned long flags;
	int rv = 0;

	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 9);

	if (resource->res_opts.auto_promote) {
		enum bsr_state_rv rv;
		/* Allow opening in read-only mode on an unconnected secondary.
		   This avoids split brain when the bsr volume gets opened
		   temporarily by udev while it scans for PV signatures. */

		if (mode & FMODE_WRITE) {
			if (resource->role[NOW] == R_SECONDARY) {
				rv = try_to_promote(device);
				if (rv < SS_SUCCESS)
					bsr_info(32, BSR_LC_STATE, resource, "Failed to set automatic state when device is opened with write option. err(%s)",
					bsr_set_st_err_str(rv));
			}
		}
		else /* READ access only */ {
			int res;
			wait_event_interruptible_timeout_ex(resource->state_wait,
				ro_open_cond(device) != -EAGAIN,
				resource->res_opts.auto_promote_timeout * HZ / 10, res);
		}
	// BSR-465 allow mount within getting volume bitmap.
	} else if (resource->role[NOW] != R_PRIMARY && !resource->bTempAllowMount && !(mode & FMODE_WRITE) && !allow_oos) {
		rv = -EMEDIUMTYPE;
		goto out;
	}

	down(&resource->state_sem);
	/* bsr_set_role() should be able to rely on nobody increasing rw_cnt */

	spin_lock_irqsave(&resource->req_lock, flags);
	/* to have a stable role and no race with updating open_cnt */

	if (test_bit(UNREGISTERED, &device->flags))
		rv = -ENODEV;

	if (mode & FMODE_WRITE) {
		if (resource->role[NOW] != R_PRIMARY)
			rv = -EROFS;
	} else /* READ access only */ {
		if (!any_disk_is_uptodate(device) ||
		    (resource->role[NOW] != R_PRIMARY &&
		     primary_peer_present(resource) &&
		     !allow_oos))
			rv = -EMEDIUMTYPE;
	}

	if (!rv) {
		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 3);
		if (mode & FMODE_WRITE)
			device->open_rw_cnt++;
		else
			device->open_ro_cnt++;
	}
	spin_unlock_irqrestore(&resource->req_lock, flags);
	up(&resource->state_sem);

out:
	kref_debug_put(&device->kref_debug, 9);
	kref_put(&device->kref, bsr_destroy_device);

	return rv;
}

static void open_counts(struct bsr_resource *resource, int *rw_count_ptr, int *ro_count_ptr)
{
	struct bsr_device *device;
	int vnr, rw_count = 0, ro_count = 0;

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		rw_count += device->open_rw_cnt;
		ro_count += device->open_ro_cnt;
	}
	*rw_count_ptr = rw_count;
	*ro_count_ptr = ro_count;
}

#ifdef _WIN
static BSR_RELEASE_RETURN bsr_release(struct gendisk *gd, fmode_t mode)
#else // _LIN
BSR_RELEASE_RETURN bsr_release(struct gendisk *gd, fmode_t mode)
#endif
{
	struct bsr_device *device = gd->private_data;
	struct bsr_resource *resource = device->resource;
	unsigned long flags;
	int open_rw_cnt, open_ro_cnt;

	spin_lock_irqsave(&resource->req_lock, flags);
	if (mode & FMODE_WRITE)
		device->open_rw_cnt--;
	else
		device->open_ro_cnt--;

	open_counts(resource, &open_rw_cnt, &open_ro_cnt);
	spin_unlock_irqrestore(&resource->req_lock, flags);

	if (open_ro_cnt == 0)
#ifdef _WIN
		wake_up(&resource->state_wait);
#else // _LIN
		wake_up_all(&resource->state_wait);
#endif

	if (resource->res_opts.auto_promote) {
		enum bsr_state_rv rv;

		if (open_rw_cnt == 0 &&
		    resource->role[NOW] == R_PRIMARY &&
		    !test_bit(EXPLICIT_PRIMARY, &resource->flags)) {
			rv = bsr_set_role(resource, R_SECONDARY, false, NULL);
			if (rv < SS_SUCCESS)
				bsr_warn(83, BSR_LC_DRIVER, resource, "Failed to set secondary in auto-demote. err(%s)",
					  bsr_set_st_err_str(rv));
		}
	}
	kref_debug_put(&device->kref_debug, 3);
	kref_put(&device->kref, bsr_destroy_device);  /* might destroy the resource as well */
#ifndef COMPAT_BSR_RELEASE_RETURNS_VOID
	return 0;
#endif
}

/* need to hold resource->req_lock */
void bsr_queue_unplug(struct bsr_device *device)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(device);
	// not support
#else // _LIN
	struct bsr_resource *resource = device->resource;
	struct bsr_connection *connection;
	u64 dagtag_sector;

	dagtag_sector = resource->dagtag_sector;

	for_each_connection(connection, resource) {
		/* use the "next" slot */
		unsigned int i = !connection->todo.unplug_slot;
		connection->todo.unplug_dagtag_sector[i] = dagtag_sector;
		wake_up(&connection->sender_work.q_wait);
	}
#endif	
}

#ifdef blk_queue_plugged
static void bsr_unplug_fn(struct request_queue *q)
{
	struct bsr_device *device = q->queuedata;
	struct bsr_resource *resource = device->resource;

	/* unplug FIRST */
	/* note: q->queue_lock == resource->req_lock */
	spin_lock_irq(&resource->req_lock);
	blk_remove_plug(q);

	/* only if connected */
	bsr_queue_unplug(device);
	spin_unlock_irq(&resource->req_lock);

	bsr_kick_lo(device);
}
#endif

static void bsr_set_defaults(struct bsr_device *device)
{
	device->disk_state[NOW] = D_DISKLESS;
}

void bsr_cleanup_device(struct bsr_device *device)
{
	device->al_writ_cnt = 0;
	device->bm_writ_cnt = 0;
	device->read_cnt = 0;
	device->writ_cnt = 0;
	// BSR-687 aggregate I/O throughput and latency
	atomic_set(&device->al_updates_cnt, 0);
	atomic_set(&device->io_cnt[READ], 0);
	atomic_set(&device->io_cnt[WRITE], 0);
	atomic_set(&device->io_size[READ], 0);
	atomic_set(&device->io_size[WRITE], 0);
	if (device->bitmap) {
		/* maybe never allocated. */
#ifdef _LIN
		// BSR-875
		atomic_sub64(device->bitmap->bm_number_of_pages, &mem_usage.bm_pp);
#endif
		bsr_bm_resize(device, 0, 1);
		bsr_bm_free(device->bitmap);
		device->bitmap = NULL;
	}

	clear_bit(AL_SUSPENDED, &device->flags);
	bsr_set_defaults(device);
}


static void bsr_destroy_mempools(void)
{
#ifdef _WIN
	bsr_pp_vacant = 0;	
#else // _LIN
	struct page *page;

	while (bsr_pp_pool) {
		page = bsr_pp_pool;
		bsr_pp_pool = page_chain_next(page);
		__free_page(page);
		bsr_pp_vacant--;
		// BSR-875
		atomic_sub64(1, &mem_usage.data_pp);
	}
#endif
	/* D_ASSERT(device, atomic_read(&bsr_pp_vacant)==0); */

	if (bsr_md_io_page_pool)
		mempool_destroy(bsr_md_io_page_pool);

	if (bsr_ee_mempool)
		mempool_destroy(bsr_ee_mempool);

	if (bsr_request_mempool)
		mempool_destroy(bsr_request_mempool);

#ifdef _WIN
	ExDeleteNPagedLookasideList(&bsr_bm_ext_cache);
	ExDeleteNPagedLookasideList(&bsr_al_ext_cache);
#else // _LIN
	bioset_exit(&bsr_io_bio_set);
	bioset_exit(&bsr_md_io_bio_set);

	if (bsr_ee_cache)
		kmem_cache_destroy(bsr_ee_cache);
	if (bsr_request_cache)
		kmem_cache_destroy(bsr_request_cache);
	if (bsr_bm_ext_cache)
		kmem_cache_destroy(bsr_bm_ext_cache);
	if (bsr_al_ext_cache)
		kmem_cache_destroy(bsr_al_ext_cache);

	bsr_md_io_page_pool = NULL;
	bsr_ee_cache = NULL;
	bsr_request_cache = NULL;
	bsr_bm_ext_cache = NULL;
	bsr_al_ext_cache = NULL;
#endif
	bsr_ee_mempool = NULL;
	bsr_request_mempool = NULL;

	return;
}

static int bsr_create_mempools(void)
{
	const int number = (BSR_MAX_BIO_SIZE / PAGE_SIZE) * minor_count;
#ifdef _LIN
	struct page *page;
	int i, ret;
#endif

	bsr_md_io_page_pool = NULL;
	
#ifdef _WIN

	ExInitializeNPagedLookasideList(&bsr_bm_ext_cache, NULL, NULL,
		0, sizeof(struct bm_extent), '28SB', 0);
	ExInitializeNPagedLookasideList(&bsr_al_ext_cache, NULL, NULL,
		0, sizeof(struct lc_element), '38SB', 0);

	bsr_request_mempool = mempool_create_slab_pool(sizeof(struct bsr_request), '48SB');
	if (bsr_request_mempool == NULL)
		goto Enomem;

	bsr_ee_mempool = mempool_create_slab_pool(sizeof(struct bsr_peer_request), '58SB');
	if (bsr_ee_mempool == NULL)
		goto Enomem;

	bsr_md_io_page_pool = mempool_create_page_pool(BSR_MIN_POOL_PAGES, 0);
	if (bsr_md_io_page_pool == NULL)
		goto Enomem;

	/* bsr's page pool */
	spin_lock_init(&bsr_pp_lock);

#else // _LIN
	/* prepare our caches and mempools */
	bsr_request_mempool = NULL;
	bsr_ee_cache        = NULL;
	bsr_request_cache   = NULL;
	bsr_bm_ext_cache    = NULL;
	bsr_al_ext_cache    = NULL;
	bsr_pp_pool         = NULL;
	/* caches */
	bsr_request_cache = kmem_cache_create(
		"bsr_req", sizeof(struct bsr_request), 0, 0, NULL);
	if (bsr_request_cache == NULL)
		goto Enomem;

	bsr_ee_cache = kmem_cache_create(
		"bsr_ee", sizeof(struct bsr_peer_request), 0, 0, NULL);
	if (bsr_ee_cache == NULL)
		goto Enomem;

	bsr_bm_ext_cache = kmem_cache_create(
		"bsr_bm", sizeof(struct bm_extent), 0, 0, NULL);
	if (bsr_bm_ext_cache == NULL)
		goto Enomem;

	bsr_al_ext_cache = kmem_cache_create(
		"bsr_al", sizeof(struct lc_element), 0, 0, NULL);
	if (bsr_al_ext_cache == NULL)
		goto Enomem;
	/* mempools */
	ret = bioset_init(&bsr_io_bio_set, BIO_POOL_SIZE, 0, 0);
	if (ret)
		goto Enomem;

	ret = bioset_init(&bsr_md_io_bio_set, BSR_MIN_POOL_PAGES, 0, BIOSET_NEED_BVECS);
	if (ret)
		goto Enomem;

	bsr_request_mempool = mempool_create_slab_pool(number, bsr_request_cache);
	if (bsr_request_mempool == NULL)
		goto Enomem;

	bsr_ee_mempool = mempool_create_slab_pool(number, bsr_ee_cache);
	if (bsr_ee_mempool == NULL)
		goto Enomem;

	bsr_md_io_page_pool = mempool_create_page_pool(BSR_MIN_POOL_PAGES, 0);
	if (bsr_md_io_page_pool == NULL)
		goto Enomem;

	/* bsr's page pool */
	spin_lock_init(&bsr_pp_lock);

	for (i = 0; i < number; i++) {
		page = alloc_page(GFP_HIGHUSER);
		if (!page)
			goto Enomem;
		set_page_chain_next_offset_size(page, bsr_pp_pool, 0, 0);
		bsr_pp_pool = page;
	}
	
#endif

	bsr_pp_vacant = number;
#ifdef _LIN
	// BSR-875
	atomic_set64(&mem_usage.data_pp, number);
#endif
	return 0;

Enomem:
	bsr_destroy_mempools(); /* in case we allocated some */
	return -ENOMEM;
}

static void free_peer_device(struct bsr_peer_device *peer_device)
{
	lc_destroy(peer_device->resync_lru);
	bsr_kfree(peer_device->rs_plan_s);
	bsr_kfree(peer_device->conf);
	bsr_kfree(peer_device);
}

/* caution. no locking. */
void bsr_destroy_device(struct kref *kref)
{
	struct bsr_device *device = container_of(kref, struct bsr_device, kref);
	struct bsr_resource *resource = device->resource;
	struct bsr_peer_device *peer_device, *tmp;
#ifdef SPLIT_REQUEST_RESYNC
	// DW-1911
	struct bsr_marked_replicate *marked_rl, *t;
	struct bsr_resync_pending_sectors *pending_st, *rpt;
#endif

	bsr_debug(97, BSR_LC_DRIVER, NO_OBJECT,"%s", __FUNCTION__);

#ifdef SPLIT_REQUEST_RESYNC
	// BSR-625
	mutex_lock(&device->resync_pending_fo_mutex);
	list_for_each_entry_safe_ex(struct bsr_resync_pending_sectors, pending_st, rpt, &(device->resync_pending_sectors), pending_sectors) {
		list_del(&pending_st->pending_sectors);
		kfree2(pending_st);
	}
	mutex_unlock(&device->resync_pending_fo_mutex);

	// DW-1911
	list_for_each_entry_safe_ex(struct bsr_marked_replicate, marked_rl, t, &(device->marked_rl_list), marked_rl_list) {
		list_del(&marked_rl->marked_rl_list);
		bsr_kfree(marked_rl);
	}
#endif

	/* cleanup stuff that may have been allocated during
	 * device (re-)configuration or state changes */
#ifdef _WIN
	if (device->this_bdev) {
		// DW-1109 put bdev when device is being destroyed.
		// DW-1300 nullify bsr_device of volume extention when destroy bsr device.
		PVOLUME_EXTENSION pvext = device->this_bdev->bd_disk->pDeviceExtension;
		if (pvext && pvext->dev) {
			unsigned char oldIRQL = ExAcquireSpinLockExclusive(&device->this_bdev->bd_disk->bsr_device_ref_lock);
			pvext->dev->bd_disk->bsr_device = NULL;
			ExReleaseSpinLockExclusive(&device->this_bdev->bd_disk->bsr_device_ref_lock, oldIRQL);
		}

		blkdev_put(device->this_bdev, 0);
		device->this_bdev = NULL;
	}
#endif

	bsr_backing_dev_free(device, device->ldev);
	device->ldev = NULL;


	lc_destroy(device->act_log);
	for_each_peer_device_safe(peer_device, tmp, device) {
		kref_debug_put(&peer_device->connection->kref_debug, 3);
		kref_put(&peer_device->connection->kref, bsr_destroy_connection);
		free_peer_device(peer_device);
	}

	if (device->bitmap) { /* should no longer be there. */
#ifdef _LIN
		// BSR-875
		atomic_sub64(device->bitmap->bm_number_of_pages, &mem_usage.bm_pp);
#endif
		bsr_bm_free(device->bitmap);
		device->bitmap = NULL;
	}
	__free_page(device->md_io.page);
#ifdef COMPAT_HAVE_BLK_ALLOC_DISK
	blk_cleanup_disk(device->vdisk);
#else
	put_disk(device->vdisk);
	blk_cleanup_queue(device->rq_queue);
#endif	

	device->vdisk = NULL;
	device->rq_queue = NULL;

	kref_debug_destroy(&device->kref_debug);

	bsr_kfree(device);

	kref_debug_put(&resource->kref_debug, 4);
	kref_put(&resource->kref, bsr_destroy_resource);
}

void bsr_destroy_resource(struct kref *kref)
{
	struct bsr_resource *resource = container_of(kref, struct bsr_resource, kref);

	bsr_debug(98, BSR_LC_DRIVER, NO_OBJECT, "%s", __FUNCTION__);

	idr_destroy(&resource->devices);
#ifdef _LIN
	free_cpumask_var(resource->cpu_mask);
#endif
	bsr_kfree(resource->name);
	kref_debug_destroy(&resource->kref_debug);
	bsr_kfree(resource);
#ifdef _LIN
	module_put(THIS_MODULE);
#endif
}

void bsr_free_resource(struct bsr_resource *resource)
{
	struct queued_twopc *q, *q1;
	struct bsr_connection *connection, *tmp;

	del_timer_sync(&resource->queued_twopc_timer);

	spin_lock_irq(&resource->queued_twopc_lock);
	list_for_each_entry_safe_ex(struct queued_twopc, q, q1, &resource->queued_twopc, w.list) {
		list_del(&q->w.list);
		kref_put(&q->connection->kref, bsr_destroy_connection);
		bsr_kfree(q);
	}
	spin_unlock_irq(&resource->queued_twopc_lock);

	bsr_thread_stop(&resource->worker);

#ifdef _WIN_MULTIVOL_THREAD
	mvolTerminateThread(&resource->WorkThreadInfo);
#endif

	list_for_each_entry_safe_ex(struct bsr_connection, connection, tmp, &resource->twopc_parents, twopc_parent_list) {
		// DW-1480
		list_del(&connection->twopc_parent_list);
		kref_debug_put(&connection->kref_debug, 9);
		kref_put(&connection->kref, bsr_destroy_connection);
	}

    if (resource->peer_ack_req)
		mempool_free(resource->peer_ack_req, bsr_request_mempool);

	del_timer_sync(&resource->twopc_timer);
	del_timer_sync(&resource->peer_ack_timer);
	del_timer_sync(&resource->repost_up_to_date_timer);
	kref_debug_put(&resource->kref_debug, 8);
	kref_put(&resource->kref, bsr_destroy_resource);
}

/* One global retry thread, if we need to push back some bio and have it
 * reinserted through our make request function.
 */
#ifdef _WIN
// moved to bsr_windows.h
struct retry_worker retry;
#else // _LIN
static struct retry_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;

	spinlock_t lock;
	struct list_head writes;
} retry;
#endif

void bsr_req_destroy_lock(struct kref *kref)
{
	struct bsr_request *req = container_of(kref, struct bsr_request, kref);
	struct bsr_resource *resource = req->device->resource;

	spin_lock_irq(&resource->req_lock);
	bsr_req_destroy(kref);
	spin_unlock_irq(&resource->req_lock);
}

static void do_retry(struct work_struct *ws)
{
	struct retry_worker *retry = container_of(ws, struct retry_worker, worker);
	LIST_HEAD(writes);
	struct bsr_request *req, *tmp;

	spin_lock_irq(&retry->lock);
	list_splice_init(&retry->writes, &writes);
	spin_unlock_irq(&retry->lock);
	list_for_each_entry_safe_ex(struct bsr_request,  req, tmp, &writes, tl_requests) {
		struct bsr_device *device = req->device;
		struct bio *bio = req->master_bio;
		ULONG_PTR start_jif = req->start_jif;
		bool expected;
		ktime_t start_kt;
		if (atomic_read(&g_bsrmon_run))
			ktime_get_accounting_assign(start_kt, req->start_kt);
		else
			start_kt = ns_to_ktime(0);

		expected =
			expect(device, atomic_read(&req->completion_ref) == 0) &&
			expect(device, req->rq_state[0] & RQ_POSTPONED) &&
			expect(device, (req->rq_state[0] & RQ_LOCAL_PENDING) == 0 ||
			       (req->rq_state[0] & RQ_LOCAL_ABORTED) != 0);

		if (!expected)
			bsr_err(3, BSR_LC_REQUEST, device, "req(%p) completion reference(%d) request state(%x)",
				req, atomic_read(&req->completion_ref),
				req->rq_state[0]);

		/* We still need to put one kref associated with the
		 * "completion_ref" going zero in the code path that queued it
		 * here.  The request object may still be referenced by a
		 * frozen local req->private_bio, in case we force-detached.
		 */
		kref_put(&req->kref, bsr_req_destroy_lock);

		/* A single suspended or otherwise blocking device may stall
		 * all others as well.  Fortunately, this code path is to
		 * recover from a situation that "should not happen":
		 * concurrent writes in multi-primary setup.
		 * In a "normal" lifecycle, this workqueue is supposed to be
		 * destroyed without ever doing anything.
		 * If it turns out to be an issue anyways, we can do per
		 * resource (replication group) or per device (minor) retry
		 * workqueues instead.
		 */

		/* We are not just doing generic_make_request(),
		 * as we want to keep the start_time information. */
		inc_ap_bio(device, bio_data_dir(bio));
		__bsr_make_request(device, bio, start_kt, start_jif);
	}
}

/* called via bsr_req_put_completion_ref(),
 * holds resource->req_lock */
void bsr_restart_request(struct bsr_request *req)
{
	unsigned long flags;
	spin_lock_irqsave(&retry.lock, flags);

	bsr_info(4, BSR_LC_REQUEST, NO_OBJECT, "The request was not completed, so we proceeded with the request again. request(%p) request net queue reference (%d)", req, atomic_read(&req->nq_ref));

#ifdef NETQUEUED_LOG
	atomic_set(&req->nq_ref, 0);
	list_del_init(&req->nq_requests);	
#endif
	
	list_move_tail(&req->tl_requests, &retry.writes);
	spin_unlock_irqrestore(&retry.lock, flags);

	/* Drop the extra reference that would otherwise
	 * have been dropped by complete_master_bio.
	 * do_retry() needs to grab a new one. */
	dec_ap_bio(req->device, bio_data_dir(req->master_bio));

	queue_work(retry.wq, &retry.worker);
}

#ifdef _WIN
void bsr_cleanup_by_win_shutdown(PVOLUME_EXTENSION VolumeExtension)
{
    bsr_info(8, BSR_LC_VOLUME, NO_OBJECT,"Proceed with volume shutdown. IRQL(%d) device(%ws) Name(%ws)",
        KeGetCurrentIrql(), VolumeExtension->PhysicalDeviceName, VolumeExtension->MountPoint);

    if (retry.wq)
        destroy_workqueue(retry.wq);
    retry.wq = NULL;

	gbShutdown = TRUE;
}
#endif

#ifdef COMPAT_HAVE_BDI_CONGESTED_FN
/**
 * bsr_congested() - Callback for the flusher thread
 * @congested_data:	User data
 * @bdi_bits:		Bits the BDI flusher thread is currently interested in
 *
 * Returns 1<<WB_async_congested and/or 1<<WB_sync_congested if we are congested.
 */
static int bsr_congested(void *congested_data, int bdi_bits)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(bdi_bits);
	UNREFERENCED_PARAMETER(congested_data);
	// BSR: not support data socket congestion
	// In V8.x, bsr_congested is called at bsr_seq_show, but In V9.x, not called , maybe replace with DEBUGFS
	return 0;
#else // _LIN
	struct bsr_device *device = congested_data;
	struct request_queue *q;
	int r = 0;

	if (!may_inc_ap_bio(device)) {
		/* BSR has frozen IO */
		r = bdi_bits;
		goto out;
	}

	if (test_bit(CALLBACK_PENDING, &device->resource->flags)) {
		r |= (1 << WB_async_congested);
		/* Without good local data, we would need to read from remote,
		 * and that would need the worker thread as well, which is
		 * currently blocked waiting for that usermode helper to
		 * finish.
		 */
		if (!get_ldev_if_state(device, D_UP_TO_DATE))
			r |= (1 << WB_sync_congested);
		else
			put_ldev(device);
		r &= bdi_bits;
		goto out;
	}

	if (get_ldev(device)) {
		q = bdev_get_queue(device->ldev->backing_bdev);
		r = bdi_congested(q->backing_dev_info, bdi_bits);
		put_ldev(device);
	}

	if (bdi_bits & (1 << WB_async_congested)) {
		struct bsr_peer_device *peer_device;

		rcu_read_lock();
		for_each_peer_device_rcu(peer_device, device) {
			if (test_bit(NET_CONGESTED, &peer_device->connection->transport.flags)) {
				r |= (1 << WB_async_congested);
				break;
			}
		}
		rcu_read_unlock();
	}

out:
	return r;
#endif
}
#endif

static void bsr_init_workqueue(struct bsr_work_queue* wq)
{
	spin_lock_init(&wq->q_lock);
	INIT_LIST_HEAD(&wq->q);
	init_waitqueue_head(&wq->q_wait);
}

struct completion_work {
	struct bsr_work w;
	struct completion done;
};

static int w_complete(struct bsr_work *w, int cancel)
{
	struct completion_work *completion_work =
		container_of(w, struct completion_work, w);

	UNREFERENCED_PARAMETER(cancel);
	complete(&completion_work->done);
	return 0;
}

void bsr_queue_work(struct bsr_work_queue *q, struct bsr_work *w)
{
	unsigned long flags;

	spin_lock_irqsave(&q->q_lock, flags);
	list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

// DW-1103 down from kernel with timeout
void bsr_flush_workqueue_timeout(struct bsr_resource* resource, struct bsr_work_queue *work_queue)
{
	struct completion_work completion_work;
	if (get_t_state(&resource->worker) != RUNNING) {
		return;
	}
	completion_work.w.cb = w_complete;
	init_completion(&completion_work.done);
	bsr_queue_work(work_queue, &completion_work.w);
#ifdef _WIN
	while (wait_for_completion_timeout(&completion_work.done, 100) == -BSR_SIGKILL) {
		bsr_info(62, BSR_LC_ETC, NO_OBJECT, "Wait a limited time for the operator queue to flush.");
	}
#else // _LIN
	wait_for_completion_timeout(&completion_work.done, 100);
#endif
}

void bsr_flush_workqueue(struct bsr_resource* resource, struct bsr_work_queue *work_queue)
{
	struct completion_work completion_work;

	if (get_t_state(&resource->worker) != RUNNING) {
		bsr_info(63, BSR_LC_ETC, NO_OBJECT, "The work queue is not flushed because it is not working.. resource(%p)", resource);
		return;
	}

	completion_work.w.cb = w_complete;
	init_completion(&completion_work.done);
	bsr_queue_work(work_queue, &completion_work.w);
#ifdef _WIN
	while (wait_for_completion(&completion_work.done) == -BSR_SIGKILL) {
		bsr_info(64, BSR_LC_ETC, NO_OBJECT, "Wait for worker queue flush to complete.");
	}
#else // _LIN
	wait_for_completion(&completion_work.done);
#endif
}

struct bsr_resource *bsr_find_resource(const char *name)
{
	struct bsr_resource *resource;

	if (!name || !name[0])
		return NULL;

	rcu_read_lock();
	for_each_resource_rcu(resource, &bsr_resources) {
		if (!strcmp(resource->name, name)) {
			kref_get(&resource->kref);
			goto found;
		}
	}
	resource = NULL;
found:
	rcu_read_unlock();
	return resource;
}

static void bsr_put_send_buffers(struct bsr_connection *connection)
{
	unsigned int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		if (connection->send_buffer[i].page) {
#ifdef _WIN
			// DW-1791 fix memory leak 
			__free_page(connection->send_buffer[i].page);
#else // _LIN
			put_page(connection->send_buffer[i].page);
#endif
			connection->send_buffer[i].page = NULL;
		}
	}
}

static int bsr_alloc_send_buffers(struct bsr_connection *connection)
{
	unsigned int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct page *page;

		page = alloc_page(GFP_KERNEL);
		if (!page) {
			bsr_put_send_buffers(connection);
			return -ENOMEM;
		}
		connection->send_buffer[i].page = page;
		connection->send_buffer[i].unsent =
		connection->send_buffer[i].pos = page_address(page);
	}

	return 0;
}

void bsr_flush_peer_acks(struct bsr_resource *resource)
{
	spin_lock_irq(&resource->req_lock);
	if (resource->peer_ack_req) {
		resource->last_peer_acked_dagtag = resource->peer_ack_req->dagtag_sector;
		bsr_queue_peer_ack(resource, resource->peer_ack_req);
		resource->peer_ack_req = NULL;
	}
	spin_unlock_irq(&resource->req_lock);
}
#ifdef _WIN
static void peer_ack_timer_fn(PKDPC Dpc, PVOID data, PVOID arg1, PVOID arg2)
#else // _LIN
static void peer_ack_timer_fn(BSR_TIMER_FN_ARG)
#endif
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(arg1);
	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(Dpc);

	struct bsr_resource *resource = (struct bsr_resource *) data;
#else // _LIN

	struct bsr_resource *resource = BSR_TIMER_ARG2OBJ(resource, peer_ack_timer);
#endif

	bsr_flush_peer_acks(resource);
}

void conn_free_crypto(struct bsr_connection *connection)
{
	crypto_free_shash(connection->csums_tfm);
	crypto_free_shash(connection->verify_tfm);
	crypto_free_shash(connection->cram_hmac_tfm);
	crypto_free_shash(connection->integrity_tfm);
	crypto_free_shash(connection->peer_integrity_tfm);
	bsr_kfree(connection->int_dig_in);
	bsr_kfree(connection->int_dig_vv);

	connection->csums_tfm = NULL;
	connection->verify_tfm = NULL;
	connection->cram_hmac_tfm = NULL;
	connection->integrity_tfm = NULL;
	connection->peer_integrity_tfm = NULL;
	connection->int_dig_in = NULL;
	connection->int_dig_vv = NULL;
}

void wake_all_device_misc(struct bsr_resource *resource)
{
	struct bsr_device *device;
	int vnr;
	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr)
		wake_up(&device->misc_wait);
	rcu_read_unlock();
}

int set_resource_options(struct bsr_resource *resource, struct res_opts *res_opts)
{
#ifdef _WIN
    resource->res_opts = *res_opts;
	return 0;
#else // _LIN
	struct bsr_connection *connection;
	cpumask_var_t new_cpu_mask;
	int err;
	bool wake_device_misc = false;

	if (!zalloc_cpumask_var(&new_cpu_mask, GFP_KERNEL))
		return -ENOMEM;

	/* silently ignore cpu mask on UP kernel */
	if (nr_cpu_ids > 1 && res_opts->cpu_mask[0] != 0) {
		err = bitmap_parse(res_opts->cpu_mask, BSR_CPU_MASK_SIZE,
				   cpumask_bits(new_cpu_mask), nr_cpu_ids);
		if (err == -EOVERFLOW) {
			/* So what. mask it out. */
			cpumask_var_t tmp_cpu_mask;
			if (zalloc_cpumask_var(&tmp_cpu_mask, GFP_KERNEL)) {
				cpumask_setall(tmp_cpu_mask);
				cpumask_and(new_cpu_mask, new_cpu_mask, tmp_cpu_mask);
				bsr_warn(75, BSR_LC_ETC, resource, "Overflow in bitmap_parse(%.12s%s), truncating to %u bits",
					res_opts->cpu_mask,
					strlen(res_opts->cpu_mask) > 12 ? "..." : "",
					nr_cpu_ids);
				free_cpumask_var(tmp_cpu_mask);
				err = 0;
			}
		}
		if (err) {
			bsr_err(76, BSR_LC_ETC, resource, "Failed to bitmap parse. err(%d)", err);
			/* retcode = ERR_CPU_MASK_PARSE; */
			goto fail;
		}
	}
	if (res_opts->nr_requests < BSR_NR_REQUESTS_MIN)
		res_opts->nr_requests = BSR_NR_REQUESTS_MIN;
	if (resource->res_opts.nr_requests < res_opts->nr_requests)
		wake_device_misc = true;
	
	resource->res_opts = *res_opts;
	if (cpumask_empty(new_cpu_mask))
		bsr_calc_cpu_mask(&new_cpu_mask);
	if (!cpumask_equal(resource->cpu_mask, new_cpu_mask)) {
		cpumask_copy(resource->cpu_mask, new_cpu_mask);
		rcu_read_lock();
		for_each_connection_rcu(connection, resource) {
			connection->receiver.reset_cpu_mask = 1;
			connection->ack_receiver.reset_cpu_mask = 1;
			connection->sender.reset_cpu_mask = 1;
		}
		rcu_read_unlock();
	}
	err = 0;
	if (wake_device_misc)
		wake_all_device_misc(resource);
	
fail:
	free_cpumask_var(new_cpu_mask);
	return err;
#endif
}

struct bsr_resource *bsr_create_resource(const char *name,
					   struct res_opts *res_opts)
{
	struct bsr_resource *resource;

	resource = bsr_kzalloc(sizeof(struct bsr_resource), GFP_KERNEL, 'A0SB');
#ifdef _WIN
	resource->bPreSecondaryLock = FALSE;
	resource->bPreDismountLock = FALSE;
#endif
	if (!resource)
		goto fail;
	resource->name = kstrdup(name, GFP_KERNEL);
	if (!resource->name)
		goto fail_free_resource;
#ifdef _LIN
	if (!zalloc_cpumask_var(&resource->cpu_mask, GFP_KERNEL))
		goto fail_free_name;
#endif
	kref_init(&resource->kref);
	kref_debug_init(&resource->kref_debug, &resource->kref, &kref_class_resource);
	idr_init(&resource->devices);
	INIT_LIST_HEAD(&resource->connections);
	INIT_LIST_HEAD(&resource->transfer_log);

#ifdef NETQUEUED_LOG
	INIT_LIST_HEAD(&resource->net_queued_log);
#endif	
	
	INIT_LIST_HEAD(&resource->peer_ack_list);
	bsr_timer_setup(resource, peer_ack_timer, peer_ack_timer_fn);
	bsr_timer_setup(resource, repost_up_to_date_timer, repost_up_to_date_fn);
	sema_init(&resource->state_sem, 1);
	resource->role[NOW] = R_SECONDARY;
	if (set_resource_options(resource, res_opts))
		goto fail_free_name;
	resource->max_node_id = res_opts->node_id;
	resource->twopc_reply.initiator_node_id = -1;
	mutex_init(&resource->conf_update);
	mutex_init(&resource->adm_mutex);
	// DW-1317
	mutex_init(&resource->vol_ctl_mutex);

	spin_lock_init(&resource->req_lock);
	INIT_LIST_HEAD(&resource->listeners);
	spin_lock_init(&resource->listeners_lock);
	init_waitqueue_head(&resource->state_wait);
	// BSR-937
	init_waitqueue_head(&resource->state_work_wait);
	init_waitqueue_head(&resource->twopc_wait);
	init_waitqueue_head(&resource->barrier_wait);

	// BSR-988
	init_waitqueue_head(&resource->resync_reply_wait);

	INIT_LIST_HEAD(&resource->twopc_parents);
	bsr_timer_setup(resource, twopc_timer, twopc_timer_fn);
	INIT_LIST_HEAD(&resource->twopc_work.list);
	INIT_LIST_HEAD(&resource->queued_twopc);
	spin_lock_init(&resource->queued_twopc_lock);
	bsr_timer_setup(resource, queued_twopc_timer, queued_twopc_timer_fn);
	bsr_init_workqueue(&resource->work);
	bsr_thread_init(resource, &resource->worker, bsr_worker, "worker");
	bsr_thread_start(&resource->worker);
	bsr_debugfs_resource_add(resource);

	list_add_tail_rcu(&resource->resources, &bsr_resources);

	// DW-1925
	atomic_set(&resource->req_write_cnt, 0);

	return resource;

fail_free_name:
	bsr_kfree(resource->name);
fail_free_resource:
	bsr_kfree(resource);
fail:
	return NULL;
}

/* caller must be under adm_mutex */
struct bsr_connection *bsr_create_connection(struct bsr_resource *resource,
					       struct bsr_transport_class *tc)
{
	struct bsr_connection *connection;
	int size;

	size = sizeof(*connection) - sizeof(connection->transport) + tc->instance_size;
	connection = bsr_kzalloc(size, GFP_KERNEL, 'D0SB');
	if (!connection)
		return NULL;

	if (bsr_alloc_send_buffers(connection))
		goto fail;

	connection->current_epoch = bsr_kzalloc(sizeof(struct bsr_epoch), GFP_KERNEL, 'E0SB');
	if (!connection->current_epoch)
		goto fail;

	INIT_LIST_HEAD(&connection->current_epoch->list);
	connection->epochs = 1;
	spin_lock_init(&connection->epoch_lock);

	INIT_LIST_HEAD(&connection->todo.work_list);
	connection->todo.req = NULL;

	// BSR-839
	set_ap_in_flight(connection, 0);
	set_rs_in_flight(connection, 0);

	connection->send.seen_any_write_yet = false;
	connection->send.current_epoch_nr = 0;
	connection->send.current_epoch_writes = 0;
	connection->send.current_dagtag_sector = 0;

	connection->cstate[NOW] = C_STANDALONE;
	connection->peer_role[NOW] = R_UNKNOWN;
	init_waitqueue_head(&connection->ping_wait);
	// BSR-863
	init_waitqueue_head(&connection->uuid_wait);
	idr_init(&connection->peer_devices);

	bsr_init_workqueue(&connection->sender_work);
	mutex_init(&connection->mutex[DATA_STREAM]);
	mutex_init(&connection->mutex[CONTROL_STREAM]);

	connection->ptxbab[DATA_STREAM] = NULL;
	connection->ptxbab[CONTROL_STREAM] = NULL;

	INIT_LIST_HEAD(&connection->connect_timer_work.list);
	bsr_timer_setup(connection, connect_timer, connect_timer_fn);
	
	bsr_thread_init(resource, &connection->receiver, bsr_receiver, "receiver");
	connection->receiver.connection = connection;
	bsr_thread_init(resource, &connection->sender, bsr_sender, "sender");
	connection->sender.connection = connection;
	bsr_thread_init(resource, &connection->ack_receiver, bsr_ack_receiver, "ack_recv");
	connection->ack_receiver.connection = connection;
	INIT_LIST_HEAD(&connection->peer_requests);
	INIT_LIST_HEAD(&connection->connections);
	INIT_LIST_HEAD(&connection->active_ee);
	INIT_LIST_HEAD(&connection->sync_ee);
	INIT_LIST_HEAD(&connection->read_ee);
	INIT_LIST_HEAD(&connection->net_ee);
	INIT_LIST_HEAD(&connection->done_ee);
	// BSR-930
#ifdef _WIN
	INIT_LIST_HEAD(&connection->inactive_ee);	// DW-1696
	atomic_set(&connection->inacitve_ee_cnt, 0); // BSR-438
#endif
	INIT_LIST_HEAD(&connection->unacked_peer_requests); // BSR-1036
	init_waitqueue_head(&connection->ee_wait);

	kref_init(&connection->kref);
	kref_debug_init(&connection->kref_debug, &connection->kref, &kref_class_connection);

	INIT_WORK(&connection->peer_ack_work, bsr_send_peer_ack_wf);
	INIT_WORK(&connection->send_acks_work, bsr_send_acks_wf);

	kref_get(&resource->kref);
	kref_debug_get(&resource->kref_debug, 3);
	connection->resource = resource;

	INIT_LIST_HEAD(&connection->transport.paths);
	connection->transport.log_prefix = resource->name;
	atomic_set64(&connection->transport.sum_sent, 0);
	atomic_set64(&connection->transport.sum_recv, 0);
	connection->transport.sum_start_time = jiffies;
	if (tc->init(&connection->transport))
		goto fail;

	return connection;

fail:
	bsr_put_send_buffers(connection);
	bsr_kfree(connection->current_epoch);
	bsr_kfree(connection);

	return NULL;
}

/* free the transport specific members (e.g., sockets) of a connection */
void bsr_transport_shutdown(struct bsr_connection *connection, enum bsr_tr_free_op op)
{
#ifdef _SEND_BUF
	// DW-689
	// redefine struct bsr_tcp_transport, buffer. required to refactoring about base, pos field 
	struct buffer {
		void *base;
		void *pos;
	};

	struct bsr_tcp_transport {
		struct bsr_transport transport; /* Must be first! */
		spinlock_t paths_lock;
		ULONG_PTR flags;
		struct socket *stream[2];
		struct buffer rbuf[2];
#ifdef _LIN_SEND_BUF
		struct _buffering_attr buffering_attr[2];
#endif
	};

	// set socket quit signal first
	struct bsr_tcp_transport *tcp_transport =
		container_of(&connection->transport, struct bsr_tcp_transport, transport);
	if (tcp_transport) {
#ifdef _WIN_SEND_BUF
		if (tcp_transport->stream[DATA_STREAM])
			tcp_transport->stream[DATA_STREAM]->buffering_attr.quit = TRUE;

		if (tcp_transport->stream[CONTROL_STREAM])
			tcp_transport->stream[CONTROL_STREAM]->buffering_attr.quit = TRUE;
#else // _LIN_SEND_BUF
		if (tcp_transport)
			tcp_transport->buffering_attr[DATA_STREAM].quit = true;

		if (tcp_transport)
			tcp_transport->buffering_attr[CONTROL_STREAM].quit = true;
#endif
	}
	// this logic must be done before mutex lock(next line) is acuquired
#endif

	mutex_lock(&connection->mutex[DATA_STREAM]);
	mutex_lock(&connection->mutex[CONTROL_STREAM]);

#ifdef	_WIN_SEND_BUF
	// bab is freed at ops->free (sock_release). and so, send-buffering threads must be terminated prior to ops->free.  
	// CONNECTION_RESET is occured at this point by stop_send_buffring 
	// connection->transport.ops->stop_send_buffring(&connection->transport);
#endif
	connection->transport.ops->free(&connection->transport, op);
#ifdef _LIN
	if (op == DESTROY_TRANSPORT)
		bsr_put_transport_class(connection->transport.class);
#endif
	mutex_unlock(&connection->mutex[CONTROL_STREAM]);
	mutex_unlock(&connection->mutex[DATA_STREAM]);
}

void bsr_destroy_path(struct kref *kref)
{
	struct bsr_path *path = container_of(kref, struct bsr_path, kref);

	bsr_kfree(path);
}

void bsr_destroy_connection(struct kref *kref)
{
	struct bsr_connection *connection = container_of(kref, struct bsr_connection, kref);
	struct bsr_resource *resource = connection->resource;
	struct bsr_peer_device *peer_device;
	struct bsr_peer_request *peer_request;
	unsigned long flags = 0;
	int vnr;

	bsr_info(1, BSR_LC_CONNECTION, connection, "The connection object is removed.");

	if (atomic_read(&connection->current_epoch->epoch_size) !=  0)
		bsr_err(4, BSR_LC_REPLICATION, connection, "epoch size is not zero. It is highly likely that replication has not been completed.. size(%d)", atomic_read(&connection->current_epoch->epoch_size));
	bsr_kfree(connection->current_epoch);

	// BSR-930	
#ifdef _WIN
	// BSR-438 if the inactive_ee is not removed, a memory leak may occur, but BSOD may occur when removing it, so do not remove it. (priority of BSOD is higher than memory leak.)
	//	inacitve_ee processing logic not completed is required (cancellation, etc.)
	if (atomic_read(&connection->inacitve_ee_cnt)) {
		bsr_warn(2, BSR_LC_PEER_REQUEST, connection, "Inactive peer request remains uncompleted. count(%d)", atomic_read(&connection->inacitve_ee_cnt));
		spin_lock_irqsave(&g_inactive_lock, flags);
		list_for_each_entry_ex(struct bsr_peer_request, peer_request, &connection->inactive_ee, w.list) {
			set_bit(__EE_WAS_LOST_REQ, &peer_request->flags);
			// BSR-930	
			if (!(peer_request->flags & EE_SPLIT_REQ))
				put_ldev(peer_request->peer_device->device);
		}
		spin_unlock_irqrestore(&g_inactive_lock, flags);
	}
#endif
	// BSR-1036
	spin_lock(&g_unacked_lock);
	list_for_each_entry_ex(struct bsr_peer_request, peer_request, &connection->unacked_peer_requests, recv_order) {
		set_bit(__EE_WAS_LOST_REQ, &peer_request->flags);
	}
	spin_unlock(&g_unacked_lock);

    idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		kref_debug_put(&peer_device->device->kref_debug, 1);

		// DW-1598 set CONNECTION_ALREADY_FREED flags 
		set_bit(CONNECTION_ALREADY_FREED, &peer_device->flags); 

		kref_put(&peer_device->device->kref, bsr_destroy_device);
		free_peer_device(peer_device);

		// DW-1791 fix memory leak
		// BSR-434 remove unnecessary lock
		idr_remove(&connection->peer_devices, vnr);
	}

	idr_destroy(&connection->peer_devices);

	bsr_kfree(connection->transport.net_conf);
	bsr_put_send_buffers(connection);
	conn_free_crypto(connection);
	kref_debug_destroy(&connection->kref_debug);
	//
	// destroy_bab
	//
#ifdef _SEND_BUF
	destroy_bab(connection);
#endif

	bsr_kfree(connection);
	kref_debug_put(&resource->kref_debug, 3);
	kref_put(&resource->kref, bsr_destroy_resource);
}

struct bsr_peer_device *create_peer_device(struct bsr_device *device, struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int err;
	peer_device = bsr_kzalloc(sizeof(struct bsr_peer_device), GFP_KERNEL, 'F0SB');
	if (!peer_device)
		return NULL;

	peer_device->connection = connection;
	peer_device->device = device;
	peer_device->disk_state[NOW] = D_UNKNOWN;
	peer_device->repl_state[NOW] = L_OFF;
	peer_device->bm_ctx.count = 0;
	spin_lock_init(&peer_device->peer_seq_lock);

	// DW-1806
	init_waitqueue_head(&peer_device->state_initial_send_wait);

	err = bsr_create_peer_device_default_config(peer_device);
	if (err) {
		bsr_kfree(peer_device);
		return NULL;
	}

	bsr_timer_setup(peer_device, start_resync_timer,
			 start_resync_timer_fn);

	INIT_LIST_HEAD(&peer_device->resync_work.list);
	peer_device->resync_work.cb  = w_resync_timer;
	bsr_timer_setup(peer_device, resync_timer, resync_timer_fn);

#ifdef _WIN
#ifdef DBG
    memset(peer_device->start_resync_timer.name, 0, Q_NAME_SZ);
	strncpy(peer_device->start_resync_timer.name, "start_resync_timer", sizeof(peer_device->start_resync_timer.name) - 1);
    memset(peer_device->resync_timer.name, 0, Q_NAME_SZ);
	strncpy(peer_device->resync_timer.name, "resync_timer", sizeof(peer_device->resync_timer.name) - 1);
#endif
#endif

	INIT_LIST_HEAD(&peer_device->propagate_uuids_work.list);
	peer_device->propagate_uuids_work.cb = w_send_uuids;

	// DW-1191 to send disappeared out-of-sync which found when req_destroy.
	INIT_LIST_HEAD(&peer_device->send_oos_list);
	INIT_WORK(&peer_device->send_oos_work, bsr_send_out_of_sync_wf);
	spin_lock_init(&peer_device->send_oos_lock);
	
	// DW-2058
	atomic_set(&peer_device->rq_pending_oos_cnt, 0);

	atomic_set(&peer_device->ap_pending_cnt, 0);
	atomic_set(&peer_device->unacked_cnt, 0);
	atomic_set(&peer_device->rs_pending_cnt, 0);
	atomic_set(&peer_device->wait_for_actlog, 0);
	atomic_set(&peer_device->rs_sect_in, 0);
	atomic_set(&peer_device->wait_for_recv_bitmap, 1);
	atomic_set(&peer_device->wait_for_bitmp_exchange_complete, 0);
	atomic_set(&peer_device->wait_for_out_of_sync, 0);

	// BSR-764
	spin_lock_init(&peer_device->timing_lock);

	// BSR-676
	atomic_set(&peer_device->notify_flags, 0);

	atomic_set64(&peer_device->s_resync_bb, 0);
	atomic_set64(&peer_device->e_resync_bb, 0);

	peer_device->bitmap_index = -1;
	peer_device->resync_wenr = LC_FREE;
	peer_device->resync_finished_pdsk = D_UNKNOWN;

	// BSR-838
	atomic_set64(&peer_device->cur_repl_sended, 0);
	atomic_set64(&peer_device->cur_resync_sended, 0);
	atomic_set64(&peer_device->last_repl_sended, 0);
	atomic_set64(&peer_device->last_resync_sended, 0);

	atomic_set64(&peer_device->repl_sended, 0);
	atomic_set64(&peer_device->resync_sended, 0);

	atomic_set64(&peer_device->cur_resync_received, 0);
	atomic_set64(&peer_device->last_resync_received, 0);

	bsr_timer_setup(peer_device, sended_timer, sended_timer_fn);
	peer_device->rs_in_flight_mark_time = 0;


	// BSR-997
	atomic_set64(&peer_device->ov_req_sector, 0);
	atomic_set64(&peer_device->ov_reply_sector, 0);
	INIT_LIST_HEAD(&peer_device->ov_skip_sectors_list);
	spin_lock_init(&peer_device->ov_lock);

	return peer_device;
}

static int init_submitter(struct bsr_device *device)
{
	/* opencoded create_singlethread_workqueue(),
	 * to be able to use format string arguments */

#ifdef _WIN
	device->submit.wq =
		create_singlethread_workqueue("bsr_submit");
#else // _LIN
	device->submit.wq =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
		alloc_ordered_workqueue("bsr%u_submit", WQ_MEM_RECLAIM, device->minor);
#else
		create_singlethread_workqueue("bsr_submit");
#endif
#endif	
	
	if (!device->submit.wq)
		return -ENOMEM;
	INIT_WORK(&device->submit.worker, do_submit);
	INIT_LIST_HEAD(&device->submit.writes);
	INIT_LIST_HEAD(&device->submit.peer_writes);
	return 0;
}


enum bsr_ret_code bsr_create_device(struct bsr_config_context *adm_ctx, unsigned int minor,
				      struct device_conf *device_conf, struct bsr_device **p_device)
{
	struct bsr_resource *resource = adm_ctx->resource;
	struct bsr_connection *connection;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device, *tmp_peer_device;
	struct gendisk *disk;
    struct request_queue *q = NULL;

	LIST_HEAD(peer_devices);
	LIST_HEAD(tmp);
	int id;
	int vnr = adm_ctx->volume;
	enum bsr_ret_code err = ERR_NOMEM;
	bool locked = false;
#ifdef _WIN
    if ((minor < 1) || (minor > MINORMASK))
        return ERR_INVALID_REQUEST;
#endif
	device = minor_to_device(minor);
	if (device)
		return ERR_MINOR_OR_VOLUME_EXISTS;

	/* GFP_KERNEL, we are outside of all write-out paths */

	device = bsr_kzalloc(sizeof(struct bsr_device), GFP_KERNEL, '01SB');
	if (!device)
		return ERR_NOMEM;
	kref_init(&device->kref);
	kref_debug_init(&device->kref_debug, &device->kref, &kref_class_device);

	kref_get(&resource->kref);
	kref_debug_get(&resource->kref_debug, 4);
	device->resource = resource;
	device->minor = minor;
	device->vnr = vnr;
	device->device_conf = *device_conf;

#ifdef PARANOIA
	SET_MDEV_MAGIC(device);
#endif

	bsr_set_defaults(device);

	atomic_set(&device->ap_bio_cnt[READ], 0);
	atomic_set(&device->ap_bio_cnt[WRITE], 0);
	atomic_set(&device->ap_actlog_cnt, 0);
	atomic_set(&device->local_cnt, 0);
	atomic_set(&device->rs_sect_ev, 0);
	atomic_set(&device->md_io.in_use, 0);

	spin_lock_init(&device->timing_lock);

	spin_lock_init(&device->al_lock);
	mutex_init(&device->bm_resync_and_resync_timer_fo_mutex);
#ifdef SPLIT_REQUEST_RESYNC
	mutex_init(&device->resync_pending_fo_mutex);
	// DW-1901
	INIT_LIST_HEAD(&device->marked_rl_list);
	//DW-2042
	INIT_LIST_HEAD(&device->resync_pending_sectors);
	
	device->s_rl_bb = UINTPTR_MAX;
	device->e_rl_bb = 0;
#endif
	INIT_LIST_HEAD(&device->pending_master_completion[0]);
	INIT_LIST_HEAD(&device->pending_master_completion[1]);
	INIT_LIST_HEAD(&device->pending_completion[0]);
	INIT_LIST_HEAD(&device->pending_completion[1]);

	
	atomic_set(&device->pending_bitmap_work.n, 0);
	spin_lock_init(&device->pending_bitmap_work.q_lock);
	INIT_LIST_HEAD(&device->pending_bitmap_work.q);

	bsr_timer_setup(device, md_sync_timer, md_sync_timer_fn);
	bsr_timer_setup(device, request_timer, request_timer_fn);

#ifdef _WIN
#ifdef DBG
    memset(device->md_sync_timer.name, 0, Q_NAME_SZ);
	strncpy(device->md_sync_timer.name, "md_sync_timer", sizeof(device->md_sync_timer.name) - 1);
    memset(device->request_timer.name, 0, Q_NAME_SZ);
	strncpy(device->request_timer.name, "request_timer", sizeof(device->request_timer.name) - 1);
#endif
#endif
	init_waitqueue_head(&device->misc_wait);
	init_waitqueue_head(&device->al_wait);
	init_waitqueue_head(&device->seq_wait);
#ifdef _WIN
	// DW-1698 Only when bsr_device is created, it requests to update information about target device To fixup the frequency of calls to update_targetdev
    PVOLUME_EXTENSION pvext = get_targetdev_by_minor(minor, TRUE);
	if (!pvext) {
		err = ERR_NO_DISK;
		bsr_err(9, BSR_LC_VOLUME, device, "Failed to device create due to device has no disk. error(%d), minor(%d)", err, minor);
		goto out_no_disk;
	}
	// BSR-617 set volume size
	unsigned long long d_size = get_targetdev_volsize(pvext);
	
	if (pvext->dev->bd_contains && (pvext->dev->bd_contains->d_size != d_size) ) {	
		pvext->dev->bd_contains->d_size = d_size;
		pvext->dev->bd_disk->queue->max_hw_sectors = d_size ? (d_size >> 9) : BSR_MAX_BIO_SIZE;
	}
#endif
	// DW-1109 don't get request queue and gendisk from volume extension, allocate new one. it will be destroyed in bsr_destroy_device.
#ifdef COMPAT_HAVE_BLK_ALLOC_DISK
	disk = blk_alloc_disk(NUMA_NO_NODE);
#else
	q = bsr_blk_alloc_queue();
	if (!q)
		goto out_no_q;
	device->rq_queue = q;
#if defined(COMPAT_HAVE_BLK_QUEUE_MERGE_BVEC) || defined(blk_queue_plugged) || defined(_WIN)
	q->queuedata   = device;
#endif
	disk = alloc_disk(1);	
#endif
	if (!disk)
		goto out_no_disk;

	device->vdisk = disk;

	set_disk_ro(disk, true);
#ifdef _LIN
	disk->major = BSR_MAJOR;
	disk->first_minor = minor;
	disk->fops = &bsr_ops;
#endif

#ifdef COMPAT_HAVE_BLK_ALLOC_DISK
	device->rq_queue = disk->queue;
	disk->minors = 1;
#else
	disk->queue = q;
#endif

#ifdef _WIN
	_snprintf(disk->disk_name, sizeof(disk->disk_name) - 1, "bsr%u", minor);
#else // _LIN
	// BSR-386 rename "bsr" to "bsr" to be the same as name of major device due to pvcreate error
	sprintf(disk->disk_name, "bsr%d", minor);
#endif
	disk->private_data = device;

#ifdef _WIN
	kref_get(&pvext->dev->kref);
	device->this_bdev = pvext->dev;
	q->logical_block_size = 512;
	// DW-1406 max_hw_sectors must be valued as number of maximum sectors.
	// DW-1510 recalculate this_bdev->d_size
	q->max_hw_sectors = ( device->this_bdev->d_size = get_targetdev_volsize(pvext) ) >> 9;
	bsr_info(10, BSR_LC_VOLUME, NO_OBJECT,"The capacity of the create device(%p) is max sectors(%llu), size(%llu bytes)", device, q->max_hw_sectors, device->this_bdev->d_size);
#endif
#ifdef COMPAT_HAVE_BDI_CONGESTED_FN
	init_bdev_info(q->backing_dev_info, bsr_congested, device);
#endif

#ifdef COMPAT_HAVE_BLK_QUEUE_MAKE_REQUEST
	blk_queue_make_request(disk->queue, bsr_make_request);
#endif
    blk_queue_write_cache(disk->queue, true, true);

#ifdef _LIN
#ifdef COMPAT_HAVE_BLK_QUEUE_MERGE_BVEC
	blk_queue_merge_bvec(disk->queue, bsr_merge_bvec);
#endif
#endif
#ifdef blk_queue_plugged
	q->queue_lock = &resource->req_lock; /* needed since we use */
	/* plugging on a queue, that actually has no requests! */
	q->unplug_fn = bsr_unplug_fn;
#endif

	device->md_io.page = alloc_page(GFP_KERNEL);
	if (!device->md_io.page)
		goto out_no_io_page;

	device->bitmap = bsr_bm_alloc();
	if (!device->bitmap)
		goto out_no_bitmap;
	device->read_requests = RB_ROOT;
	device->write_requests = RB_ROOT;

	BUG_ON(!mutex_is_locked(&resource->conf_update));
	for_each_connection(connection, resource) {
		peer_device = create_peer_device(device, connection);
		if (!peer_device)
			goto out_no_peer_device;
		list_add(&peer_device->peer_devices, &peer_devices);
	}

	/* Insert the new device into all idrs under req_lock
	   to guarantee a consistent object model. idr_preload() doesn't help
	   because it can only guarantee that a single idr_alloc() will
	   succeed. This fails (and will be retried) if no memory is
	   immediately available.
	   Keep in mid that RCU readers might find the device in the moment
	   we add it to the resources->devices IDR!
	*/

	INIT_LIST_HEAD(&device->peer_devices);
	INIT_LIST_HEAD(&device->pending_bitmap_io);

	atomic_set(&device->io_error_count, 0);
	atomic_set(&device->notify_flags, 0);

	locked = true;
	spin_lock_irq(&resource->req_lock);
	id = idr_alloc(&bsr_devices, device, minor, minor + 1, GFP_NOWAIT);
	if (id < 0) {
		if (id == -ENOSPC)
			err = ERR_MINOR_OR_VOLUME_EXISTS;
		goto out_no_minor_idr;
	}
	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 1);

	id = idr_alloc(&resource->devices, device, vnr, vnr + 1, GFP_NOWAIT);
	if (id < 0) {
		if (id == -ENOSPC)
			err = ERR_MINOR_OR_VOLUME_EXISTS;
		goto out_idr_remove_minor;
	}
	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 1);

	list_for_each_entry_safe_ex(struct bsr_peer_device, peer_device, tmp_peer_device, &peer_devices, peer_devices) {
		connection = peer_device->connection;
		id = idr_alloc(&connection->peer_devices, peer_device,
			       device->vnr, device->vnr + 1, GFP_NOWAIT);
		if (id < 0)
			goto out_remove_peer_device;
		list_del(&peer_device->peer_devices);
		list_add_rcu(&peer_device->peer_devices, &device->peer_devices);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 3);
		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 1);
	}
	spin_unlock_irq(&resource->req_lock);
	locked = false;

	if (init_submitter(device)) {
		err = ERR_NOMEM;
		goto out_remove_peer_device;
	}
#ifdef _LIN
	add_disk(disk);
#endif
	for_each_peer_device(peer_device, device) {
		connection = peer_device->connection;
		peer_device->node_id = connection->peer_node_id;

		if (connection->cstate[NOW] >= C_CONNECTED) {
			// BSR-987
			if (0 != bsr_connected(peer_device))
				change_cstate_ex(peer_device->connection, C_NETWORK_FAILURE, CS_HARD);
		}
	}
	
	// BSR-904
#ifdef _LIN
	atomic_set(&device->mounted_cnt, 0);
#endif 

	bsr_debugfs_device_add(device);
	*p_device = device;
	return ERR_NO;

out_remove_peer_device:
    {
#ifdef _WIN
		synchronize_rcu_w32_wlock();
#endif
		list_add_rcu(&tmp, &device->peer_devices);
		list_del_init(&device->peer_devices);
		synchronize_rcu();
		list_for_each_entry_safe_ex(struct bsr_peer_device, peer_device, tmp_peer_device, &tmp, peer_devices) {
			struct bsr_connection *connection = peer_device->connection;

			kref_debug_put(&connection->kref_debug, 3);
			kref_put(&connection->kref, bsr_destroy_connection);
			idr_remove(&connection->peer_devices, device->vnr);
			list_del(&peer_device->peer_devices);
			bsr_kfree(peer_device);
		}
    }
out_idr_remove_minor:
	idr_remove(&bsr_devices, minor);

out_no_minor_idr:
	if (locked)
		spin_unlock_irq(&resource->req_lock);
#ifdef _LIN
	synchronize_rcu();
#endif

out_no_peer_device:
	list_for_each_entry_safe_ex(struct bsr_peer_device, peer_device, tmp_peer_device, &peer_devices, peer_devices) {
		list_del(&peer_device->peer_devices);
		bsr_kfree(peer_device);
	}
#ifdef _LIN
	atomic_sub64(device->bitmap->bm_number_of_pages, &mem_usage.bm_pp);
#endif
	bsr_bm_free(device->bitmap);
out_no_bitmap:
	__free_page(device->md_io.page);
out_no_io_page:
#ifdef _LIN 
#ifdef COMPAT_HAVE_BLK_ALLOC_DISK
	blk_cleanup_disk(disk);
#else
	put_disk(disk);
#endif
#endif
out_no_disk:
#ifndef COMPAT_HAVE_BLK_ALLOC_DISK
	blk_cleanup_queue(q);
#endif
out_no_q:
	kref_put(&resource->kref, bsr_destroy_resource);
	bsr_kfree(device);
	return err;
}

/**
 * bsr_unregister_device()  -  make a device "invisible"
 *
 * Remove the device from the bsr object model and unregister it in the
 * kernel.  Keep reference counts on device->kref; they are dropped in
 * bsr_put_device().
 */
void bsr_unregister_device(struct bsr_device *device)
{
	struct bsr_resource *resource = device->resource;
	struct bsr_connection *connection;
	struct bsr_peer_device *peer_device;

	spin_lock_irq(&resource->req_lock);
	for_each_connection(connection, resource) {
		idr_remove(&connection->peer_devices, device->vnr);
	}
	idr_remove(&resource->devices, device->vnr);
	idr_remove(&bsr_devices, device_to_minor(device));
	spin_unlock_irq(&resource->req_lock);

	for_each_peer_device(peer_device, device)
		bsr_debugfs_peer_device_cleanup(peer_device);
	bsr_debugfs_device_cleanup(device);
	del_gendisk(device->vdisk);
}

void bsr_put_device(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;
	int refs = 3;

	destroy_workqueue(device->submit.wq);
	device->submit.wq = NULL;
	del_timer_sync(&device->request_timer);

	for_each_peer_device(peer_device, device)
		refs++;

	kref_debug_sub(&device->kref_debug, refs, 1);
	kref_sub(&device->kref, refs, bsr_destroy_device);
}

/**
 * bsr_unregister_connection()  -  make a connection "invisible"
 *
 * Remove the connection from the bsr object model.  Keep reference counts on
 * connection->kref; they are dropped in bsr_put_connection().
 */
void bsr_unregister_connection(struct bsr_connection *connection)
{
	struct bsr_resource *resource = connection->resource;
	struct bsr_peer_device *peer_device;
	int vnr;

	LIST_HEAD(work_list);
#if _LIN
	// BSR-947 create and add a separate list to ensure synchronization of the list reference of the peer_device in use in the critical area.
	struct peer_device_list {
		struct list_head list;
		struct bsr_peer_device *peer_device;
	};
	struct peer_device_list peer_head;
	struct peer_device_list *peer_list, *tmp;

	INIT_LIST_HEAD(&peer_head.list);
#endif

	// BSR-426 repositioned req_lock to resolve deadlock.
	// BSR-447 req_lock spinlock should precede the rcu lock.
	// false the locked parameter at end_state_change_locked() in bsr causes synchronization problems, the parameter is false if it is locked by req_lock spinlock.
	spin_lock_irq(&resource->req_lock);
#ifdef _WIN
	// DW-1465 Requires rcu wlock because list_del_rcu().
	// BSR-426 move code from del_connection() here
	synchronize_rcu_w32_wlock();
#endif
	set_bit(C_UNREGISTERED, &connection->flags);
	smp_wmb();

	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		list_del_rcu(&peer_device->peer_devices);
#ifdef _LIN
		peer_list = bsr_kmalloc(sizeof(*peer_list), GFP_ATOMIC, '85SB');
		if(peer_list) {
			peer_list->peer_device = peer_device;
			list_add(&peer_list->list, &peer_head.list);
			continue;
		}  
#endif
		list_add(&peer_device->peer_devices, &work_list);
	}
#ifdef _WIN
	synchronize_rcu();
#endif
	list_del_rcu(&connection->connections);
	spin_unlock_irq(&resource->req_lock);
	list_for_each_entry_ex(struct bsr_peer_device, peer_device, &work_list, peer_devices)
		bsr_debugfs_peer_device_cleanup(peer_device);

#ifdef _LIN
	synchronize_rcu();
	list_for_each_entry_safe_ex(struct peer_device_list, peer_list, tmp, &peer_head.list, list) {
		bsr_debugfs_peer_device_cleanup(peer_list->peer_device);
		list_del(&peer_list->list);
		bsr_kfree(peer_list);
	}
#endif

	bsr_debugfs_connection_cleanup(connection);
}

void del_connect_timer(struct bsr_connection *connection)
{
	if (del_timer_sync(&connection->connect_timer)) {
		kref_debug_put(&connection->kref_debug, 11);
		kref_put(&connection->kref, bsr_destroy_connection);
	}
}

void bsr_put_connection(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int vnr, rr, refs = 1;

	del_connect_timer(connection);
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr)
		refs++;

	rr = bsr_free_peer_reqs(connection->resource, &connection->done_ee, false);
	if (rr)
		bsr_err(3, BSR_LC_PEER_REQUEST, connection, "%d peer request in done list found!", rr);

	rr = bsr_free_peer_reqs(connection->resource, &connection->net_ee, true);
	if (rr)
		bsr_err(4, BSR_LC_PEER_REQUEST, connection, "%d peer request in net list found!", rr);
	bsr_transport_shutdown(connection, DESTROY_TRANSPORT);

	kref_debug_sub(&connection->kref_debug, refs - 1, 3);
	kref_debug_put(&connection->kref_debug, 10);
	kref_sub(&connection->kref, refs, bsr_destroy_connection);
}

#ifdef _WIN
struct log_rolling_file_list {
	struct list_head list;
	WCHAR *fileName;
};
#endif

// BSR-579 deletes files when the number of rolling files exceeds a specified number
#ifdef _WIN
NTSTATUS bsr_log_rolling_file_clean_up(WCHAR* filePath)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES obAttribute;
	UNICODE_STRING usfilePath;
	HANDLE hFindFile;
	IO_STATUS_BLOCK ioStatus = { 0 };
	ULONG currentSize = 0;
	FILE_BOTH_DIR_INFORMATION *pFileBothDirInfo = NULL;
	bool is_start = true;
	int log_file_max_count = 0;
	struct log_rolling_file_list rlist, *t, *tmp;

	INIT_LIST_HEAD(&rlist.list);

	RtlInitUnicodeString(&usfilePath, filePath);
	InitializeObjectAttributes(&obAttribute, &usfilePath, OBJ_CASE_INSENSITIVE, 0, 0);

	status = ZwOpenFile(&hFindFile,
		FILE_LIST_DIRECTORY | SYNCHRONIZE,
		&obAttribute, &ioStatus,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT);

	if (!NT_SUCCESS(status)) {
		bsr_err(1, BSR_LC_LOG, NO_OBJECT, "Failed to rolling log file due to failure to open log directory. status(%x)", status);
		return status;
	}

	currentSize = sizeof(FILE_BOTH_DIR_INFORMATION);
	// BSR-579
	pFileBothDirInfo = ExAllocatePoolWithTag(PagedPool, currentSize, '3ASB');
	if (!pFileBothDirInfo){
		bsr_err(76, BSR_LC_MEMORY, NO_OBJECT, "Failed to rolling log file due to failure to allocation query buffer. status(%u)", currentSize);
		status = STATUS_NO_MEMORY;
		goto out;
	}

	while (TRUE) {
		RtlZeroMemory(pFileBothDirInfo, currentSize);
		status = ZwQueryDirectoryFile(hFindFile,
											NULL,
											NULL,
											NULL,
											&ioStatus,
											pFileBothDirInfo,
											currentSize,
											FileBothDirectoryInformation,
											FALSE,
											NULL,
											is_start);

		if (STATUS_BUFFER_OVERFLOW == status) {
			kfree2(pFileBothDirInfo);
			currentSize = currentSize * 2;
			// BSR-600 paths is long (extension path is not supported)
			if (MAX_PATH < (currentSize / 2)) {
				bsr_err(3, BSR_LC_LOG, NO_OBJECT, "Failed to rolling log file due to extension paths are not supported. max path(%u), current path(%u)", MAX_PATH, (currentSize / 2));
				status = STATUS_OBJECT_PATH_INVALID;
				goto out;
			}
			// BSR-579
			pFileBothDirInfo = ExAllocatePoolWithTag(PagedPool, currentSize, '4ASB'); 
			if (pFileBothDirInfo == NULL) {
				bsr_err(77, BSR_LC_MEMORY, NO_OBJECT, "Failed to rolling log file due to failure to allocation %d size query buffer memory.", currentSize);
				status = STATUS_NO_MEMORY;
				goto out;
			}
			continue;
		}
		else if (STATUS_NO_MORE_FILES == status)
		{
			status = STATUS_SUCCESS;
			break;
		}
		else if (!NT_SUCCESS(status))
		{
			bsr_err(5, BSR_LC_LOG, NO_OBJECT, "Failed to rolling log file due to failure to query directory file. status(%x)", status);
			goto out2;
		}

		if (is_start)
			is_start = false;

		while (TRUE)
		{
			WCHAR fileName[MAX_PATH];

			memset(fileName, 0, sizeof(fileName));
			memcpy(fileName, pFileBothDirInfo->FileName, pFileBothDirInfo->FileNameLength);

			if (wcsstr(fileName, BSR_LOG_ROLLING_FILE_NAME)) {
				size_t flength = pFileBothDirInfo->FileNameLength + sizeof(WCHAR);
				struct log_rolling_file_list *r;
				// BSR-579
				r = ExAllocatePoolWithTag(PagedPool, sizeof(struct log_rolling_file_list), '5ASB');
				if (!r) {
					bsr_err(78, BSR_LC_MEMORY, NO_OBJECT, "Failed to rolling log file due to failure to allocation %d size file list memory", sizeof(struct log_rolling_file_list));
					status = STATUS_NO_MEMORY;
					goto out;
				}
				// BSR-579
				r->fileName = ExAllocatePoolWithTag(PagedPool, flength, '6ASB');
				if (!r) {
					bsr_err(79, BSR_LC_MEMORY, NO_OBJECT, "Failed to rolling log file due to failure to allocation %d size file list memory", flength);
					status = STATUS_NO_MEMORY;
					goto out;
				}
				memset(r->fileName, 0, flength);
				memcpy(r->fileName, pFileBothDirInfo->FileName, pFileBothDirInfo->FileNameLength);

				bool is_add = false;

				list_for_each_entry_ex(struct log_rolling_file_list, t, &rlist.list, list) {
					if (wcscmp(t->fileName, r->fileName) > 0) {
						list_add(&r->list, &t->list);
						is_add = true;
						break;
					}
				}

				if (is_add == false)
					list_add_tail(&r->list, &rlist.list);

				log_file_max_count = log_file_max_count + 1;
			}

			if (pFileBothDirInfo->NextEntryOffset == 0)
				break;

			pFileBothDirInfo += pFileBothDirInfo->NextEntryOffset;
		}
	}

	if (log_file_max_count >= atomic_read(&g_log_file_max_count)) {
		HANDLE hFile;
		UNICODE_STRING usFilePullPath;
		WCHAR fileFullPath[MAX_PATH];
		char buf[1] = { 0x01 };

		list_for_each_entry_ex(struct log_rolling_file_list, t, &rlist.list, list) {
			_snwprintf(fileFullPath, (sizeof(fileFullPath) / sizeof(wchar_t)) - 1, L"%ws\\%ws", filePath, t->fileName);

			RtlInitUnicodeString(&usFilePullPath, fileFullPath);
			InitializeObjectAttributes(&obAttribute, &usFilePullPath, OBJ_CASE_INSENSITIVE, 0, 0);

			status = ZwOpenFile(&hFile,
				DELETE,
				&obAttribute,
				&ioStatus,
				FILE_SHARE_VALID_FLAGS,
				FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_NON_DIRECTORY_FILE);

			if (!NT_SUCCESS(status)) {
				bsr_err(8, BSR_LC_LOG, NO_OBJECT, "Failed to open %ws file. status(%x)", fileFullPath, status);
				continue;
			}

			status = ZwSetInformationFile(hFile, &ioStatus, buf, 1, FileDispositionInformation);
			if (!NT_SUCCESS(status)) {
				bsr_err(9, BSR_LC_LOG, NO_OBJECT, "Failed to delete %ws file. status(%x)", fileFullPath, status);
			}
			ZwClose(hFile);

			log_file_max_count = log_file_max_count - 1;
			if (log_file_max_count < atomic_read(&g_log_file_max_count))
				break;
		}
	}
out:
	ZwClose(hFindFile);
out2:
	if (pFileBothDirInfo)
		kfree2(pFileBothDirInfo);

	list_for_each_entry_safe_ex(struct log_rolling_file_list, t, tmp, &rlist.list, list) {
		kfree2(t->fileName);
		list_del(&t->list);
		kfree2(t);
	}

	return status;
}
#else // LIN BSR-597

static int name_cmp(void *priv, list_cmp_t *a, list_cmp_t *b)
{
	struct log_rolling_file_list *list_a = container_of(a, struct log_rolling_file_list, list);
	struct log_rolling_file_list *list_b = container_of(b, struct log_rolling_file_list, list);

	if (list_a == NULL || list_b == NULL || (list_a == list_b))
					return 0;

	return strcmp(list_b->fileName, list_a->fileName);
}

int bsr_log_rolling_file_clean_up(void)
{
	char path[MAX_PATH] = BSR_LOG_FILE_PATH;
	int log_file_max_count = 0;

	struct log_rolling_file_list rlist = {
#ifdef COMPAT_HAVE_ITERATE_DIR
		.ctx.actor = printdir
#endif
	};
	struct log_rolling_file_list *t, *tmp;
	int err = 0;
	
	INIT_LIST_HEAD(&rlist.list);
	
	bsr_readdir(path, &rlist);
	
	list_sort(NULL, &rlist.list, name_cmp);

	list_for_each_entry_ex(struct log_rolling_file_list, t, &rlist.list, list) {
		log_file_max_count++;
		if (log_file_max_count < atomic_read(&g_log_file_max_count)) {
			continue;
		}

		err = bsr_file_remove(t->fileName);
		if (err)
			break;
	}
	
	list_for_each_entry_safe_ex(struct log_rolling_file_list, t, tmp, &rlist.list, list) {
		kfree2(t->fileName);
		list_del(&t->list);
		kfree2(t);
	}
	
	return err;
}
#endif

// BSR-579 rename the file to the rolling file format and close the handle
#ifdef _WIN
NTSTATUS bsr_log_file_rename_and_close(PHANDLE hFile) 
{
	WCHAR fileFullPath[MAX_PATH] = { 0 };
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatus;
	PFILE_RENAME_INFORMATION pRenameInfo;
	LARGE_INTEGER systemTime, localTime;
	TIME_FIELDS timeFields = { 0, };

	KeQuerySystemTime(&systemTime);
	ExSystemTimeToLocalTime(&systemTime, &localTime);
	RtlTimeToTimeFields(&localTime, &timeFields);

	memset(fileFullPath, 0, sizeof(fileFullPath));

	_snwprintf(fileFullPath, MAX_PATH - 1, L"%ws%04d-%02d-%02dT%02d%02d%02d.%03d", BSR_LOG_ROLLING_FILE_NAME,
																		timeFields.Year,
																		timeFields.Month,
																		timeFields.Day,
																		timeFields.Hour,
																		timeFields.Minute,
																		timeFields.Second,
																		timeFields.Milliseconds);

	// BSR-579
	pRenameInfo = ExAllocatePoolWithTag(PagedPool, sizeof(FILE_RENAME_INFORMATION) + sizeof(fileFullPath), '7ASB');

	pRenameInfo->ReplaceIfExists = false;
	pRenameInfo->RootDirectory = NULL;
	pRenameInfo->FileNameLength = (ULONG)(wcslen(fileFullPath) * sizeof(wchar_t));
	RtlCopyMemory(pRenameInfo->FileName, fileFullPath, (wcslen(fileFullPath) * sizeof(wchar_t)));

	status = ZwSetInformationFile(hFile,
									&ioStatus,
									(PFILE_RENAME_INFORMATION)pRenameInfo,
									sizeof(FILE_RENAME_INFORMATION) + (ULONG)(wcslen(fileFullPath) * sizeof(wchar_t)),
									FileRenameInformation);

	kfree2(pRenameInfo);
	ZwClose(hFile);

	return status;
}
#else // _LIN

int bsr_log_file_rename(void) 
{
	char new_name[MAX_PATH];
	struct timespec64 ts;
	struct tm tm;

	int err = 0;
	
	memset(new_name, 0, sizeof(new_name));

	ts = ktime_to_timespec64(ktime_get_real());
	time64_to_tm(ts.tv_sec, (9*60*60), &tm); // TODO timezone
	
	snprintf(new_name, MAX_PATH - 1, "%s_%04d-%02d-%02d_%02d%02d%02d.%03d",
									BSR_LOG_FILE_NAME,
									(int)tm.tm_year+1900,
									tm.tm_mon+1,
									tm.tm_mday,
									tm.tm_hour,
									tm.tm_min,
									tm.tm_sec,
									(int)(ts.tv_nsec / NSEC_PER_MSEC));

	err = bsr_file_rename(BSR_LOG_FILE_NAME, new_name);

	return err;
}
#endif

#ifdef _WIN
// BSR-579
void wait_for_add_device(WCHAR *path) 
{
	bool wait_device_add = true;

	while (wait_device_add) {
		MVOL_LOCK();
		if (mvolRootDeviceObject != NULL) {
			PROOT_EXTENSION r = mvolRootDeviceObject->DeviceExtension;
			if (r != NULL) {
				PVOLUME_EXTENSION v = r->Head;
				if (v != NULL) {
					// BSR-600 compare first entry
					do {
						WCHAR letter[32] = { 0, };
						// BSR-109
						memcpy(letter, v->MountPoint, wcslen(v->MountPoint) * sizeof(WCHAR));
						if (wcsstr(path, letter)) {
							wait_device_add = false;
							break;
						}
					} while ((v = v->Next) != NULL);
				}
			}
		}
		MVOL_UNLOCK();
		if (wait_device_add)
			bsr_info(10, BSR_LC_LOG, NO_OBJECT, "Wait for device to be connected for log file generation.(%ws)", path);

		msleep(1000);
	}
}
#endif

// BSR-578 threads writing logs to a file
#ifdef _WIN
LONGLONG get_file_size(HANDLE hFile)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	FILE_STANDARD_INFORMATION fileBothDirInfo;

	status = ZwQueryInformationFile(hFile,
									&iosb,
									&fileBothDirInfo,
									sizeof(fileBothDirInfo),
									FileStandardInformation);

	if (NT_SUCCESS(status))
		return fileBothDirInfo.EndOfFile.QuadPart;

	return 0;
}
#else // _LIN
long get_file_size(struct file * fd)
{
	long filesize;
	mm_segment_t oldfs;
	oldfs = get_fs();
#ifdef COMPAT_HAVE_SET_FS
	set_fs(KERNEL_DS);
#endif
	filesize = fd->f_op->llseek(fd, 0, SEEK_END);
	set_fs(oldfs);
	if (filesize > 0)
		return filesize;
	return 0;
}
#endif

// BSR-619
void start_logging_thread(void)
{
#ifdef _WIN
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hThread = NULL;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, log_consumer_thread, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrint("PsCreateSystemThread for log consumer failed with status 0x%08X", status);
		g_consumer_state = EXITING;
		return;
	}

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode,
		&g_consumer_thread, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ObReferenceObjectByHandle for log consumer failed with status 0x%08X", status);
		g_consumer_state = EXITING;
		g_consumer_thread = NULL;
		return;
	}

	if (NULL != hThread)
		ZwClose(hThread);
#else
	g_consumer_thread = kthread_run(log_consumer_thread, NULL, "bsr_log_consumer");

	if (!g_consumer_thread || IS_ERR(g_consumer_thread)) {
		printk(KERN_ERR "bsr: bsr_log_consumer thread failed(%d)", (int)IS_ERR(g_consumer_thread));
		g_consumer_state = EXITING;
		g_consumer_thread = NULL;
		return;
	}
#endif
}

#ifdef _WIN
void log_consumer_thread(PVOID param) 
#else // _LIN
int log_consumer_thread(void *unused) 
#endif
{
	char* buffer = NULL;
	atomic_t idx;
	// BSR-583
	bool chk_complete = false;
	LONGLONG logFileSize = 0;
#ifdef _WIN
	HANDLE hFile;
	IO_STATUS_BLOCK ioStatus;
	OBJECT_ATTRIBUTES obAttribute;
	UNICODE_STRING usFileFullPath, usRegPath;
	NTSTATUS status;
	ULONG uLength;
	WCHAR filePath[MAX_PATH] = { 0 };
	WCHAR fileFullPath[MAX_PATH] = { 0 };
	WCHAR* ptr;

	// BSR-600 if the LOG_FILE_MAX_REG_VALUE_NAME value is not set at all, the key value does not exist and is a normal operation.
	// BSR-579
	RtlInitUnicodeString(&usRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\bsrvflt");
	status = GetRegistryValue(LOG_FILE_MAX_REG_VALUE_NAME, &uLength, (UCHAR*)&filePath, &usRegPath);
	if (NT_SUCCESS(status))
		atomic_set(&g_log_file_max_count, *(int*)filePath);

	RtlInitUnicodeString(&usRegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
	status = GetRegistryValue(L"BSR_PATH", &uLength, (UCHAR*)&filePath, &usRegPath);

	if (!NT_SUCCESS(status)) {
		// BSR-619 if the path fails to obtain, end the real-time log write.
		gLogBuf.h.r_idx.has_consumer = false;
		g_consumer_state = EXITING;
		bsr_err(11, BSR_LC_LOG, NO_OBJECT, "log consumer thread terminate due to failure to get 'BSR_PATH' environment variable. status(%x)", status);
		return;
	}

	ptr = wcsrchr(filePath, L'\\');
	if (ptr != NULL)
		filePath[wcslen(filePath) - wcslen(ptr)] = L'\0';

	// BSR-579
	wait_for_add_device(filePath);

	uLength = _snwprintf(fileFullPath, MAX_PATH - 1, L"\\??\\%ws\\log\\bsrlog.txt", filePath);

	memcpy(filePath, fileFullPath, sizeof(fileFullPath));
	ptr = wcsrchr(filePath, L'\\');
	if (ptr != NULL)
		filePath[wcslen(filePath) - wcslen(ptr)] = L'\0';

	RtlInitUnicodeString(&usFileFullPath, fileFullPath);
	InitializeObjectAttributes(&obAttribute, &usFileFullPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&hFile,
							FILE_APPEND_DATA,
							&obAttribute,
							&ioStatus,
							NULL,
							FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ | FILE_SHARE_DELETE,
							FILE_OPEN_IF,
							FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT,
							NULL,
							0);

	if (!NT_SUCCESS(status)) {
		bsr_err(12, BSR_LC_LOG, NO_OBJECT, "Failed to create log file. status(%x)", status);
	}
#else 
	// BSR-581
	// creating a linux log file
	struct file *hFile = NULL;
	int err = 0;
	size_t filesize = 0;
	mm_segment_t oldfs;
	char filePath[sizeof(BSR_LOG_FILE_PATH) + sizeof(BSR_LOG_FILE_NAME) + 1]; 

	snprintf(filePath, sizeof(BSR_LOG_FILE_PATH) + sizeof(BSR_LOG_FILE_NAME) + 1, 
			"%s/%s", BSR_LOG_FILE_PATH, BSR_LOG_FILE_NAME);

	// BSR-610 mkdir /var/log/bsr
	err = bsr_mkdir(BSR_LOG_FILE_PATH, 0755);
	if (err != 0 && err != -EEXIST) {
		// BSR-619 if the path fails to obtain, end the real-time log write.
		gLogBuf.h.r_idx.has_consumer = false;
		g_consumer_state = EXITING;
		bsr_err(18, BSR_LC_LOG, NO_OBJECT, "log consumer thread terminate due to failure to create log directory");
		return 0;
	}

	oldfs = get_fs();
#ifdef COMPAT_HAVE_SET_FS
	set_fs(KERNEL_DS);
#endif
	hFile = filp_open(filePath, O_WRONLY | O_CREAT | O_APPEND, 0644);
	set_fs(oldfs);
	if (hFile == NULL || IS_ERR(hFile)) {
		bsr_err(19, BSR_LC_LOG, NO_OBJECT, "Failed to create log file");
	}
#endif
	else {
		logFileSize = get_file_size(hFile);

		// BSR-578 set before consumption starts.
		gLogBuf.h.r_idx.has_consumer = true;
		atomic_set(&idx, 0);

		while (g_consumer_state == RUNNING) {
			if (chk_complete == false) {
				if (!idx_ring_consume(&gLogBuf.h, &idx)) {
					msleep(100); // wait 100ms relative
					continue;
				}
			}
			chk_complete = true;

			buffer = ((char*)gLogBuf.b + (atomic_read(&idx) * (MAX_BSRLOG_BUF + IDX_OPTION_LENGTH)));
			if (*buffer == IDX_DATA_RECORDING) {
				msleep(100); // wait 100ms relative
				continue;
			}
			chk_complete = false;

#ifdef _WIN
			status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, (PVOID)(buffer + IDX_OPTION_LENGTH), (ULONG)strlen(buffer + IDX_OPTION_LENGTH), NULL, NULL);
			if (!NT_SUCCESS(status)) {
				bsr_err(13, BSR_LC_LOG, NO_OBJECT, "Failed to write log. status(%x)", status);
				break;
			}
#else
			// BSR-619 check log file exists
			if (d_unlinked(hFile->f_path.dentry)) {
				bsr_err(20, BSR_LC_LOG, NO_OBJECT, "Log file does not exist..");
				break;
			}

			// BSR-581
			// writing linux log files		
			filesize = strlen(buffer);
			oldfs = get_fs();
#ifdef COMPAT_HAVE_SET_FS
			set_fs(KERNEL_DS);
#endif
			err = bsr_write(hFile, buffer, filesize, &hFile->f_pos);
			set_fs(oldfs);

			if (err < 0 || err != filesize) {
				bsr_err(21, BSR_LC_LOG, NO_OBJECT, "Failed to write log. err(%d)", err);
				break;
			}
#endif
			logFileSize = logFileSize + strlen(buffer + IDX_OPTION_LENGTH);

			// BSR-579 apply file size or log count based on rolling judgment
			if (atomic_read(&idx) == (LOGBUF_MAXCNT - 1) || logFileSize > (MAX_BSRLOG_BUF * LOGBUF_MAXCNT)) {

#ifdef _WIN
				status = bsr_log_rolling_file_clean_up(filePath);
				if (!NT_SUCCESS(status))
					break;

				// BSR-579 if the log file is larger than 50M, do file rolling.
				status = bsr_log_file_rename_and_close(hFile);
				if (!NT_SUCCESS(status)) {
					bsr_err(14, BSR_LC_LOG, NO_OBJECT, "Failed to rename log file status(%x)", status);
					break;
				}
				status = ZwCreateFile(&hFile,
										FILE_APPEND_DATA,
										&obAttribute,
										&ioStatus,
										NULL,
										FILE_ATTRIBUTE_NORMAL,
										FILE_SHARE_READ | FILE_SHARE_DELETE,
										FILE_OPEN_IF,
										FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT,
										NULL,
										0);

				if (!NT_SUCCESS(status)) {
					bsr_err(15, BSR_LC_LOG, NO_OBJECT, "Failed to new log file status(%x)", status);
					break;
				}
#else // _LIN
				// BSR-579 rolling and clean up
				if (bsr_log_rolling_file_clean_up() != 0) {
					bsr_err(22, BSR_LC_LOG, NO_OBJECT, "Failed to remove log file");
					break;
				}

				// BSR-579 if the log file is larger than 50M, do file rolling.
				if (hFile)
					filp_close(hFile, NULL);

				if (bsr_log_file_rename() != 0) {
					bsr_err(23, BSR_LC_LOG, NO_OBJECT, "Failed to rename log file");
					break;
				}
				oldfs = get_fs();
#ifdef COMPAT_HAVE_SET_FS
				set_fs(KERNEL_DS);
#endif

				hFile = filp_open(filePath, O_WRONLY | O_CREAT, 0644);
				set_fs(oldfs);
				if (hFile == NULL || IS_ERR(hFile)) {
					bsr_err(24, BSR_LC_LOG, NO_OBJECT, "Failed to create new log file");
					break;
				}
#endif
				logFileSize = 0;
			}
			idx_ring_dispose(&gLogBuf.h, buffer);
		}
	}

	if (hFile) {
#ifdef _WIN
		ZwClose(hFile);
#else // _LIN
		filp_close(hFile, NULL);
#endif
		hFile = NULL;
	}

	gLogBuf.h.r_idx.has_consumer = false;

	// BSR-619 if a failure occurs, try again if it is in RUNNING state.
	if (g_consumer_state == RUNNING) {
		msleep(1000);
		start_logging_thread();
	}
	else 
		bsr_info(16, BSR_LC_LOG, NO_OBJECT, "The thread writing the log to the file has been terminated.");

#ifdef _LIN
	return 0;
#endif
}

void clean_logging(void)
{
#ifdef _WIN
	g_consumer_state = EXITING;
	
	if (g_consumer_thread != NULL) {
		KeWaitForSingleObject(g_consumer_thread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(g_consumer_thread);
	}
#else // _LIN
	if (g_consumer_state != EXITING) {
		g_consumer_state = EXITING;
		kthread_stop(g_consumer_thread);
	}
	g_consumer_thread = NULL;
#endif
}
#ifdef _WIN
extern PULONG InitSafeBootMode;
#endif
void init_logging(void)
{
	// BSR-578 initialize to -1 for output from 0 array
	atomic_set64(&gLogCnt, -1);
	g_consumer_state = EXITING;
	g_consumer_thread = NULL;
#ifdef _WIN
	// BSR-578 initializing log buffer
	memset(gLogBuf.b, 0, (LOGBUF_MAXCNT * MAX_BSRLOG_BUF));

	gLogBuf.h.max_count = LOGBUF_MAXCNT;
	gLogBuf.h.r_idx.has_consumer = false;

	// BSR-511 log consumer does not run in safe mode boot.
	if (*InitSafeBootMode == 0) {
		g_consumer_state = RUNNING;
		start_logging_thread();
	}
#else
	// BSR-581
	// generate logging threads
	memset(gLogBuf.b, 0, (LOGBUF_MAXCNT * MAX_BSRLOG_BUF));

	atomic_set64(&gLogBuf.h.max_count, LOGBUF_MAXCNT);
	gLogBuf.h.r_idx.has_consumer = false;
	g_consumer_state = RUNNING;

	start_logging_thread();
#endif
}

void bsr_cleanup(void)
{
	/* first remove proc,
	 * bsrsetup uses it's presence to detect
	 * whether BSR is loaded.
	 * If we would get stuck in proc removal,
	 * but have netlink already deregistered,
	 * some bsrsetup commands may wait forever
	 * for an answer.
	 */
#ifdef _WIN
	if (retry.wq)
		destroy_workqueue(retry.wq);
	
#else // _LIN
	if (bsr_proc)
		remove_proc_entry("bsr", NULL);

	if (retry.wq)
		destroy_workqueue(retry.wq);

	bsr_genl_unregister();
	// BSR-577
	misc_deregister(&bsr_misc);
	bsr_unregister_blkdev(BSR_MAJOR, "bsr");
#endif
	bsr_destroy_mempools();

	idr_destroy(&bsr_devices);

	bsr_info(68, BSR_LC_DRIVER, NO_OBJECT, "Cleanup of BSR module has been completed.");
}

#ifdef _WIN
int __init bsr_init(void)
#else // _LIN
int bsr_init(void)
#endif
{
	int err;

#ifdef _WIN
	nl_policy_init_by_manual();
	g_rcuLock = 0; // init RCU lock

	mutex_init(&g_genl_mutex);
	// DW-1998
	g_genl_run_cmd = 0;
	mutex_init(&g_genl_run_cmd_mutex);
	
	mutex_init(&notification_mutex);
	mutex_init(&att_mod_mutex); 

	ratelimit_state_init(&bsr_ratelimit_state, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);

	ct_init_thread_list();

	// BSR-438
	spin_lock_init(&g_inactive_lock);
	// BSR-822
	mutex_init(&handler_mutex);
#endif
	// BSR-1036
	spin_lock_init(&g_unacked_lock);

	if (minor_count < BSR_MINOR_COUNT_MIN || minor_count > BSR_MINOR_COUNT_MAX) {
		bsr_err(69, BSR_LC_DRIVER, NO_OBJECT, "Invalid minor count (%u) during bsr initialization", minor_count);
#ifdef MODULE
		return -EINVAL;
#else
		minor_count = BSR_MINOR_COUNT_DEF;
#endif
	}

#ifdef _LIN
	err = register_blkdev(BSR_MAJOR, "bsr");
	if (err) {
		bsr_err(70, BSR_LC_DRIVER, NO_OBJECT, "unable to register block device major %d during bsr initialization", BSR_MAJOR);
		return err;
	}

	// BSR-577
	err = misc_register(&bsr_misc);
	if (err) {
		bsr_err(71, BSR_LC_DRIVER, NO_OBJECT, "unable to register bsr-control device during bsr initialization");
		return err;
	}

#endif

	/*
	* allocate all necessary structs
	*/
#ifdef _WIN
	strncpy(bsr_pp_wait.eventName, "bsr_pp_wait", sizeof(bsr_pp_wait.eventName) - 1);
#endif
	init_waitqueue_head(&bsr_pp_wait);


#ifdef _LIN
	bsr_proc = NULL; /* play safe for bsr_cleanup */
#endif

	idr_init(&bsr_devices);
	mutex_init(&resources_mutex);
	INIT_LIST_HEAD(&bsr_resources);

#ifdef _LIN
	err = bsr_genl_register();
	if (err) {
		bsr_err(72, BSR_LC_DRIVER, NO_OBJECT, "unable to register generic netlink family");
		goto fail;
	}
#endif

	err = bsr_create_mempools();
	if (err)
		goto fail;

	err = -ENOMEM; // Used when bsr_proc and retry.wq creation failed.
#ifdef _LIN
	bsr_proc = proc_create_single("bsr", S_IFREG | S_IRUGO , NULL, bsr_seq_show);
	if (!bsr_proc)	{
		bsr_err(73, BSR_LC_DRIVER, NO_OBJECT, "unable to register proc file during bsr initialization ");
		goto fail;
	}
#endif

	retry.wq = create_singlethread_workqueue("bsr-reissue");
	if (!retry.wq) {
		bsr_err(35, BSR_LC_THREAD, NO_OBJECT, "unable to create retry workqueue during bsr initialization ");
		goto fail;
	}

	INIT_WORK(&retry.worker, do_retry);
	spin_lock_init(&retry.lock);
	INIT_LIST_HEAD(&retry.writes);

#ifdef _WIN
	// BSR-109 disable this feature as a change in how mount information is updated
#if 0
	 DW-1105 need to detect changing volume letter and adjust it to VOLUME_EXTENSION.	
	if (!NT_SUCCESS(start_mnt_monitor())) {
		bsr_err(75, BSR_LC_DRIVER, NO_OBJECT,"could not start mount monitor during bsr initialization ");
		goto fail;
	}
#endif
#endif

#ifdef _LIN
#if 0 // moved to bsr_load()
	if (bsr_debugfs_init())
		bsr_noti(142, BSR_LC_DRIVER, NO_OBJECT, "Failed to initialize debugfs -- will not be available");
#endif
#endif

	bsr_info(77, BSR_LC_DRIVER, NO_OBJECT, "BSR driver loaded and initialized successfully. "
	       "Version: " REL_VERSION " (api:%d/proto:%d-%d)",
	       GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX);
	bsr_info(78, BSR_LC_DRIVER, NO_OBJECT, "%s", bsr_buildtag());
	bsr_info(79, BSR_LC_DRIVER, NO_OBJECT, "registered as block device major %d", BSR_MAJOR);


	return 0; /* Success! */

fail:
	bsr_cleanup();
	if (err == -ENOMEM)
		bsr_err(63, BSR_LC_MEMORY, NO_OBJECT, "ran out of memory during bsr initialization");
	else
		bsr_err(81, BSR_LC_DRIVER, NO_OBJECT, "bsr initialization failure");
#ifdef _LIN
	bsr_debugfs_cleanup();
	// BSR-581
	clean_logging();
#endif

	return err;
}



/* meta data management */

void bsr_md_write(struct bsr_device *device, void *b)
{
	struct meta_data_on_disk_9 *buffer = b;
	sector_t sector;
	int i;

	memset(buffer, 0, sizeof(*buffer));

	buffer->effective_size = cpu_to_be64(device->ldev->md.effective_size);
	buffer->current_uuid = cpu_to_be64(device->ldev->md.current_uuid);
	buffer->flags = cpu_to_be32(device->ldev->md.flags);
	buffer->magic = cpu_to_be32(BSR_MD_MAGIC_09);

	buffer->md_size_sect  = cpu_to_be32(device->ldev->md.md_size_sect);
	buffer->al_offset     = cpu_to_be32(device->ldev->md.al_offset);
	buffer->al_nr_extents = cpu_to_be32(device->act_log->nr_elements);
	buffer->bm_bytes_per_bit = cpu_to_be32(BM_BLOCK_SIZE);
	buffer->device_uuid = cpu_to_be64(device->ldev->md.device_uuid);

	buffer->bm_offset = cpu_to_be32(device->ldev->md.bm_offset);
	buffer->la_peer_max_bio_size = cpu_to_be32(device->device_conf.max_bio_size);
	buffer->bm_max_peers = cpu_to_be32(device->bitmap->bm_max_peers);
	buffer->node_id = cpu_to_be32(device->ldev->md.node_id);
	for (i = 0; i < BSR_NODE_ID_MAX; i++) {
		struct bsr_peer_md *peer_md = &device->ldev->md.peers[i];

		buffer->peers[i].bitmap_uuid = cpu_to_be64(peer_md->bitmap_uuid);
		buffer->peers[i].bitmap_dagtag = cpu_to_be64(peer_md->bitmap_dagtag);
		buffer->peers[i].flags = cpu_to_be32(peer_md->flags);
		buffer->peers[i].bitmap_index = cpu_to_be32(peer_md->bitmap_index);
	}
	BUILD_BUG_ON(ARRAY_SIZE(device->ldev->md.history_uuids) != ARRAY_SIZE(buffer->history_uuids));
	for (i = 0; i < ARRAY_SIZE(buffer->history_uuids); i++)
		buffer->history_uuids[i] = cpu_to_be64(device->ldev->md.history_uuids[i]);

	buffer->al_stripes = cpu_to_be32(device->ldev->md.al_stripes);
	buffer->al_stripe_size_4k = cpu_to_be32(device->ldev->md.al_stripe_size_4k);

	D_ASSERT(device, bsr_md_ss(device->ldev) == device->ldev->md.md_offset);
	sector = device->ldev->md.md_offset;

	if (bsr_md_sync_page_io(device, device->ldev, sector, REQ_OP_WRITE)) {
		/* this was a try anyways ... */
		bsr_err(30, BSR_LC_IO, device, "Failed to update meta data due to failure to write meta-disk.");
		bsr_chk_io_error(device, 1, BSR_META_IO_ERROR);
	}
}

/**
 * __bsr_md_sync() - Writes the meta data super block (conditionally) if the MD_DIRTY flag bit is set
 * @device:    BSR device.
 * @maybe:    meta data may in fact be "clean", the actual write may be skipped.
 */
static void __bsr_md_sync(struct bsr_device *device, bool maybe)
{
	struct meta_data_on_disk_9 *buffer;

	/* Don't accidentally change the BSR meta data layout. */
	BUILD_BUG_ON(BSR_PEERS_MAX != 32);
	BUILD_BUG_ON(HISTORY_UUIDS != 32);
	BUILD_BUG_ON(sizeof(struct meta_data_on_disk_9) != 4096);

	del_timer(&device->md_sync_timer);
	/* timer may be rearmed by bsr_md_mark_dirty() now. */
	if (!test_and_clear_bit(MD_DIRTY, &device->flags) && maybe)
		return;

	/* We use here D_FAILED and not D_ATTACHING because we try to write
	 * metadata even if we detach due to a disk failure! */
	if (!get_ldev_if_state(device, D_DETACHING))
		return;

	buffer = bsr_md_get_buffer(device, __func__);
	if (!buffer)
		goto out;

	bsr_md_write(device, buffer);

	bsr_md_put_buffer(device);
out:
	put_ldev(device);
}

void bsr_md_sync(struct bsr_device *device)
{
	__bsr_md_sync(device, false);
}

void bsr_md_sync_if_dirty(struct bsr_device *device)
{
	__bsr_md_sync(device, true);
}

static int check_activity_log_stripe_size(struct bsr_device *device,
		struct meta_data_on_disk_9 *on_disk,
		struct bsr_md *in_core)
{
	u32 al_stripes = be32_to_cpu(on_disk->al_stripes);
	u32 al_stripe_size_4k = be32_to_cpu(on_disk->al_stripe_size_4k);
	u64 al_size_4k;

	/* both not set: default to old fixed size activity log */
	if (al_stripes == 0 && al_stripe_size_4k == 0) {
		al_stripes = 1;
		al_stripe_size_4k = (32768 >> 9)/8;
	}

	/* some paranoia plausibility checks */

	/* we need both values to be set */
	if (al_stripes == 0 || al_stripe_size_4k == 0)
		goto err;

	al_size_4k = (u64)(al_stripes * al_stripe_size_4k);

	/* Upper limit of activity log area, to avoid potential overflow
	 * problems in al_tr_number_to_on_disk_sector(). As right now, more
	 * than 72 * 4k blocks total only increases the amount of history,
	 * limiting this arbitrarily to 16 GB is not a real limitation ;-)  */
	if (al_size_4k > (16 * 1024 * 1024/4))
		goto err;

	/* Lower limit: we need at least 8 transaction slots (32kB)
	 * to not break existing setups */
	if (al_size_4k < (32768 >> 9)/8)
		goto err;

	in_core->al_stripe_size_4k = al_stripe_size_4k;
	in_core->al_stripes = al_stripes;
	in_core->al_size_4k = (u32)al_size_4k;

	return 0;
err:
	bsr_err(12, BSR_LC_LRU, device, "Failed to set activity log stripe size: al_stripes=%u, al_stripe_size_4k=%u",
			al_stripes, al_stripe_size_4k);
	return -EINVAL;
}

static int check_offsets_and_sizes(struct bsr_device *device,
		struct meta_data_on_disk_9 *on_disk,
		struct bsr_backing_dev *bdev)
{
#ifdef _WIN // DW-1607
	sector_t capacity = bsr_get_md_capacity(bdev->md_bdev);
#else // _LIN
	sector_t capacity = bsr_get_capacity(bdev->md_bdev);
#endif
	struct bsr_md *in_core = &bdev->md;
	u32 max_peers = be32_to_cpu(on_disk->bm_max_peers);
	s32 on_disk_al_sect;
	s32 on_disk_bm_sect;

	if (max_peers > BSR_PEERS_MAX) {
		bsr_err(37, BSR_LC_BITMAP, device, "Failed to set meta offset and size due to maximum configurable peer exceeded. max(%u), config(%u)", BSR_PEERS_MAX, max_peers);
		goto err;
	}
	device->bitmap->bm_max_peers = max_peers;

	in_core->al_offset = be32_to_cpu(on_disk->al_offset);
	in_core->bm_offset = be32_to_cpu(on_disk->bm_offset);
	in_core->md_size_sect = be32_to_cpu(on_disk->md_size_sect);

	/* The on-disk size of the activity log, calculated from offsets, and
	 * the size of the activity log calculated from the stripe settings,
	 * should match.
	 * Though we could relax this a bit: it is ok, if the striped activity log
	 * fits in the available on-disk activity log size.
	 * Right now, that would break how resize is implemented.
	 * TODO: make bsr_determine_dev_size() (and the bsrmeta tool) aware
	 * of possible unused padding space in the on disk layout. */
	if (in_core->al_offset < 0) {
		if (in_core->bm_offset > in_core->al_offset)
			goto err;
		on_disk_al_sect = -in_core->al_offset;
		on_disk_bm_sect = in_core->al_offset - in_core->bm_offset;
	} else {
		if (in_core->al_offset != (4096 >> 9))
			goto err;
		if (in_core->bm_offset < in_core->al_offset + (s32)in_core->al_size_4k * (4096 >> 9))
			goto err;

		on_disk_al_sect = in_core->bm_offset - (4096 >> 9);
		on_disk_bm_sect = in_core->md_size_sect - in_core->bm_offset;
	}

	/* old fixed size meta data is exactly that: fixed. */
	if (in_core->meta_dev_idx >= 0) {
		// DW-1335
		if (in_core->md_size_sect != (256 << 20 >> 9)
		||  in_core->al_offset != (4096 >> 9)
		||  in_core->bm_offset != (4096 >> 9) + (32768 >> 9)
		||  in_core->al_stripes != 1
		||  in_core->al_stripe_size_4k != (32768 >> 12))
			goto err;
	}

	if (capacity < in_core->md_size_sect)
		goto err;
	if (capacity - in_core->md_size_sect < bsr_md_first_sector(bdev))
		goto err;

	/* should be aligned, and at least 32k */
	if ((on_disk_al_sect & 7) || (on_disk_al_sect < (32768 >> 9)))
		goto err;

	/* should fit (for now: exactly) into the available on-disk space;
	 * overflow prevention is in check_activity_log_stripe_size() above. */
	if (on_disk_al_sect != (int)(in_core->al_size_4k * (4096 >> 9)))
		goto err;

	/* again, should be aligned */
	if (in_core->bm_offset & 7)
		goto err;

	/* FIXME check for device grow with flex external meta data? */

	/* can the available bitmap space cover the last agreed device size? */
	if (on_disk_bm_sect < bsr_capacity_to_on_disk_bm_sect(
				in_core->effective_size, max_peers))
		goto err;

	return 0;

err:
	bsr_err(31, BSR_LC_IO, device, "meta data offsets don't make sense: idx=%d "
			"al_s=%u, al_sz4k=%u, al_offset=%d, bm_offset=%d, "
			"md_size_sect=%u, la_size=%llu, md_capacity=%llu",
			in_core->meta_dev_idx,
			in_core->al_stripes, in_core->al_stripe_size_4k,
			in_core->al_offset, in_core->bm_offset, in_core->md_size_sect,
			(unsigned long long)in_core->effective_size,
			(unsigned long long)capacity);

	return -EINVAL;
}


/**
 * bsr_md_read() - Reads in the meta data super block
 * @device:	BSR device.
 * @bdev:	Device from which the meta data should be read in.
 *
 * Return ERR_NO on success, and an enum bsr_ret_code in case
 * something goes wrong.
 *
 * Called exactly once during bsr_adm_attach(), while still being D_DISKLESS,
 * even before @bdev is assigned to @device->ldev.
 */
int bsr_md_read(struct bsr_device *device, struct bsr_backing_dev *bdev)
{
	struct meta_data_on_disk_9 *buffer;
	u32 magic, flags;
	int i, rv = ERR_NO;
	int my_node_id = device->resource->res_opts.node_id;
	u32 max_peers;

	if (device->disk_state[NOW] != D_DISKLESS)
		return ERR_DISK_CONFIGURED;

	buffer = bsr_md_get_buffer(device, __func__);
	if (!buffer)
		return ERR_NOMEM;

	/* First, figure out where our meta data superblock is located,
	 * and read it. */
	bdev->md.meta_dev_idx = bdev->disk_conf->meta_dev_idx;
	bdev->md.md_offset = bsr_md_ss(bdev);
	/* Even for (flexible or indexed) external meta data,
	 * initially restrict us to the 4k superblock for now.
	 * Affects the paranoia out-of-range access check in bsr_md_sync_page_io(). */
	bdev->md.md_size_sect = 8;

	if (bsr_md_sync_page_io(device, bdev, bdev->md.md_offset,
		REQ_OP_READ)) {
		/* NOTE: can't do normal error processing here as this is
		   called BEFORE disk is attached */
		bsr_err(32, BSR_LC_IO, device, "Failed to read meta-disk.");
		rv = ERR_IO_MD_DISK;
		goto err;
	}

	magic = be32_to_cpu(buffer->magic);
	flags = be32_to_cpu(buffer->flags);
	if (magic == BSR_MD_MAGIC_09 && !(flags & MDF_AL_CLEAN)) {
			/* btw: that's Activity Log clean, not "all" clean. */
		bsr_err(33, BSR_LC_IO, device, "Failed to read meta data due to found unclean meta data. Did you \"bsradm apply-al\"?");
		rv = ERR_MD_UNCLEAN;
		goto err;
	}
	rv = ERR_MD_INVALID;
	if (magic != BSR_MD_MAGIC_09) {
		if (magic == BSR_MD_MAGIC_07 ||
		    magic == BSR_MD_MAGIC_08 ||
		    magic == BSR_MD_MAGIC_84_UNCLEAN)
			bsr_err(34, BSR_LC_IO, device, "Failed to read meta data due to found old meta data magic. Did you \"bsradm create-md\"?");
		else
			bsr_err(35, BSR_LC_IO, device, "Failed to read meta data due to magic not found. Did you \"bsradm create-md\"?");
		goto err;
	}

	if (be32_to_cpu(buffer->bm_bytes_per_bit) != BM_BLOCK_SIZE) {
		bsr_err(36, BSR_LC_IO, device, "Failed to read meta data due to size of the bitmap block set on the meta disk is different. meta(%u) config(%u)",
		    be32_to_cpu(buffer->bm_bytes_per_bit), BM_BLOCK_SIZE);
		goto err;
	}

	if (check_activity_log_stripe_size(device, buffer, &bdev->md))
		goto err;
	if (check_offsets_and_sizes(device, buffer, bdev))
		goto err;


	bdev->md.effective_size = be64_to_cpu(buffer->effective_size);
	bdev->md.current_uuid = be64_to_cpu(buffer->current_uuid);
	bdev->md.flags = be32_to_cpu(buffer->flags);
	bdev->md.device_uuid = be64_to_cpu(buffer->device_uuid);
	bdev->md.node_id = be32_to_cpu(buffer->node_id);

	bdev->md.node_id = be32_to_cpu(buffer->node_id);

	if (bdev->md.node_id != -1 && bdev->md.node_id != my_node_id) {
		bsr_err(37, BSR_LC_IO, device, "Failed to read meta data due to ambiguous node id. meta(%d), config(%d)",
			bdev->md.node_id, my_node_id);
		goto err;
	}

	max_peers = be32_to_cpu(buffer->bm_max_peers);
	for (i = 0; i < BSR_NODE_ID_MAX; i++) {
		struct bsr_peer_md *peer_md = &bdev->md.peers[i];

		peer_md->bitmap_uuid = be64_to_cpu(buffer->peers[i].bitmap_uuid);
		peer_md->bitmap_dagtag = be64_to_cpu(buffer->peers[i].bitmap_dagtag);
		peer_md->flags = be32_to_cpu(buffer->peers[i].flags);
		peer_md->bitmap_index = be32_to_cpu(buffer->peers[i].bitmap_index);

		if (peer_md->bitmap_index == -1)
			continue;
		if (i == my_node_id) {
			bsr_err(41, BSR_LC_IO, device, "Failed to read meta data due to my own node id (%d) should not have a bitmap index (%d)",
				my_node_id, peer_md->bitmap_index);
			goto err;
		}

		if (peer_md->bitmap_index < -1 || peer_md->bitmap_index >= (int)max_peers) {
			bsr_err(42, BSR_LC_IO, device, "Failed to read meta data due to peer node id %d: bitmap index (%d) exceeds allocated bitmap slots (%d)",
				i, peer_md->bitmap_index, max_peers);
			goto err;
		}
		/* maybe: for each bitmap_index != -1, create a connection object
		 * with peer_node_id = i, unless already present. */
	}
	BUILD_BUG_ON(ARRAY_SIZE(bdev->md.history_uuids) != ARRAY_SIZE(buffer->history_uuids));
	for (i = 0; i < ARRAY_SIZE(buffer->history_uuids); i++)
		bdev->md.history_uuids[i] = be64_to_cpu(buffer->history_uuids[i]);

	rv = ERR_NO;
 err:
	bsr_md_put_buffer(device);

	return rv;
}

/**
 * bsr_md_mark_dirty() - Mark meta data super block as dirty
 * @device:	BSR device.
 *
 * Call this function if you change anything that should be written to
 * the meta-data super block. This function sets MD_DIRTY, and starts a
 * timer that ensures that within five seconds you have to call bsr_md_sync().
 */
#ifdef BSR_DEBUG_MD_SYNC
void bsr_md_mark_dirty_(struct bsr_device *device, unsigned int line, const char *func)
{
	if (!test_and_set_bit(MD_DIRTY, &device->flags)) {
		mod_timer(&device->md_sync_timer, jiffies + HZ);
		device->last_md_mark_dirty.line = line;
		device->last_md_mark_dirty.func = func;
	}
}
#else
void bsr_md_mark_dirty(struct bsr_device *device)
{
	if (!test_and_set_bit(MD_DIRTY, &device->flags))
		mod_timer(&device->md_sync_timer, jiffies + 5*HZ);
}
#endif

void _bsr_uuid_push_history(struct bsr_device *device, u64 val, u64 *old_val) __must_hold(local)
{
	struct bsr_md *md = &device->ldev->md;
	int i;

	if (val == UUID_JUST_CREATED)
		return;
	val &= ~1;  /* The lowest bit only indicates that the node was primary */

	for (i = 0; i < ARRAY_SIZE(md->history_uuids); i++) {
		if (md->history_uuids[i] == val)
			return;
	}

	// BSR-863
	if (old_val) {
		*old_val = md->history_uuids[ARRAY_SIZE(md->history_uuids) - 1];
	}

	for (i = ARRAY_SIZE(md->history_uuids) - 1; i > 0; i--)
		md->history_uuids[i] = md->history_uuids[i - 1];
	md->history_uuids[i] = val;
}

u64 _bsr_uuid_pull_history(struct bsr_peer_device *peer_device, u64 *val) __must_hold(local)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_md *md = &device->ldev->md;
	u64 first_history_uuid;
	int i;

	first_history_uuid = md->history_uuids[0];
	for (i = 0; i < ARRAY_SIZE(md->history_uuids) - 1; i++)
		md->history_uuids[i] = md->history_uuids[i + 1];

	if (val) {
		md->history_uuids[i] = *val;
	}
	else {
		md->history_uuids[i] = 0;
	}

	return first_history_uuid;
}

static void __bsr_uuid_set_current(struct bsr_device *device, u64 val, u64 *current_val, const char* caller)
{
	bsr_md_mark_dirty(device);
	if (device->resource->role[NOW] == R_PRIMARY)
		val |= UUID_PRIMARY;
	else
		val &= ~UUID_PRIMARY;

	if (current_val)
		*current_val = device->ldev->md.current_uuid;

	device->ldev->md.current_uuid = val;
	bsr_info(26, BSR_LC_UUID, device, "%s => update current UUID: %016llX", caller, device->ldev->md.current_uuid);
	bsr_set_exposed_data_uuid(device, val);
}

void __bsr_uuid_set_bitmap(struct bsr_peer_device *peer_device, u64 val)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_md *peer_md = &device->ldev->md.peers[peer_device->node_id];

	bsr_md_mark_dirty(device);
	peer_md->bitmap_uuid = val;
	peer_md->bitmap_dagtag = val ? device->resource->dagtag_sector : 0;
}

void _bsr_uuid_set_current(struct bsr_device *device, u64 val) __must_hold(local)
{
	unsigned long flags;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	__bsr_uuid_set_current(device, val, NULL, __FUNCTION__);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
}

void _bsr_uuid_set_bitmap(struct bsr_peer_device *peer_device, u64 val) __must_hold(local)
{
	struct bsr_device *device = peer_device->device;
	unsigned long flags;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	__bsr_uuid_set_bitmap(peer_device, val);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
}

void bsr_uuid_set_bitmap(struct bsr_peer_device *peer_device, u64 uuid) __must_hold(local)
{
	struct bsr_device *device = peer_device->device;
	unsigned long flags;
	u64 previous_uuid;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	previous_uuid = bsr_bitmap_uuid(peer_device);
	if (previous_uuid)
		_bsr_uuid_push_history(device, previous_uuid, NULL);
	__bsr_uuid_set_bitmap(peer_device, uuid);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
}

static u64 rotate_current_into_bitmap(struct bsr_device *device, u64 weak_nodes, u64 dagtag) __must_hold(local)
{
	struct bsr_peer_md *peer_md = device->ldev->md.peers;
	struct bsr_peer_device *peer_device;
	int node_id;
	u64 bm_uuid, got_new_bitmap_uuid = 0;
	bool do_it;

	rcu_read_lock();
	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		if (node_id == device->ldev->md.node_id)
			continue;

		// DW-1360 skip considering to rotate uuid for node which doesn't exist.
		if (peer_md[node_id].bitmap_index == -1 &&
			!(peer_md[node_id].flags & MDF_NODE_EXISTS)) {
			// BSR-692 do not skip the node if UUID is in its initial state and no connecting object has been created.
			if (!((device->ldev->md.current_uuid == UUID_JUST_CREATED) &&
				list_empty(&device->resource->connections))) 
				continue;
		}

		bm_uuid = peer_md[node_id].bitmap_uuid;
		if (bm_uuid)
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device) {
			enum bsr_disk_state pdsk = peer_device->disk_state[NOW];
			
			do_it = (pdsk <= D_UNKNOWN && pdsk != D_NEGOTIATING) ||
				(NODE_MASK(node_id) & weak_nodes);

			// DW-1195 bump current uuid when disconnecting with inconsistent peer.
			do_it = do_it || ((peer_device->connection->cstate[NEW] < C_CONNECTED) && (pdsk == D_INCONSISTENT));

		} else {
			do_it = true;
		}
		if (do_it) {
			peer_md[node_id].bitmap_uuid =
				device->ldev->md.current_uuid != UUID_JUST_CREATED ?
				device->ldev->md.current_uuid : 0;

			if (peer_md[node_id].bitmap_uuid) 
				bsr_info(20, BSR_LC_UUID, peer_device, "rotate bitmap uuid %016llX", peer_md[node_id].bitmap_uuid);

			if (peer_md[node_id].bitmap_uuid)
				peer_md[node_id].bitmap_dagtag = dagtag;
			bsr_md_mark_dirty(device);
			got_new_bitmap_uuid |= NODE_MASK(node_id);
		}
	}
	rcu_read_unlock();

	return got_new_bitmap_uuid;
}

static u64 initial_resync_nodes(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;
	u64 nodes = 0;

	for_each_peer_device(peer_device, device) {
		if (peer_device->disk_state[NOW] == D_INCONSISTENT &&
		    peer_device->repl_state[NOW] == L_ESTABLISHED)
			nodes |= NODE_MASK(peer_device->node_id);
	}

	return nodes;
}

u64 bsr_weak_nodes_device(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;
	u64 not_weak = NODE_MASK(device->resource->res_opts.node_id);

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum bsr_disk_state pdsk = peer_device->disk_state[NOW];
		if (!(pdsk <= D_FAILED || pdsk == D_UNKNOWN || pdsk == D_OUTDATED))
			not_weak |= NODE_MASK(peer_device->node_id);

	}
	rcu_read_unlock();

	return ~not_weak;
}

// BSR-967 add arguments for younger primary
static void __bsr_uuid_new_current(struct bsr_device *device, bool forced, bool send, bool younger, const char* caller) __must_hold(local)
{
	struct bsr_peer_device *peer_device;
	u64 got_new_bitmap_uuid, weak_nodes, val;

	spin_lock_irq(&device->ldev->md.uuid_lock);
	got_new_bitmap_uuid = rotate_current_into_bitmap(device,
					forced ? initial_resync_nodes(device) : 0,
					device->resource->dagtag_sector);

	if (!got_new_bitmap_uuid) {
		spin_unlock_irq(&device->ldev->md.uuid_lock);
		return;
	}

	get_random_bytes(&val, sizeof(u64));
	__bsr_uuid_set_current(device, val, NULL, __FUNCTION__);
	spin_unlock_irq(&device->ldev->md.uuid_lock);
	weak_nodes = bsr_weak_nodes_device(device);
	bsr_info(3, BSR_LC_UUID, device, "%s, %016llX UUID has been generated. weak nodes %016llX", caller,
		  device->ldev->md.current_uuid, weak_nodes);

	// BSR-676 notify uuid
	bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);

	/* get it to stable storage _now_ */
	bsr_md_sync(device);
	if (!send)
		return;

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED) {
			u64 uuid_flags = 0;
			if (!forced) {
				// BSR-967 younger primary sets UUID_FLAG_NEW_DATAGEN only when the peer node is not in D_INCONSISTENT state.
				if (!younger ||
					(younger && peer_device->disk_state[NOW] != D_INCONSISTENT)) {
					uuid_flags = UUID_FLAG_NEW_DATAGEN;
				}
			}
			clear_bit(UUID_DELAY_SEND, &peer_device->flags);
			bsr_send_uuids(peer_device, uuid_flags, weak_nodes, NOW);
		} else {
			// BSR-1019 if connected, set the flag to send uuid before bitmap exchange.
			if (peer_device->connection->cstate[NOW] == C_CONNECTED) 
				set_bit(UUID_DELAY_SEND, &peer_device->flags);
		}
	}
}

/**
 * bsr_uuid_new_current() - Creates a new current UUID
 * @device:	BSR device.
 *
 * Creates a new current UUID, and rotates the old current UUID into
 * the bitmap slot. Causes an incremental resync upon next connect.
 * The caller must hold adm_mutex or conf_update
 */
void bsr_uuid_new_current(struct bsr_device *device, bool forced, bool younger, const char* caller)
{
	if (get_ldev_if_state(device, D_UP_TO_DATE)) {
		__bsr_uuid_new_current(device, forced, true, younger, caller);
		put_ldev(device);
	} else {
		struct bsr_peer_device *peer_device;
		/* The peers will store the new current UUID... */
		u64 current_uuid, weak_nodes;
		get_random_bytes(&current_uuid, sizeof(u64));
		current_uuid &= ~UUID_PRIMARY;
		bsr_set_exposed_data_uuid(device, current_uuid);
		bsr_info(4, BSR_LC_UUID, device, "%s, Sends a new current %016llX UUID.", caller, current_uuid);

		weak_nodes = bsr_weak_nodes_device(device);
		for_each_peer_device(peer_device, device) {
			bsr_send_current_uuid(peer_device, current_uuid, weak_nodes);
			peer_device->current_uuid = current_uuid; /* In case resync finishes soon */
		}
	}
}

void bsr_uuid_new_current_by_user(struct bsr_device *device)
{
	if (get_ldev(device)) {
		__bsr_uuid_new_current(device, false, false, false, __FUNCTION__);
		put_ldev(device);
	}
}

// DW-1145
void bsr_propagate_uuids(struct bsr_device *device, u64 nodes)
{
	struct bsr_peer_device *peer_device;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (!(nodes & NODE_MASK(peer_device->node_id)))
			continue;
		if (peer_device->repl_state[NOW] < L_ESTABLISHED)
			continue;

		if (list_empty(&peer_device->propagate_uuids_work.list))
			bsr_queue_work(&peer_device->connection->sender_work,
					&peer_device->propagate_uuids_work);
	}
	rcu_read_unlock();
}

void bsr_uuid_received_new_current(struct bsr_peer_device *peer_device, u64 val, u64 weak_nodes) __must_hold(local)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_device *target;
	u64 dagtag = peer_device->connection->last_dagtag_sector;
	u64 got_new_bitmap_uuid = 0;
	bool set_current = true;

	spin_lock_irq(&device->ldev->md.uuid_lock);

	for_each_peer_device(target, device) {
		// BSR-1016 during resync that started without out of sync, the received UUId is updated.
		if (((target->repl_state[NOW] == L_SYNC_TARGET) && target->rs_total) ||
			target->repl_state[NOW] == L_PAUSED_SYNC_T ||
			// BSR-242 Added a condition because there was a problem applying new UUID during synchronization.
			target->repl_state[NOW] == L_BEHIND ||
			(target->repl_state[NOW] == L_WF_BITMAP_T &&
			// BSR-974 If it is weak_node when L_WF_BITMAP_T state, it does not update the UUID.
			NODE_MASK(device->resource->res_opts.node_id) & weak_nodes)) {
			target->current_uuid = val;
			set_current = false;
		}
	}

	// DW-1340 do not update current uuid if my disk is outdated. the node sent uuid has my current uuid as bitmap uuid, and will start resync as soon as we do handshake.
	if (device->disk_state[NOW] == D_OUTDATED) {
		// BSR-974 If it is weak_node when D_OUTDATED state, it does not update the UUID.
		if (NODE_MASK(device->resource->res_opts.node_id) & weak_nodes) 
			set_current = false;
	}

	if (set_current) {

		// DW-1034 split-brain could be caused since old one's been extinguished, always preserve old one when setting new one.
		got_new_bitmap_uuid = rotate_current_into_bitmap(device, weak_nodes, dagtag);
		__bsr_uuid_set_current(device, val, NULL, __FUNCTION__);
		// DW-837 Apply updated current uuid to meta disk.
		bsr_md_mark_dirty(device);
		// BSR-767 notify uuid When the new current uuid is received and changed
		bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
	}
	else
		bsr_warn(15, BSR_LC_UUID, peer_device, "receive new current but not update UUID: %016llX", peer_device->current_uuid);

	spin_unlock_irq(&device->ldev->md.uuid_lock);

	if(set_current) {
		// DW-977 Send current uuid as soon as set it to let the node which created uuid update mine.
		bsr_send_current_uuid(peer_device, val, bsr_weak_nodes_device(device));
	}
	bsr_propagate_uuids(device, got_new_bitmap_uuid);
}

static u64 __set_bitmap_slots(struct bsr_device *device, struct bsr_peer_device *peer_device, struct bsr_peer_md *old_peer_md, u64 do_nodes) __must_hold(local)
{
	struct bsr_peer_md *peer_md = device->ldev->md.peers;
	u64 modified = 0;
	int node_id;
	u64 bitmap_uuid = 0;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		if (node_id == device->ldev->md.node_id)
			continue;
		if (!(do_nodes & NODE_MASK(node_id)))
			continue;

		// BSR-189 Update the SyncSource's bitmap_uuids to SyncTarget's bitmap_uuids.
		if (peer_device)
			bitmap_uuid = peer_device->bitmap_uuids[node_id];

		if (peer_md[node_id].bitmap_uuid != bitmap_uuid) {
			// BSR-863
			if (old_peer_md) {
				old_peer_md[node_id].bitmap_uuid = peer_md[node_id].bitmap_uuid;
				old_peer_md[node_id].bitmap_dagtag = peer_md[node_id].bitmap_dagtag;
			}

			_bsr_uuid_push_history(device, peer_md[node_id].bitmap_uuid, NULL);
			/* bsr_info(10, BSR_LC_ETC, device, "bitmap[node_id=%d] = %llX", node_id, bitmap_uuid); */
			peer_md[node_id].bitmap_uuid = bitmap_uuid;
			peer_md[node_id].bitmap_dagtag =
				bitmap_uuid ? device->resource->dagtag_sector : 0;
			bsr_md_mark_dirty(device);
			modified |= NODE_MASK(node_id);
		}
	}

	return modified;
}

static u64 __test_bitmap_slots_of_peer(struct bsr_peer_device *peer_device) __must_hold(local)
{
	u64 set_bitmap_slots = 0;
	int node_id;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		// DW-1113 identical current uuid means they've cleared each other's bitmap uuid, while I haven't known it.
		struct bsr_peer_device *found_peer = peer_device_by_node_id(peer_device->device, node_id);
		if (peer_device->bitmap_uuids[node_id] &&
			found_peer &&
			((peer_device->current_uuid & ~UUID_PRIMARY) != (found_peer->current_uuid & ~UUID_PRIMARY)))
			set_bitmap_slots |= NODE_MASK(node_id);
	}

	return set_bitmap_slots;
}


u64 bsr_uuid_resync_finished(struct bsr_peer_device *peer_device, struct bsr_peer_md *old_peer_md, u64 *removed_history, u64 *before_uuid) __must_hold(local)
{
	struct bsr_device *device = peer_device->device;
	u64 set_bitmap_slots, newer, equal;
	unsigned long flags;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	set_bitmap_slots = __test_bitmap_slots_of_peer(peer_device);
	// BSR-189 Update the SyncSource's bitmap_uuids to SyncTarget's bitmap_uuids.
	newer = __set_bitmap_slots(device, peer_device, old_peer_md, set_bitmap_slots);
	equal = __set_bitmap_slots(device, NULL, old_peer_md, ~set_bitmap_slots);
	_bsr_uuid_push_history(device, bsr_current_uuid(device), removed_history);
	__bsr_uuid_set_current(device, peer_device->current_uuid, before_uuid, __FUNCTION__);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);

	return newer;
}

// BSR-863
static u64 __rollback_bitmap_slots(struct bsr_device *device, struct bsr_peer_device *peer_device, struct bsr_peer_md *old_peer_md, u64 do_nodes) __must_hold(local)
{
	struct bsr_peer_md *peer_md = device->ldev->md.peers;
	u64 modified = 0;
	int node_id;
	u64 bitmap_uuid = 0;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		if (node_id == device->ldev->md.node_id)
			continue;
		if (!(do_nodes & NODE_MASK(node_id)))
			continue;

		if (peer_md[node_id].bitmap_uuid != bitmap_uuid) {
			peer_md[node_id].bitmap_uuid = old_peer_md[node_id].bitmap_uuid;
			peer_md[node_id].bitmap_dagtag = old_peer_md[node_id].bitmap_dagtag;
			bsr_md_mark_dirty(device);
			modified |= NODE_MASK(node_id);
		}
	}

	return modified;
}

// BSR-863
u64 bsr_uuid_resync_finished_rollback(struct bsr_peer_device *peer_device, u64 do_nodes, u64 uuid, struct bsr_peer_md *peer_md, u64 history) __must_hold(local)
{
	struct bsr_device *device = peer_device->device;
	unsigned long flags;
	u64 newer;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);

	_bsr_uuid_pull_history(peer_device, &history);
	newer = __rollback_bitmap_slots(device, peer_device, peer_md, do_nodes);
	device->ldev->md.current_uuid = uuid;
	bsr_set_exposed_data_uuid(device, uuid);
	
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);

	return newer;
}

static const char* name_of_node_id(struct bsr_resource *resource, int node_id)
{
	/* Caller need to hold rcu_read_lock */
	struct bsr_connection *connection = bsr_connection_by_node_id(resource, node_id);

	return connection ? rcu_dereference(connection->transport.net_conf)->name : "";
}

void forget_bitmap(struct bsr_device *device, int node_id) __must_hold(local) // DW-955
{
	int bitmap_index = device->ldev->md.peers[node_id].bitmap_index;
	const char* name;

	// DW-1843
	/*
	 * When an io error occurs on the primary node, oos is recorded with up_to_date maintained. 
	 * Therefore, when changing status to secondary, it is recognized as inconsistent oos and deleted through forget_bitmap. 
	 * To prevent it, use MDF_PRIMARY_IO_ERROR.
	 */
	if (_bsr_bm_total_weight(device, bitmap_index) == 0)
		return;

	spin_unlock_irq(&device->ldev->md.uuid_lock);
	rcu_read_lock();
	name = name_of_node_id(device->resource, node_id);
	bsr_info(5, BSR_LC_UUID, device, "Clearing bitmap UUID and content (%llu bits) for node %d (%s)(slot %d)",
		  (unsigned long long)_bsr_bm_total_weight(device, bitmap_index), node_id, name, bitmap_index);
	rcu_read_unlock();
	bsr_suspend_io(device, WRITE_ONLY);
	bsr_bm_lock(device, "forget_bitmap()", BM_LOCK_TEST | BM_LOCK_SET);
	bsr_bm_clear_many_bits(device, bitmap_index, 0, BSR_END_OF_BITMAP);
	bsr_bm_unlock(device);
	bsr_resume_io(device);
	bsr_md_mark_dirty(device);
	spin_lock_irq(&device->ldev->md.uuid_lock);
}

#if 0 // not used
static void copy_bitmap(struct bsr_device *device, int from_id, int to_id) __must_hold(local)
{
	int from_index = device->ldev->md.peers[from_id].bitmap_index;
	int to_index = device->ldev->md.peers[to_id].bitmap_index;
	const char *from_name, *to_name;

	spin_unlock_irq(&device->ldev->md.uuid_lock);
	rcu_read_lock();
	from_name = name_of_node_id(device->resource, from_id);
	to_name = name_of_node_id(device->resource, to_id);
	bsr_info(27, BSR_LC_ETC, device, "Node %d (%s) synced up to node %d (%s). copying bitmap slot %d to %d.",
		  to_id, to_name, from_id, from_name, from_index, to_index);
	rcu_read_unlock();
	bsr_suspend_io(device, WRITE_ONLY);
	bsr_bm_lock(device, "copy_bitmap()", BM_LOCK_ALL);
	bsr_bm_copy_slot(device, from_index, to_index);
	bsr_bm_unlock(device);
	bsr_resume_io(device);
	bsr_md_mark_dirty(device);
	spin_lock_irq(&device->ldev->md.uuid_lock);
}
#endif

#if 0 // not used.
static int find_node_id_by_bitmap_uuid(struct bsr_device *device, u64 bm_uuid) __must_hold(local)
{
	struct bsr_peer_md *peer_md = device->ldev->md.peers;
	int node_id;

	bm_uuid &= ~UUID_PRIMARY;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		if ((peer_md[node_id].bitmap_uuid & ~UUID_PRIMARY) == bm_uuid &&
		    peer_md[node_id].bitmap_index != -1)
			return node_id;
	}

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		if ((peer_md[node_id].bitmap_uuid & ~UUID_PRIMARY) == bm_uuid)
			return node_id;
	}

	return -1;
}
#endif

#if 0 // not used.
static bool node_connected(struct bsr_resource *resource, int node_id)
{
	struct bsr_connection *connection;
	bool r = false;

	rcu_read_lock();
	connection = bsr_connection_by_node_id(resource, node_id);
	if (connection)
		r = connection->cstate[NOW] == C_CONNECTED;
	rcu_read_unlock();

	return r;
}
#endif

#if 0 // not used.
static bool detect_copy_ops_on_peer(struct bsr_peer_device *peer_device) __must_hold(local)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_md *peer_md = device->ldev->md.peers;
	struct bsr_resource *resource = device->resource;
	int node_id1, node_id2, from_id;
	u64 peer_bm_uuid;
	bool modified = false;

	for (node_id1 = 0; node_id1 < BSR_NODE_ID_MAX; node_id1++) {
		if (device->ldev->md.peers[node_id1].bitmap_index == -1)
			continue;

		if (node_connected(resource, node_id1))
			continue;

		peer_bm_uuid = peer_device->bitmap_uuids[node_id1] & ~UUID_PRIMARY;
		if (!peer_bm_uuid)
			continue;

		for (node_id2 = node_id1 + 1; node_id2 < BSR_NODE_ID_MAX; node_id2++) {
			if (device->ldev->md.peers[node_id2].bitmap_index == -1)
				continue;

			if (node_connected(resource, node_id2))
				continue;

		if (peer_bm_uuid == (peer_device->bitmap_uuids[node_id2] & ~UUID_PRIMARY))
				goto found;
		}
	}
	return false;

found:
	from_id = find_node_id_by_bitmap_uuid(device, peer_bm_uuid);
	if (from_id == -1) {
		if (peer_md[node_id1].bitmap_uuid == 0 && peer_md[node_id2].bitmap_uuid == 0)
			return false;
		bsr_err(28, BSR_LC_ETC, peer_device, "unexpected");
		bsr_err(29, BSR_LC_ETC, peer_device, "In UUIDs from node %d found equal UUID (%llX) for nodes %d %d",
			 peer_device->node_id, peer_bm_uuid, node_id1, node_id2);
		bsr_err(30, BSR_LC_ETC, peer_device, "I have %llX for node_id=%d",
			 peer_md[node_id1].bitmap_uuid, node_id1);
		bsr_err(31, BSR_LC_ETC, peer_device, "I have %llX for node_id=%d",
			 peer_md[node_id2].bitmap_uuid, node_id2);
		return false;
	}

	if (peer_md[from_id].bitmap_index == -1)
		return false;

	if (from_id != node_id1 &&
	    peer_md[node_id1].bitmap_uuid != peer_bm_uuid) {
		peer_md[node_id1].bitmap_uuid = peer_bm_uuid;
		peer_md[node_id1].bitmap_dagtag = peer_md[from_id].bitmap_dagtag;
		copy_bitmap(device, from_id, node_id1);
		modified = true;

	}
	if (from_id != node_id2 &&
	    peer_md[node_id2].bitmap_uuid != peer_bm_uuid) {
		peer_md[node_id2].bitmap_uuid = peer_bm_uuid;
		peer_md[node_id2].bitmap_dagtag = peer_md[from_id].bitmap_dagtag;
		copy_bitmap(device, from_id, node_id2);
		modified = true;
	}

	return modified;
}
#endif

void bsr_uuid_detect_finished_resyncs(struct bsr_peer_device *peer_device) __must_hold(local)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_md *peer_md = device->ldev->md.peers;
	int node_id;
	bool write_bm = false;
	bool filled = false;

	spin_lock_irq(&device->ldev->md.uuid_lock);
	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		if (node_id == device->ldev->md.node_id)
			continue;

		if (peer_md[node_id].bitmap_index == -1 && !(peer_md[node_id].flags & MDF_NODE_EXISTS))
			continue;

		// DW-978 Need to check if uuid has to be propagated even if bitmap_uuid is 0, it could be set -1 during sent, check the flag 'MDF_PEER_DIFF_CUR_UUID'.
		if (peer_device->bitmap_uuids[node_id] == 0 && (peer_md[node_id].bitmap_uuid != 0 || (peer_md[node_id].flags & MDF_PEER_DIFF_CUR_UUID))) {
			u64 peer_current_uuid = peer_device->current_uuid & ~UUID_PRIMARY;
			//int from_node_id;

			if (peer_current_uuid == (bsr_current_uuid(device) & ~UUID_PRIMARY)) {
				// DW-978
				// DW-979
				// DW-980
				// bitmap_uuid was already '0', just clear_flag and bsr_propagate_uuids().
				if((peer_md[node_id].bitmap_uuid == 0) && (peer_md[node_id].flags & MDF_PEER_DIFF_CUR_UUID))
					goto clear_flag;
				_bsr_uuid_push_history(device, peer_md[node_id].bitmap_uuid, NULL);
				peer_md[node_id].bitmap_uuid = 0;
				if (node_id == peer_device->node_id) {
					bsr_print_uuids(peer_device, "updated UUIDs", __FUNCTION__);
				}
				else if (peer_md[node_id].bitmap_index != -1) {
					// DW-955 
					// DW-1116
					// DW-1131 do not forget bitmap if peer is not forgettable state.
					struct bsr_peer_device *found_peer = peer_device_by_node_id(device, node_id);
					
					if (found_peer &&
						isForgettableReplState(found_peer->repl_state[NOW])
						&& !bsr_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR)) {
						// DW-955 print log to recognize where forget_bitmap is called.
						bsr_info(38, BSR_LC_BITMAP, device, "Bitmap will be cleared due to other resync. peer disk(%s), peer repl(%s), peer dirty(%llu), peer flags(%llx)",
							bsr_disk_str(found_peer->disk_state[NOW]), bsr_repl_str(found_peer->repl_state[NOW]), found_peer->dirty_bits, (unsigned long long)found_peer->flags);
						forget_bitmap(device, node_id);
					}					
				}
				else
					bsr_info(6, BSR_LC_UUID, device, "Clearing bitmap UUID for node %d",
						  node_id);
				bsr_md_mark_dirty(device);

				// BSR-767 notify uuid when bitmap_uuid is removed
				// BSR-676 notify uuid
				bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
// DW-979
// DW-980
clear_flag:
				// DW-978 Clear the flag once we determine that uuid will be propagated.
				peer_md[node_id].flags &= ~MDF_PEER_DIFF_CUR_UUID;
				write_bm = true;
			}

#if 0 // DW-1099 copying bitmap has a defect, do sync whole out-of-sync until fixed.
			from_node_id = find_node_id_by_bitmap_uuid(device, peer_current_uuid);
			if (from_node_id != -1 && node_id != from_node_id &&
				// DW-978 Copying bitmap here assumed that bitmap uuid wasn't 0, check bitmap uuid again since flag 'MDF_PEER_DIFF_CUR_UUID' is added.
				peer_md[node_id].bitmap_uuid != 0 &&
			    dagtag_newer(peer_md[from_node_id].bitmap_dagtag,
					 peer_md[node_id].bitmap_dagtag)) {
				_bsr_uuid_push_history(device, peer_md[node_id].bitmap_uuid, NULL);
				peer_md[node_id].bitmap_uuid = peer_md[from_node_id].bitmap_uuid;
				peer_md[node_id].bitmap_dagtag = peer_md[from_node_id].bitmap_dagtag;
				if (peer_md[node_id].bitmap_index != -1 &&
				    peer_md[from_node_id].bitmap_index != -1)
					copy_bitmap(device, from_node_id, node_id);
				else
					bsr_info(45, BSR_LC_ETC, device, "Node %d synced up to node %d.",
						  node_id, from_node_id);
				bsr_md_mark_dirty(device);

				// DW-978 Clear the flag once we determine that uuid will be propagated.
				peer_md[node_id].flags &= ~MDF_PEER_DIFF_CUR_UUID;
				filled = true;
			}
#endif
		}
	}


	// DW-955 peer has already cleared my bitmap, or receiving peer_in_sync has been left out. no resync is needed.
	if (bsr_bm_total_weight(peer_device) &&
		peer_device->dirty_bits == 0 &&
		isForgettableReplState(peer_device->repl_state[NOW]) &&
		device->disk_state[NOW] > D_OUTDATED && // DW-1656 no clearing bitmap when disk is Outdated.

		// DW-1633 if the peer has lost a primary and becomes stable, the dstate of peer_device becomes D_CONSISTENT and UUID_FLAG_GOT_STABLE is set.
		// at this time, the reconciliation resync may work, so do not clear the bitmap.
		!((peer_device->disk_state[NOW] == D_CONSISTENT) && (peer_device->uuid_flags & UUID_FLAG_GOT_STABLE)) &&

		(device->disk_state[NOW] == peer_device->disk_state[NOW]) && // DW-1644 DW-1357 clear bitmap when the disk state is same.
		!(peer_device->uuid_authoritative_nodes & NODE_MASK(device->resource->res_opts.node_id)) &&
		(peer_device->current_uuid & ~UUID_PRIMARY) ==
		(bsr_current_uuid(device) & ~UUID_PRIMARY))
	{
		int peer_node_id = peer_device->node_id;
		u64 peer_bm_uuid = peer_md[peer_node_id].bitmap_uuid;
		if (peer_bm_uuid)
			_bsr_uuid_push_history(device, peer_bm_uuid, NULL);
		if (peer_md[peer_node_id].bitmap_index != -1
				&& !bsr_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR)) {
			bsr_info(39, BSR_LC_BITMAP, peer_device, "Bitmap will be cleared due to inconsistent out-of-sync, disk(%s)", bsr_disk_str(device->disk_state[NOW]));
			forget_bitmap(device, peer_node_id);
		}
		bsr_md_mark_dirty(device);
	}

	// DW-1145 clear bitmap if peer has consistent disk with primary's, peer will also clear bitmap.
	if (bsr_bm_total_weight(peer_device) &&
		peer_device->uuid_flags & UUID_FLAG_CONSISTENT_WITH_PRI &&
		is_consistent_with_primary(device, NOW) &&
		(peer_device->current_uuid & ~UUID_PRIMARY) ==
		(bsr_current_uuid(device) & ~UUID_PRIMARY))
	{
		int peer_node_id = peer_device->node_id;
		u64 peer_bm_uuid = peer_md[peer_node_id].bitmap_uuid;
		if (peer_bm_uuid)
			_bsr_uuid_push_history(device, peer_bm_uuid, NULL);
		if (peer_md[peer_node_id].bitmap_index != -1 
				&& !bsr_md_test_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR)) {
			bsr_info(40, BSR_LC_BITMAP, peer_device, "Bitmap will be cleared because peer has consistent disk with primary's");
			forget_bitmap(device, peer_node_id);
		}
		bsr_md_mark_dirty(device);

		if (peer_device->dirty_bits)
			filled = true;
	}

	spin_unlock_irq(&device->ldev->md.uuid_lock);

	if (write_bm || filled) {
		u64 to_nodes = filled ? -1 : ~NODE_MASK(peer_device->node_id);
		bsr_propagate_uuids(device, to_nodes);
		bsr_suspend_io(device, WRITE_ONLY);
		bsr_bm_lock(device, "detect_finished_resyncs()", BM_LOCK_BULK);
		bsr_bm_write(device, NULL);
		bsr_bm_unlock(device);
		bsr_resume_io(device);
	}
}

// DW-1293 it performs fast invalidate(remote) when agreed protocol version is 112 or above, and fast sync options is enabled.
int bsr_bmio_set_all_or_fast(struct bsr_device *device, struct bsr_peer_device *peer_device) __must_hold(local)
{
	int nRet = 0;
	// DW-1293 queued bitmap work increases work count which may prevents io that we need to mount volume.
	bool dec_bm_work_n = false;
	// BSR-653
	bool bSync = true;
	// BSR-832
	int pending_bm_work_n = 0;


	// BSR-52 for sync only current oos after online verify.
	if (test_bit(USE_CURRENT_OOS_FOR_SYNC, &peer_device->flags)) {
		clear_bit(USE_CURRENT_OOS_FOR_SYNC, &peer_device->flags);
		return nRet;
	}

	if (atomic_read(&device->pending_bitmap_work.n)) {
		dec_bm_work_n = true;
		// BSR-832 fix potential deadlock when invalidate-remote in multi-node
		// If the pending_bitmap_work.n value is not 0, IO pending occurs in inc_ap_bio().
		pending_bm_work_n = atomic_xchg(&device->pending_bitmap_work.n, 0);
		// possibly waiting after bsr_suspend_io() in bsr_adm_invalidate_peer()
		wake_up(&device->misc_wait);
	}


// BSR-743
retry:
	if (peer_device->repl_state[NOW] == L_STARTING_SYNC_S) {
		if (peer_device->connection->agreed_pro_version < 112 ||
			!isFastInitialSync() ||
			// BSR-904 on linux, the sync source supports fast sync only when it is mounted.
#ifdef _LIN
			!isDeviceMounted(device) ||
#endif
			!SetOOSAllocatedCluster(device, peer_device, L_SYNC_SOURCE, false, &bSync))
		{
			// BSR-653 whole bitmap set is not performed if is not sync node.
			if (bSync) {
				bsr_warn(161, BSR_LC_RESYNC_OV, peer_device, "Performs a full sync because a fast sync cannot be performed. invalidate(remote), protocol ver(%d), fast sync result(%d)", peer_device->connection->agreed_pro_version, isFastInitialSync());
				if (dec_bm_work_n) {
					// BSR-832
					atomic_add(pending_bm_work_n, &device->pending_bitmap_work.n);
					dec_bm_work_n = false;
				}
				nRet = bsr_bmio_set_n_write(device, peer_device);
			}
		}
	}
	else if (peer_device->repl_state[NOW] == L_STARTING_SYNC_T) {
		if (peer_device->connection->agreed_pro_version < 112 ||
			!isFastInitialSync() ||
			!SetOOSAllocatedCluster(device, peer_device, L_SYNC_TARGET, false, &bSync))
		{
			// BSR-653 whole bitmap set is not performed if is not sync node.
			if (bSync) {
				bsr_warn(162, BSR_LC_RESYNC_OV, peer_device, "Performs a full sync because a fast sync cannot be performed. invalidate(remote), protocol ver(%d), fast sync result(%d)", peer_device->connection->agreed_pro_version, isFastInitialSync());
				if (dec_bm_work_n) {
					// BSR-832
					atomic_add(pending_bm_work_n, &device->pending_bitmap_work.n);
					dec_bm_work_n = false;
				}
				nRet = bsr_bmio_set_all_n_write(device, peer_device);
			}
		}
	}
	else {
		// BSR-743 If repl_state[NEW] is L_STARTING_SYNC_S or L_STARTING_SYNC_T, wait because repl_stat[NOW] will change soon.
		if ((peer_device->repl_state[NEW] == L_STARTING_SYNC_S) || 
			(peer_device->repl_state[NEW] == L_STARTING_SYNC_T)) {
			long t = 0;
			bsr_warn(209, BSR_LC_RESYNC_OV, peer_device, "wait replication state: %s", bsr_repl_str(peer_device->repl_state[NEW]));
			
			wait_event_timeout_ex(device->resource->state_wait,
				((peer_device->repl_state[NOW] == L_STARTING_SYNC_S) || 
					(peer_device->repl_state[NOW] == L_STARTING_SYNC_T)),
				HZ, t);
			if (t)
				goto retry;
				
		}
	
		bsr_warn(208, BSR_LC_RESYNC_OV, peer_device, "Failed to set resync bit with unexpected replication state(%s).", bsr_repl_str(peer_device->repl_state[NOW]));
	}
	

	if (dec_bm_work_n) {
		// BSR-832
		atomic_add(pending_bm_work_n, &device->pending_bitmap_work.n);
		dec_bm_work_n = false;
	}

	return nRet;
}

int bsr_bmio_set_all_n_write(struct bsr_device *device,
			      struct bsr_peer_device *peer_device) __must_hold(local)
{
#ifdef _WIN
	unsigned long flags;
#endif
	struct bsr_peer_device *p;
	
	UNREFERENCED_PARAMETER(peer_device);
#ifdef _WIN
	// DW-2174 acquire al_lock before rcu_read_lock() to avoid deadlock.
	spin_lock_irqsave(&device->al_lock, flags);
#endif
	// DW-1333 set whole bits and update resync extent.
	// BSR-444 add rcu_read_lock()
	rcu_read_lock();
	for_each_peer_device_rcu(p, device) {
		if (!update_sync_bits(p, 0, bsr_bm_bits(device), SET_OUT_OF_SYNC, true)) {
			bsr_err(41, BSR_LC_BITMAP, device, "Failed to set range bit out of sync, no sync bit has been set for peer node(%d), set whole bits without updating resync extent instead.", p->node_id);
			bsr_bm_set_many_bits(p, 0, BSR_END_OF_BITMAP);
		}
	}
	rcu_read_unlock();
#ifdef _WIN
	spin_unlock_irqrestore(&device->al_lock, flags);
#endif
	return bsr_bm_write(device, NULL);
}

/**
 * bsr_bmio_set_n_write() - io_fn for bsr_queue_bitmap_io() or bsr_bitmap_io()
 * @device:	BSR device.
 *
 * Sets all bits in the bitmap and writes the whole bitmap to stable storage.
 */
int bsr_bmio_set_n_write(struct bsr_device *device,
			  struct bsr_peer_device *peer_device) __must_hold(local)
{
	int rv = -EIO;

	bsr_md_set_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
	bsr_md_sync(device);
	// DW-1333 set whole bits and update resync extent.
	if (!update_sync_bits(peer_device, 0, bsr_bm_bits(device), SET_OUT_OF_SYNC, false)) {
		bsr_err(42, BSR_LC_BITMAP, peer_device, "Failed to set range bit out of sync, no sync bit has been set, set whole bits without updating resync extent instead.");
		bsr_bm_set_many_bits(peer_device, 0, BSR_END_OF_BITMAP);
	}

	rv = bsr_bm_write(device, NULL);

	if (!rv) {
		bsr_md_clear_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
		bsr_md_sync(device);
	}

	return rv;
}

// DW-844
#define GetBitPos(bytes, bitsInByte)	((bytes * BITS_PER_BYTE) + bitsInByte)
			  
// set out-of-sync from provided bitmap
ULONG_PTR SetOOSFromBitmap(PVOLUME_BITMAP_BUFFER pBitmap, struct bsr_peer_device *peer_device)
{
	ULONG_PTR llStartBit = BSR_END_OF_BITMAP, llEndBit = BSR_END_OF_BITMAP;
	ULONG_PTR count = 0;
	PCHAR pByte = NULL;
	
	ULONG_PTR bitmapSize;
	ULONG_PTR llBytePos;
	short llBitPosInByte;

	
	if (NULL == pBitmap ||
		NULL == pBitmap->Buffer ||
		NULL == peer_device)
	{
		bsr_err(43, BSR_LC_BITMAP, peer_device, "Failed to set bit out of sync due to invalid parameter, bitmap(0x%p), buffer(0x%p) peer device(0x%p)", pBitmap, pBitmap ? pBitmap->Buffer : NULL, peer_device);
#ifdef _WIN
		return UINT64_MAX;
#else	// _LIN
		return -1;
#endif
	}

	pByte = (PCHAR)pBitmap->Buffer;
#ifdef _WIN
	bitmapSize = (ULONG_PTR)pBitmap->BitmapSize.QuadPart;
#else
	bitmapSize = (ULONG_PTR)pBitmap->BitmapSize;
#endif
	// find continuously set bits and set out-of-sync.
	for (llBytePos = 0; llBytePos < bitmapSize; llBytePos++) {
		for (llBitPosInByte = 0; llBitPosInByte < BITS_PER_BYTE; llBitPosInByte++) {
			CHAR pBit = (pByte[llBytePos] >> llBitPosInByte) & 0x1;

			// found first set bit.
			if (llStartBit == BSR_END_OF_BITMAP &&
				pBit == 1)
			{
				llStartBit = (ULONG_PTR)GetBitPos(llBytePos, llBitPosInByte);
				continue;
			}

			// found last set bit. set out-of-sync.
			if (llStartBit != BSR_END_OF_BITMAP &&
				pBit == 0)
			{
				llEndBit = (ULONG_PTR)GetBitPos(llBytePos, llBitPosInByte) - 1;
				count += update_sync_bits(peer_device, llStartBit, llEndBit, SET_OUT_OF_SYNC, false);

				llStartBit = BSR_END_OF_BITMAP;
				llEndBit = BSR_END_OF_BITMAP;
				continue;
			}
		}
#ifdef _LIN
		// BSR-823 cpu occupancy prevention
		cond_resched();
#endif
	}

	// met last bit while finding zero bit.
	if (llStartBit != BSR_END_OF_BITMAP) {
		llEndBit = (ULONG_PTR)bitmapSize * BITS_PER_BYTE - 1;	// last cluster
		count += update_sync_bits(peer_device, llStartBit, llEndBit, SET_OUT_OF_SYNC, false);

		llStartBit = BSR_END_OF_BITMAP;
		llEndBit = BSR_END_OF_BITMAP;
	}

	return count;
}

// BSR-1001
void check_remaining_out_of_sync(struct bsr_device* device) {
	struct bsr_peer_device *peer_device;
	ULONG_PTR bm_total;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->disk_state[NOW] == D_UP_TO_DATE &&
			peer_device->repl_state[NOW] == L_ESTABLISHED) {
			bm_total = bsr_bm_total_weight(peer_device);
			if (bm_total)
				bsr_info(217, BSR_LC_RESYNC_OV, peer_device, "The remaining out of sync is %llu", bm_total);
		}
	}
	rcu_read_unlock();
}
// BSR-904
#ifdef _LIN
bool isDeviceMounted(struct bsr_device *device)
{
	// if the UUID is UUID_JUST_CREATED at the time of promotion, it operates as fast sync regardless of whether it is mounted or not.
	if(test_bit(UUID_WERE_INITIAL_BEFORE_PROMOTION, &device->flags)) 
		return true;

	if(atomic_read(&device->mounted_cnt) > 0) 
		return true;

	bsr_warn(216, BSR_LC_RESYNC_OV, device, "Fast sync is disable because device not mounted");
	return false;
}
#endif

bool isFastInitialSync()
{
	bool bRet = false;
#ifdef _WIN
	ULONG ulLength = 0;
	int nTemp = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PROOT_EXTENSION pRootExtension = NULL;

	pRootExtension = mvolRootDeviceObject->DeviceExtension;

	if (NULL != pRootExtension) {
		status = GetRegistryValue(L"use_fast_sync", &ulLength, (UCHAR*)&nTemp, &pRootExtension->RegistryPath);
		if (status == STATUS_SUCCESS)
			bRet = (nTemp ? TRUE : FALSE);
	}

#else // _LIN
#ifdef _LIN_FAST_SYNC
	// BSR-643 read from file
	bRet = read_reg_file("/etc/bsr.d/.use_fast_sync", 1);
#else
	bRet = false;
#endif
#endif
	bsr_info(10, BSR_LC_RESYNC_OV, NO_OBJECT, "Fast sync is %s on resync with the current connection.", bRet ? "enabled" : "disabled");
	
	return bRet;
}




/* bsr assumes bytes per cluster as 4096. convert if need.
ex:
      2048 bytes    ->    4096 bytes
       00110100              0110

        16 kb       ->    4096 bytes
        0110           00001111 11110000
*/
bool ConvertVolumeBitmap(PVOLUME_BITMAP_BUFFER pVbb, PCHAR pConverted, ULONG bytesPerCluster, ULONG ulBsrBitmapUnit)
{
	int readCount = 1;
	int writeCount = 1;
	PCHAR pByte;
	
	LONGLONG ullBytePos;
	LONGLONG ullBitPos;
	LONGLONG bitmapSize;
		
	if (NULL == pVbb ||
		NULL == pVbb->Buffer ||
		NULL == pConverted)
	{
		bsr_err(68, BSR_LC_BITMAP, NO_OBJECT, "Failed to convert volume bitmap due to invalid parameter, volume bitmap(0x%p), buffer(0x%p), converted(0x%p)", pVbb, pVbb ? pVbb->Buffer : NULL, pConverted);
		return false;
	}

	writeCount = (bytesPerCluster / ulBsrBitmapUnit) + (bytesPerCluster < ulBsrBitmapUnit);	// bsr bits count affected by a bit of volume bitmap. maximum value : 16
	readCount = (ulBsrBitmapUnit / bytesPerCluster) + (bytesPerCluster > ulBsrBitmapUnit);	// volume bits count to be converted into a bsr bit. maximum value : 8
	
	pByte = (PCHAR)pVbb->Buffer;
#ifdef _WIN
	bitmapSize = (pVbb->BitmapSize.QuadPart + 1) / BITS_PER_BYTE;
#else // _LIN
	bitmapSize = pVbb->BitmapSize;
#endif

	for (ullBytePos = 0; ullBytePos < bitmapSize; ullBytePos += 1) {
		for (ullBitPos = 0; ullBitPos < BITS_PER_BYTE; ullBitPos += readCount) {
			CHAR pBit = (pByte[ullBytePos] >> ullBitPos) & ((1 << readCount) - 1);

			if (pBit) {
				LONGLONG ullBitPosTotal = ((ullBytePos * BITS_PER_BYTE + ullBitPos) * writeCount) / readCount;
				LONGLONG ullByte = ullBitPosTotal / BITS_PER_BYTE;
				LONGLONG ullBitPosInByte = ullBitPosTotal % BITS_PER_BYTE;
				int i;
				for (i = 0; i <= (writeCount - 1) / BITS_PER_BYTE; i++) {
					CHAR setBits = (1 << (writeCount - i * BITS_PER_BYTE)) - 1;

					if (i == 1)
						ullBitPosInByte = 0;
					pConverted[ullByte + i] |= (setBits << ullBitPosInByte);
				}
			}
		}
	}

	return true;
}


PVOLUME_BITMAP_BUFFER GetVolumeBitmapForBsr(struct bsr_device *device, ULONG ulBsrBitmapUnit)
{
	PVOLUME_BITMAP_BUFFER pVbb = NULL;
	PVOLUME_BITMAP_BUFFER pBsrBitmap = NULL;
	ULONG ulConvertedBitmapSize = 0;
	ULONGLONG ullTotalCluster = 0;
	ULONG ulBytesPerCluster = 0;

	do {
		pVbb = (PVOLUME_BITMAP_BUFFER)GetVolumeBitmap(device, &ullTotalCluster, &ulBytesPerCluster);
		if (NULL == pVbb) {
			bsr_err(69, BSR_LC_BITMAP, device, "Failed to get bsr bitmap due to failure to get volume bitmap, minor(%u)", device->minor);
			break;
		}
			
		// use file system returned volume bitmap if it's compatible with bsr.
		if (ulBytesPerCluster == ulBsrBitmapUnit) {
			pBsrBitmap = pVbb;
#ifdef _WIN
			// retrived bitmap size from os indicates that total bit count, convert it into byte of total bit.
			pBsrBitmap->BitmapSize.QuadPart = (ullTotalCluster / BITS_PER_BYTE);
#endif
			pVbb = NULL;
		}
		else {
			// Convert gotten bitmap into 4kb unit cluster bitmap.
			ullTotalCluster = (ullTotalCluster * ulBytesPerCluster) / ulBsrBitmapUnit;
			ulConvertedBitmapSize = (ULONG)(ullTotalCluster / BITS_PER_BYTE);
#ifdef _WIN
			pBsrBitmap = (PVOLUME_BITMAP_BUFFER)ExAllocatePoolWithTag(NonPagedPool, sizeof(VOLUME_BITMAP_BUFFER) +  ulConvertedBitmapSize, '56SB');			
#else // _LIN
			pBsrBitmap = (PVOLUME_BITMAP_BUFFER)bsr_kvmalloc(sizeof(VOLUME_BITMAP_BUFFER) + ulConvertedBitmapSize, GFP_ATOMIC|__GFP_NOWARN);
#endif
			if (NULL == pBsrBitmap) {
				bsr_err(54, BSR_LC_MEMORY, device, "Failed to get bsr bitmap due to failure to allocated %d size memory for converted bitmap", (sizeof(VOLUME_BITMAP_BUFFER) + ulConvertedBitmapSize));
				break;
			}

#ifdef _WIN
			pBsrBitmap->StartingLcn.QuadPart = 0;
			pBsrBitmap->BitmapSize.QuadPart = ulConvertedBitmapSize;
			RtlZeroMemory(pBsrBitmap->Buffer, (size_t)(pBsrBitmap->BitmapSize.QuadPart));
#else // _LIN			
			pBsrBitmap->BitmapSize = ulConvertedBitmapSize;
			memset(pBsrBitmap->Buffer, 0, pBsrBitmap->BitmapSize);			
#endif
			if (!ConvertVolumeBitmap(pVbb, (char *)pBsrBitmap->Buffer, ulBytesPerCluster, ulBsrBitmapUnit)) {
				bsr_err(70, BSR_LC_BITMAP, device, "Failed to get bsr bitmap due to could not convert bitmap, Bytes Per Cluster(%u), Bsr Bitmap Unit(%u)", ulBytesPerCluster, ulBsrBitmapUnit);
#ifdef _LIN
				sub_kvmalloc_mem_usage(pBsrBitmap, sizeof(VOLUME_BITMAP_BUFFER) + pBsrBitmap->BitmapSize);
#endif
				kvfree(pBsrBitmap);
				pBsrBitmap = NULL;
				break;
			}
		}
	} while (false);

	if (NULL != pVbb) {
#ifdef _LIN
		sub_kvmalloc_mem_usage(pVbb, sizeof(VOLUME_BITMAP_BUFFER) + pVbb->BitmapSize);
#endif
		kvfree(pVbb);
		pVbb = NULL;
	}

	return pBsrBitmap;
}


// set out-of-sync for allocated clusters.
bool SetOOSAllocatedCluster(struct bsr_device *device, struct bsr_peer_device *peer_device, enum bsr_repl_state side, bool bitmap_lock, bool *bSync)
{
	bool bRet = false;
	PVOLUME_BITMAP_BUFFER pBitmap = NULL;
	ULONG_PTR count = 0;
	// DW-1317 to support fast sync from secondary sync source whose volume is NOT mounted.
	bool bSecondary = false;
	struct bsr_bitmap *bitmap = device->bitmap;
	int bmi = peer_device->bitmap_index;

	// DW-2017 in this function, to avoid deadlock a bitmap lock within the vol_ctl_mutex should not be used.
	// if bitmap_lock is true, it was called from bsr_receiver() and the object is guaranteed to be removed after completion
	if (!bitmap_lock)
		// DW-1317: prevent from writing smt on volume, such as being primary and getting resync data, it doesn't allow to dismount volume also.
		mutex_lock(&device->resource->vol_ctl_mutex);

	// DW-2017 after locking, access to the object shall be made.
	if (NULL == device ||
		NULL == peer_device ||
		(side != L_SYNC_SOURCE && side != L_SYNC_TARGET)) {
		// DW-2017 change log output based on peer_device status
		if (peer_device)
			bsr_err(15, BSR_LC_RESYNC_OV, peer_device, "Failed to allocate set out of sync due to invalid parameter. repl state(%s)", bsr_repl_str(side));
		else
			bsr_err(16, BSR_LC_RESYNC_OV, NO_OBJECT, "Failed to allocate set out of sync due to invalid parameter. repl state(%s)", bsr_repl_str(side));

		if (!bitmap_lock)
			mutex_unlock(&device->resource->vol_ctl_mutex);

		*bSync = false;
		return false;
	}

	// DW-1317 inspect resync side first, before get the allocated bitmap.
	if (!bsr_inspect_resync_side(peer_device, side, NOW, false)) {
		bsr_warn(164, BSR_LC_RESYNC_OV, peer_device, "Not a replication state(%s) to set out of sync", bsr_repl_str(side));
		if (!bitmap_lock)
			mutex_unlock(&device->resource->vol_ctl_mutex);
		*bSync = false;
		goto out;
	}

	// clear all bits before start initial sync. (clear bits only for this peer device)	
	if (bitmap_lock)
		bsr_bm_slot_lock(peer_device, "initial sync for allocated cluster", BM_LOCK_BULK);
	bsr_bm_clear_many_bits(peer_device->device, peer_device->bitmap_index, 0, BSR_END_OF_BITMAP);
	bsr_bm_write(device, NULL);
	if (bitmap_lock) {
		bsr_bm_slot_unlock(peer_device);
		// DW-2017
		mutex_lock(&device->resource->vol_ctl_mutex);
	}
	
	if (device->resource->role[NOW] == R_SECONDARY) {
		// DW-1317 set read-only attribute and mount for temporary.
		if (side == L_SYNC_SOURCE) {
			bsr_info(17, BSR_LC_RESYNC_OV, peer_device, "The replication status is syncsource and role is secondary, so you mount the temporary volume to get the allocate cluster.");
			bSecondary = true;
		}
		else if (side == L_SYNC_TARGET) {
			bsr_info(18, BSR_LC_RESYNC_OV, peer_device, "The replication status is synctarget, so it waits for a bitmap of syncsource without obtaining an allocate cluster.");
			bRet = true;
			mutex_unlock(&device->resource->vol_ctl_mutex);
			goto out;
		}
	}

	bsr_info(19, BSR_LC_RESYNC_OV, peer_device, "Get bitmap information for the volume.");

	do {
		if (bSecondary) {
#ifdef _WIN
			mutex_lock(&att_mod_mutex);
			// set readonly attribute.
			if (!ChangeVolumeReadonly(device->minor, true)) {
				bsr_err(67, BSR_LC_VOLUME, peer_device, "Failed to allocate set out of sync due to could not change volume read-only attribute");
				mutex_unlock(&att_mod_mutex);
				bSecondary = false;
				break;
			}
#endif
			// allow mount within getting volume bitmap.
			device->resource->bTempAllowMount = true;			
		}

		// BSR-633 fix potential deadlock in bsr_uuid_detect_finished_resyncs()
		if (!bitmap_lock)
			bsr_bm_unlock(device);

		// Get volume bitmap which is converted into 4kb cluster unit.
		pBitmap = GetVolumeBitmapForBsr(device, BM_BLOCK_SIZE);
		
		// BSR-633
		if (!bitmap_lock)
			bsr_bm_lock(device, "Set out-of-sync for allocated cluster", BM_LOCK_CLEAR | BM_LOCK_BULK);

		if (NULL == pBitmap) {
			bsr_err(71, BSR_LC_BITMAP, peer_device, "Failed to allocate set out of sync due to could not get bitmap for bsr");
		}
		
		if (bSecondary) {
			// prevent from mounting volume.
			device->resource->bTempAllowMount = false;
#ifdef _WIN
			// dismount volume.
			FsctlFlushDismountVolume(device->minor, false);

			// clear readonly attribute
			if (!ChangeVolumeReadonly(device->minor, false)) {
				bsr_err(68, BSR_LC_VOLUME, peer_device, "Failed to allocate set out of sync due to read-only attribute for volume(minor: %d) had been set, but can't be reverted. force detach bsr disk", device->minor);
				if (device &&
					get_ldev_if_state(device, D_NEGOTIATING))
				{
					set_bit(FORCE_DETACH, &device->flags);
					change_disk_state(device, D_DETACHING, CS_HARD, NULL);
					put_ldev(device);
				}
			}
			mutex_unlock(&att_mod_mutex);
#endif
		}

	} while (false);

	bsr_info(23, BSR_LC_RESYNC_OV, peer_device, "%llu bits(%llu KB) have been set as out-of-sync by the allocate cluster.",
			(unsigned long long)bitmap->bm_set[bmi], (unsigned long long)(bitmap->bm_set[bmi] << (BM_BLOCK_SHIFT - 10)));

	// DW-1495 Change location due to deadlock(bm_change)
	// Set out-of-sync for allocated cluster.
	if (bitmap_lock) {
		// DW-2017
		mutex_unlock(&device->resource->vol_ctl_mutex);
		bsr_bm_lock(device, "Set out-of-sync for allocated cluster", BM_LOCK_CLEAR | BM_LOCK_BULK);
	}
	count = SetOOSFromBitmap(pBitmap, peer_device);
	if (bitmap_lock)
		bsr_bm_unlock(device);

	if (count == -1) {
		bsr_err(72, BSR_LC_BITMAP, peer_device, "Failed to allocate set out of sync due to could not set bits from gotten bitmap");
		bRet = false;
	}
	else{
		bsr_info(25, BSR_LC_RESYNC_OV, peer_device, "%llu bits(%llu KB) are set as new out-of-sync for bitmap",
				(unsigned long long)count, (unsigned long long)(count << (BM_BLOCK_SHIFT - 10)));
		bRet = true;
	}
		

	if (pBitmap) {
#ifdef _LIN
		sub_kvmalloc_mem_usage(pBitmap, sizeof(VOLUME_BITMAP_BUFFER) + pBitmap->BitmapSize);
#endif
		kvfree(pBitmap);
		pBitmap = NULL;
	}

	if (!bitmap_lock)
		mutex_unlock(&device->resource->vol_ctl_mutex);

out:
	return bRet;
}

// BSR-118
int w_fast_ov_get_bm(struct bsr_work *w, int cancel) {
	struct ov_work *fast_ov_work =
		container_of(w, struct ov_work, w);
	struct bsr_peer_device *peer_device =
		container_of(fast_ov_work, struct bsr_peer_device, fast_ov_work);
	struct bsr_device *device = peer_device->device;
	enum bsr_repl_state side = peer_device->repl_state[NOW];
	// DW-1317 to support fast sync from secondary sync source whose volume is NOT mounted.
	bool bSecondary = false;
	bool err = true;
	PVOLUME_BITMAP_BUFFER pBitmap = NULL;
	
	UNREFERENCED_PARAMETER(cancel);

	// BSR-590 freeze_bdev() performs I/O for meta flush, so pending check logic is added.
	// There is a case where Ahead mode is changed before this function execution.
	if (atomic_read(&device->pending_bitmap_work.n)) {
		bsr_info(26, BSR_LC_RESYNC_OV, peer_device, "Fast online verify canceled due to pending bitmap work.");
		if (side == L_VERIFY_S) {
			ULONG_PTR ov_tw = bsr_ov_bm_total_weight(peer_device);
			bsr_info(27, BSR_LC_RESYNC_OV, peer_device, "Starting Online Verify as %s, bitmap index(%d) start sector(%llu) (will verify %llu KB [%llu bits set]).",
				bsr_repl_str(peer_device->repl_state[NOW]), peer_device->bitmap_index, (unsigned long long)peer_device->ov_start_sector,
				(unsigned long long)ov_tw << (BM_BLOCK_SHIFT - 10),
				(unsigned long long)ov_tw);
			mod_timer(&peer_device->resync_timer, jiffies);
		}
		return err;
	}

	mutex_lock(&device->resource->vol_ctl_mutex);
	
	if (device->resource->role[NOW] == R_SECONDARY) {
		// DW-1317 set read-only attribute and mount for temporary.
		if (side == L_VERIFY_S) {
			bsr_info(28, BSR_LC_RESYNC_OV, peer_device, "The replication status is verify source and role is secondary, so you mount the temporary volume to get the allocate cluster.");
			bSecondary = true;
		}
		else {
			bsr_warn(165, BSR_LC_RESYNC_OV, peer_device, "Cluster allocation is in a replication state(%s) that cannot be allocated.", bsr_repl_str(peer_device->repl_state[NOW]));
			err = true;
			goto out;
		}
	}

	do {
		if (bSecondary) {
#ifdef _WIN
			mutex_lock(&att_mod_mutex);
			// set readonly attribute.
			if (!ChangeVolumeReadonly(device->minor, true)) {
				bsr_err(69, BSR_LC_VOLUME, peer_device, "Failed to get fast ov bitmap due to could not change volume read-only attribute");
				mutex_unlock(&att_mod_mutex);
				bSecondary = false;
				break;
			}
#endif
			// allow mount within getting volume bitmap.
			device->resource->bTempAllowMount = true;			
		}

		// Get volume bitmap which is converted into 4kb cluster unit.
		pBitmap = GetVolumeBitmapForBsr(device, BM_BLOCK_SIZE);
		
		if (NULL == pBitmap) {
			bsr_err(73, BSR_LC_BITMAP, peer_device, "Failed to get fast ov bitmap due to could not get bitmap for bsr");
			err = true;
		}
		
		if (bSecondary) {
			// prevent from mounting volume.
			device->resource->bTempAllowMount = false;
#ifdef _WIN
			// dismount volume.
			FsctlFlushDismountVolume(device->minor, false);

			// clear readonly attribute
			if (!ChangeVolumeReadonly(device->minor, false)) {
				bsr_err(70, BSR_LC_VOLUME, peer_device, "Failed to get fast ov bitmap due to read-only attribute for volume(minor: %d) had been set, but can't be reverted. force detach bsr disk", device->minor);
				if (device &&
					get_ldev_if_state(device, D_NEGOTIATING))
				{
					set_bit(FORCE_DETACH, &device->flags);
					change_disk_state(device, D_DETACHING, CS_HARD, NULL);
					put_ldev(device);
				}
			}
			mutex_unlock(&att_mod_mutex);
#endif
		}

	} while (false);


	// BSR-835 move to before execution of bsr_ov_bm_total_weight()
	mutex_unlock(&device->resource->vol_ctl_mutex);


	if (side == L_VERIFY_S) {
		ULONG_PTR ov_tw = 0;
		// BSR-835 cancel ov if not Connected or VerifyS
		if (peer_device->connection->cstate[NOW] < C_CONNECTED || peer_device->repl_state[NOW] != L_VERIFY_S) {
			if (pBitmap) {
#ifdef _LIN
				sub_kvmalloc_mem_usage(pBitmap, sizeof(VOLUME_BITMAP_BUFFER) + pBitmap->BitmapSize);
#endif
				kvfree(pBitmap);
				pBitmap = NULL;
			}
			err = true;
		} 
		else {			
			if (NULL != pBitmap) {
				peer_device->fast_ov_bitmap = pBitmap;
				// BSR-835 fix to manage ov bitmap buffer with kref
				kref_init(&peer_device->ov_bm_ref);
				bsr_info(212, BSR_LC_RESYNC_OV, peer_device, "The bitmap buffer for online verification has been allocated.");
				err = false;
			}
			ov_tw = bsr_ov_bm_total_weight(peer_device);
			if (ov_tw == 0)
				err = true;
		}

		if (err) {
			bsr_info(211, BSR_LC_RESYNC_OV, peer_device, "Online verify canceled.");
		} 
		else {
			bsr_info(32, BSR_LC_RESYNC_OV, peer_device, "Starting Online Verify as %s, bitmap index(%d) start sector(%llu) (will verify %llu KB [%llu bits set]).",
				bsr_repl_str(peer_device->repl_state[NOW]), peer_device->bitmap_index, (unsigned long long)peer_device->ov_start_sector,
				(unsigned long long)ov_tw << (BM_BLOCK_SHIFT - 10),
				(unsigned long long)ov_tw);

			// BSR-835 set ov_left value
			if (test_bit(OV_FAST_BM_SET_PENDING, &peer_device->flags)) {
				peer_device->ov_left = ov_tw;
				// BSR-997 store ov_left as sectors
				peer_device->ov_left_sectors = BM_BIT_TO_SECT(ov_tw);
			}
			
			mod_timer(&peer_device->resync_timer, jiffies);
		}

	}

out:
	return err;
}

/**
 * bsr_bmio_clear_all_n_write() - io_fn for bsr_queue_bitmap_io() or bsr_bitmap_io()
 * @device:	BSR device.
 *
 * Clears all bits in the bitmap and writes the whole bitmap to stable storage.
 */
int bsr_bmio_clear_all_n_write(struct bsr_device *device,
			    struct bsr_peer_device *peer_device) __must_hold(local)
{
	UNREFERENCED_PARAMETER(peer_device);
	bsr_resume_al(device);
	bsr_bm_clear_all(device);
	return bsr_bm_write(device, NULL);
}

static int w_bitmap_io(struct bsr_work *w, int unused)
{
	struct bm_io_work *work =
		container_of(w, struct bm_io_work, w);
	struct bsr_device *device = work->device;
	int rv = -EIO;

	UNREFERENCED_PARAMETER(unused);

	// DW-1979 bsr_send_bitmap function does not lock.
	if (&bsr_send_bitmap == work->io_fn) {
		if (atomic_dec_and_test(&device->pending_bitmap_work.n))
			wake_up(&device->misc_wait);
	}

	if (get_ldev(device)) {
		if (work->flags & BM_LOCK_SINGLE_SLOT)
			bsr_bm_slot_lock(work->peer_device, work->why, work->flags);
		else
			bsr_bm_lock(device, work->why, work->flags);

		rv = work->io_fn(device, work->peer_device);
		
		if (work->flags & BM_LOCK_SINGLE_SLOT)
			bsr_bm_slot_unlock(work->peer_device);
		else
			bsr_bm_unlock(device);
		put_ldev(device);
	}

	if (work->done)
		work->done(device, work->peer_device, rv);

	// DW-1979
	if (&bsr_send_bitmap != work->io_fn) {
		if (atomic_dec_and_test(&device->pending_bitmap_work.n))
			wake_up(&device->misc_wait);
	}

	bsr_kfree(work);

	return 0;
}

void bsr_queue_pending_bitmap_work(struct bsr_device *device)
{
	unsigned long flags;

	spin_lock_irqsave(&device->pending_bitmap_work.q_lock, flags);
	spin_lock(&device->resource->work.q_lock);
	list_splice_tail_init(&device->pending_bitmap_work.q, &device->resource->work.q);
	spin_unlock(&device->resource->work.q_lock);
	spin_unlock_irqrestore(&device->pending_bitmap_work.q_lock, flags);
	wake_up(&device->resource->work.q_wait);
}

/**
 * bsr_queue_bitmap_io() - Queues an IO operation on the whole bitmap
 * @device:	BSR device.
 * @io_fn:	IO callback to be called when bitmap IO is possible
 * @done:	callback to be called after the bitmap IO was performed
 * @why:	Descriptive text of the reason for doing the IO
 *
 * While IO on the bitmap happens we freeze application IO thus we ensure
 * that bsr_set_out_of_sync() can not be called. This function MAY ONLY be
 * called from sender context. It MUST NOT be used while a previous such
 * work is still pending!
 *
 * Its worker function encloses the call of io_fn() by get_ldev() and
 * put_ldev().
 */
void bsr_queue_bitmap_io(struct bsr_device *device,
			  int (*io_fn)(struct bsr_device *, struct bsr_peer_device *),
			  void (*done)(struct bsr_device *, struct bsr_peer_device *, int),
			  char *why, enum bm_flag flags,
			  struct bsr_peer_device *peer_device)
{
	struct bm_io_work *bm_io_work;

	// DW-1979 other threads are also used(bsr_receiver()), so i changed to the info level log to output
	if (current == device->resource->worker.task)
		bsr_info(33, BSR_LC_RESYNC_OV, device, "%s, worker.task(%p), current(%p)", why ? why : "?", device->resource->worker.task, current);

	bm_io_work = bsr_kmalloc(sizeof(*bm_io_work), GFP_NOIO, '21SB');
	if (!bm_io_work) {
		bsr_err(55, BSR_LC_MEMORY, device, "Failed to add bitmap I/O queue due to failure to allocate %d size memory for bitmap I/O work", sizeof(*bm_io_work));
		done(device, peer_device, -ENOMEM);
		return;
	}

	bm_io_work->w.cb = w_bitmap_io;
	bm_io_work->device = device;
	bm_io_work->peer_device = peer_device;
	bm_io_work->io_fn = io_fn;
	bm_io_work->done = done;
	bm_io_work->why = why;
	bm_io_work->flags = flags;

	/*
	 * Whole-bitmap operations can only take place when there is no
	 * concurrent application I/O.  We ensure exclusion between the two
	 * types of I/O  with the following mechanism:
	 *
	 *  - device->ap_bio_cnt keeps track of the number of application I/O
	 *    requests in progress.
	 *
	 *  - A non-empty device->pending_bitmap_work list indicates that
	 *    whole-bitmap I/O operations are pending, and no new application
	 *    I/O should be started.  We make sure that the list doesn't appear
	 *    empty system wide before trying to queue the whole-bitmap I/O.
	 *
	 *  - In dec_ap_bio(), we decrement device->ap_bio_cnt.  If it reaches
	 *    zero and the device->pending_bitmap_work list is non-empty, we
	 *    queue the whole-bitmap operations.
	 *
	 *  - In inc_ap_bio(), we increment device->ap_bio_cnt before checking
	 *    if the device->pending_bitmap_work list is non-empty.  If
	 *    device->pending_bitmap_work is non-empty, we immediately call
	 *    dec_ap_bio().
	 *
	 * This ensures that whenver there is pending whole-bitmap I/O, we
	 * realize in dec_ap_bio().
	 *
	 */

	/* no one should accidentally schedule the next bitmap IO
	 * when it is only half-queued yet */
	atomic_inc(&device->ap_bio_cnt[WRITE]);
	atomic_inc(&device->pending_bitmap_work.n);
	spin_lock_irq(&device->pending_bitmap_work.q_lock);
	list_add_tail(&bm_io_work->w.list, &device->pending_bitmap_work.q);
	spin_unlock_irq(&device->pending_bitmap_work.q_lock);
	dec_ap_bio(device, WRITE);  /* may move to actual work queue */
}

/**
 * bsr_bitmap_io() -  Does an IO operation on the whole bitmap
 * @device:	BSR device.
 * @io_fn:	IO callback to be called when bitmap IO is possible
 * @why:	Descriptive text of the reason for doing the IO
 *
 * freezes application IO while that the actual IO operations runs. This
 * functions MAY NOT be called from sender context.
 */
int bsr_bitmap_io(struct bsr_device *device,
		int (*io_fn)(struct bsr_device *, struct bsr_peer_device *),
		char *why, enum bm_flag flags,
		struct bsr_peer_device *peer_device)
{
	/* Only suspend io, if some operation is supposed to be locked out */
	const bool do_suspend_io = flags & (BM_LOCK_CLEAR|BM_LOCK_SET|BM_LOCK_TEST);
	int rv;

	D_ASSERT(device, current != device->resource->worker.task);

	if (do_suspend_io)
		bsr_suspend_io(device, WRITE_ONLY);

	if (flags & BM_LOCK_SINGLE_SLOT)
		bsr_bm_slot_lock(peer_device, why, flags);
	else
		bsr_bm_lock(device, why, flags);

	rv = io_fn(device, peer_device);

	if (flags & BM_LOCK_SINGLE_SLOT)
		bsr_bm_slot_unlock(peer_device);
	else
		bsr_bm_unlock(device);

	if (do_suspend_io)
		bsr_resume_io(device);

	return rv;
}

void bsr_md_set_flag(struct bsr_device *device, enum mdf_flag flag) __must_hold(local)
{
	if (!device->ldev) {
		if (bsr_ratelimit())
			bsr_warn(33, BSR_LC_STATE, device, "Failed to set flag in meta because no backing device is assigned.");
		return;
	}

	if (((int)(device->ldev->md.flags) & flag) != flag) {
		bsr_md_mark_dirty(device);
		device->ldev->md.flags |= flag;
		// BSR-676 notify flag
		if (flag == MDF_LAST_PRIMARY) {
			bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_DEVICE_FLAG);
		}
	}
}

void bsr_md_set_peer_flag(struct bsr_peer_device *peer_device,
			   enum mdf_peer_flag flag) __must_hold(local)
{
	struct bsr_md *md;
	struct bsr_device *device = peer_device->device;
	if (!device->ldev) {
		if (bsr_ratelimit())
			bsr_warn(34, BSR_LC_STATE, peer_device, "Failed to set flag of peer in meta because no backing device is assigned.");
		return;
	}

	md = &device->ldev->md;
	if (!(md->peers[peer_device->node_id].flags & flag)) {
		bsr_md_mark_dirty(device);
		md->peers[peer_device->node_id].flags |= flag;
		// BSR-676 notify flag
		if (flag == MDF_PEER_FULL_SYNC) {
			bsr_queue_notify_update_gi(NULL, peer_device, BSR_GI_NOTI_PEER_DEVICE_FLAG);
		}
	}
}

void bsr_md_clear_flag(struct bsr_device *device, enum mdf_flag flag) __must_hold(local)
{
	if (!device->ldev) {
		if (bsr_ratelimit())
			bsr_warn(35, BSR_LC_STATE, device, "backing device is not assigned.");
		return;
	}

	if ((device->ldev->md.flags & flag) != 0) {
		bsr_md_mark_dirty(device);
		device->ldev->md.flags &= ~flag;
		// BSR-676 notify flag
		if (flag == MDF_LAST_PRIMARY) {
			bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_DEVICE_FLAG);
		}
	}
}

void bsr_md_clear_peer_flag(struct bsr_peer_device *peer_device,
			     enum mdf_peer_flag flag) __must_hold(local)
{
	struct bsr_md *md;
	struct bsr_device *device = peer_device->device;
	if (!device->ldev) {
		if (bsr_ratelimit())
			bsr_warn(36, BSR_LC_STATE, peer_device, "Failed to clear flag of peer in meta because no backing device is assigned.");
		return;
	}

	md = &device->ldev->md;
	if (md->peers[peer_device->node_id].flags & flag) {
		bsr_md_mark_dirty(device);
		md->peers[peer_device->node_id].flags &= ~flag;
		// BSR-676 notify flag
		if (flag == MDF_PEER_FULL_SYNC) {
			bsr_queue_notify_update_gi(NULL, peer_device, BSR_GI_NOTI_PEER_DEVICE_FLAG);
		}
	}
}

int bsr_md_test_flag(struct bsr_device *device, enum mdf_flag flag)
{
	if (!device->ldev) {
		if (bsr_ratelimit())
			bsr_warn(37, BSR_LC_STATE, device, "Failed to test flag in meta because no backing device is assigned.");
		return 0;
	}

	return (device->ldev->md.flags & flag) != 0;
}

bool bsr_md_test_peer_flag(struct bsr_peer_device *peer_device, enum mdf_peer_flag flag)
{
	struct bsr_md *md;

	if (!peer_device->device->ldev) {
		if (bsr_ratelimit())
			bsr_warn(38, BSR_LC_STATE, peer_device, "Failed to test flag of peer in meta because no backing device is assigned.");
		return false;
	}

	md = &peer_device->device->ldev->md;
	if (peer_device->bitmap_index == -1)
		return false;

	return md->peers[peer_device->node_id].flags & flag;
}
#ifdef _WIN
static void md_sync_timer_fn(PKDPC Dpc, PVOID data, PVOID SystemArgument1, PVOID SystemArgument2)
#else // _LIN
static void md_sync_timer_fn(BSR_TIMER_FN_ARG)
#endif
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Dpc);
	struct bsr_device *device = (struct bsr_device *) data;
#else // _LIN
	struct bsr_device *device = BSR_TIMER_ARG2OBJ(device, md_sync_timer);
#endif
	bsr_device_post_work(device, MD_SYNC);
}

/**
 * bsr_wait_misc  -  wait for a request or peer request to make progress
 * @device:	device associated with the request or peer request
 * @peer_device: NULL when waiting for a request; the peer device of the peer
 *		 request when waiting for a peer request
 * @i:		the struct bsr_interval embedded in struct bsr_request or
 *		struct bsr_peer_request
 */
int bsr_wait_misc(struct bsr_device *device, struct bsr_peer_device *peer_device, struct bsr_interval *i)
{
#ifdef _LIN
	DEFINE_WAIT(wait);
#endif
	long timeout;

	rcu_read_lock();
	if (peer_device) {
		struct net_conf *net_conf = rcu_dereference(peer_device->connection->transport.net_conf);
		if (!net_conf) {
			rcu_read_unlock();
			return -ETIMEDOUT;
		}
		timeout = net_conf->ko_count ? net_conf->timeout * HZ / 10 * net_conf->ko_count :
					       MAX_SCHEDULE_TIMEOUT;
	} else {
		struct disk_conf *disk_conf = rcu_dereference(device->ldev->disk_conf);
		timeout = disk_conf->disk_timeout * HZ / 10;
	}
	rcu_read_unlock();

	/* Indicate to wake up device->misc_wait on progress.  */
	i->waiting = true;
#ifdef _LIN
	prepare_to_wait(&device->misc_wait, &wait, TASK_INTERRUPTIBLE);
#endif
	spin_unlock_irq(&device->resource->req_lock);
#ifdef _WIN
    timeout = schedule(&device->misc_wait, timeout, __FUNCTION__, __LINE__);
#else // _LIN
	timeout = schedule_timeout(timeout);
	finish_wait(&device->misc_wait, &wait);
#endif
	spin_lock_irq(&device->resource->req_lock);
	if (!timeout || (peer_device && peer_device->repl_state[NOW] < L_ESTABLISHED))
		return -ETIMEDOUT;
	if (signal_pending(current))
		return -ERESTARTSYS;
	return 0;
}

#ifndef __maybe_unused
#define __maybe_unused                  __attribute__((unused))
#endif
void lock_all_resources(void)
{
	struct bsr_resource *resource;
#ifdef _LIN
	int __maybe_unused i = 0;
#endif

	mutex_lock(&resources_mutex);


	// DW-759 irq disable is ported to continue DISPATCH_LEVEL by global lock
	local_irq_disable();
	for_each_resource(resource, &bsr_resources)
#ifdef _WIN
		spin_lock_irq(&resource->req_lock);
#else // _LIN
		spin_lock_nested(&resource->req_lock, i++);
#endif
}

void unlock_all_resources(void)
{
	struct bsr_resource *resource;

	for_each_resource(resource, &bsr_resources)
#ifdef _WIN
		spin_unlock_irq(&resource->req_lock);
#else // _LIN
		spin_unlock(&resource->req_lock);
#endif
	// DW-759 irq enable. return to PASSIVE_LEVEL
	local_irq_enable();
#ifdef _WIN
	bsr_debug_req_lock("local_irq_enable : CurrentIrql(%d)", KeGetCurrentIrql());
#endif
	mutex_unlock(&resources_mutex);
}


long twopc_timeout(struct bsr_resource *resource)
{
	return resource->res_opts.twopc_timeout * HZ/10;
}

u64 directly_connected_nodes(struct bsr_resource *resource, enum which_state which)
{
	u64 directly_connected = 0;
	struct bsr_connection *connection;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[which] < C_CONNECTED)
			continue;
		directly_connected |= NODE_MASK(connection->peer_node_id);
	}
	rcu_read_unlock();

	return directly_connected;
}

#ifdef CONFIG_BSR_FAULT_INJECTION
/* Fault insertion support including random number generator shamelessly
 * stolen from kernel/rcutorture.c */
struct fault_random_state {
	unsigned long state;
	unsigned long count;
};

#define FAULT_RANDOM_MULT 39916801  /* prime */
#define FAULT_RANDOM_ADD	479001701 /* prime */
#define FAULT_RANDOM_REFRESH 10000

/*
 * Crude but fast random-number generator.  Uses a linear congruential
 * generator, with occasional help from get_random_bytes().
 */
static unsigned long
_bsr_fault_random(struct fault_random_state *rsp)
{
	long refresh;

	if (!rsp->count--) {
		get_random_bytes(&refresh, sizeof(refresh));
		rsp->state += refresh;
		rsp->count = FAULT_RANDOM_REFRESH;
	}
	rsp->state = rsp->state * FAULT_RANDOM_MULT + FAULT_RANDOM_ADD;
#ifdef _WIN
    return rsp->state;
#else // _LIN
	return swahw32(rsp->state);
#endif
}

static char *
_bsr_fault_str(unsigned int type) {
	static char *_faults[] = {
		[BSR_FAULT_MD_WR] = "Meta-data write",
		[BSR_FAULT_MD_RD] = "Meta-data read",
		[BSR_FAULT_RS_WR] = "Resync write",
		[BSR_FAULT_RS_RD] = "Resync read",
		[BSR_FAULT_DT_WR] = "Data write",
		[BSR_FAULT_DT_RD] = "Data read",
		[BSR_FAULT_DT_RA] = "Data read ahead",
		[BSR_FAULT_BM_ALLOC] = "BM allocation",
		[BSR_FAULT_AL_EE] = "EE allocation",
		[BSR_FAULT_RECEIVE] = "receive data corruption",
	};

	return (type < BSR_FAULT_MAX) ? _faults[type] : "**Unknown**";
}

unsigned int
_bsr_insert_fault(struct bsr_device *device, unsigned int type)
{
	static struct fault_random_state rrs = {0, 0};

	unsigned int ret = (
		(fault_devs == 0 ||
			((1 << device_to_minor(device)) & fault_devs) != 0) &&
		((int)((_bsr_fault_random(&rrs) % 100) + 1) <= fault_rate));

	if (ret) {
		fault_count++;

		if (bsr_ratelimit())
			bsr_warn(43, BSR_LC_IO, device, "***Simulating %s failure",
				_bsr_fault_str(type));
	}

	return ret;
}
#endif
#ifdef _LIN
#if 0 // TODO
// moved to bsrhk_init.c
module_init(bsr_init)
module_exit(bsr_cleanup)
#endif
/* For transport layer */
EXPORT_SYMBOL(bsr_destroy_connection);
EXPORT_SYMBOL(bsr_destroy_path);
#endif
