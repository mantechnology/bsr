#define pr_fmt(fmt)	KBUILD_MODNAME " debugfs: " fmt
#ifdef _WIN
//#include "./bsr-kernel-compat/windows/seq_file.h"
//#include "./bsr-kernel-compat/windows/jiffies.h"
#else // _LIN
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#endif
#include "bsr_int.h"
#include "bsr_debugfs.h"
#include "bsr_req.h"

#include "../bsr-headers/bsr_transport.h"


/**********************************************************************
 * Whenever you change the file format, remember to bump the version. *
 **********************************************************************/

#ifdef CONFIG_DEBUG_FS
static struct dentry *bsr_debugfs_root;
static struct dentry *bsr_debugfs_version;
static struct dentry *bsr_debugfs_resources;
static struct dentry *bsr_debugfs_minors;
// BSR-875
static struct dentry *bsr_debugfs_alloc_mem;

static void seq_print_age_or_dash(struct seq_file *m, bool valid, ktime_t dt)
{
	if (valid)
		seq_printf(m, "\t%d", (int)ktime_to_ms(dt));
	else
		seq_puts(m, "\t-");
}

static void __seq_print_rq_state_bit(struct seq_file *m,
	bool is_set, char *sep, const char *set_name, const char *unset_name)
{
	if (is_set && set_name) {
		seq_putc(m, *sep);
		seq_puts(m, set_name);
		*sep = '|';
	} else if (!is_set && unset_name) {
		seq_putc(m, *sep);
		seq_puts(m, unset_name);
		*sep = '|';
	}
}

static void seq_print_rq_state_bit(struct seq_file *m,
	bool is_set, char *sep, const char *set_name)
{
	__seq_print_rq_state_bit(m, is_set, sep, set_name, NULL);
}

/* pretty print enum bsr_req_state_bits req->rq_state */
static void seq_print_request_state(struct seq_file *m, struct bsr_request *req)
{
	struct bsr_device *device = req->device;
	struct bsr_peer_device *peer_device;
	unsigned int s = req->rq_state[0];
	char sep = ' ';
	seq_printf(m, "\t0x%08x", s);
	seq_printf(m, "\tmaster: %s", req->master_bio ? "pending" : "completed");

	/* RQ_WRITE ignored, already reported */
	seq_puts(m, "\tlocal:");
	seq_print_rq_state_bit(m, s & RQ_IN_ACT_LOG, &sep, "in-AL");
	seq_print_rq_state_bit(m, s & RQ_POSTPONED, &sep, "postponed");
	seq_print_rq_state_bit(m, s & RQ_COMPLETION_SUSP, &sep, "suspended");
	sep = ' ';
	seq_print_rq_state_bit(m, s & RQ_LOCAL_PENDING, &sep, "pending");
	seq_print_rq_state_bit(m, s & RQ_LOCAL_COMPLETED, &sep, "completed");
	seq_print_rq_state_bit(m, s & RQ_LOCAL_ABORTED, &sep, "aborted");
	seq_print_rq_state_bit(m, s & RQ_LOCAL_OK, &sep, "ok");
	if (sep == ' ')
		seq_puts(m, " -");

	for_each_peer_device(peer_device, device) {
		s = req->rq_state[1 + peer_device->node_id];
		seq_printf(m, "\tnet[%d]:", peer_device->node_id);
		sep = ' ';
		seq_print_rq_state_bit(m, s & RQ_NET_PENDING, &sep, "pending");
		seq_print_rq_state_bit(m, s & RQ_NET_QUEUED, &sep, "queued");
		seq_print_rq_state_bit(m, s & RQ_NET_SENT, &sep, "sent");
		seq_print_rq_state_bit(m, s & RQ_NET_DONE, &sep, "done");
		seq_print_rq_state_bit(m, s & RQ_NET_SIS, &sep, "sis");
		seq_print_rq_state_bit(m, s & RQ_NET_OK, &sep, "ok");
		if (sep == ' ')
			seq_puts(m, " -");

		seq_puts(m, " :");
		sep = ' ';
		seq_print_rq_state_bit(m, s & RQ_EXP_RECEIVE_ACK, &sep, "B");
		seq_print_rq_state_bit(m, s & RQ_EXP_WRITE_ACK, &sep, "C");
		seq_print_rq_state_bit(m, s & RQ_EXP_BARR_ACK, &sep, "barr");
		if (sep == ' ')
			seq_puts(m, " -");
	}
	seq_putc(m, '\n');
}

#define memberat(PTR, TYPE, OFFSET) (*(TYPE *)((char *)PTR + OFFSET))

static void print_one_age_or_dash(struct seq_file *m, struct bsr_request *req,
				  unsigned int set_mask, unsigned int clear_mask,
				  ktime_t now, size_t offset)
{
	struct bsr_device *device = req->device;
	struct bsr_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		unsigned int s = bsr_req_state_by_peer_device(req, peer_device);
		if (s & set_mask && !(s & clear_mask)) {
			ktime_t ktime = ktime_sub(now, memberat(req, ktime_t, offset));
			seq_printf(m, "\t[%d]%d", peer_device->node_id, (int)ktime_to_ms(ktime));
			return;
		}
	}
	seq_puts(m, "\t-");
}

static void seq_print_one_request(struct seq_file *m, struct bsr_request *req, ktime_t now, ULONG_PTR jif)
{
	/* change anything here, fixup header below! */
	unsigned int s = req->rq_state[0];

#define RQ_HDR_ "epoch\tsector\tsize\trw"
	seq_printf(m, "0x%x\t%llu\t%u\t%s",
		req->epoch,
		(unsigned long long)req->i.sector, req->i.size >> 9,
		(s & RQ_WRITE) ? "W" : "R");

#define RQ_HDR_START "\tstart"
#define RQ_HDR_AL "\tin AL"
#define RQ_HDR_SUBMIT "\tsubmit"
#define RQ_HDR_PEER "\tsent\tacked\tdone"
	if (atomic_read(&g_bsrmon_run)) {
		seq_printf(m, "\t%d", (int)ktime_to_ms(ktime_sub(now, req->start_kt)));
		seq_print_age_or_dash(m, s & RQ_IN_ACT_LOG, ktime_sub(now, req->in_actlog_kt));
		seq_print_age_or_dash(m, s & RQ_LOCAL_PENDING, ktime_sub(now, req->submit_kt));

		print_one_age_or_dash(m, req, RQ_NET_SENT, 0, now, offsetof(struct bsr_request, pre_send_kt));
		print_one_age_or_dash(m, req, RQ_NET_SENT, RQ_NET_PENDING, now, offsetof(struct bsr_request, acked_kt));
		print_one_age_or_dash(m, req, RQ_NET_DONE, 0, now, offsetof(struct bsr_request, net_done_kt));
	} else {
		seq_printf(m, "\t%d", (int)jiffies_to_msecs(jif - req->start_jif));
	}

#define RQ_HDR_STATE "\tstate\n"
	seq_print_request_state(m, req);
}
#define RQ_HDR RQ_HDR_ RQ_HDR_START RQ_HDR_STATE
#define RQ_HDR_TIMING_STAT RQ_HDR_ RQ_HDR_START RQ_HDR_AL RQ_HDR_SUBMIT RQ_HDR_PEER RQ_HDR_STATE


static void seq_print_minor_vnr_req(struct seq_file *m, struct bsr_request *req,  ktime_t now, ULONG_PTR jif)
{
	seq_printf(m, "%u\t%u\t", req->device->minor, req->device->vnr);
	seq_print_one_request(m, req, now, jif);
}

static void seq_print_resource_pending_meta_io(struct seq_file *m, struct bsr_resource *resource, ULONG_PTR now)
{
	struct bsr_device *device;
	int i;

	seq_puts(m, "minor\tvnr\tstart\tsubmit\tintent\n");
	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, i) {
		struct bsr_md_io tmp;
		/* In theory this is racy,
		 * in the sense that there could have been a
		 * bsr_md_put_buffer(); bsr_md_get_buffer();
		 * between accessing these members here.  */
		tmp = device->md_io;
		if (atomic_read(&tmp.in_use)) {
			seq_printf(m, "%u\t%u\t%u\t", device->minor, device->vnr, jiffies_to_msecs(now - tmp.start_jif));
			if (time_before(tmp.submit_jif, tmp.start_jif))
				seq_puts(m, "-\t");
			else
			seq_printf(m, "%u\t", jiffies_to_msecs(now - tmp.submit_jif));
			seq_printf(m, "%s\n", tmp.current_use);
		}
	}
	rcu_read_unlock();
}



static void seq_print_waiting_for_AL(struct seq_file *m, struct bsr_resource *resource, ktime_t now, ULONG_PTR jif)
{
	struct bsr_device *device;
	int i;
	
	seq_puts(m, "minor\tvnr\tage\t#waiting\n");
	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, i) {
		struct bsr_request *req = NULL;
		int n = atomic_read(&device->ap_actlog_cnt);
		if (n) {
			spin_lock_irq(&device->resource->req_lock);
			req = list_first_entry_or_null(&device->pending_master_completion[1],
				struct bsr_request, req_pending_master_completion);
			/* if the oldest request does not wait for the activity log
			 * it is not interesting for us here */
			if (req && (req->rq_state[0] & RQ_IN_ACT_LOG))
				req = NULL;
			spin_unlock_irq(&device->resource->req_lock);
		}
		if (n) {
			seq_printf(m, "%u\t%u\t", device->minor, device->vnr);
			if (req) {
				if (atomic_read(&g_bsrmon_run))
					seq_printf(m, "%d\t", (int)ktime_to_ms(ktime_sub(now, req->start_kt)));
				else
					seq_printf(m, "%d\t", (int)jiffies_to_msecs(jif - req->start_jif));
			} else
				seq_puts(m, "-\t");
			seq_printf(m, "%u\n", n);
		}
	}
	rcu_read_unlock();
}

static void seq_print_device_bitmap_io(struct seq_file *m, struct bsr_device *device, ULONG_PTR now)
{
	struct bsr_bm_aio_ctx *ctx;
	ULONG_PTR start_jif = 0;
	unsigned int in_flight = 0;
	unsigned int flags = 0;
	spin_lock_irq(&device->resource->req_lock);
	ctx = list_first_entry_or_null(&device->pending_bitmap_io, struct bsr_bm_aio_ctx, list);
	if (ctx && ctx->done)
		ctx = NULL;
	if (ctx) {
		start_jif = ctx->start_jif;
		in_flight = atomic_read(&ctx->in_flight);
		flags = ctx->flags;
	}
	spin_unlock_irq(&device->resource->req_lock);
	if (ctx) {
		seq_printf(m, "%u\t%u\t%c\t%u\t%u\n",
			device->minor, device->vnr,
			(flags & BM_AIO_READ) ? 'R' : 'W',
			jiffies_to_msecs(now - start_jif),
			in_flight);
	}
}

static void seq_print_resource_pending_bitmap_io(struct seq_file *m, struct bsr_resource *resource, ULONG_PTR now)
{
	struct bsr_device *device;
	int i;

	seq_puts(m, "minor\tvnr\trw\tage\t#in-flight\n");
	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, i) {
		seq_print_device_bitmap_io(m, device, now);
	}
	rcu_read_unlock();
}

/* pretty print enum peer_req->flags */
static void seq_print_peer_request_flags(struct seq_file *m, struct bsr_peer_request *peer_req)
{
	ULONG_PTR f = peer_req->flags;
	char sep = ' ';

	__seq_print_rq_state_bit(m, f & EE_SUBMITTED, &sep, "submitted", "preparing");
	__seq_print_rq_state_bit(m, f & EE_APPLICATION, &sep, "application", "internal");
	seq_print_rq_state_bit(m, f & EE_IS_BARRIER, &sep, "barr");
	seq_print_rq_state_bit(m, f & EE_SEND_WRITE_ACK, &sep, "C");
	seq_print_rq_state_bit(m, f & EE_MAY_SET_IN_SYNC, &sep, "set-in-sync");
	seq_print_rq_state_bit(m, (f & (EE_IN_ACTLOG | EE_WRITE)) == EE_WRITE, &sep, "blocked-on-al");
	seq_print_rq_state_bit(m, f & EE_TRIM, &sep, "trim");
	seq_print_rq_state_bit(m, f & EE_ZEROOUT, &sep, "zero-out");
	seq_print_rq_state_bit(m, f & EE_WRITE_SAME, &sep, "write-same");
	seq_putc(m, '\n');
}

static void seq_print_peer_request(struct seq_file *m,
	struct bsr_connection *connection, struct list_head *lh,
	ULONG_PTR now)
{
	bool reported_preparing = false;
	struct bsr_peer_request *peer_req;

	UNREFERENCED_PARAMETER(connection);

	list_for_each_entry_ex(struct bsr_peer_request, peer_req, lh, w.list) {
		struct bsr_peer_device *peer_device = peer_req->peer_device;
		struct bsr_device *device = peer_device ? peer_device->device : NULL;

		if (reported_preparing && !(peer_req->flags & EE_SUBMITTED))
			continue;

		if (device)
			seq_printf(m, "%u\t%u\t", device->minor, device->vnr);
		seq_printf(m, "%llu\t%u\t%c\t%u\t",
			(unsigned long long)peer_req->i.sector, peer_req->i.size >> 9,
			(peer_req->flags & EE_WRITE) ? 'W' : 'R',
			jiffies_to_msecs(now - peer_req->submit_jif));
		seq_print_peer_request_flags(m, peer_req);
		if (peer_req->flags & EE_SUBMITTED)
			break;
		else
			reported_preparing = true;
	}
}

static void seq_print_connection_peer_requests(struct seq_file *m,
	struct bsr_connection *connection, ULONG_PTR now)
{
	seq_puts(m, "minor\tvnr\tsector\tsize\trw\tage\tflags\n");
	spin_lock_irq(&connection->resource->req_lock);
	seq_print_peer_request(m, connection, &connection->active_ee, now);
	seq_print_peer_request(m, connection, &connection->read_ee, now);
	seq_print_peer_request(m, connection, &connection->sync_ee, now);
	spin_unlock_irq(&connection->resource->req_lock);
}

static void seq_print_device_peer_flushes(struct seq_file *m,
	struct bsr_device *device, ULONG_PTR now)
{
	if (test_bit(FLUSH_PENDING, &device->flags)) {
		seq_printf(m, "%u\t%u\t-\t-\tF\t%u\tflush\n",
			device->minor, device->vnr,
			jiffies_to_msecs(now - device->flush_jif));
	}
}

static void seq_print_resource_pending_peer_requests(struct seq_file *m,
	struct bsr_resource *resource, ULONG_PTR now)
{
	struct bsr_connection *connection;
	struct bsr_device *device;
	int i;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		seq_print_connection_peer_requests(m, connection, now);
	}
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, i) {
		seq_print_device_peer_flushes(m, device, now);
	}
	rcu_read_unlock();
}

static void seq_print_resource_transfer_log_summary(struct seq_file *m,
	struct bsr_resource *resource,
	struct bsr_connection *connection,
	ktime_t now, ULONG_PTR jif)
{
	struct bsr_request *req;
	unsigned int count = 0;
	unsigned int show_state = 0;

	UNREFERENCED_PARAMETER(connection);
	if (atomic_read(&g_bsrmon_run)) 
		seq_puts(m, "n\tdevice\tvnr\t" RQ_HDR_TIMING_STAT);
	else
		seq_puts(m, "n\tdevice\tvnr\t" RQ_HDR);
	spin_lock_irq(&resource->req_lock);
	list_for_each_entry_ex(struct bsr_request, req, &resource->transfer_log, tl_requests) {
		struct bsr_device *device = req->device;
		struct bsr_peer_device *peer_device;
		unsigned int tmp = 0;
		unsigned int s;
		++count;

		/* don't disable irq "forever" */
		if (!(count & 0x1ff)) {
			struct bsr_request *req_next;
			kref_get(&req->kref);
			spin_unlock_irq(&resource->req_lock);
			cond_resched();
			spin_lock_irq(&resource->req_lock);
            req_next = list_next_entry_ex(struct bsr_request, req, tl_requests);
			if (kref_put(&req->kref, bsr_req_destroy))
				req = req_next;
			if (&req->tl_requests == &resource->transfer_log)
				break;
		}

		s = req->rq_state[0];

		/* This is meant to summarize timing issues, to be able to tell
		 * local disk problems from network problems.
		 * Skip requests, if we have shown an even older request with
		 * similar aspects already.  */
		if (req->master_bio == NULL)
			tmp |= 1;
		if ((s & RQ_LOCAL_MASK) && (s & RQ_LOCAL_PENDING))
			tmp |= 2;

		for_each_peer_device(peer_device, device) {
			s = req->rq_state[1 + peer_device->node_id];
			if (s & RQ_NET_MASK) {
				if (!(s & RQ_NET_SENT))
					tmp |= 4;
				if (s & RQ_NET_PENDING)
					tmp |= 8;
				if (!(s & RQ_NET_DONE))
					tmp |= 16;
			}
		}
		if ((tmp & show_state) == tmp)
			continue;
		show_state |= tmp;
		seq_printf(m, "%u\t", count);
		seq_print_minor_vnr_req(m, req, now, jif);
		if (show_state == 0x1f)
			break;
	}
	spin_unlock_irq(&resource->req_lock);
}

/* TODO: transfer_log and friends should be moved to resource */
int resource_in_flight_summary_show(struct seq_file *m, void *pos)
{
	struct bsr_resource *resource = m->private;
	struct bsr_connection *connection;
	struct bsr_transport *transport;
	struct bsr_transport_stats transport_stats;
	ktime_t now = ktime_get();
	ULONG_PTR jif = jiffies;
	UNREFERENCED_PARAMETER(pos);
	connection = first_connection(resource);
	transport = &connection->transport;
	/* This does not happen, actually.
	 * But be robust and prepare for future code changes. */
	if (!connection || !kref_get_unless_zero(&connection->kref)) {
		return -ESTALE;
	}
	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	seq_puts(m, "oldest bitmap IO\n");
	seq_print_resource_pending_bitmap_io(m, resource, jif);
	seq_putc(m, '\n');

	seq_puts(m, "meta data IO\n");
	seq_print_resource_pending_meta_io(m, resource, jif);
	seq_putc(m, '\n');

	seq_puts(m, "transport buffer stats\n");
	/* for each connection ... once we have more than one */
	rcu_read_lock();
	if (transport->ops->stream_ok(transport, DATA_STREAM)) {
		transport->ops->stats(transport, &transport_stats);
		seq_printf(m, "unread receive buffer: %u Byte\n",
				transport_stats.unread_received);
		seq_printf(m, "unacked send buffer: %u Byte\n",
				transport_stats.unacked_send);
	}
	rcu_read_unlock();
	seq_putc(m, '\n');

	seq_puts(m, "oldest peer requests\n");
	seq_print_resource_pending_peer_requests(m, resource, jif);
	seq_putc(m, '\n');

	seq_puts(m, "application requests waiting for activity log\n");
	seq_print_waiting_for_AL(m, resource, now, jif);
	seq_putc(m, '\n');

	seq_puts(m, "oldest application requests\n");
	seq_print_resource_transfer_log_summary(m, resource, connection, now, jif);
	seq_putc(m, '\n');

	jif = jiffies - jif;
	if (jif)
		seq_printf(m, "generated in %u ms\n", jiffies_to_msecs(jif));
	kref_put(&connection->kref, bsr_destroy_connection);
	return 0;
}

int resource_state_twopc_show(struct seq_file *m, void *pos)
{
	struct bsr_resource *resource = m->private;
	struct twopc_reply twopc = {0,};
	bool active = false;
	ULONG_PTR jif;
	struct queued_twopc *q;

	UNREFERENCED_PARAMETER(pos);

	spin_lock_irq(&resource->req_lock);
	if (resource->remote_state_change) {
		twopc = resource->twopc_reply;
		active = true;
	}
	spin_unlock_irq(&resource->req_lock);

	seq_printf(m, "v: %u\n\n", 0);
	if (active) {
		seq_printf(m,
			   "Executing tid: %u\n"
			   "  initiator_node_id: %d\n"
			   "  target_node_id: %d\n",
			   twopc.tid, twopc.initiator_node_id,
			   twopc.target_node_id);

		if (twopc.initiator_node_id == (int)resource->res_opts.node_id) {
			struct bsr_connection *connection;

			seq_puts(m, "  peers reply's: ");
			rcu_read_lock();
			for_each_connection(connection, resource) {
				char *name = rcu_dereference((connection)->transport.net_conf)->name;

				if (!test_bit(TWOPC_PREPARED, &connection->flags))
					seq_printf(m, "%s n.p., ", name);
				else if (test_bit(TWOPC_NO, &connection->flags))
					seq_printf(m, "%s no, ", name);
				else if (test_bit(TWOPC_RETRY, &connection->flags))
					seq_printf(m, "%s ret, ", name);
				else if (test_bit(TWOPC_YES, &connection->flags))
					seq_printf(m, "%s yes, ", name);
				else seq_printf(m, "%s ___, ", name);
			}
			rcu_read_unlock();
			seq_puts(m, "\n");
		} else {
			/* The timer is only relevant for twopcs initiated by other nodes */
			jif = resource->twopc_timer.expires - jiffies;
			seq_printf(m, "  timer expires in: %u ms\n", jiffies_to_msecs(jif));
		}
	} else {
		seq_puts(m, "No ongoing two phase state transaction\n");
	}

	spin_lock_irq(&resource->queued_twopc_lock);
	if (list_empty(&resource->queued_twopc)) {
		spin_unlock_irq(&resource->queued_twopc_lock);
		return 0;
	}
	seq_puts(m, "\n Queued for later execution:\n");
	list_for_each_entry_ex(struct queued_twopc, q, &resource->queued_twopc, w.list) {
		jif = jiffies - q->start_jif;
		seq_printf(m, "  tid: %u, initiator_node_id: %d, since: %d ms\n",
			   q->reply.tid, q->reply.initiator_node_id, jiffies_to_msecs(jif));
	}
	spin_unlock_irq(&resource->queued_twopc_lock);

	return 0;
}

int bsr_version_show(struct seq_file *m, void *ignored)
{
	seq_printf(m, "# %s\n", bsr_buildtag());
	seq_printf(m, "VERSION=%s\n", REL_VERSION);
	seq_printf(m, "API_VERSION=%u\n", GENL_MAGIC_VERSION);
	seq_printf(m, "PRO_VERSION_MIN=%u\n", PRO_VERSION_MIN);
	seq_printf(m, "PRO_VERSION_MAX=%u\n", PRO_VERSION_MAX);
	return 0;
}


#ifdef _LIN
// BSR-875 collecting memory usage of BSR module
int bsr_alloc_mem_show(struct seq_file *m, void *ignored)
{
	int pages = PAGE_SIZE / 1024; // kbytes
	int io_bio_set = 0, md_io_bio_set = 0;
	long page_pool = 0;

	io_bio_set = bioset_initialized(&bsr_io_bio_set) ? BIO_POOL_SIZE * pages : 0;
	md_io_bio_set = bioset_initialized(&bsr_md_io_bio_set) ? BSR_MIN_POOL_PAGES * pages : 0;

	page_pool = atomic_read64(&mem_usage.data_pp) 
				+ atomic_read64(&mem_usage.bm_pp) + BSR_MIN_POOL_PAGES;

	/* total_bio_set kmalloc vmalloc total_page_pool */
	seq_printf(m, "%d %lld %lld %ld\n", 
				io_bio_set + md_io_bio_set,
				(long long)(atomic_read64(&mem_usage.kmalloc) ? atomic_read64(&mem_usage.kmalloc) / 1024 : 0),
				(long long)(atomic_read64(&mem_usage.vmalloc) ? atomic_read64(&mem_usage.vmalloc) / 1024 : 0),
				page_pool * pages);
	return 0;
}
#endif

static void seq_print_one_timing_detail(struct seq_file *m,
	const struct bsr_thread_timing_details *tdp,
	ULONG_PTR now)
{
	struct bsr_thread_timing_details td;
	/* No locking...
	* use temporary assignment to get at consistent data. */
	do {
		td = *tdp;
	} while (td.cb_nr != tdp->cb_nr);
	if (!td.cb_addr)
		return;
	seq_printf(m, "%u\t%d\t%s:%u\t%ps\n",
		td.cb_nr,
		jiffies_to_msecs(now - td.start_jif),
		td.caller_fn, td.line,
		td.cb_addr);
}

static void seq_print_timing_details(struct seq_file *m,
	const char *title,
	unsigned int cb_nr, struct bsr_thread_timing_details *tdp, ULONG_PTR now)
{
	unsigned int start_idx;
	unsigned int i;

	seq_printf(m, "%s\n", title);
	/* If not much is going on, this will result in natural ordering.
	* If it is very busy, we will possibly skip events, or even see wrap
	* arounds, which could only be avoided with locking.
	*/
	start_idx = cb_nr % BSR_THREAD_DETAILS_HIST;
	for (i = start_idx; i < BSR_THREAD_DETAILS_HIST; i++)
		seq_print_one_timing_detail(m, tdp + i, now);
	for (i = 0; i < start_idx; i++)
		seq_print_one_timing_detail(m, tdp + i, now);
}

int connection_callback_history_show(struct seq_file *m, void *ignored)
{
	struct bsr_connection *connection = m->private;
	struct bsr_resource *resource = connection->resource;
	ULONG_PTR jif = jiffies;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	seq_puts(m, "n\tage\tcallsite\tfn\n");
	seq_print_timing_details(m, "sender", connection->s_cb_nr, connection->s_timing_details, jif);
	seq_print_timing_details(m, "receiver", connection->r_cb_nr, connection->r_timing_details, jif);
	seq_print_timing_details(m, "worker", resource->w_cb_nr, resource->w_timing_details, jif);
	return 0;
}

int connection_debug_show(struct seq_file *m, void *ignored)
{
	struct bsr_connection *connection = m->private;
	struct bsr_resource *resource = connection->resource;
	ULONG_PTR flags = connection->flags;
	unsigned int u1, u2;
	unsigned long long ull1, ull2;
	char sep = ' ';

	seq_puts(m, "content and format of this will change without notice\n");

	seq_printf(m, "flags: 0x%04lx :", flags);
#define pretty_print_bit(n) \
	seq_print_rq_state_bit(m, test_bit(n, &flags), &sep, #n);
	pretty_print_bit(SEND_PING);
	pretty_print_bit(GOT_PING_ACK);
	pretty_print_bit(TWOPC_PREPARED);
	pretty_print_bit(TWOPC_YES);
	pretty_print_bit(TWOPC_NO);
	pretty_print_bit(TWOPC_RETRY);
	pretty_print_bit(CONN_DRY_RUN);
	pretty_print_bit(CREATE_BARRIER);
	pretty_print_bit(DISCONNECT_EXPECTED);
	pretty_print_bit(BARRIER_ACK_PENDING);
	pretty_print_bit(DATA_CORKED);
	pretty_print_bit(CONTROL_CORKED);
	pretty_print_bit(C_UNREGISTERED);
	pretty_print_bit(RECONNECT);
	pretty_print_bit(CONN_DISCARD_MY_DATA);
#undef pretty_print_bit
	seq_putc(m, '\n');

	u1 = atomic_read(&resource->current_tle_nr);
	u2 = connection->send.current_epoch_nr;
	seq_printf(m, "resource->current_tle_nr: %u\n", u1);
	seq_printf(m, "   send.current_epoch_nr: %u (%d)\n", u2, (int)(u2 - u1));

	ull1 = resource->dagtag_sector;
	ull2 = resource->last_peer_acked_dagtag;
	seq_printf(m, " resource->dagtag_sector: %llu\n", ull1);
	seq_printf(m, "  last_peer_acked_dagtag: %llu (%lld)\n", ull2, (long long)(ull2 - ull1));
	ull2 = connection->send.current_dagtag_sector;
	seq_printf(m, " send.current_dagtag_sec: %llu (%lld)\n", ull2, (long long)(ull2 - ull1));
	ull2 = connection->last_dagtag_sector;
	seq_printf(m, "      last_dagtag_sector: %llu\n", ull2);

	return 0;
}


int connection_oldest_requests_show(struct seq_file *m, void *ignored)
{
	struct bsr_connection *connection = m->private;
	ktime_t now = ktime_get();
	ULONG_PTR jif = jiffies;
	struct bsr_request *r1, *r2;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	spin_lock_irq(&connection->resource->req_lock);
	r1 = connection->todo.req_next;
	if (r1)
		seq_print_minor_vnr_req(m, r1, now, jif);
	r2 = connection->req_ack_pending;
	if (r2 && r2 != r1) {
		r1 = r2;
		seq_print_minor_vnr_req(m, r1, now, jif);
	}
	r2 = connection->req_not_net_done;
	if (r2 && r2 != r1)
		seq_print_minor_vnr_req(m, r2, now, jif);
	spin_unlock_irq(&connection->resource->req_lock);
	return 0;
}

int connection_transport_show(struct seq_file *m, void *ignored)
{
	struct bsr_connection *connection = m->private;
	struct bsr_transport *transport = &connection->transport;
	struct bsr_transport_ops *tr_ops = transport->ops;
	enum bsr_stream i;

	seq_printf(m, "v: %u\n\n", 0);

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		struct bsr_send_buffer *sbuf = &connection->send_buffer[i];
		seq_printf(m, "%s stream\n", i == DATA_STREAM ? "data" : "control");
		seq_printf(m, "  corked: %d\n", test_bit(CORKED + i, &connection->flags));
		seq_printf(m, "  unsent: %ld bytes\n", (long)(sbuf->pos - sbuf->unsent));
		seq_printf(m, "  allocated: %d bytes\n", sbuf->allocated_size);
	}

	seq_printf(m, "\ntransport_type: %s\n", transport->class->name);

	tr_ops->debugfs_show(transport, m);

	return 0;
}

// BSR-683
int connection_transport_speed_show(struct seq_file *m, void *ignored)
{
	struct bsr_connection *connection = m->private;
	struct bsr_transport *transport = &connection->transport;
	ULONG_PTR now = jiffies;
	unsigned long long sent = (unsigned long long)atomic_xchg64(&transport->sum_sent, 0);
	unsigned long long recv = (unsigned long long)atomic_xchg64(&transport->sum_recv, 0);
	int period = (int)DIV_ROUND_UP((now - transport->sum_start_time) - HZ/2, HZ);

	transport->sum_start_time = now;
	
	// BSR-740 init sum_start_time
	if (!atomic_read(&g_bsrmon_run)) {
		seq_printf(m, "err reading 'transport_speed': bsr performance monitor is not running\n");
		return 0;
	}
	
	/* sent_byte/s recv_byte/s */
	if (period > 0)
		seq_printf(m, "%llu %llu ", sent / period, recv / period);
	else
		seq_printf(m, "%llu %llu ", sent, recv);

	return 0;
}

// BSR-571
int connection_send_buf_show(struct seq_file *m, void *ignored)
{
	struct bsr_connection *connection = m->private;
	enum bsr_stream stream;
	int i = 0;

	// BSR-839 passing in_flight_cnt as sendbuf performance data
	/* ap_in_flight size_bytes cnt */
	seq_printf(m, "ap %lld %d ", (long long)atomic_read64(&connection->ap_in_flight), atomic_read(&connection->ap_in_flight_cnt));
	/* rs_in_flight size_bytes cnt */
	seq_printf(m, "rs %lld %d ", (long long)atomic_read64(&connection->rs_in_flight), atomic_read(&connection->rs_in_flight_cnt));

	for (stream = DATA_STREAM; stream <= CONTROL_STREAM; stream++) {
		struct ring_buffer *ring = connection->ptxbab[stream];
		if (ring) {
			seq_printf(m, "%s ", stream == DATA_STREAM ? "data" : "control");

			/* size_byte used*/
			seq_printf(m, "%lld %lld ", ring->length - 1, ring->sk_wmem_queued);
			for (i = 0 ; i < P_MAY_IGNORE ; i++) {
				if (ring->packet_cnt[i]) {
					/* packet_name cnt size_byte*/
					seq_printf(m, "%s %u %llu ", bsr_packet_name(i), ring->packet_cnt[i], ring->packet_size[i]);
				}
			}
		} else {
			seq_printf(m, "no send buffer ");
			break;
		}
	}
	return 0;
}

static void seq_printf_with_thousands_grouping(struct seq_file *seq, ULONG_PTR v)
{
	/* v is in kB/sec. We don't expect TiByte/sec yet. */
	if (unlikely(v >= 1000000)) {
		/* cool: > GiByte/s */
		seq_printf(seq, "%ld,", v / 1000000);
		v %= 1000000;
		seq_printf(seq, "%03ld,%03ld", v / 1000, v % 1000);
	}
	else if (likely(v >= 1000))
		seq_printf(seq, "%ld,%03ld", v / 1000, v % 1000);
	else
		seq_printf(seq, "%ld", v);
}

static void bsr_get_syncer_progress(struct bsr_peer_device *pd,
enum bsr_repl_state repl_state, ULONG_PTR *rs_total,
	ULONG_PTR *bits_left, unsigned int *per_mil_done)
{
	/* this is to break it at compile time when we change that, in case we
	* want to support more than (1<<32) bits on a 32bit arch. */
#ifdef _LIN
	typecheck(unsigned long, pd->rs_total);
#endif
	*rs_total = pd->rs_total;

	/* note: both rs_total and rs_left are in bits, i.e. in
	* units of BM_BLOCK_SIZE.
	* for the percentage, we don't care. */

	if (repl_state == L_VERIFY_S || repl_state == L_VERIFY_T)
		*bits_left = pd->ov_left;
	else
		*bits_left = bsr_bm_total_weight(pd) - pd->rs_failed;
	/* >> 10 to prevent overflow,
	* +1 to prevent division by zero */
	if (*bits_left > *rs_total) {
		/* D'oh. Maybe a logic bug somewhere.  More likely just a race
		* between state change and reset of rs_total.
		*/
		*bits_left = *rs_total;
		*per_mil_done = *rs_total ? 0 : 1000;
	}
	else {
		/* Make sure the division happens in long context.
		* We allow up to one petabyte storage right now,
		* at a granularity of 4k per bit that is 2**38 bits.
		* After shift right and multiplication by 1000,
		* this should still fit easily into a 32bit long,
		* so we don't need a 64bit division on 32bit arch.
		* Note: currently we don't support such large bitmaps on 32bit
		* arch anyways, but no harm done to be prepared for it here.
		*/
		unsigned int shift = *rs_total > UINT_MAX ? 16 : 10;
		ULONG_PTR left = *bits_left >> shift;
		ULONG_PTR total = 1UL + (*rs_total >> shift);
		ULONG_PTR tmp = 1000UL - left * 1000UL / total;
		*per_mil_done = (unsigned int)tmp;
	}
}

static void bsr_syncer_progress(struct bsr_peer_device *pd, struct seq_file *seq,
	enum bsr_repl_state repl_state)
{
	ULONG_PTR db, dt, dbdt, rt, rs_total, rs_left;
	unsigned int res;
	int i, x, y;
	int stalled = 0;

	bsr_get_syncer_progress(pd, repl_state, &rs_total, &rs_left, &res);

	x = res / 50;
	y = 20 - x;
	seq_puts(seq, "\t[");
	for (i = 1; i < x; i++)
		seq_putc(seq, '=');
	seq_putc(seq, '>');
	for (i = 0; i < y; i++)
		seq_printf(seq, ".");
	seq_puts(seq, "] ");

	if (repl_state == L_VERIFY_S || repl_state == L_VERIFY_T)
		seq_puts(seq, "verified:");
	else
		seq_puts(seq, "sync'ed:");
	seq_printf(seq, "%3u.%u%% ", res / 10, res % 10);

	/* if more than a few GB, display in MB */
	if (rs_total > (4UL << (30 - BM_BLOCK_SHIFT)))
		seq_printf(seq, "(%lu/%lu)M",
		(unsigned long)Bit2KB(rs_left >> 10),
		(unsigned long)Bit2KB(rs_total >> 10));
	else
		seq_printf(seq, "(%lu/%lu)K",
		(unsigned long)Bit2KB(rs_left),
		(unsigned long)Bit2KB(rs_total));

	seq_puts(seq, "\n\t");

	/* see drivers/md/md.c
	* We do not want to overflow, so the order of operands and
	* the * 100 / 100 trick are important. We do a +1 to be
	* safe against division by zero. We only estimate anyway.
	*
	* dt: time from mark until now
	* db: blocks written from mark until now
	* rt: remaining time
	*/
	/* Rolling marks. last_mark+1 may just now be modified.  last_mark+2 is
	* at least (BSR_SYNC_MARKS-2)*BSR_SYNC_MARK_STEP old, and has at
	* least BSR_SYNC_MARK_STEP time before it will be modified. */
	/* ------------------------ ~18s average ------------------------ */
	i = (pd->rs_last_mark + 2) % BSR_SYNC_MARKS;
	dt = (jiffies - pd->rs_mark_time[i]) / HZ;
	if (dt > 180)
		stalled = 1;

	if (!dt)
		dt++;
	db = pd->rs_mark_left[i] - rs_left;
	rt = (dt * (rs_left / (db / 100 + 1))) / 100; /* seconds */

	seq_printf(seq, "finish: %lu:%02lu:%02lu",
		rt / 3600, (rt % 3600) / 60, rt % 60);

	dbdt = Bit2KB(db / dt);
	seq_puts(seq, " speed: ");
	seq_printf_with_thousands_grouping(seq, dbdt);
	seq_puts(seq, " (");
	/* ------------------------- ~3s average ------------------------ */
	if (1) {
		/* this is what bsr_rs_should_slow_down() uses */
		i = (pd->rs_last_mark + BSR_SYNC_MARKS - 1) % BSR_SYNC_MARKS;
		dt = (jiffies - pd->rs_mark_time[i]) / HZ;
		if (!dt)
			dt++;
		db = pd->rs_mark_left[i] - rs_left;
		dbdt = Bit2KB(db / dt);
		seq_printf_with_thousands_grouping(seq, dbdt);
		seq_puts(seq, " -- ");
	}

	/* --------------------- long term average ---------------------- */
	/* mean speed since syncer started
	* we do account for PausedSync periods */
	dt = (jiffies - pd->rs_start - pd->rs_paused) / HZ;
	if (dt == 0)
		dt = 1;
	db = rs_total - rs_left;
	dbdt = Bit2KB(db / dt);
	seq_printf_with_thousands_grouping(seq, dbdt);
	seq_putc(seq, ')');

	if (repl_state == L_SYNC_TARGET ||
		repl_state == L_VERIFY_S) {
		seq_puts(seq, " want: ");
		seq_printf_with_thousands_grouping(seq, pd->c_sync_rate);
	}
	seq_printf(seq, " K/sec%s\n", stalled ? " (stalled)" : "");

	{
		/* 64 bit:
		* we convert to sectors in the display below. */
		ULONG_PTR bm_bits = bsr_bm_bits(pd->device);
		ULONG_PTR bit_pos;
		unsigned long long stop_sector = 0;
		if (repl_state == L_VERIFY_S ||
			repl_state == L_VERIFY_T) {
			bit_pos = bm_bits - pd->ov_left;
			if (verify_can_do_stop_sector(pd))
				stop_sector = pd->ov_stop_sector;
		}
		else
			bit_pos = pd->device->bm_resync_fo;
		/* Total sectors may be slightly off for oddly
		* sized devices. So what. */
		seq_printf(seq,
			"\t%3d%% sector pos: %llu/%llu",
			(int)(bit_pos / (bm_bits / 100 + 1)),
			(unsigned long long)bit_pos * BM_SECT_PER_BIT,
			(unsigned long long)bm_bits * BM_SECT_PER_BIT);
		if (stop_sector != 0 && stop_sector != ULLONG_MAX)
			seq_printf(seq, " stop sector: %llu", stop_sector);
		seq_putc(seq, '\n');
	}
}

int peer_device_proc_bsr_show(struct seq_file *m, void *ignored)
{
	struct bsr_peer_device *peer_device = m->private;
	struct bsr_device *device = peer_device->device;
	union bsr_state state;
	const char *sn;
	struct net_conf *nc;
	__u32 wp;

	state.disk = device->disk_state[NOW];
	state.pdsk = peer_device->disk_state[NOW];
	state.conn = peer_device->repl_state[NOW];
	state.role = device->resource->role[NOW];
	state.peer = peer_device->connection->peer_role[NOW];

	state.user_isp = peer_device->resync_susp_user[NOW];
	state.peer_isp = peer_device->resync_susp_peer[NOW];
	state.aftr_isp = peer_device->resync_susp_dependency[NOW];

	sn = bsr_repl_str(state.conn);

	rcu_read_lock();
	{
		/* reset device->congestion_reason */

		nc = rcu_dereference(peer_device->connection->transport.net_conf);
		wp = nc ? nc->wire_protocol - BSR_PROT_A + 'A' : ' ';
		seq_printf(m,
			"%2u: cs:%s ro:%s/%s ds:%s/%s %c %c%c%c%c%c%c\n"
			"    ns:%u nr:%u dw:%u dr:%u al:%u bm:%u "
			"lo:%d pe:[%d;%d] ua:%d ap:[%d;%d] ep:%d wo:%d pf:%lu",
			device->minor, sn,
			bsr_role_str(state.role),
			bsr_role_str(state.peer),
			bsr_disk_str(state.disk),
			bsr_disk_str(state.pdsk),
			wp,
			bsr_suspended(device) ? 's' : 'r',
			state.aftr_isp ? 'a' : '-',
			state.peer_isp ? 'p' : '-',
			state.user_isp ? 'u' : '-',
			'-' /* congestion reason... FIXME */,
			test_bit(AL_SUSPENDED, &device->flags) ? 's' : '-',
			peer_device->send_cnt/2,
			peer_device->recv_cnt/2,
			device->writ_cnt/2,
			device->read_cnt/2,
			device->al_writ_cnt,
			device->bm_writ_cnt,
			atomic_read(&device->local_cnt),
			atomic_read(&peer_device->ap_pending_cnt),
			atomic_read(&peer_device->rs_pending_cnt),
			atomic_read(&peer_device->unacked_cnt),
			atomic_read(&device->ap_bio_cnt[WRITE]),
			atomic_read(&device->ap_bio_cnt[READ]),
			peer_device->connection->epochs,
			device->resource->write_ordering,
			peer_device->flags
			);
		seq_printf(m, " oos:%llu\n",
			Bit2KB((unsigned long long)
			bsr_bm_total_weight(peer_device)));
	}
	if (state.conn == L_SYNC_SOURCE ||
		state.conn == L_SYNC_TARGET ||
		state.conn == L_VERIFY_S ||
		state.conn == L_VERIFY_T)
		bsr_syncer_progress(peer_device, m, state.conn);

	if (get_ldev_if_state(device, D_FAILED)) {
		lc_seq_printf_stats(m, peer_device->resync_lru);
		lc_seq_printf_stats(m, device->act_log);
		put_ldev(__FUNCTION__, device);
	}

	seq_printf(m, "\tblocked on activity log: %d\n", atomic_read(&device->ap_actlog_cnt));

	rcu_read_unlock();

	return 0;
}

static void resync_dump_detail(struct seq_file *m, struct lc_element *e)
{
	struct bm_extent *bme = lc_entry(e, struct bm_extent, lce);

	seq_printf(m, "%5d %s %s %s", bme->rs_left,
		test_bit(BME_NO_WRITES, &bme->flags) ? "NO_WRITES" : "---------",
		test_bit(BME_LOCKED, &bme->flags) ? "LOCKED" : "------",
		test_bit(BME_PRIORITY, &bme->flags) ? "PRIORITY" : "--------"
		);
}

int peer_device_resync_extents_show(struct seq_file *m, void *ignored)
{
	struct bsr_peer_device *peer_device = m->private;
	struct bsr_device *device = peer_device->device;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	if (get_ldev_if_state(device, D_FAILED)) {
		lc_seq_printf_stats(m, peer_device->resync_lru);
		lc_seq_dump_details(m, peer_device->resync_lru, "rs_left flags", resync_dump_detail);
		put_ldev(__FUNCTION__, device);
	}
	return 0;
}

// BSR-970 change resync_ratio to peer_device's entry
int peer_device_resync_ratio_show(struct seq_file *m, void *ignored)
{
	struct bsr_peer_device *peer_device = m->private;
	struct bsr_device *device = peer_device->device;

	long long cur_repl_sended, cur_resync_sended, repl_sended, resync_sended, resync_sended_percent;

	if (!get_ldev_if_state(device, D_FAILED)) 
		return -ENODEV;
	
	cur_repl_sended = cur_resync_sended = repl_sended = resync_sended = resync_sended_percent = 0;

	repl_sended = atomic_read64(&peer_device->repl_sended);
	resync_sended = atomic_read64(&peer_device->resync_sended);

	if (resync_sended > 0 && repl_sended > 0) {
		if (resync_sended * 100 < repl_sended)
			resync_sended_percent = 100 - (repl_sended * 100 / (repl_sended + resync_sended));
		else
			resync_sended_percent = resync_sended * 100 / (repl_sended + resync_sended);
	} else if (resync_sended > 0 && repl_sended == 0) {
		resync_sended_percent = 100;
	} 
	seq_printf(m, "%lld %lld %lld ", repl_sended, resync_sended, resync_sended_percent);

	put_ldev(__FUNCTION__, device);

	return 0;
}

int device_act_log_extents_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	if (get_ldev_if_state(device, D_FAILED)) {
		lc_seq_printf_stats(m, device->act_log);
		lc_seq_dump_details(m, device->act_log, "", NULL);
		put_ldev(__FUNCTION__, device);
	}
	return 0;
}

int device_oldest_requests_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;
	struct bsr_resource *resource = device->resource;
	ktime_t now = ktime_get();
	ULONG_PTR jif = jiffies;
	struct bsr_request *r1, *r2;
	int i;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	if (atomic_read(&g_bsrmon_run)) 
		seq_puts(m, RQ_HDR_TIMING_STAT);
	else
		seq_puts(m, RQ_HDR); 
	spin_lock_irq(&resource->req_lock);
	/* WRITE, then READ */
	for (i = 1; i >= 0; --i) {
		r1 = list_first_entry_or_null(&device->pending_master_completion[i],
		struct bsr_request, req_pending_master_completion);
		r2 = list_first_entry_or_null(&device->pending_completion[i],
		struct bsr_request, req_pending_local);
		if (r1)
			seq_print_one_request(m, r1, now, jif);
		if (r2 && r2 != r1)
			seq_print_one_request(m, r2, now, jif);
	}
	spin_unlock_irq(&resource->req_lock);
	return 0;
}

int device_data_gen_id_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;
	struct bsr_md *md;
	int node_id, i = 0;

	if (!get_ldev_if_state(device, D_FAILED))
		return -ENODEV;

	md = &device->ldev->md;

	spin_lock_irq(&md->uuid_lock);
	seq_printf(m, "0x%016llX\n", bsr_current_uuid(device));

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		if (md->peers[node_id].bitmap_index == -1)
			continue;
		seq_printf(m, "%s[%d]0x%016llX", i++ ? " " : "", node_id,
			md->peers[node_id].bitmap_uuid);
	}
	seq_putc(m, '\n');

	for (i = 0; i < HISTORY_UUIDS; i++)
		seq_printf(m, "0x%016llX\n", bsr_history_uuid(device, i));
	spin_unlock_irq(&md->uuid_lock);
	put_ldev(__FUNCTION__, device);
	return 0;
}

int device_io_frozen_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;

	if (!get_ldev_if_state(device, D_FAILED))
		return -ENODEV;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	seq_printf(m, "bsr_suspended(): %d", bsr_suspended(device));
	seq_printf(m, "suspend_cnt: %d\n", atomic_read(&device->suspend_cnt));
	seq_printf(m, "!bsr_state_is_stable(): %d", !bsr_state_is_stable(device));
	seq_printf(m, "ap_bio_cnt[READ]: %d\n", atomic_read(&device->ap_bio_cnt[READ]));
	seq_printf(m, "ap_bio_cnt[WRITE]: %d\n", atomic_read(&device->ap_bio_cnt[WRITE]));
	seq_printf(m, "device->pending_bitmap_work.n: %d\n", atomic_read(&device->pending_bitmap_work.n));
	seq_printf(m, "may_inc_ap_bio(): %d\n", may_inc_ap_bio(device));
	put_ldev(__FUNCTION__, device);

	return 0;
}

int device_ed_gen_id_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;
	seq_printf(m, "0x%016llX\n", (unsigned long long)device->exposed_data_uuid);
	return 0;
}


#define PRId64 "lld"
#define show_stat(NAME, M, NUM)						\
	seq_printf(m, "%" PRId64 " %" PRId64 " %" PRId64,	\
			ktime_to_us(M.min_val), ktime_to_us(M.max_val),	\
			NUM > 0 ? ktime_to_us(M.total_val) / NUM : 0);	\
	seq_printf(m, " ")

#define show_req_stat(device, NAME, M)	show_stat(NAME, device->M, device->reqs)
#define show_peer_req_stat(peer_device, NAME, M)	show_stat(NAME, peer_device->M, peer_device->p_reqs)


#define show_al_stat(V1, V2) \
	seq_printf(m, "%lu %lu ", device->act_log->V1, device->act_log->V2)

static void device_act_log_stat_reset(struct bsr_device * device)
{
	device->act_log->used_max = 0;
	device->act_log->hits_cnt = 0;
	device->act_log->misses_cnt = 0;
	device->act_log->starving_cnt = 0;
	device->act_log->locked_cnt = 0;
	device->act_log->changed_cnt = 0;

	device->e_al_starving = 0;
	device->e_al_pending = 0;
	device->e_al_used = 0;
	device->e_al_busy = 0;
	device->e_al_wouldblock = 0;
	
	device->al_wait_retry_total = 0;
	device->al_wait_retry_max = 0;
}

extern atomic_t g_fake_al_used;

// BSR-765 add AL performance aggregation
int device_act_log_stat_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;

	// BSR-776 to avoid panic, check the device with get_ldev
	if (!get_ldev_if_state(device, D_FAILED)) 
		return -ENODEV;

	if (!atomic_read(&g_bsrmon_run)) {
		seq_printf(m, "err reading 'act_log_stat': bsr performance monitor is not running\n");
		device_act_log_stat_reset(device);
		put_ldev(__FUNCTION__, device);

		return 0;
	}

	spin_lock_irq(&device->al_lock);
	/* nr_elements used used_max*/
	seq_printf(m, "%u %u %u ",
		device->act_log->nr_elements, (device->act_log->used + atomic_read(&g_fake_al_used)), device->act_log->used_max);

	/*hits_cnt hits misses_cnt misses starving_cnt starving locked_cnt locked changed_cnt changed */
	show_al_stat(hits_cnt, hits);
	show_al_stat(misses_cnt, misses);
	show_al_stat(starving_cnt, starving);
	show_al_stat(locked_cnt, locked);
	show_al_stat(changed_cnt, changed);

	/* al_wait_retry_cnt al_wait_retry_total al_wait_retry_max*/
	seq_printf(m, "%u %u %u ",
		device->al_wait_retry_cnt, 
		device->al_wait_retry_total, 
		device->al_wait_retry_max);

	/* pending_changes max_pending_changes*/
	seq_printf(m, "%u %u ",
		device->act_log->pending_changes, device->act_log->max_pending_changes);

	/* e_al_starving  e_al_pending e_al_used e_al_busy e_al_wouldblock */
	seq_printf(m, "%u %u %u %u %u ",
		device->e_al_starving, 
		device->e_al_pending, 
		device->e_al_used, 
		device->e_al_busy, 
		device->e_al_wouldblock);
	
	/* flags ... */
	if(test_bit(__LC_PARANOIA, &device->act_log->flags))
		seq_printf(m, "__LC_PARANOIA ");
	if(test_bit(__LC_DIRTY, &device->act_log->flags))
		seq_printf(m, "__LC_DIRTY ");
	if(test_bit(__LC_LOCKED, &device->act_log->flags))
		seq_printf(m, "__LC_LOCKED ");
	if(test_bit(__LC_STARVING, &device->act_log->flags))
		seq_printf(m, "__LC_STARVING ");

	device_act_log_stat_reset(device);

	spin_unlock_irq(&device->al_lock);
	
	put_ldev(__FUNCTION__, device);

	seq_printf(m, "\n");
	return 0;
}


int device_io_complete_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;
	struct timing_stat local;
	struct timing_stat master;

	// BSR-776 to avoid panic, check the device with get_ldev
	if (!get_ldev_if_state(device, D_FAILED)) 
		return -ENODEV;

	// BSR-740 init perf data
	if (!atomic_read(&g_bsrmon_run)) {
		seq_printf(m, "err reading 'io_complete': bsr performance monitor is not running\n");
		memset(&device->local_complete_kt, 0, sizeof(struct timing_stat));
		memset(&device->master_complete_kt, 0, sizeof(struct timing_stat));
		put_ldev(__FUNCTION__, device);
		return 0;
	}
	local = device->local_complete_kt;
	master = device->master_complete_kt;

	memset(&device->local_complete_kt, 0, sizeof(struct timing_stat));
	memset(&device->master_complete_kt, 0, sizeof(struct timing_stat));

	// BSR-1072 add completed local/master IO count data
	/* local_cnt local_min local_max local_avg master_cnt master_min master_max master_avg */
	seq_printf(m, "%u %lld %lld %lld %u %lld %lld %lld\n",
			atomic_read(&local.cnt),
			ktime_to_us(local.min_val), 
			ktime_to_us(local.max_val), 
			atomic_read(&local.cnt) > 0 ? 
				ktime_to_us(local.total_val) / atomic_read(&local.cnt) : 0,
			atomic_read(&master.cnt),
			ktime_to_us(master.min_val), 
			ktime_to_us(master.max_val), 
			atomic_read(&master.cnt) > 0 ? 
				ktime_to_us(master.total_val) / atomic_read(&master.cnt) : 0);
	put_ldev(__FUNCTION__, device);
	return 0;
}

int device_io_stat_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;
	ktime_t now = ktime_get();
	unsigned int period = 0;
	unsigned int read_io_cnt, write_io_cnt = 0;
	unsigned int read_io_size, write_io_size = 0;

	// BSR-776 to avoid panic, check the device with get_ldev
	if (!get_ldev_if_state(device, D_FAILED)) 
		return -ENODEV;
	
	// BSR-740 init perf data
	if (!atomic_read(&g_bsrmon_run)) {
		seq_printf(m, "err reading 'io_stat': bsr performance monitor is not running\n");
		atomic_set(&device->io_cnt[READ], 0);
		atomic_set(&device->io_cnt[WRITE], 0);
		atomic_set(&device->io_size[READ], 0);
		atomic_set(&device->io_size[WRITE], 0);
		device->aggregation_start_kt = now;
		put_ldev(__FUNCTION__, device);
		return 0;
	}
	period = (unsigned int)DIV_ROUND_UP(ktime_to_ms(ktime_sub(now, device->aggregation_start_kt)) - HZ/2, HZ);

	read_io_cnt = atomic_xchg(&device->io_cnt[READ], 0);
	write_io_cnt = atomic_xchg(&device->io_cnt[WRITE], 0);
	read_io_size = atomic_xchg(&device->io_size[READ], 0);
	write_io_size = atomic_xchg(&device->io_size[WRITE], 0);

	// BSR-687 I/O throughput and latency	
	/* riops rios rkbs rkb wiops wios rkbs rkb */
	if (period > 0) {
		seq_printf(m, "%u %u %u %u %u %u %u %u\n",
				read_io_cnt / period, read_io_cnt,
				read_io_size / period, read_io_size,
				write_io_cnt / period, write_io_cnt,
				write_io_size / period, write_io_size);
	}
	else {
		// BSR-776 also output aggregated data in less than 1 second
		seq_printf(m, "%u %u %u %u %u %u %u %u\n",
				read_io_cnt, read_io_cnt,
				read_io_size, read_io_size,
				write_io_cnt, write_io_cnt,
				write_io_size, write_io_size);
	}
	device->aggregation_start_kt = now;
	put_ldev(__FUNCTION__, device);
	return 0;
}

// BSR-1054
int device_io_pending_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;
	struct io_pending_info *io_pending = NULL;
	unsigned long flags;
	ktime_t pending_latency;

	// to avoid panic, check the device with get_ldev
	if (!get_ldev_if_state(device, D_FAILED)) 
		return -ENODEV;
	
	if (!atomic_read(&g_bsrmon_run)) {
		seq_printf(m, "err reading 'io_pending': bsr performance monitor is not running\n");
		put_ldev(__FUNCTION__, device);
		return 0;
	}

	spin_lock_irqsave(&device->io_pending_list_lock, flags);
	pending_latency = device->io_pending_latency;
	if (!ktime_to_us(pending_latency)) {
		io_pending = list_first_entry_or_null(&device->io_pending_list, struct io_pending_info, list);
		if (io_pending)
			pending_latency = ktime_sub(ktime_get(), io_pending->io_start_kt);
	} else {
		// reset after reading io_pending_latency
		device->io_pending_latency = ns_to_ktime(0);
	}
	spin_unlock_irqrestore(&device->io_pending_list_lock, flags);

	// upper_pending pending_latency lower_pending al_suspended al_pending_changes al_wait_req upper_blocked suspended suspend_cnt unstable pending_bitmap_work
	seq_printf(m, "%d %llu %d %d %d %d %d %d %d %d %d\n",
			atomic_read(&device->ap_bio_cnt[READ]) + atomic_read(&device->ap_bio_cnt[WRITE]),
			ktime_to_us(pending_latency),
			atomic_read(&device->local_cnt) - 1,
			test_bit(AL_SUSPENDED, &device->flags),
			device->act_log->pending_changes,
			atomic_read(&device->ap_actlog_cnt),
			!may_inc_ap_bio(device),
			bsr_suspended(device),
			atomic_read(&device->suspend_cnt),
			!bsr_state_is_stable(device),
			atomic_read(&device->pending_bitmap_work.n));

	put_ldev(__FUNCTION__, device);
	return 0;
}

/* must_hold resource->req_lock */
static void device_req_timing_reset(struct bsr_device * device)
{
	struct bsr_peer_device *peer_device;

	device->reqs = 0;

	memset(&device->in_actlog_kt, 0, sizeof(struct timing_stat));
	memset(&device->submit_kt, 0, sizeof(struct timing_stat));
	memset(&device->bio_endio_kt, 0, sizeof(struct timing_stat));
	
	memset(&device->before_queue_kt, 0, sizeof(struct timing_stat));
	memset(&device->before_al_begin_io_kt, 0, sizeof(struct timing_stat));
	
	memset(&device->al_before_bm_write_hinted_kt, 0, sizeof(struct timing_stat));
	memset(&device->al_after_bm_write_hinted_kt, 0, sizeof(struct timing_stat));
	memset(&device->al_after_sync_page_kt, 0, sizeof(struct timing_stat));
	
	memset(&device->req_destroy_kt, 0, sizeof(struct timing_stat));

	// BSR-938
	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		peer_device->reqs = 0;
		memset(&peer_device->pre_send_kt, 0, sizeof(struct timing_stat));
		memset(&peer_device->acked_kt, 0, sizeof(struct timing_stat));
		memset(&peer_device->net_done_kt, 0, sizeof(struct timing_stat));
	}
	rcu_read_unlock();
}

int device_req_timing_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;
	struct bsr_peer_device *peer_device;
	unsigned long flags;
	unsigned int al_cnt = 0;

	// BSR-776 to avoid panic, check the device with get_ldev
	if (!get_ldev_if_state(device, D_FAILED)) 
		return -ENODEV;

	// BSR-740 init perf data
	if (!atomic_read(&g_bsrmon_run)) {
		seq_printf(m, "err reading 'req_timing': bsr performance monitor is not running\n");
		device_req_timing_reset(device);
		atomic_set(&device->al_updates_cnt, 0);
		put_ldev(__FUNCTION__, device);
		return 0;
	}

	spin_lock_irqsave(&device->timing_lock, flags);

	al_cnt = atomic_xchg(&device->al_updates_cnt, 0);
	/* req count */
	seq_printf(m, "%s %lu ", "req", device->reqs);

	show_req_stat(device, "before_queue", before_queue_kt);
	show_req_stat(device, "before_al_begin", before_al_begin_io_kt);
	show_req_stat(device, "in_actlog", in_actlog_kt);
	show_req_stat(device, "submit", submit_kt);
	show_req_stat(device, "bio_endio", bio_endio_kt);
	show_req_stat(device, "destroy", req_destroy_kt);

	seq_printf(m, "%s %u ", "al", al_cnt);
	show_stat("before_bm_write", device->al_before_bm_write_hinted_kt, al_cnt);
	show_stat("after_bm_write", device->al_after_bm_write_hinted_kt, al_cnt);
	show_stat("after_sync_page", device->al_after_sync_page_kt, al_cnt);

	// BSR-938 you can remove the list while forwarding it, so use rcu lock.
	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		struct bsr_connection *connection = peer_device->connection;
		seq_printf(m, "%s ", rcu_dereference(connection->transport.net_conf)->name);
		show_req_stat(peer_device, "pre_send", pre_send_kt);
		show_req_stat(peer_device, "acked", acked_kt);
		show_req_stat(peer_device, "net_done", net_done_kt);
	}
	rcu_read_unlock();

	seq_printf(m, "\n");
	device_req_timing_reset(device);

	spin_unlock_irqrestore(&device->timing_lock, flags);
	put_ldev(__FUNCTION__, device);

	return 0;
}


static void peer_req_timing_reset(struct bsr_peer_device * peer_device)
{
	peer_device->p_reqs = 0;

	memset(&peer_device->p_submit_kt, 0, sizeof(struct timing_stat));
	memset(&peer_device->p_bio_endio_kt, 0, sizeof(struct timing_stat));
	memset(&peer_device->p_destroy_kt, 0, sizeof(struct timing_stat));
}

// BSR-764 peer request latency	
int device_peer_req_timing_show(struct seq_file *m, void *ignored)
{
	struct bsr_device *device = m->private;
	struct bsr_peer_device *peer_device;
	unsigned long flags;

	// BSR-776 to avoid panic, check the device with get_ldev
	if (!get_ldev_if_state(device, D_FAILED)) 
		return -ENODEV;

	if (!atomic_read(&g_bsrmon_run)) {
		seq_printf(m, "err reading 'peer_req_timing': bsr performance monitor is not running\n");
		put_ldev(__FUNCTION__, device);
		return 0;
	}

	// BSR-938
	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		struct bsr_connection *connection = peer_device->connection;
		spin_lock_irqsave(&peer_device->timing_lock, flags);
		/* peer name */
		seq_printf(m, "%s ", rcu_dereference(connection->transport.net_conf)->name);
		/* req count */
		seq_printf(m, "%lu ", peer_device->p_reqs); 
		show_peer_req_stat(peer_device, "submit", p_submit_kt);
		show_peer_req_stat(peer_device, "bio_endio", p_bio_endio_kt);
		show_peer_req_stat(peer_device, "destroy", p_destroy_kt);
		peer_req_timing_reset(peer_device);
		spin_unlock_irqrestore(&peer_device->timing_lock, flags);
	}
	rcu_read_unlock();

	seq_printf(m, "\n");
	
	put_ldev(__FUNCTION__, device);
	

	return 0;
}

#ifdef _LIN
/* make sure at *open* time that the respective object won't go away. */
static int bsr_single_open(struct file *file, int (*show)(struct seq_file *, void *),
		                void *data, struct kref *kref,
				void (*release)(struct kref *))
{
	struct dentry *parent;
	int ret = -ESTALE;

	/* Are we still linked,
	 * or has debugfs_remove() already been called? */
	parent = file->f_path.dentry->d_parent;
	/* not sure if this can happen: */
	if (!parent || !parent->d_inode)
		goto out;
	/* serialize with d_delete() */
	// BSR-935 fix deadlock between bsr_single_open() and debugfs_remove()
	if (!bsr_inode_trylock(d_inode(parent)))
		goto out;
	/* Make sure the object is still alive */
	if (simple_positive(file->f_path.dentry)
	&& kref_get_unless_zero(kref))
		ret = 0;
	bsr_inode_unlock(d_inode(parent));
	if (!ret) {
		ret = single_open(file, show, data);
		if (ret)
			kref_put(kref, release);
	}
out:
	return ret;
}

static int resource_attr_release(struct inode *inode, struct file *file)
{
	struct bsr_resource *resource = inode->i_private;
	kref_put(&resource->kref, bsr_destroy_resource);
	return single_release(inode, file);
}

#define bsr_debugfs_resource_attr(name)				\
static int resource_ ## name ## _open(struct inode *inode, struct file *file) \
{									\
	struct bsr_resource *resource = inode->i_private;		\
	return bsr_single_open(file, resource_ ## name ## _show, resource, \
				&resource->kref, bsr_destroy_resource); \
}									\
static const struct file_operations resource_ ## name ## _fops = {	\
	.owner		= THIS_MODULE,					\
	.open		= resource_ ## name ## _open,			\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= resource_attr_release,			\
};

bsr_debugfs_resource_attr(in_flight_summary)
bsr_debugfs_resource_attr(state_twopc)

// BSR-1096 change debugfs file permissions 0400 -> 0444
#define bsr_dcf(top, obj, attr) do {		\
	dentry = debugfs_create_file(#attr, S_IRUGO,	\
			top, obj, &obj ## _ ## attr ## _fops);	\
	if (IS_ERR_OR_NULL(dentry))				\
		goto fail;					\
	top ## _ ## attr = dentry;				\
	} while (0)

#define res_dcf(attr) \
	bsr_dcf(resource->debugfs_res, resource, attr)

#define conn_dcf(attr) \
	bsr_dcf(connection->debugfs_conn, connection, attr)

#define vol_dcf(attr) \
	bsr_dcf(device->debugfs_vol, device, attr)

#define peer_dev_dcf(attr) \
	bsr_dcf(peer_device->debugfs_peer_dev, peer_device, attr)

void bsr_debugfs_resource_add(struct bsr_resource *resource)
{
	struct dentry *dentry;
	if (!bsr_debugfs_resources)
		return;

	dentry = debugfs_create_dir(resource->name, bsr_debugfs_resources);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	resource->debugfs_res = dentry;

	dentry = debugfs_create_dir("volumes", resource->debugfs_res);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	resource->debugfs_res_volumes = dentry;

	dentry = debugfs_create_dir("connections", resource->debugfs_res);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	resource->debugfs_res_connections = dentry;

	/* debugfs create file */
	res_dcf(in_flight_summary);
	res_dcf(state_twopc);

	return;

fail:
	bsr_debugfs_resource_cleanup(resource);
	bsr_err(11, BSR_LC_ETC, resource, "failed to create debugfs entries");
}

static void bsr_debugfs_remove(struct dentry **dp)
{
	debugfs_remove(*dp);
	*dp = NULL;
}

void bsr_debugfs_resource_cleanup(struct bsr_resource *resource)
{
	/* Older kernels have a broken implementation of
	 * debugfs_remove_recursive (prior to upstream commit 776164c1f)
	 * That unfortunately includes a number of "enterprise" kernels.
	 * Even older kernels do not even have the _recursive() helper at all.
	 * For now, remember all debugfs nodes we created,
	 * and call debugfs_remove on all of them separately.
	 */
	/* it is ok to call debugfs_remove(NULL) */
	bsr_debugfs_remove(&resource->debugfs_res_state_twopc);
	bsr_debugfs_remove(&resource->debugfs_res_in_flight_summary);
	bsr_debugfs_remove(&resource->debugfs_res_connections);
	bsr_debugfs_remove(&resource->debugfs_res_volumes);
	bsr_debugfs_remove(&resource->debugfs_res);
}

static int connection_attr_release(struct inode *inode, struct file *file)
{
	struct bsr_connection *connection = inode->i_private;
	kref_put(&connection->kref, bsr_destroy_connection);
	return single_release(inode, file);
}

#define bsr_debugfs_connection_attr(name)				\
static int connection_ ## name ## _open(struct inode *inode, struct file *file) \
{									\
	struct bsr_connection *connection = inode->i_private;		\
	return bsr_single_open(file, connection_ ## name ## _show,	\
				connection, &connection->kref,		\
				bsr_destroy_connection);		\
}									\
static const struct file_operations connection_ ## name ## _fops = {	\
	.owner		= THIS_MODULE,				      	\
	.open		= connection_ ## name ##_open,			\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= connection_attr_release,			\
};

bsr_debugfs_connection_attr(oldest_requests)
bsr_debugfs_connection_attr(callback_history)
bsr_debugfs_connection_attr(transport)
bsr_debugfs_connection_attr(transport_speed)
bsr_debugfs_connection_attr(debug)
bsr_debugfs_connection_attr(send_buf)

void bsr_debugfs_connection_add(struct bsr_connection *connection)
{
	struct dentry *conns_dir = connection->resource->debugfs_res_connections;
	struct bsr_peer_device *peer_device;
	char conn_name[SHARED_SECRET_MAX];
	struct dentry *dentry;
	int vnr;

	if (!conns_dir)
		return;

	rcu_read_lock();
	strncpy(conn_name, rcu_dereference(connection->transport.net_conf)->name, sizeof(conn_name) - 1);
	rcu_read_unlock();

	dentry = debugfs_create_dir(conn_name, conns_dir);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	connection->debugfs_conn = dentry;

	/* debugfs create file */
	conn_dcf(callback_history);
	conn_dcf(oldest_requests);
	conn_dcf(transport);
	conn_dcf(transport_speed);
	conn_dcf(debug);
	conn_dcf(send_buf);

	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if (!peer_device->debugfs_peer_dev)
			bsr_debugfs_peer_device_add(peer_device);
	}

	return;

fail:
	bsr_debugfs_connection_cleanup(connection);
	bsr_err(12, BSR_LC_ETC, connection, "failed to create debugfs entries");
}

void bsr_debugfs_connection_cleanup(struct bsr_connection *connection)
{
	bsr_debugfs_remove(&connection->debugfs_conn_send_buf);
	bsr_debugfs_remove(&connection->debugfs_conn_debug);
	bsr_debugfs_remove(&connection->debugfs_conn_transport);
	bsr_debugfs_remove(&connection->debugfs_conn_transport_speed);
	bsr_debugfs_remove(&connection->debugfs_conn_callback_history);
	bsr_debugfs_remove(&connection->debugfs_conn_oldest_requests);
	bsr_debugfs_remove(&connection->debugfs_conn);
}

static int device_attr_release(struct inode *inode, struct file *file)
{
	struct bsr_device *device = inode->i_private;
	kref_put(&device->kref, bsr_destroy_device);
	return single_release(inode, file);
}

#define __bsr_debugfs_device_attr(name, write_fn)						\
static int device_ ## name ## _open(struct inode *inode, struct file *file)	\
{										\
	struct bsr_device *device = inode->i_private;				\
	return bsr_single_open(file, device_ ## name ## _show, device,		\
				&device->kref, bsr_destroy_device);		\
}										\
static const struct file_operations device_ ## name ## _fops = {		\
	.owner		= THIS_MODULE,						\
	.open		= device_ ## name ## _open,				\
	.write          = write_fn,						\
	.read		= seq_read,						\
	.llseek		= seq_lseek,						\
	.release	= device_attr_release,					\
};

#define bsr_debugfs_device_attr(name) __bsr_debugfs_device_attr(name, NULL)

bsr_debugfs_device_attr(oldest_requests)
bsr_debugfs_device_attr(act_log_extents)
bsr_debugfs_device_attr(act_log_stat) // BSR-765
bsr_debugfs_device_attr(data_gen_id)
bsr_debugfs_device_attr(io_frozen)
bsr_debugfs_device_attr(ed_gen_id)

bsr_debugfs_device_attr(io_stat)
bsr_debugfs_device_attr(io_complete)
bsr_debugfs_device_attr(io_pending) // BSR-1054
bsr_debugfs_device_attr(req_timing)
bsr_debugfs_device_attr(peer_req_timing)

void bsr_debugfs_device_add(struct bsr_device *device)
{
	struct dentry *vols_dir = device->resource->debugfs_res_volumes;
	struct bsr_peer_device *peer_device;
	char minor_buf[8]; /* MINORMASK, MINORBITS == 20; */
	char vnr_buf[8];   /* volume number vnr is even 16 bit only; */
	char *slink_name = NULL;

	struct dentry *dentry;
	if (!vols_dir || !bsr_debugfs_minors)
		return;

	snprintf(vnr_buf, sizeof(vnr_buf), "%u", device->vnr);
	dentry = debugfs_create_dir(vnr_buf, vols_dir);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	device->debugfs_vol = dentry;

	snprintf(minor_buf, sizeof(minor_buf), "%u", device->minor);
	slink_name = kasprintf(GFP_KERNEL, "../resources/%s/volumes/%u",
			device->resource->name, device->vnr);
	if (!slink_name)
		goto fail;
	dentry = debugfs_create_symlink(minor_buf, bsr_debugfs_minors, slink_name);
	kfree(slink_name);
	slink_name = NULL;
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	device->debugfs_minor = dentry;

	/* debugfs create file */
	vol_dcf(oldest_requests);
	vol_dcf(act_log_extents);
	vol_dcf(act_log_stat); // BSR-765
	vol_dcf(data_gen_id);
	vol_dcf(io_frozen);
	vol_dcf(ed_gen_id);
	vol_dcf(io_stat);
	vol_dcf(io_complete);
	vol_dcf(io_pending); // BSR-1054
	vol_dcf(req_timing);
	vol_dcf(peer_req_timing);
	

	/* Caller holds conf_update */
	for_each_peer_device(peer_device, device) {
		if (!peer_device->debugfs_peer_dev)
			bsr_debugfs_peer_device_add(peer_device);
	}

	return;

fail:
	bsr_debugfs_device_cleanup(device);
	bsr_err(13, BSR_LC_ETC, device, "failed to create debugfs entries");
}

void bsr_debugfs_device_cleanup(struct bsr_device *device)
{
	bsr_debugfs_remove(&device->debugfs_minor);
	bsr_debugfs_remove(&device->debugfs_vol_oldest_requests);
	bsr_debugfs_remove(&device->debugfs_vol_act_log_extents);
	bsr_debugfs_remove(&device->debugfs_vol_act_log_stat); // BSR-765
	bsr_debugfs_remove(&device->debugfs_vol_data_gen_id);
	bsr_debugfs_remove(&device->debugfs_vol_io_frozen);
	bsr_debugfs_remove(&device->debugfs_vol_ed_gen_id);
	bsr_debugfs_remove(&device->debugfs_vol_io_stat);
	bsr_debugfs_remove(&device->debugfs_vol_io_complete);
	bsr_debugfs_remove(&device->debugfs_vol_io_pending); // BSR-1054
	bsr_debugfs_remove(&device->debugfs_vol_req_timing);
	bsr_debugfs_remove(&device->debugfs_vol_peer_req_timing);
	bsr_debugfs_remove(&device->debugfs_vol);
}

static int bsr_single_open_peer_device(struct file *file,
					int (*show)(struct seq_file *, void *),
					struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_connection *connection = peer_device->connection;
	bool got_connection, got_device;
	struct dentry *parent;

	parent = file->f_path.dentry->d_parent;
	if (!parent || !parent->d_inode)
		goto out;
	// BSR-935 fix deadlock between bsr_single_open() and debugfs_remove()
	if (!bsr_inode_trylock(d_inode(parent)))
		goto out;
	if (!simple_positive(file->f_path.dentry))
		goto out_unlock;

	got_connection = kref_get_unless_zero(&connection->kref);
	got_device = kref_get_unless_zero(&device->kref);

	if (got_connection && got_device) {
		int ret;
		bsr_inode_unlock(d_inode(parent));
		ret = single_open(file, show, peer_device);
		if (ret) {
			kref_put(&connection->kref, bsr_destroy_connection);
			kref_put(&device->kref, bsr_destroy_device);
		}
		return ret;
	}

	if (got_connection)
		kref_put(&connection->kref, bsr_destroy_connection);
	if (got_device)
		kref_put(&device->kref, bsr_destroy_device);
out_unlock:
	bsr_inode_unlock(d_inode(parent));
out:
	return -ESTALE;
}

#define bsr_debugfs_peer_device_attr(name)					\
static int peer_device_ ## name ## _open(struct inode *inode, struct file *file)\
{										\
	struct bsr_peer_device *peer_device = inode->i_private;		\
	return bsr_single_open_peer_device(file,				\
					    peer_device_ ## name ## _show,	\
					    peer_device);			\
}										\
static int peer_device_ ## name ## _release(struct inode *inode, struct file *file)\
{										\
	struct bsr_peer_device *peer_device = inode->i_private;		\
	kref_put(&peer_device->connection->kref, bsr_destroy_connection);	\
	kref_put(&peer_device->device->kref, bsr_destroy_device);		\
	return single_release(inode, file);					\
}										\
static const struct file_operations peer_device_ ## name ## _fops = {		\
	.owner		= THIS_MODULE,						\
	.open		= peer_device_ ## name ## _open,			\
	.read		= seq_read,						\
	.llseek		= seq_lseek,						\
	.release	= peer_device_ ## name ## _release,			\
};

bsr_debugfs_peer_device_attr(resync_extents)
bsr_debugfs_peer_device_attr(resync_ratio)
bsr_debugfs_peer_device_attr(proc_bsr)

void bsr_debugfs_peer_device_add(struct bsr_peer_device *peer_device)
{
	struct dentry *conn_dir = peer_device->connection->debugfs_conn;
	struct dentry *dentry;
	char vnr_buf[8];

	if (!conn_dir)
		return;

	snprintf(vnr_buf, sizeof(vnr_buf), "%u", peer_device->device->vnr);
	dentry = debugfs_create_dir(vnr_buf, conn_dir);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	peer_device->debugfs_peer_dev = dentry;

	/* debugfs create file */
	peer_dev_dcf(resync_extents);
	peer_dev_dcf(resync_ratio);
	peer_dev_dcf(proc_bsr);
	return;

fail:
	bsr_debugfs_peer_device_cleanup(peer_device);
	bsr_err(14, BSR_LC_ETC, peer_device, "failed to create debugfs entries");
}

void bsr_debugfs_peer_device_cleanup(struct bsr_peer_device *peer_device)
{
	bsr_debugfs_remove(&peer_device->debugfs_peer_dev_proc_bsr);
	bsr_debugfs_remove(&peer_device->debugfs_peer_dev_resync_extents);
	bsr_debugfs_remove(&peer_device->debugfs_peer_dev_resync_ratio);
	bsr_debugfs_remove(&peer_device->debugfs_peer_dev);
}

static int bsr_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, bsr_version_show, NULL);
}

// BSR-875
static int bsr_alloc_mem_open(struct inode *inode, struct file *file)
{
	return single_open(file, bsr_alloc_mem_show, NULL);
}

static const struct file_operations bsr_version_fops = {
	.owner = THIS_MODULE,
	.open = bsr_version_open,
	.llseek = seq_lseek,
	.read = seq_read,
	.release = single_release,
};

// BSR-875
static const struct file_operations bsr_alloc_mem_fops = {
	.owner = THIS_MODULE,
	.open = bsr_alloc_mem_open,
	.llseek = seq_lseek,
	.read = seq_read,
	.release = single_release,
};

/* not __exit, may be indirectly called
 * from the module-load-failure path as well. */
void bsr_debugfs_cleanup(void)
{
	// BSR-875
	bsr_debugfs_remove(&bsr_debugfs_alloc_mem);
	bsr_debugfs_remove(&bsr_debugfs_resources);
	bsr_debugfs_remove(&bsr_debugfs_minors);
	bsr_debugfs_remove(&bsr_debugfs_version);
	bsr_debugfs_remove(&bsr_debugfs_root);
}

int __init bsr_debugfs_init(void)
{
	struct dentry *dentry;

	dentry = debugfs_create_dir("bsr", NULL);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	bsr_debugfs_root = dentry;

	dentry = debugfs_create_file("version", 0444, bsr_debugfs_root, NULL, &bsr_version_fops);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	bsr_debugfs_version = dentry;

	dentry = debugfs_create_dir("resources", bsr_debugfs_root);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	bsr_debugfs_resources = dentry;

	dentry = debugfs_create_dir("minors", bsr_debugfs_root);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	bsr_debugfs_minors = dentry;

	// BSR-875
	dentry = debugfs_create_file("alloc_mem", 0444, bsr_debugfs_root, NULL, &bsr_alloc_mem_fops);
	if (IS_ERR_OR_NULL(dentry))
		goto fail;
	bsr_debugfs_alloc_mem = dentry;

	return 0;

fail:
	bsr_debugfs_cleanup();
	if (dentry)
		return PTR_ERR(dentry);
	else
		return -EINVAL;
}
#endif
#endif