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


#ifndef BSR_WINDOWS_H
#define BSR_WINDOWS_H
#include <ntddk.h>
#include <wdm.h>
#include <stdint.h>
#include <ntstrsafe.h>
#include <stdbool.h>
#include "list.h"
#include "Wait.h"
#include "bsr_endian.h"
#include "../../../bsr-headers/windows/types.h"
#include "bsrvfltmsg.h"
#include "../bsrfsflt/bsrfsflt_comm.h"

#include "disp.h"

//#define BSR_TRACE				    // trace replication flow(basic)
//#define BSR_TRACE1				    // trace replication flow(detail)

#define _WIN_SEND_BUF					// Use Send Buffering
#define _WSK_SOCKETCONNECT
#define _WIN_EVENTLOG			        // Windows Eventlog porting point
#define _WIN_TMP_Win8_BUG_0x1a_61946
#define minor_to_letter(m)	('C'+(m))
#define minor_to_mdev minor_to_device
#define bsr_conf bsr_device
#define BSR_GENERIC_POOL_TAG       ((ULONG)'dbrd')

#define BSR_EVENT_SOCKET_STRING	"BSR_EVENTS"		/// used in NETLINK
// DW-2170
#define BSR_DAEMON_SOCKET_STRING	"BSR_DAEMON"		/// used in DAEMON

//#define _WIN_WPP
#define _WIN_HANDLER_TIMEOUT	// call_usermodehelper timeout
#define WIN_AL_BUG_ON // DW-1513 Macro to print LRU

#ifdef _WIN_WPP
#define WPP_CONTROL_GUIDS \
	WPP_DEFINE_CONTROL_GUID(LogGuid, \
	(998bdf51, 0349, 4fbc, 870c, d6130a955a5f), \
	WPP_DEFINE_BIT(TRCERROR) \
	WPP_DEFINE_BIT(TRCINFO))
#endif

/// for linux code
#define inline					__inline
#define __func__				__FUNCTION__
#define __bitwise__

#define __GFP_HIGHMEM           (0x02u)
#define __GFP_ZERO              (0x8000u) 
#define __GFP_WAIT              (0x10u) 
#define __GFP_NOWARN            (0x200u)
#define __GFP_RECLAIM           (0x400u)
#define GFP_HIGHUSER            (7)

#define	KERN_EMERG				"<0>"	/* system is unusable			*/
#define	KERN_ALERT				"<1>"	/* action must be taken immediately	*/
#define	KERN_CRIT				"<2>"	/* critical conditions			*/
#define	KERN_ERR				"<3>"	/* error conditions			*/
#define	KERN_WARNING			"<4>"	/* warning conditions			*/
#define	KERN_NOTICE				"<5>"	/* normal but significant condition	*/
#define	KERN_INFO				"<6>"	/* informational			*/
#define	KERN_DEBUG				"<7>"	/* debug-level messages			*/
#define KERN_OOS				"<8>"	/* DW-1153: debug-oos */
#define KERN_LATENCY			"<9>"	/* DW-1961 feature log */

#define smp_mb()				KeMemoryBarrier() 
#define smp_rmb()				KeMemoryBarrier()
#define smp_wmb()				KeMemoryBarrier()


#define GFP_KERNEL              1
#define GFP_ATOMIC              2
#define GFP_NOIO				(__GFP_WAIT)
#define GFP_NOWAIT	            0
#define gfp_t					int

#define atomic_t				int
#define atomic_t64				LONGLONG

#define WARN_ON(x)				__noop
#define ATOMIC_INIT(i)			(i)

#define RELATIVE(wait) (-(wait))

#define __init                  NTAPI
#define __exit                  NTAPI

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define CMD_TIMEOUT_SHORT_DEF		5		/* should be synchronized with defined value in shared_main.h */

// from bio.h
#define BIO_RW					    0       /* Must match RW in req flags (blkdev.h) */
#define BIO_RW_AHEAD				1       /* Must match FAILFAST in req flags */
#define BIO_RW_BARRIER				2
#define BIO_RW_SYNCIO				3
#define BIO_RW_UNPLUG				4
#define BIO_RW_META				    5
#define BIO_RW_DISCARD				6
#define BIO_RW_FAILFAST_DEV			7
#define BIO_RW_FAILFAST_TRANSPORT	8
#define BIO_RW_FAILFAST_DRIVER		9
#define BIO_RW_NOIDLE				10

// DW-1538
#define REQ_RAHEAD		(1UL << BIO_RW_AHEAD)

#define KBUILD_MODNAME      __FILE__

/*
 * Request flags.  For use in the cmd_flags field of struct request, and in
 * bi_rw of struct bio.  Note that some flags are only valid in either one.
 */
enum rq_flag_bits {
	/* common flags */
	__REQ_WRITE,		/* not set, read. set, write */
	__REQ_FAILFAST_DEV,	/* no driver retries of device errors */
	__REQ_FAILFAST_TRANSPORT, /* no driver retries of transport errors */
	__REQ_FAILFAST_DRIVER,	/* no driver retries of driver errors */

	__REQ_SYNC,		/* request is sync (sync write or read) */
	__REQ_META,		/* metadata io request */
	__REQ_PRIO,		/* boost priority in cfq */
	__REQ_DISCARD,		/* request to discard sectors */
	__REQ_SECURE,		/* secure discard (used with __REQ_DISCARD) */
	__REQ_WRITE_SAME,	/* write same block many times */

	__REQ_NOIDLE,		/* don't anticipate more IO after this one */
	__REQ_FUA,		/* forced unit access */
	__REQ_FLUSH,		/* request for cache flush */

	/* bio only flags */
	__REQ_RAHEAD,		/* read ahead, can fail anytime */
	__REQ_THROTTLED,	/* This bio has already been subjected to
				 * throttling rules. Don't do it again. */

	/* request only flags */
	__REQ_SORTED,		/* elevator knows about this request */
	__REQ_SOFTBARRIER,	/* may not be passed by ioscheduler */
	__REQ_NOMERGE,		/* don't touch this for merging */
	__REQ_STARTED,		/* drive already may have started this one */
	__REQ_DONTPREP,		/* don't call prep for this one */
	__REQ_QUEUED,		/* uses queueing */
	__REQ_ELVPRIV,		/* elevator private data attached */
	__REQ_FAILED,		/* set if the request failed */
	__REQ_QUIET,		/* don't worry about errors */
	__REQ_PREEMPT,		/* set for "ide_preempt" requests */
	__REQ_ALLOCED,		/* request came from our alloc pool */
	__REQ_COPY_USER,	/* contains copies of user pages */
	__REQ_FLUSH_SEQ,	/* request for flush sequence */
	__REQ_IO_STAT,		/* account I/O stat */
	__REQ_MIXED_MERGE,	/* merge of different types, fail separately */
	__REQ_KERNEL, 		/* direct IO to kernel pages */
	__REQ_PM,		/* runtime pm request */
	__REQ_END,		/* last of chain of requests */
	__REQ_NR_BITS,		/* stops here */
};

// from fs.h
/* file is open for reading */
#define FMODE_READ				    0x1
/* file is open for writing */
#define FMODE_WRITE				    0x2

// from notify.h
#define NOTIFY_DONE				    0x0000          /* Don't care */
#define NOTIFY_OK				    0x0001          /* Suits me */
#define NOTIFY_STOP_MASK			0x8000          /* Don't call further */
#define NOTIFY_BAD				    (NOTIFY_STOP_MASK|0x0002)

#define KERNEL_VERSION(_x, _y, _z)	0

#define EINVAL					1
#define EOPNOTSUPP				2
#define ENOMEM					3
#define ENOENT					4
#define EMEDIUMTYPE				5
#define EROFS					6
#define	E2BIG					7	/* Argument list too long */    // from linux 2.6.32.61
#define MSG_NOSIGNAL			8
#define ETIMEDOUT				9
#define EBUSY					10
#define	EAGAIN					11	/* Try again */ // from linux 2.6.32.61
#define ENOBUFS					12
#define ENODEV					13
#define EWOULDBLOCK				14
#define EINTR					15
#define ENOSPC					16
#define ECONNRESET				17
#define ERESTARTSYS				18
#define EIO					    5 //19
#define ENOMSG					20
#define EEXIST					21
#define EPERM					22
#define EMSGSIZE				23
#define ESRCH					24
#define ERANGE					25	
#define EINPROGRESS				26	
#define ECONNREFUSED			27	
#define ENETUNREACH				28
#define EHOSTDOWN				29
#define EHOSTUNREACH			30
#define EBADR					31
#define EADDRINUSE              32
#define EINVALADDR              33	// DW-1272 STATUS_INVALID_ADDRESS_COMPONENT
#define	EOVERFLOW				75	/* Value too large for defined data type */ // from linux 2.6.32.61
#define	ESTALE					116	/* Stale NFS file handle */
#define ECONNABORTED			130 /* Software caused connection abort */ 

#define SIGXCPU					100
#define SIGHUP					101
#define MSG_MORE				102

#define MAX_ERRNO				4095
#define IS_ERR_VALUE(_x)		((_x) >= (ULONG_PTR) -MAX_ERRNO)

#define WRITE_SYNC				WRITE	// REQ_SYNC | REQ_NOIDLE not used.

// for bsr_actlog.c
#define __attribute__(packed)
#define __attribute(packed)
#ifdef LONG_MAX
#undef LONG_MAX
#endif
#define LONG_MAX				((long)(UINT32_MAX >> 1)) 
#define MAX_SCHEDULE_TIMEOUT	LONG_MAX	

#define SENDER_SCHEDULE_TIMEOUT	5 * HZ
#define _RET_IP_				(unsigned long)(0)
#define HZ					    1000

#define likely(_X)				(_X)
#define unlikely(_X)			(_X)

#define pid_t					int

#define PAGE_KERNEL				1
#define TASK_INTERRUPTIBLE		1
#define TASK_UNINTERRUPTIBLE	2
#define	BIO_UPTODATE			1

#define cond_resched()		    __noop

#define U32_MAX		(UINT32_MAX)
#define S32_MAX		((s32)(U32_MAX>>1))

enum km_type {
	KM_BOUNCE_READ,
	KM_SKB_SUNRPC_DATA,
	KM_SKB_DATA_SOFTIRQ,
	KM_USER0,
	KM_USER1,
	KM_BIO_SRC_IRQ,
	KM_BIO_DST_IRQ,
	KM_PTE0,
	KM_PTE1,
	KM_IRQ0,
	KM_IRQ1,
	KM_SOFTIRQ0,
	KM_SOFTIRQ1,
	KM_L1_CACHE,
	KM_L2_CACHE,
	KM_KDB,
	KM_TYPE_NR
};

typedef unsigned int                fmode_t;


#define LOG_LV_REG_VALUE_NAME	L"log_level"
#define LOG_FILE_MAX_REG_VALUE_NAME	L"log_file_max_count"
#define DEBUG_LOG_CATEGORY_REG_VALUE_NAME	L"debuglog_category"

#define MAX_TEXT_BUF                256

#define MAX_SPILT_BLOCK_SZ			(1 << 20)

#define BSR_THREAD_POINTER

#define FLTR_COMPONENT              DPFLTR_DEFAULT_ID
//#define FLTR_COMPONENT              DPFLTR_IHVDRIVER_ID
#define FEATURE_BSR_PRINT

extern void printk_init(void);
extern void printk_cleanup(void);

#ifdef _WIN_EVENTLOG
#define bsr_logger_init()		printk_init();
#define bsr_logger_cleanup()	printk_cleanup();
// BSR-648	
#define printk(format, ...)   \
    __printk(__FUNCTION__, -1/*not used*/, -1/*not used*/, BSR_LC_ETC, format, __VA_ARGS__)
#else
#define printk(format, ...)
#endif

#define ARRAY_SIZE(_x)				(sizeof(_x) / sizeof((_x)[0]))

#define BIT_MASK(_nr)				(1ULL << ((_nr) % BITS_PER_LONG))
#define BIT_WORD(_nr)				((_nr) / BITS_PER_LONG)

#define min_t(_type, _x, _y)		((_type)_x < (_type)_y ? (_type)_x : (_type)_y)
#define max_t(_type, _x, _y)		((_type)_x < (_type)_y ? (_type)_y : (_type)_x)

#define ALIGN(_x,_a)				(((_x) + (_a)-1) & ~((_a)-1))

#define container_of(ptr, type, member) \
	((type *)( \
	(PCHAR)(ptr) - \
	(ULONG_PTR)(&((type *)0)->member)))

struct mutex {
	KMUTEX mtx;
#ifdef _WIN_TMP_DEBUG_MUTEX
	char name[32]; 
#endif
};

struct semaphore{
    KSEMAPHORE sem;
};

struct kref {
	int refcount;
};

struct hlist_head {
	struct hlist_node *first;
};
 
struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct kobject { 
    const char          *name;
    struct kobject      *parent;
    struct kobj_type    *ktype;
    struct kref         kref;
};

#define _K_SS_MAXSIZE	128 
typedef struct sockaddr_storage_win {
	unsigned short	ss_family;		/* address family */
	char	__data[_K_SS_MAXSIZE - sizeof(unsigned short)];
} SOCKADDR_STORAGE_EX; 

struct sock {
	LONG_PTR sk_state_change;
	int sk_user_data;
	int sk_reuse;
	int sk_allocation;
	int sk_priority;
	int sk_sndtimeo; //intptr_t 
	int sk_rcvtimeo; //intptr_t
#ifdef _WIN_SEND_BUF
	// unused!
#else
	int sk_wmem_queued;
#endif
	//int sk_sndbuf;
	signed long long sk_sndbuf;
	KSPIN_LOCK sk_callback_lock; 
};

#include <wsk.h>
#ifdef _WIN_SEND_BUF
#include "../../../bsr/bsr_send_buf.h"
#endif

enum sock_state {
	WSK_NONE = 0,			// The socket structure is created but the WSK socket is not created
	WSK_INVALID_DEVICE,		// invalid socket state
	WSK_CLOSED,				// closed
	WSK_CLOSING,			// closing
	WSK_DISCONNECTED,		// disconnected
	WSK_DISCONNECTING,		// disconnecting
	WSK_INITIALIZING,		// WSK socket is created and try to connect
	WSK_CONNECTING,			// connecting
	WSK_ESTABLISHED,		// WSK socket's connection is established
};
//#define	TCP_DISCONNECTED	0
//#define	TCP_ESTABLISHED	1

struct socket {
	struct sock *sk_linux_attr;
	PWSK_SOCKET sk;
	char name[32];
#ifdef _WIN_SEND_BUF
	struct _buffering_attr buffering_attr;
#endif
	int sk_state;
};

char * get_ip4(char *buf, size_t len, struct sockaddr_in *sockaddr);
char * get_ip6(char *buf, size_t len, struct sockaddr_in6 *sockaddr);
	
#define WQNAME_LEN	16	
struct workqueue_struct {
    LIST_ENTRY list_head;
    KSPIN_LOCK list_lock;
	int run;
	KEVENT	wakeupEvent;
	KEVENT	killEvent;
	PVOID	pThread;
	void (*func)();
	char name[WQNAME_LEN];
};
struct timer_list {
    KTIMER ktimer;
    KDPC dpc;
    //void (*function)(PKDPC dpc, PVOID data, PVOID arg1, PVOID arg2);
	PKDEFERRED_ROUTINE function;
    PVOID data;             
    ULONG_PTR expires; 
#ifdef DBG
    char name[32];
#endif
};

extern void init_timer(struct timer_list *t);
extern void add_timer(struct timer_list *t);
extern int del_timer_sync(struct timer_list *t);
extern void del_timer(struct timer_list *t);
extern int mod_timer(struct timer_list *t, ULONG_PTR expires);
extern int mod_timer_pending(struct timer_list *timer, ULONG_PTR expires);

struct lock_class_key { char __one_byte; };
extern void init_timer_key(struct timer_list *timer, const char *name, struct lock_class_key *key);

static __inline void setup_timer_key(_In_ struct timer_list * timer,
    const char *name,
struct lock_class_key *key,
	//void(*function)(PKDPC dpc, PVOID data, PVOID arg1, PVOID arg2),
	PKDEFERRED_ROUTINE function,
    void * data)
{
    timer->function = function;
    timer->data = data;
    init_timer_key(timer, name, key);
}

#define setup_timer(timer, fn, data)                            \
    do {                                                        \
        setup_timer_key((timer), #timer, NULL, (fn), (data));   \
	    } while(false)

struct work_struct {
	struct list_head entry;
	void (*func)(struct work_struct *work);
};

struct work_struct_wrapper {
    struct work_struct * w;
    LIST_ENTRY  element;
};

typedef struct gendisk  gendisk;

struct block_device_operations {
	int (*open) (struct block_device *, fmode_t);
	int (*release) (struct gendisk *, fmode_t);
};

struct kobj_type {
	void(*release)(struct kobject *);
};

#define DISK_NAME_LEN		16
struct gendisk 
{
	char disk_name[DISK_NAME_LEN];  /* name of major driver */
	struct request_queue *queue;
    const struct block_device_operations *fops;
    void *private_data;
	struct bsr_device*		bsr_device;			// DW-1300 the only point to access bsr device from volume extension.
	EX_SPIN_LOCK			bsr_device_ref_lock;	// DW-1300 to synchronously access bsr_device. this lock is used when both referencing(shared) and deleting(exclusive) bsr device.
	PVOLUME_EXTENSION pDeviceExtension;
	void * part0; 
};

struct block_device {
	// If the block device descriptor refers to a disk partition,
	// the bd_contains field points to the descriptor of the
	// block device associated with the whole disk
	// Otherwise, if the block device descriptor refers to a whole disk
	// the bd_contains field points to the block device descriptor itself ...
	// FROM Understanding the Linux Kernel, 3rd Edition
	struct block_device *	bd_parent;			// DW-1109 it points the block device whose bd_contains points me.
	struct block_device *	bd_contains;
	struct gendisk * bd_disk;
    unsigned long long d_size; // volume size in bytes
	struct kref kref;
};

typedef struct kmem_cache {
	int size;
	char *name;
	ULONG tag;
} kmem_cache_t;

typedef struct mempool_s {
	struct kmem_cache *p_cache;
	int page_alloc;
	NPAGED_LOOKASIDE_LIST pageLS;
	NPAGED_LOOKASIDE_LIST page_addrLS;
} mempool_t;

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

typedef void(BIO_END_IO_CALLBACK)(void*, void*, void*);
//PIO_COMPLETION_ROUTINE bio_end_io_t;

struct splitInfo {	
	unsigned long 	finished;
	NTSTATUS 		LastError; // 0 :STATUS_SUCCESS, 
};

struct bio {
	PIRP 					pMasterIrp;  /* _WIN: for upper layer's  IRP */

	unsigned int 			split_id;
	unsigned int 			split_total_id;
	unsigned int 			split_total_length;
	char* 					bio_databuf;
	struct splitInfo*		splitInfo;

	sector_t				bi_sector;	/* device address in 512 byte sectors */
	struct bio*				bi_next;	/* request queue link */
	struct block_device*	bi_bdev;
	unsigned long			bi_flags;	/* status, command, etc */
	unsigned long			bi_rw;		
	unsigned short			bi_vcnt;	/* how many bio_vec's */
	unsigned short			bi_idx;		/* current index into bvl_vec */
	unsigned int			bi_size;	/* residual I/O count */
	atomic_t				bi_cnt;		/* pin count */
	/* bi_end_io is assigned in next comment places.
	Blkdev_issue_zeroout.c (bsr\bsr-kernel-compat):		bio->bi_end_io = bio_batch_end_io;
	Bsr_actlog.c (bsr):	bio->bi_end_io = bsr_md_endio;
	Bsr_bitmap.c (bsr):	bio->bi_end_io = bsr_bm_endio;
	Bsr_receiver.c (bsr):	bio->bi_end_io = one_flush_endio;
	Bsr_receiver.c (bsr):	bio->bi_end_io = bsr_peer_request_endio;
	Bsr_req.h (bsr):	bio->bi_end_io   = bsr_request_endio;
	*/
	//BIO_END_IO_CALLBACK*	bi_end_io; 
	PIO_COMPLETION_ROUTINE  bi_end_io;
	void*					bi_private; 
	unsigned int			bi_max_vecs;    /* max bvl_vecs we can hold */
	struct bio_vec			bi_io_vec[1]; // only one!!!
	UCHAR					MasterIrpStackFlags; //Stack Location's Flag
	LONGLONG				flush_ts;		// DW-1961
	ktime_t					io_start_kt; // BSR-687
};

struct bio_set {
	mempool_t *bio_pool;
};

struct completion {
	//unsigned int done;
	wait_queue_head_t wait;
};

struct accept_wait_data {
    struct bsr_tconn *tconn;
    struct socket *s_listen;
    struct socket *s_accept;
    struct completion door_bell;
};

extern struct bio *bio_clone(struct bio *, int x);
extern struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *bs);
extern struct bio_pair *bio_split(struct bio *bi, int first_sectors);
extern void bio_pair_release(struct bio_pair *dbio);
extern struct bio_set *bioset_create(unsigned int, unsigned int);
extern void bioset_free(struct bio_set *);
extern struct bio *bio_alloc(gfp_t, int, ULONG);
extern struct bio *bio_kmalloc(gfp_t, int);
extern struct bio *bio_alloc_bioset(gfp_t, int, struct bio_set *);
extern void bio_put(struct bio *);
extern void bio_free(struct bio *bio); 
extern void bio_endio(struct bio *, int);
extern int bio_add_page(struct bio *bio, struct page *page, unsigned int len,unsigned int offset);
extern int submit_bio(struct bio *bio); // DW-1538
extern void bio_endio(struct bio *bio, int error);

#define bio_get(bio)			atomic_inc(&(bio)->bi_cnt) 

#define bio_iovec_idx(bio, idx)		(&((bio)->bi_io_vec[(idx)]))
#define __bio_for_each_segment(bvl, bio, i, start_idx)			\
	for (bvl = bio_iovec_idx((bio), (start_idx)), i = (start_idx);	\
		i < (bio)->bi_vcnt;					\
		bvl++, i++)

#define bio_for_each_segment(bvl, bio, i)				\
	__bio_for_each_segment(bvl, bio, i, (bio)->bi_idx)

#define RW_MASK                 1 //  REQ_WRITE
#define bio_data_dir(bio)       ((bio)->bi_rw & 1)
#define bio_rw(bio)             ((bio)->bi_rw & (RW_MASK))

extern void rwlock_init(void *lock);
extern void spin_lock_init(spinlock_t *lock);
///extern void spin_lock_irqsave(spinlock_t *lock, long flags);
extern void spin_lock_irq(spinlock_t *lock);
extern void spin_lock_bh(spinlock_t *lock);
extern void spin_unlock_bh(spinlock_t *lock); 
extern void spin_lock(spinlock_t *lock);
extern void spin_unlock(spinlock_t *lock);
extern void spin_unlock_irq(spinlock_t *lock);
extern void spin_unlock_irqrestore(spinlock_t *lock, long flags);
extern unsigned long _spin_lock_irqsave(spinlock_t* lock);

#define spin_lock_irqsave(lock, flags) flags = _spin_lock_irqsave(lock); 

extern void read_lock(spinlock_t *lock);
extern void read_unlock(spinlock_t *lock);	
extern void write_unlock_bh(spinlock_t *lock);
extern void write_unlock(spinlock_t *lock);
extern void write_lock_irq(spinlock_t *lock);
extern void write_lock_bh(spinlock_t *lock);
extern void write_unlock_irq(spinlock_t *lock);

#ifdef _WIN_TMP_DEBUG_MUTEX
extern void mutex_init(struct mutex *m, char *name);
#else
extern void mutex_init(struct mutex *m);
#endif
extern void sema_init(struct semaphore *s, int limit);

extern NTSTATUS mutex_lock(struct mutex *m);
extern int mutex_lock_interruptible(struct mutex *m);
extern NTSTATUS mutex_lock_timeout(struct mutex *m, ULONG msTimeout);
extern int mutex_is_locked(struct mutex *m);
extern void mutex_unlock(struct mutex *m);
extern int mutex_trylock(struct mutex *m);

extern int kref_put(struct kref *kref, void (*release)(struct kref *kref));
extern int kref_get(struct kref *kref);
extern void kref_init(struct kref *kref);

extern struct request_queue *bdev_get_queue(struct block_device *bdev);
extern void blk_cleanup_queue(struct request_queue *q);
typedef void (make_request_fn) (struct request_queue *q, struct bio *bio);
extern void blk_queue_make_request(struct request_queue *q, make_request_fn *mfn);
extern void blk_queue_flush(struct request_queue *q, unsigned int flush);

extern struct gendisk *alloc_disk(int minors);
extern void put_disk(struct gendisk *disk);
extern void del_gendisk(struct gendisk *disk);
extern void set_disk_ro(struct gendisk *disk, int flag);


#define PREPARE_WORK(_work, _func)                                      \
	do {                                                            \
		(_work)->func = (_func);                                \
		} while(false)

#define __INIT_WORK(_work, _func, _onstack)                             \
	 do {                                                           \
	       /* __init_work((_work), _onstack);        */  \
	       /*  (_work)->data = (atomic_long_t) WORK_DATA_INIT(); */ \
		INIT_LIST_HEAD(&(_work)->entry);                        \
		PREPARE_WORK((_work), (_func));                         \
	 	} while(false)

#define INIT_WORK(_work, _func)                                         \
	 __INIT_WORK((_work), (_func), 0);  

#define TASK_COMM_LEN		32
struct task_struct {
    struct list_head list; 
	int pid; // thread ID
    KEVENT sig_event;
    BOOLEAN has_sig_event;
	int sig; 

	struct blk_plug *plug;
	
    char comm[TASK_COMM_LEN];
};

extern mempool_t *mempool_create(int min_nr, void *alloc_fn, void *free_fn, void *pool_data);
extern mempool_t *mempool_create_page_pool(int min_nr, int order);
// BSR-247 mempool_create_slab_pool() function does not use a memory pool.
extern mempool_t *mempool_create_slab_pool(int size, ULONG tag);
extern void * mempool_alloc(mempool_t *pool, gfp_t gfp_mask);
extern void mempool_free(void *req, void *mempool);
extern void mempool_destroy(void *p);
extern void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
extern void *mempool_free_slab(gfp_t gfp_mask, void *pool_data);

#define	atomic_inc_return(_p)		InterlockedIncrement((LONG volatile*)(_p))
#define	atomic_dec_return(_p)		InterlockedDecrement((LONG volatile*)(_p))
#define atomic_inc(_v)			atomic_inc_return(_v)
#define atomic_dec(_v)			atomic_dec_return(_v)

#define	atomic_inc_return64(_p)		InterlockedIncrement64((LONGLONG volatile*)(_p))
#define	atomic_dec_return64(_p)		InterlockedDecrement64((LONGLONG volatile*)(_p))
#define atomic_inc64(_v)		atomic_inc_return64(_v)
#define atomic_dec64(_v)		atomic_dec_return64(_v)

#if ( (NTDDI_VERSION < NTDDI_WIN7))
#define _vsnprintf_s(buf, size, cnt, fmt, args) _vsnprintf(buf, size, fmt, args)
#define swprintf_s _snwprintf
#define _itoa_s(val, buf, size, radix) _itoa(val, buf, radix)
#endif

extern LONG_PTR xchg(LONG_PTR *target, LONG_PTR value);
extern void atomic_set(atomic_t *v, int i);
extern void atomic_set64(atomic_t64* v, LONGLONG i);
extern void atomic_add(int i, atomic_t *v);
extern void atomic_add64(LONGLONG a, atomic_t64 *v);
extern void atomic_sub(int i, atomic_t *v);
extern void atomic_sub64(LONGLONG a, atomic_t64 *v);
extern int atomic_sub_return(int i, atomic_t *v); 
extern LONGLONG atomic_sub_return64(LONGLONG a, atomic_t64 *v);
extern int atomic_dec_and_test(atomic_t *v);
extern int atomic_sub_and_test(int i, atomic_t *v);
extern int atomic_cmpxchg(atomic_t *v, int old, int new);
extern int atomic_read(const atomic_t *v);
extern LONGLONG atomic_read64(const atomic_t64 *v);
extern int atomic_xchg(atomic_t *v, int n);
extern LONGLONG atomic_xchg64(atomic_t64 *v, LONGLONG n);

extern LARGE_INTEGER g_frequency;

// from rcu_list.h


static __inline void init_waitqueue_head(wait_queue_head_t *q)
{	
	spin_lock_init(&(q)->lock);	
	INIT_LIST_HEAD(&(q)->task_list);
	KeInitializeEvent(&q->wqh_event, NotificationEvent, FALSE);
};

typedef int (congested_fn)(void *, int);

struct backing_dev_info {
	unsigned long ra_pages; /* max readahead in PAGE_CACHE_SIZE units */ 
	congested_fn *congested_fn; /* Function pointer if device is md/dm */
	void *congested_data;   /* Pointer to aux data for congested func */
};

struct queue_limits {
    unsigned int            max_discard_sectors;
    unsigned int            discard_granularity;    
	unsigned int			discard_zeroes_data;
};

struct request_queue {
	void * queuedata;
	struct backing_dev_info backing_dev_info;
	spinlock_t *queue_lock; // _WIN: unused.
	unsigned short logical_block_size;
	// DW-1406 max_hw_sectors must be 64bit variable since it can be bigger than 4gb.
	unsigned long long max_hw_sectors;
    struct queue_limits limits; 
};

static __inline ULONG_PTR JIFFIES()
{
	LARGE_INTEGER Elapse, Qpc;

	// BSR-38 KeQueryPerformanceCounter() returns a 64-bit integer that represents the current value of a high-resolution monotonically nondecreasing counter.
	Qpc = KeQueryPerformanceCounter(NULL);
	// BSR-38 calculate in milli-seconds.
	Elapse.QuadPart = Qpc.QuadPart * 1000 / g_frequency.QuadPart;

	return (ULONG_PTR)Elapse.QuadPart;
}

#define jiffies				JIFFIES()

#define time_after(_a,_b)		((LONG_PTR)((LONG_PTR)(_b) - (LONG_PTR)(_a)) < 0)
#define time_after_eq(_a,_b)		((LONG_PTR)((LONG_PTR)(_a) - (LONG_PTR)(_b)) >= 0)

#define time_before(_a,_b)		time_after(_b, _a)
#define time_before_eq(_a,_b)		time_after_eq(_b, _a)

struct lru_cache;
extern struct lc_element *lc_element_by_index(struct lru_cache *lc, unsigned i);
extern unsigned int lc_index_of(struct lru_cache *lc, struct lc_element *e);

struct page {
	ULONG_PTR private;
	void *addr;
};

#define page_private(_page)		((_page)->private)
#define set_page_private(_page, _v)	((_page)->private = (_v))

extern void *page_address(const struct page *page);
extern int page_count(struct page *page);
extern void __free_page(struct page *page);
extern struct page * alloc_page(int flag);

struct scatterlist {
	struct page *page;
	unsigned int offset;
	unsigned int length;
};

#define MINORMASK	0xff

extern struct workqueue_struct *create_singlethread_workqueue(void * name);
extern bool queue_work(struct workqueue_struct* queue, struct work_struct* work);
extern void destroy_workqueue(struct workqueue_struct *wq);

extern void kobject_put(struct kobject *kobj);
extern void kobject_get(struct kobject *kobj);
extern void kobject_del(struct kobject *kobj);

extern void * kcalloc(int e_count, int x, int flag, ULONG Tag);
extern void * kzalloc(int x, int flag, ULONG Tag);
extern void * kmalloc(int size, int flag, ULONG Tag);
extern void kfree(void * x);
extern void kvfree(void * x);
extern void * kmem_cache_alloc(void * cache, int flag, ULONG Tag);
extern void kmem_cache_destroy(struct kmem_cache *s);
extern struct kmem_cache *kmem_cache_create(char *name, size_t size, size_t align, unsigned long flags, void (*ctor)(void *), ULONG Tag);
extern void kmem_cache_free(void * cache, void * x);

static __inline wait_queue_t initqueue(wait_queue_t *wq)
{
	INIT_LIST_HEAD(&wq->task_list);
	return *wq; 
}

#define DEFINE_WAIT(name)
#define DEFINE_WAIT_FUNC(name)

extern void init_completion(struct completion *x);
extern long wait_for_completion(struct completion *x);
extern long wait_for_completion_timeout(struct completion *x, long timeout);
extern long wait_for_completion_no_reset_event(struct completion *completion);
extern void complete(struct completion *c);
extern void complete_all(struct completion *c);

extern int signal_pending(struct task_struct *p);
extern void force_sig(int sig, struct task_struct *p);
extern void flush_signals(struct task_struct *p);
extern long schedule_ex(wait_queue_head_t *q, long timeout, char *func, int line, bool auto_reset_event);

#define schedule(q, timeout, func, line)	schedule_ex(q, timeout, func, line, true)
#define SCHED_Q_INTERRUPTIBLE	1
#define schedule_timeout_interruptible(timeout)  schedule((wait_queue_head_t *)SCHED_Q_INTERRUPTIBLE, (timeout), __FUNCTION__, __LINE__)
#define schedule_timeout_uninterruptible(timeout) schedule_timeout(timeout) 
#define schedule_timeout(timeout) schedule((wait_queue_head_t *)NULL, (timeout), __FUNCTION__, __LINE__)


#define __wait_event(wq, condition, __func, __line) \
	do {\
		bool _res = false;						\
		for (;;) {\
			_res = condition;				\
			if (_res) \
			                                                                                                            { \
				break; \
																														} \
			schedule(&wq, 1, __func, __line); /*  // DW-105 workaround: 1 ms polling  */ \
																				} \
										} while(false)

#define wait_event(wq, condition) \
	do {\
		bool _res = false;						\
		_res = condition;				\
		if (_res) \
			break; \
		__wait_event(wq, condition, __FUNCTION__, __LINE__); \
	                    } while(false)


#define __wait_event_timeout(wq, condition, ret)  \
	do {\
		int i = 0;\
		int t = 0;\
		int real_timeout = ret/100; \
		for (;;) {\
			i++; \
			if (condition)   \
																					{\
				break;     \
																					}\
			/*ret = schedule(&wq, ret, __FUNC__, __LINE__);*/\
			if (++t > real_timeout) \
																					{\
				ret = 0;\
				break;\
																					}\
			schedule(&wq, 100, __FUNCTION__, __LINE__); /*  // DW-105 workaround: 1 ms polling  */ \
														}  \
								} while(false)

#define wait_event_timeout(t, wq, condition, timeout) \
	do { \
		long __ret = timeout; \
		if (!(condition)) \
			__wait_event_timeout(wq, condition, __ret);  \
		t = __ret; \
						        		} while(false)

#define __wait_event_interruptible(wq, condition, sig)   \
    do { \
		bool _res = false;	\
        for (;;) { \
			_res = condition;	\
				if (_res) {		\
								\
                sig = 0;    \
                break;      \
						            } \
            sig = schedule(&wq, 1, __FUNCTION__, __LINE__);   \
            if (-BSR_SIGKILL == sig) { break; }    \
				        } \
			    } while(false)

#define wait_event_interruptible(sig, wq, condition) \
    do {\
        int __ret = 0;  \
        __wait_event_interruptible(wq, condition, __ret); \
        sig = __ret; \
			    } while(false)

// DW-552
#define wait_event_interruptible_timeout(ret, wq, condition, to) \
    do {\
        int t = 0;\
        int real_timeout = to/100; /*divide*/\
		bool _res = false;					\
        for (;;) { \
			_res = condition;	\
            if (_res) {   \
                break;      \
            } \
	        if (++t > real_timeout) {\
		        ret = -ETIMEDOUT;\
		        break;\
            }\
	        ret = schedule(&wq, 100, __FUNCTION__, __LINE__);  /* real_timeout = 0.1 sec*/ \
            if (-BSR_SIGKILL == ret) { break; } \
        }\
	    } while(false)

#define wake_up(q) _wake_up(q, __FUNCTION__, __LINE__)

struct bsr_thread;
extern void wake_up_process(struct bsr_thread *thi);

extern void _wake_up(wait_queue_head_t *q, char *__func, int __line);

extern int test_and_change_bit(int nr, const ULONG_PTR *vaddr);
extern ULONG_PTR find_first_bit(const ULONG_PTR* addr, ULONG_PTR size); //reference linux 3.x kernel. 64bit compatible
extern ULONG_PTR find_next_bit(const ULONG_PTR *addr, ULONG_PTR size, ULONG_PTR offset);
extern ULONG_PTR find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset);

__inline
int test_and_set_bit(int bit, ULONG_PTR * base)
{
#ifdef _WIN64
    return (InterlockedBitTestAndSet64((volatile __int64 *)base, bit));
#else
    return (InterlockedBitTestAndSet((volatile long *)base, bit));
#endif
}

__inline
int test_and_clear_bit(int bit, ULONG_PTR * base)
{
#ifdef _WIN64
    return (InterlockedBitTestAndReset64((volatile __int64 *)base, bit));
#else
    return (InterlockedBitTestAndReset((volatile long *)base, bit));
#endif
}

__inline
void set_bit(int bit, ULONG_PTR * base)
{
    test_and_set_bit(bit, base);
}

__inline
void clear_bit(int bit, ULONG_PTR * base)
{
    test_and_clear_bit(bit, base);
}

static __inline void __set_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);

	*p |= mask;
}

static __inline int __test_and_set_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);
	ULONG_PTR old = *p;

	*p = old | mask;
	return (old & mask) != 0;
}

static __inline int __test_and_clear_bit(int nr, volatile ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr) + BIT_WORD(nr);
	ULONG_PTR old = *p;

	*p = old & ~mask;
	return (old & mask) != 0;
}

static __inline BOOLEAN test_bit(int nr, const ULONG_PTR *addr)
{
#ifdef _WIN64
	return _bittest64((LONG64 *)addr, nr);
#else
	return _bittest((LONG_PTR *)addr, nr);
#endif
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define generic_test_le_bit(nr, addr)			test_bit(nr, addr)
#define generic___test_and_set_le_bit(nr, addr)		__test_and_set_bit(nr, addr)
#define generic___test_and_clear_le_bit(nr, addr)	__test_and_clear_bit(nr, addr)
#define generic_find_next_zero_le_bit(addr, size, offset) find_next_zero_bit(addr, size, offset)
#define generic_find_next_le_bit(addr, size, offset)	find_next_bit(addr, size, offset)
#endif

struct retry_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;
	spinlock_t lock;
	struct list_head writes;
	struct task_struct task;
};


#define current		    ct_find_thread((int)PsGetCurrentThreadId())

#define MAX_SEQ_BUF	4096

typedef struct crypto_tfm  crypto_tfm;

extern void *crypto_alloc_tfm(char *name, u32 mask);
extern unsigned int crypto_tfm_alg_digestsize(struct crypto_tfm *tfm);
extern int generic_make_request(struct bio *bio); // DW-649 return value is changed for error handling 2015.12.08

extern int call_usermodehelper(char *path, char **argv, char **envp, unsigned int wait);

extern void * ERR_PTR(long error);
// DW-1952 modify to use data type for 32-bit/64-bit address
extern long PTR_ERR(const void *ptr);
extern bool IS_ERR_OR_NULL(const void *ptr);
extern bool IS_ERR(void *err);

extern struct block_device *blkdev_get_by_link(UNICODE_STRING * name, bool bUpdatetargetdev);
extern struct block_device *blkdev_get_by_path(const char *path, fmode_t mode, void *holder, bool bUpdatetargetdev);

extern void hlist_add_head(struct hlist_node *n, struct hlist_head *h);
extern void hlist_del_init(struct hlist_node *entry);
extern int hlist_unhashed(const struct hlist_node *h);
extern void __hlist_del(struct hlist_node *n);

typedef struct sk_buff sk_buff;

extern uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length);
extern bool lc_is_used(struct lru_cache *lc, unsigned int enr);
extern void get_random_bytes(void *buf, int nbytes);
extern int fls(int x);
extern unsigned char *skb_put(struct sk_buff *skb, unsigned int len);
extern char *kstrdup(const char *s, int gfp);
extern void panic(char *msg);

extern int proc_details;
extern int g_bypass_level;
extern int g_read_filter;
extern int g_mj_flush_buffers_filter;

#ifdef _WIN_HANDLER_TIMEOUT
extern int g_use_volume_lock;
extern int g_netlink_tcp_port;
extern int g_daemon_tcp_port;
#endif

extern WCHAR g_ver[];

#ifdef _WIN_HANDLER_TIMEOUT
atomic_t g_handler_timeout;
int g_handler_retry;
#endif

extern PETHREAD	g_NetlinkServerThread;
extern union bsr_state g_mask; 
extern union bsr_state g_val;
///


__inline bool IsDriveLetterMountPoint(UNICODE_STRING * s)
{
	return ((s->Length == 4) &&
		(s->Buffer[0] >= 'A' && s->Buffer[0] <= 'Z') &&
		(s->Buffer[1] == ':'));
}

__inline bool IsEmptyUnicodeString(UNICODE_STRING * s)
{
	if (s == NULL)
		return true;
	return (s && (s->Length == 0) || !(s->Buffer));
}

__inline void FreeUnicodeString(UNICODE_STRING * s)
{
	if (!IsEmptyUnicodeString(s)) {
		RtlFreeUnicodeString(s);
	}
}

extern bool is_equal_volume_link(
	_In_ UNICODE_STRING * lhs,
	_In_ WCHAR * rhs,
	_In_ bool case_sensitive);

extern void dumpHex(const void *b, const size_t s, size_t w);	
extern void ResolveDriveLetters(void);
extern NTSTATUS GetRegistryValue(PCWSTR pwcsValueName, ULONG *pReturnLength, UCHAR *pucReturnBuffer, PUNICODE_STRING pRegistryPath);

extern VOID MVOL_LOCK();
extern VOID MVOL_UNLOCK();
#ifdef _WIN_MVFL
extern NTSTATUS FsctlFlushDismountVolume(unsigned int minor, bool bFlush);
extern NTSTATUS FsctlLockVolume(unsigned int minor);
extern NTSTATUS FsctlUnlockVolume(unsigned int minor);
extern NTSTATUS FsctlFlushVolume(unsigned int minor);
extern NTSTATUS FsctlCreateVolume(unsigned int minor);

// DW-1327
extern NTSTATUS NotifyCallbackObject(PWSTR pszCallbackName, PVOID pParam);
extern NTSTATUS SetBsrlockIoBlock(PVOLUME_EXTENSION pVolumeExtension, bool bBlock);
// DW-1317
extern bool ChangeVolumeReadonly(unsigned int minor, bool set);
#endif

extern KSTART_ROUTINE InitWskNetlink;
// BSR-109
#if 0
extern KSTART_ROUTINE monitor_mnt_change;
extern NTSTATUS start_mnt_monitor();
#endif 

extern
NTSTATUS ReleaseWskNetlink();

// Forward declaration for WskAcceptEvent in WSK_CLIENT_LISTEN_DISPATCH
extern
NTSTATUS WSKAPI
NetlinkAcceptEvent(
_In_  PVOID         SocketContext,
_In_  ULONG         Flags,
_In_  PSOCKADDR     LocalAddress,
_In_  PSOCKADDR     RemoteAddress,
_In_opt_  PWSK_SOCKET AcceptSocket,
PVOID *AcceptSocketContext,
CONST WSK_CLIENT_CONNECTION_DISPATCH **AcceptSocketDispatch
);
extern NTSTATUS QueryMountPoint(
	_In_ PVOID MountPoint,
	_In_ ULONG MountPointLength,
	_Inout_ PVOID MountPointInfo,
	_Out_ PULONG MountPointInfoLength);
extern PMOUNTDEV_UNIQUE_ID QueryMountDUID(PDEVICE_OBJECT devObj);

extern PVOLUME_EXTENSION mvolSearchDevice(PWCHAR PhysicalDeviceName);
extern int initRegistry(__in PUNICODE_STRING RegistryPath);
extern NTSTATUS DeleteRegistryValueKey(__in PUNICODE_STRING preg_path, __in PUNICODE_STRING pvalue_name);
extern NTSTATUS DeleteDriveLetterInRegistry(char letter);
extern NTSTATUS _QueryVolumeNameRegistry(_In_ PMOUNTDEV_UNIQUE_ID pmuid, _Out_ PVOLUME_EXTENSION pvext);
extern void NTAPI NetlinkServerThread(PVOID p);
extern struct block_device * create_bsr_block_device(IN OUT PVOLUME_EXTENSION pvext);
extern void delete_bsr_block_device(struct kref *kref);
// DW-1300
extern struct bsr_device *get_device_with_vol_ext(PVOLUME_EXTENSION pvext, bool bCheckRemoveLock);
extern BOOLEAN do_add_minor(unsigned int minor);
extern void bsrFreeDev(PVOLUME_EXTENSION pDeviceExtension);
extern void update_targetdev(PVOLUME_EXTENSION pvext, bool bMountPointUpdate);
extern void refresh_targetdev_list();
extern PVOLUME_EXTENSION get_targetdev_by_minor(unsigned int minor, bool bUpdatetargetdev);
extern LONGLONG get_targetdev_volsize(PVOLUME_EXTENSION deviceExtension);

extern int 
WriteEventLogEntryData(
	ULONG	pi_ErrorCode,
	ULONG	pi_UniqueErrorCode,
	ULONG	pi_FinalStatus,
	ULONG	pi_nDataItems,
	...
);

extern ULONG ucsdup(_Out_ UNICODE_STRING * dst, _In_ WCHAR * src, ULONG size);
extern void list_add_rcu(struct list_head *new, struct list_head *head);
extern void list_add_tail_rcu(struct list_head *new,   struct list_head *head);
extern void list_del_rcu(struct list_head *entry);

#define rcu_dereference(_PTR)		(_PTR)
#define __rcu_assign_pointer(_p, _v) \
	do { \
		/*smp_mb();*/ \
		(_p) = (_v); \
		} while(false)

#define rcu_assign_pointer(p, v) 	__rcu_assign_pointer((p), (v))
#define list_next_rcu(list)		(*((struct list_head **)(&(list)->next)))




extern EX_SPIN_LOCK g_rcuLock;

#define rcu_read_lock() \
    unsigned char oldIrql_rLock = ExAcquireSpinLockShared(&g_rcuLock);\
    bsr_debug_rcu("rcu_read_lock : currentIrql(%d), oldIrql_rLock(%d:%x) g_rcuLock(%d)", KeGetCurrentIrql(), oldIrql_rLock, &oldIrql_rLock, g_rcuLock)

#define rcu_read_unlock() \
    ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock);\
    bsr_debug_rcu("rcu_read_unlock : currentIrql(%d), oldIrql_rLock(%d:%x) g_rcuLock(%d)", KeGetCurrentIrql(), oldIrql_rLock, &oldIrql_rLock, g_rcuLock)

#define rcu_read_lock_w32_inner() \
	oldIrql_rLock = ExAcquireSpinLockShared(&g_rcuLock);\
    bsr_debug_rcu("rcu_read_lock_w32_inner : currentIrql(%d), oldIrql_rLock(%d:%x) g_rcuLock(%d)", KeGetCurrentIrql(), oldIrql_rLock, &oldIrql_rLock, g_rcuLock)

#define synchronize_rcu_w32_wlock() \
	unsigned char  oldIrql_wLock; \
	oldIrql_wLock = ExAcquireSpinLockExclusive(&g_rcuLock);\
    bsr_debug_rcu("synchronize_rcu_w32_wlock : currentIrql(%d), oldIrql_wLock(%d:%x) g_rcuLock(%lu)", KeGetCurrentIrql(), oldIrql_wLock, &oldIrql_wLock, g_rcuLock)

#define synchronize_rcu() \
	ExReleaseSpinLockExclusive(&g_rcuLock, oldIrql_wLock);\
    bsr_debug_rcu("synchronize_rcu : currentIrql(%d), oldIrql_wLock(%d:%x) g_rcuLock(%lu)", KeGetCurrentIrql(), oldIrql_wLock, &oldIrql_wLock, g_rcuLock)

#define rcu_read_lock_check(locked) \
    unsigned char oldIrql_rLock = 0;\
    if (locked) {\
		bsr_debug_rcu("rcu_read_lock_check : already locked. currentIrql(%d)", KeGetCurrentIrql());\
    } else {\
    	oldIrql_rLock = ExAcquireSpinLockShared(&g_rcuLock);\
    	bsr_debug_rcu("rcu_read_lock_check : currentIrql(%d), oldIrql_rLock(%d:%x) g_rcuLock(%d)", KeGetCurrentIrql(), oldIrql_rLock, &oldIrql_rLock, g_rcuLock);\
    }\
    
#define rcu_read_unlock_check(locked) \
	if (!locked) {\
    	ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock);\
    	bsr_debug_rcu("rcu_read_unlock_check : currentIrql(%d), oldIrql_rLock(%d:%x) g_rcuLock(%d)", KeGetCurrentIrql(), oldIrql_rLock, &oldIrql_rLock, g_rcuLock);\
	}\
	
extern void local_irq_disable();
extern void local_irq_enable();
extern void ct_init_thread_list();
extern struct task_struct * ct_add_thread(int id, const char *name, BOOLEAN event, ULONG Tag);
extern void ct_delete_thread(int id);
extern struct task_struct* ct_find_thread(int id);
extern BOOLEAN is_spin_lock_in_current_thread(spinlock_t *lock);

#define bdevname(dev, buf)   dev->bd_disk->disk_name

//
//  Lock primitives
//

_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE
VOID
MvfAcquireResourceExclusive(
_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_exclusive_lock_(*_Curr_)
PERESOURCE Resource
)
{
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    NT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
        !ExIsResourceAcquiredSharedLite(Resource));

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(Resource, TRUE);
}

_Acquires_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE
VOID
MvfAcquireResourceShared(
_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_shared_lock_(*_Curr_)
PERESOURCE Resource
)
{
    NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceSharedLite(Resource, TRUE);
}

_Releases_lock_(_Global_critical_region_)
_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE
VOID
MvfReleaseResource(
_Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
PERESOURCE Resource
)
{
    NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
    NT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
        ExIsResourceAcquiredSharedLite(Resource));

    ExReleaseResourceLite(Resource);
    KeLeaveCriticalRegion();
}

typedef struct _PTR_ENTRY
{
    SINGLE_LIST_ENTRY   slink;
    void *              ptr;
} PTR_ENTRY, * PPTR_ENTRY;


// linux-2.6.24 define 
// kernel.h 
#ifndef UINT_MAX
#define UINT_MAX	(UINT32_MAX)
#endif

// socket.h 
#define MSG_DONTROUTE	4
#define MSG_PROBE		0x10	/* Do not send. Only probe path f.e. for MTU */

//pagemap.h
#define PAGE_CACHE_SHIFT	PAGE_SHIFT

// Bio.h
#define BIO_MAX_VECS		256
#define BIO_MAX_SIZE		(BIO_MAX_VECS << PAGE_CACHE_SHIFT)

//asm-x86 , asm-generic 
#define	EDESTADDRREQ	89	/* Destination address required */

// Bitops.h
#define BITS_PER_BYTE		8

/////////////////////////////////////////////////////////////////////
// linux-2.6.24 define end
////////////////////////////////////////////////////////////////////

extern void down(struct semaphore *s);
extern int down_trylock(struct semaphore *s);
extern void up(struct semaphore *s);

// down_up RW lock port with spinlock
extern KSPIN_LOCK transport_classes_lock;

extern void downup_rwlock_init(KSPIN_LOCK* lock); // init spinlock one time at driverentry 
//extern void down_write(struct semaphore *sem);
extern KIRQL down_write(KSPIN_LOCK* lock);
//extern void down_read(struct semaphore *sem);
extern KIRQL down_read(KSPIN_LOCK* lock);
//extern void up_write(struct semaphore *sem);
extern void up_write(KSPIN_LOCK* lock);
//extern void up_read(struct semaphore *sem);
extern void up_read(KSPIN_LOCK* lock);


static int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
	sector_t nr_sects, gfp_t gfp_mask, bool discard)
{
	UNREFERENCED_PARAMETER(sector);
	UNREFERENCED_PARAMETER(nr_sects);
	UNREFERENCED_PARAMETER(bdev);
	UNREFERENCED_PARAMETER(gfp_mask);
	UNREFERENCED_PARAMETER(discard);
	// BSR: Not support
	return 0;
}


#define snprintf(a, b, c,...) memset(a, 0, b); sprintf(a, c, ##__VA_ARGS__)

typedef struct sib_info sib_info;

int bsr_genl_multicast_events(void *mdev, const struct sib_info *sib);

extern int scnprintf(char * buf, size_t size, const char *fmt, ...);

void list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry);

// for_each_set_bit = find_first_bit + find_next_bit => reference linux 3.x kernel. 
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

extern int bsr_backing_bdev_events(struct bsr_device *device);

static inline unsigned int queue_io_min(struct request_queue *q)
{
	UNREFERENCED_PARAMETER(q);
	return 0; // dummy: q->limits.io_min;
}


#define do_div(n, base)		(n = n / base)

static inline void copy_highpage(struct page *to, struct page *from)
{
	to->private = from->private;
	memcpy(to->addr, from->addr, PAGE_SIZE);
}


/*
 * blk_plug permits building a queue of related requests by holding the I/O
 * fragments for a short period. This allows merging of sequential requests
 * into single larger request. As the requests are moved from a per-task list to
 * the device's request_queue in a batch, this results in improved scalability
 * as the lock contention for request_queue lock is reduced.
 *
 * It is ok not to disable preemption when adding the request to the plug list
 * or when attempting a merge, because blk_schedule_flush_list() will only flush
 * the plug list when the task sleeps by itself. For details, please see
 * schedule() where blk_schedule_flush_plug() is called.
 */
struct blk_plug {
	ULONG_PTR magic; /* detect uninitialized use-cases */
	struct list_head list; /* requests */
	struct list_head mq_list; /* blk-mq requests */
	struct list_head cb_list; /* md requires an unplug callback */
};

struct blk_plug_cb;
typedef void (*blk_plug_cb_fn)(struct blk_plug_cb *, bool);
struct blk_plug_cb {
	struct list_head list;
	blk_plug_cb_fn callback;
	void *data;
};

extern struct blk_plug_cb *blk_check_plugged(blk_plug_cb_fn unplug, void *data, int size);
extern SIMULATION_DISK_IO_ERROR gSimulDiskIoError;

NTSTATUS SaveCurrentValue(PCWSTR valueName, int value);

BOOLEAN gbShutdown;

// DW-1469
int bsr_resize(struct bsr_device *device);

extern char *kvasprintf(int flags, const char *fmt, va_list args);
bool IsDiskError();
void msleep(int millisecs);

// BSR-874
void add_untagged_mem_usage(LONGLONG a);
void sub_untagged_mem_usage(LONGLONG a);

void add_untagged_mdl_mem_usage(PVOID buf, ULONG size);
void sub_untagged_mdl_mem_usage(PVOID buf, ULONG size);
#endif // BSR_WINDOWS_H
