#ifndef _BSR_WRAPPERS_H
#define _BSR_WRAPPERS_H

#ifdef _WIN
#include "../../../bsr-headers/bsr.h"
#include "./windows/rbtree.h"
#include "./windows/idr.h"
#include "./windows/bsr_wingenl.h"
#include "./windows/backing-dev.h"
#include "wsk_wrapper.h"
#else // _LIN
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
# error "At least kernel version 2.6.18 (with patches) required"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
# warning "Kernels <2.6.32 likely have compat issues we did not cover here"
#endif
#include "../compat.h"
#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/version.h>
#include <linux/crypto.h>
#include <linux/netlink.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/proc_fs.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#ifdef COMPAT_HAVE_PART_STAT_READ_ACCUM
#include <linux/part_stat.h>
#endif
#endif


#ifndef pr_fmt
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#endif

// TODO: data type define 

#ifdef _WIN

#define task_pid_nr(task)	(task->pid)

#else // _LIN

#ifndef ULONG_PTR
#define ULONG_PTR unsigned long
#endif
#ifndef LONG_PTR
#define LONG_PTR long
#endif

#define INT16_MAX		SHRT_MAX
#define INT32_MAX		INT_MAX

#define UINT16_MAX		USHRT_MAX
#define UINT32_MAX 		UINT_MAX

#define INTPTR_MAX		LONG_MAX
#define UINTPTR_MAX		ULONG_MAX

#define LONGLONG		long long int
#define ULONGLONG		unsigned long long
#define ULONG			unsigned int
#define LONG			int
#define PCHAR			char *
#define CHAR			char
#define PVOID			void *
#define USHORT			unsigned short

#define atomic_t64				atomic64_t
#define atomic_add64			atomic64_add
#define atomic_sub_return64		atomic64_sub_return
#define atomic_set64			atomic64_set
#define atomic_read64			atomic64_read
#define atomic_sub64			atomic64_sub
#define atomic_inc_return64		atomic64_inc_return
#define atomic_dec_return64		atomic64_dec_return
#define atomic_xchg64			atomic64_xchg

#ifndef UNREFERENCED_PARAMETER 
#define UNREFERENCED_PARAMETER(x)
#endif

#ifndef rcu_read_lock_check
#define rcu_read_lock_check(locked) rcu_read_lock()
#endif

#ifndef rcu_read_unlock_check
#define rcu_read_unlock_check(locked) rcu_read_unlock()
#endif

#endif



#ifdef _WIN
#define bsr_kmalloc	kmalloc
#define bsr_kzalloc	kzalloc
#define bsr_kfree	kfree
#else  // _LIN

// BSR-875 collecting memory usage of BSR module
struct bsr_mem_usage {
	atomic_t64 kmalloc; // bytes
	atomic_t64 vmalloc; // bytes
	atomic_t64 data_pp; // pages
	atomic_t64 bm_pp; // pages
};

extern struct bsr_mem_usage mem_usage;


#ifndef bsr_kzalloc
#define bsr_kzalloc(size, flags, args...) bsr_kzalloc(size, flags)
#endif
#ifndef bsr_kmalloc
#define bsr_kmalloc(size, flags, args...) bsr_kmalloc(size, flags)
#endif
static inline void *bsr_kcalloc(size_t n, size_t size, gfp_t flags)
{
	void *objp;

	objp = kcalloc(n, size, flags);
	if (objp)
		atomic_add64(ksize(objp), &mem_usage.kmalloc);
	
	return objp;
}

static inline void *bsr_kzalloc(size_t size, gfp_t flags)
{
	void *objp;

	objp = kzalloc(size, flags);
	if (objp)
		atomic_add64(ksize(objp), &mem_usage.kmalloc);
	
	return objp;
}

static inline void *bsr_kmalloc(size_t size, gfp_t flags)
{
	void *objp;

	objp = kmalloc(size, flags);
	if (objp)
		atomic_add64(ksize(objp), &mem_usage.kmalloc);
	
	return objp;
}

static inline void bsr_kfree(const void *objp)
{
	if (objp)
		atomic_sub64(ksize(objp), &mem_usage.kmalloc);

	kfree(objp);
}
#endif


// BSR-245 define timer_list data type for cross-platform
#ifdef _WIN
#define TIMER_DATA_TYPE PVOID
#else // _LIN
#define TIMER_DATA_TYPE unsigned long
#endif

// BSR-577 TODO remove
/* {{{ pr_* macros */
/* some very old kernels don't have them, or at least not all of them */
#ifndef pr_emerg
#define pr_emerg(fmt, ...) \
		printk(KERN_EMERG pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_alert
#define pr_alert(fmt, ...) \
		printk(KERN_ALERT pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_crit
#define pr_crit(fmt, ...) \
		printk(KERN_CRIT pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_err
#define pr_err(fmt, ...) \
		printk(KERN_ERR pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_warning
#define pr_warning(fmt, ...) \
		printk(KERN_WARNING pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_warn
#define pr_warn pr_warning
#endif
#ifndef pr_notice
#define pr_notice(fmt, ...) \
		printk(KERN_NOTICE pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_info
#define pr_info(fmt, ...) \
		printk(KERN_INFO pr_fmt(fmt), __VA_ARGS__)
#endif
#ifndef pr_cont
#define pr_cont(fmt, ...) \
		printk(KERN_CONT fmt, __VA_ARGS__)
#endif

/* pr_devel() should produce zero code unless DEBUG is defined */
#ifndef pr_devel
#ifdef DEBUG
#define pr_devel(fmt, ...) \
		printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_devel(fmt, ...) \
		no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif
#endif
/* }}} pr_* macros */

#ifdef _WIN
#define REQ_SYNC		(1ULL << __REQ_SYNC)
#define REQ_DISCARD		(1ULL << __REQ_DISCARD)
#define REQ_FUA			(1ULL << __REQ_FUA)
#define REQ_FLUSH		(1ULL << __REQ_FLUSH)
#endif

#ifndef U32_MAX
#define U32_MAX ((u32)~0U)
#endif
#ifndef S32_MAX
#define S32_MAX ((s32)(U32_MAX>>1))
#endif

#ifndef __GFP_RECLAIM
#define __GFP_RECLAIM __GFP_WAIT
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
# error "At least kernel version 2.6.18 (with patches) required"
#endif


/* The history of blkdev_issue_flush()

   It had 2 arguments before fbd9b09a177a481eda256447c881f014f29034fe,
   after it had 4 arguments. (With that commit came BLKDEV_IFL_WAIT)

   It had 4 arguments before dd3932eddf428571762596e17b65f5dc92ca361b,
   after it got 3 arguments. (With that commit came BLKDEV_DISCARD_SECURE
   and BLKDEV_IFL_WAIT disappeared again.) */
#ifndef BLKDEV_IFL_WAIT
#ifndef BLKDEV_DISCARD_SECURE
/* before fbd9b09a177 */
#ifdef _LIN
#define blkdev_issue_flush(b, gfpf, s)	blkdev_issue_flush(b, s)
#endif
#endif
/* after dd3932eddf4 no define at all */
#else
/* between fbd9b09a177 and dd3932eddf4 */
#define blkdev_issue_flush(b, gfpf, s)	blkdev_issue_flush(b, gfpf, s, BLKDEV_IFL_WAIT)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31) 
static inline unsigned short queue_logical_block_size(struct request_queue *q)
{
	int retval = 512;
	if (q && q->hardsect_size)
		retval = q->hardsect_size;
	return retval;
}

static inline sector_t bdev_logical_block_size(struct block_device *bdev)
{
    return queue_logical_block_size(bdev_get_queue(bdev));
}

static inline unsigned int queue_max_hw_sectors(struct request_queue *q)
{
    return q->max_hw_sectors;
}

static inline unsigned int queue_max_sectors(struct request_queue *q)
{
	return q->max_sectors;
}

static inline void blk_queue_logical_block_size(struct request_queue *q, unsigned short size)
{
	q->hardsect_size = size;
}
#endif



#ifdef _WIN
static inline unsigned int queue_logical_block_size(struct request_queue *q)
{
	unsigned int retval = 512;
	if (q && q->logical_block_size)
		retval = q->logical_block_size;
	return retval;
}

static inline sector_t bdev_logical_block_size(struct block_device *bdev)
{
	return queue_logical_block_size(bdev_get_queue(bdev));
}

// DW-1406 max_hw_sectors must be 64bit variable since it can be bigger than 4gb.
static inline unsigned long long queue_max_hw_sectors(struct request_queue *q)
{
	return q->max_hw_sectors;
}

static inline unsigned long long queue_max_sectors(struct request_queue *q)
{
	return q->max_hw_sectors;
}

static inline void blk_queue_logical_block_size(struct request_queue *q, unsigned short size)
{
	q->logical_block_size = size;
}
#endif

#ifndef COMPAT_QUEUE_LIMITS_HAS_DISCARD_ZEROES_DATA
static inline unsigned int queue_discard_zeroes_data(struct request_queue *q)
{
	UNREFERENCED_PARAMETER(q);
	return 0;
}
#endif

#ifdef _LIN
static inline int bsr_always_getpeername(struct socket *sock, struct sockaddr *uaddr)
{
#ifdef COMPAT_SOCK_OPS_RETURNS_ADDR_LEN
	return sock->ops->getname(sock, uaddr, 2);
#else
	int len = 0;
	int err = sock->ops->getname(sock, uaddr, &len, 2);
	return err ?: len;
#endif
}
#endif


#ifndef COMPAT_HAVE_BDEV_MAX_DISCARD_SECTORS
static inline unsigned int bdev_max_discard_sectors(struct block_device *bdev)
{
	return bdev_get_queue(bdev)->limits.max_discard_sectors;
}
#endif

#ifndef COMPAT_HAVE_BDEV_DISCARD_ALIGNMENT
static inline int bdev_discard_alignment(struct block_device *bdev)
{
	UNREFERENCED_PARAMETER(bdev);

#ifdef _WIN
	return 0;
#else // _LIN
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	return 0;
#else
	struct request_queue *q = bdev_get_queue(bdev);

	if (bdev != bdev->bd_contains)
		return bdev->bd_part->discard_alignment;

	return q->limits.discard_alignment;
#endif
#endif
}
#endif

#ifdef COMPAT_HAVE_SUBMIT_BIO
#ifdef COMPAT_HAVE_BLK_QC_T_SUBMIT_BIO
#define MAKE_REQUEST_TYPE blk_qc_t
#define MAKE_REQUEST_RETURN return BLK_QC_T_NONE
#else
#define MAKE_REQUEST_TYPE void
#define MAKE_REQUEST_RETURN return
#endif
#else
#ifdef COMPAT_HAVE_BLK_QC_T_MAKE_REQUEST
/* in Commit dece16353ef47d8d33f5302bc158072a9d65e26f
 * make_request() becomes type blk_qc_t. */
#define MAKE_REQUEST_TYPE blk_qc_t
#define MAKE_REQUEST_RETURN return BLK_QC_T_NONE
#else
#ifdef COMPAT_HAVE_VOID_MAKE_REQUEST
/* in Commit 5a7bbad27a410350e64a2d7f5ec18fc73836c14f (between Linux-3.1 and 3.2)
   make_request() becomes type void. Before it had type int. */
#define MAKE_REQUEST_TYPE void
#define MAKE_REQUEST_RETURN return
#else
#define MAKE_REQUEST_TYPE int
#define MAKE_REQUEST_RETURN return 0
#endif
#endif
#endif

// BSR-1095 5.18 and later kernel support
#ifndef __bitwise__
#define __bitwise__
#endif

#ifndef COMPAT_HAVE_FMODE_T
typedef unsigned __bitwise__ fmode_t;
#endif

#ifndef COMPAT_HAVE_BLKDEV_GET_BY_PATH
// BSR-1376
#ifndef COMPAT_HAVE_BLKDEV_GET_BY_PATH_4_PARAMS
// BSR-1452
#ifndef COMPAT_HAVE_BLKDEV_FILE
#ifndef COMPAT_HAVE_BLKDEV_HANDLE
/* see kernel 2.6.37,
 * d4d7762 block: clean up blkdev_get() wrappers and their users
 * e525fd8 block: make blkdev_get/put() handle exclusive access
 * and kernel 2.6.28
 * 30c40d2 [PATCH] propagate mode through open_bdev_excl/close_bdev_excl
 * Also note that there is no FMODE_EXCL before
 * 86d434d [PATCH] eliminate use of ->f_flags in block methods
 */
#ifndef COMPAT_HAVE_OPEN_BDEV_EXCLUSIVE
#ifndef FMODE_EXCL
#define FMODE_EXCL 0
#endif
static inline
struct block_device *open_bdev_exclusive(const char *path, fmode_t mode, void *holder)
{
	UNREFERENCED_PARAMETER(path);
	UNREFERENCED_PARAMETER(mode);
	UNREFERENCED_PARAMETER(holder);
#ifdef _LIN
	/* bsr does not open readonly, but try to be correct, anyways */
	return open_bdev_excl(path, (mode & FMODE_WRITE) ? 0 : MS_RDONLY, holder);
#endif
}
static inline
void close_bdev_exclusive(struct block_device *bdev, fmode_t mode)
{
	UNREFERENCED_PARAMETER(mode);
	UNREFERENCED_PARAMETER(bdev);
#ifdef _LIN
	/* mode ignored. */
	close_bdev_excl(bdev);
#endif
}
#endif
#ifdef _LIN
static inline struct block_device *blkdev_get_by_path(const char *path,
		fmode_t mode, void *holder)
{
	return open_bdev_exclusive(path, mode, holder);
}
#endif
static inline int bsr_blkdev_put(struct block_device *bdev, fmode_t mode)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(mode);	
	// DW-1109 put ref count and delete bdev if ref gets 0
	struct block_device *b = bdev->bd_parent?bdev->bd_parent:bdev;
	kref_put(&b->kref, delete_bsr_block_device);
#else // _LIN
	/* blkdev_put != close_bdev_exclusive, in general, so this is obviously
	 * not correct, and there should be some if (mode & FMODE_EXCL) ...
	 * But this is the only way it is used in BSR,
	 * and for <= 2.6.27, there is no FMODE_EXCL anyways. */
	close_bdev_exclusive(bdev, mode);

#endif
	/* blkdev_put seems to not have useful return values,
	 * close_bdev_exclusive is void. */
	return 0;
}
#define blkdev_put(b, m)	bsr_blkdev_put(b, m)
#else
// BSR-1376
#ifndef FMODE_EXCL
#define FMODE_EXCL 0
#endif
#endif
// BSR-1452
#else
// BSR-1376
#ifndef FMODE_EXCL
#define FMODE_EXCL 0
#endif
#endif
#else
#ifndef FMODE_EXCL
#define FMODE_EXCL 0
#endif
#endif

#endif

#define bsr_bio_uptodate(bio) bio_flagged(bio, BIO_UPTODATE)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define BIO_ENDIO_TYPE void
#define BIO_ENDIO_ARGS(b,e) (b)
#define BIO_ENDIO_FN_START int error = bio->bi_error
#define BIO_ENDIO_FN_RETURN return

#elif defined(_WIN)
typedef NTSTATUS BIO_ENDIO_TYPE;
#define FAULT_TEST_FLAG     (ULONG_PTR)0x11223344
#define BIO_ENDIO_ARGS(b,e) (void *p1, void *p2, void *p3)
#define BIO_ENDIO_FN_START 
#define BIO_ENDIO_FN_RETURN     return STATUS_MORE_PROCESSING_REQUIRED	
#define bsr_bio_endio(b,e) bio_endio(b,e)
#else
#ifdef COMPAT_HAVE_BIO_BI_STATUS
static inline void bsr_bio_endio(struct bio *bio, int error)
{
	bio->bi_status = errno_to_blk_status(error);
	bio_endio(bio);
}

#define BIO_ENDIO_TYPE void
#define BIO_ENDIO_ARGS(b) (b)
#define BIO_ENDIO_FN_START	\
	blk_status_t status = bio->bi_status;	\
	int error = blk_status_to_errno(status);
#define BIO_ENDIO_FN_RETURN return
#else


#ifdef COMPAT_HAVE_BIO_BI_ERROR
static inline void bsr_bio_endio(struct bio *bio, int error)
{
        bio->bi_error = error;
        bio_endio(bio);
}
#define BIO_ENDIO_TYPE void
#define BIO_ENDIO_ARGS(b) (b)
#define BIO_ENDIO_FN_START      \
        int error = bio->bi_error
#define BIO_ENDIO_FN_RETURN return
#else
static inline void bsr_bio_endio(struct bio *bio, int error)
{
        bio_endio(bio, error);
}
#define BIO_ENDIO_TYPE void
#define BIO_ENDIO_ARGS(b) (b, int error)
#define BIO_ENDIO_FN_START do {} while (0)
#define BIO_ENDIO_FN_RETURN return
#endif
#endif
#endif

/* bi_end_io handlers */
//extern BIO_ENDIO_TYPE bsr_md_endio BIO_ENDIO_ARGS(struct bio *bio, int error);

#ifdef _WIN
extern IO_COMPLETION_ROUTINE bsr_md_endio;
extern IO_COMPLETION_ROUTINE bsr_peer_request_endio;
extern IO_COMPLETION_ROUTINE bsr_request_endio;
extern IO_COMPLETION_ROUTINE bsr_bm_endio;
#else // _LIN
extern BIO_ENDIO_TYPE bsr_md_endio BIO_ENDIO_ARGS(struct bio *bio);
extern BIO_ENDIO_TYPE bsr_peer_request_endio BIO_ENDIO_ARGS(struct bio *bio);
extern BIO_ENDIO_TYPE bsr_request_endio BIO_ENDIO_ARGS(struct bio *bio);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define part_inc_in_flight(A, B) part_inc_in_flight(A)
#define part_dec_in_flight(A, B) part_dec_in_flight(A)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
/* Before 2.6.23 (with 20c2df83d25c6a95affe6157a4c9cac4cf5ffaac) kmem_cache_create had a
   ctor and a dtor */
#define kmem_cache_create(N,S,A,F,C) kmem_cache_create(N,S,A,F,C,NULL)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static inline void sg_set_page(struct scatterlist *sg, struct page *page,
			       unsigned int len, unsigned int offset)
{
	sg->page   = page;
	sg->offset = offset;
	sg->length = len;
}

#define sg_init_table(S,N) ({})

#endif

/* how to get to the kobj of a gendisk.
 * see also upstream commits
 * edfaa7c36574f1bf09c65ad602412db9da5f96bf
 * ed9e1982347b36573cd622ee5f4e2a7ccd79b3fd
 * 548b10eb2959c96cef6fc29fc96e0931eeb53bc5
 */
#ifndef dev_to_disk
# define disk_to_kobj(disk) (&(disk)->kobj)
#else
# ifndef disk_to_dev
#  define disk_to_dev(disk) (&(disk)->dev)
# endif
# define disk_to_kobj(disk) (&disk_to_dev(disk)->kobj)
#endif

/* see 7eaceac block: remove per-queue plugging */
#ifdef blk_queue_plugged
static inline void bsr_plug_device(struct request_queue *q)
{
	spin_lock_irq(q->queue_lock);

/* XXX the check on !blk_queue_plugged is redundant,
 * implicitly checked in blk_plug_device */

	if (!blk_queue_plugged(q)) {
		blk_plug_device(q);
		del_timer(&q->unplug_timer);
		/* unplugging should not happen automatically... */
	}
	spin_unlock_irq(q->queue_lock);
}
#else
static inline void bsr_plug_device(struct request_queue *q)
{
	UNREFERENCED_PARAMETER(q);
}
#endif

#ifdef _LIN
static inline int bsr_backing_bdev_events(struct gendisk *disk)
{
#ifdef COMPAT_HAVE_PART_STAT_READ_ACCUM
	/* recent kernel */
#ifdef COMPAT_PART_STAT_READ_TAKES_BLOCK_DEVICE
	return (int)part_stat_read_accum(disk->part0, sectors);
#else
	return (int)part_stat_read_accum(&disk->part0, sectors);
#endif
#else
	return (int)part_stat_read(&disk->part0, sectors[0])
	     + (int)part_stat_read(&disk->part0, sectors[1]);
#endif
}
#endif

#ifndef COMPAT_HAVE_SOCK_SHUTDOWN
#define COMPAT_HAVE_SOCK_SHUTDOWN 1
enum sock_shutdown_cmd {
	SHUT_RD = 0,
	SHUT_WR = 1,
	SHUT_RDWR = 2,
};



static inline int kernel_sock_shutdown(struct socket *sock, enum sock_shutdown_cmd how)
{
#ifdef _WIN
    UNREFERENCED_PARAMETER(how);
	return Disconnect(sock);
#else // _LIN
	return sock->ops->shutdown(sock, how);
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static inline void bsr_unregister_blkdev(unsigned int major, const char *name)
{
	int ret = unregister_blkdev(major, name);
	if (ret)
		pr_err("unregister of device failed\n");
}
#else
#define bsr_unregister_blkdev unregister_blkdev
#endif

#if defined(_WIN) || !defined(CRYPTO_ALG_ASYNC)
/* With Linux-2.6.19 the crypto API changed! */
/* This is not a generic backport of the new api, it just implements
   the corner case of "hmac(xxx)".  */

#define CRYPTO_ALG_ASYNC 4711
#define CRYPTO_ALG_TYPE_HASH CRYPTO_ALG_TYPE_DIGEST

struct crypto_hash {
	struct crypto_tfm *base;
	const u8 *key;
	int keylen;
};

struct hash_desc {
	struct crypto_hash *tfm;
	u32 flags;
};

#ifdef _WIN
static inline struct crypto_hash *
crypto_alloc_hash(char *alg_name, u32 type, u32 mask, ULONG Tag)
{
	UNREFERENCED_PARAMETER(type);
	UNREFERENCED_PARAMETER(mask);

	struct crypto_hash *ch;
	char *closing_bracket;

	/* "hmac(xxx)" is in alg_name we need that xxx. */
	closing_bracket = strchr(alg_name, ')');
	if (!closing_bracket) {
		ch = kmalloc(sizeof(struct crypto_hash), GFP_KERNEL, Tag);
		if (!ch)
			return ERR_PTR(-ENOMEM);
		ch->base = crypto_alloc_tfm(alg_name, 0);
		if (ch->base == NULL) {
			kfree(ch);
			return ERR_PTR(-ENOMEM);
		}
		return ch;
	}
	if (closing_bracket-alg_name < 6)
		return ERR_PTR(-ENOENT);

	ch = kmalloc(sizeof(struct crypto_hash), GFP_KERNEL, Tag);
	if (!ch)
		return ERR_PTR(-ENOMEM);

	*closing_bracket = 0;
	ch->base = crypto_alloc_tfm(alg_name + 5, 0);
	*closing_bracket = ')';

	if (ch->base == NULL) {
		kfree(ch);
		return ERR_PTR(-ENOMEM);
	}

	return ch;
}
#endif

static inline int
crypto_hash_setkey(struct crypto_hash *hash, const u8 *key, unsigned int keylen)
{
	hash->key = key;
	hash->keylen = keylen;

	return 0;
}

static inline int
crypto_hash_digest(struct hash_desc *desc, struct scatterlist *sg,
		   unsigned int nbytes, u8 *out)
{
	UNREFERENCED_PARAMETER(sg);
	UNREFERENCED_PARAMETER(out);
	UNREFERENCED_PARAMETER(nbytes);
	UNREFERENCED_PARAMETER(desc);

#ifdef _LIN
	crypto_hmac(desc->tfm->base, (u8 *)desc->tfm->key,
		    &desc->tfm->keylen, sg, 1 /* ! */ , out);
	/* ! this is not generic. Would need to convert nbytes -> nsg */
#endif
	return 0;
}

static inline void crypto_free_hash(struct crypto_hash *tfm)
{
	if (!tfm)
		return;
#ifdef _LIN
	crypto_free_tfm(tfm->base);
#endif
	bsr_kfree(tfm);
}

static inline unsigned int crypto_hash_digestsize(struct crypto_hash *tfm)
{
	return crypto_tfm_alg_digestsize(tfm->base);
}

static inline struct crypto_tfm *crypto_hash_tfm(struct crypto_hash *tfm)
{
	return tfm->base;
}

static inline int crypto_hash_init(struct hash_desc *desc)
{
	UNREFERENCED_PARAMETER(desc);

#ifdef _LIN
	crypto_digest_init(desc->tfm->base);
#endif
	return 0;
}

static inline int crypto_hash_update(struct hash_desc *desc,
				     struct scatterlist *sg,
				     unsigned int nbytes)
{
#ifdef _WIN
	*(int*)desc = crc32c(0, (uint8_t *)sg, nbytes);
#else // _LIN
	crypto_digest_update(desc->tfm->base,sg,1 /* ! */ );
	/* ! this is not generic. Would need to convert nbytes -> nsg */
#endif
	return 0;
}

static inline int crypto_hash_final(struct hash_desc *desc, u8 *out)
{
#ifdef _WIN
	int i;
	u8 *p = (u8*)desc; 
	for(i = 0; i < 4; i++) {
		*out++ = *p++; // long
	}
#else // _LIN
	crypto_digest_final(desc->tfm->base, out);
#endif
	return 0;
}

#ifdef _WIN
#define crypto_shash crypto_hash

static inline void crypto_free_shash(struct crypto_shash *tfm)
{
	crypto_free_hash(tfm);
}

static inline unsigned int crypto_shash_digestsize(struct crypto_shash *tfm)
{
    return crypto_hash_digestsize(tfm);
}
#endif

#endif

#ifdef _LIN
#ifndef COMPAT_HAVE_VZALLOC
static inline void *vzalloc(unsigned long size)
{
	void *rv = vmalloc(size);
	if (rv)
		memset(rv, 0, size);

	return rv;
}
#endif
#endif

#ifndef COMPAT_HAVE_UMH_WAIT_PROC
/* On Jul 17 2007 with commit 86313c4 usermodehelper: Tidy up waiting,
 * UMH_WAIT_PROC was added as an enum value of 1.
 * On Mar 23 2012 with commit 9d944ef3 that got changed to a define of 2. */
#define UMH_WAIT_PROC 1
#endif

/* see upstream commit 2d3854a37e8b767a51aba38ed6d22817b0631e33 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#ifndef cpumask_bits
#define nr_cpu_ids NR_CPUS
#define nr_cpumask_bits nr_cpu_ids

typedef cpumask_t cpumask_var_t[1];
#define cpumask_bits(maskp) ((unsigned long*)(maskp))
#define cpu_online_mask &(cpu_online_map)

#ifdef _LIN
static inline void cpumask_clear(cpumask_t *dstp)
{
	bitmap_zero(cpumask_bits(dstp), NR_CPUS);
}

static inline int cpumask_equal(const cpumask_t *src1p,
				const cpumask_t *src2p)
{
	return bitmap_equal(cpumask_bits(src1p), cpumask_bits(src2p),
						 nr_cpumask_bits);
}

static inline void cpumask_copy(cpumask_t *dstp,
				cpumask_t *srcp)
{
	bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

static inline unsigned int cpumask_weight(const cpumask_t *srcp)
{
	return bitmap_weight(cpumask_bits(srcp), nr_cpumask_bits);
}

static inline void cpumask_set_cpu(unsigned int cpu, cpumask_t *dstp)
{
	set_bit(cpu, cpumask_bits(dstp));
}

static inline void cpumask_setall(cpumask_t *dstp)
{
	bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
}
#endif
#endif
/* see upstream commit 0281b5dc0350cbf6dd21ed558a33cccce77abc02 */
#ifdef CONFIG_CPUMASK_OFFSTACK
static inline int zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return alloc_cpumask_var(mask, flags | __GFP_ZERO);
}
#else
static inline int zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	cpumask_clear(*mask);
	return 1;
}
#endif
/* see upstream commit cd8ba7cd9be0192348c2836cb6645d9b2cd2bfd2 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
/* As macro because RH has it in 2.6.18-128.4.1.el5, but not exported to modules !?!? */
#define set_cpus_allowed_ptr(P, NM) set_cpus_allowed(P, *NM)
#endif
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define __bitmap_parse(BUF, BUFLEN, ISUSR, MASKP, NMASK) \
	backport_bitmap_parse(BUF, BUFLEN, ISUSR, MASKP, NMASK)

#define CHUNKSZ                         32
#define nbits_to_hold_value(val)        fls(val)
#define unhex(c)                        (isdigit(c) ? (c - '0') : (toupper(c) - 'A' + 10))

static inline int backport_bitmap_parse(const char *buf, unsigned int buflen,
		int is_user, unsigned long *maskp,
		int nmaskbits)
{
	int c, old_c, totaldigits, ndigits, nchunks, nbits;
	u32 chunk;
	const char __user *ubuf = buf;

	bitmap_zero(maskp, nmaskbits);

	nchunks = nbits = totaldigits = c = 0;
	do {
		chunk = ndigits = 0;

		/* Get the next chunk of the bitmap */
		while (buflen) {
			old_c = c;
			if (is_user) {
				if (__get_user(c, ubuf++))
					return -EFAULT;
			}
			else
				c = *buf++;
			buflen--;
			if (isspace(c))
				continue;

			/*
			 * If the last character was a space and the current
			 * character isn't '\0', we've got embedded whitespace.
			 * This is a no-no, so throw an error.
			 */
			if (totaldigits && c && isspace(old_c))
				return -EINVAL;

			/* A '\0' or a ',' signal the end of the chunk */
			if (c == '\0' || c == ',')
				break;

			if (!isxdigit(c))
				return -EINVAL;

			/*
			 * Make sure there are at least 4 free bits in 'chunk'.
			 * If not, this hexdigit will overflow 'chunk', so
			 * throw an error.
			 */
			if (chunk & ~((1UL << (CHUNKSZ - 4)) - 1))
				return -EOVERFLOW;

			chunk = (chunk << 4) | unhex(c);
			ndigits++; totaldigits++;
		}
		if (ndigits == 0)
			return -EINVAL;
		if (nchunks == 0 && chunk == 0)
			continue;

		bitmap_shift_left(maskp, maskp, CHUNKSZ, nmaskbits);
		*maskp |= chunk;
		nchunks++;
		nbits += (nchunks == 1) ? nbits_to_hold_value(chunk) : CHUNKSZ;
		if (nbits > nmaskbits)
			return -EOVERFLOW;
	} while (buflen && c == ',');

	return 0;
}
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define BDI_async_congested BDI_write_congested
#define BDI_sync_congested  BDI_read_congested
#endif

#ifndef COMPAT_HAVE_PROC_CREATE_SINGLE
#ifdef _LIN
extern struct proc_dir_entry *proc_create_single(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        int (*show)(struct seq_file *, void *));
#endif
#endif

#ifndef COMPAT_HAVE_BLK_QUEUE_MAX_HW_SECTORS
static inline void blk_queue_max_hw_sectors(struct request_queue *q, unsigned int max)
{
#ifdef _WIN
	q->max_hw_sectors = max;
#else // _LIN
// BSR-1521
#ifdef COMPAT_HAVE_BLK_QUEUE_HELPER
	blk_queue_max_sectors(q, max);
#else 
	q->limits.max_sectors = max;
#endif
#endif
}
#elif defined(COMPAT_USE_BLK_QUEUE_MAX_SECTORS_ANYWAYS)
	/* For kernel versions 2.6.31 to 2.6.33 inclusive, even though
	 * blk_queue_max_hw_sectors is present, we actually need to use
	 * blk_queue_max_sectors to set max_hw_sectors. :-(
	 * RHEL6 2.6.32 chose to be different and already has eliminated
	 * blk_queue_max_sectors as upstream 2.6.34 did.
	 */
#define blk_queue_max_hw_sectors(q, max)	blk_queue_max_sectors(q, max)
#endif

#ifndef COMPAT_HAVE_BLK_QUEUE_MAX_SEGMENTS
static inline void blk_queue_max_segments(struct request_queue *q, unsigned short max_segments)
{
	UNREFERENCED_PARAMETER(q);
	UNREFERENCED_PARAMETER(max_segments);

#ifdef _LIN
// BSR-1521
#ifdef COMPAT_HAVE_BLK_QUEUE_HELPER
	blk_queue_max_phys_segments(q, max_segments);
	blk_queue_max_hw_segments(q, max_segments);
#else
    q->limits.max_segments  = max_segments;
#endif
#define BLK_MAX_SEGMENTS MAX_HW_SEGMENTS /* or max MAX_PHYS_SEGMENTS. Probably does not matter */
#endif
}
#endif

#ifdef _LIN
#ifndef COMPAT_HAVE_BOOL_TYPE
typedef _Bool                   bool;
enum {
	false = 0,
	true = 1
};
#endif
#endif

/* How do we tell the block layer to pass down flush/fua? */
// BSR-1521
#if !defined(COMPAT_HAVE_BLK_QUEUE_WRITE_CACHE) && !defined(COMPAT_HAVE_BLK_QUEUE_WRITE_CACHE_1_PARAMS)
static inline void blk_queue_write_cache(struct request_queue *q, bool enabled, bool fua)
{
#if defined(REQ_FLUSH) && !defined(REQ_HARDBARRIER)
/* Linux version 2.6.37 up to 4.7
 * needs blk_queue_flush() to announce driver support */
	blk_queue_flush(q, (enabled ? REQ_FLUSH : 0) | (fua ? REQ_FUA : 0));
#else
/* Older kernels either flag affected bios with BIO_RW_BARRIER, or do not know
 * how to handle this at all. No need to "announce" driver support. */
#endif
}
#endif

/* bio -> bi_rw/bi_opf REQ_* and BIO_RW_* REQ_OP_* compat stuff {{{1 */
/* REQ_* and BIO_RW_* flags have been moved around in the tree,
 * and have finally been "merged" with
 * 7b6d91daee5cac6402186ff224c3af39d79f4a0e and
 * 7cc015811ef8992dfcce314d0ed9642bc18143d1
 * We communicate between different systems,
 * so we have to somehow semantically map the bi_opf flags
 * bi_opf (some kernel version) -> data packet flags -> bi_opf (other kernel version)
 */

#if defined(COMPAT_HAVE_BIO_SET_OP_ATTRS) && \
	!(defined(RHEL_RELEASE_CODE) && /* 7.4 broke our compat detection here */ \
		LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))
		
/* Linux 4.8 split bio OPs and FLAGs {{{2 */

#define BSR_REQ_PREFLUSH	REQ_PREFLUSH
#define BSR_REQ_FUA		REQ_FUA
#define BSR_REQ_SYNC		REQ_SYNC

/* long gone */
#define BSR_REQ_HARDBARRIER	0
#define BSR_REQ_UNPLUG		0

/* became an op, no longer flag */
#define BSR_REQ_DISCARD	0
#define BSR_REQ_WSAME		0

/* Gone in Linux 4.10 */
#ifndef WRITE_SYNC
#define WRITE_SYNC REQ_SYNC
#endif

#define COMPAT_WRITE_SAME_CAPABLE

#ifndef COMPAT_HAVE_REQ_OP_WRITE_ZEROES
#define REQ_OP_WRITE_ZEROES (-3u)
#endif

#elif !defined(REQ_FLUSH) && defined(REQ_PREFLUSH) /* after rhel 9.3*/
#define BSR_REQ_PREFLUSH	REQ_PREFLUSH
#define BSR_REQ_FUA		REQ_FUA
#define BSR_REQ_SYNC		REQ_SYNC

#ifdef REQ_HARDBARRIER
#define BSR_REQ_HARDBARRIER	REQ_HARDBARRIER
#else
#define BSR_REQ_HARDBARRIER	0
#endif

#ifdef REQ_UNPLUG
#define BSR_REQ_UNPLUG		REQ_UNPLUG
#else
#define BSR_REQ_UNPLUG		0
#endif

#ifndef WRITE_SYNC
#define WRITE_SYNC REQ_SYNC
#endif

#elif defined(BIO_FLUSH)
/* RHEL 6.1 ("not quite 2.6.32") backported FLUSH/FUA as BIO_RW_FLUSH/FUA {{{2
 * and at that time also introduced the defines BIO_FLUSH/FUA.
 * There is also REQ_FLUSH/FUA, but these do NOT share
 * the same value space as the bio rw flags, yet.
 */


#define BSR_REQ_PREFLUSH	(1UL << BIO_RW_FLUSH)
#define BSR_REQ_FUA		(1UL << BIO_RW_FUA)
#define BSR_REQ_HARDBARRIER	(1UL << BIO_RW_BARRIER)
#define BSR_REQ_DISCARD	(1UL << BIO_RW_DISCARD)
#define BSR_REQ_SYNC		(1UL << BIO_RW_SYNCIO)
#define BSR_REQ_UNPLUG		(1UL << BIO_RW_UNPLUG)

#define REQ_RAHEAD		(1UL << BIO_RW_AHEAD)

#elif defined(REQ_FLUSH)	/* [2.6.36 .. 4.7] introduced in 2.6.36, {{{2
				 * now equivalent to bi_rw */

#define BSR_REQ_SYNC		REQ_SYNC
#define BSR_REQ_PREFLUSH	REQ_FLUSH
#define BSR_REQ_FUA		REQ_FUA
#define BSR_REQ_DISCARD	REQ_DISCARD
/* REQ_HARDBARRIER has been around for a long time,
 * without being directly related to bi_rw.
 * so the ifdef is only usful inside the ifdef REQ_FLUSH!
 * commit 7cc0158 (v2.6.36-rc1) made it a bi_rw flag, ...  */
#ifdef REQ_HARDBARRIER
#define BSR_REQ_HARDBARRIER	REQ_HARDBARRIER
#else
/* ... but REQ_HARDBARRIER was removed again in 02e031c (v2.6.37-rc4). */
#define BSR_REQ_HARDBARRIER	0
#endif

/* again: testing on this _inside_ the ifdef REQ_FLUSH,
 * see 721a960 block: kill off REQ_UNPLUG */
#ifdef REQ_UNPLUG
#define BSR_REQ_UNPLUG		REQ_UNPLUG
#else
#define BSR_REQ_UNPLUG		0
#endif

#ifdef REQ_WRITE_SAME
#define BSR_REQ_WSAME         REQ_WRITE_SAME
#define COMPAT_WRITE_SAME_CAPABLE
#endif

#else				/* "older", and hopefully not {{{2
				 * "partially backported" kernel */

#define REQ_RAHEAD		(1UL << BIO_RW_AHEAD)

#if defined(BIO_RW_SYNC)
/* see upstream commits
 * 213d9417fec62ef4c3675621b9364a667954d4dd,
 * 93dbb393503d53cd226e5e1f0088fe8f4dbaa2b8
 * later, the defines even became an enum ;-) */
#define BSR_REQ_SYNC		(1UL << BIO_RW_SYNC)
#define BSR_REQ_UNPLUG		(1UL << BIO_RW_SYNC)
#else
/* cannot test on defined(BIO_RW_SYNCIO), it may be an enum */
#define BSR_REQ_SYNC		(1UL << BIO_RW_SYNCIO)
#define BSR_REQ_UNPLUG		(1UL << BIO_RW_UNPLUG)
#endif

#define BSR_REQ_PREFLUSH	(1UL << BIO_RW_BARRIER)
/* REQ_FUA has been around for a longer time,
 * without a direct equivalent in bi_rw. */
#define BSR_REQ_FUA		(1UL << BIO_RW_BARRIER)
#define BSR_REQ_HARDBARRIER	(1UL << BIO_RW_BARRIER)

#define COMPAT_MAYBE_RETRY_HARDBARRIER

/* we don't support DISCARDS yet, anyways.
 * cannot test on defined(BIO_RW_DISCARD), it may be an enum */
#define BSR_REQ_DISCARD	0
#endif

#ifndef COMPAT_HAVE_REQ_NOUNMAP
#define REQ_NOUNMAP 0
#endif

/* this results in:
	bi_opf   -> dp_flags

< 2.6.28
	SYNC	-> SYNC|UNPLUG
	BARRIER	-> FUA|FLUSH
	there is no DISCARD
2.6.28
	SYNC	-> SYNC|UNPLUG
	BARRIER	-> FUA|FLUSH
	DISCARD	-> DISCARD
2.6.29
	SYNCIO	-> SYNC
	UNPLUG	-> UNPLUG
	BARRIER	-> FUA|FLUSH
	DISCARD	-> DISCARD
2.6.36
	SYNC	-> SYNC
	UNPLUG	-> UNPLUG
	FUA	-> FUA
	FLUSH	-> FLUSH
	DISCARD	-> DISCARD
--------------------------------------
	dp_flags   -> bi_rw
< 2.6.28
	SYNC	-> SYNC (and unplug)
	UNPLUG	-> SYNC (and unplug)
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	there is no DISCARD,
	it will be silently ignored on the receiving side.
2.6.28
	SYNC	-> SYNC (and unplug)
	UNPLUG	-> SYNC (and unplug)
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	DISCARD -> DISCARD
	(if that fails, we handle it like any other IO error)
2.6.29
	SYNC	-> SYNCIO
	UNPLUG	-> UNPLUG
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	DISCARD -> DISCARD
2.6.36
	SYNC	-> SYNC
	UNPLUG	-> UNPLUG
	FUA	-> FUA
	FLUSH	-> FLUSH
	DISCARD	-> DISCARD
*/

/* fallback defines for older kernels {{{2 */

#ifndef BSR_REQ_WSAME
#define BSR_REQ_WSAME		0
#endif

#ifndef WRITE_FLUSH
#ifndef WRITE_SYNC
#error  FIXME WRITE_SYNC undefined??
#endif
#define WRITE_FLUSH       (WRITE_SYNC | BSR_REQ_PREFLUSH)
#endif

#ifndef REQ_NOIDLE
/* introduced in aeb6faf (2.6.30), relevant for CFQ */
#define REQ_NOIDLE 0
#endif

#ifndef COMPAT_HAVE_REFCOUNT_INC
#define refcount_inc(R) atomic_inc(R)
#define refcount_set(R, V) atomic_set(R, V)
#define refcount_read(R) atomic_read(R)
#define refcount_dec_and_test(R) atomic_dec_and_test(R)
#endif

#ifndef KREF_INIT
#define KREF_INIT(N) { ATOMIC_INIT(N) }
#endif

#define _adjust_ra_pages(qrap, brap) do { \
	if (qrap != brap) { \
		bsr_info(65, BSR_LC_ETC, device, "Adjusting request queue ra_pages to backing device's (%lu -> %lu)", qrap, brap); \
		qrap = brap; \
		} \
} while(0)

#ifdef COMPAT_STRUCT_GENDISK_HAS_BACKING_DEV_INFO
#define adjust_ra_pages(q, b) _adjust_ra_pages((q)->ra_pages, (b)->ra_pages)
#else
#ifdef COMPAT_HAVE_POINTER_BACKING_DEV_INFO
#define bdi_from_device(device) (device->ldev->backing_bdev->bd_disk->queue->backing_dev_info)
#define init_bdev_info(bdev_info, bsr_congested, device) do { \
	(bdev_info)->congested_fn = bsr_congested; \
	(bdev_info)->congested_data = device; \
} while(0)
#define adjust_ra_pages(q, b) _adjust_ra_pages((q)->backing_dev_info->ra_pages, (b)->backing_dev_info->ra_pages)
#else
#define bdi_rw_congested(BDI) bdi_rw_congested(&BDI)
#define bdi_congested(BDI, BDI_BITS) bdi_congested(&BDI, (BDI_BITS))
#define bdi_from_device(device) (&device->ldev->backing_bdev->bd_disk->queue->backing_dev_info)
#define init_bdev_info(bdev_info, bsr_congested, device) do { \
	(bdev_info).congested_fn = bsr_congested; \
	(bdev_info).congested_data = device; \
} while(0)
#define adjust_ra_pages(q, b) _adjust_ra_pages((q)->backing_dev_info.ra_pages, (b)->backing_dev_info.ra_pages)
#endif
#endif

#if defined(COMPAT_HAVE_BIO_SET_OP_ATTRS) /* compat for Linux before 4.8 {{{2 */
#if (defined(RHEL_RELEASE_CODE /* 7.4 broke our compat detection here */) && \
			LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))
/* Thank you RHEL 7.4 for backporting just enough to break existing compat code,
 * but not enough to make it work for us without additional compat code.
 */
#define COMPAT_NEED_BI_OPF_AND_SUBMIT_BIO_COMPAT_DEFINES 1

#ifndef COMPAT_HAVE_REQ_OP_WRITE_ZEROES
#define REQ_OP_WRITE_ZEROES (-3u)
#endif
#endif
#else /* !defined(COMPAT_HAVE_BIO_SET_OP_ATTRS) */
#define COMPAT_NEED_BI_OPF_AND_SUBMIT_BIO_COMPAT_DEFINES 1

#ifndef REQ_WRITE
/* before 2.6.36 */
#define REQ_WRITE 1
#endif

#ifndef COMPAT_HAVE_ENUM_REQ_OP
enum req_op {
	REQ_OP_READ,				/* 0 */
	REQ_OP_WRITE = REQ_WRITE,	/* 1 */

	/* Not yet a distinguished op,
	* but identified via FLUSH/FUA flags.
	* If at all. */
	REQ_OP_FLUSH = REQ_OP_WRITE,

	/* These may be not supported in older kernels.
	* In that case, the BSR_REQ_* will be 0,
	* bio_op() aka. op_from_rq_bits() will never return these,
	* and we map the REQ_OP_* to something stupid.
	*/
	REQ_OP_DISCARD = BSR_REQ_DISCARD ? BSR_REQ_DISCARD : -1,
	REQ_OP_WRITE_SAME = BSR_REQ_WSAME ? BSR_REQ_WSAME : -2,
	REQ_OP_WRITE_ZEROES	= -3,
	/* REQ_OP_SECURE_ERASE: does not matter to us,
	* I don't see how we could support that anyways. */
};
#endif

#ifndef COMPAT_HAVE_BIO_OP
#define bio_op(bio)                            (op_from_rq_bits((bio)->bi_rw))
static inline int op_from_rq_bits(u64 flags)
{
	if (flags & BSR_REQ_DISCARD)
		return REQ_OP_DISCARD;
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
	else if (flags & BSR_REQ_WSAME)
		return REQ_OP_WRITE_SAME;
#endif
	else if (flags & REQ_WRITE)
		return REQ_OP_WRITE;
	else
		return REQ_OP_READ;
}
#endif

#ifdef _WIN
extern void bio_set_op_attrs(struct bio *bio, const int op, const long flags);
#else // LIN
static inline void bio_set_op_attrs(struct bio *bio, const int op, const long flags)
{
#ifdef COMPAT_HAVE_BIO_BI_OPF
	bio->bi_opf = op | flags;
#else
	/* If we explicitly issue discards or write_same, we use
	* blkdev_issue_discard() and blkdev_issue_write_same() helpers.
	* If we implicitly submit them, we just pass on a cloned bio to
	* generic_make_request().  We expect to use bio_set_op_attrs() with
	* REQ_OP_READ or REQ_OP_WRITE only. */
	BUG_ON(!(op == REQ_OP_READ || op == REQ_OP_WRITE));
	bio->bi_rw |= (op | flags);
#endif
}
#endif

#endif

#ifdef COMPAT_HAVE_SUBMIT_BIO_NOACCT
#define generic_make_request(bio)	submit_bio_noacct(bio)
#endif

#ifndef COMPAT_HAVE_BIO_BI_OPF
#define bi_opf	bi_rw
#endif
#ifdef COMPAT_SUBMIT_BIO_HAS_2_PARAMS
#define submit_bio(__bio)	submit_bio(__bio->bi_rw, __bio)
#endif
#ifdef COMPAT_NEED_BI_OPF_AND_SUBMIT_BIO_COMPAT_DEFINES
/* see comment in above compat enum req_op */
#define REQ_OP_FLUSH		REQ_OP_WRITE
#endif
/* }}}1 bio -> bi_rw/bi_opf REQ_* and BIO_RW_* REQ_OP_* compat stuff */


#ifndef CONFIG_DYNAMIC_DEBUG
/* At least in 2.6.34 the function macro dynamic_dev_dbg() is broken when compiling
   without CONFIG_DYNAMIC_DEBUG. It has 'format' in the argument list, it references
   to 'fmt' in its body. */
#ifdef dynamic_dev_dbg
#undef dynamic_dev_dbg
#define dynamic_dev_dbg(dev, fmt, ...)                               \
        do { if (0) dev_printk(KERN_DEBUG, dev, fmt, ##__VA_ARGS__); } while (0)
#endif
#ifdef _WIN
#define dynamic_dev_dbg(dev, fmt, ...)   
#endif
#endif

#ifndef min_not_zero
#ifdef _WIN
#define min_not_zero(x, y) (x == 0 ? y : ((y == 0) ? x : min(x, y)))
#else // _LIN
#define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })
#endif
#endif

/* Introduced with 2.6.26. See include/linux/jiffies.h */
#ifndef time_is_before_eq_jiffies
#define time_is_before_jiffies(a) time_after(jiffies, a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_before_eq_jiffies(a) time_after_eq(jiffies, a)
#define time_is_after_eq_jiffies(a) time_before_eq(jiffies, a)
#endif

#ifndef time_in_range
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))
#endif

#ifdef COMPAT_BIO_SPLIT_HAS_BIO_SPLIT_POOL_PARAMETER
#define bio_split(bi, first_sectors) bio_split(bi, bio_split_pool, first_sectors)
#endif


#ifdef _LIN
/* history of bioset_create():
 *  v4.13  011067b  blk: replace bioset_create_nobvec() with a flags arg to bioset_create()
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad, int flags)
 *
 *  v3.18  d8f429e  block: add bioset_create_nobvec()
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
 *  +struct bio_set *bioset_create_nobvec(unsigned int pool_size, unsigned int front_pad)
 *
 *  v3.16  f9c78b2  block: move bio.c and bio-integrity.c from fs/ to block/
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
 *
 *  --- we don't care for older than 2.3.32 ---
 */
#if defined(COMPAT_HAVE_BIOSET_NEED_BVECS)
/* all good, "modern" kernel before v4.18 */
#elif defined(COMPAT_HAVE_BIOSET_CREATE_FRONT_PAD)
# define bioset_create(pool_size, front_pad, flags) bioset_create(pool_size, front_pad)
#elif defined(COMPAT_HAVE_BIOSET_INIT)
/* => v4.18*/
#else
# error "bsr compat layer broken"
#endif
#endif

#if !(defined(COMPAT_HAVE_RB_AUGMENT_FUNCTIONS) && \
      defined(AUGMENTED_RBTREE_SYMBOLS_EXPORTED))

/*
 * Make sure the replacements for the augmented rbtree helper functions do not
 * clash with functions the kernel implements but does not export.
 */
#define rb_augment_f bsr_rb_augment_f
#define rb_augment_path bsr_rb_augment_path
#define rb_augment_insert bsr_rb_augment_insert
#define rb_augment_erase_begin bsr_rb_augment_erase_begin
#define rb_augment_erase_end bsr_rb_augment_erase_end

typedef void (*rb_augment_f)(struct rb_node *node, void *data);

static inline void rb_augment_path(struct rb_node *node, rb_augment_f func, void *data)
{
	struct rb_node *parent;

up:
	func(node, data);
	parent = rb_parent(node);
	if (!parent)
		return;

	if (node == parent->rb_left && parent->rb_right)
		func(parent->rb_right, data);
	else if (parent->rb_left)
		func(parent->rb_left, data);

	node = parent;
	goto up;
}

/*
 * after inserting @node into the tree, update the tree to account for
 * both the new entry and any damage done by rebalance
 */
static inline void rb_augment_insert(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node->rb_left)
		node = node->rb_left;
	else if (node->rb_right)
		node = node->rb_right;

	rb_augment_path(node, func, data);
}

/*
 * before removing the node, find the deepest node on the rebalance path
 * that will still be there after @node gets removed
 */
static inline struct rb_node *rb_augment_erase_begin(struct rb_node *node)
{
	struct rb_node *deepest;

	if (!node->rb_right && !node->rb_left)
		deepest = rb_parent(node);
	else if (!node->rb_right)
		deepest = node->rb_left;
	else if (!node->rb_left)
		deepest = node->rb_right;
	else {
		deepest = rb_next(node);
		if (deepest->rb_right)
			deepest = deepest->rb_right;
		else if (rb_parent(deepest) != node)
			deepest = rb_parent(deepest);
	}

	return deepest;
}

/*
 * after removal, update the tree to account for the removed entry
 * and any rebalance damage.
 */
static inline void rb_augment_erase_end(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node)
		rb_augment_path(node, func, data);
}
#endif

/*
 * In commit c4945b9e (v2.6.39-rc1), the little-endian bit operations have been
 * renamed to be less weird.
 */
#ifndef COMPAT_HAVE_FIND_NEXT_ZERO_BIT_LE
#define find_next_zero_bit_le(addr, size, offset) \
	generic_find_next_zero_le_bit(addr, size, offset)
#define find_next_bit_le(addr, size, offset) \
	generic_find_next_le_bit(addr, size, offset)
#define test_bit_le(nr, addr) \
	generic_test_le_bit(nr, addr)
#define __test_and_set_bit_le(nr, addr) \
	generic___test_and_set_le_bit(nr, addr)
#define __test_and_clear_bit_le(nr, addr) \
	generic___test_and_clear_le_bit(nr, addr)
#endif

#ifndef IDR_GET_NEXT_EXPORTED
/* Body in compat/idr.c */
extern void *idr_get_next(struct idr *idp, int *nextidp);
#endif

#ifndef RCU_INITIALIZER
#define RCU_INITIALIZER(v) (typeof(*(v)) *)(v)
#endif
#ifndef RCU_INIT_POINTER
#define RCU_INIT_POINTER(p, v) \
	do { \
		p = RCU_INITIALIZER(v); \
    	} while (0)
#endif

/* #ifndef COMPAT_HAVE_LIST_ENTRY_RCU */
#ifndef list_entry_rcu
#ifndef rcu_dereference_raw
/* see c26d34a rcu: Add lockdep-enabled variants of rcu_dereference() */
#define rcu_dereference_raw(p) rcu_dereference(p)
#endif
#ifdef _LIN
#define list_entry_rcu(ptr, type, member) \
	({typeof (*ptr) *__ptr = (typeof (*ptr) __force *)ptr; \
	 container_of((typeof(ptr))rcu_dereference_raw(__ptr), type, member); \
	})
#else
#define list_entry_rcu(ptr, type, member)   \
	 container_of((type *)rcu_dereference_raw(ptr), type, member)
#endif
#endif

#ifndef list_next_entry
/* introduced in 008208c (v3.13-rc1) */
#define list_next_entry_ex(type, pos, member) \
        list_entry((pos)->member.next, type, member)
#else
#define list_next_entry_ex(type, pos, member) \
		list_next_entry(pos, member)
#endif

/* for linux */
#ifndef list_for_each_entry_ex
#define list_for_each_entry_ex(type, pos, head, member) \
		list_for_each_entry(pos, head, member)
#endif
#ifndef list_for_each_entry_rcu_ex
#define list_for_each_entry_rcu_ex(type, pos, head, member) \
		list_for_each_entry_rcu(pos, head, member)
#endif
#ifndef list_for_each_entry_reverse_ex
#define list_for_each_entry_reverse_ex(type, pos, head, member) \
		list_for_each_entry_reverse(pos, head, member)
#endif
#ifndef list_prepare_entry_ex
#define list_prepare_entry_ex(type, pos, head, member) \
		list_prepare_entry(pos, head, member)
#endif
#ifndef list_for_each_entry_continue_ex
#define list_for_each_entry_continue_ex(type, pos, head, member) \
		list_for_each_entry_continue(pos, head, member)
#endif
#ifndef list_for_each_entry_safe_ex
#define list_for_each_entry_safe_ex(type, pos, n, head, member) \
		list_for_each_entry_safe(pos, n, head, member)
#endif

/*
 * Introduced in 930631ed (v2.6.19-rc1).
 */
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

/*
 * IS_ALIGNED() was added to <linux/kernel.h> in mainline commit 0c0e6195 (and
 * improved in f10db627); 2.6.24-rc1.
 */
#ifndef IS_ALIGNED
#ifdef _LIN
#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a) - 1)) == 0)
#else
#define IS_ALIGNED(x, a) (((x) & ((a) - 1)) == 0)
#endif
#endif

/*
 * NLA_TYPE_MASK and nla_type() were added to <linux/netlink.h> in mainline
 * commit 8f4c1f9b; v2.6.24-rc1.  Before that, none of the nlattr->nla_type
 * flags had a special meaning.
 */

#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK ~0

static inline int nla_type(const struct nlattr *nla)
{
#ifdef _LIN
	return nla->nla_type & NLA_TYPE_MASK;
#endif
}

#endif

/*
 * v4.12 fceb6435e852 netlink: pass extended ACK struct to parsing functions
 * and some preparation commits introduce a new "netlink extended ack" error
 * reporting mechanism. For now, only work around that here.  As trigger, use
 * NETLINK_MAX_COOKIE_LEN introduced somewhere in the middle of that patchset.
 */
#ifndef NETLINK_MAX_COOKIE_LEN
#ifdef _LIN
#include <net/netlink.h>
#endif
#define nla_parse_nested(tb, maxtype, nla, policy, extack) \
       nla_parse_nested(tb, maxtype, nla, policy)
#endif


/*
 * nlmsg_hdr was added to <linux/netlink.h> in mainline commit b529ccf2
 * (v2.6.22-rc1).
 */

#ifndef COMPAT_HAVE_NLMSG_HDR
static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
	return (struct nlmsghdr *)skb->data;
}
#endif

/*
 * genlmsg_reply() was added to <net/genetlink.h> in mainline commit 81878d27
 * (v2.6.20-rc2).
 */

#ifndef COMPAT_HAVE_GENLMSG_REPLY
#ifdef _LIN
#include <net/genetlink.h>
#endif

static inline int genlmsg_reply(struct sk_buff *skb, struct genl_info *info)
{
#ifdef _LIN
	return genlmsg_unicast(skb, info->snd_pid);
#else
	return genlmsg_unicast(skb, info);
#endif
}
#endif

/*
 * genlmsg_msg_size() and genlmsg_total_size() were added to <net/genetlink.h>
 * in mainline commit 17db952c (v2.6.19-rc1).
 */

#ifndef COMPAT_HAVE_GENLMSG_MSG_SIZE
#ifdef _LIN
#include <linux/netlink.h>
#include <linux/genetlink.h>

static inline int genlmsg_msg_size(int payload)
{
	return GENL_HDRLEN + payload;
}

static inline int genlmsg_total_size(int payload)
{
	return NLMSG_ALIGN(genlmsg_msg_size(payload));
}
#endif
#endif

/*
 * genlmsg_new() was added to <net/genetlink.h> in mainline commit 3dabc715
 * (v2.6.20-rc2).
 */

#ifndef COMPAT_HAVE_GENLMSG_NEW
#ifdef _WIN
extern struct sk_buff *genlmsg_new(size_t payload, gfp_t flags);
#else // _LIN
#include <net/genetlink.h>

static inline struct sk_buff *genlmsg_new(size_t payload, gfp_t flags)
{
	return nlmsg_new(genlmsg_total_size(payload), flags);
}
#endif
#endif


/*
 * genlmsg_put() was introduced in mainline commit 482a8524 (v2.6.15-rc1) and
 * changed in 17c157c8 (v2.6.20-rc2).  genlmsg_put_reply() was introduced in
 * 17c157c8.  We replace the compat_genlmsg_put() from 482a8524.
 */
#ifdef _WIN

extern void *compat_genlmsg_put(struct sk_buff *skb, u32 pid, u32 seq,
		           struct genl_family *family, int flags, u8 cmd);
#define genlmsg_put compat_genlmsg_put

extern void *genlmsg_put_reply(struct sk_buff *skb,
                         struct genl_info *info,
                         struct genl_family *family,
                         int flags, u8 cmd);
#else // _LIN
#ifndef COMPAT_HAVE_GENLMSG_PUT_REPLY
#include <net/genetlink.h>

static inline void *compat_genlmsg_put(struct sk_buff *skb, u32 pid, u32 seq,
				       struct genl_family *family, int flags,
				       u8 cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *hdr;

	nlh = nlmsg_put(skb, pid, seq, family->id, GENL_HDRLEN +
			family->hdrsize, flags);
	if (nlh == NULL)
		return NULL;

	hdr = nlmsg_data(nlh);
	hdr->cmd = cmd;
	hdr->version = family->version;
	hdr->reserved = 0;

	return (char *) hdr + GENL_HDRLEN;
}

#define genlmsg_put compat_genlmsg_put

static inline void *genlmsg_put_reply(struct sk_buff *skb,
                                      struct genl_info *info,
                                      struct genl_family *family,
                                      int flags, u8 cmd)
{
	return genlmsg_put(skb, info->snd_pid, info->snd_seq, family,
			   flags, cmd);
}
#endif
#endif

/*
 * compat_genlmsg_multicast() got a gfp_t parameter in mainline commit d387f6ad
 * (v2.6.19-rc1).
 */

#ifdef COMPAT_NEED_GENLMSG_MULTICAST_WRAPPER
#ifdef _LIN
#include <net/genetlink.h>
#endif
static inline int compat_genlmsg_multicast(struct sk_buff *skb, u32 pid,
					   unsigned int group, gfp_t flags)
{
	return genlmsg_multicast(skb, pid, group);
}

#define genlmsg_multicast compat_genlmsg_multicast

#endif

/*
 * Dynamic generic netlink multicast groups were introduced in mainline commit
 * 2dbba6f7 (v2.6.23-rc1).  Before that, netlink had a fixed number of 32
 * multicast groups.  Use an arbitrary hard-coded group number for that case.
 */

#ifndef COMPAT_HAVE_CTRL_ATTR_MCAST_GROUPS

struct genl_multicast_group {
	struct genl_family	*family;	/* private */
        struct list_head	list;		/* private */
        char			name[GENL_NAMSIZ];
	u32			id;
};

static inline int genl_register_mc_group(struct genl_family *family,
					 struct genl_multicast_group *grp)
{
	UNREFERENCED_PARAMETER(family);
	UNREFERENCED_PARAMETER(grp);

	grp->id = 1;
	return 0;
}

static inline void genl_unregister_mc_group(struct genl_family *family,
					    struct genl_multicast_group *grp)
{
	UNREFERENCED_PARAMETER(family);
	UNREFERENCED_PARAMETER(grp);
}

#endif

/*
 * kref_sub() was introduced in mainline commit ecf7ace9 (v2.6.38-rc1).
 */
#ifndef COMPAT_HAVE_KREF_SUB
static inline void kref_sub(struct kref *kref, unsigned int count,
			    void (*release) (struct kref *kref))
{
	while (count--)
		kref_put(kref, release);
}
#endif

/*
 * list_for_each_entry_continue_rcu() was introduced in mainline commit
 * 254245d2 (v2.6.33-rc1).
 */
#ifndef list_for_each_entry_continue_rcu
#define list_for_each_entry_continue_rcu_ex(type, pos, head, member)             \
	for (pos = list_entry_rcu(pos->member.next, type, member); \
	     &pos->member != (head);    \
	     pos = list_entry_rcu(pos->member.next, type, member))
#else
#define list_for_each_entry_continue_rcu_ex(type, pos, head, member)             \
		list_for_each_entry_continue_rcu(pos, head, member) 
#endif

#ifndef COMPAT_HAVE_IS_ERR_OR_NULL
#ifdef _LIN
static inline long __must_check IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}
#endif
#endif

#ifndef SK_CAN_REUSE
/* This constant was introduced by Pavel Emelyanov <xemul@parallels.com> on
   Thu Apr 19 03:39:36 2012 +0000. Before the release of linux-3.5
   commit 4a17fd52 sock: Introduce named constants for sk_reuse */
#define SK_CAN_REUSE   1
#endif

#ifndef COMPAT_HAVE_KREF_GET_UNLESS_ZERO
#ifdef _LIN
static inline int __must_check kref_get_unless_zero(struct kref *kref)
{
	return atomic_add_unless(&kref->refcount, 1, 0);
}
#else
static __inline int kref_get_unless_zero(struct kref *kref)
{
	// BSR-37
	if (atomic_read(&kref->refcount)) {
		atomic_add(1, &kref->refcount);
		return 1;
	}

    return 0;
}
#endif
#endif

#ifdef COMPAT_KMAP_ATOMIC_PAGE_ONLY
/* see 980c19e3
 * highmem: mark k[un]map_atomic() with two arguments as deprecated */
#define bsr_kmap_atomic(page, km)	kmap_atomic(page)
#define bsr_kunmap_atomic(addr, km)	kunmap_atomic(addr)
#else

#ifdef _LIN
#define bsr_kmap_atomic(page, km)	kmap_atomic(page, km)
#define bsr_kunmap_atomic(addr, km)	kunmap_atomic(addr, km)
#else
#define bsr_kmap_atomic(page, km)	(page->addr)
#define bsr_kunmap_atomic(addr, km)	(addr)
#define kunmap_atomic(page)	(page->addr)	
#define kmap(page)	(page->addr)	
#define kunmap(page)	(page->addr)	
#endif

#endif

#ifdef _LIN
#if !defined(for_each_set_bit) && defined(for_each_bit)
#define for_each_set_bit(bit, addr, size) for_each_bit(bit, addr, size)
#endif
#endif

#ifndef COMPAT_HAVE_THREE_PARAMATER_HLIST_FOR_EACH_ENTRY
#undef hlist_for_each_entry_ex
#define hlist_for_each_entry_ex(type, pos, head, member)				\
	for (pos = hlist_entry((head)->first, type, member);	\
	     pos;							\
	     pos = hlist_entry((pos)->member.next, type, member))
#else
#define hlist_for_each_entry_ex(type, pos, head, member)				\
		hlist_for_each_entry(pos, head, member)
#endif

#ifndef COMPAT_HAVE_PRANDOM_U32
#ifdef _WIN
static int random32()
{
    int buf;
    get_random_bytes(&buf, 4);
    return buf;
}
#endif
static inline u32 prandom_u32(void)
{
// BSR-1360
#ifdef COMPAT_HAVE_GET_RANDOM_U32
	return get_random_u32();
#else
    return random32();
#endif
}
#endif

#ifdef COMPAT_HAVE_NETLINK_CB_PORTID
#define NETLINK_CB_PORTID(skb) NETLINK_CB(skb).portid
#else
#ifdef _WIN
#define NETLINK_CB_PORTID(skb) ((struct netlink_callback *)((void *)&skb))->nlh->nlmsg_pid
#else // _LIN
#define NETLINK_CB_PORTID(skb) NETLINK_CB(skb).pid
#endif
#endif

#ifndef COMPAT_HAVE_PROC_PDE_DATA
#define PDE_DATA(inode) PDE(inode)->data
#endif

#ifndef list_first_entry
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#endif

#ifndef list_first_entry_or_null
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#endif

#ifndef COMPAT_HAVE_IDR_ALLOC
static inline int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask)
{
	int rv, got;

	if (!idr_pre_get(idr, gfp_mask))
		return -ENOMEM;
	rv = idr_get_new_above(idr, ptr, start, &got);
	if (rv < 0)
		return rv;

	if (got >= end) {
		idr_remove(idr, got);
		return -ENOSPC;
	}

	return got;
}
#endif
#ifdef _LIN
#ifndef BLKDEV_ISSUE_ZEROOUT_EXPORTED
/* Was introduced with 2.6.34 */
extern int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
				sector_t nr_sects, gfp_t gfp_mask);
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, flags /* = NOUNMAP */) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP)
#else
/* synopsis changed a few times, though */
#if  defined(BLKDEV_ZERO_NOUNMAP)
/* >= v4.12 */
/* use blkdev_issue_zeroout() as written out in the actual source code.
 * right now, we only use it with flags = BLKDEV_ZERO_NOUNMAP */
#elif  defined(COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD)
/* no BLKDEV_ZERO_NOUNMAP as last parameter, but a bool discard instead */
/* still need to define BLKDEV_ZERO_NOUNMAP, to compare against 0 */
#define BLKDEV_ZERO_NOUNMAP 1
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, flags /* = NOUNMAP */) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP, (flags) == 0 /* bool discard */)
#else /* !defined(COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD) */
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, discard) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP)
#endif
#endif
#endif

// BSR-1521
#if 0
#ifndef COMPAT_HAVE_GENL_LOCK
static inline void genl_lock(void)  { }
static inline void genl_unlock(void)  { }
#endif
#endif

#if !defined(QUEUE_FLAG_DISCARD) || !defined(QUEUE_FLAG_SECDISCARD)
#ifdef _WIN
# define queue_flag_set_unlocked(F, Q)				\
    do {							\
        if ((F) != -1)					\
            __set_bit(F, Q);		\
    } while(0)

# define queue_flag_clear_unlocked(F, Q)			\
    do {							\
        if ((F) != -1)					\
            clear_bit(F, Q);	\
    } while (0)
#else // _LIN
# define queue_flag_set_unlocked(F, Q)				\
	({							\
		if ((F) != -1)					\
			queue_flag_set_unlocked(F, Q);		\
	})

# define queue_flag_clear_unlocked(F, Q)			\
	({							\
		if ((F) != -1)					\
			queue_flag_clear_unlocked(F, Q);	\
	})
#endif

# ifndef blk_queue_secdiscard
#  define blk_queue_secdiscard(q)   (false,false)
#  define QUEUE_FLAG_SECDISCARD    (-1)
# endif
#endif

#ifndef COMPAT_HAVE_BLK_SET_STACKING_LIMITS
static inline void blk_set_stacking_limits(struct queue_limits *lim)
{
	UNREFERENCED_PARAMETER(lim);

# ifdef COMPAT_QUEUE_LIMITS_HAS_DISCARD_ZEROES_DATA
	lim->discard_zeroes_data = 1;
# endif
}
#endif

#ifdef COMPAT_HAVE_STRUCT_BVEC_ITER
/* since Linux 3.14 we have a new way to iterate a bio
   Mainline commits:
   7988613b0 block: Convert bio_for_each_segment() to bvec_iter
   4f024f379 block: Abstract out bvec iterator
 */
#define BSR_BIO_VEC_TYPE struct bio_vec
#define BSR_ITER_TYPE struct bvec_iter
#define BVD .
#define BSR_BIO_BI_SECTOR(BIO) ((BIO)->bi_iter.bi_sector)
#define BSR_BIO_BI_SIZE(BIO) ((BIO)->bi_iter.bi_size)
#else
#define BSR_BIO_VEC_TYPE struct bio_vec *
#define BSR_ITER_TYPE int
#define BVD ->
#define BSR_BIO_BI_SECTOR(BIO) ((BIO)->bi_sector)
#define BSR_BIO_BI_SIZE(BIO) ((BIO)->bi_size)

/* Attention: The backward comp version of this macro accesses bio from
   calling namespace */
#define bio_iter_last(BVEC, ITER) ((ITER) == bio->bi_vcnt - 1)
#endif

#ifndef COMPAT_HAVE_RCU_DEREFERENCE_PROTECTED
#define rcu_dereference_protected(p, c) (p)
#endif

#ifdef _LIN
#ifndef COMPAT_HAVE_F_PATH_DENTRY
#error "won't compile with this kernel version (f_path.dentry vs f_dentry)"
/* change all occurences of f_path.dentry to f_dentry, and conditionally
 * #define f_dentry to f_path.dentry */
#endif
#endif

#ifndef list_next_rcu
#define list_next_rcu(list)	(*((struct list_head **)(&(list)->next)))
#endif

#ifndef list_first_or_null_rcu
#ifdef _WIN
#define list_first_or_null_rcu_ex(conn, ptr, type, member) \
    do {    \
        struct list_head *__ptr = (ptr);    \
        struct list_head *__next = (__ptr->next);    \
        if (likely(__ptr != __next))    \
            conn = list_entry_rcu(__next, type, member);   \
        else   \
           conn = NULL;    \
	    } while(false)
#else // _LIN
#define list_first_or_null_rcu_ex(conn, ptr, type, member) \
({ \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = ACCESS_ONCE(__ptr->next); \
	conn = likely(__ptr != __next) ? list_entry_rcu(__next, type, member) : NULL; \
})
#endif
#else
#define list_first_or_null_rcu_ex(conn, ptr, type, member) \
		conn = list_first_or_null_rcu(ptr, type, member)
#endif



typedef struct hd_struct  hd_struct;

#if defined(COMPAT_HAVE_BIO_START_IO_ACCT)
	/* good, newest version */
#else
#ifdef COMPAT_HAVE_GENERIC_START_IO_ACCT
#define generic_start_io_acct(Q, RW, S, P)  (void) Q; generic_start_io_acct(RW, S, P)
#define generic_end_io_acct(Q, RW, P, J)  (void) Q; generic_end_io_acct(RW, P, J)
#elif !defined(COMPAT_HAVE_GENERIC_START_IO_ACCT_W_QUEUE)
static inline void generic_start_io_acct(struct request_queue *q, int rw, unsigned long sectors,
					 struct hd_struct *part)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(sectors);
	UNREFERENCED_PARAMETER(rw);
	UNREFERENCED_PARAMETER(part);
	// DbgPrint("generic_start_io_acct\n");
#else // _LIN
	int cpu;
	BUILD_BUG_ON(sizeof(atomic_t) != sizeof(part->in_flight[0]));

	(void)q; /* no warning about unused variable */
	cpu = part_stat_lock();
	part_round_stats(cpu, part);
	part_stat_inc(cpu, part, ios[rw]);
	part_stat_add(cpu, part, sectors[rw], sectors);
	(void) cpu; /* The macro invocations above want the cpu argument, I do not like
				the compiler warning about cpu only assigned but never used... */
	/* part_inc_in_flight(part, rw); */
	atomic_inc((atomic_t*)&part->in_flight[rw]);
	part_stat_unlock();
#endif
}

static inline void generic_end_io_acct(struct request_queue *q, int rw, struct hd_struct *part,
				  ULONG_PTR start_time)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(start_time);
	UNREFERENCED_PARAMETER(rw);
	UNREFERENCED_PARAMETER(part);
	// DbgPrint("generic_end_io_acct\n");
#else // _LIN
	unsigned long duration = jiffies - start_time;
	int cpu;

	(void)q; /* no warning about unused variable */
	cpu = part_stat_lock();
	part_stat_add(cpu, part, ticks[rw], duration);
	part_round_stats(cpu, part);
	/* part_dec_in_flight(part, rw); */
	atomic_dec((atomic_t*)&part->in_flight[rw]);
	part_stat_unlock();
#endif
}
#endif /* COMPAT_HAVE_GENERIC_START_IO_ACCT */
#endif /* !COMPAT_HAVE_BIO_START_IO_ACCT */

#ifndef COMPAT_SOCK_CREATE_KERN_HAS_FIVE_PARAMETERS
#define sock_create_kern(N,F,T,P,S) sock_create_kern(F,T,P,S)
#endif

#ifndef COMPAT_HAVE_WB_CONGESTED_ENUM
#define WB_async_congested BDI_async_congested
#define WB_sync_congested BDI_sync_congested
#endif

#ifdef _LIN
#ifndef COMPAT_HAVE_SIMPLE_POSITIVE
#include <linux/dcache.h>
static inline int simple_positive(struct dentry *dentry)
{
        return dentry->d_inode && !d_unhashed(dentry);
}
#endif
#endif

#ifdef COMPAT___VMALLOC_HAS_2_PARAMS
	#define __vmalloc_wapper(s, g, p) __vmalloc(s, g)
#else 
	#define __vmalloc_wapper(s, g, p) __vmalloc(s, g, p)
#endif


#ifdef _LIN
// BSR-453
static inline void *bsr_kvmalloc(size_t size, gfp_t flags)
{
	void *ret;

	ret = kmalloc(size, flags | __GFP_NOWARN);
	if (!ret) {
		// BSR-818 check interrupt context
		if (in_interrupt())
			return NULL;
		ret = __vmalloc_wapper(size, flags, PAGE_KERNEL);

		if (ret)
			atomic_add64(size, &mem_usage.vmalloc);
	}
	else {
		atomic_add64(ksize(ret), &mem_usage.kmalloc);
	}
	return ret;
}
#endif

#ifndef COMPAT_HAVE_IS_VMALLOC_ADDR
static inline int is_vmalloc_addr(const void *x)
{
#ifdef CONFIG_MMU
	unsigned long addr = (unsigned long)x;
	return addr >= VMALLOC_START && addr < VMALLOC_END;
#else
	return 0;
#endif
}
#endif

#ifndef COMPAT_HAVE_KVFREE
#ifdef _LIN
#include <linux/mm.h>
static inline void kvfree(void /* intentionally discarded const */ *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		bsr_kfree(addr);
}
#endif
#endif


#ifdef _LIN
#ifdef blk_queue_plugged
/* pre 7eaceac block: remove per-queue plugging
 * Code has been converted over to the new explicit on-stack plugging ...
 *
 * provide dummy struct blk_plug and blk_start_plug/blk_finish_plug,
 * so the main code won't be cluttered with ifdef.
 */
struct blk_plug { };
#if 0
static void blk_start_plug(struct blk_plug *plug) {};
static void blk_finish_plug(struct blk_plug *plug) {};
#else
#define blk_start_plug(plug) do { (void)plug; } while (0)
#define blk_finish_plug(plug) do { } while (0)
#endif
#endif
#endif

#ifndef COMPAT_HAVE_ATOMIC_DEC_IF_POSITIVE
static inline int atomic_dec_if_positive(atomic_t *v)
{
        int c, old, dec;
        c = atomic_read(v);
        for (;;) {
                dec = c - 1;
                if (unlikely(dec < 0))
                        break;
                old = atomic_cmpxchg((v), c, dec);
                if (likely(old == c))
                        break;
                c = old;
        }
        return dec;
}
#endif

#ifndef COMPAT_HAVE_IDR_IS_EMPTY
static int idr_has_entry(int id, void *p, void *data)
{
	UNREFERENCED_PARAMETER(id);
	UNREFERENCED_PARAMETER(p);
	UNREFERENCED_PARAMETER(data);
	return 1;
}

static inline bool idr_is_empty(struct idr *idr)
{
	return !idr_for_each(idr, idr_has_entry, NULL);
}
#endif

#ifdef _LIN
#ifndef COMPAT_HAVE_IB_CQ_INIT_ATTR
#include <rdma/ib_verbs.h>

struct ib_cq_init_attr {
	unsigned int    cqe;
	int             comp_vector;
	u32             flags;
};

static inline struct ib_cq *
bsr_ib_create_cq(struct ib_device *device,
		  ib_comp_handler comp_handler,
		  void (*event_handler)(struct ib_event *, void *),
		  void *cq_context,
		  const struct ib_cq_init_attr *cq_attr)
{
	return ib_create_cq(device, comp_handler, event_handler, cq_context,
			    cq_attr->cqe, cq_attr->comp_vector);
}

#define ib_create_cq(DEV, COMP_H, EVENT_H, CTX, ATTR) \
	bsr_ib_create_cq(DEV, COMP_H, EVENT_H, CTX, ATTR)
#endif
#endif

#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif

#if defined(_WIN) || defined(COMPAT_HAVE_BIO_BI_BDEV)
#if !defined(bio_set_dev) && !defined(COMPAT_HAVE_BIO_SET_DEV)
#define bio_set_dev(bio, bdev) (bio)->bi_bdev = bdev
#endif
#endif

#ifdef COMPAT_HAVE_TIMER_SETUP
/* starting with v4.16 new timer interface*/
#define BSR_TIMER_FN_ARG struct timer_list *t
#define BSR_TIMER_ARG2OBJ(OBJ, MEMBER) from_timer(OBJ, t, MEMBER)
#define bsr_timer_setup(OBJ, MEMBER, TIMER_FN) timer_setup(&OBJ->MEMBER, TIMER_FN, 0)
#define BSR_TIMER_CALL_ARG(OBJ, MEMBER) &OBJ->MEMBER
#else
/* timer interface before v4.16 */
#define BSR_TIMER_FN_ARG unsigned long data
#define BSR_TIMER_ARG2OBJ(OBJ, MEMBER) (typeof(OBJ)) data
#define bsr_timer_setup(OBJ, MEMBER, TIMER_FN) setup_timer(&OBJ->MEMBER, TIMER_FN, (TIMER_DATA_TYPE)OBJ)
#define BSR_TIMER_CALL_ARG(OBJ, MEMBER) (unsigned long) OBJ
#endif

#ifndef COMPAT_HAVE_BIOSET_INIT
#ifndef COMPAT_HAVE_BIO_CLONE_FAST
# define bio_clone_fast(bio, gfp, bio_set) bio_clone(bio, gfp)
#else
# define bio_clone_fast(BIO, GFP, P) bio_clone_fast(BIO, GFP, *P)
#endif

#define BSR_BIO_SET   bio_set *

#ifdef _LIN
#define bio_alloc_bioset(GFP, n, P) bio_alloc_bioset(GFP, n, *P)
static inline void bioset_exit(struct bio_set **bs)
{
	if (*bs) {
		bioset_free(*bs);
		*bs = NULL;
	}
}
#if defined(COMPAT_HAVE_BIOSET_NEED_BVECS)
#define bioset_init(BS, S, FP, F) __bioset_init(BS, S, FP, F)
#else
#define bioset_init(BS, S, FP, F) __bioset_init(BS, S, FP, 0)
#endif
static inline int
__bioset_init(struct bio_set **bs, unsigned int size, unsigned int front_pad, int flags)
{
	*bs = bioset_create(size, front_pad, flags);
	return *bs == NULL ? -ENOMEM : 0;
}

static inline bool
bioset_initialized(struct bio_set **bs)
{
	return *bs != NULL;
}
#endif
#else
#define BSR_BIO_SET   bio_set
#endif


#ifdef _LIN
#ifdef COMPAT_NEED_D_INODE
static inline struct inode *d_inode(struct dentry *dentry)
{
	return dentry->d_inode;
}
#endif

#ifdef COMPAT_HAVE_INODE_LOCK
#define bsr_inode_lock(i)					inode_lock(i)
#define bsr_inode_unlock(i)					inode_unlock(i)
#define bsr_inode_lock_nested(i, subclass)	inode_lock_nested(i, subclass)
#define bsr_inode_trylock(i)				inode_trylock(i)
#else
#define bsr_inode_lock(i)					mutex_lock(&(i)->i_mutex)
#define bsr_inode_unlock(i)					mutex_unlock(&(i)->i_mutex)
#define bsr_inode_lock_nested(i, subclass)	mutex_lock_nested(&(i)->i_mutex, subclass)
#define bsr_inode_trylock(i)				mutex_trylock(&(i)->i_mutex)
#endif


#if !(defined(COMPAT_HAVE_SHASH_DESC_ON_STACK) &&    \
      defined(COMPAT_HAVE_SHASH_DESC_ZERO))
#include <crypto/hash.h>

#ifndef COMPAT_HAVE_SHASH_DESC_ON_STACK
#define SHASH_DESC_ON_STACK(shash, ctx)                  \
    char __##shash##_desc[sizeof(struct shash_desc) +      \
        crypto_shash_descsize(ctx)] CRYPTO_MINALIGN_ATTR; \
    struct shash_desc *shash = (struct shash_desc *)__##shash##_desc
#endif

#ifndef COMPAT_HAVE_SHASH_DESC_ZERO
#ifndef barrier_data
#define barrier_data(ptr) barrier()
#endif

static inline void shash_desc_zero(struct shash_desc *desc)
{
	/* memzero_explicit(...) */
	memset(desc, 0, sizeof(*desc) + crypto_shash_descsize(desc->tfm));
	barrier_data(desc);
}
#endif
#endif
#endif // end _LIN

#ifdef _LIN
static inline ssize_t bsr_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	return kernel_read(file, buf, count, pos);
#else
	return vfs_read(file, buf, count, pos);
#endif
}

static inline ssize_t bsr_write(struct file *file, void *buf, size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	return kernel_write(file, buf, count, pos);
#else
	return vfs_write(file, buf, count, pos);
#endif
}

// BSR-597
static inline int bsr_unlink(struct inode *dir, struct dentry *dentry)
{
#if defined(COMPAT_VFS_UNLINK_HAS_NS_PARAMS)
		return vfs_unlink(&init_user_ns, dir, dentry, NULL);
// BSR-1360
#elif defined(COMPAT_VFS_UNLINK_HAS_IDMAP_PARAMS)
		return vfs_unlink(&nop_mnt_idmap, dir, dentry, NULL);
#elif defined(COMPAT_VFS_UNLINK_HAS_2_PARAMS)
		return vfs_unlink(dir, dentry);
#else
		return vfs_unlink(dir, dentry, NULL);
#endif
}

//BSR-597
static inline int bsr_rename(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry, struct vfsmount *old_mnt, struct vfsmount *new_mnt)
{
#if defined(COMPAT_HAVE_STRUCT_RENAMEDATA)
	struct inode *delegated_inode = NULL;

	struct renamedata rd = {
			.old_dir	= old_dir,
			.old_dentry	= old_dentry,
			// BSR-1360
#ifdef COMPAT_HAVE_STRUCT_RENAMEDATA_USED_MNT_PARAMS
			.old_mnt_userns  = mnt_user_ns(old_mnt),
#else
			.old_mnt_idmap = old_mnt->mnt_idmap,
#endif
			.new_dir	= new_dir,
			.new_dentry	= new_dentry,
#ifdef COMPAT_HAVE_STRUCT_RENAMEDATA_USED_MNT_PARAMS
			.new_mnt_userns  = mnt_user_ns(new_mnt),
#else
			.new_mnt_idmap = new_mnt->mnt_idmap,
#endif
			.delegated_inode = &delegated_inode,
	};
	return vfs_rename(&rd);
#elif defined(COMPAT_VFS_RENAME_HAS_4_PARAMS)
	return vfs_rename(old_dir, old_dentry,
	    new_dir, new_dentry);
#elif defined(COMPAT_VFS_RENAME_HAS_5_PARAMS)
	return vfs_rename(old_dir, old_dentry,
	    new_dir, new_dentry, NULL);
#else
	return vfs_rename(old_dir, old_dentry,
	    new_dir, new_dentry, NULL, 0);
#endif
}


#ifndef COMPAT_HAVE_TIME64_TO_TM
#ifndef time64_to_tm
#define time64_to_tm time_to_tm
#endif
#endif
#ifndef COMPAT_HAVE_KTIME_TO_TIMESPEC64
#ifndef ktime_to_timespec64
#define ktime_to_timespec64 ktime_to_timespec
#endif
#ifndef timespec64
#define timespec64 timespec
#endif
#endif

struct backup_file_list {
#ifdef COMPAT_HAVE_ITERATE_DIR
	struct dir_context ctx;
#endif
	struct list_head list;
	char *fileName;
};


#ifndef COMPAT_HAVE_SET_FS
#ifdef COMPAT_HAVE_FORCE_UACCESS
#define get_fs()	force_uaccess_begin()	
#define set_fs(fs)	force_uaccess_end(fs)
#else
typedef int mm_segment_t;
#define get_fs()	0	
#define set_fs(fs)	
#endif
#endif

#ifdef COMPAT_THAW_BDEV_HAS_1_PARAMS
#define thaw_bdev(bdev, sb)	thaw_bdev(bdev)
#endif

#ifndef COMPAT_HAVE_BIO_MAX_VECS
#define BIO_MAX_VECS BIO_MAX_PAGES
#endif

#ifdef COMPAT_LIST_SORT_USE_CONST_PTR
#define list_cmp_t const struct list_head
#else
#define list_cmp_t struct list_head
#endif
#endif

#endif
