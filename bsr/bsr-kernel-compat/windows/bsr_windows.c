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
#include <stdint.h>
#include <stdarg.h>
#include <intrin.h>
#include <ntifs.h>
#include "bsr_windows.h"
#include "wsk_wrapper.h"
#include "bsr_wingenl.h"
#include "idr.h"
#include "../bsr_wrappers.h"
#include "disp.h"
#include "proto.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, do_add_minor)
#endif

int g_bypass_level;
int g_read_filter;
int g_mj_flush_buffers_filter;
int g_use_volume_lock;
int g_netlink_tcp_port;
int g_daemon_tcp_port;
LARGE_INTEGER g_frequency = { .QuadPart = 0 };		// DW-1961

#ifdef _WIN_HANDLER_TIMEOUT
// BSR-1060
atomic_t g_handler_use;
atomic_t g_handler_timeout;
int g_handler_retry;
#endif

WCHAR g_ver[64];

#define MAX_IDR_SHIFT		(sizeof(int) * 8 - 1)
#define MAX_IDR_BIT		(1U << MAX_IDR_SHIFT)

/* Leave the possibility of an incomplete final layer */
#define MAX_IDR_LEVEL ((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)

/* Number of id_layer structs to leave in free list */
#define MAX_IDR_FREE (MAX_IDR_LEVEL * 2)

KSTART_ROUTINE run_singlethread_workqueue;
// BSR-109
#if 0
KSTART_ROUTINE adjust_changes_to_volume;
#endif
extern SIMULATION_DISK_IO_ERROR gSimulDiskIoError = {0,};

// DW-1105 monitoring mount change thread state (FALSE : not working, TRUE : working)
atomic_t g_monitor_mnt_working = FALSE;

extern struct mutex att_mod_mutex; 

//__ffs - find first bit in word.
ULONG_PTR __ffs(ULONG_PTR word) 
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

#define ffz(x)  __ffs(~(x))

int fls(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

#define BITOP_WORD(nr)          ((nr) / BITS_PER_LONG)

ULONG_PTR find_first_bit(const ULONG_PTR* addr, ULONG_PTR size)
{
	const ULONG_PTR* p = addr;
	ULONG_PTR result = 0;
	ULONG_PTR tmp;

	while (size & ~(BITS_PER_LONG - 1)) {
		tmp = *(p++);
		if (tmp)
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
#ifdef _WIN64
	tmp = (*p) & (UINT64_MAX >> (BITS_PER_LONG - size));
	if (tmp == UINT64_MAX)	{	/* Are any bits set? */
#else
	tmp = (*p) & (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)	{	/* Are any bits set? */
#endif
		return result + size;	/* Nope. */
	}
found:
	return result + __ffs(tmp);
}

ULONG_PTR find_next_bit(const ULONG_PTR *addr, ULONG_PTR size, ULONG_PTR offset)
{
	const ULONG_PTR *p = addr + BITOP_WORD(offset);
	ULONG_PTR result = offset & ~(BITS_PER_LONG - 1);
	ULONG_PTR tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
#ifdef _WIN64
		tmp &= (UINT64_MAX << offset);
#else
		tmp &= (~0UL << offset);
#endif
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG - 1)) {
		tmp = *(p++);
		if (tmp)
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
#ifdef _WIN64
	tmp &= (UINT64_MAX >> (BITS_PER_LONG - size));
	if (tmp == 0ULL)	/* Are any bits set? */
#else
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
#endif
		return result + size;	/* Nope. */
found_middle:
	return result + __ffs(tmp);
}

const char _zb_findmap [] = {
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,6,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,5,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,
    0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,7,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 8 };

static inline ULONG_PTR __ffz_word(ULONG_PTR nr, ULONG_PTR word)
 {
 #ifdef _WIN64
    if ((word & 0xffffffff) == 0xffffffff) {
            word >>= 32;
            nr += 32;
    }
 #endif
    if ((word & 0xffff) == 0xffff) {
            word >>= 16;
            nr += 16;
    }
    if ((word & 0xff) == 0xff) {
            word >>= 8;
            nr += 8;
    }
	return nr + _zb_findmap[(unsigned char) word];
 }
 /*
 * Find the first cleared bit in a memory region.
 */
ULONG_PTR find_first_zero_bit(const ULONG_PTR *addr, ULONG_PTR size)
 {
	const ULONG_PTR *p = addr;
	ULONG_PTR result = 0;
	ULONG_PTR tmp;

	 while (size & ~(BITS_PER_LONG - 1)) {
		 if (~(tmp = *(p++)))
			 goto found;
		 result += BITS_PER_LONG;
		 size -= BITS_PER_LONG;
	 }
	 if (!size)
		 return result;

#ifdef _WIN64
	 tmp = (*p) | (UINT64_MAX << size);
	 if (tmp == UINT64_MAX)        /* Are any bits zero? */
#else
	 tmp = (*p) | (~0UL << size);
	 if (tmp == ~0UL)        /* Are any bits zero? */
#endif
		 return result + size;        /* Nope. */
 found:
	 return result + ffz(tmp);
 }

ULONG_PTR find_next_zero_bit(const ULONG_PTR * addr, ULONG_PTR size, ULONG_PTR offset)
{
	const ULONG_PTR *p;
	ULONG_PTR bit, set;
 
    if (offset >= size)
        return size;
    bit = offset & (BITS_PER_LONG - 1);
    offset -= bit;
    size -= offset;
    p = addr + offset / BITS_PER_LONG;
    if (bit) {
        /*
        * __ffz_word returns BITS_PER_LONG
        * if no zero bit is present in the word.
        */
        set = __ffz_word(bit, *p >> bit);
        if (set >= size)
                return size + offset;
        if (set < BITS_PER_LONG)
                return set + offset;
        offset += BITS_PER_LONG;
        size -= BITS_PER_LONG;
        p++;
    }

    return offset + find_first_zero_bit(p, size);
 }

static int g_test_and_change_bit_flag = 0;
static spinlock_t g_test_and_change_bit_lock;

int test_and_change_bit(int nr, const ULONG_PTR *addr)
{
	ULONG_PTR mask = BIT_MASK(nr);
	ULONG_PTR *p = ((ULONG_PTR *) addr);
	ULONG_PTR old;

	if (!g_test_and_change_bit_flag) {
		spin_lock_init(&g_test_and_change_bit_lock);
		g_test_and_change_bit_flag = 1;
	}

	spin_lock_irq(&g_test_and_change_bit_lock);
	old = *p;
	*p = old ^ mask;
	spin_unlock_irq(&g_test_and_change_bit_lock);

    return (old & mask) != 0;
}

LONG_PTR xchg(LONG_PTR *target, LONG_PTR value)
{
#ifdef _WIN64
	return (InterlockedExchange64(target, value));
#else
	return (InterlockedExchange(target, value));
#endif
}


void atomic_set(atomic_t *v, int i)
{
	InterlockedExchange((long *)v, i);
}

void atomic_set64(atomic_t64* v, LONGLONG i)
{
	InterlockedExchange64((LONGLONG *)v, i);
}


void atomic_add(int i, atomic_t *v)
{
	InterlockedExchangeAdd((long *)v, i);
}

void atomic_add64(LONGLONG a, atomic_t64 *v)
{
	InterlockedExchangeAdd64((LONGLONG*)v, a);
}

void atomic_sub(int i, atomic_t *v)
{
	atomic_sub_return(i, v);
}

void atomic_sub64(LONGLONG a, atomic_t64 *v)
{
	atomic_sub_return64(a, v);
}

int atomic_sub_return(int i, atomic_t *v)
{
	int retval;
	retval = InterlockedExchangeAdd((LONG*)v, -i);
	retval -= i;
	return retval;
}

LONGLONG atomic_sub_return64(LONGLONG a, atomic_t64 *v)
{
	LONGLONG retval;
	retval = InterlockedExchangeAdd64((LONGLONG*)v, -a);
	retval -= a;
	return retval;
}

int atomic_dec_and_test(atomic_t *v)
{
	return (0 == InterlockedDecrement((LONG*)v));
}

int atomic_sub_and_test(int i, atomic_t *v)
{
	LONG_PTR retval;
	retval = InterlockedExchangeAdd((LONG*)v, -i);
	retval -= i;
	return (retval == 0);
}

int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return InterlockedCompareExchange((long *)v, new, old);
}


int atomic_xchg(atomic_t *v, int n)
{
	return InterlockedExchange((LONG*)v, n);
}

LONGLONG atomic_xchg64(atomic_t64 *v, LONGLONG n)
{
	return InterlockedExchange64((LONGLONG*)v, n);
}

int atomic_read(const atomic_t *v)
{
	return InterlockedAnd((LONG*)v, 0xffffffff);
}

LONGLONG atomic_read64(const atomic_t64 *v)
{
	return InterlockedAnd64((LONGLONG*)v, 0xffffffffffffffff);
}

void * kmalloc(int size, int flag, ULONG Tag)
{
	return kcalloc(size, 1, flag, Tag); // => adjust size, count parameter mismatch
}

void * kcalloc(int size, int count, int flag, ULONG Tag)
{
	UNREFERENCED_PARAMETER(flag); 

	return kzalloc(size * count, 0, Tag);
}

void * kzalloc(int size, int flag, ULONG Tag)
{
	UNREFERENCED_PARAMETER(flag); 

	void *mem;
    static int fail_count = 0;

	mem = ExAllocatePoolWithTag(NonPagedPool, size, Tag); 
	if (!mem) {
		return NULL;
	}

	RtlZeroMemory(mem, size);
	return mem;
}

char *kstrdup(const char *s, int gfp)
{
	size_t len;
	char *buf;

	if (!s)
		return NULL;

	len = strlen(s) + 1;
#ifdef _WIN64
	BUG_ON_INT32_OVER(len);
#endif
	buf = kzalloc((int)len, gfp, 'C3SB');
	if (buf)
		memcpy(buf, s, len);
	return buf;
}

void *page_address(const struct page *page)
{
	return page->addr;
}

struct page  *alloc_page(int flag)
{
	UNREFERENCED_PARAMETER(flag);

	struct page *p = kmalloc(sizeof(struct page),0, 'D3SB'); 
	if (!p)	{
		bsr_err(1, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate %d size memory for page", sizeof(struct page));
		return NULL;
	}	
	RtlZeroMemory(p, sizeof(struct page));
	
	p->addr = kzalloc(PAGE_SIZE, 0, 'E3SB');
	if (!p->addr)	{
		kfree(p); 
		bsr_err(2, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate %d size memory for page", PAGE_SIZE);
		return NULL;
	}
	RtlZeroMemory(p->addr, PAGE_SIZE);

	return p;
}

void __free_page(struct page *page)
{
	kfree(page->addr);
	kfree(page); 
}

void * kmem_cache_alloc(struct kmem_cache *cache, int flag, ULONG Tag)
{
	return kzalloc(cache->size, flag, Tag); 
}

void kmem_cache_free(struct kmem_cache *cache, void * x)
{
	UNREFERENCED_PARAMETER(cache);

	kfree(x);
}

void bsr_bp(char *msg)
{
    bsr_err(1, BSR_LC_ETC, NO_OBJECT,"breakpoint: msg(%s)", msg);
}

__inline void kfree(void * x)
{
	if (x) {
		ExFreePool(x);
	}
}

__inline void kvfree(void * x)
{
	if (x) {
		ExFreePool(x);
	}
}

mempool_t *mempool_create(int min_nr, void *alloc_fn, void *free_fn, void *pool_data)
{
	UNREFERENCED_PARAMETER(alloc_fn);
	UNREFERENCED_PARAMETER(min_nr);
	UNREFERENCED_PARAMETER(free_fn);

	mempool_t *p_pool;
	if (!pool_data) {
		return 0;
	}
	p_pool = kmalloc(sizeof(mempool_t), 0, 'F3SB');
	if (!p_pool) {
		return 0;
	}
	p_pool->p_cache = pool_data;
	p_pool->page_alloc = 0;
	return p_pool;
}

mempool_t *mempool_create_slab_pool(int size, ULONG tag)
{
	mempool_t *p_pool = kmalloc(sizeof(mempool_t), 0, tag);

	if (!p_pool) {
		return 0;
	}

	p_pool->page_alloc = 0;

	p_pool->p_cache = kmalloc(sizeof(struct kmem_cache), 0, tag);

	if (!p_pool->p_cache) {
		kfree(p_pool);
		return 0;
	}

	// BSR-247 set allocations and tags.
	p_pool->p_cache->size = size;
	p_pool->p_cache->tag = tag;

	return p_pool;
}

mempool_t *mempool_create_page_pool(int min_nr, int order)
{
	UNREFERENCED_PARAMETER(order);
	UNREFERENCED_PARAMETER(min_nr);

	mempool_t *p_pool = kmalloc(sizeof(mempool_t), 0, '04SB');
	if (!p_pool) {
		return 0;
	}
	p_pool->page_alloc = 1; 
	ExInitializeNPagedLookasideList(&p_pool->pageLS, NULL, NULL, 0, sizeof(struct page), 'B8SB', 0);
	ExInitializeNPagedLookasideList(&p_pool->page_addrLS, NULL, NULL, 0, PAGE_SIZE, 'C8SB', 0);
	
	return p_pool; 
}

void mempool_destroy_page_pool (mempool_t *p_pool)
{	
	if (p_pool) {
		if (p_pool->page_alloc) {
			ExDeleteNPagedLookasideList(&p_pool->page_addrLS);
			ExDeleteNPagedLookasideList(&p_pool->pageLS);
		}
		else {
			// BSR-247
			if (p_pool->p_cache)
				kfree(p_pool->p_cache); 
		}

		kfree(p_pool);
	}

	return;
}

void* mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	void* p = NULL;

	if (pool->page_alloc) {
		struct page* _page = NULL;
		//p = alloc_page(0);
		_page = ExAllocateFromNPagedLookasideList (&pool->pageLS);
		if(_page) {
			_page->addr = ExAllocateFromNPagedLookasideList (&pool->page_addrLS);
			if(_page->addr) {
				p = _page;	
			} else {
				ExFreeToNPagedLookasideList (&pool->pageLS, _page);
			}
		} 

		if (!p) 
			bsr_err(3, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate memory in ExAllocateFromNPagedLookasideList");
		
	} else {
		// BSR-247
		p = kzalloc(pool->p_cache->size, gfp_mask, pool->p_cache->tag);
		if (!p) 
			bsr_err(17, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate %d size memory in kzalloc", pool->p_cache->size);
	}

	return p;
}

void mempool_free(void *p, mempool_t *pool)
{
	if (pool) {
		if (pool->page_alloc) {
			struct page* _page = (struct page*)p;
			ExFreeToNPagedLookasideList(&pool->page_addrLS, _page->addr);
			ExFreeToNPagedLookasideList(&pool->pageLS, _page);

		}
		else
			kfree(p);
	}

	return;
}

void mempool_destroy(void *p)
{
	UNREFERENCED_PARAMETER(p);
	// we don't need to free mempool. bsr is static loading driver.
}

void kmem_cache_destroy(struct kmem_cache *s)
{
	kfree(s);
	s = 0;
}

struct kmem_cache *kmem_cache_create(char *name, size_t size, size_t align,
                  unsigned long flags, void (*ctor)(void *), ULONG Tag)
{
	UNREFERENCED_PARAMETER(align);
	UNREFERENCED_PARAMETER(flags);
	UNREFERENCED_PARAMETER(ctor);


	struct kmem_cache *p = kmalloc(sizeof(struct kmem_cache), 0, Tag);	
	if (!p) {
		bsr_err(4, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate %d size memory in kmalloc", sizeof(struct kmem_cache));
		return 0;
	}
#ifdef _WIN64
	BUG_ON_INT32_OVER(size);
#endif
	p->size = (int)size;
	p->name = name;
	return p;
}

// from  linux 2.6.32
int kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
	WARN_ON(release == NULL);
	WARN_ON(release == (void (*)(struct kref *))kfree);

	if (atomic_dec_and_test(&kref->refcount)) {
		release(kref);
		return 1;
	}
	return 0;
}

int kref_get(struct kref *kref)
{
	return atomic_inc_return(&kref->refcount) < 2;
}

void kref_init(struct kref *kref)
{
	atomic_set(&kref->refcount, 1);
}

struct request_queue *bdev_get_queue(struct block_device *bdev)
{
	if (bdev && bdev->bd_disk) {
		return bdev->bd_disk->queue;
	}

	return NULL;
}

struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *bs)
{
	UNREFERENCED_PARAMETER(gfp_mask);
	UNREFERENCED_PARAMETER(nr_iovecs);
	UNREFERENCED_PARAMETER(bs);

	return NULL;
}

struct bio *bio_alloc(gfp_t gfp_mask, int nr_iovecs, ULONG Tag)
{
	struct bio *bio;

	if(nr_iovecs == 0) { // DW-1242 fix nr_iovecs is zero case.
		return 0;
	}
	
	bio = kzalloc(sizeof(struct bio) + nr_iovecs * sizeof(struct bio_vec), gfp_mask, Tag);
	if (!bio) {
		bsr_err(18, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate %d size memory in kzalloc", (sizeof(struct bio) + nr_iovecs * sizeof(struct bio_vec)));
		return 0;
	}
	bio->bi_max_vecs = nr_iovecs;
	bio->bi_vcnt = 0;

	if (nr_iovecs > 256) {
		bsr_err(5, BSR_LC_MEMORY, NO_OBJECT, "BSR_PANIC: block I/O allocate too big, check over 1MB(%d)", nr_iovecs);
		BUG();
	}
	return bio;
}

void bio_put(struct bio *bio) 
{
	bio_free(bio);
}

void bio_free(struct bio *bio) 
{
	kfree(bio);
}


// DW-1538
extern int submit_bio(struct bio* bio)
{
	//bio->bi_rw |= rw; 
	return generic_make_request(bio);
}


void bio_endio(struct bio *bio, int error)
{
	if (bio->bi_end_io) {
		if(error) {
			bio->bi_bdev = NULL;
			bsr_warn(1, BSR_LC_IO, NO_OBJECT, "block I/O request error with err(%d), thread(%s)", error, current->comm);
        	bio->bi_end_io((void*)FAULT_TEST_FLAG, (void*) bio, (void*) error);
		} else { // if bio_endio is called with success(just in case)
			//bsr_info(57, BSR_LC_IO, NO_OBJECT,"thread(%s) bio_endio with err=%d.", current->comm, error);
			bio->bi_bdev = NULL;
        	bio->bi_end_io((void*)error, (void*) bio, (void*) error);
		}
	}
}

struct bio *bio_clone(struct bio * bio_src, int flag)
{
    struct bio *bio = bio_alloc(flag, bio_src->bi_max_vecs, '24SB');

    if (!bio) {
        return NULL;
    }

	memcpy(bio->bi_io_vec, bio_src->bi_io_vec, bio_src->bi_max_vecs * sizeof(struct bio_vec));
	bio->bi_sector = bio_src->bi_sector;
	bio->bi_bdev = bio_src->bi_bdev;
	//bio->bi_flags |= 1 << BIO_CLONED;
	bio->bi_rw = bio_src->bi_rw;
	bio->bi_vcnt = bio_src->bi_vcnt;
	bio->bi_size = bio_src->bi_size;
	bio->bi_idx = bio_src->bi_idx;

	return bio;
}

int bio_add_page(struct bio *bio, struct page *page, unsigned int len,unsigned int offset)
{
	struct bio_vec *bvec = &bio->bi_io_vec[bio->bi_vcnt++];
		
	if (bio->bi_vcnt > 1) {
		bsr_err(2, BSR_LC_IO, NO_OBJECT,"BSR_PANIC: block I/O multi-page not allowed. current page count %d", bio->bi_vcnt);
        BUG();
	}

	bvec->bv_page = page;
	bvec->bv_len = len;
	bvec->bv_offset = offset;
	bio->bi_size += len;

	return len;
}

#include "../../../bsr/bsr_int.h"

bool IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((ULONG_PTR) ptr);
}

void *ERR_PTR(long error)
{
	return (void *) error;
}

long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

bool IS_ERR(void *ptr)
{
	return IS_ERR_VALUE((ULONG_PTR) ptr);
}

void wake_up_process(struct bsr_thread *thi)
{
    KeSetEvent(&thi->wait_event, 0, FALSE);
}

void _wake_up(wait_queue_head_t *q, char *__func, int __line)
{
	UNREFERENCED_PARAMETER(__func);
	UNREFERENCED_PARAMETER(__line);
    KeSetEvent(&q->wqh_event, 0, FALSE);
}

void init_completion(struct completion *completion)
{
	memset(completion->wait.eventName, 0, Q_NAME_SZ);
	strncpy(completion->wait.eventName, "completion", sizeof(completion->wait.eventName) - 1);
	init_waitqueue_head(&completion->wait);
}

long wait_for_completion(struct completion *completion)
{
	return schedule(&completion->wait, MAX_SCHEDULE_TIMEOUT, __FUNCTION__, __LINE__);
}

long wait_for_completion_no_reset_event(struct completion *completion)
{
	return schedule_ex(&completion->wait, MAX_SCHEDULE_TIMEOUT, __FUNCTION__, __LINE__, false);
}

long wait_for_completion_timeout(struct completion *completion, long timeout)
{
    return schedule(&completion->wait, timeout, __FUNCTION__, __LINE__);
}

void complete(struct completion *c)
{
    KeSetEvent(&c->wait.wqh_event, 0, FALSE);
}

void complete_all(struct completion *c)
{
    KeSetEvent(&c->wait.wqh_event, 0, FALSE);
}

static  void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
{
	list_add(&new->task_list, &head->task_list);
}

long schedule_ex(wait_queue_head_t *q, long timeout, char *func, int line, bool auto_reset_event) 
{
	UNREFERENCED_PARAMETER(line);
	UNREFERENCED_PARAMETER(func);

	LARGE_INTEGER nWaitTime;
	LARGE_INTEGER *pTime;
	ULONG_PTR expire;

	expire = timeout + jiffies;
	nWaitTime.QuadPart = 0;

	if(timeout != MAX_SCHEDULE_TIMEOUT) {
		nWaitTime = RtlConvertLongToLargeInteger((timeout) * (-1 * 1000 * 10));
	} else {
		nWaitTime = RtlConvertLongToLargeInteger((60) * (-1 * 10000000));
	}

	pTime = &nWaitTime;
	if ((q == NULL) || (q == (wait_queue_head_t *)SCHED_Q_INTERRUPTIBLE)) {
		KTIMER ktimer;
		KeInitializeTimer(&ktimer);
		KeSetTimerEx(&ktimer, nWaitTime, 0, NULL);
		KeWaitForSingleObject(&ktimer, Executive, KernelMode, FALSE, NULL);

	} else {
	
		NTSTATUS status;
		PVOID waitObjects[2];
		struct task_struct *thread = current;

        int wObjCount = 1;

        waitObjects[0] = (PVOID) &q->wqh_event;
        if (thread->has_sig_event) {
            waitObjects[1] = (PVOID) &thread->sig_event;
            wObjCount = 2;
        }

        while (true) {
            status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, pTime, NULL);

            switch (status) {
            case STATUS_WAIT_0:
				// DW-1862 fflush No event reset is required when waiting for IO to complete. 
				//So we set the parameters for cases where ResetEvent is not needed.
				if (auto_reset_event)
					KeResetEvent(&q->wqh_event); // DW-105 use event and polling both.
                break;

            case STATUS_WAIT_1:
                if (thread->sig == BSR_SIGKILL) {
                    return -BSR_SIGKILL;
                }
                break;

            case STATUS_TIMEOUT:
                if (timeout == MAX_SCHEDULE_TIMEOUT) {
                     continue;
                }
                break;

            default:
				bsr_err(67, BSR_LC_DRIVER, NO_OBJECT, "BSR_PANIC: waiting is stopped for unknown reasons. status(0x%x)", status);
                BUG();
                break;
            }
            break;
        }
	}

	timeout = (long)(expire - jiffies);
	return timeout < 0 ? 0 : timeout;
}

bool queue_work(struct workqueue_struct* queue, struct work_struct* work)
{
	struct work_struct_wrapper * wr = kmalloc(sizeof(struct work_struct_wrapper), 0, '68SB');
	// DW-1051 fix NULL dereference.
	if(!wr) {
		return false;
	}

	wr->w = work;
	ExInterlockedInsertTailList(&queue->list_head, &wr->element, &queue->list_lock);
	KeSetEvent(&queue->wakeupEvent, 0, false); // signal to run_singlethread_workqueue
	return true;
}

void run_singlethread_workqueue(PVOID StartContext)
{
	struct workqueue_struct * wq = (struct workqueue_struct *)StartContext;
	if (wq == NULL)
		return;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID waitObjects[2] = { &wq->wakeupEvent, &wq->killEvent };
	int maxObj = 2;

	while (wq->run)	{
		status = KeWaitForMultipleObjects(maxObj, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
		switch (status)	{
			case STATUS_WAIT_0:	
			{
				PLIST_ENTRY entry;
				while ((entry = ExInterlockedRemoveHeadList(&wq->list_head, &wq->list_lock)) != 0) {
					struct work_struct_wrapper * wr = CONTAINING_RECORD(entry, struct work_struct_wrapper, element);
					wr->w->func(wr->w);
					kfree(wr);
				}
				break;
			}
			case (STATUS_WAIT_1) :
				wq->run = FALSE;
				break;

			default:
				continue;
		}
	}
}

struct workqueue_struct *create_singlethread_workqueue(void * name)
{

	struct workqueue_struct * wq = kzalloc(sizeof(struct workqueue_struct), 0, '31SB');
	if (!wq) {
		return NULL;
	}

	KeInitializeEvent(&wq->wakeupEvent, SynchronizationEvent, FALSE);
	KeInitializeEvent(&wq->killEvent, SynchronizationEvent, FALSE);
	InitializeListHead(&wq->list_head);
	KeInitializeSpinLock(&wq->list_lock);
	strncpy(wq->name, name, sizeof(wq->name) - 1);
	wq->run = TRUE;

	HANDLE hThread = NULL;
	NTSTATUS status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, run_singlethread_workqueue, wq);
	if (!NT_SUCCESS(status)) {
		bsr_err(1, BSR_LC_THREAD, NO_OBJECT, "Failed to create %s thread. status(0x%08x)", wq->name, status);
		kfree(wq);
		return NULL;
	}

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &wq->pThread, NULL);
	ZwClose(hThread);
	if (!NT_SUCCESS(status)) {
		bsr_err(2, BSR_LC_THREAD, NO_OBJECT, "Failed to get handle for thread. name(%s) status(0x%08x)", wq->name, status);
		kfree(wq);
		return NULL;
	}

	return wq;
}

#ifdef _WIN_TMP_DEBUG_MUTEX
void mutex_init(struct mutex *m, char *name)
#else
void mutex_init(struct mutex *m)
#endif
{
	KeInitializeMutex(&m->mtx, 0);
#ifdef _WIN_TMP_DEBUG_MUTEX
	memset(m->name, 0, 32);
	strcpy(m->name, name); 
#endif
}

NTSTATUS mutex_lock_timeout(struct mutex *m, ULONG msTimeout)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER nWaitTime = { 0, };

	if (NULL == m) {
		return STATUS_INVALID_PARAMETER;
	}

	nWaitTime.QuadPart = (-1 * 10000);
	nWaitTime.QuadPart *= msTimeout;		// multiply timeout value separately to avoid overflow.
	status = KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, &nWaitTime);

	return status;
}

__inline
NTSTATUS mutex_lock(struct mutex *m)
{
    return KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, NULL);
}

__inline
int mutex_lock_interruptible(struct mutex *m)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	int err = -EIO;
	struct task_struct *thread = current;
	PVOID waitObjects[2];
	int wObjCount = 1;

	waitObjects[0] = (PVOID)&m->mtx;
	if (thread->has_sig_event) {
		waitObjects[1] = (PVOID)&thread->sig_event;
		wObjCount++;
	}
	
	status = KeWaitForMultipleObjects(wObjCount, &waitObjects[0], WaitAny, Executive, KernelMode, FALSE, NULL, NULL);

	switch (status) {
	case STATUS_WAIT_0:		// mutex acquired.
		err = 0;
		break;
	case STATUS_WAIT_1:		// thread got signal by the func 'force_sig'
		err = thread->sig != 0 ? -thread->sig : -EIO;
		break;
	default:
		err = -EIO;
		bsr_err(66, BSR_LC_DRIVER, NO_OBJECT, "waiting is stopped for unknown reasons. status(0x%x)", status);
		break;
	}

	return err;
}

// Returns 1 if the mutex is locked, 0 if unlocked.
int mutex_is_locked(struct mutex *m)
{
	return (KeReadStateMutex(&m->mtx) == 0) ? 1 : 0;
}

// Try to acquire the mutex atomically. 
// Returns 1 if the mutex has been acquired successfully, and 0 on contention.
int mutex_trylock(struct mutex *m)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = 0; 

	if (KeWaitForMutexObject(&m->mtx, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS) {
		return 1;
	}
	else {
		return 0;
	}
}

void mutex_unlock(struct mutex *m)
{
	KeReleaseMutex(&m->mtx, FALSE);
}

void sema_init(struct semaphore *s, int limit)
{
    KeInitializeSemaphore(&s->sem, limit, limit);    
    bsr_debug_sem("KeInitializeSemaphore!  KeReadStateSemaphore (%d)", KeReadStateSemaphore(&s->sem));
}

void down(struct semaphore *s)
{
    bsr_debug_sem("KeWaitForSingleObject before! KeReadStateSemaphore (%d)", KeReadStateSemaphore(&s->sem));
    KeWaitForSingleObject(&s->sem, Executive, KernelMode, FALSE, NULL);
    bsr_debug_sem("KeWaitForSingleObject after! KeReadStateSemaphore (%d)", KeReadStateSemaphore(&s->sem));
}

/**
  * down_trylock - try to acquire the semaphore, without waiting
  * @sem: the semaphore to be acquired
  *
  * Try to acquire the semaphore atomically.  Returns 0 if the semaphore has
  * been acquired successfully or 1 if it it cannot be acquired.
  */

int down_trylock(struct semaphore *s)
{
	LARGE_INTEGER Timeout; 
	Timeout.QuadPart = 0; 

    if (KeWaitForSingleObject(&s->sem, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS) {
        bsr_debug_sem("success! KeReadStateSemaphore (%d)", KeReadStateSemaphore(&s->sem));
        return 0;
    }
    else {
        bsr_debug_sem("fail! KeReadStateSemaphore (%d)", KeReadStateSemaphore(&s->sem));
        return 1;
    }
}

void up(struct semaphore *s)
{
    if (KeReadStateSemaphore(&s->sem) < s->sem.Limit) {
        bsr_debug_sem("KeReleaseSemaphore before! KeReadStateSemaphore (%d)", KeReadStateSemaphore(&s->sem));
		// DW-1496 KeReleaseSemaphore raised an exception(STATUS_SEMAPHORE_LIMIT_EXCEEDED) and handled it in try/except syntax
		try{
			KeReleaseSemaphore(&s->sem, IO_NO_INCREMENT, 1, FALSE);
		} except(EXCEPTION_EXECUTE_HANDLER){
			bsr_debug_sem("KeReleaseSemaphore Exception occured!(ExRaiseStatus(STATUS_SEMAPHORE_LIMIT_EXCEEDED)) ");
		}
		bsr_debug_sem("KeReleaseSemaphore after! KeReadStateSemaphore (%d)", KeReadStateSemaphore(&s->sem));
    }
}

KIRQL du_OldIrql;

void downup_rwlock_init(KSPIN_LOCK* lock)
{
	KeInitializeSpinLock(lock);
}

KIRQL down_write(KSPIN_LOCK* lock)
{
	return KeAcquireSpinLock(lock, &du_OldIrql);
}

void up_write(KSPIN_LOCK* lock)
{
	KeReleaseSpinLock(lock, du_OldIrql);
	return;
}

KIRQL down_read(KSPIN_LOCK* lock)
{
	return KeAcquireSpinLock(lock, &du_OldIrql);
}

void up_read(KSPIN_LOCK* lock)
{
	KeReleaseSpinLock(lock, du_OldIrql);
	return;
}

void spin_lock_init(spinlock_t *lock)
{
	KeInitializeSpinLock(&lock->spinLock);
	lock->Refcnt = 0;
	lock->OwnerThread = 0;
}

void acquireSpinLock(KSPIN_LOCK *lock, KIRQL *flags)
{
	KeAcquireSpinLock(lock, flags);
}

void releaseSpinLock(KSPIN_LOCK *lock, KIRQL flags)
{
	KeReleaseSpinLock(lock, flags);
}

// DW-903 protect lock recursion
// if current thread equal lock owner thread, just increase refcnt

unsigned long _spin_lock_irqsave(spinlock_t *lock)
{
	KIRQL	oldIrql = 0;
	PKTHREAD curthread = KeGetCurrentThread();
	if( curthread == lock->OwnerThread) { 
		bsr_warn(24, BSR_LC_THREAD, NO_OBJECT, "thread:%p spinlock recursion is happened! function:%s line:%d", curthread, __FUNCTION__, __LINE__);
	} else {
		acquireSpinLock(&lock->spinLock, &oldIrql);
		lock->OwnerThread = curthread;
	}
	InterlockedIncrement(&lock->Refcnt);
	return (unsigned long)oldIrql;
}

void spin_lock(spinlock_t *lock)
{
	spin_lock_irq(lock);
}

void spin_unlock(spinlock_t *lock)
{
	spin_unlock_irq(lock);
}

// DW-903 protect lock recursion
// if current thread equal lock owner thread, just increase refcnt

void spin_lock_irq(spinlock_t *lock)
{
	PKTHREAD curthread = KeGetCurrentThread();
	if( curthread == lock->OwnerThread) {// DW-903 protect lock recursion
		bsr_warn(25, BSR_LC_THREAD, NO_OBJECT, "thread:%p spinlock recursion is happened! function:%s line:%d", curthread, __FUNCTION__, __LINE__);
	} else {
		acquireSpinLock(&lock->spinLock, &lock->saved_oldIrql);
		lock->OwnerThread = curthread;
	}
	InterlockedIncrement(&lock->Refcnt);
}

// fisrt, decrease refcnt
// If refcnt is 0, clear OwnerThread and release lock

void spin_unlock_irq(spinlock_t *lock)
{
	InterlockedDecrement(&lock->Refcnt);
	if(lock->Refcnt == 0) {
		lock->OwnerThread = 0;
		releaseSpinLock(&lock->spinLock, lock->saved_oldIrql);
	}
}
// fisrt, decrease refcnt
// If refcnt is 0, clear OwnerThread and release lock

void spin_unlock_irqrestore(spinlock_t *lock, long flags)
{
	InterlockedDecrement(&lock->Refcnt);
	if(lock->Refcnt == 0) {
		lock->OwnerThread = 0;
		releaseSpinLock(&lock->spinLock, (KIRQL) flags);
	}
}

// DW-903 protect lock recursion
// if current thread equal lock owner thread, just increase refcnt
void spin_lock_bh(spinlock_t *lock)
{
	PKTHREAD curthread = KeGetCurrentThread();
	if( curthread == lock->OwnerThread) {
		bsr_warn(26, BSR_LC_THREAD, NO_OBJECT, "thread:%p spinlock recursion is happened! function:%s line:%d", curthread, __FUNCTION__, __LINE__);
	} else {
		KeAcquireSpinLock(&lock->spinLock, &lock->saved_oldIrql);
		lock->OwnerThread = curthread;
	}
	InterlockedIncrement(&lock->Refcnt);
}
// fisrt, decrease refcnt
// If refcnt is 0, clear OwnerThread and release lock
void spin_unlock_bh(spinlock_t *lock)
{
	InterlockedDecrement(&lock->Refcnt);
	if(lock->Refcnt == 0) {
		lock->OwnerThread = 0;
		KeReleaseSpinLock(&lock->spinLock, lock->saved_oldIrql);
	}
}

spinlock_t g_irqLock;
void local_irq_disable()
{	
	spin_lock_irq(&g_irqLock);
}

void local_irq_enable()
{
	spin_unlock_irq(&g_irqLock);
}

// BSR-426
BOOLEAN is_spin_lock_in_current_thread(spinlock_t *lock)
{
	PKTHREAD curthread = KeGetCurrentThread();

	if (KeTestSpinLock(&lock->spinLock)) {
		if (curthread == lock->OwnerThread)
			return TRUE;
	}
	return FALSE;
}

BOOLEAN spin_trylock(spinlock_t *lock)
{
	if (FALSE == KeTestSpinLock(&lock->spinLock))
		return FALSE;
	
	spin_lock(lock);
	return TRUE;
}

ULONG get_random_ulong(PULONG seed)
{
	LARGE_INTEGER Hpts;
	if (!seed) {
		return 0;
	}
	Hpts = KeQueryPerformanceCounter(NULL);
	
	return (Hpts.LowPart + *seed);
}

void get_random_bytes(void *buf, int nbytes)
{
    ULONG rn = nbytes;
    UCHAR * target = buf;
    int length = 0;

    do {
		rn = get_random_ulong(&rn);
        length = (4 > nbytes) ? nbytes : 4;
        memcpy(target, (UCHAR *)&rn, length);
        nbytes -= length;
        target += length;
        
    } while (nbytes);
}

unsigned int crypto_tfm_alg_digestsize(struct crypto_tfm *tfm)
{
	UNREFERENCED_PARAMETER(tfm);
	return 4; // 4byte in constant
}

int page_count(struct page *page)
{
	UNREFERENCED_PARAMETER(page);
	return 1;
}

void init_timer(struct timer_list *t)
{
	KeInitializeTimer(&t->ktimer);
	KeInitializeDpc(&t->dpc, (PKDEFERRED_ROUTINE) t->function, t->data);
#ifdef DBG
	strncpy(t->name, "undefined", sizeof(t->name) - 1);
#endif
}

void init_timer_key(struct timer_list *timer, const char *name,
    struct lock_class_key *key)
{
	UNREFERENCED_PARAMETER(key);
	UNREFERENCED_PARAMETER(name);

    init_timer(timer);
#ifdef DBG
	strncpy(timer->name, name, sizeof(timer->name) - 1);
#endif
}

void add_timer(struct timer_list *t)
{
	mod_timer(t, t->expires);
}

void del_timer(struct timer_list *t)
{
	KeCancelTimer(&t->ktimer);
    t->expires = 0;
}

/**
 * timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
static __inline int timer_pending(const struct timer_list * timer)
{
    return timer->ktimer.Header.Inserted;
}

int del_timer_sync(struct timer_list *t)
{
	bool pending = 0;
	pending = timer_pending(t);

	del_timer(t);

	return pending;
}


static int
__mod_timer(struct timer_list *timer, ULONG_PTR expires, bool pending_only)
{
	if (!timer_pending(timer) && pending_only) {
		return 0;
	}

	LARGE_INTEGER nWaitTime = { .QuadPart = 0 };
	ULONG_PTR current_milisec = jiffies;

	timer->expires = expires;

	if (current_milisec >= expires) {
		nWaitTime.QuadPart = -1;
	}
	else {
		expires -= current_milisec;
		BUG_ON_UINT32_OVER(expires);
		nWaitTime = RtlConvertLongToLargeInteger(RELATIVE(MILLISECONDS((LONG)expires)));
	}

#ifdef DBG
	bsr_debug_tm("%s timer(0x%p) current(%d) expires(%d) gap(%d)",
		timer->name, timer, current_milisec, timer->expires, timer->expires - current_milisec);
#endif
	KeSetTimer(&timer->ktimer, nWaitTime, &timer->dpc);
	return 1;
}

/**
 * mod_timer_pending - modify a pending timer's timeout
 * @timer: the pending timer to be modified
 * @expires: new timeout in jiffies
 *
 * mod_timer_pending() is the same for pending timers as mod_timer(),
 * but will not re-activate and modify already deleted timers.
 *
 * It is useful for unserialized use of timers.
 */
int mod_timer_pending(struct timer_list *timer, ULONG_PTR expires)
{
    return __mod_timer(timer, expires, true);
}

int mod_timer(struct timer_list *timer, ULONG_PTR expires)
{
    return __mod_timer(timer, expires, false);
}

void kobject_put(struct kobject *kobj)
{
    if (kobj) 
    {
        if (kobj->name == NULL) {
            //bsr_warn(68, BSR_LC_ETC,"%p name is null.", kobj);
            return;
        }

		if (atomic_sub_and_test(1, &kobj->kref.refcount)) {
			void(*release)(struct kobject *kobj);
			release = kobj->ktype->release;
			if (release == 0) {
				return;
			}
			release(kobj);
		}
    }
    else {
        //bsr_warn(69, BSR_LC_ETC,"kobj is null.");
        return;
    }
}

void kobject_del(struct kobject *kobj)
{
    if (!kobj) {
		bsr_warn(70, BSR_LC_ETC, NO_OBJECT, "The kobj to be deleted has not been assigned.");
        return;
    }
    kobject_put(kobj->parent); 
}

void kobject_get(struct kobject *kobj)
{
    if (kobj) {
        kref_get(&kobj->kref);
    }
    else {
		bsr_info(2, BSR_LC_ETC, NO_OBJECT, "Reference count did not increase because no kobj were assigned.");
        return;
    }
}

void bsr_unregister_blkdev(unsigned int major, const char *name)
{
	UNREFERENCED_PARAMETER(major);
	UNREFERENCED_PARAMETER(name);

}

void del_gendisk(struct gendisk *disk)
{
	UNREFERENCED_PARAMETER(disk);
	// free disk
}

 void destroy_workqueue(struct workqueue_struct *wq)
{
	 KeSetEvent(&wq->killEvent, 0, FALSE);
	 KeWaitForSingleObject(wq->pThread, Executive, KernelMode, FALSE, NULL);
	 ObDereferenceObject(wq->pThread);
     kfree(wq);
}

 void sock_release(struct socket *sock)
{
	NTSTATUS status;
	
	if (!sock) {
		bsr_warn(1, BSR_LC_SOCKET, NO_OBJECT, "Unable to socket release because socket is not assigned.");
		return;
	}

#ifndef _WIN_SEND_BUF
	
	status = CloseSocket(sock->sk); 
	if (!NT_SUCCESS(status)) 
	{
		bsr_err(3, BSR_LC_ETC, NO_OBJECT,"error=0x%x", status);
		return;
	}
#endif

	// DW-1493 WSK_EVENT_DISCONNECT disable
	if (sock->sk){
		status = SetEventCallbacks(sock, WSK_EVENT_DISCONNECT | WSK_EVENT_DISABLE);
		bsr_debug(80, BSR_LC_SOCKET, NO_OBJECT,"WSK_EVENT_DISABLE (sock = 0x%p)", sock);
		if (!NT_SUCCESS(status)) {
			bsr_debug(81, BSR_LC_SOCKET, NO_OBJECT, "WSK_EVENT_DISABLE failed (sock = 0x%p)", sock);
		}
	}

	if (sock->sk_linux_attr) {
		kfree(sock->sk_linux_attr);
		sock->sk_linux_attr = 0;
	}

#ifdef _WIN_SEND_BUF
	struct _buffering_attr *buffering_attr = &sock->buffering_attr;
	struct ring_buffer *bab = buffering_attr->bab;

	if (bab){
		if (bab->static_big_buf) {
			kfree2(bab->static_big_buf);
		}
		//kfree2(bab);
	}
	
	bsr_debug_conn("sock_relese: called CloseSocket(%p)", sock->sk);
	status = CloseSocket(sock);
	bsr_debug_conn("CloseSocket error(%p)", status);
	if (!NT_SUCCESS(status)) {
		bsr_debug_conn("CloseSocket failed ");
		return;
	}
#endif

	kfree(sock);
}

//Linux/block/genhd.c
void set_disk_ro(struct gendisk *disk, int flag)
{
	UNREFERENCED_PARAMETER(disk);
	UNREFERENCED_PARAMETER(flag);
}

#define CT_MAX_THREAD_LIST          40
static LIST_HEAD(ct_thread_list);
static int ct_thread_num = 0;
static KSPIN_LOCK ct_thread_list_lock;
static KIRQL ct_oldIrql;

void ct_init_thread_list()
{
    KeInitializeSpinLock(&ct_thread_list_lock);
}

static struct task_struct *__find_thread(int id)
{
    struct task_struct *t;

    list_for_each_entry_ex(struct task_struct, t, &ct_thread_list, list)
    {
        if (t->pid == id) {
            return t;
        }
    }
    return NULL;
}

static void __delete_thread(struct task_struct *t)
{
    list_del(&t->list);
    kfree(t);
    ct_thread_num--;

    // logic check
    if (ct_thread_num < 0) {
		bsr_err(3, BSR_LC_THREAD, NO_OBJECT, "BSR_PANIC: unexpected number of threads in operation has been set. number(%d)", ct_thread_num);
        BUG();
    }
}

struct task_struct * ct_add_thread(int id, const char *name, BOOLEAN event, ULONG Tag)
{
    struct task_struct *t;

    if ((t = kzalloc(sizeof(*t), GFP_KERNEL, Tag)) == NULL) {
        return NULL;
    }

    t->pid = id;
    if (event) {
        KeInitializeEvent(&t->sig_event, SynchronizationEvent, FALSE);
        t->has_sig_event = TRUE;
    }
	strncpy(t->comm, name, sizeof(t->comm) - 1);
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
	list_add(&t->list, &ct_thread_list);
	if (++ct_thread_num > CT_MAX_THREAD_LIST) {
		bsr_warn(27, BSR_LC_THREAD, NO_OBJECT, "too many ct_threads (name:%s, thread_num:%d)", name, ct_thread_num);
    }
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
    return t;
}

void ct_delete_thread(int id)
{
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
    __delete_thread(__find_thread(id));
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
}

struct task_struct* ct_find_thread(int id)
{
    struct task_struct *t;
    KeAcquireSpinLock(&ct_thread_list_lock, &ct_oldIrql);
    t = __find_thread(id);
    if (!t) {
        static struct task_struct g_dummy_current;
        t = &g_dummy_current;
        t->pid = 0;
        t->has_sig_event = FALSE;
		strncpy(t->comm, "not_bsr_thread", sizeof(t->comm) - 1);
    }
    KeReleaseSpinLock(&ct_thread_list_lock, ct_oldIrql);
    return t;
}

int signal_pending(struct task_struct *task)
{
    if (task->has_sig_event) {
		if (task->sig || KeReadStateEvent(&task->sig_event)) {
			return 1;
		}
	}
	return 0;
}

void force_sig(int sig, struct task_struct  *task)
{
    if (task->has_sig_event) {
		task->sig = sig;
		KeSetEvent(&task->sig_event, 0, FALSE);
	}
}

void flush_signals(struct task_struct *task)
{
    if (task->has_sig_event) {
		KeClearEvent(&task->sig_event); 
		task->sig = 0;
	}
}

void *crypto_alloc_tfm(char *name, u32 mask)
{
	UNREFERENCED_PARAMETER(mask);

	bsr_info(59, BSR_LC_PROTOCOL, NO_OBJECT, "The hash algorithm supports only crc32c, and the received hash algorithm is %s.", name);
	return (void *)1;
}

int generic_make_request(struct bio *bio)
{
	NTSTATUS status = STATUS_SUCCESS;

	PIRP newIrp = NULL;
	PVOID buffer = NULL;
	LARGE_INTEGER offset = {0,};
	ULONG io = 0;
	PIO_STACK_LOCATION	pIoNextStackLocation = NULL;
	
	
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);

	if (!q) {
		return -EIO;
	}

	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		// DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
		if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk && bio->bi_bdev->bd_disk->pDeviceExtension) {
			status = IoAcquireRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
			if (!NT_SUCCESS(status)) {
				bsr_err(5, BSR_LC_IO, NO_OBJECT,"Failed to acquire device removal lock. device extension(%p), status(0x%x)", bio->bi_bdev->bd_disk->pDeviceExtension, status);
				return -EIO;
			}
		}
		else {
			bsr_err(39, BSR_LC_IO, NO_OBJECT, "Failed to I/O request due to failure to not found volume information. IRQL(%d)", KeGetCurrentIrql());
			return -EIO;
		}
	}
	else {
		bsr_err(40, BSR_LC_IO, NO_OBJECT, "Failed to acquire remove lock, IRQL(%d) is too high. device extension(%p)", KeGetCurrentIrql(), bio->bi_bdev->bd_disk->pDeviceExtension);
		return -EIO;
	}

	if(bio->bi_rw == WRITE_FLUSH) {
		io = IRP_MJ_FLUSH_BUFFERS;
		buffer = NULL;
		bio->bi_size = 0;
		offset.QuadPart = 0;

		// DW-1961 Save timestamp for IO latency measurement
		if (atomic_read(&g_debug_output_category) & (1 << BSR_LC_LATENCY))
			bio->flush_ts = timestamp();

	} else {
		if (bio->bi_rw & WRITE) {
			io = IRP_MJ_WRITE;
		} else {
			io = IRP_MJ_READ;
		}
		offset.QuadPart = bio->bi_sector << 9;
		if (bio->bio_databuf) {
			buffer = bio->bio_databuf;
		} else {
			if (bio->bi_max_vecs > 1) {
				BUG(); // BSR_PANIC
			}
			buffer = (PVOID) bio->bi_io_vec[0].bv_page->addr; 
		}
	}

#ifdef BSR_TRACE
    bsr_debug(47, BSR_LC_IO, NO_OBJECT,"(%s)Local I/O(%s): sect=0x%llx sz=%d IRQL=%d buf=0x%p, off&=0x%llx target=%c:", 
		current->comm, (io == IRP_MJ_READ) ? "READ" : "WRITE", 
		offset.QuadPart / 512, bio->bi_size, KeGetCurrentIrql(), &offset, buffer, q->backing_dev_info.pDeviceExtension->Letter);
#endif

	int retry = 0;
retry:
	newIrp = IoBuildAsynchronousFsdRequest(
				io,
				bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject,
				buffer,
				bio->bi_size,
				&offset,
				NULL
				);

	if (!newIrp) {
		// DW-2156 if the irp allocation fails, try again three times.
		if (retry < 3) {
			LARGE_INTEGER	delay;

			delay.QuadPart = (-1 * 1000 * 10000);   //// wait 1000ms relative
			KeDelayExecutionThread(KernelMode, FALSE, &delay);
			retry++;
			bsr_warn(90, BSR_LC_MEMORY, NO_OBJECT, "IoBuildAsynchronousFsdRequest: cannot alloc new IRP, try again (%d/3)\n", retry);
			goto retry;
		}

		bsr_err(48, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocation of IRP in IoBuildAsynchronousFsdRequest.");
		// DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
		if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk && bio->bi_bdev->bd_disk->pDeviceExtension)
			IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);
		return -ENOMEM;
	}

	if( IRP_MJ_WRITE == io) {
		pIoNextStackLocation = IoGetNextIrpStackLocation (newIrp);
		if(bio->MasterIrpStackFlags) { 
			//copy original Local I/O's Flags for private_bio instead of bsr's write_ordering, because of performance issue. (2016.03.23)
			pIoNextStackLocation->Flags = bio->MasterIrpStackFlags;
		} else { 
			//apply meta I/O's write_ordering
			// DW-1300 get bsr device from gendisk.
			struct bsr_device* device = bio->bi_bdev->bd_disk->bsr_device;
			if(device && device->resource->write_ordering >= WO_BDEV_FLUSH) {
				pIoNextStackLocation->Flags |= (SL_WRITE_THROUGH | SL_FT_SEQUENTIAL_WRITE);
			}
		}
	}
	
	IoSetCompletionRoutine(newIrp, (PIO_COMPLETION_ROUTINE)bio->bi_end_io, bio, TRUE, TRUE, TRUE);

	//
	//	simulation disk-io error point . (generic_make_request fail) - disk error simluation type 0
	//
	if (gSimulDiskIoError.ErrorFlag && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE0) {
		if (IsDiskError()) {
			bsr_err(4, BSR_LC_IO, NO_OBJECT,"SimulDiskIoError: type0...............ErrorFlag:%d ErrorCount:%d",gSimulDiskIoError.ErrorFlag, gSimulDiskIoError.ErrorCount);
			// DW-1831 check whether bio->bi_bdev and bio->bi_bdev->bd_disk are null.
			if (bio && bio->bi_bdev && bio->bi_bdev->bd_disk && bio->bi_bdev->bd_disk->pDeviceExtension)
				IoReleaseRemoveLock(&bio->bi_bdev->bd_disk->pDeviceExtension->RemoveLock, NULL);

			// DW-859 Without unlocking mdl and freeing irp, freeing buffer causes bug check code 0x4e(0x9a, ...)
			// When 'generic_make_request' returns an error code, bi_end_io is called to clean up the bio but doesn't do for irp. We should free irp that is made but wouldn't be delivered.
			// If no error simulation, calling 'IoCallDriver' verifies our completion routine called so that irp will be freed there.
			if (newIrp->MdlAddress != NULL) {
				PMDL mdl, nextMdl;
				for (mdl = newIrp->MdlAddress; mdl != NULL; mdl = nextMdl) {
					nextMdl = mdl->Next;
					MmUnlockPages(mdl);
					IoFreeMdl(mdl); // This function will also unmap pages.
				}
				newIrp->MdlAddress = NULL;
			}
			IoFreeIrp(newIrp);
			return -EIO;		
		}
	}

	add_untagged_mdl_mem_usage(buffer, bio->bi_size);
	add_untagged_mem_usage(IoSizeOfIrp(bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject->StackSize));

	// DW-1495 If any volume is set to read only, all writes operations are paused temporarily. 
	if (io == IRP_MJ_WRITE){
		mutex_lock(&att_mod_mutex);
		IoCallDriver(bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject, newIrp);
		mutex_unlock(&att_mod_mutex);
	}
	else{
		IoCallDriver(bio->bi_bdev->bd_disk->pDeviceExtension->TargetDeviceObject, newIrp);
	}

	return 0;
}

void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
}

int hlist_unhashed(const struct hlist_node *h)
{
	return !h->pprev;
}

void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

void INIT_HLIST_NODE(struct hlist_node *h)
{
    h->next = NULL;
    h->pprev = NULL;
}

void hlist_del_init(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		INIT_HLIST_NODE(n);
	}
}

void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static const u32 crc32c_table[256] = { 
	0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
	0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
	0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
	0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
	0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
	0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
	0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
	0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
	0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
	0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
	0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
	0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
	0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
	0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
	0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
	0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
	0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
	0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
	0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
	0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
	0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
	0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
	0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
	0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
	0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
	0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
	0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
	0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
	0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
	0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
	0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
	0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
	0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
	0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
	0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
	0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
	0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
	0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
	0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
	0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
	0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
	0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
	0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
	0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
	0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
	0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
	0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
	0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
	0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
	0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
	0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
	0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
	0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
	0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
	0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
	0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
	0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
	0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
	0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
	0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
	0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
	0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
	0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
	0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length)
{
	while (length--)
		crc = crc32c_table[(crc ^ *data++) & 0xFFL] ^ (crc >> 8);

	return crc;
}

inline void __list_add_rcu(struct list_head *new, struct list_head *prev, struct list_head *next)
{
	new->next = next;
	new->prev = prev;
	rcu_assign_pointer(list_next_rcu(prev), new);
	next->prev = new;
}

void list_del_rcu(struct list_head *entry)
{
     __list_del(entry->prev, entry->next);
     entry->prev = LIST_POISON2;
}

void list_add_rcu(struct list_head *new, struct list_head *head)
{
    __list_add_rcu(new, head, head->next);
}

void list_add_tail_rcu(struct list_head *new, struct list_head *head)
{
     __list_add_rcu(new, head->prev, head);
}

void blk_cleanup_queue(struct request_queue *q)
{
	kfree2(q);
}

struct gendisk *alloc_disk(int minors)
{
	UNREFERENCED_PARAMETER(minors);
	struct gendisk *p = kzalloc(sizeof(struct gendisk), 0, '44SB');
	return p;
}

void put_disk(struct gendisk *disk)
{
	kfree2(disk);
}

void blk_queue_make_request(struct request_queue *q, make_request_fn *mfn)
{
	UNREFERENCED_PARAMETER(q);
	UNREFERENCED_PARAMETER(mfn);
	// not support
}

void blk_queue_flush(struct request_queue *q, unsigned int flush)
{
	UNREFERENCED_PARAMETER(q);
	UNREFERENCED_PARAMETER(flush);
}

struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
{
	UNREFERENCED_PARAMETER(pool_size);
	UNREFERENCED_PARAMETER(front_pad);
	// not support
	return NULL;
}

//
// porting netlink interface 
//
unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb_tail_pointer(skb);
	// SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;

	if (skb->tail > skb->end) {
		bsr_err(66, BSR_LC_GENL, NO_OBJECT, "buffer size exceeds specified range. excess range(%d)", (skb->tail - skb->end));
	}

	return tmp;
}
void *compat_genlmsg_put(struct sk_buff *skb, u32 pid, u32 seq,
				       struct genl_family *family, int flags, u8 cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *hdr;

	nlh = nlmsg_put(skb, pid, seq, family->id, GENL_HDRLEN + family->hdrsize, flags);
	if (nlh == NULL)
		return NULL;

	hdr = nlmsg_data(nlh);
	hdr->cmd = cmd;
	hdr->version = (u8)family->version;
	hdr->reserved = 0;

	return (char *) hdr + GENL_HDRLEN;
}

void *genlmsg_put_reply(struct sk_buff *skb,
                         struct genl_info *info,
                         struct genl_family *family,
                         int flags, u8 cmd)
{
	return genlmsg_put(skb, info->snd_portid, info->snd_seq, family, flags, cmd);
}

void genlmsg_cancel(struct sk_buff *skb, void *hdr)
{
	UNREFERENCED_PARAMETER(skb);
	UNREFERENCED_PARAMETER(hdr);

}

int _BSR_ratelimit(struct ratelimit_state *rs, const char * func, const char * __FILE, const int __LINE)
{
	int ret;

	if (!rs ||
		!rs->interval)
		return 1;

	if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
		return 1;
	}

	//If we contend on this state's lock then almost by definition we are too busy to print a message, in addition to the one that will be printed by the entity that is holding the lock already
	if (!spin_trylock(&rs->lock))
		return 0;

	if (!rs->begin)
		rs->begin = jiffies;

	if (time_is_before_jiffies(rs->begin + rs->interval)){
		if (rs->missed)
			bsr_warn(71, BSR_LC_ETC, NO_OBJECT, "%s(%s@%d): %d callbacks suppressed", func, __FILE, __LINE, rs->missed);
		rs->begin = jiffies;
		rs->printed = 0;
		rs->missed = 0;
	}

	if (rs->burst && rs->burst > rs->printed){
		rs->printed++;
		ret = 1;
	} else {
		rs->missed++;
		ret = 0;
	}
	spin_unlock(&rs->lock);

	return ret;
}

static int idr_max(int layers)
{
	int bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);
	return (1 << bits) - 1;
}

#define __round_mask(x, y) ((y) - 1)
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

void *idr_get_next(struct idr *idp, int *nextidp)
{
	struct idr_layer *p, *pa[MAX_IDR_LEVEL + 1];
	struct idr_layer **paa = &pa[0];
	int id = *nextidp;
	int n, max;

	/* find first ent */
	if (!idp) {
		return NULL;
	}

	n = idp->layers * IDR_BITS;
	max = 1 << n;
	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;

	while (id < max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			*nextidp = id;
			return p;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}
	return NULL;
}

// BSR-109 function disable
#if 0
 * @brief
 *	Recreate the VOLUME_EXTENSION's MountPoint, Minor, block_device
 *	if it was changed
 */
void update_targetdev(PVOLUME_EXTENSION pvext, bool bMountPointUpdate)
{
	unsigned long long 	d_size;
	UNICODE_STRING 		old_mount_point;
	NTSTATUS 			status;
	bool				bWasExist = FALSE;	
	if (!pvext) {
		bsr_warn(72, BSR_LC_ETC,"update_targetdev fail pvext is NULL");
		return;
	}

	// DW-1681 Since there is a performance problem in update_targetdev, it is discriminated whether or not to update the mount point.
	if(bMountPointUpdate) {
		if(!IsEmptyUnicodeString(&pvext->MountPoint)) {
			ucsdup (&old_mount_point, pvext->MountPoint.Buffer, pvext->MountPoint.Length);
			bWasExist = TRUE;

			if (!IsEmptyUnicodeString(&old_mount_point))
				bsr_debug(49, BSR_LC_VOLUME, NO_OBJECT,"old_mount_point:%wZ", &old_mount_point);
		}
		
		status = mvolUpdateMountPointInfoByExtension(pvext);
		if(NT_SUCCESS(status)) {

			if (!IsEmptyUnicodeString(&pvext->MountPoint))
				bsr_debug(50, BSR_LC_VOLUME, NO_OBJECT,"new mount point:%wZ", &pvext->MountPoint);

			// DW-1105 detach volume when replicating volume letter is changed.
			if (pvext->Active && bWasExist) {
				if(IsEmptyUnicodeString(&pvext->MountPoint) || 
					!RtlEqualUnicodeString(&pvext->MountPoint, &old_mount_point, TRUE) ) {

					// DW-1300 get device and get reference.
					struct bsr_device *device = get_device_with_vol_ext(pvext, TRUE);
					if (device && get_ldev_if_state(device, D_NEGOTIATING)) {
						bsr_warn(73, BSR_LC_ETC,"replicating volume letter is changed, detaching");
						set_bit(FORCE_DETACH, &device->flags);
						change_disk_state(device, D_DETACHING, CS_HARD, NULL);						
						put_ldev(__FUNCTION__, device);
					}
					// DW-1300 put device reference count when no longer use.
					if (device)
						kref_put(&device->kref, bsr_destroy_device);
				}
			}
		}
		
		if(bWasExist) {
			FreeUnicodeString (&old_mount_point);
		}
	} 
	
	// DW-1109 not able to get volume size in add device routine, get it here if no size is assigned.
	// DW-1469
	d_size = get_targetdev_volsize(pvext);
	
	if ( pvext->dev->bd_contains && (pvext->dev->bd_contains->d_size != d_size) ) {	
		pvext->dev->bd_contains->d_size = d_size;
		pvext->dev->bd_disk->queue->max_hw_sectors = d_size ? (d_size >> 9) : BSR_MAX_BIO_SIZE;
	}
	bsr_debug(51, BSR_LC_VOLUME, NO_OBJECT,"d_size: %lld bytes bd_contains->d_size: %lld bytes max_hw_sectors: %lld sectors", d_size, pvext->dev->bd_contains ? pvext->dev->bd_contains->d_size : 0, pvext->dev->bd_disk->queue->max_hw_sectors);
}

// DW-1105 refresh all volumes and handle changes.
void adjust_changes_to_volume(PVOID pParam)
{
	UNREFERENCED_PARAMETER(pParam);
	refresh_targetdev_list();
}

// DW-1105 request mount manager to notify us whenever there is a change in the mount manager's persistent symbolic link name database.
void monitor_mnt_change(PVOID pParam)
{
	UNREFERENCED_PARAMETER(pParam);

	OBJECT_ATTRIBUTES oaMntMgr = { 0, };
	UNICODE_STRING usMntMgr = { 0, };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hMntMgr = NULL;
	HANDLE hEvent = NULL;
	IO_STATUS_BLOCK iosb = { 0, };
	
	RtlInitUnicodeString(&usMntMgr, MOUNTMGR_DEVICE_NAME);
	InitializeObjectAttributes(&oaMntMgr, &usMntMgr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	do {
		status = ZwCreateFile(&hMntMgr,
			FILE_READ_DATA | FILE_WRITE_DATA,
			&oaMntMgr,
			&iosb,
			NULL,
			0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE,
			NULL,
			0);

		if (!NT_SUCCESS(status)) {
			bsr_err(7, BSR_LC_ETC, NO_OBJECT,"could not open mount manager, status : 0x%x", status);
			break;
		}

		status = ZwCreateEvent(&hEvent, GENERIC_ALL, 0, NotificationEvent, FALSE);
		if (!NT_SUCCESS(status)) {
			bsr_err(4, BSR_LC_ETC, NO_OBJECT,"could not create event, status : 0x%x", status);
			break;
		}

		// DW-1105 set state as 'working', this can be set as 'not working' by stop_mnt_monitor.
		atomic_set(&g_monitor_mnt_working, TRUE);

		MOUNTMGR_CHANGE_NOTIFY_INFO mcni1 = { 0, }, mcni2 = { 0, };

		while (TRUE == atomic_read(&g_monitor_mnt_working)) {
			
			status = ZwDeviceIoControlFile(hMntMgr, hEvent, NULL, NULL, &iosb, IOCTL_MOUNTMGR_CHANGE_NOTIFY,
				&mcni1, sizeof(mcni1), &mcni2, sizeof(mcni2));

			if (!NT_SUCCESS(status)) {
				bsr_err(1, BSR_LC_DRIVER, NO_OBJECT,"ZwDeviceIoControl with IOCTL_MOUNTMGR_CHANGE_NOTIFY has been failed, status : 0x%x", status);
				break;
			} else if (STATUS_PENDING == status) {
				status = ZwWaitForSingleObject(hEvent, TRUE, NULL);
			}

			// we've got notification, refresh all volume and adjust changes if necessary.
			HANDLE hVolRefresher = NULL;
			status = PsCreateSystemThread(&hVolRefresher, THREAD_ALL_ACCESS, NULL, NULL, NULL, adjust_changes_to_volume, NULL);
			if (!NT_SUCCESS(status)) {
				bsr_err(4, BSR_LC_THREAD, NO_OBJECT,"PsCreateSystemThread for adjust_changes_to_volume failed, status : 0x%x", status);
				break;
			}

			if (NULL != hVolRefresher) {
				ZwClose(hVolRefresher);
				hVolRefresher = NULL;
			}
			
			// prepare for next change.
			mcni1.EpicNumber = mcni2.EpicNumber;
		}

	} while (0);

	atomic_set(&g_monitor_mnt_working, FALSE);

	if (NULL != hMntMgr) {
		ZwClose(hMntMgr);
		hMntMgr = NULL;
	}
}

// DW-1105 start monitoring mount change thread.
NTSTATUS start_mnt_monitor()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE	hVolMonitor = NULL;

	status = PsCreateSystemThread(&hVolMonitor, THREAD_ALL_ACCESS, NULL, NULL, NULL, monitor_mnt_change, NULL);
	if (!NT_SUCCESS(status)) {
		bsr_err(5, BSR_LC_THREAD, NO_OBJECT,"PsCreateSystemThread for monitor_mnt_change failed with status 0x%08X", status);
		return status;
	}

	if (NULL != hVolMonitor) {
		ZwClose(hVolMonitor);
		hVolMonitor = NULL;
	}

	return status;
}
#endif 

// DW-1105 stop monitoring mount change thread.
void stop_mnt_monitor()
{
	atomic_set(&g_monitor_mnt_working, FALSE);
}

// BSR-109 function disable
#if 0
/**
 * @brief
 *	refresh all VOLUME_EXTENSION's values
 */
void refresh_targetdev_list()
{
    PROOT_EXTENSION proot = mvolRootDeviceObject->DeviceExtension;

    MVOL_LOCK();
    for (PVOLUME_EXTENSION pvext = proot->Head; pvext; pvext = pvext->Next) {
        update_targetdev(pvext, TRUE);
    }
    MVOL_UNLOCK();
}
#endif

/**
 * @brief
 */
PVOLUME_EXTENSION get_targetdev_by_minor(unsigned int minor, bool bUpdatetargetdev)
{
	char path[3] = { (char)(minor_to_letter(minor)), ':', '\0' };
	struct block_device * dev = blkdev_get_by_path(path, (fmode_t)0, NULL, bUpdatetargetdev);
	if (IS_ERR(dev)) {
		return NULL;
	}

	return dev->bd_disk->pDeviceExtension;
}

/**
 * @return
 *	volume size per byte
 */
LONGLONG get_targetdev_volsize(PVOLUME_EXTENSION VolumeExtension)
{
	LARGE_INTEGER	volumeSize;
	NTSTATUS		status;
	
	if (VolumeExtension->TargetDeviceObject == NULL) {
		bsr_err(1, BSR_LC_VOLUME, NO_OBJECT, "Failed to get volume size due to volume information check failure.");
		return (LONGLONG)0;
	}
	status = mvolGetVolumeSize(VolumeExtension->TargetDeviceObject, &volumeSize);
	if (!NT_SUCCESS(status)) {
		bsr_warn(42, BSR_LC_VOLUME, NO_OBJECT, "Failed to get volume size (error = 0x%x)", status);
		volumeSize.QuadPart = 0;
	}
	return volumeSize.QuadPart;
}

#define BSR_REGISTRY_VOLUMES       L"\\volumes"

/**
* @brief   create block_device by referencing to VOLUME_EXTENSION object.
*          a created block_device must be freed by ExFreePool() elsewhere.
*/
struct block_device * create_bsr_block_device(IN OUT PVOLUME_EXTENSION pvext)
{
    struct block_device * dev;

	// DW-1109 need to increase reference count of device object to guarantee not to be freed while we're using.
	ObReferenceObject(pvext->DeviceObject);

    dev = kmalloc(sizeof(struct block_device), 0, 'C5SB');
    if (!dev) {
		bsr_err(20, BSR_LC_MEMORY, NO_OBJECT, "Failed to create bsr block device due to failure to allocate %d size memory for block device", sizeof(struct block_device));
        return NULL;
    }

	dev->bd_contains = kmalloc(sizeof(struct block_device), 0, 'D5SB');
	if (!dev->bd_contains) {
		bsr_err(21, BSR_LC_MEMORY, NO_OBJECT, "Failed to create bsr block device due to failure to allocate %d size memory for block device contains", sizeof(struct block_device));
        return NULL;
    }

	dev->bd_disk = alloc_disk(0);
	if (!dev->bd_disk) {
		bsr_err(22, BSR_LC_MEMORY, NO_OBJECT, "Failed to create bsr block device due to failure to allocate %d size memory for gendisk", sizeof(struct gendisk));
		goto gendisk_failed;
	}

	dev->bd_disk->queue = bsr_blk_alloc_queue();
	if (!dev->bd_disk->queue) {
		bsr_err(23, BSR_LC_MEMORY, NO_OBJECT, "Failed to create bsr block device due to failure to allocate %d size memory for request queue", sizeof(struct request_queue));
		goto request_queue_failed;
	}
		
	kref_init(&dev->kref);

	dev->bd_contains->bd_disk = dev->bd_disk;
	dev->bd_contains->bd_parent = dev;

	_snprintf(dev->bd_disk->disk_name, sizeof(dev->bd_disk->disk_name) - 1, "bsr%d", pvext->Minor);
	dev->bd_disk->pDeviceExtension = pvext;

	dev->bd_disk->queue->logical_block_size = 512;

    return dev;

request_queue_failed:
    kfree(dev->bd_disk);

gendisk_failed:
    kfree(dev);

	return NULL;
}

// DW-1109 delete bsr bdev when ref cnt gets 0, clean up all resources that has been created in create_bsr_block_device.
void delete_bsr_block_device(struct kref *kref)
{
	struct block_device *bdev = container_of(kref, struct block_device, kref);

	// DW-2081 pDeviceExtension shall only be referred to before calling ObDereferenceObject(). This is because the device may already be the device from which the IoDeleteDevice() has been called.
	// DW-1381: set dev as NULL not to access from this volume extension since it's being deleted.
	bdev->bd_disk->pDeviceExtension->dev = NULL;
	// DW-1109: reference count has been increased when we create block device, decrease here.
	ObDereferenceObject(bdev->bd_disk->pDeviceExtension->DeviceObject);

	blk_cleanup_queue(bdev->bd_disk->queue);

	put_disk(bdev->bd_disk);

	kfree2(bdev->bd_contains);
	kfree2(bdev);
}

// get device with volume extension in safe, user should put ref when no longer use device.
struct bsr_device *get_device_with_vol_ext(PVOLUME_EXTENSION pvext, bool bCheckRemoveLock)
{
	unsigned char oldIRQL = 0;
	struct bsr_device *device = NULL;

	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		return NULL;

	// DW-1381 dev is set as NULL when block device is destroyed.
	if (!pvext->dev) {
		bsr_err(4, BSR_LC_VOLUME, NO_OBJECT,"Failed to get bsr device due to no block device is assigned");
		return NULL;		
	}

	// DW-1381 check if device is removed already.
	if (bCheckRemoveLock) {
		NTSTATUS status = IoAcquireRemoveLock(&pvext->RemoveLock, NULL);
		if (!NT_SUCCESS(status)) {
			bsr_err(5, BSR_LC_VOLUME, NO_OBJECT,"Failed to get bsr device due to failure to acquire remove lock with status(0x%x)", status);
			return NULL;
		}
	}

	oldIRQL = ExAcquireSpinLockShared(&pvext->dev->bd_disk->bsr_device_ref_lock);
	device = pvext->dev->bd_disk->bsr_device;
	if (device) {
		if (kref_get(&device->kref)) {
			// already destroyed.
			atomic_dec(&device->kref);			
			device = NULL;
		}
	}
	ExReleaseSpinLockShared(&pvext->dev->bd_disk->bsr_device_ref_lock, oldIRQL);

	if (bCheckRemoveLock)
		IoReleaseRemoveLock(&pvext->RemoveLock, NULL);

	return device;
}

/**
* @brief  get letter from  minor and than return registry status 
*/
BOOLEAN do_add_minor(unsigned int minor)
{
    OBJECT_ATTRIBUTES           attributes;
    PKEY_FULL_INFORMATION       keyInfo = NULL;
    PKEY_VALUE_FULL_INFORMATION valueInfo = NULL;
    size_t                      valueInfoSize = sizeof(KEY_VALUE_FULL_INFORMATION) + 1024 + sizeof(ULONGLONG);
    NTSTATUS                    status;
    HANDLE                      hKey = NULL;
    ULONG                       size = 0;
    int                         count;
    bool                        ret = FALSE;

    PROOT_EXTENSION             prext = mvolRootDeviceObject->DeviceExtension;

    PAGED_CODE();

    PWCHAR new_reg_buf = (PWCHAR)ExAllocatePoolWithTag(PagedPool, MAX_TEXT_BUF, '93SB');
    if (!new_reg_buf) {
		bsr_err(6, BSR_LC_MEMORY, NO_OBJECT, "Failed to get a minor from the registry due to failure to allocate %d size regestry memory.", MAX_TEXT_BUF);
        return FALSE;
    }

    UNICODE_STRING new_reg = {0, MAX_TEXT_BUF, new_reg_buf};
	if (!prext->RegistryPath.Buffer) {
		goto cleanup;
	}
    RtlCopyUnicodeString(&new_reg, &prext->RegistryPath);
    RtlAppendUnicodeToString(&new_reg, BSR_REGISTRY_VOLUMES);

    InitializeObjectAttributes(&attributes,
        &new_reg,
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

    keyInfo = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, size, 'A3SB');
    if (!keyInfo) {
        status = STATUS_INSUFFICIENT_RESOURCES;
		bsr_err(7, BSR_LC_MEMORY, NO_OBJECT, "Failed to get a minor from the registry due to failure to allocate %u size memory for regestry key", size);
        goto cleanup;
    }

    status = ZwQueryKey(hKey, KeyFullInformation, keyInfo, size, &size);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    count = keyInfo->Values;

    valueInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoSize, 'B3SB');
    if (!valueInfo) {
        status = STATUS_INSUFFICIENT_RESOURCES;
		bsr_err(8, BSR_LC_MEMORY, NO_OBJECT, "Failed to get a minor from the registry due to failure to allocate %u size memory for regestry value", valueInfoSize);
        goto cleanup;
    }

    for (int i = 0; i < count; ++i) {
        RtlZeroMemory(valueInfo, valueInfoSize);

        status = ZwEnumerateValueKey(hKey, i, KeyValueFullInformation, valueInfo, (ULONG)valueInfoSize, &size);

        if (!NT_SUCCESS(status)) {
            if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
                goto cleanup;
            }
        }

        if (REG_BINARY == valueInfo->Type) {
            WCHAR temp = (WCHAR)toupper(valueInfo->Name[0]);
            if (minor == (unsigned int)(temp - L'C')) {
                ret = true;
                goto cleanup;
            }
        }
    }

cleanup:
    kfree(new_reg_buf);
    kfree(keyInfo);
    kfree(valueInfo);

    if (hKey) {
        ZwClose(hKey);
    }

    return ret;
}

/**
 * @brief
 *	Compare link string between unix and windows styles
 *	consider:
 *	- '/' equal '\'
 *	- ignore if last character is '/', '\', ':'
 *	- '?' equal '\' in case windows  
 */
// BSR-109 UNICODE_STRING, WCHAR comparison
bool is_equal_volume_link(
	_In_ UNICODE_STRING * lhs,
	_In_ WCHAR * rhs,
	_In_ bool case_sensitive)
{
	WCHAR* l = lhs->Buffer;
	size_t rlen = wcslen(rhs) * sizeof(WCHAR);
	USHORT index = 0;
	int gap = (int)(lhs->Length - rlen);

	if ( !l || !rhs || (abs(gap) > sizeof(WCHAR)) ) {
		return false;
	}
	


	for (; index < min(lhs->Length, rlen); ++l, ++rhs, index += sizeof(WCHAR)) {

		if ((*l == *rhs) ||
			(('/' == *l || '\\' == *l || '?' == *l) && ('/' == *rhs || '\\' == *rhs || '?' == *rhs)) ||
			(case_sensitive ? false : toupper(*l) == toupper(*rhs))) {
			continue;
		}

		return false;
	}

	if (0 == gap) {
		return true;
	}

	// if last character is '/', '\\', ':', then consider equal
	WCHAR t = (gap > 0) ? *l : *rhs;
	if (('/' == t || '\\' == t || ':' == t)) {
		return true;
	}

	return false;
}

/**
 * @brief
 *	exceptional case
 *	"////?//Volume{d41d41d1-17fb-11e6-bb93-000c29ac57ee}//" by cli
 *	to
 *	"\\\\?\\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\\"
 *	f no block_device allocated, then query
 */
static void _adjust_guid_name(char * dst, size_t dst_len, const char * src)
{
	const char token[] = "Volume{";
	char * start = strstr(src, token);
	if (start) {
		strncpy(dst, "\\\\?\\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\\", dst_len - 1);
		char * end = strstr(src, "}");
		char * t3 = strstr(dst, token);
		if (t3 && end)
			memcpy(t3, start, (int)(end - start));
	}
 	else {
		strncpy(dst, src, dst_len - 1);
	}
}

/**
 * @brief
 *	link is below 
 *	- "\\\\?\\Volume{d41d41d1-17fb-11e6-bb93-000c29ac57ee}\\"
 *	- "d" or "d:"
 *	- "c/vdrive" or "c\\vdrive"
 *	f no block_device allocated, then query
 */
struct block_device *blkdev_get_by_link(UNICODE_STRING * name, bool bUpdatetargetdev)
{
	UNREFERENCED_PARAMETER(bUpdatetargetdev);

	ROOT_EXTENSION* pRoot = mvolRootDeviceObject->DeviceExtension;
	VOLUME_EXTENSION* pVExt = pRoot->Head;
	VOLUME_EXTENSION* pRetVExt = NULL;
		
	MVOL_LOCK();
	for (; pVExt; pVExt = pVExt->Next) {
		// BSR-109 disable this feature as a change in how mount information is updated
#if 0
		// DW-1728 update the volume's GUID information again for a volume without a GUID (VHD).
		if(IsEmptyUnicodeString(&pVExt->VolumeGuid)) { 
			update_targetdev(pVExt, TRUE);
		} else {
			update_targetdev(pVExt, FALSE);
		}

		UNICODE_STRING * plink = MOUNTMGR_IS_VOLUME_NAME(name) ?
			&pVExt->VolumeGuid : &pVExt->MountPoint;
		
		if (plink && is_equal_volume_link(name, plink, false)) {
#endif
		WCHAR *plink = MOUNTMGR_IS_VOLUME_NAME(name) ?
			pVExt->VolumeGuid : pVExt->MountPoint;
		if (plink && is_equal_volume_link(name, plink, false)) {
			// break;	
			// DW-1702 fixup the logic to perform update_targetdev on all volumes at blkdev_get_by_link. Even if found VExt, no break;
			pRetVExt = pVExt;
		}
	}
	MVOL_UNLOCK();

	return (pRetVExt) ? pRetVExt->dev : NULL;
}

struct block_device *blkdev_get_by_path(const char *path, fmode_t mode, void *holder, bool bUpdatetargetdev)
{
	UNREFERENCED_PARAMETER(mode);
	UNREFERENCED_PARAMETER(holder);

	ANSI_STRING apath;
	UNICODE_STRING upath;
	char cpath[64] = { 0, };

	_adjust_guid_name(cpath, sizeof(cpath), path);

	RtlInitAnsiString(&apath, cpath);
	NTSTATUS status = RtlAnsiStringToUnicodeString(&upath, &apath, TRUE);
	if (!NT_SUCCESS(status)) {
		bsr_warn(43, BSR_LC_VOLUME, NO_OBJECT, "Failed to change path Unicode (%s)", path);
		return ERR_PTR(-EINVAL);
	}

	struct block_device * dev = blkdev_get_by_link(&upath, bUpdatetargetdev);
	RtlFreeUnicodeString(&upath);

	return dev ? dev : ERR_PTR(-ENODEV);
}

void dumpHex(const void *aBuffer, const size_t aBufferSize, size_t aWidth)
{
	char           sHexBuffer[6] = {0};  
	size_t         sLineSize;  
	size_t         sLineLength;    /* the number of bytes printed in a line */  
	char          *sLine = NULL;  
	size_t         sPos = 0;  
	size_t         i;  

	const uint8_t *sBuffer = (const uint8_t *)aBuffer;  
	const size_t   sAddrAreaSize = 6; /* address column (e.g. FFFF  ) */  
	const size_t   sColWidth     = 4; /* the number of bytes that consists a column (FF FF FF FF  FF FF FF FF  ) */  

	aWidth = ((aWidth + (sColWidth - 1)) / sColWidth) * sColWidth;  

	const size_t  sHexAreaSize = (aWidth * 3) + /* 3 chars required to display a byte (FF ) - including trailing space */
		(aWidth / sColWidth);  /* to distinguish a column by inserting additional space */

	const size_t  sCharAreaStartPos = sAddrAreaSize + sHexAreaSize;
	sLineSize = sAddrAreaSize + sHexAreaSize + aWidth + 1; /* Null terminator */
#ifdef _WIN64
	BUG_ON_INT32_OVER(sLineSize);
#endif
	sLine = (char *) kmalloc((int)sLineSize, 0, '54SB');
	if (!sLine) {
		bsr_err(9, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate %d size memory for line", sLineSize);
		return;
	}

	*(sLine + sLineSize - 1) = '\0';

	bsr_info(5, BSR_LC_ETC, NO_OBJECT, "Dump changed to hexadecimal. addr(0x%p), size(%d). width(%d)", aBuffer, aBufferSize, aWidth);

	while (sPos < aBufferSize) {
		memset(sLine, ' ', sLineSize - 1);
		sLineLength = ((aBufferSize - sPos) > aWidth) ? aWidth : (aBufferSize - sPos);

		/* Address */
		//snprintf(sHexBuffer, sizeof(sHexBuffer), "%04X:", (uint16_t) (sPos & 0xFFFF));
		memset(sHexBuffer, 0, 6);
		_snprintf(sHexBuffer, sizeof(sHexBuffer) - 1, "%04X:", (uint16_t)(sPos & 0xFFFF));
		memcpy(sLine, sHexBuffer, 5);

		/* Hex part */
		for (i = 0; i < sLineLength; i++) {
			//snprintf(sHexBuffer, sizeof(sHexBuffer), "%02X", *(sBuffer + sPos + i));
			memset(sHexBuffer, 0, 6);
			_snprintf(sHexBuffer, sizeof(sHexBuffer) - 1, "%02X", *(sBuffer + sPos + i));
			memcpy(sLine + sAddrAreaSize + (i * 3) + (i / sColWidth), sHexBuffer, 2);
		}

		/* Character part */
		for (i = 0; i < sLineLength; i++) {
			uint8_t sByte = *(sBuffer + sPos + i);
			*(sLine + sCharAreaStartPos + i) = (sByte < 127 && sByte >= 0x20) ? (char) sByte : '.';
		}
		sPos += aWidth;
		bsr_info(6, BSR_LC_ETC, NO_OBJECT, "%s", sLine);
	}
	kfree(sLine);
}

int call_usermodehelper(char *path, char **argv, char **envp, unsigned int wait)
{
	UNREFERENCED_PARAMETER(wait);
	UNREFERENCED_PARAMETER(envp);

	SOCKADDR_IN		LocalAddress = { 0 }, RemoteAddress = { 0 };
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;
	//PWSK_SOCKET		Socket = NULL;
	char *cmd_line;
	int leng;
	char ret = 0;
	struct socket* pSock = NULL;
	int handler_timeout = atomic_read(&g_handler_timeout);

	if (0 == atomic_read(&g_handler_use))	{
		return -1;
	}

	pSock = kzalloc(sizeof(struct socket), 0, 'C0SB');
	if (!pSock) {
		bsr_err(10, BSR_LC_MEMORY, NO_OBJECT, "Failed to usermodehelper execution due to failure to allocate %d size memory for socket", sizeof(struct socket));
		return -1;
	}
#ifdef _WIN64
	BUG_ON_INT32_OVER(strlen(path) + 1 + strlen(argv[0]) + 1 + strlen(argv[1]) + 1 + strlen(argv[2]) + 1);
#endif
	leng = (int)(strlen(path) + 1 + strlen(argv[0]) + 1 + strlen(argv[1]) + 1 + strlen(argv[2]) + 1);
	cmd_line = kcalloc(leng, 1, 0, '64SB');
	if (!cmd_line) {
		bsr_err(11, BSR_LC_MEMORY, NO_OBJECT, "Failed to usermodehelper execution due to failure to allocate %d size memory for command line", leng);
		if(pSock) {
			kfree(pSock);
		}
		return -1;
	}

	_snprintf(cmd_line, leng - 1, "%s %s\0", argv[1], argv[2]); // except "bsradm.exe" string
	bsr_debug(12, BSR_LC_MEMORY, NO_OBJECT, "command(%s), allocate length (%d)", cmd_line, leng);

    pSock->sk = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSK_FLAG_CONNECTION_SOCKET);
	if (pSock->sk == NULL) {
		bsr_err(2, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to failure to create socket");
		kfree(cmd_line);
		if(pSock) {
			kfree(pSock);
		}
		return -1; 
	}

	LocalAddress.sin_family = AF_INET;
	LocalAddress.sin_addr.s_addr = INADDR_ANY;
	LocalAddress.sin_port = 0; 

	Status = Bind(pSock, (PSOCKADDR) &LocalAddress);
	if (!NT_SUCCESS(Status)) {
		goto error;
	}

	RemoteAddress.sin_family = AF_INET;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b1 = 127;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b2 = 0;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b3 = 0;
	RemoteAddress.sin_addr.S_un.S_un_b.s_b4 = 1;
	RemoteAddress.sin_port = HTONS(g_daemon_tcp_port); 

	Status = Connect(pSock, (PSOCKADDR) &RemoteAddress);
	if (!NT_SUCCESS(Status)) {
		bsr_warn(106, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to connect not completed. status(%x), IRQL(%d)", Status, KeGetCurrentIrql());
		ret = -1;
		goto error;
	} else if (Status == STATUS_TIMEOUT) {
		bsr_warn(3, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to connect not completed in time-out. IRQL(%d)", KeGetCurrentIrql());
		ret = -1;
		goto error;
	}

	bsr_debug(4, BSR_LC_SOCKET, NO_OBJECT, "Connected to the %u.%u.%u.%u:%u. status(0x%08X) IRQL(%d)",
			RemoteAddress.sin_addr.S_un.S_un_b.s_b1,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b2,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b3,
			RemoteAddress.sin_addr.S_un.S_un_b.s_b4,
			HTONS(RemoteAddress.sin_port),
			Status, KeGetCurrentIrql());

	{
		LONG readcount;
		char hello[32];
		memset(hello, 0, sizeof(hello));

		bsr_debug(82, BSR_LC_SOCKET, NO_OBJECT, "Wait Hi");

		// DW-2170 the first received data after connection must be the same as DRBD_DAEMON_SOCKET_STRING.
		if ((readcount = Receive(pSock, &hello, (long)strlen(BSR_DAEMON_SOCKET_STRING), 0, handler_timeout, NULL)) == (long)strlen(BSR_DAEMON_SOCKET_STRING)) {
			bsr_debug(83, BSR_LC_SOCKET, NO_OBJECT, "recv HI!!! ");
		} else {
			if (readcount == -EAGAIN) {
				bsr_err(5, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to timeout(%d) occurred for receiving Hello. Retry(%d)", g_handler_timeout, g_handler_retry);
			} else {
				bsr_err(6, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to failure to receive. status(0x%x)", readcount);

			}
			ret = -1;

			// _WIN_HANDLER_TIMEOUT
			goto error;
		}

		if (0 != memcmp(hello, BSR_DAEMON_SOCKET_STRING, strlen(BSR_DAEMON_SOCKET_STRING))) {
			bsr_err(107, BSR_LC_SOCKET, NO_OBJECT, "this is not a daemon connection.\n");
			goto error;
		}

		// DW-2170 send DRBD_DAEMON_SOCKET_STRING.
		if ((Status = SendLocal(pSock, BSR_DAEMON_SOCKET_STRING, (unsigned int)strlen(BSR_DAEMON_SOCKET_STRING), 0, handler_timeout)) != (long)strlen(BSR_DAEMON_SOCKET_STRING)) {
			bsr_err(108, BSR_LC_SOCKET, NO_OBJECT, "send socket string fail stat=0x%x\n", Status);
			ret = -1;
			goto error;
		}

		if ((Status = SendLocal(pSock, cmd_line, (unsigned int)strlen(cmd_line), 0, handler_timeout)) != (long)strlen(cmd_line)) {
			bsr_err(7, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to failure to send command. status(0x%x)", Status);
			ret = -1;
			goto error;
		}

		if ((readcount = Receive(pSock, &ret, 1, 0, handler_timeout, NULL)) > 0) {
			bsr_debug(84, BSR_LC_SOCKET, NO_OBJECT, "recv val=0x%x", ret);
		} else {
			if (readcount == -EAGAIN) {
				bsr_err(8, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to receive timed out(%d)", handler_timeout);
			} else {
				bsr_err(9, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to failure to receive. status(0x%x)", readcount);
			}
			ret = -1;
			goto error;
		}


		if ((Status = SendLocal(pSock, "BYE", 3, 0, handler_timeout)) != 3) {
			bsr_err(10, BSR_LC_SOCKET, NO_OBJECT, "Failed to usermodehelper execution due to failure to send finished. status(0x%x)", Status); // ignore!
		}

		bsr_debug(85, BSR_LC_SOCKET, NO_OBJECT, "Disconnect:shutdown...", Status);
		Disconnect(pSock);

#if 0
		if ((readcount = Receive(Socket, &ret, 1, 0, 0)) > 0) {
			bsr_info(11, BSR_LC_SOCKET, NO_OBJECT,"recv dummy  val=0x%x", ret);// ignore!
		} else {
			bsr_info(12, BSR_LC_SOCKET, NO_OBJECT,"recv dummy  status=%d", readcount);// ignore!
		}
#endif
	}

error:
	CloseSocket(pSock);
	kfree(cmd_line);
	if(pSock) {
		kfree(pSock);
	}
	return ret;
}

void panic(char *msg)
{
    bsr_err(9, BSR_LC_IO_ERROR, NO_OBJECT,"%s", msg);
#ifdef _WIN_EVENTLOG
	WriteEventLogEntryData((ULONG) DEV_ERR_3003, 0, 0, 1, L"%S", msg);
#endif
// DW-1587 
//	The code that caused the BugCheck was written as needed.
#pragma warning (disable: 28159)
	KeBugCheckEx(0xddbd, (ULONG_PTR)__FILE__, (ULONG_PTR)__func__, 0x12345678, 0xd8bdd8bd);
#pragma warning (default: 28159)
}

int scnprintf(char * buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i = 0;

	va_start(args, fmt);
	i = _vsnprintf(buf, size - 1, fmt, args);
	va_end(args);

	return (int)((-1 == i) ? (size - 1) : i);
}

int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}

void __list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry)
{
	struct list_head *new_first = entry->next;
	list->next = head->next;
	list->next->prev = list;
	list->prev = entry;
	entry->next = list;
	head->next = new_first;
	new_first->prev = head;
}
// from linux kernel 3.14 
void list_cut_position(struct list_head *list, struct list_head *head, struct list_head *entry)
{
	if (list_empty(head))
		return;
	if (list_is_singular(head) &&
		(head->next != entry && head != entry))
		return;
	if (entry == head)
		INIT_LIST_HEAD(list);
	else
		__list_cut_position(list, head, entry);
}

int bsr_backing_bdev_events(struct bsr_device *device)
{
#ifdef _WIN_GetDiskPerf
	extern NTSTATUS mvolGetDiskPerf(PDEVICE_OBJECT TargetDeviceObject, PDISK_PERFORMANCE pDiskPerf);
	NTSTATUS status;
	DISK_PERFORMANCE diskPerf;

	status = mvolGetDiskPerf(mdev->ldev->backing_bdev->bd_disk->pDeviceExtension->TargetDeviceObject, &diskPerf);
	if (!NT_SUCCESS(status)) {
		bsr_err(8, BSR_LC_ETC, NO_OBJECT,"mvolGetDiskPerf status=0x%x", status);
		return mdev->writ_cnt + mdev->read_cnt;
	}
	// bsr_info(9, BSR_LC_ETC, NO_OBJECT,"mdev: %d + %d = %d, diskPerf: %lld + %lld = %lld",
	//		mdev->read_cnt, mdev->writ_cnt, mdev->writ_cnt + mdev->read_cnt,
	//		diskPerf.BytesRead.QuadPart/512, diskPerf.BytesWritten.QuadPart/512,
	//		diskPerf.BytesRead.QuadPart/512 + diskPerf.BytesWritten.QuadPart/512);

	return (diskPerf.BytesRead.QuadPart / 512) + (diskPerf.BytesWritten.QuadPart / 512);
#else
	if ((device->writ_cnt + device->read_cnt) == 0) {
		// initial value
		return 100;
	}
	return device->writ_cnt + device->read_cnt;
#endif
}

char * get_ip4(char *buf, size_t len, struct sockaddr_in *sockaddr)
{
	_snprintf(buf, len - 1, "%u.%u.%u.%u:%u\0",
		sockaddr->sin_addr.S_un.S_un_b.s_b1,
		sockaddr->sin_addr.S_un.S_un_b.s_b2,
		sockaddr->sin_addr.S_un.S_un_b.s_b3,
		sockaddr->sin_addr.S_un.S_un_b.s_b4,
		HTONS(sockaddr->sin_port)
		);
	return buf;
}

char * get_ip6(char *buf, size_t len, struct sockaddr_in6 *sockaddr)
{
	_snprintf(buf, len - 1, "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u\0",
			sockaddr->sin6_addr.u.Byte[0],
			sockaddr->sin6_addr.u.Byte[1],
			sockaddr->sin6_addr.u.Byte[2],
			sockaddr->sin6_addr.u.Byte[3],
			sockaddr->sin6_addr.u.Byte[4],
			sockaddr->sin6_addr.u.Byte[5],
			sockaddr->sin6_addr.u.Byte[6],
			sockaddr->sin6_addr.u.Byte[7],
			sockaddr->sin6_addr.u.Byte[8],
			sockaddr->sin6_addr.u.Byte[9],
			sockaddr->sin6_addr.u.Byte[10],
			sockaddr->sin6_addr.u.Byte[11],
			sockaddr->sin6_addr.u.Byte[12],
			sockaddr->sin6_addr.u.Byte[13],
			sockaddr->sin6_addr.u.Byte[14],
			sockaddr->sin6_addr.u.Byte[15],
			HTONS(sockaddr->sin6_port)
			);
	return buf;
}

struct blk_plug_cb *blk_check_plugged(blk_plug_cb_fn unplug, void *data, int size)
{
	UNREFERENCED_PARAMETER(size);
	UNREFERENCED_PARAMETER(unplug);
	UNREFERENCED_PARAMETER(data);

	return NULL;
}
/* Save current value in registry, this value is used when bsr is loading.*/
NTSTATUS SaveCurrentValue(PCWSTR valueName, int value)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PROOT_EXTENSION pRootExtension = NULL;
	UNICODE_STRING usValueName = { 0, };
	OBJECT_ATTRIBUTES oa = { 0, };
	HANDLE hKey = NULL;

	if (NULL == mvolRootDeviceObject ||
		NULL == mvolRootDeviceObject->DeviceExtension)
		return STATUS_UNSUCCESSFUL;

	do {
		pRootExtension = mvolRootDeviceObject->DeviceExtension;

		InitializeObjectAttributes(&oa, &pRootExtension->RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
		if (!NT_SUCCESS(status))
			break;

		RtlInitUnicodeString(&usValueName, valueName);
		status = ZwSetValueKey(hKey, &usValueName, 0, REG_DWORD, &value, sizeof(value));
		if (!NT_SUCCESS(status))
			break;

	} while (false);

	if (NULL != hKey) {
		ZwClose(hKey);
		hKey = NULL;
	}

	return status;
}

// DW-1469
int bsr_resize(struct bsr_device *device)
{
	struct disk_conf *old_disk_conf, *new_disk_conf = NULL;
	struct resize_parms rs;
	enum bsr_ret_code retcode = 0;
	enum determine_dev_size dd;
	bool change_al_layout = false;
	enum dds_flags ddsf;
	sector_t u_size;
	struct bsr_peer_device *peer_device;
	
	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto fail;
	}

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] > L_ESTABLISHED)
			bsr_err(6, BSR_LC_VOLUME, device, "Unable to resize during resync. disconnecting..");
		else if (peer_device->repl_state[NOW] == L_ESTABLISHED)
			bsr_err(7, BSR_LC_VOLUME, device, "Unable to resize in establised state. disconnecting..");
		else
			continue;
		change_cstate_ex(peer_device->connection, C_DISCONNECTING, CS_HARD);
	}		

	memset(&rs, 0, sizeof(struct resize_parms));
	rs.al_stripes = device->ldev->md.al_stripes;
	rs.al_stripe_size = device->ldev->md.al_stripe_size_4k * 4;	
	rs.no_resync = 1;	// Do not run a resync for the new space
	rs.resize_force = 1;

	rcu_read_lock();
	u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
	rcu_read_unlock();
	if (u_size != (sector_t)rs.resize_size) {
		new_disk_conf = kmalloc(sizeof(struct disk_conf), GFP_KERNEL, 'C1SB');
		if (!new_disk_conf) {
			retcode = ERR_NOMEM;
			goto fail_ldev;
		}
	}

	if (device->ldev->md.al_stripes != rs.al_stripes ||
		device->ldev->md.al_stripe_size_4k != rs.al_stripe_size / 4) {
		u32 al_size_k = rs.al_stripes * rs.al_stripe_size;

		if (al_size_k > (16 * 1024 * 1024)) {
			retcode = ERR_MD_LAYOUT_TOO_BIG;
			goto fail_ldev;
		}

		if (al_size_k < (32768 >> 10)) {
			retcode = ERR_MD_LAYOUT_TOO_SMALL;
			goto fail_ldev;
		}

		change_al_layout = true;
	}

	device->ldev->known_size = bsr_get_capacity(device->ldev->backing_bdev);
	if (new_disk_conf) {
		mutex_lock(&device->resource->conf_update);
		old_disk_conf = device->ldev->disk_conf;
		*new_disk_conf = *old_disk_conf;
		new_disk_conf->disk_size = (sector_t)rs.resize_size;		
		synchronize_rcu_w32_wlock();
		rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
		mutex_unlock(&device->resource->conf_update);
		synchronize_rcu();
		kfree(old_disk_conf);
		new_disk_conf = NULL;			
	}

	ddsf = (rs.resize_force ? DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE : 0)
		| (rs.no_resync ? DDSF_NO_RESYNC : 0);

	dd = bsr_determine_dev_size(device, 0, ddsf, change_al_layout ? &rs : NULL);

	bsr_md_sync_if_dirty(device);
	put_ldev(__FUNCTION__, device);
	if (dd == DS_ERROR) {
		retcode = ERR_NOMEM_BITMAP;
		goto fail;
	} else if (dd == DS_ERROR_SPACE_MD) {
		retcode = ERR_MD_LAYOUT_NO_FIT;
		goto fail;
	} else if (dd == DS_ERROR_SHRINK) {
		retcode = ERR_IMPLICIT_SHRINK;
		goto fail;
	} else if (dd == DS_2PC_ERR) {
		retcode = SS_INTERRUPTED;
		goto fail;
	}

 fail:
	return retcode;

 fail_ldev:
	put_ldev(__FUNCTION__, device);
	kfree(new_disk_conf);
	goto fail;
}

char *kvasprintf(int flags, const char *fmt, va_list args)
{
	char *buffer;
	const int size = 4096;
	NTSTATUS status;

	buffer = kzalloc(size, flags, 'AVSB');
	if (buffer) {
		status = RtlStringCchVPrintfA(buffer, size, fmt, args);
		if (status == STATUS_SUCCESS)
			return buffer;

		kfree(buffer);
	}

	return NULL;
}

bool IsDiskError()
{
	bool bErr = FALSE;
	if( gSimulDiskIoError.ErrorFlag == SIMUL_DISK_IO_ERROR_FLAG1) {
		bErr = TRUE;
	}
	if( (gSimulDiskIoError.ErrorFlag == SIMUL_DISK_IO_ERROR_FLAG2) && gSimulDiskIoError.ErrorCount) {
		bErr = TRUE;
		gSimulDiskIoError.ErrorCount--;
	}
	return bErr;
}

void msleep(int millisecs)
{
	LARGE_INTEGER delay;
	delay.QuadPart = (-1 * millisecs * 10000);
	KeDelayExecutionThread(KernelMode, FALSE, &delay);
}

// BSR-874
extern atomic_t64 g_untagged_mem_usage;

void add_untagged_mem_usage(LONGLONG a)
{
	atomic_add64(a, &g_untagged_mem_usage);
}

void add_untagged_mdl_mem_usage(PVOID buf, ULONG size)
{
	int s = ADDRESS_AND_SIZE_TO_SPAN_PAGES(buf, size);
	if (s > 23) {
		s *= sizeof(PFN_NUMBER);
		s += sizeof(MDL);
	}
	else {
		s = (23 * sizeof(PFN_NUMBER)) + sizeof(MDL);
	}

	add_untagged_mem_usage(s);
}

void sub_untagged_mem_usage(LONGLONG a)
{
	atomic_sub64(a, &g_untagged_mem_usage);
}

void sub_untagged_mdl_mem_usage(PVOID buf, ULONG size)
{
	int s = ADDRESS_AND_SIZE_TO_SPAN_PAGES(buf, size);
	if (s > 23) {
		s *= sizeof(PFN_NUMBER);
		s += sizeof(MDL);
	}
	else {
		s = (23 * sizeof(PFN_NUMBER)) + sizeof(MDL);
	}

	sub_untagged_mem_usage(s);
}