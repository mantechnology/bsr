/*
   bsr_bitmap.c

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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include "bsr_int.h"
#ifdef _WIN
#include "./bsr-kernel-compat/windows/bitops.h"
#include "../bsr-headers/bsr.h"
#include "./bsr-kernel-compat/windows/bsr_endian.h"
#else // _LIN
#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <bsr.h>
#include <linux/slab.h>
#include <linux/dynamic_debug.h>
#endif

/* See the ifdefs and comments inside that header file.
 * On recent kernels this is not needed. */
#include "bsr-kernel-compat/bitops.h"

#ifndef BITS_PER_PAGE
#define BITS_PER_PAGE		(1UL << (PAGE_SHIFT + 3))
#else
# if BITS_PER_PAGE != (1UL << (PAGE_SHIFT + 3))
#  error "ambiguous BITS_PER_PAGE"
# endif
#endif

// DW-917
#define BYTES_PER_BM_WORD	(sizeof(u32))
#define BITS_PER_BM_WORD	(BYTES_PER_BM_WORD << 3)

#ifdef _WIN
IO_COMPLETION_ROUTINE bsr_bm_endio;
#endif

/* OPAQUE outside this file!
 * interface defined in bsr_int.h

 * convention:
 * function name bsr_bm_... => used elsewhere, "public".
 * function name      bm_... => internal to implementation, "private".
 */


/*
 * LIMITATIONS:
 * We want to support >= peta byte of backend storage, while for now still using
 * a granularity of one bit per 4KiB of storage.
 * 1 << 50		bytes backend storage (1 PiB)
 * 1 << (50 - 12)	bits needed
 *	38 --> we need u64 to index and count bits
 * 1 << (38 - 3)	bitmap bytes needed
 *	35 --> we still need u64 to index and count bytes
 *			(that's 32 GiB of bitmap for 1 PiB storage)
 * 1 << (35 - 2)	32bit longs needed
 *	33 --> we'd even need u64 to index and count 32bit long words.
 * 1 << (35 - 3)	64bit longs needed
 *	32 --> we could get away with a 32bit unsigned int to index and count
 *	64bit long words, but I rather stay with unsigned long for now.
 *	We probably should neither count nor point to bytes or long words
 *	directly, but either by bitnumber, or by page index and offset.
 * 1 << (35 - 12)
 *	22 --> we need that much 4KiB pages of bitmap.
 *	1 << (22 + 3) --> on a 64bit arch,
 *	we need 32 MiB to store the array of page pointers.
 *
 * Because I'm lazy, and because the resulting patch was too large, too ugly
 * and still incomplete, on 32bit we still "only" support 16 TiB (minus some),
 * (1 << 32) bits * 4k storage.
 *

 * bitmap storage and IO:
 *	Bitmap is stored little endian on disk, and is kept little endian in
 *	core memory. Currently we still hold the full bitmap in core as long
 *	as we are "attached" to a local disk, which at 32 GiB for 1PiB storage
 *	seems excessive.
 *
 *	We plan to reduce the amount of in-core bitmap pages by paging them in
 *	and out against their on-disk location as necessary, but need to make
 *	sure we don't cause too much meta data IO, and must not deadlock in
 *	tight memory situations. This needs some more work.
 */

/*
 * NOTE
 *  Access to the *bm_pages is protected by bm_lock.
 *  It is safe to read the other members within the lock.
 *
 *  bsr_bm_set_bits is called from bio_endio callbacks,
 *  We may be called with irq already disabled,
 *  so we need spin_lock_irqsave().
 *  And we need the kmap_atomic.
 */

#define bm_print_lock_info(m) __bm_print_lock_info(m, __func__)
static void __bm_print_lock_info(struct bsr_device *device, const char *func)
{
	struct bsr_bitmap *b = device->bitmap;
	if (!bsr_ratelimit())
		return;
	
	// DW-898 at this point bm_task can be NULL.
	bsr_err(8, BSR_LC_BITMAP, device, "FIXME, %s[%d] in %s, bitmap locked for '%s' by %s[%d]",
		current->comm,
		task_pid_nr(current),
		func,
		b->bm_why ? b->bm_why : "?",
		b->bm_task ? b->bm_task->comm : "?",
		b->bm_task ? task_pid_nr(b->bm_task) : 0);
}

/* bsr_bm_lock() was introduced before bsr-9.0 to ensure that access to
   bitmap is locked out by other means (states, etc..). If a needed lock was
   not acquired or already taken a warning gets logged, and the critical
   sections get serialized on a mutex.

   Since bsr-9.0 actions on the bitmap could happen in parallel (e.g. "receive
   bitmap").
   The cheap solution taken right now, is to completely serialize bitmap
   operations but do not warn if they operate on different bitmap slots.

   The real solution is to make the locking more fine grained (one lock per
   bitmap slot) and to allow those operations to happen parallel.
 */
static void
_bsr_bm_lock(struct bsr_device *device, struct bsr_peer_device *peer_device,
	      char *why, enum bm_flag flags)
{
	struct bsr_bitmap *b = device->bitmap;
	int trylock_failed;

	if (!b) {
		bsr_err(9, BSR_LC_BITMAP, device, "FIXME, Failed to lock bitmap due to unable to find lock information for bitmap");
		return;
	}

	trylock_failed = !mutex_trylock(&b->bm_change);

	if (trylock_failed && peer_device && b->bm_locked_peer != peer_device) {
		mutex_lock(&b->bm_change);
		trylock_failed = 0;
	}

	if (trylock_failed) {		
		// DW-962 DW-1778 fix. bm_task can be NULL
		struct task_struct *bm_task = b->bm_task;
		bsr_warn(58, BSR_LC_BITMAP, device, "%s[%d] going to '%s' but bitmap already locked for '%s' by %s[%d]",
			current->comm, 
			task_pid_nr(current),
			why, 
			b->bm_why ? b->bm_why : "?",
			bm_task ? bm_task->comm : "?", 
			bm_task ? task_pid_nr(bm_task) : 0);		
		mutex_lock(&b->bm_change);
	}
	if (b->bm_flags & BM_LOCK_ALL)
		bsr_err(10, BSR_LC_BITMAP, device, "FIXME, Failed to lock bitmap due to already locked in bm_lock");
	// DW-1979
	b->bm_flags |= ((flags & BM_LOCK_ALL) | (flags & BM_LOCK_POINTLESS));

	b->bm_why  = why;
	b->bm_task = current;
	b->bm_locked_peer = peer_device;
}

void bsr_bm_lock(struct bsr_device *device, char *why, enum bm_flag flags)
{
	_bsr_bm_lock(device, NULL, why, flags);
}

void bsr_bm_slot_lock(struct bsr_peer_device *peer_device, char *why, enum bm_flag flags)
{
	_bsr_bm_lock(peer_device->device, peer_device, why, flags);
}

void bsr_bm_unlock(struct bsr_device *device)
{
	struct bsr_bitmap *b = device->bitmap;
	if (!b) {
		bsr_err(11, BSR_LC_BITMAP, device, "FIXME, Failed to lock bitmap due to no bitmap allocated.");
		return;
	}

	if (!(device->bitmap->bm_flags & BM_LOCK_ALL))
		bsr_err(12, BSR_LC_BITMAP, device, "FIXME, Failed to lock bitmap due to no lock is set on bitmap flags.");

	// DW-1979
	b->bm_flags &= ~(BM_LOCK_ALL | BM_LOCK_POINTLESS);
	b->bm_why  = NULL;
	b->bm_task = NULL;
	b->bm_locked_peer = NULL;
	mutex_unlock(&b->bm_change);
}

void bsr_bm_slot_unlock(struct bsr_peer_device *peer_device)
{
	bsr_bm_unlock(peer_device->device);
}

/* we store some "meta" info about our pages in page->private */
/* at a granularity of 4k storage per bitmap bit:
 * one peta byte storage: 1<<50 byte, 1<<38 * 4k storage blocks
 *  1<<38 bits,
 *  1<<23 4k bitmap pages.
 * Use 24 bits as page index, covers 2 peta byte storage
 * at a granularity of 4k per bit.
 * Used to report the failed page idx on io error from the endio handlers.
 */
#define BM_PAGE_IDX_MASK	((1UL<<24)-1)
/* this page is currently read in, or written back */
#define BM_PAGE_IO_LOCK		31
/* if there has been an IO error for this page */
#define BM_PAGE_IO_ERROR	30
/* this is to be able to intelligently skip disk IO,
 * set if bits have been set since last IO. */
#define BM_PAGE_NEED_WRITEOUT	29
/* to mark for lazy writeout once syncer cleared all clearable bits,
 * we if bits have been cleared since last IO. */
#define BM_PAGE_LAZY_WRITEOUT	28
/* pages marked with this "HINT" will be considered for writeout
 * on activity log transactions */
#define BM_PAGE_HINT_WRITEOUT	27

/* store_page_idx uses non-atomic assignment. It is only used directly after
 * allocating the page.  All other bm_set_page_* and bm_clear_page_* need to
 * use atomic bit manipulation, as set_out_of_sync (and therefore bitmap
 * changes) may happen from various contexts, and wait_on_bit/wake_up_bit
 * requires it all to be atomic as well. */
static void bm_store_page_idx(struct page *page, ULONG_PTR idx)
{
	BUG_ON(0 != (idx & ~BM_PAGE_IDX_MASK));
	set_page_private(page, idx);
}
static ULONG_PTR bm_page_to_idx(struct page *page)
{
	return (ULONG_PTR)page_private(page) & BM_PAGE_IDX_MASK;
}

/* As is very unlikely that the same page is under IO from more than one
 * context, we can get away with a bit per page and one wait queue per bitmap.
 */
static void bm_page_lock_io(struct bsr_device *device, int page_nr)
{
	struct bsr_bitmap *b = device->bitmap;
	void *addr = &page_private(b->bm_pages[page_nr]);
	wait_event(b->bm_io_wait, !test_and_set_bit(BM_PAGE_IO_LOCK, addr));
}

static void bm_page_unlock_io(struct bsr_device *device, int page_nr)
{
	struct bsr_bitmap *b = device->bitmap;
	void *addr = &page_private(b->bm_pages[page_nr]);
	clear_bit_unlock(BM_PAGE_IO_LOCK, addr);
	wake_up(&device->bitmap->bm_io_wait);
}

/* set _before_ submit_io, so it may be reset due to being changed
 * while this page is in flight... will get submitted later again */
static void bm_set_page_unchanged(struct page *page)
{
	/* use cmpxchg? */
	clear_bit(BM_PAGE_NEED_WRITEOUT, &page_private(page));
	clear_bit(BM_PAGE_LAZY_WRITEOUT, &page_private(page));
}

static void bm_set_page_need_writeout(struct page *page)
{
	set_bit(BM_PAGE_NEED_WRITEOUT, &page_private(page));
}

void bsr_bm_reset_al_hints(struct bsr_device *device)
{
	device->bitmap->n_bitmap_hints = 0;
}

static int bm_test_page_unchanged(struct page *page)
{
	volatile const ULONG_PTR *addr = &page_private(page);
	return (*addr & ((1UL<<BM_PAGE_NEED_WRITEOUT)|(1UL<<BM_PAGE_LAZY_WRITEOUT))) == 0;
}

static void bm_set_page_io_err(struct page *page)
{
	set_bit(BM_PAGE_IO_ERROR, &page_private(page));
}

static void bm_clear_page_io_err(struct page *page)
{
	clear_bit(BM_PAGE_IO_ERROR, &page_private(page));
}

static void bm_set_page_lazy_writeout(struct page *page)
{
	set_bit(BM_PAGE_LAZY_WRITEOUT, &page_private(page));
}

static int bm_test_page_lazy_writeout(struct page *page)
{
	return test_bit(BM_PAGE_LAZY_WRITEOUT, &page_private(page));
}

/*
 * actually most functions herein should take a struct bsr_bitmap*, not a
 * struct bsr_device*, but for the debug macros I like to have the device around
 * to be able to report device specific.
 */

static void bm_free_pages(struct page **pages, ULONG_PTR number)
{
	ULONG_PTR i;
	if (!pages)
		return;

	for (i = 0; i < number; i++) {
		if (!pages[i]) {
			bsr_alert(13, BSR_LC_BITMAP, NO_OBJECT, "The bitmap page you are trying to unassign does not exist. page index(%lu), total(%lu)",
				 i, number);
			continue;
		}
		__free_page(pages[i]);
		pages[i] = NULL;
	}
}

/*
 * "have" and "want" are NUMBER OF PAGES.
 */
static struct page **bm_realloc_pages(struct bsr_bitmap *b, ULONG_PTR want)
{
	struct page **old_pages = b->bm_pages;
	struct page **new_pages, *page;
	unsigned int i, bytes;
    ULONG_PTR have = b->bm_number_of_pages;
	BUG_ON(have == 0 && old_pages != NULL);
	BUG_ON(have != 0 && old_pages == NULL);

	if (have == want)
		return old_pages;

#ifdef _WIN64
	BUG_ON_UINT32_OVER(sizeof(struct page *)*want);
#endif
	/* Trying kmalloc first, falling back to vmalloc.
	 * GFP_NOIO, as this is called while bsr IO is "suspended",
	 * and during resize or attach on diskless Primary,
	 * we must not block on IO to ourselves.
	 * Context is receiver thread or dmsetup. */
	bytes = (unsigned int)(sizeof(struct page *)*want);
	new_pages = bsr_kzalloc(bytes, GFP_NOIO | __GFP_NOWARN, '60SB');

	if (!new_pages) {
#ifdef _LIN
		new_pages = __vmalloc(bytes,
				GFP_NOIO | __GFP_HIGHMEM | __GFP_ZERO,
				PAGE_KERNEL);
		if (new_pages) {
			atomic_add64(bytes, &mem_usage.vmalloc);
		}
		else
#endif
			return NULL;
	}

	if (want >= have) {
		for (i = 0; i < have; i++)
			new_pages[i] = old_pages[i];
		for (; i < want; i++) {
			page = alloc_page(GFP_NOIO | __GFP_HIGHMEM | __GFP_ZERO);
			if (!page) {
				bm_free_pages(new_pages + have, i - have);
#ifdef _LIN
				sub_kvmalloc_mem_usage(new_pages, bytes);				
#endif
				kvfree(new_pages);
				return NULL;
			}
			/* we want to know which page it is
			 * from the endio handlers */
			bm_store_page_idx(page, i);
			new_pages[i] = page;
		}
	} else {
		for (i = 0; i < want; i++)
			new_pages[i] = old_pages[i];
		/* NOT HERE, we are outside the spinlock!
		bm_free_pages(old_pages + want, have - want);
		*/
	}
	return new_pages;
}

struct bsr_bitmap *bsr_bm_alloc(void)
{
	struct bsr_bitmap *b;
	b = bsr_kzalloc(sizeof(struct bsr_bitmap), GFP_KERNEL, '70SB');
	if (!b)
		return NULL;

	spin_lock_init(&b->bm_lock);
	mutex_init(&b->bm_change);
	init_waitqueue_head(&b->bm_io_wait);

	b->bm_max_peers = 1;

	return b;
}

sector_t bsr_bm_capacity(struct bsr_device *device)
{
	if (!expect(device, device->bitmap))
		return 0;
	return device->bitmap->bm_dev_capacity;
}

void bsr_bm_free(struct bsr_bitmap *bitmap)
{
	bm_free_pages(bitmap->bm_pages, bitmap->bm_number_of_pages);
	kvfree(bitmap->bm_pages);
	bsr_kfree(bitmap);
}

enum bitmap_operations {
	BM_OP_CLEAR,
	BM_OP_SET,
	BM_OP_TEST,
	BM_OP_COUNT,
	BM_OP_MERGE,
	BM_OP_EXTRACT,
	BM_OP_FIND_BIT,
	BM_OP_FIND_ZERO_BIT,
	// DW-1978 used to find bit the range.
	BM_OP_RANGE_FIND_BIT,
	// DW-1979 used to find zero bit the range.
	BM_OP_RANGE_FIND_ZERO_BIT,
};

static inline ULONG_PTR interleaved_word32(struct bsr_bitmap *bitmap,
					       unsigned int bitmap_index,
					       ULONG_PTR bit)
{
	return (bit >> 5) * bitmap->bm_max_peers + bitmap_index;
}

static inline ULONG_PTR word32_to_page(ULONG_PTR word)
{
	return word >> (PAGE_SHIFT - 2);
}

static inline unsigned int word32_in_page(ULONG_PTR word)
{
	return word & ((1 << (PAGE_SHIFT - 2)) - 1);
}

static inline ULONG_PTR last_bit_on_page(struct bsr_bitmap *bitmap,
					     unsigned int bitmap_index,
					     ULONG_PTR bit)
{
	ULONG_PTR word = interleaved_word32(bitmap, bitmap_index, bit);

	return (bit | 31) + ((ULONG_PTR)(word32_in_page(~word) / bitmap->bm_max_peers) << 5);
}

static inline ULONG_PTR bit_to_page_interleaved(struct bsr_bitmap *bitmap,
						    unsigned int bitmap_index,
						    ULONG_PTR bit)
{
	return word32_to_page(interleaved_word32(bitmap, bitmap_index, bit));
}

#ifdef COMPAT_KMAP_ATOMIC_PAGE_ONLY
#define ____bm_op(device, bitmap_index, start, end, op, buffer, km_type) \
	____bm_op(device, bitmap_index, start, end, op, buffer)
#endif
static __always_inline ULONG_PTR
____bm_op(struct bsr_device *device, unsigned int bitmap_index, ULONG_PTR start, ULONG_PTR end,
	 enum bitmap_operations op, __le32 *buffer, enum km_type km_type)
{
	struct bsr_bitmap *bitmap = device->bitmap;
	unsigned int word32_skip = 32 * bitmap->bm_max_peers;
	ULONG_PTR total = 0;
	ULONG_PTR word;
	ULONG_PTR page;
	unsigned int bit_in_page;
#ifdef _DEBUG_OOS	
	ULONG_PTR init_start = start;
#endif
	ULONG_PTR real_end = 0;

	if (op == BM_OP_RANGE_FIND_BIT ||
		op == BM_OP_RANGE_FIND_ZERO_BIT)
		real_end = end + 1;

	if (end >= bitmap->bm_bits)
		end = bitmap->bm_bits - 1;

	word = interleaved_word32(bitmap, bitmap_index, start);
	page = word32_to_page(word);
	bit_in_page = ((ULONG_PTR)word32_in_page(word) << 5) | (start & 31);

	for (; start <= end; page++) {
		ULONG_PTR count = 0;
		void *addr;

		addr = bsr_kmap_atomic(bitmap->bm_pages[page], km_type);
		if (((start & 31) && (start | 31) <= end) || op == BM_OP_TEST) {
			unsigned int last = bit_in_page | 31;
			switch(op) {
			default:
				do {
					switch(op) {
					case BM_OP_CLEAR:
						if (__test_and_clear_bit_le(bit_in_page, addr))
							count++;
						break;
					case BM_OP_SET:
						if (!__test_and_set_bit_le(bit_in_page, addr))
							count++;
						break;
					case BM_OP_COUNT:
						if (test_bit_le(bit_in_page, addr))
							total++;
						break;
					case BM_OP_TEST:
						total = !!test_bit_le(bit_in_page, addr);
						bsr_kunmap_atomic(addr, km_type);
						return total;
					default:
						break;
					}
					bit_in_page++;
				} while (bit_in_page <= last);
				break;
			case BM_OP_MERGE:
			case BM_OP_EXTRACT:
				BUG();
				break;
			case BM_OP_RANGE_FIND_BIT:
			case BM_OP_FIND_BIT:
				count = find_next_bit_le(addr, last + 1, bit_in_page);
				if (count < last + 1)
					goto found;
				bit_in_page = last + 1;
				break;
			case BM_OP_RANGE_FIND_ZERO_BIT:
			case BM_OP_FIND_ZERO_BIT:
				count = find_next_zero_bit_le(addr, last + 1, bit_in_page);
				if (count < last + 1)
					goto found;
				bit_in_page = last + 1;
				break;
			}
			start = (start | 31) + 1;
			bit_in_page += word32_skip - 32;
			if (bit_in_page >= BITS_PER_PAGE)
				goto next_page;
		}

		while (start + 31 <= end) {
			__le32 *p = (__le32 *)addr + (bit_in_page >> 5);

			switch(op) {
			case BM_OP_CLEAR:
				count += hweight32(*p);
				*p = 0;
				break;
			case BM_OP_SET:
				count += hweight32(~*p);
				*p = UINT32_MAX;
				break;
			case BM_OP_TEST:
				BUG();
				break;
			case BM_OP_COUNT:
				total += hweight32(*p);
				break;
			case BM_OP_MERGE:
				count += hweight32(~*p & *buffer);
				*p |= *buffer++;
				break;
			case BM_OP_EXTRACT:
				*buffer++ = *p;
				break;
			case BM_OP_RANGE_FIND_BIT:
			case BM_OP_FIND_BIT:
				count = find_next_bit_le(addr, bit_in_page + 32, bit_in_page);
				if (count < bit_in_page + 32)
					goto found;
				break;
			case BM_OP_RANGE_FIND_ZERO_BIT:
			case BM_OP_FIND_ZERO_BIT:
				count = find_next_zero_bit_le(addr, bit_in_page + 32, bit_in_page);
				if (count < bit_in_page + 32)
					goto found;
				break;
			}
			start += 32;
			bit_in_page += word32_skip;
			if (bit_in_page >= BITS_PER_PAGE)
				goto next_page;
		}

		/* don't overrun buffers with MERGE or EXTRACT,
		 * jump to the kunmap and then out... */
		if (start > end)
			goto next_page;

		switch(op) {
		default:
			while (start <= end) {
				switch(op) {
				case BM_OP_CLEAR:
					if (__test_and_clear_bit_le(bit_in_page, addr))
						count++;
					break;
				case BM_OP_SET:
					if (!__test_and_set_bit_le(bit_in_page, addr))
						count++;
					break;
				case BM_OP_COUNT:
					if (test_bit_le(bit_in_page, addr))
						total++;
					break;
				default:
					break;
				}
				start++;
				bit_in_page++;
			}
			break;
		case BM_OP_MERGE:
			{
				__le32 *p = (__le32 *)addr + (bit_in_page >> 5);
				__le32 b = *buffer++ & cpu_to_le32((1 << (end - start + 1)) - 1);

				count += hweight32(~*p & b);
				*p |= b;

				start = end + 1;
			}
			break;
		case BM_OP_EXTRACT:
			{
				__le32 *p = (__le32 *)addr + (bit_in_page >> 5);

				*buffer++ = *p & cpu_to_le32((1 << (end - start + 1)) - 1);
				start = end + 1;
			}
			break;
		case BM_OP_RANGE_FIND_BIT:
		case BM_OP_FIND_BIT:
			{
				ULONG_PTR last = bit_in_page + (end - start);

				count = find_next_bit_le(addr, last + 1, bit_in_page);
				if (count < last + 1)
					goto found;
				start = end + 1;
			}
			break;
		case BM_OP_RANGE_FIND_ZERO_BIT:
		case BM_OP_FIND_ZERO_BIT:
			{
				ULONG_PTR last = bit_in_page + (end - start);
				count = find_next_zero_bit_le(addr, last + 1, bit_in_page);
				if (count < last + 1)
					goto found;
				start = end + 1;
			}
			break;
		}

	    next_page:
		bsr_kunmap_atomic(addr, km_type);
		bit_in_page -= BITS_PER_PAGE;
		switch(op) {
		case BM_OP_CLEAR:
			if (count) {
				bm_set_page_lazy_writeout(bitmap->bm_pages[page]);
				total += count;
			}
			break;
		case BM_OP_SET:
		case BM_OP_MERGE:
			if (count) {
				bm_set_page_need_writeout(bitmap->bm_pages[page]);
				total += count;
			}
			break;
		default:
			break;
		}
		continue;

	    found:
		bsr_kunmap_atomic(addr, km_type);
		return start + count - bit_in_page;
	}
	switch(op) {
	case BM_OP_CLEAR:
		if (total)
#ifdef _DEBUG_OOS
		{
			bitmap->bm_set[bitmap_index] -= total;
			// DW-1153 Write log when clear bit.
			WriteOOSTraceLog(bitmap_index, init_start, end, total, SET_IN_SYNC);
		}
#else
			bitmap->bm_set[bitmap_index] -= total;
#endif
		break;
	case BM_OP_SET:
	case BM_OP_MERGE:
		if (total)
#ifdef _DEBUG_OOS
		{
			bitmap->bm_set[bitmap_index] += total;
			// DW-1153 Write log when set bit.
			WriteOOSTraceLog(bitmap_index, init_start, end, total, SET_OUT_OF_SYNC);
		}
#else
			bitmap->bm_set[bitmap_index] += total;
#endif
		break;
	case BM_OP_RANGE_FIND_ZERO_BIT:
	case BM_OP_RANGE_FIND_BIT:
		total = real_end;
		break;
	case BM_OP_FIND_BIT:
	case BM_OP_FIND_ZERO_BIT:
		total = BSR_END_OF_BITMAP;
		break;
	default:
		break;
	}
	return total;
}

/* Returns the number of bits changed.  */
static __always_inline ULONG_PTR
__bm_op(struct bsr_device *device, unsigned int bitmap_index, ULONG_PTR start, ULONG_PTR end,
	enum bitmap_operations op, __le32 *buffer)
{
	struct bsr_bitmap *bitmap = device->bitmap;

	if (!expect(device, bitmap))
		// DW-1153 add error log
	{
#ifdef _DEBUG_OOS
		bsr_err(14, BSR_LC_BITMAP, device, "Failed to bitmap operation due to no bitmap is assigned, start(%llu)", (unsigned long long)start);
#endif
		return 1;
	}
	if (!expect(device, bitmap->bm_pages))
	{
#ifdef _DEBUG_OOS
		// DW-1153 add error log
		bsr_err(15, BSR_LC_BITMAP, device, "Failed to bitmap operation due to no bitmap pages is assigned, start(%llu)", (unsigned long long)start);
#endif
		return 0;
	}

	if (!bitmap->bm_bits)
	{
#ifdef _DEBUG_OOS
		// DW-1153 add error log
		bsr_err(16, BSR_LC_BITMAP, device, "Failed to bitmap operation due to bitmap bits is 0, start(%llu)", (unsigned long long)start);
#endif
		return 0;
	}

	if (bitmap->bm_task != current) {
		switch(op) {
		case BM_OP_CLEAR:
			if (bitmap->bm_flags & BM_LOCK_CLEAR && !(bitmap->bm_flags & BM_LOCK_POINTLESS))
				bm_print_lock_info(device);
			break;
		case BM_OP_SET:
		case BM_OP_MERGE:
			if (bitmap->bm_flags & BM_LOCK_SET && !(bitmap->bm_flags & BM_LOCK_POINTLESS))
				bm_print_lock_info(device);
			break;
		case BM_OP_TEST:
		case BM_OP_COUNT:
		case BM_OP_EXTRACT:
		case BM_OP_FIND_BIT:
		case BM_OP_FIND_ZERO_BIT:
		case BM_OP_RANGE_FIND_BIT:
		case BM_OP_RANGE_FIND_ZERO_BIT:
			if (bitmap->bm_flags & BM_LOCK_TEST && !(bitmap->bm_flags & BM_LOCK_POINTLESS))
				bm_print_lock_info(device);
			break;
		}
	}
	return ____bm_op(device, bitmap_index, start, end, op, buffer, KM_IRQ1);
}
static __always_inline ULONG_PTR
bm_op(struct bsr_device *device, unsigned int bitmap_index, ULONG_PTR start, ULONG_PTR end,
      enum bitmap_operations op, __le32 *buffer)
{
	struct bsr_bitmap *bitmap = device->bitmap;
	unsigned long irq_flags;
	ULONG_PTR count;

	spin_lock_irqsave(&bitmap->bm_lock, irq_flags);
	count = __bm_op(device, bitmap_index, start, end, op, buffer);
	spin_unlock_irqrestore(&bitmap->bm_lock, irq_flags);
	return count;
}

#ifdef BITMAP_DEBUG
#define bm_op(device, bitmap_index, start, end, op, buffer) \
	({ unsigned long ret; \
	   bsr_info(17, BSR_LC_BITMAP, device, "%s: bm_op(..., %u, %lu, %lu, %u, %p)", \
		     __func__, bitmap_index, start, end, op, buffer); \
	   ret = bm_op(device, bitmap_index, start, end, op, buffer); \
	   bsr_info(18, BSR_LC_BITMAP, device, "= %lu", ret); \
	   ret; })

#define __bm_op(device, bitmap_index, start, end, op, buffer) \
	({ unsigned long ret; \
	   bsr_info(19, BSR_LC_BITMAP, device, "%s: __bm_op(..., %u, %lu, %lu, %u, %p)", \
		     __func__, bitmap_index, start, end, op, buffer); \
	   ret = __bm_op(device, bitmap_index, start, end, op, buffer); \
	   bsr_info(20, BSR_LC_BITMAP, device, "= %lu", ret); \
	   ret; })
#endif

#ifdef BITMAP_DEBUG
#define ___bm_op(device, bitmap_index, start, end, op, buffer, km_type) \
	({ unsigned long ret; \
	   bsr_info(21, BSR_LC_BITMAP, device, "%s: ___bm_op(..., %u, %lu, %lu, %u, %p)", \
		     __func__, bitmap_index, start, end, op, buffer); \
	   ret = ____bm_op(device, bitmap_index, start, end, op, buffer, km_type); \
	   bsr_info(22, BSR_LC_BITMAP, device, "= %lu", ret); \
	   ret; })
#else
#define ___bm_op(device, bitmap_index, start, end, op, buffer, km_type) \
	____bm_op(device, bitmap_index, start, end, op, buffer, km_type)
#endif

/* you better not modify the bitmap while this is running,
 * or its results will be stale */
static void bm_count_bits(struct bsr_device *device)
{
	struct bsr_bitmap *bitmap = device->bitmap;
	unsigned int bitmap_index;

	for (bitmap_index = 0; bitmap_index < bitmap->bm_max_peers; bitmap_index++) {
		ULONG_PTR bit = 0, bits_set = 0;
		while (bit < bitmap->bm_bits) {
			ULONG_PTR last_bit = last_bit_on_page(bitmap, bitmap_index, bit);
			bits_set += ___bm_op(device, bitmap_index, bit, last_bit, BM_OP_COUNT, NULL, KM_USER0);
			bit = last_bit + 1;
			cond_resched();
		}
		bitmap->bm_set[bitmap_index] = bits_set;
	}
}

/* For the layout, see comment above bsr_md_set_sector_offsets(). */
static u64 bsr_md_on_disk_bits(struct bsr_device *device)
{
	struct bsr_backing_dev *ldev = device->ldev;
	u64 bitmap_sectors, word64_on_disk;
	if (ldev->md.al_offset == 8)
		bitmap_sectors = ldev->md.md_size_sect - ldev->md.bm_offset;
	else
		bitmap_sectors = ldev->md.al_offset - ldev->md.bm_offset;

	/* for interoperability between 32bit and 64bit architectures,
	 * we round on 64bit words.  FIXME do we still need this? */
	word64_on_disk = bitmap_sectors << (9 - 3); /* x * (512/8) */

	do_div(word64_on_disk, device->bitmap->bm_max_peers);
	return word64_on_disk << 6; /* x * 64 */;
}

/*
 * make sure the bitmap has enough room for the attached storage,
 * if necessary, resize.
 * called whenever we may have changed the device size.
 * returns -ENOMEM if we could not allocate enough memory, 0 on success.
 * In case this is actually a resize, we copy the old bitmap into the new one.
 * Otherwise, the bitmap is initialized to all bits set.
 */
int bsr_bm_resize(struct bsr_device *device, sector_t capacity, int set_new_bits)
{
	struct bsr_bitmap *b = device->bitmap;
	ULONG_PTR bits, words, obits;
	ULONG_PTR want, have, onpages; /* number of pages */
	struct page **npages, **opages = NULL;
	int err = 0;
	bool growing;

	if (!expect(device, b))
		return -ENOMEM;

	bsr_bm_lock(device, "resize", BM_LOCK_ALL);

	bsr_info(23, BSR_LC_BITMAP, device, "Start resizing the bitmap size to disk capacity. capacity sector(%llu)",
			(unsigned long long)capacity);

	if (capacity == b->bm_dev_capacity)
		goto out;

	if (capacity == 0) {
		unsigned int bitmap_index;

		spin_lock_irq(&b->bm_lock);
		opages = b->bm_pages;
		onpages = b->bm_number_of_pages;
		b->bm_pages = NULL;
		b->bm_number_of_pages = 0;
		for (bitmap_index = 0; bitmap_index < b->bm_max_peers; bitmap_index++)
			b->bm_set[bitmap_index] = 0;
		b->bm_bits = 0;
		b->bm_words = 0;
		b->bm_dev_capacity = 0;
		spin_unlock_irq(&b->bm_lock);
		bm_free_pages(opages, onpages);
#ifdef _LIN
		sub_kvmalloc_mem_usage(opages, sizeof(struct page *)*onpages);
#endif
		kvfree(opages);
		goto out;
	}
	bits  = BM_SECT_TO_BIT(ALIGN(capacity, BM_SECT_PER_BIT));

	// DW-917 The calculation of counting words should be divided by the bit count of 'int' since the accessing unit of data word for bitmap is 'int'.
	words = (ALIGN(bits, 64) * b->bm_max_peers) / BITS_PER_BM_WORD;

	if (get_ldev(device)) {
		u64 bits_on_disk = bsr_md_on_disk_bits(device);
		put_ldev(__FUNCTION__, device);
		if (bits > bits_on_disk) {
			bsr_err(24, BSR_LC_BITMAP, device, "Failed to resize bitmap due to not enough space for bitmap. bitmap(%llu) space(%llu)",
				(unsigned long long)bits, bits_on_disk);
			err = -ENOSPC;
			goto out;
		}
	}

	// DW-917 Need to multiply the bytes of each word.
    want = ALIGN(words*BYTES_PER_BM_WORD, PAGE_SIZE) >> PAGE_SHIFT;

	have = b->bm_number_of_pages;
	if (want == have) {
		D_ASSERT(device, b->bm_pages != NULL);
		npages = b->bm_pages;
	} else {
		if (bsr_insert_fault(device, BSR_FAULT_BM_ALLOC))
			npages = NULL;
		else
			npages = bm_realloc_pages(b, want);
	}

	if (!npages) {
		err = -ENOMEM;
		goto out;
	}

	spin_lock_irq(&b->bm_lock);
	opages = b->bm_pages;
	obits  = b->bm_bits;

	growing = bits > obits;

	b->bm_pages = npages;
	b->bm_number_of_pages = want;
	b->bm_bits  = bits;
	b->bm_words = words;
	b->bm_dev_capacity = capacity;

	if (growing) {
		unsigned int bitmap_index;

		for (bitmap_index = 0; bitmap_index < b->bm_max_peers; bitmap_index++) {
			ULONG_PTR bm_set = b->bm_set[bitmap_index];

			if (set_new_bits) { 
				___bm_op(device, bitmap_index, obits, BSR_END_OF_BITMAP, BM_OP_SET, NULL, KM_IRQ1);
				bm_set += bits - obits;
			}
			else
				___bm_op(device, bitmap_index, obits, BSR_END_OF_BITMAP, BM_OP_CLEAR, NULL, KM_IRQ1);

			b->bm_set[bitmap_index] = bm_set;
		}
	}

	if (want < have) {
#ifdef _LIN
		atomic_sub64(have - want, &mem_usage.bm_pp);
#endif
		/* implicit: (opages != NULL) && (opages != npages) */
		bm_free_pages(opages + want, have - want);
	} else {
#ifdef _LIN
		atomic_add64(want - have, &mem_usage.bm_pp);
#endif
	}

	spin_unlock_irq(&b->bm_lock);
	if (opages != npages) {
#ifdef _LIN
		sub_kvmalloc_mem_usage(opages, sizeof(struct page *)*have);
#endif
		kvfree(opages);
	}
	if (!growing)
		bm_count_bits(device);
	bsr_info(25, BSR_LC_BITMAP, device, "The bitmap size has been resized to disk capacity. bits(%llu) words(%llu) pages(%llu)", (unsigned long long)bits, (unsigned long long)words, (unsigned long long)want);

 out:
	bsr_bm_unlock(device);
	return err;
}

/* inherently racy:
 * if not protected by other means, return value may be out of date when
 * leaving this function...
 * we still need to lock it, since it is important that this returns
 * bm_set == 0 precisely.
 */
ULONG_PTR _bsr_bm_total_weight(struct bsr_device *device, int bitmap_index)
{
	struct bsr_bitmap *b = device->bitmap;
	ULONG_PTR s;
	unsigned long flags;

	if (!expect(device, b))
		return 0;
	if (!expect(device, b->bm_pages))
		return 0;

	spin_lock_irqsave(&b->bm_lock, flags);
	s = b->bm_set[bitmap_index];
	spin_unlock_irqrestore(&b->bm_lock, flags);

	return s;
}

ULONG_PTR bsr_bm_total_weight(struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
    ULONG_PTR s;

	if (peer_device->bitmap_index == -1)
		return 0;

	/* if I don't have a disk, I don't know about out-of-sync status */
	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return 0;
	s = _bsr_bm_total_weight(device, peer_device->bitmap_index);
	put_ldev(__FUNCTION__, device);
	return s;
}

// DW-1859
void check_and_clear_io_error_in_primary(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;
	ULONG_PTR total_count = 0;
	unsigned long flags;
	bool all_disconnected = true;

	if (!device || !device->bitmap || !device->bitmap->bm_pages)
		return;

	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return;

	// DW-1859 BSR-744 make sure the io-error is cleared only when MDF_IO_ERROR is set.
	if (!bsr_md_test_flag(device, MDF_IO_ERROR)) {
		put_ldev(__FUNCTION__, device);
		return;
	}

	// DW-1859 MDF_PRIMARY_IO_ERROR is the value required to check if io-error is cleared.
	 /* If all peer's OOS are removed, the io-error is considered to be resolved
	 * and the number of io-errors is initialized to zero. 
	 */
	
	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->cstate[NOW] == C_CONNECTED) {
			ULONG_PTR count = 0;
			all_disconnected = false;
			spin_lock_irqsave(&device->bitmap->bm_lock, flags);
			count = device->bitmap->bm_set[peer_device->bitmap_index];
			spin_unlock_irqrestore(&device->bitmap->bm_lock, flags);

			if (count == 0)
				bsr_md_clear_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR);

			total_count += count;
		}
	}

	// DW-1859 At primary, all OOS with all peers must be removed before the io - error count can be initialized.
	// DW-1870 If all nodes are not connected, it is not resolved.
	if (total_count == 0 && !all_disconnected) {
		bsr_md_clear_flag(device, MDF_IO_ERROR);
		bsr_info(1, BSR_LC_IO_ERROR, device, "Primary I/O errors have been resolved.");
		atomic_set(&device->io_error_count, 0);
		bsr_queue_notify_io_error_cleared(device);
	}

	put_ldev(__FUNCTION__, device);
}

void check_and_clear_io_error_in_secondary(struct bsr_peer_device *peer_device)
{
	struct bsr_bitmap *b;
	struct bsr_device *device;
	ULONG_PTR count;
	unsigned long flags;

	if (!peer_device || !peer_device->device || !peer_device->device->bitmap)
		return;

	device = peer_device->device;
	b = device->bitmap;

	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return;

	// DW-1859 If MDF_IO_ERROR is not set, and if io_error_count is also 0, there is certainly no error.
	if (!bsr_md_test_flag(device, MDF_IO_ERROR) && (atomic_read(&device->io_error_count) == 0)) {
		put_ldev(__FUNCTION__, device);
		return;
	}

	// DW-1859 In secondary, initialize io - error count when OOS with one peer is removed.
	spin_lock_irqsave(&b->bm_lock, flags);
	count = b->bm_set[peer_device->bitmap_index];
	spin_unlock_irqrestore(&b->bm_lock, flags);
	if (count == 0) {
		bsr_md_clear_peer_flag(peer_device, MDF_PEER_PRIMARY_IO_ERROR);
		bsr_md_clear_flag(device, MDF_IO_ERROR);
		bsr_info(6, BSR_LC_IO_ERROR, peer_device, "Secondary I/O errors have been resolved.");
		atomic_set(&device->io_error_count, 0);
		bsr_queue_notify_io_error_cleared(device);
	}

	put_ldev(__FUNCTION__, device);
}

/* Returns the number of unsigned long words per peer */
size_t bsr_bm_words(struct bsr_device *device)
{
	struct bsr_bitmap *b = device->bitmap;
	if (!expect(device, b))
		return 0;
	if (!expect(device, b->bm_pages))
		return 0;

	return b->bm_words / b->bm_max_peers;
}

ULONG_PTR bsr_bm_bits(struct bsr_device *device)
{
	struct bsr_bitmap *b = device->bitmap;
	if (!expect(device, b))
		return 0;

	return b->bm_bits;
}

/* merge number words from buffer into the bitmap starting at offset.
 * buffer[i] is expected to be little endian unsigned long.
 * bitmap must be locked by bsr_bm_lock.
 * currently only used from receive_bitmap.
 */
void bsr_bm_merge_lel(struct bsr_peer_device *peer_device, size_t offset, size_t number,
	ULONG_PTR *buffer)
{
	ULONG_PTR start, end;
	start = offset * BITS_PER_LONG;
	end = start + number * BITS_PER_LONG - 1;
	bm_op(peer_device->device, peer_device->bitmap_index, start, end, BM_OP_MERGE, (__le32 *)buffer);
}

/* copy number words from the bitmap starting at offset into the buffer.
 * buffer[i] will be little endian unsigned long.
 */
void bsr_bm_get_lel(struct bsr_peer_device *peer_device, size_t offset, size_t number,
	ULONG_PTR *buffer)
{
	ULONG_PTR start, end;
	start = offset * BITS_PER_LONG;
	end = start + number * BITS_PER_LONG - 1;
	bm_op(peer_device->device, peer_device->bitmap_index, start, end, BM_OP_EXTRACT, (__le32 *)buffer);
}


static void bsr_bm_aio_ctx_destroy(struct kref *kref)
{
	struct bsr_bm_aio_ctx *ctx = container_of(kref, struct bsr_bm_aio_ctx, kref);
	unsigned long flags;

	spin_lock_irqsave(&ctx->device->resource->req_lock, flags);
	list_del(&ctx->list);
	spin_unlock_irqrestore(&ctx->device->resource->req_lock, flags);
	put_ldev(__FUNCTION__, ctx->device);
	bsr_kfree(ctx);
}

/* bv_page may be a copy, or may be the original */
#ifdef _WIN
NTSTATUS bsr_bm_endio(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
#else // _LIN
static BIO_ENDIO_TYPE bsr_bm_endio BIO_ENDIO_ARGS(struct bio *bio)
#endif
{
#ifdef _WIN
    struct bio *bio = NULL;
    int error = 0;

	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
        error = Irp->IoStatus.Status;
		bio = (struct bio *)Context;
		//
		//	Simulation Local Disk I/O Error Point. disk error simluation type 4
		//
		if(gSimulDiskIoError.ErrorFlag && gSimulDiskIoError.ErrorType == SIMUL_DISK_IO_ERROR_TYPE4) {
			if(IsDiskError()) {
				bsr_err(23, BSR_LC_IO, NO_OBJECT,"SimulDiskIoError: Bitmap I/O Error type4.....ErrorFlag:%lu ErrorCount:%lu",gSimulDiskIoError.ErrorFlag, gSimulDiskIoError.ErrorCount);
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
	/*
	 * The generic_make_request calls IoAcquireRemoveLock before the IRP is created
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
#endif // _WIN END
	struct bsr_bm_aio_ctx *ctx = bio->bi_private;
	struct bsr_device *device = ctx->device;
	struct bsr_bitmap *b = device->bitmap;
	ULONG_PTR idx = bm_page_to_idx(bio->bi_io_vec[0].bv_page);

	BIO_ENDIO_FN_START;
#ifdef _WIN64
	BUG_ON_INT32_OVER(idx);
#endif
	if ((ctx->flags & BM_AIO_COPY_PAGES) == 0 &&
	    !bm_test_page_unchanged(b->bm_pages[idx]))
		bsr_warn(59, BSR_LC_BITMAP, device, "Bitmap page idx %llu changed during I/O", (unsigned long long)idx);

	if (error) {
		/* ctx error will hold the completed-last non-zero error code,
		 * in case error codes differ. */
		ctx->error = error;
		bm_set_page_io_err(b->bm_pages[idx]);
		/* Not identical to on disk version of it.
		 * Is BM_PAGE_IO_ERROR enough? */
		if (bsr_ratelimit())
			bsr_err(24, BSR_LC_IO, device, "Failed to I/O bitmap ERROR %d on bitmap page idx %llu",
					error, (unsigned long long)idx);
	} else {
		bm_clear_page_io_err(b->bm_pages[idx]);
		dynamic_bsr_dbg(device, "bitmap page idx %llu completed", (unsigned long long)idx);
	}

	bm_page_unlock_io(device, (int)idx);

#ifdef _WIN
	// DW-1838 
	//If IoAcquireRemoveLock fails, 
	//DeviceObjects points to FAULT_TEST_FLAG, and IRP variable points to bio instead of IRP.
	if ((ULONG_PTR)DeviceObject != FAULT_TEST_FLAG) {
		if (Irp) {
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
	}
#endif

	if (ctx->flags & BM_AIO_COPY_PAGES)
		mempool_free(bio->bi_io_vec[0].bv_page, bsr_md_io_page_pool);
	
	bio_put(bio);

	if (atomic_dec_and_test(&ctx->in_flight)) {
		ctx->done = 1;
		wake_up(&device->misc_wait);
		kref_put(&ctx->kref, &bsr_bm_aio_ctx_destroy);
	}
#ifdef BSR_TRACE	
	{
		static int cnt = 0;
		bsr_debug(48, BSR_LC_IO, NO_OBJECT,"bm_async_io_complete done.(%d).................!!!", cnt++);
	}
#endif

	BIO_ENDIO_FN_RETURN;
}

static int bm_page_io_async(struct bsr_bm_aio_ctx *ctx, int page_nr) __must_hold(local)
{
	struct bsr_device *device = ctx->device;
	struct bsr_bitmap *b = device->bitmap;
	struct page *page;
	unsigned int len;
	unsigned int op = (ctx->flags & BM_AIO_READ) ? REQ_OP_READ : REQ_OP_WRITE;
	sector_t on_disk_sector;
#ifdef _WIN
	struct bio *bio = bio_alloc_bsr(GFP_NOIO, '50SB');
#else // _LIN
	struct bio *bio = bio_alloc_bsr(device->ldev->md_bdev, GFP_NOIO, op);
#endif

    if (!bio) {
        goto no_memory;
    }

	on_disk_sector =
		device->ldev->md.md_offset + device->ldev->md.bm_offset;
	on_disk_sector += ((sector_t)page_nr) << (PAGE_SHIFT-9);

	/* this might happen with very small
	 * flexible external meta data device,
	 * or with PAGE_SIZE > 4k */
	len = min_t(unsigned int, PAGE_SIZE,
		(bsr_md_last_sector(device->ldev) - on_disk_sector + 1)<<9);

	// DW-1617 bsr_bm_endio is not called if len is 0. If len is 0, change it to PAGE_SIZE.
	if (len == 0){
		bsr_warn(60, BSR_LC_BITMAP, device, "Last sector of metadata is less than on disk sector");
		len = PAGE_SIZE; 
	}

	/* serialize IO on this page */
	bm_page_lock_io(device, page_nr);
	/* before memcpy and submit,
	 * so it can be redirtied any time */
	bm_set_page_unchanged(b->bm_pages[page_nr]);

	if (ctx->flags & BM_AIO_COPY_PAGES) {
		page = mempool_alloc(bsr_md_io_page_pool, __GFP_HIGHMEM|__GFP_RECLAIM);
		if (!page) {
			bio_put(bio);
			goto no_memory;
		}
		copy_highpage(page, b->bm_pages[page_nr]);
		bm_store_page_idx(page, page_nr);
	} else
		page = b->bm_pages[page_nr];

#ifndef COMPAT_BIO_ALLOC_HAS_4_PARAMS
	bio_set_dev(bio, device->ldev->md_bdev);
#endif

	BSR_BIO_BI_SECTOR(bio) = on_disk_sector;
	/* bio_add_page of a single page to an empty bio will always succeed,
	 * according to api.  Do we want to assert that? */
	bio_add_page(bio, page, len, 0);
	bio->bi_private = ctx;
	bio->bi_end_io = bsr_bm_endio;
#ifndef COMPAT_BIO_ALLOC_HAS_4_PARAMS
	bio_set_op_attrs(bio, op, 0);
#endif
	if (bsr_insert_fault(device, (op == REQ_OP_WRITE) ? BSR_FAULT_MD_WR : BSR_FAULT_MD_RD)) {
		bsr_bio_endio(bio, -EIO);
	} else {
#ifdef _WIN
		if (submit_bio(bio)) {
			bio_endio(bio, -EIO);
		}
		else {
			/* this should not count as user activity and cause the
			* resync to throttle -- see bsr_rs_should_slow_down(). */
			atomic_add(len >> 9, &device->rs_sect_ev);
		}
#else // _LIN
		submit_bio(bio);
		/* this should not count as user activity and cause the
		 * resync to throttle -- see bsr_rs_should_slow_down(). */
		atomic_add(len >> 9, &device->rs_sect_ev);
#endif
	}
	// DW-938 
	return 0;

no_memory :
	bsr_err(45, BSR_LC_MEMORY, NO_OBJECT,"Failed to I/O bitmap page due to no memory");
	return -ENOMEM;
}

/**
 * bm_rw_range() - read/write the specified range of bitmap pages
 * @device: bsr device this bitmap is associated with
 * @rw:	READ or WRITE
 * @start_page, @end_page: inclusive range of bitmap page indices to process
 * @flags: BM_AIO_*, see struct bm_aio_ctx.
 *
 * Silently limits end_page to the current bitmap size.
 *
 * We don't want to special case on logical_block_size of the backend device,
 * so we submit PAGE_SIZE aligned pieces.
 * Note that on "most" systems, PAGE_SIZE is 4k.
 *
 * In case this becomes an issue on systems with larger PAGE_SIZE,
 * we may want to change this again to do 4k aligned 4k pieces.
 */
static int bm_rw_range(struct bsr_device *device,
	ULONG_PTR start_page, ULONG_PTR end_page,
	unsigned flags) __must_hold(local)
{
	struct bsr_bm_aio_ctx *ctx;
	struct bsr_bitmap *b = device->bitmap;
	ULONG_PTR i, count = 0;

	ULONG_PTR now;
	int err = 0;

	/*
	 * We are protected against bitmap disappearing/resizing by holding an
	 * ldev reference (caller must have called get_ldev()).
	 * For read/write, we are protected against changes to the bitmap by
	 * the bitmap lock (see bsr_bitmap_io).
	 * For lazy writeout, we don't care for ongoing changes to the bitmap,
	 * as we submit copies of pages anyways.
	 */

	/* if we reach this, we should have at least *some* bitmap pages. */
	if (!expect(device, b->bm_number_of_pages))
		return -ENODEV;

	ctx = bsr_kmalloc(sizeof(struct bsr_bm_aio_ctx), GFP_NOIO, '80SB');
	if (!ctx)
		return -ENOMEM;

	*ctx = (struct bsr_bm_aio_ctx) {
		.device = device,
		.start_jif = jiffies,
		.in_flight = ATOMIC_INIT(1),
		.done = 0,
		.flags = flags,
		.error = 0,
		.kref = KREF_INIT(2),
	};

	if (!expect(device, get_ldev_if_state(device, D_ATTACHING))) {  /* put is in bsr_bm_aio_ctx_destroy() */
		bsr_kfree(ctx);
		return -ENODEV;
	}
	/* Here, D_ATTACHING is sufficient because bsr_bm_read() is only
	 * called from bsr_adm_attach(), after device->ldev has been assigned.
	 *
	 * The corresponding put_ldev() happens in bm_aio_ctx_destroy().
	 */

	if (0 == (ctx->flags & ~BM_AIO_READ))
		WARN_ON(!(b->bm_flags & BM_LOCK_ALL));

	if (end_page >= b->bm_number_of_pages) {
		end_page = b->bm_number_of_pages - 1;
	}

	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&ctx->list, &device->pending_bitmap_io);
	spin_unlock_irq(&device->resource->req_lock);

	now = jiffies;
#ifdef _WIN64
	BUG_ON_INT32_OVER(start_page);
	BUG_ON_INT32_OVER(end_page);
#endif

	/* let the layers below us try to merge these bios... */
	if (flags & BM_AIO_READ) {
		for (i = start_page; i <= end_page; i++) {
			atomic_inc(&ctx->in_flight);
			// DW-938 
			if(-ENOMEM == bm_page_io_async(ctx, (int)i)) {
				ctx->error = -ENOMEM;
				break;
			}
			++count;
			cond_resched();
		}
	} else if (flags & BM_AIO_WRITE_HINTED) {
		/* ASSERT: BM_AIO_WRITE_ALL_PAGES is not set. */
		unsigned int hint;
		for (hint = 0; hint < b->n_bitmap_hints; hint++) {
			i = b->al_bitmap_hints[hint];
			if (i > end_page)
				continue;
			/* Several AL-extents may point to the same page. */
			if (!test_and_clear_bit(BM_PAGE_HINT_WRITEOUT,
			    &page_private(b->bm_pages[i])))
				continue;
			/* Has it even changed? */
			if (bm_test_page_unchanged(b->bm_pages[i]))
				continue;
			atomic_inc(&ctx->in_flight);
			// DW-938 
			if(-ENOMEM == bm_page_io_async(ctx, (int)i)) {
				ctx->error = -ENOMEM;
				break;
			}
			++count;
		}
	} else {
		for (i = start_page; i <= end_page; i++) {
			/* ignore completely unchanged pages,
			 * unless specifically requested to write ALL pages */
			if (!(flags & BM_AIO_WRITE_ALL_PAGES) &&
			    bm_test_page_unchanged(b->bm_pages[i])) {
				//dynamic_bsr_dbg(device, "skipped bm write for idx %u", i);
				continue;
			}
			/* during lazy writeout,
			 * ignore those pages not marked for lazy writeout. */
			if ((flags & BM_AIO_WRITE_LAZY) &&
			    !bm_test_page_lazy_writeout(b->bm_pages[i])) {
				//dynamic_bsr_dbg(device, "skipped bm lazy write for idx %u", i);
				continue;
			}
			atomic_inc(&ctx->in_flight);
			// DW-938
			if(-ENOMEM == bm_page_io_async(ctx, (int)i)) {
				ctx->error = -ENOMEM;
				break;
			}
			++count;
			cond_resched();
		}
	}

	/*
	 * We initialize ctx->in_flight to one to make sure bsr_bm_endio
	 * will not set ctx->done early, and decrement / test it here.  If there
	 * are still some bios in flight, we need to wait for them here.
	 * If all IO is done already (or nothing had been submitted), there is
	 * no need to wait.  Still, we need to put the kref associated with the
	 * "in_flight reached zero, all done" event.
	 */
	if (!atomic_dec_and_test(&ctx->in_flight)) {
		bsr_blk_run_queue(bdev_get_queue(device->ldev->md_bdev));
		wait_until_done_or_force_detached(device, device->ldev, &ctx->done);
	} else
		kref_put(&ctx->kref, &bsr_bm_aio_ctx_destroy);

	/* summary for global bitmap IO */
	if (flags == 0 && count) {
		unsigned int ms = jiffies_to_msecs(jiffies - now);
		if (ms > 5) {
			bsr_info(27, BSR_LC_BITMAP, device, "Bitmap %s of %llu pages took %ums",
				 (flags & BM_AIO_READ) ? "READ" : "WRITE",
				 (unsigned long long)count, ms);
		}
	}

	if (ctx->error) {
		bsr_alert(28, BSR_LC_BITMAP, device, "Meta disk I/O error occurred during bitmap I/O");
		bsr_chk_io_error(device, 1, BSR_META_IO_ERROR);
		err = -EIO; /* ctx->error ? */
	}

	if (atomic_read(&ctx->in_flight))
		err = -EIO; /* Disk timeout/force-detach during IO... */

	if (flags & BM_AIO_READ) {
		now = jiffies;
		bm_count_bits(device);
		bsr_info(29, BSR_LC_BITMAP, device, "Recounting of set bits took additional %ums",
		     jiffies_to_msecs(jiffies - now));
	}

	kref_put(&ctx->kref, &bsr_bm_aio_ctx_destroy);
	return err;
}

static int bm_rw(struct bsr_device *device, unsigned flags)
{
#ifdef _WIN64
	BUG_ON_UINT32_OVER(device->bitmap->bm_number_of_pages);
#endif
	return bm_rw_range(device, 0, device->bitmap->bm_number_of_pages, flags);
}

/**
 * bsr_bm_read() - Read the whole bitmap from its on disk location.
 * @device:	BSR device.
 */
int bsr_bm_read(struct bsr_device *device,
		 struct bsr_peer_device *peer_device) __must_hold(local)
{
	UNREFERENCED_PARAMETER(peer_device);
	return bm_rw(device, BM_AIO_READ);
}

static void push_al_bitmap_hint(struct bsr_device *device, unsigned int page_nr)
{
	struct bsr_bitmap *b = device->bitmap;
	struct page *page = b->bm_pages[page_nr];
	BUG_ON(b->n_bitmap_hints >= ARRAY_SIZE(b->al_bitmap_hints));
	if (!test_and_set_bit(BM_PAGE_HINT_WRITEOUT, &page_private(page)) && (b->n_bitmap_hints < ARRAY_SIZE(b->al_bitmap_hints)))
		b->al_bitmap_hints[b->n_bitmap_hints++] = page_nr;
}

/**
 * bsr_bm_mark_range_for_writeout() - mark with a "hint" to be considered for writeout
 * @device:	BSR device.
 *
 * From within an activity log transaction, we mark a few pages with these
 * hints, then call bsr_bm_write_hinted(), which will only write out changed
 * pages which are flagged with this mark.
 */
void bsr_bm_mark_range_for_writeout(struct bsr_device *device, ULONG_PTR start, ULONG_PTR end)
{
	struct bsr_bitmap *bitmap = device->bitmap;
	ULONG_PTR last_page;
	ULONG_PTR page_nr;

	if (end >= bitmap->bm_bits)
		end = bitmap->bm_bits - 1;

	page_nr = bit_to_page_interleaved(bitmap, 0, start);
	last_page = bit_to_page_interleaved(bitmap, bitmap->bm_max_peers - 1, end);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(page_nr);
#endif
	for (; page_nr <= last_page; page_nr++) 
		push_al_bitmap_hint(device, (unsigned int)page_nr);
}


/**
 * bsr_bm_write() - Write the whole bitmap to its on disk location.
 * @device:	BSR device.
 *
 * Will only write pages that have changed since last IO.
 */
int bsr_bm_write(struct bsr_device *device,
		  struct bsr_peer_device *peer_device) __must_hold(local)
{
	UNREFERENCED_PARAMETER(peer_device);
	return bm_rw(device, 0);
}

/**
 * bsr_bm_write_all() - Write the whole bitmap to its on disk location.
 * @mdev:	BSR device.
 *
 * Will write all pages.
 */
int bsr_bm_write_all(struct bsr_device *device,
		      struct bsr_peer_device *peer_device) __must_hold(local)
{
	UNREFERENCED_PARAMETER(peer_device);
	return bm_rw(device, BM_AIO_WRITE_ALL_PAGES);
}

/**
 * bsr_bm_write_lazy() - Write bitmap pages 0 to @upper_idx-1, if they have changed.
 * @device:	BSR device.
 * @upper_idx:	0: write all changed pages; +ve: page index to stop scanning for changed pages
 */
int bsr_bm_write_lazy(struct bsr_device *device, unsigned upper_idx) __must_hold(local)
{
	return bm_rw_range(device, 0, upper_idx - 1, BM_AIO_COPY_PAGES | BM_AIO_WRITE_LAZY);
}

/**
 * bsr_bm_write_copy_pages() - Write the whole bitmap to its on disk location.
 * @device:	BSR device.
 *
 * Will only write pages that have changed since last IO.
 * In contrast to bsr_bm_write(), this will copy the bitmap pages
 * to temporary writeout pages. It is intended to trigger a full write-out
 * while still allowing the bitmap to change, for example if a resync or online
 * verify is aborted due to a failed peer disk, while local IO continues, or
 * pending resync acks are still being processed.
 */
int bsr_bm_write_copy_pages(struct bsr_device *device,
			     struct bsr_peer_device *peer_device) __must_hold(local)
{
	UNREFERENCED_PARAMETER(peer_device);
	return bm_rw(device, BM_AIO_COPY_PAGES);
}

/**
 * bsr_bm_write_hinted() - Write bitmap pages with "hint" marks, if they have changed.
 * @device:	BSR device.
 */
int bsr_bm_write_hinted(struct bsr_device *device) __must_hold(local)
{
	return bm_rw(device, BM_AIO_WRITE_HINTED | BM_AIO_COPY_PAGES);
}
ULONG_PTR bsr_bm_find_next(struct bsr_peer_device *peer_device, ULONG_PTR start)
{
	return bm_op(peer_device->device, peer_device->bitmap_index, start, BSR_END_OF_BITMAP,
		     BM_OP_FIND_BIT, NULL);
}

// BSR-835
extern void bsr_free_ov_bm(struct kref *kref)
{
	struct bsr_peer_device *peer_device = container_of(kref, struct bsr_peer_device, ov_bm_ref);
	if (peer_device->fast_ov_bitmap != NULL) {
#ifdef _LIN
		sub_kvmalloc_mem_usage(peer_device->fast_ov_bitmap, sizeof(VOLUME_BITMAP_BUFFER) + peer_device->fast_ov_bitmap->BitmapSize);
#endif
		kvfree(peer_device->fast_ov_bitmap);
		peer_device->fast_ov_bitmap = NULL;
		bsr_info(213, BSR_LC_RESYNC_OV, peer_device, "The bitmap buffer for online verification has been removed.");
	}
}

// BSR-1121
extern ULONG_PTR bsr_ov_bm_bits(struct bsr_peer_device *peer_device)
{
	if (peer_device->fast_ov_bitmap == NULL)
		return bsr_bm_bits(peer_device->device);
#ifdef _WIN
	return (ULONG_PTR)peer_device->fast_ov_bitmap->BitmapSize.QuadPart * BITS_PER_BYTE;
#else // _LIN
	return peer_device->fast_ov_bitmap->BitmapSize * BITS_PER_BYTE;
#endif
}

// BSR-118
extern ULONG_PTR bsr_ov_bm_test_bit(struct bsr_peer_device *peer_device, const ULONG_PTR bitnr)
{
	PCHAR pByte;
	ULONG_PTR ret;

	// full ov
	if(peer_device->fast_ov_bitmap == NULL)
		return 1;

	// BSR-835
	if (!kref_get_unless_zero(&peer_device->ov_bm_ref))
		return 0;

	pByte = (PCHAR)peer_device->fast_ov_bitmap->Buffer;

	if (bitnr >= bsr_ov_bm_bits(peer_device))
		ret = BSR_END_OF_BITMAP;
	else
		ret = (pByte[BM_SECT_TO_BIT(bitnr)] >> (bitnr % BITS_PER_BYTE)) & 0x01;

	// BSR-835
	kref_put(&peer_device->ov_bm_ref, bsr_free_ov_bm);

	return ret;
}

extern ULONG_PTR bsr_ov_bm_total_weight(struct bsr_peer_device *peer_device)
{
	PCHAR pByte;
	ULONG_PTR bit;
	ULONG_PTR s = 0;

	// full ov
	if (peer_device->fast_ov_bitmap == NULL)
		return bsr_bm_bits(peer_device->device);
	
	// BSR-835 if kref is 0, it has been freed by another thread
	if (!kref_get_unless_zero(&peer_device->ov_bm_ref))
		return 0;

	pByte = (PCHAR)peer_device->fast_ov_bitmap->Buffer;

	for (bit = peer_device->ov_bm_position; bit < bsr_ov_bm_bits(peer_device); bit++) {
		// BSR-835 if not Connected or VerifyS, stop checking the bit
		if (peer_device->connection->cstate[NOW] < C_CONNECTED || peer_device->repl_state[NOW] != L_VERIFY_S) {
			s = 0;
			break;
		}

		if (((pByte[BM_SECT_TO_BIT(bit)] >> (bit % BITS_PER_BYTE)) & 0x01) == 1)
			s++;
	}

	// BSR-835 if kref is 0, the bitmap buffer needs to be freed
	kref_put(&peer_device->ov_bm_ref, bsr_free_ov_bm);

	return s;
}

extern ULONG_PTR bsr_ov_bm_range_find_next(struct bsr_peer_device *peer_device, ULONG_PTR start, ULONG_PTR end)
{
	PCHAR pByte;
	ULONG_PTR bit;

	// full ov
	if(peer_device->fast_ov_bitmap == NULL)
		return start;

	// BSR-835
	if (!kref_get_unless_zero(&peer_device->ov_bm_ref))
		return start;

	pByte = (PCHAR)peer_device->fast_ov_bitmap->Buffer;
	
	for(bit = start; bit < end; bit++) {
		// BSR-835
		if (peer_device->connection->cstate[NOW] < C_CONNECTED || peer_device->repl_state[NOW] != L_VERIFY_S) {
			bit = start; 
			break;
		}
		
		if (bit >= bsr_ov_bm_bits(peer_device))
			break;

		if (((pByte[BM_SECT_TO_BIT(bit)] >> (bit % BITS_PER_BYTE)) & 0x01) == 1)
			break;
	}
	

	// BSR-835
	kref_put(&peer_device->ov_bm_ref, bsr_free_ov_bm);
	
	return bit;
}


/*
* caution: requires spinlock unlock, otherwise using it may cause DPC timeout.
*/
extern ULONG_PTR bsr_ov_bm_find_abort_bit(struct bsr_peer_device *peer_device)
{
	PCHAR pByte;
	ULONG_PTR bit;
	ULONG_PTR s = 0;

	if(peer_device->fast_ov_bitmap == NULL)
		return bsr_bm_bits(peer_device->device) - peer_device->ov_left;

	// BSR-835
	if (!kref_get_unless_zero(&peer_device->ov_bm_ref))
		return 0;

	pByte = (PCHAR)peer_device->fast_ov_bitmap->Buffer;

	for (bit = (bsr_ov_bm_bits(peer_device) - 1); bit > 0; bit--) {
		if (((pByte[BM_SECT_TO_BIT(bit)] >> (bit % BITS_PER_BYTE)) & 0x01) == 1) {
			s++;
			if (s == peer_device->ov_left)
				break;
		}
	}
	// BSR-835
	kref_put(&peer_device->ov_bm_ref, bsr_free_ov_bm);

	return bit;
}

extern ULONG_PTR bsr_bm_range_find_next(struct bsr_peer_device *peer_device, ULONG_PTR start, ULONG_PTR end) 
{
	return bm_op(peer_device->device, peer_device->bitmap_index, start, end,
		BM_OP_RANGE_FIND_BIT, NULL);
}

// DW-1979
extern ULONG_PTR bsr_bm_range_find_next_zero(struct bsr_peer_device *peer_device, ULONG_PTR start, ULONG_PTR end)
{
	return bm_op(peer_device->device, peer_device->bitmap_index, start, end,
		BM_OP_RANGE_FIND_ZERO_BIT, NULL);
}

#if 0
/* not yet needed for anything. */
unsigned long bsr_bm_find_next_zero(struct bsr_peer_device *peer_device, unsigned long start)
{
	return bm_op(peer_device->device, peer_device->bitmap_index, start, -1UL,
		     BM_OP_FIND_ZERO_BIT, NULL);
}
#endif

/* does not spin_lock_irqsave.
 * you must take bsr_bm_lock() first */
ULONG_PTR _bsr_bm_find_next(struct bsr_peer_device *peer_device, ULONG_PTR start)
{
	/* WARN_ON(!(device->b->bm_flags & BM_LOCK_SET)); */
	return ____bm_op(peer_device->device, peer_device->bitmap_index, start, BSR_END_OF_BITMAP,
		    BM_OP_FIND_BIT, NULL, KM_USER0);
}
ULONG_PTR _bsr_bm_find_next_zero(struct bsr_peer_device *peer_device, ULONG_PTR start)
{
	/* WARN_ON(!(device->b->bm_flags & BM_LOCK_SET)); */
	return ____bm_op(peer_device->device, peer_device->bitmap_index, start, BSR_END_OF_BITMAP,
		    BM_OP_FIND_ZERO_BIT, NULL, KM_USER0);
}
ULONG_PTR bsr_bm_set_bits(struct bsr_device *device, unsigned int bitmap_index,
    ULONG_PTR start, ULONG_PTR end)
{
	ULONG_PTR count = bm_op(device, bitmap_index, start, end, BM_OP_SET, NULL);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(count);
#endif
	return count;
}
static __always_inline void
__bm_many_bits_op(struct bsr_device *device, unsigned int bitmap_index, ULONG_PTR start, ULONG_PTR end,
	enum bitmap_operations op)
{
	struct bsr_bitmap *bitmap = device->bitmap;
	ULONG_PTR bit = start;
#ifdef _WIN
	ULONG_PTR offset = start;
#endif
	spin_lock_irq(&bitmap->bm_lock);

	if (end >= bitmap->bm_bits)
		end = bitmap->bm_bits - 1;

	while (bit <= end) {
		ULONG_PTR last_bit = last_bit_on_page(bitmap, bitmap_index, bit);
		if (end < last_bit)
			last_bit = end;

		__bm_op(device, bitmap_index, bit, last_bit, op, NULL);
		bit = last_bit + 1;

		// DW-1996 use windows instead of need_resched()
#ifdef _WIN
		if (1 <= ((bit - offset) / RANGE_FIND_NEXT_BIT)) {
			spin_unlock_irq(&bitmap->bm_lock);
			offset = bit;
			spin_lock_irq(&bitmap->bm_lock);
		}
#else // _LIN
		if (need_resched()) {
			spin_unlock_irq(&bitmap->bm_lock);
			cond_resched();
			spin_lock_irq(&bitmap->bm_lock);
		}
#endif
	}
	spin_unlock_irq(&bitmap->bm_lock);
}
void bsr_bm_set_many_bits(struct bsr_peer_device *peer_device, ULONG_PTR start, ULONG_PTR end)
{
	__bm_many_bits_op(peer_device->device, peer_device->bitmap_index, start, end, BM_OP_SET);
}
void bsr_bm_clear_many_bits(struct bsr_device *device, int bitmap_index, ULONG_PTR start, ULONG_PTR end)
{
	__bm_many_bits_op(device, bitmap_index, start, end, BM_OP_CLEAR);
}

/* set all bits in the bitmap */
void bsr_bm_set_all(struct bsr_device *device)
{
       struct bsr_bitmap *bitmap = device->bitmap;
       unsigned int bitmap_index;

       for (bitmap_index = 0; bitmap_index < bitmap->bm_max_peers; bitmap_index++)
		   __bm_many_bits_op(device, bitmap_index, 0, BSR_END_OF_BITMAP, BM_OP_SET);
}

/* clear all bits in the bitmap */
void bsr_bm_clear_all(struct bsr_device *device)
{
	struct bsr_bitmap *bitmap = device->bitmap;
	unsigned int bitmap_index;

	for (bitmap_index = 0; bitmap_index < bitmap->bm_max_peers; bitmap_index++)
		__bm_many_bits_op(device, bitmap_index, 0, BSR_END_OF_BITMAP, BM_OP_CLEAR);
}
ULONG_PTR bsr_bm_clear_bits(struct bsr_device *device, unsigned int bitmap_index,
	ULONG_PTR start, ULONG_PTR end)
{
	ULONG_PTR count = bm_op(device, bitmap_index, start, end, BM_OP_CLEAR, NULL);
#ifdef _WIN64
	BUG_ON_UINT32_OVER(count);
#endif
	return count;
}

/* returns bit state
 * wants bitnr, NOT sector.
 * inherently racy... area needs to be locked by means of {al,rs}_lru
 *  1 ... bit set
 *  0 ... bit not set
 * -1 ... first out of bounds access, stop testing for bits!
 */
ULONG_PTR bsr_bm_test_bit(struct bsr_peer_device *peer_device, const ULONG_PTR bitnr)
{
	struct bsr_bitmap *bitmap = peer_device->device->bitmap;
	unsigned long irq_flags;
	ULONG_PTR ret;

	spin_lock_irqsave(&bitmap->bm_lock, irq_flags);
	if (bitnr >= bitmap->bm_bits)
		ret = BSR_END_OF_BITMAP;
	else {
		ret = __bm_op(peer_device->device, peer_device->bitmap_index, bitnr, bitnr,
			BM_OP_COUNT, NULL);
	}
	spin_unlock_irqrestore(&bitmap->bm_lock, irq_flags);
	return ret;
}

/* returns number of bits set in the range [s, e] */
ULONG_PTR bsr_bm_count_bits(struct bsr_device *device, unsigned int bitmap_index, ULONG_PTR s, ULONG_PTR e)
{
	ULONG_PTR count = bm_op(device, bitmap_index, s, e, BM_OP_COUNT, NULL);
#ifdef _WIN64
	BUG_ON_INT32_OVER(count);
#endif
	return count;
}

#if 0
void bsr_bm_copy_slot(struct bsr_device *device, unsigned int from_index, unsigned int to_index)
{
	struct bsr_bitmap *bitmap = device->bitmap;
	ULONG_PTR word_nr, from_word_nr, to_word_nr;
	unsigned int from_page_nr, to_page_nr, current_page_nr;
	u32 data_word, *addr;

	spin_lock_irq(&bitmap->bm_lock);

	bitmap->bm_set[to_index] = 0;
	current_page_nr = 0;
	addr = bsr_kmap_atomic(bitmap->bm_pages[current_page_nr], KM_IRQ1);
	for (word_nr = 0; word_nr < bitmap->bm_words; word_nr += bitmap->bm_max_peers) {
		from_word_nr = word_nr + from_index;
		from_page_nr = (unsigned int)word32_to_page(from_word_nr);
		to_word_nr = word_nr + to_index;
		to_page_nr = (unsigned int)word32_to_page(to_word_nr);

		if (current_page_nr != from_page_nr) {
			bsr_kunmap_atomic(addr, KM_IRQ1);
			if (need_resched()) {
				spin_unlock_irq(&bitmap->bm_lock);
				cond_resched();
				spin_lock_irq(&bitmap->bm_lock);
			}
			current_page_nr = from_page_nr;
			addr = bsr_kmap_atomic(bitmap->bm_pages[current_page_nr], KM_IRQ1);
		}
		data_word = addr[word32_in_page(from_word_nr)];

		if (word_nr == bitmap->bm_words - bitmap->bm_max_peers) {
            ULONG_PTR lw = word_nr / bitmap->bm_max_peers;
			if (bitmap->bm_bits < (lw + 1) * 32)
			    data_word &= cpu_to_le32((1 << (bitmap->bm_bits - lw * 32)) - 1);
		}

		if (current_page_nr != to_page_nr) {
			bsr_kunmap_atomic(addr, KM_IRQ1);
			current_page_nr = to_page_nr;
			addr = bsr_kmap_atomic(bitmap->bm_pages[current_page_nr], KM_IRQ1);
		}

		if (addr[word32_in_page(to_word_nr)] != data_word)
			bm_set_page_need_writeout(bitmap->bm_pages[current_page_nr]);
		addr[word32_in_page(to_word_nr)] = data_word;
		bitmap->bm_set[to_index] += hweight32(data_word);
	}
	bsr_kunmap_atomic(addr, KM_IRQ1);

	spin_unlock_irq(&bitmap->bm_lock);
}
#endif