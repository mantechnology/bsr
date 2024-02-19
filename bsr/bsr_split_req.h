
#ifndef _BSR_SPLIT_REQ_H
#define _BSR_SPLIT_REQ_H

#include "bsr_int.h"
#ifdef _WIN
#include "../bsr-headers/bsr.h"
#else // _LIN
#include <linux/module.h>
#include <linux/slab.h>
#include <bsr.h>
#endif

// DW-2042
struct bsr_resync_pending_sectors {
	sector_t sst;	/* start sector number */
	sector_t est;	/* end sector number */
	struct list_head pending_sectors;
};

// BSR-997
struct bsr_ov_skip_sectors {
	sector_t sst;	/* start sector number */
	sector_t est;	/* end sector number */
	struct list_head sector_list;
};

// DW-1911
struct bsr_marked_replicate {
	ULONG_PTR bb;	/* current bitmap bit */
	u8 marked_rl;    /* marks the sector as bit. (4k = 8sector = u8(8bit)) */
	struct list_head marked_rl_list;
	u16 end_unmarked_rl;
};

struct split_req_bitmap_bit {
	struct split_bitmap_bit s;
	ULONG_PTR cur;
	ULONG_PTR end_oos;
};

bool prepare_split_peer_request(struct bsr_peer_device *peer_device, struct split_req_bitmap_bit *bb, atomic_t *split_count);
bool is_oos_belong_to_repl_area(struct bsr_peer_device *peer_device, ULONG_PTR start_bb, ULONG_PTR end_next_bb);

int split_marked_request_submit(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req, uint32_t peer_seq, struct split_req_bitmap_bit bb,
	struct bsr_marked_replicate *marked_rl, atomic_t *split_count, int *submit_count, int(*cb)(struct bsr_work *, int cancel));
int split_request_submit(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req, uint32_t peer_seq, struct split_req_bitmap_bit bb, ULONG_PTR offset, atomic_t *split_count,
	int *submit_count, struct bsr_marked_replicate *marked_rl, int(*cb)(struct bsr_work *, int cancel));
struct bsr_peer_request *split_read_in_block(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_request, sector_t sector,
	ULONG_PTR offset, unsigned int size, struct split_req_bitmap_bit bb, ULONG_PTR flags, atomic_t* split_count, char* verify, int(*cb)(struct bsr_work *, int cancel));

bool is_marked_rl_bb(struct bsr_peer_device *peer_device, struct bsr_marked_replicate **marked_rl, ULONG_PTR bb);
int list_add_marked(struct bsr_peer_device* peer_device, sector_t sst, sector_t est, unsigned int size, ULONG_PTR in_sync);
bool check_unmarked_and_processing(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req);

// DW-2042 get duplicate or non-redundant ranges from sst to est (cst is the last search sector)
bool get_resync_pending_range(struct bsr_peer_device* peer_device, sector_t sst, sector_t est, sector_t *cst, bool locked);
// DW-2042 remove the duplicate range.(examined for all/front/middle/end)
int dedup_from_resync_pending(struct bsr_peer_device *peer_device, sector_t sst, sector_t est);
// DW-2042 if you already have a range, remove the duplicate entry. (all list item)
void resync_pending_list_all_check_and_dedup(struct bsr_device* device, struct bsr_resync_pending_sectors *pending_st);
// DW-2042 validate that range is already (null return if not already)
struct bsr_resync_pending_sectors *resync_pending_check_and_expand_dup(struct bsr_device* device, sector_t sst, sector_t est);
// DW-2042 add resync pending only when the range is not included. (sort and add)
int list_add_resync_pending(struct bsr_device* device, sector_t sst, sector_t est);

// BSR-997 validate that range is already (null return if not already)
// similar to resync_pending_check_and_expand_dup()
struct bsr_ov_skip_sectors *ov_check_and_expand_dup(struct bsr_peer_device *peer_device, sector_t sst, sector_t est);
// BSR-997 if you already have a range, remove the duplicate entry. (all list item)
// similar to resync_pending_list_all_check_and_dedup()
void ov_list_all_check_and_dedup(struct bsr_peer_device *peer_device, struct bsr_ov_skip_sectors *ov_st);
#endif