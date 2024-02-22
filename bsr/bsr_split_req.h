
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

// BSR-997
// DW-2042
struct bsr_scope_sector {
	sector_t start;	/* start sector number */
	sector_t end;	/* end sector number */
	struct list_head sector_list;
};

// DW-1911
struct bsr_marked_replicate {
	ULONG_PTR bb;	/* current bitmap bit */
	u8 marked_rl;    /* marks the sector as bit. (4k = 8sector = u8(8bit)) */
	struct list_head marked_rl_list;
	u16 end_unmarked_rl;
};

struct bsr_split_req_bitmap_bit {
	struct bsr_scope_bitmap_bit s;
	ULONG_PTR cur;
	ULONG_PTR end_oos;
};

// DW-2042, BSR-997
int bsr_scope_list_add(struct list_head *scope_sectors, sector_t sst, sector_t est);
// DW-2042, BSR-997 if you already have a range, remove the duplicate entry. (all list item)
void bsr_scope_list_all_check_and_dedup(struct list_head *scope_sectors, struct bsr_scope_sector *new_scope);
// DW-2042, BSR-997 validate that range is already (null return if not already)
struct bsr_scope_sector *bsr_scope_list_check_and_expand_dup(struct list_head *scope_sectors, sector_t sst, sector_t est);

/* 
	"resync_pending" is used to ensure consistency for the OOS area received during synchronization.
*/
// DW-2042 get duplicate or non-redundant ranges from sst to est (cst is the last search sector)
bool bsr_resync_pending_scope(struct bsr_peer_device* peer_device, sector_t sst, sector_t est, sector_t *cst);
// DW-2042 remove the duplicate range.(examined for all/front/middle/end)
int bsr_dedup_from_resync_pending(struct bsr_peer_device *peer_device, sector_t sst, sector_t est);

/* 
	"marked_replicate" is used to ensure consistency if replication received during synchronization is smaller than the bitmap size. 
*/
int bsr_list_add_marked(struct bsr_peer_device* peer_device, sector_t sst, sector_t est, unsigned int size, ULONG_PTR in_sync);
bool is_marked_rl_bb(struct bsr_peer_device *peer_device, struct bsr_marked_replicate **marked_rl, ULONG_PTR bb);
bool check_unmarked_and_processing(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req);

/* 
	"split request" is used to ensure consistency if there are "marked_replicate" or "resync_pending" and "in sync" in the synchronization response data reception area.
*/
bool prepare_split_peer_request(struct bsr_peer_device *peer_device, struct bsr_split_req_bitmap_bit *bb, atomic_t *split_count);
bool is_oos_belong_to_repl_area(struct bsr_peer_device *peer_device, struct bsr_scope_bitmap_bit sbb);
int split_request_marked_submit(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req, uint32_t peer_seq, struct bsr_split_req_bitmap_bit bb,
struct bsr_marked_replicate *marked_rl, atomic_t *split_count, int *submit_count, int(*cb)(struct bsr_work *, int cancel));
int split_request_submit(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_req, uint32_t peer_seq, struct bsr_split_req_bitmap_bit bb, ULONG_PTR offset, atomic_t *split_count,
	int *submit_count, struct bsr_marked_replicate *marked_rl, int(*cb)(struct bsr_work *, int cancel));
struct bsr_peer_request *split_read_in_block(struct bsr_peer_device *peer_device, struct bsr_peer_request *peer_request, sector_t sector,
	ULONG_PTR offset, unsigned int size, struct bsr_split_req_bitmap_bit bb, ULONG_PTR flags, atomic_t* split_count, char* verify, int(*cb)(struct bsr_work *, int cancel));

#endif