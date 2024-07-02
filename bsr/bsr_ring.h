#ifndef BSR_RING_H
#define BSR_RING_H

#ifdef _WIN
#include <ntddk.h>
#include <stdbool.h>
#include "./bsr-kernel-compat/windows/bsr_windows.h"
#else
// BSR-581
// add headers for linux
#include "./bsr-kernel-compat/bsr_wrappers.h"
#include <linux/types.h>
#include <linux/delay.h>
#endif

#define IDX_DATA_RECORDING	0x00
#define IDX_DATA_COMPLETION	0x01

#define IDX_OPTION_LENGTH	0x01

struct ring_index_t {
	// writable 
	atomic_t acquired;
	// write completed 
	//atomic_t committed;
	// readable 
	atomic_t consumed;
	// next read 
	atomic_t disposed;
	// it's a variable to determine whether a consumer exists or not.
	// used to prevent infinite atmosphere in bsr_idx_ring_acquire().
	bool has_consumer;
	// BSR-583
	bool is_overflowing;
};

struct bsr_idx_ring_buffer {
	struct ring_index_t r_idx;
	atomic_t64 total_count;
	atomic_t64 max_count;
};

// BSR-583 commit, only IDX_DATA_COMPLETION flag is set.
void bsr_idx_ring_commit(struct bsr_idx_ring_buffer *rb, char* flags);
// BSR-583 dispose, set the IDX_DATA_RECORDING flag.
bool bsr_idx_ring_dispose(struct bsr_idx_ring_buffer *rb, char* flags);
bool bsr_idx_ring_acquire(struct bsr_idx_ring_buffer *rb, LONGLONG *idx);
bool bsr_idx_ring_consume(struct bsr_idx_ring_buffer *rb, atomic_t *consume);


// BSR-1145 if a dispose request is made for a non-order "buffer offset", it is flagged without disposeding it.
// if the "buffer offset" in order is disposed, check that the flag is set for the next "buffer offset" and dispose it.
#define OFFSET_MOVE_TO_THE_FRONT 1
#define OFFSET_ALREADY_DISPOSED_FLAG 2

struct ring_offset_t  {
	atomic_t acquired;
	atomic_t disposed;

};
struct bsr_offset_buffer {
	char *buf;
	// BSR-1282 used to prevent duplicate allocates. 0 - not allocated, 1 - already allocated
	atomic_t allocated;
	// BSR-1324
	atomic_t deallocated;
	struct ring_offset_t r_offset;
	u64 total_size;
	atomic_t64 used_size;
};

struct bsr_offset_ring_header {
	int size;
	int flags;
};

// BSR-1145 allocate and reallocate to the specified size.
// only proceed with the reallocate when the buffer is not in use.
char *bsr_offset_ring_adjust(struct bsr_offset_buffer *buf, u64 new_size, char* name);
void bsr_offset_ring_free(struct bsr_offset_buffer *buf);
bool bsr_offset_ring_acquire(struct bsr_offset_buffer *buf, int *offset, int size);
/* must_hold lock */
bool bsr_offset_ring_dispose(struct bsr_offset_buffer *buf, int offset);
#endif