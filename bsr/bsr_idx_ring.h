#ifndef BSR_IDX_RING_H
#define BSR_IDX_RING_H

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
	atomic_t committed;
	// readable 
	atomic_t consumed;
	// next read 
	atomic_t disposed;
	// it's a variable to determine whether a consumer exists or not.
	// used to prevent infinite atmosphere in idx_ring_acquire().
	bool has_consumer;
	// BSR-583
	bool is_overflowing;
};

struct idx_ring_buffer {
	struct ring_index_t r_idx;
	atomic_t64 total_count;
	atomic_t64 max_count;
};

// BSR-583 commit, only IDX_DATA_COMPLETION flag is set.
void idx_ring_commit(struct idx_ring_buffer *rb, char* flags);
// BSR-583 dispose, set the IDX_DATA_RECORDING flag.
bool idx_ring_dispose(struct idx_ring_buffer *rb, char* flags);
bool idx_ring_acquire(struct idx_ring_buffer *rb, LONGLONG *idx);
bool idx_ring_consume(struct idx_ring_buffer *rb, atomic_t *consume);

#endif