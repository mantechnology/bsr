#ifndef BSR_IDX_RING_BUF_H
#define BSR_IDX_RING_BUF_H

#ifdef _WIN
#include <ntddk.h>
#include <stdbool.h>
#include "./bsr-kernel-compat/windows/bsr_windows.h"
#else
	// BSR-581
	// TODO add headers required for linux
#endif

struct acquire_data {
	atomic_t prev;
	atomic_t next;
};

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
};

struct idx_ring_buffer {
	struct ring_index_t r_idx;
	atomic_t64 total_count;
	atomic_t64 max_count;
};

bool idx_ring_commit(struct idx_ring_buffer *rb, struct acquire_data ad);
bool idx_ring_dispose(struct idx_ring_buffer *rb);
LONG idx_ring_acquire(struct idx_ring_buffer *rb, struct acquire_data* ad);
bool idx_ring_consume(struct idx_ring_buffer *rb, atomic_t *consume);

#endif