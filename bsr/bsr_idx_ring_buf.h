#ifndef BSR_IDX_RING_BUF_H
#define BSR_IDX_RING_BUF_H

#include <ntddk.h>
#include <stdbool.h>

struct acquire_data {
	LONG prev;
	LONG next;
};

struct ring_index_t {
	// writable 
	LONG acquired;
	// write completed 
	LONG committed;
	// readable 
	LONG consumed;
	// next read 
	LONG disposed;
	// it's a variable to determine whether a consumer exists or not.
	// used to prevent infinite atmosphere in idx_ring_acquire().
	bool has_consumer;
};

struct idx_ring_buffer {
	struct ring_index_t r_idx;
	LONGLONG total_count;
	LONGLONG max_count;
};

bool idx_ring_commit(struct idx_ring_buffer *rb, struct acquire_data ad);
bool idx_ring_dispose(struct idx_ring_buffer *rb);
LONG idx_ring_acquire(struct idx_ring_buffer *rb, struct acquire_data* ad);
bool idx_ring_consume(struct idx_ring_buffer *rb, LONG *consume);

#endif