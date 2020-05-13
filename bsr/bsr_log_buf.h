#ifndef BSR_LOG_BUF_H
#define BSR_LOG_BUF_H

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
};

struct log_ring_buffer {
	struct ring_index_t index;
	LONGLONG total_count;
	LONGLONG max_count;
};

bool log_ring_commit(struct log_ring_buffer *rb, struct acquire_data ad);
bool log_ring_dispose(struct log_ring_buffer *rb);
LONG log_ring_acquire(struct log_ring_buffer *rb, struct acquire_data* ad);
bool log_ring_consume(struct log_ring_buffer *rb, LONG *consume);

#endif