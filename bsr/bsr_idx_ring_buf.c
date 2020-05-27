#include "./bsr_idx_ring_buf.h"
#include "./bsr_int.h"

// BSR-583
void idx_ring_commit(struct idx_ring_buffer *rb, char* flags)
{
	*flags = IDX_DATA_COMPLETION;
}

bool idx_ring_consume(struct idx_ring_buffer *rb, atomic_t *consume)
{
	int acquired, consumed, next; 
	//head
	acquired = atomic_read(&rb->r_idx.acquired);

	//tail
	consumed = atomic_read(&rb->r_idx.consumed);
	atomic_set(consume, consumed);
	next = consumed + 1;

	if (acquired == consumed) {
		return false;
	}

	atomic_set(&rb->r_idx.consumed, (next % atomic_read64(&rb->max_count)));

	return true;
}


bool idx_ring_dispose(struct idx_ring_buffer *rb, char* flags)
{
	int acquired,disposed, next;
	//head
	acquired = atomic_read(&rb->r_idx.acquired);
	//tail
	disposed = atomic_read(&rb->r_idx.disposed);
	next = disposed + 1;

	if (acquired == disposed) {
		return false;
	}

	*flags = IDX_DATA_RECORDING;
	atomic_set(&rb->r_idx.disposed, (next % atomic_read64(&rb->max_count)));

	return true;
}

bool idx_ring_acquire(struct idx_ring_buffer *rb, LONGLONG *idx)
{
	int acquired = 0, disposed = 0, next = 0;
	LONGLONG remaining = 0;

	while (true) {
		acquired = atomic_read(&rb->r_idx.acquired);
		disposed = atomic_read(&rb->r_idx.disposed);
		next = acquired + 1;

		// BSR-583 after an overflow occurs, it fails until more than 10% of space is left.
		if (rb->r_idx.is_overflowing == true) {
			if (acquired < disposed)
				remaining = (acquired + atomic_read64(&rb->max_count)) - disposed;
			else 
				remaining = acquired - disposed;
		
			if (remaining < (atomic_read64(&rb->max_count) / 10))
				return false;
		}
		// 100 < 500 
		if (acquired < disposed) {
			if (next < disposed) {
				if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, next) != acquired)
					continue;
				break;
			}
			else {
				// BSR-578 when the buffer is overflowing but there is no consumer
				if (!rb->r_idx.has_consumer) {
					if (!atomic_cmpxchg(&rb->r_idx.acquired, acquired, next) != acquired)
						break;
				}
				else {
					// BSR-583 occurs when consumption is slow.
					rb->r_idx.is_overflowing = true;
					return false;
				}

				continue;
			}
		}
		else {
			if (next >= atomic_read64(&rb->max_count)) {
				if (disposed) {
					if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, (next % atomic_read64(&rb->max_count))) != acquired) {
						continue;
					}
					break;
				}
				else {
					// BSR-578 when the buffer is overflowing but there is no consumer
					if (!rb->r_idx.has_consumer) {
						if (!atomic_cmpxchg(&rb->r_idx.acquired, acquired, next) != acquired)
							break;
					}
					else {
						// BSR-583 supply not consumed
						rb->r_idx.is_overflowing = true;
						return false;
					}
				}
			}
			else {
				if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, next) != acquired)
					continue;

				break;
			}
		}
	}

	rb->r_idx.is_overflowing = false;
	*idx = acquired;

	return true;
}

