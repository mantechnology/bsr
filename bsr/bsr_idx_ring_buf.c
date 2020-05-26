#include "./bsr_int.h"
#include "./bsr_idx_ring_buf.h"

bool idx_ring_commit(struct idx_ring_buffer *rb, struct acquire_data ad)
{
	while (atomic_cmpxchg(&rb->r_idx.committed, atomic_read(&ad.prev), (atomic_read(&ad.next) % atomic_read64(&rb->max_count))) != atomic_read(&ad.prev)) {
		msleep(10); // wait 10ms relative
	}

	// BSR-578 if the consumer is not started, initialize disposed and consumed to committed
	if (!rb->r_idx.has_consumer) {
		LONG committed = atomic_read(&rb->r_idx.committed);

		if (atomic_read64(&rb->max_count) < atomic_read64(&rb->total_count)) {
			atomic_set(&rb->r_idx.disposed, committed);
			atomic_set(&rb->r_idx.consumed, committed);
		}
	}

	return true;
}

bool idx_ring_consume(struct idx_ring_buffer *rb, atomic_t *consume)
{
	int committed, consumed, next;
	//head
	committed = atomic_read(&rb->r_idx.committed);
	//tail
	consumed = atomic_read(&rb->r_idx.consumed);
	atomic_set(consume, consumed);
	next = consumed + 1;

	if (committed == consumed) {
		return false;
	}

	atomic_set(&rb->r_idx.consumed, (next % atomic_read64(&rb->max_count)));

	return true;
}


bool idx_ring_dispose(struct idx_ring_buffer *rb)
{
	int committed, disposed, next;
	//head
	committed = atomic_read(&rb->r_idx.committed);
	//tail
	disposed = atomic_read(&rb->r_idx.disposed);
	next = disposed + 1;

	if (committed == disposed) {
		return false;
	}

	atomic_set(&rb->r_idx.disposed, (next % atomic_read64(&rb->max_count)));

	return true;
}

LONG idx_ring_acquire(struct idx_ring_buffer *rb, struct acquire_data* ad)
{
	int acquired = 0, disposed = 0, next = 0;

	while (true) {
		acquired = atomic_read(&rb->r_idx.acquired);
		disposed = atomic_read(&rb->r_idx.disposed);
		next = acquired + 1;

		if (acquired < disposed) {
			if (next < disposed) {
				if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, next) != acquired)  {
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
					// BSR-578 short delay may result in hang
					msleep(100); // wait 10ms relative
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
						// BSR-578 short delay may result in hang
						msleep(100); // wait 10ms relative
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

	atomic_set(&ad->prev, acquired);
	atomic_set(&ad->next, next);

	return acquired;
}

