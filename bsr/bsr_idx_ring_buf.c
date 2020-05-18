#include "./bsr_idx_ring_buf.h"
#include "./bsr_int.h"

bool idx_ring_commit(struct idx_ring_buffer *rb, struct acquire_data ad)
{
	while (atomic_cmpxchg(&rb->r_idx.committed, ad.prev, (ad.next % rb->max_count)) != ad.prev) {
		msleep(10); // wait 10ms relative
	}

	// BSR-578 if the consumer is not started, initialize disposed and consumed to committed
	if (!rb->r_idx.has_consumer) {
		LONG committed = atomic_cmpxchg(&rb->r_idx.committed, 0, 0);

		if (atomic_cmpxchg64(&rb->max_count, 0, 0) <
			atomic_cmpxchg64(&rb->total_count, 0, 0)) {
			atomic_set(&rb->r_idx.disposed, committed);
			atomic_set(&rb->r_idx.consumed, committed);
		}
	}

	return true;
}

bool idx_ring_consume(struct idx_ring_buffer *rb, atomic_t *consume)
{
	atomic_t committed, consumed, next;
	//head
	committed = atomic_cmpxchg(&rb->r_idx.committed, 0, 0);
	//tail
	*consume = consumed = atomic_cmpxchg(&rb->r_idx.consumed, 0, 0);
	next = consumed + 1;

	if (committed == consumed) {
		return false;
	}

	atomic_set(&rb->r_idx.consumed, (next % rb->max_count));

	return true;
}


bool idx_ring_dispose(struct idx_ring_buffer *rb)
{
	LONG committed, disposed, next;
	//head
	committed = atomic_cmpxchg(&rb->r_idx.committed, 0, 0);
	//tail
	disposed = atomic_cmpxchg(&rb->r_idx.disposed, 0, 0);
	next = disposed + 1;

	if (committed == disposed) {
		return false;
	}

	atomic_set(&rb->r_idx.disposed, (next % rb->max_count));

	return true;
}

LONG idx_ring_acquire(struct idx_ring_buffer *rb, struct acquire_data* ad)
{
	LONG acquired = 0, disposed = 0, next = 0;

	while (true) {
		acquired = atomic_cmpxchg(&rb->r_idx.acquired, 0, 0);
		disposed = atomic_cmpxchg(&rb->r_idx.disposed, 0, 0);
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
			if (next >= rb->max_count) {
				if (disposed) {
					if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, (next % rb->max_count)) != acquired) {
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

	ad->prev = acquired;
	ad->next = next;

	return acquired;
}
