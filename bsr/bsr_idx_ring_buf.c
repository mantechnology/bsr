#include "./bsr_idx_ring_buf.h"
#include "./bsr_int.h"

bool idx_ring_commit(struct idx_ring_buffer *rb, struct acquire_data ad)
{
	LARGE_INTEGER	interval;
	interval.QuadPart = (-1 * 1 * 10000);   // wait 1ms relative

	while (InterlockedCompareExchange(&rb->r_idx.committed, (ad.next % rb->max_count), ad.prev) != ad.prev) {
		//SwitchToThread()	
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	return true;
}

bool idx_ring_consume(struct idx_ring_buffer *rb, LONG *consume)
{
	LONG committed, consumed, next;
	//head
	committed = InterlockedCompareExchange(&rb->r_idx.committed, 0, 0);
	//tail
	*consume = consumed = InterlockedCompareExchange(&rb->r_idx.consumed, 0, 0);
	next = consumed + 1;

	if (committed == consumed) {
		return false;
	}

	InterlockedExchange(&rb->r_idx.consumed, (next % rb->max_count));

	return true;
}


bool idx_ring_dispose(struct idx_ring_buffer *rb)
{
	LONG committed, disposed, next;
	//head
	committed = InterlockedCompareExchange(&rb->r_idx.committed, 0, 0);
	//tail
	disposed = InterlockedCompareExchange(&rb->r_idx.disposed, 0, 0);
	next = disposed + 1;

	if (committed == disposed) {
		return false;
	}

	InterlockedExchange(&rb->r_idx.disposed, (next % rb->max_count));

	return true;
}

LONG idx_ring_acquire(struct idx_ring_buffer *rb, struct acquire_data* ad)
{
	LONG acquired = 0, disposed = 0, next = 0;
	LARGE_INTEGER	interval;
	interval.QuadPart = (-1 * 10 * 10000);   // wait 10ms relative

	while (rb->r_idx.has_consumer) {
		acquired = InterlockedCompareExchange(&rb->r_idx.acquired, 0, 0);
		disposed = InterlockedCompareExchange(&rb->r_idx.disposed, 0, 0);
		next = acquired + 1;

		if (acquired < disposed) {
			if (next < disposed) {
				if (InterlockedCompareExchange(&rb->r_idx.acquired, next, acquired) != acquired)  {
					continue;
				}

				break;
			}
			else {
				KeDelayExecutionThread(KernelMode, FALSE, &interval);
				continue;
			}
		}
		else {
			if (next >= rb->max_count) {
				if (disposed) {
					if (InterlockedCompareExchange(&rb->r_idx.acquired, (next % rb->max_count), acquired) != acquired) {
						continue;
					}

					break;
				}
				else {
					KeDelayExecutionThread(KernelMode, FALSE, &interval);
					continue;
				}
			}
			else {
				if (InterlockedCompareExchange(&rb->r_idx.acquired, next, acquired) != acquired)
					continue;

				break;
			}
		}
	}

	ad->prev = acquired;
	ad->next = next;

	return acquired;
}
