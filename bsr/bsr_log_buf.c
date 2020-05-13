#include "./bsr_log_buf.h"
#include "./bsr_int.h"

bool log_ring_commit(struct log_ring_buffer *rb, struct acquire_data ad)
{
	LARGE_INTEGER	interval;
	interval.QuadPart = (-1 * 1 * 10000);   // wait 1ms relative

	while (InterlockedCompareExchange(&rb->index.committed, (ad.next % rb->max_count), ad.prev) != ad.prev) {
		//SwitchToThread()	
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	return true;
}

bool log_ring_consume(struct log_ring_buffer *rb, LONG *consume)
{
	LONG committed, consumed, next;

	//head
	committed = InterlockedCompareExchange(&rb->index.committed, 0, 0);
	//tail
	*consume = consumed = InterlockedCompareExchange(&rb->index.consumed, 0, 0);
	next = consumed + 1;

	if (committed == consumed) {
		return false;
	}

	InterlockedExchange(&rb->index.consumed, (next % rb->max_count));

	return true;
}


bool log_ring_dispose(struct log_ring_buffer *rb)
{
	LONG committed, disposed, next;
	//head
	committed = InterlockedCompareExchange(&rb->index.committed, 0, 0);
	//tail
	disposed = InterlockedCompareExchange(&rb->index.disposed, 0, 0);
	next = disposed + 1;

	if (committed == disposed) {
		return false;
	}

	InterlockedExchange(&rb->index.disposed, (next % rb->max_count));

	return true;
}

LONG log_ring_acquire(struct log_ring_buffer *rb, struct acquire_data* ad)
{
	LONG acquired, disposed, next;
	LARGE_INTEGER	interval;
	interval.QuadPart = (-1 * 10 * 10000);   // wait 10ms relative

	for (;;) {
		acquired = InterlockedCompareExchange(&rb->index.acquired, 0, 0);
		disposed = InterlockedCompareExchange(&rb->index.disposed, 0, 0);
		next = acquired + 1;

		if (acquired < disposed) {
			if (next < disposed) {
				if (InterlockedCompareExchange(&rb->index.acquired, next, acquired) != acquired) 
					continue;

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
					if (InterlockedCompareExchange(&rb->index.acquired, (next % rb->max_count), acquired) != acquired) 
						continue;

					break;
				}
				else {
					KeDelayExecutionThread(KernelMode, FALSE, &interval);
					continue;
				}
			}
			else {
				if (InterlockedCompareExchange(&rb->index.acquired, next, acquired) != acquired) 
					continue;

				break;
			}
		}
	}

	ad->prev = acquired;
	ad->next = next;

	return acquired;
}
