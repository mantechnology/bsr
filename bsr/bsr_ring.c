#include "./bsr_int.h"
#include "./bsr_ring.h"

// BSR-583
void bsr_idx_ring_commit(struct bsr_idx_ring_buffer *rb, char* flags)
{
	*flags = IDX_DATA_COMPLETION;
}

bool bsr_idx_ring_consume(struct bsr_idx_ring_buffer *rb, atomic_t *consume)
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


bool bsr_idx_ring_dispose(struct bsr_idx_ring_buffer *rb, char* flags)
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

bool bsr_idx_ring_acquire(struct bsr_idx_ring_buffer *rb, LONGLONG *idx)
{
	int acquired = 0, disposed = 0, next = 0;
	LONGLONG remaining = 0;
	LONGLONG max_count = atomic_read64(&rb->max_count);

	while (true) {
		acquired = atomic_read(&rb->r_idx.acquired);
		disposed = atomic_read(&rb->r_idx.disposed);
		next = acquired + 1;

		// BSR-583 after an overflow occurs, it fails until more than 10% of space is left.
		if (rb->r_idx.is_overflowing == true) {
			if (next < disposed) 
				remaining = (next + max_count) - disposed;
			else 
				remaining = max_count - (next - disposed);

			if (remaining < (max_count / 10))
				return false;
		}

		if (acquired < disposed) {
			if (next < disposed) {
				if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, next) != acquired)
					continue;
				break;
			}
			else {
				// BSR-578 when the buffer is overflowing but there is no consumer
				if (!rb->r_idx.has_consumer) {
					if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, next) == acquired)
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
			if (next >= max_count) {
				if (disposed) {
					if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, (next % max_count)) != acquired) {
						continue;
					}
					break;
				}
				else {
					// BSR-578 when the buffer is overflowing but there is no consumer
					if (!rb->r_idx.has_consumer) {
						if (atomic_cmpxchg(&rb->r_idx.acquired, acquired, (next % max_count)) == acquired)
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

// BSR-1145
char* bsr_offset_ring_adjust(struct bsr_offset_buffer *buf, u64 new_size, char *name)
{
	int allocated = atomic_read(&buf->allocated);
	char *buffer = NULL;

	if (buf->buf == NULL) {
		if (new_size == 0) {
			buf->total_size = new_size;
		} else {
			// BSR-1282
			if (!allocated && (allocated == atomic_cmpxchg(&buf->allocated, allocated, 1))) {
				// BSR-1282 increase 1 to prevent unintended deallocation during or after allocation.
				atomic_add64(1, &buf->used_size);
#ifdef _WIN
				buf->buf = (char *)ExAllocatePoolWithTag(NonPagedPool, (size_t)new_size, '63SB');
#else
				buf->buf = (char *)bsr_kvmalloc(new_size, GFP_ATOMIC | __GFP_NOWARN);
#endif
				if (buf->buf) {
					bsr_info(90, BSR_LC_ETC, NO_OBJECT, "%p, allocation of offset buffer to %s, size %d", buf->buf, name, new_size);

					memset(buf->buf, 0, new_size);

					atomic_set(&buf->r_offset.acquired, 0);
					atomic_set(&buf->r_offset.disposed, 0);

					buf->total_size = new_size;
					buffer = buf->buf;
				} else {
					bsr_warn(91, BSR_LC_ETC, NO_OBJECT, "allocation of %s to offset buffer failed. size %d", name, new_size);
					atomic_set(&buf->allocated, 0);
				}

				atomic_sub64(1, &buf->used_size);
			}
		}
	} else {
		if (buf->total_size != new_size) {
			// BSR-1145 when reallocating a buffer, if the buffer is in use, it returns NULL to deactivate the buffer and then reassign it.
			if (!atomic_read64(&buf->used_size)) {
#ifdef _LIN
				sub_kvmalloc_mem_usage(buf->buf, buf->total_size);
#endif
				kvfree2(buf->buf);
				// BSR-1282
				atomic_set(&buf->allocated, 0);

				if (new_size == 0)
					buf->total_size = new_size;
			}
		} else 
			buffer = buf->buf;
	}

	return buffer;
}

void bsr_offset_ring_free(struct bsr_offset_buffer *buf)
{
	if (buf->buf) {
#ifdef _LIN
		sub_kvmalloc_mem_usage(buf->buf, buf->total_size);
#endif
		kvfree2(buf->buf);
		atomic_set(&buf->allocated, 0);
		buf->total_size = 0;
	}
}

bool bsr_offset_ring_dispose(struct bsr_offset_buffer *buf, int offset)
{
	int acquired, disposed, next;
	struct bsr_offset_ring_header *h;
	int size;

	acquired = atomic_read(&buf->r_offset.acquired);
	disposed = atomic_read(&buf->r_offset.disposed);

	h = (struct bsr_offset_ring_header*)(buf->buf + offset);
	size = h->size;
	if (buf->total_size <= (disposed + size))
		disposed = 0;

	next = disposed + size;

	if (disposed != offset) {
		// BSR-1145 if you dispose non-order offsets, set the next flag.
		// failure to do so will result in incorrect data being referenced and inconsistent.
		h->flags |= OFFSET_ALREADY_DISPOSED_FLAG;
		return true;
	}

	if (acquired == disposed)
		return false;

	memset(buf->buf + offset, 0, size);

	// BSR-1145 if OFFSET_ALREADY_DISPOSED_FLAG is set among the successive offsets, it is included in the dispose.
	if (acquired != next) {
		do {
			h = (struct bsr_offset_ring_header*)(buf->buf + next);

			if ((buf->total_size <= (next + sizeof(struct bsr_offset_ring_header))) || 
				(h->flags & OFFSET_MOVE_TO_THE_FRONT)) {
				next = 0;
				if (!acquired)
					break;
				continue;
			}

			if (!(h->flags & OFFSET_ALREADY_DISPOSED_FLAG)) 
				break;

			size = h->size;
			memset(buf->buf + next, 0, size);

			next = next + size;
		} while (acquired != next);
	}

	atomic_set(&buf->r_offset.disposed, next);

	return true;
}

bool bsr_offset_ring_acquire(struct bsr_offset_buffer *buf, int *offset, int size)
{
	int acquired = 0, disposed = 0, next = 0;
	u64 buf_size = buf->total_size;
	struct bsr_offset_ring_header* h;

	acquired = atomic_read(&buf->r_offset.acquired);
	disposed = atomic_read(&buf->r_offset.disposed);
	next = acquired + size;

	if (acquired < disposed) {
		if (next < disposed) {
			if (atomic_cmpxchg(&buf->r_offset.acquired, acquired, next) != acquired) 
				return false;
		} else {
			return false;
		}
	} else {
		if (buf_size <= next) {
			h = (struct bsr_offset_ring_header*)(buf->buf + acquired);
			next = size;
			if (next < disposed) {
				if (atomic_cmpxchg(&buf->r_offset.acquired, acquired, next) != acquired) 
					return false;
				// BSR-1145 set the OFFSET_MOVE_TO_THE_FRONT flag if the remaining buffer size is less than the request size and moves for the front
				// if the size left in the buffer is less than the header, the flags is not set.
				if ((u64)(acquired + sizeof(struct bsr_offset_ring_header)) < buf_size)
					h->flags = OFFSET_MOVE_TO_THE_FRONT;
				acquired = 0;
			} else {
				return false;
			}
		} else {
			if (atomic_cmpxchg(&buf->r_offset.acquired, acquired, next) != acquired) 
				return false;
		}
	}

	h = (struct bsr_offset_ring_header*)(buf->buf + acquired);
	h->size = size;
	h->flags = 0;

	*offset = acquired;

	return true;
}
