// BSR-1512
/*
 * Check if blk_queue_write_cache() takes only one parameter (struct request_queue *q).
 *
 * In some kernel versions, blk_queue_write_cache() accepts three parameters:
 *   (struct request_queue *q, bool write_cache, bool fua)
 * while in others it has been simplified to accept only the request_queue pointer.
 *
 * When it takes only one parameter, all write cache flags should be set
 * through the queue's limits (q->limits) before calling this function.
 *
 * This check helps ensure compatibility with different kernel APIs.
 */
#include <linux/blkdev.h>
#include <linux/blk_types.h> 

void dummy(struct request_queue *q)
{
	blk_queue_write_cache(q);
}
