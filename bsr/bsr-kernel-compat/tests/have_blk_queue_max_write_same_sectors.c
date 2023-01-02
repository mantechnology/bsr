// BSR-1006 rhel 9.1(5.14.0-162.6.1.el9_1.x86_64)
#include <linux/blkdev.h>

void foo(struct request_queue *q, unsigned int s)
{
	blk_queue_max_write_same_sectors(q, s);
}
