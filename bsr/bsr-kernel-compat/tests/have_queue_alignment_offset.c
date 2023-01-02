// BSR-1006 rhel 9.1(5.14.0-162.6.1.el9_1.x86_64)
#include <linux/blkdev.h>

int foo(void)
{
	struct request_queue *q = NULL;
	queue_alignment_offset(q);
}
