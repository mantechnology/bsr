#include <linux/blkdev.h>

struct request_queue *foo(make_request_fn *fn)
{
	return blk_alloc_queue(fn, NUMA_NO_NODE);
}
