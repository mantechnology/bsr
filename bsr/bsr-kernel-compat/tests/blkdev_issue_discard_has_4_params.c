// BSR-1006 rhel 9.1(5.14.0-162.6.1.el9_1.x86_64)
#include <linux/blkdev.h>

void foo(void)
{
	struct block_device *bdev = NULL;
	sector_t start = 0;
	unsigned int max_discard_sectors = 0;
	
	blkdev_issue_discard(bdev, start, max_discard_sectors, GFP_NOIO);
}
