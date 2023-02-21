/* { "version": "v5.19-rc1", "commit": "cf0fbf894bb543f472f682c486be48298eccf199", "comment": "The bdev_max_discard_sectors was added", "author": "Christoph Hellwig <hch@lst.de>", "date": "Fri Apr 15 06:52:54 2022 +0200" } */

#include <linux/blkdev.h>

// BSR-1037 rhel 9.1(5.14.0-162.6.1.el9_1.x86_64)
unsigned int foo(struct block_device *bdev)
{
	return bdev_max_discard_sectors(bdev);
}
