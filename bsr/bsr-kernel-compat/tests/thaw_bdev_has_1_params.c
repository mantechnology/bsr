#include <linux/fs.h>
#include <linux/blkdev.h>

void foo(struct block_device *bdev) {
	thaw_bdev(bdev);
}
