#include <linux/blkdev.h>
#include <linux/fs.h>

void foo(void) {
	struct block_device *bdev = NULL;
	void *holder = NULL;
	
	void (*holder_blkdev_put)(struct block_device *, void *) = blkdev_put;
	
	holder_blkdev_put(bdev, holder);
}
