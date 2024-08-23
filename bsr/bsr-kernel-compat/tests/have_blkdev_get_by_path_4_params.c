#include <linux/blkdev.h>
#include <linux/fs.h>

void foo(void) {
	struct block_device *blkdev;

	blkdev = blkdev_get_by_path("", (fmode_t) 0, (void *) 0, NULL);
}
