#include <linux/blkdev.h>

void foo(struct gendisk *disk)
{
	blk_cleanup_disk(disk);
}

