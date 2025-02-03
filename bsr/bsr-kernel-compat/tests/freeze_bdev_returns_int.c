#include <linux/blkdev.h>

void dummy(void)
{
	struct block_device *bdev = NULL;
	BUILD_BUG_ON(!(__same_type(freeze_bdev(bdev), int)));  
}
