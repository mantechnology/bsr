#include <linux/blkdev.h>
#include <linux/fs.h>

struct super_block *foo(struct block_device *bdev)
{
	return bdev->bd_super;
}
