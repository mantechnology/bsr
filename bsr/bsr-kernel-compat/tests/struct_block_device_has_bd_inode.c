
#include <linux/blkdev.h>

struct inode  *foo(struct block_device *bdev)
{
	return bdev->bd_inode;
}
