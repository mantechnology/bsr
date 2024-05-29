// BSR-1242 header changed by committing v5.18-rc1.
#include <linux/blkdev.h>

bool foo(struct gendisk *disk, sector_t size)
{
	return set_capacity_and_notify(disk, size);
}
