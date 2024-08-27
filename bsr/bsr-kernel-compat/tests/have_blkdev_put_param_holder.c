#include <linux/blkdev.h>
#include <linux/fs.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void holder_blkdev_put(struct block_device *bdev, void *holder);

void foo(void)
{
    BUILD_BUG_ON(!(__same_type(blkdev_put, holder_blkdev_put)));
}