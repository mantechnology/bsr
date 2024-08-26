#include <linux/blkdev.h>

static int _bsr_open(struct gendisk *gd, blk_mode_t mode);
static void _bsr_release(struct gendisk *gd);

const struct block_device_operations bsr_ops = {
	.owner =   THIS_MODULE,
	.open =    _bsr_open,
	.release = _bsr_release,
};

static int _bsr_open(struct gendisk *gd, blk_mode_t mode) 
{
	return 0;
}
static void _bsr_release(struct gendisk *gd) 
{
}