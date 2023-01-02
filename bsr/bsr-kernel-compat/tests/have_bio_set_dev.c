// BSR-1006 rhel 9.0 (5.14.0-70.13.1.el9_0.x86_64)
#include <linux/bio.h>

void foo(struct bio *bio, struct block_device *bdev)
{
	bio_set_dev(bio, bdev);
}
