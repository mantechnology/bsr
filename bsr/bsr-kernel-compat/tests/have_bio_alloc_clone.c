// BSR-1006 rhel 9.1(5.14.0-162.6.1.el9_1.x86_64)
#include <linux/bio.h>

struct bio *dummy(struct block_device *bdev, struct bio *bio_src, gfp_t gfp,
		struct bio_set *bs)
{
	return bio_alloc_clone(bdev, bio_src, gfp, bs);
}