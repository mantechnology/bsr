// BSR-1006 rhel 9.0 (5.14.0-70.13.1.el9_0.x86_64)
#include <linux/blkdev.h>

blk_qc_t bsr_submit_bio(struct bio *bio)
{
	return BLK_QC_T_NONE;
}

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void foo(void)
{
	BUILD_BUG_ON(!(__same_type(bsr_submit_bio, submit_bio)));
}
