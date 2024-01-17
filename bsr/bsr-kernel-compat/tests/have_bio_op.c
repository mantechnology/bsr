#include <linux/bio.h>

void dummy(struct bio *bio)
{
	bio_op(bio);
}
