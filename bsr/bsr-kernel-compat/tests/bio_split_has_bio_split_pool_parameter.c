#include <linux/bio.h>

/*
 * bio_split() had a memory pool parameter until commit 6feef53 (2.6.28-rc1).
 */
struct bio_pair * test(void)
{
	struct bio *bio = NULL;

	return bio_split(bio, bio_split_pool, 0);
}
