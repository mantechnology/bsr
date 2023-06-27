#include <linux/blkdev.h>

bool test(struct block_device *b) {
	return bdi_congested(b);
}
