#include <linux/blkdev.h>
#include <linux/fs.h>

struct bdev_handle* foo(void);

struct bdev_handle* foo(void) {
	return bdev_open_by_path("", BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_EXCL, NULL, NULL);
}
