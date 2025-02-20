#include <linux/blkdev.h>
#include <linux/fs.h>
struct file* foo(void);
struct file* foo(void) {
	return bdev_file_open_by_path("", BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_EXCL, NULL, NULL);
}