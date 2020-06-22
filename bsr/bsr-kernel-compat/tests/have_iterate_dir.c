#include <linux/fs.h>

void foo(void)
{
	struct file *fd;

	iterate_dir(fd, NULL);
}
