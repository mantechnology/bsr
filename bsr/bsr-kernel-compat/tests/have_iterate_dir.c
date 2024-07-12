#include <linux/fs.h>

void foo(void)
{
	struct file *fd = NULL;

	iterate_dir(fd, NULL);
}
