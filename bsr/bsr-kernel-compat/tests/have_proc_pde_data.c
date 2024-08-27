#include <linux/proc_fs.h>

void * main(void)
{
	struct inode *inode = NULL;

	return PDE_DATA(inode);
}
