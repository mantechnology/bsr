#include <linux/fs.h>

void foo(void) 
{
	vfs_unlink((struct inode *) NULL, (struct dentry *) NULL);
}