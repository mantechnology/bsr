#include <linux/fs.h>

void foo(void) 
{
	vfs_rename((struct inode *) NULL,
				(struct dentry *) NULL,
				(struct inode *) NULL,
				(struct dentry *) NULL,
				(struct inode **) NULL);
}