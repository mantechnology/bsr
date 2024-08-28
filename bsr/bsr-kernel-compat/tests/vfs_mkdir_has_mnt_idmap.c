#include <linux/fs.h>

void foo(void) 
{
	vfs_mkdir(&nop_mnt_idmap, (struct inode *) NULL, (struct dentry *) NULL, 0);
}