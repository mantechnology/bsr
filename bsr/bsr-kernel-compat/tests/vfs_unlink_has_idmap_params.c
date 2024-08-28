#include <linux/fs.h>

void foo(void) 
{
	vfs_unlink(&nop_mnt_idmap,(struct inode *) NULL, (struct dentry *) NULL, NULL);
}