/* { "version": "5.12-rc1", "commit": "7d6beb71da3cc033649d641e1e608713b8220290" */
#include <linux/fs.h>

void foo(void) 
{
	vfs_mkdir(&init_user_ns, (struct inode *) NULL, (struct dentry *) NULL, 0);
}