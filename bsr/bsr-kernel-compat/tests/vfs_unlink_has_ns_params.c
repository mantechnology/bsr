#include <linux/fs.h>

void foo(void) 
{
	vfs_unlink(&init_user_ns, (struct inode *) NULL, (struct dentry *) NULL, NULL);
}