#include <linux/fs.h>

void dummy(void)
{
	struct super_block *sb = NULL;
	freeze_super(sb);  
}
