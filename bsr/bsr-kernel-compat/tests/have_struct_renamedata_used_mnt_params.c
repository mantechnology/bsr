#include <linux/fs.h>

struct renamedata *foo(struct renamedata *rd)
{	
	rd->old_mnt_userns  = (struct user_namespace *)NULL;
	rd->new_mnt_userns  = (struct user_namespace *)NULL;
	
	return rd;
}

