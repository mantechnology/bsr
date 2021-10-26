/* { "version": "3.1-rc1", "commit": "dae6ad8f37529963ae7df52baaccf056b38f210e", "comment": "new helpers: kern_path_create/user_path_create" */
#include <linux/fs.h>
#include <linux/namei.h>

void foo(char *name)
{
	struct path path;

	kern_path_create(AT_FDCWD, name, &path, 0);
}

