#include <linux/fs.h>
#include <linux/namei.h>

void foo(char *name)
{
	struct path path;

	kern_path_create(AT_FDCWD, name, &path, 0);
}

