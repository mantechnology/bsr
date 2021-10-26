/* { "version": "5..12-rc1", "commit": "9fe61450972d3900bffb1dc26a17ebb9cdd92db2", "comment": "namei: introduce struct renamedata" */
#include <linux/fs.h>
#include <linux/namei.h>

void foo(char *name)
{
	struct renamedata rd = {};
	return 0;
}

