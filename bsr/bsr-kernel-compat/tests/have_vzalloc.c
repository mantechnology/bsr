#include <linux/vmalloc.h>

void *foo(void)
{
	return vzalloc(8);
}
