#include <linux/dcache.h>

/* Since dc3f4198e (linux v4.2) simple_positive is accessible for modules */

int foo(void)
{
	return simple_positive((struct dentry *)NULL);
}
