#include <linux/fs.h>

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void dummy(void)
{
	bool (*filldir) (struct dir_context *, const char *, int, loff_t, u64, unsigned) = NULL;
	struct dir_context ctx;
	BUILD_BUG_ON(!(__same_type(ctx.actor, filldir)));
}

