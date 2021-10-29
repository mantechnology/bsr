/* { "version": "v5.13-rc1", "commit": "4f0f586bf0c898233d8f316f471a21db2abd522d", "comment": "Change list_sort to use const pointers" } */
#include <linux/kernel.h>
#include <linux/list_sort.h>

extern void compat_check_list_sort(void *priv, struct list_head *head,
			int (*cmp)(void *priv, const struct list_head *a, const struct list_head *b));

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

void dummy(void)
{
	BUILD_BUG_ON(!__same_type(compat_check_list_sort, list_sort));
}
