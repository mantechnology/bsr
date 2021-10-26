/* { "version": "v5.13-rc1", "commit": "4f0f586bf0c898233d8f316f471a21db2abd522d", "comment": "Change list_sort to use const pointers" } */
#include <linux/list_sort.h>

void dummy(void)
{
	struct list_head *list;
	int (*cmp)(void *, const struct list_head *, const struct list_head *);
	list_sort(NULL, list, cmp);
}
