#include <linux/spinlock.h>
#include <linux/gfp.h>
#include <linux/idr.h>

int foo(void)
{
	int i;
	struct idr idr;
	int n = 10;

	return idr_alloc(&idr, &i, n, n+1, GFP_KERNEL);
}
