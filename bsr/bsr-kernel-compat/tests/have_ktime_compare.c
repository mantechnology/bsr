#include <linux/ktime.h>

void foo(ktime_t t1, ktime_t t2) {
	ktime_compare(t1, t2);
}