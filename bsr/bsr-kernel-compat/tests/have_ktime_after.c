#include <linux/ktime.h>

void foo(ktime_t t1, ktime_t t2) {
	ktime_after(t1, t2);
}
