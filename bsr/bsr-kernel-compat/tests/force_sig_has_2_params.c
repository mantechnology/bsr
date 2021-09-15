#include <linux/sched/signal.h>
#include <linux/sched.h>

void foo(void) {
	force_sig(1, current);
}
