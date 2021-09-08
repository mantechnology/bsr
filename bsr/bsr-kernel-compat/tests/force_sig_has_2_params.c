#include <linux/sched/signal.h>
void foo(void) {
	force_sig(1, current);
}
