#include <linux/mm.h>
// BSR-1006 rhel 8.7 (4.18.0-425.3.1.el8.x86_64)
#include <linux/slab.h>

void foo(void) {
	kvfree(NULL);
}
