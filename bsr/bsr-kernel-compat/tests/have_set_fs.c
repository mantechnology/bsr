#include <linux/uaccess.h>

void test(void)
{
	set_fs(KERNEL_DS);
}
