#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static int __init bsr_initialize(void)
{
	int err = 0;
	printk("hello bsr!\n");	
	return err;
}

static void bsr_finalize(void)
{
	printk("a good day to die...\n");
	return;
}


module_init(bsr_initialize)
module_exit(bsr_finalize)


