#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/bsr.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h> 
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/kthread.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");

#ifdef COMPAT_BSR_RELEASE_RETURNS_VOID
#define BSR_RELEASE_RETURN void
#else
#define BSR_RELEASE_RETURN int
#endif

static int bsr_open(struct block_device *bdev, fmode_t mode);
static BSR_RELEASE_RETURN bsr_release(struct gendisk *gd, fmode_t mode);


static const struct block_device_operations bsr_ops = {
	.owner =   THIS_MODULE,
	.open =    bsr_open,
	.release = bsr_release,
};

static int __init bsr_init(void)
{
	int err = 0;	
	printk("hello bsr!\n");	
//	return drbd_init();	
	return err;
}

static void bsr_cleanup(void)
{	
	printk("a good day to die...\n");
//	return drbd_cleanup();	
	return;
}

static int bsr_open(struct block_device *bdev, fmode_t mode)
{
	int rv = 0;
//	return drbd_open(bdev, mode);
	return rv;
}

static BSR_RELEASE_RETURN bsr_release(struct gendisk *gd, fmode_t mode)
{
//	return drbd_release(gd, mode);
#ifndef COMPAT_BSR_RELEASE_RETURNS_VOID
	return 0;
#endif
}

module_init(bsr_init)
module_exit(bsr_cleanup)