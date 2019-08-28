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
#include <linux/dynamic_debug.h>
#include <bsr_debugfs.h>

MODULE_LICENSE("GPL");

#ifdef COMPAT_BSR_RELEASE_RETURNS_VOID
#define BSR_RELEASE_RETURN void
#else
#define BSR_RELEASE_RETURN int
#endif

extern int bsr_init(void);
extern void bsr_cleanup(void);
extern int bsr_open(struct block_device *bdev, fmode_t mode);
extern BSR_RELEASE_RETURN bsr_release(struct gendisk *gd, fmode_t mode);

static int bsr_mount(struct block_device *bdev, fmode_t mode);
static BSR_RELEASE_RETURN bsr_umount(struct gendisk *gd, fmode_t mode);


static const struct block_device_operations bsr_ops = {
	.owner =   THIS_MODULE,
	.open =    bsr_mount,
	.release = bsr_umount,
};

static int __init bsr_load(void)
{
	printk("bsr kernel driver load\n");	
	if (drbd_debugfs_init())
		pr_notice("failed to initialize debugfs -- will not be available\n");
	return bsr_init();	
}

static void bsr_unload(void)
{	
	bsr_cleanup();	
	printk("bsr kernel driver unload done\n");
	return;
}

static int bsr_mount(struct block_device *bdev, fmode_t mode)
{
	printk("bsr_mount block_device:%p, mode:%d\n",bdev, mode);
	return bsr_open(bdev, mode);
}

static BSR_RELEASE_RETURN bsr_umount(struct gendisk *gd, fmode_t mode)
{
	printk("bsr_umount gendisk:%p, mode:%d\n",gd, mode);
	return bsr_release(gd, mode);
}

module_init(bsr_load)
module_exit(bsr_unload)
