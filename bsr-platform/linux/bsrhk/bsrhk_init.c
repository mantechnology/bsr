#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <bsr.h>

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
#include <bsr_log.h>
#include "../bsr-headers/linux/bsr_ioctl.h"

MODULE_LICENSE("GPL");

//#ifdef COMPAT_BSR_RELEASE_RETURNS_VOID
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


const struct block_device_operations bsr_ops = {
	.owner =   THIS_MODULE,
	.open =    bsr_mount,
	.release = bsr_umount,
};


static int __init bsr_load(void)
{
	long log_level = 0;
	unsigned int dbglog_ctrg = 0;

#ifdef _LIN
	// BSR-581
	init_logging();
#endif

	log_level = read_reg_file(BSR_LOG_LEVEL_REG, LOG_LV_DEFAULT);
	Set_log_lv(log_level);

	// BSR-654
	dbglog_ctrg = read_reg_file(BSR_DEBUG_LOG_CATEGORY_REG, DEBUG_LOG_OUT_PUT_CATEGORY_DEFAULT);
	atomic_set(&g_debug_output_category, dbglog_ctrg);

	// BSR-597 set max log count
	atomic_set(&g_log_file_max_count, read_reg_file(BSR_LOG_FILE_MAXCNT_REG, LOG_FILE_COUNT_DEFAULT));

	// BSR-626 porting handler_use to linux
	g_handler_use = read_reg_file(BSR_HANDLER_USE_REG, g_handler_use);

	bsr_info(120, BSR_LC_DRIVER, NO_OBJECT, "bsr kernel driver load");
	initialize_kref_debugging();
	if (bsr_debugfs_init())
		bsr_noti(95, BSR_LC_DRIVER, NO_OBJECT, "Failed to initialize debugfs -- will not be available");

	return bsr_init();	
}

static void bsr_unload(void)
{	
	bsr_cleanup();	
	//  _WIN32_V9_DEBUGFS: minord is cleanup at this point, required to analyze it.
	bsr_debugfs_cleanup();
	bsr_info(121, BSR_LC_DRIVER, NO_OBJECT, "bsr kernel driver unload done");
#ifdef _LIN
	// BSR-581
	clean_logging();
#endif

	return;
}

static int bsr_mount(struct block_device *bdev, fmode_t mode)
{
	bsr_info(122, BSR_LC_DRIVER, NO_OBJECT, "bsr mount block_device:%p, mode:%d", bdev, mode);
	return bsr_open(bdev, mode);
}

static BSR_RELEASE_RETURN bsr_umount(struct gendisk *gd, fmode_t mode)
{
	bsr_info(123, BSR_LC_DRIVER, NO_OBJECT, "bsr umount gendisk:%p, mode:%d", gd, mode);
#ifdef COMPAT_BSR_RELEASE_RETURNS_VOID
	bsr_release(gd, mode);
#else
	return bsr_release(gd, mode);
#endif
}

module_init(bsr_load)
module_exit(bsr_unload)
