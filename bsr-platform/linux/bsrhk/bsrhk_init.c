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


// BSR-584 reading log level from /etc/bsr.d/.log_level file
static long read_reg_file(char *file_path, long default_val)
{	
	struct file *fd = NULL;
	char *buffer = NULL;
	int filesize = 0;
	long log_level = default_val;
	int err = 0;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	fd = filp_open(file_path, O_RDONLY, 0);

	if (fd == NULL || IS_ERR(fd))
		goto out;

	filesize = fd->f_op->llseek(fd, 0, SEEK_END);
	if (filesize <= 0)
		goto close;

	buffer = kmalloc(filesize, GFP_ATOMIC|__GFP_NOWARN);

	memset(buffer, 0, sizeof(filesize));
	
	if (fd->f_op->llseek(fd, 0, SEEK_SET) < 0)
		goto close;
	err = bsr_read(fd, buffer, filesize, &fd->f_pos);
	if (err < 0 || err != filesize)
		goto close;

	err = kstrtol(buffer, 0, &log_level);
	if (err < 0 || log_level == 0)
		log_level = default_val;

close:
	if (buffer != NULL)
		kfree(buffer);
	if (fd != NULL)
		filp_close(fd, NULL);
out:
	set_fs(oldfs);
	return log_level;
}


static int __init bsr_load(void)
{
	long log_level = 0;

#ifdef _LIN
	// BSR-581
	init_logging();
#endif

	log_level = read_reg_file(BSR_LOG_LEVEL_REG, LOG_LV_DEFAULT);
	Set_log_lv(log_level);

	// BSR-597 set max log count
	atomic_set(&g_log_file_max_count, read_reg_file(BSR_LOG_FILE_MAXCNT_REG, LOG_FILE_COUNT_DEFAULT));

	bsr_info(NO_OBJECT, "bsr kernel driver load\n");
	initialize_kref_debugging();
	if (bsr_debugfs_init())
		bsr_noti(NO_OBJECT, "failed to initialize debugfs -- will not be available\n");

	return bsr_init();	
}

static void bsr_unload(void)
{	
	bsr_cleanup();	
	//  _WIN32_V9_DEBUGFS: minord is cleanup at this point, required to analyze it.
	bsr_debugfs_cleanup();
	bsr_info(NO_OBJECT, "bsr kernel driver unload done\n");
#ifdef _LIN
	// BSR-581
	clean_logging();
#endif

	return;
}

static int bsr_mount(struct block_device *bdev, fmode_t mode)
{
	bsr_info(NO_OBJECT, "bsr_mount block_device:%p, mode:%d\n",bdev, mode);
	return bsr_open(bdev, mode);
}

static BSR_RELEASE_RETURN bsr_umount(struct gendisk *gd, fmode_t mode)
{
	bsr_info(NO_OBJECT, "bsr_umount gendisk:%p, mode:%d\n",gd, mode);
#ifdef COMPAT_BSR_RELEASE_RETURNS_VOID
	bsr_release(gd, mode);
#else
	return bsr_release(gd, mode);
#endif
}

module_init(bsr_load)
module_exit(bsr_unload)
