#include "../../../bsr/bsr_int.h"
#ifdef _LIN_FAST_SYNC
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include "ext_fs.h"
#include "xfs_fs.h"

static char * read_superblock(struct file *fd)
{
	ssize_t ret;
	static char super_block[EXT_SUPER_BLOCK_OFFSET + EXT_SUPER_BLOCK_SIZE];
	
	/* read 2048 bytes.
	 *   ext superblock is starting at the 1024 bytes, size is 1024 bytes
	 *   xfs superblock is starting at the 0 byte, size is 512 bytes	
	*/
	ret = fd->f_op->read(fd, super_block, sizeof(super_block), &fd->f_pos); // TODO : change to __bread? vfs_read? kernel_read?
	
	if (ret < 0 || ret != sizeof(super_block)) {
		drbd_err(NO_OBJECT, "failed to read super_block (err=%ld)\n", ret);
		return NULL;
	}

	return super_block;
}

PVOID GetVolumeBitmap(struct drbd_device *device, ULONGLONG * ptotal_block, ULONG * pbytes_per_block)
{
	struct file *fd;
	PVOLUME_BITMAP_BUFFER bitmap_buf = NULL;
	char * super_block = NULL;
	char disk_name[512] = {0};
	mm_segment_t old_fs = get_fs();
	
	sprintf(disk_name, "/dev/bsr%d", device->minor);
	set_fs(KERNEL_DS);

	fd = filp_open(disk_name, O_RDONLY, 0);
	if (fd == NULL || IS_ERR(fd)) {
		drbd_err(device, "%s open failed\n", disk_name);
		goto out;
	}

	if(device->this_bdev->bd_super) {
		// journal log flush
		freeze_bdev(device->this_bdev);
	
		// meta flush
		fsync_bdev(device->this_bdev);
		invalidate_bdev(device->this_bdev);
	}

	super_block = read_superblock(fd);
	if (super_block == NULL) {		
		goto close;
	}

	if (is_ext_fs((struct ext_super_block *)(super_block + EXT_SUPER_BLOCK_OFFSET))) {
		// for ext-filesystem
		struct ext_super_block *ext_sb = (struct ext_super_block *)(super_block + EXT_SUPER_BLOCK_OFFSET);

		*ptotal_block = ALIGN(ext_blocks_count(ext_sb), BITS_PER_BYTE);
		*pbytes_per_block = EXT_BLOCK_SIZE(ext_sb);

		bitmap_buf = read_ext_bitmap(fd, ext_sb);
	}
	else if (is_xfs_fs((struct xfs_sb *)super_block)){
		// for xfs filesystem
		struct xfs_sb *xfs_sb = (struct xfs_sb *)super_block;

		*ptotal_block = ALIGN(be64_to_cpu(xfs_sb->sb_dblocks), BITS_PER_BYTE);
		*pbytes_per_block = be32_to_cpu(xfs_sb->sb_blocksize);
		
		bitmap_buf = read_xfs_bitmap(fd, xfs_sb);
	}
	else {
		drbd_warn(device, "(%s) not supported for fast sync.\n", disk_name);
	}

close:
	filp_close(fd, NULL);
	set_fs(old_fs);

	if(device->this_bdev->bd_super) {
		thaw_bdev(device->this_bdev, device->this_bdev->bd_super);
	}

out:
	if (bitmap_buf)
		return (PVOLUME_BITMAP_BUFFER)bitmap_buf;
	else 
		return NULL;
}
#else
PVOID GetVolumeBitmap(struct drbd_device *device, ULONGLONG * ptotal_block, ULONG * pbytes_per_block)
{
	return NULL;
}
#endif