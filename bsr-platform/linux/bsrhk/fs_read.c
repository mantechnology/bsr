#include "../../../bsr/bsr_int.h"
#ifdef _LIN_FAST_SYNC
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include "ext_fs.h"
#include "xfs_fs.h"
#include "btrfs_fs.h"

static bool read_ext_and_xfs_superblock(struct file *fd, char *super_block, int size)
{
	ssize_t ret;

	if(super_block == NULL)
		return false;
	/* read 2048 bytes.
	 *   ext superblock is starting at the 1024 bytes, size is 1024 bytes
	 *   xfs superblock is starting at the 0 byte, size is 512 bytes	
	*/

	ret = bsr_read(fd, super_block, size, &fd->f_pos);
	
	if (ret < 0 || ret != size) {
		bsr_err(91, BSR_LC_BITMAP, NO_OBJECT, "Failed to read super block. err(%ld)", ret);
		return false;
	}
	return true;
}

static void try_update_superblock(struct bsr_device *device, struct file *fd, struct btrfs_super_block *btrfs_sb, struct btrfs_super_block *tmp_sb, u64 offset, const char *label) {
    if (BTRFS_SUPER_BLOCK_SIZE == bsr_read_data(fd, tmp_sb, BTRFS_SUPER_BLOCK_SIZE, offset)) {
        if (is_btrfs_fs(tmp_sb)) {
            u64 gen = le64_to_cpu(tmp_sb->generation);
            bsr_info(131, BSR_LC_BITMAP, device, "BTRFS %s super block generation : %llu", label, gen);
            if (le64_to_cpu(btrfs_sb->generation) < gen) {
                memcpy(btrfs_sb, tmp_sb, BTRFS_SUPER_BLOCK_SIZE);
            }
        }
    }
}

PVOID GetVolumeBitmap(struct bsr_device *device, ULONGLONG * ptotal_block, ULONG * pbytes_per_block)
{
	struct file *fd;
	PVOLUME_BITMAP_BUFFER bitmap_buf = NULL;
	char * super_block = NULL;
	char disk_name[512] = {0};
	bool freezed = false;
	
#ifndef COMPAT_HAVE_BD_SUPER
	struct super_block *sb;
#endif

#ifdef COMPAT_HAVE_SET_FS
	mm_segment_t old_fs = get_fs();
#endif
	struct block_device *bdev = NULL;
	
	sprintf(disk_name, "/dev/bsr%d", device->minor);
#ifdef COMPAT_HAVE_SET_FS
	set_fs(KERNEL_DS);
#endif

	fd = filp_open(disk_name, O_RDONLY, 0);
	if (fd == NULL || IS_ERR(fd)) {
		bsr_err(71, BSR_LC_VOLUME, device, "Failed to get volume bitmap due to failure to open %s", disk_name);
		goto out;
	}

#if defined(COMPAT_HAVE_HD_STRUCT)
	bdev = bdget_disk(device->vdisk, 0);
#elif defined(COMPAT_HAVE_BDGRAB)
	bdev = bdgrab(device->vdisk->part0);
#else // kernel >= v5.14
	bdev = device->vdisk->part0;
#endif
	if (bdev == NULL)
		goto out;
	
#ifdef COMPAT_HAVE_BD_SUPER
	if(bdev->bd_super) {
		// BSR-1360
		// journal log flush
#ifdef COMPAT_FREEZE_BDEV_RETURNS_INT
        if(freeze_bdev(bdev))
            goto close;
#else
		if(IS_ERR(freeze_bdev(bdev)))
			goto close;
#endif
		freezed = true;
		// meta flush
		if(fsync_bdev(bdev))
			goto close;
		invalidate_bdev(bdev);
	} 
#else
	// BSR-1360 based on kernel 6.8, bd_holder has super_block set.
	sb = (struct super_block *)(bdev->bd_holder);
	if(sb && (sb->s_bdev == bdev)) {
		if(freeze_super(sb, FREEZE_HOLDER_KERNEL))
			goto close;
		freezed = true;
		invalidate_bdev(bdev);
	} 
#endif
	// BSR-1407 allocate as the superblock size of btrfs with the largest superblock size among ext, xfs, and btrfs supported.
	super_block = bsr_kmalloc(BTRFS_SUPER_BLOCK_SIZE, GFP_ATOMIC|__GFP_NOWARN, '');
	if(!read_ext_and_xfs_superblock(fd, super_block, BTRFS_SUPER_BLOCK_SIZE)) {
		if(super_block) {
			bsr_kfree(super_block);
			super_block = NULL;
		}
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
	} else {
		// BSR-1407
		struct btrfs_super_block *btrfs_sb = NULL;
		
		btrfs_sb = bsr_kmalloc(BTRFS_SUPER_BLOCK_SIZE, GFP_ATOMIC|__GFP_NOWARN, '');
		if(!btrfs_sb) {
			bsr_kfree(super_block);
			super_block = NULL;
			goto close;
		}

		// BSR-1407 get the latest superblock among superblocks
		memset(super_block, 0, BTRFS_SUPER_BLOCK_SIZE);
		memset(btrfs_sb, 0, BTRFS_SUPER_BLOCK_SIZE);
		try_update_superblock(device, fd, btrfs_sb, (struct btrfs_super_block *)super_block, BTRFS_SUPER_BLOCK_OFFSET, "primary");
		try_update_superblock(device, fd, btrfs_sb, (struct btrfs_super_block *)super_block, BTRFS_FIRST_COPY_SUPER_BLOCK_OFFSET, "first");
		try_update_superblock(device, fd, btrfs_sb, (struct btrfs_super_block *)super_block, BTRFS_SECOND_COPY_SUPER_BLOCK_OFFSET, "secondary");

		if(is_btrfs_fs(btrfs_sb)) {
			struct btrfs_dev_item *dev_item = &btrfs_sb->dev_item; 

			*ptotal_block = ALIGN((le64_to_cpu(dev_item->total_bytes) >> BM_BLOCK_SHIFT), BITS_PER_BYTE);
			*pbytes_per_block = 1 << BM_BLOCK_SHIFT;
			bitmap_buf = read_btrfs_bitmap(fd, btrfs_sb);
		} else 
			bsr_warn(174, BSR_LC_RESYNC_OV, device, "Disk (%s) is a file system that does not support fast sync. fast sync supports ext, xfs, btrfs.", disk_name);
		
		if(btrfs_sb) {
			bsr_kfree(btrfs_sb);
			btrfs_sb = NULL;
		} 
	}

	if(super_block) {
		bsr_kfree(super_block);
		super_block = NULL;
	}

close:
	filp_close(fd, NULL);
#ifdef COMPAT_HAVE_SET_FS
	set_fs(old_fs);
#endif
	
#ifdef COMPAT_HAVE_BD_SUPER
	if(freezed)
		thaw_bdev(bdev, bdev->bd_super);
#else 
	if(freezed)
		thaw_super(sb, FREEZE_HOLDER_KERNEL);
#endif

#if defined(COMPAT_HAVE_BDGRAB) || defined(COMPAT_HAVE_HD_STRUCT)
	if (bdev)
		bdput(bdev);
#endif

out:
	if (bitmap_buf)
		return (PVOLUME_BITMAP_BUFFER)bitmap_buf;
	else 
		return NULL;
}
#else
PVOID GetVolumeBitmap(struct bsr_device *device, ULONGLONG * ptotal_block, ULONG * pbytes_per_block)
{
	return NULL;
}
#endif
