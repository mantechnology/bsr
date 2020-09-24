#include "../../../bsr/bsr_int.h"
#ifdef _LIN_FAST_SYNC
#include "xfs_fs.h"

inline bool xfs_sb_version_hasmorebits(struct xfs_sb *sbp)
{
	return be16_to_cpu(XFS_SB_VERSION_NUM(sbp)) == XFS_SB_VERSION_5 ||
	       (sbp->sb_versionnum & be16_to_cpu(XFS_SB_VERSION_MOREBITSBIT));
}
/*
 * sb_features2 bit version macros.
 */
inline bool xfs_sb_version_haslazysbcount(struct xfs_sb *sbp)
{
	return (be16_to_cpu(XFS_SB_VERSION_NUM(sbp)) == XFS_SB_VERSION_5) ||
	       (xfs_sb_version_hasmorebits(sbp) &&
		(sbp->sb_features2 & be32_to_cpu(XFS_SB_VERSION2_LAZYSBCOUNTBIT)));
}
/*
 * V5 superblock specific feature checks
 */
inline bool xfs_sb_version_hascrc(struct xfs_sb *sbp)
{
	return be16_to_cpu(XFS_SB_VERSION_NUM(sbp)) == XFS_SB_VERSION_5;
}

PVOLUME_BITMAP_BUFFER read_xfs_bitmap(struct file *fd, struct xfs_sb *xfs_sb)
{
	unsigned int ag_count = 0;
	unsigned int ag_no = 0;
	//unsigned int agf_root = 0;
	int blk_size = 0;
	int sect_size = 0;
	unsigned short bb_level = 0;
	unsigned short bb_numrecs = 0;
	int bb_numrecs_no = 0;
	int bb_leftsib = 0;
	int bb_rightsib = 0;
	//xfs_agf_t agf;
	struct xfs_btree_block btsb;
	xfs_alloc_rec_t ar;
	long long int bitmap_size;
	PVOLUME_BITMAP_BUFFER bitmap_buf;
	ULONGLONG total_block;
	ULONGLONG free_bits_co = 0;
	ULONGLONG free_blocks_co = 0;
	loff_t offset, ag_blocks_offset = 0;
	int startblock = 0;
	int blockcount = 0;
	int startbit = 0;
	int bitcount_no = 0;
	int ret = 0;
	
	ag_count = be32_to_cpu(xfs_sb->sb_agcount);
	ag_blocks_offset = be32_to_cpu(xfs_sb->sb_agblocks);
	blk_size = be32_to_cpu(xfs_sb->sb_blocksize);
	sect_size = be16_to_cpu(xfs_sb->sb_sectsize);
	total_block = be64_to_cpu(xfs_sb->sb_dblocks);

	bitmap_size = ALIGN(total_block, BITS_PER_BYTE) / BITS_PER_BYTE;
	bitmap_buf = (PVOLUME_BITMAP_BUFFER)kmalloc(sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size, GFP_ATOMIC|__GFP_NOWARN, '');

	if (bitmap_buf == NULL) {
		bsr_err(59, BSR_LC_MEMORY, NO_OBJECT, "Failed to read xfs bitmap due to failure to allocate %d size memory for bitmap buffer\n", (sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size));
		return NULL;
	}

	bitmap_buf->BitmapSize = bitmap_size;
	memset(bitmap_buf->Buffer, 0xFF, bitmap_buf->BitmapSize);

	if (debug_fast_sync) {
		bsr_info(203, BSR_LC_RESYNC_OV, NO_OBJECT, "=============================\n");
		bsr_info(204, BSR_LC_RESYNC_OV, NO_OBJECT, "version : %d \n", be16_to_cpu(XFS_SB_VERSION_NUM(xfs_sb)));
		bsr_info(205, BSR_LC_RESYNC_OV, NO_OBJECT, "ag_count : %d \n", ag_count);
		bsr_info(206, BSR_LC_RESYNC_OV, NO_OBJECT, "total block count : %llu \n", total_block);	
		bsr_info(207, BSR_LC_RESYNC_OV, NO_OBJECT, "blocks_per_ag : %ld \n", (long int)ag_blocks_offset);
		bsr_info(208, BSR_LC_RESYNC_OV, NO_OBJECT, "block size : %d \n", blk_size);
		bsr_info(209, BSR_LC_RESYNC_OV, NO_OBJECT, "sector size : %d \n", sect_size);
		bsr_info(210, BSR_LC_RESYNC_OV, NO_OBJECT, "bitmap size : %lld \n", bitmap_buf->BitmapSize);
		bsr_info(211, BSR_LC_RESYNC_OV, NO_OBJECT, "=============================\n");
	}

	for (ag_no = 0; ag_no < ag_count; ag_no++) {
		/* TODO? : find first leaf block using ptr node */
		// read ag free space block
		// Move position to bitmap btree root block
		// read bitmap btree root block
		// Move position to ptr offset
		// read bitmap ptr node
		// find first btree leaf block

		// Move position to btree first leaf block
		offset = fd->f_op->llseek(fd, (ag_blocks_offset * ag_no + 1) * blk_size, SEEK_SET);
		if (offset < 0) {
			bsr_err(93, BSR_LC_BITMAP, NO_OBJECT, "Failed to read xfs bitmap due to failure to lseek first leaf node of btree_block (err=%lld)\n", offset);
			goto fail_and_free;
		}

		// read free block btree first leaf block
		ret = bsr_read(fd, (char *)&btsb, sizeof(struct xfs_btree_block), &fd->f_pos);
		if (ret < 0 || ret != sizeof(struct xfs_btree_block)) {
			bsr_err(94, BSR_LC_BITMAP, NO_OBJECT, "Failed to read xfs bitmap due to failure to read first leaf node of btree_block (err=%d)\n", ret);
			goto fail_and_free;
		}

		// check if xfs version5
		if (!xfs_sb_version_hascrc(xfs_sb)) {
			// offset is reduced if not version5 because the structure changed since version5.
			offset = fd->f_op->llseek(fd, -XFS_BTREE_SHDR_ADDITIONAL_SIZE_TO_VERSION_5, SEEK_CUR);
			if (offset < 0) {
				bsr_err(95, BSR_LC_BITMAP, NO_OBJECT, "Failed to read xfs bitmap due to failure to lseek reduced addition size of btree_block since version5(err=%lld)\n", offset);
				goto fail_and_free;
			}
		}

		bb_level = be16_to_cpu(btsb.bb_level);
		if(bb_level != 0) {
			bsr_err(96, BSR_LC_BITMAP, NO_OBJECT, "Failed to read xfs bitmap due to failure to read leaf node (err=%hd)\n", bb_level);
			goto fail_and_free;
		}
		bb_numrecs = be16_to_cpu(btsb.bb_numrecs);

		if (debug_fast_sync) {
			bsr_info(97, BSR_LC_BITMAP, NO_OBJECT, "[ag_no:%d] first leaf node bb_level : %hd bb_numrecs : %hd\n", ag_no, bb_level, bb_numrecs);
		}

		do {
			if(bb_rightsib > 0) {
				offset = fd->f_op->llseek(fd, (ag_blocks_offset * ag_no + bb_rightsib) * blk_size, SEEK_SET);
				if (offset < 0) {
					bsr_err(98, BSR_LC_BITMAP, NO_OBJECT, "Failed to read xfs bitmap due to failure to lseek secondary btree_block (err=%lld)\n", offset);
					goto fail_and_free;
				}
				
				// read free block btree secondary leaf block
				ret = bsr_read(fd, (char *)&btsb, sizeof(struct xfs_btree_block), &fd->f_pos);
				if (ret < 0 || ret != sizeof(struct xfs_btree_block)) {
					bsr_err(99, BSR_LC_BITMAP, NO_OBJECT, "Failed to read secondary btree_block (err=%d)\n", ret);
					goto fail_and_free;
				}

				bb_level = be16_to_cpu(btsb.bb_level);
				if(bb_level != 0) {
					bsr_err(100, BSR_LC_BITMAP, NO_OBJECT, "Failed to read xfs bitmap due to failure to read secondary leaf node (err=%hd)\n", bb_level);
					goto fail_and_free;
				}
				bb_numrecs = be16_to_cpu(btsb.bb_numrecs);
			}
			
			for(bb_numrecs_no = 0 ; bb_numrecs_no < bb_numrecs ; bb_numrecs_no++) {
				// read free block info
				ret = bsr_read(fd, (char *)&ar, sizeof(xfs_alloc_rec_t), &fd->f_pos);
				startblock = be32_to_cpu(ar.ar_startblock);
				blockcount = be32_to_cpu(ar.ar_blockcount);

				offset = ((ag_blocks_offset * ag_no) + startblock) / BITS_PER_BYTE;
				startbit = ((ag_blocks_offset * ag_no) + startblock) % BITS_PER_BYTE;

				// convert free block info to bitmap
				for(bitcount_no = startbit ; bitcount_no < (blockcount + startbit) ; bitcount_no++) {
					if(offset + (bitcount_no/BITS_PER_BYTE) >= bitmap_buf->BitmapSize) {
						bsr_err(101, BSR_LC_BITMAP, NO_OBJECT, "Failed to read xfs bitmap due to failure to read free block info, bitmap buffer overflow! (startblock:%d, blockcount:%d)\n", startblock, blockcount);
						goto fail_and_free;
					}
					// set bitmap bit to '0' for free block
					bitmap_buf->Buffer[offset + (bitcount_no/BITS_PER_BYTE)] &= ~(1 << (bitcount_no % BITS_PER_BYTE));
					free_bits_co++;
				}

				free_blocks_co += blockcount;
			}

			bb_leftsib = be32_to_cpu(btsb.bb_u.s.bb_leftsib);
			bb_rightsib = be32_to_cpu(btsb.bb_u.s.bb_rightsib);

		} while(bb_rightsib > 0);

	}
	if (debug_fast_sync) {
		bsr_info(102, BSR_LC_BITMAP, NO_OBJECT, "total free_blocks : %llu free_bits : %llu\n", free_blocks_co, free_bits_co);
	}

	return bitmap_buf;

fail_and_free:
	if (bitmap_buf != NULL) {
		kfree(bitmap_buf);
		bitmap_buf = NULL;
	}
	
	return NULL;
}

bool is_xfs_fs(struct xfs_sb *xfs_sb)
{
	if (xfs_sb->sb_magicnum == cpu_to_be32(XFS_SB_MAGIC) && 
		be64_to_cpu(xfs_sb->sb_dblocks) > 0 && 
		be32_to_cpu(xfs_sb->sb_agblocks) > 0 &&
		be32_to_cpu(xfs_sb->sb_agcount) > 0) {
		return true;
	}

	return false;
}

#endif