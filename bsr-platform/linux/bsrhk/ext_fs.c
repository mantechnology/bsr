#include "../../../bsr/bsr_int.h"
#ifdef _LIN_FAST_SYNC
#include "ext_fs.h"

inline unsigned long long ext_blocks_count(struct ext_super_block *es)
{
	if(ext_has_feature_64bit(es)) {
		return ((unsigned long long)le32_to_cpu(es->s_blocks_count_hi) << 32) |
			le32_to_cpu(es->s_blocks_count_lo);
	}
	else {
		return le32_to_cpu(es->s_blocks_count_lo);
	}
}

unsigned long long ext_block_bitmap(struct ext_super_block *sb,
			       struct ext_group_desc *bg)
{
	return le32_to_cpu(bg->bg_block_bitmap_lo) |
		(sb->s_desc_size >= EXT_MIN_DESC_SIZE_64BIT ?
		 (unsigned long long)le32_to_cpu(bg->bg_block_bitmap_hi) << 32 : 0);
}

// BSR-903
static __u32 ext_free_blocks_count(struct ext_super_block *sb,
			       struct ext_group_desc *bg)
{
	return le16_to_cpu(bg->bg_free_blocks_count_lo) |
		(sb->s_desc_size >= EXT_MIN_DESC_SIZE_64BIT ?
		 (__u32)le16_to_cpu(bg->bg_free_blocks_count_hi) << 16 : 0);
}

// for ext-fs debugging
int ext_used_blocks(unsigned int group, char * bitmap,
			unsigned int nbytes, unsigned int offset, unsigned int count)
{
	int used = 0;
	unsigned int i;
	unsigned int j;
	
	offset += group * nbytes;
	for (i = 0; i < count; i++) {
		if (test_bit_le(i, (void *)bitmap)) {
			used++;
			for (j = ++i; j < count && test_bit_le(j, (void *)bitmap); j++)
				used++;
			if (--j != i) {
				i = j;
			}
		}
	}
	
	return used;
}

// for ext-fs debugging
int ext_free_blocks(unsigned int group, char * bitmap,
			unsigned int nbytes, unsigned int offset, unsigned int count)
{
	unsigned int i;
	unsigned int j;
	int free = 0;

	offset += group * nbytes;
	for (i = 0; i < count; i++) {
		if (!test_bit_le(i, (void *)bitmap)) {
			free++;
			for (j = ++i; j < count && !test_bit_le(j, (void *)bitmap); j++)
				free++;
			if (--j != i) {
				i = j;
			}
		}
	}
	
	return free;
}

PVOLUME_BITMAP_BUFFER read_ext_bitmap(struct file *fd, struct ext_super_block *ext_sb)
{
	unsigned long group_count = 0;
	unsigned int group_no;
	unsigned int read_size;
	long long int bitmap_size;
	unsigned short desc_size;
	PVOLUME_BITMAP_BUFFER bitmap_buf;
	ULONGLONG total_block;
	ssize_t ret;
	loff_t offset, group_desc_offset;
	unsigned long free_blocks_co = 0;	
	unsigned long bytes_per_block;
	unsigned long first_data_block = le32_to_cpu(ext_sb->s_first_data_block);
	unsigned long blocks_per_group = le32_to_cpu(ext_sb->s_blocks_per_group);

	
	if (ext_has_feature_meta_bg(ext_sb)) {
		bsr_info(74, BSR_LC_BITMAP, NO_OBJECT, "EXT_FEATURE_INCOMPAT_META_BG is set. fastsync not support");
		// TODO : support MEAT_BG
		return NULL;
	}
	
	// get size of group descriptor
	if (ext_has_feature_64bit(ext_sb)) {
		if (!ext_sb->s_desc_size) {
			bsr_err(75, BSR_LC_BITMAP, NO_OBJECT, "Failed to read ext bitmap due to wrong s_desc_size");
			return NULL;
		}

		desc_size = le16_to_cpu(ext_sb->s_desc_size);
	}
	else {
		desc_size = EXT_MIN_DESC_SIZE;
	}

	
	total_block = ext_blocks_count(ext_sb);
	bytes_per_block = EXT_BLOCK_SIZE(ext_sb);
	group_count = (total_block - first_data_block + blocks_per_group - 1) / blocks_per_group;

	bitmap_size = ALIGN(total_block, BITS_PER_BYTE) / BITS_PER_BYTE;
	// BSR-818 fix to execute vmalloc() when kmalloc() fails
	bitmap_buf = (PVOLUME_BITMAP_BUFFER)bsr_kvmalloc(sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size, GFP_ATOMIC|__GFP_NOWARN);

	if (bitmap_buf == NULL) {
		bsr_err(58, BSR_LC_MEMORY, NO_OBJECT, "Failed to read ext bitmap due to failure to allocate %d size memory for bitmap buffer", (sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size));
		return NULL;
	}


	bitmap_buf->BitmapSize = bitmap_size;
	memset(bitmap_buf->Buffer, 0, bitmap_buf->BitmapSize);

	if (debug_fast_sync) {
		bsr_info(109, BSR_LC_BITMAP, NO_OBJECT, "=============================");
		bsr_info(110, BSR_LC_BITMAP, NO_OBJECT, "first_data_block : %lu ", first_data_block);
		bsr_info(111, BSR_LC_BITMAP, NO_OBJECT, "total block count : %llu ", total_block);	
		bsr_info(112, BSR_LC_BITMAP, NO_OBJECT, "blocks_per_group : %lu ", blocks_per_group);
		bsr_info(113, BSR_LC_BITMAP, NO_OBJECT, "group descriptor size : %u ", desc_size);
		bsr_info(114, BSR_LC_BITMAP, NO_OBJECT, "block size : %lu ", bytes_per_block);
		bsr_info(115, BSR_LC_BITMAP, NO_OBJECT, "bitmap size : %lld ", bitmap_size);
		bsr_info(116, BSR_LC_BITMAP, NO_OBJECT, "group count : %lu ", group_count);
		bsr_info(117, BSR_LC_BITMAP, NO_OBJECT, "=============================");
	}

	group_desc_offset = bytes_per_block * (first_data_block + 1);
	read_size = bytes_per_block;

	for (group_no = 0; group_no < group_count; group_no++) {
		struct ext_group_desc group_desc= {0,};
		unsigned int used = 0;
		unsigned int free = 0;
		ULONGLONG first_block = 0;
		ULONGLONG last_block = 0;
		bool block_uninit = false;
		unsigned long long bg_block_bitmap;
		unsigned int bg_free_blocks_count;
		
		first_block = (ULONGLONG)group_no * blocks_per_group + first_data_block;
		last_block = first_block + (blocks_per_group - 1);
		if (last_block > total_block - 1) {
			last_block = total_block - 1;
		}

		offset = fd->f_op->llseek(fd, group_desc_offset + group_no * desc_size, SEEK_SET);
		if (offset < 0) {
			bsr_err(76, BSR_LC_BITMAP, NO_OBJECT, "Failed to read ext bitmap due to failure to lseek group_descriptor (err=%lld)", offset);
			goto fail_and_free;
		}

		// read group descriptor
		ret = bsr_read(fd, (char *)&group_desc, desc_size, &fd->f_pos);
		if (ret < 0 || ret != desc_size) {
			bsr_err(77, BSR_LC_BITMAP, NO_OBJECT, "Failed to read ext bitmap due to failure to read group_descriptor (err=%ld)", ret);
			goto fail_and_free;
		}	
		
		block_uninit = group_desc.bg_flags & cpu_to_le16(EXT_BG_BLOCK_UNINIT);
		bg_block_bitmap = ext_block_bitmap(ext_sb, &group_desc);
		// BSR-903
		bg_free_blocks_count = ext_free_blocks_count(ext_sb, &group_desc);

		if (!bg_block_bitmap) {
			bsr_err(78, BSR_LC_BITMAP, NO_OBJECT, "Failed to read ext bitmap due to failure to read bg_block_bitmap");
			goto fail_and_free;
		}
		
		if (debug_fast_sync) {
			bsr_info(79, BSR_LC_BITMAP, NO_OBJECT, "Group %u (Blocks %llu ~ %llu) ", group_no, first_block, last_block);
			bsr_info(80, BSR_LC_BITMAP, NO_OBJECT, "block bitmap : %llu", bg_block_bitmap);
			bsr_info(81, BSR_LC_BITMAP, NO_OBJECT, "block bitmap offset : %llu", bg_block_bitmap * bytes_per_block);
		}


		if (block_uninit) {
			if (debug_fast_sync) {
				bsr_info(82, BSR_LC_BITMAP, NO_OBJECT, "skip BLOCK_UNINIT group");
				bsr_info(83, BSR_LC_BITMAP, NO_OBJECT, "=============================");
				free_blocks_co += bytes_per_block * BITS_PER_BYTE;
			}
			continue;
		}

		if (bytes_per_block * (group_no + 1) > bitmap_size)
				read_size = bitmap_size - (group_no * bytes_per_block);

		// Move position to bitmap block
		offset = fd->f_op->llseek(fd, bg_block_bitmap * bytes_per_block, SEEK_SET);
		if (offset < 0) {
			bsr_err(84, BSR_LC_BITMAP, NO_OBJECT, "Failed to read ext bitmap due to failure to lseek bitmap_block (err=%lld)", offset);
			goto fail_and_free;
		}

		// read bitmap block
		ret = bsr_read(fd, &bitmap_buf->Buffer[bytes_per_block * group_no], read_size, &fd->f_pos);
		if (ret < 0 || ret != read_size) {
			bsr_err(85, BSR_LC_BITMAP, NO_OBJECT, "Failed to read ext bitmap due to failure to read bitmap_block (err=%ld)", ret);
			goto fail_and_free;
		}

		// BSR-903 compare the number of free blocks counted in block_bitmap with bg_free_blocks_count of group_desc.
		// if the values are different, may be an error in the block bitmap. all blocks in this group must be synchronized.
		free = ext_free_blocks(group_no, &bitmap_buf->Buffer[bytes_per_block * group_no],
						blocks_per_group,
						first_data_block, 
						last_block - first_block + 1);

		if (free != bg_free_blocks_count) {
			memset(&bitmap_buf->Buffer[bytes_per_block * group_no], 0xFF, read_size);

			if (debug_fast_sync) {
				bsr_info(88, BSR_LC_BITMAP, NO_OBJECT, "mismatch free block count : %d bg_free_blocks_count : %d", free, bg_free_blocks_count);
				bsr_info(88, BSR_LC_BITMAP, NO_OBJECT, "all (%d) blocks in this group need to sync", bytes_per_block * BITS_PER_BYTE);
				bsr_info(89, BSR_LC_BITMAP, NO_OBJECT, "=============================");
			}
		} 
		else {
			if (debug_fast_sync) {
				bsr_info(86, BSR_LC_BITMAP, NO_OBJECT, "read bitmap_block (%ld)", ret);
				used = ext_used_blocks(group_no, &bitmap_buf->Buffer[bytes_per_block * group_no],
								blocks_per_group,
								first_data_block,
								last_block - first_block + 1);
				bsr_info(87, BSR_LC_BITMAP, NO_OBJECT, "used block count : %d", used);
				bsr_info(88, BSR_LC_BITMAP, NO_OBJECT, "free block count : %d", free);
				bsr_info(89, BSR_LC_BITMAP, NO_OBJECT, "=============================");
				free_blocks_co += free;
			}
		}

		// BSR-823 cpu occupancy prevention
		cond_resched();

	}
	if (debug_fast_sync) {
		bsr_info(90, BSR_LC_BITMAP, NO_OBJECT, "free_blocks : %lu", free_blocks_co);
	}

	return bitmap_buf;

fail_and_free:
	if (bitmap_buf != NULL) {
		sub_kvmalloc_mem_usage(bitmap_buf, sizeof(VOLUME_BITMAP_BUFFER) + bitmap_buf->BitmapSize);
		kvfree(bitmap_buf);
		bitmap_buf = NULL;
	}
	
	return NULL;
}

bool is_ext_fs(struct ext_super_block *ext_sb)
{
	if (le16_to_cpu(ext_sb->s_magic) == EXT_SUPER_MAGIC && 
		le32_to_cpu(ext_sb->s_blocks_count_lo) > 0 && 
		le32_to_cpu(ext_sb->s_blocks_per_group) > 0 && 
		le32_to_cpu(ext_sb->s_inodes_per_group) > 0 &&
		le16_to_cpu(ext_sb->s_inode_size) > 0  && 
		EXT_BLOCK_SIZE(ext_sb) > 0) {
		return true;
	}

	return false;
}

#endif