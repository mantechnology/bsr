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

// for ext-fs debugging
int ext_used_blocks(unsigned int group, char * bitmap,
			unsigned int nbytes, unsigned int offset, unsigned int count)
{
	int p = 0;
	int used = 0;
	unsigned int i;
	unsigned int j;

	static char buf[128];
	int buf_offset;
	
	buf_offset = sprintf(buf, "used_blocks : ");
	offset += group * nbytes;
	for (i = 0; i < count; i++) {
		if (test_bit_le(i, (void *)bitmap)) {
			used++;
			if (p)
				buf_offset += sprintf(buf + buf_offset,", ");
			buf_offset += sprintf(buf + buf_offset, "%u", i + offset);
			for (j = ++i; j < count && test_bit_le(j, (void *)bitmap); j++)
				used++;
			if (--j != i) {
				buf_offset += sprintf(buf + buf_offset, "-%u", j + offset);
				i = j;
			}
			p = 1;
		}
	}
	
	bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "%s\n", buf);
	return used;
}

// for ext-fs debugging
int ext_free_blocks(unsigned int group, char * bitmap,
			unsigned int nbytes, unsigned int offset, unsigned int count)
{
	int p = 0;
	unsigned int i;
	unsigned int j;
	int free = 0;

	static char buf[128];
	int buf_offset;

	buf_offset = sprintf(buf, "free_blocks : ");
	offset += group * nbytes;
	for (i = 0; i < count; i++) {
		if (!test_bit_le(i, (void *)bitmap)) {
			free++;
			if (p)
				buf_offset += sprintf(buf + buf_offset,", ");
			buf_offset += sprintf(buf + buf_offset, "%u", i + offset);
			for (j = ++i; j < count && !test_bit_le(j, (void *)bitmap); j++)
				free++;
			if (--j != i) {
				buf_offset += sprintf(buf + buf_offset, "-%u", j + offset);
				i = j;
			}
			p = 1;
		}
	}
	
	bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "%s\n", buf);
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
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "EXT_FEATURE_INCOMPAT_META_BG is set. fastsync not support \n");
		// TODO : support MEAT_BG
		return NULL;
	}
	
	// get size of group descriptor
	if (ext_has_feature_64bit(ext_sb)) {
		if (!ext_sb->s_desc_size) {
			bsr_err(0, BSR_LC_TEMP, NO_OBJECT, "wrong s_desc_size\n");
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
	bitmap_buf = (PVOLUME_BITMAP_BUFFER)kmalloc(sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size, GFP_ATOMIC|__GFP_NOWARN, '');

	if (bitmap_buf == NULL) {
		bsr_err(0, BSR_LC_TEMP, NO_OBJECT, "bitmap_buf allocation failed\n");
		return NULL;
	}


	bitmap_buf->BitmapSize = bitmap_size;
	memset(bitmap_buf->Buffer, 0, bitmap_buf->BitmapSize);

	if (debug_fast_sync) {
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "=============================\n");
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "first_data_block : %lu \n", first_data_block);
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "total block count : %llu \n", total_block);	
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "blocks_per_group : %lu \n", blocks_per_group);
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "group descriptor size : %u \n", desc_size);
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "block size : %lu \n", bytes_per_block);
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "bitmap size : %lld \n", bitmap_size);
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "group count : %lu \n", group_count);
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "=============================\n");
	}

	group_desc_offset = bytes_per_block * (first_data_block + 1);
	read_size = bytes_per_block;

	for (group_no = 0; group_no < group_count; group_no++) {
		struct ext_group_desc group_desc= {0,};
		unsigned int used = 0;
		unsigned int free = 0;
		unsigned int first_block = 0;
		unsigned int last_block = 0;
		bool block_uninit = false;
		unsigned long long bg_block_bitmap;
		
		
		if (debug_fast_sync) {
			first_block = group_no * blocks_per_group + first_data_block;
			last_block = first_block + (blocks_per_group - 1);
			if (last_block > total_block - 1) {
				last_block = total_block - 1;
			}
		}

		offset = fd->f_op->llseek(fd, group_desc_offset + group_no * desc_size, SEEK_SET);
		if (offset < 0) {
			bsr_err(0, BSR_LC_TEMP, NO_OBJECT, "failed to lseek group_descriptor (err=%lld)\n", offset);
			goto fail_and_free;
		}

		// read group descriptor
		ret = bsr_read(fd, (char *)&group_desc, desc_size, &fd->f_pos);
		if (ret < 0 || ret != desc_size) {
			bsr_err(0, BSR_LC_TEMP, NO_OBJECT, "failed to read group_descriptor (err=%ld)\n", ret);
			goto fail_and_free;
		}	
		
		block_uninit = group_desc.bg_flags & cpu_to_le16(EXT_BG_BLOCK_UNINIT);
		bg_block_bitmap = ext_block_bitmap(ext_sb, &group_desc);

		if (!bg_block_bitmap) {
			bsr_err(0, BSR_LC_TEMP, NO_OBJECT, "failed to read bg_block_bitmap\n");
			goto fail_and_free;
		}
		
		if (debug_fast_sync) {
			bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "Group %u (Blocks %u ~ %u) \n", group_no, first_block, last_block);
			bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "block bitmap : %llu\n", bg_block_bitmap);
			bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "block bitmap offset : %llu\n", bg_block_bitmap * bytes_per_block);
		}


		if (block_uninit) {
			if (debug_fast_sync) {
				bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "skip BLOCK_UNINIT group\n");
				bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "=============================\n");
				free_blocks_co += bytes_per_block * BITS_PER_BYTE;
			}
			continue;
		}

		if (bytes_per_block * (group_no + 1) > bitmap_size)
				read_size = bitmap_size - (group_no * bytes_per_block);

		// Move position to bitmap block
		offset = fd->f_op->llseek(fd, bg_block_bitmap * bytes_per_block, SEEK_SET);
		if (offset < 0) {
			bsr_err(0, BSR_LC_TEMP, NO_OBJECT, "failed to lseek bitmap_block (err=%lld)\n", offset);
			goto fail_and_free;
		}

		// read bitmap block
		ret = bsr_read(fd, &bitmap_buf->Buffer[bytes_per_block * group_no], read_size, &fd->f_pos);
		if (ret < 0 || ret != read_size) {
			bsr_err(0, BSR_LC_TEMP, NO_OBJECT, "failed to read bitmap_block (err=%ld)\n", ret);
			goto fail_and_free;
		}

		if (debug_fast_sync) {
			bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "read bitmap_block (%ld)\n", ret);
			used = ext_used_blocks(group_no, &bitmap_buf->Buffer[bytes_per_block * group_no],
							blocks_per_group,
							first_data_block,
							last_block - first_block + 1);
			bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "used block count : %d\n", used);

			free = ext_free_blocks(group_no, &bitmap_buf->Buffer[bytes_per_block * group_no],
							blocks_per_group,
							first_data_block, 
							last_block - first_block + 1);
			bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "free block count : %d\n", free);
			bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "=============================\n");
			free_blocks_co += free;
		}

	}
	if (debug_fast_sync) {
		bsr_info(0, BSR_LC_TEMP, NO_OBJECT, "free_blocks : %lu\n", free_blocks_co);
	}

	return bitmap_buf;

fail_and_free:
	if (bitmap_buf != NULL) {
		kfree(bitmap_buf);
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