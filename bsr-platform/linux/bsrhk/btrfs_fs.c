#include "../../../bsr/bsr_int.h"
#ifdef _LIN_FAST_SYNC
#include "btrfs_fs.h"

bool is_btrfs_fs(struct btrfs_super_block *btrfs_sb)
{
    if (memcmp(btrfs_sb->magic, BTRFS_SUPER_MAGIC, 8) == 0) 
    {
        return true;
    } else {
        return false;
    }
}

int bsr_read_data(struct file *fd, void *buf, size_t size, off_t offset) 
{
    ssize_t ret;
    off_t ret_offset = fd->f_op->llseek(fd, offset, SEEK_SET);
    if (ret_offset < 0) {
        return -1;
    }
    ret = bsr_read(fd, buf, size, &fd->f_pos);
    if (ret < 0 || ret != size) {
        return -1;
    }
    return ret;
}
/*
    Chunk Root (Level 2)
    ├── Internal Node 1 (Level 1)
    │    ├── Leaf Node A (Level 0) → [Chunk Offset, Length]
    │    ├── Leaf Node B (Level 0) → [Chunk Offset, Length]
    │
    ├── Internal Node 2 (Level 1)
    │    ├── Leaf Node C (Level 0) → [Chunk Offset, Length]
    │    ├── Leaf Node D (Level 0) → [Chunk Offset, Length]
*/
bool traverse_chunk_tree(struct file *fd, uint64_t node_offset, PVOLUME_BITMAP_BUFFER bitmap_buf) 
{
    struct btrfs_header header;
    struct btrfs_chunk chunk;
    struct btrfs_item item;

    if (bsr_read_data(fd, &header, sizeof(struct btrfs_header), node_offset) < 0) 
        return false;

    bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT, "traversing mode @ %llu, level: %u, items: %u", node_offset, header.level, le32_to_cpu(header.nritems));
    if (header.level > 0) {
        // internal node
        for (uint32_t i = 0; i < le32_to_cpu(header.nritems); i++) {
            uint64_t child_offset;
            off_t child_offset_position = node_offset + sizeof(struct btrfs_header) + i * sizeof(uint64_t);

            if (bsr_read_data(fd, &child_offset, sizeof(uint64_t), child_offset_position) < 0) {
                bsr_err(134, BSR_LC_BITMAP, NO_OBJECT, "Failed to read child offset. offset = %llu", child_offset_position);
                return false;
            }
            if(!traverse_chunk_tree(fd, child_offset, bitmap_buf)) {
                bsr_err(135, BSR_LC_BITMAP, NO_OBJECT, "Failed to traverse chunk tree. offset = %llu", child_offset);
                return false;
            }
        }
    } else if (header.level == 0) {
        // leaf node
        for (uint32_t i = 0; i < header.nritems; i++) {
            off_t chunk_offset, item_offset = node_offset + sizeof(struct btrfs_header) + i * sizeof(struct btrfs_item);
            struct btrfs_stripe stripe;
            if (bsr_read_data(fd, &item, sizeof(struct btrfs_item), item_offset) < 0) {
                bsr_err(136, BSR_LC_BITMAP, NO_OBJECT, "Failed to read item. offset = %llu", item_offset);
                return false;
            }

            if(item.key.type != BTRFS_CHUNK_ITEM_KEY)
                continue;

            chunk_offset = node_offset + sizeof(struct btrfs_header) + le64_to_cpu(item.offset);  
            if (bsr_read_data(fd, &chunk, sizeof(struct btrfs_chunk), chunk_offset) < 0) {
                bsr_err(137, BSR_LC_BITMAP, NO_OBJECT, "Failed to read chunk. offset = %llu", chunk_offset);
                return false;
            }
            
            for(uint32_t i = 0; i < le16_to_cpu(chunk.num_stripes); i++) {
                uint64_t start_bit = 0, end_bit = 0, start_byte = 0, end_byte = 0, bit_count = 0;
                u8 start_mask, end_mask;

                if (bsr_read_data(fd, &stripe, sizeof(struct btrfs_stripe), 
                        chunk_offset + sizeof(struct btrfs_chunk) - sizeof(struct btrfs_stripe) + (sizeof(struct btrfs_stripe) * i) ) < 0) {
                    bsr_err(138, BSR_LC_BITMAP, NO_OBJECT, "Failed to read stripe. offset = %llu", chunk_offset + sizeof(struct btrfs_chunk) - sizeof(struct btrfs_stripe) + (sizeof(struct btrfs_stripe) * i));
                    return false;
                }

                start_bit = le64_to_cpu(stripe.offset) >> BM_BLOCK_SHIFT;
                bit_count = (le64_to_cpu(chunk.length) + BM_BLOCK_SIZE - 1) >> BM_BLOCK_SHIFT; 
                end_bit = start_bit + bit_count - 1;

                start_byte = start_bit / BITS_PER_BYTE;
                end_byte = end_bit / BITS_PER_BYTE;

                start_mask = 0xFF << (start_bit % BITS_PER_BYTE);
                end_mask = 0xFF >> (7 - (end_bit % BITS_PER_BYTE));
                
                if (start_byte == end_byte) {
                    u8 mask = start_mask & end_mask;
                    bitmap_buf->Buffer[start_byte] |= mask;
                } else {
                    bitmap_buf->Buffer[start_byte] |= start_mask;
                    if (end_byte > start_byte + 1)
                        memset(bitmap_buf->Buffer + start_byte + 1, 0xFF, end_byte - start_byte - 1);
                    bitmap_buf->Buffer[end_byte] |= end_mask;
                }

                bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT, "node offset = %llu, item offset = %llu offset = %llu, chunk offset %llu, stripe offset = %llu, size = %llu",
                   node_offset, item_offset, le64_to_cpu(item.offset), chunk_offset, le64_to_cpu(stripe.offset), le64_to_cpu(chunk.length));
                bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT, "bitmap buffer offset = %llu, end offset = %llu, start_mask %d, end_mask %d, BM_BLOCK_SHIFT %d", 
                    start_byte, end_byte, start_mask, end_mask, BM_BLOCK_SHIFT);
            }
        }
    } else {
        bsr_err(139, BSR_LC_BITMAP, NO_OBJECT, "Invalid header level: %u", header.level);
        return false;
    }
    return true;
}

void set_bitmap(uint8_t *bitmap_buf, uint64_t offset) 
{
    uint64_t bit_index = offset >> BM_BLOCK_SHIFT;         
    uint64_t byte_index = bit_index / BITS_PER_BYTE;       
    uint8_t bit_in_byte = bit_index % BITS_PER_BYTE;      
    uint8_t mask = 1 << bit_in_byte;                  
    bitmap_buf[byte_index] |= mask;
    bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT, "byte index = %llu, bit index = %llu, mask = %d", byte_index, bit_index, mask);
}

PVOLUME_BITMAP_BUFFER read_btrfs_bitmap(struct file *fd, struct btrfs_super_block *btrfs_sb)
{
	PVOLUME_BITMAP_BUFFER bitmap_buf;
	long long int bitmap_size;
    uint64_t chunk_root_offset = le64_to_cpu(btrfs_sb->chunk_root);
    struct btrfs_header header;
    struct btrfs_dev_item *dev_item = &btrfs_sb->dev_item; 

	bitmap_size = ALIGN(le64_to_cpu(dev_item->total_bytes) >> BM_BLOCK_SHIFT, BITS_PER_BYTE) / BITS_PER_BYTE;
	bitmap_buf = (PVOLUME_BITMAP_BUFFER)bsr_kvmalloc(sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size, GFP_ATOMIC|__GFP_NOWARN);

    if(!bitmap_buf) {
        bsr_err(98, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate memory for bitmap buffer. size = %llu", sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size);
        return NULL;
    }

	bitmap_buf->BitmapSize = bitmap_size;
	memset(bitmap_buf->Buffer, 0, bitmap_buf->BitmapSize);

    if (bsr_read_data(fd, &header, sizeof(header), chunk_root_offset) < 0) {
        bsr_err(132, BSR_LC_BITMAP, NO_OBJECT, "Failed to read chunk root header. offset = %llu", chunk_root_offset);
        bsr_kfree(bitmap_buf);
        return NULL;
    }

    // BSR-1407 set up a bitmap for a super block
    set_bitmap(bitmap_buf->Buffer, BTRFS_SUPER_BLOCK_OFFSET);
    if(le64_to_cpu(dev_item->total_bytes) >= BTRFS_FIRST_COPY_SUPER_BLOCK_OFFSET + sizeof(struct btrfs_super_block))
        set_bitmap(bitmap_buf->Buffer, BTRFS_FIRST_COPY_SUPER_BLOCK_OFFSET);
    if(le64_to_cpu(dev_item->total_bytes) >= BTRFS_SECOND_COPY_SUPER_BLOCK_OFFSET + sizeof(struct btrfs_super_block))
        set_bitmap(bitmap_buf->Buffer, BTRFS_SECOND_COPY_SUPER_BLOCK_OFFSET);

    if(!traverse_chunk_tree(fd, chunk_root_offset, bitmap_buf)) {
        bsr_err(133, BSR_LC_BITMAP, NO_OBJECT, "Failed to traverse chunk tree. offset = %llu", chunk_root_offset);
        bsr_kfree(bitmap_buf);
        return NULL;
    }
    
    return bitmap_buf;
}

#endif