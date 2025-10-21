#include "../../../bsr/bsr_int.h"
#ifdef _LIN_FAST_SYNC
#include "btrfs_fs.h"

bool is_btrfs_fs(struct btrfs_super_block *btrfs_sb)
{
    if (memcmp(btrfs_sb->magic, BTRFS_MAGIC, 8) == 0) 
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
static bool traverse_chunk_tree(struct file *fd, uint64_t node_offset, PVOLUME_BITMAP_BUFFER bitmap_buf) 
{
    struct btrfs_header header;
    struct btrfs_chunk chunk;
    struct btrfs_item item;
    uint32_t i, j;

    if (bsr_read_data(fd, &header, sizeof(struct btrfs_header), node_offset) < 0) 
        return false;

    bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT, "traversing mode @ %llu, level: %u, items: %u", node_offset, header.level, le32_to_cpu(header.nritems));
    if (header.level > 0) {
        // internal node
        if (le32_to_cpu(header.nritems) == 0) {
            bsr_err(148, BSR_LC_BITMAP, NO_OBJECT,
                    "Corrupt internal node: zero nritems (node_offset=%llu level=%u)",
                    (unsigned long long)node_offset, header.level);
            return false;
        }

        for (i = 0; i < le32_to_cpu(header.nritems); i++) {
            struct btrfs_key_ptr kptr;
            uint64_t child_offset;
            off_t child_offset_position = node_offset + sizeof(struct btrfs_header) + (off_t)i * sizeof(struct btrfs_key_ptr);

            if (bsr_read_data(fd, &kptr, sizeof(struct btrfs_key_ptr), child_offset_position) < 0) {
                bsr_err(134, BSR_LC_BITMAP, NO_OBJECT, "Failed to read key pointer. offset = %llu", child_offset_position);
                return false;
            }
            child_offset = le64_to_cpu(kptr.blockptr);
            if (child_offset == 0) {
                bsr_err(149, BSR_LC_BITMAP, NO_OBJECT,
                        "Zero child blockptr i=%u pos=%llu",
                        i, (unsigned long long)child_offset_position);
                return false;
            }
            if (child_offset == node_offset) {
                bsr_err(150, BSR_LC_BITMAP, NO_OBJECT,
                        "Self-referencing child blockptr i=%u node=%llu",
                        i, (unsigned long long)node_offset);
                return false;
            }

            bsr_info(152, BSR_LC_BITMAP, NO_OBJECT,
                      "chunk_tree: internal node=%llu level=%u idx=%u nritems=%u key_ptr_pos=%llu child_logical=%llu gen=%llu key.objectid=%llu key.type=%u key.offset=%llu",
                      (unsigned long long)node_offset, header.level, i, le32_to_cpu(header.nritems),
                      (unsigned long long)child_offset_position,
                      (unsigned long long)child_offset,
                      (unsigned long long)le64_to_cpu(kptr.generation),
                      (unsigned long long)le64_to_cpu(kptr.key.objectid),
                      kptr.key.type,
                      (unsigned long long)le64_to_cpu(kptr.key.offset));
            
            // BSR-1584 Fast sync for internal nodes is not validated yet; unsupported path.
            // Abort traversal here to avoid unverified internal node fast sync handling.
            // TODO: Remove this early abort once internal node fast sync logic is verified.
            bsr_err(151, BSR_LC_BITMAP, NO_OBJECT,
                    "Fast sync unsupported for chunk tree internal node (node=%llu level=%u)",
                    (unsigned long long)node_offset, header.level);
            return false;

            if (!traverse_chunk_tree(fd, child_offset, bitmap_buf)) {
                bsr_err(135, BSR_LC_BITMAP, NO_OBJECT, "Failed to traverse chunk tree. offset = %llu", child_offset);
                return false;
            }
        }
    } else if (header.level == 0) {
        // leaf node
        for (i = 0; i < header.nritems; i++) {
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
            
            for(j = 0; j < le16_to_cpu(chunk.num_stripes); j++) {
                uint64_t start_bit = 0, end_bit = 0, start_byte = 0, end_byte = 0, bit_count = 0;
                u8 start_mask, end_mask;

                if (bsr_read_data(fd, &stripe, sizeof(struct btrfs_stripe), 
                        chunk_offset + sizeof(struct btrfs_chunk) - sizeof(struct btrfs_stripe) + (sizeof(struct btrfs_stripe) * j) ) < 0) {
                    bsr_err(138, BSR_LC_BITMAP, NO_OBJECT, "Failed to read stripe. offset = %llu", chunk_offset + sizeof(struct btrfs_chunk) - sizeof(struct btrfs_stripe) + (sizeof(struct btrfs_stripe) * j));
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

static void set_bitmap(uint8_t *bitmap_buf, uint64_t offset) 
{
    uint64_t bit_index = offset >> BM_BLOCK_SHIFT;         
    uint64_t byte_index = bit_index / BITS_PER_BYTE;       
    uint8_t bit_in_byte = bit_index % BITS_PER_BYTE;      
    uint8_t mask = 1 << bit_in_byte;                  
    bitmap_buf[byte_index] |= mask;
    bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT, "byte index = %llu, bit index = %llu, mask = %d", byte_index, bit_index, mask);
}

/* 
 * BSR-1574
 * ---- Logical -> Physical mapping based on sys_chunk_array ----
 * Parse the superblock's sys_chunk_array (repeating key + chunk)
 * Find the chunk that contains the given logical (bytenr) and compute the physical offset.
 * 
 * On success set *phys_out and return true.
 * On failure (not contained / unsupported layout) return false.
 */
static bool map_logical_from_sys_chunk_array(const struct btrfs_super_block *sb,
                                             uint64_t logical,
                                             uint64_t *phys_out)
{
    const u8 *p;
    u32 remain;
    u32 item_idx = 0;

    remain = le32_to_cpu(sb->sys_chunk_array_size);
    if (!remain) {
        bsr_err(140, BSR_LC_BITMAP, NO_OBJECT, "Failed to read sys_chunk_array. size=0");
        return false;
    }

    bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
              "sys_chunk_array: start parse logical=%llu size=%u", logical, remain);

    p = (const u8 *)&sb->sys_chunk_array;

    while (remain > 0) {
        struct btrfs_disk_key key;
        struct btrfs_chunk on_disk_chunk;
        u16 num_stripes;
        size_t base_need;
        uint64_t c_off;
        uint64_t c_len;
        uint64_t stripe_len;

        if (remain < sizeof(key)) {
            bsr_err(141, BSR_LC_BITMAP, NO_OBJECT,
                    "Failed to read disk_key from sys_chunk_array. remaining=%u bytes, need %zu",
                    remain, sizeof(key));
            return false;
        }
        memcpy(&key, p, sizeof(key));
        p += sizeof(key);
        remain -= sizeof(key);

        bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                  "sys_chunk_array: item %u key.objectid=%llu type=%u offset=%llu remain=%u",
                  item_idx, (unsigned long long)le64_to_cpu(key.objectid),
                  key.type, (unsigned long long)le64_to_cpu(key.offset), remain);

        if (key.type != BTRFS_CHUNK_ITEM_KEY) {
            bsr_err(142, BSR_LC_BITMAP, NO_OBJECT,
                      "Failed to read sys_chunk_array. non chunk item(type=%u) encountered -> stop", key.type);
            return false;
        }

        if (remain < sizeof(struct btrfs_chunk)) {
            bsr_err(143, BSR_LC_BITMAP, NO_OBJECT,
                    "Failed to read sys_chunk_array. remain %u < btrfs_chunk (%zu) stop", remain, sizeof(struct btrfs_chunk));
            return false;
        }

        memcpy(&on_disk_chunk, p, sizeof(struct btrfs_chunk));
        num_stripes = le16_to_cpu(on_disk_chunk.num_stripes);
        if (num_stripes == 0) {
            bsr_err(144, BSR_LC_BITMAP, NO_OBJECT,
                    "Failed to read sys_chunk_array. item %u has zero stripes -> abort", item_idx);
            return false;
        }

        base_need = sizeof(struct btrfs_chunk) +
                    (num_stripes - 1) * sizeof(struct btrfs_stripe);
        if (remain < base_need) {
            bsr_err(145, BSR_LC_BITMAP, NO_OBJECT,
                    "Failed to read sys_chunk_array. item %u need %zu bytes for chunk+stripes but remain=%u",
                    item_idx, base_need, remain);
            return false;
        }
        
        // Check if 'logical' is within this chunk's range
        c_off = le64_to_cpu(key.offset);
        c_len = le64_to_cpu(on_disk_chunk.length);
        stripe_len = le64_to_cpu(on_disk_chunk.stripe_len);

        bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                  "sys_chunk_array: item %u chunk logical_range=[%llu..%llu) len=%llu stripes=%u",
                  item_idx, c_off, c_off + c_len, c_len, num_stripes);
        if (!c_len)
            goto next_item;
        if (c_off + c_len < c_off) /* overflow */
            goto next_item;
                  
        if (logical >= c_off && logical < c_off + c_len) {
            const struct btrfs_stripe *stripes =
                (const struct btrfs_stripe *)(p +
                    sizeof(struct btrfs_chunk) - sizeof(struct btrfs_stripe));
            uint64_t rel = logical - c_off;
            int i;
            bool all_equal = true;

            // single stripe: direct map
            if (num_stripes == 1) {
                *phys_out = le64_to_cpu(stripes[0].offset) + rel;
                bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                            "sys_chunk_array: single stripe map logical=%llu rel=%llu phys=%llu",
                            logical, rel, *phys_out);
                return true;
            }

            // multiple stripes: check if all equal
            for (i = 1; i < num_stripes; i++) {
                if (le64_to_cpu(stripes[i].offset) != le64_to_cpu(stripes[0].offset)) {
                    all_equal = false;
                    break;
                }
            }

            if (all_equal) {
                *phys_out = le64_to_cpu(stripes[0].offset) + rel;
                bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                            "sys_chunk_array: mirrored layout map logical=%llu rel=%llu phys=%llu",
                            logical, rel, *phys_out);
                return true;
            }

            // stripe unit based layout
            if (stripe_len && (stripe_len * num_stripes) <= c_len) {
                uint64_t stripe_index = (rel / stripe_len) % num_stripes;
                uint64_t within = rel % stripe_len;
                *phys_out = le64_to_cpu(stripes[stripe_index].offset) + within;
                bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                            "sys_chunk_array: stripe layout map logical=%llu rel=%llu stripe_len=%llu stripe=%llu within=%llu phys=%llu stripes=%u",
                            logical, rel, stripe_len, stripe_index, within, *phys_out, num_stripes);
                return true;
            }

            // evenly divided layout
            if ((c_len % num_stripes) == 0) {
                uint64_t stripe_unit = c_len / num_stripes;
                uint64_t stripe_index = (rel / stripe_unit) % num_stripes;
                uint64_t within = rel % stripe_unit;
                *phys_out = le64_to_cpu(stripes[stripe_index].offset) + within;
                bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                            "sys_chunk_array: even-split map logical=%llu rel=%llu stripe_unit=%llu stripe=%llu within=%llu phys=%llu",
                            logical, rel, stripe_unit, stripe_index, within, *phys_out);
                return true;
            }

            bsr_err(146, BSR_LC_BITMAP, NO_OBJECT,
                        "Failed to map logical. unsupported layout (num_stripes=%u len=%llu)",
                        num_stripes, c_len);
            return false;
        }
next_item:
        p += base_need;
        remain -= base_need;
        item_idx++;
    }

    bsr_err(147, BSR_LC_BITMAP, NO_OBJECT, "logical %llu not covered by any chunk", logical);
    return false;
}

/* 
 * BSR-1574
 * Tree block (header) validation helper: btrfs_header has no magic field.
 * Only the superblock has a magic, so tree block validation is performed by
 * checking bytenr / level / nritems ranges.
 * expect_logical: the logical bytenr the block is supposed to reference (e.g. chunk_root)
 */
static bool bsr_validate_tree_block(const struct btrfs_header *h, uint64_t expect_logical)
{
    if (!h)
        return false;

    bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT, "validate_tree: expect_logical=%llu bytenr=%llu level=%u nritems=%u",
        expect_logical, le64_to_cpu(h->bytenr), h->level, le32_to_cpu(h->nritems));
    
    if (le64_to_cpu(h->bytenr) != expect_logical)
        return false;
    if (h->level > 7)
        return false;
    if (le32_to_cpu(h->nritems) > 0x10000)
        return false;

    return true;
}


PVOLUME_BITMAP_BUFFER read_btrfs_bitmap(struct file *fd, struct btrfs_super_block *btrfs_sb)
{
	PVOLUME_BITMAP_BUFFER bitmap_buf;
	long long int bitmap_size;
    uint64_t chunk_root_offset = le64_to_cpu(btrfs_sb->chunk_root);
    struct btrfs_header header;
    struct btrfs_dev_item *dev_item = &btrfs_sb->dev_item; 
    uint64_t device_bytes = le64_to_cpu(dev_item->total_bytes);
    uint64_t physical_root = chunk_root_offset; /* Physical offset actually used (initial assumption) */
    bool need_mapping = false; /* Whether we must resolve logical -> physical via sys_chunk_array */
    bool header_ok = false;


	bitmap_size = ALIGN(device_bytes >> BM_BLOCK_SHIFT, BITS_PER_BYTE) / BITS_PER_BYTE;
	bitmap_buf = (PVOLUME_BITMAP_BUFFER)bsr_kvmalloc(sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size, GFP_ATOMIC|__GFP_NOWARN);

    if(!bitmap_buf) {
        bsr_err(98, BSR_LC_MEMORY, NO_OBJECT, "Failed to allocate memory for bitmap buffer. size = %llu", sizeof(VOLUME_BITMAP_BUFFER) + bitmap_size);
        return NULL;
    }

	bitmap_buf->BitmapSize = bitmap_size;
	memset(bitmap_buf->Buffer, 0, bitmap_buf->BitmapSize);


    // BSR-1574 attempt a direct read (already a physical offset)
    if (chunk_root_offset < device_bytes) {
        if (bsr_read_data(fd, &header, sizeof(header), chunk_root_offset) >= 0 &&
            bsr_validate_tree_block(&header, chunk_root_offset)) {
            header_ok = true;
            physical_root = chunk_root_offset;
        } else {
            bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                    "Direct read failed or invalid header at %llu, attempting sys_chunk_array mapping",
                    chunk_root_offset);
            need_mapping = true;
        }
    } else {
        // If larger than the device size, treat it as a logical address
        bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                  "Chunk root offset %llu outside device range %llu, attempting sys_chunk_array mapping",
                  chunk_root_offset, device_bytes);
        need_mapping = true;
    }

    // BSR-1574 Try sys_chunk_array-based mapping (if direct read failed or was outside device range)
    if (need_mapping) {
        uint64_t phys_tmp;
        if (map_logical_from_sys_chunk_array(btrfs_sb, chunk_root_offset, &phys_tmp)) {
            if (bsr_read_data(fd, &header, sizeof(header), phys_tmp) >= 0 &&
                bsr_validate_tree_block(&header, chunk_root_offset)) {
                physical_root = phys_tmp;
                header_ok = true;
                bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                          "Mapped chunk_root via sys_chunk_array: logical=%llu -> physical=%llu",
                          chunk_root_offset, phys_tmp);
            } else {
                bsr_debug(-1, BSR_LC_BITMAP, NO_OBJECT,
                        "sys_chunk_array resolved %llu but header verify failed",
                        phys_tmp);
            }
        }
    }

    if (!header_ok) {
        bsr_err(132, BSR_LC_BITMAP, NO_OBJECT, "Failed to read chunk root header. offset = %llu", chunk_root_offset);
        bsr_kfree(bitmap_buf);
        return NULL;
    }

    // BSR-1407 set up a bitmap for a super block
    set_bitmap(bitmap_buf->Buffer, BTRFS_SUPER_BLOCK_OFFSET);
    if(device_bytes >= BTRFS_FIRST_COPY_SUPER_BLOCK_OFFSET + sizeof(struct btrfs_super_block))
        set_bitmap(bitmap_buf->Buffer, BTRFS_FIRST_COPY_SUPER_BLOCK_OFFSET);
    if(device_bytes >= BTRFS_SECOND_COPY_SUPER_BLOCK_OFFSET + sizeof(struct btrfs_super_block))
        set_bitmap(bitmap_buf->Buffer, BTRFS_SECOND_COPY_SUPER_BLOCK_OFFSET);

    // BSR-1574 Chunk tree traversal using physical offset
    if (!traverse_chunk_tree(fd, physical_root, bitmap_buf)) {
        bsr_err(133, BSR_LC_BITMAP, NO_OBJECT,
                "Failed to traverse chunk tree at physical=%llu (logical=%llu)",
                physical_root, chunk_root_offset);
        bsr_kfree(bitmap_buf);
        return NULL;
    }
    
    return bitmap_buf;
}

#endif