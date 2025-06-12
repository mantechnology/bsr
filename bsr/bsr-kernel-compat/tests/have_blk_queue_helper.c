// BSR-1512
/*
 * Check for the presence of blk_queue_max_phys_segments() to determine
 * whether blk_queue_* helper functions are available in this kernel version.
 *
 * This function is commonly defined alongside other queue helper functions such as:
 *  - blk_queue_logical_block_size()
 *  - blk_queue_physical_block_size()
 *  - blk_queue_max_hw_sectors()
 *  - blk_queue_dma_alignment()
 *
 * If blk_queue_max_phys_segments() is available, it is safe to assume
 * that the rest of the blk_queue_* helper functions can also be used.
 *
 * This is useful for writing portable kernel code across different versions.
 */
#include <linux/blkdev.h>  
#include <linux/blk_types.h> 

void dummy(struct request_queue *q)
{
    blk_queue_max_phys_segments(q, 128);
}
