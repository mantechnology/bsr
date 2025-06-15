// BSR-1512 
/*
 * The blk_alloc_disk() function's parameters have changed from one to two.
 *
 * Previously, blk_alloc_disk() took a single parameter (e.g., number of minors).
 * Now, it takes two parameters:
 *   - A pointer to struct queue_limits, which defines I/O constraints such as
 *     block sizes, maximum segments, and alignment requirements.
 *   - An integer node_id indicating the NUMA node affinity for the disk.
 *
 * This change allows more precise and explicit configuration of the block device's
 * characteristics and its placement relative to system memory topology at allocation time.
 *
 * When supporting multiple kernel versions, be sure to handle both parameter styles accordingly.
 */
#include <linux/blkdev.h>

void foo(void)
{
    blk_alloc_disk(NULL, 0);
}
