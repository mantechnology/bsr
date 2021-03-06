#include "./bsr_int.h"
#include "bsr_interval.h"
#include "./bsr-kernel-compat/bsr_wrappers.h"

/**
 * interval_end  -  return end of @node
 */
static inline
sector_t interval_end(struct rb_node *node)
{
	struct bsr_interval *this = rb_entry(node, struct bsr_interval, rb);
	return this->end;
}

/**
 * update_interval_end  -  recompute end of @node
 *
 * The end of an interval is the highest (start + (size >> 9)) value of this
 * node and of its children.  Called for @node and its parents whenever the end
 * may have changed.
 */
static void
update_interval_end(struct rb_node *node, void *__unused)
{
	struct bsr_interval *this = rb_entry(node, struct bsr_interval, rb);
	sector_t end;

	UNREFERENCED_PARAMETER(__unused);

	end = this->sector + (this->size >> 9);
	if (node->rb_left) {
		sector_t left = interval_end(node->rb_left);
		if (left > end)
			end = left;
	}
	if (node->rb_right) {
		sector_t right = interval_end(node->rb_right);
		if (right > end)
			end = right;
	}
	this->end = end;
}

/**
 * bsr_insert_interval  -  insert a new interval into a tree
 */
bool
bsr_insert_interval(struct rb_root *root, struct bsr_interval *this)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;

	BUG_ON(!IS_ALIGNED(this->size, 512));

	while (*new) {
		struct bsr_interval *here =
			rb_entry(*new, struct bsr_interval, rb);

		parent = *new;
		if (this->sector < here->sector)
			new = &(*new)->rb_left;
		else if (this->sector > here->sector)
			new = &(*new)->rb_right;
		else if (this < here)
			new = &(*new)->rb_left;
		else if (this > here)
			new = &(*new)->rb_right;
		else
			return false;
	}

	rb_link_node(&this->rb, parent, new);
	rb_insert_color(&this->rb, root);
	rb_augment_insert(&this->rb, update_interval_end, NULL);
	return true;
}

/**
 * bsr_contains_interval  -  check if a tree contains a given interval
 * @sector:	start sector of @interval
 * @interval:	may be an invalid pointer
 *
 * Returns if the tree contains the node @interval with start sector @start.
 * Does not dereference @interval until @interval is known to be a valid object
 * in @tree.  Returns %false if @interval is in the tree but with a different
 * sector number.
 */
bool
bsr_contains_interval(struct rb_root *root, sector_t sector,
		       struct bsr_interval *interval)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct bsr_interval *here =
			rb_entry(node, struct bsr_interval, rb);

		if (sector < here->sector)
			node = node->rb_left;
		else if (sector > here->sector)
			node = node->rb_right;
		else if (interval < here)
			node = node->rb_left;
		else if (interval > here)
			node = node->rb_right;
		else
			return true;
	}
	return false;
}

/**
 * bsr_remove_interval  -  remove an interval from a tree
 */
void
bsr_remove_interval(struct rb_root *root, struct bsr_interval *this)
{
	struct rb_node *deepest;

	/* avoid endless loop */
	if (bsr_interval_empty(this))
		return;

	deepest = rb_augment_erase_begin(&this->rb);
	rb_erase(&this->rb, root);
	rb_augment_erase_end(deepest, update_interval_end, NULL);
}

/**
 * bsr_find_overlap  - search for an interval overlapping with [sector, sector + size)
 * @sector:	start sector
 * @size:	size, aligned to 512 bytes
 *
 * Returns an interval overlapping with [sector, sector + size), or NULL if
 * there is none.  When there is more than one overlapping interval in the
 * tree, the interval with the lowest start sector is returned, and all other
 * overlapping intervals will be on the right side of the tree, reachable with
 * rb_next().
 */
struct bsr_interval *
bsr_find_overlap(struct rb_root *root, sector_t sector, unsigned int size)
{
	struct rb_node *node = root->rb_node;
	struct bsr_interval *overlap = NULL;
	sector_t end = sector + (size >> 9);

	BUG_ON(!IS_ALIGNED(size, 512));

	while (node) {
		struct bsr_interval *here =
			rb_entry(node, struct bsr_interval, rb);

		if (node->rb_left &&
		    sector < interval_end(node->rb_left)) {
			/* Overlap if any must be on left side */
			node = node->rb_left;
		} else if (here->sector < end &&
			   sector < here->sector + (here->size >> 9)) {
            // PERFORMANCE_CHECK: this logic is entered when crystal 32QD test. required performance tuning for small I/O 
			overlap = here;
			break;
		} else if (sector >= here->sector) {
			/* Overlap if any must be on right side */
			node = node->rb_right;
		} else
			break;
	}
	return overlap;
}

struct bsr_interval *
bsr_next_overlap(struct bsr_interval *i, sector_t sector, unsigned int size)
{
	sector_t end = sector + (size >> 9);
	struct rb_node *node;

	for (;;) {
		node = rb_next(&i->rb);
		if (!node)
			return NULL;
		i = rb_entry(node, struct bsr_interval, rb);
		if (i->sector >= end)
			return NULL;
		if (sector < i->sector + (i->size >> 9))
			return i;
	}
}
