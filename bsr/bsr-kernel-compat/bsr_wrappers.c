#include "bsr_wrappers.h"
#include "../../bsr/bsr_int.h"

#ifndef bio_set_op_attrs
void bio_set_op_attrs(struct bio *bio, const int op, const long flags)
{
	/* If we explicitly issue discards or write_same, we use
	* blkdev_isse_discard() and blkdev_issue_write_same() helpers.
	* If we implicitly submit them, we just pass on a cloned bio to
	* generic_make_request().  We expect to use bio_set_op_attrs() with
	* REQ_OP_READ or REQ_OP_WRITE only. */
	BUG_ON(!(op == REQ_OP_READ || op == REQ_OP_WRITE));
	bio->bi_rw |= (op | flags);
}
#endif