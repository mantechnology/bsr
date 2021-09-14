#include "../../bsr/bsr_int.h"
#include "bsr_wrappers.h"

#ifdef _WIN
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

#ifdef _LIN
#ifndef COMPAT_HAVE_PROC_CREATE_SINGLE
#include <linux/proc_fs.h>
/* This compat wrapper is not generic, only good enough for bsr */
extern int bsr_seq_show(struct seq_file *seq, void *v);

static int bsr_proc_single_open(struct inode *inode, struct file *file)
{
    return single_open(file, bsr_seq_show, NULL);
}

struct proc_dir_entry *proc_create_single(const char *name, umode_t mode,
        struct proc_dir_entry *parent,
        int (*show)(struct seq_file *, void *))
{
    static const struct file_operations bsr_proc_single_fops = {
        .open           = bsr_proc_single_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
    };

    return proc_create_data(name, mode, parent, &bsr_proc_single_fops, NULL);
}
#endif
#endif