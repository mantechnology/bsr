#ifndef __BSR_INTERVAL_H
#define __BSR_INTERVAL_H

#ifdef _WIN
#include "../bsr-headers/windows/types.h"
#include "./bsr-kernel-compat/windows/rbtree.h"
#define inline __inline
#define __always_inline __inline
#else // _LIN
#include <linux/version.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#endif
/* Compatibility code for 2.6.16 (SLES10) */
#ifndef rb_parent
#define rb_parent(r)   ((r)->rb_parent)
#endif

/*
 * Kernels between mainline commit dd67d051 (v2.6.18-rc1) and 10fd48f2
 * (v2.6.19-rc1) have a broken version of RB_EMPTY_NODE().
 *
 * RHEL5 kernels until at least 2.6.18-238.12.1.el5 have the broken definition.
 */
#ifdef _WIN
#if !defined(RB_EMPTY_NODE)
#undef RB_EMPTY_NODE                                                        
#define RB_EMPTY_NODE(node)     (rb_parent(node) == node)           
#endif   
#else // _LIN
#if !defined(RB_EMPTY_NODE) || LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,19)
#undef RB_EMPTY_NODE                                                        
#define RB_EMPTY_NODE(node)     (rb_parent(node) == node)                                                                                        
#endif      
#endif


#ifndef RB_CLEAR_NODE
static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
        rb->rb_parent = p;
}
#define RB_CLEAR_NODE(node)     (rb_set_parent(node, node))
#endif
/* /Compatibility code */

struct bsr_interval {
	struct rb_node rb;
	sector_t sector;		/* start sector of the interval */
	unsigned int size;		/* size in bytes */
	sector_t end;			/* highest interval end in subtree */
	unsigned int local:1		/* local or remote request? */;
	unsigned int waiting:1;		/* someone is waiting for completion */
	unsigned int completed:1;	/* this has been completed already;
					 * ignore for conflict detection */
};

static inline void bsr_clear_interval(struct bsr_interval *i)
{
	RB_CLEAR_NODE(&i->rb);
}

static inline bool bsr_interval_empty(struct bsr_interval *i)
{
	return RB_EMPTY_NODE(&i->rb);
}

extern bool bsr_insert_interval(struct rb_root *, struct bsr_interval *);
extern bool bsr_contains_interval(struct rb_root *, sector_t,
				   struct bsr_interval *);
extern void bsr_remove_interval(struct rb_root *, struct bsr_interval *);
extern struct bsr_interval *bsr_find_overlap(struct rb_root *, sector_t,
					unsigned int);
extern struct bsr_interval *bsr_next_overlap(struct bsr_interval *, sector_t,
					unsigned int);

#define bsr_for_each_overlap(i, root, sector, size)		\
	for (i = bsr_find_overlap(root, sector, size);		\
	     i;							\
	     i = bsr_next_overlap(i, sector, size))

#endif  /* __BSR_INTERVAL_H */
