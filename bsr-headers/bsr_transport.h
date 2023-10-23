#ifndef BSR_TRANSPORT_H
#define BSR_TRANSPORT_H
#ifdef _WIN
#include "../bsr/bsr-kernel-compat/windows/list.h"
#include "../bsr/bsr-kernel-compat/windows/wait.h"
#include "../bsr/bsr-kernel-compat/windows/bsr_windows.h"
#else // _LIN
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/socket.h>
#include <bsr_wrappers.h>
#endif

/* Whenever touch this file in a non-trivial way, increase the
   BSR_TRANSPORT_API_VERSION
   So that transport compiled against an older version of this
   header will no longer load in a module that assumes a newer
   version. */
#define BSR_TRANSPORT_API_VERSION 15

/* MSG_MSG_DONTROUTE and MSG_PROBE are not used by BSR. I.e.
   we can reuse these flags for our purposes */
#define CALLER_BUFFER  MSG_DONTROUTE
#define GROW_BUFFER    MSG_PROBE

// BSR-12
#define _SEND_BUF

#ifdef _SEND_BUF		// Use Send Buffering
#ifdef _WIN
#define _WIN_SEND_BUF
#else // _LIN
#define _LIN_SEND_BUF
#endif
#endif

/*
 * gfp_mask for allocating memory with no write-out.
 *
 * When bsr allocates memory on behalf of the peer, we prevent it from causing
 * write-out because in a criss-cross setup, the write-out could lead to memory
 * pressure on the peer, eventually leading to deadlock.
 */
#define GFP_TRY	(__GFP_HIGHMEM | __GFP_NOWARN | __GFP_RECLAIM)
#ifdef _WIN
#define tr_printk(level, transport, fmt, ...)  do {		\
	rcu_read_lock();					\
	printk(level "bsr %s: " fmt,			\
	       rcu_dereference((transport)->net_conf)->name,	\
	       __VA_ARGS__);					\
	rcu_read_unlock();					\
	}while (false)

#define tr_err(transport, fmt, ...) \
	tr_printk(KERN_ERR, transport, fmt, ## __VA_ARGS__)
#define tr_warn(transport, fmt, ...) \
	tr_printk(KERN_WARNING, transport, fmt, ## __VA_ARGS__)
#define tr_info(transport, fmt, ...) \
	tr_printk(KERN_INFO, transport, fmt, ## __VA_ARGS__)
#else // _LIN
#define tr_printk(category, index, level, transport, fmt, args...)  ({		\
	rcu_read_lock();					\
	__printk(__FUNCTION__, index, level, category, "<%c> bsr %s %s:%s: " fmt,			\
	       level[1],	\
		   (transport)->log_prefix,				\
	       (transport)->class->name,			\
	       rcu_dereference((transport)->net_conf)->name,	\
	       ## args);					\
	rcu_read_unlock();					\
	})

#define tr_err(transport, fmt, args...) \
	tr_printk(BSR_LC_ETC, -1, KERN_ERR, transport, fmt, ## args)
#define tr_warn(transport, fmt, args...) \
	tr_printk(BSR_LC_ETC, -1, KERN_WARNING, transport, fmt, ## args)
#define tr_info(transport, fmt, args...) \
	tr_printk(BSR_LC_ETC, -1, KERN_INFO, transport, fmt, ## args)
#endif

#define TR_ASSERT(x, exp)							\
	do {									\
		if (!(exp))							\
			tr_err(x, "ASSERTION %s FAILED in %s\n", 		\
				 #exp, __func__);				\
	} while (0)

struct bsr_resource;
struct bsr_connection;
struct bsr_peer_device;

enum bsr_stream {
	DATA_STREAM,
	CONTROL_STREAM
};

enum bsr_tr_hints {
	CORK,
	UNCORK,
	NODELAY,
	NOSPACE,
	QUICKACK
};

enum { /* bits in the flags word */
	NET_CONGESTED,		/* The data socket is congested */
	RESOLVE_CONFLICTS,	/* Set on one node, cleared on the peer! */
	// DW-1204 flag to flush send buffer when disconnecting.
	DISCONNECT_FLUSH,
};

enum bsr_tr_free_op {
	CLOSE_CONNECTION,
	DESTROY_TRANSPORT
};

struct bsr_listener;

#ifdef _LIN
typedef struct sockaddr_storage SOCKADDR_STORAGE_EX;
#endif

/* A transport might wrap its own data structure around this. Having
   this base class as its first member. */
struct bsr_path {
	SOCKADDR_STORAGE_EX my_addr;
	SOCKADDR_STORAGE_EX peer_addr;

	struct kref kref;

	int my_addr_len;
	int peer_addr_len;
	bool established; /* updated by the transport */
	
	struct list_head list; /* paths of a connection */
	struct list_head listener_link; /* paths waiting for an incomming connection,
									head is in a bsr_listener */
	struct bsr_listener *listener;
};

/* Each transport implementation should embed a struct bsr_transport
   into it's instance data structure. */
struct bsr_transport {
	struct bsr_transport_ops *ops;
	struct bsr_transport_class *class;

	struct list_head paths;

	const char *log_prefix;		/* resource name */
	struct net_conf *net_conf;	/* content protected by rcu */

	// BSR-683
	atomic_t64 sum_sent;
	atomic_t64 sum_recv;
	ULONG_PTR sum_start_time;
	/* These members are intended to be updated by the transport: */
	// BSR-977 sets the ko_count based on the stream.
	unsigned int ko_count[2];
	ULONG_PTR flags;
};

struct bsr_transport_stats {
	int unread_received;
	int unacked_send;
#ifdef _WIN
	signed long long send_buffer_size;
	signed long long send_buffer_used;
#else // _LIN
	int send_buffer_size;
	int send_buffer_used;
#endif
};

/* argument to ->recv_pages() */
struct bsr_page_chain_head {
	struct page *head; // WIN32:used by void pointer to memory which alloccated by malloc()
	unsigned int nr_pages;
};


typedef struct seq_file seq_file;

struct bsr_transport_ops {
	void (*free)(struct bsr_transport *, enum bsr_tr_free_op free_op);
	int (*connect)(struct bsr_transport *);

/**
 * recv() - Receive data via the transport
 * @transport:	The transport to use
 * @stream:	The stream within the transport to use. Ether DATA_STREAM or CONTROL_STREAM
 * @buf:	The function will place here the pointer to the data area
 * @size:	Number of byte to receive
 * @msg_flags:	Bitmask of CALLER_BUFFER, GROW_BUFFER and MSG_DONTWAIT
 *
 * recv() returns the requests data in a buffer (owned by the transport).
 * You may pass MSG_DONTWAIT as flags.  Usually with the next call to recv()
 * or recv_pages() on the same stream, the buffer may no longer be accessed
 * by the caller. I.e. it is reclaimed by the transport.
 *
 * If the transport was not capable of fulfilling the complete "wish" of the
 * caller (that means it returned a smaller size that size), the caller may
 * call recv() again with the flag GROW_BUFFER, and *buf as returned by the
 * previous call.
 * Note1: This can happen if MSG_DONTWAIT was used, or if a receive timeout
 *	was we with set_rcvtimeo().
 * Note2: recv() is free to re-locate the buffer in such a call. I.e. to
 *	modify *buf. Then it copies the content received so far to the new
 *	memory location.
 *
 * Last not least the caller may also pass an arbitrary pointer in *buf with
 * the CALLER_BUFFER flag. This is expected to be used for small amounts
 * of data only
 *
 * Upon success the function returns the bytes read. Upon error the return
 * code is negative. A 0 indicates that the socket was closed by the remote
 * side.
 */
	int (*recv)(struct bsr_transport *, enum bsr_stream, void **buf, size_t size, int flags);

/**
 * recv_pages() - Receive bulk data via the transport's DATA_STREAM
 * @peer_device: Identify the transport and the device
 * @page_chain:	Here recv_pages() will place the page chain head and length
 * @size:	Number of bytes to receive
 *
 * recv_pages() will return the requested amount of data from DATA_STREAM,
 * and place it into pages allocated with bsr_alloc_pages().
 *
 * Upon success the function returns 0. Upon error the function returns a
 * negative value
 */
	int (*recv_pages)(struct bsr_transport *, struct bsr_page_chain_head *, size_t size);

	void (*stats)(struct bsr_transport *, struct bsr_transport_stats *stats);
	void (*set_rcvtimeo)(struct bsr_transport *, enum bsr_stream, long timeout);
	long (*get_rcvtimeo)(struct bsr_transport *, enum bsr_stream);
	int (*send_page)(struct bsr_transport *, enum bsr_stream, struct page *,
					int offset, size_t size,
					// BSR-1116
					int type, unsigned msg_flags);
	int (*send_zc_bio)(struct bsr_transport *, struct bio *bio);
	bool (*stream_ok)(struct bsr_transport *, enum bsr_stream);
	bool (*hint)(struct bsr_transport *, enum bsr_stream, enum bsr_tr_hints hint);
	void (*debugfs_show)(struct bsr_transport *, struct seq_file *m);
	int (*add_path)(struct bsr_transport *, struct bsr_path *path);
	int (*remove_path)(struct bsr_transport *, struct bsr_path *path);
#ifdef _SEND_BUF 
	bool (*start_send_buffring)(struct bsr_transport *, signed long long size);
	void (*stop_send_buffring)(struct bsr_transport *);
#endif
};

struct bsr_transport_class {
	const char *name;
	const int instance_size;
	const int path_instance_size;
#ifdef _LIN 
	struct module *module;
#endif
	int (*init)(struct bsr_transport *);
	struct list_head list;
};


/* An "abstract base class" for transport implementations. I.e. it
   should be embedded into a transport specific representation of a
   listening "socket" */
struct bsr_listener {
	struct kref kref;
	struct bsr_resource *resource;
	struct list_head list; /* link for resource->listeners */
	struct list_head waiters; /* list head for paths */
	spinlock_t waiters_lock;
	int pending_accepts;
	SOCKADDR_STORAGE_EX listen_addr;
	void (*destroy)(struct bsr_listener *);
};

/* bsr_main.c */
extern void bsr_destroy_path(struct kref *kref);

/* bsr_transport.c */
extern int bsr_register_transport_class(struct bsr_transport_class *transport_class,
					 int api_version,
					 int bsr_transport_size);
extern void bsr_unregister_transport_class(struct bsr_transport_class *transport_class);
extern struct bsr_transport_class *bsr_get_transport_class(const char *transport_name);
extern void bsr_put_transport_class(struct bsr_transport_class *);
extern void bsr_print_transports_loaded(struct seq_file *seq);
// DW-1498
extern bool addr_and_port_equal(const SOCKADDR_STORAGE_EX *addr1, const SOCKADDR_STORAGE_EX *addr2);
extern int bsr_get_listener(struct bsr_transport *transport, struct bsr_path *path,
	int(*create_fn)(struct bsr_transport *, const struct sockaddr *, struct bsr_listener **));
extern void bsr_put_listener(struct bsr_path *path);
extern struct bsr_path *bsr_find_path_by_addr(struct bsr_listener *, SOCKADDR_STORAGE_EX *);
extern bool bsr_stream_send_timed_out(struct bsr_transport *transport, enum bsr_stream stream);
extern bool bsr_should_abort_listening(struct bsr_transport *transport);
extern void bsr_path_event(struct bsr_transport *transport, struct bsr_path *path);

/* bsr_receiver.c*/
#ifdef _WIN
extern void* bsr_alloc_pages(struct bsr_transport *, unsigned int, bool);
extern void bsr_free_pages(struct bsr_transport *transport, int page_count, int is_net);
#else // _LIN
extern struct page *bsr_alloc_pages(struct bsr_transport *, unsigned int, gfp_t);
extern void bsr_free_pages(struct bsr_transport *transport, struct page *page, int is_net);
#endif
static inline void bsr_alloc_page_chain(struct bsr_transport *t,
	struct bsr_page_chain_head *chain, unsigned int nr, gfp_t gfp_flags)
{
	chain->head = bsr_alloc_pages(t, nr, gfp_flags);
	chain->nr_pages = chain->head ? nr : 0;
}

static inline void bsr_free_page_chain(struct bsr_transport *transport, struct bsr_page_chain_head *chain, int is_net)
{
#ifdef _WIN
	// DW-1239 decrease nr_pages before bsr_free_pages().
	int page_count = atomic_xchg((atomic_t *)&chain->nr_pages, 0);
	bsr_free_pages(transport, page_count, is_net);
#else // _LIN
	bsr_free_pages(transport, chain->head, is_net);
	chain->nr_pages = 0;
#endif
	chain->head = NULL;
}

/*
 * Some helper functions to deal with our page chains.
 */
/* Our transports may sometimes need to only partially use a page.
 * We need to express that somehow.  Use this struct, and "graft" it into
 * struct page at page->lru.
 *
 * According to include/linux/mm.h:
 *  | A page may be used by anyone else who does a __get_free_page().
 *  | In this case, page_count still tracks the references, and should only
 *  | be used through the normal accessor functions. The top bits of page->flags
 *  | and page->virtual store page management information, but all other fields
 *  | are unused and could be used privately, carefully. The management of this
 *  | page is the responsibility of the one who allocated it, and those who have
 *  | subsequently been given references to it.
 * (we do alloc_page(), that is equivalent).
 *
 * Red Hat struct page is different from upstream (layout and members) :(
 * So I am not too sure about the "all other fields", and it is not as easy to
 * find a place where sizeof(struct bsr_page_chain) would fit on all archs and
 * distribution-changed layouts.
 *
 * But (upstream) struct page also says:
 *  | struct list_head lru;   * ...
 *  |       * Can be used as a generic list
 *  |       * by the page owner.
 *
 * On 32bit, use unsigned short for offset and size,
 * to still fit in sizeof(page->lru).
 */

/* grafted over struct page.lru */
struct bsr_page_chain {
	struct page *next;	/* next page in chain, if any */
#ifdef CONFIG_64BIT
	unsigned int offset;	/* start offset of data within this page */
	unsigned int size;	/* number of data bytes within this page */
#else
#if PAGE_SIZE > (1U<<16)
#error "won't work."
#endif
	unsigned short offset;	/* start offset of data within this page */
	unsigned short size;	/* number of data bytes within this page */
#endif
};

#ifdef _LIN
static inline void dummy_for_buildbug(void)
{
	struct page *dummy;
	BUILD_BUG_ON(sizeof(struct bsr_page_chain) > sizeof(dummy->lru));
}
#endif

#define page_chain_next(page) \
	(((struct bsr_page_chain*)&(page)->lru)->next)
#define page_chain_size(page) \
	(((struct bsr_page_chain*)&(page)->lru)->size)
#define page_chain_offset(page) \
	(((struct bsr_page_chain*)&(page)->lru)->offset)
#define set_page_chain_next(page, v) \
	(((struct bsr_page_chain*)&(page)->lru)->next = (v))
#define set_page_chain_size(page, v) \
	(((struct bsr_page_chain*)&(page)->lru)->size = (v))
#define set_page_chain_offset(page, v) \
	(((struct bsr_page_chain*)&(page)->lru)->offset = (v))
#define set_page_chain_next_offset_size(page, n, o, s)	\
	*((struct bsr_page_chain*)&(page)->lru) =	\
	((struct bsr_page_chain) {			\
		.next = (n),				\
		.offset = (o),				\
		.size = (s),				\
	 })
#ifdef _WIN
#define page_chain_for_each(page) \
	for (; page ; page = page_chain_next(page))
#define page_chain_for_each_safe(page, n) \
	for (; page && ( n = page_chain_next(page)); page = n) 
#else // _LIN
#define page_chain_for_each(page) \
	for (; page && ({ prefetch(page_chain_next(page)); 1; }); \
			page = page_chain_next(page))
#define page_chain_for_each_safe(page, n) \
	for (; page && ({ n = page_chain_next(page); 1; }); page = n)
#endif

#ifndef SK_CAN_REUSE
/* This constant was introduced by Pavel Emelyanov <xemul@parallels.com> on
   Thu Apr 19 03:39:36 2012 +0000. Before the release of linux-3.5
   commit 4a17fd52 sock: Introduce named constants for sk_reuse */
#define SK_CAN_REUSE   1
#endif

#endif
