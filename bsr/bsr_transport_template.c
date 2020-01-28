#ifdef _WIN32

#include "../bsr-headers/bsr_transport.h"
#include "bsr_int.h"

#else
#include <linux/module.h>
#endif

#ifndef _WIN32
MODULE_AUTHOR("xxx");
MODULE_DESCRIPTION("xxx transport layer for BSR");
MODULE_LICENSE("GPL");
#endif

struct bsr_xxx_transport {
	struct bsr_transport transport;
	/* xxx */
};

struct xxx_listener {
	struct bsr_listener listener;
	/* xxx */
};

struct xxx_waiter {
	struct bsr_waiter waiter;
	/* xxx */
};

static struct bsr_transport *xxx_create(struct bsr_connection* connection);
static void xxx_free(struct bsr_transport *transport, enum bsr_tr_free_op free_op);
static int xxx_connect(struct bsr_transport *transport);
static int xxx_recv(struct bsr_transport *transport, enum bsr_stream stream, void *buf, size_t size, int flags);
static void xxx_stats(struct bsr_transport* transport, struct bsr_transport_stats *stats);
static void xxx_set_rcvtimeo(struct bsr_transport *transport, enum bsr_stream stream, long timeout);
static long xxx_get_rcvtimeo(struct bsr_transport *transport, enum bsr_stream stream);
static int xxx_send_page(struct bsr_transport *transport, enum bsr_stream stream, struct page *page,
		    int offset, size_t size, unsigned msg_flags);
static bool xxx_stream_ok(struct bsr_transport *transport, enum bsr_stream stream);
static bool xxx_hint(struct bsr_transport *transport, enum bsr_stream stream, enum bsr_tr_hints hint);


static struct bsr_transport_class xxx_transport_class = {
	.name = "xxx",
#ifndef _WIN32
	.create = xxx_create,
#endif
	.list = LIST_HEAD_INIT(xxx_transport_class.list),
};

static struct bsr_transport_ops xxx_ops = {
	.free = xxx_free,
	.connect = xxx_connect,
	.recv = xxx_recv,
	.stats = xxx_stats,
	.set_rcvtimeo = xxx_set_rcvtimeo,
	.get_rcvtimeo = xxx_get_rcvtimeo,
	.send_page = xxx_send_page,
	.stream_ok = xxx_stream_ok,
	.hint = xxx_hint,
};


static struct bsr_transport *xxx_create(struct bsr_connection* connection)
{
	struct bsr_xxx_transport *xxx_transport;

#ifndef _WIN32 // try_module_get is linux kernel func., THIS_MODULE is linux define
	if (!try_module_get(THIS_MODULE))
		return NULL;
#endif

	xxx_transport = kzalloc(sizeof(struct bsr_xxx_transport), GFP_KERNEL);
	if (!xxx_transport) {
#ifndef _WIN32 // module_put is linux kernel func., THIS_MODULE is linux define
		module_put(THIS_MODULE);
#endif
		return NULL;
	}

	xxx_transport->transport.ops = &xxx_ops;
#ifndef _WIN32 
	xxx_transport->transport.connection = connection;
#endif
	return &xxx_transport->transport;
}

static void xxx_free(struct bsr_transport *transport, enum bsr_tr_free_op free_op)
{
	struct bsr_xxx_transport *xxx_transport =
		container_of(transport, struct bsr_xxx_transport, transport);

	/* disconnect here */

	if (free_op == DESTROY_TRANSPORT) {
		kfree(xxx_transport);
#ifndef _WIN32 // module_put is linux kernel func., THIS_MODULE is linux define
		module_put(THIS_MODULE);
#endif
	}
}

static int xxx_send(struct bsr_transport *transport, enum bsr_stream stream, void *buf, size_t size, unsigned msg_flags)
{
	struct bsr_xxx_transport *xxx_transport =
		container_of(transport, struct bsr_xxx_transport, transport);

	return 0;
}

static int xxx_recv(struct bsr_transport *transport, enum bsr_stream stream, void *buf, size_t size, int flags)
{
	struct bsr_xxx_transport *xxx_transport =
		container_of(transport, struct bsr_xxx_transport, transport);

	return 0;
}

static void xxx_stats(struct bsr_transport* transport, struct bsr_transport_stats *stats)
{
}

static int xxx_connect(struct bsr_transport *transport)
{
	struct bsr_xxx_transport *xxx_transport =
		container_of(transport, struct bsr_xxx_transport, transport);

	return true;
}

static void xxx_set_rcvtimeo(struct bsr_transport *transport, enum bsr_stream stream, long timeout)
{
}

static long xxx_get_rcvtimeo(struct bsr_transport *transport, enum bsr_stream stream)
{
	return 0;
}

static bool xxx_stream_ok(struct bsr_transport *transport, enum bsr_stream stream)
{
	return true;
}

static int xxx_send_page(struct bsr_transport *transport, enum bsr_stream stream, struct page *page,
		    int offset, size_t size, unsigned msg_flags)
{
	return 0;
}

static bool xxx_hint(struct bsr_transport *transport, enum bsr_stream stream,
		enum bsr_tr_hints hint)
{
	switch (hint) {
	default: /* not implemented, but should not trigger error handling */
		return true;
	}
	return true;
}

static int __init xxx_init(void)
{
#ifdef _WIN32
	return 0;
#else
	return bsr_register_transport_class(&xxx_transport_class);
#endif
}

static void __exit xxx_cleanup(void)
{
	bsr_unregister_transport_class(&xxx_transport_class);
}

#ifndef _WIN32
module_init(xxx_init)
module_exit(xxx_cleanup)
#endif