#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#include "bsr_int.h"
#ifdef _WIN
#include <ntddk.h>
#include "./bsr-kernel-compat/windows/spinlock.h"
#else // _LIN
#include <linux/spinlock.h>
#include <linux/module.h>
#include <net/ipv6.h>
#endif
#include "../bsr-headers/bsr_transport.h"


static LIST_HEAD(transport_classes);
#ifdef _WIN
extern int __init dtt_initialize(void);
KSPIN_LOCK	transport_classes_lock;
#else // _LIN
extern int dtt_initialize(void);
static DECLARE_RWSEM(transport_classes_lock);
#endif

static struct bsr_transport_class *__find_transport_class(const char *transport_name)
{
	struct bsr_transport_class *transport_class;

	list_for_each_entry_ex(struct bsr_transport_class, transport_class, &transport_classes, list)
		if (!strcmp(transport_class->name, transport_name))
			return transport_class;

	return NULL;
}

int bsr_register_transport_class(struct bsr_transport_class *transport_class, int version,
				  int bsr_transport_size)
{
	int rv = 0;
	if (version != BSR_TRANSPORT_API_VERSION) {
		bsr_err(18, BSR_LC_SOCKET, NO_OBJECT, "Failed to initialization transport due to transport version not compatible. current(%x), compatible(%x) ", version, BSR_TRANSPORT_API_VERSION);
		return -EINVAL;
	}

	if (bsr_transport_size != sizeof(struct bsr_transport)) {
		bsr_err(19, BSR_LC_SOCKET, NO_OBJECT, "Failed to initialization transport due to sizeof(bsr_transport) not compatible. current(%x), compatible(%x)", bsr_transport_size, sizeof(struct bsr_transport));
		return -EINVAL;
	}

	down_write(&transport_classes_lock);
	if (__find_transport_class(transport_class->name)) {
		bsr_err(20, BSR_LC_SOCKET, NO_OBJECT, "Failed to initialization transport due to transport class '%s' already registered", transport_class->name);
		rv = -EEXIST;
	} else
		list_add_tail(&transport_class->list, &transport_classes);
	up_write(&transport_classes_lock);
	return rv;
}

void bsr_unregister_transport_class(struct bsr_transport_class *transport_class)
{
	down_write(&transport_classes_lock);
	if (!__find_transport_class(transport_class->name)) {
		bsr_crit(21, BSR_LC_SOCKET, NO_OBJECT, "unregistering unknown transport class '%s'",
			transport_class->name);
		BUG();
	}
	list_del_init(&transport_class->list);
	up_write(&transport_classes_lock);
}

static struct bsr_transport_class *get_transport_class(const char *name)
{
	struct bsr_transport_class *tc;

	down_read(&transport_classes_lock);
	tc = __find_transport_class(name);
#ifdef _LIN
	if (tc && !try_module_get(tc->module))
		tc = NULL;
#endif
	up_read(&transport_classes_lock);
	return tc;
}

struct bsr_transport_class *bsr_get_transport_class(const char *name)
{
	struct bsr_transport_class *tc = get_transport_class(name);

	if (!tc) {
		dtt_initialize();
		tc = get_transport_class(name);
	}

	return tc;
}

#ifdef _LIN // TODO: required to port on linux
void bsr_put_transport_class(struct bsr_transport_class *tc)
{
	/* convenient in the error cleanup path */
	if (!tc)
		return;
	down_read(&transport_classes_lock);
	module_put(tc->module);
	up_read(&transport_classes_lock);
}
#endif

void bsr_print_transports_loaded(struct seq_file *seq)
{
	struct bsr_transport_class *tc;

	down_read(&transport_classes_lock);

	seq_puts(seq, "Transports (api:" __stringify(BSR_TRANSPORT_API_VERSION) "):");
	list_for_each_entry_ex(struct bsr_transport_class, tc, &transport_classes, list) {
#ifdef _WIN
		seq_printf(seq, " %s ", tc->name);
#else // _LIN
		seq_printf(seq, " %s (%s)", tc->name,
				tc->module->version ? tc->module->version : "NONE");
#endif
	}
	seq_putc(seq, '\n');

	up_read(&transport_classes_lock);
}

static bool addr_equal(const SOCKADDR_STORAGE_EX *addr1, const SOCKADDR_STORAGE_EX *addr2, const SOCKADDR_STORAGE_EX *listen_addr)
{
	if (addr1->ss_family != addr2->ss_family)
		return false;

	if (addr1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *v6a1 = (const struct sockaddr_in6 *)addr1;
		const struct sockaddr_in6 *v6a2 = (const struct sockaddr_in6 *)addr2;
#ifdef _WIN
		if (!IN6_ADDR_EQUAL(&v6a1->sin6_addr, &v6a2->sin6_addr))
#else // _LIN
		if (!ipv6_addr_equal(&v6a1->sin6_addr, &v6a2->sin6_addr))
#endif
			return false;
#ifdef _WIN
		else if (IN6_IS_ADDR_LINKLOCAL(&v6a1->sin6_addr))
#else // _LIN
		else if (ipv6_addr_type(&v6a1->sin6_addr) & IPV6_ADDR_LINKLOCAL)
#endif
		{
			// BSR-1026
			if (listen_addr) {
				const struct sockaddr_in6 *laddr = (const struct sockaddr_in6 *)listen_addr;
				// scope_id set in peer_path(v6a1) is null
				// compare the scope_id of the listen and accept(v6a2) addresses
				return laddr->sin6_scope_id == v6a2->sin6_scope_id;
			} else {
				return v6a1->sin6_scope_id == v6a2->sin6_scope_id;
			}
		}
		return true;
	} else /* AF_INET, AF_SSOCKS, AF_SDP */ {
		const struct sockaddr_in *v4a1 = (const struct sockaddr_in *)addr1;
		const struct sockaddr_in *v4a2 = (const struct sockaddr_in *)addr2;

		return v4a1->sin_addr.s_addr == v4a2->sin_addr.s_addr;
	}
}

// BSR-1387
bool addr_any(const SOCKADDR_STORAGE_EX *addr)
{
	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)addr;
#ifdef _WIN
		if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr))
#else // _LIN
		if (ipv6_addr_any(&addr6->sin6_addr))
#endif
			return true;

		return false;
	}
	else {
		const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;

		if (addr4->sin_addr.s_addr == INADDR_ANY)
			return true;

		return false;
	}
}

bool port_equal(const SOCKADDR_STORAGE_EX *addr1, const SOCKADDR_STORAGE_EX *addr2)
{
	if (addr1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *v6a1 = (const struct sockaddr_in6 *)addr1;
		const struct sockaddr_in6 *v6a2 = (const struct sockaddr_in6 *)addr2;

		return v6a1->sin6_port == v6a2->sin6_port;
	}
	else /* AF_INET, AF_SSOCKS, AF_SDP */ {
		const struct sockaddr_in *v4a1 = (const struct sockaddr_in *)addr1;
		const struct sockaddr_in *v4a2 = (const struct sockaddr_in *)addr2;

		return v4a1->sin_port == v4a2->sin_port;
	}
}

bool addr_and_port_equal(const SOCKADDR_STORAGE_EX *addr1, const SOCKADDR_STORAGE_EX *addr2)
{
	if (!addr_equal(addr1, addr2, NULL))
		return false;

	if (!port_equal(addr1, addr2))
		return false;

	return true;
}

static struct bsr_listener *find_listener(struct bsr_connection *connection,
					   const SOCKADDR_STORAGE_EX *addr)
{
	struct bsr_resource *resource = connection->resource;
	struct bsr_listener *listener;
	list_for_each_entry_ex(struct bsr_listener, listener, &resource->listeners, list) {
		if (addr_and_port_equal(&listener->listen_addr, addr) ||
			// BSR-1387
			(addr_any(&listener->listen_addr) && port_equal(&listener->listen_addr, addr))) {
			kref_get(&listener->kref);
			return listener;
		}
	}
	return NULL;
}

int bsr_get_listener(struct bsr_transport *transport, struct bsr_path *path,
	int(*create_listener)(struct bsr_transport *, const struct sockaddr *addr, struct bsr_listener **))
{
	struct bsr_connection *connection =
		container_of(transport, struct bsr_connection, transport);
	struct sockaddr *addr = (struct sockaddr *)&path->my_addr;
	struct bsr_resource *resource = connection->resource;
	struct bsr_listener *listener, *new_listener = NULL;
	int err, tries = 0;

	while (1) {
		spin_lock_bh(&resource->listeners_lock);

		listener = find_listener(connection, (SOCKADDR_STORAGE_EX *)addr);
		if (!listener && new_listener) {
			list_add(&new_listener->list, &resource->listeners);
			listener = new_listener;
			new_listener = NULL;
		}
		if (listener) {
			// BSR-951
			spin_lock(&listener->waiters_lock);
			list_add(&path->listener_link, &listener->waiters);
			spin_unlock(&listener->waiters_lock);
			path->listener = listener;
		}
		spin_unlock_bh(&resource->listeners_lock);

		if (new_listener)
			new_listener->destroy(new_listener);

		if (listener)
			return 0;

		err = create_listener(transport, addr, &new_listener);
		if (err) {
			if (err == -EADDRINUSE && ++tries < 3) {
				schedule_timeout_uninterruptible(HZ / 20);
				continue;
			}
			return err;
		}

		kref_init(&new_listener->kref);
		INIT_LIST_HEAD(&new_listener->waiters);
		new_listener->resource = resource;
		new_listener->pending_accepts = 0;
		spin_lock_init(&new_listener->waiters_lock);
	}
}

static void bsr_listener_destroy(struct kref *kref)
{
	struct bsr_listener *listener = container_of(kref, struct bsr_listener, kref);
	struct bsr_resource *resource = listener->resource;

	// BSR-960 The reference to listener and synchronization to the release must obtain a lock from caller kref_put().
	list_del(&listener->list);
	// BSR-1029
	spin_unlock_bh(&resource->listeners_lock);

	listener->destroy(listener);
}

void bsr_put_listener(struct bsr_path *path)
{
	struct bsr_resource *resource;
	struct bsr_listener *listener;

	// DW-1538 Sometimes null values come in. 
	if (!path)
		return;
#ifdef _WIN
	listener = (struct bsr_listener*)xchg((LONG_PTR*)&path->listener, (LONG_PTR)NULL);
#else // _LIN
	listener = xchg(&path->listener, NULL);
#endif
	if (!listener)
		return;

	resource = listener->resource;
	// BSR-951 fix panic caused by list_del() while referencing path->listener_link
	// changed to use waiters_lock same as reference logic.
	spin_lock_bh(&listener->waiters_lock);
	list_del(&path->listener_link);
	spin_unlock_bh(&listener->waiters_lock);

	// BSR-960
	spin_lock_bh(&resource->listeners_lock);
	// BSR-1029 The bsr_listener_destroy() call adjusts the lockout range because it may cause a longer wait time.
	if(!kref_put(&listener->kref, bsr_listener_destroy))
		spin_unlock_bh(&resource->listeners_lock);
}

#ifdef _WIN
extern char * get_ip4(char *buf, size_t len, struct sockaddr_in *sockaddr);
extern char * get_ip6(char *buf, size_t len, struct sockaddr_in6 *sockaddr);
#endif

// TODO: Check again that bsr_find_waiter_by_addr is not needed.
//struct bsr_waiter *bsr_find_waiter_by_addr(struct bsr_listener *listener, SOCKADDR_STORAGE_EX *addr)
struct bsr_path *bsr_find_path_by_addr(struct bsr_listener *listener, SOCKADDR_STORAGE_EX *addr)
{
	struct bsr_path *path;

	// DW-1481 fix listener->list's NULL dereference, sanity check 
	if(!addr || !listener || (listener->list.next == NULL) ) {
		return NULL;
	}
	list_for_each_entry_ex(struct bsr_path, path, &listener->waiters, listener_link) {
#ifdef _WIN
		//bsr_debug_co("[%p] bsr_find_waiter_by_addr: pathr=%p", KeGetCurrentThread(), path);
		char sbuf[128], dbuf[128];
		if (path->peer_addr.ss_family == AF_INET6) {
			bsr_debug_co("[%p] path->peer:%s addr:%s ", KeGetCurrentThread(), get_ip6(sbuf, sizeof(sbuf), (struct sockaddr_in6*)&path->peer_addr), get_ip6(dbuf, sizeof(dbuf), (struct sockaddr_in6*)addr));
		} else {
			bsr_debug_co("[%p] path->peer:%s addr:%s ", KeGetCurrentThread(), get_ip4(sbuf, sizeof(sbuf), (struct sockaddr_in*)&path->peer_addr), get_ip4(dbuf, sizeof(dbuf), (struct sockaddr_in*)addr));
		}
		// BSR-787 skip if path is established
		if ((addr_equal(&path->peer_addr, addr, &listener->listen_addr) ||
			// BSR-1387
			addr_any(&listener->listen_addr)) && 
			!path->established)
			return path;
#else // _LIN
		if (addr_equal(&path->peer_addr, addr, &listener->listen_addr) ||
			// BSR-1387
			addr_any(&listener->listen_addr))
			return path;
#endif
		
	}

	return NULL;
}

/**
 * bsr_stream_send_timed_out() - Tells transport if the connection should stay alive
 * @connection:	BSR connection to operate on.
 * @stream:     DATA_STREAM or CONTROL_STREAM
 *
 * When it returns true, the transport should return -EAGAIN to its caller of the
 * send function. When it returns false the transport should keep on trying to
 * get the packet through.
 */
bool bsr_stream_send_timed_out(struct bsr_transport *transport, enum bsr_stream stream)
{
	struct bsr_connection *connection =
		container_of(transport, struct bsr_connection, transport);
	bool drop_it;

	drop_it = stream == CONTROL_STREAM
		|| !connection->ack_receiver.task
		|| get_t_state(&connection->ack_receiver) != RUNNING
		|| connection->cstate[NOW] < C_CONNECTED;

	if (drop_it)
		return true;

	// BSR-977
	if (!connection->transport.ko_count[stream])
		return true;
	drop_it = !--connection->transport.ko_count[stream];

	if (!drop_it) {
		bsr_err(22, BSR_LC_SOCKET, connection, "Failed to send %s stream due to [%s/%d] sending time expired, ko = %u",
			stream == DATA_STREAM ? "data" : "meta", current->comm, current->pid, connection->transport.ko_count[stream]);
		request_ping(connection);
	}

	return drop_it;

}

bool bsr_should_abort_listening(struct bsr_transport *transport)
{
	struct bsr_connection *connection =
		container_of(transport, struct bsr_connection, transport);
	bool abort = false;

	if (connection->cstate[NOW] <= C_DISCONNECTING)
		abort = true;
	if (signal_pending(current)) {
		flush_signals(current);
		smp_rmb();
		if (get_t_state(&connection->receiver) == EXITING)
			abort = true;
	}

	return abort;
}

/* Called by a transport if a path was established / disconnected */
void bsr_path_event(struct bsr_transport *transport, struct bsr_path *path)
{
	struct bsr_connection *connection =
		container_of(transport, struct bsr_connection, transport);

	notify_path(connection, path, NOTIFY_CHANGE);
}


//#ifdef _LIN
//EXPORT_SYMBOL_GPL(bsr_register_transport_class);
//EXPORT_SYMBOL_GPL(bsr_unregister_transport_class);
//EXPORT_SYMBOL_GPL(bsr_get_listener);
//EXPORT_SYMBOL_GPL(bsr_put_listener);
//EXPORT_SYMBOL_GPL(bsr_find_path_by_addr);
//EXPORT_SYMBOL_GPL(bsr_stream_send_timed_out);
//EXPORT_SYMBOL_GPL(bsr_should_abort_listening);
//EXPORT_SYMBOL_GPL(bsr_path_event);
//#endif
