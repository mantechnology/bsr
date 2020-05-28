#include "bsr_int.h"
#include "bsr_kref_debug.h"

#ifdef _LIN
static void get_resource_name(const struct kref_debug_info *debug_info, char *name)
{
	struct bsr_resource *resource = container_of(debug_info, struct bsr_resource, kref_debug);
	if (resource->name)
		strncpy(name, resource->name, sizeof(name) - 1);
	else
		strncpy(name, "unnamed", sizeof(name) - 1);
}

static void get_connection_name(const struct kref_debug_info *debug_info, char *name)
{
	struct bsr_connection *connection = container_of(debug_info, struct bsr_connection, kref_debug);
	struct net_conf *nc;
	const char *resource_n =
		connection->resource && connection->resource->name ? connection->resource->name : "unknown";

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	sprintf(name, "%s:%s", resource_n , nc ? nc->name : "unnamed");
	rcu_read_unlock();
}

static void get_device_name(const struct kref_debug_info *debug_info, char *name)
{
	struct bsr_device *device = container_of(debug_info, struct bsr_device, kref_debug);
	const char *resource_n =
		device->resource && device->resource->name ? device->resource->name : "unknown";

	sprintf(name, "%s/%d minor-%d", resource_n, device->vnr, device->minor);
}

struct kref_debug_class kref_class_resource = {
	"resource", 
	get_resource_name,
	{
		[1] = "kthread",
		[2] = "bsr_adm_prepare()/bsr_adm_finish()",
		[3] = "struct bsr_connection",
		[4] = "struct bsr_device",
		[5] = "struct bsr_state_change",
		[6] = "bsr_adm_dump_connections()",
		[7] = "bsr_adm_dump_devices()",
		[8] = "free",
		[9] = "bsr_adm_dump_peer_devices()",
	}
};

struct kref_debug_class kref_class_connection = {
	"connection",
	get_connection_name,
	{
		[1] = "kthread",
		[2] = "bsr_adm_prepare()/bsr_adm_finish()",
		[3] = "struct bsr_peer_device",
		[4] = "conn_try_outdate_peer_async()",
		[5] = "remember_state_change()forget_state_change()",
		[6] = "change_cluster_wide_state()",
		[7] = "struct bsr_state_change",
		[8] = "target_connection/change_cluster_wide_state()",
		[9] = "resource->twopc_parent",
		[10] = "free",
		[11] = "connect_timer",
		[12] = "receive_peer_dagtag()",
		[13] = "for_each_conneciton_ref()",
		[14] = "w_update_peers",
		[15] = "for_each_peer_device_ref()",
		[16] = "queue_twopc",
	}
};

struct kref_debug_class kref_class_device = {
	"device", 
	get_device_name,
	{
		[1] = "struct bsr_peer_device / free",
		[2] = "struct bsr_state_change",
		[3] = "open / release",
		[4] = "bsr_adm_prepare()/bsr_adm_finish()",
		[5] = "w_update_peers",
		[6] = "bsr_request",
		[7] = "flush_after_epoch",
		[8] = "send_acks_wf",
		[9] = "open()",
	}
};


#endif
