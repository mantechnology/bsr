/*
   bsr_state.c

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>.

   Thanks to Carter Burden, Bart Grantham and Gennadiy Nerubayev
   from Logicworks, Inc. for making SDP replication support possible.

   bsr is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   bsr is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with bsr; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef _WIN
#include "./bsr-kernel-compat/windows/bsr_endian.h"
#else // _LIN
#include <linux/bsr_limits.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#endif

#include "bsr_int.h"
#include "../bsr-headers/bsr_protocol.h"
#include "bsr_req.h"
#include "bsr_state_change.h"

/* in bsr_main.c */
extern void tl_abort_disk_io(struct bsr_device *device);

struct after_state_change_work {
	struct bsr_work w;
	struct bsr_state_change *state_change;
	struct completion *done;
};

struct quorum_info {
	int votes;
	int voters;
	int quorum_at;
};

struct change_context {
	struct bsr_resource *resource;
	int vnr;
	union bsr_state mask;
	union bsr_state val;
	int target_node_id;
	enum chg_state_flags flags;
	bool change_local_state_last;
	const char **err_str;
};

enum change_phase {
	PH_LOCAL_COMMIT,
	PH_PREPARE,
	PH_84_COMMIT,
	PH_COMMIT,
};

static bool lost_contact_to_peer_data(enum bsr_disk_state *peer_disk_state);
static bool got_contact_to_peer_data(enum bsr_disk_state *peer_disk_state);
static bool peer_returns_diskless(struct bsr_peer_device *peer_device,
enum bsr_disk_state os, enum bsr_disk_state ns);

// BSR-421 add locked status
static void print_state_change(struct bsr_resource *resource, const char *prefix, bool locked, const char *caller);

static void finish_state_change(struct bsr_resource *, struct completion *, bool locked, const char *caller);
static int w_after_state_change(struct bsr_work *w, int unused);
static enum bsr_state_rv is_valid_soft_transition(struct bsr_resource *);
static enum bsr_state_rv is_valid_transition(struct bsr_resource *resource);
static void sanitize_state(struct bsr_resource *resource);
static enum bsr_state_rv change_peer_state(struct bsr_connection *, int, union bsr_state,
union bsr_state, unsigned long *);


/**
* may_be_up_to_date()  -  check if transition from D_CONSISTENT to D_UP_TO_DATE is allowed
*
* When fencing is enabled, it may only transition from D_CONSISTENT to D_UP_TO_DATE
* when ether all peers are connected, or outdated.
*/
static bool may_be_up_to_date(struct bsr_device *device) __must_hold(local)
{
	bool all_peers_outdated = true;
	int node_id;

	rcu_read_lock();
	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		struct bsr_peer_md *peer_md = &device->ldev->md.peers[node_id];
		struct bsr_peer_device *peer_device;
		enum bsr_disk_state peer_disk_state;
		bool want_bitmap = true;

		if (node_id == device->ldev->md.node_id)
			continue;

		if (peer_md->bitmap_index == -1 && !(peer_md->flags & MDF_NODE_EXISTS))
			continue; 

		if (!(peer_md->flags & MDF_PEER_FENCING))
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device) {
			peer_disk_state = peer_device->disk_state[NEW];
		}
		else {
			peer_disk_state = D_UNKNOWN;
		}

		switch (peer_disk_state) {
		case D_DISKLESS:
			if (!(peer_md->flags & MDF_PEER_DEVICE_SEEN))
				continue;
			/* Fall through */
		case D_ATTACHING:
		case D_DETACHING:
		case D_FAILED:
		case D_NEGOTIATING:
		case D_UNKNOWN:
			if (!want_bitmap)
				continue;
			if ((peer_md->flags & MDF_PEER_OUTDATED))
				continue;
			break;
		case D_INCONSISTENT:
		case D_OUTDATED:
			continue;
		case D_CONSISTENT:
		case D_UP_TO_DATE:
			/* These states imply that there is a connection. If there is
			a conneciton we do not need to insist that the peer was
			outdated. */
			continue;
		case D_MASK:;
		}

		all_peers_outdated = false;
	}
	rcu_read_unlock();
	return all_peers_outdated;
}

/**
* disk_state_from_md()  -  determine initial disk state
*
* When a disk is attached to a device, we set the disk state to D_NEGOTIATING.
* We then wait for all connected peers to send the peer disk state.  Once that
* has happened, we can determine the actual disk state based on the peer disk
* states and the state of the disk itself.
*
* The initial disk state becomes D_UP_TO_DATE without fencing or when we know
* that all peers have been outdated, and D_CONSISTENT otherwise.
*
* The caller either needs to have a get_ldev() reference, or need to call
* this function only if disk_state[NOW] >= D_NEGOTIATING and holding the
* req_lock
*/
enum bsr_disk_state disk_state_from_md(struct bsr_device *device) __must_hold(local)
{
	enum bsr_disk_state disk_state;

	if (!bsr_md_test_flag(device, MDF_CONSISTENT))
		disk_state = D_INCONSISTENT;
	else if (!bsr_md_test_flag(device, MDF_WAS_UP_TO_DATE))
		disk_state = D_OUTDATED;
	else
		disk_state = may_be_up_to_date(device) ? D_UP_TO_DATE : D_CONSISTENT;

	return disk_state;
}

bool is_suspended_fen(struct bsr_resource *resource, enum which_state which, bool locked)
{
	struct bsr_connection *connection;
	bool rv = false;

	// BSR-421 modify deadlock of rcu_read_lock
#ifdef _WIN
	// BSR-330
	unsigned char oldIrql_rLock = 0;
	if (!locked) 
		rcu_read_lock_w32_inner();
#else
	rcu_read_lock();
#endif
		for_each_connection_rcu(connection, resource) {
			if (connection->susp_fen[which]) {
				rv = true;
				break;
			}
		}
#ifdef _WIN
	if(!locked)
#endif
		rcu_read_unlock();

	return rv;
}

bool is_suspended_quorum(struct bsr_resource *resource, enum which_state which, bool locked)
{
	struct bsr_device *device;
	bool rv = false;
	int vnr;

	// BSR-421 modify deadlock of rcu_read_lock
#ifdef _WIN
	// BSR-330
	unsigned char oldIrql_rLock = 0;
	if (!locked)
		rcu_read_lock_w32_inner();
#else
	rcu_read_lock();
#endif

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		if (device->susp_quorum[which]) {
			rv = true;
			break;
		}
	}

#ifdef _WIN
	if (!locked)
#endif
		rcu_read_unlock();

	return rv;
}

bool resource_is_suspended(struct bsr_resource *resource, enum which_state which, bool locked)
{
	bool rv = resource->susp[which] || resource->susp_nod[which];

	if (rv)
		return rv;

	return is_suspended_fen(resource, which, locked) || is_suspended_quorum(resource, which, locked);
}

static void count_objects(struct bsr_resource *resource,
			  unsigned int *n_devices,
			  unsigned int *n_connections)
{
	/* Caller holds req_lock */
	struct bsr_device *device;
	struct bsr_connection *connection;
	int vnr;

	*n_devices = 0;
	*n_connections = 0;

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr)
		(*n_devices)++;
	for_each_connection(connection, resource)
		(*n_connections)++;
}

static struct bsr_state_change *alloc_state_change(unsigned int n_devices, unsigned int n_connections, gfp_t flags)
{
	struct bsr_state_change *state_change;
	unsigned int size, n;

	size = sizeof(struct bsr_state_change) +
	       n_devices * sizeof(struct bsr_device_state_change) +
	       n_connections * sizeof(struct bsr_connection_state_change) +
	       n_devices * n_connections * sizeof(struct bsr_peer_device_state_change);

	state_change = bsr_kmalloc(size, flags, '73SB');
	if (!state_change)
		return NULL;
	state_change->n_devices = n_devices;
	state_change->n_connections = n_connections;
	state_change->devices = (void *)(state_change + 1);
	state_change->connections = (void *)&state_change->devices[n_devices];
	state_change->peer_devices = (void *)&state_change->connections[n_connections];
	state_change->resource->resource = NULL;
	for (n = 0; n < n_devices; n++) {
		state_change->devices[n].device = NULL;
		state_change->devices[n].have_ldev = false;
	}
	for (n = 0; n < n_connections; n++)
		state_change->connections[n].connection = NULL;
	return state_change;
}

struct bsr_state_change *remember_state_change(struct bsr_resource *resource, gfp_t gfp)
{
	/* Caller holds req_lock */
	struct bsr_state_change *state_change;
	struct bsr_device *device;
	unsigned int n_devices;
	struct bsr_connection *connection;
	unsigned int n_connections;
	int vnr;

	struct bsr_device_state_change *device_state_change;
	struct bsr_peer_device_state_change *peer_device_state_change;
	struct bsr_connection_state_change *connection_state_change;

	count_objects(resource, &n_devices, &n_connections);
	state_change = alloc_state_change(n_devices, n_connections, gfp);
	if (!state_change)
		return NULL;

	kref_get(&resource->kref);
	kref_debug_get(&resource->kref_debug, 5);
	state_change->resource->resource = resource;
	memcpy(state_change->resource->role,
	       resource->role, sizeof(resource->role));
	memcpy(state_change->resource->susp,
	       resource->susp, sizeof(resource->susp));
	memcpy(state_change->resource->susp_nod,
	       resource->susp_nod, sizeof(resource->susp_nod));

	device_state_change = state_change->devices;
	peer_device_state_change = state_change->peer_devices;
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_device *peer_device;

		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 2);
		device_state_change->device = device;
		memcpy(device_state_change->disk_state,
		       device->disk_state, sizeof(device->disk_state));
		memcpy(device_state_change->susp_quorum,
			device->susp_quorum, sizeof(device->susp_quorum));
		if (test_and_clear_bit(HAVE_LDEV, &device->flags))
			device_state_change->have_ldev = true;

		// BSR-676
		device_state_change->notify_flags = atomic_xchg(&device->notify_flags, 0);

		/* The peer_devices for each device have to be enumerated in
		   the order of the connections. We may not use for_each_peer_device() here. */
		for_each_connection(connection, resource) {
			peer_device = conn_peer_device(connection, device->vnr);

			peer_device_state_change->peer_device = peer_device;
			memcpy(peer_device_state_change->disk_state,
			       peer_device->disk_state, sizeof(peer_device->disk_state));
			memcpy(peer_device_state_change->repl_state,
			       peer_device->repl_state, sizeof(peer_device->repl_state));
			memcpy(peer_device_state_change->resync_susp_user,
			       peer_device->resync_susp_user,
			       sizeof(peer_device->resync_susp_user));
			memcpy(peer_device_state_change->resync_susp_peer,
			       peer_device->resync_susp_peer,
			       sizeof(peer_device->resync_susp_peer));
			memcpy(peer_device_state_change->resync_susp_dependency,
			       peer_device->resync_susp_dependency,
			       sizeof(peer_device->resync_susp_dependency));
			memcpy(peer_device_state_change->resync_susp_other_c,
			       peer_device->resync_susp_other_c,
			       sizeof(peer_device->resync_susp_other_c));
			// BSR-676
			peer_device_state_change->notify_flags = atomic_xchg(&peer_device->notify_flags, 0);
			peer_device_state_change++;
		}
		device_state_change++;
	}

	connection_state_change = state_change->connections;
	for_each_connection(connection, resource) {
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 7);
		connection_state_change->connection = connection;
		memcpy(connection_state_change->cstate,
		       connection->cstate, sizeof(connection->cstate));
		memcpy(connection_state_change->peer_role,
		       connection->peer_role, sizeof(connection->peer_role));
		memcpy(connection_state_change->susp_fen,
			connection->susp_fen, sizeof(connection->susp_fen));

		connection_state_change++;
	}

	return state_change;
}

void copy_old_to_new_state_change(struct bsr_state_change *state_change)
{
	struct bsr_resource_state_change *resource_state_change = &state_change->resource[0];
	unsigned int n_device, n_connection, n_peer_device, n_peer_devices;

#define OLD_TO_NEW(x) \
	(x[NEW] = x[OLD])

	OLD_TO_NEW(resource_state_change->role);
	OLD_TO_NEW(resource_state_change->susp);
	OLD_TO_NEW(resource_state_change->susp_nod);

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_connection_state_change *connection_state_change =
				&state_change->connections[n_connection];

		OLD_TO_NEW(connection_state_change->peer_role);
		OLD_TO_NEW(connection_state_change->cstate);
		OLD_TO_NEW(connection_state_change->susp_fen);
	}

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct bsr_device_state_change *device_state_change =
			&state_change->devices[n_device];

		OLD_TO_NEW(device_state_change->disk_state);
		OLD_TO_NEW(device_state_change->susp_quorum);
	}

	n_peer_devices = state_change->n_devices * state_change->n_connections;
	for (n_peer_device = 0; n_peer_device < n_peer_devices; n_peer_device++) {
		struct bsr_peer_device_state_change *p =
			&state_change->peer_devices[n_peer_device];

		OLD_TO_NEW(p->disk_state);
		OLD_TO_NEW(p->repl_state);
		OLD_TO_NEW(p->resync_susp_user);
		OLD_TO_NEW(p->resync_susp_peer);
		OLD_TO_NEW(p->resync_susp_dependency);
		OLD_TO_NEW(p->resync_susp_other_c);
	}

#undef OLD_TO_NEW
}

void forget_state_change(struct bsr_state_change *state_change)
{
	unsigned int n;

	if (!state_change)
		return;

	if (state_change->resource->resource) {
		kref_debug_put(&state_change->resource->resource->kref_debug, 5);
		kref_put(&state_change->resource->resource->kref, bsr_destroy_resource);
	}
	for (n = 0; n < state_change->n_devices; n++) {
		struct bsr_device *device = state_change->devices[n].device;

		if (device) {
			kref_debug_put(&device->kref_debug, 2);
			kref_put(&device->kref, bsr_destroy_device);
		}
	}
	for (n = 0; n < state_change->n_connections; n++) {
		struct bsr_connection *connection =
			state_change->connections[n].connection;

		if (connection) {
			kref_debug_put(&connection->kref_debug, 7);
			kref_put(&connection->kref, bsr_destroy_connection);
		}
	}
	bsr_kfree(state_change);
}

static bool state_has_changed(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	struct bsr_device *device;
	int vnr;


// DW-1362 To avoid, twopc_commit processing with nostatechange should clear remote_state_change_flag
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_device *peer_device;
		for_each_peer_device(peer_device, device) {
			peer_device->uuid_flags &= ~UUID_FLAG_GOT_STABLE;
		}
	}
	
	if (test_and_clear_bit(NEGOTIATION_RESULT_TOUCHED, &resource->flags))
		return true;

	if (resource->role[OLD] != resource->role[NEW] ||
	    resource->susp[OLD] != resource->susp[NEW] ||
	    resource->susp_nod[OLD] != resource->susp_nod[NEW])
		return true;

	for_each_connection(connection, resource) {
		if (connection->cstate[OLD] != connection->cstate[NEW] ||
		    connection->peer_role[OLD] != connection->peer_role[NEW] ||
			connection->susp_fen[OLD] != connection->susp_fen[NEW])
			return true;
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_device *peer_device;

		if (device->disk_state[OLD] != device->disk_state[NEW] ||
			device->susp_quorum[OLD] != device->susp_quorum[NEW])
			return true;

		for_each_peer_device(peer_device, device) {
			if (peer_device->disk_state[OLD] != peer_device->disk_state[NEW] ||
			    peer_device->repl_state[OLD] != peer_device->repl_state[NEW] ||
			    peer_device->resync_susp_user[OLD] !=
				peer_device->resync_susp_user[NEW] ||
			    peer_device->resync_susp_peer[OLD] !=
				peer_device->resync_susp_peer[NEW] ||
			    peer_device->resync_susp_dependency[OLD] !=
				peer_device->resync_susp_dependency[NEW] ||
			    peer_device->resync_susp_other_c[OLD] !=
				// DW-1362 To avoid, twopc_commit processing with nostatechange should clear remote_state_change_flag
				peer_device->resync_susp_other_c[NEW])
				return true;
		}
	}
	return false;
}

static void ___begin_state_change(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	struct bsr_device *device;
	int vnr;

	resource->role[NEW] = resource->role[NOW];
	__change_io_susp_user(resource, resource->susp[NOW]);
	__change_io_susp_no_data(resource, resource->susp_nod[NOW]);

	for_each_connection(connection, resource) {
		__change_cstate_state(connection, connection->cstate[NOW], NULL);
		__change_peer_role(connection, connection->peer_role[NOW], NULL);
		__change_io_susp_fencing(connection, connection->susp_fen[NOW]);
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_device *peer_device;

		__change_disk_state(device, device->disk_state[NOW], NULL);
		__change_io_susp_quorum(device, device->susp_quorum[NOW]);

		for_each_peer_device(peer_device, device) {
			__change_peer_disk_state(peer_device, peer_device->disk_state[NOW], NULL);
			__change_repl_state(peer_device, peer_device->repl_state[NOW], NULL);
			__change_resync_susp_user(peer_device, peer_device->resync_susp_user[NOW], NULL);
			__change_resync_susp_peer(peer_device, peer_device->resync_susp_peer[NOW], NULL); 
			__change_resync_susp_dependency(peer_device, peer_device->resync_susp_dependency[NOW], NULL);
			__change_resync_susp_other_c(peer_device, peer_device->resync_susp_other_c[NOW], NULL);
		}
	}
}

static void __begin_state_change(struct bsr_resource *resource)
{
#ifdef _WIN
	// _WIN32_V9_RCU //(4) required to refactoring because lock, unlock position is diffrent, maybe global scope lock is needed 
    bsr_debug_rcu("rcu_read_lock()");
#else // _LIN
	rcu_read_lock();
#endif
	___begin_state_change(resource);
}

static enum bsr_state_rv try_state_change(struct bsr_resource *resource)
{
	enum bsr_state_rv rv;

	if (!state_has_changed(resource))
		return SS_NOTHING_TO_DO;
	sanitize_state(resource);
	rv = is_valid_transition(resource);
	if (rv >= SS_SUCCESS && !(resource->state_change_flags & CS_HARD))
		rv = is_valid_soft_transition(resource);
	return rv;
}

static void __clear_remote_state_change(struct bsr_resource *resource) {
	struct bsr_connection *connection, *tmp;

	resource->remote_state_change = false;
	resource->twopc_reply.initiator_node_id = -1;
	resource->twopc_reply.tid = 0;
	list_for_each_entry_safe_ex(struct bsr_connection, connection, tmp, &resource->twopc_parents, twopc_parent_list) {
		// DW-1480
		list_del(&connection->twopc_parent_list);
		kref_debug_put(&connection->kref_debug, 9);
		kref_put(&connection->kref, bsr_destroy_connection);
	}
	INIT_LIST_HEAD(&resource->twopc_parents);
	
	wake_up(&resource->twopc_wait);
	queue_queued_twopc(resource);
}
static enum bsr_state_rv ___end_state_change(struct bsr_resource *resource, struct completion *done,
					      enum bsr_state_rv rv, bool locked, const char* caller)
{
	enum chg_state_flags flags = resource->state_change_flags;
	struct bsr_connection *connection;
	struct bsr_device *device;
	int vnr;

	if (flags & CS_ABORT)
		goto out;
	if (rv >= SS_SUCCESS)
		rv = try_state_change(resource);
	if (rv < SS_SUCCESS) {
		if (flags & CS_VERBOSE) {
			bsr_err(14, BSR_LC_STATE, resource, "State change failed: %s", bsr_set_st_err_str(rv));
			print_state_change(resource, "Failed: caller ", locked, caller);
		}
		goto out;
	}
	if (flags & CS_PREPARE)
		goto out;

	finish_state_change(resource, done, locked, caller);

	/* changes to local_cnt and device flags should be visible before
	 * changes to state, which again should be visible before anything else
	 * depending on that change happens. */
	smp_wmb();
	resource->role[NOW] = resource->role[NEW];
	resource->susp[NOW] = resource->susp[NEW];
	resource->susp_nod[NOW] = resource->susp_nod[NEW];

	for_each_connection(connection, resource) {
		connection->cstate[NOW] = connection->cstate[NEW];
		connection->peer_role[NOW] = connection->peer_role[NEW];
		connection->susp_fen[NOW] = connection->susp_fen[NEW];

		wake_up(&connection->ping_wait);
		wake_up(&connection->ee_wait);
		// BSR-928 avoid potential hung task panic in bsr_uuid_peer()
		wake_up(&connection->uuid_wait);
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_device *peer_device;

		device->disk_state[NOW] = device->disk_state[NEW];
		device->susp_quorum[NOW] = device->susp_quorum[NEW];

		for_each_peer_device(peer_device, device) {
			peer_device->disk_state[NOW] = peer_device->disk_state[NEW];

			// DW-1131 move to queue_after_state_change_work.
			// BSR-439 keep the updates repl_state
			peer_device->repl_state[NOW] = 
				peer_device->repl_state[NEW];
			peer_device->resync_susp_user[NOW] =
				peer_device->resync_susp_user[NEW];
			peer_device->resync_susp_peer[NOW] =
				peer_device->resync_susp_peer[NEW];
			peer_device->resync_susp_dependency[NOW] =
				peer_device->resync_susp_dependency[NEW];
			peer_device->resync_susp_other_c[NOW] =
				peer_device->resync_susp_other_c[NEW];
		}
	}
	smp_wmb(); /* Make the NEW_CUR_UUID bit visible after the state change! */

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		if (test_bit(__NEW_CUR_UUID, &device->flags)) {
			clear_bit(__NEW_CUR_UUID, &device->flags);
			set_bit(NEW_CUR_UUID, &device->flags);
			bsr_info(28, BSR_LC_UUID, device, "clear the UUID creation schedule and set the UUID creation flag");
		}

		wake_up(&device->al_wait);
		wake_up(&device->misc_wait);
	}

	wake_up(&resource->state_wait);
out:
#ifdef _WIN
	// __begin_state_change aquire lock at the beginning
	// unlock is processed other function scope. required to refactoring (maybe required global scope lock)
	// _WIN32_V9_RCU //(5) temporary dummy.
    bsr_debug_rcu("rcu_read_unlock()");
#else // _LIN
	rcu_read_unlock();
#endif

	if ((flags & CS_TWOPC) && !(flags & CS_PREPARE))
		__clear_remote_state_change(resource);

	resource->state_change_err_str = NULL;
	return rv;
}

void state_change_lock(struct bsr_resource *resource, unsigned long *irq_flags, enum chg_state_flags flags)
{
	if ((flags & CS_SERIALIZE) && !(flags & (CS_ALREADY_SERIALIZED | CS_PREPARED))) {
#ifdef _WIN
		bsr_info(40, BSR_LC_STATE, NO_OBJECT, "Worker should not initiate state changes with CS_SERIALIZE current:%p resource->worker.task:%p", current, resource->worker.task);
#else // _LIN
		WARN_ONCE(current == resource->worker.task,
			"worker should not initiate state changes with CS_SERIALIZE");
#endif
		down(&resource->state_sem);
	}
	spin_lock_irqsave(&resource->req_lock, *irq_flags);
	resource->state_change_flags = flags;
}

static void __state_change_unlock(struct bsr_resource *resource, unsigned long *irq_flags, struct completion *done)
{
	enum chg_state_flags flags = resource->state_change_flags;

	resource->state_change_flags = 0;
	spin_unlock_irqrestore(&resource->req_lock, *irq_flags);
	if (get_t_state(&resource->worker) == RUNNING) {
		if (done && expect(resource, current != resource->worker.task)) {
#ifdef _WIN
	        while (wait_for_completion(done) == -BSR_SIGKILL) {
				bsr_info(15, BSR_LC_STATE, NO_OBJECT, "BSR_SIGKILL occurred instead of a wait event. Ignore and wait for real event");
	        }
#else // _LIN
			wait_for_completion(done);
#endif
		}
	} 
	
	if ((flags & CS_SERIALIZE) && !(flags & (CS_ALREADY_SERIALIZED | CS_PREPARE)))
		up(&resource->state_sem);
}

void state_change_unlock(struct bsr_resource *resource, unsigned long *irq_flags)
{
	__state_change_unlock(resource, irq_flags, NULL);
}

/**
 * abort_prepared_state_change
 *
 * Use when a remote state change request was prepared but neither committed
 * nor aborted; the remote state change still "holds the state mutex".
 */
void abort_prepared_state_change(struct bsr_resource *resource)
{
	up(&resource->state_sem);
}

void begin_state_change_locked(struct bsr_resource *resource, enum chg_state_flags flags)
{
	BUG_ON(flags & (CS_SERIALIZE | CS_WAIT_COMPLETE | CS_PREPARE | CS_ABORT));
	resource->state_change_flags = flags;
	__begin_state_change(resource);
}


enum bsr_state_rv end_state_change_locked(struct bsr_resource *resource, bool locked, const char* caller)
{
	return ___end_state_change(resource, NULL, SS_SUCCESS, locked, caller);
}

void begin_state_change(struct bsr_resource *resource, unsigned long *irq_flags, enum chg_state_flags flags)
{
	state_change_lock(resource, irq_flags, flags);
	__begin_state_change(resource);
}

static bool all_peer_devices_connected(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int vnr;
	bool rv = true;

	// BSR-426 
#ifdef _WIN
	bool need_spinlock = false;

	if (is_spin_lock_in_current_thread(&connection->resource->req_lock)) {
		spin_unlock(&connection->resource->req_lock);
		need_spinlock = true;
	}
#endif
	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] < L_ESTABLISHED) {
			rv = false;
			break;
		}
	}
	rcu_read_unlock();

#ifdef _WIN
	if (need_spinlock)
		spin_lock(&connection->resource->req_lock);
#endif

	return rv;
}

static enum bsr_state_rv __end_state_change(struct bsr_resource *resource,
					     unsigned long *irq_flags,
						enum bsr_state_rv rv, const char* caller)
{
	enum chg_state_flags flags = resource->state_change_flags;
	struct completion __done, *done = NULL;

	if ((flags & CS_WAIT_COMPLETE) && !(flags & (CS_PREPARE | CS_ABORT))) {
		done = &__done;
		init_completion(done);
	} 
	rv = ___end_state_change(resource, done, rv, false, caller);
	__state_change_unlock(resource, irq_flags, rv >= SS_SUCCESS ? done : NULL);
	return rv;
}

enum bsr_state_rv end_state_change(struct bsr_resource *resource, unsigned long *irq_flags, const char* caller)
{
	return __end_state_change(resource, irq_flags, SS_SUCCESS, caller);
}

void abort_state_change(struct bsr_resource *resource, unsigned long *irq_flags, const char* caller)
{
	resource->state_change_flags &= ~CS_VERBOSE;
	__end_state_change(resource, irq_flags, SS_UNKNOWN_ERROR, caller);
}

void abort_state_change_locked(struct bsr_resource *resource, bool locked, const char* caller)
{
	resource->state_change_flags &= ~CS_VERBOSE;
	___end_state_change(resource, NULL, SS_UNKNOWN_ERROR, locked, caller);
}

static void begin_remote_state_change(struct bsr_resource *resource, unsigned long *irq_flags)
{
#ifdef _WIN
	// __begin_state_change aquire lock at the beginning
	// unlock is processed other function scope. required to refactoring (maybe required global scope lock)
	// _WIN32_V9_RCU //(6) temporary dummy.
    bsr_debug_rcu("rcu_read_unlock()");
#else // _LIN
	rcu_read_unlock();
#endif
	spin_unlock_irqrestore(&resource->req_lock, *irq_flags);
}

static void __end_remote_state_change(struct bsr_resource *resource, enum chg_state_flags flags)
{
#ifdef _WIN
	// __begin_state_change aquire lock at the beginning
	// unlock is processed other function scope. required to refactoring (maybe required global scope lock)
	// _WIN32_V9_RCU //(7) temporary dummy.
    bsr_debug_rcu("rcu_read_lock()");
#else // _LIN
	rcu_read_lock();
#endif
	resource->state_change_flags = flags;
	___begin_state_change(resource);
}

static void end_remote_state_change(struct bsr_resource *resource, unsigned long *irq_flags, enum chg_state_flags flags)
{
	spin_lock_irqsave(&resource->req_lock, *irq_flags);
	__end_remote_state_change(resource, flags);
}

void clear_remote_state_change(struct bsr_resource *resource) {
	unsigned long irq_flags;

	spin_lock_irqsave(&resource->req_lock, irq_flags);
	__clear_remote_state_change(resource);
	spin_unlock_irqrestore(&resource->req_lock, irq_flags);
}

// DW-1894
void clear_remote_state_change_without_lock(struct bsr_resource *resource) {
	__clear_remote_state_change(resource);
}

static union bsr_state bsr_get_resource_state(struct bsr_resource *resource, enum which_state which)
{
	union bsr_state rv = { {
		.conn = C_STANDALONE,  /* really: undefined */
		/* (user_isp, peer_isp, and aftr_isp are undefined as well.) */
		.disk = D_UNKNOWN,  /* really: undefined */
		.role = resource->role[which],
		.peer = R_UNKNOWN,  /* really: undefined */
		.susp = resource->susp[which] || is_suspended_quorum(resource, which, false),
		.susp_nod = resource->susp_nod[which],
		.susp_fen = is_suspended_fen(resource, which, false),
		.pdsk = D_UNKNOWN,  /* really: undefined */
	} };

	return rv;
}

union bsr_state bsr_get_device_state(struct bsr_device *device, enum which_state which)
{
	union bsr_state rv = bsr_get_resource_state(device->resource, which);

	rv.disk = device->disk_state[which];

	return rv;
}

union bsr_state bsr_get_peer_device_state(struct bsr_peer_device *peer_device, enum which_state which)
{
	struct bsr_connection *connection = peer_device->connection;
	union bsr_state rv;

	rv = bsr_get_device_state(peer_device->device, which);
	rv.user_isp = peer_device->resync_susp_user[which];
	rv.peer_isp = peer_device->resync_susp_peer[which];
	rv.aftr_isp = peer_device->resync_susp_dependency[which] || peer_device->resync_susp_other_c[which];
	rv.conn = combined_conn_state(peer_device, which);
	rv.peer = connection->peer_role[which];
	rv.pdsk = peer_device->disk_state[which];

	return rv;
}

union bsr_state bsr_get_connection_state(struct bsr_connection *connection, enum which_state which)
{
	union bsr_state rv = bsr_get_resource_state(connection->resource, which);

	rv.conn = connection->cstate[which];
	rv.peer = connection->peer_role[which];

	return rv;
}

static inline bool is_susp(union bsr_state s)
{
        return s.susp || s.susp_nod || s.susp_fen;
}

enum bsr_disk_state conn_highest_disk(struct bsr_connection *connection)
{
	enum bsr_disk_state disk_state = D_DISKLESS;
	struct bsr_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		struct bsr_device *device = peer_device->device;
		disk_state = max_t(enum bsr_disk_state, disk_state, device->disk_state[NOW]);
	}
	rcu_read_unlock();

	return disk_state;
}

enum bsr_disk_state conn_lowest_disk(struct bsr_connection *connection)
{
	enum bsr_disk_state disk_state = D_MASK;
	struct bsr_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		struct bsr_device *device = peer_device->device;
		disk_state = min_t(enum bsr_disk_state, disk_state, device->disk_state[NOW]);
	}
	rcu_read_unlock();

	return disk_state;
}

enum bsr_disk_state conn_highest_pdsk(struct bsr_connection *connection)
{
	enum bsr_disk_state disk_state = D_DISKLESS;
	struct bsr_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr)
		disk_state = max_t(enum bsr_disk_state, disk_state, peer_device->disk_state[NOW]);
	rcu_read_unlock();

	return disk_state;
}

static enum bsr_repl_state conn_lowest_repl_state(struct bsr_connection *connection)
{
	unsigned int repl_state = UINT32_MAX;
	struct bsr_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if ((unsigned int)peer_device->repl_state[NOW] < repl_state)
			repl_state = peer_device->repl_state[NOW];
	}
	rcu_read_unlock();

	if (repl_state == UINT32_MAX)
		return L_OFF;

	return repl_state;
}

static bool resync_suspended(struct bsr_peer_device *peer_device, enum which_state which)
{
	return peer_device->resync_susp_user[which] ||
		peer_device->resync_susp_peer[which] ||
		peer_device->resync_susp_dependency[which] ||
		peer_device->resync_susp_other_c[which];
}

static void set_resync_susp_other_c(struct bsr_peer_device *peer_device, bool val, bool start, const char* caller)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_device *p;
	enum bsr_repl_state r;

	/* When the resync_susp_other_connection flag gets cleared, make sure it gets
	   cleared first on all connections where we are L_PAUSED_SYNC_T. Clear it on
	   one L_PAUSED_SYNC_T at a time. Only if we have no connection that is
	   L_PAUSED_SYNC_T clear it on all L_PAUSED_SYNC_S connections at once. */

	if (val) {
		for_each_peer_device(p, device) {
			if (p == peer_device)
				continue;

			r = p->repl_state[NEW];
			__change_resync_susp_other_c(p, true, NULL);

			if (p->resync_susp_other_c[NOW] != p->resync_susp_other_c[NEW])
				bsr_info(16, BSR_LC_STATE, peer_device, "%s => node_id(%d), resync_susp_other_c : true", caller, p->node_id);

			if (start && p->disk_state[NEW] >= D_INCONSISTENT && r == L_ESTABLISHED)
				__change_repl_state(p, L_PAUSED_SYNC_T, __FUNCTION__);
		}
	} else {
		for_each_peer_device(p, device) {
			if (p == peer_device)
				continue;

			r = p->repl_state[NEW];
			if (r == L_PAUSED_SYNC_S)
				continue;

			__change_resync_susp_other_c(p, false, NULL);

			if (p->resync_susp_other_c[NOW] != p->resync_susp_other_c[NEW])
				bsr_info(17, BSR_LC_STATE, peer_device, "%s => node_id(%d), resync_susp_other_c : false", caller, p->node_id);

			if (r == L_PAUSED_SYNC_T && !resync_suspended(p, NEW)) {
				__change_repl_state(p, L_SYNC_TARGET, __FUNCTION__);
	
				if (device->disk_state[NEW] != D_INCONSISTENT) {
					// DW-1075 
					// Min/Max disk state of the SyncTarget is D_INCONSISTENT.
					// So, change disk_state to D_INCONSISTENT.
					__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
				}

				if (peer_device->repl_state[NEW] == L_BEHIND) {
					// DW-1085 fix resync stop in the state of 'PausedSyncS/SyncTarget'.
					// Set resync_susp_other_c when repl_state is L_BEHIND. L_BEHIND will transition to L_PAUSED_SYNC_T.
					__change_resync_susp_other_c(peer_device, true, NULL);
				}

				return;
			}
		}

		for_each_peer_device(p, device) {
			if (p == peer_device)
				continue;

			__change_resync_susp_other_c(p, false, NULL);

			if (p->repl_state[NEW] == L_PAUSED_SYNC_S && !resync_suspended(p, NEW))
				__change_repl_state(p, L_SYNC_SOURCE, __FUNCTION__);
		}
	}
}

static int scnprintf_resync_suspend_flags(char *buffer, size_t size,
					  struct bsr_peer_device *peer_device,
					  enum which_state which)
{
	char *b = buffer, *end = buffer + size;

	if (!resync_suspended(peer_device, which))
		return scnprintf(buffer, size, "no");

	if (peer_device->resync_susp_user[which])
		b += scnprintf(b, end - b, "user,");
	if (peer_device->resync_susp_peer[which])
		b += scnprintf(b, end - b, "peer,");
	if (peer_device->resync_susp_dependency[which])
		b += scnprintf(b, end - b, "after dependency,");
	if (peer_device->resync_susp_other_c[which])
		b += scnprintf(b, end - b, "connection dependency,");
	*(--b) = 0;

	return (int)(b - buffer);
}

static int scnprintf_io_suspend_flags(char *buffer, size_t size,
				      struct bsr_resource *resource,
				      enum which_state which,
						  bool locked)
{
	char *b = buffer, *end = buffer + size;

	if (!resource_is_suspended(resource, which, false))
		return scnprintf(buffer, size, "no");

	if (resource->susp[which])
		b += scnprintf(b, end - b, "user,");
	if (resource->susp_nod[which])
		b += scnprintf(b, end - b, "no-disk,");
	if (is_suspended_fen(resource, which, locked))
		b += scnprintf(b, end - b, "fencing,");
	if (is_suspended_quorum(resource, which, locked))
		b += scnprintf(b, end - b, "quorum,");
	*(--b) = 0;

	return (int)(b - buffer);
}

static void print_state_change(struct bsr_resource *resource, const char *prefix, bool locked, const char *caller)
{
	char buffer[150], *b, *end = buffer + sizeof(buffer);
	struct bsr_connection *connection;
	struct bsr_device *device;
	enum bsr_role *role = resource->role;
	int vnr;

	b = buffer;
	if (role[OLD] != role[NEW])
		b += scnprintf(b, end - b, "role( %s -> %s ) ",
			       bsr_role_str(role[OLD]),
			       bsr_role_str(role[NEW]));
	if (resource_is_suspended(resource, OLD, locked) != resource_is_suspended(resource, NEW, locked)) {
		b += scnprintf(b, end - b, "susp-io( ");
		b += scnprintf_io_suspend_flags(b, end - b, resource, OLD, locked);
		b += scnprintf(b, end - b, " -> ");
		b += scnprintf_io_suspend_flags(b, end - b, resource, NEW, locked);
		b += scnprintf(b, end - b, ") ");
	}
	if (b != buffer) {
		*(b-1) = 0;
		bsr_info(18, BSR_LC_STATE, resource, "%s, %s%s", caller, prefix, buffer);
	}

	for_each_connection(connection, resource) {
		enum bsr_conn_state *cstate = connection->cstate;
		enum bsr_role *peer_role = connection->peer_role;

		b = buffer;
		if (cstate[OLD] != cstate[NEW])
			b += scnprintf(b, end - b, "conn( %s -> %s ) ",
				       bsr_conn_str(cstate[OLD]),
				       bsr_conn_str(cstate[NEW]));
		if (peer_role[OLD] != peer_role[NEW])
			b += scnprintf(b, end - b, "peer( %s -> %s ) ",
				       bsr_role_str(peer_role[OLD]),
				       bsr_role_str(peer_role[NEW]));

		if (b != buffer) {
			*(b-1) = 0;
			bsr_info(19, BSR_LC_STATE, connection, "%s, %s%s", caller, prefix, buffer);
		}
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_device *peer_device;
		enum bsr_disk_state *disk_state = device->disk_state;

		if (disk_state[OLD] != disk_state[NEW])
		{
			// BSR-649 The log is output at the error level when the status is changed to D_FAILED or D_DISKLESS.
			if (disk_state[NEW] == D_FAILED ||
					(disk_state[OLD] != D_DETACHING && disk_state[NEW] == D_DISKLESS))
			{
				bsr_err(61, BSR_LC_STATE, device, "%s, %sdisk( %s -> %s )",
					caller,
					prefix,
					bsr_disk_str(disk_state[OLD]),
					bsr_disk_str(disk_state[NEW]));
			}
			else
			{
				bsr_info(20, BSR_LC_STATE, device, "%s, %sdisk( %s -> %s )",
					caller,
					prefix,
					bsr_disk_str(disk_state[OLD]),
					bsr_disk_str(disk_state[NEW]));
			}
		}

		for_each_peer_device(peer_device, device) {
			enum bsr_disk_state *peer_disk_state = peer_device->disk_state;
			enum bsr_repl_state *repl_state = peer_device->repl_state;

			b = buffer;
			if (peer_disk_state[OLD] != peer_disk_state[NEW])
				b += scnprintf(b, end - b, "pdsk( %s -> %s ) ",
					       bsr_disk_str(peer_disk_state[OLD]),
					       bsr_disk_str(peer_disk_state[NEW]));
			if (repl_state[OLD] != repl_state[NEW])
				b += scnprintf(b, end - b, "repl( %s -> %s ) ",
					       bsr_repl_str(repl_state[OLD]),
					       bsr_repl_str(repl_state[NEW]));

			if (resync_suspended(peer_device, OLD) !=
			    resync_suspended(peer_device, NEW)) {
				b += scnprintf(b, end - b, "resync-susp( ");
				b += scnprintf_resync_suspend_flags(b, end - b, peer_device, OLD);
				b += scnprintf(b, end - b, " -> ");
				b += scnprintf_resync_suspend_flags(b, end - b, peer_device, NEW);
				b += scnprintf(b, end - b, " ) ");
			}

			if (b != buffer) {
				*(b-1) = 0;
				bsr_info(21, BSR_LC_STATE, peer_device, "%s, %s%s", caller, prefix, buffer);
			}
		}
	}
}

static bool local_disk_may_be_outdated(struct bsr_device *device, enum which_state which)
{
	struct bsr_peer_device *peer_device;

	if (device->resource->role[which] == R_PRIMARY)
		return false;

	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->peer_role[which] == R_PRIMARY &&
		    peer_device->repl_state[which] > L_OFF)
			goto have_primary_neighbor;
	}

	return true;	/* No neighbor primary, I might be outdated*/

have_primary_neighbor:
	for_each_peer_device(peer_device, device) {
		enum bsr_repl_state repl_state = peer_device->repl_state[which];
		switch(repl_state) {
		case L_WF_BITMAP_S:
		case L_STARTING_SYNC_S:
		case L_SYNC_SOURCE:
		case L_PAUSED_SYNC_S:
		case L_AHEAD:
		case L_ESTABLISHED:
		case L_VERIFY_S:
		case L_VERIFY_T:
		case L_OFF:
			continue;
		case L_WF_SYNC_UUID:
		case L_WF_BITMAP_T:
		case L_STARTING_SYNC_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
		case L_BEHIND:
			return true;
		}
	}

	return false;
}

static bool calc_quorum(struct bsr_device *device, enum which_state which, struct quorum_info *qi)
{
	struct bsr_resource *resource = device->resource;
	const int my_node_id = resource->res_opts.node_id;
	int node_id, voters, votes = 0, outdated = 0, unknown = 0, quorum_at;
	enum bsr_disk_state disk_state;
	bool have_quorum;

	rcu_read_lock();
	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		struct bsr_peer_md *peer_md = &device->ldev->md.peers[node_id];
		struct bsr_peer_device *peer_device;

		if (node_id == my_node_id) {
			votes++;
			continue;
		}

		if (peer_md->bitmap_index == -1 && !(peer_md->flags & MDF_NODE_EXISTS))
			continue;

		peer_device = peer_device_by_node_id(device, node_id);
		disk_state = peer_device ? peer_device->disk_state[which] : D_UNKNOWN;
		if (disk_state == D_OUTDATED)
			outdated++;
		else if (disk_state == D_UNKNOWN || disk_state <= D_FAILED)
			unknown++;
		else /* D_NEGOTIATING, D_INCONSISTENT, D_CONSISTENT, D_UP_TO_DATE */
			votes++;
	}
	rcu_read_unlock();

	/* When all the absent nodes are D_OUTDATED (no one D_UNKNOWN), we can be
	sure that the other partition is not able to promote. ->
	We remove them from the voters. -> We have quorum */
	if (unknown)
		voters = outdated + unknown + votes;
	else
		voters = votes;

	switch (resource->res_opts.quorum) {
	case QOU_MAJORITY:
		quorum_at = voters / 2 + 1;
		break;
	case QOU_ALL:
		quorum_at = voters;
		break;
	default:
		quorum_at = resource->res_opts.quorum;
	}

	if (qi) {
		qi->voters = voters;
		qi->votes = votes;
		qi->quorum_at = quorum_at;
	}

	have_quorum = votes >= quorum_at;
	return have_quorum;
}

#ifdef _WIN
static void _bsr_state_err(struct change_context *context, const char *fmt, ...)
#else // _LIN
static __printf(2, 3) void _bsr_state_err(struct change_context *context, const char *fmt, ...)
#endif
{
	struct bsr_resource *resource = context->resource;
#ifdef _WIN
	char *err_str;
#else // _LIN
	const char *err_str;
#endif 
	va_list args;

	va_start(args, fmt);
	err_str = kvasprintf(GFP_ATOMIC, fmt, args);
	va_end(args);
	if (!err_str)
		return;
	if (context->flags & CS_VERBOSE)
		bsr_err(22, BSR_LC_STATE, resource, "%s", err_str);
	if (context->err_str)
		*context->err_str = err_str;
	else
		kfree2(err_str);
}

#ifdef _WIN
static void bsr_state_err(struct bsr_resource *resource, const char *fmt, ...)
#else // _LIN
static __printf(2, 3) void bsr_state_err(struct bsr_resource *resource, const char *fmt, ...)
#endif
{
#ifdef _WIN
	char *err_str;
#else // _LIN
	const char *err_str;
#endif 
	va_list args;

	va_start(args, fmt);
	err_str = kvasprintf(GFP_ATOMIC, fmt, args);
	va_end(args);
	if (!err_str)
		return;
	if (resource->state_change_flags & CS_VERBOSE)
		bsr_err(23, BSR_LC_STATE, resource, "%s", err_str);
	if (resource->state_change_err_str)
		*resource->state_change_err_str = err_str;
	else
		kfree2(err_str);
}

static enum bsr_state_rv __is_valid_soft_transition(struct bsr_resource *resource)
{
	enum bsr_role *role = resource->role;
	struct bsr_connection *connection;
	struct bsr_device *device;
	int vnr;

	/* See bsr_state_sw_errors in bsr_strings.c */

	if (role[OLD] != R_PRIMARY && role[NEW] == R_PRIMARY) {
		for_each_connection(connection, resource) {
			struct net_conf *nc;

			nc = rcu_dereference(connection->transport.net_conf);
			if (!nc || nc->two_primaries)
				continue;
			if (connection->peer_role[NEW] == R_PRIMARY)
				return SS_TWO_PRIMARIES;
		}
	}

	for_each_connection(connection, resource) {
		enum bsr_conn_state *cstate = connection->cstate;
		enum bsr_role *peer_role = connection->peer_role;
		struct net_conf *nc;
		bool two_primaries;

		if (cstate[NEW] == C_DISCONNECTING && cstate[OLD] == C_STANDALONE)
			return SS_ALREADY_STANDALONE;

		if (cstate[NEW] == C_CONNECTING && cstate[OLD] < C_UNCONNECTED)
			return SS_NO_NET_CONFIG;

		if (cstate[NEW] == C_DISCONNECTING && cstate[OLD] == C_UNCONNECTED)
			return SS_IN_TRANSIENT_STATE;

		/* While establishing a connection only allow cstate to change.
		   Delay/refuse role changes, detach attach etc... */
		if (!(cstate[OLD] == C_CONNECTED ||
		     (cstate[NEW] == C_CONNECTED && cstate[OLD] == C_CONNECTING))) {
			struct bsr_peer_device *peer_device;

			idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
				if (test_bit(INITIAL_STATE_SENT, &peer_device->flags) &&
				    !test_bit(INITIAL_STATE_RECEIVED, &peer_device->flags))
					return SS_IN_TRANSIENT_STATE;
			}
		}

		nc = rcu_dereference(connection->transport.net_conf);
		two_primaries = nc ? nc->two_primaries : false;
		if (peer_role[NEW] == R_PRIMARY && peer_role[OLD] != R_PRIMARY && !two_primaries) {
			if (role[NOW] == R_PRIMARY)
				return SS_TWO_PRIMARIES;
			idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
				if (device->open_ro_cnt)
					return SS_PRIMARY_READER;
			}
		}
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		enum bsr_disk_state *disk_state = device->disk_state;
		struct bsr_peer_device *peer_device;
		bool any_disk_up_to_date[2];
		enum which_state which;
		int nr_negotiating = 0;

		if (role[OLD] != R_SECONDARY && role[NEW] == R_SECONDARY && device->open_rw_cnt)
			return SS_DEVICE_IN_USE;

		if (disk_state[NEW] > D_ATTACHING && disk_state[OLD] == D_DISKLESS)
			return SS_IS_DISKLESS;

		if (disk_state[NEW] == D_OUTDATED && disk_state[OLD] < D_OUTDATED &&
		    disk_state[OLD] != D_ATTACHING) {
			/* Do not allow outdate of inconsistent or diskless.
			   But we have to allow Inconsistent -> Outdated if a resync
			   finishes over one connection, and is paused on other connections */

			for_each_peer_device(peer_device, device) {
				enum bsr_repl_state *repl_state = peer_device->repl_state;
				if (repl_state[OLD] == L_SYNC_TARGET && repl_state[NEW] == L_ESTABLISHED)
					goto allow;
				// DW-891
				if (test_bit(RECONCILIATION_RESYNC, &peer_device->flags) && repl_state[NEW] == L_WF_BITMAP_S) {
					/* If it fails to change the repl_state, reconciliation resync does not do. 
					So clear the RECONCILIATION_RESYNC bit. */
					clear_bit(RECONCILIATION_RESYNC, &peer_device->flags);
				}
			}
			return SS_LOWER_THAN_OUTDATED;
		}
		allow:

		for (which = OLD; which <= NEW; which++) {
			any_disk_up_to_date[which] = disk_state[which] == D_UP_TO_DATE;
			if (any_disk_up_to_date[which])
				continue;
			for_each_peer_device(peer_device, device) {
				enum bsr_disk_state *peer_disk_state = peer_device->disk_state;

				if (peer_disk_state[which] == D_UP_TO_DATE) {
					any_disk_up_to_date[which] = true;
					break;
				}
			}
		}
		/* Prevent becoming primary while there is not data accessible
		   and prevent detach or disconnect while primary */
		if (!(role[OLD] == R_PRIMARY && !any_disk_up_to_date[OLD]) &&
		     (role[NEW] == R_PRIMARY && !any_disk_up_to_date[NEW]))
			return SS_NO_UP_TO_DATE_DISK;

		// DW-1155 not support Outdated-Primary
		if (!(role[OLD] == R_PRIMARY && (disk_state[OLD] <= D_OUTDATED)) &&
		     (role[NEW] == R_PRIMARY && (disk_state[NEW] <= D_OUTDATED)))
		{
			return SS_NO_UP_TO_DATE_DISK;
		}

		/* Prevent detach or disconnect while held open read only */
		if (device->open_ro_cnt && any_disk_up_to_date[OLD] && !any_disk_up_to_date[NEW])
			return SS_NO_UP_TO_DATE_DISK;

		if (disk_state[NEW] == D_NEGOTIATING)
			nr_negotiating++;

		if (role[NEW] == R_PRIMARY &&
			resource->res_opts.quorum != QOU_OFF && get_ldev(device)) {
			struct quorum_info qi;
			bool had_quorum = role[OLD] == R_PRIMARY ? calc_quorum(device, OLD, NULL) : true;
			bool have_quorum = calc_quorum(device, NEW, &qi);

			put_ldev(device);

			if (had_quorum && !have_quorum) {
				bsr_state_err(resource, "%d of %d nodes visible, need %d for quorum",
					qi.votes, qi.voters, qi.quorum_at);
				return SS_NO_QUORUM;
			}
		}

		for_each_peer_device(peer_device, device) {
			enum bsr_disk_state *peer_disk_state = peer_device->disk_state;
			enum bsr_repl_state *repl_state = peer_device->repl_state;

			if (peer_disk_state[NEW] == D_NEGOTIATING)
				nr_negotiating++;

			if (nr_negotiating > 1)
				return SS_IN_TRANSIENT_STATE;

			// DW-1340 
			// do not change the repl_state to L_WF_BITMAP_T when peer disk state is lower than outdated.
			if (repl_state[NEW] == L_WF_BITMAP_T && peer_disk_state[NEW] == D_OUTDATED && peer_disk_state[OLD] < D_OUTDATED && 
				peer_disk_state[OLD] != D_ATTACHING) {				
				return SS_LOWER_THAN_OUTDATED_PEER; 
			}

			if (peer_device->connection->fencing_policy >= FP_RESOURCE &&
			    !(role[OLD] == R_PRIMARY && repl_state[OLD] < L_ESTABLISHED && !(peer_disk_state[OLD] <= D_OUTDATED)) &&
			     (role[NEW] == R_PRIMARY && repl_state[NEW] < L_ESTABLISHED && !(peer_disk_state[NEW] <= D_OUTDATED)))
				return SS_PRIMARY_NOP;

			if (!(repl_state[OLD] > L_ESTABLISHED && disk_state[OLD] < D_INCONSISTENT) &&
			     (repl_state[NEW] > L_ESTABLISHED && disk_state[NEW] < D_INCONSISTENT))
				return SS_NO_LOCAL_DISK;

			if (!(repl_state[OLD] > L_ESTABLISHED && peer_disk_state[OLD] < D_INCONSISTENT) &&
			     (repl_state[NEW] > L_ESTABLISHED && peer_disk_state[NEW] < D_INCONSISTENT))
				return SS_NO_REMOTE_DISK;

			/*
			if (!(repl_state[OLD] > L_ESTABLISHED && disk_state[OLD] < D_OUTDATED && peer_disk_state[OLD] < D_OUTDATED) &&
			     (repl_state[NEW] > L_ESTABLISHED && disk_state[NEW] < D_OUTDATED && peer_disk_state[NEW] < D_OUTDATED))
				return SS_NO_UP_TO_DATE_DISK;
			*/


			if (disk_state[OLD] > D_OUTDATED && disk_state[NEW] == D_OUTDATED &&
			    !local_disk_may_be_outdated(device, NEW))
				return SS_CONNECTED_OUTDATES;

			if (!(repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) &&
			     (repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T)) {
				struct net_conf *nc = rcu_dereference(peer_device->connection->transport.net_conf);

				if (!nc || nc->verify_alg[0] == 0)
					return SS_NO_VERIFY_ALG;
			}

			if (repl_state[OLD] == L_SYNC_SOURCE && repl_state[NEW] == L_WF_BITMAP_S)
				return SS_RESYNC_RUNNING;

			if (repl_state[OLD] == L_SYNC_TARGET && repl_state[NEW] == L_WF_BITMAP_T)
				return SS_RESYNC_RUNNING;

			if (repl_state[NEW] != repl_state[OLD] &&
			    (repl_state[NEW] == L_STARTING_SYNC_T || repl_state[NEW] == L_STARTING_SYNC_S) &&
			    repl_state[OLD] > L_ESTABLISHED )
				return SS_RESYNC_RUNNING;

			/* if (repl_state[NEW] == repl_state[OLD] && repl_state[NEW] == L_OFF)
				return SS_IN_TRANSIENT_STATE; */

			if ((repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T) && repl_state[OLD] < L_ESTABLISHED)
				return SS_NEED_CONNECTION;

			if ((repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T) &&
			    repl_state[NEW] != repl_state[OLD] && repl_state[OLD] > L_ESTABLISHED)
				return SS_RESYNC_RUNNING;

			if ((repl_state[NEW] == L_STARTING_SYNC_S || repl_state[NEW] == L_STARTING_SYNC_T) &&
			    repl_state[OLD] < L_ESTABLISHED)
				return SS_NEED_CONNECTION;

			if ((repl_state[NEW] == L_SYNC_TARGET || repl_state[NEW] == L_SYNC_SOURCE)
			    && repl_state[OLD] < L_OFF)
				return SS_NEED_CONNECTION; /* No NetworkFailure -> SyncTarget etc... */
		}
	}

	return SS_SUCCESS;
}

/**
 * is_valid_soft_transition() - Returns an SS_ error code if state[NEW] is not valid
 *
 * "Soft" transitions are voluntary state changes which bsr may decline, such
 * as a user request to promote a resource to primary.  Opposed to that are
 * involuntary or "hard" transitions like a network connection loss.
 *
 * When deciding if a "soft" transition should be allowed, "hard" transitions
 * may already have forced the resource into a critical state.  It may take
 * several "soft" transitions to get the resource back to normal.  To allow
 * those, rather than checking if the desired new state is valid, we can only
 * check if the desired new state is "at least as good" as the current state.
 */
static enum bsr_state_rv is_valid_soft_transition(struct bsr_resource *resource)
{
	enum bsr_state_rv rv;

	rcu_read_lock();
	rv = __is_valid_soft_transition(resource);
	rcu_read_unlock();

	return rv;
}

static enum bsr_state_rv
is_valid_conn_transition(enum bsr_conn_state oc, enum bsr_conn_state nc)
{
	/* no change -> nothing to do, at least for the connection part */
	if (oc == nc)
		return SS_NOTHING_TO_DO;

	/* disconnect of an unconfigured connection does not make sense */
	if (oc == C_STANDALONE && nc == C_DISCONNECTING)
		return SS_ALREADY_STANDALONE;

	/* from C_STANDALONE, we start with C_UNCONNECTED */
	if (oc == C_STANDALONE && nc != C_UNCONNECTED)
		return SS_NEED_CONNECTION;

	/* After a network error only C_UNCONNECTED or C_DISCONNECTING may follow. */
	if (oc >= C_TIMEOUT && oc <= C_TEAR_DOWN && nc != C_UNCONNECTED && nc != C_DISCONNECTING)
		return SS_IN_TRANSIENT_STATE;

	/* After C_DISCONNECTING only C_STANDALONE may follow */
	if (oc == C_DISCONNECTING && nc != C_STANDALONE)
		return SS_IN_TRANSIENT_STATE;

	return SS_SUCCESS;
}


/**
 * is_valid_transition() - Returns an SS_ error code if the state transition is not possible
 * This limits hard state transitions. Hard state transitions are facts there are
 * imposed on BSR by the environment. E.g. disk broke or network broke down.
 * But those hard state transitions are still not allowed to do everything.
 */
static enum bsr_state_rv is_valid_transition(struct bsr_resource *resource)
{
	enum bsr_state_rv rv;
	struct bsr_connection *connection;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device;
	int vnr;

	for_each_connection(connection, resource) {
		rv = is_valid_conn_transition(connection->cstate[OLD], connection->cstate[NEW]);
		if (rv < SS_SUCCESS)
			return rv;

		idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
			/* When establishing a connection we need to go through C_CONNECTED!
			   Necessary to do the right thing upon invalidate-remote on a disconnected
			   resource */
			if (connection->cstate[OLD] < C_CONNECTED &&
			    peer_device->repl_state[NEW] >= L_ESTABLISHED)
			{
				// DW-1529 Eliminated stopped state of WFBitMapT. This node will try to reconnect after the state change fails. 
				bsr_info(24, BSR_LC_STATE, connection, "Must be connected when status change. return SS_NEED_CONNECTION. cs=%d repl=%d ",
					connection->cstate[OLD], peer_device->repl_state[NEW]);
				return SS_NEED_CONNECTION; 
			}
		}
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		/* we cannot fail (again) if we already detached */
		if ((device->disk_state[NEW] == D_FAILED || device->disk_state[NEW] == D_DETACHING) &&
		    device->disk_state[OLD] == D_DISKLESS) {
			return SS_IS_DISKLESS;
		}
	}

	return SS_SUCCESS;
}

static bool is_sync_target_other_c(struct bsr_peer_device *ign_peer_device)
{
	struct bsr_device *device = ign_peer_device->device;
	struct bsr_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		enum bsr_repl_state r;

		if (peer_device == ign_peer_device)
			continue;

		r = peer_device->repl_state[NEW];
		if (r == L_SYNC_TARGET || r == L_PAUSED_SYNC_T)
			return true;
	}

	return false;
}


static void sanitize_state(struct bsr_resource *resource)
{
	enum bsr_role *role = resource->role;
	struct bsr_connection *connection;
	struct bsr_device *device;
	bool maybe_crashed_primary = false;
	int connected_primaries = 0;
	int vnr;

	rcu_read_lock();
	for_each_connection(connection, resource) {
		enum bsr_conn_state *cstate = connection->cstate;

		if (cstate[NEW] < C_CONNECTED)
			__change_peer_role(connection, R_UNKNOWN, __FUNCTION__);

		if (connection->peer_role[OLD] == R_PRIMARY && cstate[OLD] == C_CONNECTED &&
			((cstate[NEW] >= C_TIMEOUT && cstate[NEW] <= C_PROTOCOL_ERROR) ||
			(cstate[NEW] == C_DISCONNECTING && resource->state_change_flags & CS_HARD)))
			/* implies also C_BROKEN_PIPE and C_NETWORK_FAILURE */
			maybe_crashed_primary = true;

		if (connection->peer_role[NEW] == R_PRIMARY)
			connected_primaries++;
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_device *peer_device;
		enum bsr_disk_state *disk_state = device->disk_state;
		bool lost_connection = false;
		int good_data_count[2] = { 0 };

		if (disk_state[OLD] == D_DISKLESS && disk_state[NEW] == D_DETACHING)
			__change_disk_state(device, D_DISKLESS, __FUNCTION__);

		if ((resource->state_change_flags & CS_IGN_OUTD_FAIL) &&
		    disk_state[OLD] < D_OUTDATED && disk_state[NEW] == D_OUTDATED)
			__change_disk_state(device, disk_state[OLD], __FUNCTION__);

		/* Is disk state negotiation finished? */
		if (disk_state[OLD] == D_NEGOTIATING && disk_state[NEW] == D_NEGOTIATING) {
			int all = 0, target = 0, no_result = 0;
			bool up_to_date_neighbor = false;
			
			for_each_peer_device(peer_device, device) {
				enum bsr_repl_state nr = peer_device->negotiation_result;
				enum bsr_disk_state pdsk = peer_device->disk_state[NEW];

				if (pdsk == D_UNKNOWN || pdsk < D_NEGOTIATING)
					continue;

				if (pdsk == D_UP_TO_DATE)
					up_to_date_neighbor = true;

				all++;
				if (nr == L_NEG_NO_RESULT)
					no_result++;
				else if (nr == L_NEGOTIATING)
					goto stay_negotiating;
				else if (nr == L_WF_BITMAP_T)
					target++;
				else if (nr != L_ESTABLISHED && nr != L_WF_BITMAP_S)
					bsr_err(25, BSR_LC_STATE, peer_device, "Unexpected negotiation result(%s)", bsr_repl_str(nr));
			}

			/* negotiation finished */
			if (no_result > 0 && no_result == all)
				__change_disk_state(device, D_DETACHING, __FUNCTION__);
			else if (target)
				__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
			else
				__change_disk_state(device, up_to_date_neighbor ? D_UP_TO_DATE : disk_state_from_md(device), __FUNCTION__);

			for_each_peer_device(peer_device, device) {
				enum bsr_repl_state nr = peer_device->negotiation_result;

				if (peer_device->connection->cstate[NEW] < C_CONNECTED ||
				    nr == L_NEGOTIATING)
					continue;

				if (nr == L_NEG_NO_RESULT)
					nr = L_ESTABLISHED;

				if (nr == L_WF_BITMAP_S && disk_state[NEW] == D_INCONSISTENT) {
					/* Should be sync source for one peer and sync
					   target for an other peer. Delay the sync source
					   role */
					nr = L_PAUSED_SYNC_S;
					__change_resync_susp_other_c(peer_device, true, NULL);
					bsr_warn(41, BSR_LC_STATE, peer_device, "Delay the sync source role");
				}
				__change_repl_state(peer_device, nr, __FUNCTION__);
			}
		}
	stay_negotiating:

		for_each_peer_device(peer_device, device) {
			enum bsr_repl_state *repl_state = peer_device->repl_state;
			enum bsr_disk_state *peer_disk_state = peer_device->disk_state;
			struct bsr_connection *connection = peer_device->connection;
			enum bsr_conn_state *cstate = connection->cstate;
			enum bsr_disk_state min_disk_state, max_disk_state;
			enum bsr_disk_state min_peer_disk_state, max_peer_disk_state;

			if (repl_state[NEW] < L_ESTABLISHED) {
				__change_resync_susp_peer(peer_device, false, __FUNCTION__);
				// DW-1031 Changes the peer disk state to D_UNKNOWN when peer is disconnected, even if it is D_INCONSISTENT.
				if (peer_disk_state[NEW] > D_UNKNOWN ||
					peer_disk_state[NEW] < D_OUTDATED)
					__change_peer_disk_state(peer_device, D_UNKNOWN, __FUNCTION__);
			}
			if (repl_state[OLD] >= L_ESTABLISHED && repl_state[NEW] < L_ESTABLISHED)
				lost_connection = true;

			/* Clear the aftr_isp when becoming unconfigured */
			if (cstate[NEW] == C_STANDALONE &&
			    disk_state[NEW] == D_DISKLESS &&
				role[NEW] == R_SECONDARY)
				__change_resync_susp_dependency(peer_device, false, __FUNCTION__);

			/* Abort resync if a disk fails/detaches */
			if (repl_state[NEW] > L_ESTABLISHED &&
			    (disk_state[NEW] <= D_FAILED ||
				peer_disk_state[NEW] <= D_FAILED))
				__change_repl_state(peer_device, L_ESTABLISHED, __FUNCTION__);

			// DW-1314 restrict to be sync side when it is not able to.
			if ((repl_state[NEW] >= L_STARTING_SYNC_S && repl_state[NEW] <= L_PAUSED_SYNC_T)) {
				if (((repl_state[NEW] != L_STARTING_SYNC_S && repl_state[NEW] != L_STARTING_SYNC_T) ||
					repl_state[NOW] >= L_ESTABLISHED) &&
					!bsr_inspect_resync_side(peer_device, repl_state[NEW], NOW, true)) {					
					bsr_warn(42, BSR_LC_STATE, peer_device, "Force it to be Established due to unsyncable stability");
					__change_repl_state(peer_device, L_ESTABLISHED, __FUNCTION__);
					set_bit(UNSTABLE_TRIGGER_CP, &peer_device->flags); // DW-1341
				}
			}

			// DW-885
			// DW-897
			// DW-907 Abort resync if disk state goes unsyncable.
			if (((repl_state[NEW] == L_SYNC_TARGET || repl_state[NEW] == L_PAUSED_SYNC_T ) && peer_disk_state[NEW] <= D_INCONSISTENT) ||
				((repl_state[NEW] == L_SYNC_SOURCE || repl_state[NEW] == L_PAUSED_SYNC_S ) && disk_state[NEW] <= D_INCONSISTENT))
			{
				__change_repl_state(peer_device, L_ESTABLISHED, __FUNCTION__);
				// DW-955 need to set flag to resume aborted resync when it goes syncable.
				set_bit(RESYNC_ABORTED, &peer_device->flags);
			}

			// DW-955 (peer)disk state is going syncable, resume aborted resync.
			if ((disk_state[OLD] <= D_INCONSISTENT && peer_disk_state[OLD] <= D_INCONSISTENT) &&
				(disk_state[NEW] <= D_INCONSISTENT || peer_disk_state[NEW] <= D_INCONSISTENT) &&
				test_bit(RESYNC_ABORTED, &peer_device->flags))
			{		
				if (disk_state[NEW] == D_OUTDATED ||
					disk_state[NEW] == D_CONSISTENT ||
					disk_state[NEW] == D_UP_TO_DATE)
				{
					__change_repl_state(peer_device, L_SYNC_SOURCE, __FUNCTION__);
					clear_bit(RESYNC_ABORTED, &peer_device->flags);
				}		
				else if (peer_disk_state[NEW] == D_OUTDATED ||
					peer_disk_state[NEW] == D_CONSISTENT ||
					peer_disk_state[NEW] == D_UP_TO_DATE)
				{
					__change_repl_state(peer_device, L_SYNC_TARGET, __FUNCTION__);
					clear_bit(RESYNC_ABORTED, &peer_device->flags);
				}				
			}

			/* D_CONSISTENT vanish when we get connected (pre 9.0) */
			if (connection->agreed_pro_version < 110 &&
			    repl_state[NEW] >= L_ESTABLISHED && repl_state[NEW] < L_AHEAD) {
				if (disk_state[NEW] == D_CONSISTENT)
					__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);
				if (peer_disk_state[NEW] == D_CONSISTENT)
					__change_peer_disk_state(peer_device, D_UP_TO_DATE, __FUNCTION__);
			}

			/* Implications of the repl state on the disk states */
			min_disk_state = D_DISKLESS;
			max_disk_state = D_UP_TO_DATE;
			min_peer_disk_state = D_INCONSISTENT;
			max_peer_disk_state = D_UNKNOWN;
			switch (repl_state[NEW]) {
			case L_OFF:
				/* values from above */
				break;
			case L_WF_BITMAP_T:
			case L_PAUSED_SYNC_T:
			case L_STARTING_SYNC_T:
			case L_WF_SYNC_UUID:
			case L_BEHIND:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_OUTDATED;
				min_peer_disk_state = D_OUTDATED;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_VERIFY_S:
			case L_VERIFY_T:
				min_disk_state = D_UP_TO_DATE;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_UP_TO_DATE;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_ESTABLISHED:
				min_disk_state = D_DISKLESS;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_DISKLESS;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_WF_BITMAP_S:
			case L_PAUSED_SYNC_S:
			case L_STARTING_SYNC_S:
			case L_AHEAD:
				min_disk_state = D_OUTDATED;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_INCONSISTENT;
				max_peer_disk_state = D_CONSISTENT; /* D_OUTDATED would be nice. But explicit outdate necessary*/
				break;
			case L_SYNC_TARGET:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_INCONSISTENT;
				min_peer_disk_state = D_OUTDATED;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_SYNC_SOURCE:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_INCONSISTENT;
				max_peer_disk_state = D_INCONSISTENT;
				break;
			}

			/* Implications of the repl state on the disk states */
			if (disk_state[NEW] > max_disk_state) {
				__change_disk_state(device, max_disk_state, __FUNCTION__);
			}

			if (disk_state[NEW] < min_disk_state) {
				__change_disk_state(device, min_disk_state, __FUNCTION__);
			}

			if (peer_disk_state[NEW] > max_peer_disk_state)
				__change_peer_disk_state(peer_device, max_peer_disk_state, __FUNCTION__);

			if (peer_disk_state[NEW] < min_peer_disk_state)
				// DW-885
				// DW-897
				// DW-907 
				// Do not discretionally make disk state syncable, syncable repl state would be changed once it tries to change to 'L_(PAUSED_)SYNC_TARGET', depending on disk state.
				if (repl_state[NEW] != L_STARTING_SYNC_T)
					__change_peer_disk_state(peer_device, min_peer_disk_state, __FUNCTION__);

			/* Suspend IO while fence-peer handler runs (peer lost) */
			if (connection->fencing_policy == FP_STONITH &&
			    (role[NEW] == R_PRIMARY &&
			     repl_state[NEW] < L_ESTABLISHED &&
			     peer_disk_state[NEW] == D_UNKNOWN) &&
			    (role[OLD] != R_PRIMARY ||
			     peer_disk_state[OLD] != D_UNKNOWN))
				 __change_io_susp_fencing(connection, true);

			/* Count access to good data */
			if (peer_disk_state[OLD] == D_UP_TO_DATE)
				++good_data_count[OLD];
			if (peer_disk_state[NEW] == D_UP_TO_DATE)
				++good_data_count[NEW];

			/* Pause a SyncSource until it finishes resync as target on other connecitons */
			if (repl_state[OLD] != L_SYNC_SOURCE && repl_state[NEW] == L_SYNC_SOURCE &&
				is_sync_target_other_c(peer_device))
				__change_resync_susp_other_c(peer_device, true, __FUNCTION__);

			if (resync_suspended(peer_device, NEW)) {
				if (repl_state[NEW] == L_SYNC_SOURCE)
					__change_repl_state(peer_device, L_PAUSED_SYNC_S, __FUNCTION__);
				if (repl_state[NEW] == L_SYNC_TARGET)
					__change_repl_state(peer_device, L_PAUSED_SYNC_T, __FUNCTION__);
			} else {
				if (repl_state[NEW] == L_PAUSED_SYNC_S)
					__change_repl_state(peer_device, L_SYNC_SOURCE, __FUNCTION__);
				if (repl_state[NEW] == L_PAUSED_SYNC_T)
					__change_repl_state(peer_device, L_SYNC_TARGET, __FUNCTION__);
			}

			/* This needs to be after the previous block, since we should not set
			   the bit if we are paused ourself */
			if (repl_state[OLD] != L_SYNC_TARGET && repl_state[NEW] == L_SYNC_TARGET)
				set_resync_susp_other_c(peer_device, true, false, __FUNCTION__);

			// DW-1854 resync_susp_other_c must be set to false even when L_WF_BITMAP_T state
			if ((repl_state[OLD] == L_WF_BITMAP_T && (repl_state[NEW] != L_SYNC_TARGET && repl_state[NEW] != L_WF_BITMAP_T)) ||
				(repl_state[OLD] == L_SYNC_TARGET && repl_state[NEW] != L_SYNC_TARGET))
				set_resync_susp_other_c(peer_device, false, false, __FUNCTION__);

			/* Implication of the repl state on other peer's repl state */
			if (repl_state[OLD] != L_STARTING_SYNC_T && repl_state[NEW] == L_STARTING_SYNC_T)
				// DW-885
				// DW-897
				// DW-907 Do not discretionally change other peer's replication state. 
				// We should always notify state change, or possibly brought unpaired sync target up.
				set_resync_susp_other_c(peer_device, true, false, __FUNCTION__);

			// DW-885
			// DW-897
			// DW-907 Clear resync_susp_other_c when state change is aborted, to get resynced from other node.
			if (repl_state[OLD] == L_STARTING_SYNC_T && 
				// DW-1854 If the current state is L_STARTING_SYNC_T, the new state must be L_WF_BITMAP_T, otherwise change resync_sp_other_c to false.
				(repl_state[NEW] != L_STARTING_SYNC_T && repl_state[NEW] != L_WF_BITMAP_T))
				//repl_state[NEW] == L_ESTABLISHED)
				set_resync_susp_other_c(peer_device, false, false, __FUNCTION__);


			/* A detach is a cluster wide transaction. The peer_disk_state updates
			   are coming in while we have it prepared. When the cluster wide
			   state change gets committed prevent D_DISKLESS -> D_FAILED */
			if (peer_disk_state[OLD] == D_DISKLESS &&
				(peer_disk_state[NEW] == D_FAILED || peer_disk_state[NEW] == D_DETACHING))
				__change_peer_disk_state(peer_device, D_DISKLESS, __FUNCTION__);

			/* Upgrade myself from D_OUTDATED if..
				1) We connect to stable D_UP_TO_DATE(or D_CONSISTENT) peer without resnyc
				2) The peer just became stable
				3) the peer was stable and just became D_UP_TO_DATE */
			if (repl_state[NEW] == L_ESTABLISHED && disk_state[NEW] == D_OUTDATED &&
				peer_disk_state[NEW] >= D_CONSISTENT && peer_device->uuids_received &&
				peer_device->uuid_flags & UUID_FLAG_STABLE &&
				(repl_state[OLD] < L_ESTABLISHED ||
				peer_device->uuid_flags & UUID_FLAG_GOT_STABLE ||
				peer_disk_state[OLD] == D_OUTDATED))
				__change_disk_state(device, peer_disk_state[NEW], __FUNCTION__);
			/* clause intentional here, the D_CONSISTENT form above might trigger this */
			if (repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] >= L_ESTABLISHED &&
				disk_state[NEW] == D_CONSISTENT && may_be_up_to_date(device))
				__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);

			peer_device->uuid_flags &= ~UUID_FLAG_GOT_STABLE;

			if (resource->res_opts.quorum != QOU_OFF && role[NEW] == R_PRIMARY &&
				get_ldev(device)) {
				if (lost_contact_to_peer_data(peer_disk_state)) {
					bool had_quorum = calc_quorum(device, OLD, NULL);
					bool have_quorum = calc_quorum(device, NEW, NULL);

					if (had_quorum && !have_quorum)
						__change_io_susp_quorum(device, true);
				}
				put_ldev(device);
			}
		}
		if (disk_state[OLD] == D_UP_TO_DATE)
			++good_data_count[OLD];
		if (disk_state[NEW] == D_UP_TO_DATE)
			++good_data_count[NEW];

		/* Suspend IO if we have no accessible data available.
		 * Policy may be extended later to be able to suspend
		 * if redundancy falls below a certain level. */
		if (resource->res_opts.on_no_data == OND_SUSPEND_IO &&
		    (role[NEW] == R_PRIMARY && good_data_count[NEW] == 0) &&
		   !(role[OLD] == R_PRIMARY && good_data_count[OLD] == 0))
		   __change_io_susp_no_data(resource, true);
		if (lost_connection && disk_state[NEW] == D_NEGOTIATING)
			__change_disk_state(device, disk_state_from_md(device), __FUNCTION__);

		if (maybe_crashed_primary && !connected_primaries &&
			disk_state[NEW] == D_UP_TO_DATE && role[NOW] == R_SECONDARY)
			__change_disk_state(device, D_CONSISTENT, __FUNCTION__);
	}
	rcu_read_unlock();
}

void bsr_resume_al(struct bsr_device *device)
{
	if (test_and_clear_bit(AL_SUSPENDED, &device->flags))
		bsr_info(15, BSR_LC_LRU, device, "Resumed activity log updates");
}

static void set_ov_position(struct bsr_peer_device *peer_device,
			    enum bsr_repl_state repl_state)
{
	struct bsr_device *device = peer_device->device;
	if (peer_device->connection->agreed_pro_version < 90)
		peer_device->ov_start_sector = 0;
	peer_device->rs_total = bsr_bm_bits(device);
	peer_device->ov_bm_position = 0;
	peer_device->ov_position = 0;
	peer_device->ov_acked_sector = 0;
	if (repl_state == L_VERIFY_T) {
		/* starting online verify from an arbitrary position
		 * does not fit well into the existing protocol.
		 * on L_VERIFY_T, we initialize ov_left and friends
		 * implicitly in receive_DataRequest once the
		 * first P_OV_REQUEST is received */
		peer_device->ov_start_sector = ~(sector_t)0;
	} else {
		ULONG_PTR bit = (ULONG_PTR)BM_SECT_TO_BIT(peer_device->ov_start_sector);
		if (bit >= peer_device->rs_total) {
			peer_device->ov_start_sector =
				BM_BIT_TO_SECT(peer_device->rs_total - 1);
			peer_device->rs_total = 1;
		} else
			peer_device->rs_total -= bit;
		peer_device->ov_position = peer_device->ov_start_sector;
		peer_device->ov_bm_position = (ULONG_PTR)BM_SECT_TO_BIT(peer_device->ov_position);
	}
	peer_device->ov_left = peer_device->rs_total;
	peer_device->ov_skipped = 0;
}

static void queue_after_state_change_work(struct bsr_resource *resource,
					  struct completion *done)
{
	/* Caller holds req_lock */
	struct after_state_change_work *work;
	gfp_t gfp = GFP_ATOMIC;

	work = bsr_kmalloc(sizeof(*work), gfp, '83SB');
	if (work)
		work->state_change = remember_state_change(resource, gfp);
	
	if (work && work->state_change) {
		// BSR-439 if the new disk state value is D_DETACHING, it will be reflected immediately.
		struct bsr_device *device;
		struct bsr_peer_device *peer_device;
		int vnr;

		idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
			if (device->disk_state[NEW] == D_DETACHING &&
				device->disk_state[NOW] != D_DETACHING)
				device->disk_state[NOW] = device->disk_state[NEW];

			for_each_peer_device(peer_device, device) {
				// DW-1131 updating repl_state, before w_after_state_change add to bsr_work_queue. 
				// BSR-439 update only in the specified state (L_WF_BITMAP_S, L_WF_BITMAP_T)
				if (peer_device->repl_state[NEW] == L_WF_BITMAP_S || peer_device->repl_state[NEW] == L_WF_BITMAP_T)
					peer_device->repl_state[NOW] = peer_device->repl_state[NEW];
			}
		}

		work->w.cb = w_after_state_change;
		work->done = done;
		bsr_queue_work(&resource->work, &work->w);
	} else {
		bsr_kfree(work);
		bsr_err(42, BSR_LC_MEMORY, resource, "Failed to queue state change work due to failure to allocate memory for work");
		if (done)
			complete(done);
	}
}

static void initialize_resync(struct bsr_peer_device *peer_device)
{
    ULONG_PTR tw = bsr_bm_total_weight(peer_device);
    ULONG_PTR now = jiffies;
	int i;

	peer_device->rs_failed = 0;
	peer_device->rs_paused = 0;
	peer_device->rs_same_csum = 0;
	peer_device->rs_last_sect_ev = 0;
	peer_device->rs_total = tw;
	peer_device->rs_start = now;
	// DW-1886
	peer_device->rs_send_req = 0;
	peer_device->rs_recv_res = 0;
	atomic_set64(&peer_device->rs_written, 0);

	for (i = 0; i < BSR_SYNC_MARKS; i++) {
		peer_device->rs_mark_left[i] = tw;
		peer_device->rs_mark_time[i] = now;
	}

	bsr_rs_controller_reset(peer_device);
}

/* Is there a primary with access to up to date data known */
static bool primary_and_data_present(struct bsr_device *device)
{
	bool up_to_date_data = device->disk_state[NOW] == D_UP_TO_DATE;
	bool primary = device->resource->role[NOW] == R_PRIMARY;
	struct bsr_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->peer_role[NOW] == R_PRIMARY)
			primary = true;

		if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
			up_to_date_data = true;
	}

	return primary && up_to_date_data;
}

/**
 * finish_state_change  -  carry out actions triggered by a state change
 */
static void finish_state_change(struct bsr_resource *resource, struct completion *done, bool locked, const char* caller)
{
	enum bsr_role *role = resource->role;
	struct bsr_device *device;
	struct bsr_connection *connection;
	bool starting_resync = false;
	bool start_new_epoch = false;
	bool lost_a_primary_peer = false;
	int vnr;

	print_state_change(resource, "", locked, caller);

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_device *peer_device;

		for_each_peer_device(peer_device, device) {
			bool did, should;

			did = bsr_should_do_remote(peer_device, NOW);
			should = bsr_should_do_remote(peer_device, NEW);

			if (did != should)
				start_new_epoch = true;

			if (!is_sync_state(peer_device, NOW) &&
			    is_sync_state(peer_device, NEW))
				clear_bit(RS_DONE, &peer_device->flags);
		}
	}
	if (start_new_epoch)
		start_new_tl_epoch(resource);

	if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY && resource->peer_ack_req) {
		resource->last_peer_acked_dagtag = resource->peer_ack_req->dagtag_sector;
		bsr_queue_peer_ack(resource, resource->peer_ack_req);
		resource->peer_ack_req = NULL;
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		enum bsr_disk_state *disk_state = device->disk_state;
		struct bsr_peer_device *peer_device;
		bool one_peer_disk_up_to_date[2] = {0, };
		bool create_new_uuid = false;

		if (disk_state[OLD] != D_NEGOTIATING && disk_state[NEW] == D_NEGOTIATING) {
			for_each_peer_device(peer_device, device)
				peer_device->negotiation_result = L_NEGOTIATING;
		}

		/* if we are going -> D_FAILED or D_DISKLESS, grab one extra reference
		 * on the ldev here, to be sure the transition -> D_DISKLESS resp.
		 * bsr_ldev_destroy() won't happen before our corresponding
		 * w_after_state_change works run, where we put_ldev again. */
		if ((disk_state[OLD] != D_FAILED && disk_state[NEW] == D_FAILED) ||
		    (disk_state[OLD] != D_DETACHING && disk_state[NEW] == D_DETACHING) ||
		    (disk_state[OLD] != D_DISKLESS && disk_state[NEW] == D_DISKLESS)) {
			atomic_inc(&device->local_cnt);
			BUG_ON(test_and_set_bit(HAVE_LDEV, &device->flags));
		}

		if (disk_state[OLD] == D_ATTACHING && disk_state[NEW] >= D_NEGOTIATING)
			bsr_info(14, BSR_LC_UUID, device, "attached to current UUID: %016llX", device->ldev->md.current_uuid);

		// BSR-676 current UUID output when setting D_DETACHING state
		if (disk_state[NEW] == D_DETACHING)
			bsr_info(19, BSR_LC_UUID, device, "detaching to current UUID: %016llX", device->ldev->md.current_uuid);

		for_each_peer_device(peer_device, device) {
			enum bsr_repl_state *repl_state = peer_device->repl_state;
			struct bsr_connection *connection = peer_device->connection;
			enum bsr_disk_state *peer_disk_state = peer_device->disk_state;
			enum which_state which;


			/* Wake up role changes, that were delayed because of connection establishing */
			if (repl_state[OLD] == L_OFF && repl_state[NEW] != L_OFF &&
			    all_peer_devices_connected(connection))
				clear_bit(INITIAL_STATE_SENT, &peer_device->flags);

			for (which = OLD; which <= NEW; which++) {
				if (peer_disk_state[which] == D_UP_TO_DATE)
					one_peer_disk_up_to_date[which] = true;
			}

		}

		for_each_peer_device(peer_device, device) {
			enum bsr_repl_state *repl_state = peer_device->repl_state;
			enum bsr_disk_state *peer_disk_state = peer_device->disk_state;
			struct bsr_connection *connection = peer_device->connection;
			enum bsr_role *peer_role = connection->peer_role;

			// DW-892
			enum bsr_conn_state *cstate = connection->cstate;

			if (repl_state[OLD] <= L_ESTABLISHED && repl_state[NEW] == L_WF_BITMAP_S)
				starting_resync = true;

			// DW-1315 check resync availability as state changes, set RESYNC_ABORTED flag by going unsyncable, actual aborting will be occured in w_after_state_change().
			if ((repl_state[NEW] >= L_STARTING_SYNC_S && repl_state[NEW] <= L_WF_BITMAP_T) ||
				(repl_state[NEW] >= L_SYNC_SOURCE && repl_state[NEW] <= L_PAUSED_SYNC_T))
			{
				if (repl_state[NOW] >= L_ESTABLISHED &&
					!bsr_inspect_resync_side(peer_device, repl_state[NEW], NEW, locked))				
					set_bit(RESYNC_ABORTED, &peer_device->flags);
			}

			/* Aborted verify run, or we reached the stop sector.
			 * Log the last position, unless end-of-device. */
			if ((repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) &&
			    repl_state[NEW] <= L_ESTABLISHED) {
				// BSR-118
				// BSR-835
				if (peer_device->ov_acked_sector)
					peer_device->ov_start_sector = peer_device->ov_acked_sector;
				if (peer_device->ov_left) {
					// BSR-52
					ov_out_of_sync_print(peer_device, true);
					ov_skipped_print(peer_device, true);

					bsr_info(147, BSR_LC_RESYNC_OV, peer_device, "Online Verify reached sector %llu",
						  (unsigned long long)peer_device->ov_start_sector);
				}
			}

			if ((repl_state[OLD] == L_PAUSED_SYNC_T || repl_state[OLD] == L_PAUSED_SYNC_S) &&
			    (repl_state[NEW] == L_SYNC_TARGET  || repl_state[NEW] == L_SYNC_SOURCE)) {
				bsr_info(148, BSR_LC_RESYNC_OV, peer_device, "The resync will resume.");
				peer_device->rs_paused += (long)jiffies
						  -(long)peer_device->rs_mark_time[peer_device->rs_last_mark];

				// DW-972 PausedSyncSource could have bit to be resynced outside of previous sync range, need to find bit from the beginning when switching resync.
				device->bm_resync_fo = 0;

				if (repl_state[NEW] == L_SYNC_TARGET)
					mod_timer(&peer_device->resync_timer, jiffies);

				/* Setting the find_offset back is necessary when switching resync from
				   one peer to the other. Since in the bitmap of the new peer, there
				   might be bits before the current find_offset. Since the peer is
				   notified about the resync progress in BM_EXT sized chunks. */
			}

			if ((repl_state[OLD] == L_SYNC_TARGET  || repl_state[OLD] == L_SYNC_SOURCE) &&
			    (repl_state[NEW] == L_PAUSED_SYNC_T || repl_state[NEW] == L_PAUSED_SYNC_S)) {
				bsr_info(149, BSR_LC_RESYNC_OV, peer_device, "Resync suspended");
				peer_device->rs_mark_time[peer_device->rs_last_mark] = jiffies;
			}


			if (repl_state[OLD] > L_ESTABLISHED && repl_state[NEW] <= L_ESTABLISHED)
				clear_bit(RECONCILIATION_RESYNC, &peer_device->flags);
#if 0
/* Why would I want to reset this?
 * It is useful to not accidentally resize beyond end of backend of peer.
 */
			if (repl_state[OLD] >= L_ESTABLISHED && repl_state[NEW] < L_ESTABLISHED)
				peer_device->max_size = 0;
#endif

			if (repl_state[OLD] == L_ESTABLISHED &&
			    (repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T)) {
                ULONG_PTR now = jiffies;
				int i;

				set_ov_position(peer_device, repl_state[NEW]);
				// init
				if (NULL != peer_device->fast_ov_bitmap) {
					// BSR-835
					kref_put(&peer_device->ov_bm_ref, bsr_free_ov_bm);
				}

				peer_device->rs_start = now;
				peer_device->rs_last_sect_ev = 0;
				peer_device->ov_last_oos_size = 0;
				peer_device->ov_last_oos_start = 0;
				peer_device->ov_last_skipped_size = 0;
				peer_device->ov_last_skipped_start = 0;
				INIT_LIST_HEAD(&peer_device->ov_oos_info_list);
				INIT_LIST_HEAD(&peer_device->ov_skipped_info_list);
				peer_device->ov_oos_info_list_cnt = 0;
				peer_device->ov_oos_info_report_num = 0;
				peer_device->ov_skipped_info_list_cnt = 0;
				peer_device->ov_skipped_info_report_num = 0;
				for (i = 0; i < BSR_SYNC_MARKS; i++) {
					peer_device->rs_mark_left[i] = peer_device->ov_left;
					peer_device->rs_mark_time[i] = now;
				}

				bsr_rs_controller_reset(peer_device);

			} else if (!(repl_state[OLD] >= L_SYNC_SOURCE && repl_state[OLD] <= L_PAUSED_SYNC_T) &&
				   (repl_state[NEW] >= L_SYNC_SOURCE && repl_state[NEW] <= L_PAUSED_SYNC_T)) {
				initialize_resync(peer_device);
			}

			if (disk_state[NEW] != D_NEGOTIATING && get_ldev(device)) {
				if (peer_device->bitmap_index != -1) {
					enum bsr_disk_state pdsk = peer_device->disk_state[NEW];
					u32 mdf = device->ldev->md.peers[peer_device->node_id].flags;
					/* Do NOT clear MDF_PEER_DEVICE_SEEN.
					 * We want to be able to refuse a resize beyond "last agreed" size,
					 * even if the peer is currently detached.
					 */
					mdf &= ~(MDF_PEER_CONNECTED | MDF_PEER_OUTDATED | MDF_PEER_FENCING);
					if (repl_state[NEW] > L_OFF)
						mdf |= MDF_PEER_CONNECTED;
					if (pdsk >= D_INCONSISTENT) {
						if (pdsk <= D_OUTDATED)
							mdf |= MDF_PEER_OUTDATED;
						if (pdsk != D_UNKNOWN)
							mdf |= MDF_PEER_DEVICE_SEEN;
                    }
					if (peer_device->connection->fencing_policy != FP_DONT_CARE)
						mdf |= MDF_PEER_FENCING;
					if (mdf != device->ldev->md.peers[peer_device->node_id].flags) {
						device->ldev->md.peers[peer_device->node_id].flags = mdf;
						bsr_md_mark_dirty(device);
						// BSR-676 notify flag
						atomic_set(&peer_device->notify_flags, (atomic_read(&peer_device->notify_flags) | 1));
					}
				}

				/* Peer was forced D_UP_TO_DATE & R_PRIMARY, consider to resync */
				if (disk_state[OLD] == D_INCONSISTENT &&
				    peer_disk_state[OLD] == D_INCONSISTENT && peer_disk_state[NEW] == D_UP_TO_DATE &&
				    peer_role[OLD] == R_SECONDARY && peer_role[NEW] == R_PRIMARY)
					set_bit(CONSIDER_RESYNC, &peer_device->flags);

				/* Resume AL writing if we get a connection */
				if (repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] >= L_ESTABLISHED)
					bsr_resume_al(device);
				put_ldev(device);
			}

			if (repl_state[OLD] == L_AHEAD && repl_state[NEW] == L_SYNC_SOURCE) {
				set_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags);
				set_bit(SEND_STATE_AFTER_AHEAD_C, &connection->flags);
				wake_up(&connection->sender_work.q_wait);
			}

			// DW-1195 bump current uuid when disconnecting with inconsistent peer.
			if (lost_contact_to_peer_data(peer_disk_state) || (peer_disk_state[NEW] == D_INCONSISTENT)) {
				if (role[NEW] == R_PRIMARY && !test_bit(UNREGISTERED, &device->flags) &&
					// DW-892 Bumping uuid during starting resync seems to be inadequate, this is a stopgap work as long as the purpose of 'lost_contact_to_peer_data' is unclear.
					(repl_state[NEW] != L_AHEAD && cstate[NEW] < C_CONNECTED) &&
					(disk_state[NEW] == D_UP_TO_DATE || one_peer_disk_up_to_date[NEW])) {
					bsr_info(21, BSR_LC_UUID, peer_device, "set UUID creation schedule flag due to lost peer data");
					create_new_uuid = true;
				}

				if (connection->agreed_pro_version < 110 &&
					peer_role[NEW] == R_PRIMARY &&
					disk_state[NEW] >= D_UP_TO_DATE) {
					bsr_info(22, BSR_LC_UUID, peer_device, "set UUID creation schedule flag due to lost peer data");
					create_new_uuid = true;
				}
			}
			if (peer_returns_diskless(peer_device, peer_disk_state[OLD], peer_disk_state[NEW])) {
				if (role[NEW] == R_PRIMARY && !test_bit(UNREGISTERED, &device->flags) &&
					disk_state[NEW] == D_UP_TO_DATE) {
					bsr_info(23, BSR_LC_UUID, peer_device, "set UUID creation schedule flag due to the peer is diskless");
					create_new_uuid = true;
				}
			}
		}

		if (disk_state[OLD] >= D_INCONSISTENT && disk_state[NEW] < D_INCONSISTENT &&
			role[NEW] == R_PRIMARY && one_peer_disk_up_to_date[NEW]) {
			bsr_info(24, BSR_LC_UUID, device, "set UUID creation schedule flag due to changing the disk state");
			create_new_uuid = true;
		}

		if (create_new_uuid)
			set_bit(__NEW_CUR_UUID, &device->flags);

		if (disk_state[NEW] != D_NEGOTIATING && get_ldev(device)) {
			u32 mdf = device->ldev->md.flags & ~(MDF_PRIMARY_IND | MDF_CRASHED_PRIMARY);
			mdf &= ~MDF_AL_CLEAN;
			if (test_bit(CRASHED_PRIMARY, &device->flags))
				mdf |= MDF_CRASHED_PRIMARY;
			if (device->resource->role[NEW] == R_PRIMARY && disk_state[NEW] != D_DETACHING)
				mdf |= MDF_PRIMARY_IND;
			/* Do not touch MDF_CONSISTENT if we are D_FAILED */
			if (disk_state[NEW] >= D_INCONSISTENT) {
				mdf &= ~(MDF_CONSISTENT | MDF_WAS_UP_TO_DATE);

				if (disk_state[NEW] > D_INCONSISTENT)
					mdf |= MDF_CONSISTENT;
				if (disk_state[NEW] > D_OUTDATED)
					mdf |= MDF_WAS_UP_TO_DATE;
			} else if ((disk_state[NEW] == D_FAILED || disk_state[NEW] == D_DETACHING) &&
				   mdf & MDF_WAS_UP_TO_DATE &&
				   primary_and_data_present(device)) {
				/* There are cases when we still can update meta-data event disk
				   state is failed.... Clear MDF_WAS_UP_TO_DATE if appropriate */
				mdf &= ~MDF_WAS_UP_TO_DATE;
			}
			if (mdf != device->ldev->md.flags) {
				device->ldev->md.flags = mdf;
				bsr_md_mark_dirty(device);
				// BSR-676 notify flag
				atomic_set(&device->notify_flags, (atomic_read(&device->notify_flags) | 1));
			}
			if (disk_state[OLD] < D_CONSISTENT && disk_state[NEW] >= D_CONSISTENT)
				bsr_set_exposed_data_uuid(device, device->ldev->md.current_uuid);
			put_ldev(device);
		}

		/* remember last attach time so request_timer_fn() won't
		 * kill newly established sessions while we are still trying to thaw
		 * previously frozen IO */
		if ((disk_state[OLD] == D_ATTACHING || disk_state[OLD] == D_NEGOTIATING) &&
		    disk_state[NEW] > D_NEGOTIATING)
			device->last_reattach_jif = jiffies;
	}

	for_each_connection(connection, resource) {
		enum bsr_conn_state *cstate = connection->cstate;
		enum bsr_role *peer_role = connection->peer_role;

		/* Receiver should clean up itself */
		if (cstate[OLD] != C_DISCONNECTING && cstate[NEW] == C_DISCONNECTING) 
			bsr_thread_stop_nowait(&connection->receiver);

		/* Now the receiver finished cleaning up itself, it should die */
		if (cstate[OLD] != C_STANDALONE && cstate[NEW] == C_STANDALONE) 
			bsr_thread_stop_nowait(&connection->receiver);

		/* Upon network failure, we need to restart the receiver. */
		if (cstate[OLD] >= C_CONNECTING &&
			cstate[NEW] <= C_TEAR_DOWN && cstate[NEW] >= C_TIMEOUT) {
			bsr_thread_restart_nowait(&connection->receiver);
			twopc_connection_down(connection);
		}

		if (cstate[NEW] < C_CONNECTED) {
			struct bsr_peer_device *peer_device;

			idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
				clear_bit(INITIAL_STATE_SENT, &peer_device->flags);
				clear_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
				// DW-1799
				clear_bit(INITIAL_SIZE_RECEIVED, &peer_device->flags);
			}
		}

		/* remember last connect time so request_timer_fn() won't
		 * kill newly established sessions while we are still trying to thaw
		 * previously frozen IO */
		if (cstate[OLD] < C_CONNECTED && cstate[NEW] == C_CONNECTED) {
			if (connection->last_reconnect_jif)
		       set_bit(RECONNECT, &connection->flags);
			connection->last_reconnect_jif = jiffies;
		}

		if (starting_resync && peer_role[NEW] == R_PRIMARY)
			apply_unacked_peer_requests(connection);

		if (peer_role[OLD] == R_PRIMARY && peer_role[NEW] == R_UNKNOWN)
			lost_a_primary_peer = true;

		if (cstate[OLD] == C_CONNECTED && cstate[NEW] < C_CONNECTED) {
			clear_bit(BARRIER_ACK_PENDING, &connection->flags);
			wake_up(&resource->barrier_wait);
		}
	}

	if (lost_a_primary_peer) {
		idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
			struct bsr_peer_device *peer_device;

			for_each_peer_device(peer_device, device) {
				enum bsr_repl_state repl_state = peer_device->repl_state[NEW];

				if (!test_bit(UNSTABLE_RESYNC, &peer_device->flags) &&
				    (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
				    !(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
				    !bsr_stable_sync_source_present(peer_device, NEW))
					set_bit(UNSTABLE_RESYNC, &peer_device->flags);
			}
		}
	}

	queue_after_state_change_work(resource, done);
}

static void abw_start_sync(struct bsr_device *device,
			   struct bsr_peer_device *peer_device, int rv)
{
	struct bsr_peer_device *pd;

	if (rv) {
		bsr_err(151, BSR_LC_RESYNC_OV, device, "Failed to starting resync due to failure to writing the bitmap.");
		stable_change_repl_state(peer_device, L_ESTABLISHED, CS_VERBOSE);
		return;
	}

	switch (peer_device->repl_state[NOW]) {
	case L_STARTING_SYNC_T:
		/* Since the number of set bits changed and the other peer_devices are
		   lready in L_PAUSED_SYNC_T state, we need to set rs_total here */
#ifdef _WIN
	{ 
#endif
		rcu_read_lock();
		for_each_peer_device_rcu(pd, device)
			initialize_resync(pd);
		rcu_read_unlock();

		// DW-1293 peer's bitmap will be reflected on local device's bitmap to perform fast invalidate(remote).
		if (peer_device->connection->agreed_pro_version >= 112)
			stable_change_repl_state(peer_device, L_WF_BITMAP_T, CS_VERBOSE);
		else if (peer_device->connection->agreed_pro_version < 110)
			stable_change_repl_state(peer_device, L_WF_SYNC_UUID, CS_VERBOSE);
		else
			bsr_start_resync(peer_device, L_SYNC_TARGET);
		break;
#ifdef _WIN
	}
#endif
	case L_STARTING_SYNC_S:
		// DW-1293 peer's bitmap will be reflected on local device's bitmap to perform fast invalidate(remote).
		if (peer_device->connection->agreed_pro_version >= 112)
			stable_change_repl_state(peer_device, L_WF_BITMAP_S, CS_VERBOSE);
		else
			bsr_start_resync(peer_device, L_SYNC_SOURCE);
		break;
	default:
		break;
	}
}

int bsr_bitmap_io_from_worker(struct bsr_device *device,
		int (*io_fn)(struct bsr_device *, struct bsr_peer_device *),
		char *why, enum bm_flag flags,
		struct bsr_peer_device *peer_device)
{
	int rv;

	D_ASSERT(device, current == device->resource->worker.task);

	/* open coded non-blocking bsr_suspend_io(device); */
	atomic_inc(&device->suspend_cnt);

	if (flags & BM_LOCK_SINGLE_SLOT)
		bsr_bm_slot_lock(peer_device, why, flags);
	else
		bsr_bm_lock(device, why, flags);
	rv = io_fn(device, peer_device);
	if (flags & BM_LOCK_SINGLE_SLOT)
		bsr_bm_slot_unlock(peer_device);
	else
		bsr_bm_unlock(device);

	bsr_resume_io(device);

	return rv;
}

static inline bool state_change_is_susp_fen(struct bsr_state_change *state_change,
					    enum which_state which)
{
	unsigned int n_connection;

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_connection_state_change *connection_state_change =
				&state_change->connections[n_connection];

		if (connection_state_change->susp_fen[which])
			return true;
	}

	return false;
}

static inline bool state_change_is_susp_quorum(struct bsr_state_change *state_change,
					       enum which_state which)
{
	unsigned int n_device;

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct bsr_device_state_change *device_state_change =
				&state_change->devices[n_device];

		if (device_state_change->susp_quorum[which])
			return true;
	}

	return false;
}


static union bsr_state state_change_word(struct bsr_state_change *state_change,
					  unsigned int n_device, int n_connection,
					  enum which_state which)
{
	struct bsr_resource_state_change *resource_state_change =
		&state_change->resource[0];
	struct bsr_device_state_change *device_state_change =
		&state_change->devices[n_device];
	union bsr_state state = { {
		.role = R_UNKNOWN,
		.peer = R_UNKNOWN,
		.conn = C_STANDALONE,
		.disk = D_UNKNOWN,
		.pdsk = D_UNKNOWN,
	} };

	state.role = resource_state_change->role[which];
	state.susp = resource_state_change->susp[which] || state_change_is_susp_quorum(state_change, which);
	state.susp_nod = resource_state_change->susp_nod[which];
	state.susp_fen = state_change_is_susp_fen(state_change, which);
	state.disk = device_state_change->disk_state[which];
	if (n_connection != -1) {
		struct bsr_connection_state_change *connection_state_change =
			&state_change->connections[n_connection];
		struct bsr_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];

		state.peer = connection_state_change->peer_role[which];
		state.conn = peer_device_state_change->repl_state[which];
		if (state.conn <= L_OFF)
			state.conn = connection_state_change->cstate[which];
		state.pdsk = peer_device_state_change->disk_state[which];
		state.aftr_isp = peer_device_state_change->resync_susp_dependency[which] ||
			peer_device_state_change->resync_susp_other_c[which];
		state.peer_isp = peer_device_state_change->resync_susp_peer[which];
		state.user_isp = peer_device_state_change->resync_susp_user[which];
	}
	return state;
}

void notify_resource_state_change(struct sk_buff *skb,
				  unsigned int seq,
				  struct bsr_state_change *state_change,
				  enum bsr_notification_type type)
{
	struct bsr_resource_state_change *resource_state_change = state_change->resource;
	struct bsr_resource *resource = resource_state_change->resource;
	struct resource_info resource_info = {
		.res_role = resource_state_change->role[NEW],
		.res_susp = resource_state_change->susp[NEW],
		.res_susp_nod = resource_state_change->susp_nod[NEW],
		.res_susp_fen = state_change_is_susp_fen(state_change, NEW),
		.res_susp_quorum = state_change_is_susp_quorum(state_change, NEW),
	};

	notify_resource_state(skb, seq, resource, &resource_info, type);
}

void notify_connection_state_change(struct sk_buff *skb,
				    unsigned int seq,
				    struct bsr_connection_state_change *connection_state_change,
				    enum bsr_notification_type type)
{
	struct bsr_connection *connection = connection_state_change->connection;
	struct connection_info connection_info = {
		.conn_connection_state = connection_state_change->cstate[NEW],
		.conn_role = connection_state_change->peer_role[NEW],
	};

	notify_connection_state(skb, seq, connection, &connection_info, type);
}

void notify_device_state_change(struct sk_buff *skb,
				unsigned int seq,
				struct bsr_device_state_change *device_state_change,
				enum bsr_notification_type type)
{
	struct bsr_device *device = device_state_change->device;
	struct device_info device_info;

	device_to_info(&device_info, device);

	notify_device_state(skb, seq, device, &device_info, type);
}

void notify_peer_device_state_change(struct sk_buff *skb,
				     unsigned int seq,
				     struct bsr_peer_device_state_change *p,
				     enum bsr_notification_type type)
{
	struct bsr_peer_device *peer_device = p->peer_device;
	/* THINK maybe unify with peer_device_to_info */
	struct peer_device_info peer_device_info = {
		.peer_repl_state = p->repl_state[NEW],
		.peer_disk_state = p->disk_state[NEW],
		.peer_resync_susp_user = p->resync_susp_user[NEW],
		.peer_resync_susp_peer = p->resync_susp_peer[NEW],
		.peer_resync_susp_dependency = p->resync_susp_dependency[NEW] || p->resync_susp_other_c[NEW],
		.peer_is_intentional_diskless = false,
	};

	notify_peer_device_state(skb, seq, peer_device, &peer_device_info, type);
}

static void notify_state_change(struct bsr_state_change *state_change)
{
	struct bsr_resource_state_change *resource_state_change = &state_change->resource[0];
	bool resource_state_has_changed;
	unsigned int n_device, n_connection, n_peer_device, n_peer_devices;
	void (*last_func)(struct sk_buff *, unsigned int, void *,
			  enum bsr_notification_type) = NULL;
    void *last_arg = NULL;

#define HAS_CHANGED(state) ((state)[OLD] != (state)[NEW])
#ifdef _WIN
#define FINAL_STATE_CHANGE(type) \
	{ if (last_func) \
		last_func(NULL, 0, last_arg, type); \
	}
#define REMEMBER_STATE_CHANGE(func, arg, type) \
	{ FINAL_STATE_CHANGE(type | NOTIFY_CONTINUES); \
	   last_func = func; \
	   last_arg = arg; \
	}
#else // _LIN
#define FINAL_STATE_CHANGE(type) \
	({ if (last_func) \
		last_func(NULL, 0, last_arg, type); \
	})
#define REMEMBER_STATE_CHANGE(func, arg, type) \
	({ FINAL_STATE_CHANGE(type | NOTIFY_CONTINUES); \
	   last_func = (typeof(last_func))func; \
	   last_arg = arg; \
	 })
#endif
	mutex_lock(&notification_mutex);

	resource_state_has_changed =
		HAS_CHANGED(resource_state_change->role) ||
		HAS_CHANGED(resource_state_change->susp) ||
		HAS_CHANGED(resource_state_change->susp_nod) ||
		state_change_is_susp_fen(state_change, OLD) !=
		state_change_is_susp_fen(state_change, NEW) ||
		state_change_is_susp_quorum(state_change, OLD) !=
		state_change_is_susp_quorum(state_change, NEW);

	if (resource_state_has_changed)
		REMEMBER_STATE_CHANGE(notify_resource_state_change,
				      state_change, NOTIFY_CHANGE);

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_connection_state_change *connection_state_change =
				&state_change->connections[n_connection];

		if (HAS_CHANGED(connection_state_change->peer_role) ||
		    HAS_CHANGED(connection_state_change->cstate))
			REMEMBER_STATE_CHANGE(notify_connection_state_change,
					      connection_state_change, NOTIFY_CHANGE);
	}

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct bsr_device_state_change *device_state_change =
			&state_change->devices[n_device];

		if (HAS_CHANGED(device_state_change->disk_state))
			REMEMBER_STATE_CHANGE(notify_device_state_change,
					      device_state_change, NOTIFY_CHANGE);
	}

	n_peer_devices = state_change->n_devices * state_change->n_connections;
	for (n_peer_device = 0; n_peer_device < n_peer_devices; n_peer_device++) {
		struct bsr_peer_device_state_change *p =
			&state_change->peer_devices[n_peer_device];

		if (HAS_CHANGED(p->disk_state) ||
		    HAS_CHANGED(p->repl_state) ||
		    HAS_CHANGED(p->resync_susp_user) ||
		    HAS_CHANGED(p->resync_susp_peer) ||
		    HAS_CHANGED(p->resync_susp_dependency) ||
		    HAS_CHANGED(p->resync_susp_other_c))
			REMEMBER_STATE_CHANGE(notify_peer_device_state_change,
					      p, NOTIFY_CHANGE);
	}

	FINAL_STATE_CHANGE(NOTIFY_CHANGE);
	mutex_unlock(&notification_mutex);

#undef HAS_CHANGED
#undef FINAL_STATE_CHANGE
#undef REMEMBER_STATE_CHANGE
}

static void send_role_to_all_peers(struct bsr_state_change *state_change)
{
	unsigned int n_connection;

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_connection_state_change *connection_state_change =
			&state_change->connections[n_connection];
		struct bsr_connection *connection = connection_state_change->connection;
		enum bsr_conn_state new_cstate = connection_state_change->cstate[NEW];

		if (new_cstate < C_CONNECTED)
			continue;

		if (connection->agreed_pro_version < 110) {
			unsigned int n_device;

			/* Before BSR 9, the role is a device attribute
			 * instead of a resource attribute. */
			for (n_device = 0; n_device < state_change->n_devices; n_device++) {
				struct bsr_peer_device *peer_device =
					state_change->peer_devices[n_connection].peer_device;
				union bsr_state state =
					state_change_word(state_change, n_device, n_connection, NEW);

				bsr_send_state(peer_device, state);
			}
		} else {
			union bsr_state state = { {
				.role = state_change->resource[0].role[NEW],
			} };

			conn_send_state(connection, state);
		}
	}
}

static void send_new_state_to_all_peer_devices(struct bsr_state_change *state_change, unsigned int n_device)
{
	unsigned int n_connection;

	BUG_ON(state_change->n_devices <= n_device);
	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
		struct bsr_peer_device *peer_device = peer_device_state_change->peer_device;
		union bsr_state new_state = state_change_word(state_change, n_device, n_connection, NEW);

		if (new_state.conn >= C_CONNECTED)
			bsr_send_state(peer_device, new_state);
	}
}
static void notify_peers_lost_primary(struct bsr_connection *lost_peer)
{
	struct bsr_resource *resource = lost_peer->resource;
	struct bsr_connection *connection;
	u64 im;

	// TODO BSR-326 need this?
	// DW-1502 FIXME: Wait 1000ms until receive_data is completely processed 
	msleep(1000);

	for_each_connection_ref(connection, im, resource) {
		if (connection == lost_peer)
			continue;
		if (connection->cstate[NOW] == C_CONNECTED) {
			struct bsr_peer_device *peer_device;
			int vnr;

			idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
				struct bsr_device *device = peer_device->device;
				u64 current_uuid = bsr_current_uuid(device);
				u64 weak_nodes = bsr_weak_nodes_device(device);
				bsr_send_current_uuid(peer_device, current_uuid, weak_nodes);
			}
			bsr_send_peer_dagtag(connection, lost_peer);
		}
	}
}

/* This function is supposed to have the same semantics as bsr_device_stable() in bsr_main.c
   A primary is stable since it is authoritative.
   Unstable are neighbors of a primary and resync target nodes.
   Nodes further away from a primary are stable! Do no confuse with "weak".*/
#if 0 // deprecated. use calc_device_stable_ex
static bool calc_device_stable(struct bsr_state_change *state_change, int n_device, enum which_state which)
{
	unsigned int n_connection;

	if (state_change->resource->role[which] == R_PRIMARY)
		return true;

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_connection_state_change *connection_state_change =
			&state_change->connections[n_connection];
		enum bsr_role *peer_role = connection_state_change->peer_role;
		struct bsr_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
		enum bsr_repl_state *repl_state = peer_device_state_change->repl_state;

		if (peer_role[which] == R_PRIMARY)
			return false;

		switch (repl_state[which]) {
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			return false;
		default:
			continue;
		}
	}

	return true;
}
#endif

// DW-1315 This function is supposed to have the same semantics as calc_device_stable which doesn't return authoritative node.
 //  We need to notify peer when keeping unstable device and authoritative node's changed as long as it is the criterion of operating resync. 
static bool calc_device_stable_ex(struct bsr_state_change *state_change, int n_device, enum which_state which, u64* authoritative)
{
	unsigned int n_connection;
		
	if (state_change->resource->role[which] == R_PRIMARY)
		return true;

	// try to find primary node first, which has the first priority of becoming authoritative node.
	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_connection_state_change *connection_state_change =
			&state_change->connections[n_connection];
		enum bsr_role *peer_role = connection_state_change->peer_role;

		if (peer_role[which] == R_PRIMARY) {
			if (authoritative) {
				struct bsr_peer_device_state_change *peer_device_state_change = &state_change->peer_devices[n_device * state_change->n_connections + n_connection];
				struct bsr_peer_device *peer_device = peer_device_state_change->peer_device;
				*authoritative |= NODE_MASK(peer_device->node_id);
			}
			return false;
		}
	}

	// no primary exists at least we have connected, try to find node of resync source side.
	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {		
		struct bsr_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
		enum bsr_repl_state *repl_state = peer_device_state_change->repl_state;
		
		switch (repl_state[which]) {
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			if (authoritative) {
				struct bsr_peer_device *peer_device = peer_device_state_change->peer_device;
				*authoritative |= NODE_MASK(peer_device->node_id);
			}			
			return false;
		default:
			continue;
		}
	}

	return true;
}

/* takes old and new peer disk state */
static bool lost_contact_to_peer_data(enum bsr_disk_state *peer_disk_state)
{
	enum bsr_disk_state os = peer_disk_state[OLD];
	enum bsr_disk_state ns = peer_disk_state[NEW];

	return (os >= D_INCONSISTENT && os != D_UNKNOWN && os != D_OUTDATED)
		&& (ns < D_INCONSISTENT || ns == D_UNKNOWN || ns == D_OUTDATED);
}

static bool got_contact_to_peer_data(enum bsr_disk_state *peer_disk_state)
{
	enum bsr_disk_state os = peer_disk_state[OLD];
	enum bsr_disk_state ns = peer_disk_state[NEW];

	return (ns >= D_INCONSISTENT && ns != D_UNKNOWN && ns != D_OUTDATED)
		&& (os < D_INCONSISTENT || os == D_UNKNOWN || os == D_OUTDATED);
}

static bool peer_returns_diskless(struct bsr_peer_device *peer_device,
enum bsr_disk_state os, enum bsr_disk_state ns)
{
	struct bsr_device *device = peer_device->device;
	bool rv = false;
	
	/* Scenario, starting with normal operation
	 * Connected Primary/Secondary UpToDate/UpToDate
	 * NetworkFailure Primary/Unknown UpToDate/DUnknown (frozen)
	 * ...
	 * Connected Primary/Secondary UpToDate/Diskless (resumed; needs to bump uuid!)
	 */
	if (get_ldev(device)) {
		if (os == D_UNKNOWN && (ns == D_DISKLESS || ns == D_FAILED || ns == D_OUTDATED) &&
			bsr_bitmap_uuid(peer_device) == 0)
			rv = true;
		put_ldev(device);
	}

	return rv;
}

static void check_may_resume_io_after_fencing(struct bsr_state_change *state_change, int n_connection)
{
	struct bsr_connection_state_change *connection_state_change = &state_change->connections[n_connection];
	struct bsr_resource_state_change *resource_state_change = &state_change->resource[0];
	struct bsr_connection *connection = connection_state_change->connection;
	struct bsr_resource *resource = resource_state_change->resource;
	bool all_peer_disks_outdated = true;
	bool all_peer_disks_connected = true;
	struct bsr_peer_device *peer_device;
	unsigned long irq_flags;
	int vnr;
	unsigned int n_device;

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct bsr_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
		enum bsr_repl_state *repl_state = peer_device_state_change->repl_state;
		enum bsr_disk_state *peer_disk_state = peer_device_state_change->disk_state;

		if (peer_disk_state[NEW] > D_OUTDATED)
			all_peer_disks_outdated = false;
		if (repl_state[NEW] < L_ESTABLISHED)
			all_peer_disks_connected = false;
	}

	/* case1: The outdate peer handler is successful: */
	if (all_peer_disks_outdated) {
		mutex_lock(&resource->conf_update);
		idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
			struct bsr_device *device = peer_device->device;
			if (test_and_clear_bit(NEW_CUR_UUID, &device->flags)) {
				bsr_info(36, BSR_LC_UUID, device, "clear the UUID creation flag because the disks on all nodes are outdate and attempt to create a UUID");
				bsr_uuid_new_current(device, false, false, __FUNCTION__);
			}
		}
		mutex_unlock(&resource->conf_update);
		begin_state_change(resource, &irq_flags, CS_VERBOSE);
		_tl_restart(connection, CONNECTION_LOST_WHILE_PENDING);
		__change_io_susp_fencing(connection, false);
		end_state_change(resource, &irq_flags, __FUNCTION__);
	}
	/* case2: The connection was established again: */
	if (all_peer_disks_connected) {
		rcu_read_lock();
		idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
			struct bsr_device *device = peer_device->device;
			if (test_bit(NEW_CUR_UUID, &device->flags)) 
				bsr_info(37, BSR_LC_UUID, device, "clear the UUID creation flag because all nodes are connected");
			clear_bit(NEW_CUR_UUID, &device->flags);
		}
		rcu_read_unlock();
		begin_state_change(resource, &irq_flags, CS_VERBOSE);
		_tl_restart(connection, RESEND);
		__change_io_susp_fencing(connection, false);
		end_state_change(resource, &irq_flags, __FUNCTION__);
	}
}

/*
 BSR-175 it is called when we determined that crashed primary is no longer need for one of peer at least.
	I am no longer crashed primary for all peers if..
		1. I've done resync as a sync target from one of uptodate peer.
		2. I've done resync as a sync source for all existing peers.
	I am no longer crashed primary for only this peer if..
		1. I've done resync as a sync source for this peer, but have not done resync for another peer.
*/ 
static void consider_finish_crashed_primary(struct bsr_peer_device *peer_device, bool done)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_device *p;

	if (done) {
		clear_bit(CRASHED_PRIMARY, &device->flags);

		for_each_peer_device(p, device)
			bsr_md_clear_peer_flag(p, MDF_CRASHED_PRIMARY_WORK_PENDING);

		return;
	}

	bsr_md_clear_peer_flag(peer_device, MDF_CRASHED_PRIMARY_WORK_PENDING);

	done = true;
	for_each_peer_device(p, device) {
		if (p != peer_device && 
			bsr_md_test_peer_flag(p, MDF_CRASHED_PRIMARY_WORK_PENDING)) {
			done = false;
			break;
		}
	}

	if (done)
		clear_bit(CRASHED_PRIMARY, &device->flags);
}


/*
 * Perform after state change actions that may sleep.
 */
static int w_after_state_change(struct bsr_work *w, int unused)
{
	struct after_state_change_work *work =
		container_of(w, struct after_state_change_work, w);
	struct bsr_state_change *state_change = work->state_change;
	struct bsr_resource_state_change *resource_state_change = &state_change->resource[0];
	struct bsr_resource *resource = resource_state_change->resource;
	enum bsr_role *role = resource_state_change->role;
	struct bsr_peer_device *send_state_others = NULL;
	bool *susp_nod = resource_state_change->susp_nod;
	unsigned int n_device, n_connection;
	bool still_connected = false;
	bool try_become_up_to_date = false;
	bool resync_finished = false;

	UNREFERENCED_PARAMETER(unused);

	notify_state_change(state_change);

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct bsr_device_state_change *device_state_change = &state_change->devices[n_device];
		struct bsr_device *device = device_state_change->device;
		enum bsr_disk_state *disk_state = device_state_change->disk_state;
		bool *susp_quorum = device_state_change->susp_quorum;
		bool effective_disk_size_determined = false;
		bool one_peer_disk_up_to_date[2] = { 0 };
		bool device_stable[2];
		enum which_state which;
		// DW-1315
		u64 authoritative[2] = { 0, };

		// BSR-676
		if (device_state_change->notify_flags & 1) {
			mutex_lock(&notification_mutex);
			notify_gi_device_mdf_flag_state(NULL, 0, device, NOTIFY_CHANGE);
			mutex_unlock(&notification_mutex);
		}

		for (which = OLD; which <= NEW; which++)
			// DW-1315 need changes of authoritative node to notify peers.
			device_stable[which] = calc_device_stable_ex(state_change, n_device, which, &authoritative[which]);

		if (disk_state[NEW] == D_UP_TO_DATE)
			effective_disk_size_determined = true;

		for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
			struct bsr_peer_device_state_change *peer_device_state_change =
				&state_change->peer_devices[
					n_device * state_change->n_connections + n_connection];
			struct bsr_peer_device *peer_device = peer_device_state_change->peer_device;
			enum bsr_disk_state *peer_disk_state = peer_device_state_change->disk_state;
			enum bsr_repl_state *repl_state = peer_device_state_change->repl_state;

			for (which = OLD; which <= NEW; which++) {
				if (peer_disk_state[which] == D_UP_TO_DATE)
					one_peer_disk_up_to_date[which] = true;
			}

			if ((repl_state[OLD] == L_SYNC_TARGET || repl_state[OLD] == L_PAUSED_SYNC_T) &&
				repl_state[NEW] == L_ESTABLISHED)
				 resync_finished = true;

			if (disk_state[OLD] == D_INCONSISTENT && disk_state[NEW] == D_UP_TO_DATE &&
				peer_disk_state[OLD] == D_INCONSISTENT && peer_disk_state[NEW] == D_UP_TO_DATE)	
				send_state_others = peer_device;


			// DW-998 Disk state is adopted by peer disk and it could have any syncable state, so is local disk state.
			if (resync_finished && disk_state[NEW] >= D_OUTDATED && disk_state[NEW] == peer_disk_state[NOW]) {
				//BSR-175 clear CRASHED_PRIMARY flag if I've done resync as a sync target from one of peer.
				if (test_bit(CRASHED_PRIMARY, &device->flags)) 
					consider_finish_crashed_primary(peer_device, repl_state[NOW] == L_SYNC_TARGET && repl_state[NEW] == L_ESTABLISHED);

				if (peer_device->uuids_received)
					peer_device->uuid_flags &= ~((u64)UUID_FLAG_CRASHED_PRIMARY);
			}

			// BSR-676
			if (peer_device_state_change->notify_flags & 1) {
				mutex_lock(&notification_mutex);
				notify_gi_peer_device_mdf_flag_state(NULL, 0, peer_device, NOTIFY_CHANGE);
				mutex_unlock(&notification_mutex);
			}
		}

		for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
			struct bsr_connection_state_change *connection_state_change = &state_change->connections[n_connection];
			struct bsr_connection *connection = connection_state_change->connection;
			enum bsr_conn_state *cstate = connection_state_change->cstate;
			enum bsr_role *peer_role = connection_state_change->peer_role;
			struct bsr_peer_device_state_change *peer_device_state_change =
				&state_change->peer_devices[
					n_device * state_change->n_connections + n_connection];
			struct bsr_peer_device *peer_device = peer_device_state_change->peer_device;
			enum bsr_repl_state *repl_state = peer_device_state_change->repl_state;
			enum bsr_disk_state *peer_disk_state = peer_device_state_change->disk_state;
			bool *resync_susp_user = peer_device_state_change->resync_susp_user;
			bool *resync_susp_peer = peer_device_state_change->resync_susp_peer;
			bool *resync_susp_dependency = peer_device_state_change->resync_susp_dependency;
			bool *resync_susp_other_c = peer_device_state_change->resync_susp_other_c;
			union bsr_state new_state =
				state_change_word(state_change, n_device, n_connection, NEW);
			bool send_state = false;

			// DW-1447 
			bool send_bitmap = false;

			// DW-1806 If the initial state is not sent, wait for it to be sent.(Maximum 3 seconds)
			if (connection->cstate[NOW] == C_CONNECTED && !test_bit(INITIAL_STATE_SENT, &peer_device->flags)) {
				long res;
				wait_event_timeout_ex(peer_device->state_initial_send_wait, test_bit(INITIAL_STATE_SENT, &peer_device->flags), HZ * 3, res);
				if (!res) {
					/* FIXME timeout when sending initial state? */
					bsr_err(27, BSR_LC_STATE, peer_device, "Failed to send initial packet within timeout(3 second)");
				}
			}

			/* In case we finished a resync as resync-target update all neighbors
			   about having a bitmap_uuid of 0 towards the previous sync-source.
			   That needs to go out before sending the new disk state
			   (To avoid a race where the other node might downgrade our disk
			   state due to old UUID valued) */
			// BSR-863
			if (connection->agreed_pro_version < 115) {
				if (resync_finished && peer_disk_state[NEW] != D_UNKNOWN)
					bsr_send_uuids(peer_device, 0, 0, NOW);
			}

			if (peer_disk_state[NEW] == D_UP_TO_DATE)
				effective_disk_size_determined = true;

			if ((disk_state[OLD] != D_UP_TO_DATE || peer_disk_state[OLD] != D_UP_TO_DATE) &&
			    (disk_state[NEW] == D_UP_TO_DATE && peer_disk_state[NEW] == D_UP_TO_DATE)) {
				// BSR-175 clear CRASHED_PRIMARY flag if I've done resync as a sync target from one of peer.
				if (test_bit(CRASHED_PRIMARY, &device->flags))
					consider_finish_crashed_primary(peer_device, repl_state[NOW] == L_SYNC_TARGET && repl_state[NEW] == L_ESTABLISHED);

				if (peer_device->uuids_received)
					peer_device->uuid_flags &= ~((u64)UUID_FLAG_CRASHED_PRIMARY);
			}
			
			if (!(role[OLD] == R_PRIMARY && disk_state[OLD] < D_UP_TO_DATE && !one_peer_disk_up_to_date[OLD]) &&
			     (role[NEW] == R_PRIMARY && disk_state[NEW] < D_UP_TO_DATE && !one_peer_disk_up_to_date[NEW]) &&
			    !test_bit(UNREGISTERED, &device->flags))
				bsr_khelper(device, connection, "pri-on-incon-degr");

			// DW-1291 provide LastPrimary Information for Local Primary
			if( (role[OLD] == R_SECONDARY) && (role[NEW] == R_PRIMARY) ) {
				if(get_ldev_if_state(device, D_NEGOTIATING)) {
					bsr_md_set_flag (device, MDF_LAST_PRIMARY );
					put_ldev(device);
				}
			} else if( (peer_role[NEW] == R_PRIMARY) 
			|| ((role[NOW] == R_SECONDARY) && (resource->twopc_reply.primary_nodes != 0) // disk detach case || detach & reconnect daisy chain case
			// DW-1312 no clearing MDF_LAST_PRIMARY when primary_nodes of twopc_reply involves my node id.
			&& !(resource->twopc_reply.primary_nodes & NODE_MASK(resource->res_opts.node_id)))) { 
				if(get_ldev_if_state(device, D_NEGOTIATING)) {
					bsr_md_clear_flag (device, MDF_LAST_PRIMARY );
					put_ldev(device);
				}
			} 

			if (susp_nod[NEW]) {
				enum bsr_req_event what = NOTHING_EVENT;

				if (repl_state[OLD] < L_ESTABLISHED &&
				    conn_lowest_repl_state(connection) >= L_ESTABLISHED)
					what = RESEND;

#if 0
/* FIXME currently broken.
 * RESTART_FROZEN_DISK_IO may need a (temporary?) dedicated kernel thread */
				if ((disk_state[OLD] == D_ATTACHING || disk_state[OLD] == D_NEGOTIATING) &&
				    conn_lowest_disk(connection) == D_UP_TO_DATE)
					what = RESTART_FROZEN_DISK_IO;
#endif

				if (what != NOTHING_EVENT) {
					unsigned long irq_flags;

					/* Is this too early?  We should only
					 * resume after the iteration over all
					 * connections?
					 */
					begin_state_change(resource, &irq_flags, CS_VERBOSE);
					if (what == RESEND)
						connection->todo.req_next = TL_NEXT_REQUEST_RESEND;
					__change_io_susp_no_data(resource, false);
					end_state_change(resource, &irq_flags, __FUNCTION__);
				}
			}

			/* Became sync source.  With protocol >= 96, we still need to send out
			 * the sync uuid now. Need to do that before any bsr_send_state, or
			 * the other side may go "paused sync" before receiving the sync uuids,
			 * which is unexpected. */
			if (!(repl_state[OLD] == L_SYNC_SOURCE || repl_state[OLD] == L_PAUSED_SYNC_S) &&
			     (repl_state[NEW] == L_SYNC_SOURCE || repl_state[NEW] == L_PAUSED_SYNC_S) &&
			    connection->agreed_pro_version >= 96 && connection->agreed_pro_version < 110 &&
			    get_ldev(device)) {
				bsr_gen_and_send_sync_uuid(peer_device);
				put_ldev(device);
			}

			/* Do not change the order of the if above and the two below... */
			if (peer_disk_state[OLD] == D_DISKLESS &&
			    peer_disk_state[NEW] > D_DISKLESS && peer_disk_state[NEW] != D_UNKNOWN) {      /* attach on the peer */
				/* we probably will start a resync soon.
				 * make sure those things are properly reset. */
				peer_device->rs_total = 0;
				peer_device->rs_failed = 0;
				atomic_set(&peer_device->rs_pending_cnt, 0);
				bsr_rs_cancel_all(peer_device);

				bsr_send_uuids(peer_device, 0, 0, NOW);
				bsr_send_state(peer_device, new_state);
			}

			/* No point in queuing send_bitmap if we don't have a connection
			 * anymore, so check also the _current_ state, not only the new state
			 * at the time this work was queued. */

			// DW-1447 If the SEND_BITMAP_WORK_PENDING flag is set, also check the peer's repl_state. if L_WF_BITMAP_T, queuing send_bitmap().
			if (test_bit(SEND_BITMAP_WORK_PENDING, &peer_device->flags)) {
				if (repl_state[NEW] == L_WF_BITMAP_S && 
					((peer_device->repl_state[NOW] == L_WF_BITMAP_S && peer_device->last_repl_state == L_WF_BITMAP_T) ||
					// DW-2064 send bitmap when L_AHEAD is in state and wait_for_recv_bitmap is set
					(peer_device->repl_state[NOW] == L_AHEAD && atomic_read(&peer_device->wait_for_recv_bitmap)))) {
					send_bitmap = true;
					clear_bit(SEND_BITMAP_WORK_PENDING, &peer_device->flags);
				}
				else if (repl_state[NEW] != L_STARTING_SYNC_S && repl_state[NEW] != L_WF_BITMAP_S) {
					clear_bit(SEND_BITMAP_WORK_PENDING, &peer_device->flags);
				}
			}
			else if (repl_state[OLD] != L_WF_BITMAP_S && repl_state[NEW] == L_WF_BITMAP_S &&
					((peer_device->repl_state[NOW] == L_WF_BITMAP_S) ||
					// DW-2064 send bitmap when L_AHEAD is in state and wait_for_recv_bitmap is set
					(peer_device->repl_state[NOW] == L_AHEAD && atomic_read(&peer_device->wait_for_recv_bitmap)))) {
				send_bitmap = true;
			}

			// DW-1447
			if (send_bitmap) {
				bsr_queue_bitmap_io(device, &bsr_send_bitmap, &bsr_send_bitmap_source_complete,
						"send_bitmap (WFBitMapS)",
						BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK | BM_LOCK_SINGLE_SLOT | BM_LOCK_POINTLESS,
						peer_device);
			}

			if (repl_state[NEW] == L_WF_BITMAP_T &&
				peer_device->repl_state[NOW] == L_WF_BITMAP_T) {
				// DW-1447
				if (repl_state[OLD] == L_STARTING_SYNC_T)
					send_state = true;
				// DW-2026 if the status is not L_STARTING_SYNC_T, the status is not send.
				else
					bsr_info(28, BSR_LC_STATE, peer_device, "Not sending state because of old replication state(%s)", bsr_repl_str(repl_state[OLD]));
			}

			if (peer_disk_state[NEW] < D_INCONSISTENT && get_ldev(device)) {
				/* D_DISKLESS Peer becomes secondary */
				if (peer_role[OLD] == R_PRIMARY && peer_role[NEW] == R_SECONDARY)
					/* We may still be Primary ourselves.
					 * No harm done if the bitmap still changes,
					 * redirtied pages will follow later. */
					bsr_bitmap_io_from_worker(device, &bsr_bm_write,
						"demote diskless peer", BM_LOCK_CLEAR | BM_LOCK_BULK,
						NULL);
				put_ldev(device);
			}

			/* Write out all changed bits on demote.
			 * Though, no need to da that just yet
			 * if there is a resync going on still */
			if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY &&
				peer_device->repl_state[NOW] <= L_ESTABLISHED && get_ldev(device)) {
				/* No changes to the bitmap expected this time, so assert that,
				 * even though no harm was done if it did change. */
				bsr_bitmap_io_from_worker(device, &bsr_bm_write,
						"demote", BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,
						NULL);
				put_ldev(device);
			}

			/* Last part of the attaching process ... */
			if (repl_state[NEW] >= L_ESTABLISHED &&
			    disk_state[OLD] == D_ATTACHING && disk_state[NEW] >= D_NEGOTIATING) {
				bsr_send_sizes(peer_device, 0, 0);  /* to start sync... */
				bsr_send_uuids(peer_device, 0, 0, NOW);
				bsr_send_state(peer_device, new_state);
			}

			/* Started resync, tell peer if bsr9 */
			if (repl_state[NEW] >= L_SYNC_SOURCE && repl_state[NEW] <= L_PAUSED_SYNC_T &&
				(repl_state[OLD] < L_SYNC_SOURCE || repl_state[OLD] > L_PAUSED_SYNC_T))
				send_state = true;

			/* We want to pause/continue resync, tell peer. */			
			if (repl_state[NEW] >= L_ESTABLISHED &&
			     ((resync_susp_dependency[OLD] != resync_susp_dependency[NEW]) ||
			      (resync_susp_other_c[OLD] != resync_susp_other_c[NEW]) ||
			      (resync_susp_user[OLD] != resync_susp_user[NEW])))
				send_state = true;

			/* finished resync, tell sync source */
			if ((repl_state[OLD] == L_SYNC_TARGET || repl_state[OLD] == L_PAUSED_SYNC_T) &&
			    repl_state[NEW] == L_ESTABLISHED)
				send_state = true;

			/* In case one of the isp bits got set, suspend other devices. */
			if (!(resync_susp_dependency[OLD] || resync_susp_peer[OLD] || resync_susp_user[OLD]) &&
			     (resync_susp_dependency[NEW] || resync_susp_peer[NEW] || resync_susp_user[NEW]))
				suspend_other_sg(device);

			/* Make sure the peer gets informed about eventual state
			   changes (ISP bits) while we were in L_OFF. */
			if (repl_state[OLD] == L_OFF && repl_state[NEW] >= L_ESTABLISHED) {
				send_state = true;
			}

			if (repl_state[OLD] != L_AHEAD && repl_state[NEW] == L_AHEAD)
				send_state = true;

			/* We are in the progress to start a full sync. SyncTarget sets all slots. */
			if (repl_state[OLD] != L_STARTING_SYNC_T && repl_state[NEW] == L_STARTING_SYNC_T)
				bsr_queue_bitmap_io(device,
				// DW-1293
					&bsr_bmio_set_all_or_fast, &abw_start_sync,
					"set_n_write from StartingSync",
					BM_LOCK_CLEAR | BM_LOCK_BULK,
					peer_device);

			/* We are in the progress to start a full sync. SyncSource one slot. */
			if (repl_state[OLD] != L_STARTING_SYNC_S && repl_state[NEW] == L_STARTING_SYNC_S) {
				bsr_queue_bitmap_io(device,
				// DW-1293
					&bsr_bmio_set_all_or_fast, &abw_start_sync,
					"set_n_write from StartingSync",
					BM_LOCK_CLEAR | BM_LOCK_BULK,
					peer_device);
				// DW-1447
				set_bit(SEND_BITMAP_WORK_PENDING, &peer_device->flags);
			}


			/* Disks got bigger while they were detached */
			if (disk_state[NEW] > D_NEGOTIATING && peer_disk_state[NEW] > D_NEGOTIATING &&
			    test_and_clear_bit(RESYNC_AFTER_NEG, &peer_device->flags)) {
				if (repl_state[NEW] == L_ESTABLISHED)
					resync_after_online_grow(peer_device);
			}

			/* A resync finished or aborted, wake paused devices... */
			if ((repl_state[OLD] > L_ESTABLISHED && repl_state[NEW] <= L_ESTABLISHED) ||
			    (resync_susp_peer[OLD] && !resync_susp_peer[NEW]) ||
			    (resync_susp_user[OLD] && !resync_susp_user[NEW]))
				resume_next_sg(device);

			/* sync target done with resync. Explicitly notify all peers. Our sync
			   source should even know by himself, but the others need that info. */
			if (disk_state[OLD] < D_UP_TO_DATE && repl_state[OLD] >= L_SYNC_SOURCE && repl_state[NEW] == L_ESTABLISHED)
				send_new_state_to_all_peer_devices(state_change, n_device);

			// DW-885
			// DW-897
			// DW-907 We should notify our disk state when it goes unsyncable so that peer doesn't request to sync anymore.
			//Outdated myself, become D_INCONSISTENT, or became D_UP_TO_DATE tell peers 
			if (disk_state[OLD] >= D_OUTDATED && disk_state[NEW] >= D_INCONSISTENT &&
			    disk_state[NEW] != disk_state[OLD] && repl_state[NEW] >= L_ESTABLISHED)
				send_state = true;

			/* Skipped resync with peer_device, tell others... */
			if (send_state_others && send_state_others != peer_device)
				send_state = true;

			/* This triggers bitmap writeout of potentially still unwritten pages
			 * if the resync finished cleanly, or aborted because of peer disk
			 * failure, or on transition from resync back to AHEAD/BEHIND.
			 *
			 * Connection loss is handled in conn_disconnect() by the receiver.
			 *
			 * For resync aborted because of local disk failure, we cannot do
			 * any bitmap writeout anymore.
			 *
			 * No harm done if some bits change during this phase.
			 */
			if ((repl_state[OLD] > L_ESTABLISHED && repl_state[OLD] < L_AHEAD) &&
			    (repl_state[NEW] == L_ESTABLISHED || repl_state[NEW] >= L_AHEAD) &&
			    get_ldev(device)) {
				bsr_queue_bitmap_io(device, &bsr_bm_write_copy_pages, NULL,
					"write from resync_finished", BM_LOCK_BULK,
					NULL);
				put_ldev(device);
			}

			// BSR-118
			if (repl_state[OLD] != L_VERIFY_S && repl_state[NEW] == L_VERIFY_S) {
				if (peer_device->connection->agreed_pro_version >= 114 && isFastInitialSync()) {
					set_bit(OV_FAST_BM_SET_PENDING, &peer_device->flags);
					peer_device->fast_ov_work.w.cb = w_fast_ov_get_bm;
					bsr_queue_work(&resource->work, &peer_device->fast_ov_work.w);
				} else {
					ULONG_PTR ov_tw = bsr_ov_bm_total_weight(peer_device);
					bsr_info(150, BSR_LC_RESYNC_OV, peer_device, "Starting Online Verify as %s, bitmap_index(%d) start_sector(%llu) (will verify %llu KB [%llu bits set]).",
						bsr_repl_str(peer_device->repl_state[NEW]), peer_device->bitmap_index, (unsigned long long)peer_device->ov_start_sector,
						(unsigned long long)ov_tw << (BM_BLOCK_SHIFT - 10),
						(unsigned long long)ov_tw);

					mod_timer(&peer_device->resync_timer, jiffies);
				}
			}

			/* Verify finished, or reached stop sector.  Peer did not know about
			 * the stop sector, and we may even have changed the stop sector during
			 * verify to interrupt/stop early.  Send the new state. */
 			if ((repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) && 
				repl_state[NEW] == L_ESTABLISHED && verify_can_do_stop_sector(peer_device)) {
				// ov stop
				if (NULL != peer_device->fast_ov_bitmap) {
					// BSR-835
					kref_put(&peer_device->ov_bm_ref, bsr_free_ov_bm);
				}
				send_new_state_to_all_peer_devices(state_change, n_device);
			}

			if (disk_state[NEW] == D_DISKLESS &&
			    cstate[NEW] == C_STANDALONE &&
			    role[NEW] == R_SECONDARY) {
				if (resync_susp_dependency[OLD] != resync_susp_dependency[NEW])
					resume_next_sg(device);
			}

			if (device_stable[OLD] && !device_stable[NEW] &&
			    repl_state[NEW] >= L_ESTABLISHED && get_ldev(device)) {
				/* Inform peers about being unstable...
				   Maybe it would be a better idea to have the stable bit as
				   part of the state (and being sent with the state) */
				// DW-1359 I got unstable since one of my peer goes primary, start resync if need.
				bool bConsiderResync = false;

				if (peer_role[OLD] != R_PRIMARY && peer_role[NEW] == R_PRIMARY &&
					cstate[OLD] >= C_CONNECTED &&
					peer_disk_state[NEW] >= D_OUTDATED)
				{
					// DW-1359 initial sync will be started if both nodes are inconsistent and peer goes uptodate.
					if (peer_disk_state[OLD] != D_INCONSISTENT ||
						peer_disk_state[NEW] != D_UP_TO_DATE ||
						disk_state[OLD] != D_INCONSISTENT)
						bConsiderResync = true;
				}
				
				bsr_send_uuids(peer_device, bConsiderResync ? UUID_FLAG_AUTHORITATIVE : 0, 0, NOW);

				put_ldev(device);
			}

			if (send_state) {
				// BSR-937 fix avoid state change races between change_cluster_wide_state() and w_after_state_change()
				// set STATE_WORK_PENDING while sending state in w_after_state_change()
				wait_event(resource->state_work_wait, !test_and_set_bit(STATE_WORK_PENDING, &resource->flags));
				
				// BSR-937 init sync won't start if secondary state send after twopc commit primary state
				// fix to send role[NEW] state
				if ((enum bsr_role)new_state.role != resource->role[NEW])
					new_state.role = resource->role[NEW];
				
				bsr_send_state(peer_device, new_state);

				// BSR-937
				clear_bit(STATE_WORK_PENDING, &resource->flags);
				wake_up(&resource->state_work_wait);
			}
			if (!device_stable[OLD] && device_stable[NEW] &&
			    !(repl_state[OLD] == L_SYNC_TARGET || repl_state[OLD] == L_PAUSED_SYNC_T) &&
			    !(peer_role[OLD] == R_PRIMARY) && disk_state[NEW] >= D_OUTDATED &&
			    repl_state[NEW] >= L_ESTABLISHED &&
			    get_ldev(device)) {
				/* Offer all peers a resync, with the exception of ...
				   ... the node that made me up-to-date (with a resync)
				   ... I was primary
				   ... the peer that transitioned from primary to secondary
				*/
				// BSR-936 if device stable has been updated, send UUID information to "NEW"
				bsr_send_uuids(peer_device, UUID_FLAG_GOT_STABLE, 0, NEW);
				put_ldev(device);
			}
			// DW-1315 notify peer that I got stable, no resync available in this case.
			else if (!device_stable[OLD] && device_stable[NEW] &&
				repl_state[NEW] >= L_ESTABLISHED &&
				get_ldev(device))
			{
				// BSR-936 if device stable has been updated, send UUID information to "NEW"
				bsr_send_uuids(peer_device, 0, 0, NEW);
				put_ldev(device);
			}

			// DW-1315 I am still unstable but authoritative node's changed, need to notify peers.
			if(!device_stable[OLD] && !device_stable[NEW] &&
				authoritative[OLD] != authoritative[NEW] &&
				get_ldev(device)) {	
				// DW-1315 peer checks resync availability as soon as it gets UUID_FLAG_AUTHORITATIVE, and replies by sending uuid with both flags UUID_FLAG_AUTHORITATIVE and UUID_FLAG_RESYNC 
				// BSR-990 set the UUID send criteria to NEW because the change criteria for the authoritative node is NEW
				bsr_send_uuids(peer_device, (NODE_MASK(peer_device->node_id)&authoritative[NEW]) ? UUID_FLAG_AUTHORITATIVE : 0, 0, NEW);
				put_ldev(device);
			}

			// DW-1315 resync availability has been checked in finish_state_change(), abort resync here by changing replication state to L_ESTABLISHED.
			if (test_and_clear_bit(RESYNC_ABORTED, &peer_device->flags)) {
				bsr_info(152, BSR_LC_RESYNC_OV, peer_device, "Resync will be aborted due to change of state.");

				if (repl_state[NOW] > L_ESTABLISHED) {
					unsigned long irq_flags;
					begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
					__change_repl_state_and_auto_cstate(peer_device, L_ESTABLISHED, __FUNCTION__);
					end_state_change(device->resource, &irq_flags, __FUNCTION__);
				}
			}

			if (peer_disk_state[OLD] == D_UP_TO_DATE &&
			    (peer_disk_state[NEW] == D_FAILED || peer_disk_state[NEW] == D_INCONSISTENT) &&
				test_and_clear_bit(NEW_CUR_UUID, &device->flags)) {
				bsr_info(38, BSR_LC_UUID, device, "clear the UUID creation flag with peer node disk settings and attempt to create a UUID");
				/* When a peer disk goes from D_UP_TO_DATE to D_FAILED or D_INCONSISTENT
				   we know that a write failed on that node. Therefore we need to create
				   the new UUID right now (not wait for the next write to come in) */
				bsr_uuid_new_current(device, false, false, __FUNCTION__);
			}


			if (device->susp_quorum[NEW] && got_contact_to_peer_data(peer_disk_state) &&
				get_ldev(device)) {
				bool have_quorum = calc_quorum(device, NEW, NULL);
				if (have_quorum) {
					unsigned long irq_flags;

					if (test_bit(NEW_CUR_UUID, &device->flags)){
						bsr_info(39, BSR_LC_UUID, device, "clear the UUID creation flag");
					}
					clear_bit(NEW_CUR_UUID, &device->flags);

					begin_state_change(resource, &irq_flags, CS_VERBOSE);
					_tl_restart(connection, RESEND);
					__change_io_susp_quorum(device, false);
					end_state_change(resource, &irq_flags, __FUNCTION__);
				}
				put_ldev(device);
			}

			// DW-1145 propagate uuid when I got connected with primary and established state.
			if (repl_state[OLD] < L_ESTABLISHED &&
				repl_state[NEW] >= L_ESTABLISHED &&
				peer_role[NEW] == R_PRIMARY)
				bsr_propagate_uuids(device, ~NODE_MASK(peer_device->node_id));
		}


		/* Make sure the effective disk size is stored in the metadata
		 * if a local disk is attached and either the local disk state
		 * or a peer disk state is D_UP_TO_DATE.  */
		if (effective_disk_size_determined && get_ldev(device)) {
			sector_t size = bsr_get_vdisk_capacity(device);
			if (device->ldev->md.effective_size != size) {
				char ppb[10];

				bsr_info(95, BSR_LC_VOLUME, device, "Update the disk size in the meta. %s (%llu KB)", ppsize(ppb, sizeof(ppb), size >> 1),
				     (unsigned long long)size >> 1);
				device->ldev->md.effective_size = size;
				bsr_md_mark_dirty(device);
			}
			put_ldev(device);
		}

		/* first half of local IO error, failure to attach,
		 * or administrative detach */
		if ((disk_state[OLD] != D_FAILED && disk_state[NEW] == D_FAILED) ||
		    (disk_state[OLD] != D_DETACHING && disk_state[NEW] == D_DETACHING)) {
			enum bsr_io_error_p eh = EP_PASS_ON;
			int was_io_error = 0;

			/* Our cleanup here with the transition to D_DISKLESS.
			 * It is still not safe to dereference ldev here, since
			 * we might come from an failed Attach before ldev was set. */
			if (expect(device, device_state_change->have_ldev) && device->ldev) {
				rcu_read_lock();
				eh = rcu_dereference(device->ldev->disk_conf)->on_io_error;
				rcu_read_unlock();

				was_io_error = disk_state[NEW] == D_FAILED;

				/* Intentionally call this handler first, before bsr_send_state().
				 * See: 2932204 bsr: call local-io-error handler early
				 * People may chose to hard-reset the box from this handler.
				 * It is useful if this looks like a "regular node crash". */
				if (was_io_error && eh == EP_CALL_HELPER)
					bsr_khelper(device, NULL, "local-io-error");

				/* Immediately allow completion of all application IO,
				 * that waits for completion from the local disk,
				 * if this was a force-detach due to disk_timeout
				 * or administrator request (bsrsetup detach --force).
				 * Do NOT abort otherwise.
				 * Aborting local requests may cause serious problems,
				 * if requests are completed to upper layers already,
				 * and then later the already submitted local bio completes.
				 * This can cause DMA into former bio pages that meanwhile
				 * have been re-used for other things.
				 * So aborting local requests may cause crashes,
				 * or even worse, silent data corruption.
				 */
				if (test_and_clear_bit(FORCE_DETACH, &device->flags))
					tl_abort_disk_io(device);

				send_new_state_to_all_peer_devices(state_change, n_device);

				for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
					struct bsr_peer_device_state_change *peer_device_state_change =
						&state_change->peer_devices[
							n_device * state_change->n_connections + n_connection];
					struct bsr_peer_device *peer_device = peer_device_state_change->peer_device;
					bsr_rs_cancel_all(peer_device);
				}

				/* In case we want to get something to stable storage still,
				 * this may be the last chance.
				 * Following put_ldev may transition to D_DISKLESS. */
				bsr_md_sync_if_dirty(device);
			}
		}

		/* second half of local IO error, failure to attach,
		 * or administrative detach,
		 * after local_cnt references have reached zero again */
		if (disk_state[OLD] != D_DISKLESS && disk_state[NEW] == D_DISKLESS) {
			/* We must still be diskless,
			 * re-attach has to be serialized with this! */
			if (device->disk_state[NOW] != D_DISKLESS)
				bsr_err(30, BSR_LC_STATE, device,
					"ASSERT FAILED: disk is %s while going diskless",
					bsr_disk_str(device->disk_state[NOW]));

			/* we may need to cancel the md_sync timer */
			del_timer_sync(&device->md_sync_timer);

			if (expect(device, device_state_change->have_ldev))
				send_new_state_to_all_peer_devices(state_change, n_device);
		}

		if (device_state_change->have_ldev)
			put_ldev(device);

		/* Notify peers that I had a local IO error and did not detach. */
		if (disk_state[OLD] == D_UP_TO_DATE && disk_state[NEW] == D_INCONSISTENT)
			send_new_state_to_all_peer_devices(state_change, n_device);

		if (disk_state[OLD] == D_UP_TO_DATE && disk_state[NEW] == D_CONSISTENT)
			try_become_up_to_date = true;

		bsr_md_sync_if_dirty(device);

		if (!susp_quorum[OLD] && susp_quorum[NEW])
			bsr_khelper(device, NULL, "quorum-lost");
	}

	if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY)
		send_role_to_all_peers(state_change);

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_connection_state_change *connection_state_change = &state_change->connections[n_connection];
		struct bsr_connection *connection = connection_state_change->connection;
		enum bsr_conn_state *cstate = connection_state_change->cstate;
		enum bsr_role *peer_role = connection_state_change->peer_role;
		bool *susp_fen = connection_state_change->susp_fen;

		/* Upon network configuration, we need to start the receiver */
		if (cstate[OLD] == C_STANDALONE && cstate[NEW] == C_UNCONNECTED) 
			bsr_thread_start(&connection->receiver);

		if (susp_fen[NEW])
			check_may_resume_io_after_fencing(state_change, n_connection);

		if (peer_role[OLD] == R_PRIMARY &&
			// DW-891
			cstate[OLD] == C_CONNECTED && cstate[NEW] >= C_TIMEOUT && cstate[NEW] <= C_PROTOCOL_ERROR) {
			/* A connection to a primary went down, notify other peers about that */
			notify_peers_lost_primary(connection);
		}
	}

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct bsr_connection_state_change *connection_state_change = &state_change->connections[n_connection];
		enum bsr_conn_state *cstate = connection_state_change->cstate;

		if (cstate[NEW] == C_CONNECTED || cstate[NEW] == C_CONNECTING)
			still_connected = true;
	}

	if (try_become_up_to_date)
		bsr_post_work(resource, TRY_BECOME_UP_TO_DATE);

	if (!still_connected)
		mod_timer_pending(&resource->twopc_timer, jiffies);

	if (work->done)
		complete(work->done);
	forget_state_change(state_change);
	bsr_kfree(work);

	return 0;
}

static inline bool local_state_change(enum chg_state_flags flags)
{
	return flags & (CS_HARD | CS_LOCAL_ONLY);
}

static enum bsr_state_rv
__peer_request(struct bsr_connection *connection, int vnr,
	       union bsr_state mask, union bsr_state val)
{
	enum bsr_state_rv rv = SS_SUCCESS;

	if (connection->cstate[NOW] == C_CONNECTED) {
		enum bsr_packet cmd = (vnr == -1) ? P_CONN_ST_CHG_REQ : P_STATE_CHG_REQ;
		if (!conn_send_state_req(connection, vnr, cmd, mask, val)) {
			set_bit(TWOPC_PREPARED, &connection->flags);
			rv = SS_CW_SUCCESS;
		}
	}
	return rv;
}

static enum bsr_state_rv __peer_reply(struct bsr_connection *connection)
{
	if (test_and_clear_bit(TWOPC_NO, &connection->flags))
		return SS_CW_FAILED_BY_PEER;
	if (test_and_clear_bit(TWOPC_YES, &connection->flags) ||
	    !test_bit(TWOPC_PREPARED, &connection->flags))
		return SS_CW_SUCCESS;

	/* This is BSR 9.x <-> 8.4 compat code.
	 * Consistent with __peer_request() above:
	 * No more connection: fake success. */
	if (connection->cstate[NOW] != C_CONNECTED)
		return SS_SUCCESS;
	return SS_UNKNOWN_ERROR;
}

static bool when_done_lock(struct bsr_resource *resource,
			   unsigned long *irq_flags)
{
	spin_lock_irqsave(&resource->req_lock, *irq_flags);
	if (!resource->remote_state_change && resource->twopc_work.cb == NULL)
		return true;
	spin_unlock_irqrestore(&resource->req_lock, *irq_flags);
	return false;
}

/**
 * complete_remote_state_change  -  Wait for other remote state changes to complete
 */
static void complete_remote_state_change(struct bsr_resource *resource,
					 unsigned long *irq_flags)
{
	if (resource->remote_state_change) {
		enum chg_state_flags flags = resource->state_change_flags;

		begin_remote_state_change(resource, irq_flags);
		for(;;) {
			long t = twopc_timeout(resource);

			wait_event_timeout_ex(resource->twopc_wait, when_done_lock(resource, irq_flags), t, t);

			if (t) {
				break;
			} else { // DW-1073 The condition evaluated to false after the timeout elapsed, stop waiting for remote state change.
				// DW-1414 need to acquire req_lock while accessing twopc_parents list.
				spin_lock_irq(&resource->req_lock);
				__clear_remote_state_change(resource);
				spin_unlock_irq(&resource->req_lock);
				twopc_end_nested(resource, P_TWOPC_NO, true);
			}

			if (when_done_lock(resource, irq_flags)) {
				bsr_info(33, BSR_LC_TWOPC, resource, "Two-phase commit: "
					  "not woken up in time");
				break;
			}
		}
		__end_remote_state_change(resource, flags);
	}
}

static enum bsr_state_rv
change_peer_state(struct bsr_connection *connection, int vnr,
		  union bsr_state mask, union bsr_state val, unsigned long *irq_flags)
{
	struct bsr_resource *resource = connection->resource;
	enum chg_state_flags flags = resource->state_change_flags | CS_TWOPC;
	enum bsr_state_rv rv;

	if (!expect(resource, flags & CS_SERIALIZE))
		return SS_CW_FAILED_BY_PEER;

	complete_remote_state_change(resource, irq_flags);

	resource->remote_state_change = true;
	resource->twopc_reply.initiator_node_id = resource->res_opts.node_id;
	resource->twopc_reply.tid = 0;
	begin_remote_state_change(resource, irq_flags);
	rv = __peer_request(connection, vnr, mask, val);
	if (rv == SS_CW_SUCCESS) {
		wait_event(resource->state_wait,
			((rv = __peer_reply(connection)) != SS_UNKNOWN_ERROR));
		clear_bit(TWOPC_PREPARED, &connection->flags);
	}
	end_remote_state_change(resource, irq_flags, flags);
	return rv;
}

// DW-2029
static enum bsr_state_rv
conn_send_twopc(struct bsr_resource *resource, struct bsr_connection *connection, struct p_twopc_request *request,
			int vnr, enum bsr_packet cmd, u64 reach_immediately)
{
	u64 mask;
	enum bsr_state_rv rv = SS_SUCCESS;

	clear_bit(TWOPC_PREPARED, &connection->flags);

	if (connection->agreed_pro_version < 110)
		return rv;

	mask = NODE_MASK(connection->peer_node_id);
	if (reach_immediately & mask)
		set_bit(TWOPC_PREPARED, &connection->flags);
	else
		return rv;

	clear_bit(TWOPC_YES, &connection->flags);
	clear_bit(TWOPC_NO, &connection->flags);
	clear_bit(TWOPC_RETRY, &connection->flags);

	if (!conn_send_twopc_request(connection, vnr, cmd, request)) {
		rv = SS_CW_SUCCESS;
	}
	else {
		clear_bit(TWOPC_PREPARED, &connection->flags);
		wake_up(&resource->work.q_wait);
	}
	
	return rv;
}

static enum bsr_state_rv
__cluster_wide_request(struct bsr_resource *resource, int vnr, enum bsr_packet cmd,
		       struct p_twopc_request *request, u64 reach_immediately)
{
	struct bsr_connection *connection;
	enum bsr_state_rv rv = SS_SUCCESS;
	u64 im;
	unsigned int target_node_id = be32_to_cpu(request->target_node_id);

	// DW-2029 send a twopc request to target node first
	if (target_node_id != -1) {
		connection = bsr_connection_by_node_id(resource, target_node_id);
		if (connection) {
			if (SS_SUCCESS != conn_send_twopc(resource, connection, request, vnr, cmd, reach_immediately))
				rv = SS_CW_SUCCESS;
		}
	}

	// send to other nodes
	for_each_connection_ref(connection, im, resource) {
		if (target_node_id != -1 && target_node_id == connection->peer_node_id)
			continue;

		if (SS_SUCCESS != conn_send_twopc(resource, connection, request, vnr, cmd, reach_immediately))
			rv = SS_CW_SUCCESS;
	}
	return rv;
}

bool cluster_wide_reply_ready(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	bool ready = true;

	if (test_bit(TWOPC_ABORT_LOCAL, &resource->flags))
		return ready;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (!test_bit(TWOPC_PREPARED, &connection->flags))
			continue;
		if(test_bit(TWOPC_NO, &connection->flags) ||
			test_bit(TWOPC_RETRY, &connection->flags)) {
			bsr_debug(55, BSR_LC_TWOPC, connection, "Reply not ready yet");
			ready = true;
			break;
		}
		if (!test_bit(TWOPC_YES, &connection->flags))
			ready = false; 

	}
	rcu_read_unlock();
	return ready;
}

static enum bsr_state_rv get_cluster_wide_reply(struct bsr_resource *resource,
struct change_context *context, bool bDisconnecting)
{
	struct bsr_connection *connection, *failed_by = NULL;
	enum bsr_state_rv rv = SS_CW_SUCCESS;

	if (test_bit(TWOPC_ABORT_LOCAL, &resource->flags))
		return SS_CONCURRENT_ST_CHG;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (!test_bit(TWOPC_PREPARED, &connection->flags))
			continue;
		if (test_bit(TWOPC_NO, &connection->flags)) {
			// BSR-797 if a connection error occurs during connection termination twopc processing, TOWPC_NO is ignored..
			// this is because when all nodes are terminated at the same time, the other node is terminated first during the twopc process and causes an error.
			if (!(bDisconnecting && 
				connection->cstate[NOW] <= C_TEAR_DOWN && connection->cstate[NOW] >= C_TIMEOUT)) {
				failed_by = connection;
				rv = SS_CW_FAILED_BY_PEER;
			}
			else {
				bsr_info(57, BSR_LC_TWOPC, connection, "ignore the connection with the connection error among the twopc results of disconnecting.");
			}
		}
		if (test_bit(TWOPC_RETRY, &connection->flags)) {
			rv = SS_CONCURRENT_ST_CHG;
			break;
		}
	}
	if (rv == SS_CW_FAILED_BY_PEER && context)
		_bsr_state_err(context, "Declined by peer %s (id: %d), see the kernel log there",
		rcu_dereference((failed_by)->transport.net_conf)->name,
		failed_by->peer_node_id);
	rcu_read_unlock();
	return rv;
}

static bool supports_two_phase_commit(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	bool supported = true;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] != C_CONNECTED)
			continue;
		if (connection->agreed_pro_version < 110) {
			supported = false;
			break;
		}
	}
	rcu_read_unlock();

	return supported;
}

static struct bsr_connection *get_first_connection(struct bsr_resource *resource)
{
	struct bsr_connection *connection = NULL;

	rcu_read_lock();
	if (!list_empty(&resource->connections)) {
		connection = first_connection(resource);
		kref_get(&connection->kref);
	}
	rcu_read_unlock();
	return connection;
}

/* Think: Can this be replaced by a call to __is_valid_soft_transition() */
static enum bsr_state_rv primary_nodes_allowed(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	enum bsr_state_rv rv = SS_SUCCESS;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		u64 mask;

		/* If this peer is primary as well, the config must allow it. */
		mask = NODE_MASK(connection->peer_node_id);
		if ((resource->twopc_reply.primary_nodes & mask) &&
		    !(connection->transport.net_conf->two_primaries)) {
			rv = SS_TWO_PRIMARIES;
			break;
		}
	}
	rcu_read_unlock();
	return rv;
}

static enum bsr_state_rv
check_primaries_distances(struct bsr_resource *resource)
{
	struct twopc_reply *reply = &resource->twopc_reply;
	u64 common_server;
	int node_id;


	/* All primaries directly connected. Good */
	if (!(reply->primary_nodes & reply->weak_nodes))
		return SS_SUCCESS;

	/* For virtualisation setups with diskless hypervisors (R_PRIMARY) and one
	 or multiple storage servers (R_SECONDAY) allow live-migration between the
	 hypervisors. */
	common_server = ~reply->weak_nodes;
	if (common_server) {
		/* Only allow if the new primary is diskless. See also far_away_change()
		 in bsr_receiver.c for the diskless check on the other primary */
		if ((reply->primary_nodes & NODE_MASK(resource->res_opts.node_id)) &&
			bsr_have_local_disk(resource))
			return SS_WEAKLY_CONNECTED;

		for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
			struct bsr_connection *connection;
			struct net_conf *nc;
			bool two_primaries;

			if (!(common_server & NODE_MASK(node_id)))
				continue;
			connection = bsr_connection_by_node_id(resource, node_id);
			if (!connection)
				continue;

			rcu_read_lock();
			nc = rcu_dereference(connection->transport.net_conf);
			two_primaries = nc ? nc->two_primaries : false;
			rcu_read_unlock();

			if (!two_primaries)
				return SS_TWO_PRIMARIES;
		}
		return SS_SUCCESS;
	}
	return SS_WEAKLY_CONNECTED;
}


long twopc_retry_timeout(struct bsr_resource *resource, int retries)
{
	struct bsr_connection *connection;
	int connections = 0;
	long timeout = 0;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] < C_CONNECTING)
			continue;
		connections++;
	}
	rcu_read_unlock();

	if (connections > 0) {
		if (retries > 5)
			retries = 5;
		timeout = resource->res_opts.twopc_retry_timeout *
			  HZ / 10 * connections * (1 << retries);
		timeout = prandom_u32() % timeout;
	}
	return timeout;
}

static void twopc_phase2(struct bsr_resource *resource, int vnr,
			 bool success,
			 struct p_twopc_request *request,
			 u64 reach_immediately)
{
	enum bsr_packet twopc_cmd = success ? P_TWOPC_COMMIT : P_TWOPC_ABORT;
	struct bsr_connection *connection;
	u64 im;

	// DW-2093
	//unsigned int target_node_id = be32_to_cpu(request->target_node_id);
	
	// DW-2093 rollback DW-2029 modifications due to timing problems.
	// DW-2029 send a twopc request to target node first
	//if (target_node_id != -1) {
	//	connection = drbd_connection_by_node_id(resource, target_node_id);
	//	if (connection && (reach_immediately & NODE_MASK(connection->peer_node_id)))
	//		conn_send_twopc_request(connection, vnr, twopc_cmd, request);
	//}

	// send to other nodes
	for_each_connection_ref(connection, im, resource) {
		u64 mask = NODE_MASK(connection->peer_node_id);

		// DW-2029
		//if (target_node_id != -1 && target_node_id == connection->peer_node_id)
		//	continue;

		if (!(reach_immediately & mask))
			continue;

		conn_send_twopc_request(connection, vnr, twopc_cmd, request);
	}
}

/**
 * change_cluster_wide_state  -  Cluster-wide two-phase commit
 *
 * Perform a two-phase commit transaction among all (reachable) nodes in the
 * cluster.  In our transaction model, the initiator of a transaction is also
 * the coordinator.
 *
 * In phase one of the transaction, the coordinator sends all nodes in the
 * cluster a P_TWOPC_PREPARE packet.  Each node replies with either P_TWOPC_YES
 * if it consents or with P_TWOPC_NO if it denies the transaction.  Once all
 * replies have been received, the coordinator sends all nodes in the cluster a
 * P_TWOPC_COMMIT or P_TWOPC_ABORT packet to finish the transaction.
 *
 * When a node in the cluster is busy with another transaction, it replies with
 * P_TWOPC_NO.  The coordinator is then responsible for retrying the
 * transaction.
 *
 * Since a cluster is not guaranteed to always be fully connected, some nodes
 * will not be directly reachable from other nodes.  In order to still reach
 * all nodes in the cluster, participants will forward requests to nodes which
 * haven't received the request yet:
 *
 * The nodes_to_reach field in requests indicates which nodes have received the
 * request already.  Before forwarding a request to a peer, a node removes
 * itself from nodes_to_reach; it then sends the request to all directly
 * connected nodes in nodes_to_reach.
 *
 * If there are redundant paths in the cluster, requests will reach some nodes
 * more than once.  Nodes remember when they are taking part in a transaction;
 * they detect duplicate requests and reply to them with P_TWOPC_YES packets.
 * (Transactions are identified by the node id of the initiator and a random,
 * unique-enough transaction identifier.)
 *
 * A configurable timeout determines how long a coordinator or participant will
 * wait for a transaction to finish.  A transaction that times out is assumed
 * to have aborted.
 */
static enum bsr_state_rv
change_cluster_wide_state(bool (*change)(struct change_context *, enum change_phase),
						struct change_context *context, const char* caller)
{
	struct bsr_resource *resource = context->resource;
	unsigned long irq_flags;
	struct p_twopc_request request;
	struct twopc_reply *reply = &resource->twopc_reply;
	struct bsr_connection *connection, *target_connection = NULL;
	enum bsr_state_rv rv;
	u64 reach_immediately;
	// DW-1204 twopc is for disconnecting.
	bool bDisconnecting = false;
    ULONG_PTR start_time;
	bool have_peers;

	begin_state_change(resource, &irq_flags, context->flags | CS_LOCAL_ONLY);
	resource->state_change_err_str = context->err_str;

	if (local_state_change(context->flags)) {
		/* Not a cluster-wide state change. */       
		change(context, PH_LOCAL_COMMIT);
		return end_state_change(resource, &irq_flags, caller);
	} else {
		if (!change(context, PH_PREPARE)) {
			/* Not a cluster-wide state change. */
			return end_state_change(resource, &irq_flags, caller);
		}
		rv = try_state_change(resource);
		if (rv != SS_SUCCESS) {
			/* Failure or nothing to do. */
			/* abort_state_change(resource, &irq_flags); */
			if (rv == SS_NOTHING_TO_DO)
				resource->state_change_flags &= ~CS_VERBOSE;
			return __end_state_change(resource, &irq_flags, rv, caller);
		}
		/* Really a cluster-wide state change. */
	}

	if (!supports_two_phase_commit(resource)) {
		connection = get_first_connection(resource);
		rv = SS_SUCCESS;
		if (connection) {
			kref_debug_get(&connection->kref_debug, 6);
			rv = change_peer_state(connection, context->vnr, context->mask, context->val, &irq_flags);
			kref_debug_put(&connection->kref_debug, 6);
			kref_put(&connection->kref, bsr_destroy_connection);
		}
		if (rv >= SS_SUCCESS)
			change(context, PH_84_COMMIT);
		return __end_state_change(resource, &irq_flags, rv, caller);
	}

	if (!expect(resource, context->flags & CS_SERIALIZE)) {
		rv = SS_CW_FAILED_BY_PEER;
		return __end_state_change(resource, &irq_flags, rv, caller);
	}

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (!expect(connection, current != connection->receiver.task) ||
		    !expect(connection, current != connection->ack_receiver.task)) {
			BUG();
		}
	}
	rcu_read_unlock();

	if (current == resource->worker.task && resource->remote_state_change) {
		return __end_state_change(resource, &irq_flags, SS_CONCURRENT_ST_CHG, caller);
	}

	complete_remote_state_change(resource, &irq_flags);
	start_time = jiffies;
	resource->state_change_err_str = context->err_str;

	reach_immediately = directly_connected_nodes(resource, NOW);
	if (context->target_node_id != -1) {
		struct bsr_connection *connection;

		/* Fail if the target node is no longer directly reachable. */
		connection = bsr_get_connection_by_node_id(resource, context->target_node_id);
		if (!connection) {
			rv = SS_CW_FAILED_BY_PEER;
			return __end_state_change(resource, &irq_flags, rv, caller);
		}
		kref_debug_get(&connection->kref_debug, 8);

		if (!(connection->cstate[NOW] == C_CONNECTED ||
		      (connection->cstate[NOW] == C_CONNECTING &&
		       context->mask.conn == conn_MASK &&
		       context->val.conn == C_CONNECTED))) {
			rv = SS_CW_FAILED_BY_PEER;

			kref_debug_put(&connection->kref_debug, 8);
			kref_put(&connection->kref, bsr_destroy_connection);
			return __end_state_change(resource, &irq_flags, rv, caller);
		}
		target_connection = connection;

		// DW-1204 clear disconnect_flush flag when starting twopc and got target connection.
		clear_bit(DISCONNECT_FLUSH, &target_connection->transport.flags);

		/* For connect transactions, add the target node id. */
		reach_immediately |= NODE_MASK(context->target_node_id);
	}

	do
		reply->tid = prandom_u32();
	while (!reply->tid);

	request.tid = cpu_to_be32(reply->tid);
	request.initiator_node_id = cpu_to_be32(resource->res_opts.node_id);
	request.target_node_id = cpu_to_be32(context->target_node_id);
	request.nodes_to_reach = cpu_to_be64(
		~(reach_immediately | NODE_MASK(resource->res_opts.node_id)));
	request.primary_nodes = 0;  /* Computed in phase 1. */
	request.mask = cpu_to_be32(context->mask.i);
	request.val = cpu_to_be32(context->val.i);

	bsr_info(34, BSR_LC_TWOPC, resource, "Preparing cluster-wide state change %u (%u->%d %u/%u)",
			be32_to_cpu(request.tid),
		  	resource->res_opts.node_id,
		  	context->target_node_id,
		  	context->mask.i,
		  	context->val.i);

	bsr_info(35, BSR_LC_TWOPC, resource, "[TWOPC:%u] target_node_id(%d) conn(%s) repl(%s) disk(%s) pdsk(%s) role(%s) peer(%s) flags (%d) ",
				be32_to_cpu(request.tid),
				context->target_node_id,
				context->mask.conn == conn_MASK ? bsr_conn_str(context->val.conn) : "-",
				context->mask.conn == conn_MASK ? ((context->val.conn < conn_MASK && context->val.conn > C_CONNECTED) ? bsr_repl_str(context->val.conn) : "-") : "-",
				context->mask.disk == disk_MASK ? bsr_disk_str(context->val.disk) : "-",
				context->mask.pdsk == pdsk_MASK ? bsr_disk_str(context->val.pdsk) : "-",
				context->mask.role == role_MASK ? bsr_role_str(context->val.role) : "-",
				context->mask.peer == peer_MASK ? bsr_role_str(context->val.peer) : "-",
				context->flags);

		  
	resource->remote_state_change = true;
	resource->twopc_parent_nodes = 0;
	resource->twopc_type = TWOPC_STATE_CHANGE;
	reply->initiator_node_id = resource->res_opts.node_id;
	reply->target_node_id = context->target_node_id;
	reply->primary_nodes = 0;
	reply->weak_nodes = 0;

	reply->reachable_nodes = directly_connected_nodes(resource, NOW) |
				       NODE_MASK(resource->res_opts.node_id);
	if (context->mask.conn == conn_MASK && context->val.conn == C_CONNECTED) {
		reply->reachable_nodes |= NODE_MASK(context->target_node_id);
		reply->target_reachable_nodes = reply->reachable_nodes;
	} else if (context->mask.conn == conn_MASK && context->val.conn == C_DISCONNECTING) {
		reply->target_reachable_nodes = NODE_MASK(context->target_node_id);
		reply->reachable_nodes &= ~reply->target_reachable_nodes;
		// DW-1204 this twopc is for disconnecting.
		bDisconnecting = true;
	} else {
		reply->target_reachable_nodes = reply->reachable_nodes;
	}

	D_ASSERT(resource, resource->twopc_work.cb == NULL);
	begin_remote_state_change(resource, &irq_flags);
	rv = __cluster_wide_request(resource, context->vnr, P_TWOPC_PREPARE,
				    &request, reach_immediately);
	have_peers = rv == SS_CW_SUCCESS;
	if (have_peers) {
		long t = 0;
		wait_event_timeout_ex(resource->state_wait,
								cluster_wide_reply_ready(resource),
								twopc_timeout(resource), t);
        if (t) {
			rv = get_cluster_wide_reply(resource, context, bDisconnecting);
			bsr_info(36, BSR_LC_TWOPC, resource, "[TWOPC:%u] target_node_id(%d) get_cluster_wide_reply (%d) ",
						reply->tid,
						context->target_node_id, 
						rv);
		}
		else
			rv = SS_TIMEOUT;

		if (rv == SS_CW_SUCCESS) {
			u64 directly_reachable =
				directly_connected_nodes(resource, NOW) |
				NODE_MASK(resource->res_opts.node_id);

			if (context->mask.conn == conn_MASK) {
				if (context->val.conn == C_CONNECTED)
					directly_reachable |= NODE_MASK(context->target_node_id);
				if (context->val.conn == C_DISCONNECTING)
					directly_reachable &= ~NODE_MASK(context->target_node_id);
			}
			if ((context->mask.role == role_MASK && context->val.role == R_PRIMARY) ||
			    (context->mask.role != role_MASK && resource->role[NOW] == R_PRIMARY)) {
				reply->primary_nodes |=
					NODE_MASK(resource->res_opts.node_id);
				reply->weak_nodes |= ~directly_reachable;
			}
			bsr_info(37, BSR_LC_TWOPC, resource, "State change %u: primary_nodes=%lX, weak_nodes=%lX",
				  reply->tid, (unsigned long)reply->primary_nodes,
				  (unsigned long)reply->weak_nodes);
			if (context->mask.role == role_MASK && context->val.role == R_PRIMARY)
				rv = primary_nodes_allowed(resource);
			if ((context->mask.role == role_MASK && context->val.role == R_PRIMARY) ||
				(context->mask.conn == conn_MASK && context->val.conn == C_CONNECTED))
				rv = check_primaries_distances(resource);

			// DW-1231 not allowed multiple primaries.
			if (context->target_node_id != -1 && (reply->primary_nodes & NODE_MASK(context->target_node_id))) {
				rcu_read_lock();
				for_each_connection_rcu(connection, resource) {
					if (connection->peer_node_id != (unsigned int)context->target_node_id) {
						if (connection->peer_role[NOW] == R_PRIMARY) {
							rv = SS_TWO_PRIMARIES;
							break;
						}
					}
				}
				rcu_read_unlock();
			}

			if (!(context->mask.conn == conn_MASK && context->val.conn == C_DISCONNECTING) ||
			    (reply->reachable_nodes & reply->target_reachable_nodes)) {
				/* The cluster is still connected after this
				 * transaction: either this transaction does
				 * not disconnect a connection, or there are
				 * redundant connections.  */

				u64 m;

				m = reply->reachable_nodes | reply->target_reachable_nodes;
				reply->reachable_nodes = m;
				reply->target_reachable_nodes = m;
			} else {
				rcu_read_lock();
				for_each_connection_rcu(connection, resource) {
					int node_id = connection->peer_node_id;

					if (node_id == context->target_node_id) {
						bsr_info(38, BSR_LC_TWOPC, connection, "Cluster is now split");
						break;
					}
				}
				rcu_read_unlock();
			}
			request.primary_nodes = cpu_to_be64(reply->primary_nodes);
		}
	}
	
	// DW-1204 sending twopc prepare needs to wait crowded send buffer, takes too much time. no more retry.
	if (bDisconnecting 
		&& (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG))	// DW-1705 set C_DISCONNECT when the result value is SS_CONCURRENT_ST_CHG
		 
	{
		bsr_warn(49, BSR_LC_TWOPC, resource, "twopc timeout occurred, no more retries");
		
		if (target_connection) {
			kref_debug_put(&target_connection->kref_debug, 8);
			kref_put(&target_connection->kref, bsr_destroy_connection);
			target_connection = NULL;
		}

		clear_remote_state_change(resource);
		end_remote_state_change(resource, &irq_flags, context->flags);
		context->flags |= CS_HARD;
		change(context, PH_COMMIT);
		return end_state_change(resource, &irq_flags, caller);
	}

	if ((rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG) &&
	    !(context->flags & CS_DONT_RETRY)) {
		if (have_peers)
			twopc_phase2(resource, context->vnr, 0, &request, reach_immediately);
		if (target_connection) {
			kref_debug_put(&target_connection->kref_debug, 8);
			kref_put(&target_connection->kref, bsr_destroy_connection);
			target_connection = NULL;
		}

		clear_remote_state_change(resource);
		end_remote_state_change(resource, &irq_flags, context->flags | CS_TWOPC);
		abort_state_change(resource, &irq_flags, caller);
		// DW-1545 Modified to not display error messages and errors to users
		rv = SS_NOTHING_TO_DO; 
		return rv;
	}


	// DW-1204 twopc prepare has been sent, I must send twopc commit also, need to flush send buffer.
	if (bDisconnecting &&
		target_connection)
		set_bit(DISCONNECT_FLUSH, &target_connection->transport.flags);

	if (rv >= SS_SUCCESS)
		bsr_info(39, BSR_LC_TWOPC, resource, "Committing cluster-wide state change %u (%ums) (%u->%d)",
			  be32_to_cpu(request.tid),
			  jiffies_to_msecs(jiffies - start_time),
			  resource->res_opts.node_id,
			  context->target_node_id);

	else
		bsr_info(40, BSR_LC_TWOPC, resource, "Aborting cluster-wide state change %u (%ums) rv = %d (%u->%d)",
			  be32_to_cpu(request.tid),
			  jiffies_to_msecs(jiffies - start_time),
			  rv,
			  resource->res_opts.node_id,
			  context->target_node_id);

	// BSR-937 fix avoid state change races between change_cluster_wide_state() and w_after_state_change()
	// set STATE_WORK_PENDING while sending commits and changing local state
	wait_event(resource->state_work_wait, !test_and_set_bit(STATE_WORK_PENDING, &resource->flags));

	if (have_peers && context->change_local_state_last) {
		twopc_phase2(resource, context->vnr, rv >= SS_SUCCESS, &request, reach_immediately);
	}
	end_remote_state_change(resource, &irq_flags, context->flags | CS_TWOPC);
	if (rv >= SS_SUCCESS) {
		change(context, PH_COMMIT);
		if (target_connection &&
		    target_connection->peer_role[NOW] == R_UNKNOWN) {
			enum bsr_role target_role =
				(reply->primary_nodes & NODE_MASK(context->target_node_id)) ?
				R_PRIMARY : R_SECONDARY;
			__change_peer_role(target_connection, target_role, __FUNCTION__);
		}
		// BSR-937
		clear_bit(STATE_WORK_PENDING, &resource->flags);
		wake_up(&resource->state_work_wait);

		rv = end_state_change(resource, &irq_flags, caller);
	} else {
		// BSR-937	
		clear_bit(STATE_WORK_PENDING, &resource->flags);
		wake_up(&resource->state_work_wait);
		abort_state_change(resource, &irq_flags, caller);
	}
	if (have_peers && !context->change_local_state_last)
		twopc_phase2(resource, context->vnr, rv >= SS_SUCCESS, &request, reach_immediately);

	if (target_connection) {
		kref_debug_put(&target_connection->kref_debug, 8);
		kref_put(&target_connection->kref, bsr_destroy_connection);
	}
	return rv;
}

enum determine_dev_size
	change_cluster_wide_device_size(struct bsr_device *device,
	sector_t local_max_size,
	uint64_t new_user_size,
	enum dds_flags dds_flags,
	struct resize_parms * rs)
{
	struct bsr_resource *resource = device->resource;
	struct twopc_reply *reply = &resource->twopc_reply;
	struct p_twopc_request request;
	ULONG_PTR start_time;
	unsigned long irq_flags;
	enum bsr_state_rv rv;
	enum determine_dev_size dd;
	u64 reach_immediately;
	bool have_peers, commit_it;
	sector_t new_size = 0;
	int retries = 1;

retry:
	rv = bsr_support_2pc_resize(resource);
	if (rv < SS_SUCCESS)
		return DS_2PC_NOT_SUPPORTED;

	state_change_lock(resource, &irq_flags, CS_VERBOSE | CS_LOCAL_ONLY);
	complete_remote_state_change(resource, &irq_flags);
	start_time = jiffies;
	reach_immediately = directly_connected_nodes(resource, NOW);

	do
		reply->tid = prandom_u32();
	while (!reply->tid);

	request.tid = cpu_to_be32(reply->tid);
	request.initiator_node_id = cpu_to_be32(resource->res_opts.node_id);
	request.target_node_id = UINT32_MAX;
	request.nodes_to_reach = cpu_to_be64(
		~(reach_immediately | NODE_MASK(resource->res_opts.node_id)));
	request.dds_flags = cpu_to_be16(dds_flags);
	request.user_size = cpu_to_be64(new_user_size);

	resource->remote_state_change = true;
	resource->twopc_parent_nodes = 0;
	resource->twopc_type = TWOPC_RESIZE;

	reply->initiator_node_id = resource->res_opts.node_id;
	reply->target_node_id = -1;
	reply->max_possible_size = local_max_size;
	reply->reachable_nodes = reach_immediately | NODE_MASK(resource->res_opts.node_id);
	reply->target_reachable_nodes = reply->reachable_nodes;
	state_change_unlock(resource, &irq_flags);

	bsr_info(41, BSR_LC_TWOPC, resource, "Preparing cluster-wide state change %u "
		"(local_max_size = %llu KB, user_cap = %llu KB)",
		be32_to_cpu(request.tid),
		(unsigned long long)local_max_size >> 1,
		(unsigned long long)new_user_size >> 1);

	rv = __cluster_wide_request(resource, device->vnr, P_TWOPC_PREP_RSZ,
		&request, reach_immediately);

	have_peers = rv == SS_CW_SUCCESS;
	if (have_peers) {
		long t = 0;
		wait_event_timeout_ex(resource->state_wait,
									cluster_wide_reply_ready(resource),
									twopc_timeout(resource), t);
		if (t)
			rv = get_cluster_wide_reply(resource, NULL, false);
		else
			rv = SS_TIMEOUT;

		if (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG) {
			long timeout = twopc_retry_timeout(resource, retries++);

			bsr_info(42, BSR_LC_TWOPC, resource, "Retrying cluster-wide state change after %ums",
				jiffies_to_msecs(timeout));

			twopc_phase2(resource, device->vnr, 0, &request, reach_immediately);

			clear_remote_state_change(resource);
			schedule_timeout_interruptible(timeout);
			goto retry;
		}
	}

	if (rv >= SS_SUCCESS) {
		new_size = min_not_zero(reply->max_possible_size, new_user_size);
		commit_it = new_size != bsr_get_vdisk_capacity(device);

		if (commit_it) {
			request.exposed_size = cpu_to_be64(new_size);
			request.diskful_primary_nodes = cpu_to_be64(reply->diskful_primary_nodes);
			bsr_info(43, BSR_LC_TWOPC, resource, "Committing cluster-wide state change %u (%ums)",
				be32_to_cpu(request.tid),
				jiffies_to_msecs(jiffies - start_time));
		}
		else {
			bsr_info(44, BSR_LC_TWOPC, resource, "Aborting cluster-wide state change %u (%ums) size unchanged",
				be32_to_cpu(request.tid),
				jiffies_to_msecs(jiffies - start_time));
		}
	}
	else {
		commit_it = false;
		bsr_info(45, BSR_LC_TWOPC, resource, "Aborting cluster-wide state change %u (%ums) rv = %d",
			be32_to_cpu(request.tid),
			jiffies_to_msecs(jiffies - start_time),
			rv);
	}

	if (have_peers)
		twopc_phase2(resource, device->vnr, commit_it, &request, reach_immediately);

	if (commit_it) {
		struct twopc_resize *tr = &resource->twopc_resize;

		tr->diskful_primary_nodes = reply->diskful_primary_nodes;
		tr->new_size = new_size;
		tr->dds_flags = dds_flags;
		tr->user_size = new_user_size;

		dd = bsr_commit_size_change(device, rs, reach_immediately);
	}
	else {
		if (rv == SS_CW_FAILED_BY_PEER)
			dd = DS_2PC_NOT_SUPPORTED;
		else if (rv >= SS_SUCCESS)
			dd = DS_UNCHANGED;
		else
			dd = DS_2PC_ERR;
	}

	clear_remote_state_change(resource);
	return dd;
}

void twopc_end_nested(struct bsr_resource *resource, enum bsr_packet cmd, bool as_work)
{
	struct bsr_connection *twopc_parent, *tmp;
	struct twopc_reply twopc_reply;
	struct bsr_connection **connections = NULL;
	unsigned int connectionCount = 0;
	unsigned int i = 0;

	LIST_HEAD(parents);

	spin_lock_irq(&resource->req_lock);
	// DW-1257 infinite loop when twopc_work.cb = NULL, resolve linbit patching 04f979d3
	twopc_reply = resource->twopc_reply;
	if (twopc_reply.tid){
		resource->twopc_prepare_reply_cmd = cmd;
		list_splice_init(&resource->twopc_parents, &parents);
	}
	if (as_work)
		resource->twopc_work.cb = NULL;

	// DW-1414 postpone releasing req_lock until get all connections to send twopc reply.
	//spin_unlock_irq(&resource->req_lock);

	if (!twopc_reply.tid){
		bsr_info(46, BSR_LC_TWOPC, resource, "!twopc_reply.tid = %u result: %s", twopc_reply.tid, bsr_packet_name(cmd));
		// DW-1414
		spin_unlock_irq(&resource->req_lock);

		return;
	}

	// DW-1414 postpone releasing req_lock until get all connections to send twopc reply.
	// get connection count from twopc_parent_list.
	list_for_each_entry_safe_ex(struct bsr_connection, twopc_parent, tmp, &parents, twopc_parent_list) {
		if (&twopc_parent->twopc_parent_list == twopc_parent->twopc_parent_list.next) {
			bsr_err(47, BSR_LC_TWOPC, resource, "Failed to send twopc reply due to connected to twopc not found");
			// DW-1480
			list_del(&twopc_parent->twopc_parent_list);
			spin_unlock_irq(&resource->req_lock);
			return;
		}
		connectionCount += 1;
	}

	// no connection in list.
	if (connectionCount == 0) {
		spin_unlock_irq(&resource->req_lock);
		return;
	}

	// allocate memory for connection pointers.
	// BSR-427 fix hang. change GFP_KERNEL flag to GFP_ATOMIC
	connections = (struct bsr_connection**)bsr_kmalloc(sizeof(struct bsr_connection*) * connectionCount, GFP_ATOMIC, 'D8SB');
	if (connections == NULL) {
		spin_unlock_irq(&resource->req_lock);
		bsr_err(43, BSR_LC_MEMORY, resource, "Failed to send twopc reply due to failure to allocate memory for connections");
		return;
	}

	// store connection object address.
	connectionCount = 0;
	list_for_each_entry_safe_ex(struct bsr_connection, twopc_parent, tmp, &parents, twopc_parent_list) {
		connections[connectionCount++] = twopc_parent;
	}
	
	// release req_lock.
	spin_unlock_irq(&resource->req_lock);

    bsr_debug(56, BSR_LC_TWOPC, resource, "Nested state change %u result: %s", twopc_reply.tid, bsr_packet_name(cmd));

	for (i = 0; i < connectionCount; i++) {
		twopc_parent = connections[i];	

		if (twopc_reply.is_disconnect)
			set_bit(DISCONNECT_EXPECTED, &twopc_parent->flags);
		bsr_send_twopc_reply(twopc_parent, cmd, &twopc_reply);
		// DW-1480
		list_del(&twopc_parent->twopc_parent_list);
		kref_debug_put(&twopc_parent->kref_debug, 9);
		kref_put(&twopc_parent->kref, bsr_destroy_connection);
	}

	if (connections) {
		bsr_kfree(connections);
		connections = NULL;
	}

	wake_up(&resource->twopc_wait);
}

int nested_twopc_work(struct bsr_work *work, int cancel)
{
	struct bsr_resource *resource =
		container_of(work, struct bsr_resource, twopc_work);
	enum bsr_state_rv rv;
	enum bsr_packet cmd;

	UNREFERENCED_PARAMETER(cancel);

	rv = get_cluster_wide_reply(resource, NULL, false);
	if (rv >= SS_SUCCESS)
		cmd = P_TWOPC_YES;
	else if (rv == SS_CONCURRENT_ST_CHG)
		cmd = P_TWOPC_RETRY;
	else
		cmd = P_TWOPC_NO;
	twopc_end_nested(resource, cmd, true);
	return 0;
}

enum bsr_state_rv
nested_twopc_request(struct bsr_resource *resource, int vnr, enum bsr_packet cmd,
		     struct p_twopc_request *request)
{
	enum bsr_state_rv rv;
	u64 nodes_to_reach, reach_immediately;

	spin_lock_irq(&resource->req_lock);
	nodes_to_reach = be64_to_cpu(request->nodes_to_reach);
	reach_immediately = directly_connected_nodes(resource, NOW) & nodes_to_reach;
	nodes_to_reach &= ~(reach_immediately | NODE_MASK(resource->res_opts.node_id));
	request->nodes_to_reach = cpu_to_be64(nodes_to_reach);
	spin_unlock_irq(&resource->req_lock);

	rv = __cluster_wide_request(resource, vnr, cmd, request, reach_immediately);
	if (cmd == P_TWOPC_PREPARE || cmd == P_TWOPC_PREP_RSZ) {
		if (rv <= SS_SUCCESS) {
			cmd = (rv == SS_SUCCESS) ? P_TWOPC_YES : P_TWOPC_NO;
			twopc_end_nested(resource, cmd, false);
		}
	}
	return rv;
}

/* not used
static bool has_up_to_date_peer_disks(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;

	for_each_peer_device(peer_device, device)
		if (peer_device->disk_state[NEW] == D_UP_TO_DATE)
			return true;
	return false;
}
*/

struct change_role_context {
	struct change_context context;
	bool force;
};

static void __change_role(struct change_role_context *role_context)
{
	struct bsr_resource *resource = role_context->context.resource;
	enum bsr_role role = role_context->context.val.role;
	bool force = role_context->force;
	struct bsr_device *device;
	int vnr;

	resource->role[NEW] = role;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		if (role == R_PRIMARY && force) {
			if (device->disk_state[NEW] < D_UP_TO_DATE &&
				device->disk_state[NEW] >= D_INCONSISTENT 
				// DW-1155 
				/* If Force-Primary, change the disk state to D_UP_TO_DATE. Do not consider a peer_disks. */
				/* && !has_up_to_date_peer_disks(device) */
			) {
				__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);
				/* adding it to the context so that it gets sent to the peers */
				role_context->context.mask.disk |= disk_MASK;
				role_context->context.val.disk |= D_UP_TO_DATE;
			}
		} else if (role == R_SECONDARY) {
			__change_io_susp_quorum(device, false);
		}
	}
	rcu_read_unlock();
}

static bool do_change_role(struct change_context *context, enum change_phase phase)
{
	struct change_role_context *role_context =
		container_of(context, struct change_role_context, context);

	__change_role(role_context);
	return phase != PH_PREPARE ||
	       (context->resource->role[NOW] != R_PRIMARY &&
		context->val.role == R_PRIMARY);
}

enum bsr_state_rv change_role(struct bsr_resource *resource,
			       enum bsr_role role,
			       enum chg_state_flags flags,
			       bool force,
			       const char **err_str)
{
	struct change_role_context role_context = {
		.context = {
			.resource = resource,
			.vnr = -1,
			.mask = { { .role = role_MASK } },
			.val = { { .role = role } },
			.target_node_id = -1,
			.flags = flags | CS_SERIALIZE,
			// DW-1233 send TWOPC packets to other nodes before updating the local state
			.change_local_state_last = true,
			.err_str = err_str,
		},
		.force = force,
	};
	enum bsr_state_rv rv;
	bool got_state_sem = false;

	if (role == R_SECONDARY) {
		struct bsr_device *device;
		int vnr;

		if (!(flags & CS_ALREADY_SERIALIZED)) {
			down(&resource->state_sem);
			got_state_sem = true;
			role_context.context.flags |= CS_ALREADY_SERIALIZED;
		}
		idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr)
			wait_event(device->misc_wait, !atomic_read(&device->ap_bio_cnt[WRITE]));
	}
	rv = change_cluster_wide_state(do_change_role, &role_context.context, __FUNCTION__);
	if (got_state_sem)
		up(&resource->state_sem);
	return rv;
}

void __change_io_susp_user(struct bsr_resource *resource, bool value)
{
	resource->susp[NEW] = value;
}

enum bsr_state_rv change_io_susp_user(struct bsr_resource *resource,
				       bool value,
				       enum chg_state_flags flags)
{
	unsigned long irq_flags;

	begin_state_change(resource, &irq_flags, flags);
	__change_io_susp_user(resource, value);
	return end_state_change(resource, &irq_flags, __FUNCTION__);
}

void __change_io_susp_no_data(struct bsr_resource *resource, bool value)
{
	resource->susp_nod[NEW] = value;
}

void __change_io_susp_fencing(struct bsr_connection *connection, bool value)
{
	connection->susp_fen[NEW] = value;
}

void __change_io_susp_quorum(struct bsr_device *device, bool value)
{
	device->susp_quorum[NEW] = value;
}

void __change_disk_state(struct bsr_device *device, enum bsr_disk_state disk_state, const char* caller)
{
	device->disk_state[NEW] = disk_state;
	if (caller != NULL && device->disk_state[NEW] != device->disk_state[NOW]) {
		bsr_debug(48, BSR_LC_STATE, device, "%s, disk_state : %s", caller, bsr_disk_str(device->disk_state[NEW]));
	}
}

void __change_disk_states(struct bsr_resource *resource, enum bsr_disk_state disk_state)
{
	struct bsr_device *device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr)
		__change_disk_state(device, disk_state, __FUNCTION__);
	rcu_read_unlock();
}

void __outdate_myself(struct bsr_resource *resource)
{
	struct bsr_device *device;
	int vnr;

	// DW-663 
	if (resource->role[NOW] == R_PRIMARY)
		return;

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		if (device->disk_state[NOW] > D_OUTDATED)
			__change_disk_state(device, D_OUTDATED, __FUNCTION__);
	}
}

static bool device_has_connected_peer_devices(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;

	for_each_peer_device(peer_device, device)
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			return true;
	return false;
}

static bool device_has_peer_devices_with_disk(struct bsr_device *device, enum change_phase phase)
{
	struct bsr_peer_device *peer_device;
	bool rv = false;

	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->cstate[NOW] == C_CONNECTED) {
			/* We expect to receive up-to-date UUIDs soon.
			   To avoid a race in receive_state, "clear" uuids while
			   holding req_lock. I.e. atomic with the state change */
			// DW-1321 just clear uuids once, not twice because sometimes peer uuid comes eariler than local state change
			if (phase == PH_PREPARE)
				peer_device->uuids_received = false;

			// DW-1263 the peers that has disk state lower than D_NEGOTIATING can't be negotiated with, skip this peer.
			if (peer_device->disk_state[NOW] < D_NEGOTIATING)
				continue;

			if (peer_device->disk_state[NOW] != D_UNKNOWN ||
			    peer_device->repl_state[NOW] != L_OFF)
				rv = true;
		}
	}

	return rv;
}

static void restore_outdated_in_pdsk(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;

	if (!get_ldev_if_state(device, D_ATTACHING))
		return;

	for_each_peer_device(peer_device, device) {
		int node_id = peer_device->connection->peer_node_id;
		struct bsr_peer_md *peer_md = &device->ldev->md.peers[node_id];

		if ((peer_md->flags & MDF_PEER_OUTDATED) &&
			peer_device->disk_state[NEW] == D_UNKNOWN)
			__change_peer_disk_state(peer_device, D_OUTDATED, __FUNCTION__);
	}

	put_ldev(device);
}

static bool do_change_from_consistent(struct change_context *context, enum change_phase phase)
{
	struct bsr_resource *resource = context->resource;
	struct twopc_reply *reply = &resource->twopc_reply;
	u64 directly_reachable = directly_connected_nodes(resource, NEW) |
		NODE_MASK(resource->res_opts.node_id);

	if (phase == PH_COMMIT && (reply->primary_nodes & ~directly_reachable)) {
		__outdate_myself(resource);
	} else {
		struct bsr_device *device;
		int vnr;

		idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
			if (device->disk_state[NOW] == D_CONSISTENT)
				__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);
		}
	}

	return phase != PH_PREPARE || reply->reachable_nodes != NODE_MASK(resource->res_opts.node_id);
}

enum bsr_state_rv change_from_consistent(struct bsr_resource *resource,
					  enum chg_state_flags flags)
{
	struct change_context context = {
		.resource = resource,
		.vnr = -1,
#ifdef _WIN
		.mask = { 0 },
		.val = { 0 },
#else // _LIN
		.mask = { },
		.val = { },
#endif
		.target_node_id = -1,
		.flags = flags,
		.change_local_state_last = false,
	};

	/* The other nodes get the request for an empty state change. I.e. they
	   will agree to this change request. At commit time we know where to
	   go from the D_CONSISTENT, since we got the primary mask. */
	return change_cluster_wide_state(do_change_from_consistent, &context, __FUNCTION__);
}

struct change_disk_state_context {
	struct change_context context;
	struct bsr_device *device;
};

static bool do_change_disk_state(struct change_context *context, enum change_phase phase)
{
	struct bsr_device *device =
		container_of(context, struct change_disk_state_context, context)->device;
	bool cluster_wide_state_change = false;

	if (device->disk_state[NOW] == D_ATTACHING &&
	    context->val.disk == D_NEGOTIATING) {

		if (device_has_peer_devices_with_disk(device, phase)) {

			struct bsr_connection *connection =
				first_connection(device->resource);
			cluster_wide_state_change =
				connection && connection->agreed_pro_version >= 110;
		} else {
			/* very last part of attach */
			context->val.disk = disk_state_from_md(device);
			restore_outdated_in_pdsk(device);
		}
	} else if (device->disk_state[NOW] != D_DETACHING &&
		   context->val.disk == D_DETACHING &&
		   device_has_connected_peer_devices(device)) {
		cluster_wide_state_change = true;
	}
	__change_disk_state(device, context->val.disk, __FUNCTION__);
	return phase != PH_PREPARE || cluster_wide_state_change;
}

enum bsr_state_rv change_disk_state(struct bsr_device *device,
				     enum bsr_disk_state disk_state,
					 enum chg_state_flags flags,
					 const char **err_str)
{
	struct change_disk_state_context disk_state_context = {
		.context = {
			.resource = device->resource,
			.vnr = device->vnr,
			.mask = { { .disk = disk_MASK } },
			.val = { { .disk = disk_state } },
			.target_node_id = -1,
			.flags = flags,
			.change_local_state_last = true,
			.err_str = err_str,
		},
		.device = device,
	};
	return change_cluster_wide_state(do_change_disk_state,
										&disk_state_context.context, __FUNCTION__);
}

void __change_cstate(struct bsr_connection *connection, enum bsr_conn_state cstate)
{
	if (cstate == C_DISCONNECTING)
		set_bit(DISCONNECT_EXPECTED, &connection->flags);

	__change_cstate_state(connection, cstate, __FUNCTION__);
	if (cstate < C_CONNECTED) {
		struct bsr_peer_device *peer_device;
		int vnr;

		rcu_read_lock();
		idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr)
			__change_repl_state_and_auto_cstate(peer_device, L_OFF, __FUNCTION__);
		rcu_read_unlock();
	}
}

static bool connection_has_connected_peer_devices(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int vnr;

	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			return true;
	}
	return false;
}

enum outdate_what { OUTDATE_NOTHING, OUTDATE_DISKS, OUTDATE_PEER_DISKS };

static enum outdate_what outdate_on_disconnect(struct bsr_connection *connection)
{
	struct bsr_resource *resource = connection->resource;

	if ((connection->fencing_policy >= FP_RESOURCE ||
		connection->resource->res_opts.quorum != QOU_OFF) &&
		resource->role[NOW] != connection->peer_role[NOW]) {
		/* primary politely disconnects from secondary,
		 * tells peer to please outdate itself */

		if (resource->role[NOW] == R_PRIMARY)
			return OUTDATE_PEER_DISKS;
		/* secondary politely disconnect from primary,
    	 * proposes to outdate itself. */
		if (connection->peer_role[NOW] == R_PRIMARY)
			return OUTDATE_DISKS;
	}
	return OUTDATE_NOTHING;
}

static void __change_cstate_and_outdate(struct bsr_connection *connection,
					enum bsr_conn_state cstate,
					enum outdate_what outdate_what)
{
	__change_cstate(connection, cstate);
	switch(outdate_what) {
		case OUTDATE_DISKS:
			__change_disk_states(connection->resource, D_OUTDATED);
			break;
		case OUTDATE_PEER_DISKS:
			__change_peer_disk_states(connection, D_OUTDATED);
			break;
		case OUTDATE_NOTHING:
			break;
	}
}

struct change_cstate_context {
	struct change_context context;
	struct bsr_connection *connection;
	enum outdate_what outdate_what;
};

static bool do_change_cstate(struct change_context *context, enum change_phase phase)
{
	struct change_cstate_context *cstate_context =
		container_of(context, struct change_cstate_context, context);

	if (phase == PH_PREPARE) {
		cstate_context->outdate_what = OUTDATE_NOTHING;
		if (context->val.conn == C_DISCONNECTING && !(context->flags & CS_HARD)) {
			cstate_context->outdate_what =
				outdate_on_disconnect(cstate_context->connection);
			switch(cstate_context->outdate_what) {
			case OUTDATE_DISKS:
				context->mask.disk = disk_MASK;
				context->val.disk = D_OUTDATED;
				break;
			case OUTDATE_PEER_DISKS:
				context->mask.pdsk = pdsk_MASK;
				context->val.pdsk = D_OUTDATED;
				break;
			case OUTDATE_NOTHING:
				break;
			}
		}
	}
	__change_cstate_and_outdate(cstate_context->connection,
				    context->val.conn,
				    cstate_context->outdate_what);

	if (phase == PH_COMMIT) {
		struct bsr_resource *resource = context->resource;
		struct twopc_reply *reply = &resource->twopc_reply;
		u64 directly_reachable = directly_connected_nodes(resource, NEW) |
			NODE_MASK(resource->res_opts.node_id);

		if (reply->primary_nodes & ~directly_reachable)
			__outdate_myself(resource);
	}

	return phase != PH_PREPARE ||
	       context->val.conn == C_CONNECTED ||
	       (context->val.conn == C_DISCONNECTING &&
		connection_has_connected_peer_devices(cstate_context->connection));
}

/**
 * change_cstate_es()  -  change the connection state of a connection
 *
 * When disconnecting from a peer, we may also need to outdate the local or
 * peer disks depending on the fencing policy.  This cannot easily be split
 * into two state changes.
 */
enum bsr_state_rv change_cstate_es(struct bsr_connection *connection,
				    enum bsr_conn_state cstate,
				    enum chg_state_flags flags,
				    const char **err_str,
					const char *caller
	)
{
	struct change_cstate_context cstate_context = {
		.context = {
			.resource = connection->resource,
			.vnr = -1,
			.mask = { { .conn = conn_MASK } },
			.val = { { .conn = cstate } },
			.target_node_id = connection->peer_node_id,
			.flags = flags,
			.change_local_state_last = true,
			.err_str = err_str,
		},
		.connection = connection,
	};

	if (cstate == C_CONNECTED) {
		cstate_context.context.mask.role = role_MASK;
		cstate_context.context.val.role = connection->resource->role[NOW];
	}

	/*
	 * Hard connection state changes like a protocol error or forced
	 * disconnect may occur while we are holding resource->state_sem.  In
	 * that case, omit CS_SERIALIZE so that we don't deadlock trying to
	 * grab that mutex again.
	 */
	if (!(flags & CS_HARD))
		cstate_context.context.flags |= CS_SERIALIZE;

	return change_cluster_wide_state(do_change_cstate, &cstate_context.context, caller);
}

void __change_peer_role(struct bsr_connection *connection, enum bsr_role peer_role, const char* caller)
{
	connection->peer_role[NEW] = peer_role;
	if (caller != NULL && connection->peer_role[NEW] != connection->peer_role[NOW]) {
		bsr_debug(49, BSR_LC_STATE, connection, "%s, peer_role : %s", caller, bsr_role_str(connection->peer_role[NEW]));
	}
}

void __change_cstate_state(struct bsr_connection *connection, enum bsr_conn_state cstate, const char* caller)
{
	connection->cstate[NEW] = cstate;
	if (caller != NULL && connection->cstate[NEW] != connection->cstate[NOW]) {
		bsr_debug(50, BSR_LC_STATE, connection, "%s, cstate : %s", caller, bsr_conn_str(connection->cstate[NEW]));
	}
}

void __change_repl_state(struct bsr_peer_device *peer_device, enum bsr_repl_state repl_state, const char* caller)
{
	peer_device->repl_state[NEW] = repl_state;
	if (caller != NULL && peer_device->repl_state[NEW] != peer_device->repl_state[NOW]) {
		bsr_debug(51, BSR_LC_STATE, peer_device, "%s, repl_state : %s", caller, bsr_repl_str(peer_device->repl_state[NEW]));
	}
}

void __change_repl_state_and_auto_cstate(struct bsr_peer_device *peer_device, enum bsr_repl_state repl_state, const char* caller)
{
	__change_repl_state(peer_device, repl_state, caller);
	if (repl_state > L_OFF)
		__change_cstate_state(peer_device->connection, C_CONNECTED, caller);
}

struct change_repl_context {
	struct change_context context;
	struct bsr_peer_device *peer_device;
};

static bool do_change_repl_state(struct change_context *context, enum change_phase phase)
{
	struct change_repl_context *repl_context =
		container_of(context, struct change_repl_context, context);
	struct bsr_peer_device *peer_device = repl_context->peer_device;
	enum bsr_repl_state *repl_state = peer_device->repl_state;
	enum bsr_repl_state new_repl_state = context->val.conn;

	__change_repl_state_and_auto_cstate(peer_device, new_repl_state, __FUNCTION__);

	return phase != PH_PREPARE ||
		((repl_state[NOW] >= L_ESTABLISHED &&
		  (new_repl_state == L_STARTING_SYNC_S || new_repl_state == L_STARTING_SYNC_T)) ||
		 (repl_state[NOW] == L_ESTABLISHED &&
		  (new_repl_state == L_VERIFY_S || new_repl_state == L_OFF)));
}

enum bsr_state_rv change_repl_state(struct bsr_peer_device *peer_device,
				     enum bsr_repl_state new_repl_state,
				     enum chg_state_flags flags)
{
	struct change_repl_context repl_context = {
		.context = {
			.resource = peer_device->device->resource,
			.vnr = peer_device->device->vnr,
			.mask = { { .conn = conn_MASK } },
			.val = { { .conn = new_repl_state } },
			.target_node_id = peer_device->node_id,
			// DW-954 send TWOPC_COMMIT packets to other nodes before updating the local state
			.change_local_state_last = true,
			.flags = flags
		},
		.peer_device = peer_device
	};

	return change_cluster_wide_state(do_change_repl_state, &repl_context.context, __FUNCTION__);
}

enum bsr_state_rv stable_change_repl_state(struct bsr_peer_device *peer_device,
					    enum bsr_repl_state repl_state,
					    enum chg_state_flags flags)
{
	// DW-1605
	enum bsr_state_rv rv = SS_SUCCESS;
	stable_state_change(rv, peer_device->device->resource,
		change_repl_state(peer_device, repl_state, flags));
	return rv;
}

void __change_peer_disk_state(struct bsr_peer_device *peer_device, enum bsr_disk_state disk_state, const char* caller)
{
	peer_device->disk_state[NEW] = disk_state;
	if (caller != NULL && peer_device->disk_state[NEW] != peer_device->disk_state[NOW]) {
		bsr_debug(52, BSR_LC_STATE, peer_device, "%s, disk_state : %s", caller, bsr_disk_str(peer_device->disk_state[NEW]));
	}
}

void __change_peer_disk_states(struct bsr_connection *connection,
			       enum bsr_disk_state disk_state)
{
	struct bsr_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr)
		__change_peer_disk_state(peer_device, disk_state, __FUNCTION__);
	rcu_read_unlock();
}

enum bsr_state_rv change_peer_disk_state(struct bsr_peer_device *peer_device,
					  enum bsr_disk_state disk_state,
					  enum chg_state_flags flags)
{
	struct bsr_resource *resource = peer_device->device->resource;
	unsigned long irq_flags;

	begin_state_change(resource, &irq_flags, flags);
	__change_peer_disk_state(peer_device, disk_state, __FUNCTION__);
	return end_state_change(resource, &irq_flags, __FUNCTION__);
}

void __change_resync_susp_user(struct bsr_peer_device *peer_device,
				       bool value, const char* caller)
{
	peer_device->resync_susp_user[NEW] = value;
	if (peer_device->resync_susp_user[NOW] != peer_device->resync_susp_user[NEW] && caller != NULL) {
		bsr_debug(53, BSR_LC_STATE, peer_device, "%s, resync_susp_user : %s", caller, peer_device->resync_susp_user[NEW] ? "true" : "false");
	}
}

enum bsr_state_rv change_resync_susp_user(struct bsr_peer_device *peer_device,
						   bool value,
						   enum chg_state_flags flags,
						const char* caller)
{
	struct bsr_resource *resource = peer_device->device->resource;
	unsigned long irq_flags;

	begin_state_change(resource, &irq_flags, flags);
	__change_resync_susp_user(peer_device, value, caller);
	return end_state_change(resource, &irq_flags, __FUNCTION__);
}

void __change_resync_susp_peer(struct bsr_peer_device *peer_device,
				       bool value, const char* caller)
{
	peer_device->resync_susp_peer[NEW] = value;
	if (peer_device->resync_susp_peer[NOW] != peer_device->resync_susp_peer[NEW] && caller != NULL) {
		bsr_debug(54, BSR_LC_STATE, peer_device, "%s, resync_susp_peer : %s", caller, peer_device->resync_susp_peer[NEW] ? "true" : "false");
	}
}

void __change_resync_susp_dependency(struct bsr_peer_device *peer_device,
					     bool value, const char* caller)
{
	peer_device->resync_susp_dependency[NEW] = value;
	if (peer_device->resync_susp_dependency[NOW] != peer_device->resync_susp_dependency[NEW] && caller != NULL) {
		bsr_debug(55, BSR_LC_STATE, peer_device, "%s, resync_susp_dependency : %s", caller, peer_device->resync_susp_dependency[NEW] ? "true" : "false");
	}
}

void __change_resync_susp_other_c(struct bsr_peer_device *peer_device,
						bool value, const char* caller)
{
	peer_device->resync_susp_other_c[NEW] = value;
	if (peer_device->resync_susp_other_c[NOW] != peer_device->resync_susp_other_c[NEW] && caller != NULL) {
		bsr_debug(56, BSR_LC_STATE, peer_device, "%s, resync_susp_other_c : %s", caller, peer_device->resync_susp_other_c[NEW] ? "true" : "false");
	}
}
