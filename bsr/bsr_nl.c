/*
   bsr_nl.c

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>.

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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include "bsr_int.h"
#include "../bsr-headers/bsr.h"
#include "../bsr-headers/bsr_protocol.h"
#include "bsr_req.h"
#include "bsr_state_change.h"
#include "bsr_debugfs.h"
#include "../bsr-headers/bsr_transport.h"
#include "../bsr-headers/linux/bsr_limits.h"

#ifdef _WIN
#define		ERR_LOCAL_AND_PEER_ADDR 173	
#include "proto.h"

#else // _LIN

#include <linux/module.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/blkpg.h>
#include <linux/cpumask.h>
#include <linux/random.h>
#include <asm/unaligned.h>
#include <linux/kthread.h>
#include <linux/security.h>
#include <net/genetlink.h>
#endif


#ifdef _WIN
bool capable(int cap)
{
	UNREFERENCED_PARAMETER(cap);
    // not supported
    return false;
}
#endif

/* .doit */
// int bsr_adm_create_resource(struct sk_buff *skb, struct genl_info *info);
// int bsr_adm_delete_resource(struct sk_buff *skb, struct genl_info *info);

int bsr_adm_new_minor(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_del_minor(struct sk_buff *skb, struct genl_info *info);

int bsr_adm_new_resource(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_del_resource(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_down(struct sk_buff *skb, struct genl_info *info);

int bsr_adm_set_role(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_attach(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_disk_opts(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_detach(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_connect(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_new_peer(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_del_peer(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_new_path(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_del_path(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_net_opts(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_peer_device_opts(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_resize(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_start_ov(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_stop_ov(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_new_c_uuid(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_disconnect(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_invalidate(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_invalidate_peer(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_pause_sync(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_resume_sync(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_suspend_io(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_resume_io(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_outdate(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_resource_opts(struct sk_buff *skb, struct genl_info *info);
// BSR-1392
int bsr_adm_apply_persist_role(struct sk_buff *skb, struct genl_info *info);
// BSR-718
int bsr_adm_node_opts(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_get_status(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_get_timeout_type(struct sk_buff *skb, struct genl_info *info);
int bsr_adm_forget_peer(struct sk_buff *skb, struct genl_info *info);
/* .dumpit */
int bsr_adm_dump_resources(struct sk_buff *skb, struct netlink_callback *cb);
int bsr_adm_dump_devices(struct sk_buff *skb, struct netlink_callback *cb);
int bsr_adm_dump_devices_done(struct netlink_callback *cb);
int bsr_adm_dump_connections(struct sk_buff *skb, struct netlink_callback *cb);
int bsr_adm_dump_connections_done(struct netlink_callback *cb);
int bsr_adm_dump_peer_devices(struct sk_buff *skb, struct netlink_callback *cb);
int bsr_adm_dump_peer_devices_done(struct netlink_callback *cb);
int bsr_adm_get_initial_state(struct sk_buff *skb, struct netlink_callback *cb);
int bsr_adm_get_initial_state_done(struct netlink_callback *cb);

#ifdef _WIN
KSTART_ROUTINE _try_outdate_peer_async;
#endif

#include "../bsr-headers/linux/bsr_genl_api.h"
#include "bsr_nla.h"
#include "../bsr-headers/linux/genl_magic_func.h"

atomic_t bsr_genl_seq = ATOMIC_INIT(2); /* two. */

#ifdef _WIN 
// noti mutex 
struct mutex notification_mutex;
extern struct mutex handler_mutex;
#else // _LIN
DEFINE_MUTEX(notification_mutex);
#endif

/* used blkdev_get_by_path, to claim our meta data device(s) */
static char *bsr_m_holder = "Hands off! this is BSR's meta data device.";

#ifdef _WIN
int bsr_adm_send_reply(struct sk_buff *skb, struct genl_info *info)
#else // _LIN
static void bsr_adm_send_reply(struct sk_buff *skb, struct genl_info *info)
#endif
{
	genlmsg_end(skb, genlmsg_data(nlmsg_data(nlmsg_hdr(skb))));
#ifdef NL_PACKET_MSG
    {
        struct nlmsghdr * pnlh = (struct nlmsghdr *)skb->data;
        struct genlmsghdr * pgenlh = nlmsg_data(pnlh);

        bsr_debug(88, BSR_LC_GENL, NO_OBJECT,"len(%d), type(0x%x), flags(0x%x), seq(%d), pid(%d), cmd(%d), version(%d)",
            pnlh->nlmsg_len, pnlh->nlmsg_type, pnlh->nlmsg_flags, pnlh->nlmsg_seq, pnlh->nlmsg_pid, pgenlh->cmd, pgenlh->version);

        if (pnlh->nlmsg_flags & NLM_F_ECHO) {
            bsr_debug(89, BSR_LC_GENL, NO_OBJECT,"done", 0);
            return 0;
        }
    }
#endif
	if (genlmsg_reply(skb, info)) {
		bsr_err(1, BSR_LC_GENL, NO_OBJECT, "Failed to send reply genl due to error sending genl reply");
#ifdef _WIN
		return -1;
#endif
	} 

#ifdef _WIN
	return 0;
#endif
	
}

/* Used on a fresh "bsr_adm_prepare"d reply_skb, this cannot fail: The only
 * reason it could fail was no space in skb, and there are 4k available. */
static int bsr_msg_put_info(struct sk_buff *skb, const char *info)
{
	struct nlattr *nla;
	int err = -EMSGSIZE;

	if (!info || !info[0])
		return 0;

	nla = nla_nest_start(skb, BSR_NLA_CFG_REPLY);
	if (!nla)
		return err;

	err = nla_put_string(skb, T_info_text, info);
	if (err) {
		nla_nest_cancel(skb, nla);
		return err;
	} else
		nla_nest_end(skb, nla);
	return 0;
}

static int bsr_adm_finish(struct bsr_config_context *, struct genl_info *, int);

extern struct genl_ops bsr_genl_ops[];

#ifdef COMPAT_HAVE_SECURITY_NETLINK_RECV
#define bsr_security_netlink_recv(skb, cap) \
	security_netlink_recv(skb, cap)
#else
#ifdef _LIN
/* see
 * fd77846 security: remove the security_netlink_recv hook as it is equivalent to capable()
 */
static inline bool bsr_security_netlink_recv(struct sk_buff *skb, int cap)
{
	return !capable(cap);
}
#endif
#endif

static bool need_sys_admin(u8 cmd)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(bsr_genl_ops); i++)
		if (bsr_genl_ops[i].cmd == cmd)
			return 0 != (bsr_genl_ops[i].flags & GENL_ADMIN_PERM);
	return true;
}

static struct bsr_path *first_path(struct bsr_connection *connection)
{
	/* Ideally this function is removed at a later point in time.
	   It was introduced when replacing the single address pair
	   with a list of address pairs (or paths). */

	return list_first_entry_or_null(&connection->transport.paths, struct bsr_path, list);
}

/* This would be a good candidate for a "pre_doit" hook,
 * and per-family private info->pointers.
 * But we need to stay compatible with older kernels.
 * If it returns successfully, adm_ctx members are valid.
 */
#define BSR_ADM_NEED_MINOR        (1 << 0)
#define BSR_ADM_NEED_RESOURCE     (1 << 1)
#define BSR_ADM_NEED_CONNECTION   (1 << 2)
#define BSR_ADM_NEED_PEER_DEVICE  (1 << 3)
#define BSR_ADM_NEED_PEER_NODE    (1 << 4)
#define BSR_ADM_IGNORE_VERSION    (1 << 5)

// BSR-1192
int netlink_work_thread_cnt = 0;

#ifdef _WIN
void log_for_netlink_cli_recv(const u8 cmd)
{
#else
static void log_for_netlink_cli_recv(const u8 cmd)
{
	netlink_work_thread_cnt++;
#endif

	if ((BSR_ADM_GET_RESOURCES <= cmd) && (cmd <= BSR_ADM_GET_PEER_DEVICES)) {
#ifdef _WIN
		bsr_debug(32, BSR_LC_NETLINK, NO_OBJECT, "bsr netlink cmd(%s:%u) begin ->", bsr_genl_cmd_to_str(cmd), cmd);
#else
		bsr_debug(32, BSR_LC_NETLINK, NO_OBJECT, "bsr netlink cmd(%s:%u) begin ->", bsr_genl_cmd_to_str(cmd), cmd);
#endif
	}
	else {
#ifdef _WIN
		bsr_info(18, BSR_LC_NETLINK, NO_OBJECT, "%s:%u command has been received. Execute the command.", bsr_genl_cmd_to_str(cmd), cmd);
#else
		bsr_info(18, BSR_LC_NETLINK, NO_OBJECT, "%s:%u command has been received. Execute the command.", bsr_genl_cmd_to_str(cmd), cmd);
#endif
	}
}

#ifdef _WIN
void log_for_netlink_cli_done(const u8 cmd)
{
#else
static void log_for_netlink_cli_done(const u8 cmd)
{
	netlink_work_thread_cnt--;
#endif

	if ((BSR_ADM_GET_RESOURCES <= cmd) && (cmd <= BSR_ADM_GET_PEER_DEVICES)) {
#ifdef _WIN
		bsr_debug(33, BSR_LC_NETLINK, NO_OBJECT, "bsr netlink cmd(%s:%u) done (cmd_pending:%d) <-", bsr_genl_cmd_to_str(cmd), cmd, netlink_work_thread_cnt - 1);
#else
		bsr_debug(33, BSR_LC_NETLINK, NO_OBJECT, "bsr netlink cmd(%s:%u) done (cmd_pending:%d) <-", bsr_genl_cmd_to_str(cmd), cmd, netlink_work_thread_cnt);
#endif
	}
	else {
#ifdef _WIN
		bsr_info(20, BSR_LC_NETLINK, NO_OBJECT, "%s:%u command execution done. (pending command:%d)", bsr_genl_cmd_to_str(cmd), cmd, netlink_work_thread_cnt - 1);
#else
		bsr_info(20, BSR_LC_NETLINK, NO_OBJECT, "%s:%u command execution done. (pending command:%d)", bsr_genl_cmd_to_str(cmd), cmd, netlink_work_thread_cnt);
#endif
	}
}

static int bsr_adm_prepare(struct bsr_config_context *adm_ctx,
	struct sk_buff *skb, struct genl_info *info, unsigned flags)
{
	// BSR-1360
#ifdef COMPAT_HAVE_GENL_INFO_USERHDR
	struct bsr_genlmsghdr *d_in = (struct bsr_genlmsghdr *)genl_info_userhdr(info);
#else
	struct bsr_genlmsghdr *d_in = info->userhdr;
#endif	
	const u8 cmd = info->genlhdr->cmd;
	int err;

	UNREFERENCED_PARAMETER(skb);

	memset(adm_ctx, 0, sizeof(*adm_ctx));
#ifdef _LIN
	// BSR-1192
	log_for_netlink_cli_recv(cmd);

	/*
	 * genl_rcv_msg() only checks if commands with the GENL_ADMIN_PERM flag
	 * set have CAP_NET_ADMIN; we also require CAP_SYS_ADMIN for
	 * administrative commands.
	 */
	if (need_sys_admin(cmd) &&
	    bsr_security_netlink_recv(skb, CAP_SYS_ADMIN))
		return -EPERM;
#endif

	adm_ctx->reply_skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);

	if (!adm_ctx->reply_skb) {
		err = -ENOMEM;
		goto fail;
	}
	adm_ctx->reply_dh = genlmsg_put_reply(adm_ctx->reply_skb,
		info, &bsr_genl_family, 0, cmd);
	
	/* put of a few bytes into a fresh skb of >= 4k will always succeed.
	 * but anyways */
	if (!adm_ctx->reply_dh) {
		err = -ENOMEM;
		goto fail;
	}

	if (info->genlhdr->version != GENL_MAGIC_VERSION && (flags & BSR_ADM_IGNORE_VERSION) == 0) {
		bsr_msg_put_info(adm_ctx->reply_skb, "Failed to prepare bsradm due to wrong API version, upgrade your bsr utils.");
		err = -EINVAL;
		goto fail;
	}

	if (flags & BSR_ADM_NEED_PEER_DEVICE)
		flags |= BSR_ADM_NEED_CONNECTION;
	if (flags & BSR_ADM_NEED_CONNECTION)
		flags |= BSR_ADM_NEED_PEER_NODE;
	if (flags & BSR_ADM_NEED_PEER_NODE)
		flags |= BSR_ADM_NEED_RESOURCE;

	adm_ctx->reply_dh->minor = d_in->minor;
	adm_ctx->reply_dh->ret_code = ERR_NO;

	adm_ctx->volume = VOLUME_UNSPECIFIED;
	adm_ctx->peer_node_id = PEER_NODE_ID_UNSPECIFIED;
	if (info->attrs[BSR_NLA_CFG_CONTEXT]) {
		struct nlattr *nla;
		/* parse and validate only */
		err = bsr_cfg_context_from_attrs(NULL, info);
		if (err)
			goto fail;

		/* It was present, and valid,
		 * copy it over to the reply skb. */
		err = nla_put_nohdr(adm_ctx->reply_skb,
				info->attrs[BSR_NLA_CFG_CONTEXT]->nla_len,
				info->attrs[BSR_NLA_CFG_CONTEXT]);
		if (err)
			goto fail;

		/* and assign stuff to the adm_ctx */
		nla = nested_attr_tb[__nla_type(T_ctx_volume)];
		if (nla)
			adm_ctx->volume = nla_get_u32(nla);
		nla = nested_attr_tb[__nla_type(T_ctx_peer_node_id)];
		if (nla)
			adm_ctx->peer_node_id = nla_get_u32(nla);
		nla = nested_attr_tb[__nla_type(T_ctx_resource_name)];
		if (nla)
			adm_ctx->resource_name = nla_data(nla);
	}

	if (adm_ctx->resource_name) {
		adm_ctx->resource = bsr_find_resource(adm_ctx->resource_name);
		if (adm_ctx->resource)
			kref_debug_get(&adm_ctx->resource->kref_debug, 2);
	}

	adm_ctx->minor = d_in->minor;
	rcu_read_lock();
	adm_ctx->device = minor_to_device(d_in->minor);
	if (adm_ctx->device) {
		kref_get(&adm_ctx->device->kref);
		kref_debug_get(&adm_ctx->device->kref_debug, 4);
	}
	rcu_read_unlock();

	if (!adm_ctx->device && (flags & BSR_ADM_NEED_MINOR)) {
		bsr_msg_put_info(adm_ctx->reply_skb, "unknown minor");
		err = ERR_MINOR_INVALID;
		goto finish;
	}
	if (!adm_ctx->resource && (flags & BSR_ADM_NEED_RESOURCE)) {
		bsr_msg_put_info(adm_ctx->reply_skb, "unknown resource");
		err = ERR_INVALID_REQUEST;
		if (adm_ctx->resource_name)
			err = ERR_RES_NOT_KNOWN;
		goto finish;
	}
	if (adm_ctx->peer_node_id != PEER_NODE_ID_UNSPECIFIED) {
		/* peer_node_id is unsigned int */
		if (adm_ctx->peer_node_id >= BSR_NODE_ID_MAX) {
			bsr_msg_put_info(adm_ctx->reply_skb, "peer node id out of range");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
		if (adm_ctx->resource && adm_ctx->peer_node_id == adm_ctx->resource->res_opts.node_id) {
			bsr_msg_put_info(adm_ctx->reply_skb, "peer node id cannot be my own node id");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}

		// BSR-939 fix avoid potential NULL pointer dereferences
		// adm_ctx->resource can be NULL.
		if (adm_ctx->resource) {
			adm_ctx->connection = bsr_get_connection_by_node_id(adm_ctx->resource, adm_ctx->peer_node_id);
			if (adm_ctx->connection)
				kref_debug_get(&adm_ctx->connection->kref_debug, 2);
		}
	} else if (flags & BSR_ADM_NEED_PEER_NODE) {
		bsr_msg_put_info(adm_ctx->reply_skb, "peer node id missing");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (flags & BSR_ADM_NEED_CONNECTION) {
		if (!adm_ctx->connection) {
			bsr_msg_put_info(adm_ctx->reply_skb, "unknown connection");
			err = ERR_INVALID_REQUEST;
			goto finish;
		}
	}
	if (flags & BSR_ADM_NEED_PEER_DEVICE) {
		rcu_read_lock();
		if (adm_ctx->volume != VOLUME_UNSPECIFIED)
			adm_ctx->peer_device =
				idr_find(&adm_ctx->connection->peer_devices,
					 adm_ctx->volume);
		if (!adm_ctx->peer_device) {
			bsr_msg_put_info(adm_ctx->reply_skb, "unknown volume");
			err = ERR_INVALID_REQUEST;
			rcu_read_unlock();
			goto finish;
		}
		if (!adm_ctx->device) {
			adm_ctx->device = adm_ctx->peer_device->device;
			kref_get(&adm_ctx->device->kref);
			kref_debug_get(&adm_ctx->device->kref_debug, 4);
		}
		rcu_read_unlock();
	}

	/* some more paranoia, if the request was over-determined */
	if (adm_ctx->device && adm_ctx->resource && adm_ctx->device->resource && 
	    adm_ctx->device->resource != adm_ctx->resource) {
		bsr_err(67, BSR_LC_GENL, NO_OBJECT, "Failed to prepare bsradm due to minor exists in different resource, request: minor=%u, resource=%s; but that minor belongs to resource %s",
				adm_ctx->minor, adm_ctx->resource->name,
				adm_ctx->device->resource->name);
		bsr_msg_put_info(adm_ctx->reply_skb, "Failed to prepare bsradm due to minor exists in different resource");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (adm_ctx->device && adm_ctx->device->resource && 
	    adm_ctx->volume != VOLUME_UNSPECIFIED &&
	    adm_ctx->volume != adm_ctx->device->vnr) {
		bsr_err(68, BSR_LC_GENL, NO_OBJECT, "Failed to prepare bsradm due to minor exists in different volume, request: minor=%u, volume=%u; but that minor is volume %u in %s",
				adm_ctx->minor, adm_ctx->volume,
				adm_ctx->device->vnr,
				adm_ctx->device->resource->name);
		bsr_msg_put_info(adm_ctx->reply_skb, "Failed to prepare bsradm due to minor exists as different volume");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}
	if (adm_ctx->device && adm_ctx->peer_device &&
		adm_ctx->resource && adm_ctx->resource->name &&
	    adm_ctx->peer_device->device != adm_ctx->device) {
		bsr_err(69, BSR_LC_GENL, NO_OBJECT, "Failed to prepare bsradm due to device does not exist in peer device, request: minor=%u, resource=%s, volume=%u, peer_node=%u; device != peer_device->device",
				adm_ctx->minor, adm_ctx->resource->name,
				adm_ctx->device->vnr, adm_ctx->peer_node_id);
		bsr_msg_put_info(adm_ctx->reply_skb, "Failed to prepare bsradm due to device does not exist in peer device");
		err = ERR_INVALID_REQUEST;
		goto finish;
	}

	/* still, provide adm_ctx->resource always, if possible. */
	if (!adm_ctx->resource) {
		adm_ctx->resource = adm_ctx->device ? adm_ctx->device->resource
			: adm_ctx->connection ? adm_ctx->connection->resource : NULL;
		if (adm_ctx->resource) {
			kref_get(&adm_ctx->resource->kref);
			kref_debug_get(&adm_ctx->resource->kref_debug, 2);
		}
	}

	return ERR_NO;

fail:
	nlmsg_free(adm_ctx->reply_skb);
	adm_ctx->reply_skb = NULL;

	// BSR-1192
#ifdef _LIN
	log_for_netlink_cli_done(cmd);
#endif
	return err;

finish:
	return bsr_adm_finish(adm_ctx, info, err);
}

static int bsr_adm_finish(struct bsr_config_context *adm_ctx, struct genl_info *info, int retcode)
{
	int ret = 0;

	if (retcode < SS_SUCCESS) {
		struct bsr_resource *resource = adm_ctx->resource;		
		bsr_err(2, BSR_LC_GENL, resource, "Failed to finish bsradm due to cmd(%u) error: %s", info->genlhdr->cmd, bsr_set_st_err_str(retcode));
	}

	if (adm_ctx->device) {
		kref_debug_put(&adm_ctx->device->kref_debug, 4);
		kref_put(&adm_ctx->device->kref, bsr_destroy_device);
		adm_ctx->device = NULL;
	}
	if (adm_ctx->connection) {
		kref_debug_put(&adm_ctx->connection->kref_debug, 2);
		kref_put(&adm_ctx->connection->kref, bsr_destroy_connection);
		adm_ctx->connection = NULL;
	}
	if (adm_ctx->resource) {
		kref_debug_put(&adm_ctx->resource->kref_debug, 2);
		kref_put(&adm_ctx->resource->kref, bsr_destroy_resource);
		adm_ctx->resource = NULL;
	}

	if (!adm_ctx->reply_skb) {
		ret = -ENOMEM;
	} else {
		adm_ctx->reply_dh->ret_code = retcode;
		bsr_adm_send_reply(adm_ctx->reply_skb, info);
#ifdef _WIN
		// DW-211 fix memory leak
		nlmsg_free(adm_ctx->reply_skb);
#endif
		adm_ctx->reply_skb = NULL;
		ret = 0;
	}
	// BSR-1192
#ifdef _LIN
	log_for_netlink_cli_done(info->genlhdr->cmd);
#endif

	return ret;
}

static void conn_md_sync(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		struct bsr_device *device = peer_device->device;
		kref_get(&device->kref);
		rcu_read_unlock();
		bsr_md_sync_if_dirty(device);
		kref_put(&device->kref, bsr_destroy_device);
#ifdef _WIN
        rcu_read_lock_w32_inner();
#else // _LIN
		rcu_read_lock();
#endif
	}
	rcu_read_unlock();
}

/* Try to figure out where we are happy to become primary.
   This is unsed by the crm-fence-peer mechanism
*/
static u64 up_to_date_nodes(struct bsr_device *device, bool op_is_fence)
{
	struct bsr_resource *resource = device->resource;
	const int my_node_id = resource->res_opts.node_id;
	u64 mask = NODE_MASK(my_node_id);

	if (resource->role[NOW] == R_PRIMARY || op_is_fence) {
		struct bsr_peer_device *peer_device;

		rcu_read_lock();
		for_each_peer_device_rcu(peer_device, device) {
			enum bsr_disk_state pdsk = peer_device->disk_state[NOW];
			if (pdsk == D_UP_TO_DATE)
				mask |= NODE_MASK(peer_device->node_id);
		}
		rcu_read_unlock();
	} else if (device->disk_state[NOW] == D_UP_TO_DATE) {
		struct bsr_peer_md *peer_md = device->ldev->md.peers;
		int node_id;

		for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
			struct bsr_peer_device *peer_device;
			if (node_id == my_node_id)
				continue;

			peer_device = peer_device_by_node_id(device, node_id);

			if ((peer_device && peer_device->disk_state[NOW] == D_UP_TO_DATE) ||
			    (peer_md[node_id].flags & MDF_NODE_EXISTS &&
			     peer_md[node_id].bitmap_uuid == 0))
				mask |= NODE_MASK(node_id);
		}
	} else
		  mask = 0;

	return mask;
}

/* Buffer to construct the environment of a user-space helper in. */
struct env {
	char *buffer;
	int size, pos;
};

/* Print into an env buffer. */
#ifdef _WIN
static int env_print(struct env *env, const char *fmt, ...)
#else // _LIN
static __printf(2, 3) int env_print(struct env *env, const char *fmt, ...)
#endif
{
	va_list args;
	int pos, ret;

	pos = env->pos;
	if (pos < 0)
		return pos;
	va_start(args, fmt);
#ifdef _WIN
	ret = _vsnprintf(env->buffer + pos, env->size - pos - 1, fmt, args);
#else // _LIN
	ret = vsnprintf(env->buffer + pos, env->size - pos, fmt, args);
#endif
	va_end(args);
	if (ret < 0) {
		env->pos = ret;
		goto out;
	}
	if (ret >= env->size - pos) {
		ret = env->pos = -ENOMEM;
		goto out;
	}
	env->pos += ret + 1;
    out:
	return ret;
}

/* Put env variables for an address into an env buffer. */
static void env_print_address(struct env *env, const char *prefix,
			      SOCKADDR_STORAGE_EX *storage)
{
	const char *afs;

	switch (storage->ss_family) {
	case AF_INET6:
		afs = "ipv6";
		env_print(env, "%sADDRESS=%pI6", prefix,
			  &((struct sockaddr_in6 *)storage)->sin6_addr);
		break;
	case AF_INET:
		afs = "ipv4";
		env_print(env, "%sADDRESS=%pI4", prefix,
			  &((struct sockaddr_in *)storage)->sin_addr);
		break;
	default:
		afs = "ssocks";
		env_print(env, "%sADDRESS=%pI4", prefix,
			  &((struct sockaddr_in *)storage)->sin_addr);
	}
	env_print(env, "%sAF=%s", prefix, afs);
}

/* Construct char **envp inside an env buffer. */
static char **make_envp(struct env *env)
{
	char **envp, *b;
	unsigned int n;

	if (env->pos < 0)
		return NULL;
	if (env->pos >= env->size)
		goto out_nomem;
	env->buffer[env->pos++] = 0;
	for (b = env->buffer, n = 1; *b; n++)
		b = strchr(b, 0) + 1;
	if (env->size - env->pos < (int)(sizeof(envp) * n))
		goto out_nomem;
	envp = (char **)(env->buffer + env->size) - n;

	for (b = env->buffer; *b; ) {
		*envp++ = b;
		b = strchr(b, 0) + 1;
	}
	*envp++ = NULL;
	return envp - n;

    out_nomem:
	env->pos = -ENOMEM;
	return NULL;
}

/* Macro refers to local variables peer_device, device and connection! */
#ifdef _WIN
#define magic_printk(index, category, level, fmt, ...)				\
	if (peer_device)						\
		__bsr_printk_peer_device(category, index, level, peer_device, fmt, __VA_ARGS__); \
	else if (device)						\
		__bsr_printk_device(category, index, level, device, fmt, __VA_ARGS__);		\
	else								\
		__bsr_printk_connection(category, index, level, connection, fmt, __VA_ARGS__);
#else // _LIN
#define magic_printk(index, category, level, fmt, args...)				\
	if (peer_device)						\
		__bsr_printk_peer_device(category, index, level, peer_device, fmt, args); \
	else if (device)						\
		__bsr_printk_device(category, index, level, device, fmt, args);		\
	else								\
		__bsr_printk_connection(category, index, level, connection, fmt, args);
#endif

int bsr_khelper(struct bsr_device *device, struct bsr_connection *connection, char *cmd)
{
	struct bsr_resource *resource = device ? device->resource : connection->resource;
	char *argv[] = {usermode_helper, cmd, resource->name, NULL };
	struct bsr_peer_device *peer_device = NULL;
	struct env env = { .size = PAGE_SIZE };
	char **envp;
	int ret;

	// BSR-626 skip if handler_use is disable
	if (!atomic_read(&g_handler_use))
		return 0;

    enlarge_buffer:
#ifdef _WIN
	env.buffer = (char *)kmalloc(env.size, 0, '77SB');
#else // _LIN
	env.buffer = (char *)__get_free_pages(GFP_NOIO, get_order(env.size));
#endif
	if (!env.buffer) {
		ret = -ENOMEM;
		goto out_err;
	}
	env.pos = 0;

	rcu_read_lock();
	env_print(&env, "HOME=/");
	env_print(&env, "TERM=linux");
	env_print(&env, "PATH=/sbin:/usr/sbin:/bin:/usr/bin");
	if (device) {
		env_print(&env, "BSR_MINOR=%u", device_to_minor(device));
		env_print(&env, "BSR_VOLUME=%u", device->vnr);
		if (get_ldev(device)) {
			struct disk_conf *disk_conf =
				rcu_dereference(device->ldev->disk_conf);
			env_print(&env, "BSR_BACKING_DEV=%s",
				  disk_conf->backing_dev);
			put_ldev(__FUNCTION__, device);
		}
	}
	if (connection) {
		struct bsr_path *path = first_path(connection);
		if (path) {
			/* TO BE DELETED */
			env_print_address(&env, "BSR_MY_", &path->my_addr);
			env_print_address(&env, "BSR_PEER_", &path->peer_addr);
		}
		env_print(&env, "BSR_PEER_NODE_ID=%u", connection->peer_node_id);
	}
	if (connection && !device) {
		struct bsr_peer_device *peer_device;
		int vnr;

		idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
			struct bsr_device *device = peer_device->device;

			env_print(&env, "BSR_MINOR_%u=%u",
				  vnr, peer_device->device->minor);
			if (get_ldev(device)) {
				struct disk_conf *disk_conf =
					rcu_dereference(device->ldev->disk_conf);
				env_print(&env, "BSR_BACKING_DEV_%u=%s",
					  vnr, disk_conf->backing_dev);
				put_ldev(__FUNCTION__, device);
			}
		}
	}
	rcu_read_unlock();

	if (strstr(cmd, "fence") && connection) {
		bool op_is_fence = strcmp(cmd, "fence-peer") == 0;
		struct bsr_peer_device *peer_device;
		u64 mask = ULLONG_MAX;
		int vnr;
		idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
			struct bsr_device *device = peer_device->device;

			if (get_ldev(device)) {
				u64 m = up_to_date_nodes(device, op_is_fence);
				if (m)
					mask &= m;
				put_ldev(__FUNCTION__, device);
				/* Yes we outright ignore volumes that are not up-to-date
				   on a single node. */
			}
		}
		env_print(&env, "UP_TO_DATE_NODES=0x%08llX", mask);
	}

	envp = make_envp(&env);
	if (!envp) {
		if (env.pos == -ENOMEM) {
#ifdef _WIN
			kfree(env.buffer);
#else // _LIN
			free_pages((unsigned long)env.buffer, get_order(env.size));
#endif
			env.size += PAGE_SIZE;
			goto enlarge_buffer;
		}
		ret = env.pos;
		goto out_err;
	}

	if (current == resource->worker.task)
		set_bit(CALLBACK_PENDING, &resource->flags);

	/* The helper may take some time.
	 * write out any unsynced meta data changes now */
	if (device)
		bsr_md_sync_if_dirty(device);
	else if (connection)
		conn_md_sync(connection);

	if (connection && device)
		peer_device = conn_peer_device(connection, device->vnr);

#ifdef _WIN
	magic_printk(83, BSR_LC_ETC, KERN_INFO_NUM, "helper command: %s %s", usermode_helper, cmd);
#elif _LIN
	magic_printk(84, BSR_LC_ETC, KERN_INFO, "helper command: %s %s", usermode_helper, cmd);
#endif

	notify_helper(NOTIFY_CALL, device, connection, cmd, 0);

#ifdef _WIN
	// BSR-822 fix to serializes handler operations
	mutex_lock(&handler_mutex);
#endif
	ret = call_usermodehelper(usermode_helper, argv, envp, UMH_WAIT_PROC);
#ifdef _WIN
	mutex_unlock(&handler_mutex);
#endif

#ifdef _WIN
	magic_printk(85, BSR_LC_ETC, ret ? KERN_WARNING_NUM : KERN_INFO_NUM,
			"helper command: %s %s exit code %u (0x%x)",
			usermode_helper, cmd,
			ret & 0xff, ret);
#elif _LIN
	magic_printk(86, BSR_LC_ETC, ret ? KERN_WARNING : KERN_INFO,
		     "helper command: %s %s exit code %u (0x%x)",
		     usermode_helper, cmd,
		     (ret >> 8) & 0xff, ret);
#endif
	notify_helper(NOTIFY_RESPONSE, device, connection, cmd, ret);

	if (current == resource->worker.task)
		clear_bit(CALLBACK_PENDING, &resource->flags);

	if (ret < 0) /* Ignore any ERRNOs we got. */
		ret = 0;
#ifdef _WIN
	kfree(env.buffer);
#else // _LIN
	free_pages((unsigned long)env.buffer, get_order(env.size));
#endif
	return ret;

    out_err:
	bsr_err(3, BSR_LC_GENL, resource, "Could not call %s user-space helper: error %d"
		 "out of memory", cmd, ret);
	return 0;
}

#undef magic_printk

static bool initial_states_pending(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	int vnr;
	bool pending = false;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if (test_bit(INITIAL_STATE_SENT, &peer_device->flags) &&
		    !test_bit(INITIAL_STATE_RECEIVED, &peer_device->flags)) {
			pending = true;
			break;
		}
	}
	rcu_read_unlock();
	return pending;
}

static bool intentional_diskless(struct bsr_resource *resource)
{
	bool intentional_diskless = true;
	struct bsr_device *device;
	int vnr;

	rcu_read_lock();

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		if (!device->device_conf.intentional_diskless) {
			intentional_diskless = false;
			break;
		}
	}
	rcu_read_unlock();

	return intentional_diskless;
}

bool conn_try_outdate_peer(struct bsr_connection *connection)
{
	struct bsr_resource *resource = connection->resource;
	ULONG_PTR last_reconnect_jif;
	enum bsr_fencing_policy fencing_policy;
	enum bsr_disk_state disk_state;
	char *ex_to_string;
	int r;
	unsigned long irq_flags;

	spin_lock_irq(&resource->req_lock);
	if (connection->cstate[NOW] >= C_CONNECTED) {
		bsr_err(4, BSR_LC_GENL, connection, "Failed to set outdate peer due to not connected. cstate(%s)", bsr_conn_str(connection->cstate[NOW]));
		spin_unlock_irq(&resource->req_lock);
		return false;
	}

	last_reconnect_jif = connection->last_reconnect_jif;

	disk_state = conn_highest_disk(connection);
	if (disk_state < D_CONSISTENT &&
		!(disk_state == D_DISKLESS && intentional_diskless(resource))) {
		begin_state_change_locked(resource, CS_VERBOSE | CS_HARD);
		__change_io_susp_fencing(connection, false);
		/* We are no longer suspended due to the fencing policy.
		 * We may still be suspended due to the on-no-data-accessible policy.
		 * If that was OND_IO_ERROR, fail pending requests. */
		if (!resource_is_suspended(resource, NOW, false))
			_tl_restart(connection, CONNECTION_LOST_WHILE_PENDING);
		end_state_change_locked(resource, false, __FUNCTION__);
		spin_unlock_irq(&resource->req_lock);
		return false;
	}
	spin_unlock_irq(&resource->req_lock);

	fencing_policy = connection->fencing_policy;
	if (fencing_policy == FP_DONT_CARE)
		return true;

	r = bsr_khelper(NULL, connection, "fence-peer");

	// DW-798, BSR-399
#ifdef _WIN
	r = r & 0xff;
#else // _LIN
	r = (r >> 8) & 0xff;
#endif

	begin_state_change(resource, &irq_flags, CS_VERBOSE);
	switch (r) {
	case P_INCONSISTENT: /* peer is inconsistent */
		ex_to_string = "peer is inconsistent or worse";
		__change_peer_disk_states(connection, D_INCONSISTENT);
		break;
	case P_OUTDATED: /* peer got outdated, or was already outdated */
		ex_to_string = "peer was fenced";
		__change_peer_disk_states(connection, D_OUTDATED);
		break;
	case P_DOWN: /* peer was down */
		if (conn_highest_disk(connection) == D_UP_TO_DATE) {
			/* we will(have) create(d) a new UUID anyways... */
			ex_to_string = "peer is unreachable, assumed to be dead";
			__change_peer_disk_states(connection, D_OUTDATED);
		} else {
			ex_to_string = "peer unreachable, doing nothing since disk != UpToDate";
		}
		break;
	case P_PRIMARY: /* Peer is primary, voluntarily outdate myself.
		 * This is useful when an unconnected R_SECONDARY is asked to
		 * become R_PRIMARY, but finds the other peer being active. */
		ex_to_string = "peer is active";
		bsr_warn(70, BSR_LC_GENL, connection, "Peer is primary, outdating myself.");
		__change_disk_states(resource, D_OUTDATED);
		break;
	case P_FENCING:
		/* THINK: do we need to handle this
		 * like case 4 P_OUTDATED, or more like case 5 P_DOWN? */
		if (fencing_policy != FP_STONITH)
			bsr_err(5, BSR_LC_GENL, connection, "fence-peer() = 7 && fencing != Stonith !!!");
		ex_to_string = "peer was stonithed";
		__change_peer_disk_states(connection, D_OUTDATED);
		break;
	default:
		/* The script is broken ... */
		bsr_err(6, BSR_LC_GENL, connection, "fence-peer helper broken, returned %d", (r >> 8) & 0xff);
		abort_state_change(resource, &irq_flags, __FUNCTION__);
		return false; /* Eventually leave IO frozen */
	}

	bsr_info(7, BSR_LC_GENL, connection, "fence-peer helper returned %d (%s)",
		  r, ex_to_string);

	if (connection->cstate[NOW] >= C_CONNECTED ||
	    initial_states_pending(connection)) {
		/* connection re-established; do not fence */
		goto abort;
	}
	if (connection->last_reconnect_jif != last_reconnect_jif) {
		/* In case the connection was established and dropped
		   while the fence-peer handler was running, ignore it */
		bsr_info(8, BSR_LC_GENL, connection, "Ignoring fence-peer exit code");
		goto abort;
	}

	end_state_change(resource, &irq_flags, __FUNCTION__);

	goto out;
 abort:
	abort_state_change(resource, &irq_flags, __FUNCTION__);
 out:
	return conn_highest_pdsk(connection) <= D_OUTDATED;
}

#ifdef _WIN
void _try_outdate_peer_async(void *data)
#else // _LIN
static int _try_outdate_peer_async(void *data)
#endif
{
	struct bsr_connection *connection = (struct bsr_connection *)data;

	conn_try_outdate_peer(connection);

	kref_debug_put(&connection->kref_debug, 4);
	kref_put(&connection->kref, bsr_destroy_connection);
#ifdef _WIN
	PsTerminateSystemThread(STATUS_SUCCESS); 
#else // _LIN
	return 0;
#endif
}

void conn_try_outdate_peer_async(struct bsr_connection *connection)
{
#ifdef _LIN
	struct task_struct *opa;
#endif
	kref_get(&connection->kref);
	kref_debug_get(&connection->kref_debug, 4);
#ifdef _WIN
	HANDLE		hThread = NULL;
	NTSTATUS	Status = STATUS_UNSUCCESSFUL;

	Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, _try_outdate_peer_async, (void *)connection);
	if (!NT_SUCCESS(Status)) {
		bsr_err(37, BSR_LC_THREAD, NO_OBJECT, "PsCreateSystemThread(_try_outdate_peer_async) failed with status 0x%08X", Status);
		kref_put(&connection->kref, bsr_destroy_connection);
	}
	else
		ZwClose (hThread);
#else // _LIN
	/* We may just have force_sig()'ed this thread
	 * to get it out of some blocking network function.
	 * Clear signals; otherwise kthread_run(), which internally uses
	 * wait_on_completion_killable(), will mistake our pending signal
	 * for a new fatal signal and fail. */
	flush_signals(current);
	opa = kthread_run(_try_outdate_peer_async, connection, "bsr_async_h");
	if (IS_ERR(opa)) {
		bsr_err(10, BSR_LC_GENL, connection, "out of mem, failed to invoke fence-peer helper");
		kref_debug_put(&connection->kref_debug, 4);
		kref_put(&connection->kref, bsr_destroy_connection);
	}
#endif
}

static bool barrier_pending(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	bool rv = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (test_bit(BARRIER_ACK_PENDING, &connection->flags)) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

// BSR-988 check whether there is resync reply data waiting for send in the send buffer.
static bool resync_reply_data_pending(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	struct bsr_peer_device *peer_device;
	LONGLONG rs_in_flight;
	int vnr;
	bool rv = false;
	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
			// BSR-988 check whether the sned buffer has resync reply data only when it is congested.
			if (peer_device->repl_state[NOW] == L_AHEAD) {
				rs_in_flight = atomic_read64(&connection->rs_in_flight);
				if (rs_in_flight) {
					rv = true;
					break;
				}
			}
		}
		if (rv)
			break;
	}
	rcu_read_unlock();
	return rv;
}

// DW-1103 down from kernel with timeout
static bool wait_for_peer_disk_updates_timeout(struct bsr_resource *resource)
{
	struct bsr_peer_device *peer_device;
	struct bsr_device *device;
	int vnr;
	long time_out = 100;
	int retry_count = 0;
restart:
	if(retry_count == 2) { // retry 2 times and if it expired, return FALSE
		return false;
	}
	rcu_read_lock();
	
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		for_each_peer_device_rcu(peer_device, device) {
			if (test_bit(GOT_NEG_ACK, &peer_device->flags)) {
				clear_bit(GOT_NEG_ACK, &peer_device->flags);
				rcu_read_unlock();
				wait_event_timeout_ex(resource->state_wait, peer_device->disk_state[NOW] < D_UP_TO_DATE, time_out, time_out);
				retry_count++;
				goto restart;
			}
		}
	}

	rcu_read_unlock();
	return true;
}



enum bsr_state_rv
bsr_set_role(struct bsr_resource *resource, enum bsr_role role, bool force, struct sk_buff *reply_skb)
{
	struct bsr_device *device;
	int vnr;
	const int max_tries = 4;
	enum bsr_state_rv rv = SS_UNKNOWN_ERROR;
	int try_val = 0;
	int forced = 0;
	bool with_force = false;
	const char *err_str = NULL;
	long timeout = 10 * HZ;
	enum chg_state_flags flags = CS_ALREADY_SERIALIZED | CS_DONT_RETRY | CS_WAIT_COMPLETE;


retry:
	down(&resource->state_sem);

	if (role == R_PRIMARY) {
		struct bsr_connection *connection;

		/* Detect dead peers as soon as possible.  */

		rcu_read_lock();
		for_each_connection_rcu(connection, resource) {
			// BSR-1393 The target-only setup node can only be promoted when the connection status with all nodes is standalone.
			if (resource->node_opts.target_only &&
				connection->cstate[NOW] != C_STANDALONE) {
				rv = SS_TARGET_ONLY;
			}
			request_ping(connection);
		}
		rcu_read_unlock();
		if (rv == SS_TARGET_ONLY)
			goto out;

	} else /* (role == R_SECONDARY) */ {
		if (start_new_tl_epoch(resource)) {
			struct bsr_connection *connection;
			u64 im;

			for_each_connection_ref(connection, im, resource)
				bsr_flush_workqueue(resource, &connection->sender_work);
		}
		// DW-1626 A long wait occurs when the barrier is delayed. Wait 10 seconds.
		wait_event_timeout_ex(resource->barrier_wait, !barrier_pending(resource), timeout, timeout);

		if (!timeout){
			bsr_warn(71, BSR_LC_GENL, NO_OBJECT, "Failed to set secondary role due to barrier ack pending timeout(10s).");
			rv = SS_BARRIER_ACK_PENDING_TIMEOUT;
			goto out;
		}

		// BSR-988
		wait_event_timeout_ex(resource->resync_reply_wait, !resync_reply_data_pending(resource), timeout, timeout);
		if (!timeout){
			bsr_warn(92, BSR_LC_GENL, NO_OBJECT, "Failed to set secondary role due to resync reply data pending timeout(10s).\n");
			rv = SS_RESYNC_REPLY_DATA_PENDING_TIMEOUT;
			goto out;
		}

		/* After waiting for pending barriers, we got any possible NEG_ACKs,
			and see them in wait_for_peer_disk_updates() */
		// DW-1460 fixup infinate wait when network connection is disconnected.
		wait_for_peer_disk_updates_timeout(resource);

		/* In case switching from R_PRIMARY to R_SECONDARY works
		   out, there is no rw opener at this point. Thus, no new
		   writes can come in. -> Flushing queued peer acks is
		   necessary and sufficient.
		   The cluster wide role change required packets to be
		   received by the aserder. -> We can be sure that the
		   peer_acks queued on asender's TODO list go out before
		   we send the two phase commit packet.
		*/
		bsr_flush_peer_acks(resource);
	}

	while (try_val++ < max_tries) {
		if (try_val == max_tries - 1)
			flags |= CS_VERBOSE;

		if (err_str) {
			bsr_kfree((void*)err_str);
			err_str = NULL;
		}
		// DW-1605
		stable_state_change(rv, resource,
			change_role(resource, role, flags, with_force, &err_str));

		if (rv == SS_CONCURRENT_ST_CHG)
			continue;

		if (rv == SS_TIMEOUT) {
			long timeout = twopc_retry_timeout(resource, try_val);
			/* It might be that the receiver tries to start resync, and
			   sleeps on state_sem. Give it up, and retry in a short
			   while */
			up(&resource->state_sem);
			schedule_timeout_interruptible(timeout);
			goto retry;
		}
		/* in case we first succeeded to outdate,
		 * but now suddenly could establish a connection */
		if (rv == SS_CW_FAILED_BY_PEER) {
			with_force = false;
			continue;
		}

		if (rv == SS_NO_UP_TO_DATE_DISK && force && !with_force) {
			// DW-647 volume size comparison before initial sync
			u64 im;
			idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
				struct bsr_peer_device *peer_device;
				for_each_peer_device_ref(peer_device, im, device) {
					unsigned long long p_size = peer_device->max_size << 9; // volume size in bytes
#ifdef _WIN
					unsigned long long l_size = get_targetdev_volsize(device->this_bdev->bd_disk->pDeviceExtension); // volume size in bytes
#else // _LIN
					unsigned long long l_size = bsr_get_max_capacity(device->ldev) << 9; // volume size in bytes
#endif
					// DW-1323 abort initial full sync when target disk is smaller than source
					// If p_size is nonzero, it was connected with the peer.
					if ((bsr_current_uuid(device) == UUID_JUST_CREATED) && 
						(p_size != 0) && 
						(l_size > p_size))
						rv = SS_TARGET_DISK_TOO_SMALL;
				}
			}

			if (rv == SS_TARGET_DISK_TOO_SMALL)
				goto out;

			with_force = true;
			forced = 1;
			continue;
		}

		if (rv == SS_NO_UP_TO_DATE_DISK && !with_force) {
			struct bsr_connection *connection;
			u64 im;

			up(&resource->state_sem); /* Allow connect while fencing */
			for_each_connection_ref(connection, im, resource) {
				struct bsr_peer_device *peer_device;
				int vnr;

				if (conn_highest_pdsk(connection) != D_UNKNOWN)
					continue;

				idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
					struct bsr_device *device = peer_device->device;

					if (device->disk_state[NOW] != D_CONSISTENT)
						continue;

					if (conn_try_outdate_peer(connection))
						with_force = true;
				}
			}
			down(&resource->state_sem);
			if (with_force)
				continue;
		}

		if (rv == SS_NOTHING_TO_DO)
			goto out;
		if (rv == SS_PRIMARY_NOP && !with_force) {
			struct bsr_connection *connection;
			u64 im;

			up(&resource->state_sem); /* Allow connect while fencing */
			for_each_connection_ref(connection, im, resource) {
				if (!conn_try_outdate_peer(connection) && force) {
					bsr_warn(72, BSR_LC_GENL, connection, "Forced into split brain situation.");
					with_force = true;
				}
			}
			down(&resource->state_sem);
			if (with_force)
				continue;
		}

		if (rv == SS_TWO_PRIMARIES) {
			struct bsr_connection *connection;
			struct net_conf *nc;
			unsigned int timeout = 0;

			/*
			 * Catch the case where we discover that the other
			 * primary has died soon after the state change
			 * failure: retry once after a short timeout.
			 */

			rcu_read_lock();
			for_each_connection_rcu(connection, resource) {
				nc = rcu_dereference(connection->transport.net_conf);
				if (nc && nc->ping_timeo > timeout)
					timeout = nc->ping_timeo;
			}
			rcu_read_unlock();
			timeout = timeout * HZ / 10;
			if (timeout == 0)
				timeout = 1;

			schedule_timeout_interruptible(timeout);
			if (try_val < max_tries)
				try_val = max_tries - 1;
			continue;
		}

		if (rv < SS_SUCCESS && !(flags & CS_VERBOSE)) {
			flags |= CS_VERBOSE;
			continue;
		}
		break;
	}

	if (rv < SS_SUCCESS)
		goto out;

	if (forced)
		bsr_warn(73, BSR_LC_GENL, resource, "Forced to consider local data as UpToDate.");

	if (role == R_SECONDARY) {
		idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
			// BSR-1191
			struct bsr_peer_device *peer_device;
			for_each_peer_device(peer_device, device) {
				ULONG_PTR bm_total = bsr_bm_total_weight(peer_device);
				bsr_info(128, BSR_LC_BITMAP, peer_device, "after completion of the secondary, the out-of-sync bit is %llu (%lluk).", bm_total, (bm_total == 0 ? 0 : bm_total * 4));
			}

			if (get_ldev(device)) {
				device->ldev->md.current_uuid &= ~UUID_PRIMARY;
				if (test_bit(__NEW_CUR_UUID, &device->flags)) {
					bsr_info(30, BSR_LC_UUID, device, "clear the UUID creation schedule flag due to secondary settings");
				}
				// DW-1985 remove NEW_CUR_UUID, __NEW_CUR_UUID when role is secondary.
				clear_bit(__NEW_CUR_UUID, &device->flags);
				if (test_bit(NEW_CUR_UUID, &device->flags)) {
					bsr_info(31, BSR_LC_UUID, device, "clear the UUID creation flag due to secondary settings");
				}
				clear_bit(NEW_CUR_UUID, &device->flags);
				// BSR-904
#ifdef _LIN
				clear_bit(UUID_WERE_INITIAL_BEFORE_PROMOTION, &device->flags);
#endif
				put_ldev(__FUNCTION__, device);
			}
		}
	} else {
		struct bsr_connection *connection;

		rcu_read_lock();
		for_each_connection_rcu(connection, resource) {
			struct bsr_peer_device *peer_device;
			clear_bit(CONN_DISCARD_MY_DATA, &connection->flags);
			// BSR-1155
			idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) 
				clear_bit(DISCARD_MY_DATA, &peer_device->flags);
		}
		rcu_read_unlock();


		idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
			// DW-1609 It has been modified to function similar to 8.4.x for younger primary 
			struct bsr_peer_device *peer_device;
			u64 im;
			bool younger_primary = false; // Add a younger_primary variable to create a new UUID if the condition is met.
			bool all_peer_uptodate = true;

			// If secondary node was promoted from Uptodate state under the following conditions, 
			// it is hard to distinguish younger primary.
			for_each_peer_device_ref(peer_device, im, device) {
				if ((peer_device->connection->cstate[NOW] < C_CONNECTED || 
					peer_device->disk_state[NOW] <= D_FAILED) 
					&& (device->ldev->md.peers[peer_device->node_id].bitmap_uuid == 0)) {
					if (younger_primary == false){
						younger_primary = true; 

						// DW-1850
						//If for_each_peer_device_ref exits to break, 
						//the reference count should be decremented.
						kref_put(&peer_device->connection->kref, bsr_destroy_connection);

						break; 
					}
				}

				// BSR-1354 
				if ((peer_device->disk_state[NOW] != D_UP_TO_DATE) || 
					(peer_device->connection->cstate[NOW] != C_CONNECTED)) {
					all_peer_uptodate = false;
				}
			} 

			if (forced) {
				// BSR-904
#ifdef _LIN
				if (UUID_JUST_CREATED == device->ldev->md.current_uuid) 
					set_bit(UUID_WERE_INITIAL_BEFORE_PROMOTION, &device->flags);
#endif
				bsr_uuid_new_current(device, true, false, true, __FUNCTION__);
			}
			else if (younger_primary) 
				// BSR-967
				// BSR-433 set UUID_FLAG_NEW_DATAGEN when sending new current UUID
				bsr_uuid_new_current(device, false, true, true, __FUNCTION__);
			else {
				// BSR-1354 if all nodes are connected and the disk state is uptodate, do not set NEW_CUR_UUID flag.
				if (all_peer_uptodate) {
					bsr_info(41, BSR_LC_UUID, device, "all nodes are connected and up to date");
				} else {
					bsr_info(25, BSR_LC_UUID, device, "set UUID creation flag due to promotion");
					set_bit(NEW_CUR_UUID, &device->flags);
				}
			}

			// DW-1154 set UUID_PRIMARY when promote a resource to primary role.
			if (get_ldev(device)) {
				device->ldev->md.current_uuid |= UUID_PRIMARY;
				put_ldev(__FUNCTION__, device);
			}
		} 
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		 struct bsr_peer_device *peer_device;
		 u64 im;

		 for_each_peer_device_ref(peer_device, im, device) {
			/* writeout of activity log covered areas of the bitmap
			 * to stable storage done in after state change already */

			if (peer_device->connection->cstate[NOW] == C_CONNECTED) {
				/* if this was forced, we should consider sync */
				if (forced) {
					bsr_send_uuids(peer_device, 0, 0, NOW);
					set_bit(CONSIDER_RESYNC, &peer_device->flags);
				}
				bsr_send_current_state(peer_device);
			}
		}
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		// DW-1154 After changing role, writes the meta data.
		bsr_md_sync(device);
		set_disk_ro(device->vdisk, role == R_SECONDARY);
		if (!resource->res_opts.auto_promote && role == R_PRIMARY)
			bsr_kobject_uevent(device);
	}

out:
	up(&resource->state_sem);

	if (err_str) {
		if (reply_skb)
			bsr_msg_put_info(reply_skb, err_str);
		bsr_kfree((void*)err_str);
		err_str = NULL;
	}
	return rv;
}

static const char *from_attrs_err_to_txt(int err)
{
	return	err == -ENOMSG ? "required attribute missing" :
		err == -EOPNOTSUPP ? "unknown mandatory attribute" :
		err == -EEXIST ? "can not change invariant setting" :
		"invalid attribute value";
}

// BSR-1064
bool wait_until_vol_ctl_mutex_is_used(struct bsr_resource *resource)
{
	int try_val = 0, max_tries = 30;
	
	// BSR-1064 wait up to 3 seconds for bsr_worker() to use vol_ctl_tx.
	while (try_val++ < max_tries) {
		if (atomic_read(&resource->will_be_used_vol_ctl_mutex) > 0)
			msleep(100);
		else
			break;
	}
	
	// BSR-1064 wait for 3 seconds and return an error if using vol_ctl_tx is not complete.
	if (try_val > max_tries) {
		return false;
	}

	return true;
}

int bsr_adm_apply_persist_role(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_state_rv retcode;
	int vnr;
	struct bsr_resource * resource;
	struct bsr_device * device;
	bool promote = false;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	resource = adm_ctx.resource;

	mutex_lock(&resource->adm_mutex);
	mutex_lock(&resource->vol_ctl_mutex);

	if (resource->res_opts.persist_role) {
		idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
			if (bsr_md_test_flag(device, MDF_WAS_PRIMARY)) {
				// BSR-1411
				if (resource->node_opts.target_only) {
					bsr_md_clear_flag(device, MDF_WAS_PRIMARY);
					bsr_md_sync(device);
				}
				promote = true;
			}
		}
		// BSR-1411
		if (resource->node_opts.target_only && promote) {
			bsr_info(93, BSR_LC_ETC, resource, "The target-only is set and will not be promoted.");
			promote = false;
		}

		if (promote) {
			idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
				if (D_DISKLESS == device->disk_state[NOW]) {
					retcode = SS_IS_DISKLESS;
					goto fail;
				}
			}

			retcode = bsr_set_role(resource, R_PRIMARY, false, NULL);

			if (retcode >= SS_SUCCESS) {
				set_bit(EXPLICIT_PRIMARY, &resource->flags);
#ifdef _WIN
				resource->bPreSecondaryLock = FALSE;
				// BSR-1463
				idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
					PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
					if (pvext)
						SetBsrlockIoBlock(pvext, FALSE);
				}
#endif
			}
			else if (retcode == SS_TARGET_DISK_TOO_SMALL)
				goto fail;

			bsr_info(94, BSR_LC_ETC, resource, "Promoted due to persist-role setting.");
		}
	}

fail:
	mutex_unlock(&resource->vol_ctl_mutex);
	mutex_unlock(&resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, (enum bsr_ret_code)retcode);

	return 0;
}

int bsr_adm_set_role(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct set_role_parms parms;
	int err;
	enum bsr_state_rv retcode;
	int vnr;
	struct bsr_device * device;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	memset(&parms, 0, sizeof(parms));
	if (info->attrs[BSR_NLA_SET_ROLE_PARMS]) {
		err = set_role_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);

	// BSR-1064
	if (!wait_until_vol_ctl_mutex_is_used(adm_ctx.resource)) {
		mutex_unlock(&adm_ctx.resource->adm_mutex);
		retcode = ERR_VOL_LOCK_ACQUISITION_TIMEOUT;
		bsr_msg_put_info(adm_ctx.reply_skb, "Failed to change role");
		goto out;
	}

	// DW-1317 acquire volume control mutex, not to conflict to (dis)mount volume.
	mutex_lock(&adm_ctx.resource->vol_ctl_mutex);

	if (info->genlhdr->cmd == BSR_ADM_PRIMARY) {
		// DW-839 not support diskless Primary
		idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
			if (D_DISKLESS == device->disk_state[NOW]) {
				retcode = SS_IS_DISKLESS;
				goto fail;
			}
		}

		retcode = bsr_set_role(adm_ctx.resource, R_PRIMARY, parms.assume_uptodate,
			adm_ctx.reply_skb);
		if (retcode >= SS_SUCCESS) {
			set_bit(EXPLICIT_PRIMARY, &adm_ctx.resource->flags);
#ifdef _WIN
			adm_ctx.resource->bPreSecondaryLock = FALSE;
#endif
			// BSR-1463 unblock I/O block on promotion and set persist role
			idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
#ifdef _WIN
				PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
				if (pvext)
					SetBsrlockIoBlock(pvext, FALSE);
#endif
				// BSR-1411
				if (!adm_ctx.resource->node_opts.target_only) {
					// BSR-1392
					bsr_md_set_flag(device, MDF_WAS_PRIMARY);
					bsr_md_sync(device);
				}
			}
		}
		else if (retcode == SS_TARGET_DISK_TOO_SMALL)
			goto fail;
		else if (retcode == SS_TARGET_ONLY)
			goto fail;
	}
	else {
#ifdef _WIN_MVFL
#ifdef _WIN_MULTI_VOLUME        
		retcode = SS_SUCCESS;

		// DW-1327 
		idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
			PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
			if (pvext)
				SetBsrlockIoBlock(pvext, TRUE);
		}

		idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
			if (device->disk_state[NOW] == D_DISKLESS)
				continue;

			if (!NT_SUCCESS(FsctlLockVolume(device->minor)))
				continue;
		}

		idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
			if (device->disk_state[NOW] == D_DISKLESS)
				continue;

			adm_ctx.resource->bPreDismountLock = TRUE;
			NTSTATUS status = FsctlFlushDismountVolume(device->minor, true);
			if (!NT_SUCCESS(status)) {
				retcode = SS_UNKNOWN_ERROR;
				adm_ctx.resource->bPreDismountLock = FALSE;
				break;
			}
		}
		
		if (retcode == SS_SUCCESS) {
			adm_ctx.resource->bPreSecondaryLock = TRUE;
			retcode = bsr_set_role(adm_ctx.resource, R_SECONDARY, false, adm_ctx.reply_skb);
			adm_ctx.resource->bPreSecondaryLock = FALSE;
			adm_ctx.resource->bPreDismountLock = FALSE;
		}

		idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
			if (device->disk_state[NOW] == D_DISKLESS)
				continue;

			FsctlUnlockVolume(device->minor);
		}

		// DW-2107 remove from block target if setting from primary to secondary fails
		if (retcode != SS_SUCCESS && adm_ctx.resource->role[NOW] == R_PRIMARY) {
			idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr)
			{
				PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
				if (pvext)
				{
					SetBsrlockIoBlock(pvext, FALSE);
				}
			}
		}
#else
		idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
			if (D_DISKLESS == device->disk_state[NOW]) {
				retcode = bsr_set_role(adm_ctx.resource, R_SECONDARY, false, adm_ctx.reply_skb);				
			} else if (NT_SUCCESS(FsctlLockVolume(device->minor))) {
				if (retcode < SS_SUCCESS) {
					FsctlUnlockVolume(device->minor);
					goto fail;
				}
				adm_ctx.resource->bPreDismountLock = TRUE;
				NTSTATUS status = FsctlFlushDismountVolume(device->minor, true);
				adm_ctx.resource->bPreSecondaryLock = TRUE;
				FsctlUnlockVolume(device->minor);

				if (!NT_SUCCESS(status)) {
					retcode = SS_UNKNOWN_ERROR;
					adm_ctx.resource->bPreDismountLock = FALSE;
					goto fail;
				}
				retcode = bsr_set_role(adm_ctx.resource, R_SECONDARY, false, adm_ctx.reply_skb);
				adm_ctx.resource->bPreSecondaryLock = FALSE;
				adm_ctx.resource->bPreDismountLock = FALSE;
			} else {
				retcode = SS_DEVICE_IN_USE;
			}
		}
#endif
#else
		retcode = bsr_set_role(adm_ctx.resource, R_SECONDARY, false, adm_ctx.reply_skb);
#endif
		if (retcode >= SS_SUCCESS) {
			clear_bit(EXPLICIT_PRIMARY, &adm_ctx.resource->flags);
			// BSR-1392
			idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
				bsr_md_clear_flag(device, MDF_WAS_PRIMARY);
				bsr_md_sync(device);
			}
		}
	}
fail:
	// DW-1317
	mutex_unlock(&adm_ctx.resource->vol_ctl_mutex);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	bsr_adm_finish(&adm_ctx, info, (enum bsr_ret_code)retcode);
	return 0;
}


u64 bsr_capacity_to_on_disk_bm_sect(u64 capacity_sect, unsigned int max_peers)
{
	u64 bits, bytes;

	/* round up storage sectors to full "bitmap sectors per bit", then
	 * convert to number of bits needed, and round that up to 64bit words
	 * to ease interoperability between 32bit and 64bit architectures.
	 */
	bits = ALIGN(BM_SECT_TO_BIT(ALIGN(capacity_sect, BM_SECT_PER_BIT)), 64);

	/* convert to bytes, multiply by number of peers,
	 * and, because we do all our meta data IO in 4k blocks,
	 * round up to full 4k
	 */
	bytes = ALIGN(bits / 8 * max_peers, 4096);

	/* convert to number of sectors */
	return bytes >> 9;
}

/* Initializes the md.*_offset members, so we are able to find
 * the on disk meta data.
 *
 * We currently have two possible layouts:
 * external:
 *   |----------- md_size_sect ------------------|
 *   [ 4k superblock ][ activity log ][  Bitmap  ]
 *   | al_offset == 8 |
 *   | bm_offset = al_offset + X      |
 *  ==> bitmap sectors = md_size_sect - bm_offset
 *
 * internal:
 *            |----------- md_size_sect ------------------|
 * [data.....][  Bitmap  ][ activity log ][ 4k superblock ]
 *                        | al_offset < 0 |
 *            | bm_offset = al_offset - Y |
 *  ==> bitmap sectors = Y = al_offset - bm_offset
 *
 *  Activity log size used to be fixed 32kB,
 *  but is about to become configurable.
 */
void bsr_md_set_sector_offsets(struct bsr_device *device,
				struct bsr_backing_dev *bdev)
{
	sector_t md_size_sect = 0;
	unsigned int al_size_sect = bdev->md.al_size_4k * 8;
	int max_peers;

	if (device->bitmap)
		max_peers = device->bitmap->bm_max_peers;
	else
		max_peers = 1;

	bdev->md.md_offset = bsr_md_ss(bdev);

	switch (bdev->md.meta_dev_idx) {
	default:
		/* v07 style fixed size indexed meta data */
		/* FIXME we should drop support for this! */
		// DW-1335
		bdev->md.md_size_sect = (256 << 20 >> 9);

		bdev->md.al_offset = (4096 >> 9);
		bdev->md.bm_offset = (4096 >> 9) + al_size_sect;
		break;
	case BSR_MD_INDEX_FLEX_EXT:
		/* just occupy the full device; unit: sectors */
#ifdef _WIN // DW-1607
		bdev->md.md_size_sect = (u32)bsr_get_md_capacity(bdev->md_bdev);
#else // _LIN
		bdev->md.md_size_sect = bsr_get_capacity(bdev->md_bdev);
#endif
		bdev->md.al_offset = (4096 >> 9);
		bdev->md.bm_offset = (4096 >> 9) + al_size_sect;
		break;
	case BSR_MD_INDEX_INTERNAL:
	case BSR_MD_INDEX_FLEX_INT:
		bdev->md.al_offset = (~al_size_sect + 1);

		/* enough bitmap to cover the storage,
		 * plus the "bsr meta data super block",
		 * and the activity log; */
		md_size_sect = bsr_capacity_to_on_disk_bm_sect(
				bsr_get_capacity(bdev->backing_bdev),
				max_peers)
			+ (4096 >> 9) + al_size_sect;

		bdev->md.md_size_sect = (u32)md_size_sect;
		/* bitmap offset is adjusted by 'super' block size */
		bdev->md.bm_offset   = (s32)(~md_size_sect + 1) + (4096 >> 9);
		break;
	}
}

/* input size is expected to be in KB */
char *ppsize(char *buf, size_t len, unsigned long long size)
{
	/* Needs 9 bytes at max including trailing NUL:
	 * -1ULL ==> "16384 EB" */
	static char units[] = { 'K', 'M', 'G', 'T', 'P', 'E' };
	int base = 0;
	while (size >= 10000 && base < sizeof(units)-1) {
		/* shift + round */
		size = (size >> 10) + !!(size & (1<<9));
		base++;
	}
#ifdef _WIN
	_snprintf(buf, len-1, "%u %cB", (unsigned)size, units[base]);
#else // _LIN
	sprintf(buf, "%u %cB", (unsigned)size, units[base]);
#endif
	
	return buf;
}

/* The receiver may call bsr_suspend_io(device, WRITE_ONLY).
 * It should not call bsr_suspend_io(device, READ_AND_WRITE) since
 * if the node is an D_INCONSISTENT R_PRIMARY (L_SYNC_TARGET) it
 * may need to issue remote READs. Those is turn need the receiver
 * to complete. -> calling bsr_suspend_io(device, READ_AND_WRITE) deadlocks.
 */
/* Note these are not to be confused with
 * bsr_adm_suspend_io/bsr_adm_resume_io,
 * which are (sub) state changes triggered by admin (bsrsetup),
 * and can be long lived.
 * This changes an device->flag, is triggered by bsr internals,
 * and should be short-lived. */
/* It needs to be a counter, since multiple threads might
   independently suspend and resume IO. */
void bsr_suspend_io(struct bsr_device *device, enum suspend_scope ss)
{
	atomic_inc(&device->suspend_cnt);
	if (bsr_suspended(device))
		return;
	wait_event(device->misc_wait,
		   (atomic_read(&device->ap_bio_cnt[WRITE]) +
		    ss == READ_AND_WRITE ? atomic_read(&device->ap_bio_cnt[READ]) : 0) == 0);
}

void bsr_resume_io(struct bsr_device *device)
{
	if (atomic_dec_and_test(&device->suspend_cnt))
		wake_up(&device->misc_wait);
}

/**
 * effective_disk_size_determined()  -  is the effective disk size "fixed" already?
 *
 * When a device is configured in a cluster, the size of the replicated disk is
 * determined by the minimum size of the disks on all nodes.  Additional nodes
 * can be added, and this can still change the effective size of the replicated
 * disk.
 *
 * When the disk on any node becomes D_UP_TO_DATE, the effective disk size
 * becomes "fixed".  It is written to the metadata so that it will not be
 * forgotten across node restarts.  Further nodes can only be added if their
 * disks are big enough.
 */
static bool effective_disk_size_determined(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;
	bool rv = false;

	if (device->ldev->md.effective_size != 0)
		return true;
	if (device->disk_state[NEW] == D_UP_TO_DATE)
		return true;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->disk_state[NEW] == D_UP_TO_DATE) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

/**
 * bsr_determine_dev_size() -  Sets the right device size obeying all constraints
 * @device:	BSR device.
 *
 * You should call bsr_md_sync() after calling this function.
 */
enum determine_dev_size
bsr_determine_dev_size(struct bsr_device *device, sector_t peer_current_size,
		enum dds_flags flags, struct resize_parms *rs) __must_hold(local)
{
	struct md_offsets_and_sizes {
		u64 effective_size;
		u64 md_offset;
		s32 al_offset;
		s32 bm_offset;
		u32 md_size_sect;

		u32 al_stripes;
		u32 al_stripe_size_4k;
	} prev;
	sector_t u_size, size;
	struct bsr_md *md = &device->ldev->md;
	char ppb[10];
	void *buffer;

	int md_moved, la_size_changed;
	enum determine_dev_size rv = DS_UNCHANGED;

	/* We may change the on-disk offsets of our meta data below.  Lock out
	 * anything that may cause meta data IO, to avoid acting on incomplete
	 * layout changes or scribbling over meta data that is in the process
	 * of being moved.
	 *
	 * Move is not exactly correct, btw, currently we have all our meta
	 * data in core memory, to "move" it we just write it all out, there
	 * are no reads. */
	bsr_suspend_io(device, READ_AND_WRITE);
	buffer = bsr_md_get_buffer(device, __func__); /* Lock meta-data IO */
	if (!buffer) {
		bsr_resume_io(device);
		return DS_ERROR;
	}

	/* remember current offset and sizes */
	prev.effective_size = md->effective_size;
	prev.md_offset = md->md_offset;
	prev.al_offset = md->al_offset;
	prev.bm_offset = md->bm_offset;
	prev.md_size_sect = md->md_size_sect;
	prev.al_stripes = md->al_stripes;
	prev.al_stripe_size_4k = md->al_stripe_size_4k;

	if (rs) {
		/* rs is non NULL if we should change the AL layout only */
		md->al_stripes = rs->al_stripes;
		md->al_stripe_size_4k = rs->al_stripe_size / 4;
		md->al_size_4k = (u64)rs->al_stripes * rs->al_stripe_size / 4;
	}

	bsr_md_set_sector_offsets(device, device->ldev);

	rcu_read_lock();
	u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
	rcu_read_unlock();
	size = bsr_new_dev_size(device, peer_current_size, u_size, flags);

	if (size < prev.effective_size) {
		if (rs && u_size == 0) {
			/* Remove "rs &&" later. This check should always be active, but
			   right now the receiver expects the permissive behavior */
			bsr_warn(74, BSR_LC_GENL, device, "Implicit shrink not allowed. "
				 "Use --size=%llus for explicit shrink.",
				 (unsigned long long)size);
			rv = DS_ERROR_SHRINK;
		}
		if (u_size > size)
			rv = DS_ERROR_SPACE_MD;
		if (rv != DS_UNCHANGED)
			goto err_out;
	}

	if (bsr_get_vdisk_capacity(device) != size ||
	    bsr_bm_capacity(device) != size) {
		int err;
		err = bsr_bm_resize(device, size, flags);
		if (unlikely(err)) {
			/* currently there is only one error: ENOMEM! */
			size = bsr_bm_capacity(device);
			if (size == 0) {
				bsr_err(103, BSR_LC_BITMAP, device, "Failed to determine device size due to device is not assigned bitmap.");
			} else {
				bsr_err(104, BSR_LC_BITMAP, device, "Failed to determine device size due to bitmap resizing failed. Leaving size unchanged");
			}
			rv = DS_ERROR;
		}
		/* racy, see comments above. */
		bsr_set_my_capacity(device, size);
		if (effective_disk_size_determined(device)) {
			md->effective_size = size;
			bsr_info(96, BSR_LC_VOLUME, device, "Update the disk size in the meta. %s (%llu KB)", ppsize(ppb, sizeof(ppb), size >> 1),
			     (unsigned long long)size >> 1);
		}
	}
	if (rv <= DS_ERROR)
		goto err_out;

	la_size_changed = (prev.effective_size != md->effective_size);

	md_moved = prev.md_offset    != md->md_offset
		|| prev.md_size_sect != md->md_size_sect;

	if (la_size_changed || md_moved || rs) {
		int i;
		bool prev_al_disabled = 0;
		u32 prev_peer_full_sync = 0;
		struct bsr_peer_device* peer_device;

		/* We do some synchronous IO below, which may take some time.
		 * Clear the timer, to avoid scary "timer expired!" messages,
		 * "Superblock" is written out at least twice below, anyways. */
		del_timer(&device->md_sync_timer);

		/* We won't change the "al-extents" setting, we just may need
		 * to move the on-disk location of the activity log ringbuffer.
		 * Lock for transaction is good enough, it may well be "dirty"
		 * or even "starving". */
		wait_event(device->al_wait, bsr_al_try_lock_for_transaction(device));

		/* mark current on-disk bitmap and activity log as unreliable */
		prev_al_disabled = !!(md->flags & MDF_AL_DISABLED);
		md->flags |= MDF_AL_DISABLED;
		for (i = 0; i < BSR_PEERS_MAX; i++) {
			if (md->peers[i].flags & MDF_PEER_FULL_SYNC)
				prev_peer_full_sync |= 1 << i;
			else
				md->peers[i].flags |= MDF_PEER_FULL_SYNC;
		}
		bsr_md_write(device, buffer);

		bsr_al_initialize(device, buffer);

		bsr_info(97, BSR_LC_VOLUME, device, "Writing the whole bitmap, %s",
			 la_size_changed && md_moved ? "replication volume size changed and meta disk data moved" :
			 la_size_changed ? "replication volume size changed" : "meta disk data moved");
		/* next line implicitly does bsr_suspend_io()+bsr_resume_io() */
		bsr_bitmap_io(device, md_moved ? &bsr_bm_write_all : &bsr_bm_write,
			       "size changed", BM_LOCK_ALL, NULL);

		/* on-disk bitmap and activity log is authoritative again
		 * (unless there was an IO error meanwhile...) */
		if (!prev_al_disabled)
			md->flags &= ~MDF_AL_DISABLED;
		for (i = 0; i < BSR_PEERS_MAX; i++) {
			if (0 == (prev_peer_full_sync & (1 << i)))
				md->peers[i].flags &= ~MDF_PEER_FULL_SYNC;
		}
		bsr_md_write(device, buffer);

		for_each_peer_device(peer_device, device) {
			// BSR-676 notify flag
			bsr_queue_notify_update_gi(NULL, peer_device, BSR_GI_NOTI_PEER_DEVICE_FLAG);
		}

		if (rs)
			bsr_info(41, BSR_LC_LRU, device, "Changed activity log layout to activity stripes(%u), activity stripe size(%ukB)",
				 md->al_stripes, md->al_stripe_size_4k * 4);
	}

	if (size > prev.effective_size)
		rv = prev.effective_size ? DS_GREW : DS_GREW_FROM_ZERO;
	if (size < prev.effective_size)
		rv = DS_SHRUNK;


	if (0) {
	err_out:
		/* restore previous offset and sizes */
		md->effective_size = prev.effective_size;
		md->md_offset = prev.md_offset;
		md->al_offset = prev.al_offset;
		md->bm_offset = prev.bm_offset;
		md->md_size_sect = prev.md_size_sect;
		md->al_stripes = prev.al_stripes;
		md->al_stripe_size_4k = prev.al_stripe_size_4k;
		md->al_size_4k = (u64)prev.al_stripes * prev.al_stripe_size_4k;
	}
	lc_unlock(device->act_log);
	wake_up(&device->al_wait);
	bsr_md_put_buffer(device);
	bsr_resume_io(device);

	return rv;
}

/**
 * all_known_peer_devices_connected()
 *
 * Check if all peer devices that have bitmap slots assigned in the metadata
 * are connected.
 */
static bool get_max_agreeable_size(struct bsr_device *device, uint64_t *max, uint64_t min) __must_hold(local)
{
	int node_id;
	bool all_known;

	all_known = true;
	rcu_read_lock();
	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		struct bsr_peer_md *peer_md = &device->ldev->md.peers[node_id];
		struct bsr_peer_device *peer_device;

		if (device->ldev->md.node_id == node_id) {
			bsr_info(98, BSR_LC_VOLUME, device, "Skip the replication volume size comparison because it is a local node id(%d)", node_id);
			continue; /* skip myself... */
		}
		/* Have we met this peer node id before? */
		if (peer_md->bitmap_index == -1)
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device) {
			enum bsr_disk_state pdsk = peer_device->disk_state[NOW];
			bsr_info(99, BSR_LC_VOLUME, peer_device, "node id(%u) bitmap index(%u) bitmap uuid(0x%llx) flags(0x%x) max size(%llu) disk state(%s)",
					node_id,
					peer_md->bitmap_index,
					peer_md->bitmap_uuid,
					peer_md->flags,
					peer_device->max_size,
					bsr_disk_str(pdsk));

			/* Note: in receive_sizes during connection handshake,
			 * repl_state may still be L_OFF;
			 * double check on cstate ... */
			if ((peer_device->repl_state[NOW] >= L_ESTABLISHED || peer_device->connection->cstate[NOW] >= C_CONNECTED)
				// DW-1799
				&& test_bit(INITIAL_SIZE_RECEIVED, &peer_device->flags)) {
				/* If we still can see it, consider its last
				 * known size, even if it may have meanwhile
				 * detached from its disk.
				 * If we no longer see it, we may want to
				 * ignore the size we last knew, and
				 * "assume_peer_has_space".  */

				if ((bsr_current_uuid(device) == UUID_JUST_CREATED) && peer_device->c_size) {
					// DW-1337 peer has already been agreed and has smaller current size. this node needs to also accept already agreed size.
					// DW-1469 only for initial sync
					*max = min_not_zero(*max, peer_device->c_size);
				} else {
					// DW-2152 if the size of the connected nodes is 0, set the minimum size.
					if (peer_device->max_size == 0)
						*max = min_not_zero(*max, min);
					else
						*max = min_not_zero(*max, peer_device->max_size);
				}
				continue;
			}
		} else {
			bsr_info(100, BSR_LC_VOLUME, device, "node id(%u) bitmap index(%u) bitmap uuid(0x%llx) flags(0x%x). not currently reachable",
					node_id,
					peer_md->bitmap_index,
					peer_md->bitmap_uuid,
					peer_md->flags);
		}
		/* Even the currently diskless peer does not really know if it
		 * is diskless on purpose (a "BSR client") or if it just was
		 * not possible to attach (backend device gone for some
		 * reason).  But we remember in our meta data if we have ever
		 * seen a peer disk for this peer.  If we did not ever see a
		 * peer disk, assume that's intentional. */
		if ((peer_md->flags & MDF_PEER_DEVICE_SEEN) == 0)
			continue;

		all_known = false;
		/* don't break yet, min aggregation may still find a peer */
	}
	rcu_read_unlock();
	return all_known;
}

#if 0
#define DDUMP_LLU(d, x) do { bsr_info(54, BSR_LC_ETC, d, "%u: " #x ": %llu", __LINE__, (unsigned long long)x); } while (0)
#else
#define DDUMP_LLU(d, x) do { } while (0)
#endif

/* MUST hold a reference on ldev. */

sector_t
bsr_new_dev_size(struct bsr_device *device,
		sector_t current_size, /* need at least this much */
		sector_t user_capped_size, /* want (at most) this much */
		enum dds_flags flags) __must_hold(local)
{
	struct bsr_resource *resource = device->resource;
	uint64_t p_size = 0;
	uint64_t la_size = device->ldev->md.effective_size; /* last agreed size */
	uint64_t m_size; /* my size */
	uint64_t size = 0;
	bool all_known_connected;

	if (flags & DDSF_2PC)
		return resource->twopc_resize.new_size;

	m_size = bsr_get_max_capacity(device->ldev);
	// DW-2152 the minimum value is the last agreed size.
	all_known_connected = get_max_agreeable_size(device, &p_size, la_size);

	if (all_known_connected) {
		/* If we currently can see all peer devices,
		 * and p_size is still 0, apparently all our peers have been
		 * diskless, always.  If we have the only persistent backend,
		 * only our size counts. */
		DDUMP_LLU(device, p_size);
		DDUMP_LLU(device, m_size);
		p_size = min_not_zero(p_size, m_size);
	} else if (flags & DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE) {
		DDUMP_LLU(device, p_size);
		DDUMP_LLU(device, m_size);
		DDUMP_LLU(device, la_size);
		p_size = min_not_zero(p_size, m_size);
		if (p_size > la_size)
			bsr_warn(75, BSR_LC_GENL, device, "Resize the volume even if it is not connected to all peers.");
	} else {
		DDUMP_LLU(device, p_size);
		DDUMP_LLU(device, m_size);
		DDUMP_LLU(device, la_size);
		/* We currently cannot see all peer devices,
		 * fall back to what we last agreed upon. */
		p_size = min_not_zero(p_size, la_size);
	}

	DDUMP_LLU(device, p_size);
	DDUMP_LLU(device, m_size);
	size = min_not_zero(p_size, m_size);
	DDUMP_LLU(device, size);


	if (size == 0)
		bsr_err(19, BSR_LC_GENL, device, "Failed to get new device size due to all nodes diskless!");

	if (flags & DDSF_IGNORE_PEER_CONSTRAINTS) {
		if (current_size > size
			&&  current_size <= m_size)
			size = current_size;
	}

	if (user_capped_size > size)
		bsr_err(20, BSR_LC_GENL, device, "Failed to get new device size due to requested disk size is too big (%llu > %llu)kiB",
		(unsigned long long)user_capped_size >> 1,
		(unsigned long long)size >> 1);
	else if (user_capped_size)
		size = user_capped_size;

	return size;
}

/**
 * bsr_check_al_size() - Ensures that the AL is of the right size
 * @device:	BSR device.
 *
 * Returns -EBUSY if current al lru is still used, -ENOMEM when allocation
 * failed, and 0 on success. You should call bsr_md_sync() after you called
 * this function.
 */
static int bsr_check_al_size(struct bsr_device *device, struct disk_conf *dc)
{
	struct lru_cache *n, *t;
	struct lc_element *e;
	unsigned int in_use;
	unsigned int i;

	if (device->act_log &&
	    device->act_log->nr_elements == dc->al_extents)
		return 0;

	in_use = 0;
	t = device->act_log;
#ifdef _WIN
	n = lc_create("act_log", &bsr_al_ext_cache, AL_UPDATES_PER_TRANSACTION,
		dc->al_extents, sizeof(struct lc_element), 0);
#else // _LIN
	n = lc_create("act_log", bsr_al_ext_cache, AL_UPDATES_PER_TRANSACTION,
		dc->al_extents, sizeof(struct lc_element), 0);
#endif
	if (n == NULL) {
		bsr_err(34, BSR_LC_LRU, device, "Failed to check activity log size due to cannot allocate activity log LRU");
		return -ENOMEM;
	}
	spin_lock_irq(&device->al_lock);
	if (t) {
		for (i = 0; i < t->nr_elements; i++) {
			e = lc_element_by_index(t, i);
			if (e->refcnt)
				bsr_err(35, BSR_LC_LRU, device, "reference count has non-zero element(%u), reference count(%u)", e->lc_number, e->refcnt);
			in_use += e->refcnt;
		}
	}
	if (!in_use)
		device->act_log = n;
	spin_unlock_irq(&device->al_lock);
	if (in_use) {
		bsr_err(36, BSR_LC_LRU, device, "Failed to check activity log size due to activity log is already in use.");
		lc_destroy(n);
		return -EBUSY;
	} else {
		lc_destroy(t);
	}
	bsr_md_mark_dirty(device); /* we changed device->act_log->nr_elemens */
	return 0;
}

static u32 common_connection_features(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	u32 features = UINT32_MAX;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] < C_CONNECTED)
			continue;
		features &= connection->agreed_features;
	}
	rcu_read_unlock();

	return features;
}

static void blk_queue_discard_granularity(struct request_queue *q, unsigned int granularity)
{
	q->limits.discard_granularity = granularity;
}

static unsigned int bsr_max_discard_sectors(struct bsr_resource *resource)
{
	struct bsr_connection *connection;
	unsigned int s = BSR_MAX_BBIO_SECTORS;

	/* when we introduced WRITE_SAME support, we also bumped
	 * our maximum supported batch bio size used for discards. */
	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (!(connection->agreed_features & BSR_FF_WSAME)) {
			/* before, with BSR <= 8.4.6, we only allowed up to one AL_EXTENT_SIZE. */
			s = AL_EXTENT_SIZE >> 9;
		}
	}
	rcu_read_unlock();

	return s;
}

#ifdef _LIN

#ifndef COMPAT_HAVE_BLK_QUEUE_FLAG_SET
static void blk_queue_flag_set(unsigned int flag, struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	queue_flag_set(flag, q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static void blk_queue_flag_clear(unsigned int flag, struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	queue_flag_clear(flag, q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
#endif


static void decide_on_discard_support(struct bsr_device *device,
			struct request_queue *q,
			struct request_queue *b,
			bool discard_zeroes_if_aligned)
{
	/* q = bsr device queue (device->rq_queue)
	 * b = backing device queue (device->ldev->backing_bdev->bd_disk->queue),
	 *     or NULL if diskless
	 */
	bool can_do = b ? bdev_max_discard_sectors(device->ldev->backing_bdev) : true;

	if (can_do && b && !queue_discard_zeroes_data(b) && !discard_zeroes_if_aligned) {
		can_do = false;
		bsr_info(24, BSR_LC_GENL, device, "discard zeroes data=0 and discard zeroes if aligned=no: disabling discards");
	}
	if (can_do && !(common_connection_features(device->resource) & BSR_FF_TRIM)) {
		can_do = false;
		bsr_info(25, BSR_LC_GENL, device, "peer BSR too old, does not support TRIM: disabling discards");
	}
	if (can_do) {
		/* We don't care for the granularity, really.
		 * Stacking limits below should fix it for the local
		 * device.  Whether or not it is a suitable granularity
		 * on the remote device is not our problem, really. If
		 * you care, you need to use devices with similar
		 * topology on all peers. */
		blk_queue_discard_granularity(q, 512);
		q->limits.max_discard_sectors = bsr_max_discard_sectors(device->resource);
#ifdef COMPAT_HAVE_QUEUE_FLAG_DISCARD
		blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
#endif
	} else {
#ifdef COMPAT_HAVE_QUEUE_FLAG_DISCARD
		blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
#endif
		blk_queue_discard_granularity(q, 0);
		q->limits.max_discard_sectors = 0;
	}
}

static void fixup_discard_if_not_supported(struct bsr_device *device, struct request_queue *q)
{
	/* To avoid confusion, if this queue does not support discard, clear
	 * max_discard_sectors, which is what lsblk -D reports to the user.
	 * Older kernels got this wrong in "stack limits".
	 * */

	unsigned int max_discard = device->rq_queue->limits.max_discard_sectors;
	unsigned int discard_granularity = device->rq_queue->limits.discard_granularity >> SECTOR_SHIFT;

	if (discard_granularity > max_discard) {
		blk_queue_max_discard_sectors(q, 0);
#ifdef COMPAT_HAVE_QUEUE_FLAG_DISCARD
		blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
#endif
		blk_queue_discard_granularity(q, 0);
	}
}

static void fixup_write_zeroes(struct bsr_device *device, struct request_queue *q)
{
#ifdef COMPAT_HAVE_REQ_OP_WRITE_ZEROES
	/* Fixup max_write_zeroes_sectors after blk_stack_limits():
	 * if we can handle "zeroes" efficiently on the protocol,
	 * we want to do that, even if our backend does not announce
	 * max_write_zeroes_sectors itself. */

	/* If all peers announce WZEROES support, use it.  Otherwise, rather
	 * send explicit zeroes than rely on some discard-zeroes-data magic. */
	if (common_connection_features(device->resource) & BSR_FF_WZEROES)
		q->limits.max_write_zeroes_sectors = BSR_MAX_BBIO_SECTORS;
	else
		q->limits.max_write_zeroes_sectors = 0;
#endif
}

#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
static void decide_on_write_same_support(struct bsr_device *device,
			struct request_queue *q,
			struct request_queue *b, struct o_qlim *o,
			bool disable_write_same)
{
#ifndef COMPAT_WRITE_SAME_CAPABLE
	bsr_dbg(device, "This kernel is too old, no WRITE_SAME support.");
#else
	bool can_do = b ? b->limits.max_write_same_sectors : true;

	if (can_do && disable_write_same) {
		can_do = false;
		bsr_info(26, BSR_LC_GENL, device, "WRITE_SAME disabled by config");
	}

	if (can_do && !(common_connection_features(device->resource) & BSR_FF_WSAME)) {
		can_do = false;
		bsr_info(27, BSR_LC_GENL, device, "peer does not support WRITE_SAME");
	}

	if (o) {
		/* logical block size; queue_logical_block_size(NULL) is 512 */
		unsigned int peer_lbs = be32_to_cpu(o->logical_block_size);
		unsigned int me_lbs_b = queue_logical_block_size(b);
		unsigned int me_lbs = queue_logical_block_size(q);

		if (me_lbs_b != me_lbs) {
			bsr_warn(76, BSR_LC_GENL, device,
				"Logical block size of local backend does not match (bsr:%u, backend:%u).",
				me_lbs, me_lbs_b);
			/* rather disable write same than trigger some BUG_ON later in the scsi layer. */
			can_do = false;
		}
		if (me_lbs_b != peer_lbs) {
			bsr_warn(77, BSR_LC_GENL, device, "Logical block size mismatch between local and peer (me:%u, peer:%u). This may cause problems.",
				me_lbs, peer_lbs);
			if (can_do) {
				bsr_dbg(device, "logical block size mismatch: WRITE_SAME disabled.");
				can_do = false;
			}
			me_lbs = max(me_lbs, me_lbs_b);
			/* We cannot change the logical block size of an in-use queue.
			 * We can only hope that access happens to be properly aligned.
			 * If not, the peer will likely produce an IO error, and detach. */
			if (peer_lbs > me_lbs) {
				if (device->resource->role[NOW] != R_PRIMARY) {
					blk_queue_logical_block_size(q, peer_lbs);
					bsr_warn(78, BSR_LC_GENL, device, "Logical block size set to %u", peer_lbs);
				} else {
					bsr_warn(79, BSR_LC_GENL, device,
						"Current Primary must NOT adjust logical block size (%u -> %u); hope for the best.",
						me_lbs, peer_lbs);
				}
			}
		}
		if (can_do && !o->write_same_capable) {
			/* If we introduce an open-coded write-same loop on the receiving side,
			 * the peer would present itself as "capable". */
			bsr_dbg(device, "WRITE_SAME disabled (peer device not capable)");
			can_do = false;
		}
	}

	blk_queue_max_write_same_sectors(q, can_do ? BSR_MAX_BBIO_SECTORS : 0);
#endif
}
#endif
#endif

static void bsr_setup_queue_param(struct bsr_device *device, struct bsr_backing_dev *bdev,
				   unsigned int max_bio_size, struct o_qlim *o)
{
	struct request_queue * const q = device->rq_queue;
	unsigned int max_hw_sectors = max_bio_size >> 9;
	struct request_queue *b = NULL;
	struct disk_conf *dc;
	bool discard_zeroes_if_aligned = true;
	// BSR-985 set the default value to disable write same 
	bool disable_write_same = true;

	UNREFERENCED_PARAMETER(o);

	if (bdev) {
		b = bdev->backing_bdev->bd_disk->queue;

		max_hw_sectors = (unsigned int)(min(queue_max_hw_sectors(b), max_bio_size >> 9));
		rcu_read_lock();
		dc = rcu_dereference(device->ldev->disk_conf);
		discard_zeroes_if_aligned = dc->discard_zeroes_if_aligned;
		disable_write_same = dc->disable_write_same;
		rcu_read_unlock();

		blk_set_stacking_limits(&q->limits);
	}

	blk_queue_max_hw_sectors(q, max_hw_sectors);
	/* This is the workaround for "bio would need to, but cannot, be split" */
#ifdef _LIN
	blk_queue_segment_boundary(q, PAGE_SIZE-1);
	decide_on_discard_support(device, q, b, discard_zeroes_if_aligned);
#ifdef COMPAT_HAVE_BLK_QUEUE_MAX_WRITE_SAME_SECTORS
	decide_on_write_same_support(device, q, b, o, disable_write_same);

#endif
	if (b) {
		blk_stack_limits(&q->limits, &b->limits, 0);
#if defined(COMPAT_HAVE_DISK_UPDATE_READAHEAD)
		disk_update_readahead(device->vdisk);
#elif defined(COMPAT_HAVE_BLK_QUEUE_UPDATE_READAHEAD)
		blk_queue_update_readahead(q);
#else
		adjust_ra_pages(q, b);
#endif
	}
	fixup_discard_if_not_supported(device, q);
	fixup_write_zeroes(device, q);
#endif
}

void bsr_reconsider_queue_parameters(struct bsr_device *device, struct bsr_backing_dev *bdev, struct o_qlim *o)
{
	unsigned int max_bio_size = device->device_conf.max_bio_size;
	struct bsr_peer_device *peer_device;

	if (bdev) {
		max_bio_size = (unsigned int)(min(max_bio_size,
			queue_max_hw_sectors(bdev->backing_bdev->bd_disk->queue) << 9));
	}

	spin_lock_irq(&device->resource->req_lock);
	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			max_bio_size = min(max_bio_size, peer_device->max_bio_size);
	}
	spin_unlock_irq(&device->resource->req_lock);

	bsr_setup_queue_param(device, bdev, max_bio_size, o);
}

/* Make sure IO is suspended before calling this function(). */
static void bsr_try_suspend_al(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;
	bool suspend = true;
	int max_peers = device->bitmap->bm_max_peers, bitmap_index;

	for (bitmap_index = 0; bitmap_index < max_peers; bitmap_index++) {
		if (_bsr_bm_total_weight(device, bitmap_index) !=
		    bsr_bm_bits(device))
			return;
	}

	if (!bsr_al_try_lock(device)) {
		bsr_warn(80, BSR_LC_GENL, device, "Failed to lock activity log in %s()", __func__);
		return;
	}

	bsr_al_shrink(device);
	spin_lock_irq(&device->resource->req_lock);
	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED) {
			suspend = false;
			break;
		}
	}
	if (suspend)
		suspend = !test_and_set_bit(AL_SUSPENDED, &device->flags);
	spin_unlock_irq(&device->resource->req_lock);
	lc_unlock(device->act_log);

	if (suspend)
		bsr_info(28, BSR_LC_GENL, device, "Suspended AL updates");
}


static bool should_set_defaults(struct genl_info *info)
{

#ifdef COMPAT_HAVE_GENL_INFO_USERHDR
	unsigned flags = ((struct bsr_genlmsghdr*)genl_info_userhdr(info))->flags;
#else
	unsigned flags = ((struct bsr_genlmsghdr*)info->userhdr)->flags;
#endif	
	return 0 != (flags & BSR_GENL_F_SET_DEFAULTS);
}

static unsigned int bsr_al_extents_max(struct bsr_backing_dev *bdev)
{
	/* This is limited by 16 bit "slot" numbers,
	 * and by available on-disk context storage.
	 *
	 * Also (u16)~0 is special (denotes a "free" extent).
	 *
	 * One transaction occupies one 4kB on-disk block,
	 * we have n such blocks in the on disk ring buffer,
	 * the "current" transaction may fail (n-1),
	 * and there is 919 slot numbers context information per transaction.
	 *
	 * 72 transaction blocks amounts to more than 2**16 context slots,
	 * so cap there first.
	 */
	const unsigned int max_al_nr = BSR_AL_EXTENTS_MAX;
	const unsigned int sufficient_on_disk =
		(max_al_nr + AL_CONTEXT_PER_TRANSACTION -1)
		/AL_CONTEXT_PER_TRANSACTION;

	unsigned int al_size_4k = bdev->md.al_size_4k;

	if (al_size_4k > sufficient_on_disk)
		return max_al_nr;

	return (al_size_4k - 1) * AL_CONTEXT_PER_TRANSACTION;
}

static bool write_ordering_changed(struct disk_conf *a, struct disk_conf *b)
{
	return	a->disk_barrier != b->disk_barrier ||
		a->disk_flushes != b->disk_flushes ||
		a->disk_drain != b->disk_drain;
}

static void sanitize_disk_conf(struct bsr_device *device, struct disk_conf *disk_conf,
			       struct bsr_backing_dev *nbc)
{
	struct request_queue * const q = nbc->backing_bdev->bd_disk->queue;

	if (disk_conf->al_extents < BSR_AL_EXTENTS_MIN)
		disk_conf->al_extents = BSR_AL_EXTENTS_MIN;
	if (disk_conf->al_extents > bsr_al_extents_max(nbc))
		disk_conf->al_extents = bsr_al_extents_max(nbc);

	if (!bdev_max_discard_sectors(nbc->backing_bdev) ||
	    (!queue_discard_zeroes_data(q) && !disk_conf->discard_zeroes_if_aligned)) {
		if (disk_conf->rs_discard_granularity) {
			disk_conf->rs_discard_granularity = 0; /* disable feature */
			bsr_info(29, BSR_LC_GENL, device, "Disable rs-discard-granularity feature in disk configuration");
		}
	}

	if (disk_conf->rs_discard_granularity) {
		int orig_value = disk_conf->rs_discard_granularity;
		int remainder;

		if (q->limits.discard_granularity > disk_conf->rs_discard_granularity)
			disk_conf->rs_discard_granularity = q->limits.discard_granularity;

		remainder = disk_conf->rs_discard_granularity % q->limits.discard_granularity;
		disk_conf->rs_discard_granularity += remainder;

		if (disk_conf->rs_discard_granularity > q->limits.max_discard_sectors << 9)
			disk_conf->rs_discard_granularity = q->limits.max_discard_sectors << 9;

		if (disk_conf->rs_discard_granularity != (unsigned int)orig_value)
			bsr_info(30, BSR_LC_GENL, device, "changed the rs-discard-granularity setting %u to %u",
					(unsigned int)orig_value, disk_conf->rs_discard_granularity);
	}
}

int bsr_adm_disk_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;
	struct bsr_device *device;
	struct bsr_resource *resource;
	struct disk_conf *new_disk_conf, *old_disk_conf;
	struct bsr_peer_device *peer_device; 
	u32 md_flags;
	int err;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;
	resource = device->resource;
	mutex_lock(&adm_ctx.resource->adm_mutex);

	/* we also need a disk
	 * to change the options on */
	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}

	new_disk_conf = bsr_kmalloc(sizeof(struct disk_conf), GFP_KERNEL, '51SB');
	if (!new_disk_conf) {
		retcode = ERR_NOMEM;
		goto fail;
	}

	mutex_lock(&resource->conf_update);
	old_disk_conf = device->ldev->disk_conf;
	*new_disk_conf = *old_disk_conf;
	if (should_set_defaults(info))
		set_disk_conf_defaults(new_disk_conf);

	err = disk_conf_from_attrs_for_change(new_disk_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail_unlock;
	}

	sanitize_disk_conf(device, new_disk_conf, device->ldev);

	bsr_suspend_io(device, READ_AND_WRITE);
	wait_event(device->al_wait, bsr_al_try_lock(device));
	bsr_al_shrink(device);
	err = bsr_check_al_size(device, new_disk_conf);
	lc_unlock(device->act_log);
	wake_up(&device->al_wait);
	bsr_resume_io(device);

	if (err) {
		retcode = ERR_NOMEM;
		goto fail_unlock;
	}

	lock_all_resources();
	retcode = bsr_resync_after_valid(device, new_disk_conf->resync_after);
	if (retcode == ERR_NO) {
#ifdef _WIN
		synchronize_rcu_w32_wlock();
#endif
		rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
#ifdef _WIN
		synchronize_rcu();
#endif
		bsr_resync_after_changed(device);
	}
	unlock_all_resources();

	if (retcode != ERR_NO)
		goto fail_unlock;

	mutex_unlock(&resource->conf_update);

	md_flags = device->ldev->md.flags;

	if (new_disk_conf->al_updates)
		device->ldev->md.flags &= ~MDF_AL_DISABLED;
	else
		device->ldev->md.flags |= MDF_AL_DISABLED;

	if (new_disk_conf->md_flushes)
		clear_bit(MD_NO_FUA, &device->flags);
	else
		set_bit(MD_NO_FUA, &device->flags);

	if (write_ordering_changed(old_disk_conf, new_disk_conf))
		bsr_bump_write_ordering(device->resource, NULL, WO_BIO_BARRIER);

	if (old_disk_conf->discard_zeroes_if_aligned != new_disk_conf->discard_zeroes_if_aligned
		|| old_disk_conf->disable_write_same != new_disk_conf->disable_write_same)
		bsr_reconsider_queue_parameters(device, device->ldev, NULL);

	bsr_md_sync_if_dirty(device);

	// BSR-676 notify flag
	if ((md_flags & MDF_AL_DISABLED) != (device->ldev->md.flags & MDF_AL_DISABLED)) {
		bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_DEVICE_FLAG);
	}

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			bsr_send_sync_param(peer_device);
	}

#ifdef _LIN
	// windows skip synchronize_rcu 
	synchronize_rcu();
#endif
	bsr_kfree(old_disk_conf);
	mod_timer(&device->request_timer, jiffies + HZ);
	goto success;

fail_unlock:
	mutex_unlock(&resource->conf_update);
 fail:
	bsr_kfree(new_disk_conf);
success:
#ifdef _LIN
    // windows skip synchronize_rcu 
	if (retcode != ERR_NO)
		synchronize_rcu();
#endif
	put_ldev(__FUNCTION__, device);
out:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static void mutex_unlock_cond(struct mutex *mutex, bool *have_mutex)
{
	if (*have_mutex) {
		mutex_unlock(mutex);
		*have_mutex = false;
	}
}

static void update_resource_dagtag(struct bsr_resource *resource, struct bsr_backing_dev *bdev)
{
	u64 dagtag = 0;
	int node_id;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		struct bsr_peer_md *peer_md;
		if (bdev->md.node_id == node_id)
			continue;

		peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_uuid)
			dagtag = max(peer_md->bitmap_dagtag, dagtag);
	}
	if (dagtag > resource->dagtag_sector)
		resource->dagtag_sector = dagtag;
}

static int used_bitmap_slots(struct bsr_backing_dev *bdev)
{
	int node_id;
	int used = 0;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		struct bsr_peer_md *peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_index != -1)
			used++;
	}

	return used;
}

static bool bitmap_index_vacant(struct bsr_backing_dev *bdev, int bitmap_index)
{
	int node_id;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		struct bsr_peer_md *peer_md = &bdev->md.peers[node_id];

		if (peer_md->bitmap_index == bitmap_index)
			return false;
	}
	return true;
}

static int
allocate_bitmap_index(struct bsr_peer_device *peer_device,
struct bsr_backing_dev *nbc)
{
	struct bsr_device *device = peer_device->device;
	const int peer_node_id = peer_device->connection->peer_node_id;
	unsigned int bitmap_index;

	for (bitmap_index = 0; bitmap_index < device->bitmap->bm_max_peers; bitmap_index++) {
		if (bitmap_index_vacant(nbc, bitmap_index)) {
			struct bsr_peer_md *peer_md = &nbc->md.peers[peer_node_id];

			peer_md->bitmap_index = bitmap_index;
			peer_device->bitmap_index = bitmap_index;
			peer_md->flags &= ~MDF_NODE_EXISTS; /* it is a peer now */
			return 0;
		}
	}
	bsr_err(105, BSR_LC_BITMAP, peer_device, "Failed to allocate bitmap index due to not enough free bitmap slots");
	return -ENOSPC;
}
// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
static struct file *open_backing_dev(
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
static struct bdev_handle *open_backing_dev(
#else
static struct block_device *open_backing_dev(
#endif
#endif
	struct bsr_device *device, const char *bdev_path, void *claim_ptr, bool do_bd_link)
{

#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	struct bdev_handle *handle;
#endif
	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	struct file *file;
#endif
	struct block_device *bdev = NULL;
	int err = 0;
	int retry = 0;

retry:
	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	file = bdev_file_open_by_path(bdev_path, BLK_OPEN_READ | BLK_OPEN_WRITE, claim_ptr, NULL);
	if (IS_ERR(file)) {
		bsr_err(140, BSR_LC_DRIVER, device, "Failed to open(\"%s\") backing device with %ld",
			bdev_path, PTR_ERR(file));
		return file;
	}

	if (!do_bd_link)
		return file;
	bdev = file_bdev(file);
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	handle = bdev_open_by_path(bdev_path, BLK_OPEN_READ | BLK_OPEN_WRITE, claim_ptr, NULL);
	if (!handle) {
		pr_err("Failed to open block device\n");
		return -EINVAL;
	}

	if (!do_bd_link)
		return handle;
	bdev = handle->bdev;
#else
#ifdef _WIN
	bdev = blkdev_get_by_path(bdev_path, FMODE_READ | FMODE_WRITE | FMODE_EXCL, claim_ptr, false);
#else // _LIN
#ifdef COMPAT_HAVE_BLKDEV_GET_BY_PATH_4_PARAMS
	bdev = blkdev_get_by_path(bdev_path, FMODE_READ | FMODE_WRITE | FMODE_EXCL, claim_ptr, NULL);
#else
	bdev = blkdev_get_by_path(bdev_path, FMODE_READ | FMODE_WRITE | FMODE_EXCL, claim_ptr);	
#endif
#endif
	if (IS_ERR(bdev)) {
		bsr_err(140, BSR_LC_DRIVER, device, "Failed to open(\"%s\") backing device with %ld",
				bdev_path, PTR_ERR(bdev));
		// BSR-1106 retry up to 3 times if the specified error occurs.
		if (PTR_ERR(bdev) == -EBUSY) {
			if (retry < 3) {
				msleep(1000);
				retry++;
				goto retry;
			}
		}
		return bdev;
	}

#ifdef _WIN
	// DW-1109 inc ref when open it.
	kref_get(&bdev->kref);
#endif
	if (!do_bd_link)
		return bdev;
#endif
#endif

#if   defined(COMPAT_HAVE_BD_UNLINK_DISK_HOLDER)
	err = bd_link_disk_holder(bdev, device->vdisk);
#elif defined(COMPAT_HAVE_BD_CLAIM_BY_DISK)
	err = bd_claim_by_disk(bdev, claim_ptr, device->vdisk);
#endif
	if (err) {

		// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
		fput(file);
		bsr_err(141, BSR_LC_DRIVER, device, "Failed to open(\"%s\") backing device due to bd_link_disk_holder() with %d",
			bdev_path, err);
		file = ERR_PTR(err);
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
		bdev_release(handle);

		bsr_err(141, BSR_LC_DRIVER, device, "Failed to open(\"%s\") backing device due to bd_link_disk_holder() with %d",
			bdev_path, err);
		handle = ERR_PTR(err);
#else
		// BSR-1376
#ifdef COMPAT_HAVE_BLKDEV_PUT_PARAM_HOLDER
		blkdev_put(bdev, claim_ptr);
#else
		blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
#endif
		bsr_err(141, BSR_LC_DRIVER, device, "Failed to open(\"%s\") backing device due to bd_link_disk_holder() with %d",
			bdev_path, err);
		bdev = ERR_PTR(err);
#endif
#endif
	}
#if 0 // DW-1510 The bd_contains value is not appropriate when the device size is updated. Return bdev.
#ifdef _WIN
	if (bdev->bd_contains) {
		return bdev->bd_contains;
	}
#endif
#endif

	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	return file;
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	return handle;
#else
	return bdev;
#endif
#endif
}

static int open_backing_devices(struct bsr_device *device,
		struct disk_conf *new_disk_conf,
		struct bsr_backing_dev *nbc)
{
	struct block_device *bdev;
	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	struct file *file;

	file = open_backing_dev(device, new_disk_conf->backing_dev, device, true);
	if (IS_ERR(file))
		return ERR_OPEN_DISK;
	nbc->backing_bdev_file = file;
	bdev = file_bdev(file);
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	struct bdev_handle *handle;

	handle = open_backing_dev(device, new_disk_conf->backing_dev, device, true);
	if (IS_ERR(handle))
		return ERR_OPEN_DISK;
	nbc->backing_bdev_handle = handle;
	bdev = handle->bdev;
#else

	bdev = open_backing_dev(device, new_disk_conf->backing_dev, device, true);
	if (IS_ERR(bdev))
		return ERR_OPEN_DISK;
#endif
#endif
	nbc->backing_bdev = bdev;
#ifdef _WIN
	// DW-1277 mark that this will be using as replication volume.
	set_bit(VOLUME_TYPE_REPL, &bdev->bd_disk->pDeviceExtension->Flag);
#endif

	/*
	 * meta_dev_idx >= 0: external fixed size, possibly multiple
	 * bsr sharing one meta device.  TODO in that case, paranoia
	 * check that [md_bdev, meta_dev_idx] is not yet used by some
	 * other bsr minor!  (if you use bsr.conf + bsradm, that
	 * should check it for you already; but if you don't, or
	 * someone fooled it, we need to double check here)
	 */
	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	file = open_backing_dev(device, new_disk_conf->meta_dev,
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	handle = open_backing_dev(device, new_disk_conf->meta_dev,
#else
	bdev = open_backing_dev(device, new_disk_conf->meta_dev,
#endif
#endif
		/* claim ptr: device, if claimed exclusively; shared bsr_m_holder,
		 * if potentially shared with other bsr minors */
			(new_disk_conf->meta_dev_idx < 0) ? (void*)device : (void*)bsr_m_holder,
		/* avoid double bd_claim_by_disk() for the same (source,target) tuple,
		 * as would happen with internal metadata. */
			(new_disk_conf->meta_dev_idx != BSR_MD_INDEX_FLEX_INT &&
			 new_disk_conf->meta_dev_idx != BSR_MD_INDEX_INTERNAL));

	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	if (IS_ERR(file))
		return ERR_OPEN_MD_DISK;
	nbc->md_bdev_file = file;
	bdev = file_bdev(file);
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	if (IS_ERR(handle))
		return ERR_OPEN_MD_DISK;
	nbc->md_bdev_handle = handle;
	bdev = handle->bdev;
#else
	if (IS_ERR(bdev))
		return ERR_OPEN_MD_DISK;
#endif
#endif
	nbc->md_bdev = bdev;
#ifdef _WIN
	// DW-1277 mark that this will be using as meta volume.
	set_bit(VOLUME_TYPE_META, &bdev->bd_disk->pDeviceExtension->Flag);
	bdev->bd_disk->private_data = nbc;		// for removing
#endif
	return ERR_NO;
}

		// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
static void close_backing_dev(struct bsr_device *device, struct file *file, 
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE

static void close_backing_dev(struct bsr_device *device, struct bdev_handle *handle,
#else
static void close_backing_dev(struct bsr_device *device, struct block_device *bdev,
#endif
#endif
	// BSR-1376
#ifdef COMPAT_HAVE_BLKDEV_PUT_PARAM_HOLDER
	void *holder,
#endif
	bool do_bd_unlink)
{
	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	struct block_device *bdev;
	if (!file)
		return;
	bdev = file_bdev(file);
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	struct block_device *bdev;
	
	if (!handle)
		return;
	bdev = handle->bdev;
#endif
#endif
	UNREFERENCED_PARAMETER(device);

	if (!bdev)
		return;
	if (do_bd_unlink) {
#if   defined(COMPAT_HAVE_BD_UNLINK_DISK_HOLDER)
		bd_unlink_disk_holder(bdev, device->vdisk);
#elif defined(COMPAT_HAVE_BD_CLAIM_BY_DISK)
		bd_release_from_disk(bdev, device->vdisk);
#endif
	}

	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	fput(file);
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	bdev_release(handle);
#else
// BSR-1376
#ifdef COMPAT_HAVE_BLKDEV_PUT_PARAM_HOLDER
	blkdev_put(bdev, holder);
#else
	blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
#endif
#endif
#endif
}

void bsr_backing_dev_free(struct bsr_device *device, struct bsr_backing_dev *ldev)
{
	if (ldev == NULL)
		return;
#ifdef _WIN
	if (ldev->md_bdev) {
		// Unlink not to be referred when removing meta volume
		struct block_device * bd = ldev->md_bdev;
		bd->bd_disk->private_data = NULL;
	}
#endif
	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	close_backing_dev(device, ldev->md_bdev_file,
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	close_backing_dev(device, ldev->md_bdev_handle,
#else
	close_backing_dev(device, ldev->md_bdev,
#endif
#endif
// BSR-1376
#ifdef COMPAT_HAVE_BLKDEV_PUT_PARAM_HOLDER
		(rcu_dereference(device->ldev->disk_conf)->meta_dev_idx < 0) ? (void*)device : (void*)bsr_m_holder, 
#endif
		ldev->md_bdev != ldev->backing_bdev);

	// BSR-1452
#ifdef COMPAT_HAVE_BLKDEV_FILE
	close_backing_dev(device, ldev->backing_bdev_file,
#else
#ifdef COMPAT_HAVE_BLKDEV_HANDLE
	close_backing_dev(device, ldev->backing_bdev_handle,
#else
	close_backing_dev(device, ldev->backing_bdev,
#endif
#endif
		// BSR-1376
#ifdef COMPAT_HAVE_BLKDEV_PUT_PARAM_HOLDER
		(void*)device,
#endif
		true);

	bsr_kfree(ldev->disk_conf);
	bsr_kfree(ldev);
}

static void discard_not_wanted_bitmap_uuids(struct bsr_device *device, struct bsr_backing_dev *ldev)
{
	struct bsr_peer_device *peer_device;
	int node_id;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		peer_device = peer_device_by_node_id(device, node_id);
	}
}

#ifdef _WIN
BOOLEAN is_volume_previously_resynced(struct bsr_backing_dev *nbc, unsigned int node_id)
{
	BOOLEAN bRet = TRUE;

	// BSR-958 uuid is UUID_JUST_CREATED and sets the flag to allow write cache flush if no resync has occurred before.
	if (nbc->md.current_uuid == UUID_JUST_CREATED) {
		if (nbc->md.node_id == -1 || (unsigned int)nbc->md.node_id == node_id) {
			BOOLEAN resync_already_progressed = FALSE;
			for (int i = 0; i < BSR_NODE_ID_MAX; i++) {
				if (nbc->md.peers[i].flags & MDF_PEER_INIT_SYNCT_BEGIN) {
					resync_already_progressed = TRUE;
					break;
				}
			}

			if (!resync_already_progressed) {
				bRet = FALSE;
			}
		}
	}

	return bRet;
}
#endif

int bsr_adm_attach(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_device *device;
	struct bsr_resource *resource;
	int err;
	enum bsr_ret_code retcode;
	enum determine_dev_size dd;
	sector_t max_possible_sectors;
	sector_t min_md_device_sectors;
	struct bsr_backing_dev *nbc = NULL; /* new_backing_conf */
	struct disk_conf *new_disk_conf = NULL;
	enum bsr_state_rv rv;
	struct bsr_peer_device *peer_device;
	unsigned int slots_needed = 0;
	bool have_conf_update = false;
	unsigned int md_flags;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	device = adm_ctx.device;
	resource = device->resource;
	mutex_lock(&resource->adm_mutex);

#ifdef _LIN
	// BSR-953 verify that device is valid.
	if (adm_ctx.device) {
		rcu_read_lock();
		if (!minor_to_device(adm_ctx.minor)) {
			rcu_read_unlock();
			bsr_msg_put_info(adm_ctx.reply_skb, "unknown minor");
			retcode = ERR_MINOR_INVALID;
			goto fail;
		}
		rcu_read_unlock();
	}
#endif

	/* allocation not in the IO path, bsrsetup context */
	nbc = bsr_kzalloc(sizeof(struct bsr_backing_dev), GFP_KERNEL, '61SB');

	if (!nbc) {
		retcode = ERR_NOMEM;
		goto fail;
	}
	spin_lock_init(&nbc->md.uuid_lock);

	new_disk_conf = bsr_kzalloc(sizeof(struct disk_conf), GFP_KERNEL, '71SB');

	if (!new_disk_conf) {
		retcode = ERR_NOMEM;
		goto fail;
	}
	nbc->disk_conf = new_disk_conf;

	set_disk_conf_defaults(new_disk_conf);
	err = disk_conf_from_attrs(new_disk_conf, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	if (new_disk_conf->meta_dev_idx < BSR_MD_INDEX_FLEX_INT) {
		retcode = ERR_MD_IDX_INVALID;
		goto fail;
	}

	lock_all_resources();
	retcode = bsr_resync_after_valid(device, new_disk_conf->resync_after);
	unlock_all_resources();
	if (retcode != ERR_NO)
		goto fail;

	retcode = open_backing_devices(device, new_disk_conf, nbc);
	if (retcode != ERR_NO)
		goto fail;

	if ((nbc->backing_bdev == nbc->md_bdev) !=
	    (new_disk_conf->meta_dev_idx == BSR_MD_INDEX_INTERNAL ||
	     new_disk_conf->meta_dev_idx == BSR_MD_INDEX_FLEX_INT)) {
		retcode = ERR_MD_IDX_INVALID;
		goto fail;
	}

	/* if you want to reconfigure, please tear down first */
	if (device->disk_state[NOW] > D_DISKLESS) {
		retcode = ERR_DISK_CONFIGURED;
		goto fail;
	}
	/* It may just now have detached because of IO error.  Make sure
	 * bsr_ldev_destroy is done already, we may end up here very fast,
	 * e.g. if someone calls attach from the on-io-error handler,
	 * to realize a "hot spare" feature (not that I'd recommend that) */
	wait_event(device->misc_wait, !test_bit(GOING_DISKLESS, &device->flags));

	/* make sure there is no leftover from previous force-detach attempts */
	clear_bit(FORCE_DETACH, &device->flags);

	/* and no leftover from previously aborted resync or verify, either */
	for_each_peer_device(peer_device, device) {
		peer_device->rs_total = 0;
		peer_device->rs_failed = 0;
		atomic_set(&peer_device->rs_pending_cnt, 0);
	}

	if (!device->bitmap) {
		device->bitmap = bsr_bm_alloc();
		if (!device->bitmap) {
			retcode = ERR_NOMEM;
			goto fail;
		}
	}

	/* Read our meta data super block early.
	 * This also sets other on-disk offsets. */
	retcode = bsr_md_read(device, nbc);

	if (retcode != ERR_NO)
		goto fail;

	discard_not_wanted_bitmap_uuids(device, nbc);
	sanitize_disk_conf(device, new_disk_conf, nbc);

	if (bsr_get_max_capacity(nbc) < new_disk_conf->disk_size) {
		bsr_err(34, BSR_LC_GENL, device, "Failed to attach due to max capacity %llu smaller than disk size %llu",
			(unsigned long long) bsr_get_max_capacity(nbc),
			(unsigned long long) new_disk_conf->disk_size);
		retcode = ERR_DISK_TOO_SMALL;
		goto fail;
	}

	if (new_disk_conf->meta_dev_idx < 0) {
		max_possible_sectors = BSR_MAX_SECTORS_FLEX;
		/* at least one MB, otherwise it does not make sense */
		min_md_device_sectors = (2<<10);
	} else {
		max_possible_sectors = BSR_MAX_SECTORS;
		// DW-1335
		min_md_device_sectors = (256 << 20 >> 9) * (new_disk_conf->meta_dev_idx + 1);
	}

#ifdef _WIN // DW-1607
	if (bsr_get_md_capacity(nbc->md_bdev) < min_md_device_sectors) {
#else // _LIN
	if (bsr_get_capacity(nbc->md_bdev) < min_md_device_sectors) {
#endif
		retcode = ERR_MD_DISK_TOO_SMALL;
		bsr_err(81, BSR_LC_GENL, device, "Failed to attach due to refusing attach: md-device too small, "
		     "at least %llu sectors needed for this meta-disk type",
		     (unsigned long long) min_md_device_sectors);
		goto fail;
	}

	/* Make sure the new disk is big enough
	 * (we may currently be R_PRIMARY with no local disk...) */
	if (bsr_get_max_capacity(nbc) <
	    bsr_get_vdisk_capacity(device)) {
		bsr_err(35, BSR_LC_GENL, device,
			"Failed to attach due to current (diskless) capacity %llu, cannot attach smaller (%llu) disk",
			(unsigned long long)bsr_get_vdisk_capacity(device),
			(unsigned long long)bsr_get_max_capacity(nbc));
		retcode = ERR_DISK_TOO_SMALL;
		goto fail;
	}

	nbc->known_size = bsr_get_capacity(nbc->backing_bdev);

	if (nbc->known_size > max_possible_sectors) {
		bsr_warn(82, BSR_LC_GENL, device, "Truncating very big lower level device "
			"to currently maximum possible %llu sectors",
			(unsigned long long) max_possible_sectors);
		if (new_disk_conf->meta_dev_idx >= 0)
			bsr_warn(83, BSR_LC_GENL, device, "Using internal or flexible "
				      "meta data may help");
	}

	bsr_suspend_io(device, READ_AND_WRITE);
	wait_event(resource->barrier_wait, !barrier_pending(resource));
	for_each_peer_device(peer_device, device)
		wait_event(device->misc_wait,
			   (!atomic_read(&peer_device->ap_pending_cnt) ||
			    bsr_suspended(device)));
	/* and for other previously queued resource work */
	bsr_flush_workqueue(resource, &resource->work);

	// DW-1605
	stable_state_change(rv, resource,
		change_disk_state(device, D_ATTACHING, CS_VERBOSE | CS_SERIALIZE, NULL));

	retcode = rv;  /* FIXME: Type mismatch. */
	if (rv >= SS_SUCCESS)
		update_resource_dagtag(resource, nbc);
	bsr_resume_io(device);
	if (rv < SS_SUCCESS)
		goto fail;

	if (!get_ldev_if_state(device, D_ATTACHING))
		goto force_diskless;
#ifdef _WIN_MVFL
	struct bsr_genlmsghdr *dh = info->userhdr;
	if (do_add_minor(dh->minor)) {
		PVOLUME_EXTENSION pvext = get_targetdev_by_minor(dh->minor, FALSE);
		if (pvext) {
			NTSTATUS status = STATUS_UNSUCCESSFUL;
			// DW-1461 set volume protection when attaching.
			SetBsrlockIoBlock(pvext, resource->role[NOW] == R_PRIMARY ? FALSE : TRUE);
#ifdef _WIN_MULTIVOL_THREAD
			pvext->WorkThreadInfo = &resource->WorkThreadInfo;
			// BSR-958
			pvext->bPreviouslyResynced = is_volume_previously_resynced(nbc, resource->res_opts.node_id);
			pvext->Active = TRUE;
			FsctlLockVolume(dh->minor);

			status = FsctlFlushDismountVolume(dh->minor, true);
			pvext->bPreviouslyResynced = TRUE;

			FsctlUnlockVolume(dh->minor);

			if (!NT_SUCCESS(status)) {
				retcode = ERR_RES_NOT_KNOWN;
				goto force_diskless_dec;
			}
#else
			status = mvolInitializeThread(pvext, &pvext->WorkThreadInfo, mvolWorkThread);
			if (NT_SUCCESS(status)) {
				// BSR-958
				pvext->bPreviouslyResynced = is_volume_previously_resynced(nbc, resource->res_opts.node_id);
				pvext->Active = TRUE;
				FsctlLockVolume(dh->minor);

				status = FsctlFlushDismountVolume(dh->minor, true);
				pvext->bPreviouslyResynced = TRUE;

				FsctlUnlockVolume(dh->minor);

				if (!NT_SUCCESS(status)) {
					retcode = ERR_RES_NOT_KNOWN;
					goto force_diskless_dec;
				}
			}
			else if (STATUS_DEVICE_ALREADY_ATTACHED == status) {
				struct block_device * bd = pvext->dev;
				if (bd) {
					// required to analyze that this job is done at this point
					//bd->bd_disk->fops->open(bd, FMODE_WRITE);
					//bd->bd_disk->fops->release(bd->bd_disk, FMODE_WRITE);
				}
			}
			else {
				bsr_warn(84, BSR_LC_GENL, NO_OBJECT, "Failed to initialize WorkThread. status(0x%x)", status);
			}
#endif
		}
	}
#endif
	bsr_info(36, BSR_LC_GENL, device, "The maximum number of bitmap peer devices is %u.",
		  device->bitmap->bm_max_peers);
	mutex_lock(&resource->conf_update);
	have_conf_update = true;

	/* Make sure the local node id matches or is unassigned */
	if (nbc->md.node_id != -1 && (unsigned int)nbc->md.node_id != resource->res_opts.node_id) {
		bsr_err(37, BSR_LC_GENL, device, "Failed to attach due to local node id %u differs from local "
			 "node id %d on device",
			 resource->res_opts.node_id,
			 nbc->md.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto force_diskless_dec;
	}

	/* Make sure no bitmap slot has our own node id */
	if (nbc->md.peers[resource->res_opts.node_id].bitmap_index != -1) {
		bsr_err(38, BSR_LC_GENL, device, "Failed to attach due to there is a bitmap for my own node id (%u)",
			 resource->res_opts.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto force_diskless_dec;
	}

	/* Make sure we have a bitmap slot for each peer id */
	for_each_peer_device(peer_device, device) {
		struct bsr_connection *connection = peer_device->connection;
		int bitmap_index;

		bitmap_index = nbc->md.peers[connection->peer_node_id].bitmap_index;
		if (bitmap_index != -1)
			peer_device->bitmap_index = bitmap_index;
		else 
			slots_needed++;
	}
	if (slots_needed) {
		unsigned int slots_available = device->bitmap->bm_max_peers - used_bitmap_slots(nbc);

		if (slots_needed > slots_available) {
			bsr_err(39, BSR_LC_GENL, device, "Failed to attach due to not enough free bitmap "
				 "slots (available=%u, needed=%u)",
				 slots_available,
				 slots_needed);
			retcode = ERR_INVALID_REQUEST;
			goto force_diskless_dec;
		}
		for_each_peer_device(peer_device, device) {
			if (peer_device->bitmap_index != -1)
				continue;

			err = allocate_bitmap_index(peer_device, nbc); 
			if (err){
				retcode = ERR_INVALID_REQUEST;
				goto force_diskless_dec;
			}
		}
	}

	/* Assign the local node id (if not assigned already) */
	nbc->md.node_id = resource->res_opts.node_id;

	if (resource->role[NOW] == R_PRIMARY && device->exposed_data_uuid &&
	    (device->exposed_data_uuid & ~UUID_PRIMARY) !=
	    (nbc->md.current_uuid & ~UUID_PRIMARY)) {
		int data_present = false;
		for_each_peer_device(peer_device, device) {
			if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
				data_present = true;
		}
		if (!data_present) {
			bsr_err(40, BSR_LC_GENL, device, "Failed to attach due to no latest data among peer devices with current UUID=%016llX",
				 (unsigned long long)device->exposed_data_uuid);
			retcode = ERR_DATA_NOT_CURRENT;
			goto force_diskless_dec;
		}
	}

	/* Since we are diskless, fix the activity log first... */
	if (bsr_check_al_size(device, new_disk_conf)) {
		retcode = ERR_NOMEM;
		goto force_diskless_dec;
	}

	/* Point of no return reached.
	 * Devices and memory are no longer released by error cleanup below.
	 * now device takes over responsibility, and the state engine should
	 * clean it up somewhere.  */
	D_ASSERT(device, device->ldev == NULL);
	device->ldev = nbc;
	nbc = NULL;
	new_disk_conf = NULL;

#ifdef _WIN
	// DW-1376 this_bdev indicates block device of replication volume, which can be removed anytime. need to get newly created block device.
	if (device->this_bdev->bd_disk->pDeviceExtension != device->ldev->backing_bdev->bd_disk->pDeviceExtension) {
		// DW-1376 put old one.
		blkdev_put(device->this_bdev, 0);

		// DW-1376 get new one.
		device->this_bdev = device->ldev->backing_bdev->bd_parent?device->ldev->backing_bdev->bd_parent : device->ldev->backing_bdev;
		kref_get(&device->this_bdev->kref);
	}

	// DW-1300 set bsr device to access from volume extention
	unsigned char oldIRQL = ExAcquireSpinLockExclusive(&device->this_bdev->bd_disk->bsr_device_ref_lock);	
	device->this_bdev->bd_disk->bsr_device = device;
	ExReleaseSpinLockExclusive(&device->this_bdev->bd_disk->bsr_device_ref_lock, oldIRQL);
#endif
	for_each_peer_device(peer_device, device) {
		err = bsr_attach_peer_device(peer_device);
		if (err) {
			retcode = ERR_NOMEM;
			goto force_diskless_dec;
		}
	}

	mutex_unlock(&resource->conf_update);
	have_conf_update = false;

	lock_all_resources();
	retcode = bsr_resync_after_valid(device, device->ldev->disk_conf->resync_after);
	if (retcode != ERR_NO) {
		unlock_all_resources();
		goto force_diskless_dec;
	}

	/* Reset the "barriers don't work" bits here, then force meta data to
	 * be written, to ensure we determine if barriers are supported. */
	if (device->ldev->disk_conf->md_flushes)
		clear_bit(MD_NO_FUA, &device->flags);
	else
		set_bit(MD_NO_FUA, &device->flags);

	bsr_resync_after_changed(device);
	bsr_bump_write_ordering(resource, device->ldev, WO_BIO_BARRIER);
	unlock_all_resources();

	/* Prevent shrinking of consistent devices ! */
	{
	unsigned long long nsz = bsr_new_dev_size(device, 0, device->ldev->disk_conf->disk_size, 0);
	unsigned long long eff = device->ldev->md.effective_size;
	if (bsr_md_test_flag(device, MDF_CONSISTENT) && nsz < eff) {
		bsr_err(85, BSR_LC_GENL, device,
			"Failed to attach due to refusing to truncate a consistent device (%llu < %llu)",
			nsz, eff);		
		retcode = ERR_DISK_TOO_SMALL;
		goto force_diskless_dec;
	}
	}

	if (bsr_md_test_flag(device, MDF_CRASHED_PRIMARY))
		set_bit(CRASHED_PRIMARY, &device->flags);
	else
		clear_bit(CRASHED_PRIMARY, &device->flags);

	// BSR-1482
	if (!resource->res_opts.persist_role)
		bsr_md_clear_flag(device, MDF_WAS_PRIMARY);

	if (bsr_md_test_flag(device, MDF_PRIMARY_IND) &&
	    !(resource->role[NOW] == R_PRIMARY && resource->susp_nod[NOW]) &&
	    !device->exposed_data_uuid && !test_bit(NEW_CUR_UUID, &device->flags)) {
		
		set_bit(CRASHED_PRIMARY, &device->flags);
		
		// BSR-175 set crashed primary work pending flags
		for_each_peer_device(peer_device, device)
			bsr_md_set_peer_flag(peer_device, MDF_CRASHED_PRIMARY_WORK_PENDING);

	}

	device->read_cnt = 0;
	device->writ_cnt = 0;
	// BSR-687 aggregate I/O throughput and latency
	atomic_set(&device->io_cnt[READ], 0);
	atomic_set(&device->io_cnt[WRITE], 0);
	atomic_set(&device->io_size[READ], 0);
	atomic_set(&device->io_size[WRITE], 0);
	device->aggregation_start_kt = ktime_get();

	bsr_reconsider_queue_parameters(device, device->ldev, NULL);

	/* If I am currently not R_PRIMARY,
	 * but meta data primary indicator is set,
	 * I just now recover from a hard crash,
	 * and have been R_PRIMARY before that crash.
	 *
	 * Now, if I had no connection before that crash
	 * (have been degraded R_PRIMARY), chances are that
	 * I won't find my peer now either.
	 *
	 * In that case, and _only_ in that case,
	 * we use the degr-wfc-timeout instead of the default,
	 * so we can automatically recover from a crash of a
	 * degraded but active "cluster" after a certain timeout.
	 */
	for_each_peer_device(peer_device, device) {
		clear_bit(USE_DEGR_WFC_T, &peer_device->flags);
		if (resource->role[NOW] != R_PRIMARY &&
			bsr_md_test_flag(device, MDF_PRIMARY_IND) &&
			!bsr_md_test_peer_flag(peer_device, MDF_PEER_CONNECTED))
			set_bit(USE_DEGR_WFC_T, &peer_device->flags);
	}

	dd = bsr_determine_dev_size(device, 0, DDSF_ATTACHING, NULL);
	if (dd == DS_ERROR) {
		retcode = ERR_NOMEM_BITMAP;
		goto force_diskless_dec;
	} else if (dd == DS_GREW) {
		for_each_peer_device(peer_device, device)
			set_bit(RESYNC_AFTER_NEG, &peer_device->flags);
	}

	if (bsr_bitmap_io(device, &bsr_bm_read,
		"read from attaching", BM_LOCK_ALL,
		NULL)) {
		retcode = ERR_IO_MD_DISK;
		goto force_diskless_dec;
	}

	for_each_peer_device(peer_device, device) {
		if ((test_bit(CRASHED_PRIMARY, &device->flags) &&
		     bsr_md_test_flag(device, MDF_AL_DISABLED)) ||
		    bsr_md_test_peer_flag(peer_device, MDF_PEER_FULL_SYNC)) {
			bsr_info(41, BSR_LC_GENL, peer_device, "Set all out of sync because of %s.",
				(test_bit(CRASHED_PRIMARY, &device->flags) && bsr_md_test_flag(device, MDF_AL_DISABLED)) ? "crashed primary setting and activity log disable" : "peer full sync is set");
			if (bsr_bitmap_io(device, &bsr_bmio_set_n_write,
				"set_n_write from attaching", BM_LOCK_ALL,
				peer_device)) {
				retcode = ERR_IO_MD_DISK;
				goto force_diskless_dec;
			}
		}
	}

	bsr_try_suspend_al(device); /* IO is still suspended here... */

	
#ifdef _WIN
	unsigned char oldIrql_rLock1; // RCU_SPECIAL_CASE
	oldIrql_rLock1 = ExAcquireSpinLockShared(&g_rcuLock);
#else // _LIN
	rcu_read_lock();
#endif
	md_flags = device->ldev->md.flags;

	if (rcu_dereference(device->ldev->disk_conf)->al_updates)
		device->ldev->md.flags &= ~MDF_AL_DISABLED;
	else
		device->ldev->md.flags |= MDF_AL_DISABLED;
#ifdef _WIN
	// RCU_SPECIAL_CASE
	ExReleaseSpinLockShared(&g_rcuLock, oldIrql_rLock1);

	// BSR-1444 if the attach target volume is in a readonly state, release it.
	ChangeVolumeReadonly(device->minor, false);
#else // _LIN
	rcu_read_unlock();
#endif

	/* change_disk_state uses disk_state_from_md(device); in case D_NEGOTIATING not
	   necessary, and falls back to a local state change */
	// DW-1605
	stable_state_change(rv, resource,
		change_disk_state(device, D_NEGOTIATING, CS_VERBOSE | CS_SERIALIZE, NULL));

	if (rv < SS_SUCCESS)
		goto force_diskless_dec;

	mod_timer(&device->request_timer, jiffies + HZ);

	if (resource->role[NOW] == R_PRIMARY)
		device->ldev->md.current_uuid |= UUID_PRIMARY;
	else
		device->ldev->md.current_uuid &= ~UUID_PRIMARY;

	bsr_md_sync(device);

	// BSR-676 notify GI
	bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
	bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_DEVICE_FLAG);
	for_each_peer_device(peer_device, device) {
		bsr_queue_notify_update_gi(NULL, peer_device, BSR_GI_NOTI_PEER_DEVICE_FLAG);
	}

	bsr_kobject_uevent(device);
	put_ldev(__FUNCTION__, device);
	mutex_unlock(&resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;

 force_diskless_dec:
	put_ldev(__FUNCTION__, device);
 force_diskless:
	change_disk_state(device, D_DISKLESS, CS_HARD, NULL);
 fail:
	mutex_unlock_cond(&resource->conf_update, &have_conf_update);
	bsr_backing_dev_free(device, nbc);
	mutex_unlock(&resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum bsr_disk_state get_disk_state(struct bsr_device *device)
{
	struct bsr_resource *resource = device->resource;
	enum bsr_disk_state disk_state;

	spin_lock_irq(&resource->req_lock);
	disk_state = device->disk_state[NOW];
	spin_unlock_irq(&resource->req_lock);
	return disk_state;
}

static int adm_detach(struct bsr_device *device, int force, struct sk_buff *reply_skb)
{
	enum bsr_state_rv retcode;
	long timeo = 3*HZ;
	const char *err_str = NULL;

	if (force) {
		set_bit(FORCE_DETACH, &device->flags);
		change_disk_state(device, D_DETACHING, CS_HARD, NULL);
		retcode = SS_SUCCESS;
		goto out;
	}

	bsr_suspend_io(device, READ_AND_WRITE); /* so no-one is stuck in bsr_al_begin_io */
	// DW-1605
	stable_state_change(retcode, device->resource,
		change_disk_state(device, D_DETACHING,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, &err_str));

	/* D_DETACHING will transition to DISKLESS. */
	bsr_resume_io(device);
	// DW-1046 detour adm_detach hang
	// TODO: When passing the result of timeout to ret, it should be verified that there is no problem.
	 wait_event_interruptible_timeout_ex(device->misc_wait,
						 get_disk_state(device) != D_DETACHING,
						 timeo, timeo);

	 // BSR-925 returns an error if the detaching is not completed during the wait time.
	if (get_disk_state(device) == D_DETACHING) {
		bsr_info(42, BSR_LC_GENL, NO_OBJECT, "Detach complete event wait timeout. time out(%ld) disk state(%s)", 3 * HZ, bsr_disk_str(device->disk_state[NOW]));
		retcode = ERR_INTR;;
	}
	else {
		if (retcode >= SS_SUCCESS) {
			int res;

			// BSR-439
			/* wait for completion of bsr_ldev_destroy() */
			wait_event_interruptible_ex(device->misc_wait, !test_bit(GOING_DISKLESS, &device->flags), res);
			bsr_cleanup_device(device);
		}
		if (retcode == SS_IS_DISKLESS)
			retcode = SS_NOTHING_TO_DO;
	}
out:
	if (err_str) {
		if (reply_skb)
			bsr_msg_put_info(reply_skb, err_str);
		bsr_kfree((void*)err_str);
		err_str = NULL;
	}
	return retcode;
}

/* Detaching the disk is a process in multiple stages.  First we need to lock
 * out application IO, in-flight IO, IO stuck in bsr_al_begin_io.
 * Then we transition to D_DISKLESS, and wait for put_ldev() to return all
 * internal references as well.
 * Only then we have finally detached. */
int bsr_adm_detach(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;
    struct detach_parms parms = { 0 };
	int err;
	struct bsr_peer_device *peer_device;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	if (info->attrs[BSR_NLA_DETACH_PARMS]) {
		err = detach_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}

	// DW-839 not support diskless Primary
	peer_device = NULL;
	for_each_peer_device(peer_device, adm_ctx.device) {
		if (peer_device->repl_state[NOW] > L_OFF && adm_ctx.device->resource->role[NOW] == R_PRIMARY) {
			retcode = SS_CONNECTED_DISKLESS;
			goto out;
		}
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	retcode = adm_detach(adm_ctx.device, parms.force_detach, adm_ctx.reply_skb);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static bool conn_resync_running(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	bool rv = false;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] == L_SYNC_SOURCE ||
		    peer_device->repl_state[NOW] == L_SYNC_TARGET ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_S ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static bool conn_ov_running(struct bsr_connection *connection)
{
	struct bsr_peer_device *peer_device;
	bool rv = false;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] == L_VERIFY_S ||
		    peer_device->repl_state[NOW] == L_VERIFY_T) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static enum bsr_ret_code
_check_net_options(struct bsr_connection *connection, struct net_conf *old_net_conf, struct net_conf *new_net_conf)
{
	if (old_net_conf && connection->cstate[NOW] == C_CONNECTED && connection->agreed_pro_version < 100) {
		if (new_net_conf->wire_protocol != old_net_conf->wire_protocol)
			return ERR_NEED_APV_100;

		if (new_net_conf->two_primaries != old_net_conf->two_primaries)
			return ERR_NEED_APV_100;

		if (!new_net_conf->integrity_alg != !old_net_conf->integrity_alg)
			return ERR_NEED_APV_100;

		if (strcmp(new_net_conf->integrity_alg, old_net_conf->integrity_alg))
			return ERR_NEED_APV_100;
	}

	if (!new_net_conf->two_primaries &&
	    connection->resource->role[NOW] == R_PRIMARY &&
	    connection->peer_role[NOW] == R_PRIMARY)
		return ERR_NEED_ALLOW_TWO_PRI;

	if (new_net_conf->two_primaries &&
	    (new_net_conf->wire_protocol != BSR_PROT_C))
		return ERR_NOT_PROTO_C;

	if (new_net_conf->wire_protocol == BSR_PROT_A &&
	    new_net_conf->fencing_policy == FP_STONITH)
		return ERR_STONITH_AND_PROT_A;

	if (new_net_conf->on_congestion != OC_BLOCK &&
	    new_net_conf->wire_protocol != BSR_PROT_A)
		return ERR_CONG_NOT_PROTO_A;

	// DW-1436 sndbuf-size must be at least 10M 
	if (new_net_conf->sndbuf_size < BSR_SNDBUF_SIZE_MIN && new_net_conf->sndbuf_size > 0){
		return ERR_SNDBUF_SIZE_TOO_SMALL;
	}

	return ERR_NO;
}

static enum bsr_ret_code
check_net_options(struct bsr_connection *connection, struct net_conf *new_net_conf)
{
	enum bsr_ret_code rv;
	struct bsr_peer_device *peer_device;
	int i;

	rcu_read_lock();
	rv = _check_net_options(connection, rcu_dereference(connection->transport.net_conf), new_net_conf);
	rcu_read_unlock();

	/* connection->peer_devices protected by resource->conf_update here */
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, i) {
		struct bsr_device *device = peer_device->device;
		if (!device->bitmap) {
			device->bitmap = bsr_bm_alloc();
			if (!device->bitmap)
				return ERR_NOMEM;
		}
	}

	return rv;
}

struct crypto {
	struct crypto_shash *verify_tfm;
	struct crypto_shash *csums_tfm;
	struct crypto_shash *cram_hmac_tfm;
	struct crypto_shash *integrity_tfm;
};

static int
alloc_shash(struct crypto_shash **tfm, char *tfm_name, int err_alg)
{
	if (!tfm_name[0])
		return ERR_NO;
#ifdef _WIN
	*tfm = crypto_alloc_hash(tfm_name, 0, 0, '11SB');
#else // _LIN
	*tfm = crypto_alloc_shash(tfm_name, 0, 0);
#endif
	if (IS_ERR(*tfm)) {
		*tfm = NULL;
		return err_alg;
	}

	return ERR_NO;
}

static enum bsr_ret_code
alloc_crypto(struct crypto *crypto, struct net_conf *new_net_conf)
{
#ifdef _WIN
#define CRYPTO_MAX_ALG_NAME             64
#endif
	char hmac_name[CRYPTO_MAX_ALG_NAME];
	enum bsr_ret_code rv;

	rv = alloc_shash(&crypto->csums_tfm, new_net_conf->csums_alg,
		       ERR_CSUMS_ALG);
	if (rv != ERR_NO)
		return rv;
	rv = alloc_shash(&crypto->verify_tfm, new_net_conf->verify_alg,
		       ERR_VERIFY_ALG);
	if (rv != ERR_NO)
		return rv;
	rv = alloc_shash(&crypto->integrity_tfm, new_net_conf->integrity_alg,
		       ERR_INTEGRITY_ALG);
	if (rv != ERR_NO)
		return rv;
	if (new_net_conf->cram_hmac_alg[0] != 0) {
#ifdef _WIN
		_snprintf(hmac_name, CRYPTO_MAX_ALG_NAME-1, "hmac(%s)", new_net_conf->cram_hmac_alg);
#else // _LIN
		snprintf(hmac_name, CRYPTO_MAX_ALG_NAME-1, "hmac(%s)", new_net_conf->cram_hmac_alg);
#endif

		rv = alloc_shash(&crypto->cram_hmac_tfm, hmac_name,
			       ERR_AUTH_ALG);
	}

	return rv;
}

static void free_crypto(struct crypto *crypto)
{
	crypto_free_shash(crypto->cram_hmac_tfm);
	crypto_free_shash(crypto->integrity_tfm);
	crypto_free_shash(crypto->csums_tfm);
	crypto_free_shash(crypto->verify_tfm);
}

int bsr_adm_net_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;
	struct bsr_connection *connection;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	int err;
	int ovr; /* online verify running */
	int rsr; /* re-sync running */
	struct crypto crypto = { 0 };
	bool resched_req_timer = false;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	connection = adm_ctx.connection;
	mutex_lock(&adm_ctx.resource->adm_mutex);
	
	new_net_conf = bsr_kzalloc(sizeof(struct net_conf), GFP_KERNEL, 'A1SB');
	if (!new_net_conf) {
		retcode = ERR_NOMEM;
		goto out;
	}
	bsr_flush_workqueue(adm_ctx.resource, &connection->sender_work);

	mutex_lock(&connection->resource->conf_update);
	mutex_lock(&connection->mutex[DATA_STREAM]);
	old_net_conf = connection->transport.net_conf;

	if (!old_net_conf) {
		bsr_msg_put_info(adm_ctx.reply_skb, "net conf missing, try connect");
		retcode = ERR_INVALID_REQUEST;
		goto fail;
	}

	*new_net_conf = *old_net_conf;
	if (should_set_defaults(info))
		set_net_conf_defaults(new_net_conf);

	err = net_conf_from_attrs_for_change(new_net_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	retcode = check_net_options(connection, new_net_conf);
	if (retcode != ERR_NO)
		goto fail;


#ifdef _SEND_BUF
	// DW-1436 unable to change send buffer size dynamically
	if (connection->cstate[NOW] >= C_CONNECTED){
		if (old_net_conf->sndbuf_size != new_net_conf->sndbuf_size){
			retcode = ERR_CANT_CHANGE_SNDBUF_SIZE_WHEN_CONNECTED;
			goto fail;
		}
	}

	// DW-1927 If the send buffer is not NULL, the del-peer command has not been executed.
	if (old_net_conf->sndbuf_size != new_net_conf->sndbuf_size) {
		if (connection->ptxbab[DATA_STREAM] != NULL ||
			// BSR-989 If the new send buffer size is different from the old send buffer size and the old send buffer size is 0, the del-peer command was not executed.
			old_net_conf->sndbuf_size == 0) {
			retcode = ERR_CANT_CHANGE_SNDBUF_SIZE_WITHOUT_DEL_PEER;
			goto fail;
			
		}
	}
#endif

	// BSR-975 do reschedule request timer if ko_count enabled
	if (old_net_conf->ko_count == 0 && new_net_conf->ko_count != 0)
		resched_req_timer = true;

	/* re-sync running */
	rsr = conn_resync_running(connection);
	if (rsr && strcmp(new_net_conf->csums_alg, old_net_conf->csums_alg)) {
		retcode = ERR_CSUMS_RESYNC_RUNNING;
		goto fail;
	}

	/* online verify running */
	ovr = conn_ov_running(connection);
	if (ovr && strcmp(new_net_conf->verify_alg, old_net_conf->verify_alg)) {
		retcode = ERR_VERIFY_RUNNING;
		goto fail;
	}

	retcode = alloc_crypto(&crypto, new_net_conf);
	if (retcode != ERR_NO)
		goto fail;

	// BSR-859 notify by event when peer node name changes
	if (strcmp(new_net_conf->peer_node_name, old_net_conf->peer_node_name)) {
		mutex_lock(&notification_mutex);
		notify_node_info(NULL, 0, adm_ctx.resource, connection, 
				new_net_conf->peer_node_name, BSR_PEER_NODE_INFO, NOTIFY_CHANGE);
		mutex_unlock(&notification_mutex);

	}

#ifdef _WIN
	synchronize_rcu_w32_wlock();
#endif
	rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
	connection->fencing_policy = new_net_conf->fencing_policy;
#ifdef _WIN
	synchronize_rcu();
#endif

	if (!rsr) {
		crypto_free_shash(connection->csums_tfm);
		connection->csums_tfm = crypto.csums_tfm;
		crypto.csums_tfm = NULL;
	}
	if (!ovr) {
		crypto_free_shash(connection->verify_tfm);
		connection->verify_tfm = crypto.verify_tfm;
		crypto.verify_tfm = NULL;
	}

	crypto_free_shash(connection->integrity_tfm);
	connection->integrity_tfm = crypto.integrity_tfm;
	if (connection->cstate[NOW] >= C_CONNECTED && connection->agreed_pro_version >= 100)
		/* Do this without trying to take connection->data.mutex again.  */
		__bsr_send_protocol(connection, P_PROTOCOL_UPDATE);

	crypto_free_shash(connection->cram_hmac_tfm);
	connection->cram_hmac_tfm = crypto.cram_hmac_tfm;

	mutex_unlock(&connection->mutex[DATA_STREAM]);
	mutex_unlock(&connection->resource->conf_update);
#ifdef _LIN
	synchronize_rcu();
#endif
	bsr_kfree(old_net_conf);

	if (connection->cstate[NOW] >= C_CONNECTED) {
		struct bsr_peer_device *peer_device;
		int vnr;

		idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
			bsr_send_sync_param(peer_device);
			// BSR-975
			if (resched_req_timer)
				mod_timer(&peer_device->device->request_timer, jiffies + HZ);
		}
	}

	goto out;

 fail:
	mutex_unlock(&connection->mutex[DATA_STREAM]);
	mutex_unlock(&connection->resource->conf_update);
	free_crypto(&crypto);
	bsr_kfree(new_net_conf);
 out:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int adjust_resync_fifo(struct bsr_peer_device *peer_device,
			      struct peer_device_conf *conf,
			      struct fifo_buffer **pp_old_plan)
{
	struct fifo_buffer *old_plan, *new_plan = NULL;
	int fifo_size;

	fifo_size = (conf->c_plan_ahead * 10 * SLEEP_TIME) / HZ;

	old_plan = rcu_dereference_protected(peer_device->rs_plan_s,
			     lockdep_is_held(&peer_device->connection->resource->conf_update));
	if (!old_plan || (unsigned int)fifo_size != old_plan->size) {
#ifdef _WIN
		new_plan = fifo_alloc(fifo_size, '81SB');
#else // _LIN
		new_plan = fifo_alloc(fifo_size);
#endif
		if (!new_plan) {
			bsr_err(43, BSR_LC_GENL, peer_device, "Failed to attach due to failure to allocate %d size memory in kmalloc", fifo_size);
			return -ENOMEM;
		}
		rcu_assign_pointer(peer_device->rs_plan_s, new_plan);
		if (pp_old_plan)
			*pp_old_plan = old_plan;
		else
			kfree2(old_plan);
	}

	return 0;
}
#ifdef _WIN
bool string_to_long(char *data, ULONG *num)
#else 
bool string_to_long(char *data, long *num)
#endif
{
#ifdef _WIN
	ANSI_STRING a_token;
	UNICODE_STRING u_token;
	NTSTATUS status; 

	RtlInitAnsiString(&a_token, data);
	if ((status = RtlAnsiStringToUnicodeString(&u_token, &a_token, TRUE)) == STATUS_SUCCESS) {
		status = RtlUnicodeStringToInteger(&u_token, 10, num);
		RtlFreeUnicodeString(&u_token);
	}

	return (status == STATUS_SUCCESS ? true : false);
#else
	int err;
	err = kstrtol(data, 10, num);
	if (err)
		return false;
	return true;
#endif
}

int bsr_adm_peer_device_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;
	struct bsr_peer_device *peer_device;
	struct peer_device_conf *old_peer_device_conf, *new_peer_device_conf = NULL;
	struct fifo_buffer *old_plan = NULL;
	int err;

#ifdef _WIN
	ULONG repl_ratio = 0, resync_ratio = 0;
#else
	long repl_ratio = 0, resync_ratio = 0;
#endif

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	mutex_lock(&adm_ctx.resource->conf_update);

	new_peer_device_conf = bsr_kzalloc(sizeof(struct peer_device_conf), GFP_KERNEL, '91SB');
	if (!new_peer_device_conf)
		goto fail;

	old_peer_device_conf = peer_device->conf;
	*new_peer_device_conf = *old_peer_device_conf;
	if (should_set_defaults(info))
		set_peer_device_conf_defaults(new_peer_device_conf);

	err = peer_device_conf_from_attrs_for_change(new_peer_device_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail_ret_set;
	}

	if (!expect(peer_device, new_peer_device_conf->resync_rate >= 1))
		new_peer_device_conf->resync_rate = 1;

	if (new_peer_device_conf->c_plan_ahead > BSR_C_PLAN_AHEAD_MAX)
		new_peer_device_conf->c_plan_ahead = BSR_C_PLAN_AHEAD_MAX;

	err = adjust_resync_fifo(peer_device, new_peer_device_conf, &old_plan);
	if (err)
		goto fail;

	if (strlen(new_peer_device_conf->resync_ratio)) {
		char *ptr = NULL, *token = NULL, c[12];
#ifdef _WIN
		memcpy(c, new_peer_device_conf->resync_ratio, strlen(new_peer_device_conf->resync_ratio));

		token = strtok_s(c, ":", &ptr);
		if (token) {
			if (!string_to_long(token, &repl_ratio))
				goto fail;

			token = strtok_s(ptr, ":", &ptr);
			if (token) {
				if (!string_to_long(token, &resync_ratio))
					goto fail;
			}
		}
#else 
		memcpy(c, new_peer_device_conf->resync_ratio, strlen(new_peer_device_conf->resync_ratio));
		ptr = c;

		token = strsep(&ptr, ":");
		if (ptr) {
			if (!string_to_long(token, &repl_ratio))
				goto fail;

			if (!string_to_long(token, &resync_ratio))
				goto fail;
		}
#endif
	}

	atomic_set64(&peer_device->repl_ratio, repl_ratio);
	atomic_set64(&peer_device->resync_ratio, resync_ratio);

#ifdef _WIN
	synchronize_rcu_w32_wlock();
#endif
	bsr_info(44, BSR_LC_GENL, peer_device, "new peer device option. resync_rate : %uk, c_plan_ahead : %uk, c_delay_target : %uk, c_fill_target : %us, c_max_rate : %uk, c_min_rate : %uk, ov_req_num : %ub, ov_req_interval : %ums, repl_ratio : %u, resync_ratio : %u)", 
		new_peer_device_conf->resync_rate, new_peer_device_conf->c_plan_ahead, new_peer_device_conf->c_delay_target, 
		new_peer_device_conf->c_fill_target, new_peer_device_conf->c_max_rate, new_peer_device_conf->c_min_rate,
		new_peer_device_conf->ov_req_num, new_peer_device_conf->ov_req_interval, repl_ratio, resync_ratio);

	rcu_assign_pointer(peer_device->conf, new_peer_device_conf);

	synchronize_rcu();
	bsr_kfree(old_peer_device_conf);
	bsr_kfree(old_plan);

	if (0) {
fail:
		retcode = ERR_NOMEM;
fail_ret_set:
		bsr_kfree(new_peer_device_conf);
	}

	mutex_unlock(&adm_ctx.resource->conf_update);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;

}

int bsr_create_peer_device_default_config(struct bsr_peer_device *peer_device)
{
	struct peer_device_conf *conf;
	int err;

	conf = bsr_kzalloc(sizeof(*conf), GFP_KERNEL, 'B1SB');
	if (!conf)
		return -ENOMEM;

	set_peer_device_conf_defaults(conf);
	err = adjust_resync_fifo(peer_device, conf, NULL);
	if (err)
		return err;

	bsr_info(45, BSR_LC_GENL, peer_device, "default peer device option. resync_rate : %uk, c_plan_ahead : %uk, c_delay_target : %uk, c_fill_target : %us, c_max_rate : %uk, c_min_rate : %uk, ov_req_num : %ub, ov_req_interval : %ums",
		conf->resync_rate, conf->c_plan_ahead, conf->c_delay_target,
		conf->c_fill_target, conf->c_max_rate, conf->c_min_rate,
		conf->ov_req_num, conf->ov_req_interval);

	peer_device->conf = conf;

	return 0;
}

static void connection_to_info(struct connection_info *info,
			       struct bsr_connection *connection)
{
	info->conn_connection_state = connection->cstate[NOW];
	info->conn_role = connection->peer_role[NOW];
	// BSR-892
	info->conn_last_error = connection->last_error;
}

static void peer_device_to_info(struct peer_device_info *info,
				struct bsr_peer_device *peer_device)
{
	info->peer_repl_state = peer_device->repl_state[NOW];
	info->peer_disk_state = peer_device->disk_state[NOW];
	info->peer_resync_susp_user = peer_device->resync_susp_user[NOW];
	info->peer_resync_susp_peer = peer_device->resync_susp_peer[NOW];
	info->peer_resync_susp_dependency = peer_device->resync_susp_dependency[NOW];
	info->peer_is_intentional_diskless = false;
}

static bool is_resync_target_in_other_connection(struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_device *p;

	for_each_peer_device(p, device) {
		if (p == peer_device)
			continue;

		if (p->repl_state[NEW] == L_SYNC_TARGET)
			return true;
	}

	return false;
}

static int adm_new_connection(struct bsr_connection **ret_conn,
		struct bsr_config_context *adm_ctx, struct genl_info *info)
{
	struct connection_info connection_info;
	enum bsr_notification_type flags;
	unsigned int peer_devices = 0;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device;
	struct net_conf *old_net_conf, *new_net_conf = NULL;
	struct crypto crypto = { NULL, };
	struct bsr_connection *connection;
	enum bsr_ret_code retcode;
	int i, err;
	char *transport_name;
	struct bsr_transport_class *tr_class;

	*ret_conn = NULL;
	if (adm_ctx->connection) {
		struct bsr_resource * resource = adm_ctx->resource;
		bsr_err(46, BSR_LC_GENL, resource, "Failed to new connection due to peer node id %u already exists",
			adm_ctx->peer_node_id);
		return ERR_INVALID_REQUEST;
	}

	/* allocation not in the IO path, bsrsetup / netlink process context */
	new_net_conf = bsr_kzalloc(sizeof(*new_net_conf), GFP_KERNEL, 'E1SB');
	if (!new_net_conf)
		return ERR_NOMEM;

	set_net_conf_defaults(new_net_conf);

	err = net_conf_from_attrs(new_net_conf, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	transport_name = new_net_conf->transport_name[0] ? new_net_conf->transport_name : "tcp";
	tr_class = bsr_get_transport_class(transport_name);
	if (!tr_class) {
		retcode = ERR_CREATE_TRANSPORT;
		goto fail;
	}

	connection = bsr_create_connection(adm_ctx->resource, tr_class);
	if (!connection) {
		retcode = ERR_NOMEM;
		goto fail_put_transport;
	}
	connection->peer_node_id = adm_ctx->peer_node_id;
	/* transport class reference now owned by connection,
	 * prevent double cleanup. */
	tr_class = NULL;

	retcode = check_net_options(connection, new_net_conf);
	if (retcode != ERR_NO)
		goto fail_free_connection;

	retcode = alloc_crypto(&crypto, new_net_conf);
	if (retcode != ERR_NO)
		goto fail_free_connection;

	((char *)new_net_conf->shared_secret)[SHARED_SECRET_MAX-1] = 0;

	mutex_lock(&adm_ctx->resource->conf_update);
	idr_for_each_entry_ex(struct bsr_device *, &adm_ctx->resource->devices, device, i) {
		int id;

		retcode = ERR_NOMEM;
		peer_device = create_peer_device(device, connection);
		if (!peer_device)
			goto unlock_fail_free_connection;
		id = idr_alloc(&connection->peer_devices, peer_device,
			       device->vnr, device->vnr + 1, GFP_KERNEL);
		if (id < 0)
			goto unlock_fail_free_connection;

		// BSR-708 When attach is called and new-peer is called, notify current information of GI as an event.
		bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
		bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_DEVICE_FLAG);
		bsr_queue_notify_update_gi(NULL, peer_device, BSR_GI_NOTI_PEER_DEVICE_FLAG);
	}

	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, i) {
		struct bsr_device *device = peer_device->device;

		peer_device->resync_susp_other_c[NOW] =
			is_resync_target_in_other_connection(peer_device);
		list_add_rcu(&peer_device->peer_devices, &device->peer_devices);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 3);
		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 1);
		peer_devices++;
		peer_device->node_id = connection->peer_node_id;
	}
	spin_lock_irq(&adm_ctx->resource->req_lock);
	list_add_tail_rcu(&connection->connections, &adm_ctx->resource->connections);
	spin_unlock_irq(&adm_ctx->resource->req_lock);

	old_net_conf = connection->transport.net_conf;
	if (old_net_conf) {
		retcode = ERR_NET_CONFIGURED;
		goto unlock_fail_free_connection;
	}
	rcu_assign_pointer(connection->transport.net_conf, new_net_conf);
	connection->fencing_policy = new_net_conf->fencing_policy;

	connection->cram_hmac_tfm = crypto.cram_hmac_tfm;
	connection->integrity_tfm = crypto.integrity_tfm;
	connection->csums_tfm = crypto.csums_tfm;
	connection->verify_tfm = crypto.verify_tfm;

	/* transferred ownership. prevent double cleanup. */
	new_net_conf = NULL;
	memset(&crypto, 0, sizeof(crypto));

	if (connection->peer_node_id > adm_ctx->resource->max_node_id)
		adm_ctx->resource->max_node_id = connection->peer_node_id;

	/* Set bitmap_index if it was allocated previously */
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, i) {
		unsigned int bitmap_index;

		device = peer_device->device;
		if (!get_ldev(device))
			continue;

		bitmap_index = device->ldev->md.peers[adm_ctx->peer_node_id].bitmap_index;
		if (bitmap_index != -1)
			peer_device->bitmap_index = bitmap_index;
		put_ldev(__FUNCTION__, device); 
	}

	connection_to_info(&connection_info, connection);
	flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
	mutex_lock(&notification_mutex);
	notify_connection_state(NULL, 0, connection, &connection_info, NOTIFY_CREATE | flags);

	// BSR-859 notify by event when setting peer node name
	notify_node_info(NULL, 0, adm_ctx->resource, connection, 
				connection->transport.net_conf->peer_node_name, BSR_PEER_NODE_INFO, NOTIFY_CHANGE);

    idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, i) {
		struct peer_device_info peer_device_info;

		peer_device_to_info(&peer_device_info, peer_device);
		flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
		notify_peer_device_state(NULL, 0, peer_device, &peer_device_info, NOTIFY_CREATE | flags);
	}
	mutex_unlock(&notification_mutex);

	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, i) {
		if (get_ldev_if_state(peer_device->device, D_NEGOTIATING)) {
			err = bsr_attach_peer_device(peer_device);
			put_ldev(__FUNCTION__, peer_device->device);
			if (err) {
				retcode = ERR_NOMEM;
				goto unlock_fail_free_connection;
			}
		}
		peer_device->send_cnt = 0;
		peer_device->recv_cnt = 0;
	}
	mutex_unlock(&adm_ctx->resource->conf_update);

#ifdef _SEND_BUF
	if(alloc_bab(connection, connection->transport.net_conf)) {
	} else {
	}
#endif
	bsr_debugfs_connection_add(connection); /* after ->net_conf was assigned */
	bsr_thread_start(&connection->sender);
	*ret_conn = connection;
	return ERR_NO;

unlock_fail_free_connection:
	mutex_unlock(&adm_ctx->resource->conf_update);
fail_free_connection:
	if (!list_empty(&connection->connections)) {
		bsr_unregister_connection(connection);
		// BSR-426
#ifdef _LIN
		synchronize_rcu();
#endif
	}
	bsr_put_connection(connection);
fail_put_transport:
#ifdef _LIN
	bsr_put_transport_class(tr_class);
#endif
fail:
	free_crypto(&crypto);
	bsr_kfree(new_net_conf);

	return retcode;
}

bool addr_eq_nla(const SOCKADDR_STORAGE_EX *addr, const int addr_len, const struct nlattr *nla)
{
	return	nla_len(nla) == addr_len && memcmp(nla_data(nla), addr, addr_len) == 0;
}

static enum bsr_ret_code
check_path_against_nla(const struct bsr_path *path,
		       const struct nlattr *my_addr, const struct nlattr *peer_addr)
{
	enum bsr_ret_code ret = ERR_NO;

	if (addr_eq_nla(&path->my_addr, path->my_addr_len, my_addr))
		ret = ERR_LOCAL_ADDR;
	if (addr_eq_nla(&path->peer_addr, path->peer_addr_len, peer_addr))
		ret = (ret == ERR_LOCAL_ADDR ? ERR_LOCAL_AND_PEER_ADDR : ERR_PEER_ADDR);
	return ret;
}

static enum bsr_ret_code
check_path_usable(const struct bsr_config_context *adm_ctx,
		  const struct nlattr *my_addr, const struct nlattr *peer_addr)
{
	struct bsr_resource *resource;
	struct bsr_connection *connection;
	enum bsr_ret_code retcode;

	if (!(my_addr && peer_addr)) {
		bsr_msg_put_info(adm_ctx->reply_skb, "connection endpoint(s) missing");
		return ERR_INVALID_REQUEST;
	}

	/* No need for _rcu here. All reconfiguration is
	 * strictly serialized on resources_mutex. We are protected against
	 * concurrent reconfiguration/addition/deletion */
	for_each_resource(resource, &bsr_resources) {
		for_each_connection(connection, resource) {
			struct bsr_path *path;
			list_for_each_entry_ex(struct bsr_path, path, &connection->transport.paths, list) {
				retcode = check_path_against_nla(path, my_addr, peer_addr);
				if (retcode == ERR_NO)
					continue;
				/* Within the same resource, it is ok to use
				 * the same endpoint several times */
				if (retcode != ERR_LOCAL_AND_PEER_ADDR &&
				    resource == adm_ctx->resource)
					continue;
				return retcode;
			}
		}
	}
	return ERR_NO;
}

static enum bsr_ret_code
adm_add_path(struct bsr_config_context *adm_ctx,  struct genl_info *info)
{
	struct bsr_transport *transport = &adm_ctx->connection->transport;
	struct nlattr *my_addr = NULL, *peer_addr = NULL, *disable_ip_verify;
	struct bsr_path *path;
	enum bsr_ret_code retcode;
	int err;

	/* parse and validate only */
	err = path_parms_from_attrs(NULL, info);
	if (err) {
		bsr_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		return ERR_MANDATORY_TAG;
	}
	my_addr = nested_attr_tb[__nla_type(T_my_addr)];
	peer_addr = nested_attr_tb[__nla_type(T_peer_addr)];
	disable_ip_verify = nested_attr_tb[__nla_type(T_disable_ip_verify)];

	retcode = check_path_usable(adm_ctx, my_addr, peer_addr);
	if (retcode != ERR_NO)
		return retcode;

	path = bsr_kzalloc(transport->class->path_instance_size, GFP_KERNEL, '57SB');
	if (!path)
		return ERR_NOMEM;

	path->my_addr_len = (int)nla_len(my_addr);
	memcpy(&path->my_addr, nla_data(my_addr), path->my_addr_len);
	path->peer_addr_len = nla_len(peer_addr);
	memcpy(&path->peer_addr, nla_data(peer_addr), path->peer_addr_len);
	// BSR-1387
	path->disable_ip_verify = *(__u32 *)nla_data(disable_ip_verify);

	kref_init(&path->kref);

	err = transport->ops->add_path(transport, path);
	if (err) {
		struct bsr_connection * connection = adm_ctx->connection;
		kref_put(&path->kref, bsr_destroy_path);
		bsr_err(47, BSR_LC_GENL, connection, "Failed to add path due to failure to get an listener. err(%d)", err);
		bsr_msg_put_info(adm_ctx->reply_skb, "Failed to add path due to failure to get an listener");
		return ERR_INVALID_REQUEST;
	}
	notify_path(adm_ctx->connection, path, NOTIFY_CREATE);
	return ERR_NO;
}

int bsr_adm_connect(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct connect_parms parms = { 0, };
	struct bsr_peer_device *peer_device;
	struct bsr_connection *connection;
	enum bsr_ret_code retcode;
	enum bsr_conn_state cstate;
	int i, err;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	// BSR-919 fix potential deadlock occurs when connect is executed during down
	mutex_lock(&adm_ctx.resource->adm_mutex);

	connection = adm_ctx.connection;
	cstate = connection->cstate[NOW];
	if (cstate != C_STANDALONE) {
#if 0	// DW-1292 skip if cstate is not StandAlone
		retcode = ERR_NET_CONFIGURED;
#endif
		// DW-1574 Returns an error message to the user in the disconnecting status
		// Disconnecting status will soon change the standalone status
		if (cstate == C_DISCONNECTING) {
			retcode = ERR_NET_CONFIGURED;
		}
		goto out;
	}

	// BSR-1393 target-only set node cannot connect to another node in the promoted state.
	if (connection->resource->node_opts.target_only &&
		connection->resource->role[NOW] == R_PRIMARY) {
		retcode = ERR_PEER_TARGET_ONLY;
		goto out;
	}

	if (first_path(connection) == NULL) {
		bsr_msg_put_info(adm_ctx.reply_skb, "connection endpoint(s) missing");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}

	if (info->attrs[BSR_NLA_CONNECT_PARMS]) {
		err = connect_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		}
	}
	if (parms.discard_my_data) {
		if (adm_ctx.resource->role[NOW] == R_PRIMARY) {
			retcode = ERR_DISCARD_IMPOSSIBLE;
			goto out;
		}
		set_bit(CONN_DISCARD_MY_DATA, &connection->flags);
	}
	if (parms.tentative)
		set_bit(CONN_DRY_RUN, &connection->flags);

	/* Eventually allocate bitmap indexes for the peer_devices here */
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, i) {
		struct bsr_device *device;

		if (peer_device->bitmap_index != -1)
			continue;

		device = peer_device->device;
		if (!get_ldev(device))
			continue;

		err = allocate_bitmap_index(peer_device, device->ldev);
		put_ldev(__FUNCTION__, device);
		if (err) {
			retcode = ERR_INVALID_REQUEST;
			goto out;
		}
		bsr_md_mark_dirty(device);
	}

	retcode = change_cstate_ex(connection, C_UNCONNECTED, CS_VERBOSE);

out:
	// BSR-919
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_adm_new_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_connection *connection;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_PEER_NODE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	if (adm_ctx.connection) {
		retcode = ERR_INVALID_REQUEST;
		bsr_msg_put_info(adm_ctx.reply_skb, "peer connection already exists");
	} else {
		retcode = adm_new_connection(&connection, &adm_ctx, info);
	}

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_adm_new_path(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	/* remote transport endpoints need to be globaly unique */
	// BSR-966 lock adm_mutex first when executing a command.
	mutex_lock(&adm_ctx.resource->adm_mutex);
	mutex_lock(&resources_mutex);

	retcode = adm_add_path(&adm_ctx, info);

	mutex_unlock(&resources_mutex);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum bsr_ret_code
adm_del_path(struct bsr_config_context *adm_ctx,  struct genl_info *info)
{
	struct bsr_connection *connection = adm_ctx->connection;
	struct bsr_transport *transport = &connection->transport;
	struct nlattr *my_addr = NULL, *peer_addr = NULL;
	struct bsr_path *path = NULL; 
	int nr_paths = 0;
	int err;

	/* parse and validate only */
	err = path_parms_from_attrs(NULL, info);
	if (err) {
		bsr_msg_put_info(adm_ctx->reply_skb, from_attrs_err_to_txt(err));
		return ERR_MANDATORY_TAG;
	}
	my_addr = nested_attr_tb[__nla_type(T_my_addr)];
	peer_addr = nested_attr_tb[__nla_type(T_peer_addr)];
	list_for_each_entry_ex(struct bsr_path, path, &transport->paths, list)
		nr_paths++;

	// BSR-1013 fix failed reconnect due to path deletion during Unconnected
	if (nr_paths == 1 && connection->cstate[NOW] >= C_UNCONNECTED) {
		bsr_msg_put_info(adm_ctx->reply_skb,
				  "Can not delete last path, use disconnect first!");
		return ERR_INVALID_REQUEST;
	}

	// BSR-762 fix BSOD due to path deletion during disconnecting
	if (connection->cstate[NOW] == C_DISCONNECTING) {
		bsr_msg_put_info(adm_ctx->reply_skb,
				"Can not delete path during disconnecting, retry after reaching standalone state.");
		return ERR_INVALID_REQUEST;
	}
	
	err = -ENOENT;
	list_for_each_entry_ex(struct bsr_path, path, &transport->paths, list) {
		if (!addr_eq_nla(&path->my_addr, path->my_addr_len, my_addr))
			continue;
		if (!addr_eq_nla(&path->peer_addr, path->peer_addr_len, peer_addr))
			continue;

		err = transport->ops->remove_path(transport, path);
		if (err)
			break;
#ifdef _LIN
		synchronize_rcu();
#endif
		/* Transport modules might use RCU on the path list.
		   We do the synchronize_rcu() here in the generic code */
		INIT_LIST_HEAD(&path->list);
		notify_path(connection, path, NOTIFY_DESTROY);
		kref_put(&path->kref, bsr_destroy_path);
		return ERR_NO;
	}

	bsr_err(48, BSR_LC_GENL, connection, "Failed to delete path due to failure to put an listener. err(%d)", err);
	bsr_msg_put_info(adm_ctx->reply_skb,
			  err == -ENOENT ? "no such path" : "del_path on transport failed");
	return ERR_INVALID_REQUEST;
}

int bsr_adm_del_path(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	/* remote transport endpoints need to be globaly unique */
	// BSR-966 lock adm_mutex first when executing a command.
	mutex_lock(&adm_ctx.resource->adm_mutex);
	mutex_lock(&resources_mutex);

	retcode = adm_del_path(&adm_ctx, info);

	mutex_unlock(&resources_mutex);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_open_count(struct bsr_resource *resource)
{
	struct bsr_device *device;
	int vnr, open_cnt = 0;

	spin_lock_irq(&resource->req_lock);
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr)
		open_cnt += device->open_cnt;
	spin_unlock_irq(&resource->req_lock);

	return open_cnt;
}


static enum bsr_state_rv conn_try_disconnect(struct bsr_connection *connection, bool force,
					      // DW-2035 no wait resync option (sync_ee)
						  // BSR-930 
					      bool no_wait_resync,
					      struct sk_buff *reply_skb)
{
	struct bsr_resource *resource = connection->resource;
	enum bsr_conn_state cstate;
	enum bsr_state_rv rv;
	enum chg_state_flags flags = force ? CS_HARD : 0;
	long t = 0;
#ifdef _WIN
	char *err_str = NULL;
#else // _LIN
	const char *err_str = NULL;
#endif 

repeat:
	// DW-2035
	if (no_wait_resync)
		set_bit(DISCONN_NO_WAIT_RESYNC, &connection->flags);

	rv = change_cstate_es(connection, C_DISCONNECTING, flags, &err_str, __FUNCTION__);
	switch (rv) {
	case SS_CW_FAILED_BY_PEER:
		spin_lock_irq(&resource->req_lock);
		cstate = connection->cstate[NOW];
		spin_unlock_irq(&resource->req_lock);
		if (cstate < C_CONNECTED)
			goto repeat;
		break; 
	case SS_NO_UP_TO_DATE_DISK:
		if (resource->role[NOW] == R_PRIMARY)
			break;
		/* Most probably udev opened it read-only. That might happen
		if it was demoted very recently. Wait up to one second. */
		wait_event_interruptible_timeout_ex(resource->state_wait,
			bsr_open_count(resource) == 0,
			HZ, t);

		if (t <= 0)
			break;
		goto repeat;
	case SS_ALREADY_STANDALONE:
		rv = SS_SUCCESS;
		break;
	case SS_IS_DISKLESS:
	case SS_LOWER_THAN_OUTDATED:
		rv = change_cstate_ex(connection, C_DISCONNECTING, CS_HARD);
		break;
	case SS_NO_QUORUM:
		if (!(flags & CS_VERBOSE)) {
			flags |= CS_VERBOSE;
			goto repeat;
		}
		break;
	default:;
		/* no special handling necessary */
	}

	if (rv >= SS_SUCCESS) {
		int timeo;
		// DW-1574 Increase the wait time from 1 second to 3 seconds.
		wait_event_interruptible_timeout_ex(resource->state_wait,
						 connection->cstate[NOW] == C_STANDALONE,
						 3*HZ, timeo);
	}
	
	if (err_str) {
		if (reply_skb)
			bsr_msg_put_info(reply_skb, err_str);
		bsr_kfree(err_str);
		err_str = NULL;
	}

	return rv;
}

/* this cann only be called immediately after a successful
 * conn_try_disconnect, within the same resource->adm_mutex */
void del_connection(struct bsr_connection *connection)
{
	struct bsr_resource *resource = connection->resource;
	struct bsr_peer_device *peer_device;
	enum bsr_state_rv rv2;
	int vnr;

	/* No one else can reconfigure the network while I am here.
	 * The state handling only uses bsr_thread_stop_nowait(),
	 * we want to really wait here until the receiver is no more.
	 */
	bsr_thread_stop(&connection->receiver);

	/* Race breaker.  This additional state change request may be
	 * necessary, if this was a forced disconnect during a receiver
	 * restart.  We may have "killed" the receiver thread just
	 * after bsr_receiver() returned.  Typically, we should be
	 * C_STANDALONE already, now, and this becomes a no-op.
	 */
	rv2 = change_cstate_ex(connection, C_STANDALONE, CS_VERBOSE | CS_HARD);
	if (rv2 < SS_SUCCESS)
		bsr_err(31, BSR_LC_CONNECTION, connection, "Failed to delete connection due to failure to change status to standalone. state(%d)", rv2);
	/* Make sure the sender thread has actually stopped: state
	 * handling only does bsr_thread_stop_nowait().
	 */
	bsr_thread_stop(&connection->sender);

	bsr_unregister_connection(connection);

	/*
	 * Flush the resource work queue to make sure that no more
	 * events like state change notifications for this connection
	 * are queued: we want the "destroy" event to come last.
	 */
	bsr_flush_workqueue(resource, &resource->work);

	// BSR-920 
	// fix potential deadlock when executing bsr_flush_workqueue() with conf_update lock acquired
	mutex_lock(&resource->conf_update);
	
	mutex_lock(&notification_mutex);
	idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr)
		notify_peer_device_state(NULL, 0, peer_device, NULL,
					 NOTIFY_DESTROY | NOTIFY_CONTINUES);
	notify_connection_state(NULL, 0, connection, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);
#ifdef _LIN
	//windows, (1) synchronize_rcu_w32_wlock() is disabled, because Assertion: *** DPC watchdog timeout
	synchronize_rcu();
#endif

	// BSR-920
	mutex_unlock(&resource->conf_update);

	bsr_put_connection(connection);
}

int adm_disconnect(struct sk_buff *skb, struct genl_info *info, bool destroy)
{
	struct bsr_config_context adm_ctx;
	struct disconnect_parms parms;
	struct bsr_connection *connection;
	enum bsr_state_rv rv;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_CONNECTION);
	if (!adm_ctx.reply_skb)
		return retcode;

	memset(&parms, 0, sizeof(parms));
	if (info->attrs[BSR_NLA_DISCONNECT_PARMS]) {
		int err = disconnect_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto fail;
		}
	}

	connection = adm_ctx.connection;
	mutex_lock(&adm_ctx.resource->adm_mutex);

	// BSR-1233 del_connection() skip if C_UNREGISTERED flag is set
	if (test_bit(C_UNREGISTERED, &connection->flags))
		goto out;

	rv = conn_try_disconnect(connection, parms.force_disconnect, false, adm_ctx.reply_skb);
	if (rv >= SS_SUCCESS && destroy) {
		// BSR-920 moved inside del_connection()
		// mutex_lock(&connection->resource->conf_update);
		del_connection(connection);
		// mutex_unlock(&connection->resource->conf_update);
	}
	if (rv < SS_SUCCESS)
		retcode = rv;  /* FIXME: Type mismatch. */
	else
		retcode = ERR_NO;
out:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
 fail:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_adm_disconnect(struct sk_buff *skb, struct genl_info *info)
{
	return adm_disconnect(skb, info, 0);
}

int bsr_adm_del_peer(struct sk_buff *skb, struct genl_info *info)
{
	return adm_disconnect(skb, info, 1);
}

void resync_after_online_grow(struct bsr_peer_device *peer_device)
{
	struct bsr_connection *connection = peer_device->connection;
	struct bsr_device *device = peer_device->device;
	bool sync_source = false;
	s32 peer_id;

	bsr_info(50, BSR_LC_GENL, peer_device, "Resync of new storage after online grow");
	if (device->resource->role[NOW] != connection->peer_role[NOW])
		sync_source = (device->resource->role[NOW] == R_PRIMARY);
	else if (connection->agreed_pro_version < 111)
		sync_source = test_bit(RESOLVE_CONFLICTS,
				&peer_device->connection->transport.flags);
	else if (get_ldev(device)) {
		/* multiple or no primaries, proto new enough, resolve by node-id */
		s32 self_id = device->ldev->md.node_id;
		put_ldev(__FUNCTION__, device);
		peer_id = peer_device->node_id;

		sync_source = self_id < peer_id ? 1 : 0;
	}

	if (!sync_source && connection->agreed_pro_version < 110) {
		stable_change_repl_state(__FUNCTION__, peer_device, L_WF_SYNC_UUID,
					 CS_VERBOSE | CS_SERIALIZE);
		return;
	}
	bsr_start_resync(peer_device, sync_source ? L_SYNC_SOURCE : L_SYNC_TARGET);
}

sector_t bsr_local_max_size(struct bsr_device *device) __must_hold(local)
{
	struct bsr_backing_dev *tmp_bdev;
	sector_t s;

	tmp_bdev = bsr_kmalloc(sizeof(struct bsr_backing_dev), GFP_ATOMIC, '97SB');
	if (!tmp_bdev)
		return 0;

	*tmp_bdev = *device->ldev;
	bsr_md_set_sector_offsets(device, tmp_bdev);
	s = bsr_get_max_capacity(tmp_bdev);
	bsr_kfree(tmp_bdev);

	return s;
}

int bsr_adm_resize(struct sk_buff *skb, struct genl_info *info)
{
#ifdef _WIN
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	// DW-1469 disable bsr_adm_resize
	bsr_msg_put_info(adm_ctx.reply_skb, "cmd(bsr_adm_resize) error: not support.");
	bsr_adm_finish(&adm_ctx, info, ERR_INVALID_REQUEST);
	return 0;
#else // _LIN
	struct bsr_config_context adm_ctx;
	struct disk_conf *old_disk_conf, *new_disk_conf = NULL;
	struct resize_parms rs;
	struct bsr_device *device;
	enum bsr_ret_code retcode;
	enum determine_dev_size dd;
	bool change_al_layout = false;
	enum dds_flags ddsf;
	sector_t u_size;
	int err;
	struct bsr_peer_device *peer_device;
	bool resolve_by_node_id = true;
	bool has_up_to_date_primary;
	bool traditional_resize = false;
	sector_t local_max_size;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	device = adm_ctx.device;
	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto fail;
	}
	
	memset(&rs, 0, sizeof(struct resize_parms));
	rs.al_stripes = device->ldev->md.al_stripes;
	rs.al_stripe_size = device->ldev->md.al_stripe_size_4k * 4;
	if (info->attrs[BSR_NLA_RESIZE_PARMS]) {
		err = resize_parms_from_attrs(&rs, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto fail_ldev;
		}
	}
	
	device = adm_ctx.device;
	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] > L_ESTABLISHED) {
			retcode = ERR_RESIZE_RESYNC;
			goto fail_ldev;
		}
	}
	
	local_max_size = bsr_local_max_size(device);
	if (rs.resize_size && local_max_size < (sector_t)rs.resize_size) {
		bsr_err(51, BSR_LC_GENL, device, "Failed to resize due to requested %llu sectors, backend seems only able to support %llu",
			(unsigned long long)(sector_t)rs.resize_size,
			(unsigned long long)local_max_size);
		retcode = ERR_DISK_TOO_SMALL;
		goto fail_ldev;
	}
	
	/* Maybe I could serve as sync source myself? */
	has_up_to_date_primary =
		device->resource->role[NOW] == R_PRIMARY &&
		device->disk_state[NOW] == D_UP_TO_DATE;
	
	if (!has_up_to_date_primary) {
		for_each_peer_device(peer_device, device) {
			/* ignore unless connection is fully established */
			if (peer_device->repl_state[NOW] < L_ESTABLISHED)
				continue;
			if (peer_device->connection->agreed_pro_version < 111) {
				resolve_by_node_id = false;
				if (peer_device->connection->peer_role[NOW] == R_PRIMARY                
				&&  peer_device->disk_state[NOW] == D_UP_TO_DATE) {
					has_up_to_date_primary = true;
					break;
				}
			}
		}
	}
	if (!has_up_to_date_primary && !resolve_by_node_id) {
		retcode = ERR_NO_PRIMARY;
		goto fail_ldev;
	}
	
	for_each_peer_device(peer_device, device) {
		struct bsr_connection *connection = peer_device->connection;
		if (rs.no_resync &&
			connection->cstate[NOW] == C_CONNECTED &&
			connection->agreed_pro_version < 93) {
			retcode = ERR_NEED_APV_93;
			goto fail_ldev;
		}
	}
	
	rcu_read_lock();
	u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
	rcu_read_unlock();
	if (u_size != (sector_t)rs.resize_size) {
		new_disk_conf = bsr_kmalloc(sizeof(struct disk_conf), GFP_KERNEL, '');
		if (!new_disk_conf) {
			retcode = ERR_NOMEM;
			goto fail_ldev;
		}
	}
	
	if (device->ldev->md.al_stripes != rs.al_stripes ||
	    device->ldev->md.al_stripe_size_4k != rs.al_stripe_size / 4) {
		u32 al_size_k = rs.al_stripes * rs.al_stripe_size;
	
		if (al_size_k > (16 * 1024 * 1024)) {
			retcode = ERR_MD_LAYOUT_TOO_BIG;
			goto fail_ldev;
		}
	
		if (al_size_k < (32768 >> 10)) {
			retcode = ERR_MD_LAYOUT_TOO_SMALL;
			goto fail_ldev;
		}
	
		/* Removed this pre-condition while merging from 8.4 to 9.0
		if (device->state.conn != C_CONNECTED && !rs.resize_force) {
			retcode = ERR_MD_LAYOUT_CONNECTED;
			goto fail_ldev;
		} */
	
		change_al_layout = true;
	}
	
	device->ldev->known_size = bsr_get_capacity(device->ldev->backing_bdev);
	
	if (new_disk_conf) {
		mutex_lock(&device->resource->conf_update);
		old_disk_conf = device->ldev->disk_conf;
		*new_disk_conf = *old_disk_conf;
		new_disk_conf->disk_size = (sector_t)rs.resize_size;
		rcu_assign_pointer(device->ldev->disk_conf, new_disk_conf);
		mutex_unlock(&device->resource->conf_update);
		synchronize_rcu();
		bsr_kfree(old_disk_conf);
		new_disk_conf = NULL;
	}
	
	ddsf = (rs.resize_force ? DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE : 0)
		| (rs.no_resync ? DDSF_NO_RESYNC : 0);
	
	dd = change_cluster_wide_device_size(device, local_max_size, rs.resize_size, ddsf,
				change_al_layout ? &rs : NULL);
	if (dd == DS_2PC_NOT_SUPPORTED) {
		traditional_resize = true;
		dd = bsr_determine_dev_size(device, 0, ddsf, change_al_layout ? &rs : NULL);
	}
	
	bsr_md_sync_if_dirty(device);
	put_ldev(__FUNCTION__, device);
	if (dd == DS_ERROR) {
		retcode = ERR_NOMEM_BITMAP;
		goto fail;
	} else if (dd == DS_ERROR_SPACE_MD) {
		retcode = ERR_MD_LAYOUT_NO_FIT;
		goto fail;
	} else if (dd == DS_ERROR_SHRINK) {
		retcode = ERR_IMPLICIT_SHRINK;
		goto fail;
	} else if (dd == DS_2PC_ERR) {
		retcode = SS_INTERRUPTED;
		goto fail;
	}
	
	if (traditional_resize) {
		for_each_peer_device(peer_device, device) {
			if (peer_device->repl_state[NOW] == L_ESTABLISHED) {
				if (dd == DS_GREW)
					set_bit(RESIZE_PENDING, &peer_device->flags);
				bsr_send_uuids(peer_device, 0, 0, NOW);
				bsr_send_sizes(peer_device, rs.resize_size, ddsf);
			}
		}
	}
	
 fail:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;

 fail_ldev:
	put_ldev(__FUNCTION__, device);
	bsr_kfree(new_disk_conf);
	goto fail;
#endif	
}

int bsr_adm_resource_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;
	struct res_opts res_opts;
	int err;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	res_opts = adm_ctx.resource->res_opts;
	if (should_set_defaults(info))
		set_res_opts_defaults(&res_opts);

	err = res_opts_from_attrs_for_change(&res_opts, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	err = set_resource_options(adm_ctx.resource, &res_opts);
	if (err) {
		retcode = ERR_INVALID_REQUEST;
		if (err == -ENOMEM)
			retcode = ERR_NOMEM;
	}
	mutex_unlock(&adm_ctx.resource->adm_mutex);

fail:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_adm_node_opts(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;
	struct node_opts node_opts;
	int err;
	bool old_target_only = false;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	node_opts = adm_ctx.resource->node_opts;
	if (should_set_defaults(info))
		set_node_opts_defaults(&node_opts);

	err = node_opts_from_attrs_for_change(&node_opts, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto fail;
	}

	if (adm_ctx.resource->role[NOW] == R_PRIMARY) {
		if (node_opts.target_only) {
			retcode = ERR_LOCAL_TARGET_ONLY;
			goto fail;
		}
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);

	// BSR-859 notify by event when setting node name
	if (strcmp(adm_ctx.resource->node_opts.node_name, node_opts.node_name)) {
		mutex_lock(&notification_mutex);
		notify_node_info(NULL, 0, adm_ctx.resource, NULL, node_opts.node_name, BSR_NODE_INFO, NOTIFY_CHANGE);
		mutex_unlock(&notification_mutex);
	}
	old_target_only = adm_ctx.resource->node_opts.target_only;
	adm_ctx.resource->node_opts = node_opts;

	// BSR-1393
	if (old_target_only != node_opts.target_only) {
		struct bsr_connection *connection;
		struct bsr_peer_device *peer_device;
		struct bsr_device *device;
		int vnr;
		u64 im;

		// BSR-1411
		if (node_opts.target_only) {
			idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
				if (bsr_md_test_flag(device, MDF_WAS_PRIMARY)) {
					bsr_md_clear_flag(device, MDF_WAS_PRIMARY);
					bsr_md_sync(device);
				}
			}
		}

		for_each_connection_ref(connection, im, adm_ctx.resource) {
			idr_for_each_entry_ex(struct bsr_peer_device *, &connection->peer_devices, peer_device, vnr) {
				bsr_send_uuids(peer_device, 0, 0, NOW);
				if (!old_target_only) {
					// BSR-1393 If resync when setting target-only, stop it.
					if (peer_device->repl_state[NOW] == L_SYNC_SOURCE ||
						peer_device->repl_state[NOW] == L_PAUSED_SYNC_S) {
						unsigned long irq_flags;

						begin_state_change(adm_ctx.resource, &irq_flags, CS_HARD);
						__change_repl_state(peer_device, L_ESTABLISHED, __FUNCTION__);
						end_state_change(adm_ctx.resource, &irq_flags, __FUNCTION__);
					}	
				}
			}
		}
	}

	mutex_unlock(&adm_ctx.resource->adm_mutex);

fail:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum bsr_state_rv invalidate_resync(struct bsr_peer_device *peer_device)
{
	struct bsr_resource *resource = peer_device->connection->resource;
	enum bsr_state_rv rv;
	int res = 0;

	bsr_flush_workqueue(resource, &peer_device->connection->sender_work);
	// BSR-1427 check that the peer node is in a stable state.
	if (!bsr_inspect_resync_side(peer_device, L_SYNC_TARGET, NOW, false))
		return SS_CW_FAILED_BY_PEER;

	rv = change_repl_state(__FUNCTION__, peer_device, L_STARTING_SYNC_T, CS_SERIALIZE);

	if (rv < SS_SUCCESS && rv != SS_NEED_CONNECTION)
		rv = stable_change_repl_state(__FUNCTION__, peer_device, L_STARTING_SYNC_T,
			CS_VERBOSE | CS_SERIALIZE);

	wait_event_interruptible_ex(resource->state_wait,
				 peer_device->repl_state[NOW] != L_STARTING_SYNC_T, res);

	return rv;
}

#if 0 // BSR-174 not used
static enum bsr_state_rv invalidate_no_resync(struct bsr_device *device) __must_hold(local)
{
	struct bsr_resource *resource = device->resource;
	struct bsr_peer_device *peer_device;
	struct bsr_connection *connection;
	unsigned long irq_flags;
	enum bsr_state_rv rv;

	begin_state_change(resource, &irq_flags, CS_VERBOSE);
	for_each_connection(connection, resource) {
		peer_device = conn_peer_device(connection, device->vnr);
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED) {
			abort_state_change(resource, &irq_flags, __FUNCTION__);
			return SS_UNKNOWN_ERROR;
		}
	}
	__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
	rv = end_state_change(resource, &irq_flags, __FUNCTION__);

	if (rv >= SS_SUCCESS) {
		bsr_bitmap_io(device, &bsr_bmio_set_all_n_write,
			       "set_n_write from invalidate",
			       BM_LOCK_CLEAR | BM_LOCK_BULK,
			       NULL);
	}

	return rv;
}
#endif

int bsr_adm_invalidate(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_peer_device *sync_from_peer_device = NULL;
	struct bsr_resource *resource;
	struct bsr_peer_device *peer_device;
	struct bsr_device *device;
	int retcode = 0; /* enum bsr_ret_code rsp. enum bsr_state_rv */

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;

	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out_no_ldev;
	}

	for_each_peer_device(peer_device, device) {
		enum bsr_repl_state *repl_state = peer_device->repl_state;
		if ((repl_state[NEW] >= L_STARTING_SYNC_S && repl_state[NEW] <= L_WF_BITMAP_T) ||
			(repl_state[NEW] >= L_SYNC_SOURCE && repl_state[NEW] <= L_PAUSED_SYNC_T)) {
			if (repl_state[NOW] >= L_ESTABLISHED && !bsr_inspect_resync_side(peer_device, repl_state[NEW], NEW, false)) {
				retcode = ERR_CODE_BASE;
			}
			// DW-2031 add put_ldev() due to ldev leak occurrence
			put_ldev(__FUNCTION__, device);
			goto out_no_ldev;
		}
	}

	resource = device->resource;

	mutex_lock(&resource->adm_mutex);

	if (info->attrs[BSR_NLA_INVALIDATE_PARMS]) {
		struct invalidate_parms inv = { 0, };
		int err;

		inv.sync_from_peer_node_id = -1;
		err = invalidate_parms_from_attrs(&inv, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out_no_resume;
		}

		if (inv.sync_from_peer_node_id != -1) {
			struct bsr_connection *connection =
				bsr_connection_by_node_id(resource, inv.sync_from_peer_node_id);
			// DW-1134 fix crash for invalid peer node id
			if(connection == NULL) {
				retcode = ERR_INVALID_PEER_NODE_ID;
				bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
				goto out_no_resume;
			}

			// BSR-917 if it is not connected, treat it as an error.
			if (connection->cstate[NOW] != C_CONNECTED) {
				retcode = SS_NEED_CONNECTION;
				goto out_no_resume;
			}
			sync_from_peer_device = conn_peer_device(connection, device->vnr);
		}
	}

	/* If there is still bitmap IO pending, probably because of a previous
	 * resync just being finished, wait for it before requesting a new resync.
	 * Also wait for its after_state_ch(). */
	bsr_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));

	if (sync_from_peer_device) {
		// BSR-1393
		if (sync_from_peer_device->uuid_flags & UUID_FLAG_TARGET_ONLY)
			retcode = ERR_PEER_TARGET_ONLY;
		else
			retcode = invalidate_resync(sync_from_peer_device);
	} else {
		int retry = 3;
		do {
			struct bsr_connection *connection;
			// DW-907
			int success = 0;

			for_each_connection(connection, resource) {
				struct bsr_peer_device *peer_device;

				// BSR-917 ignore if not connected.
				if (connection->cstate[NOW] != C_CONNECTED) {
					retcode = SS_NEED_CONNECTION;
					continue;
				}

				peer_device = conn_peer_device(connection, device->vnr);

				// BSR-1393
				if (peer_device->uuid_flags & UUID_FLAG_TARGET_ONLY) {
					if (!success)
						retcode = ERR_PEER_TARGET_ONLY;
				}
				else
					retcode = invalidate_resync(peer_device);

				if (retcode >= SS_SUCCESS)
				// DW-907 implicitly request to get synced to all peers, as a way of hedging first source node put out.
				{
					success = retcode;
				}
			}
			// DW-907 retcode will be success at least one succeeded peer.
			if (success) {
				retcode = success;
				goto out;
			}

			// BSR-917
			if (retcode < SS_UNKNOWN_ERROR)
				break;
			
			// BSR-174 not allow invalidate when disconnected
			//retcode = invalidate_no_resync(device);
			
		} while (retcode == SS_UNKNOWN_ERROR && retry--);
	}

out:
	bsr_resume_io(device);
out_no_resume:
	mutex_unlock(&resource->adm_mutex);
	put_ldev(__FUNCTION__, device);
out_no_ldev:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

#if 0 // BSR-174 not used
static int bsr_bmio_set_susp_al(struct bsr_device *device, struct bsr_peer_device *peer_device) __must_hold(local)
{
	int rv;

	rv = bsr_bmio_set_n_write(device, peer_device);
	bsr_try_suspend_al(device);
	return rv;
}
#endif

int bsr_adm_invalidate_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_peer_device *peer_device;
	struct bsr_resource *resource;
	struct bsr_device *device;
	struct bsr_peer_device *temp_peer_device;
	int retcode; /* enum bsr_ret_code rsp. enum bsr_state_rv */

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;
	device = peer_device->device;
	resource = device->resource;

	for_each_peer_device(temp_peer_device, device) {
		enum bsr_role *role = resource->role;
		enum bsr_repl_state *repl_state = temp_peer_device->repl_state;

		if ( (role[NOW] == R_SECONDARY)
			&& ( repl_state[NOW] == L_STARTING_SYNC_T 
				|| repl_state[NOW] == L_WF_BITMAP_T 
				|| repl_state[NOW] == L_SYNC_TARGET 
				|| repl_state[NOW] == L_PAUSED_SYNC_T 
				|| repl_state[NOW] == L_VERIFY_T ) )
		{
			retcode = ERR_CODE_BASE;
			goto out;
		}
	}

	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}

	// BSR-1393
	if (resource->node_opts.target_only) {
		retcode = ERR_LOCAL_TARGET_ONLY;
		put_ldev(__FUNCTION__, device);
		goto out;
	}

	mutex_lock(&resource->adm_mutex);

	// BSR-1254 verify that you are connected
	if (peer_device->connection->cstate[NOW] != C_CONNECTED) {
		retcode = SS_NEED_CONNECTION;
		goto out_no_resume;
	}

	clear_bit(USE_CURRENT_OOS_FOR_SYNC, &peer_device->flags);
	if (info->attrs[BSR_NLA_INVALIDATE_PEER_PARMS]) {
		struct invalidate_peer_parms inv = { 0, };
		int err;

		err = invalidate_peer_parms_from_attrs(&inv, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out_no_resume;
		}

		if(inv.use_current_oos)
			set_bit(USE_CURRENT_OOS_FOR_SYNC, &peer_device->flags);
	}

	bsr_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));
	bsr_flush_workqueue(resource, &peer_device->connection->sender_work);
	
	retcode = stable_change_repl_state(__FUNCTION__, peer_device, L_STARTING_SYNC_S, CS_SERIALIZE);

	if (retcode < SS_SUCCESS) {
		// BSR-174 not allow invalidate-remote when disconnected
#if 0
		if (retcode == SS_NEED_CONNECTION && resource->role[NOW] == R_PRIMARY) {
			/* The peer will get a resync upon connect anyways.
			 * Just make that into a full resync. */
			retcode = change_peer_disk_state(peer_device, D_INCONSISTENT,
							 CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
			if (retcode >= SS_SUCCESS) {
				if (bsr_bitmap_io(adm_ctx.device, &bsr_bmio_set_susp_al,
						   "set_n_write from invalidate_peer",
						   BM_LOCK_CLEAR | BM_LOCK_BULK, peer_device))
					retcode = ERR_IO_MD_DISK;
			}
		} else
#endif
			retcode = stable_change_repl_state(__FUNCTION__, peer_device, L_STARTING_SYNC_S,
							   CS_VERBOSE | CS_SERIALIZE);
	}
	bsr_resume_io(device);

	
out_no_resume:
	mutex_unlock(&resource->adm_mutex);
	put_ldev(__FUNCTION__, device);
out:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_adm_pause_sync(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_peer_device *peer_device;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	peer_device = adm_ctx.peer_device;
	if (change_resync_susp_user(peer_device, true,
		CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, __FUNCTION__) == SS_NOTHING_TO_DO)
		retcode = ERR_PAUSE_IS_SET;

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_adm_resume_sync(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_peer_device *peer_device;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);

	peer_device = adm_ctx.peer_device;
	if (change_resync_susp_user(peer_device, false,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, __FUNCTION__) == SS_NOTHING_TO_DO) {

		if (peer_device->repl_state[NOW] == L_PAUSED_SYNC_S ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
			if (peer_device->resync_susp_dependency[NOW])
				retcode = ERR_PIC_AFTER_DEP;
			else if (peer_device->resync_susp_peer[NOW])
				retcode = ERR_PIC_PEER_DEP;
			else
				retcode = ERR_PAUSE_IS_CLEAR;
		} else {
			retcode = ERR_PAUSE_IS_CLEAR;
		}
	}

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_adm_suspend_io(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_resource *resource;
	enum bsr_state_rv retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	resource = adm_ctx.device->resource;

#ifdef _WIN 
	// DW-1361 disable bsr_adm_suspend_io
	bsr_err(52, BSR_LC_GENL, resource, "Failed to I/O(%d) suspend due to not supported.", info->genlhdr->cmd);
	bsr_adm_finish(&adm_ctx, info, -ENOMSG);
	return -ENOMSG;
#else // _LIN
	//TODO: support for suspend io on linux?
	mutex_lock(&resource->adm_mutex);
	// DW-1605
	stable_state_change(retcode, resource,
		change_io_susp_user(resource, true,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE));

	mutex_unlock(&resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
#endif
}

int bsr_adm_resume_io(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_resource *resource;
	int retcode; /* enum bsr_ret_code rsp. enum bsr_state_rv */
#ifdef _LIN
	struct bsr_device *device;	
	struct bsr_connection *connection;
	ULONG_PTR irq_flags;
#endif

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

#ifdef _WIN
	// DW-1361 disable bsr_adm_resume_io
	resource = adm_ctx.device->resource;
	bsr_err(53, BSR_LC_GENL, resource, "Failed to I/O(%d) resume due to not supported.", info->genlhdr->cmd);;
	bsr_adm_finish(&adm_ctx, info, -ENOMSG);
	return -ENOMSG;
#else // _LIN
	//TODO: support for resumio on linux?
	mutex_lock(&adm_ctx.resource->adm_mutex);
	device = adm_ctx.device;
	resource = device->resource;
	if (test_and_clear_bit(NEW_CUR_UUID, &device->flags)) {
		bsr_info(32, BSR_LC_UUID, device, "clear UUID creation flag due to resume i/o");
		bsr_uuid_new_current(device, false, false, true, __FUNCTION__);
	}
	bsr_suspend_io(device, READ_AND_WRITE);
	begin_state_change(resource, &irq_flags, CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
	__change_io_susp_user(resource, false);
	__change_io_susp_no_data(resource, false);

	for_each_connection(connection, resource)
		__change_io_susp_fencing(connection, false);
	__change_io_susp_quorum(device, false);
	retcode = end_state_change(resource, &irq_flags, __FUNCTION__);
	if (retcode == SS_SUCCESS) {
		struct bsr_peer_device *peer_device;

		for_each_peer_device(peer_device, device) {
			struct bsr_connection *connection = peer_device->connection;

			if (peer_device->repl_state[NOW] < L_ESTABLISHED)
				tl_clear(connection);
			if (device->disk_state[NOW] == D_DISKLESS ||
			    device->disk_state[NOW] == D_FAILED ||
			    device->disk_state[NOW] == D_DETACHING)
				tl_restart(connection, FAIL_FROZEN_DISK_IO);
		}
	}
	bsr_resume_io(device);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
#endif
}

int bsr_adm_outdate(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_state_rv retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;
	mutex_lock(&adm_ctx.resource->adm_mutex);
	// DW-1605
	stable_state_change(retcode, adm_ctx.device->resource,
		change_disk_state(adm_ctx.device, D_OUTDATED,
			CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE, NULL));

	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int nla_put_bsr_cfg_context(struct sk_buff *skb,
				    struct bsr_resource *resource,
				    struct bsr_connection *connection,
				    struct bsr_device *device,
				    struct bsr_path *path)
{
	struct nlattr *nla;
	nla = nla_nest_start(skb, BSR_NLA_CFG_CONTEXT);
	if (!nla)
		goto nla_put_failure;
	if (device)
		nla_put_u32(skb, T_ctx_volume, device->vnr);
	if (resource)
		nla_put_string(skb, T_ctx_resource_name, resource->name);
	if (connection) {
		nla_put_u32(skb, T_ctx_peer_node_id, connection->peer_node_id);
		rcu_read_lock();
		if (connection->transport.net_conf && connection->transport.net_conf->name)
			nla_put_string(skb, T_ctx_conn_name, connection->transport.net_conf->name);
		rcu_read_unlock();
	}
	if (path) {
		nla_put(skb, T_ctx_my_addr, path->my_addr_len, &path->my_addr);
		nla_put(skb, T_ctx_peer_addr, path->peer_addr_len, &path->peer_addr);
	}
	nla_nest_end(skb, nla);
	return 0;

nla_put_failure:
	if (nla)
		nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

// BSR-859 set node events context
static int nla_put_bsr_node_cfg_context(struct sk_buff *skb,
				    struct bsr_resource *resource,
				    struct bsr_connection *connection)
{
	struct nlattr *nla;
	nla = nla_nest_start(skb, BSR_NLA_CFG_CONTEXT);
	if (!nla)
		goto nla_put_failure;
	if (resource)
		nla_put_string(skb, T_ctx_resource_name, resource->name);
	if (connection)
		nla_put_u32(skb, T_ctx_peer_node_id, connection->peer_node_id);

	nla_nest_end(skb, nla);
	return 0;

nla_put_failure:
	if (nla)
		nla_nest_cancel(skb, nla);
	return -EMSGSIZE;
}

/*
 * The generic netlink dump callbacks are called outside the genl_lock(), so
 * they cannot use the simple attribute parsing code which uses global
 * attribute tables.
 */
static struct nlattr *find_cfg_context_attr(const struct nlmsghdr *nlh, int attr)
{
	const unsigned hdrlen = GENL_HDRLEN + GENL_MAGIC_FAMILY_HDRSZ;
	const int maxtype = ARRAY_SIZE(bsr_cfg_context_nl_policy) - 1;
	struct nlattr *nla;

	nla = nla_find(nlmsg_attrdata(nlh, hdrlen), nlmsg_attrlen(nlh, hdrlen),
		       BSR_NLA_CFG_CONTEXT);
	if (!nla)
		return NULL;
	return bsr_nla_find_nested(maxtype, nla, __nla_type(attr));
}

static void resource_to_info(struct resource_info *, struct bsr_resource *);

int bsr_adm_dump_resources(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct bsr_genlmsghdr *dh;
	struct bsr_resource *resource;
	struct resource_info resource_info;
	struct resource_statistics resource_statistics;
	int err;

	rcu_read_lock();
	if (cb->args[0]) {
		for_each_resource_rcu(resource, &bsr_resources)
			if (resource == (struct bsr_resource *)cb->args[0])
				goto found_resource;
		err = 0;  /* resource was probably deleted */
		goto out;
	}
	resource = list_entry(&bsr_resources,
			      struct bsr_resource, resources);

found_resource:
#ifdef _WIN
	resource = list_entry_rcu(resource->resources.next, struct bsr_resource, resources); 
	if (&resource->resources != (&bsr_resources))
		goto put_result;
#else // _LIN
	list_for_each_entry_continue_rcu_ex(struct bsr_resource, resource, &bsr_resources, resources) {
		goto put_result;
	}
#endif
	err = 0;
	goto out;

put_result:
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &bsr_genl_family,
		NLM_F_MULTI, BSR_ADM_GET_RESOURCES);
	
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;

#ifdef _WIN
	// BSR-421 modify deadlock of rcu_read_lock
	rcu_read_unlock();
#endif
	err = nla_put_bsr_cfg_context(skb, resource, NULL, NULL, NULL);
#ifdef _WIN
	rcu_read_lock_w32_inner();
#endif

	if (err)
		goto out;
	err = res_opts_to_skb(skb, &resource->res_opts, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;

	// BSR-718
	err = node_opts_to_skb(skb, &resource->node_opts, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;

#ifdef _WIN
	// BSR-421 modify deadlock of rcu_read_lock
	rcu_read_unlock();
#endif
	resource_to_info(&resource_info, resource);
#ifdef _WIN
	rcu_read_lock_w32_inner();
#endif

	err = resource_info_to_skb(skb, &resource_info, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;
	resource_statistics.res_stat_write_ordering = resource->write_ordering;
	// DW-1925
	resource_statistics.res_stat_req_write_cnt = atomic_read(&resource->req_write_cnt);
	err = resource_statistics_to_skb(skb, &resource_statistics, !capable(CAP_SYS_ADMIN));
	if (err)
		goto out;
	cb->args[0] = (LONG_PTR)resource;
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

extern atomic_t g_fake_al_used;

static void device_to_statistics(struct device_statistics *s,
				 struct bsr_device *device)
{
	memset(s, 0, sizeof(*s));
	s->dev_upper_blocked = !may_inc_ap_bio(device, NULL);
	if (get_ldev(device)) {
		struct bsr_md *md = &device->ldev->md;
		u64 *history_uuids = (u64 *)s->history_uuids;
		struct request_queue *q;
		int n;

		spin_lock_irq(&md->uuid_lock);
		s->dev_current_uuid = md->current_uuid;
		BUILD_BUG_ON(sizeof(s->history_uuids) != sizeof(md->history_uuids));
		for (n = 0; n < ARRAY_SIZE(md->history_uuids); n++)
			history_uuids[n] = md->history_uuids[n];
		s->history_uuids_len = sizeof(s->history_uuids);
		spin_unlock_irq(&md->uuid_lock);

		s->dev_disk_flags = md->flags;
		q = bdev_get_queue(device->ldev->backing_bdev);
#ifdef _LIN
		s->dev_lower_blocked = 
// BSR-1095
#ifdef COMPAT_HAVE_BDI_CONGESTED_FN
#ifdef COMPAT_STRUCT_GENDISK_HAS_BACKING_DEV_INFO
			bdi_congested(device->ldev->backing_bdev->bd_disk->bdi,
#else
			bdi_congested(q->backing_dev_info,
#endif
				      (1 << WB_async_congested) |
					  (1 << WB_sync_congested));
#else
			0;
#endif
#endif
		put_ldev(__FUNCTION__, device);
	}
	s->dev_size = bsr_get_vdisk_capacity(device);
	s->dev_read = device->read_cnt;
	s->dev_write = device->writ_cnt;
	s->dev_al_writes = device->al_writ_cnt;
	s->dev_bm_writes = device->bm_writ_cnt;
	s->dev_upper_pending = atomic_read(&device->ap_bio_cnt[READ]) +
		atomic_read(&device->ap_bio_cnt[WRITE]);
	s->dev_accelbuf_used = atomic_read64(&device->accelbuf.used_size);
	s->dev_lower_pending = atomic_read(&device->local_cnt);
	s->dev_al_suspended = test_bit(AL_SUSPENDED, &device->flags);
	s->dev_exposed_data_uuid = device->exposed_data_uuid;
	// DW-1945 check status of Activity-Log
	if (device->act_log) {
		s->dev_al_pending_changes = device->act_log->pending_changes;
		s->dev_al_used = device->act_log->used + atomic_read(&g_fake_al_used);
	}
}

static int put_resource_in_arg0(struct netlink_callback *cb, int holder_nr)
{
	if (cb->args[0]) {
		struct bsr_resource *resource =
			(struct bsr_resource *)cb->args[0];
		kref_debug_put(&resource->kref_debug, holder_nr); /* , 6); , 7); */
		kref_put(&resource->kref, bsr_destroy_resource);
	}

	return 0;
}

int bsr_adm_dump_devices_done(struct netlink_callback *cb) {
	return put_resource_in_arg0(cb, 7);
}

int bsr_adm_dump_devices(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct bsr_resource *resource;	
	int minor = 0, err = 0, retcode = 0;
	struct bsr_device *device = NULL;
	struct bsr_genlmsghdr *dh;
	struct device_info device_info;
	struct device_statistics device_statistics;
	struct idr *idr_to_search;

	resource = (struct bsr_resource *)cb->args[0];

	rcu_read_lock();
	if (!cb->args[0] && !cb->args[1]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
#ifdef _WIN // DW-900 to avoid the recursive lock
			rcu_read_unlock();
#endif
			resource = bsr_find_resource(nla_data(resource_filter));
#ifdef _WIN // DW-900 to avoid the recursive lock
			rcu_read_lock_w32_inner();
#endif
			if (!resource)
				goto put_result;
			kref_debug_get(&resource->kref_debug, 7);
			cb->args[0] = (LONG_PTR)resource;
		}
	}
#ifdef _WIN64
	BUG_ON_INT32_OVER(cb->args[1]);
#endif
	minor = (int)cb->args[1];
	idr_to_search = resource ? &resource->devices : &bsr_devices;
	device = idr_get_next(idr_to_search, &minor);
	if (!device) {
		err = 0;
		goto out;
	}

//	idr_for_each_entry_continue_ex(struct bsr_device *, idr_to_search, device, minor) {
//		retcode = ERR_NO;
//		goto put_result;  /* only one iteration */
//	}

	device = (struct bsr_device *)idr_get_next((idr_to_search), &(minor));
	if (device) {
			retcode = ERR_NO;
			goto put_result;  /* only one iteration */
	}

	err = 0;
	goto out;  /* no more devices */

put_result:
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &bsr_genl_family,
		NLM_F_MULTI, BSR_ADM_GET_DEVICES);
	
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = UINT32_MAX;
	if (retcode == ERR_NO) {
		dh->minor = device->minor;

#ifdef _WIN
		// BSR-421 modify deadlock of rcu_read_lock
		rcu_read_unlock();
#endif
		err = nla_put_bsr_cfg_context(skb, device->resource, NULL, device, NULL);
#ifdef _WIN
		rcu_read_lock_w32_inner();
#endif
		if (err)
			goto out;
		if (get_ldev(device)) {
			struct disk_conf *disk_conf =
				rcu_dereference(device->ldev->disk_conf);

			err = disk_conf_to_skb(skb, disk_conf, !capable(CAP_SYS_ADMIN));
			put_ldev(__FUNCTION__, device);
			if (err)
				goto out;
		}
		err = device_conf_to_skb(skb, &device->device_conf, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		device_to_info(&device_info, device);
		err = device_info_to_skb(skb, &device_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
#ifdef _WIN // DW-900 to avoid the recursive lock
		rcu_read_unlock();
#endif
		device_to_statistics(&device_statistics, device);
#ifdef _WIN // DW-900 to avoid the recursive lock
		rcu_read_lock_w32_inner();
#endif
		err = device_statistics_to_skb(skb, &device_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		cb->args[1] = minor + 1;
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

int bsr_adm_dump_connections_done(struct netlink_callback *cb)
{
	return put_resource_in_arg0(cb, 6);
}

int connection_paths_to_skb(struct sk_buff *skb, struct bsr_connection *connection)
{
	struct bsr_path *path;
	struct nlattr *tla = nla_nest_start(skb, BSR_NLA_PATH_PARMS);
	if (!tla)
		goto nla_put_failure;

	/* array of such paths. */
	list_for_each_entry_ex(struct bsr_path, path, &connection->transport.paths, list) {
		if (nla_put(skb, T_my_addr, path->my_addr_len, &path->my_addr))
			goto nla_put_failure;
		if (nla_put(skb, T_peer_addr, path->peer_addr_len, &path->peer_addr))
			goto nla_put_failure;
	}
	nla_nest_end(skb, tla);
	return 0;

nla_put_failure:
	if (tla)
		nla_nest_cancel(skb, tla);
	return -EMSGSIZE;
}

enum { SINGLE_RESOURCE, ITERATE_RESOURCES };

int bsr_adm_dump_connections(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct bsr_resource *resource = NULL, *next_resource;
	struct bsr_connection *connection = NULL;
	int err = 0, retcode;
	struct bsr_genlmsghdr *dh;
	struct connection_info connection_info;
	struct connection_statistics connection_statistics;

	rcu_read_lock();
	resource = (struct bsr_resource *)cb->args[0];
	if (!cb->args[0]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
#ifdef _WIN // DW-900 to avoid the recursive lock
			rcu_read_unlock();
#endif
			resource = bsr_find_resource(nla_data(resource_filter));
#ifdef _WIN // DW-900 to avoid the recursive lock
			rcu_read_lock_w32_inner();
#endif
			if (!resource)
				goto put_result;
			kref_debug_get(&resource->kref_debug, 6);
			cb->args[0] = (LONG_PTR)resource;
			cb->args[1] = SINGLE_RESOURCE;
		}
	}
	if (!resource) {
		if (list_empty(&bsr_resources))
			goto out;
		resource = list_first_entry(&bsr_resources, struct bsr_resource, resources);
		kref_get(&resource->kref);
		kref_debug_get(&resource->kref_debug, 6);
		cb->args[0] = (LONG_PTR)resource;
		cb->args[1] = ITERATE_RESOURCES;
	}

    next_resource:
	rcu_read_unlock();
	mutex_lock(&resource->conf_update);
#ifdef _WIN
	rcu_read_lock_w32_inner();
#else // _LIN
	rcu_read_lock();
#endif
	if (cb->args[2]) {
		for_each_connection_rcu(connection, resource)
			if (connection == (struct bsr_connection *)cb->args[2])
				goto found_connection;
		/* connection was probably deleted */
		goto no_more_connections;
	}
	connection = list_entry(&resource->connections, struct bsr_connection, connections);

found_connection:
#ifdef _WIN
	connection = list_entry_rcu(connection->connections.next, struct bsr_connection, connections);
	if(&connection->connections != &(resource->connections)) {        
		retcode = ERR_NO;
		goto put_result;  /* only one iteration */
	}
#else // _LIN
	list_for_each_entry_continue_rcu_ex(struct bsr_connection, connection, &resource->connections, connections) {
		retcode = ERR_NO;
		goto put_result;  /* only one iteration */
	}
#endif

no_more_connections:
	if (cb->args[1] == ITERATE_RESOURCES) {
		for_each_resource_rcu(next_resource, &bsr_resources) {
			if (next_resource == resource)
				goto found_resource;
		}
		/* resource was probably deleted */
	}
	goto out;

found_resource:
	next_resource = list_entry_rcu(next_resource->resources.next, struct bsr_resource, resources);
	if (&next_resource->resources != &(bsr_resources)) {
		mutex_unlock(&resource->conf_update);
		kref_debug_put(&resource->kref_debug, 6);
		kref_put(&resource->kref, bsr_destroy_resource);
		resource = next_resource;
		kref_get(&resource->kref);
		kref_debug_get(&resource->kref_debug, 6);
		cb->args[0] = (LONG_PTR)resource;
		cb->args[2] = 0;
		goto next_resource;
	}

	goto out;  /* no more resources */

put_result:
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &bsr_genl_family,
		NLM_F_MULTI, BSR_ADM_GET_CONNECTIONS);
	
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = UINT32_MAX;
	if (retcode == ERR_NO) {
		struct net_conf *net_conf;

#ifdef _WIN
		// BSR-421 modify deadlock of rcu_read_lock
		rcu_read_unlock();
#endif
		err = nla_put_bsr_cfg_context(skb, resource, connection, NULL, NULL);
#ifdef _WIN
		rcu_read_lock_w32_inner();
#endif
		if (err)
			goto out;
		net_conf = rcu_dereference(connection->transport.net_conf);
		if (net_conf) {
			err = net_conf_to_skb(skb, net_conf, !capable(CAP_SYS_ADMIN));
			if (err)
				goto out;
		}
		connection_to_info(&connection_info, connection);
		connection_paths_to_skb(skb, connection);
		err = connection_info_to_skb(skb, &connection_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		connection_statistics.conn_congested = test_bit(NET_CONGESTED, &connection->transport.flags);
		err = connection_statistics_to_skb(skb, &connection_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		cb->args[2] = (LONG_PTR)connection;
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (resource)
		mutex_unlock(&resource->conf_update);
	if (err)
		return err;
	return skb->len;
}

static void peer_device_to_statistics(struct peer_device_statistics *s,
				      struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
	ULONG_PTR now = jiffies;
	ULONG_PTR rs_left = 0;
	int i;

	memset(s, 0, sizeof(*s));
	s->peer_dev_received = peer_device->recv_cnt;
	s->peer_dev_sent = peer_device->send_cnt;
	s->peer_dev_pending = atomic_read(&peer_device->ap_pending_cnt) +
			      atomic_read(&peer_device->rs_pending_cnt);
	s->peer_dev_unacked = atomic_read(&peer_device->unacked_cnt);

	s->peer_dev_out_of_sync = BM_BIT_TO_SECT(bsr_bm_total_weight(peer_device));
	s->peer_dev_resync_failed = BM_BIT_TO_SECT(peer_device->rs_failed);

	// BSR-580
	if (is_verify_state(peer_device, NOW)) {
		rs_left = BM_BIT_TO_SECT(peer_device->ov_left);
		s->peer_dev_ov_left = BM_BIT_TO_SECT(peer_device->ov_left);
	}
	else if (is_sync_state(peer_device, NOW)) {
		rs_left = s->peer_dev_out_of_sync - BM_BIT_TO_SECT(peer_device->rs_failed);
	}

	// BSR-191 sync progress
	if (rs_left) {
		enum bsr_repl_state repl_state = peer_device->repl_state[NOW];
		if (repl_state == L_SYNC_TARGET || repl_state == L_VERIFY_S)
			s->peer_dev_rs_c_sync_rate = peer_device->c_sync_rate;

		s->peer_dev_rs_total = BM_BIT_TO_SECT(peer_device->rs_total);

		i = (peer_device->rs_last_mark + BSR_SYNC_MARKS-1) % BSR_SYNC_MARKS;
		s->peer_dev_rs_dt_ms = jiffies_to_msecs(now - peer_device->rs_mark_time[i]);
		s->peer_dev_rs_db_sectors = BM_BIT_TO_SECT(peer_device->rs_mark_left[i]) - rs_left;

		// BSR-1125
		s->peer_dev_disk_size = bsr_get_vdisk_capacity(peer_device->device);
	}

	if (get_ldev(device)) {
		struct bsr_md *md = &device->ldev->md;
		struct bsr_peer_md *peer_md = &md->peers[peer_device->node_id];

		spin_lock_irq(&md->uuid_lock);
		s->peer_dev_bitmap_uuid = peer_md->bitmap_uuid;
		spin_unlock_irq(&md->uuid_lock);
		s->peer_dev_flags = peer_md->flags;
		put_ldev(__FUNCTION__, device);
	}
}

int bsr_adm_dump_peer_devices_done(struct netlink_callback *cb)
{
	return put_resource_in_arg0(cb, 9);
}

int bsr_adm_dump_peer_devices(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *resource_filter;
	struct bsr_resource *resource;
	struct bsr_device *device = NULL;
	struct bsr_peer_device *peer_device = NULL;
	int minor = 0, err = 0, retcode = 0;
	
	struct bsr_genlmsghdr *dh;
	struct idr *idr_to_search;

	resource = (struct bsr_resource *)cb->args[0];

	rcu_read_lock();
	if (!cb->args[0] && !cb->args[1]) {
		resource_filter = find_cfg_context_attr(cb->nlh, T_ctx_resource_name);
		if (resource_filter) {
			retcode = ERR_RES_NOT_KNOWN;
#ifdef _WIN // DW-900 to avoid the recursive lock
			rcu_read_unlock();
#endif
			resource = bsr_find_resource(nla_data(resource_filter));
#ifdef _WIN // DW-900 to avoid the recursive lock
			rcu_read_lock_w32_inner();
#endif
			if (!resource)
				goto put_result;

			kref_debug_get(&resource->kref_debug, 9);
		}
		cb->args[0] = (LONG_PTR)resource;
	}
#ifdef _WIN64
	BUG_ON_INT32_OVER(cb->args[1]);
#endif
	minor = (int)cb->args[1];
	idr_to_search = resource ? &resource->devices : &bsr_devices;
	device = idr_find(idr_to_search, minor);
	if (!device) {
next_device:
		minor++;
		cb->args[2] = 0;
		device = idr_get_next(idr_to_search, &minor);
		if (!device) {
			err = 0;
			goto out;
		}
	}
	if (cb->args[2]) {
		for_each_peer_device_rcu(peer_device, device)
			if (peer_device == (struct bsr_peer_device *)cb->args[2])
				goto found_peer_device;
		/* peer device was probably deleted */
		goto next_device;
	}
	/* Make peer_device point to the list head (not the first entry). */
	peer_device = list_entry(&device->peer_devices, struct bsr_peer_device, peer_devices);

found_peer_device:
#ifdef _WIN
	peer_device = list_entry_rcu(peer_device->peer_devices.next, struct bsr_peer_device, peer_devices);
	if (&peer_device->peer_devices != &(device->peer_devices)) {
		retcode = ERR_NO;
		goto put_result;  /* only one iteration */
	}
#else // _LIN
	list_for_each_entry_continue_rcu_ex(struct bsr_peer_device, peer_device, &device->peer_devices, peer_devices) {
		retcode = ERR_NO;
		goto put_result;  /* only one iteration */
	}
#endif
	goto next_device;

put_result:
	dh = genlmsg_put(skb, NETLINK_CB_PORTID(cb->skb),
		cb->nlh->nlmsg_seq, &bsr_genl_family,
		NLM_F_MULTI, BSR_ADM_GET_PEER_DEVICES);
	
	err = -ENOMEM;
	if (!dh)
		goto out;
	dh->ret_code = retcode;
	dh->minor = UINT32_MAX;
	if (retcode == ERR_NO) {
		struct peer_device_info peer_device_info;
		struct peer_device_statistics peer_device_statistics;
		struct peer_device_conf *peer_device_conf;

		dh->minor = minor;
#ifdef _WIN // DW-900 to avoid the recursive lock
		rcu_read_unlock();
#endif
		err = nla_put_bsr_cfg_context(skb, device->resource, peer_device->connection, device, NULL);
#ifdef _WIN // DW-900 to avoid the recursive lock
		rcu_read_lock_w32_inner();
#endif
		if (err)
			goto out;
		peer_device_to_info(&peer_device_info, peer_device);
		err = peer_device_info_to_skb(skb, &peer_device_info, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		peer_device_to_statistics(&peer_device_statistics, peer_device);
		err = peer_device_statistics_to_skb(skb, &peer_device_statistics, !capable(CAP_SYS_ADMIN));
		if (err)
			goto out;
		peer_device_conf = rcu_dereference(peer_device->conf);
		if (peer_device_conf) {
			err = peer_device_conf_to_skb(skb, peer_device_conf, !capable(CAP_SYS_ADMIN));
			if (err)
				goto out;
		}

		cb->args[1] = minor;
		cb->args[2] = (LONG_PTR)peer_device;
	}
	genlmsg_end(skb, dh);
	err = 0;

out:
	rcu_read_unlock();
	if (err)
		return err;
	return skb->len;
}

int bsr_adm_get_timeout_type(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_peer_device *peer_device;
	enum bsr_ret_code retcode;
	struct timeout_parms tp;
	int err;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;
	peer_device = adm_ctx.peer_device;

	tp.timeout_type =
		peer_device->disk_state[NOW] == D_OUTDATED ? UT_PEER_OUTDATED :
		test_bit(USE_DEGR_WFC_T, &peer_device->flags) ? UT_DEGRADED :
		UT_DEFAULT;

	err = timeout_parms_to_priv_skb(adm_ctx.reply_skb, &tp);
	if (err) {
		nlmsg_free(adm_ctx.reply_skb);
		return err;
	}

	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

int bsr_adm_start_ov(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device;
	enum bsr_ret_code retcode;
	struct start_ov_parms parms;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;
	device = peer_device->device;


	// BSR-1412
	if (device->resource->node_opts.target_only) {
		retcode = ERR_LOCAL_TARGET_ONLY;
		goto out;
	}

	if (!bsr_inspect_resync_side(peer_device, L_VERIFY_S, NOW, false)) {
		retcode = ERR_NODE_UNSTABLE;
		goto out;
	}


	/* resume from last known position, if possible */
	parms.ov_start_sector = peer_device->ov_start_sector;
	parms.ov_stop_sector = ULLONG_MAX;
	if (info->attrs[BSR_NLA_START_OV_PARMS]) {
		int err = start_ov_parms_from_attrs(&parms, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out;
		} 
	}
	mutex_lock(&adm_ctx.resource->adm_mutex);

	/* w_make_ov_request expects position to be aligned */
	peer_device->ov_start_sector = parms.ov_start_sector & ~(BM_SECT_PER_BIT-1);
	peer_device->ov_stop_sector = parms.ov_stop_sector;

	/* If there is still bitmap IO pending, e.g. previous resync or verify
	 * just being finished, wait for it before requesting a new resync. */
	bsr_suspend_io(device, READ_AND_WRITE);
	wait_event(device->misc_wait, !atomic_read(&device->pending_bitmap_work.n));
	retcode = stable_change_repl_state(__FUNCTION__, peer_device,
		L_VERIFY_S, CS_VERBOSE | CS_SERIALIZE);
	bsr_resume_io(device);

	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

// BSR-52
int bsr_adm_stop_ov(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_PEER_DEVICE);
	if (!adm_ctx.reply_skb)
		return retcode;

	peer_device = adm_ctx.peer_device;
	device = peer_device->device;

	if (!is_verify_state(peer_device, NOW)) {
		retcode = ERR_VERIFY_NOT_RUNNING;
		goto out;
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	// BSR-835 acquire volume control mutex, verify-stop does not run while getting bitmap
	mutex_lock(&adm_ctx.resource->vol_ctl_mutex);

	retcode = stable_change_repl_state(__FUNCTION__, peer_device,
		L_ESTABLISHED, CS_VERBOSE | CS_SERIALIZE);

	mutex_unlock(&adm_ctx.resource->vol_ctl_mutex);
	mutex_unlock(&adm_ctx.resource->adm_mutex);
out:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static bool should_skip_initial_sync(struct bsr_peer_device *peer_device)
{
	return peer_device->repl_state[NOW] == L_ESTABLISHED &&
	       peer_device->connection->agreed_pro_version >= 90 &&
	       bsr_current_uuid(peer_device->device) == UUID_JUST_CREATED;
}

int bsr_adm_new_c_uuid(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device;
	enum bsr_ret_code retcode;
	int err;
	struct new_c_uuid_parms args;
	u64 nodes = 0, diskfull = 0;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	device = adm_ctx.device;
	memset(&args, 0, sizeof(args));
	if (info->attrs[BSR_NLA_NEW_C_UUID_PARMS]) {
		err = new_c_uuid_parms_from_attrs(&args, info);
		if (err) {
			retcode = ERR_MANDATORY_TAG;
			bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
			goto out_nolock;
		}
	}

	mutex_lock(&adm_ctx.resource->adm_mutex);
	down(&device->resource->state_sem);

	if (!get_ldev(device)) {
		retcode = ERR_NO_DISK;
		goto out;
	}

	/* this is "skip initial sync", assume to be clean */
	for_each_peer_device(peer_device, device) {
		if (args.clear_bm && should_skip_initial_sync(peer_device)) {
			if (peer_device->disk_state[NOW] >= D_INCONSISTENT) {
				bsr_info(54, BSR_LC_GENL, peer_device, "Skip initial resync due to peer node disk state(%s).", bsr_disk_str(peer_device->disk_state[NOW]));
				diskfull |= NODE_MASK(peer_device->node_id);
			}
			nodes |= NODE_MASK(peer_device->node_id);
		} else if (peer_device->repl_state[NOW] != L_OFF) {
			retcode = ERR_CONNECTED;
			goto out_dec;
		}

	}

	bsr_uuid_new_current_by_user(device, (!args.no_rotate_bm)); /* New current, previous to UI_BITMAP */

	if (args.clear_bm) {
		unsigned long irq_flags;
		bool updated_uuid = false;

		err = bsr_bitmap_io(device, &bsr_bmio_clear_all_n_write,
			"clear_n_write from new_c_uuid", BM_LOCK_ALL, NULL);
		if (err) {
			bsr_err(55, BSR_LC_GENL, device, "Failed to create new uuid due to writing bitmap failed with err %d",err);
			retcode = ERR_IO_MD_DISK;
		}
		for_each_peer_device(peer_device, device) {
			if (NODE_MASK(peer_device->node_id) & nodes) {
				if (NODE_MASK(peer_device->node_id) & diskfull)
					bsr_send_uuids(peer_device, UUID_FLAG_SKIP_INITIAL_SYNC, 0, NOW);
				_bsr_uuid_set_bitmap(peer_device, 0);
				bsr_print_uuids(peer_device, "cleared bitmap UUID", __FUNCTION__);
				updated_uuid = true;
			}
		}

		if (updated_uuid) {
			// BSR-676 notify uuid
			bsr_queue_notify_update_gi(device, NULL, BSR_GI_NOTI_UUID);
		}

		begin_state_change(device->resource, &irq_flags, CS_VERBOSE);
		__change_disk_state(device, D_UP_TO_DATE, __FUNCTION__);
		for_each_peer_device(peer_device, device) {
			if (NODE_MASK(peer_device->node_id) & diskfull)
				__change_peer_disk_state(peer_device, D_UP_TO_DATE, __FUNCTION__);
		}
		end_state_change(device->resource, &irq_flags, __FUNCTION__);
	}

	bsr_md_sync_if_dirty(device);
out_dec:
	put_ldev(__FUNCTION__, device);
out:
	up(&device->resource->state_sem);
out_nolock:
	mutex_unlock(&adm_ctx.resource->adm_mutex);
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum bsr_ret_code
bsr_check_resource_name(struct bsr_config_context *adm_ctx)
{
	const char *name = adm_ctx->resource_name;
	if (!name || !name[0]) {
		bsr_msg_put_info(adm_ctx->reply_skb, "resource name missing");
		return ERR_MANDATORY_TAG;
	}
	/* As we want to use these in sysfs/configfs/debugfs,
	 * we must not allow slashes. */
	if (strchr(name, '/')) {
		bsr_msg_put_info(adm_ctx->reply_skb, "invalid resource name");
		return ERR_INVALID_REQUEST;
	}
	return ERR_NO;
}

static void resource_to_info(struct resource_info *info,
			     struct bsr_resource *resource)
{
	info->res_role = resource->role[NOW];
	info->res_susp = resource->susp[NOW];
	info->res_susp_nod = resource->susp_nod[NOW];
	info->res_susp_fen = is_suspended_fen(resource, NOW, false);
	info->res_susp_quorum = is_suspended_quorum(resource, NOW, false);
}

int bsr_adm_new_resource(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_resource *resource;
	enum bsr_ret_code retcode;
	struct res_opts res_opts;
	int err;

#ifdef _PARALLEL_OPS
	mutex_lock(&resources_mutex);
#endif
	retcode = bsr_adm_prepare(&adm_ctx, skb, info, 0);
	if (!adm_ctx.reply_skb) {
#ifdef _PARALLEL_OPS
		mutex_unlock(&resources_mutex);
#endif		
		return retcode;
	}

	set_res_opts_defaults(&res_opts);
	err = res_opts_from_attrs(&res_opts, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out;
	}

	retcode = bsr_check_resource_name(&adm_ctx);
	if (retcode != ERR_NO)
		goto out;

	if (adm_ctx.resource)
		goto out;
#ifdef _WIN 
	if (res_opts.node_id >= BSR_NODE_ID_MAX) {
#else // _LIN
	// TODO node id -1??
	if (res_opts.node_id < 0 || res_opts.node_id >= BSR_NODE_ID_MAX) {
#endif
		bsr_err(56, BSR_LC_GENL, NO_OBJECT, "Failed to create new resource due to invalid node id (%d)", res_opts.node_id);
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}
#ifdef _LIN
	if (!try_module_get(THIS_MODULE)) {
		bsr_err(57, BSR_LC_GENL, NO_OBJECT, "Failed to create new resource due to could not get a module reference");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}
#endif

#ifndef _PARALLEL_OPS
	mutex_lock(&resources_mutex);
#endif
	resource = bsr_create_resource(adm_ctx.resource_name, &res_opts);
#ifndef _PARALLEL_OPS
	mutex_unlock(&resources_mutex);
#endif
	if (resource) {
		struct resource_info resource_info;

		mutex_lock(&notification_mutex);
		resource_to_info(&resource_info, resource);
		notify_resource_state(NULL, 0, resource, &resource_info, NOTIFY_CREATE);
		mutex_unlock(&notification_mutex);

#ifdef _WIN_MULTIVOL_THREAD
		NTSTATUS status;
		status = mvolInitializeThread(&resource->WorkThreadInfo, mvolWorkThread);
		if (!NT_SUCCESS(status)) {
			bsr_warn(86, BSR_LC_GENL, NO_OBJECT, "Failed to initialize WorkThread. status(0x%x)", status);
		}
#endif
		
	} else {
#ifdef _LIN
		module_put(THIS_MODULE);
#endif
		retcode = ERR_NOMEM;
	}

out:
#ifdef _PARALLEL_OPS
	mutex_unlock(&resources_mutex);
#endif
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

void device_to_info(struct device_info *info,
			   struct bsr_device *device)
{
	info->dev_disk_state = device->disk_state[NOW];
	info->is_intentional_diskless = device->device_conf.intentional_diskless;
	// DW-1755 Pass the value for use when outputting the disk error count at the status command.
	info->io_error_count = atomic_read(&device->io_error_count);  
}

int bsr_adm_new_minor(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
#ifdef COMPAT_HAVE_GENL_INFO_USERHDR
	struct bsr_genlmsghdr *dh = (struct bsr_genlmsghdr *)genl_info_userhdr(info);
#else
	struct bsr_genlmsghdr *dh = info->userhdr;
#endif	
	struct device_conf device_conf;
	struct bsr_resource *resource;
	struct bsr_device *device;
	enum bsr_ret_code retcode;
	int err;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	set_device_conf_defaults(&device_conf);
	err = device_conf_from_attrs(&device_conf, info);
	if (err && err != -ENOMSG) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out;
	}

	if (dh->minor > MINORMASK) {
		bsr_msg_put_info(adm_ctx.reply_skb, "requested minor out of range");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}
	if (adm_ctx.volume > BSR_VOLUME_MAX) {
		bsr_msg_put_info(adm_ctx.reply_skb, "requested volume id out of range");
		retcode = ERR_INVALID_REQUEST;
		goto out;
	}

	if (adm_ctx.device)
		goto out;

	resource = adm_ctx.resource;
	mutex_lock(&resource->conf_update);
	for(;;) {
		retcode = bsr_create_device(&adm_ctx, dh->minor, &device_conf, &device);
		if (retcode != ERR_NOMEM ||
		    schedule_timeout_interruptible(HZ / 10))
			break;
		/* Keep retrying until the memory allocations eventually succeed. */
	}
	if (retcode == ERR_NO) {
		struct bsr_peer_device *peer_device;
		struct device_info info;
		unsigned int peer_devices = 0;
		enum bsr_notification_type flags;

		for_each_peer_device(peer_device, device)
			peer_devices++;

		device_to_info(&info, device);
		mutex_lock(&notification_mutex);
		flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
		notify_device_state(NULL, 0, device, &info, NOTIFY_CREATE | flags);
		for_each_peer_device(peer_device, device) {
			struct peer_device_info peer_device_info;

			peer_device_to_info(&peer_device_info, peer_device);
			flags = (peer_devices--) ? NOTIFY_CONTINUES : 0;
			notify_peer_device_state(NULL, 0, peer_device, &peer_device_info,
						 NOTIFY_CREATE | flags);
		}
		mutex_unlock(&notification_mutex);
	}
	mutex_unlock(&resource->conf_update);
out:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static enum bsr_ret_code adm_del_minor(struct bsr_device *device)
{
	struct bsr_resource *resource = device->resource;
	struct bsr_peer_device *peer_device;
	enum bsr_ret_code ret;
	u64 im;

	spin_lock_irq(&resource->req_lock);
	if (device->disk_state[NOW] == D_DISKLESS &&
	    device->open_cnt == 0) {
		set_bit(UNREGISTERED, &device->flags);
		ret = ERR_NO;
	} else {
		ret = ERR_MINOR_CONFIGURED;
	}
	spin_unlock_irq(&resource->req_lock);

	if (ret != ERR_NO)
		return ret;

	for_each_peer_device_ref(peer_device, im, device)
		stable_change_repl_state(__FUNCTION__, peer_device, L_OFF,
					 CS_VERBOSE | CS_WAIT_COMPLETE);

	// BSR-439
	/* If the worker still has to find it to call bsr_ldev_destroy(),
	* we must not unregister the device yet. */
	wait_event(device->misc_wait, !test_bit(GOING_DISKLESS, &device->flags));

	/*
	 * Flush the resource work queue to make sure that no more events like
	 * state change notifications for this device are queued: we want the
	 * "destroy" event to come last.
	 */
	bsr_flush_workqueue(resource, &resource->work);
	
	bsr_unregister_device(device);

	mutex_lock(&notification_mutex);
	for_each_peer_device_ref(peer_device, im, device)
		notify_peer_device_state(NULL, 0, peer_device, NULL,
					 NOTIFY_DESTROY | NOTIFY_CONTINUES);
	notify_device_state(NULL, 0, device, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);
#ifdef _LIN
	synchronize_rcu();
#endif
	bsr_put_device(device);

	return ret;
}

int bsr_adm_del_minor(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_MINOR);
	if (!adm_ctx.reply_skb)
		return retcode;

	mutex_lock(&adm_ctx.resource->adm_mutex);
	retcode = adm_del_minor(adm_ctx.device);
	mutex_unlock(&adm_ctx.resource->adm_mutex);

	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int adm_del_resource(struct bsr_resource *resource)
{
	int err;

	/*
	 * Flush the resource work queue to make sure that no more events like
	 * state change notifications are queued: we want the "destroy" event
	 * to come last.
	 */
	bsr_flush_workqueue(resource, &resource->work);
	
	mutex_lock(&resources_mutex);
	err = ERR_NET_CONFIGURED;
	if (!list_empty(&resource->connections))
		goto out;
	err = ERR_RES_IN_USE;
	if (!idr_is_empty(&resource->devices))
		goto out;
	err = ERR_NO;

	mutex_lock(&notification_mutex);
	notify_resource_state(NULL, 0, resource, NULL, NOTIFY_DESTROY);
	mutex_unlock(&notification_mutex);

#ifdef _WIN
	synchronize_rcu_w32_wlock();
#endif
	list_del_rcu(&resource->resources);
	bsr_debugfs_resource_cleanup(resource);
	synchronize_rcu();
	bsr_free_resource(resource);
out:
	mutex_unlock(&resources_mutex);
	return err;
}

int bsr_adm_down(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_resource *resource;
	struct bsr_connection *connection;
	struct bsr_device *device;
	int retcode; /* enum bsr_ret_code rsp. enum bsr_state_rv */
	enum bsr_ret_code ret;
	int i;
	u64 im;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info,
			BSR_ADM_NEED_RESOURCE | BSR_ADM_IGNORE_VERSION);
	if (!adm_ctx.reply_skb)
		return retcode;

	resource = adm_ctx.resource;

	mutex_lock(&resource->adm_mutex);

	// BSR-1064
	if (!wait_until_vol_ctl_mutex_is_used(adm_ctx.resource)) {
		mutex_unlock(&adm_ctx.resource->adm_mutex);
		retcode = ERR_VOL_LOCK_ACQUISITION_TIMEOUT;
		bsr_msg_put_info(adm_ctx.reply_skb, "Failed to change role");
		goto out;
	}

	// DW-1317 acquire volume control mutex, not to conflict to (dis)mount volume.
	mutex_lock(&adm_ctx.resource->vol_ctl_mutex);

	// BSR-855 prevents abnormal termination when the down cmd is duplicated.
	// if the worker is not running, it is already down.
	if (get_t_state(&resource->worker) != RUNNING) {		
		bsr_msg_put_info(adm_ctx.reply_skb, "resource already down");
		retcode = SS_NOTHING_TO_DO;
		goto fail;
	}
	
	/* demote */
#ifdef _WIN_MVFL
    // continue to dismount volume after bsradm down is done.

#ifdef _WIN_MULTI_VOLUME    
	int vnr;
	retcode = SS_SUCCESS;

	// DW-1461 set volume protection when going down. 
	idr_for_each_entry_ex(struct bsr_device *, &adm_ctx.resource->devices, device, vnr) {
		PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
		if (pvext)
			SetBsrlockIoBlock(pvext, TRUE);
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		if (device->disk_state[NOW] == D_DISKLESS)
			continue;

		if (!NT_SUCCESS(FsctlLockVolume(device->minor)))
			continue;
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		if (device->disk_state[NOW] == D_DISKLESS)
			continue;

		resource->bPreDismountLock = TRUE;
		NTSTATUS status = FsctlFlushDismountVolume(device->minor, true);			
		if (!NT_SUCCESS(status)) {
			retcode = SS_UNKNOWN_ERROR;
			resource->bPreDismountLock = FALSE;
			break;
		}		
	}
				
	if (retcode == SS_SUCCESS) {
		resource->bPreSecondaryLock = TRUE;
		retcode = bsr_set_role(resource, R_SECONDARY, false, adm_ctx.reply_skb);
		if (retcode < SS_SUCCESS)
			bsr_msg_put_info(adm_ctx.reply_skb, "failed to demote");

		resource->bPreSecondaryLock = FALSE;
		resource->bPreDismountLock = FALSE;
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		if (device->disk_state[NOW] == D_DISKLESS)
			continue;
		FsctlUnlockVolume(device->minor);
	}

	if(retcode < SS_SUCCESS) {
		// DW-2107 remove from block target if setting from primary to secondary fails
		if (resource->role[NOW] == R_PRIMARY) {
			idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr)
			{
				PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor, FALSE);
				if (pvext)
				{
					SetBsrlockIoBlock(pvext, FALSE);
				}
			}
		}
		goto fail;
	}
#else
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, i) {
		PVOLUME_EXTENSION pvext = get_targetdev_by_minor(device->minor);
		if (pvext)
			SetBsrlockIoBlock(pvext, TRUE);

		if (D_DISKLESS == device->disk_state[NOW]) {
			retcode = bsr_set_role(resource, R_SECONDARY, false, adm_ctx.reply_skb);
		} else if (NT_SUCCESS(FsctlLockVolume(device->minor))) {
			
			resource->bPreDismountLock = TRUE;
			NTSTATUS status = FsctlFlushDismountVolume(device->minor, true);
			resource->bPreSecondaryLock = TRUE;
			FsctlUnlockVolume(device->minor);

			if (!NT_SUCCESS(status)) {
				retcode = ERR_RES_NOT_KNOWN;
				resource->bPreDismountLock = FALSE;
				goto fail;
			}

			retcode = bsr_set_role(resource, R_SECONDARY, false, adm_ctx.reply_skb);
			resource->bPreSecondaryLock = FALSE;
			resource->bPreDismountLock = FALSE;
			if (retcode < SS_SUCCESS) {
				bsr_msg_put_info(adm_ctx.reply_skb, "failed to demote");
				FsctlUnlockVolume(device->minor);
				goto fail;
			}
		} else {
			retcode = ERR_RES_IN_USE;
			goto fail;
		}
	}
#endif
#else
	retcode = bsr_set_role(resource, R_SECONDARY, false, adm_ctx.reply_skb);
	if (retcode < SS_SUCCESS) {
		bsr_msg_put_info(adm_ctx.reply_skb, "failed to demote");
		goto fail;
	}
#endif

	for_each_connection_ref(connection, im, resource) {
		// DW-2035
		retcode = conn_try_disconnect(connection, false, true, adm_ctx.reply_skb);
		if (retcode >= SS_SUCCESS) {
			// BSR-920 moved inside del_connection()
			// mutex_lock(&resource->conf_update);
			// BSR-418 vol_ctl_mutex deadlock in function SetOOSAllocatedCluster()
			mutex_unlock(&adm_ctx.resource->vol_ctl_mutex);
			del_connection(connection);
			// BSR-418 
			mutex_lock(&adm_ctx.resource->vol_ctl_mutex);

			// mutex_unlock(&resource->conf_update);
		} else {
			bsr_info(58, BSR_LC_GENL, connection, "Connection was not terminated during resource down. ret(%d)", retcode);
			kref_debug_put(&connection->kref_debug, 13);
			kref_put(&connection->kref, bsr_destroy_connection);
			goto fail;
		}
	}

	
	/* detach and delete minor */
	rcu_read_lock();
	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, i) {
		kref_get(&device->kref);
		rcu_read_unlock();
		retcode = adm_detach(device, 0, adm_ctx.reply_skb);
		// BSR-925
		if (retcode < SS_SUCCESS || retcode > ERR_NO) {
			bsr_msg_put_info(adm_ctx.reply_skb, "failed to detach");
			kref_put(&device->kref, bsr_destroy_device);
			goto fail;
		}
		mutex_lock(&resource->conf_update);
		ret = adm_del_minor(device);
		mutex_unlock(&resource->conf_update);
		kref_put(&device->kref, bsr_destroy_device);
		if (ret != ERR_NO) {
			/* "can not happen" */
			bsr_msg_put_info(adm_ctx.reply_skb, "failed to delete volume");
			goto fail;
		}
		rcu_read_lock();
	}
	rcu_read_unlock();

	mutex_lock(&resource->conf_update);
	retcode = adm_del_resource(resource);
	/* holding a reference to resource in adm_crx until bsr_adm_finish() */
	mutex_unlock(&resource->conf_update);
fail:
	// DW-1317
	mutex_unlock(&adm_ctx.resource->vol_ctl_mutex);
	mutex_unlock(&resource->adm_mutex);
out:
	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}


int bsr_adm_del_resource(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	enum bsr_ret_code retcode;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	retcode = adm_del_resource(adm_ctx.resource);

	bsr_adm_finish(&adm_ctx, info, retcode);
	return 0;
}

static int nla_put_notification_header(struct sk_buff *msg,
				       enum bsr_notification_type type)
{
	struct bsr_notification_header nh = {
		.nh_type = type,
	};

	return bsr_notification_header_to_skb(msg, &nh, true);
}

void notify_resource_state(struct sk_buff *skb,
			   unsigned int seq,
			   struct bsr_resource *resource,
			   struct resource_info *resource_info,
			   enum bsr_notification_type type)
{
	struct resource_statistics resource_statistics;
	struct bsr_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&bsr_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_RESOURCE_STATE);
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;
	if (nla_put_bsr_cfg_context(skb, resource, NULL, NULL, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     resource_info_to_skb(skb, resource_info, true)))
		goto nla_put_failure;
	resource_statistics.res_stat_write_ordering = resource->write_ordering;
	// DW-1925
	resource_statistics.res_stat_req_write_cnt = atomic_read(&resource->req_write_cnt);
	err = resource_statistics_to_skb(skb, &resource_statistics, !capable(CAP_SYS_ADMIN));
	if (err)
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	if (multicast) {
		err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	bsr_err(59, BSR_LC_GENL, resource, "Failed to notification resource state. error %d, event seq:%u",
			err, seq);
}

void notify_device_state(struct sk_buff *skb,
			 unsigned int seq,
			 struct bsr_device *device,
			 struct device_info *device_info,
			 enum bsr_notification_type type)
{
	struct device_statistics device_statistics;
	struct bsr_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&bsr_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_DEVICE_STATE);
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = device->minor;
	dh->ret_code = ERR_NO;
	if (nla_put_bsr_cfg_context(skb, device->resource, NULL, device, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     device_info_to_skb(skb, device_info, true)))
		goto nla_put_failure;
	device_to_statistics(&device_statistics, device);
	device_statistics_to_skb(skb, &device_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	bsr_err(60, BSR_LC_GENL, device, "Failed to notification device state. error %d, event seq:%u",
		 err, seq);
}

/* open coded path_parms_to_skb() iterating of the list */
void notify_connection_state(struct sk_buff *skb,
			     unsigned int seq,
			     struct bsr_connection *connection,
			     struct connection_info *connection_info,
			     enum bsr_notification_type type)
{
	struct connection_statistics connection_statistics;
	struct bsr_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&bsr_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_CONNECTION_STATE);
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;
	if (nla_put_bsr_cfg_context(skb, connection->resource, connection, NULL, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     connection_info_to_skb(skb, connection_info, true)))
		goto nla_put_failure;
	connection_paths_to_skb(skb, connection);
	connection_statistics.conn_congested = test_bit(NET_CONGESTED, &connection->transport.flags);
	connection_statistics_to_skb(skb, &connection_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	bsr_err(61, BSR_LC_GENL, connection, "Failed to notification connection state. error %d, event seq:%u",
		 err, seq);
}

void notify_peer_device_state(struct sk_buff *skb,
			      unsigned int seq,
			      struct bsr_peer_device *peer_device,
			      struct peer_device_info *peer_device_info,
			      enum bsr_notification_type type)
{
	struct peer_device_statistics peer_device_statistics;
	struct bsr_resource *resource = peer_device->device->resource;
	struct bsr_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&bsr_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_PEER_DEVICE_STATE);
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;
	if (nla_put_bsr_cfg_context(skb, resource, peer_device->connection, peer_device->device, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    ((type & ~NOTIFY_FLAGS) != NOTIFY_DESTROY &&
	     peer_device_info_to_skb(skb, peer_device_info, true)))
		goto nla_put_failure;
	peer_device_to_statistics(&peer_device_statistics, peer_device);
	peer_device_statistics_to_skb(skb, &peer_device_statistics, !capable(CAP_SYS_ADMIN));
	genlmsg_end(skb, dh);
	if (multicast) {
		err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

nla_put_failure:
	nlmsg_free(skb);
failed:
	bsr_err(62, BSR_LC_GENL, peer_device, "Failed to notification peer device state. error %d, event seq:%u",
		 err, seq);
}

// BSR-1125 notify sync progress
void bsr_broadcast_peer_device_state(struct bsr_peer_device *peer_device)
{
	struct peer_device_info peer_device_info;
	mutex_lock(&notification_mutex);
	peer_device_to_info(&peer_device_info, peer_device);
	notify_peer_device_state(NULL, 0, peer_device, &peer_device_info, NOTIFY_SYNC);
	mutex_unlock(&notification_mutex);
}
		  
void notify_io_error(struct bsr_device *device, struct bsr_io_error *io_error)
{
	struct bsr_io_error_info io_error_info;
	unsigned int seq;
	struct sk_buff *skb = NULL;
	struct bsr_genlmsghdr *dh;
	int err;

	io_error_info.error_code = io_error->error_code;
	io_error_info.sector = io_error->sector;
	io_error_info.size = io_error->size;
	io_error_info.disk_type = io_error->disk_type;
	io_error_info.io_type = io_error->io_type;
	io_error_info.is_cleared = io_error->is_cleared;
	
	seq = atomic_inc_return(&bsr_genl_seq);
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_IO_ERROR);
	
	if (!dh)
		goto fail;

	dh->minor = device->minor;
	dh->ret_code = ERR_NO;
	mutex_lock(&notification_mutex);
	if (nla_put_bsr_cfg_context(skb, device->resource, NULL, device, NULL) ||
		nla_put_notification_header(skb, NOTIFY_ERROR) ||
		bsr_io_error_info_to_skb(skb, &io_error_info, true))
		goto unlock_fail;

	genlmsg_end(skb, dh);
	err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto unlock_fail;
	mutex_unlock(&notification_mutex);
	return;

unlock_fail:
	mutex_unlock(&notification_mutex);
fail:
	// DW-1556 fix DV crash, NULL dereference
	if(skb)
		nlmsg_free(skb);
}

// BSR-676 notify when UUID is changed
void notify_gi_uuid_state(struct sk_buff *skb, unsigned int seq, struct bsr_peer_device *peer_device, enum bsr_notification_type type)
{
	struct bsr_updated_gi_uuid_info gi;
	struct bsr_genlmsghdr *dh;
	struct bsr_device *device;
	struct bsr_connection *connection = NULL;
	int err;
	bool multicast = false;

	if (!peer_device)
		return;

	device = peer_device->device;
	connection = peer_device->connection;

	if (!connection || !device || !device->ldev)
		return;

	memset(&gi, 0, sizeof(struct bsr_updated_gi_uuid_info));

	gi.uuid_current = (unsigned long long)bsr_current_uuid(device);
	gi.uuid_bitmap = (unsigned long long)bsr_bitmap_uuid(peer_device);
	gi.uuid_history1 = (unsigned long long)bsr_history_uuid(device, 0);
	gi.uuid_history2 = (unsigned long long)bsr_history_uuid(device, 1);
	
	if (!skb) {
		seq = atomic_inc_return(&bsr_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto fail;
		multicast = true;
	}
		
	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_UPDATED_GI_UUID);
		
	if (!dh)
		goto fail;
		
	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;

	if (nla_put_bsr_cfg_context(skb, device->resource, connection, device, NULL) ||
		nla_put_notification_header(skb, type) ||
		bsr_updated_gi_uuid_info_to_skb(skb, &gi, true))
		goto fail;
		
	genlmsg_end(skb, dh);
	if (multicast) {
		err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto fail;
	}

	return;

fail:
	if (skb)
		nlmsg_free(skb);
}

// BSR-676 notify when device mdf flag is changed.
void notify_gi_device_mdf_flag_state(struct sk_buff *skb, unsigned int seq, struct bsr_device *device, enum bsr_notification_type type)
{
	struct bsr_updated_gi_device_mdf_flag_info gi;
	struct bsr_genlmsghdr *dh;
	int err;
	bool multicast = false;

	if (!device || !device->ldev)
		return;

	gi.dev_mdf_consistent = device->ldev->md.flags & MDF_CONSISTENT ? 1 : 0;
	gi.dev_mdf_was_uptodate = device->ldev->md.flags & MDF_WAS_UP_TO_DATE ? 1 : 0;
	gi.dev_mdf_primary_ind = device->ldev->md.flags & MDF_PRIMARY_IND ? 1 : 0;
	gi.dev_mdf_crashed_primary = device->ldev->md.flags & MDF_CRASHED_PRIMARY ? 1 : 0;
	gi.dev_mdf_al_clean = device->ldev->md.flags & MDF_AL_CLEAN ? 1 : 0;
	gi.dev_mdf_al_disabled = device->ldev->md.flags & MDF_AL_DISABLED ? 1 : 0;
	gi.dev_mdf_last_primary = device->ldev->md.flags & MDF_LAST_PRIMARY ? 1 : 0;

	if (!skb) {
		seq = atomic_inc_return(&bsr_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto fail;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_UPDATED_GI_DEVICE_MDF_FLAG);

	if (!dh)
		goto fail;

	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;

	if (nla_put_bsr_cfg_context(skb, device->resource, NULL, device, NULL) ||
		nla_put_notification_header(skb, type) ||
		bsr_updated_gi_device_mdf_flag_info_to_skb(skb, &gi, true))
		goto fail;

	genlmsg_end(skb, dh);

	if (multicast) {
		err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto fail;
	}

	return;

fail:
	if (skb)
		nlmsg_free(skb);
}


// BSR-676 notify when peer_device is changed.
void notify_gi_peer_device_mdf_flag_state(struct sk_buff *skb, unsigned int seq, struct bsr_peer_device *peer_device, enum bsr_notification_type type)
{
	struct bsr_updated_gi_peer_device_mdf_flag_info gi;
	struct bsr_connection *connection = NULL;
	struct bsr_genlmsghdr *dh;
	struct bsr_device *device;
	int err;
	u32 peer_flags;
	bool multicast = false;

	if (!peer_device)
		return;

	device = peer_device->device;

	if (!device || !device->ldev) 
		return;

	peer_flags = device->ldev->md.peers[peer_device->node_id].flags;

	if (peer_device->connection)
		connection = peer_device->connection;
	
	gi.peer_dev_mdf_cconnected = peer_flags & MDF_PEER_CONNECTED ? 1 : 0;
	gi.peer_dev_mdf_outdate = peer_flags & MDF_PEER_OUTDATED ? 1 : 0;
	gi.peer_dev_mdf_fencing = peer_flags & MDF_PEER_FENCING ? 1 : 0;
	gi.peer_dev_mdf_full_sync = peer_flags & MDF_PEER_FULL_SYNC ? 1 : 0;

	if (!skb) {
		seq = atomic_inc_return(&bsr_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto fail;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_UPDATED_GI_PEER_DEVICE_MDF_FLAG);

	if (!dh)
		goto fail;

	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;

	if (nla_put_bsr_cfg_context(skb, device->resource, connection, device, NULL) ||
		nla_put_notification_header(skb, type) ||
		bsr_updated_gi_peer_device_mdf_flag_info_to_skb(skb, &gi, true))
		goto fail;

	genlmsg_end(skb, dh);
	if (multicast) {
		err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto fail;
	}

	return;

fail:
	if (skb)
		nlmsg_free(skb);
}


void notify_path(struct bsr_connection *connection, struct bsr_path *path,
		 enum bsr_notification_type type)
{
	struct bsr_resource *resource = connection->resource;
	struct bsr_path_info path_info;
	unsigned int seq = atomic_inc_return(&bsr_genl_seq);
	struct sk_buff *skb = NULL;
	struct bsr_genlmsghdr *dh;
	int err;

	path_info.path_established = path->established;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_PATH_STATE);
	
	if (!dh)
		goto fail;

	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;
	mutex_lock(&notification_mutex);
	if (nla_put_bsr_cfg_context(skb, resource, connection, NULL, path) ||
	    nla_put_notification_header(skb, type) ||
	    bsr_path_info_to_skb(skb, &path_info, true))
		goto unlock_fail;

	genlmsg_end(skb, dh);
	err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto unlock_fail;
	mutex_unlock(&notification_mutex);
	return;

unlock_fail:
	mutex_unlock(&notification_mutex);
fail:
	// DW-1556 fix DV crash, NULL dereference
	if(skb)
		nlmsg_free(skb);
	bsr_err(63, BSR_LC_GENL, resource, "Failed to notification path. error %d, event seq:%u",
		 err, seq);
}


// BSR-859 notify by event when setting node name
void notify_node_info(struct sk_buff *skb, unsigned int seq, struct bsr_resource *resource, struct bsr_connection *connection, 
				char * node_name, __u8 cmd, enum bsr_notification_type type)
{
	struct bsr_node_info info;
	struct bsr_genlmsghdr *dh;
	bool multicast = false;
	int err;

	if (!skb) {
		seq = atomic_inc_return(&bsr_genl_seq);
		skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
		err = -ENOMEM;
		if (!skb)
			goto failed;
		multicast = true;
	}

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, cmd);
	
	if (!dh)
		goto failed;

#ifdef _WIN
	strncpy(info._nodename, node_name, sizeof(info._nodename) - 1);
	info._nodename[sizeof(info._nodename) - 1] = '\0';
#else // _LIN
	// BSR-1360
#ifdef COMPAT_HAVE_STRLCPY
	strlcpy(info._nodename, node_name, sizeof(info._nodename));
#else
	strscpy(info._nodename, node_name, sizeof(info._nodename));
#endif
#endif
	info._nodename_len = (__u32)(min(strlen(node_name), sizeof(info._nodename)));

	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;

	if (nla_put_bsr_node_cfg_context(skb, resource, connection) ||
		nla_put_notification_header(skb, type) ||
		bsr_node_info_to_skb(skb, &info, true))
		goto failed;

	genlmsg_end(skb, dh);
	if (multicast) {
		err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
		/* skb has been consumed or freed in netlink_broadcast() */
		if (err && err != -ESRCH)
			goto failed;
	}
	return;

failed:
	if (skb)
		nlmsg_free(skb);
}

void notify_helper(enum bsr_notification_type type,
		   struct bsr_device *device, struct bsr_connection *connection,
		   const char *name, int status)
{
	struct bsr_resource *resource = device ? device->resource : connection->resource;
	struct bsr_helper_info helper_info;
	unsigned int seq = atomic_inc_return(&bsr_genl_seq);
	struct sk_buff *skb = NULL;
	struct bsr_genlmsghdr *dh;
	int err;

#ifdef _WIN
	strncpy(helper_info.helper_name, name, sizeof(helper_info.helper_name) - 1);
	helper_info.helper_name[sizeof(helper_info.helper_name) - 1] = '\0';
#else // _LIN
#ifdef COMPAT_HAVE_STRLCPY
	strlcpy(helper_info.helper_name, name, sizeof(helper_info.helper_name));
#else
	strscpy(helper_info.helper_name, name, sizeof(helper_info.helper_name));
#endif
#endif
	helper_info.helper_name_len = (__u32)(min(strlen(name), sizeof(helper_info.helper_name)));
	helper_info.helper_status = status;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_HELPER);
	
	if (!dh)
		goto fail;
	dh->minor = device ? device->minor : -1;
	dh->ret_code = ERR_NO;
	mutex_lock(&notification_mutex);
	if (nla_put_bsr_cfg_context(skb, resource, connection, device, NULL) ||
	    nla_put_notification_header(skb, type) ||
	    bsr_helper_info_to_skb(skb, &helper_info, true))
		goto unlock_fail;
	genlmsg_end(skb, dh);
	err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto unlock_fail;
	mutex_unlock(&notification_mutex);
	return;

unlock_fail:
	mutex_unlock(&notification_mutex);
fail:
	// DW-1556 fix DV crash, NULL dereference
	if(skb)
		nlmsg_free(skb);
	bsr_err(64, BSR_LC_GENL, resource, "Failed to notification helper. error %d, event seq:%u",
		 err, seq);
}

// BSR-734 notify by event when split-brain occurs
void notify_split_brain(struct bsr_connection *connection, char * recover_type)
{
	struct bsr_split_brain_info sb_info;
	unsigned int seq;
	struct sk_buff *skb = NULL;
	struct bsr_genlmsghdr *dh;
	int err;
	
#ifdef _WIN
	strncpy(sb_info.recover, recover_type, sizeof(sb_info.recover) - 1);
	sb_info.recover[sizeof(sb_info.recover) - 1] = '\0';
#else // _LIN
#ifdef COMPAT_HAVE_STRLCPY
	strlcpy(sb_info.recover, recover_type, sizeof(sb_info.recover));
#else
	strscpy(sb_info.recover, recover_type, sizeof(sb_info.recover));
#endif
#endif
	sb_info.recover_len = (__u32)(min(strlen(recover_type), sizeof(sb_info.recover)));
	
	seq = atomic_inc_return(&bsr_genl_seq);
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_NOIO);
	err = -ENOMEM;
	if (!skb)
		goto fail;

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_SPLIT_BRAIN);
	
	if (!dh)
		goto fail;

	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;

	mutex_lock(&notification_mutex);
	if (nla_put_bsr_cfg_context(skb, connection->resource, connection, NULL, NULL) ||
		nla_put_notification_header(skb, NOTIFY_DETECT) ||
		bsr_split_brain_info_to_skb(skb, &sb_info, true))
		goto unlock_fail;

	genlmsg_end(skb, dh);
	err = bsr_genl_multicast_events(skb, GFP_NOWAIT);
	skb = NULL;
	/* skb has been consumed or freed in netlink_broadcast() */
	if (err && err != -ESRCH)
		goto unlock_fail;
	mutex_unlock(&notification_mutex);
	return;

unlock_fail:
	mutex_unlock(&notification_mutex);
fail:
	if(skb)
		nlmsg_free(skb);
}

static void notify_initial_state_done(struct sk_buff *skb, unsigned int seq)
{
	struct bsr_genlmsghdr *dh;
	int err;

	err = -EMSGSIZE;
	dh = genlmsg_put(skb, 0, seq, &bsr_genl_family, 0, BSR_INITIAL_STATE_DONE);
	
	if (!dh)
		goto nla_put_failure;
	dh->minor = UINT32_MAX;
	dh->ret_code = ERR_NO;
	if (nla_put_notification_header(skb, NOTIFY_EXISTS))
		goto nla_put_failure;
	genlmsg_end(skb, dh);
	return;

nla_put_failure:
	nlmsg_free(skb);
	bsr_err(65, BSR_LC_GENL, NO_OBJECT, "Failed to notification initial state. error %d, event seq:%u", err, seq);
}

static void free_state_changes(struct list_head *list)
{
	while (!list_empty(list)) {
		struct bsr_state_change *state_change =
			list_first_entry(list, struct bsr_state_change, list);
		list_del(&state_change->list);
		forget_state_change(state_change);
	}
}

static unsigned int notifications_for_state_change(struct bsr_state_change *state_change)
{
	return 1 +
		// BSR-859 added 1 for node name output
		1 +
		// BSR-859 added * 2 for peer node name output
		(state_change->n_connections * 2) +
		// BSR-676 added * 2 for GI information output
		(state_change->n_devices * 2) +
		// BSR-676 added * 3 for GI information output
		((state_change->n_devices * state_change->n_connections) * 3);
}

static int get_initial_state(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct bsr_state_change *state_change = (struct bsr_state_change *)cb->args[0];
	ULONG_PTR seq = cb->args[2];
	ULONG_PTR n;
	enum bsr_notification_type flags = 0;

	/* There is no need for taking notification_mutex here: it doesn't
	   matter if the initial state events mix with later state chage
	   events; we can always tell the events apart by the NOTIFY_EXISTS
	   flag. */
#ifdef _WIN64
	BUG_ON_UINT32_OVER(seq);
#endif

	cb->args[5]--;
	if (cb->args[5] == 1) {
		notify_initial_state_done(skb, (unsigned int)seq);
		goto out;
	}
	n = cb->args[4]++;
	if (cb->args[4] < cb->args[3])
		flags |= NOTIFY_CONTINUES;
	if (n < 1) {
		bsr_info(91, BSR_LC_GENL, NO_OBJECT, "notify_resource_state_change args[3](%d), args[4](%d), args[5](%d), n(%d), len(%d)", cb->args[3], cb->args[4], cb->args[5], n, skb->len);
		notify_resource_state_change(skb, (unsigned int)seq, state_change,
					     NOTIFY_EXISTS | flags);
		goto next;
	}

	n--;

	// BSR-859 for node events
	if (n < 1) {
		struct bsr_resource *resource = state_change->resource->resource;
		notify_node_info(skb, (unsigned int)seq, resource, NULL,
						 resource->node_opts.node_name,
						 BSR_NODE_INFO,
					     NOTIFY_EXISTS | flags);
		goto next;
	}

	n--;

	if (n < state_change->n_connections) {
		notify_connection_state_change(skb, (unsigned int)seq, &state_change->connections[n],
					       NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= state_change->n_connections;

	// BSR-859 for peer node events
	if (n < state_change->n_connections) {
		struct bsr_connection * connection = (&state_change->connections[n])->connection;
		char * node_name;
		rcu_read_lock();
		node_name = rcu_dereference(connection->transport.net_conf)->peer_node_name;
		rcu_read_unlock();	
		notify_node_info(skb, (unsigned int)seq, connection->resource, connection,
						node_name,
						BSR_PEER_NODE_INFO,
						NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= state_change->n_connections;

	if (n < state_change->n_devices) {
		notify_device_state_change(skb, (unsigned int)seq, &state_change->devices[n],
			NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= state_change->n_devices;

	if (n < state_change->n_devices * state_change->n_connections) {
		// BSR-676 
		notify_gi_uuid_state(skb, (unsigned int)seq, (&state_change->peer_devices[n])->peer_device,
			NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= (state_change->n_devices * state_change->n_connections);

	if (n < state_change->n_devices) {
		// BSR-676 
		notify_gi_device_mdf_flag_state(skb, (unsigned int)seq, (&state_change->devices[n])->device, 
			NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= state_change->n_devices;

	if (n < state_change->n_devices * state_change->n_connections) {
		notify_peer_device_state_change(skb, (unsigned int)seq, &state_change->peer_devices[n],
			NOTIFY_EXISTS | flags);
		goto next;
	}
	n -= (state_change->n_devices * state_change->n_connections);
	
	if (n < state_change->n_devices * state_change->n_connections) {
		// BSR-676 
		notify_gi_peer_device_mdf_flag_state(skb, (unsigned int)seq, (&state_change->peer_devices[n])->peer_device, 
			NOTIFY_EXISTS | flags);
		goto next;
	}

next:
	if (cb->args[4] == cb->args[3]) {
		struct bsr_state_change *next_state_change =
			list_entry(state_change->list.next,
				   struct bsr_state_change, list);
		cb->args[0] = (LONG_PTR)next_state_change;
		cb->args[3] = notifications_for_state_change(next_state_change);
		cb->args[4] = 0;
	}
out:
	return skb->len;
}

int bsr_adm_get_initial_state_done(struct netlink_callback *cb)
{
	LIST_HEAD(head);
	if (cb->args[0]) {
		struct bsr_state_change *state_change =
			(struct bsr_state_change *)cb->args[0];
		cb->args[0] = 0;

		/* connect list to head */
		list_add(&head, &state_change->list);
		free_state_changes(&head);
	}
	return 0;
}

int bsr_adm_get_initial_state(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct bsr_resource *resource;
	LIST_HEAD(head);

	if (cb->args[5] >= 1) {
		if (cb->args[5] > 1)
			return get_initial_state(skb, cb);
		return 0;
	}

	cb->args[5] = 2;  /* number of iterations */
	mutex_lock(&resources_mutex);
	for_each_resource(resource, &bsr_resources) {
		struct bsr_state_change *state_change;

		state_change = remember_state_change(resource, GFP_KERNEL);
		if (!state_change) {
			if (!list_empty(&head))
				free_state_changes(&head);
			mutex_unlock(&resources_mutex);
			return -ENOMEM;
		}
		copy_old_to_new_state_change(state_change);
		list_add_tail(&state_change->list, &head);
		cb->args[5] += notifications_for_state_change(state_change);
	}
	mutex_unlock(&resources_mutex);

	if (!list_empty(&head)) {
		struct bsr_state_change *state_change =
			list_entry(head.next, struct bsr_state_change, list);
		cb->args[0] = (LONG_PTR)state_change;
		cb->args[3] = notifications_for_state_change(state_change);
		list_del(&head);  /* detach list from head */
	}

	cb->args[2] = cb->nlh->nlmsg_seq;
	return get_initial_state(skb, cb);
}

int bsr_adm_forget_peer(struct sk_buff *skb, struct genl_info *info)
{
	struct bsr_config_context adm_ctx;
	struct bsr_resource *resource;
	struct bsr_device *device;
	struct forget_peer_parms parms = { 0 };
	enum bsr_state_rv retcode;
	int vnr, peer_node_id, err;

	retcode = bsr_adm_prepare(&adm_ctx, skb, info, BSR_ADM_NEED_RESOURCE);
	if (!adm_ctx.reply_skb)
		return retcode;

	resource = adm_ctx.resource;

	err = forget_peer_parms_from_attrs(&parms, info);
	if (err) {
		retcode = ERR_MANDATORY_TAG;
		bsr_msg_put_info(adm_ctx.reply_skb, from_attrs_err_to_txt(err));
		goto out_no_adm;
	}

	mutex_lock(&resource->adm_mutex);

	peer_node_id = parms.forget_peer_node_id;
	if (bsr_connection_by_node_id(resource, peer_node_id)) {
		retcode = ERR_NET_CONFIGURED;
		goto out;
	}

	if (peer_node_id < 0 || peer_node_id >= BSR_NODE_ID_MAX) {
		retcode = ERR_INVALID_PEER_NODE_ID;
		goto out;
	}

	idr_for_each_entry_ex(struct bsr_device *, &resource->devices, device, vnr) {
		struct bsr_peer_md *peer_md;

		if (!get_ldev(device))
			continue;

		peer_md = &device->ldev->md.peers[peer_node_id];
		if (peer_md->bitmap_index == -1) {
			put_ldev(__FUNCTION__, device);
			retcode = ERR_INVALID_PEER_NODE_ID;
			break;
		}

		peer_md->bitmap_uuid = 0;
		peer_md->flags = 0;
		peer_md->bitmap_index = -1;

		bsr_md_sync(device);
		put_ldev(__FUNCTION__, device);
	}
out:
	mutex_unlock(&resource->adm_mutex);
out_no_adm:
	bsr_adm_finish(&adm_ctx, info, (enum bsr_ret_code)retcode);
	return 0;

}
#ifdef _WIN
// DW-1229 using global attr may cause BSOD when we receive plural netlink requests. use local attr.
int bsr_tla_parse(struct nlmsghdr *nlh, struct nlattr **attr)
{
	bsr_genl_family.id = nlh->nlmsg_type;

	return nla_parse(attr, ARRAY_SIZE(bsr_tla_nl_policy) - 1,
		nlmsg_attrdata(nlh, GENL_HDRLEN + bsr_genl_family.hdrsize),
		nlmsg_attrlen(nlh, GENL_HDRLEN + bsr_genl_family.hdrsize),
		bsr_tla_nl_policy);
}

void nl_policy_init_by_manual()
{
	extern void manual_nl_policy_init(void);
	manual_nl_policy_init();
}

struct genl_ops * get_bsr_genl_ops(u8 cmd)
{
	for (int i = 0; i < sizeof(bsr_genl_ops) / sizeof((bsr_genl_ops)[0]); i++) {
		if (bsr_genl_ops[i].cmd == cmd) {
			return &bsr_genl_ops[i];
		}
	}

	return NULL;
}
#endif
