/*
 * BSR setup via genetlink
 *
 * This file is part of BSR by Man Technology inc.
 *
 * Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>.
 *
 * bsr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * bsr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with bsr; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64

#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <stdarg.h>
#include <libgen.h>
#include <time.h>
#include <search.h>
#ifdef _LIN
#include <linux/netlink.h>
#include <linux/genetlink.h>
#endif
#define EXIT_NOMEM 20
#define EXIT_NO_FAMILY 20
#define EXIT_SEND_ERR 20
#define EXIT_RECV_ERR 20
#define EXIT_TIMED_OUT 20
#define EXIT_NOSOCK 30
#define EXIT_THINKO 42

/* is_intentional is a boolean value we get via nl from kernel. if we use new
* utils and old kernel we don't get it, so we set this default, get kernel
* info, and then decide from the value if the kernel was new enough */
#define IS_INTENTIONAL_DEF 3

/*
 * We are not using libnl,
 * using its API for the few things we want to do
 * ends up being almost as much lines of code as
 * coding the necessary bits right here.
 */

#include "libgenl.h"
#include "bsr_nla.h"
#include <linux/bsr_config.h>
#include <linux/bsr_genl_api.h>
#include <linux/bsr_limits.h>
#include "bsrtool_common.h"
#ifdef _LIN
#include <sys/prctl.h>
#endif
#include <linux/genl_magic_func.h>
#include "bsr_strings.h"
#include "registry.h"
#include "config.h"
#include "config_flags.h"
#include "wrap_printf.h"
#include "bsrsetup_colors.h"

// BSR-1002
#ifdef _WIN
#include <iphlpapi.h>
#endif

char *progname;

/* for parsing of messages */
static struct nlattr *global_attrs[128];
/* there is an other table, nested_attr_tb, defined in genl_magic_func.h,
 * which can be used after <struct>_from_attrs,
 * to check for presence of struct fields. */
#define ntb(t)	nested_attr_tb[__nla_type(t)]

#ifdef PRINT_NLMSG_LEN
/* I'm to lazy to check the maximum possible nlmsg length by hand */
int main(void)
{
	static __u16 nla_attr_minlen[NLA_TYPE_MAX+1] __read_mostly = {
		[NLA_U8]        = sizeof(__u8),
		[NLA_U16]       = sizeof(__u16),
		[NLA_U32]       = sizeof(__u32),
		[NLA_U64]       = sizeof(__u64),
		[NLA_NESTED]    = NLA_HDRLEN,
	};
	int i;
	int sum_total = 0;
#define LEN__(policy) do {					\
	int sum = 0;						\
	for (i = 0; i < ARRAY_SIZE(policy); i++) {		\
		sum += nla_total_size(policy[i].len ?:		\
			nla_attr_minlen[policy[i].type]);	\
								\
	}							\
	sum += 4;						\
	sum_total += sum;					\
	printf("%-30s %4u [%4u]\n",				\
			#policy ":", sum, sum_total);		\
} while (false)
#define LEN_(p) LEN__(p ## _nl_policy)
	LEN_(disk_conf);
	LEN_(syncer_conf);
	LEN_(net_conf);
	LEN_(set_role_parms);
	LEN_(resize_parms);
	LEN_(state_info);
	LEN_(start_ov_parms);
	LEN_(new_c_uuid_parms);
	sum_total += sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr)
		+ sizeof(struct bsr_genlmsghdr);
	printf("sum total inclusive hdr overhead: %4u\n", sum_total);
	return 0;
}
#else

#ifndef AF_INET_SDP
#define AF_INET_SDP 27
#define PF_INET_SDP AF_INET_SDP
#endif

#define MULTIPLE_TIMEOUTS (-2)

/* pretty print helpers */
static int indent = 0;
#define INDENT_WIDTH	4
#define printI(fmt, args... ) printf("%*s" fmt,INDENT_WIDTH * indent,"" , ## args )

enum usage_type {
	BRIEF,
	FULL,
	XML,
};

struct bsr_argument {
	const char* name;
	__u16 nla_type;
	int (*convert_function)(struct bsr_argument *,
				struct msg_buff *,
				struct bsr_genlmsghdr *dhdr,
				char *);
};

/* Configuration requests typically need a context to operate on.
 * Possible keys are device minor/volume id (both fit in the bsr_genlmsghdr),
 * the replication link (aka connection) name,
 * and/or the replication group (aka resource) name */
enum cfg_ctx_key {
	/* Only one of these can be present in a command: */
	CTX_RESOURCE = 1,
	CTX_PEER_NODE_ID = 2,
	CTX_MINOR = 4,
	CTX_VOLUME = 8,
	CTX_MY_ADDR = 16,
	CTX_PEER_ADDR = 32,
	CTX_ALL = 64,

	CTX_MULTIPLE_ARGUMENTS = 128,

	/* To identify a connection, we use (resource_name, peer_node_id) */
	CTX_PEER_NODE = CTX_RESOURCE | CTX_PEER_NODE_ID | CTX_MULTIPLE_ARGUMENTS,
	CTX_PEER_DEVICE = CTX_PEER_NODE | CTX_VOLUME,
};

enum cfg_ctx_key ctx_next_arg(enum cfg_ctx_key *key)
{
	enum cfg_ctx_key next_arg;

	if (*key & CTX_MULTIPLE_ARGUMENTS) {
		next_arg = *key & ~(*key - 1);  /* the lowest set bit */
		next_arg &= ~CTX_MULTIPLE_ARGUMENTS;
	} else
		next_arg = *key;

	*key &= ~next_arg;
	return next_arg;
}

const char *ctx_arg_string(enum cfg_ctx_key key, enum usage_type ut)
{
	bool xml = (ut == XML);

	switch(key) {
	case CTX_RESOURCE:
		return xml ? "resource" : "{resource}";
	case CTX_PEER_NODE_ID:
		return xml ? "peer_node_id" : "{peer_node_id}";
	case CTX_MINOR:
		return xml ? "minor" : "{minor}";
	case CTX_VOLUME:
		return xml ? "volume" : "{volume}";
	case CTX_MY_ADDR:
		return xml ? "local_addr" : "[local:][{af}:]{local_addr}[:{port}]";
	case CTX_PEER_ADDR:
		return xml ? "remote_addr" : "[peer:][{af}:]{remote_addr}[:{port}]";
	case CTX_ALL:
		return "all";
	default:
		assert(0);
	}

	return "unknown argument";
}

struct bsr_cmd {
	const char* cmd;
	enum cfg_ctx_key ctx_key;
	int cmd_id;
	int tla_id; /* top level attribute id */
	int (*function)(struct bsr_cmd *, int, char **);
	struct bsr_argument *bsr_args;
	int (*show_function)(struct bsr_cmd*, struct genl_info *, void *u_ptr);
	struct option *options;
	bool missing_ok;
	bool warn_on_missing;
	bool continuous_poll;
	bool set_defaults;
	bool lockless;
	struct context_def *ctx;
	const char *summary;
	bool is_status_cmd; // BSR-1031
};

// other functions
static int get_af_ssocks(int warn);
static void print_command_usage(struct bsr_cmd *cm, enum usage_type);
static void print_usage_and_exit(const char *addinfo)
		__attribute__ ((noreturn));
static const char *resync_susp_str(struct peer_device_info *info);
static const char *intentional_diskless_str(struct device_info *info);
static const char *peer_intentional_diskless_str(struct peer_device_info *info);

// command functions
static int generic_config_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int down_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int generic_get_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int del_minor_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int del_resource_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int show_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int status_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int role_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int cstate_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int dstate_cmd(struct bsr_cmd *cm, int argc, char **argv);
static int check_resize_cmd(struct bsr_cmd *cm, int argc, char **argv);
#ifdef _LIN
// BSR-823
static int check_fs_cmd(struct bsr_cmd *cm, int argc, char **argv);
#endif
static int show_or_get_gi_cmd(struct bsr_cmd *cm, int argc, char **argv);

// sub commands for generic_get_cmd
static int print_notifications(struct bsr_cmd *, struct genl_info *, void *);
static int wait_for_family(struct bsr_cmd *, struct genl_info *, void *);
static int remember_resource(struct bsr_cmd *, struct genl_info *, void *);
static int remember_device(struct bsr_cmd *, struct genl_info *, void *);
static int remember_connection(struct bsr_cmd *, struct genl_info *, void *);
static int remember_peer_device(struct bsr_cmd *, struct genl_info *, void *);

#define ADDRESS_STR_MAX 256
static char *address_str(char *buffer, void* address, int addr_len);

// convert functions for arguments
static int conv_block_dev(struct bsr_argument *ad, struct msg_buff *msg, struct bsr_genlmsghdr *dhdr, char* arg);
static int conv_md_idx(struct bsr_argument *ad, struct msg_buff *msg, struct bsr_genlmsghdr *dhdr, char* arg);
static int conv_u32(struct bsr_argument *, struct msg_buff *, struct bsr_genlmsghdr *, char *);
static int conv_addr(struct bsr_argument *ad, struct msg_buff *msg, struct bsr_genlmsghdr *dhdr, char* arg);

struct resources_list {
	struct resources_list *next;
	char *name;
	struct nlattr *res_opts;
	struct nlattr *node_opts;
	struct resource_info info;
	struct resource_statistics statistics;
};
static struct resources_list *list_resources(void);
static struct resources_list *sort_resources(struct resources_list *);
static void free_resources(struct resources_list *);

struct devices_list {
	struct devices_list *next;
	unsigned minor;
	struct bsr_cfg_context ctx;
	struct nlattr *disk_conf_nl;
	struct disk_conf disk_conf;
	struct device_info info;
	struct device_statistics statistics;
};
static struct devices_list *list_devices(char *);
static void free_devices(struct devices_list *);

struct connections_list {
	struct connections_list *next;
	struct bsr_cfg_context ctx;
	struct nlattr *path_list;
	struct nlattr *net_conf;
	struct connection_info info;
	struct connection_statistics statistics;
};
static struct connections_list *sort_connections(struct connections_list *);
static struct connections_list *list_connections(char *);
static void free_connections(struct connections_list *);

struct peer_devices_list {
	struct peer_devices_list *next;
	struct bsr_cfg_context ctx;
	struct nlattr *peer_device_conf;
	struct peer_device_info info;
	struct peer_device_statistics statistics;
	struct devices_list *device;
	int timeout_ms; /* used only by wait_for_family() */
};
static struct peer_devices_list *list_peer_devices(char *);
static void free_peer_devices(struct peer_devices_list *);

struct option wait_cmds_options[] = {
	{ "wfc-timeout", required_argument, 0, 't' },
	{ "degr-wfc-timeout", required_argument, 0, 'd'},
	{ "outdated-wfc-timeout", required_argument, 0, 'o'},
	{ "wait-after-sb", optional_argument, 0, 'w'},
	{ }
};

struct option events_cmd_options[] = {
	{ "timestamps", no_argument, 0, 'T' },
	{ "statistics", no_argument, 0, 's' },
	{ "now", no_argument, 0, 'n' },
	{ "poll", no_argument, 0, 'p' },
	{ "color", optional_argument, 0, 'c' },
	{ }
};

struct option show_cmd_options[] = {
	{ "show-defaults", no_argument, 0, 'D' },
	{ }
};

static struct option status_cmd_options[] = {
	{ "verbose", no_argument, 0, 'v' },
	{ "statistics", no_argument, 0, 's' },
	{ "color", optional_argument, 0, 'c' },
	{ "json", no_argument, 0, 'j' },
	{ }
};

#define F_CONFIG_CMD	generic_config_cmd
#define NO_PAYLOAD	0
#define F_NEW_EVENTS_CMD(scmd)	BSR_ADM_GET_INITIAL_STATE, NO_PAYLOAD, generic_get_cmd, \
			.show_function = scmd

struct bsr_cmd commands[] = {
	{"primary", CTX_RESOURCE, BSR_ADM_PRIMARY, BSR_NLA_SET_ROLE_PARMS,
		F_CONFIG_CMD,
	 .ctx = &primary_cmd_ctx,
	 .summary = "Change the role of a node in a resource to primary." },

	{"secondary", CTX_RESOURCE, BSR_ADM_SECONDARY, NO_PAYLOAD, F_CONFIG_CMD,
	 .summary = "Change the role of a node in a resource to secondary." },

	{"attach", CTX_MINOR, BSR_ADM_ATTACH, BSR_NLA_DISK_CONF,
		F_CONFIG_CMD,
	 .bsr_args = (struct bsr_argument[]) {
		 { "lower_dev",		T_backing_dev,	conv_block_dev },
		 { "meta_data_dev",	T_meta_dev,	conv_block_dev },
		 { "meta_data_index",	T_meta_dev_idx,	conv_md_idx },
		 { } },
	 .ctx = &attach_cmd_ctx,
	 .summary = "Attach a lower-level device to an existing replicated device." },

	{"disk-options", CTX_MINOR, BSR_ADM_CHG_DISK_OPTS, BSR_NLA_DISK_CONF,
		F_CONFIG_CMD,
	 .set_defaults = true,
	 .ctx = &disk_options_ctx,
	 .summary = "Change the disk options of an attached lower-level device." },

	{"detach", CTX_MINOR, BSR_ADM_DETACH, BSR_NLA_DETACH_PARMS, F_CONFIG_CMD,
	 .ctx = &detach_cmd_ctx,
	 .summary = "Detach the lower-level device of a replicated device." },

	{"connect", CTX_PEER_NODE,
		BSR_ADM_CONNECT, BSR_NLA_CONNECT_PARMS,
		F_CONFIG_CMD,
	 .ctx = &connect_cmd_ctx,
	 .summary = "Attempt to (re)establish a replication link to a peer host." },

	{"new-peer", CTX_PEER_NODE,
		BSR_ADM_NEW_PEER, BSR_NLA_NET_CONF,
		F_CONFIG_CMD,
	 .ctx = &new_peer_cmd_ctx,
	 .summary = "Make a peer host known to a resource." },

	{"del-peer", CTX_PEER_NODE,
		BSR_ADM_DEL_PEER, BSR_NLA_DISCONNECT_PARMS,
		F_CONFIG_CMD,
	 .ctx = &disconnect_cmd_ctx,
	 .summary = "Remove a connection to a peer host." },

	{"new-path", CTX_PEER_NODE,
		BSR_ADM_NEW_PATH, BSR_NLA_PATH_PARMS,
		F_CONFIG_CMD,
	 .bsr_args = (struct bsr_argument[]) {
		{ "local-addr", T_my_addr, conv_addr },
		{ "remote-addr", T_peer_addr, conv_addr },
		{ } },
	 .ctx = &path_cmd_ctx,
	 .summary = "Add a path (endpoint address pair) where a peer host should be reachable." },

	{"del-path", CTX_PEER_NODE,
		BSR_ADM_DEL_PATH, BSR_NLA_PATH_PARMS,
		F_CONFIG_CMD,
	 .bsr_args = (struct bsr_argument[]) {
		{ "local-addr", T_my_addr, conv_addr },
		{ "remote-addr", T_peer_addr, conv_addr },
		{ } },
	 .ctx = &path_cmd_ctx,
	 .summary = "Remove a path (endpoint address pair) from a connection to a peer host." },

	{"net-options", CTX_PEER_NODE, BSR_ADM_CHG_NET_OPTS, BSR_NLA_NET_CONF,
		F_CONFIG_CMD,
	 .set_defaults = true,
	 .ctx = &net_options_ctx,
	 .summary = "Change the network options of a connection." },

	{"disconnect", CTX_PEER_NODE, BSR_ADM_DISCONNECT, BSR_NLA_DISCONNECT_PARMS,
		F_CONFIG_CMD,
	 .ctx = &disconnect_cmd_ctx,
	 .summary = "Unconnect from a peer host." },

	{"resize", CTX_MINOR, BSR_ADM_RESIZE, BSR_NLA_RESIZE_PARMS,
		F_CONFIG_CMD,
	 .ctx = &resize_cmd_ctx,
	 .summary = "Reexamine the lower-level device sizes to resize a replicated device." },

	{"resource-options", CTX_RESOURCE, BSR_ADM_RESOURCE_OPTS, BSR_NLA_RESOURCE_OPTS,
		F_CONFIG_CMD,
	 .set_defaults = true,
	 .ctx = &resource_options_ctx,
	 .summary = "Change the resource options of an existing resource." },

	{"node-options", CTX_RESOURCE, BSR_ADM_NODE_OPTS, BSR_NLA_NODE_OPTS,
		F_CONFIG_CMD,
	 .set_defaults = true,
	 .ctx = &node_options_cmd_ctx,
	 .summary = "Change the node options of an existing resource." },

	{"peer-device-options", CTX_PEER_DEVICE, BSR_ADM_CHG_PEER_DEVICE_OPTS,
		BSR_NLA_PEER_DEVICE_OPTS, F_CONFIG_CMD,
	 .set_defaults = true,
	 .ctx = &peer_device_options_ctx,
	 .summary = "Change peer-device options." },

	{"new-current-uuid", CTX_MINOR, BSR_ADM_NEW_C_UUID, BSR_NLA_NEW_C_UUID_PARMS,
		F_CONFIG_CMD,
	 .ctx = &new_current_uuid_cmd_ctx,
	 .summary = "Generate a new current UUID." },

	{"invalidate", CTX_MINOR, BSR_ADM_INVALIDATE, BSR_NLA_INVALIDATE_PARMS, F_CONFIG_CMD,
	 .ctx = &invalidate_ctx,
	 .summary = "Replace the local data of a volume with that of a peer." },
	{"invalidate-remote", CTX_PEER_DEVICE, BSR_ADM_INVAL_PEER, BSR_NLA_INVALIDATE_PEER_PARMS, F_CONFIG_CMD,
	.ctx = &invalidate_peer_ctx,
	 .summary = "Replace a peer's data of a volume with the local data." },
	{"pause-sync", CTX_PEER_DEVICE, BSR_ADM_PAUSE_SYNC, NO_PAYLOAD, F_CONFIG_CMD,
	 .summary = "Stop resynchronizing between a local and a peer device." },
	{"resume-sync", CTX_PEER_DEVICE, BSR_ADM_RESUME_SYNC, NO_PAYLOAD, F_CONFIG_CMD,
	 .summary = "Allow resynchronization to resume on a replicated device." },
	{"suspend-io", CTX_MINOR, BSR_ADM_SUSPEND_IO, NO_PAYLOAD, F_CONFIG_CMD,
	 .summary = "Suspend I/O on a replicated device." },
	{"resume-io", CTX_MINOR, BSR_ADM_RESUME_IO, NO_PAYLOAD, F_CONFIG_CMD,
	 .summary = "Resume I/O on a replicated device." },
	{"outdate", CTX_MINOR, BSR_ADM_OUTDATE, NO_PAYLOAD, F_CONFIG_CMD,
	 .summary = "Mark the data on a lower-level device as outdated." },
	{"verify", CTX_PEER_DEVICE, BSR_ADM_START_OV, BSR_NLA_START_OV_PARMS, F_CONFIG_CMD,
	 .ctx = &verify_cmd_ctx,
	 .summary = "Verify the data on a lower-level device against a peer device." },
	{"verify-stop", CTX_PEER_DEVICE, BSR_ADM_STOP_OV, NO_PAYLOAD, F_CONFIG_CMD,
	 .summary = "Stop verify" },
	{"down", CTX_RESOURCE | CTX_ALL, BSR_ADM_DOWN, NO_PAYLOAD, down_cmd,
	 .missing_ok = true,
	 .warn_on_missing = true,
	 .summary = "Take a resource down." },
	{"role", CTX_RESOURCE, 0, NO_PAYLOAD, role_cmd,
	 .lockless = true,
	 .summary = "Show the current role of a resource." },
	{"cstate", CTX_PEER_NODE, 0, NO_PAYLOAD, cstate_cmd,
	 .lockless = true,
	 .is_status_cmd = true,
	 .summary = "Show the current state of a connection." },
	{"dstate", CTX_MINOR, 0, NO_PAYLOAD, dstate_cmd,
	 .lockless = true,
	 .is_status_cmd = true,
	 .summary = "Show the current disk state of a lower-level device." },
	{"show-gi", CTX_PEER_DEVICE, 0, NO_PAYLOAD, show_or_get_gi_cmd,
	 .lockless = true,
	 .is_status_cmd = true,
	 .summary = "Show the data generation identifiers for a device on a particular connection, with explanations." },
	{"get-gi", CTX_PEER_DEVICE, 0, NO_PAYLOAD, show_or_get_gi_cmd,
	 .lockless = true,
	 .is_status_cmd = true,
	 .summary = "Show the data generation identifiers for a device on a particular connection." },
	{"show", CTX_RESOURCE | CTX_ALL, 0, 0, show_cmd,
	 .options = show_cmd_options,
	 .lockless = true,
	 .is_status_cmd = true,
	 .summary = "Show the current configuration of a resource, or of all resources." },
	{"status", CTX_RESOURCE | CTX_ALL, 0, 0, status_cmd,
	 .options = status_cmd_options,
	 .lockless = true,
	 .is_status_cmd = true,
	 .summary = "Show the state of a resource, or of all resources." },
	{"check-resize", CTX_MINOR, 0, NO_PAYLOAD, check_resize_cmd,
	 .lockless = true,
	 .summary = "Remember the current size of a lower-level device." },
#ifdef _LIN
	// BSR-823
	{"check-fs", CTX_MINOR, 0, NO_PAYLOAD, check_fs_cmd,
	 .lockless = true,
	 .summary = "Check a filesystem of a backing device." },
#endif
	{"events2", CTX_RESOURCE | CTX_ALL, F_NEW_EVENTS_CMD(print_notifications),
	 .options = events_cmd_options,
	 .missing_ok = true,
	 .continuous_poll = true,
	 .lockless = true,
	 .summary = "Show the current state and all state changes of a resource, or of all resources." },
	{"wait-sync-volume", CTX_PEER_DEVICE, F_NEW_EVENTS_CMD(wait_for_family),
	 .options = wait_cmds_options,
	 .continuous_poll = true,
	 .lockless = true,
	 .summary = "Wait until resync finished on a volume." },
	{"wait-sync-connection", CTX_PEER_NODE, F_NEW_EVENTS_CMD(wait_for_family),
	 .options = wait_cmds_options,
	 .continuous_poll = true,
	 .lockless = true,
	 .summary = "Wait until resync finished on all volumes of a connection." },
	{"wait-sync-resource", CTX_RESOURCE, F_NEW_EVENTS_CMD(wait_for_family),
	 .options = wait_cmds_options,
	 .continuous_poll = true,
	 .lockless = true,
	 .summary = "Wait until resync finished on all volumes." },
	{"wait-connect-volume", CTX_PEER_DEVICE, F_NEW_EVENTS_CMD(wait_for_family),
	 .options = wait_cmds_options,
	 .continuous_poll = true,
	 .lockless = true,
	 .summary = "Wait until a device on a peer is visible." },
	{"wait-connect-connection", CTX_PEER_NODE, F_NEW_EVENTS_CMD(wait_for_family),
	 .options = wait_cmds_options,
	 .continuous_poll = true,
	 .lockless = true,
	 .summary = "Wait until all peer volumes of connection are visible." },
	{"wait-connect-resource", CTX_RESOURCE, F_NEW_EVENTS_CMD(wait_for_family),
	 .options = wait_cmds_options,
	 .continuous_poll = true,
	 .lockless = true,
	 .summary = "Wait until all connections are establised." },

	{"new-resource", CTX_RESOURCE, BSR_ADM_NEW_RESOURCE, BSR_NLA_RESOURCE_OPTS, F_CONFIG_CMD,
	 .bsr_args = (struct bsr_argument[]) {
		 { "node_id",		T_node_id,	conv_u32 },
		 { } },
	 .ctx = &resource_options_ctx,
	 .summary = "Create a new resource." },

	{"new-minor", CTX_RESOURCE | CTX_MINOR | CTX_VOLUME | CTX_MULTIPLE_ARGUMENTS,
		BSR_ADM_NEW_MINOR, BSR_NLA_DEVICE_CONF,
		F_CONFIG_CMD,
	 .ctx = &device_options_ctx,
	 .summary = "Create a new replicated device within a resource." },

	{"del-minor", CTX_MINOR, BSR_ADM_DEL_MINOR, NO_PAYLOAD, del_minor_cmd,
	 .summary = "Remove a replicated device." },
	{"del-resource", CTX_RESOURCE, BSR_ADM_DEL_RESOURCE, NO_PAYLOAD, del_resource_cmd,
	 .summary = "Remove a resource." },
	{"forget-peer", CTX_RESOURCE, BSR_ADM_FORGET_PEER, BSR_NLA_FORGET_PEER_PARMS, F_CONFIG_CMD,
	 .bsr_args = (struct bsr_argument[]) {
		 { "peer_node_id",	T_forget_peer_node_id,	conv_u32 },
		 { } },
	 .summary = "Completely remove any reference to a unconnected peer from meta-data." },
};

bool show_defaults;
bool wait_after_split_brain;

#define OTHER_ERROR 900

#define EM(C) [ C - ERR_CODE_BASE ]

/* The EM(123) are used for old error messages. */
static const char *error_messages[] = {
	EM(ERR_NO) = "No further Information available.",
	EM(ERR_LOCAL_ADDR) = "Local address(port) already in use.",
	EM(ERR_PEER_ADDR) = "Remote address(port) already in use.",
	EM(ERR_OPEN_DISK) = "Can not open backing device.",
	EM(ERR_OPEN_MD_DISK) = "Can not open meta device.",
	EM(106) = "Lower device already in use.",
	EM(ERR_DISK_NOT_BDEV) = "Lower device is not a block device.",
	EM(ERR_MD_NOT_BDEV) = "Meta device is not a block device.",
	EM(109) = "Open of lower device failed.",
	EM(110) = "Open of meta device failed.",
	EM(ERR_DISK_TOO_SMALL) = "Low.dev. smaller than requested BSR-dev. size.",
	EM(ERR_MD_DISK_TOO_SMALL) = "Meta device too small.",
	EM(113) = "You have to use the disk command first.",
	EM(ERR_BDCLAIM_DISK) = "Lower device is already claimed. This usually means it is mounted.",
	EM(ERR_BDCLAIM_MD_DISK) = "Meta device is already claimed. This usually means it is mounted.",
	EM(ERR_MD_IDX_INVALID) = "Lower device / meta device / index combination invalid.",
	EM(117) = "Currently we only support devices up to 3.998TB.\n"
	"(up to 2TB in case you do not have CONFIG_LBD set)\n"
	"Contact bsr@mantech.co.kr, if you need more.",
	EM(ERR_IO_MD_DISK) = "IO error(s) occurred during initial access to meta-data.\n",
	EM(ERR_MD_UNCLEAN) = "Unclean meta-data found.\nYou need to 'bsrdadm apply-al res'\n",
	EM(ERR_MD_INVALID) = "No valid meta-data signature found.\n\n"
	"\t==> Use 'bsradm create-md res' to initialize meta-data area. <==\n",
	EM(ERR_AUTH_ALG) = "The 'cram-hmac-alg' you specified is not known in "
	"the kernel. (Maybe you need to modprobe it, or modprobe hmac?)",
	EM(ERR_AUTH_ALG_ND) = "The 'cram-hmac-alg' you specified is not a digest.",
	EM(ERR_NOMEM) = "kmalloc() failed. Out of memory?",
	EM(ERR_DISCARD_IMPOSSIBLE) = "--discard-my-data not allowed when primary.",
	EM(ERR_DISK_CONFIGURED) = "Device is attached to a disk (use detach first)",
	EM(ERR_NET_CONFIGURED) = "Device has a net-config (use disconnect first)",
	EM(ERR_MANDATORY_TAG) = "UnknownMandatoryTag",
	EM(ERR_MINOR_INVALID) = "Device minor not allocated",
	EM(128) = "Resulting device state would be invalid",
	EM(ERR_INTR) = "Interrupted by Signal",
	EM(ERR_RESIZE_RESYNC) = "Resize not allowed during resync.",
	EM(ERR_NO_PRIMARY) = "Need one Primary node to resize.",
	EM(ERR_RESYNC_AFTER) = "The resync-after minor number is invalid",
	EM(ERR_RESYNC_AFTER_CYCLE) = "This would cause a resync-after dependency cycle",
	EM(ERR_PAUSE_IS_SET) = "Sync-pause flag is already set",
	EM(ERR_PAUSE_IS_CLEAR) = "Sync-pause flag is already cleared",
	EM(136) = "Disk state is lower than outdated",
	EM(ERR_PACKET_NR) = "Kernel does not know how to handle your request.\n"
	"Maybe API_VERSION mismatch?",
	EM(ERR_NO_DISK) = "Device does not have a disk-config",
	EM(ERR_NOT_PROTO_C) = "Protocol C required",
	EM(ERR_NOMEM_BITMAP) = "vmalloc() failed. Out of memory?",
	EM(ERR_INTEGRITY_ALG) = "The 'data-integrity-alg' you specified is not known in "
	"the kernel. (Maybe you need to modprobe it, or modprobe hmac?)",
	EM(ERR_INTEGRITY_ALG_ND) = "The 'data-integrity-alg' you specified is not a digest.",
	EM(ERR_CPU_MASK_PARSE) = "Invalid cpu-mask.",
	EM(ERR_VERIFY_ALG) = "VERIFYAlgNotAvail",
	EM(ERR_VERIFY_ALG_ND) = "VERIFYAlgNotDigest",
	EM(ERR_VERIFY_RUNNING) = "Can not change verify-alg while online verify runs",
	EM(ERR_DATA_NOT_CURRENT) = "Can only attach to the data we lost last (see kernel log).",
	EM(ERR_CONNECTED) = "Need to be StandAlone",
	EM(ERR_CSUMS_ALG) = "CSUMSAlgNotAvail",
	EM(ERR_CSUMS_ALG_ND) = "CSUMSAlgNotDigest",
	EM(ERR_CSUMS_RESYNC_RUNNING) = "Can not change csums-alg while resync is in progress",
	EM(ERR_PERM) = "Permission denied. CAP_SYS_ADMIN necessary",
	EM(ERR_NEED_APV_93) = "Protocol version 93 required to use --assume-clean",
	EM(ERR_STONITH_AND_PROT_A) = "Fencing policy resource-and-stonith only with prot B or C allowed",
	EM(ERR_CONG_NOT_PROTO_A) = "on-congestion policy pull-ahead only with prot A allowed",
	EM(ERR_PIC_AFTER_DEP) = "Sync-pause flag is already cleared.\n"
	"Note: Resync pause caused by a local resync-after dependency.",
	EM(ERR_PIC_PEER_DEP) = "Sync-pause flag is already cleared.\n"
	"Note: Resync pause caused by the peer node.",
	EM(ERR_RES_NOT_KNOWN) = "Unknown resource",
	EM(ERR_RES_IN_USE) = "Resource still in use (delete all minors first)",
	EM(ERR_MINOR_CONFIGURED) = "Minor still configured (down it first)",
	EM(ERR_MINOR_OR_VOLUME_EXISTS) = "Minor or volume exists already (delete it first)",
	EM(ERR_INVALID_REQUEST) = "Invalid configuration request",
	EM(ERR_NEED_APV_100) = "Prot version 100 required in order to change\n"
	"these network options while connected",
	EM(ERR_NEED_ALLOW_TWO_PRI) = "Can not clear allow_two_primaries as long as\n"
	"there a primaries on both sides",
	EM(ERR_MD_LAYOUT_CONNECTED) = "BSR need to be connected for online MD layout change\n",
	EM(ERR_MD_LAYOUT_TOO_BIG) = "Resulting AL area too big\n",
	EM(ERR_MD_LAYOUT_TOO_SMALL) = "Resulting AL are too small\n",
	EM(ERR_MD_LAYOUT_NO_FIT) = "Resulting AL does not fit into available meta data space\n",
	EM(ERR_IMPLICIT_SHRINK) = "Implicit device shrinking not allowed. See kernel log.\n",
	EM(ERR_INVALID_PEER_NODE_ID) = "Invalid peer-node-id\n",
	EM(ERR_CREATE_TRANSPORT) = "Failed to create transport (bsr_transport_xxx module missing?)\n",
	EM(ERR_LOCAL_AND_PEER_ADDR) = "Combination of local address(port) and remote address(port) already in use\n",
	EM(ERR_SNDBUF_SIZE_TOO_SMALL) = "sndbuf-size must be at least 10M to use send buffer\n",
	EM(ERR_CANT_CHANGE_SNDBUF_SIZE_WHEN_CONNECTED) = "Cannot change sndbuf-size when connected. Please disconnect first and change the attribute value with adjust command\n",
	EM(ERR_CANT_CHANGE_SNDBUF_SIZE_WITHOUT_DEL_PEER) = "Cannot change sndbuf-size without del-peer command. Please run the 'del-peer' command first and change the attribute value with adjust command \n",
	EM(ERR_VERIFY_NOT_RUNNING) = "Since verify is not running, it cannot be stopped.",
	// BSR-1064
	EM(ERR_VOL_LOCK_ACQUISITION_TIMEOUT) = "Failed due to timeout on volume lock acquisition. Please try the command again.",
};
#define MAX_ERROR (sizeof(error_messages)/sizeof(*error_messages))

const char * error_to_string(int err_no)
{
	const unsigned int idx = err_no - ERR_CODE_BASE;
	if (idx >= MAX_ERROR) return "Unknown... maybe API_VERSION mismatch?";
	return error_messages[idx];
}
#undef MAX_ERROR

char *cmdname = NULL; /* "bsrsetup" for reporting in usage etc. */

/*
 * In CTX_MINOR, CTX_RESOURCE, CTX_ALL, objname and minor refer to the object
 * the command operates on.
 */
char *objname;
unsigned minor = -1U;
struct bsr_cfg_context global_ctx;
enum cfg_ctx_key context;

int lock_fd;

struct genl_sock *bsr_sock = NULL;

struct genl_family bsr_genl_family = {
#ifdef _WIN    //  require a value over NLMSG_MIN_TYPE, and then a continuous nl command processing can be possiable.
    .id = NLMSG_MIN_TYPE + 1,
#endif
	.name = "bsr",
	.version = GENL_MAGIC_VERSION,
	.hdrsize = GENL_MAGIC_FAMILY_HDRSZ,
};

#if 0
/* currently unused. */
static bool endpoints_equal(struct bsr_cfg_context *a, struct bsr_cfg_context *b)
{
	return a->ctx_my_addr_len == b->ctx_my_addr_len &&
	       a->ctx_peer_addr_len == b->ctx_peer_addr_len &&
	       !memcmp(a->ctx_my_addr, b->ctx_my_addr, a->ctx_my_addr_len) &&
	       !memcmp(a->ctx_peer_addr, b->ctx_peer_addr, a->ctx_peer_addr_len);
}
#endif

static int conv_block_dev(struct bsr_argument *ad, struct msg_buff *msg,
			  struct bsr_genlmsghdr *dhdr, char* arg)
{
	struct stat sb;
	int device_fd;

#ifdef _WIN
    nla_put_string(msg, ad->nla_type, arg);
    return ERR_NO;
#endif

#ifdef _WIN
    //char *vol = "\\\\.\\Volume{606d8688-83b7-4625-8a41-3c5e39a3e618}";
    // char *buf = malloc(strlen(cfg->md_device_name) + 20); // additional space 20 bytes are enough
    char buf[1024];
    sprintf(buf, "\\\\.\\Volume{%s}", arg);
    arg = buf;
#endif
	if ((device_fd = open(arg,O_RDWR))==-1) {
		PERROR("Can not open device '%s'", arg);
		return OTHER_ERROR;
	}

	if (fstat(device_fd, &sb)) {
		PERROR("fstat(%s) failed", arg);
		return OTHER_ERROR;
	}

	if(!S_ISBLK(sb.st_mode)) {
		CLI_ERRO_LOG_STDERR(false, "%s is not a block device!", arg);
		return OTHER_ERROR;
	}

	close(device_fd);

	nla_put_string(msg, ad->nla_type, arg);

	return ERR_NO;
}

static int conv_md_idx(struct bsr_argument *ad, struct msg_buff *msg,
		       struct bsr_genlmsghdr *dhdr, char* arg)
{
	int idx;

	if(!strcmp(arg,"internal")) idx = BSR_MD_INDEX_FLEX_INT;
	else if(!strcmp(arg,"flexible")) idx = BSR_MD_INDEX_FLEX_EXT;
#ifdef _WIN_VHD_META_SUPPORT
	else if(strstr(arg,".vhd")) idx = BSR_MD_INDEX_FLEX_EXT;
#endif
#ifdef _LIN_LOOP_META_SUPPORT
	else if(strstr(arg,"/")) idx = BSR_MD_INDEX_FLEX_EXT;
#endif
	else idx = m_strtoll(arg,1);

	nla_put_u32(msg, ad->nla_type, idx);

	return ERR_NO;
}

static int conv_u32(struct bsr_argument *ad, struct msg_buff *msg,
		    struct bsr_genlmsghdr *dhdr, char* arg)
{
	unsigned int i = m_strtoll(arg, 1);

	nla_put_u32(msg, ad->nla_type, i);

	return ERR_NO;
}

static void resolv6(const char *name, struct sockaddr_in6 *addr)
{
	struct addrinfo hints, *res, *tmp;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(name, 0, &hints, &res);
	if (err) {
		CLI_ERRO_LOG_STDERR(false, "getaddrinfo %s: %s", name, gai_strerror(err));
		exit(20);
	}

	/* Yes, it is a list. We use only the first result. The loop is only
	 * there to document that we know it is a list */
	for (tmp = res; tmp; tmp = tmp->ai_next) {
		memcpy(addr, tmp->ai_addr, sizeof(*addr));
		break;
	}
	freeaddrinfo(res);
	if (false) { /* debug output */
		char ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr->sin6_addr, ip, sizeof(ip));
		CLI_ERRO_LOG_STDERR(false, "%s -> %02x %04x %08x %s %08x",
				name,
				addr->sin6_family,
				addr->sin6_port,
				addr->sin6_flowinfo,
				ip,
				addr->sin6_scope_id);
	}
}

static unsigned long resolv(const char* name)
{
	unsigned long retval;

	if((retval = inet_addr(name)) == INADDR_NONE ) {
		struct hostent *he;
		he = gethostbyname(name);
		if (!he) {
			CLI_ERRO_LOG_STDERR(false, "can not resolve the hostname: gethostbyname(%s): %s",
					name, hstrerror(h_errno));
			exit(20);
		}
		retval = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
	}
	return retval;
}

#ifdef _WIN
#include <ifaddrs.h>
// BSR-1057 verify that the specified address has the same address locally.
static bool is_adapter_ip_addr(const char* address)
{
	char host[NI_MAXHOST];
	struct ifaddrs *ifaddr, *ifa;
	int s;
	if (getifaddrs(&ifaddr) < 0) {
		CLI_ERRO_LOG(false, true, "error %s", __FUNCTION__);
		exit(20);
	}
	memset(host, 0, sizeof(host));
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		s = getnameinfo(ifa->ifa_addr, (ifa->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (s != 0) {
			CLI_ERRO_LOG(false, true, "getnameinfo() failed: %s", gai_strerror(s));
			freeifaddrs(ifaddr);
			exit(20);
		}

		if (0 == strcmp(address, host)) {
			CLI_INFO_LOG(false, "found adater (%s), address (%s)", ifa->ifa_name, host);
			return true;
		}
	}
	freeifaddrs(ifaddr);
	return false;
}

static void scope_id_from_alias_to_index(const char* scopeId, char **address, bool *re_alloc)
{
	NET_LUID interfaceLuid;
	NET_IFINDEX ifindex = 0;
	char ifindex_str[32] = { 0, };
	wchar_t* scopeId_w;
	int len;

	len = mbstowcs(NULL, scopeId, 0);
	if (len != -1) {
		scopeId_w = (LPWSTR)malloc(sizeof(wchar_t) * (len + 1));
		if (scopeId_w) {
			if (-1 != mbstowcs(scopeId_w, scopeId, (len + 1))) {
				if ((NO_ERROR == ConvertInterfaceAliasToLuid(scopeId_w, &interfaceLuid)) &&
					(NO_ERROR == ConvertInterfaceLuidToIndex(&interfaceLuid, &ifindex))) {

					// BSR-1057
					wchar_t alias_w[IF_MAX_STRING_SIZE + 1];
					
					memset(alias_w, 0, sizeof(alias_w));
					
					if (NO_ERROR == ConvertInterfaceLuidToAlias(&interfaceLuid, alias_w, IF_MAX_STRING_SIZE + 1)) {
						if (0 != wcscmp(scopeId_w, alias_w)) {
							CLI_ERRO_LOG(false, true, "failed to find alias corresponding to scope id (%s)", scopeId);
							exit(20);
						}
					} else {
						CLI_ERRO_LOG(false, true, "failed to luid to alias (%s)", scopeId);
						exit(20);
					}

					// BSR-1002 set to the index corresponding to the alias.
					sprintf(ifindex_str, "%d", ifindex);
					CLI_INFO_LOG(false, "matching aliases found, (%s => %s)", scopeId, ifindex_str);
					if (strlen(scopeId) <= strlen(ifindex_str)) {
						char *addr_new = (char*)calloc(strlen(*address) + strlen(ifindex_str) + 1, sizeof(char));
						if (addr_new) {
							memcpy(addr_new, *address, strlen(*address));
							free(*address);
							*address = addr_new;
							*re_alloc = true;
							scopeId = strrchr(*address, '%');
							scopeId++;
							memcpy(scopeId, ifindex_str, strlen(ifindex_str) + 1);
						}
						else {
							CLI_ERRO_LOG(false, true, "failed to allocate address, size is %d", (strlen(*address) + strlen(ifindex_str) + 1) * sizeof(char));
							exit(20);
						}
					}
					else {
						memset(scopeId, 0, strlen(ifindex_str) + 1);
						memcpy(scopeId, ifindex_str, strlen(ifindex_str));
					}
				}
				else {
					CLI_INFO_LOG(false, "no matching aliases found, (%s)", scopeId);
				}
			}
			else {
				CLI_ERRO_LOG(false, true, "failed to convert to multi-byte, (%s)", scopeId);
				exit(20);
			}
			free(scopeId_w);
		}
		else {
			CLI_ERRO_LOG(false, true, "failed to allocate scope id, size is %d", (sizeof(wchar_t) * len + 1));
			exit(20);
		}
	}
	else {
		CLI_ERRO_LOG(false, true, "failed to get multi-byte size, (%s)", scopeId);
		exit(20);
	}
}

#endif

static void split_ipv6_addr(char **address, int *port, bool *re_alloc, bool is_peer)
{
	// BSR-1002
	char *scopeId = NULL;
	/* ipv6:[fe80::0234:5678:9abc:def1]:8000; */
	char *b = strrchr(*address,']');
	if (address[0][0] != '[' || b == NULL ||
		(b[1] != ':' && b[1] != '\0')) {
		CLI_ERRO_LOG_STDERR(false, "unexpected ipv6 format: %s",
				*address);
		exit(20);
	}

	*b = 0;
	*address += 1; /* skip '[' */
	*re_alloc = false;

	if (b[1] == ':')
		*port = m_strtoll(b + 2, 1); /* b+2: "]:" */
	else
		*port = 7788; /* will we ever get rid of that default port? */

	scopeId = strrchr(*address, '%');

	// BSR-1018 fix exception
	if (!scopeId) {
		// unique local address
		return;
	}
	
	// BSR-1026 remove scope_id if peer address
	if (is_peer) {
		*scopeId = 0;
	}
#ifdef _WIN
	else {
		// BSR-1002 bsr uses the alias as the default for ipv6 link-local
		// BSR-1057
		if (!is_adapter_ip_addr(*address)) {
			scopeId++;
			scope_id_from_alias_to_index(scopeId, address, re_alloc);
		}
	}
#endif
}

static char* split_address(int *af, char** address, int* port, bool is_peer)
{
	static struct { char* text; int af; } afs[] = {
		{ "ipv4:", AF_INET  },
		{ "ipv6:", AF_INET6 },
		{ "sdp:",  AF_INET_SDP },
		{ "ssocks:",  -1 },
	};

	unsigned int i;
	char *b;
	char *a = *address;

	*af=AF_INET;
	for (i=0; i<ARRAY_SIZE(afs); i++) {
		if (!strncmp(*address, afs[i].text, strlen(afs[i].text))) {
			*af = afs[i].af;
			*address += strlen(afs[i].text);
			break;
		}
	}

	if (*af == AF_INET6 && address[0][0] == '[') {
		// BSR-1002
		bool re_alloc = false;
		split_ipv6_addr(address, port, &re_alloc, is_peer);
		if (re_alloc)
			return *address;
		else
			return a;
	}

	if (*af == -1)
		*af = get_af_ssocks(1);

	b=strrchr(*address,':');
	if (b) {
		*b = 0;
		if (*af == AF_INET6) {
			/* compatibility handling of ipv6 addresses,
			 * in the style expected before bsr 8.3.9.
			 * may go wrong without explicit port */
			CLI_ERRO_LOG_STDERR(false, "interpreting ipv6:%s:%s as ipv6:[%s]:%s",
					*address, b+1, *address, b+1);
		}
		*port = m_strtoll(b+1,1);
	} else
		*port = 7788;

	return a;
}

static int sockaddr_from_str(struct sockaddr_storage *storage, const char *str, bool is_peer)
{
	int af, port;
	char *address = strdup(str);
	// BSR-1002 
	char *release_to = split_address(&af, &address, &port, is_peer);
	if (af == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)storage;

		memset(sin6, 0, sizeof(*sin6));
		resolv6(address, sin6);
		sin6->sin6_port = htons(port);
		// BSR-1002
		free(release_to);
		/* sin6->sin6_len = sizeof(*sin6); */
		return sizeof(*sin6);
	} else {
		/* AF_INET, AF_SDP, AF_SSOCKS,
		 * all use the IPv4 addressing scheme */
		struct sockaddr_in *sin = (struct sockaddr_in *)storage;

		memset(sin, 0, sizeof(*sin));
		sin->sin_port = htons(port);
		sin->sin_family = af;
		sin->sin_addr.s_addr = resolv(address);
		// BSR-1002
		free(release_to);
		return sizeof(*sin);
	}

	// BSR-1002
	free(release_to);
	return 0;
}

static int conv_addr(struct bsr_argument *ad, struct msg_buff *msg,
			  struct bsr_genlmsghdr *dhdr, char* arg)
{
	struct sockaddr_storage x;
	int addr_len;
	bool is_peer = false;

	if (strncmp(arg, "local:", 6) == 0)
		arg += 6;
	else if (strncmp(arg, "peer:", 5) == 0)
		arg += 5;

	// BSR-1026
	is_peer = (strcmp(ad->name, "remote-addr") == 0);
	addr_len = sockaddr_from_str(&x, arg, is_peer);
	
	if (addr_len == 0) {
		CLI_ERRO_LOG_STDERR(false, "does not look like an endpoint address '%s'", arg);
		return OTHER_ERROR;
	}

	nla_put(msg, ad->nla_type, addr_len, &x);
	return ERR_NO;
}


/* It will only print the WARNING if the warn flag is set
   with the _first_ call! */
#define PROC_NET_AF_SCI_FAMILY "/proc/net/af_sci/family"
#define PROC_NET_AF_SSOCKS_FAMILY "/proc/net/af_ssocks/family"

static int get_af_ssocks(int warn_and_use_default)
{
	char buf[16];
	int c, fd;
	static int af = -1;

	if (af > 0)
		return af;

	fd = open(PROC_NET_AF_SSOCKS_FAMILY, O_RDONLY);

	if (fd < 0)
		fd = open(PROC_NET_AF_SCI_FAMILY, O_RDONLY);

	if (fd < 0) {
		if (warn_and_use_default) {
			CLI_ERRO_LOG_STDERR(false, "open(" PROC_NET_AF_SSOCKS_FAMILY ") "
				"failed: %m\n WARNING: assuming AF_SSOCKS = 27. "
				"Socket creation may fail.\n");
			af = 27;
		}
		return af;
	}
	c = read(fd, buf, sizeof(buf)-1);
	if (c > 0) {
		buf[c] = 0;
		if (buf[c-1] == '\n')
			buf[c-1] = 0;
		af = m_strtoll(buf,1);
	} else {
		if (warn_and_use_default) {
			CLI_ERRO_LOG_STDERR(false, "read(" PROC_NET_AF_SSOCKS_FAMILY ") "
				"failed: %m\n WARNING: assuming AF_SSOCKS = 27. "
				"Socket creation may fail.\n");
			af = 27;
		}
	}
	close(fd);
	return af;
}

static struct option *make_longoptions(struct bsr_cmd *cm)
{
	static struct option buffer[47];
	int i = 0;
	int primary_force_index = -1;
	int connect_tentative_index = -1;

	if (cm->ctx) {
		struct field_def *field;

		/*
		 * Make sure to keep cm->ctx->fields first: we use the index
		 * returned by getopt_long() to access cm->ctx->fields.
		 */
		for (field = cm->ctx->fields; field->name; field++) {
			assert(i < ARRAY_SIZE(buffer));
			buffer[i].name = field->name;
			buffer[i].has_arg = field->argument_is_optional ?
				optional_argument : required_argument;
			buffer[i].flag = NULL;
			buffer[i].val = 0;
			if (!strcmp(cm->cmd, "primary") && !strcmp(field->name, "force"))
				primary_force_index = i;
			if (!strcmp(cm->cmd, "connect") && !strcmp(field->name, "tentative"))
				connect_tentative_index = i;
			i++;
		}
		assert(field - cm->ctx->fields == i);
	}

	if (cm->options) {
		struct option *option;

		for (option = cm->options; option->name; option++) {
			assert(i < ARRAY_SIZE(buffer));
			buffer[i] = *option;
			i++;
		}
	}

	if (primary_force_index != -1) {
		/*
		 * For backward compatibility, add --overwrite-data-of-peer as
		 * an alias to --force.
		 */
		assert(i < ARRAY_SIZE(buffer));
		buffer[i] = buffer[primary_force_index];
		buffer[i].name = "overwrite-data-of-peer";
		buffer[i].val = 1000 + primary_force_index;
		i++;
	}

	if (connect_tentative_index != -1) {
		/*
		 * For backward compatibility, add --dry-run as an alias to
		 * --tentative.
		 */
		assert(i < ARRAY_SIZE(buffer));
		buffer[i] = buffer[connect_tentative_index];
		buffer[i].name = "dry-run";
		buffer[i].val = 1000 + connect_tentative_index;
		i++;
	}

	if (cm->set_defaults) {
		assert(i < ARRAY_SIZE(buffer));
		buffer[i].name = "set-defaults";
		buffer[i].has_arg = 0;
		buffer[i].flag = NULL;
		buffer[i].val = '(';
		i++;
	}

	assert(i < ARRAY_SIZE(buffer));
	buffer[i].name = NULL;
	buffer[i].has_arg = 0;
	buffer[i].flag = NULL;
	buffer[i].val = 0;

	return buffer;
}

/* prepends global objname to output (if any) */
static int check_error(int err_no, char *desc)
{
	int rv = 0;

	if (err_no == ERR_NO || err_no == SS_SUCCESS)
		return 0;

	if (err_no == OTHER_ERROR) {
		if (desc) {
			CLI_ERRO_LOG_STDERR(false, "%s: %s", objname, desc);
		}
		return 20;
	}

	if ( ( err_no >= AFTER_LAST_ERR_CODE || err_no <= ERR_CODE_BASE ) &&
	     ( err_no > SS_CW_NO_NEED || err_no <= SS_AFTER_LAST_ERROR) ) {
		CLI_ERRO_LOG_STDERR(false, "%s: Error code %d unknown."
			"You should update the bsr userland tools.\n",
			objname, err_no);
		rv = 20;
	} else {
		if(err_no > ERR_CODE_BASE ) {
			CLI_ERRO_LOG_STDERR(false, "%s: Failure: (%d) %s",
				objname, err_no, desc ?: error_to_string(err_no));
			rv = 10;
		} else if (err_no == SS_UNKNOWN_ERROR) {
			CLI_ERRO_LOG_STDERR(false, "%s: State change failed: (%d)"
				"unknown error.\n", objname, err_no);
			rv = 11;
		} else if (err_no > SS_TWO_PRIMARIES) {
			// Ignore SS_SUCCESS, SS_NOTHING_TO_DO, SS_CW_Success...
		} else {
			CLI_ERRO_LOG_STDERR(false, "%s: State change failed: (%d) %s",
				objname, err_no, bsr_set_st_err_str(err_no));
			if (err_no == SS_NO_UP_TO_DATE_DISK) {
				/* all available disks are inconsistent,
				 * or I am consistent, but cannot outdate the peer. */
				rv = 17;
			} else if (err_no == SS_LOWER_THAN_OUTDATED) {
				/* was inconsistent anyways */
				rv = 5;
			} else if (err_no == SS_NO_LOCAL_DISK) {
				/* Can not start resync, no local disks, try with bsrmeta */
				rv = 16;
			}
			// DW-1626 Other programs use these return value. Return -SS_BARRIER_ACK_PENDING_TIMEOUT.
			else if (err_no == SS_BARRIER_ACK_PENDING_TIMEOUT){
				rv = -SS_BARRIER_ACK_PENDING_TIMEOUT; 
			}
			else {
				rv = 11;
			}
		}
	}
	if (global_attrs[BSR_NLA_CFG_REPLY] &&
	    global_attrs[BSR_NLA_CFG_REPLY]->nla_len) {
		struct nlattr *nla;
		int rem;
		CLI_ERRO_LOG_STDERR(false, "additional info from kernel:");
		nla_for_each_nested(nla, global_attrs[BSR_NLA_CFG_REPLY], rem) {
			if (nla_type(nla) == __nla_type(T_info_text))
				CLI_ERRO_LOG_STDERR(false, "%s", (char*)nla_data(nla));
		}
	}
	return rv;
}

static void warn_print_excess_args(int argc, char **argv, int i)
{
	CLI_ERRO_LOG_STDERR(false, "Excess arguments:");
	for (; i < argc; i++)
		CLI_ERRO_LOG_STDERR(false, " %s", argv[i]);
	printf("\n");
}

int bsr_tla_parse(struct nlmsghdr *nlh)
{
	return nla_parse(global_attrs, ARRAY_SIZE(bsr_tla_nl_policy)-1,
		nlmsg_attrdata(nlh, GENL_HDRLEN + bsr_genl_family.hdrsize),
		nlmsg_attrlen(nlh, GENL_HDRLEN + bsr_genl_family.hdrsize),
		bsr_tla_nl_policy);
}

#define ASSERT(exp) if (!(exp)) \
		CLI_ERRO_LOG_STDERR(false, "ASSERT( " #exp " ) in %s:%d", __FILE__,__LINE__);


#ifdef _LIN
// BSR-823 run filesystem check command
int run_check_fs(char **argv, pid_t *kid, int *fd, char *output_file)
{
	pid_t pid;
	int status, rv = -1;

	fflush(stdout);
	fflush(stderr);

	pid = fork();
	
	if (pid == -1) {
		CLI_ERRO_LOG_STDERR(false,  "Can not fork");
		exit(20);
	}
	if (pid == 0) {
		FILE *f_out;
		prctl(PR_SET_PDEATHSIG, SIGKILL);

		f_out = freopen(output_file, "w", stdout);
		if (!f_out) {
			CLI_ERRO_LOG_STDERR(false,  "reopen stdout to %s failed", output_file);
			exit(20);
		}

		dup2(fileno(stdout), fileno(stderr));

		if (argv[0]) {
			execvp(argv[0], argv);
		}
		CLI_ERRO_LOG_STDERR(false,  "Can not exec %s", argv[0]);
		exit(20);
	}

	if (kid)
		*kid = pid;

	while (1) {
		if (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR)
				break;
		} else {
			if (WIFEXITED(status)) {
				rv = WEXITSTATUS(status);
				break;
			}
		}
	}

	fflush(stdout);
	fflush(stderr);

	return rv;
}

// BSR-747
static int need_filesystem_recovery(char * dev_name)
{
	char cmd[256], buf[1024];
	int ret = 0;
	int fast_sync = 0;
	FILE *fp;
	bool journal_recovery = false;
	bool xfs_fs = false;
	char *argv[] = { NULL, NULL, NULL, NULL };
	char  *n_dev_name, *ptr;
	char fs_check_log[256];
	char journal_check_log[256];

	// check fast sync settings
	fp = fopen("/etc/bsr.d/.use_fast_sync", "r");

	if (fp) {
		ret = fscanf(fp, "%d", &fast_sync);	
		fclose(fp);

		// if full sync, skip filesystem check
		if (ret == 1 && !fast_sync)
			return 0;
	} 
	memset(cmd, 0, sizeof(cmd));	
	sprintf(cmd, "blkid -o value -s TYPE %s", dev_name);

	// get filesystem type
	fp = popen(cmd, "r");
	if (!fp) 
		return 0;

	memset(buf, 0, sizeof(buf));
	if (!fgets(buf, sizeof(buf), fp)) {
		pclose(fp);
		return 0;
	}
	pclose(fp);

	if (!strncmp(buf, "xfs", 3))
		xfs_fs = true;
	else if (!strncmp(buf, "ext", 3))
		xfs_fs = false;
	else
		return 0;

	// convert dev_name for use in log file names
	// ex) /dev/sdb1 -> _dev_sdb1
	n_dev_name = calloc(strlen(dev_name) + 1, sizeof(char));
	if (!n_dev_name)
		return 0;

	strcpy(n_dev_name, dev_name);
	ptr = strchr(n_dev_name, '/');
	while (ptr != NULL) {
		*ptr = '_';
		ptr = strchr(ptr + 1, '/');
	}
	
	memset(journal_check_log, 0, sizeof(journal_check_log));	
	memset(fs_check_log, 0, sizeof(fs_check_log));
	if (xfs_fs) {
		sprintf(journal_check_log, "/var/log/bsr/xfs_logprint%s.log", n_dev_name);
		sprintf(fs_check_log, "/var/log/bsr/xfs_repair%s.log", n_dev_name);
	} else {
		sprintf(journal_check_log, "/var/log/bsr/tune2fs%s.log", n_dev_name);
		sprintf(fs_check_log, "/var/log/bsr/fsck%s.log", n_dev_name);
	}

	free(n_dev_name);

	// remove old log files
	remove(journal_check_log);
	remove(fs_check_log);


	/*
	* start file system check
	*/

	// 1. Check if journal recovery is required.	
	if (xfs_fs) {
		argv[0] = "xfs_logprint";
		argv[1] = "-t";
	} else {
		argv[0] = "tune2fs";
		argv[1] = "-l";
	}
	argv[2] = dev_name;
	ret = run_check_fs(argv, NULL, NULL, journal_check_log);

	if (ret != 0) {
		CLI_ERRO_LOG_STDERR(false, "'%s' exits with error (%d)", cmd, ret);
		return 1;
	}

	memset(buf, 0, sizeof(buf));
	fp = fopen(journal_check_log, "r");
	if (!fp) {
		CLI_ERRO_LOG_STDERR(false, "could not read '%s'", argv[0]);
		return 1;
	}

	if (xfs_fs) {
		while (fgets(buf, sizeof(buf), fp)) {
			/**
			* check xfs log state. if <DIRTY>, journal recovery is required.
			* ex 1) log tail: 26 head: 32 state: <DIRTY>
			* ex 2) log tail: 2 head: 2 state: <CLEAN>
			*/
			if (strstr(buf, "log tail:") != NULL) {
				if (strstr(buf, "<DIRTY>") != NULL)
					journal_recovery = true;
				break;
			}
		}
	}
	else {
		// BSR-821 for ext filesystems
		while (fgets(buf, sizeof(buf), fp)) {
			// check filesystem features. if needs_recovery is set, journal recovery is required.
			if (strstr(buf, "Filesystem features:") != NULL) {
				if (strstr(buf, "needs_recovery") != NULL)
					journal_recovery = true;
				break;
			}
		}
	}

	fclose(fp);
	if (journal_recovery) {
		CLI_ERRO_LOG_STDERR(false, "%s: needs journal recovery", dev_name);
		return 1;
	}
	
	// 2. Check if filesystem recovery is required.
	memset(argv, 0, sizeof(argv));

	if (xfs_fs) {
		argv[0] = "xfs_repair";
	} else {
		argv[0] = "fsck";
	}
	argv[1] = "-n";
	argv[2] = dev_name;
	ret = run_check_fs(argv, NULL, NULL, fs_check_log);

	if (ret == -1 || ret == 127) {
		CLI_ERRO_LOG_STDERR(false,
			"could not be executed '%s'", cmd);
	}
	else if (ret != 0) {
		CLI_ERRO_LOG_STDERR(false, "%s: Filesystem has errors", dev_name);
	}

	return ret;
}
#endif

static int _generic_config_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct bsr_argument *ad;
	struct nlattr *nla;
	struct option *options;
	int c, i;
	int rv;
	char *desc = NULL; /* error description from kernel reply message */

	struct bsr_genlmsghdr *dhdr;
	struct msg_buff *smsg;
	struct iovec iov;
	struct nlmsghdr *nlh;
	struct bsr_genlmsghdr *dh;
	struct timespec retry_timeout = {
		.tv_nsec = 62500000L,  /* 1/16 second */
	};

	/* pre allocate request message and reply buffer */
	iov.iov_len = DEFAULT_MSG_SIZE;
	iov.iov_base = malloc(iov.iov_len);
	smsg = msg_new(DEFAULT_MSG_SIZE);
	if (!smsg || !iov.iov_base) {
		desc = "could not allocate netlink messages";
		rv = OTHER_ERROR;
		goto error;
	}
	nlh = (struct nlmsghdr*)iov.iov_base;
	dh = genlmsg_data(nlmsg_data(nlh));

	dhdr = genlmsg_put(smsg, &bsr_genl_family, 0, cm->cmd_id);
	dhdr->minor = -1;
	dhdr->flags = 0;

	if (context & CTX_MINOR)
		dhdr->minor = minor;

	if (context & ~CTX_MINOR) {
		nla = nla_nest_start(smsg, BSR_NLA_CFG_CONTEXT);
		if (context & CTX_RESOURCE)
			nla_put_string(smsg, T_ctx_resource_name, objname);
		if (context & CTX_PEER_NODE_ID)
			nla_put_u32(smsg, T_ctx_peer_node_id, global_ctx.ctx_peer_node_id);
		if (context & CTX_VOLUME)
			nla_put_u32(smsg, T_ctx_volume, global_ctx.ctx_volume);
		nla_nest_end(smsg, nla);
	}

	nla = NULL;

	options = make_longoptions(cm);
	optind = 0;  /* reset getopt_long() */
	for (;;) {
		int idx;

		c = getopt_long(argc, argv, "(", options, &idx);
		if (c == -1)
			break;
		if (c >= 1000) {
			/* This is a field alias. */
			idx = c - 1000;
			c = 0;
		}
		if (c == 0) {
			struct field_def *field = &cm->ctx->fields[idx];
			assert (field->name == options[idx].name);
			if (!nla) {
				assert (cm->tla_id != NO_PAYLOAD);
				nla = nla_nest_start(smsg, cm->tla_id);
			}
			if (!field->ops->put(cm->ctx, field, smsg, optarg)) {
				CLI_ERRO_LOG_STDERR(false, "Option --%s: invalid "
					"argument '%s'\n",
					field->name, optarg);
				rv = OTHER_ERROR;
				goto error;
			}


		} else if (c == '(')
			dhdr->flags |= BSR_GENL_F_SET_DEFAULTS;
		else {
			rv = OTHER_ERROR;
			goto error;
		}
	}

	for (i = optind, ad = cm->bsr_args; ad && ad->name; i++) {
		if (argc < i + 1) {
			CLI_ERRO_LOG_STDERR(false, "Missing argument '%s'", ad->name);
			print_command_usage(cm, FULL);
			rv = OTHER_ERROR;
			goto error;
		}
		if (!nla) {
			assert (cm->tla_id != NO_PAYLOAD);
			nla = nla_nest_start(smsg, cm->tla_id);
		}
		rv = ad->convert_function(ad, smsg, dhdr, argv[i]);
		if (rv != ERR_NO)
			goto error;
		ad++;
	}
	/* dhdr->minor may have been set by one of the convert functions. */
	minor = dhdr->minor;

	if (nla)
		nla_nest_end(smsg, nla);

	/* argc should be cmd + n options + n args;
	 * if it is more, we did not understand some */
	if (i < argc) {
		warn_print_excess_args(argc, argv, i);
		rv = OTHER_ERROR;
		goto error;
	}

	for(;;) {
		if (genl_send(bsr_sock, smsg)) {
			desc = "error sending config command";
			rv = OTHER_ERROR;
			goto error;
		}
		do {
			int received;

			/* reduce timeout! limit retries */
			received = genl_recv_msgs(bsr_sock, &iov, &desc, 120000);
			if (received <= 0) {
				if (received == -E_RCV_ERROR_REPLY && !errno)
					continue;
				if (!desc)
					desc = "error receiving config reply";
				rv = OTHER_ERROR;
				goto error;
			}
		} while (false);
		ASSERT(dh->minor == minor);
		rv = dh->ret_code;
		if (rv != SS_IN_TRANSIENT_STATE)
			break;
		nanosleep(&retry_timeout, NULL);
		/* Double the timeout, up to 10 seconds. */
		if (retry_timeout.tv_sec < 10) {
			retry_timeout.tv_sec *= 2;
			retry_timeout.tv_nsec *= 2;
			if (retry_timeout.tv_nsec > 1000000000L) {
				retry_timeout.tv_sec++;
				retry_timeout.tv_nsec -= 1000000000L;
			}
		}
	}
	if (rv == ERR_RES_NOT_KNOWN) {
		if (cm->warn_on_missing && isatty(STDERR_FILENO))
			CLI_ERRO_LOG_STDERR(false, "Resource unknown");

		if (cm->missing_ok)
			rv = ERR_NO;
	}
	bsr_tla_parse(nlh);

error:
	msg_free(smsg);

	rv = check_error(rv, desc);
	free(iov.iov_base);
	return rv;
}

static int generic_config_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	return _generic_config_cmd(cm, argc, argv);
}

static int del_minor_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	int rv;

	rv = generic_config_cmd(cm, argc, argv);
	if (!rv)
		unregister_minor(minor);
	return rv;
}

static int del_resource_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	int rv;

	rv = generic_config_cmd(cm, argc, argv);
	if (!rv)
		unregister_resource(objname);
	return rv;
}

static struct bsr_cmd *find_cmd_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!strcmp(name, commands[i].cmd)) {
			return commands + i;
		}
	}
	return NULL;
}

static void print_options(struct nlattr *attr, struct context_def *ctx, const char *sect_name)
{
	struct field_def *field;
	int opened = 0;

	if (!attr)
		return;

	if (bsr_nla_parse_nested(nested_attr_tb, ctx->nla_policy_size - 1,
				  attr, ctx->nla_policy)) {
		CLI_ERRO_LOG_STDERR(false, "nla_policy violation for %s payload!", sect_name);
		/* still, print those that validated ok */
	}

	for (field = ctx->fields; field->name; field++) {
		struct nlattr *nlattr;
		const char *str;
		bool is_default;

		nlattr = ntb(field->nla_type);
		if (!nlattr)
			continue;

		// BSR-859 skip, output in another section
		// node-name is output in the _this_host section
		// peer-node-name is output in the connection section
		if (!strcmp(field->name, "peer-node-name") || !strcmp(field->name, "node-name"))
			continue;
		str = field->ops->get(ctx, field, nlattr);
		is_default = field->ops->is_default(field, str);
		if (is_default && !show_defaults)
			continue;
		if (!opened) {
			opened=1;
			printI("%s {\n",sect_name);
			++indent;
		}
		if (field->needs_double_quoting)
			str = double_quote_string(str);
		printI("%-16s\t%s;",field->name, str);
		if (field->unit || is_default) {
				printf(" # ");
			if (field->unit)
				printf("%s", field->unit);
			if (field->unit && is_default)
				printf(", ");
			if (is_default)
				printf("default");
		}
		printf("\n");
	}
	if(opened) {
		--indent;
		printI("}\n");
	}
}

struct choose_timeout_ctx {
	struct bsr_cfg_context ctx;
	struct msg_buff *smsg;
	struct iovec *iov;
	int timeout;
	int wfc_timeout;
	int degr_wfc_timeout;
	int outdated_wfc_timeout;
};

int choose_timeout(struct choose_timeout_ctx *ctx)
{
	char *desc = NULL;
	struct bsr_genlmsghdr *dhdr;
	struct nlattr *nla;
	int rr;

	if (0 < ctx->wfc_timeout &&
	      (ctx->wfc_timeout < ctx->degr_wfc_timeout || ctx->degr_wfc_timeout == 0)) {
		ctx->degr_wfc_timeout = ctx->wfc_timeout;
		CLI_ERRO_LOG_STDERR(false, "degr-wfc-timeout has to be shorter than wfc-timeout"
				"degr-wfc-timeout implicitly set to wfc-timeout (%ds)\n",
				ctx->degr_wfc_timeout);
	}

	if (0 < ctx->degr_wfc_timeout &&
	    (ctx->degr_wfc_timeout < ctx->outdated_wfc_timeout || ctx->outdated_wfc_timeout == 0)) {
		ctx->outdated_wfc_timeout = ctx->wfc_timeout;
		CLI_ERRO_LOG_STDERR(false, "outdated-wfc-timeout has to be shorter than degr-wfc-timeout"
				"outdated-wfc-timeout implicitly set to degr-wfc-timeout (%ds)\n",
				ctx->degr_wfc_timeout);
	}
	dhdr = genlmsg_put(ctx->smsg, &bsr_genl_family, 0, BSR_ADM_GET_TIMEOUT_TYPE);
	dhdr->minor = -1;
	dhdr->flags = 0;

	nla = nla_nest_start(ctx->smsg, BSR_NLA_CFG_CONTEXT);
	nla_put_string(ctx->smsg, T_ctx_resource_name, ctx->ctx.ctx_resource_name);
	nla_put_u32(ctx->smsg, T_ctx_peer_node_id, ctx->ctx.ctx_peer_node_id);
	nla_put_u32(ctx->smsg, T_ctx_volume, ctx->ctx.ctx_volume);
	nla_nest_end(ctx->smsg, nla);

	if (genl_send(bsr_sock, ctx->smsg)) {
		desc = "error sending config command";
		goto error;
	}

	rr = genl_recv_msgs(bsr_sock, ctx->iov, &desc, 120000);
	if (rr > 0) {
		struct nlmsghdr *nlh = (struct nlmsghdr*)ctx->iov->iov_base;
		struct genl_info info = {
			.seq = nlh->nlmsg_seq,
			.nlhdr = nlh,
			.genlhdr = nlmsg_data(nlh),
			.userhdr = genlmsg_data(nlmsg_data(nlh)),
			.attrs = global_attrs,
		};
		struct bsr_genlmsghdr *dh = info.userhdr;
		struct timeout_parms parms;
		rr = dh->ret_code;
		if (rr == ERR_MINOR_INVALID) {
			desc = "minor not available";
			goto error;
		}
		if (rr != ERR_NO)
			goto error;
		if (bsr_tla_parse(nlh)
		|| timeout_parms_from_attrs(&parms, &info)) {
			desc = "reply did not validate - "
				"do you need to upgrade your userland tools?";
			goto error;
		}
		rr = parms.timeout_type;
		ctx->timeout =
			(rr == UT_DEGRADED) ? ctx->degr_wfc_timeout :
			(rr == UT_PEER_OUTDATED) ? ctx->outdated_wfc_timeout :
			ctx->wfc_timeout;
		return 0;
	}
error:
	if (!desc)
		desc = "error receiving netlink reply";
	CLI_ERRO_LOG_STDERR(false, "error determining which timeout to use: %s",
			desc);
	return 20;
}

#include <sys/utsname.h>
static bool kernel_older_than(int version, int patchlevel, int sublevel)
{
	struct utsname utsname;
	char *rel;
	int l;
#ifdef _WIN_CLI_UPDATE
	// DW-1210 Not required on Windows OS
	return true; 
#endif
	if (uname(&utsname) != 0)
		return false;
	rel = utsname.release;
	l = strtol(rel, &rel, 10);
	if (l > version)
		return false;
	else if (l < version || *rel == 0)
		return true;
	l = strtol(rel + 1, &rel, 10);
	if (l > patchlevel)
		return false;
	else if (l < patchlevel || *rel == 0)
		return true;
	l = strtol(rel + 1, &rel, 10);
	if (l >= sublevel)
		return false;
	return true;
}

static int shortest_timeout(struct peer_devices_list *peer_devices)
{
	struct peer_devices_list *peer_device;
	int timeout = -1;

	/* There is no point waiting for peers I do not even know about. */
	if (peer_devices == NULL)
		return 1;
	
	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
		if (peer_device->timeout_ms > 0 &&
		    (peer_device->timeout_ms < timeout || timeout == -1))
			timeout = peer_device->timeout_ms;
	}

	return timeout;
}

static bool update_timeouts(struct peer_devices_list *peer_devices, int elapsed)
{
	struct peer_devices_list *peer_device;
	bool all_expired = true;

	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
		if (peer_device->timeout_ms != -1) {
			peer_device->timeout_ms -= elapsed;
			if (peer_device->timeout_ms < 0)
				peer_device->timeout_ms = 0;
		}
		if (peer_device->timeout_ms != 0)
			all_expired = false;
	}

	return all_expired;
}

static bool parse_color_argument(void)
{
	if (!optarg || !strcmp(optarg, "always"))
		opt_color = ALWAYS_COLOR;
	else if (!strcmp(optarg, "never"))
		opt_color = NEVER_COLOR;
	else if (!strcmp(optarg, "auto"))
		opt_color = AUTO_COLOR;
	else
		return 0;
	return 1;
}

static bool opt_now;
static bool opt_poll;
static bool opt_verbose;
static bool opt_statistics;
static bool opt_timestamps;

static int generic_get(struct bsr_cmd *cm, int timeout_arg, void *u_ptr)
{
	char *desc = NULL;
	struct bsr_genlmsghdr *dhdr;
	struct msg_buff *smsg;
	struct iovec iov;
	int timeout_ms, flags;
	int rv = ERR_NO;
	int err = 0;

	/* pre allocate request message and reply buffer */
	iov.iov_len = DEFAULT_MSG_SIZE;
	iov.iov_base = malloc(iov.iov_len);
	smsg = msg_new(DEFAULT_MSG_SIZE);
	if (!smsg || !iov.iov_base) {
		desc = "could not allocate netlink messages";
		rv = OTHER_ERROR;
		goto out;
	}

	if (cm->continuous_poll) {
#ifdef _LIN
		/* also always (try to) listen to nlctrl notify,
		* so we have a chance to notice rmmod.  */
		int id = GENL_ID_CTRL;
		setsockopt(bsr_sock->s_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			&id, sizeof(id));
#endif
		if (genl_join_mc_group(bsr_sock, "events") &&
		    !kernel_older_than(2, 6, 23)) {
			desc = "unable to join bsr events multicast group";
			rv = OTHER_ERROR;
			goto out2;
		}
	}

	flags = 0;
	if (minor == -1U)
		flags |= NLM_F_DUMP;
	dhdr = genlmsg_put(smsg, &bsr_genl_family, flags, cm->cmd_id);
	dhdr->minor = minor;
	dhdr->flags = 0;
	if (minor == -1U && strcmp(objname, "all")) {
		/* Restrict the dump to a single resource. */
		struct nlattr *nla;
		nla = nla_nest_start(smsg, BSR_NLA_CFG_CONTEXT);
		nla_put_string(smsg, T_ctx_resource_name, objname);
		nla_nest_end(smsg, nla);
	}

	if (genl_send(bsr_sock, smsg)) {
		desc = "error sending config command";
		rv = OTHER_ERROR;
		goto out2;
	}

	/* disable sequence number check in genl_recv_msgs */
	bsr_sock->s_seq_expect = 0;

	for (;;) {
		int received, ret;
		struct nlmsghdr *nlh;
		struct timeval before;
		struct pollfd pollfds[2] = {
			[0] = {
				.fd = 1,
				.events = POLLHUP,
			},
			[1] = {
				.fd = bsr_sock->s_fd,
				.events = POLLIN,
			},
		};

		gettimeofday(&before, NULL);

		timeout_ms =
			timeout_arg == MULTIPLE_TIMEOUTS ? shortest_timeout(u_ptr) : timeout_arg;

		ret = poll(pollfds, 2, timeout_ms);
		if (ret == 0) {
			err = 5;
			goto out2;
		}
		if (pollfds[0].revents == POLLERR || pollfds[0].revents == POLLHUP)
			goto out2;

		received = genl_recv_msgs(bsr_sock, &iov, &desc, -1);

		// BSR-699 fix potential segmentation fault
		nlh = (struct nlmsghdr *)iov.iov_base;

		if (received < 0) {
			switch(received) {
			case E_RCV_TIMEDOUT:
				err = 5;
				goto out2;
			case -E_RCV_FAILED:
				err = 20;
				goto out2;
			case -E_RCV_NO_SOURCE_ADDR:
				continue; /* ignore invalid message */
			case -E_RCV_SEQ_MISMATCH:
				/* we disabled it, so it should not happen */
				err = 20;
				goto out2;
			case -E_RCV_MSG_TRUNC:
				continue;
			case -E_RCV_UNEXPECTED_TYPE:
				continue;
			case -E_RCV_NLMSG_DONE:
				if (cm->continuous_poll)
					continue;
				err = cm->show_function(cm, NULL, u_ptr);
				if (err)
					goto out2;
				err = -*(int*)nlmsg_data(nlh);
				if (err &&
				    (err != ENODEV || !cm->missing_ok)) {
					CLI_ERRO_LOG_STDERR(false, "received netlink error reply: %s",
						strerror(err));
					err = 20;
				}
				goto out2;
			case -E_RCV_ERROR_REPLY:
				if (!errno) /* positive ACK message */
					continue;
				if (!desc)
					desc = strerror(errno);
				CLI_ERRO_LOG_STDERR(false, "received netlink error reply: %s",
					       desc);
				err = 20;
				goto out2;
			default:
				if (!desc)
					desc = "error receiving config reply";
				err = 20;
				goto out2;
			}
		}

		if (timeout_ms != -1) {
			struct timeval after;
			int elapsed_ms;
			bool exit;

			gettimeofday(&after, NULL);
			elapsed_ms =
				(after.tv_sec - before.tv_sec) * 1000 +
				(after.tv_usec - before.tv_usec) / 1000;

			if (timeout_arg == MULTIPLE_TIMEOUTS) {
				exit = update_timeouts(u_ptr, elapsed_ms);
			} else {
				timeout_ms -= elapsed_ms;
				exit = timeout_ms <= 0;
			}

			if (exit) {
				err = 5;
				goto out2;
			}
		}

		struct bsr_genlmsghdr *dh = genlmsg_data(nlmsg_data(nlh));
		struct genl_info info = (struct genl_info){
			.seq = nlh->nlmsg_seq,
			.nlhdr = nlh,
			.genlhdr = nlmsg_data(nlh),
			.userhdr = genlmsg_data(nlmsg_data(nlh)),
			.attrs = global_attrs,
		};

		dbg(3, "received type:%x\n", nlh->nlmsg_type);
		if (nlh->nlmsg_type < NLMSG_MIN_TYPE) {
			/* Ignore netlink control messages. */
			continue;
		}
		if (nlh->nlmsg_type == GENL_ID_CTRL) {
#ifdef HAVE_CTRL_CMD_DELMCAST_GRP
			dbg(3, "received cmd:%x\n", info.genlhdr->cmd);
			if (info.genlhdr->cmd == CTRL_CMD_DELMCAST_GRP) {
				struct nlattr *nla =
					nlmsg_find_attr(nlh, GENL_HDRLEN, CTRL_ATTR_FAMILY_ID);
				if (nla && nla_get_u16(nla) == bsr_genl_family.id) {
					/* FIXME: We could wait for the
						multicast group to be recreated ... */
					goto out2;
				}
			}
#endif
			/* Ignore other generic netlink control messages. */
			continue;
		}
		if (nlh->nlmsg_type != bsr_genl_family.id) {
			/* Ignore messages for all other netlink families. */
			continue;
		}

		/* parse early, otherwise bsr_cfg_context_from_attrs
			* can not work */
		if (bsr_tla_parse(nlh)) {
			/* FIXME
				* should continuous_poll continue?
				*/
			desc = "reply did not validate - "
				"do you need to upgrade your userland tools?";
			rv = OTHER_ERROR;
			goto out2;
		}
		if (cm->continuous_poll) {
			struct bsr_cfg_context ctx;
			/*
				* We will receive all events and have to
				* filter for what we want ourself.
				*/
			/* FIXME
				* Do we want to ignore broadcasts until the
				* initial get/dump requests is done? */

			if (!bsr_cfg_context_from_attrs(&ctx, &info)) {
				switch ((int)cm->ctx_key) {
				case CTX_MINOR:
					/* Assert that, for an unicast reply,
						* reply minor matches request minor.
						* "unsolicited" kernel broadcasts are "pid=0" (netlink "port id")
						* (and expected to be genlmsghdr.cmd == BSR_EVENT) */
					if (minor != dh->minor) {
						if (info.nlhdr->nlmsg_pid != 0)
							dbg(1, "received netlink packet for minor %u, while expecting %u\n",
								dh->minor, minor);
						continue;
					}
					break;
				case CTX_PEER_DEVICE:
					if (ctx.ctx_volume != global_ctx.ctx_volume)
						continue;
					/* also needs to match the connection, of course */
				case CTX_PEER_NODE:
					if (ctx.ctx_peer_node_id != global_ctx.ctx_peer_node_id)
						continue;
					/* also needs to match the resource, of course */
				case CTX_RESOURCE:
				case CTX_RESOURCE | CTX_ALL:
					if (!strcmp(objname, "all"))
						break;

					if (strcmp(objname, ctx.ctx_resource_name))
						continue;

					break;
				default:
					CLI_ERRO_LOG_STDERR(false, "DRECK: %x", cm->ctx_key);
					assert(0);
				}
			}
		}
		rv = dh->ret_code;
		if (rv == ERR_MINOR_INVALID && cm->missing_ok)
			rv = ERR_NO;
		if (rv != ERR_NO)
			goto out2;
		err = cm->show_function(cm, &info, u_ptr);
		if (err) {
			if (err < 0)
				err = 0;
			goto out2;
		}

		if (!cm->continuous_poll && !(flags & NLM_F_DUMP)) {
			/* There will be no more reply packets.  */
			err = cm->show_function(cm, NULL, u_ptr);
			goto out2;
		}
	}

out2:
	msg_free(smsg);

out:
	if (!err)
		err = check_error(rv, desc);
	free(iov.iov_base);
	return err;
}

static int generic_get_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	static struct option no_options[] = { { } };
	struct choose_timeout_ctx timeo_ctx = {
		.wfc_timeout = BSR_WFC_TIMEOUT_DEF,
		.degr_wfc_timeout = BSR_DEGR_WFC_TIMEOUT_DEF,
		.outdated_wfc_timeout = BSR_OUTDATED_WFC_TIMEOUT_DEF,
	};
	int c, timeout_ms, err = ERR_NO;
	struct peer_devices_list *peer_devices = NULL;
	struct option *options = cm->options ? cm->options : no_options;
	const char *opts = make_optstring(options);

	optind = 0;  /* reset getopt_long() */
	for(;;) {
		c = getopt_long(argc, argv, opts, options, 0);
		if (c == -1)
			break;
		switch(c) {
		default:
		case '?':
			return 20;
		case 't':
			timeo_ctx.wfc_timeout = m_strtoll(optarg, 1);
			if(BSR_WFC_TIMEOUT_MIN > timeo_ctx.wfc_timeout ||
			   timeo_ctx.wfc_timeout > BSR_WFC_TIMEOUT_MAX) {
				CLI_ERRO_LOG_STDERR(false, "wfc_timeout => %d"
					" out of range [%d..%d]\n",
					timeo_ctx.wfc_timeout,
					BSR_WFC_TIMEOUT_MIN,
					BSR_WFC_TIMEOUT_MAX);
				return 20;
			}
			break;
		case 'd':
			timeo_ctx.degr_wfc_timeout = m_strtoll(optarg, 1);
			if(BSR_DEGR_WFC_TIMEOUT_MIN > timeo_ctx.degr_wfc_timeout ||
			   timeo_ctx.degr_wfc_timeout > BSR_DEGR_WFC_TIMEOUT_MAX) {
				CLI_ERRO_LOG_STDERR(false, "degr_wfc_timeout => %d"
					" out of range [%d..%d]\n",
					timeo_ctx.degr_wfc_timeout,
					BSR_DEGR_WFC_TIMEOUT_MIN,
					BSR_DEGR_WFC_TIMEOUT_MAX);
				return 20;
			}
			break;
		case 'o':
			timeo_ctx.outdated_wfc_timeout = m_strtoll(optarg, 1);
			if(BSR_OUTDATED_WFC_TIMEOUT_MIN > timeo_ctx.outdated_wfc_timeout ||
			   timeo_ctx.outdated_wfc_timeout > BSR_OUTDATED_WFC_TIMEOUT_MAX) {
				CLI_ERRO_LOG_STDERR(false, "outdated_wfc_timeout => %d"
					" out of range [%d..%d]\n",
					timeo_ctx.outdated_wfc_timeout,
					BSR_OUTDATED_WFC_TIMEOUT_MIN,
					BSR_OUTDATED_WFC_TIMEOUT_MAX);
				return 20;
			}
			break;

		case 'n':
			opt_now = true;
			break;

		case 'p':
			opt_poll = true;
			break;

		case 's':
			opt_verbose = true;
			opt_statistics = true;
			break;

		case 'w':
			if (!optarg || !strcmp(optarg, "yes"))
				wait_after_split_brain = true;
			break;

		case 'D':
			show_defaults = true;
			break;

		case 'T':
			opt_timestamps = true;
			break;

		case 'c':
			if (!parse_color_argument())
				print_usage_and_exit("unknown --color argument");
			break;
		}
	}
	if (optind < argc) {
		warn_print_excess_args(argc, argv, optind + 1);
		return 20;
	}

	timeout_ms = -1;
	if (cm->show_function == &wait_for_family) {
		struct peer_devices_list *peer_device;
		struct msg_buff *smsg;
		struct iovec iov;
		int rr;
		char *res_name = cm->ctx_key & CTX_RESOURCE ? objname : "all";

		peer_devices = list_peer_devices(res_name);

		/* if there are no peer devices, we don't wait by definition */
		if (!peer_devices)
			return 0;

		iov.iov_len = DEFAULT_MSG_SIZE;
		iov.iov_base = malloc(iov.iov_len);
		smsg = msg_new(DEFAULT_MSG_SIZE);
		if (!smsg || !iov.iov_base) {
			msg_free(smsg);
			free(iov.iov_base);
			CLI_ERRO_LOG_STDERR(false, "could not allocate netlink messages");
			return 20;
		}

		timeo_ctx.smsg = smsg;
		timeo_ctx.iov = &iov;

		for (peer_device = peer_devices;
		     peer_device;
		     peer_device = peer_device->next) {

			timeo_ctx.ctx = peer_device->ctx;
			rr = choose_timeout(&timeo_ctx);

			if (rr)
				return rr;

			peer_device->timeout_ms =
				timeo_ctx.timeout ? timeo_ctx.timeout * 1000 : -1;

			/* rewind send message buffer */
			smsg->tail = smsg->data;
		}

		msg_free(smsg);
		free(iov.iov_base);

		timeout_ms = MULTIPLE_TIMEOUTS;
	}

	if (!cm->continuous_poll)
		timeout_ms = 120000; /* normal "get" request, or "show" */

	err = generic_get(cm, timeout_ms, peer_devices);
	if (cm->show_function == &print_notifications &&
		opt_now && opt_poll) { /* events2 --now --poll */
		while ((c = fgetc(stdin)) != EOF) {
			switch (c) {
			case 'n': /* now */
				err = generic_get(cm, timeout_ms, peer_devices);
				break;
			case '\n':
				break;
			default:
				goto out_polling;
			}
		}
out_polling:;
	}

	free_peer_devices(peer_devices);

	return err;
}

static bool options_empty(struct nlattr *attr, struct context_def *ctx)
{
	struct field_def *field;

	if (!attr)
		return true;

	if (bsr_nla_parse_nested(nested_attr_tb, ctx->nla_policy_size - 1,
				  attr, ctx->nla_policy)) {
		CLI_ERRO_LOG_STDERR(false, "nla_policy violation");
	}

	for (field = ctx->fields; field->name; field++) {
		struct nlattr *nlattr;
		const char *str;
		bool is_default;

		nlattr = ntb(field->nla_type);
		if (!nlattr)
			continue;
		str = field->ops->get(ctx, field, nlattr);
		is_default = field->ops->is_default(field, str);
		if (is_default && !show_defaults)
			continue;
		return false;
	}

	return true;
}

static void show_peer_device(struct peer_devices_list *peer_device)
{
	if (options_empty(peer_device->peer_device_conf, &peer_device_options_ctx))
		return;

	printI("volume %d {\n", peer_device->ctx.ctx_volume);
	++indent;
	print_options(peer_device->peer_device_conf, &peer_device_options_ctx, "disk");
	--indent;
	printI("}\n");
}

static void print_paths(struct connections_list *connection)
{
	char address[ADDRESS_STR_MAX];
	char *colon;
	struct nlattr *nla;
	int tmp;

	if (!connection->path_list)
		return;

	nla_for_each_nested(nla, connection->path_list, tmp) {
		int l = nla_len(nla);

		if (!address_str(address, nla_data(nla), l))
			continue;
		colon = strchr(address, ':');
		if (colon)
			*colon = ' ';
		if (nla->nla_type == T_my_addr) {
			printI("path {\n");
			++indent;
			printI("_this_host %s;\n", address);
		}
		if (nla->nla_type == T_peer_addr) {
			printI("_remote_host %s;\n", address);
			--indent;
			printI("}\n");
		}
	}
}

static void show_connection(struct connections_list *connection, struct peer_devices_list *peer_devices)
{
	struct peer_devices_list *peer_device;
	struct nlattr *nla;

	printI("connection {\n");
	++indent;
	printI("_peer_node_id %d;\n", connection->ctx.ctx_peer_node_id);
		
	nla = nla_find_nested(connection->net_conf, __nla_type(T_peer_node_name));
	if (nla)
		printI("_peer_node_name\t\"%s\";\n", (char *)nla_data(nla));

	print_paths(connection);
	if (connection->info.conn_connection_state == C_STANDALONE)
		printI("_is_standalone;\n");
	print_options(connection->net_conf, &show_net_options_ctx, "net");

	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
		if (connection->ctx.ctx_peer_node_id == peer_device->ctx.ctx_peer_node_id)
			show_peer_device(peer_device);
	}

	--indent;
	printI("}\n");
}

static void show_volume(struct devices_list *device)
{
	printI("volume %d {\n", device->ctx.ctx_volume);
	++indent;
	printI("device\t\t\tminor %d;\n", device->minor);
	if (device->disk_conf.backing_dev[0]) {
		printI("disk\t\t\t\"%s\";\n", device->disk_conf.backing_dev);
		printI("meta-disk\t\t\t");
		switch(device->disk_conf.meta_dev_idx) {
		case BSR_MD_INDEX_INTERNAL:
		case BSR_MD_INDEX_FLEX_INT:
			printf("internal;\n");
			break;
		case BSR_MD_INDEX_FLEX_EXT:
			printf("%s;\n",
			       double_quote_string(device->disk_conf.meta_dev));
			break;
		default:
			printf("%s [ %d ];\n",
			       double_quote_string(device->disk_conf.meta_dev),
			       device->disk_conf.meta_dev_idx);
		}
	} else if (device->info.is_intentional_diskless == 1) {
		printI("disk\t\t\tnone;\n");
	}

	print_options(device->disk_conf_nl, &attach_cmd_ctx, "disk");
	--indent;
	printI("}\n"); /* close volume */
}

static int show_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct resources_list *resources_list, *resource;
	char *old_objname = objname;
	int c;

	optind = 0;  /* reset getopt_long() */
	for (;;) {
		c = getopt_long(argc, argv, "D", show_cmd_options, 0);
		if (c == -1)
			break;
		switch(c) {
		default:
		case '?':
			return 20;
		case 'D':
			show_defaults = true;
			break;
		}
	}

	resources_list = sort_resources(list_resources());

	if (resources_list == NULL)
		printf("# No currently configured BSR found.\n");
	
	for (resource = resources_list; resource; resource = resource->next) {
		struct devices_list *devices, *device;
		struct connections_list *connections, *connection;
		struct peer_devices_list *peer_devices = NULL;

		struct nlattr *nla;

		if (strcmp(old_objname, "all") && strcmp(old_objname, resource->name))
			continue;

		devices = list_devices(resource->name);
		connections = sort_connections(list_connections(resource->name));
		if (devices && connections)
			peer_devices = list_peer_devices(resource->name);

		objname = resource->name;

		printI("resource %s {\n", resource->name);
		++indent;

		print_options(resource->res_opts, &resource_options_ctx, "options");

		printI("_this_host {\n");
		++indent;

		nla = nla_find_nested(resource->res_opts, __nla_type(T_node_id));
		if (nla)
			printI("node-id\t\t\t%d;\n", *(uint32_t *)nla_data(nla));

		// BSR-859
		nla = nla_find_nested(resource->node_opts, __nla_type(T_node_name));
		if (nla)
		printI("node-name\t\t\"%s\";\n", (char *)nla_data(nla));
		
		for (device = devices; device; device = device->next)
			show_volume(device);

		// BSR-718
		print_options(resource->node_opts, &node_options_ctx, "options");

		--indent;
		printI("}\n");

		for (connection = connections; connection; connection = connection->next)
			show_connection(connection, peer_devices);

		--indent;
		printI("}\n\n");

		free_connections(connections);
		free_devices(devices);
		free_peer_devices(peer_devices);
	}

	free(resources_list);
	objname = old_objname;
	return 0;
}

static const char *susp_str(struct resource_info *info)
{
	static char buffer[32];

	*buffer = 0;
	if (info->res_susp)
		strcat(buffer, ",user" + (*buffer == 0));
	if (info->res_susp_nod)
		strcat(buffer, ",no-data" + (*buffer == 0));
	if (info->res_susp_fen)
		strcat(buffer, ",fencing" + (*buffer == 0));
	if (info->res_susp_quorum)
		strcat(buffer, ",quorum" + (*buffer == 0));

	if (*buffer == 0)
		strcat(buffer, "no");

	return buffer;
}

int nowrap_printf(int indent, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vprintf(format, ap);
	va_end(ap);

	return ret;
}

void print_resource_statistics(int indent,
			       struct resource_statistics *old,
			       struct resource_statistics *new,
			       int (*wrap_printf)(int, const char *, ...))
{
	static const char *write_ordering_str[] = {
		[WO_NONE] = "none",
		[WO_DRAIN_IO] = "drain",
		[WO_BDEV_FLUSH] = "flush",
		[WO_BIO_BARRIER] = "barrier",
	};
	uint32_t wo = new->res_stat_write_ordering;

	if ((!old ||
	     old->res_stat_write_ordering != wo) &&
	    wo < ARRAY_SIZE(write_ordering_str) &&
	    write_ordering_str[wo]) {
		wrap_printf(indent, " write-ordering:%s", write_ordering_str[wo]);
	}

	// DW-1925
	wrap_printf(indent, " req-pending:" U32,
		(int)new->res_stat_req_write_cnt);
}

void print_device_statistics(int indent,
			     struct device_statistics *old,
			     struct device_statistics *new,
			     int (*wrap_printf)(int, const char *, ...))
{
	if (opt_statistics) {
		if (opt_verbose)
			wrap_printf(indent, " size:" U64,
				    (uint64_t)new->dev_size / 2);
		wrap_printf(indent, " read:" U64,
			    (uint64_t)new->dev_read / 2);
		wrap_printf(indent, " written:" U64,
			    (uint64_t)new->dev_write / 2);
		if (opt_verbose) {
			wrap_printf(indent, " al-writes:" U64,
				    (uint64_t)new->dev_al_writes);
			wrap_printf(indent, " bm-writes:" U64,
				    (uint64_t)new->dev_bm_writes);
			wrap_printf(indent, " upper-pending:" U32,
				    new->dev_upper_pending);
			wrap_printf(indent, " lower-pending:" U32,
				    new->dev_lower_pending);
			if (!old ||
			    old->dev_al_suspended != new->dev_al_suspended)
				wrap_printf(indent, " al-suspended:%s",
					    new->dev_al_suspended ? "yes" : "no");

			wrap_printf(indent, " al-pending-changes:" U32,
				new->dev_al_pending_changes);

			wrap_printf(indent, " al-used:" U32,
				new->dev_al_used);
		}
	}
	if ((!old ||
	     old->dev_upper_blocked != new->dev_upper_blocked ||
	     old->dev_lower_blocked != new->dev_lower_blocked) &&
	    new->dev_size != -1 &&
	    (opt_verbose ||
	     new->dev_upper_blocked ||
	     new->dev_lower_blocked)) {
		const char *x1 = "", *x2 = "";
		bool first = true;

		if (new->dev_upper_blocked) {
			x1 = ",upper" + first;
			first = false;
		}
		if (new->dev_lower_blocked) {
			x2 = ",lower" + first;
			first = false;
		}
		if (first)
			x1 = "no";

		wrap_printf(indent, " blocked:%s%s", x1, x2);
	}
}

void print_connection_statistics(int indent,
				 struct connection_statistics *old,
				 struct connection_statistics *new,
				 int (*wrap_printf)(int, const char *, ...))
{
	if (!old ||
	    old->conn_congested != new->conn_congested)
		wrap_printf(indent, " congested:%s", new->conn_congested ? "yes" : "no");
}

static void peer_device_status_json(struct peer_devices_list *peer_device)
{
	struct peer_device_statistics *s = &peer_device->statistics;
	bool in_rsync = (peer_device->info.peer_repl_state >= L_SYNC_SOURCE &&
		peer_device->info.peer_repl_state <= L_PAUSED_SYNC_T);

	printf("        {\n"
	       "          \"volume\": %d,\n"
	       "          \"replication-state\": \"%s\",\n"
	       "          \"peer-disk-state\": \"%s\",\n"
		   "          \"peer-client\": \"%s\",\n"
	       "          \"resync-suspended\": \"%s\",\n"
	       "          \"received\": " U64 ",\n"
	       "          \"sent\": " U64 ",\n"
	       "          \"out-of-sync\": " U64 ",\n"
	       "          \"pending\": " U32 ",\n"
		   "          \"unacked\": " U32 "%s\n",
	       peer_device->ctx.ctx_volume,
	       bsr_repl_str(peer_device->info.peer_repl_state),
	       bsr_disk_str(peer_device->info.peer_disk_state),
		   peer_intentional_diskless_str(&peer_device->info),
	       resync_susp_str(&peer_device->info),
	       (uint64_t)s->peer_dev_received / 2,
	       (uint64_t)s->peer_dev_sent / 2,
	       (uint64_t)s->peer_dev_out_of_sync / 2,
	       s->peer_dev_pending,
		   s->peer_dev_unacked,
		   in_rsync ? "," : "");

	if (in_rsync)
		printf("          \"resync-done\": %.2f\n",
		       100 * (1 - (double)peer_device->statistics.peer_dev_out_of_sync /
			      (double)peer_device->device->statistics.dev_size));

	printf("        }");
}

static void connection_status_json(struct connections_list *connection,
				   struct peer_devices_list *peer_devices)
{
	struct peer_devices_list *peer_device;
	int i = 0;

	printf("    {\n"
	       "      \"peer-node-id\": %d,\n"
	       "      \"name\": \"%s\",\n"
	       "      \"connection-state\": \"%s\", \n"
	       "      \"congested\": %s,\n"
	       "      \"peer-role\": \"%s\",\n"
	       "      \"peer_devices\": [\n",
	       connection->ctx.ctx_peer_node_id,
	       connection->ctx.ctx_conn_name,
	       bsr_conn_str(connection->info.conn_connection_state),
	       connection->statistics.conn_congested ? "true" : "false",
	       bsr_role_str(connection->info.conn_role));

	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
		if (connection->ctx.ctx_peer_node_id != peer_device->ctx.ctx_peer_node_id)
			continue;
		if (i)
			puts(",");
		peer_device_status_json(peer_device);
		i++;
	}
	printf(" ]\n    }");
}

static void device_status_json(struct devices_list *device)
{
	enum bsr_disk_state disk_state = device->info.dev_disk_state;
	bool d_statistics = (device->statistics.dev_size != -1);

	printf("    {\n"
	       "      \"volume\": %d,\n"
	       "      \"minor\": %d,\n"
		   "      \"disk-state\": \"%s\",\n"
		   "      \"client\": \"%s\"%s\n",
	       device->ctx.ctx_volume,
	       device->minor,
		   bsr_disk_str(disk_state),
		   intentional_diskless_str(&device->info),
		   d_statistics ? "," : "");

	if (d_statistics) {
		struct device_statistics *s = &device->statistics;

		printf("      \"size\": " U64 ",\n"
		       "      \"read\": " U64 ",\n"
		       "      \"written\": " U64 ",\n"
		       "      \"al-writes\": " U64 ",\n"
		       "      \"bm-writes\": " U64 ",\n"
		       "      \"upper-pending\": " U32 ",\n"
		       "      \"lower-pending\": " U32 "\n",
		       (uint64_t)s->dev_size / 2,
		       (uint64_t)s->dev_read / 2,
		       (uint64_t)s->dev_write / 2,
		       (uint64_t)s->dev_al_writes,
		       (uint64_t)s->dev_bm_writes,
		       s->dev_upper_pending,
		       s->dev_lower_pending);
	}
	printf("    }");
}

static void resource_status_json(struct resources_list *resource)
{
	static const char *write_ordering_str[] = {
		[WO_NONE] = "none",
		[WO_DRAIN_IO] = "drain",
		[WO_BDEV_FLUSH] = "flush",
		[WO_BIO_BARRIER] = "barrier",
	};

	struct nlattr *nla;
	int node_id = -1;
	bool suspended =
		resource->info.res_susp ||
		resource->info.res_susp_nod ||
		resource->info.res_susp_fen ||
		resource->info.res_susp_quorum;

	nla = nla_find_nested(resource->res_opts, __nla_type(T_node_id));
	if (nla)
		node_id = *(uint32_t *)nla_data(nla);

	printf("{\n"
	       "  \"name\": \"%s\",\n"
	       "  \"node-id\": %d,\n"
	       "  \"role\": \"%s\",\n"
	       "  \"suspended\": %s,\n"
	       "  \"write-ordering\": \"%s\",\n"
	       "  \"devices\": [\n",
	       resource->name,
	       node_id,
	       bsr_role_str(resource->info.res_role),
	       suspended ? "true" : "false",
	       write_ordering_str[resource->statistics.res_stat_write_ordering]);
}

void print_peer_device_statistics(int indent,
				  struct peer_device_statistics *old,
				  struct peer_device_statistics *new,
				  int (*wrap_printf)(int, const char *, ...))
{
	// BSR-191
	double db, dt, rt;
	uint64_t sectors_to_go = 0;
	bool sync_details =
		(new->peer_dev_rs_total != 0) &&
		(new->peer_dev_rs_total != -1ULL);
		
	if (sync_details)
		sectors_to_go = new->peer_dev_ov_left ?:
			new->peer_dev_out_of_sync - new->peer_dev_resync_failed;

	wrap_printf(indent, " received:" U64,
		    (uint64_t)new->peer_dev_received / 2);
	wrap_printf(indent, " sent:" U64,
		    (uint64_t)new->peer_dev_sent / 2);
	if (opt_verbose || new->peer_dev_out_of_sync)
		wrap_printf(indent, " out-of-sync:" U64,
			    (uint64_t)new->peer_dev_out_of_sync / 2);
	if (opt_verbose) {
		wrap_printf(indent, " pending:" U32,
			    new->peer_dev_pending);
		wrap_printf(indent, " unacked:" U32,
			    new->peer_dev_unacked);
	}

	if (!sync_details)
		return;

	// BSR-191 sync progress
	db = (int64_t) new->peer_dev_rs_db_sectors;
	dt = new->peer_dev_rs_dt_ms ?: 1;
	wrap_printf(indent, " speed:%.0f", db/dt *1000.0/2.0); /* KiB/s */
	wrap_printf(indent, " want:%lu", new->peer_dev_rs_c_sync_rate); /* KiB/s */
	/* estimate time-to-run, based on "db/dt" */
	rt = db > 0 ? dt * 1e-3 * sectors_to_go / db : -1; /* seconds */
	wrap_printf(indent, " eta:%lu:%02lu:%02lu", 
		(unsigned long)rt / 3600, ((unsigned long)rt % 3600) / 60, (unsigned long)rt % 60);
}

void resource_status(struct resources_list *resource)
{
	enum bsr_role role = resource->info.res_role;

	wrap_printf(0, "%s", resource->name);
	if (opt_verbose) {
		struct nlattr *nla;

		nla = nla_find_nested(resource->res_opts, __nla_type(T_node_id));
		if (nla)
			wrap_printf(4, " node-id:%d", *(uint32_t *)nla_data(nla));
	}
	wrap_printf(4, " role:%s%s%s",
		    role_color_start(role, true),
		    bsr_role_str(role),
		    role_color_stop(role, true));
	if (opt_verbose ||
	    resource->info.res_susp ||
	    resource->info.res_susp_nod ||
		resource->info.res_susp_fen ||
		resource->info.res_susp_quorum)
		wrap_printf(4, " suspended:%s", susp_str(&resource->info));
	if (opt_statistics && opt_verbose) {
		wrap_printf(4, "\n");
		print_resource_statistics(4, NULL, &resource->statistics, wrap_printf);
	}
	wrap_printf(0, "\n");
}

static void device_status(struct devices_list *device, bool single_device)
{
	enum bsr_disk_state disk_state = device->info.dev_disk_state;
	bool intentional_diskless = device->info.is_intentional_diskless == 1;
	int indent = 2;

	if (opt_verbose || !(single_device && device->ctx.ctx_volume == 0)) {
		wrap_printf(indent, "volume:%u",  device->ctx.ctx_volume);
		indent = 6;
		if (opt_verbose)
			wrap_printf(indent, " minor:%u", device->minor);
	}
	wrap_printf(indent, " disk:%s%s%s",
			disk_state_color_start(disk_state, intentional_diskless, true),
		    bsr_disk_str(disk_state),
		    disk_state_color_stop(disk_state, true));
	if (disk_state == D_DISKLESS && opt_verbose) {
		wrap_printf(indent, " client:%s", intentional_diskless_str(&device->info));
	}

	// DW-1755 In the passthrough policy,
	 /* the disk status is kept up_to_date in the event of a primary failure,
	 * so disk error information should be displayed seperately.
	 */

	// DW-1820
	 /* Modified to print io-error on secondary. 
	 * In secondary io-error, it is not UpToDate, so modify the condition.
	 */
	if (device->info.io_error_count) {
		wrap_printf(indent, " %sio-error:%d%s", 
			disk_state_color_start(D_DISKLESS, intentional_diskless, true),
			device->info.io_error_count,
			disk_state_color_stop(D_DISKLESS, true));
	}

	indent = 6;
	if (device->statistics.dev_size != -1) {
		if (opt_statistics)
			wrap_printf(indent, "\n");
		print_device_statistics(indent, NULL, &device->statistics, wrap_printf);
	}
	wrap_printf(indent, "\n");
}

static const char *_intentionall_diskless_str(unsigned char intentional_diskless) {
	switch (intentional_diskless) {
	case 0:
		return "no";
	case 1:
		return "yes";
	default:
		return "unknown";
	}
}

static const char *intentional_diskless_str(struct device_info *info)
{
	return _intentionall_diskless_str(info->is_intentional_diskless);
}

static const char *peer_intentional_diskless_str(struct peer_device_info *info) {
	return _intentionall_diskless_str(info->peer_is_intentional_diskless);
}

static const char *resync_susp_str(struct peer_device_info *info)
{
	static char buffer[64];

	*buffer = 0;
	if (info->peer_resync_susp_user)
		strcat(buffer, ",user" + (*buffer == 0));
	if (info->peer_resync_susp_peer)
		strcat(buffer, ",peer" + (*buffer == 0));
	if (info->peer_resync_susp_dependency)
		strcat(buffer, ",dependency" + (*buffer == 0));
	if (*buffer == 0)
		strcat(buffer, "no");

	return buffer;
}

static void peer_device_status(struct peer_devices_list *peer_device, bool single_device)
{
	int indent = 4;
	bool intentional_diskless = peer_device->info.peer_is_intentional_diskless == 1;

	if (opt_verbose || !(single_device && peer_device->ctx.ctx_volume == 0)) {
		wrap_printf(indent, "volume:%d", peer_device->ctx.ctx_volume);
		indent = 8;
	}
	if (opt_verbose || peer_device->info.peer_repl_state > L_ESTABLISHED) {
		enum bsr_repl_state repl_state = peer_device->info.peer_repl_state;

		wrap_printf(indent, " replication:%s%s%s",
			    repl_state_color_start(repl_state),
			    bsr_repl_str(repl_state),
			    repl_state_color_stop(repl_state));
		indent = 8;
	}
	if (opt_verbose || opt_statistics ||
	    peer_device->info.peer_repl_state != L_OFF ||
	    peer_device->info.peer_disk_state != D_UNKNOWN) {
		enum bsr_disk_state disk_state = peer_device->info.peer_disk_state;

		wrap_printf(indent, " peer-disk:%s%s%s",
				disk_state_color_start(disk_state, intentional_diskless, false),
			    bsr_disk_str(disk_state),
			    disk_state_color_stop(disk_state, false));
		if (disk_state == D_DISKLESS && opt_verbose)
			wrap_printf(indent, " peer-client:%s", peer_intentional_diskless_str(&peer_device->info));
		indent = 8;
		if (peer_device->info.peer_repl_state >= L_SYNC_SOURCE &&
		    peer_device->info.peer_repl_state <= L_PAUSED_SYNC_T) {
			if(peer_device->info.peer_repl_state == L_VERIFY_S || peer_device->info.peer_repl_state == L_VERIFY_T)
				wrap_printf(indent, " done:%.2f", (int)(10000 * (1 -
					(double)peer_device->statistics.peer_dev_ov_left /
					(double)peer_device->device->statistics.dev_size)) / 100.f);
			else
				wrap_printf(indent, " done:%.2f", (int)(10000 * (1 -
					(double)peer_device->statistics.peer_dev_out_of_sync /
					(double)peer_device->device->statistics.dev_size)) / 100.f);
		}
		if (opt_verbose ||
		    peer_device->info.peer_resync_susp_user ||
		    peer_device->info.peer_resync_susp_peer ||
		    peer_device->info.peer_resync_susp_dependency)
			wrap_printf(indent, " resync-suspended:%s",
				    resync_susp_str(&peer_device->info));
		if (opt_statistics && peer_device->statistics.peer_dev_received != -1) {
			wrap_printf(indent, "\n");
			print_peer_device_statistics(indent, NULL, &peer_device->statistics, wrap_printf);
		}
	}

	wrap_printf(0, "\n");
}

static void peer_devices_status(struct bsr_cfg_context *ctx, struct peer_devices_list *peer_devices, bool single_device)
{
	struct peer_devices_list *peer_device;

	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
		if (ctx->ctx_peer_node_id != peer_device->ctx.ctx_peer_node_id)
			continue;
		peer_device_status(peer_device, single_device);
	}
}

static void connection_status(struct connections_list *connection,
			      struct peer_devices_list *peer_devices,
			      bool single_device)
{
	if (connection->ctx.ctx_conn_name_len)
		wrap_printf(2, "%s", connection->ctx.ctx_conn_name);

	if (opt_verbose || connection->ctx.ctx_conn_name_len == 0) {
		int in = connection->ctx.ctx_conn_name_len ? 6 : 2;
		wrap_printf(in, " node-id:%d", connection->ctx.ctx_peer_node_id);
	}
	if (opt_verbose || connection->info.conn_connection_state != C_CONNECTED) {
		enum bsr_conn_state cstate = connection->info.conn_connection_state;
		wrap_printf(6, " connection:%s%s%s",
			    cstate_color_start(cstate),
			    bsr_conn_str(cstate),
			    cstate_color_stop(cstate));
	}
	if (opt_verbose || connection->info.conn_connection_state == C_CONNECTED) {
		enum bsr_role role = connection->info.conn_role;
		wrap_printf(6, " role:%s%s%s",
			    role_color_start(role, false),
			    bsr_role_str(role),
			    role_color_stop(role, false));
	}
	if (opt_verbose || connection->statistics.conn_congested > 0)
		print_connection_statistics(6, NULL, &connection->statistics, wrap_printf);
	wrap_printf(0, "\n");
	if (opt_verbose || opt_statistics || connection->info.conn_connection_state == C_CONNECTED)
		peer_devices_status(&connection->ctx, peer_devices, single_device);
}

static void stop_colors(int sig)
{
	printf("%s", stop_color_code());
	signal(sig, SIG_DFL);
	raise(sig);
}

static void link_peer_devices_to_devices(struct peer_devices_list *peer_devices, struct devices_list *devices)
{
	struct peer_devices_list *peer_device;
	struct devices_list *device;

	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
		for (device = devices; device; device = device->next) {
			if (peer_device->ctx.ctx_volume == device->ctx.ctx_volume) {
				peer_device->device = device;
				break;
			}
		}
	}
}

static int status_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct resources_list *resources, *resource;
	struct sigaction sa = {
		.sa_handler = stop_colors,
		.sa_flags = SA_RESETHAND,
	};
	bool found = false;
	bool json = false; 
	int c;

	optind = 0;  /* reset getopt_long() */
	for (;;) {
		c = getopt_long(argc, argv, make_optstring(cm->options), cm->options, 0);
		if (c == -1)
			break;
		switch(c) {
		default:
		case '?':
			return 20;
		case 'v':
			opt_verbose = true;
			break;
		case 's':
			opt_statistics = true;
			break;
		case 'c':
			if (!parse_color_argument())
				print_usage_and_exit("unknown --color argument");
			break;
		case 'j':
			json = true;
			break;
		}
	}

	resources = sort_resources(list_resources());

	if (resources == NULL)
		printf("# No currently configured BSR found.\n");
	
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (json)
		puts("[");

	for (resource = resources; resource; resource = resource->next) {
		struct devices_list *devices, *device;
		struct connections_list *connections, *connection;
		struct peer_devices_list *peer_devices = NULL;
		bool single_device;
		static bool jsonisfirst = true;

		if (strcmp(objname, "all") && strcmp(objname, resource->name))
			continue;
		if (json)
			jsonisfirst ? jsonisfirst = false : puts(",");

		devices = list_devices(resource->name);
		connections = sort_connections(list_connections(resource->name));
		if (devices && connections)
			peer_devices = list_peer_devices(resource->name);

		link_peer_devices_to_devices(peer_devices, devices);

		if (json) {
			resource_status_json(resource);
			for (device = devices; device; device = device->next) {
				device_status_json(device);
				if (device->next)
					puts(",");
			}
			puts(" ],\n  \"connections\": [");
			for (connection = connections; connection; connection = connection->next) {
				connection_status_json(connection, peer_devices);
				if (connection->next)
					puts(",");
			}
			puts(" ]\n}");
		} else {
			resource_status(resource);
			single_device = devices && !devices->next;
			for (device = devices; device; device = device->next)
				device_status(device, single_device);
			for (connection = connections; connection; connection = connection->next)
				connection_status(connection, peer_devices, single_device);
			wrap_printf(0, "\n");
		}

		free_connections(connections);
		free_devices(devices);
		free_peer_devices(peer_devices);
		found = true;
	}

	if (json)
		puts("]\n");

	free_resources(resources);
	if (!found && strcmp(objname, "all")) {
		CLI_ERRO_LOG_STDERR(false, "%s: No such resource", objname);
		return 10;
	}
	return 0;
}

static int role_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct resources_list *resources, *resource;
	int ret = ERR_RES_NOT_KNOWN;

	resources = list_resources();

	for (resource = resources; resource; resource = resource->next) {
		if (strcmp(objname, resource->name))
			continue;

		printf("%s\n", bsr_role_str(resource->info.res_role));
		ret = ERR_NO;
		break;
	}

	free_resources(resources);

	if (ret != ERR_NO) {
		CLI_ERRO_LOG_STDERR(false, "%s: %s", objname, error_to_string(ret));
		return 10;
	}
	return 0;
}

static int cstate_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct connections_list *connections, *connection;
	bool found = false;

	connections = list_connections(objname);
	for (connection = connections; connection; connection = connection->next) {
		if (connection->ctx.ctx_peer_node_id != global_ctx.ctx_peer_node_id)
			continue;

		printf("%s\n", bsr_conn_str(connection->info.conn_connection_state));
		found = true;
		break;
	}
	free_connections(connections);

	if (!found) {
		CLI_ERRO_LOG_STDERR(false, "%s: No such connection", objname);
		return 10;
	}
	return 0;
}

static int dstate_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct devices_list *devices, *device;
	bool found = false;
	struct peer_devices_list *peer_devices, *peer_device;

	devices = list_devices(NULL);
	for (device = devices; device; device = device->next) {
		if (device->minor != minor)
			continue;

		printf("%s", bsr_disk_str(device->info.dev_disk_state));
		/* printf("%s/%s\n",bsr_disk_str(state.disk),bsr_disk_str(state.pdsk)); */

		peer_devices = list_peer_devices(device->ctx.ctx_resource_name);
		for (peer_device = peer_devices;
				peer_device;
				peer_device = peer_device->next) {

			if (device->ctx.ctx_volume == peer_device->ctx.ctx_volume)
				printf("/%s", bsr_disk_str(peer_device->info.peer_disk_state));
		}
		printf("\n");
		found = true;
		break;
	}
	free_devices(devices);

	if (!found) {
		CLI_ERRO_LOG_STDERR(false, "%s: No such device", objname);
		return 10;
	}
	return 0;
}

static char *af_to_str(int af)
{
	if (af == AF_INET)
		return "ipv4";
	else if (af == AF_INET6)
		return "ipv6";
	/* AF_SSOCKS typically is 27, the same as AF_INET_SDP.
	 * But with warn_and_use_default = 0, it will stay at -1 if not available.
	 * Just keep the test on ssocks before the one on SDP (which is hard-coded),
	 * and all should be fine.  */
	else if (af == get_af_ssocks(0))
		return "ssocks";
	else if (af == AF_INET_SDP)
		return "sdp";
	else return "unknown";
}

// BSR-1018
#ifdef _WIN
static void convert_scopeid_to_alias(char *address)
{
	char *scopeId = NULL;
	wchar_t if_alias_w[IF_MAX_STRING_SIZE + 1] = { 0, };
	NET_LUID if_luid;
	NET_IFINDEX if_index = 0;
	char *if_alias;
	int len;

	scopeId = strrchr(address, '%');

	if (!scopeId) {
		// unique local address
		return;
	}

	scopeId++;
	if_index = strtol(scopeId, NULL, 10);

	if (NO_ERROR == ConvertInterfaceIndexToLuid(if_index, &if_luid) &&
		NO_ERROR == ConvertInterfaceLuidToAlias(&if_luid, &if_alias_w, IF_MAX_STRING_SIZE + 1)) {
		
		len = wcstombs(NULL, if_alias_w, 0);
		if (len != -1) {
			if_alias = (char*)malloc(len + 1);
			if (if_alias) {
				if (wcstombs(if_alias, if_alias_w, len + 1) != -1)
					memcpy(scopeId, if_alias, len + 1);
				else
					CLI_ERRO_LOG(false, true, "failed to convert to multi-byte, (%s)", scopeId);

				free(if_alias);

			} 
			else {
				CLI_ERRO_LOG(false, true, "failed to allocate scope id, size is %d", (sizeof(wchar_t) * len + 1));
			}
		} 
		else {
			CLI_ERRO_LOG(false, true, "failed to get wc string size");
		}

	}
	else {
		CLI_INFO_LOG(false, "no matching interface index found, (%s)", scopeId);
	}
}
#endif

static char *address_str(char *buffer, void* address, int addr_len)
{
	union {
		struct sockaddr     addr;
		struct sockaddr_in  addr4;
		struct sockaddr_in6 addr6;
	} a;

	/* avoid alignment issues on certain platforms (e.g. armel) */
	memset(&a, 0, sizeof(a));
	memcpy(&a.addr, address, addr_len);
	if (a.addr.sa_family == AF_INET
	|| a.addr.sa_family == get_af_ssocks(0)
	|| a.addr.sa_family == AF_INET_SDP) {
		snprintf(buffer, ADDRESS_STR_MAX, "%s:%s:%u",
			 af_to_str(a.addr4.sin_family),
			 inet_ntoa(a.addr4.sin_addr),
			 ntohs(a.addr4.sin_port));
		return buffer;
	} else if (a.addr.sa_family == AF_INET6) {
		char buf2[ADDRESS_STR_MAX];
		int n;
		buf2[0] = 0;
		/* inet_ntop does not include scope info */
		getnameinfo(&a.addr, addr_len, buf2, sizeof(buf2),
			NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV);
#ifdef _WIN
		// BSR-1018 show by converting to scopeid interface alias
		convert_scopeid_to_alias(buf2);
#endif
		
		n = snprintf(buffer, ADDRESS_STR_MAX, "%s:[%s]:%u",
		        af_to_str(a.addr6.sin6_family), buf2,
		        ntohs(a.addr6.sin6_port));
		assert(n > 0);
		assert(n < ADDRESS_STR_MAX); /* there should be no need to truncate */
		return buffer;
	} else
		return NULL;
}

static int remember_resource(struct bsr_cmd *cmd, struct genl_info *info, void *u_ptr)
{
	struct resources_list ***tail = u_ptr;
	struct bsr_cfg_context cfg = { .ctx_volume = -1U, .ctx_peer_node_id = -1U };

	if (!info)
		return 0;

	bsr_cfg_context_from_attrs(&cfg, info);
	if (cfg.ctx_resource_name) {
		struct resources_list *r = calloc(1, sizeof(*r));
		struct nlattr *res_opts = global_attrs[BSR_NLA_RESOURCE_OPTS];
		struct nlattr *node_opts = global_attrs[BSR_NLA_NODE_OPTS];

		if (!r) {
			CLI_ERRO_LOG(false, true, "failed to allocate resources list(20)");
			exit(20);
		}

		r->name = strdup(cfg.ctx_resource_name);
		if (res_opts) {
			int size;

			// DW-2072 make sure that it is smaller than the NLA_HDRLEN
			if (res_opts->nla_len <= NLA_HDRLEN) {
				CLI_ERRO_LOG(false, true, "make sure that it is smaller than the NLA_HDRLEN(20)");
				exit(20);
			}

			size = nla_total_size((int)nla_len(res_opts));

			r->res_opts = malloc(size);
			memcpy(r->res_opts, res_opts, size);
		}

		// BSR-718
		if (node_opts) {
			int size;

			if (node_opts->nla_len <= NLA_HDRLEN) {
				CLI_ERRO_LOG(false, true, "make sure that it is smaller than the NLA_HDRLEN(20)");
				exit(20);
			}

			size = nla_total_size((int)nla_len(node_opts));

			r->node_opts = malloc(size);
			memcpy(r->node_opts, node_opts, size);
		}

		resource_info_from_attrs(&r->info, info);
		memset(&r->statistics, -1, sizeof(r->statistics));
		resource_statistics_from_attrs(&r->statistics, info);
		**tail = r;
		*tail = &r->next;
	}
	return 0;
}

static void free_resources(struct resources_list *resources)
{
	while (resources) {
		struct resources_list *r = resources;
		resources = resources->next;
		free(r->name);
		free(r->res_opts);
		free(r);
	}
}

static int resource_name_cmp(const struct resources_list * const *a, const struct resources_list * const *b)
{
	return strcmp((*a)->name, (*b)->name);
}

static struct resources_list *sort_resources(struct resources_list *resources)
{
	struct resources_list *r;
	int n;

	for (r = resources, n = 0; r; r = r->next)
		n++;
	if (n > 1) {
		struct resources_list **array;

		array = malloc(sizeof(*array) * n);
		for (r = resources, n = 0; r; r = r->next)
			array[n++] = r;
		qsort(array, n, sizeof(*array), (int (*)(const void *, const void *)) resource_name_cmp);
		n--;
		array[n]->next = NULL;
		for (; n > 0; n--)
			array[n - 1]->next = array[n];
		resources = array[0];
		free(array);
	}
	return resources;
}

/*
 * Expects objname to be set to the resource name or "all".
 */
static struct resources_list *list_resources(void)
{
	struct bsr_cmd cmd = {
		.cmd_id = BSR_ADM_GET_RESOURCES,
		.show_function = remember_resource,
		.missing_ok = false,
	};
	struct resources_list *list = NULL, **tail = &list;
	char *old_objname = objname;
	unsigned old_minor = minor;
	int old_my_addr_len = global_ctx.ctx_my_addr_len;
	int old_peer_addr_len = global_ctx.ctx_peer_addr_len;
	int err;

	objname = "all";
	minor = -1;
	global_ctx.ctx_my_addr_len = 0;
	global_ctx.ctx_peer_addr_len = 0;
	err = generic_get(&cmd, 120000, &tail);
	objname = old_objname;
	minor = old_minor;
	global_ctx.ctx_my_addr_len = old_my_addr_len;
	global_ctx.ctx_peer_addr_len = old_peer_addr_len;
	if (err) {
		free_resources(list);
		list = NULL;
	}

	return list;
}

static int remember_device(struct bsr_cmd *cm, struct genl_info *info, void *u_ptr)
{
	struct devices_list ***tail = u_ptr;
	struct bsr_cfg_context ctx = { .ctx_volume = -1U, .ctx_peer_node_id = -1U };

	if (!info)
		return 0;

	bsr_cfg_context_from_attrs(&ctx, info);

	if (ctx.ctx_volume != -1U) {
		struct devices_list *d = calloc(1, sizeof(*d));
		struct nlattr *disk_conf_nl = global_attrs[BSR_NLA_DISK_CONF];

		if (!d) {
			CLI_ERRO_LOG(false, true, "failed to allocate devices list(20)");
			exit(20);
		}

		d->minor =  ((struct bsr_genlmsghdr*)(info->userhdr))->minor;
		d->ctx = ctx;
		if (disk_conf_nl) {
			int size;

			// DW-2072 make sure that it is smaller than the NLA_HDRLEN
			if (disk_conf_nl->nla_len <= NLA_HDRLEN) {
				CLI_ERRO_LOG(false, true, "make sure that it is smaller than the NLA_HDRLEN(20)");
				exit(20);
			}

			size = nla_total_size((int)nla_len(disk_conf_nl));

			d->disk_conf_nl = malloc(size);
			memcpy(d->disk_conf_nl, disk_conf_nl, size);
		}
		disk_conf_from_attrs(&d->disk_conf, info);
		d->info.dev_disk_state = D_DISKLESS;
		d->info.is_intentional_diskless = IS_INTENTIONAL_DEF;
		device_info_from_attrs(&d->info, info);
		memset(&d->statistics, -1, sizeof(d->statistics));
		device_statistics_from_attrs(&d->statistics, info);
		**tail = d;
		*tail = &d->next;
	}
	return 0;
}

/*
 * Expects objname to be set to the resource name or "all".
 */
static struct devices_list *list_devices(char *resource_name)
{
	struct bsr_cmd cmd = {
		.cmd_id = BSR_ADM_GET_DEVICES,
		.show_function = remember_device,
		.missing_ok = false,
	};
	struct devices_list *list = NULL, **tail = &list;
	char *old_objname = objname;
	unsigned old_minor = minor;
	int old_my_addr_len = global_ctx.ctx_my_addr_len;
	int old_peer_addr_len = global_ctx.ctx_peer_addr_len;
	int err;

	objname = resource_name ? resource_name : "all";
	minor = -1;
	global_ctx.ctx_my_addr_len = 0;
	global_ctx.ctx_peer_addr_len = 0;
	err = generic_get(&cmd, 120000, &tail);
	objname = old_objname;
	minor = old_minor;
	global_ctx.ctx_my_addr_len = old_my_addr_len;
	global_ctx.ctx_peer_addr_len = old_peer_addr_len;
	if (err) {
		free_devices(list);
		list = NULL;
	}
	return list;
}

static void free_devices(struct devices_list *devices)
{
	while (devices) {
		struct devices_list *d = devices;
		devices = devices->next;
		free(d->disk_conf_nl);
		free(d);
	}
}

static int remember_connection(struct bsr_cmd *cmd, struct genl_info *info, void *u_ptr)
{
	struct connections_list ***tail = u_ptr;
	struct bsr_cfg_context ctx = { .ctx_volume = -1U, .ctx_peer_node_id = -1U };

	if (!info)
		return 0;

	bsr_cfg_context_from_attrs(&ctx, info);
	if (ctx.ctx_resource_name) {
		struct connections_list *c = calloc(1, sizeof(*c));
		struct nlattr *net_conf = global_attrs[BSR_NLA_NET_CONF];
		struct nlattr *path_list = global_attrs[BSR_NLA_PATH_PARMS];

		if (!c) {
			CLI_ERRO_LOG(false, true, "failed to allocate connections list (20)");
			exit(20);
		}

		c->ctx = ctx;
		if (net_conf) {
			int size;

			// DW-2072 make sure that it is smaller than the NLA_HDRLEN
			if (net_conf->nla_len <= NLA_HDRLEN) {
				CLI_ERRO_LOG(false, true, "make sure that it is smaller than the NLA_HDRLEN(20)");
				exit(20);
			}

			size = nla_total_size((int)nla_len(net_conf));

			c->net_conf = malloc(size);
			memcpy(c->net_conf, net_conf, size);
		}
		if (path_list) {
			int size = nla_total_size((int)nla_len(path_list));
			c->path_list = malloc(size);
			memcpy(c->path_list, path_list, size);
		}
		connection_info_from_attrs(&c->info, info);
		memset(&c->statistics, -1, sizeof(c->statistics));
		connection_statistics_from_attrs(&c->statistics, info);
		**tail = c;
		*tail = &c->next;
	}
	return 0;
}

static int connection_name_cmp(const struct connections_list * const *a, const struct connections_list * const *b)
{
	if (!(*a)->ctx.ctx_conn_name_len != !(*b)->ctx.ctx_conn_name_len)
		return !(*b)->ctx.ctx_conn_name_len;
	return strcmp((*a)->ctx.ctx_conn_name, (*b)->ctx.ctx_conn_name);
}

static struct connections_list *sort_connections(struct connections_list *connections)
{
	struct connections_list *c;
	int n;

	for (c = connections, n = 0; c; c = c->next)
		n++;
	if (n > 1) {
		struct connections_list **array;

		array = malloc(sizeof(*array) * n);
		for (c = connections, n = 0; c; c = c->next)
			array[n++] = c;
		qsort(array, n, sizeof(*array), (int (*)(const void *, const void *)) connection_name_cmp);
		n--;
		array[n]->next = NULL;
		for (; n > 0; n--)
			array[n - 1]->next = array[n];
		connections = array[0];
		free(array);
	}
	return connections;
}

/*
 * Expects objname to be set to the resource name or "all".
 */
static struct connections_list *list_connections(char *resource_name)
{
	struct bsr_cmd cmd = {
		.cmd_id = BSR_ADM_GET_CONNECTIONS,
		.show_function = remember_connection,
		.missing_ok = true,
	};
	struct connections_list *list = NULL, **tail = &list;
	char *old_objname = objname;
	unsigned old_minor = minor;
	int old_my_addr_len = global_ctx.ctx_my_addr_len;
	int old_peer_addr_len = global_ctx.ctx_peer_addr_len;
	int err;

	objname = resource_name ? resource_name : "all";
	minor = -1;
	global_ctx.ctx_my_addr_len = 0;
	global_ctx.ctx_peer_addr_len = 0;
	err = generic_get(&cmd, 120000, &tail);
	objname = old_objname;
	minor = old_minor;
	global_ctx.ctx_my_addr_len = old_my_addr_len;
	global_ctx.ctx_peer_addr_len = old_peer_addr_len;
	if (err) {
		free_connections(list);
		list = NULL;
	}
	return list;
}

static void free_connections(struct connections_list *connections)
{
	while (connections) {
		struct connections_list *l = connections;
		connections = connections->next;
		free(l->net_conf);
		free(l);
	}
}

static int remember_peer_device(struct bsr_cmd *cmd, struct genl_info *info, void *u_ptr)
{
	struct peer_devices_list ***tail = u_ptr;
	struct bsr_cfg_context ctx = { .ctx_volume = -1U, .ctx_peer_node_id = -1U };

	if (!info)
		return 0;

	bsr_cfg_context_from_attrs(&ctx, info);
	if (ctx.ctx_resource_name) {
		struct peer_devices_list *p = calloc(1, sizeof(*p));
		struct nlattr *peer_device_conf = global_attrs[BSR_NLA_PEER_DEVICE_OPTS];
		if (!p) {
			CLI_ERRO_LOG(false, true, "failed to allocate peer devices list (20)");
			exit(20);
		}

		p->ctx = ctx;
		if (peer_device_conf) {
			int size;

			// DW-2072 make sure that it is smaller than the NLA_HDRLEN
			if (peer_device_conf->nla_len <= NLA_HDRLEN) {
				CLI_ERRO_LOG(false, true, "make sure that it is smaller than the NLA_HDRLEN(20)");
				exit(20);
			}

			size = nla_total_size((int)nla_len(peer_device_conf));

			p->peer_device_conf = malloc(size);
			memcpy(p->peer_device_conf, peer_device_conf, size);
		}
		p->info.peer_is_intentional_diskless = IS_INTENTIONAL_DEF;
		peer_device_info_from_attrs(&p->info, info);
		memset(&p->statistics, -1, sizeof(p->statistics));
		peer_device_statistics_from_attrs(&p->statistics, info);
		**tail = p;
		*tail = &p->next;
	}
	return 0;
}

/*
 * Expects objname to be set to the resource name or "all".
 */
static struct peer_devices_list *list_peer_devices(char *resource_name)
{
	struct bsr_cmd cmd = {
		.cmd_id = BSR_ADM_GET_PEER_DEVICES,
		.show_function = remember_peer_device,
		.missing_ok = false,
	};
	struct peer_devices_list *list = NULL, **tail = &list;
	char *old_objname = objname;
	unsigned old_minor = minor;
	int old_my_addr_len = global_ctx.ctx_my_addr_len;
	int old_peer_addr_len = global_ctx.ctx_peer_addr_len;
	int err;

	objname = resource_name ? resource_name : "all";
	minor = -1;
	global_ctx.ctx_my_addr_len = 0;
	global_ctx.ctx_peer_addr_len = 0;
	err = generic_get(&cmd, 120000, &tail);
	objname = old_objname;
	minor = old_minor;
	global_ctx.ctx_my_addr_len = old_my_addr_len;
	global_ctx.ctx_peer_addr_len = old_peer_addr_len;
	if (err) {
		free_peer_devices(list);
		list = NULL;
	}
	return list;
}

static void free_peer_devices(struct peer_devices_list *peer_devices)
{
	while (peer_devices) {
		struct peer_devices_list *p = peer_devices;
		peer_devices = peer_devices->next;
		free(p->peer_device_conf);
		free(p);
	}
}

static int check_resize_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct devices_list *devices, *device;
	bool found = false;
	bool ret = 0;

	devices = list_devices(NULL);
	for (device = devices; device; device = device->next) {
		struct bdev_info bd = { 0, };
		uint64_t bd_size;
		int fd;

		if (device->minor != minor)
			continue;
		found = true;

		if (!device->disk_conf.backing_dev) {
			CLI_ERRO_LOG_STDERR(false, "Has no disk config, try with bsrmeta.");
			ret = 1;
			break;
		}

		if (device->disk_conf.meta_dev_idx >= 0 ||
		    device->disk_conf.meta_dev_idx == BSR_MD_INDEX_FLEX_EXT) {
			lk_bdev_delete(minor);
			break;
		}

#ifdef _WIN
        char buf[256];
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "\\\\.\\%1s", device->disk_conf.backing_dev);
        strcpy(device->disk_conf.backing_dev, buf);
#endif
		fd = open(device->disk_conf.backing_dev, O_RDONLY);
		if (fd == -1) {
			CLI_ERRO_LOG_STDERR(false, "Could not open %s: %m.", device->disk_conf.backing_dev);
			ret = 1;
			break;
		}
#ifdef _WIN
        bd_size = bdev_size(device->disk_conf.backing_dev);
#else // _LIN
		bd_size = bdev_size(fd);
#endif
		close(fd);

		if (lk_bdev_load(minor, &bd) == 0 &&
		    bd.bd_size == bd_size &&
		    bd.bd_name && !strcmp(bd.bd_name, device->disk_conf.backing_dev))
			break;	/* nothing changed. */

		bd.bd_size = bd_size;
		bd.bd_name = device->disk_conf.backing_dev;
		lk_bdev_save(minor, &bd);
		break;
	}
	free_devices(devices);

	if (!found) {
		CLI_ERRO_LOG_STDERR(false, "%s: No such device", objname);
		return 10;
	}
	return ret;
}

#ifdef _LIN
// BSR-823
static int check_fs_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	// BSR-747 check for filesystem errors before initial synchronization
	struct devices_list *devices, *device;
	int need_recovery = 0;
	int ret = 0;
	struct peer_devices_list *peer_devices = NULL, *peer_device;

	devices = list_devices(NULL);
	for (device = devices; device; device = device->next) {
		if (device->minor != minor)
			continue;
		if (device->statistics.dev_current_uuid != UUID_JUST_CREATED)
			goto out;

		peer_devices = list_peer_devices(device->ctx.ctx_resource_name);
		for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
			// BSR-830 fix not to check filesystem if Inconsistent/SyncTarget state
			if (device->ctx.ctx_volume == peer_device->ctx.ctx_volume
				&& peer_device->info.peer_repl_state > L_ESTABLISHED)
				goto out;
		}
		
		need_recovery = need_filesystem_recovery(device->disk_conf.backing_dev);
		break;
	}

out:
	free_devices(devices);
	free_peer_devices(peer_devices);

	if (need_recovery) {
		CLI_ERRO_LOG_STDERR(false, "Filesystem check and recovery is required.");
		ret = 10;
	}

	return ret;
}
#endif

static bool peer_device_ctx_match(struct bsr_cfg_context *a, struct bsr_cfg_context *b)
{
	return
		strcmp(a->ctx_resource_name, b->ctx_resource_name) == 0
	&&	a->ctx_peer_node_id == b->ctx_peer_node_id
	&&	a->ctx_volume == b->ctx_volume;
}

static int show_or_get_gi_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct peer_devices_list *peer_devices, *peer_device;
	struct devices_list *devices = NULL, *device;
	uint64_t uuids[UI_SIZE];
	int ret = 0, i;

	peer_devices = list_peer_devices(NULL);
	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
		if (!peer_device_ctx_match(&global_ctx, &peer_device->ctx))
			continue;

		devices = list_devices(peer_device->ctx.ctx_resource_name);
		for (device = devices; device; device = device->next) {
			if (device->ctx.ctx_volume == global_ctx.ctx_volume)
				goto found;
		}
	}
	CLI_ERRO_LOG_STDERR(false, "%s: No such peer device", objname);
	ret = 10;

out:
	free_devices(devices);
	free_peer_devices(peer_devices);
	return ret;

found:
	if (peer_device->info.peer_repl_state == L_OFF &&
	    device->info.dev_disk_state == D_DISKLESS) {
		CLI_ERRO_LOG_STDERR(false, "Device is unconfigured");
		ret = 1;
		goto out;
	}
	if (device->info.dev_disk_state == D_DISKLESS) {
		/* XXX we could print the exposed_data_uuid anyways: */
		if (false)
			printf(X64(016)"\n", (uint64_t)device->statistics.dev_exposed_data_uuid);
		CLI_ERRO_LOG_STDERR(false, "Device has no disk");
		ret = 1;
		goto out;
	}
	memset(uuids, 0, sizeof(uuids));
	uuids[UI_CURRENT] = device->statistics.dev_current_uuid;
	uuids[UI_BITMAP] = peer_device->statistics.peer_dev_bitmap_uuid;
	i = device->statistics.history_uuids_len / 8;
	if (i >= HISTORY_UUIDS_V08)
		i = HISTORY_UUIDS_V08 - 1;
	for (; i >= 0; i--)
		uuids[UI_HISTORY_START + i] =
			((uint64_t *)device->statistics.history_uuids)[i];
	if(!strcmp(cm->cmd, "show-gi"))
		dt_pretty_print_v9_uuids(uuids, device->statistics.dev_disk_flags,
					 peer_device->statistics.peer_dev_flags);
	else
		dt_print_v9_uuids(uuids, device->statistics.dev_disk_flags,
				  peer_device->statistics.peer_dev_flags);
	goto out;
}

static int down_cmd(struct bsr_cmd *cm, int argc, char **argv)
{
	struct resources_list *resources, *resource;
	char *old_objname;
	int rv = 0;

	if(argc > 2) {
		warn_print_excess_args(argc, argv, 2);
		return OTHER_ERROR;
	}

	old_objname = objname;
	context = CTX_RESOURCE;

	resources = list_resources();
	for (resource = resources; resource; resource = resource->next) {
		struct devices_list *devices;
		int rv2;

		if (strcmp(old_objname, "all") && strcmp(old_objname, resource->name))
			continue;

		objname = resource->name;
		devices = list_devices(objname);
		rv2 = _generic_config_cmd(cm, argc, argv);
		if (!rv2) {
			struct devices_list *device;

			for (device = devices; device; device = device->next)
				unregister_minor(device->minor);
			unregister_resource(objname);
		}
		if (!rv)
			rv = rv2;
		free_devices(devices);
	}
	free_resources(resources);
	return rv;
}

#define EVENT_KEY_MAX 8192

#define _EVPRINT(checksize, fstr, ...) do { \
    ret = snprintf(key + pos, size, fstr, __VA_ARGS__); \
    if (ret < 0) \
        return ret; \
    pos += ret; \
    if (size && checksize) \
        size -= ret; \
} while(false)
#define EVPRINT(...) _EVPRINT(1, __VA_ARGS__)
/* for llvm static analyzer */
#define EVPRINT_NOSIZE(...) _EVPRINT(0, __VA_ARGS__)
static int event_key(char *key, int size, const char *name, unsigned minor,
		     struct bsr_cfg_context *ctx)
{
	char addr[ADDRESS_STR_MAX];
	int ret, pos = 0;

	if (!ctx) 
		return -1;

	if (name)
		EVPRINT("%s", name);

	if (ctx->ctx_resource_name)
		EVPRINT(" name:%s", ctx->ctx_resource_name);

	if (ctx->ctx_peer_node_id != -1U)
		EVPRINT(" peer-node-id:%d", ctx->ctx_peer_node_id);

	if (ctx->ctx_conn_name_len)
		EVPRINT(" conn-name:%s", ctx->ctx_conn_name);

	if (ctx->ctx_my_addr_len &&
		address_str(addr, ctx->ctx_my_addr, ctx->ctx_my_addr_len))
		EVPRINT(" local:%s", addr);
		    
	if (ctx->ctx_peer_addr_len &&
		address_str(addr, ctx->ctx_peer_addr, ctx->ctx_peer_addr_len))
		EVPRINT(" peer:%s", addr);

	if (ctx->ctx_volume != -1U)
		EVPRINT(" volume:%u", ctx->ctx_volume);

	if (minor != -1U)
		EVPRINT_NOSIZE(" minor:%u", minor);
	
	return pos;
}

static int known_objects_cmp(const void *a, const void *b) {
	return strcmp(((const struct entry *)a)->key, ((const struct entry *)b)->key);
}

static void *update_info(char **key, void *value, size_t size)
{
	static void *known_objects;

	struct entry entry = { .key = *key }, **found;

	if (value) {
		void *old_value = NULL;

		found = tsearch(&entry, &known_objects, known_objects_cmp);
		if (*found != &entry)
			old_value = (*found)->data;
		else {
			*found = malloc(sizeof(**found));
			if (!*found)
				goto fail;
			(*found)->key = *key;
			*key = NULL;
		}

		(*found)->data = malloc(size);
		if (!(*found)->data)
			goto fail;
		memcpy((*found)->data, value, size);

		return old_value;
	} else {
		found = tfind(&entry, &known_objects, known_objects_cmp);
		if (found) {
			struct entry *entry = *found;

			tdelete(entry, &known_objects, known_objects_cmp);
			free(entry->data);
			free(entry->key);
			free(entry);
		}
		return NULL;
	}

fail:
	CLI_ERRO_LOG_PEEROR(false, progname);
	exit(20);
}

static int print_notifications(struct bsr_cmd *cm, struct genl_info *info, void *u_ptr)
{
	static const char *action_name[] = {
		[NOTIFY_EXISTS] = "exists",
		[NOTIFY_CREATE] = "create",
		[NOTIFY_CHANGE] = "change",
		[NOTIFY_DESTROY] = "destroy",
		[NOTIFY_CALL] = "call",
		[NOTIFY_RESPONSE] = "response",
		// DW-1755
		[NOTIFY_ERROR] = "notify",
		// BSR-734
		[NOTIFY_DETECT] = "detect"
	};
	static char *object_name[] = {
		[BSR_RESOURCE_STATE] = "resource",
		[BSR_DEVICE_STATE] = "device",
		[BSR_CONNECTION_STATE] = "connection",
		[BSR_PEER_DEVICE_STATE] = "peer-device",
		[BSR_HELPER] = "helper",
		[BSR_PATH_STATE] = "path",
		[BSR_IO_ERROR] = "io-error",
		// BSR-676
		[BSR_UPDATED_GI_UUID] = "gi-uuid",
		[BSR_UPDATED_GI_DEVICE_MDF_FLAG] = "gi-device-mdf-flag",
		[BSR_UPDATED_GI_PEER_DEVICE_MDF_FLAG] = "gi-peer-device-mdf-flag",
		// BSR-734
		[BSR_SPLIT_BRAIN] = "split-brain",
		// BSR-859
		[BSR_NODE_INFO] = "node",
		[BSR_PEER_NODE_INFO] = "peer-node"
	};
	static uint32_t last_seq;
	static bool last_seq_known;
	static struct timeval tv;
	static bool keep_tv;

	struct bsr_cfg_context ctx = { .ctx_volume = -1U, .ctx_peer_node_id = -1U, };
	struct bsr_notification_header nh = { .nh_type = -1U };
	enum bsr_notification_type action;
	struct bsr_genlmsghdr *dh;
	char *key = NULL;

	if (!info) {
		keep_tv = false;
		return 0;
	}

	dh = info->userhdr;
	if (dh->ret_code == ERR_MINOR_INVALID && cm->missing_ok)
		return 0;
	if (dh->ret_code != ERR_NO)
		return dh->ret_code;

	if (bsr_notification_header_from_attrs(&nh, info))
		return 0;
	action = nh.nh_type & ~NOTIFY_FLAGS;
	if (action >= ARRAY_SIZE(action_name) ||
	    !action_name[action]) {
		dbg(1, "unknown notification type\n");
		goto out;
	}

	if (opt_now && action != NOTIFY_EXISTS)
		return 0;
	
	if (info->genlhdr->cmd != BSR_INITIAL_STATE_DONE) {
		if (bsr_cfg_context_from_attrs(&ctx, info)) {
			return 0;
		}

		if (info->genlhdr->cmd >= ARRAY_SIZE(object_name) ||
		    !object_name[info->genlhdr->cmd]) {
			dbg(1, "unknown notification\n");
			goto out;
		}
	}

	if (action != NOTIFY_EXISTS) {
		if (last_seq_known) {
			int skipped = info->nlhdr->nlmsg_seq - (last_seq + 1);

			if (skipped)
				printf("- skipped %d\n", skipped);
		}
		last_seq = info->nlhdr->nlmsg_seq;
		last_seq_known = true;
	}

	if (opt_timestamps) {
		struct tm *tm;

		if (!keep_tv)
			gettimeofday(&tv, NULL);
		keep_tv = !!(nh.nh_type & NOTIFY_CONTINUES);

		tm = localtime(&tv.tv_sec);
		printf("%04u-%02u-%02uT%02u:%02u:%02u.%06u%+03d:%02u ",
		       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		       tm->tm_hour, tm->tm_min, tm->tm_sec,
		       (int)tv.tv_usec,
		       (int)(tm->tm_gmtoff / 3600),
		       (int)((abs(tm->tm_gmtoff) / 60) % 60));
	}
	if (info->genlhdr->cmd != BSR_INITIAL_STATE_DONE) {
		const char *name = NULL;
		if (info->genlhdr->cmd != BSR_IO_ERROR)
			name = object_name[info->genlhdr->cmd];
		int size;

		size = event_key(NULL, 0, name, dh->minor, &ctx);
		if (size < 0 ||
			// DW-2072 add event_key() maximum(EVENT_KEY_MAX == 8192) value comparison condition
			size > EVENT_KEY_MAX)
			goto fail;
		key = malloc(size + 1);
		if (!key)
			goto fail;
		event_key(key, size + 1, name, dh->minor, &ctx);
	}

	// DW-1755
	if (info->genlhdr->cmd == BSR_IO_ERROR) {
		printf("%s %s%s%s",
			action_name[action], io_error_color_start(),
			object_name[info->genlhdr->cmd], io_error_color_stop());
	}
	else {
		printf("%s %s",
			action_name[action],
			key ? key : "-");
	}

	switch (info->genlhdr->cmd) {
	case BSR_RESOURCE_STATE:
		if (action != NOTIFY_DESTROY) {
			struct {
				struct resource_info i;
				struct resource_statistics s;
			} *old, new;

			if (resource_info_from_attrs(&new.i, info)) {
				dbg(1, "resource info missing\n");
				goto nl_out;
			}
			old = update_info(&key, &new, sizeof(new));
			if (!old || new.i.res_role != old->i.res_role)
				printf(" role:%s%s%s",
						ROLE_COLOR_STRING(new.i.res_role, 1));
			if (!old ||
			    new.i.res_susp != old->i.res_susp ||
			    new.i.res_susp_nod != old->i.res_susp_nod ||
			    new.i.res_susp_fen != old->i.res_susp_fen ||
			    new.i.res_susp_quorum != old->i.res_susp_quorum)
				printf(" suspended:%s",
				       susp_str(&new.i));
			if (opt_statistics) {
				if (resource_statistics_from_attrs(&new.s, info)) {
					dbg(1, "resource statistics missing\n");
					if (old)
						new.s = old->s;
				} else
					print_resource_statistics(0, old ? &old->s : NULL,
								  &new.s, nowrap_printf);
			}
			free(old);
		} else
			update_info(&key, NULL, 0);
		break;
	case BSR_DEVICE_STATE:
		if (action != NOTIFY_DESTROY) {
			struct {
				struct device_info i;
				struct device_statistics s;
			} *old, new;

			new.i.is_intentional_diskless = IS_INTENTIONAL_DEF;
			if (device_info_from_attrs(&new.i, info)) {
				dbg(1, "device info missing\n");
				goto nl_out;
			}
			old = update_info(&key, &new, sizeof(new));
			if (!old || new.i.dev_disk_state != old->i.dev_disk_state) {
				bool intentional = new.i.is_intentional_diskless == 1;
				printf(" disk:%s%s%s",
					DISK_COLOR_STRING(new.i.dev_disk_state, intentional, true));
				printf(" client:%s", intentional_diskless_str(&new.i));
			}
			if (opt_statistics) {
				if (device_statistics_from_attrs(&new.s, info)) {
					dbg(1, "device statistics missing\n");
					if (old)
						new.s = old->s;
				} else
					print_device_statistics(0, old ? &old->s : NULL,
								&new.s, nowrap_printf);
			}
			free(old);
		} else
			update_info(&key, NULL, 0);
		break;
	case BSR_CONNECTION_STATE:
		if (action != NOTIFY_DESTROY) {
			struct {
				struct connection_info i;
				struct connection_statistics s;
			} *old, new;

			if (connection_info_from_attrs(&new.i, info)) {
				dbg(1, "connection info missing\n");
				goto nl_out;
			}
			old = update_info(&key, &new, sizeof(new));
			if (!old ||
			    new.i.conn_connection_state != old->i.conn_connection_state)
				printf(" connection:%s%s%s",
						CONN_COLOR_STRING(new.i.conn_connection_state));
			if (!old ||
			    new.i.conn_role != old->i.conn_role)
				printf(" role:%s%s%s",
						ROLE_COLOR_STRING(new.i.conn_role, 0));
			if (opt_statistics) {
				if (connection_statistics_from_attrs(&new.s, info)) {
					dbg(1, "connection statistics missing\n");
					if (old)
						new.s = old->s;
				} else
					print_connection_statistics(0, old ? &old->s : NULL,
								    &new.s, nowrap_printf);
			}
			free(old);
		} else
			update_info(&key, NULL, 0);
		break;
	case BSR_PEER_DEVICE_STATE:
		if (action != NOTIFY_DESTROY) {
			struct {
				struct peer_device_info i;
				struct peer_device_statistics s;
			} *old, new;

			new.i.peer_is_intentional_diskless = IS_INTENTIONAL_DEF;
			if (peer_device_info_from_attrs(&new.i, info)) {
				dbg(1, "peer device info missing\n");
				goto nl_out;
			}
			old = update_info(&key, &new, sizeof(new));
			if (!old || new.i.peer_repl_state != old->i.peer_repl_state)
				printf(" replication:%s%s%s",
						REPL_COLOR_STRING(new.i.peer_repl_state));
			if (!old || new.i.peer_disk_state != old->i.peer_disk_state) {
				bool intentional = new.i.peer_is_intentional_diskless == 1;
				printf(" peer-disk:%s%s%s",
					DISK_COLOR_STRING(new.i.peer_disk_state, intentional, false));
				printf(" peer-client:%s", peer_intentional_diskless_str(&new.i));
			}
			if (!old ||
			    new.i.peer_resync_susp_user != old->i.peer_resync_susp_user ||
			    new.i.peer_resync_susp_peer != old->i.peer_resync_susp_peer ||
			    new.i.peer_resync_susp_dependency != old->i.peer_resync_susp_dependency)
				printf(" resync-suspended:%s",
				       resync_susp_str(&new.i));
			if (opt_statistics) {
				if (peer_device_statistics_from_attrs(&new.s, info)) {
					dbg(1, "peer device statistics missing\n");
					if (old)
						new.s = old->s;
				} else
					print_peer_device_statistics(0, old ? &old->s : NULL,
								     &new.s, nowrap_printf);
			}
			free(old);
		} else
			update_info(&key, NULL, 0);
		break;
	case BSR_PATH_STATE:
		if (action != NOTIFY_DESTROY) {
			struct bsr_path_info new = {}, *old;

			if (bsr_path_info_from_attrs(&new, info)) {
				dbg(1, "path info missing\n");
				goto nl_out;
			}
			old = update_info(&key, &new, sizeof(new));
			if (!old || old->path_established != new.path_established)
				printf(" established:%s",
				       new.path_established ? "yes" : "no");
			free(old);
		} else
			update_info(&key, NULL, 0);
		break;
	case BSR_HELPER: 
	{
		struct bsr_helper_info helper_info;

		if (!bsr_helper_info_from_attrs(&helper_info, info)) {
			printf(" helper:%s", helper_info.helper_name);
			if (action == NOTIFY_RESPONSE)
				printf(" status:%u", helper_info.helper_status);
		} else {
			dbg(1, "helper info missing\n");
			goto nl_out;
		}
	}
		break;
	// DW-1755
	case BSR_IO_ERROR: 
	{
		struct bsr_io_error_info io_error = { 0, };
		if (!bsr_io_error_info_from_attrs(&io_error, info)) {
			if (io_error.is_cleared)
				printf(" cleared%s", key ? key : "-");
			else {

				printf("%s disk:%s io:%s", key ? key : "-", bsr_disk_type_name(io_error.disk_type), bsr_io_type_name(io_error.io_type));

				printf(" error-code:0x%08X sector:%llus size:%u", io_error.error_code, io_error.sector, io_error.size);
			}
		}
		else {
			dbg(1, "io_error info missing\n");
			goto nl_out;
		}
	}
		break;
	// BSR-676 UUID information is output.
	case BSR_UPDATED_GI_UUID:
	{
		struct bsr_updated_gi_uuid_info gi = { 0, };
		if (!bsr_updated_gi_uuid_info_from_attrs(&gi, info)) {
			printf(" %s", gi.uuid);
		}
		break;
	}
	// BSR-676 device mdf flag information is output.
	case BSR_UPDATED_GI_DEVICE_MDF_FLAG:
	{
		struct bsr_updated_gi_device_mdf_flag_info gi = { 0, };
		if (!bsr_updated_gi_device_mdf_flag_info_from_attrs(&gi, info)) {
			printf(" %s", gi.device_mdf);
		}
		break;
	}
	// BSR-676 peer_device mdf flag information is output.
	case BSR_UPDATED_GI_PEER_DEVICE_MDF_FLAG:
	{
		struct bsr_updated_gi_peer_device_mdf_flag_info gi = { 0, };
		if (!bsr_updated_gi_peer_device_mdf_flag_info_from_attrs(&gi, info)) {
			printf(" %s", gi.peer_device_mdf);
		}
		break;
	}
	// BSR-734
	case BSR_SPLIT_BRAIN:
	{
		struct bsr_split_brain_info sb_info;
		if (!bsr_split_brain_info_from_attrs(&sb_info, info)) {
			printf(" recover:%s", sb_info.recover);
		}
		break;
	}

	// BSR-859
	case BSR_NODE_INFO:
	case BSR_PEER_NODE_INFO:
	{
		struct bsr_node_info new = {}, *old;
	
		if (bsr_node_info_from_attrs(&new, info)) {
			dbg(1, "node info missing\n");
			goto nl_out;
		}
		old = update_info(&key, &new, sizeof(new));

		if (!old || old->_nodename != new._nodename) {
			printf(" type:%s", bsr_host_type_name(new._nodename));
			printf(" %s:%s", 
				(info->genlhdr->cmd == BSR_NODE_INFO) ? "node-name" : "peer-node-name",
				strcmp(new._nodename, "") ? new._nodename : "unknown");
		}
		free(old);
		break;
	}

	case BSR_INITIAL_STATE_DONE:
		break;
	}

nl_out:
	printf("\n");
out:
	free(key);
	fflush(stdout);
	if (opt_now && info->genlhdr->cmd == BSR_INITIAL_STATE_DONE)
		return -1;
	return 0;

fail:
	CLI_ERRO_LOG_PEEROR(false, progname);
	exit(20);
}

void peer_devices_append(struct peer_devices_list *peer_devices, struct genl_info *info)
{
	struct peer_devices_list *peer_device, **tail;

	if (!peer_devices)
		return;

	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next)
		tail = &peer_device->next;

	remember_peer_device(NULL, info, &tail);
}

/* Actually waits for all volumes of a connection... */
static int wait_for_family(struct bsr_cmd *cm, struct genl_info *info, void *u_ptr)
{
	struct peer_devices_list *peer_devices = u_ptr;
	struct bsr_cfg_context ctx = { .ctx_volume = -1U, .ctx_peer_node_id = -1U };
	struct bsr_notification_header nh = { .nh_type = -1U };
	struct bsr_genlmsghdr *dh;

	if (!info)
		return 0;

	if (bsr_cfg_context_from_attrs(&ctx, info) ||
	    bsr_notification_header_from_attrs(&nh, info))
		return 0;

	dh = info->userhdr;
	if (dh->ret_code != ERR_NO)
		return dh->ret_code;

	if ((nh.nh_type & ~NOTIFY_FLAGS) == NOTIFY_DESTROY)
		return 0;

	switch(info->genlhdr->cmd) {
	case BSR_CONNECTION_STATE: {
		struct connection_info connection_info;

		if ((nh.nh_type & ~NOTIFY_FLAGS) == NOTIFY_CREATE)
			break; /* Ignore C_STANDALONE while creating it */

		if (connection_info_from_attrs(&connection_info, info)) {
			dbg(1, "connection info missing\n");
			break;
		}
		if (connection_info.conn_connection_state < C_UNCONNECTED) {
			if (!wait_after_split_brain)
				return -1;  /* done waiting */

			CLI_ERRO_LOG_STDERR(false, "\nbsr %s connection to peer-id %u ('%s') is %s, "
						"but I'm configured to wait anways (--wait-after-sb)\n",
						ctx.ctx_resource_name, ctx.ctx_peer_node_id, ctx.ctx_conn_name,
						bsr_conn_str(connection_info.conn_connection_state));
		}
		break;
	}
	case BSR_PEER_DEVICE_STATE: {
		struct peer_device_info peer_device_info;
		struct peer_devices_list *peer_device;
		int nr_peer_devices = 0, nr_done = 0;
		bool wait_connect;

		if (peer_device_info_from_attrs(&peer_device_info, info)) {
			dbg(1, "peer device info missing\n");
			break;
		}

		wait_connect = strstr(cm->cmd, "sync") == NULL;

		if ((nh.nh_type & ~NOTIFY_FLAGS) == NOTIFY_CREATE)
			peer_devices_append(peer_devices, info);

		for (peer_device = peer_devices;
		     peer_device;
		     peer_device = peer_device->next) {
			enum bsr_repl_state rs;

			if (peer_device_ctx_match(&ctx, &peer_device->ctx))
				peer_device->info = peer_device_info;

			/* wait-*-volume: filter out all but the specific peer device */
			if (cm->ctx_key == CTX_PEER_DEVICE &&
			    !peer_device_ctx_match(&global_ctx, &peer_device->ctx))
				continue;

			/* wait-*-connection: filter out other connections */
			if (cm->ctx_key == CTX_PEER_NODE &&
			    peer_device->ctx.ctx_peer_node_id != global_ctx.ctx_peer_node_id)
				continue;

			/* wait-*-resource: no filter */
			nr_peer_devices++;

			rs = peer_device->info.peer_repl_state;
			if (rs == L_ESTABLISHED ||
			    (wait_connect && rs > L_ESTABLISHED) ||
			    peer_device->timeout_ms == 0)
				nr_done++;
		}

		if (nr_peer_devices == nr_done)
			return -1; /* Done with waiting */

		break;
	}
	}

	return 0;
}

/*
 * Check if an integer is a power of two.
 */
static bool power_of_two(int i)
{
	return i && !(i & (i - 1));
}

static void print_command_usage(struct bsr_cmd *cm, enum usage_type ut)
{
	struct bsr_argument *args;

	if(ut == XML) {
		printf("<command name=\"%s\">\n", cm->cmd);
		if (cm->summary)
			printf("\t<summary>%s</summary>\n", cm->summary);
		if (cm->ctx_key && ut != BRIEF) {
			enum cfg_ctx_key ctx = cm->ctx_key, arg;
			bool more_than_one_choice =
				!power_of_two(ctx & ~CTX_MULTIPLE_ARGUMENTS) &&
				!(ctx & CTX_MULTIPLE_ARGUMENTS);
			const char *indent = "\t\t" + !more_than_one_choice;

			if (more_than_one_choice)
				printf("\t<group>\n");
			ctx |= CTX_MULTIPLE_ARGUMENTS;
			for (arg = ctx_next_arg(&ctx); arg; arg = ctx_next_arg(&ctx))
				printf("%s<argument>%s</argument>\n",
				       indent, ctx_arg_string(arg, ut));
			if (more_than_one_choice)
				printf("\t</group>\n");
		}

		if(cm->bsr_args) {
			for (args = cm->bsr_args; args->name; args++) {
				printf("\t<argument>%s</argument>\n",
				       args->name);
			}
		}

		if (cm->options) {
			struct option *option;

			for (option = cm->options; option->name; option++) {
				/*
				 * The "string" options here really are
				 * timeouts, but we can't describe them
				 * in a resonable way here.
				 */
				printf("\t<option name=\"%s\" type=\"%s\">\n"
				       "\t</option>\n",
				       option->name,
				       option->has_arg == no_argument ?
					 "flag" : "string");
			}
		}

		if (cm->set_defaults)
			printf("\t<option name=\"set-defaults\" type=\"flag\">\n"
			       "\t</option>\n");

		if (cm->ctx) {
			struct field_def *field;

			for (field = cm->ctx->fields; field->name; field++)
				field->ops->describe_xml(field);
		}
		printf("</command>\n");
		return;
	}

	if (ut == BRIEF) {
		wrap_printf(4, "%s - ", cm->cmd);
		if (cm->summary)
			wrap_printf_wordwise(8, cm->summary);
		wrap_printf(4, "\n");
	} else {
		wrap_printf(0, "%s %s", progname, cm->cmd);
		if (cm->summary)
			wrap_printf(4, " - %s", cm->summary);
		wrap_printf(4, "\n\n");

		wrap_printf(0, "USAGE: %s %s", progname, cm->cmd);

		if (cm->ctx_key && ut != BRIEF) {
			enum cfg_ctx_key ctx = cm->ctx_key, arg;
			bool more_than_one_choice =
				!power_of_two(ctx & ~CTX_MULTIPLE_ARGUMENTS) &&
				!(ctx & CTX_MULTIPLE_ARGUMENTS);
			bool first = true;

			if (more_than_one_choice)
				wrap_printf(4, " {");
			ctx |= CTX_MULTIPLE_ARGUMENTS;
			for (arg = ctx_next_arg(&ctx); arg; arg = ctx_next_arg(&ctx)) {
				if (more_than_one_choice && !first)
					wrap_printf(4, " |");
				first = false;
				wrap_printf(4, " %s", ctx_arg_string(arg, ut));
			}
			if (more_than_one_choice)
				wrap_printf(4, " }");
		}

		if (cm->bsr_args) {
			for (args = cm->bsr_args; args->name; args++)
				wrap_printf(4, " {%s}", args->name);
		}

		if (cm->options || cm->set_defaults || cm->ctx)
			wrap_printf(4, "\n");

		if (cm->options) {
			struct option *option;

			for (option = cm->options; option->name; option++)
				wrap_printf(4, " [--%s%s]",
					    option->name,
					    option->has_arg == no_argument ?
					        "" : "=...");
		}

		if (cm->set_defaults)
			wrap_printf(4, " [--set-defaults]");

		if (cm->ctx) {
			struct field_def *field;

			for (field = cm->ctx->fields; field->name; field++) {
				char buffer[300];
				int n;
				n = field->ops->usage(field, buffer, sizeof(buffer));
				assert(n < sizeof(buffer));
				wrap_printf(4, " %s", buffer);
			}
		}
		wrap_printf(4, "\n");
	}
}

static void print_usage_and_exit(const char *addinfo)
{
	size_t i;

	printf("bsrsetup - Configure the BSR kernel module.\n\n"
	       "USAGE: %s command {arguments} [options]\n"
	       "\nCommands:\n",cmdname);


	for (i = 0; i < ARRAY_SIZE(commands); i++)
		print_command_usage(&commands[i], BRIEF);

	printf("\nUse 'bsrsetup help command' for command-specific help.\n\n");
	if (addinfo)  /* FIXME: ?! */
		printf("\n%s\n", addinfo);

	CLI_WRAN_LOG(false, "print usage and exit(20)\n");
	exit(20);
}

static int modprobe_bsr(void)
{
#ifdef _LIN
	struct stat sb;
	int ret, retries = 10;

	ret = stat("/proc/bsr", &sb);
	if (ret && errno == ENOENT) {
		// BSR-1089 BSR-1097 if modprobe provides the --allow-unsupported option, use it.
		ret = system("/sbin/modprobe --dry-run --allow-unsupported bsr > /dev/null 2>&1");
		if (ret == 0)
			ret = system("/sbin/modprobe --allow-unsupported bsr");
		else
			ret = system("/sbin/modprobe bsr");

		if (ret != 0) {
			CLI_ERRO_LOG_STDERR(false, "Failed to modprobe bsr (%m)");
			return 0;
		}
		for(;;) {
			struct timespec ts = {
				.tv_nsec = 1000000,
			};

			ret = stat("/proc/bsr", &sb);
			if (!ret || retries-- == 0)
				break;
			nanosleep(&ts, NULL);
		}
	}
	if (ret) {
		CLI_ERRO_LOG_STDERR(false, "Could not stat /proc/bsr: %m");
		CLI_ERRO_LOG_STDERR(false, "Make sure that the BSR kernel module is installed "
				"and can be loaded!\n");
	}
	return ret == 0;
#endif
	return 1;
}

static void maybe_exec_legacy_bsrsetup(char **argv)
{
	const struct version *driver_version = bsr_driver_version(FALLBACK_TO_UTILS);

	if (driver_version->version.major == 8 &&
	    driver_version->version.minor == 3) {
#ifdef BSR_LEGACY_83
		static const char * const bsrsetup_83 = "bsrsetup-83";

		add_lib_bsr_to_path();
		execvp(bsrsetup_83, argv);
		CLI_ERRO_LOG_STDERR(false, "execvp() failed to exec %s: %m", bsrsetup_83);
#else
		config_help_legacy("bsrsetup", driver_version);

#endif
		exit(20);
	}
	if (driver_version->version.major == 8 &&
	    driver_version->version.minor == 4) {
#ifdef BSR_LEGACY_84
		static const char * const bsrsetup_84 = "bsrsetup-84";

		add_lib_bsr_to_path();
		execvp(bsrsetup_84, argv);
		CLI_ERRO_LOG_STDERR(false, "execvp() failed to exec %s: %m", bsrsetup_84);
#else
		config_help_legacy("bsrsetup", driver_version);
#endif
		exit(20);
	}
}

extern char* lprogram;
// BSR-614
extern int llevel;

int main(int argc, char **argv)
{
	struct bsr_cmd *cmd;
	struct option *options;
	const char *opts;
	int c, rv = 0;
	int longindex, first_optind;

	lprogram = progname = basename(argv[0]);

	// BSR-1031 set execution_log, output on error
	set_exec_log(argc, argv);

	if (chdir("/")) {
		/* highly unlikely, but gcc is picky */
		CLI_ERRO_LOG_PEEROR(false, "cannot chdir /");
		return -111;
	}

	cmdname = strrchr(argv[0],'/');
	if (cmdname)
		argv[0] = ++cmdname;
	else
		cmdname = argv[0];

	if (argc > 2 && (!strcmp(argv[2], "--help")  || !strcmp(argv[2], "-h"))) {
		char *swap = argv[1];
		argv[1] = argv[2];
		argv[2] = swap;
	}

	if (argc > 1 && (!strcmp(argv[1], "help") || !strcmp(argv[1], "xml-help")  ||
			 !strcmp(argv[1], "--help")  || !strcmp(argv[1], "-h"))) {
		enum usage_type usage_type = !strcmp(argv[1], "xml-help") ? XML : FULL;
		if(argc > 2) {
			cmd = find_cmd_by_name(argv[2]);
			if(cmd) {
				print_command_usage(cmd, usage_type);
				CLI_INFO_LOG(false, "print command usage");
				exit(0);
			} else
				print_usage_and_exit("unknown command");
		} else
			print_usage_and_exit(NULL);
	}

	/*
	 * bsrsetup previously took the object to operate on as its first argument,
	 * followed by the command.  For backwards compatibility, still support his.
	 */
	if (argc >= 3 && !find_cmd_by_name(argv[1]) && find_cmd_by_name(argv[2])) {
		char *swap = argv[1];
		argv[1] = argv[2];
		argv[2] = swap;
	}

	if (argc < 2)
		print_usage_and_exit(NULL);

	if (!modprobe_bsr()) {
		if (!strcmp(argv[1], "down") ||
		    !strcmp(argv[1], "secondary") ||
		    !strcmp(argv[1], "disconnect") ||
		    !strcmp(argv[1], "detach"))
			return 0; /* "down" succeeds even if bsr is missing */
		return 20;
	}

	maybe_exec_legacy_bsrsetup(argv);

	cmd = find_cmd_by_name(argv[1]);
	if (!cmd)
		print_usage_and_exit("invalid command");

	lcmd = (char *)cmd->cmd;
	// BSR-1031
	lstatus = cmd->is_status_cmd ? 1 : 0;
	// execution_log output
	bsr_exec_log();

	/* Make argv[0] the command name so that getopt_long() will leave it in
	 * the first position. */
	argv++;
	argc--;

	options = make_longoptions(cmd);
	opts = make_optstring(options);
	for (;;) {
		c = getopt_long(argc, argv, opts, options, &longindex);
		if (c == -1)
			break;
		if (c == '?' || c == ':')
			print_usage_and_exit(NULL);
	}
	/* All non-option arguments now are in argv[optind .. argc - 1]. */
	first_optind = optind;

	if (cmd->continuous_poll && kernel_older_than(2, 6, 23)) {
		/* with newer kernels, we need to use setsockopt NETLINK_ADD_MEMBERSHIP */
		/* maybe more specific: (1 << GENL_ID_CTRL)? */
		bsr_genl_family.nl_groups = -1;
	}
	bsr_sock = genl_connect_to_family(&bsr_genl_family);
	if (!bsr_sock) {
		CLI_ERRO_LOG_STDERR(false, "Could not connect to 'bsr' generic netlink family");
		return 20;
	}

	if (bsr_genl_family.version != GENL_MAGIC_VERSION ||
	    bsr_genl_family.hdrsize != sizeof(struct bsr_genlmsghdr)) {
		CLI_ERRO_LOG_STDERR(false, "API mismatch!\n\t"
			"API version bsrsetup: %u kernel: %u\n\t"
			"header size bsrsetup: %u kernel: %u\n",
			GENL_MAGIC_VERSION, bsr_genl_family.version,
			(unsigned)sizeof(struct bsr_genlmsghdr),
			bsr_genl_family.hdrsize);
		return 20;
	}

	context = 0;
	enum cfg_ctx_key ctx_key = cmd->ctx_key, next_arg;
	for (next_arg = ctx_next_arg(&ctx_key);
	     next_arg;
	     next_arg = ctx_next_arg(&ctx_key), optind++) {
		if (argc == optind &&
		    !(ctx_key & CTX_MULTIPLE_ARGUMENTS) && (next_arg & CTX_ALL)) {
			context |= CTX_ALL;  /* assume "all" if no argument is given */
			objname = "all";
			break;
		} else if (argc <= optind) {
			CLI_ERRO_LOG_STDERR(false, "Missing argument %d to command", optind);
			print_command_usage(cmd, FULL);
			exit(20);
		} else if (next_arg & (CTX_RESOURCE | CTX_MINOR | CTX_ALL)) {
			ensure_sanity_of_res_name(argv[optind]);
			if (!objname)
				objname = argv[optind];
			if (!strcmp(argv[optind], "all")) {
				if (!(next_arg & CTX_ALL))
					print_usage_and_exit("command does not accept argument 'all'");
				context |= CTX_ALL;
			} else if (next_arg & CTX_MINOR) {
				minor = dt_minor_of_dev(argv[optind]);
				if (minor == -1U && next_arg == CTX_MINOR) {
					CLI_ERRO_LOG_STDERR(false, "Cannot determine minor device number of "
							"device '%s'\n",
						argv[optind]);
					exit(20);
				}
				context |= CTX_MINOR;
			} else /* not "all", and not a minor number/device name */ {
				if (!(next_arg & CTX_RESOURCE)) {
					CLI_ERRO_LOG_STDERR(false, "command does not accept argument '%s'",
						objname);
					print_command_usage(cmd, FULL);
					exit(20);
				}
				context |= CTX_RESOURCE;
				assert(strlen(objname) < sizeof(global_ctx.ctx_resource_name));
				memset(global_ctx.ctx_resource_name, 0, sizeof(global_ctx.ctx_resource_name));
				global_ctx.ctx_resource_name_len = strlen(objname);
				strcpy(global_ctx.ctx_resource_name, objname);
			}
		} else {
			if (next_arg == CTX_MY_ADDR) {
				const char *str = argv[optind];
				struct sockaddr_storage *x;

				if (strncmp(str, "local:", 6) == 0)
					str += 6;
				assert(sizeof(global_ctx.ctx_my_addr) >= sizeof(*x));
				x = (struct sockaddr_storage *)&global_ctx.ctx_my_addr;
				global_ctx.ctx_my_addr_len = sockaddr_from_str(x, str, false);
			} else if (next_arg == CTX_PEER_ADDR) {
				const char *str = argv[optind];
				struct sockaddr_storage *x;

				if (strncmp(str, "peer:", 5) == 0)
					str += 5;
				assert(sizeof(global_ctx.ctx_peer_addr) >= sizeof(*x));
				x = (struct sockaddr_storage *)&global_ctx.ctx_peer_addr;
				global_ctx.ctx_peer_addr_len = sockaddr_from_str(x, str, true);
			} else if (next_arg == CTX_VOLUME) {
				global_ctx.ctx_volume = m_strtoll(argv[optind], 1);
			} else if (next_arg == CTX_PEER_NODE_ID) {
				global_ctx.ctx_peer_node_id = m_strtoll(argv[optind], 1);
			} else
				assert(0);
			context |= next_arg;
		}
	}

	/* Remove the options we have already processed from argv */
	if (first_optind != optind) {
		int n;

		for (n = 0; n < argc - optind; n++)
			argv[first_optind + n] = argv[optind + n];
		argc -= optind - first_optind;
	}

	if (!objname)
		objname = "??";

	if ((context & CTX_MINOR) && !cmd->lockless)
		lock_fd = dt_lock_bsr(minor);

	rv = cmd->function(cmd, argc, argv);

	if ((context & CTX_MINOR) && !cmd->lockless)
		dt_unlock_bsr(lock_fd);

	bsr_terminate_log(rv);

	return rv;
}
#endif
