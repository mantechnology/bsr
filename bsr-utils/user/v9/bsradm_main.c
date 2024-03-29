/*
   bsradm_main.c

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

#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <search.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include "bsr.h"
#include "linux/bsr_limits.h"
#include "bsrtool_common.h"
#include "bsradm.h"
#include "registry.h"
#include "config_flags.h"
#include "bsradm_dump.h"
#include "shared_main.h"
#include "bsradm_parser.h"
#ifdef _WIN
#include <windows.h>
typedef _off64_t off64_t;
#undef BSR_CONFIG_DIR
#define BSR_CONFIG_DIR "/etc"
#endif

#define MAX_ARGS 40

char *progname;

struct deferred_cmd {
	struct cfg_ctx ctx;
	STAILQ_ENTRY(deferred_cmd) link;
};

struct option general_admopt[] = {
	{"stacked", no_argument, 0, 'S'},
	{"dry-run", no_argument, 0, 'd' },
	{"log-level-trace", no_argument, 0, 'T' },
	{"ignore-hostname", no_argument, 0, 'i'}, // DW-1719
	{"verbose", no_argument, 0, 'v'},
	{"config-file", required_argument, 0, 'c'},
	{"config-to-test", required_argument, 0, 't'},
	{"config-to-exclude", required_argument, 0, 'E'},
	{"bsrsetup", required_argument, 0, 's'},
	{"bsrmeta", required_argument, 0, 'm'},
	{"bsr-proxy-ctl", required_argument, 0, 'p'},
	{"sh-varname", required_argument, 0, 'n'},
	{"peer", required_argument, 0, 'P'},
	{"version", no_argument, 0, 'V'},
	{"setup-option", required_argument, 0, 'W'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};
struct option *admopt = general_admopt;

extern int yydebug;
extern FILE *yyin;

static int adm_adjust(const struct cfg_ctx *ctx);
static int adm_new_minor(const struct cfg_ctx *ctx);
static int adm_resource(const struct cfg_ctx *);
static int adm_node(const struct cfg_ctx *);
static int adm_attach(const struct cfg_ctx *);
static int adm_connect(const struct cfg_ctx *);
static int adm_new_peer(const struct cfg_ctx *);
static int adm_path(const struct cfg_ctx *);
static int adm_resize(const struct cfg_ctx *);
static int adm_up(const struct cfg_ctx *);
static int adm_wait_c(const struct cfg_ctx *);
static int adm_wait_ci(const struct cfg_ctx *);
static int adm_proxy_up(const struct cfg_ctx *);
static int adm_proxy_down(const struct cfg_ctx *);
static int sh_nop(const struct cfg_ctx *);
static int sh_resources_list(const struct cfg_ctx *);
// DW-1249 auto-start by svc
static int sh_resource_option(const struct cfg_ctx *);
static int sh_node_option(const struct cfg_ctx *);
static int sh_resources(const struct cfg_ctx *);
static int sh_resource(const struct cfg_ctx *);
static int sh_mod_parms(const struct cfg_ctx *);
static int sh_dev(const struct cfg_ctx *);
static int sh_udev(const struct cfg_ctx *);
static int sh_minor(const struct cfg_ctx *);
static int sh_ip(const struct cfg_ctx *);
static int sh_lres(const struct cfg_ctx *);
static int sh_ll_dev(const struct cfg_ctx *);
static int sh_md_dev(const struct cfg_ctx *);
static int sh_md_idx(const struct cfg_ctx *);
// BSR-675
static int sh_peer_node_id(const struct cfg_ctx *);
static int sh_dev_vnr(const struct cfg_ctx *);
// BSR-688
static int sh_peer_node_name(const struct cfg_ctx *);
// BSR-808
static int sh_peer_nodes(const struct cfg_ctx *);
static int adm_bsrmeta(const struct cfg_ctx *);
static int adm_khelper(const struct cfg_ctx *);
static int adm_setup_and_meta(const struct cfg_ctx *);
static int hidden_cmds(const struct cfg_ctx *);
static int adm_outdate(const struct cfg_ctx *);
static int adm_chk_resize(const struct cfg_ctx *);
static int adm_bsrsetup(const struct cfg_ctx *);
static int adm_invalidate(const struct cfg_ctx *);
static int __adm_bsrsetup_silent(const struct cfg_ctx *ctx);
static int adm_forget_peer(const struct cfg_ctx *);
static int adm_peer_device(const struct cfg_ctx *);
// BSR-823
static int adm_primary(const struct cfg_ctx *);

int ctx_by_name(struct cfg_ctx *ctx, const char *id, checks check);
int was_file_already_seen(char *fn);

static char *get_opt_val(struct options *, const char *, char *);

char ss_buffer[1024];
const char *hostname;
int line = 1;
int fline;

char *config_file = NULL;
char *config_save = NULL;
char *config_test = NULL;
char *parse_file = NULL;
struct resources config = STAILQ_HEAD_INITIALIZER(config);
struct d_resource *common = NULL;
struct ifreq *ifreq_list = NULL;
int is_bsr_top;
enum { NORMAL, STACKED, IGNORED, __N_RESOURCE_TYPES };
int nr_resources[__N_RESOURCE_TYPES];
int nr_volumes[__N_RESOURCE_TYPES];
int number_of_minors = 0;
int config_from_stdin = 0;
int config_valid = 1;
int no_tty;
int dry_run = 0;
int ignore_hostname = 0; // DW-1719 Added option to ignore hostname check
int verbose = 0;
int adjust_with_progress = 0;
bool help;
int do_verify_ips = 0;
int do_register = 1;
/* whether bsradm was called with "all" instead of resource name(s) */
int all_resources = 0;
/* if we want to adjust more than one resource,
* instead of iteratively calling "bsrsetup show" for each of them,
* call "bsrsetup show" once for all of them. */
int adjust_more_than_one_resource = 0;
char *bsrsetup = NULL;
char *bsrmeta = NULL;
char *bsradm_83 = NULL;
char *bsradm_84 = NULL;
char *bsr_proxy_ctl;
char *sh_varname = NULL;
struct names backend_options = STAILQ_HEAD_INITIALIZER(backend_options);

char *connect_to_host = NULL;
#ifdef _LIN
bool force_primary = false;
#endif
STAILQ_HEAD(deferred_cmds, deferred_cmd) deferred_cmds[__CFG_LAST];

int adm_adjust_wp(const struct cfg_ctx *ctx)
{
	if (!verbose && !dry_run)
		adjust_with_progress = 1;
	return adm_adjust(ctx);
}

/* BSR adm_cmd flags shortcuts,
 * to avoid merge conflicts and unreadable diffs
 * when we add the next flag */

#define ACF1_DEFAULT			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define ACF1_MINOR_ONLY			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 0,		\
	.iterate_volumes = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\
	.disk_required = 1,		\

#define ACF1_RESNAME			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.uc_dialog = 1,			\

#define ACF1_CONNECT			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.iterate_volumes = 0,		\
	.verify_ips = 1,		\
	.need_peer = 1,			\
	.uc_dialog = 1,			\

#define ACF1_DISCONNECT			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.need_peer = 1,			\
	.uc_dialog = 1,			\

#define ACF1_DEFNET			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 1,		\
	.need_peer = 1,			\
	.uc_dialog = 1,			\

#define ACF1_WAIT			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.vol_id_optional = 1,		\
	.verify_ips = 1,		\
	.uc_dialog = 1,			\

#define ACF1_PEER_DEVICE		\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.iterate_volumes = 1,		\
	.need_peer = 1,			\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define ACF3_RES_HANDLER		\
	.show_in_usage = 3,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.iterate_volumes = 0,		\
	.vol_id_required = 0,		\
	.verify_ips = 0,		\
	.use_cached_config_file = 1,	\

#define ACF4_ADVANCED			\
	.show_in_usage = 4,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define ACF4_ADVANCED_NEED_VOL		\
	.show_in_usage = 4,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.iterate_volumes = 1,		\
	.vol_id_required = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define ACF1_DUMP			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.verify_ips = 1,		\
	.uc_dialog = 1,			\
	.test_config = 1,		\

#define ACF2_SHELL			\
	.show_in_usage = 2,		\
	.iterate_volumes = 1,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.verify_ips = 0,		\

#define ACF2_SH_RESNAME			\
	.show_in_usage = 2,		\
	.iterate_volumes = 0,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.verify_ips = 0,		\

#define ACF2_PROXY			\
	.show_in_usage = 2,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.verify_ips = 0,		\
	.need_peer = 1,			\
	.is_proxy_cmd = 1,		\

#define ACF2_HOOK			\
	.show_in_usage = 2,		\
	.res_name_required = 1,		\
	.backend_res_name = 1,		\
	.verify_ips = 0,                \
	.use_cached_config_file = 1,	\

#define ACF2_GEN_SHELL			\
	.show_in_usage = 2,		\
	.res_name_required = 0,		\
	.verify_ips = 0,		\

/*  */ struct adm_cmd attach_cmd = {"attach", adm_attach, &attach_cmd_ctx, ACF1_MINOR_ONLY };
/*  */ struct adm_cmd disk_options_cmd = {"disk-options", adm_attach, &attach_cmd_ctx, ACF1_MINOR_ONLY };
/*  */ struct adm_cmd detach_cmd = {"detach", adm_bsrsetup, &detach_cmd_ctx, .takes_long = 1, ACF1_MINOR_ONLY };
/*  */ struct adm_cmd new_peer_cmd = {"new-peer", adm_new_peer, &new_peer_cmd_ctx, ACF1_CONNECT};
/*  */ struct adm_cmd del_peer_cmd = {"del-peer", adm_bsrsetup, &disconnect_cmd_ctx, ACF1_CONNECT};
/*  */ struct adm_cmd new_path_cmd = {"new-path", adm_path, &path_cmd_ctx, ACF1_CONNECT .iterate_paths = 1};
/*  */ struct adm_cmd del_path_cmd = {"del-path", adm_path, &path_cmd_ctx, ACF1_CONNECT .iterate_paths = 1};
/*  */ struct adm_cmd connect_cmd = {"connect", adm_connect, &connect_cmd_ctx, ACF1_CONNECT};
/*  */ struct adm_cmd net_options_cmd = {"net-options", adm_new_peer, &net_options_ctx, ACF1_CONNECT};
/*  */ struct adm_cmd disconnect_cmd = {"disconnect", adm_bsrsetup, &disconnect_cmd_ctx, ACF1_DISCONNECT};
static struct adm_cmd up_cmd = {"up", adm_up, ACF1_RESNAME };
/*  */ struct adm_cmd res_options_cmd = {"resource-options", adm_resource, &resource_options_ctx, ACF1_RESNAME};
/*  */ struct adm_cmd node_options_cmd = {"node-options", adm_node, &node_options_cmd_ctx, ACF1_RESNAME};
static struct adm_cmd down_cmd = {"down", adm_bsrsetup, ACF1_RESNAME .takes_long = 1};
// BSR-823
static struct adm_cmd primary_cmd = {"primary", adm_primary, &primary_cmd_ctx, ACF1_RESNAME .takes_long = 1};
static struct adm_cmd secondary_cmd = {"secondary", adm_bsrsetup, ACF1_RESNAME .takes_long = 1};
static struct adm_cmd invalidate_cmd = {"invalidate", adm_invalidate, ACF1_MINOR_ONLY };
static struct adm_cmd invalidate_remote_cmd = {"invalidate-remote", adm_bsrsetup, &invalidate_peer_ctx, ACF1_PEER_DEVICE .takes_long = 1};
// DW-774
static struct adm_cmd outdate_cmd = {"outdate", adm_outdate, ACF1_DEFAULT .backend_res_name = 0};
/*  */ struct adm_cmd resize_cmd = {"resize", adm_resize, &resize_cmd_ctx, ACF1_DEFAULT .disk_required = 1};
static struct adm_cmd verify_cmd = {"verify", adm_bsrsetup, &verify_cmd_ctx, ACF1_PEER_DEVICE};
static struct adm_cmd verify_stop_cmd = {"verify-stop", adm_bsrsetup, ACF1_PEER_DEVICE .takes_long = 1}; // BSR-835 increase verify-stop timeout
static struct adm_cmd pause_sync_cmd = {"pause-sync", adm_bsrsetup, ACF1_PEER_DEVICE};
static struct adm_cmd resume_sync_cmd = {"resume-sync", adm_bsrsetup, ACF1_PEER_DEVICE};
static struct adm_cmd adjust_cmd = { "adjust", adm_adjust, &adjust_ctx, ACF1_RESNAME.vol_id_optional = 1, .exclude_parse_show = 1};
static struct adm_cmd adjust_wp_cmd = {"adjust-with-progress", adm_adjust_wp, ACF1_RESNAME .exclude_parse_show = 1};
static struct adm_cmd wait_c_cmd = {"wait-connect", adm_wait_c, ACF1_WAIT};
static struct adm_cmd wait_sync_cmd = {"wait-sync", adm_wait_c, ACF1_WAIT};
static struct adm_cmd wait_ci_cmd = {"wait-con-int", adm_wait_ci, .show_in_usage = 1,.verify_ips = 1,};
static struct adm_cmd role_cmd = {"role", adm_bsrsetup, ACF1_RESNAME};
static struct adm_cmd cstate_cmd = {"cstate", adm_bsrsetup, ACF1_DISCONNECT .is_status_cmd=1};
static struct adm_cmd dstate_cmd = {"dstate", adm_setup_and_meta, ACF1_MINOR_ONLY .is_status_cmd=1};
static struct adm_cmd status_cmd = {"status", adm_bsrsetup, .show_in_usage = 1, .uc_dialog = 1, .backend_res_name=1, .is_status_cmd=1};
static struct adm_cmd peer_device_options_cmd = {"peer-device-options", adm_peer_device,
						 &peer_device_options_ctx, ACF1_PEER_DEVICE};
static struct adm_cmd dump_cmd = {"dump", adm_dump, ACF1_DUMP .is_status_cmd=1};
static struct adm_cmd dump_xml_cmd = {"dump-xml", adm_dump_xml, ACF1_DUMP .is_status_cmd=1};

static struct adm_cmd create_md_cmd = {"create-md", adm_create_md, &create_md_ctx, ACF1_MINOR_ONLY };
static struct adm_cmd show_gi_cmd = {"show-gi", adm_setup_and_meta, ACF1_PEER_DEVICE .disk_required = 1, .is_status_cmd=1};
static struct adm_cmd get_gi_cmd = {"get-gi", adm_setup_and_meta, ACF1_PEER_DEVICE .disk_required = 1, .is_status_cmd=1};
static struct adm_cmd dump_md_cmd = {"dump-md", adm_bsrmeta, ACF1_MINOR_ONLY };
// DW-1922 Added '--force' option to wipe-md command
static struct adm_cmd wipe_md_cmd = { "wipe-md", adm_bsrmeta, &wipe_md_ctx, ACF1_MINOR_ONLY };
static struct adm_cmd apply_al_cmd = {"apply-al", adm_bsrmeta, ACF1_MINOR_ONLY };
static struct adm_cmd forget_peer_cmd = {"forget-peer", adm_forget_peer, ACF1_DISCONNECT };

static struct adm_cmd hidden_cmd = {"hidden-commands", hidden_cmds,.show_in_usage = 1,};

static struct adm_cmd sh_nop_cmd = {"sh-nop", sh_nop, ACF2_GEN_SHELL .uc_dialog = 1, .test_config = 1};
static struct adm_cmd sh_resources_list_cmd = { "sh-resources-list", sh_resources_list, ACF2_GEN_SHELL .need_peer = 1, .exclude_parse_show = 1, .is_status_cmd=1};
// DW-1249 auto-start by svc
static struct adm_cmd sh_resource_option_cmd = { "sh-resource-option", sh_resource_option, ACF1_RESNAME };
// BSR-718
static struct adm_cmd sh_node_option_cmd = { "sh-node-option", sh_node_option, ACF1_RESNAME };
static struct adm_cmd sh_resources_cmd = {"sh-resources", sh_resources, ACF2_GEN_SHELL .need_peer = 1, .is_status_cmd=1};
static struct adm_cmd sh_resource_cmd = {"sh-resource", sh_resource, ACF2_SH_RESNAME .is_status_cmd=1};
static struct adm_cmd sh_mod_parms_cmd = {"sh-mod-parms", sh_mod_parms, ACF2_GEN_SHELL .is_status_cmd=1};
static struct adm_cmd sh_dev_cmd = {"sh-dev", sh_dev, ACF2_SHELL .is_status_cmd=1};
static struct adm_cmd sh_udev_cmd = {"sh-udev", sh_udev, .vol_id_required = 1, ACF2_HOOK .is_status_cmd=1};
static struct adm_cmd sh_minor_cmd = {"sh-minor", sh_minor, ACF2_SHELL .is_status_cmd=1};
static struct adm_cmd sh_ll_dev_cmd = {"sh-ll-dev", sh_ll_dev, ACF2_SHELL .disk_required = 1, .is_status_cmd=1};
static struct adm_cmd sh_md_dev_cmd = {"sh-md-dev", sh_md_dev, ACF2_SHELL .disk_required = 1, .is_status_cmd=1};
static struct adm_cmd sh_md_idx_cmd = {"sh-md-idx", sh_md_idx, ACF2_SHELL .disk_required = 1, .is_status_cmd=1};
static struct adm_cmd sh_ip_cmd = {"sh-ip", sh_ip, ACF2_SHELL .is_status_cmd=1};
static struct adm_cmd sh_lr_of_cmd = {"sh-lr-of", sh_lres, ACF2_SHELL .is_status_cmd=1};
// BSR-675 
static struct adm_cmd sh_peer_node_id_cmd = {"sh-peer-node-id", sh_peer_node_id, ACF2_GEN_SHELL .need_peer = 1, .res_name_required = 1, .exclude_parse_show = 1,.is_status_cmd=1};
static struct adm_cmd sh_dev_vnr_cmd = {"sh-dev-vnr", sh_dev_vnr, ACF2_SHELL .exclude_parse_show = 1, .is_status_cmd=1};
// BSR-688
static struct adm_cmd sh_peer_node_name_cmd = {"sh-peer-node-name", sh_peer_node_name, ACF2_GEN_SHELL .need_peer = 1, .res_name_required = 1, .exclude_parse_show = 1, .is_status_cmd=1};
// BSR-808
static struct adm_cmd sh_peer_nodes_cmd = {"sh-peer-nodes", sh_peer_nodes, ACF2_GEN_SHELL .need_peer = 1, .res_name_required = 1, .exclude_parse_show = 1, .is_status_cmd=1};

static struct adm_cmd proxy_up_cmd = {"proxy-up", adm_proxy_up, ACF2_PROXY};
static struct adm_cmd proxy_down_cmd = {"proxy-down", adm_proxy_down, ACF2_PROXY};

/*  */ struct adm_cmd new_resource_cmd = {"new-resource", adm_resource, &resource_options_ctx, ACF2_SH_RESNAME};
/*  */ struct adm_cmd new_minor_cmd = {"new-minor", adm_new_minor, &device_options_ctx, ACF4_ADVANCED};
/*  */ struct adm_cmd del_minor_cmd = { "del-minor", adm_bsrsetup, ACF1_MINOR_ONLY.show_in_usage = 4, .disk_required = 0, };

static struct adm_cmd khelper01_cmd = {"before-resync-target", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper02_cmd = {"after-resync-target", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper03_cmd = {"before-resync-source", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper04_cmd = {"pri-on-incon-degr", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper05_cmd = {"pri-lost-after-sb", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper06_cmd = {"fence-peer", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper07_cmd = {"local-io-error", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper08_cmd = {"pri-lost", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper09_cmd = {"initial-split-brain", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper10_cmd = {"split-brain", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper11_cmd = {"out-of-sync", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper12_cmd = {"unfence-peer", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper13_cmd = { "quorum-lost", adm_khelper, ACF3_RES_HANDLER };


static struct adm_cmd suspend_io_cmd = {"suspend-io", adm_bsrsetup, ACF4_ADVANCED  .backend_res_name = 0 };
static struct adm_cmd resume_io_cmd = {"resume-io", adm_bsrsetup, ACF4_ADVANCED  .backend_res_name = 0 };
static struct adm_cmd set_gi_cmd = {"set-gi", adm_bsrmeta, &wildcard_ctx, .disk_required = 1, .need_peer = 1, ACF4_ADVANCED_NEED_VOL};
static struct adm_cmd new_current_uuid_cmd = {"new-current-uuid", adm_bsrsetup, &new_current_uuid_cmd_ctx, ACF4_ADVANCED_NEED_VOL .backend_res_name = 0};
static struct adm_cmd check_resize_cmd = {"check-resize", adm_chk_resize, ACF4_ADVANCED};

struct adm_cmd *cmds[] = {
	/*  name, function, flags
	 *  sort order:
	 *  - normal config commands,
	 *  - normal meta data manipulation
	 *  - sh-*
	 *  - handler
	 *  - advanced
	 ***/
	&attach_cmd,
	&disk_options_cmd,
	&detach_cmd,
	&new_peer_cmd,
	&del_peer_cmd,
	&new_path_cmd,
	&del_path_cmd,
	&connect_cmd,
	&net_options_cmd,
	&disconnect_cmd,
	&up_cmd,
	&res_options_cmd,
	&node_options_cmd,
	&peer_device_options_cmd,
	&down_cmd,
	&primary_cmd,
	&secondary_cmd,
	&invalidate_cmd,
	&invalidate_remote_cmd,
	&outdate_cmd,
	&resize_cmd,
	&verify_cmd,
	&verify_stop_cmd,
	&pause_sync_cmd,
	&resume_sync_cmd,
	&adjust_cmd,
	&adjust_wp_cmd,
	&wait_c_cmd,
	&wait_sync_cmd,
	&wait_ci_cmd,
	&role_cmd,
	&cstate_cmd,
	&dstate_cmd,
	&status_cmd,
	&dump_cmd,
	&dump_xml_cmd,

	&create_md_cmd,
	&show_gi_cmd,
	&get_gi_cmd,
	&dump_md_cmd,
	&wipe_md_cmd,
	&apply_al_cmd,
	&forget_peer_cmd,

	&hidden_cmd,

	&sh_nop_cmd,

    &sh_resources_list_cmd,
	// DW-1249 auto-start by svc
	&sh_resource_option_cmd,
	&sh_node_option_cmd,
	&sh_resources_cmd,
	&sh_resource_cmd,
	&sh_mod_parms_cmd,
	&sh_dev_cmd,
	&sh_udev_cmd,
	&sh_minor_cmd,
	&sh_ll_dev_cmd,
	&sh_md_dev_cmd,
	&sh_md_idx_cmd,
	&sh_ip_cmd,
	&sh_lr_of_cmd,
	// BSR-675
	&sh_peer_node_id_cmd,
	&sh_dev_vnr_cmd,
	// BSR-688
	&sh_peer_node_name_cmd,
	// BSR-808
	&sh_peer_nodes_cmd,

	&proxy_up_cmd,
	&proxy_down_cmd,

	&new_resource_cmd,
	&new_minor_cmd,
	&del_minor_cmd,

	&khelper01_cmd,
	&khelper02_cmd,
	&khelper03_cmd,
	&khelper04_cmd,
	&khelper05_cmd,
	&khelper06_cmd,
	&khelper07_cmd,
	&khelper08_cmd,
	&khelper09_cmd,
	&khelper10_cmd,
	&khelper11_cmd,
	&khelper12_cmd,
	&khelper13_cmd,
	
	&suspend_io_cmd,
	&resume_io_cmd,
	&set_gi_cmd,
	&new_current_uuid_cmd,
	&check_resize_cmd,
};

/* internal commands: */
/*  */ struct adm_cmd res_options_defaults_cmd = {
	"resource-options",
	adm_resource,
	&resource_options_ctx,
	ACF1_RESNAME
};
/*  */ struct adm_cmd node_options_defaults_cmd = {
	"node-options",
	adm_node,
	&node_options_cmd_ctx,
	ACF1_RESNAME
};
/*  */ struct adm_cmd disk_options_defaults_cmd = {
	"disk-options",
	adm_attach,
	&attach_cmd_ctx,
	ACF1_MINOR_ONLY
};
/*  */ struct adm_cmd net_options_defaults_cmd = {
	"net-options",
	adm_new_peer,
	&net_options_ctx,
	ACF1_CONNECT
};
/*  */ struct adm_cmd peer_device_options_defaults_cmd = {
	"peer-device-options",
	adm_peer_device,
	&peer_device_options_ctx,
	ACF1_CONNECT
};
/*  */ struct adm_cmd proxy_conn_down_cmd = { "", do_proxy_conn_down, ACF1_DEFAULT};
/*  */ struct adm_cmd proxy_conn_up_cmd = { "", do_proxy_conn_up, ACF1_DEFAULT};
/*  */ struct adm_cmd proxy_conn_plugins_cmd = { "", do_proxy_conn_plugins, ACF1_DEFAULT};

static const struct adm_cmd invalidate_setup_cmd = {
	"invalidate",
	__adm_bsrsetup_silent,
	ACF1_MINOR_ONLY
};

static const struct adm_cmd forget_peer_setup_cmd = {
	"forget-peer",
	__adm_bsrsetup_silent,
	ACF1_DISCONNECT
};

static void initialize_deferred_cmds()
{
	enum bsr_cfg_stage stage;
	for (stage = CFG_PREREQ; stage < __CFG_LAST; stage++)
		STAILQ_INIT(&deferred_cmds[stage]);
}

void schedule_deferred_cmd(struct adm_cmd *cmd,
			   const struct cfg_ctx *ctx,
			   enum bsr_cfg_stage stage)
{
	struct deferred_cmd *d;

	if (stage & SCHEDULE_ONCE) {
		stage &= ~SCHEDULE_ONCE;

		STAILQ_FOREACH(d, &deferred_cmds[stage], link) {
			if (d->ctx.cmd == cmd &&
			    d->ctx.res == ctx->res &&
			    d->ctx.conn == ctx->conn &&
				d->ctx.vol->vnr == ctx->vol->vnr)
				return;
		}
	}

	d = calloc(1, sizeof(struct deferred_cmd));
	if (d == NULL) {
		CLI_ERRO_LOG_PEEROR(false, "calloc");
		exit(E_EXEC_ERROR);
	}

	d->ctx = *ctx;
	d->ctx.cmd = cmd;

	CLI_TRAC_LOG(false, "INSERT_TAIL, %s", d->ctx.cmd->name);
	STAILQ_INSERT_TAIL(&deferred_cmds[stage], d, link);
}

enum on_error { KEEP_RUNNING, EXIT_ON_FAIL };
static int __call_cmd_fn(const struct cfg_ctx *ctx, enum on_error on_error)
{
	struct d_volume *vol = ctx->vol;
	bool iterate_paths;
	int rv = 0;

	iterate_paths = ctx->path ? 0 : ctx->cmd->iterate_paths;

	if (ctx->cmd->disk_required &&
	    (!vol->disk || !vol->meta_disk || !vol->meta_index)) {
		rv = 10;
		err("The %s command requires a local disk, but the configuration gives none.\n",
		    ctx->cmd->name);
		if (on_error == EXIT_ON_FAIL)
			exit(rv);
		return rv;
	}

	if (iterate_paths) {
		struct cfg_ctx tmp_ctx = *ctx;
		struct path *path;

		for_each_path(path, &tmp_ctx.conn->paths) {
			tmp_ctx.path = path;
			CLI_TRAC_LOG(false, "tmp_ctx.function, %s", tmp_ctx.cmd->name);
			rv = tmp_ctx.cmd->function(&tmp_ctx);
			if (rv >= 20) {
				if (on_error == EXIT_ON_FAIL) {
					CLI_ERRO_LOG(false, true, "error EXIT_ON_FAIL(%d)", rv);
					exit(rv);
				}
			}

		}
	}
	else {
		CLI_TRAC_LOG(false, "cmd->function, %s", ctx->cmd->name);
		rv = ctx->cmd->function(ctx);
		if (rv >= 20) {
			if (on_error == EXIT_ON_FAIL) {
				CLI_ERRO_LOG(false, true, "error EXIT_ON_FAIL(%d)", rv);
				exit(rv);
			}
		}
	}
	return rv;
}

static int call_cmd_fn(struct adm_cmd *cmd, const struct cfg_ctx *ctx, enum on_error on_error)
{
	struct cfg_ctx tmp_ctx = *ctx;

	tmp_ctx.cmd = cmd;
	return __call_cmd_fn(&tmp_ctx, on_error);
}

/* If ctx->vol is NULL, and cmd->iterate_volumes is set,
 * iterate over all volumes in ctx->res.
 * Else, just pass it on.
 * */
int call_cmd(const struct adm_cmd *cmd, const struct cfg_ctx *ctx,
	     enum on_error on_error)
{
	struct cfg_ctx tmp_ctx = *ctx;
	struct d_resource *res = ctx->res;
	struct d_volume *vol;
	struct connection *conn;
	bool iterate_vols, iterate_conns;
	int ret = 0;

	if (!res->peers_addrs_set && cmd->need_peer)
		set_peer_in_resource(res, cmd->need_peer);

	iterate_vols = ctx->vol ? 0 : cmd->iterate_volumes;
	iterate_conns = ctx->conn ? 0 : cmd->need_peer;

	tmp_ctx.cmd = cmd;

	if (iterate_vols && iterate_conns) {
		for_each_volume(vol, &res->me->volumes) {
			tmp_ctx.vol = vol;
			for_each_connection(conn, &res->connections) {
				if (conn->ignore)
					continue;
				tmp_ctx.conn = conn;
				ret = __call_cmd_fn(&tmp_ctx, on_error);
				if (ret)
					goto out;
			}
		}
	} else if (iterate_vols) {

		// DW-1459 Set KEEP_RUNNING to run attach_cmd on all volumes.
		bool is_attach = (cmd == &attach_cmd);
		if (is_attach)
			on_error = KEEP_RUNNING;

		for_each_volume(vol, &res->me->volumes) {
			tmp_ctx.vol = vol;
			ret = __call_cmd_fn(&tmp_ctx, on_error);
		// DW-1459 attach_cmd runs on all volumes, regardless of return value.
			if (is_attach)
				continue;

			if (ret)
				break;
		}
	} else if (iterate_conns) {
		for_each_connection(conn, &res->connections) {
			if (conn->ignore)
				continue;
			tmp_ctx.conn = conn;
			ret = __call_cmd_fn(&tmp_ctx, on_error);
			if (ret)
				break;
		}
	} else {
		ret = __call_cmd_fn(&tmp_ctx, on_error);
	}
out:
	return ret;
}

static char *bsr_cfg_stage_string[] = {
	[CFG_PREREQ] = "create res",
	[CFG_RESOURCE] = "adjust res",
	[CFG_DISK_PREP_DOWN] = "prepare disk",
	[CFG_DISK_PREP_UP] = "prepare disk",
	[CFG_DISK] = "adjust disk",
	[CFG_NET_DISCONNECT] = "prepare net",
	[CFG_NET_PREP_DOWN] = "prepare net",
	[CFG_NET_PREP_UP] = "prepare net",	
	[CFG_NET_PATH] = "prepare net",
	[CFG_NET] = "adjust net",
	[CFG_PEER_DEVICE] = "adjust peer_devices",
	[CFG_NET_CONNECT] = "attempt to connect",
};

int _run_deferred_cmds(enum bsr_cfg_stage stage)
{
	struct d_resource *last_res = NULL;
	struct deferred_cmd *d = STAILQ_FIRST(&deferred_cmds[stage]);
	struct deferred_cmd *t;
	int r;
	int rv = 0;

	if (d && adjust_with_progress) {
		printf("\n%15s:", bsr_cfg_stage_string[stage]);
		fflush(stdout);
	}

	while (d) {
		if (d->ctx.res->skip_further_deferred_command) {
			if (adjust_with_progress) {
				if (d->ctx.res != last_res)
					printf(" [skipped:%s]", d->ctx.res->name);
			} else
				err("%s: %s %s: skipped due to earlier error\n",
				    progname, d->ctx.cmd->name, d->ctx.res->name);
			r = 0;
		} else {
			if (adjust_with_progress) {
				if (d->ctx.res != last_res)
					printf(" %s", d->ctx.res->name);
			}
			r = __call_cmd_fn(&d->ctx, KEEP_RUNNING);
			if (r) {
				/* If something in the "prerequisite" stages failed,
				 * there is no point in trying to continue.
				 * However if we just failed to adjust some
				 * options, or failed to attach, we still want
				 * to adjust other options, or try to connect.
				 */
				if (stage == CFG_PREREQ
				||  stage == CFG_DISK_PREP_DOWN
				||  stage == CFG_DISK_PREP_UP
				||  stage == CFG_NET_PREP_DOWN
				||  stage == CFG_NET_PREP_UP)
					d->ctx.res->skip_further_deferred_command = 1;
				if (adjust_with_progress)
					printf(":failed(%s:%u)", d->ctx.cmd->name, r);
			}
		}
		last_res = d->ctx.res;
		t = STAILQ_NEXT(d, link);
		free(d);
		d = t;
		if (r > rv)
			rv = r;
	}
	return rv;
}

int run_deferred_cmds(void)
{
	enum bsr_cfg_stage stage;
	int r;
	int ret = 0;
	if (adjust_with_progress)
		printf("[");
	for (stage = CFG_PREREQ; stage < __CFG_LAST; stage++) {
		r = _run_deferred_cmds(stage);
		if (r) {
			if (!adjust_with_progress)
				return 1; /* FIXME r? */
			ret = 1;
		}
	}
	if (adjust_with_progress)
		printf("\n]\n");
	return ret;
}

static int adm_adjust(const struct cfg_ctx *ctx)
{
	static int adjust_flags = 0;
	struct d_name *opt;

	if (!adjust_flags) {
		opt = find_backend_option("--skip-disk");
		if (opt)
			STAILQ_REMOVE(&backend_options, opt, d_name, link);
		else
			adjust_flags |= ADJUST_DISK;

		opt = find_backend_option("--skip-net");
		if (opt)
			STAILQ_REMOVE(&backend_options, opt, d_name, link);
		else
			adjust_flags |= ADJUST_NET;

		adjust_flags |= ADJUST_SKIP_CHECKED;
	}
	
	return _adm_adjust(ctx, adjust_flags);
}


static int sh_nop(const struct cfg_ctx *ctx)
{
	if (!config_valid)
		return 10;
	return 0;
}

static int sh_resources_list(const struct cfg_ctx *ctx)
{
	struct d_resource *res;
	for_each_resource(res, &config) {
		// BSR-1099 get resource list without verifying hostname when using -i option
		if (res->ignore && !ignore_hostname)
			continue;
		if (is_bsr_top != res->stacked)
			continue;
		printf("%s\n", esc(res->name));
	}
	return 0;
}

// DW-1249 get specified option value from resource.
static int sh_resource_option(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	char optionName[64] = "";
	
	if (sh_varname) {
		int len = 0;
		strcpy(optionName, sh_varname);
		len = strlen(optionName);

		while (len--) {
			if (optionName[len] == '_')
				optionName[len] = '-';
		}

		struct d_option* opt = find_opt(&res->res_options, optionName);
		if (opt) {
			printf("%s\n\n", esc(opt->value));
		}
		else {			
			printf("%s\n", esc("NULL"));
		}
	}

	return 0;
}

// BSR-718 move svc-auto-xxx option to node option
static int sh_node_option(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	char optionName[64] = "";
	
	if (sh_varname) {
		int len = 0;
		strcpy(optionName, sh_varname);
		len = strlen(optionName);

		while (len--) {
			if (optionName[len] == '_')
				optionName[len] = '-';
		}
		
		struct d_option* opt = find_opt(&res->me->node_options, optionName);

		if (opt) {
			printf("%s\n\n", esc(opt->value));
		}
		else {		
			printf("%s\n", esc("NULL"));
		}
	}

	return 0;
}

static int sh_resources(const struct cfg_ctx *ctx)
{
	struct d_resource *res;
	
	for_each_resource(res, &config) {
		if (res->ignore)
			continue;
		if (is_bsr_top != res->stacked)
			continue;
		printf("%s\n", res->name);
	}
	return 0;
}

static int sh_resource(const struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->res->name);
	return 0;
}

static int sh_dev(const struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->vol->device);
	return 0;
}

static int sh_udev(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct d_volume *vol = ctx->vol;

	/* No shell escape necessary. Udev does not handle it anyways... */
	if (!vol) {
		err("volume not specified\n");
		return 1;
	}

	// BSR-386 rename "bsr" to "bsr" to be the same as name of major device due to pvcreate error
	if (!strncmp(vol->device, "/dev/bsr", 8))
		printf("DEVICE=%s\n", vol->device + 5);
	else
		printf("DEVICE=bsr%u\n", vol->device_minor);

	/* in case older udev rules are still in place,
	* but do not yet have the work-around for the
	* udev default change of "string_escape=none" -> "replace",
	* populate plain "SYMLINK" with just the "by-res" one. */
	printf("SYMLINK=");
	if (vol->implicit && !global_options.udev_always_symlink_vnr)
		printf("bsr/by-res/%s\n", res->name);
	else
		printf("bsr/by-res/%s/%u\n", res->name, vol->vnr);

	/* repeat, with _BY_RES */
	printf("SYMLINK_BY_RES=");
	if (vol->implicit && !global_options.udev_always_symlink_vnr)
		printf("bsr/by-res/%s\n", res->name);
	else
		printf("bsr/by-res/%s/%u\n", res->name, vol->vnr);

	/* and add the _BY_DISK one explicitly */
	if (vol->disk) {
		printf("SYMLINK_BY_DISK=");
		if (!strncmp(vol->disk, "/dev/", 5))
			printf("bsr/by-disk/%s\n", vol->disk + 5);
		else
			printf("bsr/by-disk/%s\n", vol->disk);
	}

	return 0;
}

static int sh_minor(const struct cfg_ctx *ctx)
{
	printf("%d\n", ctx->vol->device_minor);
	return 0;
}

static int sh_ip(const struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->res->me->address.addr);
	return 0;
}

static int sh_lres(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	if (!is_bsr_top) {
		err("sh-lower-resource only available in stacked mode\n");
		exit(E_USAGE);
	}
	if (!res->stacked) {
		err("'%s' is not stacked on this host (%s)\n", res->name, hostname);
		exit(E_USAGE);
	}
	printf("%s\n", res->me->lower->name);

	return 0;
}

static int sh_ll_dev(const struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->vol->disk);
	return 0;
}


static int sh_md_dev(const struct cfg_ctx *ctx)
{
	struct d_volume *vol = ctx->vol;
	char *r;

	if (strcmp("internal", vol->meta_disk) == 0)
		r = vol->disk;
	else
		r = vol->meta_disk;

	printf("%s\n", r);
	return 0;
}

static int sh_md_idx(const struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->vol->meta_index);
	return 0;
}

/* FIXME this module parameter will go */
static int sh_mod_parms(const struct cfg_ctx *ctx)
{
	int mc = global_options.minor_count;

	if (mc == 0) {
		mc = number_of_minors + 3;
		if (mc > BSR_MINOR_COUNT_MAX)
			mc = BSR_MINOR_COUNT_MAX;

		if (mc < BSR_MINOR_COUNT_DEF)
			mc = BSR_MINOR_COUNT_DEF;
	}
	printf("minor_count=%d\n", mc);
	return 0;
}

// BSR-675
static int sh_peer_node_id(const struct cfg_ctx *ctx)
{
	struct connection *conn = ctx->conn;
	printf("%s\n", conn->peer->node_id);
	return 0;
}
static int sh_dev_vnr(const struct cfg_ctx *ctx)
{
	struct d_volume *vol = ctx->vol;
	printf("%u\n", vol->vnr);
	return 0;
}
// BSR-688
static int sh_peer_node_name(const struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->conn->peer->on_hosts.stqh_first->name);
	return 0;
}

// BSR-808 look up the peer's node-id and name list
static int sh_peer_nodes(const struct cfg_ctx *ctx)
{
	printf("%s %s\n", ctx->conn->peer->node_id, ctx->conn->peer->on_hosts.stqh_first->name);
	return 0;
}


static void free_volume(struct d_volume *vol)
{
	if (!vol)
		return;

	free(vol->device);
	free(vol->disk);
	free(vol->meta_disk);
	free(vol->meta_index);
	free(vol);
}

static void free_host_info(struct d_host_info *hi)
{
	struct d_volume *vol, *n;

	if (!hi)
		return;

	free_names(&hi->on_hosts);
	vol = STAILQ_FIRST(&hi->volumes);
	while (vol) {
		n = STAILQ_NEXT(vol, link);
		free_volume(vol);
		vol = n;
	}
	free(hi->address.addr);
	free(hi->address.af);
	free(hi->address.port);
}

static void free_options(struct options *options)
{
	struct d_option *f, *option = STAILQ_FIRST(options);
	while (option) {
		free(option->value);
		f = option;
		option = STAILQ_NEXT(option, link);
		free(f);
	}
}

static void free_config()
{
	struct d_resource *f, *t;
	struct d_host_info *host, *th;

	f = STAILQ_FIRST(&config);
	while (f) {
		free(f->name);
		host = STAILQ_FIRST(&f->all_hosts);
		while (host) {
			th = STAILQ_NEXT(host, link);
			free_host_info(host);
			host = th;
		}
		free_options(&f->net_options);
		free_options(&f->disk_options);
		free_options(&f->startup_options);
		free_options(&f->proxy_options);
		free_options(&f->handlers);
		t = STAILQ_NEXT(f, link);
		free(f);
		f = t;
	}
	if (common) {
		free_options(&common->net_options);
		free_options(&common->disk_options);
		free_options(&common->startup_options);
		free_options(&common->proxy_options);
		free_options(&common->handlers);
		free(common);
	}

	free(ifreq_list);

}

static void find_bsrcmd(char **cmd, char **pathes)
{
	char **path;

	path = pathes;
	while (*path) {
		if (access(*path, X_OK) == 0) {
			*cmd = *path;
			return;
		}
		path++;
	}

	err("Can not find command (bsrsetup/bsrmeta)\n");
	exit(E_EXEC_ERROR);
}
#ifdef _WIN_MVFL
const PCHAR gRegistryPath = "System\\CurrentControlSet\\Services\\bsrvflt\\volumes";

DWORD add_registry_volume(char * letter)
{
    DWORD disposition = 0, status = ERROR_SUCCESS;
    HKEY hKey = NULL;

    status = RegCreateKeyExA(HKEY_LOCAL_MACHINE, gRegistryPath, 0, (PWCHAR)NULL, REG_OPTION_NON_VOLATILE,
    					   	KEY_ALL_ACCESS, (LPSECURITY_ATTRIBUTES) NULL, &hKey, &disposition);
    if ( ERROR_SUCCESS != status ) {
    	printf("Failed to RegCreateKeyEx(). status(0x%x)\n", status);
    	return status;
    }

    status = RegSetValueExA(hKey, letter, 0, REG_BINARY, 0, 0);
    if ( ERROR_SUCCESS != status ) {
        RegCloseKey(hKey);
    	printf( "Failed to RegSetValueEx status(0x%x)\n", status );
    	return status;
    }

    RegCloseKey(hKey);

    return status;
}

DWORD del_registry_volume(char * letter)
{
    HKEY hKey = NULL;
    DWORD status = ERROR_SUCCESS, dwIndex = 0;
    CHAR szRegLetter[256] = {0, };
    UCHAR volGuid[256] = {0, };
    DWORD cbRegLetter = 256, cbVolGuid = 256;

    status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, gRegistryPath, 0, KEY_ALL_ACCESS, &hKey );
    if (ERROR_SUCCESS != status) {
        return status;
    }

    while (ERROR_SUCCESS == RegEnumValueA(hKey, dwIndex++, szRegLetter, &cbRegLetter, NULL, NULL, (LPBYTE)volGuid, &cbVolGuid)) {
    
#ifdef _WIN_CLI_UPDATE
	if (!strcasecmp(szRegLetter, letter))
#else 	    
	if (!stricmp(szRegLetter, letter))
#endif       
      	{
            status = RegDeleteValue(hKey, szRegLetter);
            RegCloseKey(hKey);
            return status;
        }

        memset(szRegLetter, 0, 256);
        memset(volGuid, 0, 256);
        cbRegLetter = 256;
        cbVolGuid = 256;
    }

    RegCloseKey(hKey);

    return ERROR_SUCCESS;
}
#endif
#define NA(ARGC) \
  ({ if((ARGC) >= MAX_ARGS) { err("MAX_ARGS too small\n"); \
       exit(E_THINKO); \
     } \
     (ARGC)++; \
  })

static bool is_valid_backend_option(const char* name, const struct context_def *context_def)
{
	const struct field_def *field;
	int len_to_equal_sign_or_nul; 

	if (context_def == &wildcard_ctx)
		return true;
	
	if (!context_def || strlen(name) <= 2)
		return false;
	
	/* options have a leading "--", while field names do not have that */
	name += 2; 
	/* compare only until first equal sign, if any */
	len_to_equal_sign_or_nul = strcspn(name, "="); 

	for (field = context_def->fields; field->name; field++) {
		if (!strncmp(name, field->name, len_to_equal_sign_or_nul))
			return true;
	}
	return false;
}

static void add_setup_options(char **argv, int *argcp, const struct context_def *context_def)
{
	struct d_name *b_opt;
	int argc = *argcp;

	STAILQ_FOREACH(b_opt, &backend_options, link) {
		if (is_valid_backend_option(b_opt->name, context_def))
			argv[NA(argc)] = b_opt->name;
	}
	*argcp = argc;
}

#define make_option(ARG, OPT) do {					\
     struct d_name *b_opt;                             \
     bool found = false;                             \
     STAILQ_FOREACH(b_opt, &backend_options, link) {                \
         if (!strncmp(OPT->name, b_opt->name+2, strlen(OPT->name))) {    \
             found = true;                        \
             break;                             \
         }                                 \
     }                                     \
     if (!found) {                                \
         if(OPT->value)                            \
             ARG = ssprintf("--%s=%s", OPT->name, OPT->value);    \
         else                                  \
             ARG = ssprintf("--%s", OPT->name);            \
     }                                    \
} while (false)

#define make_options(ARG, OPTIONS) do {					\
	struct d_option *option;					\
	STAILQ_FOREACH(option, OPTIONS, link) 				\
		make_option(ARG, option);				\
} while (false)

#define ssprintf_addr(A)					\
ssprintf(strcmp((A)->af, "ipv6") ? "%s:%s:%s" : "%s:[%s]:%s",	\
	 (A)->af, (A)->addr, (A)->port);

static int adm_attach(const struct cfg_ctx *ctx)
{
	struct d_volume *vol = ctx->vol;
	char *argv[MAX_ARGS];
	int argc = 0;
	bool do_attach = (ctx->cmd == &attach_cmd);
	bool reset = (ctx->cmd == &disk_options_defaults_cmd);

	if (do_attach) {
		int rv = call_cmd_fn(&apply_al_cmd, ctx, KEEP_RUNNING);
		if (rv)
			return rv;
	}

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* "attach" : "disk-options"; */
	argv[NA(argc)] = ssprintf("%d", vol->device_minor);
	if (do_attach) {
		assert(vol->disk != NULL);
		assert(vol->disk[0] != '\0');
		argv[NA(argc)] = vol->disk;
		if (!strcmp(vol->meta_disk, "internal")) {
			argv[NA(argc)] = vol->disk;
		} else {
			argv[NA(argc)] = vol->meta_disk;
		}
		argv[NA(argc)] = vol->meta_index;
	}
	if (reset)
		argv[NA(argc)] = "--set-defaults";
	if (reset || do_attach) {
		if (!do_attach) {
			struct d_option *option;
			STAILQ_FOREACH(option, &ctx->vol->disk_options, link)
				if (!option->adj_skip)
					make_option(argv[NA(argc)], option);
		} else {
			make_options(argv[NA(argc)], &ctx->vol->disk_options);
		}
	}
	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_LONG, ctx->res->name);
}

struct d_option *find_opt(struct options *base, const char *name)
{
	struct d_option *option;

	STAILQ_FOREACH(option, base, link)
		if (!strcmp(option->name, name))
			return option;

	return NULL;
}

bool del_opt(struct options *base, const char * const name)
{
	struct d_option *opt;
	
	if ((opt = find_opt(base, name))) {
		STAILQ_REMOVE(base, opt, d_option, link);
		free_opt(opt);
		return true;
	}
	
	return false;
}


int adm_new_minor(const struct cfg_ctx *ctx)
{
	char *argv[MAX_ARGS];
	int argc = 0, ex;

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = "new-minor";
	argv[NA(argc)] = ssprintf("%s", ctx->res->name);
	argv[NA(argc)] = ssprintf("%u", ctx->vol->device_minor);
	argv[NA(argc)] = ssprintf("%u", ctx->vol->vnr);
	if (!ctx->vol->disk)
		argv[NA(argc)] = ssprintf("--diskless");
	argv[NA(argc)] = NULL;
#ifdef _WIN_MVFL
	ex = add_registry_volume(ctx->vol->disk);
	if (ERROR_SUCCESS != ex) {
		return ex;
	}
#endif
	ex = m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
	if (!ex && do_register)
		register_minor(ctx->vol->device_minor, config_save);

	return ex;
}

// BSR-718
static int adm_node(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	char *argv[MAX_ARGS];
	int argc = 0;
	bool reset = (ctx->cmd == &node_options_defaults_cmd);

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* "node-options"*/
	argv[NA(argc)] = ssprintf("%s", res->name);
	if (reset)
		argv[NA(argc)] = "--set-defaults";
	make_options(argv[NA(argc)], &res->me->node_options);
	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = NULL;

	return m_system_ex(argv, SLEEPS_SHORT, res->name);
}


static int adm_resource(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	char *argv[MAX_ARGS];
	int argc = 0, ex;
	bool do_new_resource = (ctx->cmd == &new_resource_cmd);
	bool reset = (ctx->cmd == &res_options_defaults_cmd);

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* "new-resource" or "resource-options" */
	argv[NA(argc)] = ssprintf("%s", res->name);
	if (do_new_resource)
		argv[NA(argc)] = ctx->res->me->node_id;
	if (reset)
		argv[NA(argc)] = "--set-defaults";
	if (reset || do_new_resource)
		make_options(argv[NA(argc)], &res->res_options);
	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = NULL;

	ex = m_system_ex(argv, SLEEPS_SHORT, res->name);
	if (!ex && do_new_resource && do_register)
		register_resource(res->name, config_save);
	return ex;
}

static off64_t read_bsr_dev_size(int minor)
{
	char *path;
	FILE *file;
	off64_t val;
	int r;

	m_asprintf(&path, "/sys/block/bsr%d/size", minor);
	file = fopen(path, "r");
	if (file) {
		r = fscanf(file, "%" SCNd64, &val);
		fclose(file);
		if (r != 1)
			val = -1;
	}
	else
		val = -1;

	return val;
}

int adm_resize(const struct cfg_ctx *ctx)
{
	char *argv[MAX_ARGS];
	struct d_option *opt;
	bool is_resize = !strcmp(ctx->cmd->name, "resize");
	off64_t old_size = -1;
	off64_t target_size = 0;
	off64_t new_size;
	int argc = 0;
	int silent;
	int ex;

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = "resize"; /* first execute resize, even if called from check-resize context */
	argv[NA(argc)] = ssprintf("%d", ctx->vol->device_minor);
	opt = find_opt(&ctx->vol->disk_options, "size");
	if (!opt)
		opt = find_opt(&ctx->res->disk_options, "size");
	if (opt) {
		argv[NA(argc)] = ssprintf("--%s=%s", opt->name, opt->value);
		target_size = m_strtoll(opt->value, 's');
		/* FIXME: what if "add_setup_options" below overrides target_size
		* with an explicit, on-command-line target_size? */
	}
	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = 0;

	if (is_resize && !dry_run)
		old_size = read_bsr_dev_size(ctx->vol->device_minor);

	/* if this is a "resize" triggered by "check-resize", be silent! */
	silent = is_resize ? 0 : SUPRESS_STDERR;
	ex = m_system_ex(argv, SLEEPS_LONG | silent, ctx->res->name);

	if (ex && target_size) {
		new_size = read_bsr_dev_size(ctx->vol->device_minor);
		if (new_size == target_size) {
			CLI_ERRO_LOG_STDERR(false, "Current size of bsr%u equals target size (%llu byte), exit code %d ignored.",
				ctx->vol->device_minor, (unsigned long long)new_size, ex);
			ex = 0;
		}
	}

	if (ex)
		return ex;

	/* Record last-known bdev info.
	 * Unfortunately bsrsetup did not have enough information
	 * when doing the "resize", and in theory, _our_ information
	 * about the backing device may even be wrong.
	 * Call bsrsetup again, tell it to ask the kernel for
	 * current config, and update the last known bdev info
	 * according to that. */
	/* argv[0] = bsrsetup; */
	argv[1] = "check-resize";
	/* argv[2] = minor; */
	argv[3] = NULL;
	/* ignore exit code */
	m_system_ex(argv, SLEEPS_SHORT | silent, ctx->res->name);

	/* Here comes a really uggly hack. Wait until the device size actually
	changed, but only up to 10 seconds if know the target size, up to
	3 seconds waiting for some change. */
	if (old_size > 0) {
		int timeo = target_size ? 100 : 30;

		do {
			new_size = read_bsr_dev_size(ctx->vol->device_minor);
			if (new_size >= target_size) /* should be == , but driver ignores usize right now */
				return 0;
			if (new_size != old_size) {
				if (target_size == 0)
					return 0;
				err("Size changed from %"PRId64" to %"PRId64", waiting for %"PRId64".\n",
					old_size, new_size, target_size);
				old_size = new_size; /* I want to see it only once.*/
			}

			usleep(100000);
		} while (timeo-- > 0);
		return 1;
	}

	return 0;
}

int _adm_bsrmeta(const struct cfg_ctx *ctx, int flags, char *argument)
{
	struct d_volume *vol = ctx->vol;
	char *argv[MAX_ARGS];
	int argc = 0;

	argv[NA(argc)] = bsrmeta;
	argv[NA(argc)] = ssprintf("%d", vol->device_minor);
	argv[NA(argc)] = "v09";
	if (!strcmp(vol->meta_disk, "internal")) {
		assert(vol->disk != NULL);
		assert(vol->disk[0] != '\0');
		argv[NA(argc)] = vol->disk;
	} else {
		argv[NA(argc)] = vol->meta_disk;
	}
	if (!strcmp(vol->meta_index, "flexible")) {
		if (!strcmp(vol->meta_disk, "internal")) {
			argv[NA(argc)] = "flex-internal";
		} else {
			argv[NA(argc)] = "flex-external";
		}
	} else {
		argv[NA(argc)] = vol->meta_index;
	}
	if (ctx->cmd->need_peer)
		argv[NA(argc)] = ssprintf("--node-id=%s", ctx->conn->peer->node_id);
	argv[NA(argc)] = (char *)ctx->cmd->name;
	if (argument)
		argv[NA(argc)] = argument;
 // DW-774
	if (ctx->cmd->bsrsetup_ctx)
		add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, flags, ctx->res->name);
}

static int adm_bsrmeta(const struct cfg_ctx *ctx)
{
	return _adm_bsrmeta(ctx, SLEEPS_VERY_LONG, NULL);
}

static void __adm_bsrsetup(const struct cfg_ctx *ctx, int flags, pid_t *pid, int *fd, int *ex)
{
	char *argv[MAX_ARGS];
	int argc = 0;

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name;

	if (ctx->cmd->backend_res_name && ctx->res)
		argv[NA(argc)] = ssprintf("%s", ctx->res->name);

	if (ctx->cmd->need_peer)
		argv[NA(argc)] = ssprintf("%s", ctx->conn->peer->node_id);

	if (ctx->vol) {
		if (ctx->cmd->need_peer && ctx->cmd->iterate_volumes)
			argv[NA(argc)] = ssprintf("%d", ctx->vol->vnr);
		else
			argv[NA(argc)] = ssprintf("%d", ctx->vol->device_minor);
	}

	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);

	if (ctx->cmd == &invalidate_setup_cmd && ctx->conn)
		argv[NA(argc)] = ssprintf("--sync-from-peer-node-id=%s", ctx->conn->peer->node_id);

	argv[NA(argc)] = 0;

	if (ctx->res)
		setenv("BSR_RESOURCE", ctx->res->name, 1);

	m__system(argv, flags, ctx->res ? ctx->res->name : NULL, pid, fd, ex);
}

static int _adm_bsrsetup(const struct cfg_ctx *ctx, int flags)
{
	int ex;
	__adm_bsrsetup(ctx, flags, NULL, NULL, &ex);
	return ex;
}

static int adm_bsrsetup(const struct cfg_ctx *ctx)
{
	return _adm_bsrsetup(ctx, ctx->cmd->takes_long ? SLEEPS_LONG : SLEEPS_SHORT);
}

// BSR-823
static int adm_primary(const struct cfg_ctx *ctx)
{
#ifdef _LIN
	const char *opt_name = "--skip-check-fs";
	struct d_name *opt;
	opt = find_backend_option(opt_name);

	if (force_primary) {
		bool do_check_fs = true;

		if (opt) {
			if (strlen(opt->name) > strlen(opt_name)) {
				char *opt_val = NULL;
				opt_val = ssprintf("%s", opt->name + strlen(opt_name) + 1);
				if (opt_val && strcmp(opt_val, "false"))
					do_check_fs = false;
			} else {
				do_check_fs = false;
			}
		}
		// run bsrsetup check-fs if --force primary and no --skip-check-fs option
		if (do_check_fs) {
			char *argv[4] = {bsrsetup, "check-fs", NULL, NULL};
			struct d_volume *vol = ctx->vol;
			struct cfg_ctx tmp_ctx = *ctx;
			int rv = 0;
			
			for_each_volume(vol, &ctx->res->me->volumes) {
				tmp_ctx.vol = vol;
				argv[2] = ssprintf("%d", tmp_ctx.vol->device_minor);
				rv = m_system_ex(argv, SLEEPS_LONG, tmp_ctx.res->name);
				if (rv)
					return rv;
			}	
		}
	}

	if (opt)
		STAILQ_REMOVE(&backend_options, opt, d_name, link);
#endif
	return _adm_bsrsetup(ctx, ctx->cmd->takes_long ? SLEEPS_LONG : SLEEPS_SHORT);
}

static int __adm_bsrsetup_silent(const struct cfg_ctx *ctx)
{
	char buffer[4096];
	int fd, status, rv = 0;
	pid_t pid;
	ssize_t rr;
	ssize_t rw __attribute((unused));
	size_t s = 0;

	__adm_bsrsetup(ctx, SLEEPS_SHORT | RETURN_STDERR_FD, &pid, &fd, NULL);

	if (!dry_run) {
		if (fd < 0) {
			err("Strange: got negative fd.\n");
			exit(E_THINKO);
		}

		while (1) {
			rr = read(fd, buffer + s, 4096 - s);
			if (rr <= 0)
				break;
			s += rr;
		}

		close(fd);
		(void) waitpid(pid, &status, 0);
		alarm(0);

		if (WIFEXITED(status))
			rv = WEXITSTATUS(status);
		if (alarm_raised) {
			rv = 0x100;
		}
	}

	/* see bsrsetup.c, print_config_error():
	 *  11: some unspecific state change error.
	 *  17: SS_NO_UP_TO_DATE_DISK */
	// BSR-174 error output to console when invalidate fails
	if (rv == 11 || rv == 17)
		rw = write(fileno(stderr), buffer, s);

	return rv;
}

static int adm_outdate(const struct cfg_ctx *ctx)
{
	int rv;

	rv = _adm_bsrsetup(ctx, SLEEPS_SHORT | SUPRESS_STDERR);
	/* special cases for outdate:
	 * 17: bsrsetup outdate, but is primary and thus cannot be outdated.
	 *  5: bsrsetup outdate, and is inconsistent or worse anyways. */
	if (rv == 17)
		return rv;

	if (rv == 5) {
		/* That might mean it is diskless. */
		rv = adm_bsrmeta(ctx);
		if (rv)
			rv = 5;
		return rv;
	}

	if (rv || dry_run) {
		rv = adm_bsrmeta(ctx);
	}
	return rv;
}

/* shell equivalent:
 * ( bsrsetup resize && bsrsetup check-resize ) || bsrmeta check-resize */
static int adm_chk_resize(const struct cfg_ctx *ctx)
{
	/* bsrsetup resize && bsrsetup check-resize */
	int ex = adm_resize(ctx);
	if (ex == 0)
		return 0;

	/* try bsrmeta check-resize */
	return adm_bsrmeta(ctx);
}

static int adm_setup_and_meta(const struct cfg_ctx *ctx)
{
	int rv;

	rv = __adm_bsrsetup_silent(ctx);

	if (rv == 11 || rv == 17) {
		/* see bsrsetup.c, print_config_error():
		 *  11: some unspecific state change error. (ignore for invalidate)
		 *  17: SS_NO_UP_TO_DATE_DISK */
		return rv;
	}

	if (rv || dry_run)
		rv = adm_bsrmeta(ctx);

	return rv;
}

static int adm_invalidate(const struct cfg_ctx *ctx)
{
	static const struct adm_cmd invalidate_meta_cmd = {
		"invalidate",
		adm_bsrmeta,
		ACF1_MINOR_ONLY
	};

	int rv;

	rv = call_cmd(&invalidate_setup_cmd, ctx, KEEP_RUNNING);
	if (rv == 11 || rv == 17) {
		/* see bsrsetup.c, print_config_error():
		 *  11: some unspecific state change error.
		 *       Means that there are multiple peers
		 *  17: SS_NO_UP_TO_DATE_DISK */
		return rv;
	}

	if (rv || dry_run == 1)
		rv = call_cmd(&invalidate_meta_cmd, ctx, KEEP_RUNNING);

	return rv;
}

static int adm_forget_peer(const struct cfg_ctx *ctx)
{
	static const struct adm_cmd forget_peer_meta_cmd = {
		"forget-peer",
		adm_bsrmeta,
		ACF1_PEER_DEVICE .disk_required = 1
	};

	int rv;

	rv = call_cmd(&forget_peer_setup_cmd, ctx, KEEP_RUNNING);
	if (rv == 11 || rv == 17)
		return rv;

	if (rv || dry_run == 1)
		rv = call_cmd(&forget_peer_meta_cmd, ctx, KEEP_RUNNING);

	return rv;
}

static void setenv_node_id_and_uname(struct d_resource *res)
{
	char key[sizeof("BSR_NODE_ID_32")];
	int i;
	struct d_host_info *host;

	for (i = 0; i < BSR_NODE_ID_MAX; i++) {
		snprintf(key, sizeof(key), "BSR_NODE_ID_%u", i);
		unsetenv(key);
	}
	for_each_host(host, &res->all_hosts) {
		if (!host->node_id)
			continue;
		/* range check in post parse has already clamped this */
		snprintf(key, sizeof(key), "BSR_NODE_ID_%s", host->node_id);
		setenv(key, names_to_str(&host->on_hosts), 1);
	}

	/* Maybe we will pass it in from kernel some day */
	if (!getenv("BSR_MY_NODE_ID"))
		setenv("BSR_MY_NODE_ID", res->me->node_id, 1);
}

static int adm_khelper(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct d_volume *vol = ctx->vol;
	int rv = 0;
	char *sh_cmd;
	char minor_string[8];
	char volume_string[8];
#ifdef _WIN
	char *argv[] = { "cmd", "/c", NULL, NULL };
#else // _LIN
	char *argv[] = { "/bin/sh", "-c", NULL, NULL };
#endif
	setenv("BSR_CONF", config_save, 1);
	setenv("BSR_RESOURCE", res->name, 1);
	setenv_node_id_and_uname(res);

	if (vol) {
		snprintf(minor_string, sizeof(minor_string), "%u", vol->device_minor);
		snprintf(volume_string, sizeof(volume_string), "%u", vol->vnr);
		setenv("BSR_MINOR", minor_string, 1);
		setenv("BSR_VOLUME", volume_string, 1);
		setenv("BSR_LL_DISK", shell_escape(vol->disk ? : "none"), 1);
	} else {
		char *minor_list;
		char *volume_list;
		char *ll_list;
		char *separator = "";
		char *pos_minor;
		char *pos_volume;
		char *pos_ll;
		int volumes = 0;
		int minor_len, volume_len, ll_len = 0;
		int n;

		for_each_volume(vol, &res->me->volumes) {
			volumes++;
			ll_len += strlen(shell_escape(vol->disk ? : "none")) + 1;
		}

		/* max minor number is 2**20 - 1, which is 7 decimal digits.
		 * plus separator respective trailing zero. */
		minor_len = volumes * 8 + 1;
		volume_len = minor_len;
		minor_list = alloca(minor_len);
		volume_list = alloca(volume_len);
		ll_list = alloca(ll_len);

		pos_minor = minor_list;
		pos_volume = volume_list;
		pos_ll = ll_list;
		for_each_volume(vol, &res->me->volumes) {
#define append(name, fmt, v) do {						\
			n = snprintf(pos_ ## name, name ## _len, "%s" fmt,	\
					separator, v);				\
			if (n >= name ## _len) {				\
				/* "can not happen" */				\
				err("buffer too small when generating the "	\
					#name " list\n");			\
				abort();					\
				break;						\
			}							\
			name ## _len -= n;					\
			pos_ ## name += n;					\
			} while (false)

			append(minor, "%d", vol->device_minor);
			append(volume, "%d", vol->vnr);
			append(ll, "%s", shell_escape(vol->disk ? : "none"));

#undef append
			separator = " ";
		}
		setenv("BSR_MINOR", minor_list, 1);
		setenv("BSR_VOLUME", volume_list, 1);
		setenv("BSR_LL_DISK", ll_list, 1);
	}

	if ((sh_cmd = get_opt_val(&res->handlers, ctx->cmd->name, NULL))) {
		argv[2] = sh_cmd;
		rv = m_system_ex(argv, SLEEPS_VERY_LONG, res->name);
	}
	return rv;
}

int adm_peer_device(const struct cfg_ctx *ctx)
{
	bool reset = (ctx->cmd == &peer_device_options_defaults_cmd);
	struct d_resource *res = ctx->res;
	struct connection *conn = ctx->conn;
	struct d_volume *vol = ctx->vol;
	struct peer_device *peer_device;
	char *argv[MAX_ARGS];
	int argc = 0;

	peer_device = find_peer_device(conn, vol->vnr);
	if (!peer_device) {
		err("Could not find peer_device object!\n");
		exit(E_THINKO);
	}

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* peer-device-options */

	argv[NA(argc)] = ssprintf("%s", res->name);
	argv[NA(argc)] = ssprintf("%s", conn->peer->node_id);
	argv[NA(argc)] = ssprintf("%d", vol->vnr);

	if (reset)
		argv[NA(argc)] = "--set-defaults";

	make_options(argv[NA(argc)], &peer_device->pd_options);
	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_SHORT, res->name);
}

static int adm_connect(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct connection *conn = ctx->conn;
	char *argv[MAX_ARGS];
	int argc = 0;

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* "connect" */
	argv[NA(argc)] = ssprintf("%s", res->name);
	argv[NA(argc)] = ssprintf("%s", conn->peer->node_id);

	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_SHORT, res->name);
}

static int adm_new_peer(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct connection *conn = ctx->conn;

	char *argv[MAX_ARGS];
	int argc = 0;

	bool reset = (ctx->cmd == &net_options_defaults_cmd);

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* "new-peer", "net-options" */
	argv[NA(argc)] = ssprintf("%s", res->name);
	argv[NA(argc)] = ssprintf("%s", conn->peer->node_id);

	if (reset)
		argv[NA(argc)] = "--set-defaults";

	if (!strncmp(ctx->cmd->name, "net-options", 11))
		del_opt(&conn->net_options, "transport");
	
	make_options(argv[NA(argc)], &conn->net_options);

	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_SHORT, res->name);
}

static int adm_path(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct connection *conn = ctx->conn;
	struct path *path = ctx->path;

	char *argv[MAX_ARGS];
	int argc = 0;

	argv[NA(argc)] = bsrsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* add-path, del-path */
	argv[NA(argc)] = ssprintf("%s", res->name);
	argv[NA(argc)] = ssprintf("%s", conn->peer->node_id);

	argv[NA(argc)] = ssprintf_addr(path->my_address);
	argv[NA(argc)] = ssprintf_addr(path->connect_to);

	add_setup_options(argv, &argc, ctx->cmd->bsrsetup_ctx);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_SHORT, res->name);
}

void free_opt(struct d_option *item)
{
	free(item->value);
	free(item);
}

int _proxy_connect_name_len(const struct d_resource *res, const struct connection *conn)
{
	struct path *path = STAILQ_FIRST(&conn->paths); /* multiple paths via proxy, later! */

	// DW-1426 avoid crash when no proxy exists.
	if (!path ||
		!path->peer_proxy ||
		!path->my_proxy)
		return 0;

	return (conn->name ? strlen(conn->name) : strlen(res->name)) +
		strlen(names_to_str_c(&path->peer_proxy->on_hosts, '_')) +
		strlen(names_to_str_c(&path->my_proxy->on_hosts, '_')) +
		3 /* for the two dashes and the trailing 0 character */;
}

char *_proxy_connection_name(char *conn_name, const struct d_resource *res, const struct connection *conn)
{
	struct path *path = STAILQ_FIRST(&conn->paths); /* multiple paths via proxy, later! */

	// DW-1426 avoid crash when no proxy exists.
	if (!path ||
		!path->peer_proxy ||
		!path->my_proxy)
		return (char*)0;

	sprintf(conn_name, "%s-%s-%s",
		conn->name ?: res->name,
		names_to_str_c(&path->peer_proxy->on_hosts, '_'),
		names_to_str_c(&path->my_proxy->on_hosts, '_'));
	return conn_name;
}

int do_proxy_conn_up(const struct cfg_ctx *ctx)
{
	char *argv[4] = { bsr_proxy_ctl, "-c", NULL, NULL };
	struct connection *conn;
	char *conn_name;
	int rv;

	rv = 0;

	for_each_connection(conn, &ctx->res->connections) {
		struct path *path = STAILQ_FIRST(&conn->paths); /* multiple paths via proxy, later! */

		// DW-1426
		if (!path || !path->my_proxy || !path->peer_proxy)
			continue;

		conn_name = proxy_connection_name(ctx->res, conn);

		// DW-1426 avoid crash when no proxy exists.
		if (conn_name == (char*)0)
			continue;

		argv[2] = ssprintf(
				"add connection %s %s:%s %s:%s %s:%s %s:%s",
				conn_name,
				path->my_proxy->inside.addr,
				path->my_proxy->inside.port,
				path->peer_proxy->outside.addr,
				path->peer_proxy->outside.port,
				path->my_proxy->outside.addr,
				path->my_proxy->outside.port,
				path->my_address->addr,
				path->my_address->port);

		rv = m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
		if (rv)
			break;
	}
	return rv;
}

int do_proxy_conn_plugins(const struct cfg_ctx *ctx)
{
	struct connection *conn;
	char *argv[MAX_ARGS];
	char *conn_name;
	int argc = 0;
	struct d_option *opt;
	int counter;
	int rv;

	rv = 0;

	for_each_connection(conn, &ctx->res->connections) {
		struct path *path = STAILQ_FIRST(&conn->paths); /* multiple paths via proxy, later! */

		// DW-1426
		if (!path || !path->my_proxy || !path->peer_proxy)
			continue;

		conn_name = proxy_connection_name(ctx->res, conn);

		// DW-1426 avoid crash when no proxy exists.
		if (conn_name == (char*)0)
			continue;

		argc = 0;
		argv[NA(argc)] = bsr_proxy_ctl;
		STAILQ_FOREACH(opt, &path->my_proxy->options, link) {
			argv[NA(argc)] = "-c";
			argv[NA(argc)] = ssprintf("set %s %s %s",
					opt->name, conn_name, opt->value);
		}

		counter = 0;
		/* Don't send the "set plugin ... END" line if no plugins are defined
		 * - that's incompatible with the bsr proxy version 1. */
		if (!STAILQ_EMPTY(&path->my_proxy->plugins)) {
			STAILQ_FOREACH(opt, &path->my_proxy->plugins, link) {
				argv[NA(argc)] = "-c";
				argv[NA(argc)] = ssprintf("set plugin %s %d %s",
						conn_name, counter, opt->name);
				counter++;
			}
			argv[NA(argc)] = ssprintf("set plugin %s %d END", conn_name, counter);
		}

		argv[NA(argc)] = 0;
		if (argc > 2)
			rv = m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
		if (rv)
			break;
	}

	return rv;
}

int do_proxy_conn_down(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct connection *conn;
	char *conn_name;
	char *argv[4] = { bsr_proxy_ctl, "-c", NULL, NULL};
	int rv;


	rv = 0;
	for_each_connection(conn, &res->connections) {
		struct path *path = STAILQ_FIRST(&conn->paths); /* multiple paths via proxy, later! */

		// DW-1426
		if (!path || !path->my_proxy || !path->peer_proxy)
			continue;

		conn_name = proxy_connection_name(ctx->res, conn);

		// DW-1426 avoid crash when no proxy exists.
		if (conn_name == (char*)0)
			continue;

		argv[2] = ssprintf("del connection %s", conn_name);

		rv = m_system_ex(argv, SLEEPS_SHORT, res->name);
		if (rv)
			break;
	}
	return rv;
}

static int check_proxy(const struct cfg_ctx *ctx, int do_up)
{
	struct connection *conn = ctx->conn;
	struct path *path = STAILQ_FIRST(&conn->paths); /* multiple paths via proxy, later! */
	int rv;

	if (STAILQ_NEXT(path, link)) {
		err("Multiple paths in connection within proxy setup not allowed\n");
		exit(E_CONFIG_INVALID);
	}

	if (!path->my_proxy) {
		return 0;
#if 0 // DW-1719 Ignore connections that do not use proxy
		if (all_resources)
			return 0;
		err("%s:%d: In resource '%s',no proxy config for connection %sfrom '%s' to '%s'%s.\n",
		    ctx->res->config_file, conn->config_line, ctx->res->name,
		    conn->name ? ssprintf("'%s' (", conn->name) : "",
		    hostname,
		    names_to_str(&conn->peer->on_hosts),
		    conn->name ? ")" : "");
		exit(E_CONFIG_INVALID);
#endif
	}

	if (!hostname_in_list(hostname, &path->my_proxy->on_hosts)) {
		if (all_resources)
			return 0;
		err("The proxy config in resource %s is not for %s.\n",
		    ctx->res->name, hostname);
		exit(E_CONFIG_INVALID);
	}

	if (!path->peer_proxy) {
		err("There is no proxy config for the peer in resource %s.\n",
		    ctx->res->name);
		if (all_resources)
			return 0;
		exit(E_CONFIG_INVALID);
	}


	if (do_up) {
		rv = do_proxy_conn_up(ctx);
		if (!rv)
			rv = do_proxy_conn_plugins(ctx);
	}
	else
		rv = do_proxy_conn_down(ctx);

	return rv;
}

static int adm_proxy_up(const struct cfg_ctx *ctx)
{
	return check_proxy(ctx, 1);
}

static int adm_proxy_down(const struct cfg_ctx *ctx)
{
	return check_proxy(ctx, 0);
}

/* The "main" loop iterates over resources.
 * This "sorts" the bsrsetup commands to bring those up
 * so we will later first create all objects,
 * then attach all local disks,
 * adjust various settings,
 * and then configure the network part */
static int adm_up(const struct cfg_ctx *ctx)
{
	struct cfg_ctx tmp_ctx = *ctx;
	struct connection *conn;
	struct d_volume *vol;

	schedule_deferred_cmd(&new_resource_cmd, ctx, CFG_PREREQ);
	schedule_deferred_cmd(&node_options_defaults_cmd, ctx, CFG_RESOURCE);
	set_peer_in_resource(ctx->res, true);
	for_each_connection(conn, &ctx->res->connections) {
		struct peer_device *peer_device;

		if (conn->ignore)
			continue;

		tmp_ctx.conn = conn;

		schedule_deferred_cmd(&new_peer_cmd, &tmp_ctx, CFG_NET_PREP_UP);
		schedule_deferred_cmd(&new_path_cmd, &tmp_ctx, CFG_NET_PATH);
		schedule_deferred_cmd(&connect_cmd, &tmp_ctx, CFG_NET_CONNECT);

		STAILQ_FOREACH(peer_device, &conn->peer_devices, connection_link) {
			struct cfg_ctx tmp2_ctx;

			if (STAILQ_EMPTY(&peer_device->pd_options))
				continue;

			tmp2_ctx = tmp_ctx;
			tmp2_ctx.vol = volume_by_vnr(&conn->peer->volumes, peer_device->vnr);
			schedule_deferred_cmd(&peer_device_options_cmd, &tmp2_ctx, CFG_PEER_DEVICE);
		}
	}
	tmp_ctx.conn = NULL;

	for_each_volume(vol, &ctx->res->me->volumes) {
		tmp_ctx.vol = vol;
		schedule_deferred_cmd(&new_minor_cmd, &tmp_ctx, CFG_DISK_PREP_UP);
		if (vol->disk)
			schedule_deferred_cmd(&attach_cmd, &tmp_ctx, CFG_DISK);
	}

	return 0;
}

/* The stacked-timeouts switch in the startup sections allows us
   to enforce the use of the specified timeouts instead the use
   of a sane value. Should only be used if the third node should
   never become primary. */
static int adm_wait_c(const struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct d_volume *vol = ctx->vol;
	char *argv[MAX_ARGS];
	int argc = 0, rv;

	argv[NA(argc)] = bsrsetup;
	if (ctx->vol && ctx->conn) {
		argv[NA(argc)] = ssprintf("%s-%s", ctx->cmd->name, "volume");
		argv[NA(argc)] = res->name;
		argv[NA(argc)] = ssprintf("%s", ctx->conn->peer->node_id);
		argv[NA(argc)] = ssprintf("%d", vol->vnr);
	} else if (ctx->conn) {
		argv[NA(argc)] = ssprintf("%s-%s", ctx->cmd->name, "connection");
		argv[NA(argc)] = res->name;
		argv[NA(argc)] = ssprintf("%s", ctx->conn->peer->node_id);
	} else {
		argv[NA(argc)] = ssprintf("%s-%s", ctx->cmd->name, "resource");
		argv[NA(argc)] = res->name;
	}

	if (is_bsr_top && !res->stacked_timeouts) {
		struct d_option *opt;
		unsigned long timeout = 20;
		if ((opt = find_opt(&res->net_options, "connect-int"))) {
			timeout = strtoul(opt->value, NULL, 10);
			// one connect-interval? two?
			timeout *= 2;
		}
		argv[argc++] = "--wfc-timeout";
		argv[argc] = ssprintf("%lu", timeout);
		argc++;
	} else
		make_options(argv[NA(argc)], &res->startup_options);
	argv[NA(argc)] = 0;

	rv = m_system_ex(argv, SLEEPS_FOREVER, res->name);

	return rv;
}

int ctx_by_minor(struct cfg_ctx *ctx, const char *id)
{
	struct d_resource *res;
	struct d_volume *vol;
	unsigned int mm;

	mm = minor_by_id(id);
	if (mm == -1U)
		return -ENOENT;

	for_each_resource(res, &config) {
		if (res->ignore)
			continue;
		for_each_volume(vol, &res->me->volumes) {
			if (mm == vol->device_minor) {
				is_bsr_top = res->stacked;
				ctx->res = res;
				ctx->vol = vol;
				return 0;
			}
		}
	}
	return -ENOENT;
}

struct d_volume *volume_by_vnr(struct volumes *volumes, int vnr)
{
	struct d_volume *vol;

	for_each_volume(vol, volumes)
		if (vnr == vol->vnr)
			return vol;

	return NULL;
}

/* if there is something to check:
 * return true if check succeeds, otherwise false */
static bool set_ignore_flag(struct connection * const conn, checks check, bool ignore)
{
	if (ignore == false) {
		if (check == WOULD_ENABLE_DISABLED && conn->ignore_tmp)
			return false;
		else if (check == WOULD_ENABLE_MULTI_TIMES && !conn->ignore_tmp)
			return false;

		if (check == WOULD_ENABLE_MULTI_TIMES)
			conn->ignore_tmp = ignore;
	}

	if (check == SETUP_MULTI)
		conn->ignore = ignore;

	return true;
}

int ctx_by_name(struct cfg_ctx *ctx, const char *id, checks check)
{
	struct d_resource *res;
	struct d_volume *vol;
	struct connection *conn;
	char *input = strdupa(id);
	char *vol_id;
	char *res_name, *conn_or_hostname;
	unsigned vol_nr = UINT32_MAX;

	res_name = input;
	vol_id = strrchr(input, '/');
	if (vol_id) {
		*vol_id++ = '\0';
		vol_nr = m_strtoll(vol_id, 0);
	}
	conn_or_hostname = strchr(input, ':');
	if (conn_or_hostname)
		*conn_or_hostname++ = '\0';

	res = res_by_name(res_name);
	// DW-1719 Added option to ignore hostname check
	if (!res || (!ignore_hostname && res->ignore))
		return -ENOENT;
	ctx->res = res;

	set_peer_in_resource(res, 1);

	/* resource name only (e.g., r0) and in check state
	 * this would enable all connectionst that are not ignored */
	if (!conn_or_hostname && check == WOULD_ENABLE_MULTI_TIMES)
		for_each_connection(conn, &res->connections)
			if (!conn->ignore) {
				if (!conn->ignore_tmp)
					return 1;
				else
					conn->ignore_tmp = false;
			}

	if (conn_or_hostname) {
		/* per se we do not know if the part after ':' is a host or a connection name */
		struct d_host_info *hi;
		bool valid_conns = false;

		ctx->conn = NULL;

		hi = find_host_info_by_name(res, conn_or_hostname);
		for_each_connection(conn, &res->connections) {
			if (hi) { /* it was host name */
				if (res->me == hi) {
					err("Host name '%s' (given with --peer option) is not a "
					    "peer, but the local node\n",
					    conn_or_hostname);
					return -ENOENT;
				}

				if (conn->peer == hi && check == CTX_FIRST)
					goto found;

				if (conn->peer && !strcmp(conn->peer->node_id, hi->node_id)) {
					conn->me = true;
					if (!set_ignore_flag(conn, check, false))
						return 1;
				}
				else /* a connection that should be ignored */
					set_ignore_flag(conn, check, true);
			} else { /* it was a connection name */
				struct d_option *opt;
				opt = find_opt(&conn->net_options, "_name");
				if (opt && !strcmp(opt->value, conn_or_hostname)) {
					if (check == CTX_FIRST)
						goto found;

					conn->me = true;
					if (!set_ignore_flag(conn, check, false))
						return 1;
				}
				else { /* a connection that should be ignored */
					set_ignore_flag(conn, check, true);
				}
			}

			if (!conn->ignore)
				valid_conns = true;
		}

		if (check == SETUP_MULTI && !valid_conns) {
			err("Not a valid connection (%s) for this host\n", id);
			return -ENOENT;
		}
	}

	if (check != SETUP_MULTI)
		return 0;

	if (false) {
found:
		if (conn->ignore) {
			err("Connection '%s' has the ignore flag set\n",
			    conn_or_hostname);
			return -ENOENT;
		}

		ctx->conn = conn;
	}

	if (!vol_id) {
		/* We could assign implicit volumes here.
		 * But that broke "bsradm up specific-resource".
		 */
		ctx->vol = NULL;
		return 0;
	}

	vol = volume_by_vnr(&res->me->volumes, vol_nr);
	if (vol_nr != UINT32_MAX) {
		if (vol) {
			ctx->vol = vol;
			return 0;
		} else {
			err("Resource '%s' has no volume %d\n", res_name,
			    vol_nr);
			return -ENOENT;
		}
	}

	return -ENOENT;
}

/* In case a child exited, or exits, its return code is stored as
   negative number in the pids[i] array */
static int childs_running(pid_t * pids, int opts)
{
	int i = 0, wr, rv = 0, status;
	int N = nr_volumes[is_bsr_top ? STACKED : NORMAL];

	for (i = 0; i < N; i++) {
		if (pids[i] <= 0)
			continue;
		wr = waitpid(pids[i], &status, opts);
		if (wr == -1) {	// Wait error.
			if (errno == ECHILD) {
				printf("No exit code for %d\n", pids[i]);
				pids[i] = 0;	// Child exited before ?
				continue;
			}
			CLI_ERRO_LOG_PEEROR(false, "waitpid");
			exit(E_EXEC_ERROR);
		}
		if (wr == 0)
			rv = 1;	// Child still running.
		if (wr > 0) {
			pids[i] = 0;
			if (WIFEXITED(status))
				pids[i] = -WEXITSTATUS(status);
			if (WIFSIGNALED(status))
				pids[i] = -1000;
		}
	}
	return rv;
}

static void kill_childs(pid_t * pids)
{
	int i;
	int N = nr_volumes[is_bsr_top ? STACKED : NORMAL];

	for (i = 0; i < N; i++) {
		if (pids[i] <= 0)
			continue;
		kill(pids[i], SIGINT);
	}
}

/*
  returns:
  -1 ... all childs terminated
   0 ... timeout expired
   1 ... a string was read
 */
int gets_timeout(pid_t * pids, char *s, int size, int timeout)
{
	int pr, rr, n = 0;
	struct pollfd pfd;

	if (s) {
		pfd.fd = fileno(stdin);
		pfd.events = POLLIN | POLLHUP | POLLERR | POLLNVAL;
		n = 1;
	}

redo_without_fd:
	if (!childs_running(pids, WNOHANG)) {
		pr = -1;
		goto out;
	}

	do {
		pr = poll(&pfd, n, timeout);

		if (pr == -1) {	// Poll error.
			if (errno == EINTR) {
				if (childs_running(pids, WNOHANG))
					continue;
				goto out;	// pr = -1 here.
			}
			CLI_ERRO_LOG_PEEROR(false, "poll");
			exit(E_EXEC_ERROR);
		}
	} while (pr == -1);

	if (pr == 1 && s) {		// Input available and s not NULL.
      /* TODO: what should happen if s == NULL? is this correct?
       * at least we check here and do not nullptr deref */
		rr = read(fileno(stdin), s, size - 1);
		if (rr == -1) {
			CLI_ERRO_LOG_PEEROR(false, "read");
			exit(E_EXEC_ERROR);
		} else if (size > 1 && rr == 0) {
			/* WTF. End-of-file... avoid busy loop. */
			s[0] = 0;
			n = 0;
			goto redo_without_fd;
		}
		s[rr] = 0;
	}

out:
	return pr;
}

static char *get_opt_val(struct options *base, const char *name, char *def)
{
	struct d_option *option;

	option = find_opt(base, name);
	return option ? option->value : def;
}

static int check_exit_codes(pid_t * pids)
{
	struct d_resource *res;
	int i = 0, rv = 0;

	for_each_resource(res, &config) {
		if (res->ignore)
			continue;
		if (is_bsr_top != res->stacked)
			continue;
		if (pids[i] == -5 || pids[i] == -1000) {
			pids[i] = 0;
		}
		if (pids[i] == -20)
			rv = 20;
		i++;
	}
	return rv;
}

static int adm_wait_ci(const struct cfg_ctx *ctx)
{
	struct d_resource *res;
	char *argv[20], answer[40];
	pid_t *pids;
	int rr, wtime, argc, i = 0;
	time_t start;
	int saved_stdin, saved_stdout, fd;
	int N;
	struct sigaction so, sa;
	int have_tty = 1;

	saved_stdin = -1;
	saved_stdout = -1;
	if (no_tty) {
		err("WARN: stdin/stdout is not a TTY; using /dev/console");
		fprintf(stdout,
			"WARN: stdin/stdout is not a TTY; using /dev/console");
		saved_stdin = dup(fileno(stdin));
		if (saved_stdin == -1)
			CLI_ERRO_LOG_PEEROR(false, "dup(stdin)");
		saved_stdout = dup(fileno(stdout));
		if (saved_stdin == -1)
			CLI_ERRO_LOG_PEEROR(false, "dup(stdout)");
		fd = open("/dev/console", O_RDONLY);
		if (fd == -1) {
			CLI_ERRO_LOG_PEEROR(false, "open('/dev/console, O_RDONLY)");
			have_tty = 0;
		} else {
			dup2(fd, fileno(stdin));
			fd = open("/dev/console", O_WRONLY);
			if (fd == -1)
				CLI_ERRO_LOG_PEEROR(false, "open('/dev/console, O_WRONLY)");
			dup2(fd, fileno(stdout));
		}
	}

	sa.sa_handler = chld_sig_hand;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, &so);

	N = nr_volumes[is_bsr_top ? STACKED : NORMAL];
	pids = alloca(N * sizeof(pid_t));
	/* alloca can not fail, it can "only" overflow the stack :)
	 * but it needs to be initialized anyways! */
	memset(pids, 0, N * sizeof(pid_t));

	for_each_resource(res, &config) {
		if (res->ignore)
			continue;
		if (is_bsr_top != res->stacked)
			continue;

		/* ctx is not used */
		argc = 0;
		argv[NA(argc)] = bsrsetup;
		argv[NA(argc)] = "wait-connect-resource";
		argv[NA(argc)] = res->name;
		make_options(argv[NA(argc)], &res->startup_options);
		argv[NA(argc)] = 0;

		m__system(argv, RETURN_PID, res->name, &pids[i++], NULL, NULL);
	}

	wtime = global_options.dialog_refresh ? : -1;

	start = time(0);
	for (i = 0; i < 10; i++) {
		// no string, but timeout
		rr = gets_timeout(pids, 0, 0, 1 * 1000);
		if (rr < 0)
			break;
		putchar('.');
		fflush(stdout);
		check_exit_codes(pids);
	}

	if (rr == 0) {
		/* track a "yes", as well as ctrl-d and ctrl-c,
		 * in case our tty is stuck in "raw" mode, and
		 * we get it one character a time (-icanon) */
		char yes_string[] = "yes\n";
		char *yes_expect = yes_string;
		int ctrl_c_count = 0;
		int ctrl_d_count = 0;

		/* Just in case, if plymouth or usplash is running,
		 * tell them to step aside.
		 * Also try to force canonical tty mode. */
		printf
		    ("\n***************************************************************\n"
		     " BSR's startup script waits for the peer node(s) to appear.\n"
		     " - If this node was already a degraded cluster before the\n"
		     "   reboot, the timeout is %s seconds. [degr-wfc-timeout]\n"
		     " - If the peer was available before the reboot, the timeout\n"
		     "   is %s seconds. [wfc-timeout]\n"
		     "   (These values are for resource '%s'; 0 sec -> wait forever)\n",
		     get_opt_val(&STAILQ_FIRST(&config)->startup_options, "degr-wfc-timeout",
				 "0"), get_opt_val(&STAILQ_FIRST(&config)->startup_options,
						   "wfc-timeout", "0"),
		     STAILQ_FIRST(&config)->name);

		if (!have_tty) {
			printf(" To abort waiting for BSR connections, kill this process: kill %u\n", getpid());
			fflush(stdout);
			/* wait untill killed, or all bsrsetup children have finished. */
			do {
				rr = poll(NULL, 0, -1);
				if (rr == -1) {
					if (errno == EINTR) {
						if (childs_running(pids, WNOHANG))
							continue;
						break;
					}
					CLI_ERRO_LOG_PEEROR(false, "poll");
					exit(E_EXEC_ERROR);
				}
			} while (rr != -1);

			kill_childs(pids);
			childs_running(pids, 0);
			check_exit_codes(pids);
			return 0;
		}
#ifdef _LIN
		if (system("exec > /dev/null 2>&1; plymouth quit ; usplash_write QUIT ; "
			   "stty echo icanon icrnl"))
			/* Ignore return value. Cannot do anything about it anyways. */;
#endif

		printf(" To abort waiting enter 'yes' [ -- ]: ");
		do {
			printf("\e[s\e[31G[%4d]:\e[u", (int)(time(0) - start));	// Redraw sec.
			fflush(stdout);
			rr = gets_timeout(pids, answer, 40, wtime * 1000);
			check_exit_codes(pids);

			if (rr != 1)
				continue;

			/* If our tty is in "sane" or "canonical" mode,
			 * we get whole lines.
			 * If it still is in "raw" mode, even though we
			 * tried to set ICANON above, possibly some other
			 * "boot splash thingy" is in operation.
			 * We may be lucky to get single characters.
			 * If a sysadmin sees things stuck during boot,
			 * I expect that ctrl-c or ctrl-d will be one
			 * of the first things that are tried.
			 * In raw mode, we get these characters directly.
			 * But I want them to try that three times ;)
			 */
			if (answer[0] && answer[1] == 0) {
				if (answer[0] == '\3')
					++ctrl_c_count;
				if (answer[0] == '\4')
					++ctrl_d_count;
				if (yes_expect && answer[0] == *yes_expect)
					++yes_expect;
				else if (answer[0] == '\n')
					yes_expect = yes_string;
				else
					yes_expect = NULL;
			}

			if (!strcmp(answer, "yes\n") ||
			    (yes_expect && *yes_expect == '\0') ||
			    ctrl_c_count >= 3 ||
			    ctrl_d_count >= 3) {
				kill_childs(pids);
				childs_running(pids, 0);
				check_exit_codes(pids);
				break;
			}

			printf(" To abort waiting enter 'yes' [ -- ]:");
		} while (rr != -1);
		printf("\n");
	}

	if (saved_stdin != -1) {
		dup2(saved_stdin, fileno(stdin));
		dup2(saved_stdout, fileno(stdout));
	}

	return 0;
}

static int adm_cmd_cmp(const void *a, const void *b)
{
	return strcmp((*(struct adm_cmd **)a)->name,
		      (*(struct adm_cmd **)b)->name);
}

static void print_cmds(int level)
{
	const struct adm_cmd **cmds2;
	int i, j, half;

	cmds2 = alloca(ARRAY_SIZE(cmds) * sizeof(struct adm_cmd));
	for (i = 0, j = 0; i < ARRAY_SIZE(cmds); i++) {
		if (cmds[i]->show_in_usage != level)
			continue;
		cmds2[j++] = cmds[i];
	}
	qsort(cmds2, j, sizeof(struct adm_cmd *), adm_cmd_cmp);
	half = (j + 1) / 2;
	for (i = 0; i < half; i++) {
		if (i + half < j)
			printf(" %-35s %-35s\n",
			       cmds2[i]->name,
			       cmds2[i + half]->name);
		else
			printf(" %-35s\n",
			       cmds2[i]->name);
	}
}

static int hidden_cmds(const struct cfg_ctx *ignored __attribute((unused)))
{
	printf("\nThese additional commands might be useful for writing\n"
	       "nifty shell scripts around bsradm:\n\n");

	print_cmds(2);

	printf("\nThese commands are used by the kernel part of BSR to\n"
	       "invoke user mode helper programs:\n\n");

	print_cmds(3);

	printf
	    ("\nThese commands ought to be used by experts and developers:\n\n");

	print_cmds(4);

	printf("\n");

	CLI_INFO_LOG(false, "hidden_cmds exit(0)");
	exit(0);
}

static void field_to_option(const struct field_def *field, struct option *option)
{
	option->name = field->name;
	option->has_arg = field->argument_is_optional ?
		optional_argument : required_argument;
	option->flag = NULL;
	option->val = 257;
}

static void print_option(struct option *opt)
{
	if (opt->has_arg == required_argument) {
		printf("  --%s=...", opt->name);
		if (opt->val > 1 && opt->val < 256)
			 printf(", -%c ...", opt->val);
		printf("\n");
	} else if (opt->has_arg == optional_argument) {
		printf("  --%s[=...]", opt->name);
		if (opt->val > 1 && opt->val < 256)
			 printf(", -%c...", opt->val);
		printf("\n");
	} else {
		printf("  --%s", opt->name);
		if (opt->val > 1 && opt->val < 256)
			 printf(", -%c", opt->val);
		printf("\n");
	}
}

void print_usage_and_exit(struct adm_cmd *cmd, const char *addinfo, int status)
{
	struct option *opt;

	printf("\nUSAGE: %s %s [OPTION...] {all|RESOURCE...}\n\n"
	       "GENERAL OPTIONS:\n", progname, cmd ? cmd->name : "COMMAND");

	for (opt = general_admopt; opt->name; opt++)
		print_option(opt);
	if (cmd && cmd->bsrsetup_ctx) {
		const struct field_def *field;

		printf("\nOPTIONS FOR %s:\n", cmd->name);
		for (field = cmd->bsrsetup_ctx->fields; field->name; field++) {
			struct option opt;

			field_to_option(field, &opt);
			print_option(&opt);
		}
	}

	if (!cmd) {
		printf("\nCOMMANDS:\n");

		print_cmds(1);
	}

	printf("\nVersion: " PACKAGE_VERSION " (api:%d)\n%s\n",
	       API_VERSION, bsr_buildtag());

	if (addinfo)
		printf("\n%s\n", addinfo);

	CLI_WRAN_LOG(false, "print usage and exit(%d)\n", status);
	exit(status);
}

void verify_ips(struct d_resource *res)
{
	if (global_options.disable_ip_verification)
		return;
	if (dry_run == 1 || do_verify_ips == 0)
		return;
	if (res->ignore)
		return;
	if (res->stacked && !is_bsr_top)
		return;
	if (!res->me->address.addr)
		return;

	if (!have_ip(res->me->address.af, res->me->address.addr)) {
		ENTRY *e, *ep, *f;
		e = calloc(1, sizeof *e);
		if (!e) {
			err("calloc: %m\n");
			exit(E_EXEC_ERROR);
		}
		m_asprintf(&e->key, "%s:%s", res->me->address.addr, res->me->address.port);
		f = tfind(e, &global_btree, btree_key_cmp);
		free(e);
		if (f)
			ep = *(ENTRY **)f;
		err("%s: in resource %s, on %s:\n\t""IP %s not found on this host.\n",
			f ? (char *)ep->data : res->config_file, res->name,
		    names_to_str(&res->me->on_hosts), res->me->address.addr);
		if (INVALID_IP_IS_INVALID_CONF)
			config_valid = 0;
	}
}

static char *conf_file[] = {
	BSR_CONFIG_DIR "/bsr-90.conf",
	BSR_CONFIG_DIR "/bsr-84.conf",
	BSR_CONFIG_DIR "/bsr-83.conf",
	BSR_CONFIG_DIR "/bsr-82.conf",
	BSR_CONFIG_DIR "/bsr-08.conf",
	BSR_CONFIG_DIR "/bsr.conf",
	0
};

int pushd(const char *path)
{
	int cwd_fd = -1;
	cwd_fd = open(".", O_RDONLY | O_CLOEXEC);
	if (cwd_fd < 0) {
		err("open(\".\") failed: %m\n");
		exit(E_USAGE);
	}
	if (path && path[0] && chdir(path)) {
		err("chdir(\"%s\") failed: %m\n", path);
		exit(E_USAGE);
	}
	return cwd_fd;
}

void popd(int fd)
{
	if (fd >= 0) {
		if (fchdir(fd) < 0) {
			err("fchdir() failed: %m\n");
			exit(E_USAGE);
		}
		close(fd);
	}
}


/*
 * returns a pointer to an malloced area that contains
 * an absolute, canonical, version of path.
 * aborts if any allocation or syscall fails.
 * return value should be free()d, once no longer needed.
 */
char *canonify_path(char *path)
{
	int cwd_fd = -1;
	char *last_slash;
	char *tmp;
	char *that_wd;
	char *abs_path;

	if (!path || !path[0]) {
		err("cannot canonify an empty path\n");
		exit(E_USAGE);
	}

	tmp = strdupa(path);
	last_slash = strrchr(tmp, '/');

	/* Maybe this already is in the top level directory. */
	if (last_slash == tmp)
		return strdup(path);

	if (last_slash) {
		*last_slash++ = '\0';
		cwd_fd = pushd(tmp);
	} else {
		last_slash = tmp;
	}

	that_wd = getcwd(NULL, 0);
	if (!that_wd) {
		err("getcwd() failed: %m\n");
		exit(E_USAGE);
	}

	/* could have been a symlink to / */
	if (!strcmp("/", that_wd))
		m_asprintf(&abs_path, "/%s", last_slash);
	else
		m_asprintf(&abs_path, "%s/%s", that_wd, last_slash);

	free(that_wd);
	popd(cwd_fd);

	return abs_path;
}

void assign_command_names_from_argv0(char **argv)
{
	struct cmd_helper {
		char *name;
		char **var;
	};
	static struct cmd_helper helpers[] = {
		{"bsrsetup", &bsrsetup},
		{"bsrmeta", &bsrmeta},
		{"bsr-proxy-ctl", &bsr_proxy_ctl},
		{"bsradm-83", &bsradm_83},
		{"bsradm-84", &bsradm_84},
		{NULL, NULL}
	};
	struct cmd_helper *c;

	/* in case bsradm is called with an absolute or relative pathname
	 * look for the bsrsetup binary in the same location,
	 * otherwise, just let execvp sort it out... */
	if ((progname = strrchr(argv[0], '/')) == NULL) {
		progname = argv[0];
		for (c = helpers; c->name; ++c)
			*(c->var) = strdup(c->name);
	} else {
		size_t len_dir, l;

		++progname;
		len_dir = progname - argv[0];

		for (c = helpers; c->name; ++c) {
			l = len_dir + strlen(c->name) + 1;
			*(c->var) = malloc(l);
			if (*(c->var)) {
				strncpy(*(c->var), argv[0], len_dir);
				strcpy(*(c->var) + len_dir, c->name);
				if (access(*(c->var), X_OK))
					strcpy(*(c->var), c->name); /* see add_lib_bsr_to_path() */
			}
		}

		/* for pretty printing, truncate to basename */
		argv[0] = progname;
	}
}

static void recognize_all_bsrsetup_options(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		const struct adm_cmd *cmd = cmds[i];
		const struct field_def *field;

		if (!cmd->bsrsetup_ctx)
			continue;

		for (field = cmd->bsrsetup_ctx->fields; field->name; field++) {
			struct option opt;
			int n;

			field_to_option(field, &opt);
			for (n = 0; admopt[n].name; n++) {
				if (!strcmp(admopt[n].name, field->name)) {
					if (admopt[n].val == 257)
						assert (admopt[n].has_arg == opt.has_arg);
					else {
						err("Warning: bsrsetup %s option --%s "
						    "can only be passed as -W--%s\n",
                                                    cmd->name, admopt[n].name, admopt[n].name);
						goto skip;
					}
				}
			}

			if (admopt == general_admopt) {
				admopt = malloc((n + 2) * sizeof(*admopt));
				memcpy(admopt, general_admopt, (n + 1) * sizeof(*admopt));
			} else
				admopt = realloc(admopt, (n + 2) * sizeof(*admopt));
			memcpy(&admopt[n+1], &admopt[n], sizeof(*admopt));
			admopt[n] = opt;

		    skip:
			/* dummy statement required because of label */ ;
		}
	}
}

struct adm_cmd *find_cmd(char *cmdname);

int parse_options(int argc, char **argv, struct adm_cmd **cmd, char ***resource_names)
{
	const char *optstring = make_optstring(admopt);
	struct names backend_options_check;
	struct d_name *b_opt;
	int longindex, first_arg_index;
#ifdef _LIN
	bool force_opt = false;
#endif
	STAILQ_INIT(&backend_options_check);
	*cmd = NULL;
	*resource_names = calloc(argc + 1, sizeof(char *));

	opterr = 1;
	optind = 0;
	while (1) {
		int c;

		c = getopt_long(argc, argv, optstring, admopt, &longindex);
		if (c == -1)
			break;
		switch (c) {
		case 257:  /* bsrsetup option */
			{
				struct option *option = &admopt[longindex];
				char *opt;
#ifdef _LIN
				// BSR-823
				if (!strcmp(option->name, "force")) {
					if (!optarg || (optarg && !strcmp(option->name, "true")))
						force_opt = true;
				}
#endif				
				if (optarg)
					opt = ssprintf("--%s=%s", option->name, optarg);
				else
					opt = ssprintf("--%s", option->name);
				insert_tail(&backend_options_check, names_from_str(opt));
			}
			break;
		case 'S':
			is_bsr_top = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			dry_run = 1;
			break;
		case 'T':
			llevel = TRACE_LEVEL;
			break;
		case 'i': // DW-1719 Added option to ignore hostname check
			ignore_hostname = 1;
			break;
		case 'c':
			if (!strcmp(optarg, "-")) {
				yyin = stdin;
				if (asprintf(&config_file, "STDIN") < 0) {
					err("asprintf(config_file): %m\n");
					return 20;
				}
				config_from_stdin = 1;
			} else {
				yyin = fopen(optarg, "r");
				if (!yyin) {
					err("Can not open '%s'.\n.", optarg);
					exit(E_EXEC_ERROR);
				}
				if (asprintf(&config_file, "%s", optarg) < 0) {
					err("asprintf(config_file): %m\n");
					return 20;
				}
			}
			break;
		case 't':
			config_test = optarg;
			break;
		case 'E':
			/* Remember as absolute name */
			was_file_already_seen(optarg);
			break;
		case 's':
			{
				char *pathes[2];
				pathes[0] = optarg;
				pathes[1] = 0;
				find_bsrcmd(&bsrsetup, pathes);
			}
			break;
		case 'm':
			{
				char *pathes[2];
				pathes[0] = optarg;
				pathes[1] = 0;
				find_bsrcmd(&bsrmeta, pathes);
			}
			break;
		case 'p':
			{
				char *pathes[2];
				pathes[0] = optarg;
				pathes[1] = 0;
				find_bsrcmd(&bsr_proxy_ctl, pathes);
			}
			break;
		case 'n':
			{
				char *c;
				int shell_var_name_ok = 1;
				for (c = optarg; *c && shell_var_name_ok; c++) {
					switch (*c) {
					case 'a'...'z':
					case 'A'...'Z':
					case '0'...'9':
					case '_':
						break;
					default:
						shell_var_name_ok = 0;
					}
				}
				if (shell_var_name_ok)
					sh_varname = optarg;
				else
					err("ignored --sh-varname=%s: "
					    "contains suspect characters, allowed set is [a-zA-Z0-9_]\n",
					    optarg);
			}
			break;
		case 'V':
			printf("BSRADM_BUILDTAG=%s\n", shell_escape(bsr_buildtag()));
			printf("BSRADM_API_VERSION=%u\n", API_VERSION);
			printf("BSR_KERNEL_VERSION_CODE=0x%08x\n", version_code_kernel());
			printf("BSR_KERNEL_VERSION=%s\n", shell_escape(PACKAGE_VERSION));
			printf("BSRADM_VERSION_CODE=0x%08x\n", version_code_userland());
			printf("BSRADM_VERSION=%s\n", shell_escape(PACKAGE_VERSION));
			bsr_terminate_log(0);
			exit(0);
			break;
		case 'P':
			connect_to_host = optarg;
			break;
		case 'W':
			insert_tail(&backend_options, names_from_str(optarg));
			break;
		case 'h':
			help = true;
			break;
		case '?':
			goto help;
		}
	}

	first_arg_index = optind;
	for (; optind < argc; optind++) {
		optarg = argv[optind];
		if (*cmd) {
			static int last_idx = 0;
			ensure_sanity_of_res_name(optarg);
			(*resource_names)[last_idx++] = optarg;
		}
		else if (!strcmp(optarg, "help"))
			help = true;
		else {
			*cmd = find_cmd(optarg);
			if (!*cmd) {
				/* Passing bsrsetup options like this is discouraged! */
				insert_tail(&backend_options, names_from_str(optarg));
			}
		}
	}

	if (help)
		print_usage_and_exit(*cmd, NULL, 0);

	if (*cmd == NULL) {
		if (first_arg_index < argc) {
			err("%s: Unknown command '%s'\n", progname, argv[first_arg_index]);
			return E_USAGE;
		}
		print_usage_and_exit(*cmd, "No command specified", E_USAGE);
	}

	/*
	 * The backend (bsrsetup) options are command specific.  Make sure that only
	 * setup options that this command recognizes are used.
	 */
	STAILQ_FOREACH(b_opt, &backend_options_check, link) {
		const struct field_def *field;
		const char *option;
		int len;

		option = b_opt->name;
		for (len = 0; option[len]; len++)
			if (option[len] == '=')
				break;

		field = NULL;
		if (option[0] == '-' && option[1] == '-' && (*cmd)->bsrsetup_ctx &&
			(*cmd)->bsrsetup_ctx != &wildcard_ctx) {
			for (field = (*cmd)->bsrsetup_ctx->fields; field->name; field++) {
				if (strlen(field->name) == len - 2 &&
				    !strncmp(option + 2, field->name, len - 2))
					break;
			}
			if (!field->name)
				field = NULL;
		}
		if (!field && (*cmd)->bsrsetup_ctx != &wildcard_ctx) {
			err("%s: unrecognized option '%.*s'\n", progname, len, option);
			goto help;
		}
	}
	STAILQ_CONCAT(&backend_options, &backend_options_check);

#ifdef _LIN
	// BSR-823
	if (!strcmp((*cmd)->name, "primary") && force_opt)
		force_primary = true;
#endif

	return 0;

help:
	if (*cmd)
		err("try '%s help %s'\n", progname, (*cmd)->name);
	else
		err("try '%s help'\n", progname);
	return E_USAGE;
}

struct adm_cmd *find_cmd(char *cmdname)
{
	struct adm_cmd *cmd = NULL;
	unsigned int i;
	if (!strcmp("hidden-commands", cmdname)) {
		// before parsing the configuration file...
		hidden_cmds(NULL);
		exit(0);
	}

	/* R_PRIMARY / R_SECONDARY is not a state, but a role.  Whatever that
	 * means, actually.  But anyways, we decided to start using _role_ as
	 * the terminus of choice, and deprecate "state". */
	substitute_deprecated_cmd(&cmdname, "state", "role");

	/* "outdate-peer" got renamed to fence-peer,
	 * it is not required to actually outdate the peer,
	 * depending on situation it may be sufficient to power-reset it
	 * or do some other fencing action, or even call out to "meatware".
	 * The name of the handler should not imply something that is not done. */
	substitute_deprecated_cmd(&cmdname, "outdate-peer", "fence-peer");

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (!strcmp(cmds[i]->name, cmdname)) {
			cmd = cmds[i];
			break;
		}
	}
	return cmd;
}

char *config_file_from_arg(char *arg)
{
	char *f;
	int minor = minor_by_id(arg);

	if (minor >= 0) {
		f = lookup_minor(minor);
		if (!f) {
			err("Don't know which config file belongs to minor %d, trying default ones...\n", minor);
			return NULL;
		}
	} else {
		f = lookup_resource(arg);
		if (!f) {
			err("Don't know which config file belongs to resource %s, trying default ones...\n", arg);
			return NULL;
		}
	}

	yyin = fopen(f, "r");
	if (yyin == NULL) {
		err("Couldn't open file %s for reading, reason: %m\ntrying default config file...\n", config_file);
		return NULL;
	}
	return f;
}

void assign_default_config_file(void)
{
	int i;
	for (i = 0; conf_file[i]; i++) {
		yyin = fopen(conf_file[i], "r");
		if (yyin) {
			config_file = conf_file[i];
			break;
		}
	}
	if (!config_file) {
		err("Can not open '%s': %m\n", conf_file[i - 1]);
		exit(E_CONFIG_INVALID);
	}
}

void count_resources(void)
{
	struct d_resource *res;
	struct d_volume *vol;

	number_of_minors = 0;
	for_each_resource(res, &config) {
		if (res->ignore) {
			nr_resources[IGNORED]++;
			/* How can we count ignored volumes?
			 * Do we want to? */
			continue;
		} else if (res->stacked)
			nr_resources[STACKED]++;
		else
			nr_resources[NORMAL]++;

		for_each_volume(vol, &res->me->volumes) {
			number_of_minors++;
			if (res->stacked)
				nr_volumes[STACKED]++;
			/* res->ignored won't come here */
			else
				nr_volumes[NORMAL]++;
		}
	}
}

void die_if_no_resources(void)
{
	if (!is_bsr_top && nr_resources[IGNORED] > 0 && nr_resources[NORMAL] == 0) {
		err("WARN: no normal resources defined for this host (%s)!?\n"
		    "Misspelled name of the local machine with the 'on' keyword ?\n",
		    hostname);
		exit(E_USAGE);
	}
	if (!is_bsr_top && nr_resources[NORMAL] == 0) {
		err("WARN: no normal resources defined for this host (%s)!?\n", hostname);
		exit(E_USAGE);
	}
	if (is_bsr_top && nr_resources[STACKED] == 0) {
		err("WARN: nothing stacked for this host (%s), "
		    "nothing to do in stacked mode!\n",
		    hostname);
		exit(E_USAGE);
	}
}

extern char* lprogram;
extern char* lcmd;
// BSR-614
extern int llevel;
// BSR-1031
extern int lstatus;
extern char execution_log[512];

int main(int argc, char **argv)
{
	size_t i;
	int rv = 0, r;
	struct adm_cmd *cmd = NULL;
	char **resource_names = NULL;
	struct d_resource *res;
	char *env_bsr_nodename = NULL;
	int is_dump_xml;
	int is_dump;
	int is_adjust;
	struct cfg_ctx ctx = { };

	lprogram = basename(argv[0]);

	// BSR-1031 set execution_log, output on error
	set_exec_log(argc, argv);

	initialize_err();
	initialize_deferred_cmds();
#ifdef _WIN
	{
        extern void manual_nl_policy_init_by_app(void);
        manual_nl_policy_init_by_app();
	}
#endif
	yyin = NULL;
	hostname = get_hostname();
	no_tty = (!isatty(fileno(stdin)) || !isatty(fileno(stdout)));

	env_bsr_nodename = getenv("__BSR_NODE__");
	if (env_bsr_nodename && *env_bsr_nodename) {
		hostname = strdup(env_bsr_nodename);
		err("\n"
		    "   found __BSR_NODE__ in environment\n"
		    "   PRETENDING that I am >>%s<<\n\n",
		    hostname);
	}

	assign_command_names_from_argv0(argv);

	CLI_TRAC_LOG(false, "check deferred cmd bsrsetup(%s), bsrmeta(%s), bsr_proxy_ctl(%s)", 
					bsrsetup != NULL ? "true" : "false",
					bsrmeta != NULL ? "true" : "false",
					bsr_proxy_ctl != NULL ? "true" : "false");

	if (bsrsetup == NULL || bsrmeta == NULL || bsr_proxy_ctl == NULL) {
		err("could not strdup argv[0].\n");
		exit(E_EXEC_ERROR);
	}

	maybe_exec_legacy_bsradm(argv);

	recognize_all_bsrsetup_options();
	rv = parse_options(argc, argv, &cmd, &resource_names);

	CLI_TRAC_LOG(false, "check parse_option (%d)", rv);

	if (rv)
		return rv;

	lcmd = (char *)cmd->name;
	// BSR-1031
	lstatus = cmd->is_status_cmd;
	// execution_log output
	bsr_exec_log();

	if (config_test && !cmd->test_config) {
		err("The --config-to-test (-t) option is only allowed "
		    "with the dump and sh-nop commands\n");
		exit(E_USAGE);
	}

	do_verify_ips = cmd->verify_ips;

	is_dump_xml = (cmd == &dump_xml_cmd);
	is_dump = (is_dump_xml || cmd == &dump_cmd);
	is_adjust = (cmd == &adjust_cmd || cmd == &adjust_wp_cmd);

	if (!resource_names[0]) {
		if (is_dump)
			all_resources = 1;
		else if (cmd->res_name_required)
			print_usage_and_exit(cmd, "No resource names specified", E_USAGE);
	} else if (resource_names[0]) {
		if (cmd->backend_res_name)
			/* Okay */  ;
		else if (!cmd->res_name_required)
			err("This command will ignore resource names!\n");
		else if (resource_names[1] && cmd->use_cached_config_file)
			err("You should not use this command with multiple resources!\n");
	}

	if (!config_file && cmd->use_cached_config_file)
		config_file = config_file_from_arg(resource_names[0]);

	if (!config_file)
		/* may exit if no config file can be used! */
		assign_default_config_file();

	/* for error-reporting reasons config_file may be re-assigned by adm_adjust,
	 * we need the current value for register_minor, though.
	 * save that. */
	if (config_from_stdin)
		config_save = config_file;
	else
		config_save = canonify_path(config_file);

	// DW-1569
	parse_file = config_file;

	my_parse();
	CLI_TRAC_LOG(false, "config_file(%s) => my_parse() called", config_file);

	if (config_test) {
		char *saved_config_file = config_file;
		char *saved_config_save = config_save;

		config_file = config_test;
		config_save = canonify_path(config_test);

		fclose(yyin);
		yyin = fopen(config_test, "r");
		CLI_TRAC_LOG(false, "config_test file open(%s)", yyin != NULL ? "true" : "false");
		if (!yyin) {
			err("Can not open '%s'.\n.", config_test);
			exit(E_EXEC_ERROR);
		}
		my_parse();

		config_file = saved_config_file;
		config_save = saved_config_save;
	}


	if (!config_valid) {
		CLI_ERRO_LOG(false, true, "invalid config");
		exit(E_CONFIG_INVALID);
	}

	// DW-889 parsing running_config before post_parse().
	// BSR-446 fix adjust-with-progress segfault
	// exclude adjust_cmd and adjust_wp_cmd. it will be run in _adm_adjust().
	// BSR-721 exclude the cmd with need_peer set. it will output "invalid host" error.
	if (!cmd->need_peer && !cmd->exclude_parse_show) {
		char *temp_file = config_file;
		int temp_config_valid = config_valid;

		if (!resource_names[0] || !strcmp(resource_names[0], "all")) {	
			parse_bsrsetup_show(NULL);
		}
		else {	
			parse_bsrsetup_show(resource_names[0]);
		}
		
		config_file = temp_file;
		config_valid = temp_config_valid;
	}

	post_parse(&config, cmd->is_proxy_cmd ? MATCH_ON_PROXY : 0);
	CLI_TRAC_LOG(false, "post_parse called : cmd->is_proxy_cmd(%s)", cmd->is_proxy_cmd ? "true" : "false");

	if (!is_dump || dry_run || verbose)
		expand_common();
	if (dry_run || config_from_stdin)
		do_register = 0;

	count_resources();

#if 0 // TODO : usage count 기능 정리 필요
	if (cmd->uc_dialog)
		uc_node(global_options.usage_count);
#endif

	ctx.cmd = cmd;
	if (cmd->res_name_required || resource_names[0]) {
		if (STAILQ_EMPTY(&config) && !is_dump) {
			err("no resources defined!\n");
			exit(E_USAGE);
		}

		global_validate_maybe_expand_die_if_invalid(!is_dump,
							    cmd->is_proxy_cmd ? MATCH_ON_PROXY : 0);

		if (!resource_names[0] || !strcmp(resource_names[0], "all")) {
			/* either no resource arguments at all,
			 * but command is dump / dump-xml, so implicit "all",
			 * or an explicit "all" argument is given */
			all_resources = 1;
			if (!is_dump)
				die_if_no_resources();
			/* verify ips first, for all of them */
			for_each_resource(res, &config) {
				verify_ips(res);
			}
			if (!config_valid)
				exit(E_CONFIG_INVALID);

			if (is_dump_xml)
				print_dump_xml_header();
			else if (is_dump)
				print_dump_header();
			if (is_adjust)
				adjust_more_than_one_resource = 1;

			for_each_resource(res, &config) {
				if (!is_dump && res->ignore)
					continue;

				if (!is_dump && is_bsr_top != res->stacked) {
					continue;
				}
				ctx.res = res;
				ctx.vol = NULL;
				CLI_TRAC_LOG(false, "call cmd resource(%s), command(%s)", ctx.res->name, cmd->name);
				r = call_cmd(cmd, &ctx, EXIT_ON_FAIL);	/* does exit for r >= 20! */
				/* this super positioning of return values is soo ugly
				 * anyone any better idea? */
				if (r > rv)
					rv = r;
			}
			if (is_dump_xml)
				printf("</config>\n");
		} else {
			/* explicit list of resources to work on */
			struct connection *conn;

			/* first we execute some sanity checks,
			 * the checks use ignore_tmp */
			for_each_resource(res, &config)
				for_each_connection(conn, &res->connections)
					conn->ignore_tmp = conn->ignore;

			/* check if we would enable a connection that should be ignored */
			for (i = 0; resource_names[i]; i++)
				if (ctx_by_name(&ctx, resource_names[i], WOULD_ENABLE_DISABLED) > 0) {
					err("USAGE_BUG: Tried to enable disabled connections %s\n",
					    resource_names[i]);
					exit(E_USAGE);
				}

			/* check if we would enable a connection that was already enabled.
			 * set all connections to ignore and then check if we would enable a
			 * connection twice */
			for_each_resource(res, &config)
				for_each_connection(conn, &res->connections)
					conn->ignore_tmp = true;

			for (i = 0; resource_names[i]; i++)
				if (ctx_by_name(&ctx, resource_names[i], WOULD_ENABLE_MULTI_TIMES) > 0) {
					err("USAGE_BUG: %s would enable an already enabled connection\n",
					    resource_names[i]);
					exit(E_USAGE);
				}

			if (is_adjust && resource_names[1])
				adjust_more_than_one_resource = 1;

			for (i = 0; resource_names[i]; i++) {
				ctx.res = NULL;
				ctx.vol = NULL;
				r = ctx_by_name(&ctx, resource_names[i], SETUP_MULTI);
				if (!ctx.res) {
					ctx_by_minor(&ctx, resource_names[i]);
					r = 0;
				}
				if (!ctx.res) {
					// DW-889
					ctx.res = res_by_name(resource_names[i]);
					if(ctx.res && ctx.res->ignore) {
						err("'%s' ignored, invalid host.\n", resource_names[i]);
					}
					else {
						err("'%s' not defined in your config (for this host).\n", resource_names[i]);
					}
					exit(E_USAGE);
				}
				if (r)
					exit(E_USAGE);
				if (!cmd->vol_id_required && !cmd->iterate_volumes && ctx.vol != NULL && !cmd->vol_id_optional) {
					if (ctx.vol->implicit)
						ctx.vol = NULL;
					else {
						err("%s operates on whole resources, but you specified a specific volume!\n",
						    cmd->name);
						exit(E_USAGE);
					}
				}
				if (cmd->vol_id_required && !ctx.vol && STAILQ_FIRST(&ctx.res->me->volumes)->implicit)
					ctx.vol = STAILQ_FIRST(&ctx.res->me->volumes);
				if (cmd->vol_id_required && !ctx.vol) {
					err("%s requires a specific volume id, but none is specified.\n"
					    "Try '%s minor-<minor_number>' or '%s %s/<vnr>'\n",
					    cmd->name, cmd->name, cmd->name, resource_names[i]);
					exit(E_USAGE);
				}
				if (ctx.res->ignore && !is_dump) {
					err("'%s' ignored, since this host (%s) is not mentioned with an 'on' keyword.\n",
					    ctx.res->name, hostname);
					if (rv < E_USAGE)
						rv = E_USAGE;
					continue;
				}
				if (is_bsr_top != ctx.res->stacked && !is_dump) {
					err("'%s' is a %s resource, and not available in %s mode.\n",
					    ctx.res->name,
					    ctx.res->stacked ? "stacked" : "normal",
					    is_bsr_top ? "stacked" : "normal");
					if (rv < E_USAGE)
						rv = E_USAGE;
					continue;
				}
				verify_ips(ctx.res);
				if (!is_dump && !config_valid)
					exit(E_CONFIG_INVALID);

				CLI_TRAC_LOG(false, "call cmd resource(%s), command(%s)", resource_names[i], cmd->name);
				r = call_cmd(cmd, &ctx, EXIT_ON_FAIL);	/* does exit for r >= 20! */
				if (r > rv)
					rv = r;
			}
		}
	} else {		// Commands which do not need a resource name
		/* no call_cmd, as that implies register_minor,
		 * which does not make sense for resource independent commands.
		 * It does also not need to iterate over volumes: it does not even know the resource. */
		 ctx.cmd = cmd;
		 CLI_TRAC_LOG(false, "call cmd command(%s)", cmd->name);
		rv = __call_cmd_fn(&ctx, KEEP_RUNNING);
		if (rv >= 10) {	/* why do we special case the "generic sh-*" commands? */
			err("command %s exited with code %d\n", cmd->name, rv);
			exit(rv);
		}
	}

	CLI_TRAC_LOG(false, "run deferred cmd(%s)", cmd->name);
	r = run_deferred_cmds();
	CLI_TRAC_LOG(false, "run deferred cmd result(%d)", r);
	if (r > rv)
		rv = r;

	free_config();
	free(resource_names);
	if (admopt != general_admopt)
		free(admopt);
	free_btrees();

	bsr_terminate_log(rv);

	return rv;
}

void yyerror(char *text)
{
	err("%s:%d: %s\n", config_file, line, text);
	exit(E_SYNTAX);
}
