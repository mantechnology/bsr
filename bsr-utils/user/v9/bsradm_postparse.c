/*
   bsradm_postparse.c actions to do after config parsing

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2012, Man Technology inc

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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "bsrtool_common.h"
#include "bsradm.h"
#include "config_flags.h"
#include <search.h>

static void inherit_volumes(struct volumes *from, struct d_host_info *host);
static void check_volume_sets_equal(struct d_resource *, struct d_host_info *, struct d_host_info *);
static void expand_opts(struct d_resource *, struct context_def *, struct options *, struct options *);

static void append_names(struct names *head, struct names *to_copy)
{
	struct d_name *new, *copy;

	STAILQ_FOREACH(copy, to_copy, link) {
		new = malloc(sizeof(struct d_name));
		new->name = strdup(copy->name);
		insert_tail(head, new);
	}
}

void set_on_hosts_in_res(struct d_resource *res)
{
	struct d_resource *l_res;
	struct d_host_info *host, *host2;
	struct d_name *h;

	for_each_host(host, &res->all_hosts) {
		if (host->lower_name) {
			for_each_resource(l_res, &config) {
				if (!strcmp(l_res->name, host->lower_name))
					break;
			}

			if (l_res == NULL) {
				err("%s:%d: in resource %s, "
				    "referenced resource '%s' not defined.\n",
				    res->config_file, res->start_line,
				    res->name, host->lower_name);
				config_valid = 0;
				continue;
			}

			/* Simple: host->on_hosts = concat_names(l_res->me->on_hosts, l_res->peer->on_hosts); */
			for_each_host(host2, &l_res->all_hosts)
				if (!host2->lower_name) {
					append_names(&host->on_hosts, &host2->on_hosts);

					for_each_host(h, &host2->on_hosts) {
						struct d_volume *vol;

						for_each_volume(vol, &host->volumes)
							check_uniq_file_line(vol->v_config_file, vol->v_device_line,
								"device-minor", "device-minor:%s:%u", h->name,
								vol->device_minor);

						for_each_volume(vol, &host->volumes)
							if (vol->device)
								check_uniq_file_line(vol->v_config_file, vol->v_device_line,
								"device", "device:%s:%s", h->name, vol->device);
					}
				}

			host->lower = l_res;

			/* */
			if (addr_scope_local(host->address.addr))
				STAILQ_FOREACH(h, &host->on_hosts, link)
					check_uniq("IP", "%s:%s:%s", h->name, host->address.addr, host->address.port);

		}
	}
}

struct d_host_info *find_host_info_by_name(struct d_resource* res, char *name)
{
	struct d_host_info *host;

	for_each_host(host, &res->all_hosts)
		if (hostname_in_list(name, &host->on_hosts))
			return host;

	return NULL;
}

static struct d_host_info *find_host_info_by_address(struct d_resource* res, struct d_address *address)
{
	struct d_host_info *host;

	for_each_host(host, &res->all_hosts) {
		if (!host->address.addr)
			continue;

		if (!strcmp(host->address.addr, address->addr) &&
			!strcmp(host->address.af, address->af) &&
			!strcmp(host->address.port, address->port))
			return host;
	}

	return NULL;
}

static bool generate_implicit_node_id(int *addr_hash, struct d_host_info **host_info_array)
{
	if (addr_hash[0] > addr_hash[1]) {
		host_info_array[0]->node_id = strdup("0");
		host_info_array[1]->node_id = strdup("1");
	} else if (addr_hash[0] < addr_hash[1]) {
		host_info_array[0]->node_id = strdup("1");
		host_info_array[1]->node_id = strdup("0");
	} else {
		return false;
	}
	return true;
}

static void _set_host_info_in_host_address_pairs(struct d_resource *res,
						 struct connection *conn,
						 struct path *path)
{
	struct hname_address *ha;
	struct d_host_info *host_info;
	int addr_hash[2], i = 0;
	struct d_host_info *host_info_array[2];

	STAILQ_FOREACH(ha, &path->hname_address_pairs, link) {
		if (ha->host_info) { /* Implicit connection have that already set. */
			host_info = ha->host_info;
			if (i == 2) {
				err("LOGIC BUG in set_host_info_in_host_address_pairs()\n");
				exit(20);
			}
			if (!host_info->address.addr) {
				err("\"connection-mesh\" (for \"%s\") with a host (\"%s\") "
						"that has no \"address\" defined\n",
						res->name, ha->name);
				config_valid = 0;
				return;
			}
			addr_hash[i] = crc32c(0x1a656f21,
					(void *)host_info->address.addr,
					strlen(host_info->address.addr));
			host_info_array[i++] = host_info;
		} else if (ha->by_address) {
			host_info = find_host_info_by_address(res, &ha->address);
			/* The name will be used for nice comments only ... */
			// BSR-479
			if (!host_info) {
				err("%s:%d: in resource %s a hostname is given\n"
					"with a \"address\" keyword, and no matching host section\n",
					res->config_file, ha->config_line, res->name, ha->name);
				exit(E_CONFIG_INVALID);
			} else {
				ha->name = strdup(names_to_str_c(&host_info->on_hosts, '_'));
			}
		} else {
			host_info = find_host_info_by_name(res, ha->name);
		}
		if (!host_info && !strcmp(ha->name, "_remote_host")) {
			if (conn->peer)
				host_info = conn->peer; /* With new format we create one for _peer_node_id */
			else
				continue; /* Old bsrsetup does not houtput a host section */
		}
		
		if (!host_info) {
			err("%s:%d: in resource %s a hostname (\"%s\") is given\n"
			    "with a \"host\" keyword, has no \"address\" keyword, and no matching\n"
			    "host section (\"on\" keyword)\n",
			    res->config_file, ha->config_line, res->name, ha->name);
			config_valid = 0;
			/* Can't continue. */
			exit(E_CONFIG_INVALID);
		}
		ha->host_info = host_info;
		if (!(ha->address.addr && ha->address.af && ha->address.port)) {
			bool have_address = true;
			bool have_port = true;

			if (!(ha->address.addr && ha->address.af)) {
				if (host_info->address.addr && host_info->address.af) {
					ha->address.addr = host_info->address.addr;
					ha->address.af = host_info->address.af;
					ha->address.is_local_address = host_info->address.is_local_address;
				} else
					have_address = false;
			}
			if (!ha->address.port) {
				if (host_info->address.port)
					ha->address.port = host_info->address.port;
				else
					have_port = false;
			}
			if (!(have_address && have_port)) {
				err("%s:%d: Resource %s, host %s: "
				    "cannot determine which %s%s%s to use\n",
				    config_file, ha->config_line, res->name,
				    ha->name, have_address ? "" : "address",
				    have_address != have_port ? "" : " and ",
				    have_port ? "" : "port");
				config_valid = 0;
			}
		}

		fline = ha->config_line;
	}

	if (conn->implicit && i == 2 && !host_info_array[0]->node_id && !host_info_array[1]->node_id) {
		/* This is bsr-8.3 / bsr-8.4 compatibility, auto created node-id */
		bool have_node_ids;

		have_node_ids = generate_implicit_node_id(addr_hash, host_info_array);

		if (!have_node_ids) {
			/* That might be a config with equal node addresses, since it is
			  127.0.0.1:xxx with a proxy... */
			i = 0;
			path = STAILQ_FIRST(&conn->paths); /* there may only be one */
			STAILQ_FOREACH(ha, &path->hname_address_pairs, link) {
				if (!ha->host_info)
					continue;

				if (!ha->proxy)
					break;

				addr_hash[i++] = crc32c(0x1a656f21,
							(void *)ha->proxy->outside.addr,
							strlen(ha->proxy->outside.addr));
			}
			have_node_ids = generate_implicit_node_id(addr_hash, host_info_array);
		}
		if (!have_node_ids) {
			err("BAD LUCK, equal hashes\n");
			exit(20);
		}
	}
}

static void set_host_info_in_host_address_pairs(struct d_resource *res, struct connection *conn)
{
	struct path *path;

	for_each_path(path, &conn->paths)
		_set_host_info_in_host_address_pairs(res, conn, path);
}

static bool test_proxy_on_host(struct d_resource* res, struct d_host_info *host)
{
	struct connection *conn;
	struct path *path;
	for_each_connection(conn, &res->connections) {
		struct hname_address *ha;

		for_each_path(path, &conn->paths) {
			STAILQ_FOREACH(ha, &path->hname_address_pairs, link) {
				if (!ha->proxy)
					continue;
				if (ha->host_info == host) {
					return hostname_in_list(hostname, &ha->proxy->on_hosts);
				}
			}
		}
	}
	return false;
}

// BSR-859
void create_node_name_options(struct d_host_info *host)
{
	char *value;

	if (find_opt(&host->node_options, "node-name"))
		return;

	value = names_to_str(&host->on_hosts);
	
	if (!strcmp("_this_host", value)) {
		value = host->node_name;
	}

	insert_head(&host->node_options, new_opt(strdup("node-name"), strdup(value)));
}


void set_me_in_resource(struct d_resource* res, int match_on_proxy)
{
	struct d_host_info *host;
	struct connection *conn;

	CLI_TRAC_LOG(false, "resource_name(%s), match_on_proxy(%s), hostname(%s)", res->name, match_on_proxy ? "true" : "false", hostname);
	/* Determine the local host section */
	for_each_host(host, &res->all_hosts) {
		/* do we match  this host? */
		if (match_on_proxy) {
			if (!test_proxy_on_host(res, host))
			       continue;
		}
		else if (host->by_address) {
			if (!have_ip(host->address.af, host->address.addr) &&
				/* for debugging only, e.g. __BSR_NODE__=10.0.0.1 */
			    strcmp(hostname, host->address.addr))
				continue;
		} else if (host->lower) {
			if (!host->lower->me)
				continue;
		} else if (STAILQ_EMPTY(&host->on_hosts)) {
			/* huh? a resource without hosts to run on?! */
			continue;
		} else {
			if (!hostname_in_list(hostname, &host->on_hosts) &&
			    strcmp("_this_host", STAILQ_FIRST(&host->on_hosts)->name))
				continue;
		}
		/* we matched. */
		if (res->ignore) {
			config_valid = 0;
			err("%s:%d: in resource %s, %s %s { ... }:\n"
			    "\tYou cannot ignore and define at the same time.\n",
			    res->config_file, host->config_line, res->name,
			    host->lower ? "stacked-on-top-of" : "on",
			    host->lower ? host->lower->name : names_to_str(&host->on_hosts));
		}
		if (res->me && res->me != host) {
			config_valid = 0;
			err("%s:%d: in resource %s, %s %s { ... } ... %s %s { ... }:\n"
			    "\tThere are multiple host sections for this node.\n",
			    res->config_file, host->config_line, res->name,
			    res->me->lower ? "stacked-on-top-of" : "on",
			    res->me->lower ? res->me->lower->name : names_to_str(&res->me->on_hosts),
			    host->lower ? "stacked-on-top-of" : "on",
			    host->lower ? host->lower->name : names_to_str(&host->on_hosts));
		}
		res->me = host;

		create_node_name_options(res->me);
		
		CLI_TRAC_LOG(false, "res->me(%s)", host->lower ? host->lower->name : names_to_str(&host->on_hosts));
		host->used_as_me = 1;
		if (host->lower) {
			res->stacked = 1;
		}
	}

	// DW-889 The host is invalid, find it in running_config.
	if (!res->me) {
		struct d_resource* running;
		running = running_res_by_name(res->name, false);
		if(running && running->me) {
			res->me = running->me;
			res->me->used_as_me = 1;
			if (res->me->lower) {
				res->stacked = 1;
			}
		}
	}

	/* If there is no me, implicitly ignore that resource */
	if (!res->me) {
		res->ignore = 1;
		return;
	}

	/* set con->my_address in every path in every connection */
	for_each_connection(conn, &res->connections) {
		struct path *path;
		struct hname_address *h = NULL;

		for_each_path(path, &conn->paths) {
			STAILQ_FOREACH(h, &path->hname_address_pairs, link) {
				if (h->host_info == res->me)
					break;
			}

			if (h) {
				h->used_as_me = 1;
				if (!path->my_address)
					path->my_address = h->address.addr ? &h->address : &res->me->address;
				path->my_proxy = h->proxy;
			} else {
				if (!conn->peer) /* Keep w/o addresses form "bsrsetup show" for adjust */
					conn->ignore = 1;
			}
		}
	}
}


static void set_peer_in_connection(struct d_resource* res, struct connection *conn, int peer_required)
{
	struct hname_address *host = NULL, *candidate = NULL;
	struct d_host_info *host_info;
	struct path *path;

	if (res->ignore || conn->ignore)
		return;

	/* me must be already set */
	if (!res->me) {
		/* should have been implicitly ignored. */
		err("%s:%d: in resource %s:\n"
		    "\tcannot determine the peer, don't even know myself!\n",
		    res->config_file, res->start_line, res->name);
		exit(E_THINKO);
	}

	for_each_path(path, &conn->paths) {
		int nr_hosts = 0, candidates = 0;

		STAILQ_FOREACH(host, &path->hname_address_pairs, link) {
			nr_hosts++;
			if (!host->used_as_me) {
				candidates++;
				candidate = host;
			}
		}

		if (nr_hosts < 2) {
			if (peer_required) {
				err("%s:%d: in connection in resource %s:\n"
				    "\tMissing statement 'host <PEER> '.\n",
				    res->config_file, conn->config_line, res->name);
				config_valid = 0;
			}
			return;
		}

		if (candidates == 1 && nr_hosts == 2) {
			if (conn->peer) {
				host_info = conn->peer;
			} else {
				host_info = find_host_info_by_name(res, candidate->name);
				conn->peer = host_info;
			}
			path->peer_address = candidate->address.addr ? &candidate->address : &host_info->address;
			path->peer_proxy = candidate->proxy;
			path->connect_to = path->my_proxy ? &path->my_proxy->inside : path->peer_address;
			continue;
		}

		err("%s:%d: in connection in resource %s:\n"
		    "\tBug in set_peer_in_connection()\n",
		    res->config_file, conn->config_line, res->name);
		config_valid = 0;
		return;
	}
}

void create_implicit_net_options(struct connection *conn)
{
	char *value;

	if (find_opt(&conn->net_options, "_name"))
		return;

	if (conn->name)
		value = conn->name;
	else if (conn->peer)
		value = names_to_str_c(&conn->peer->on_hosts, '_');
	else
		return;

	insert_head(&conn->net_options, new_opt(strdup("_name"), strdup(value)));
}

void create_peer_node_name_options(struct connection *conn)
{
	char *value;

	if (find_opt(&conn->net_options, "peer-node-name")) {
		return;
	}

	if (conn->peer) {
		if (conn->peer->node_name)
			value = conn->peer->node_name;
		else 
			value = names_to_str(&conn->peer->on_hosts);
	}
	else {
		return;
	}

	insert_head(&conn->net_options, new_opt(strdup("peer-node-name"), strdup(value)));
}

bool peer_diskless(struct peer_device *peer_device)
{
	struct d_volume *vol;

	vol = volume_by_vnr(&peer_device->connection->peer->volumes, peer_device->vnr);
	return vol->disk == NULL;
}


static void add_no_bitmap_opt(struct d_resource *res)
{
	struct connection *conn;

	if (res->no_bitmap_done)
		return;

	for_each_connection(conn, &res->connections) {
		struct peer_device *peer_device;

		if (conn->ignore)
			continue;

		STAILQ_FOREACH(peer_device, &conn->peer_devices, connection_link) {
			if (peer_device->connection->peer && peer_diskless(peer_device))
				insert_tail(&peer_device->pd_options, new_opt("bitmap", "no"));
		}
	}
	res->no_bitmap_done = 1;
}

void set_peer_in_resource(struct d_resource* res, int peer_required)
{
	struct connection *conn;
	int peers_addrs_set = 1;

	for_each_connection(conn, &res->connections) {
		struct path *path;
		set_peer_in_connection(res, conn, peer_required);

		for_each_path(path, &conn->paths) {
			if (!path->peer_address)
				peers_addrs_set = 0;
		}
		// BSR-859
		create_peer_node_name_options(conn);
		create_implicit_net_options(conn);
	}
	res->peers_addrs_set = peers_addrs_set;

	if (!(peer_required & BSRSETUP_SHOW))
		add_no_bitmap_opt(res);
}

void set_disk_in_res(struct d_resource *res)
{
	struct d_host_info *host;
	struct d_volume *a, *b;

	if (res->ignore)
		return;

	for_each_host(host, &res->all_hosts) {
		if (!host->lower)
			continue;

		if (host->lower->ignore)
			continue;

		check_volume_sets_equal(res, host, host->lower->me);
		if (!config_valid)
			/* don't even bother for broken config. */
			continue;

		/* volume lists are sorted on vnr */
		a = STAILQ_FIRST(&host->volumes);
		b = STAILQ_FIRST(&host->lower->me->volumes);
		while (a) {
			while (b && a->vnr > b->vnr) {
				/* Lower resource has more volumes.
				 * Probably unusual, but we decided
				 * that it should be legal.
				 * Skip those that do not match */
				b = STAILQ_NEXT(b, link);
			}
			if (a && b && a->vnr == b->vnr) {
				if (b->device)
					m_asprintf(&a->disk, "%s", b->device);
				else
					// BSR-386 rename to be the same as name of major device due to pvcreate error
					m_asprintf(&a->disk, "/dev/bsr%u", b->device_minor);
				/* stacked implicit volumes need internal meta data, too */
				if (!a->meta_disk)
					m_asprintf(&a->meta_disk, "internal");
				if (!a->meta_index)
					m_asprintf(&a->meta_index, "internal");
				a = STAILQ_NEXT(a, link);
				b = STAILQ_NEXT(b, link);
			} else {
				/* config_invalid should have been set
				 * by check_volume_sets_equal */
				assert(0);
			}
		}
	}
}

static struct d_volume *find_volume(struct volumes *volumes, int vnr)
{
	struct d_volume *vol;

	for_each_volume(vol, volumes)
		if (vol->vnr == vnr)
			return vol;

	return NULL;
}

static void derror(struct d_host_info *host, struct d_resource *res, char *text)
{
	config_valid = 0;
	err("%s:%d: in resource %s, on %s { ... }: '%s' keyword missing.\n",
	    res->config_file, host->config_line, res->name,
	    names_to_str(&host->on_hosts), text);
}

static void inherit_volumes(struct volumes *from, struct d_host_info *host)
{
	struct d_volume *s, *t;
	struct d_name *h;

	for_each_volume(s, from) {
		t = find_volume(&host->volumes, s->vnr);
		if (!t) {
			t = alloc_volume();
			t->device_minor = -1;
			t->vnr = s->vnr;
			t->implicit = s->implicit;
			t->v_config_file = s->v_config_file;
			t->v_device_line = s->v_device_line;
			t->v_disk_line = s->v_disk_line;
			t->v_meta_disk_line = s->v_meta_disk_line;
			t->platform = s->platform;
			insert_volume(&host->volumes, t);
		}
		if (!t->disk && s->disk) {
			t->disk = strdup(s->disk);
			STAILQ_FOREACH(h, &host->on_hosts, link)
				check_uniq_file_line(t->v_config_file, t->v_disk_line,
					"disk", "disk:%s:%s", h->name, t->disk);
		}
		if (!t->device && s->device)
			t->device = strdup(s->device);
		if (t->device_minor == -1U && s->device_minor != -1U) {
			t->device_minor = s->device_minor;
			STAILQ_FOREACH(h, &host->on_hosts, link) {
				check_uniq_file_line(t->v_config_file, t->v_device_line,
					"device-minor", "device-minor:%s:%u", h->name, t->device_minor);
				if (t->device)
					check_uniq_file_line(t->v_config_file, t->v_device_line,
						"device", "device:%s:%s", h->name, t->device);
			}
		}
		if (!t->meta_disk && s->meta_disk) {
			t->meta_disk = strdup(s->meta_disk);
			if (s->meta_index)
				t->meta_index = strdup(s->meta_index);
		}
	}
}

static void check_volume_complete(struct d_resource *res, struct d_host_info *host, struct d_volume *vol)
{
	if (!vol->device && vol->device_minor == -1U)
		derror(host, res, "device");
	if (vol->disk || vol->meta_disk || vol->meta_index) {
		if (!(vol->disk && !strcmp(vol->disk, "none"))) {
			if (!vol->disk)
				derror(host, res, "disk");
			if (!vol->meta_disk)
				derror(host, res, "meta-disk");
			if (!vol->meta_index)
				derror(host, res, "meta-index");
		}
	}
}

static void check_volumes_complete(struct d_resource *res, struct d_host_info *host)
{
	struct d_volume *vol;
	unsigned vnr = -1U;

	for_each_volume(vol, &host->volumes) {
		if (vnr == -1U || vnr < vol->vnr)
			vnr = vol->vnr;
		else
			err("internal error: in %s: unsorted volumes list\n",
			    res->name);
		check_volume_complete(res, host, vol);
	}
}

static void check_meta_disk(struct d_volume *vol, struct d_host_info *host)
{
	struct d_name *h;
	/* when parsing "bsrsetup show[-all]" output,
	 * a detached volume will only have device/minor,
	 * but no disk or meta disk. */
	if (vol->meta_disk == NULL)
		return;
	if (strcmp(vol->meta_disk, "internal") != 0) {
		/* index either some number, or "flexible" */
		STAILQ_FOREACH(h, &host->on_hosts, link)
			check_uniq_file_line(vol->v_config_file, vol->v_meta_disk_line,
				"meta-disk", "%s:%s[%s]", h->name, vol->meta_disk, vol->meta_index);
	}
}

static void check_volume_sets_equal(struct d_resource *res, struct d_host_info *host1, struct d_host_info *host2)
{
	struct d_volume *a, *b;

	/* change the error output, if we have been called to
	 * compare stacked with lower resource volumes */
	int compare_stacked = host1->lower && host1->lower->me == host2;

	if (host1 == host2)
		return;

	a = STAILQ_FIRST(&host1->volumes);
	b = STAILQ_FIRST(&host2->volumes);

	/* volume lists are supposed to be sorted on vnr */
	while (a || b) {
		while (a && (!b || a->vnr < b->vnr)) {
			err("%s:%d: in resource %s, on %s { ... }: volume %d not defined on %s\n",
			    config_file, line, res->name,
			    names_to_str(&host1->on_hosts), a->vnr,
			    compare_stacked ? host1->lower->name : names_to_str(&host2->on_hosts));
			a = STAILQ_NEXT(a, link);
			config_valid = 0;
		}
		while (b && (!a || a->vnr > b->vnr)) {
			/* Though unusual, it is "legal" for a lower resource
			 * to have more volumes than the resource stacked on
			 * top of it.  Warn (if we have a terminal),
			 * but consider it as valid. */
			if (!(compare_stacked && no_tty))
				err("%s:%d: in resource %s, on %s { ... }: "
				    "volume %d missing (present on %s)\n",
				    config_file, line, res->name,
				    names_to_str(&host1->on_hosts), b->vnr,
				    compare_stacked ? host1->lower->name : names_to_str(&host2->on_hosts));
			if (!compare_stacked)
				config_valid = 0;
			b = STAILQ_NEXT(b, link);
		}
		if (a && b && a->vnr == b->vnr) {
			if (a->implicit != b->implicit) {
				err("%s:%d: in resource %s, on %s resp. %s: volume %d must not be implicit on one but not the other\n",
					config_file, line, res->name,
					names_to_str(&host1->on_hosts),
					compare_stacked ? host1->lower->name : names_to_str(&host2->on_hosts),
					a->vnr);
				config_valid = 0;
			}

			a = STAILQ_NEXT(a, link);
			b = STAILQ_NEXT(b, link);
		}
	}
}

/* Ensure that in all host sections the same volumes are defined */
static void check_volumes_hosts(struct d_resource *res)
{
	struct d_host_info *host1, *host2;

	host1 = STAILQ_FIRST(&res->all_hosts);

	if (!host1)
		return;

	for_each_host(host2, &res->all_hosts)
		check_volume_sets_equal(res, host1, host2);
}

static struct hname_address *alloc_hname_address()
{
	struct hname_address *ha;

	ha = calloc(1, sizeof(struct hname_address));
	if (ha == NULL) {
		err("calloc", ": %m\n");
		exit(E_EXEC_ERROR);
	}
	return ha;
}

static void create_implicit_connections(struct d_resource *res)
{
	struct connection *conn;
	struct path *path;
	struct hname_address *ha;
	struct d_host_info *host_info;
	int hosts = 0;

	if (!STAILQ_EMPTY(&res->connections))
		return;

	conn = alloc_connection();
	conn->implicit = 1;
	path = alloc_path();
	path->implicit = 1;
	insert_tail(&conn->paths, path);

	for_each_host(host_info, &res->all_hosts) {
		if (++hosts == 3) {
			err("Resource %s:\n\t"
			    "Use explicit 'connection' sections with more than two 'on' sections.\n",
		            res->name);
			break;
		}
		if (host_info->address.af && host_info->address.addr && host_info->address.port) {
			ha = alloc_hname_address();
			ha->host_info = host_info;
			ha->proxy = host_info->proxy_compat_only;
			if (!host_info->lower) {
				ha->name = STAILQ_FIRST(&host_info->on_hosts)->name;
			} else {
				ha->name = strdup(names_to_str_c(&host_info->on_hosts, '_'));
				ha->address = host_info->address;
				ha->faked_hostname = 1;
				ha->parsed_address = 1; /* not true, but makes dump nicer */
			}			
			CLI_TRAC_LOG(false, "INSERT_TAIL, %s, hosts %s", res->name, ha->name);
			STAILQ_INSERT_TAIL(&path->hname_address_pairs, ha, link);
		}
	}

	if (hosts == 2) {
		CLI_TRAC_LOG(false, "INSERT_TAIL, %s, hosts(2)", res->name);
		STAILQ_INSERT_TAIL(&res->connections, conn, link);
	}
	else
		free_connection(conn);
}

static struct d_host_info *find_host_info_or_invalid(struct d_resource *res, char *name)
{
	struct d_host_info *host_info = find_host_info_by_name(res, name);

	if (!host_info) {
		err("%s:%d: in resource %s:\n\t"
		    "There is no 'on' section for hostname '%s' named in the connection-mesh\n",
		    res->config_file, res->start_line, res->name, name);
		config_valid = 0;
	}

	return host_info;
}

static void create_connections_from_mesh(struct d_resource *res, struct mesh *mesh)
{
	struct d_name *hname1, *hname2;
	struct d_host_info *hi1, *hi2;

	for_each_host(hname1, &mesh->hosts) {
		hi1 = find_host_info_or_invalid(res, hname1->name);
		if (!hi1)
			return;
		hname2 = STAILQ_NEXT(hname1, link);
		while (hname2) {
			struct hname_address *ha;
			struct connection *conn;
			struct path *path;

			hi2 = find_host_info_or_invalid(res, hname2->name);
			if (!hi2)
				return;

			if (hi1 == hi2)
				goto skip;

			conn = alloc_connection();
			conn->implicit = 1;
			path = alloc_path();
			path->implicit = 1;
			insert_tail(&conn->paths, path);

			expand_opts(res, &show_net_options_ctx, &mesh->net_options, &conn->net_options);

			ha = alloc_hname_address();
			ha->host_info = hi1;
			ha->name = STAILQ_FIRST(&hi1->on_hosts)->name;
			CLI_TRAC_LOG(false, "INSERT_TAIL, hosts1, %s", ha->name);
			STAILQ_INSERT_TAIL(&path->hname_address_pairs, ha, link);

			ha = alloc_hname_address();
			ha->host_info = hi2;
			ha->name = STAILQ_FIRST(&hi2->on_hosts)->name;
			CLI_TRAC_LOG(false, "INSERT_TAIL, hosts2, %s", ha->name);
			STAILQ_INSERT_TAIL(&path->hname_address_pairs, ha, link);

			CLI_TRAC_LOG(false, "INSERT_TAIL, connections, %s", res->name);
			STAILQ_INSERT_TAIL(&res->connections, conn, link);
		skip:
			hname2 = STAILQ_NEXT(hname2, link);
		}
	}
}

int addresses_cmp(struct d_address *addr1, struct d_address *addr2)
{
	int ret;

	if ((ret = strcmp(addr1->addr, addr2->addr)))
		return ret;

	if ((ret = strcmp(addr1->port, addr2->port)))
		return ret;

	return strcmp(addr1->af, addr2->af);
}

bool addresses_equal(struct d_address *addr1, struct d_address *addr2)
{
	return !addresses_cmp(addr1, addr2);
}

struct addrtree_entry {
	struct d_address *da;
	struct d_resource *res;
};

static void *addrtree = NULL;

static int addrtree_key_cmp(const void *a, const void *b)
{
	struct addrtree_entry *e1 = (struct addrtree_entry *)a;
	struct addrtree_entry *e2 = (struct addrtree_entry *)b;

	return addresses_cmp(e1->da, e2->da);
}

static struct hname_address *find_hname_addr_in_res(struct d_resource *res, struct hname_address* ha1, int address_type, bool is_same_res)
{
	struct hname_address *ha;
	struct connection *conn;
	struct path *path;
	struct d_address *addr = NULL;

	if(address_type == 0)
		addr = ha1->address.addr ? &ha1->address : &ha1->host_info->address;
	else if(address_type == 1)
		addr = &ha1->host_info->proxy_compat_only->inside;
	else if(address_type == 2)
		addr = &ha1->host_info->proxy_compat_only->outside;

	for_each_connection(conn, &res->connections) {
		for_each_path(path, &conn->paths) {
			STAILQ_FOREACH(ha, &path->hname_address_pairs, link) {
				struct d_address *addr2;

				addr2 = ha->address.addr ? &ha->address : &ha->host_info->address;
				if (addresses_equal(addr, addr2))
					return ha;

				if(ha1->host_info->proxy_compat_only) {
					if(is_same_res && !strcmp(ha1->name, ha->name)) {
						// BSR-167 compare the inside proxy with the outside proxy
						// address_type(1) : inside proxy
						if(address_type == 1) {
							addr2 = &ha->host_info->proxy_compat_only->outside;
							if (addresses_equal(addr, addr2))
								return ha;
						}
						// address_type(2) : outside proxy
						else if(address_type == 2) {
							addr2 = &ha->host_info->proxy_compat_only->inside;
							if (addresses_equal(addr, addr2))
								return ha;
						}
					}
					else {
						addr2 = &ha->host_info->proxy_compat_only->inside;
						if (addresses_equal(addr, addr2))
							return ha;

						addr2 = &ha->host_info->proxy_compat_only->outside;
						if (addresses_equal(addr, addr2))
							return ha;
					}
				}
			}
		}
	}

	return NULL;
}

/* An AF/IP/addr triple might be used by multiple connections within one resource,
   but may not be mentioned in any other resource. Also make sure that the two
   endpoints are not configured as the same.
 */
static void check_addr_conflict(void *addrtree_root, struct resources *resources)
{
	struct d_resource *res;
	struct hname_address *ha1, *ha2;
	struct connection *conn;
	struct path *path;
	struct addrtree_entry *e, *ep, *f;

	for_each_resource(res, resources) {
		for_each_connection(conn, &res->connections) {
			for_each_path(path, &conn->paths) {
				struct d_address *addr[2];
				struct d_address *in_proxy[2];
				struct d_address *out_proxy[2];
				int i = 0;

				STAILQ_FOREACH(ha1, &path->hname_address_pairs, link) {
					int j = 0;

					addr[i] = ha1->address.addr ? &ha1->address : &ha1->host_info->address;
					if (addr[i]->is_local_address)
						continue;

					// BSR-167 includes proxy in duplicates of network information checks.
					if(ha1->host_info->proxy_compat_only) {
						in_proxy[i] = &ha1->host_info->proxy_compat_only->inside;
						out_proxy[i] = &ha1->host_info->proxy_compat_only->outside;
						if (in_proxy[i]->is_local_address || out_proxy[i]->is_local_address)
							continue;
					}

					while(true) {
						e = malloc(sizeof *e);
						if (!e) {
							err("malloc: %m\n");
							exit(E_EXEC_ERROR);
						}
					
						if(j == 0)
							e->da = addr[i];
						if(j == 1)
							e->da = in_proxy[i];
						if(j == 2)
							e->da = out_proxy[i];
						e->res = res;

						f = tfind(e, &addrtree_root, addrtree_key_cmp);
						if (f) {
							ep = *(struct addrtree_entry **)f;

							if (ha1->conflicts)
								break;

							ha2 = find_hname_addr_in_res(ep->res, ha1, j, (ep->res == res));
							if (!ha2)
								break;

							if (ha2->conflicts)
								break;

							if (ep->res != res) {
								CLI_ERRO_LOG_STDERR(false, "%s:%d: in resource %s"
									"    %s:%s:%s is also used %s:%d (resource %s)\n",
									e->res->config_file, ha1->config_line, e->res->name,
									e->da->af, e->da->addr, e->da->port,
									ep->res->config_file, ha2->config_line, ep->res->name);
									
								ha2->conflicts = 1;
								ha1->conflicts = 1;
								config_valid = 0;
							}
							// BSR-167 check duplication of node and proxy network information in same resource
							else if(j != 0) {
								CLI_ERRO_LOG_STDERR(false, "%s:%d: in resource %s"
									"    %s:%s:%s is also used in proxy section %s:%d (resource %s)\n",
									e->res->config_file, ha1->config_line, e->res->name,
									e->da->af, e->da->addr, e->da->port,
									ep->res->config_file, ha2->config_line, ep->res->name);

								ha2->conflicts = 1;
								ha1->conflicts = 1;
								config_valid = 0;
							}
						}
						else
							tsearch(e, &addrtree_root, addrtree_key_cmp);
						j++;
						if(!ha1->host_info->proxy_compat_only)
							break;
						else if(j == 3)
							break;
					}
					i++;
				}
				if (i == 2 && addresses_equal(addr[0], addr[1]) &&
					!addr[0]->is_local_address) {
					err("%s:%d: in resource %s %s:%s:%s is used for both endpoints\n",
					    res->config_file, conn->config_line,
					    res->name, addr[0]->af, addr[0]->addr,
					    addr[0]->port);
					config_valid = 0;
				}
			}
		}
	}

	/* free element from tree, but not its members, they are pointers to list entries */
	tdestroy(addrtree_root, free);
	addrtree_root = NULL;

}

static void _must_have_two_hosts(struct d_resource *res, struct path *path)
{
	struct hname_address *ha;
	int i = 0;

	STAILQ_FOREACH(ha, &path->hname_address_pairs, link)
		i++;
	if (i != 2) {
		err("%s:%d: Resource %s: %s needs to have two endpoints\n",
		    res->config_file, path->config_line, res->name,
		    path->implicit ? "connection" : "path");
		config_valid = 0;
	}
}

static void must_have_two_hosts(struct d_resource *res, struct connection *conn)
{
	struct path *path;

	for_each_path(path, &conn->paths)
		_must_have_two_hosts(res, path);
}

struct peer_device *find_peer_device(struct connection *conn, int vnr)
{
	struct peer_device *peer_device;

	STAILQ_FOREACH(peer_device, &conn->peer_devices, connection_link) {
		if (peer_device->vnr == vnr)
			return peer_device;
	}

	return NULL;
}

static void fixup_peer_devices(struct d_resource *res)
{
	struct connection *conn;

	for_each_connection(conn, &res->connections) {
		struct peer_device *peer_device;
		struct hname_address *ha;
		struct d_volume *vol;
		struct path *some_path;
		struct d_host_info *some_host;

		some_path = STAILQ_FIRST(&conn->paths);
		if (!some_path)
			continue;

		STAILQ_FOREACH(peer_device, &conn->peer_devices, connection_link) {
			STAILQ_FOREACH(ha, &some_path->hname_address_pairs, link) {
				struct d_host_info *host = ha->host_info;
				if (!strcmp("_remote_host", ha->name)) /* && PARSE_FOR_ADJUST */
					continue; /* no on section for _remote_host in show output! */
				vol = volume_by_vnr(&host->volumes, peer_device->vnr);
				if (!vol) {
					err("%s:%d: Resource %s: There is a reference to a volume %d that "
						"is not known in this resource on host %s\n",
						res->config_file, peer_device->config_line, res->name,
						peer_device->vnr, ha->name);
					config_valid = 0;
				}
			}
		}		

		some_host = STAILQ_FIRST(&some_path->hname_address_pairs)->host_info;
		for_each_volume(vol, &some_host->volumes) {
			peer_device = find_peer_device(conn, vol->vnr);
			if (peer_device)
				continue;
			peer_device = alloc_peer_device();
			peer_device->vnr = vol->vnr;
			peer_device->implicit = 1;
			peer_device->connection = conn;
			CLI_TRAC_LOG(false, "INSERT_TAIL, peer_devices, volume vnr : %d", vol->vnr);
			STAILQ_INSERT_TAIL(&conn->peer_devices, peer_device, connection_link);
		}
	}
}

void post_parse(struct resources *resources, enum pp_flags flags)
{
	struct d_resource *res;
	struct connection *con;

	/* inherit volumes from resource level into the d_host_info objects */
	for_each_resource(res, resources) {
		struct d_host_info *host;
		bool any_implicit = false;
		bool any_non_zero_vnr = false;
		for_each_host(host, &res->all_hosts) {
			struct d_volume *vol;
			inherit_volumes(&res->volumes, host);

			for_each_volume(vol, &host->volumes) {
				any_implicit |= vol->implicit;
				any_non_zero_vnr |= vol->vnr != 0;

				check_meta_disk(vol, host);
			}

			if (host->require_minor)
				check_volumes_complete(res, host);
		}

		check_volumes_hosts(res);

		if (any_implicit && any_non_zero_vnr) {
			err("%s:%d: in resource %s: you must not mix implicit any explicit volumes\n",
				config_file, line, res->name);
			config_valid = 0;
		}
	}

	for_each_resource(res, resources)
		if (res->stacked_on_one)
			set_on_hosts_in_res(res); /* sets on_hosts and host->lower */

	for_each_resource(res, resources) {
		struct d_host_info *host;
		struct mesh *mesh;

		if (!(flags & BSRSETUP_SHOW)) {
			for_each_connection(con, &res->connections)
				must_have_two_hosts(res, con);
		}

		/* Other steps make no sense. */
		if (!config_valid)
			continue;

		STAILQ_FOREACH(mesh, &res->meshes, link)
			create_connections_from_mesh(res, mesh);
		create_implicit_connections(res);
		for_each_connection(con, &res->connections)
			set_host_info_in_host_address_pairs(res, con);
		for_each_host(host, &res->all_hosts) {
			if (!host->node_id)
				derror(host, res, "node-id");
		}
	}

	if (config_valid) {
		check_addr_conflict(addrtree, resources);
	}

	/* Needs "on_hosts" and host->lower already set */
	for_each_resource(res, resources)
		if (!res->stacked_on_one)
			set_me_in_resource(res, flags & MATCH_ON_PROXY);

	/* Needs host->lower->me already set */
	for_each_resource(res, resources)
		if (res->stacked_on_one)
			set_me_in_resource(res, flags & MATCH_ON_PROXY);

	// Needs "me" set already
	for_each_resource(res, resources)
		if (res->stacked_on_one)
			set_disk_in_res(res);

	for_each_resource(res, resources)
		fixup_peer_devices(res);
}

static void expand_opts(struct d_resource *res, struct context_def *oc, struct options *common, struct options *options)
{
	struct d_option *option, *new_option, *existing_option;

	STAILQ_FOREACH(option, common, link) {
		existing_option = find_opt(options, option->name);
		if (!existing_option) {
			new_option = new_opt(strdup(option->name),
					     option->value ? strdup(option->value) : NULL);
			new_option->inherited = true;
			insert_head(options, new_option);
		} else if (existing_option->inherited && oc != &wildcard_ctx) {
			if (!is_equal(oc, existing_option, option)) {
				err("%s:%d: in resource %s, "
					"ambiguous inheritance for option \"%s\".\n"
					"should be \"%s\" and \"%s\" at the same time\n.",
					res->config_file, res->start_line, res->name,
					option->name, existing_option->value, option->value);
				config_valid = 0;
			}
			/* else {
			err("%s:%d: WARNING: in resource %s, "
			"multiple inheritance for option \"%s\".\n"
			"with same value\n.",
			res->config_file, res->start_line, res->name,
			option->name, existing_option->value, option->value);
			}
			*/
		}
	}
}

void expand_common(void)
{
	struct d_resource *res;
	struct d_volume *vol, *host_vol;
	struct d_host_info *h;
	struct connection *conn;
	struct d_resource *template;

	for_each_resource(res, &config) {
		/* make sure vol->device is non-NULL */
		for_each_host(h, &res->all_hosts) {
			for_each_volume(vol, &h->volumes) {
				if (vol->disk && !strcmp(vol->disk, "none")) {
					free(vol->disk);
					free(vol->meta_disk);
					free(vol->meta_index);
					vol->disk = NULL;
					vol->meta_disk = NULL;
					vol->meta_index = NULL;
				}

				if (!vol->device)
					// BSR-386 rename to be the same as name of major device due to pvcreate error
					m_asprintf(&vol->device, "/dev/bsr%u",
						   vol->device_minor);
			}
		}

		if (res->template)
			template = res->template;
		else
			template = common;

		if (template) {
			expand_opts(res, &show_net_options_ctx, &template->net_options, &res->net_options);
			expand_opts(res, &disk_options_ctx, &template->disk_options, &res->disk_options);
			expand_opts(res, &device_options_ctx, &template->pd_options, &res->pd_options);
			expand_opts(res, &startup_options_ctx, &template->startup_options, &res->startup_options);
			expand_opts(res, &proxy_options_ctx, &template->proxy_options, &res->proxy_options);
			expand_opts(res, &handlers_ctx, &template->handlers, &res->handlers);
			expand_opts(res, &resource_options_ctx, &template->res_options, &res->res_options);
			// BSR-718
			expand_opts(res, &node_options_ctx, &template->node_options, &res->node_options);

			if (template->stacked_timeouts)
				res->stacked_timeouts = 1;

			expand_opts(res, &wildcard_ctx, &template->proxy_plugins, &res->proxy_plugins);
		}

		/* now that common disk options (if any) have been propagated to the
		 * resource level, further propagate them to the volume level. */
		for_each_host(h, &res->all_hosts) {
			// BSR-718
			expand_opts(res, &node_options_ctx, &res->node_options, &h->node_options);
			for_each_volume(vol, &h->volumes) {
				expand_opts(res, &disk_options_ctx, &res->disk_options, &vol->disk_options);
				expand_opts(res, &peer_device_options_ctx, &res->pd_options, &vol->pd_options);
			}
		}

		/* now from all volume/disk-options on resource level to host level */
		for_each_volume(vol, &res->volumes) {
			for_each_host(h, &res->all_hosts) {
				host_vol = volume_by_vnr(&h->volumes, vol->vnr);
				expand_opts(res, &disk_options_ctx, &vol->disk_options, &host_vol->disk_options);
				expand_opts(res, &peer_device_options_ctx, &vol->pd_options, &host_vol->pd_options);
			}
		}

		/* inherit network options from resource objects into connection objects */
		for_each_connection(conn, &res->connections)
			expand_opts(res, &show_net_options_ctx, &res->net_options, &conn->net_options);

		/* inherit proxy options from resource to the proxies in the connections */
		for_each_connection(conn, &res->connections) {
			struct path *path;
			for_each_path(path, &conn->paths) {
				struct hname_address *ha;
				STAILQ_FOREACH(ha, &path->hname_address_pairs, link) {
					if (!ha->proxy)
						continue;

					expand_opts(res, &proxy_options_ctx, &res->proxy_options, &ha->proxy->options);
					expand_opts(res, &wildcard_ctx, &res->proxy_plugins, &ha->proxy->plugins);
				}
			}
		}

		/* inherit peer_device options from connections to peer_devices AND
		   tie the peer_device options from the volume to peer_devices */
		for_each_connection(conn, &res->connections) {
			struct peer_device *peer_device;
			struct hname_address *ha;
			struct path *some_path;

			STAILQ_FOREACH(peer_device, &conn->peer_devices, connection_link)
				expand_opts(res, &peer_device_options_ctx, &conn->pd_options, &peer_device->pd_options);
			
			some_path = STAILQ_FIRST(&conn->paths);
			if (!some_path)
				continue;

			STAILQ_FOREACH(ha, &some_path->hname_address_pairs, link) {
				h = ha->host_info;
				for_each_volume(vol, &h->volumes) {
					peer_device = find_peer_device(conn, vol->vnr);

					expand_opts(res, &peer_device_options_ctx, &vol->pd_options, &peer_device->pd_options);
				}
			}
		}
	}
}

struct d_resource *res_by_name(const char *name)
{
	struct d_resource *res;

	for_each_resource(res, &config) {
		if (strcmp(name, res->name) == 0)
			return res;
	}
	return NULL;
}

static int sanity_check_abs_cmd(char *cmd_name)
{
	struct stat sb;

	if (stat(cmd_name, &sb)) {
		/* If stat fails, just ignore this sanity check,
		 * we are still iterating over $PATH probably. */
		return 0;
	}

	if (!(sb.st_mode & S_ISUID) || sb.st_mode & S_IXOTH || sb.st_gid == 0) {
		static int did_header = 0;
		if (!did_header)
			err("WARN:\n"
			    "  You are using the 'bsr-peer-outdater' as fence-peer program.\n"
			    "  If you use that mechanism the dopd heartbeat plugin program needs\n"
			    "  to be able to call bsrsetup and bsrmeta with root privileges.\n\n"
			    "  You need to fix this with these commands:\n");
		did_header = 1;
		err("  chgrp haclient %s\n"
		    "  chmod o-x %s\n"
		    "  chmod u+s %s\n\n",
		    cmd_name, cmd_name, cmd_name);
	}
	return 1;
}

static void sanity_check_cmd(char *cmd_name)
{
	char *path, *pp, *c;
	char abs_path[100];

	if (strchr(cmd_name, '/')) {
		sanity_check_abs_cmd(cmd_name);
	} else {
		path = pp = c = strdup(getenv("PATH"));

		while (1) {
			c = strchr(pp, ':');
			if (c)
				*c = 0;
			snprintf(abs_path, 100, "%s/%s", pp, cmd_name);
			if (sanity_check_abs_cmd(abs_path))
				break;
			if (!c)
				break;
			c++;
			if (!*c)
				break;
			pp = c;
		}
		free(path);
	}
}

/* if the config file is not readable by haclient,
 * dopd cannot work.
 * NOTE: we assume that any gid != 0 will be the group dopd will run as,
 * typically haclient. */
static void sanity_check_conf(char *c)
{
	struct stat sb;

	/* if we cannot stat the config file,
	 * we have other things to worry about. */
	if (stat(c, &sb))
		return;

	/* permissions are funny: if it is world readable,
	 * but not group readable, and it belongs to my group,
	 * I am denied access.
	 * For the file to be readable by dopd (hacluster:haclient),
	 * it is not enough to be world readable. */

	/* ok if world readable, and NOT group haclient (see NOTE above) */
	if (sb.st_mode & S_IROTH && sb.st_gid == 0)
		return;

	/* ok if group readable, and group haclient (see NOTE above) */
	if (sb.st_mode & S_IRGRP && sb.st_gid != 0)
		return;

	err("WARN:\n"
	    "  You are using the 'bsr-peer-outdater' as fence-peer program.\n"
	    "  If you use that mechanism the dopd heartbeat plugin program needs\n"
	    "  to be able to read the bsr.config file.\n\n"
	    "  You need to fix this with these commands:\n"
	    "  chgrp haclient %s\n"
	    "  chmod g+r %s\n\n", c, c);
}

static void sanity_check_perm()
{
	static int checked = 0;
	if (checked)
		return;

	sanity_check_cmd(bsrsetup);
	sanity_check_cmd(bsrmeta);
	sanity_check_conf(config_file);
	checked = 1;
}

static bool host_name_known(struct d_resource *res, char *name)
{
	struct d_host_info *host;

	for_each_host(host, &res->all_hosts)
		if (hostname_in_list(name, &host->on_hosts))
			return 1;

	return 0;
}

/* Check that either all host sections have a proxy subsection, or none */
static void ensure_proxy_sections(struct d_resource *res)
{
	struct d_host_info *host;
	struct connection *conn;
	enum { INIT, HAVE, MISSING } proxy_sect = INIT, prev_proxy_sect;

	for_each_host(host, &res->all_hosts) {
		prev_proxy_sect = proxy_sect;
		proxy_sect = host->proxy_compat_only ? HAVE : MISSING;
		if (prev_proxy_sect == INIT)
			continue;
		if (prev_proxy_sect != proxy_sect) {
			err("%s:%d: in resource %s:\n\t"
			    "Either all 'on' sections must contain a proxy subsection, or none.\n",
			    res->config_file, res->start_line, res->name);
			config_valid = 0;
		}
	}

	for_each_connection(conn, &res->connections) {
		struct path *path;

		for_each_path(path, &conn->paths) {
			struct hname_address *ha;
			proxy_sect = INIT;

			STAILQ_FOREACH(ha, &path->hname_address_pairs, link) {
				prev_proxy_sect = proxy_sect;
				proxy_sect = ha->proxy ? HAVE : MISSING;
				if (prev_proxy_sect == INIT)
					continue;
				if (prev_proxy_sect != proxy_sect) {
					err("%s:%d: in connection in resource %s:\n"
					    "Either all 'host' statements must have a proxy subsection, or none.\n",
					    res->config_file, conn->config_line,
					    res->name);
					config_valid = 0;
				}
			}
		}
	}
}

static void validate_resource(struct d_resource *res, enum pp_flags flags)
{
	struct d_option *opt;

	/* there may be more than one "resync-after" statement,
	 * see commit 89cd0585 */
	STAILQ_FOREACH(opt, &res->disk_options, link) {
		struct d_resource *rs_after_res;
	next:
		if (strcmp(opt->name, "resync-after"))
			continue;
		rs_after_res = res_by_name(opt->value);
		if (rs_after_res == NULL ||
		    (rs_after_res->ignore && !(flags & MATCH_ON_PROXY))) {
			err("%s:%d: in resource %s:\n\tresource '%s' mentioned in "
			    "'resync-after' option is not known%s.\n",
			    res->config_file, res->start_line, res->name,
			    opt->value, rs_after_res ? " on this host" : "");
			/* Non-fatal if run from some script.
			 * When deleting resources, it is an easily made
			 * oversight to leave references to the deleted
			 * resources in resync-after statements.  Don't fail on
			 * every pacemaker-induced action, as it would
			 * ultimately lead to all nodes committing suicide. */
			if (no_tty) {
				struct d_option *next = STAILQ_NEXT(opt, link);
				STAILQ_REMOVE(&res->disk_options, opt, d_option, link);
				free_opt(opt);
				opt = next;
				if (opt)
					goto next;
				else
					break;
			} else
				config_valid = 0;
		}
	}
	if (STAILQ_EMPTY(&res->all_hosts)) {
		err("%s:%d: in resource %s:\n\ta host sections ('on %s { ... }') is missing.\n",
		    res->config_file, res->start_line, res->name, hostname);
		config_valid = 0;
	}
	if (res->ignore)
		return;
	if (!res->me) {
		err("%s:%d: in resource %s:\n\tmissing section 'on %s { ... }'.\n",
		    res->config_file, res->start_line, res->name, hostname);
		config_valid = 0;
	}
	// need to verify that in the discard-node-nodename options only known
	// nodenames are mentioned.
	if ((opt = find_opt(&res->net_options, "after-sb-0pri"))) {
		if (!strncmp(opt->value, "discard-node-", 13)) {
			if (!host_name_known(res, opt->value + 13)) {
				err("%s:%d: in resource %s:\n\t"
				    "the nodename in the '%s' option is "
				    "not known.\n",
				    res->config_file, res->start_line,
				    res->name, opt->value);
				config_valid = 0;
			}
		}
	}

	if ((opt = find_opt(&res->handlers, "fence-peer"))) {
		if (strstr(opt->value, "bsr-peer-outdater"))
			sanity_check_perm();
	}

	ensure_proxy_sections(res); /* All or none. */
}

static int ctx_set_implicit_volume(struct cfg_ctx *ctx)
{
	struct d_volume *vol, *v = NULL;
	int volumes = 0;

	if (ctx->vol || !ctx->res)
		return 0;

	if (!ctx->res->me) {
		return 0;
	}

	for_each_volume(vol, &ctx->res->me->volumes) {
		volumes++;
		v = vol;
	}

	if (volumes == 1)
		ctx->vol = v;

	return volumes;
}

// Need to convert after from resourcename to minor_number.
static void _convert_after_option(struct d_resource *res, struct d_volume *vol)
{
	struct d_option *opt;
	struct cfg_ctx depends_on_ctx = { };
	int volumes;

	if (res == NULL)
		return;

	STAILQ_FOREACH(opt, &vol->disk_options, link) {
	next:
		if (strcmp(opt->name, "resync-after"))
			continue;
		ctx_by_name(&depends_on_ctx, opt->value, CTX_FIRST);
		volumes = ctx_set_implicit_volume(&depends_on_ctx);
		if (volumes > 1) {
			err("%s:%d: in resource %s:\n\t"
			    "resync-after contains '%s', which is ambiguous, since it contains %d volumes\n",
			    res->config_file, res->start_line, res->name,
			    opt->value, volumes);
			config_valid = 0;
			return;
		}

		if (!depends_on_ctx.res || depends_on_ctx.res->ignore) {
			struct d_option *next = STAILQ_NEXT(opt, link);
			STAILQ_REMOVE(&vol->disk_options, opt, d_option, link);
			free_opt(opt);
			opt = next;
			if (opt)
				goto next;
			else
				break;
		} else {
			free(opt->value);
			m_asprintf(&opt->value, "%d", depends_on_ctx.vol->device_minor);
		}
	}
}

// Need to convert after from resourcename/volume to minor_number.
static void convert_after_option(struct d_resource *res)
{
	struct d_volume *vol;
	struct d_host_info *h;

	for_each_host(h, &res->all_hosts)
		for_each_volume(vol, &h->volumes)
			_convert_after_option(res, vol);
}

// need to convert discard-node-nodename to discard-local or discard-remote.
static void convert_discard_opt(struct options *net_options)
{
	struct d_option *opt;

	if ((opt = find_opt(net_options, "after-sb-0pri"))) {
		if (!strncmp(opt->value, "discard-node-", 13)) {
			if (!strcmp(hostname, opt->value + 13)) {
				free(opt->value);
				opt->value = strdup("discard-local");
			} else {
				free(opt->value);
				opt->value = strdup("discard-remote");
			}
		}
	}
}

void global_validate_maybe_expand_die_if_invalid(int expand, enum pp_flags flags)
{
	struct d_resource *res;
	for_each_resource(res, &config) {
		validate_resource(res, flags);
		if (!config_valid) {
			CLI_ERRO_LOG(false, true, "invalid config");
			exit(E_CONFIG_INVALID);
		}
		if (expand) {
			struct connection *conn;

			convert_after_option(res);
			convert_discard_opt(&res->net_options);

			for_each_connection(conn, &res->connections)
				convert_discard_opt(&conn->net_options);
		}
		if (!config_valid) {
			CLI_ERRO_LOG(false, true, "invalid config");
			exit(E_CONFIG_INVALID);
		}
	}
}
