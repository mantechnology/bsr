/*
  bsr.h

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
#include "bsr.h"
#ifdef _LIN
#include <linux/fs.h>
#endif
#ifndef __KERNEL__
#include <string.h>
#endif
#include "bsr_strings.h"
#include "bsr_protocol.h"

// BSR-892 the output string for the connection error is lowercase with a space of -.
static const char * const __conn_error_names[] = {
	[C_NO_ERROR] = "no-error",
	[C_SPLIT_BRAIN_ERROR] = "split-brain",
};

struct state_names bsr_conn_error_names = {
	.names = __conn_error_names,
	.size = sizeof __conn_error_names / sizeof __conn_error_names[0],
};

static const char * const __conn_state_names[] = {
	[C_STANDALONE]       = "StandAlone",
	[C_DISCONNECTING]    = "Disconnecting",
	[C_UNCONNECTED]      = "Unconnected",
	[C_TIMEOUT]          = "Timeout",
	[C_BROKEN_PIPE]      = "BrokenPipe",
	[C_NETWORK_FAILURE]  = "NetworkFailure",
	[C_PROTOCOL_ERROR]   = "ProtocolError",
	[C_TEAR_DOWN]        = "TearDown",
	[C_CONNECTING]       = "Connecting",
	[C_CONNECTED]	     = "Connected",
};

struct state_names bsr_conn_state_names = {
	.names = __conn_state_names,
	.size = sizeof __conn_state_names / sizeof __conn_state_names[0],
};

static const char * const __repl_state_names[] = {
	[L_OFF]              = "Off",
	[L_ESTABLISHED]      = "Established",
	[L_STARTING_SYNC_S]  = "StartingSyncS",
	[L_STARTING_SYNC_T]  = "StartingSyncT",
	[L_WF_BITMAP_S]      = "WFBitMapS",
	[L_WF_BITMAP_T]      = "WFBitMapT",
	[L_WF_SYNC_UUID]     = "WFSyncUUID",
	[L_SYNC_SOURCE]      = "SyncSource",
	[L_SYNC_TARGET]      = "SyncTarget",
	[L_VERIFY_S]         = "VerifyS",
	[L_VERIFY_T]         = "VerifyT",
	[L_PAUSED_SYNC_S]    = "PausedSyncS",
	[L_PAUSED_SYNC_T]    = "PausedSyncT",
	[L_AHEAD]            = "Ahead",
	[L_BEHIND]           = "Behind",
};

struct state_names bsr_repl_state_names = {
	.names = __repl_state_names,
	.size = sizeof __repl_state_names / sizeof __repl_state_names[0],
};

static const char * const __role_state_names[] = {
	[R_UNKNOWN]   = "Unknown",
	[R_PRIMARY]   = "Primary",
	[R_SECONDARY] = "Secondary",
};

struct state_names bsr_role_state_names = {
	.names = __role_state_names,
	.size = sizeof __role_state_names / sizeof __role_state_names[0],
};

static const char * const __disk_state_names[] = {
	[D_DISKLESS]     = "Diskless",
	[D_ATTACHING]    = "Attaching",
	[D_DETACHING]    = "Detaching",
	[D_FAILED]       = "Failed",
	[D_NEGOTIATING]  = "Negotiating",
	[D_INCONSISTENT] = "Inconsistent",
	[D_OUTDATED]     = "Outdated",
	[D_UNKNOWN]      = "DUnknown",
	[D_CONSISTENT]   = "Consistent",
	[D_UP_TO_DATE]   = "UpToDate",
};

struct state_names bsr_disk_state_names = {
	.names = __disk_state_names,
	.size = sizeof __disk_state_names / sizeof __disk_state_names[0],
};

static const char * const __error_messages[] = {
	[-SS_TWO_PRIMARIES] = "Multiple primaries not allowed by config",
	[-SS_NO_UP_TO_DATE_DISK] = "Need access to UpToDate data",
	[-SS_NO_LOCAL_DISK] = "Can not resync without local disk",
	[-SS_NO_REMOTE_DISK] = "Can not resync without remote disk",
	[-SS_CONNECTED_OUTDATES] = "Refusing to be Outdated while Connected",
	[-SS_PRIMARY_NOP] = "Refusing to be Primary while peer is not outdated",
	[-SS_RESYNC_RUNNING] = "Can not start OV/resync since it is already active",
	[-SS_ALREADY_STANDALONE] = "Can not disconnect a StandAlone device",
	[-SS_CW_FAILED_BY_PEER] = "State change was refused by peer node",
	[-SS_IS_DISKLESS] = "Device is diskless, the requested operation requires a disk",
	[-SS_DEVICE_IN_USE] = "Device is held open by someone",
	[-SS_NO_NET_CONFIG] = "Have no net/connection configuration",
	[-SS_NO_VERIFY_ALG] = "Need a verify algorithm to start online verify",
	[-SS_NEED_CONNECTION] = "Need a connection to start verify or resync",
	[-SS_NOT_SUPPORTED] = "Peer does not support protocol",
	[-SS_LOWER_THAN_OUTDATED] = "Disk state is lower than outdated",
	[-SS_IN_TRANSIENT_STATE] = "In transient state, retry after next state change",
	[-SS_CONCURRENT_ST_CHG] = "Concurrent state changes detected and aborted",
	[-SS_O_VOL_PEER_PRI] = "Other vol primary on peer not allowed by config",
	[-SS_PRIMARY_READER] = "Peer may not become primary while device is opened read-only",
	[-SS_INTERRUPTED] = "Interrupted state change",
	[-SS_TIMEOUT] = "Timeout in operation",
	[-SS_WEAKLY_CONNECTED] = "Primary nodes must be strongly connected among each other",
	[-SS_NO_QUORUM] = "No quorum",
	[-SS_TARGET_DISK_TOO_SMALL] = "Target disk is smaller than source.",
	// DW-839
	[-SS_CONNECTED_DISKLESS] = "Refusing to be Diskless while Connected",
	[-SS_LOWER_THAN_OUTDATED_PEER] = "Peer disk state is lower than outdated",
	[-SS_BARRIER_ACK_PENDING_TIMEOUT] = "Failed to set secondary role due to barrier ack pending timeout(10s). Retry to demote first(bsradm secondary r0). if demote timeout continues, disconnect and demote forcibly.",
	// BSR-988
	[-SS_RESYNC_REPLY_DATA_PENDING_TIMEOUT] = "Failed to set secondary role due to resync reply data pending timeout(10s). Retry to demote first(drbdadm secondary r0). if demote timeout continues, disconnect and demote forcibly.",
};

struct state_names bsr_error_messages = {
	.names = __error_messages,
	.size = sizeof __error_messages / sizeof __error_messages[0],
};

static const char * const __packet_names[] = {
	[P_DATA]	        = "P_DATA",
	[P_WSAME]               = "P_WSAME",
	[P_TRIM]                = "P_TRIM",
	[P_DATA_REPLY]	        = "P_DATA_REPLY",
	[P_RS_DATA_REPLY]	= "P_RS_DATA_REPLY",
	[P_BARRIER]	        = "P_BARRIER",
	[P_BITMAP]	        = "P_BITMAP",
	[P_BECOME_SYNC_TARGET]  = "P_BECOME_SYNC_TARGET",
	[P_BECOME_SYNC_SOURCE]  = "P_BECOME_SYNC_SOURCE",
	[P_UNPLUG_REMOTE]	= "P_UNPLUG_REMOTE",
	[P_DATA_REQUEST]	= "P_DATA_REQUEST",
	[P_RS_DATA_REQUEST]     = "P_RS_DATA_REQUEST",
	[P_SYNC_PARAM]	        = "P_SYNC_PARAM",
	[P_SYNC_PARAM89]	= "P_SYNC_PARAM89",
	[P_PROTOCOL]            = "P_PROTOCOL",
	[P_UUIDS]	        = "P_UUIDS",
	[P_SIZES]	        = "P_SIZES",
	[P_STATE]	        = "P_STATE",
	[P_SYNC_UUID]           = "P_SYNC_UUID",
	[P_AUTH_CHALLENGE]      = "P_AUTH_CHALLENGE",
	[P_AUTH_RESPONSE]	= "P_AUTH_RESPONSE",
	[P_PING]		= "P_PING",
	[P_PING_ACK]	        = "P_PING_ACK",
	[P_RECV_ACK]	        = "P_RECV_ACK",
	[P_WRITE_ACK]	        = "P_WRITE_ACK",
	[P_RS_WRITE_ACK]	= "P_RS_WRITE_ACK",
	[P_SUPERSEDED]		= "P_SUPERSEDED",
	[P_NEG_ACK]	        = "P_NEG_ACK",
	[P_NEG_DREPLY]	        = "P_NEG_DREPLY",
	[P_NEG_RS_DREPLY]	= "P_NEG_RS_DREPLY",
	[P_BARRIER_ACK]	        = "P_BARRIER_ACK",
	[P_STATE_CHG_REQ]       = "P_STATE_CHG_REQ",
	[P_STATE_CHG_REPLY]     = "P_STATE_CHG_REPLY",
	[P_OV_REQUEST]          = "P_OV_REQUEST",
	[P_OV_REPLY]            = "P_OV_REPLY",
	[P_OV_RESULT]           = "P_OV_RESULT",
	[P_CSUM_RS_REQUEST]     = "P_CSUM_RS_REQUEST",
	[P_RS_IS_IN_SYNC]	= "P_RS_IS_IN_SYNC",
	[P_COMPRESSED_BITMAP]   = "P_COMPRESSED_BITMAP",
	[P_DELAY_PROBE]         = "P_DELAY_PROBE",
	[P_OUT_OF_SYNC]		= "P_OUT_OF_SYNC",
	[P_RETRY_WRITE]		= "P_RETRY_WRITE",
	[P_RS_CANCEL]		= "P_RS_CANCEL",
	[P_CONN_ST_CHG_REQ]	= "P_CONN_ST_CHG_REQ",
	[P_CONN_ST_CHG_REPLY]	= "P_CONN_ST_CHG_REPLY",
	[P_PROTOCOL_UPDATE]	= "P_PROTOCOL_UPDATE",
	[P_TWOPC_PREPARE]	= "P_TWOPC_PREPARE",
	[P_TWOPC_ABORT]		= "P_TWOPC_ABORT",
	[P_DAGTAG]		= "P_DAGTAG",
	[P_PEER_ACK]		= "P_PEER_ACK",
	[P_PEERS_IN_SYNC]       = "P_PEERS_IN_SYNC",
	[P_UUIDS110]            = "P_UUIDS110",
	[P_PEER_DAGTAG]         = "P_PEER_DAGTAG",
	[P_CURRENT_UUID]        = "P_CURRENT_UUID",
	[P_TWOPC_COMMIT]	= "P_TWOPC_COMMIT",
	[P_TWOPC_YES]		= "P_TWOPC_YES",
	[P_TWOPC_NO]		= "P_TWOPC_NO",
	[P_TWOPC_RETRY]		= "P_TWOPC_RETRY",
	[P_RS_THIN_REQ]		= "P_RS_THIN_REQ",
	[P_RS_DEALLOCATED]	= "P_RS_DEALLOCATED",
	[P_TWOPC_PREP_RSZ]	= "P_TWOPC_PREP_RSZ",
	[P_BM_EXCHANGE_STATE]	= "P_BM_EXCHANGE_STATE",
	[P_ZEROES]		= "P_ZEROES",
	/* enum bsr_packet, but not commands - obsoleted flags:
	 *	P_MAY_IGNORE
	 *	P_MAX_OPT_CMD
	 */
};

struct state_names bsr_packet_names = {
        .names = __packet_names,
        .size = sizeof __packet_names / sizeof __packet_names[0],
};

const char *bsr_repl_str(enum bsr_repl_state s)
{
	return (s < 0 || (unsigned int)s >= bsr_repl_state_names.size ||
	        !bsr_repl_state_names.names[s]) ?
	       "?" : bsr_repl_state_names.names[s];
}

const char *bsr_conn_str(enum bsr_conn_state s)
{
	return (s < 0 || (unsigned int)s >= bsr_conn_state_names.size ||
	        !bsr_conn_state_names.names[s]) ?
	       "?" : bsr_conn_state_names.names[s];
}

const char *bsr_role_str(enum bsr_role s)
{
	return (s < 0 || (unsigned int)s >= bsr_role_state_names.size ||
	        !bsr_role_state_names.names[s]) ?
	       "?" : bsr_role_state_names.names[s];
}

// BSR-892
const char *bsr_conn_err_str(enum bsr_conn_error e)
{
	return (e < 0 || (unsigned int)e >= bsr_conn_error_names.size ||
		!bsr_conn_error_names.names[e]) ?
		"?" : bsr_conn_error_names.names[e];
}

const char *bsr_disk_str(enum bsr_disk_state s)
{
	return (s < 0 || (unsigned int)s >= bsr_disk_state_names.size ||
	        !bsr_disk_state_names.names[s]) ?
	       "?" : bsr_disk_state_names.names[s];
}

const char *bsr_set_st_err_str(enum bsr_state_rv err)
{
	return (-err < 0 || (unsigned int)(~err + 1) >= bsr_error_messages.size ||
	        !bsr_error_messages.names[-err]) ?
	       "?" : bsr_error_messages.names[-err];
}

const char *bsr_packet_name(enum bsr_packet cmd)
{
	/* too big for the array: 0xfffX */
	if (cmd == P_INITIAL_META)
		return "InitialMeta";
	if (cmd == P_INITIAL_DATA)
		return "InitialData";
	if (cmd == P_CONNECTION_FEATURES)
		return "ConnectionFeatures";
	return (cmd < 0 || cmd >= ARRAY_SIZE(__packet_names) ||
		!__packet_names[cmd]) ?
	       "?" : __packet_names[cmd];
}


//DW-1755
const char *bsr_disk_type_name(unsigned char type) {
	switch (type) {
	case VOLUME_TYPE_REPL:
		return "data";
	case VOLUME_TYPE_META:
		return "meta";
	}
	return "unknown";
}

const char *bsr_io_type_name(unsigned char type) {
	switch (type) {
	case READ:
		return "read";
	case WRITE:
		return "write";
	}
	return "unknown";
}

// BSR-859
const char *bsr_host_type_name(char *node_name) {
	if (!node_name || !strcmp(node_name, ""))
		return "unknown";
	if (strchr(node_name, ':'))
		return "floating";
	else
		return "host";
}