﻿/*
   bsrmeta.c

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2007-2020, Man Technology inc  <bsr@mantech.co.kr>

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

/* have the <sys/....h> first, otherwise you get e.g. "redefined" types from
 * sys/types.h and other weird stuff */

#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "bsr.h"		/* only use BSR_MAGIC from here! */
#ifdef _WIN
#include <windows.h>
#else // _LIN
#include <linux/major.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>           /* for BLKFLSBUF */
#endif

#include "bsr_endian.h"
#include "bsrtool_common.h"
#include "bsr_strings.h"
#include "bsr_meta_data.h"

#include "bsrmeta_parser.h"

#include "config.h"

#ifdef _LIN_LOOP_META_SUPPORT
#include <linux/loop.h>
#endif

/* BLKZEROOUT, available on linux-3.6 and later,
* and maybe backported to distribution kernels,
* even if they pretend to be older.
* Yes, we encountered a number of systems that already had it in their
* kernels, but not yet in the headers used to build userland stuff like this.
*/
#ifndef BLKZEROOUT
#define BLKZEROOUT    _IO(0x12,127)
#endif

extern FILE* yyin;
YYSTYPE yylval;

int	force = 0;
int	verbose = 0;
int	ignore_sanity_checks = 0;
int	dry_run = 0;
int     option_peer_max_bio_size = 0;
int     option_node_id = -1;
unsigned option_al_stripes = 1;
unsigned option_al_stripe_size_4k = 8;
unsigned option_al_stripes_used = 0;
char *progname = NULL;

struct option metaopt[] = {
    { "ignore-sanity-checks",  no_argument, &ignore_sanity_checks, 1000 },
    { "dry-run",  no_argument, &dry_run, 1000 },
    { "force",  no_argument,    0, 'f' },
    { "verbose",  no_argument,    0, 'v' },
    { "peer-max-bio-size",  required_argument, NULL, 'p' },
    { "node-id",  required_argument, NULL, 'i' },
    { "al-stripes",  required_argument, NULL, 's' },
    { "al-stripe-size-kB",  required_argument, NULL, 'z' },
    { NULL,     0,              0, 0 },
};

/* FIXME? should use sector_t and off_t, not long/uint64_t ... */

/* Note RETURN VALUES:
 * exit code convention: int vXY_something() and meta_blah return some negative
 * error code, usually -1, when failed, 0 for success.
 *
 * FIXME some of the return -1; probably should better be exit(something);
 * or some of the exit() should be rather some return?
 *
 * AND, the exit codes should follow some defined scheme.
 */

#if 0
#define ASSERT(x) ((void)(0))
#define d_expect(x) (x)
#else
#define ASSERT(x) do { if (!(x)) {				\
	CLI_ERRO_LOG_STDERR(false, "%s:%u:%s: ASSERT(%s) failed.",	\
		__FILE__ , __LINE__ , __func__ , #x );		\
	abort(); }						\
	} while (false)
#define d_expect(x) ({						\
	int _x = (x);						\
	if (!_x)						\
		CLI_ERRO_LOG_STDERR(false, "%s:%u:%s: ASSERT(%s) failed.",\
			__FILE__ , __LINE__ , __func__ , #x );	\
	_x; })
#endif

static int confirmed(const char *text)
{
	const char yes[] = "yes";
	const ssize_t N = sizeof(yes);
	char *answer = NULL;
	size_t n = 0;
	int ok;

	fprintf(stderr, "\n%s\n", text);

	if (force) {
		fprintf(stderr, "*** confirmation forced via --force option ***\n");
	    ok = 1;
	}
	else {
		fprintf(stderr, "[need to type '%s' to confirm] ", yes);
	    ok = getline(&answer,&n,stdin) == N &&
		strncmp(answer,yes,N-1) == 0;
	    free(answer);
		fprintf(stderr, "\n");
	}
	return ok;
}

/*
 * FIXME
 *
 * when configuring a bsr device:
 *
 * Require valid bsr meta data at the respective location.  A meta data
 * block would only be created by the bsrmeta command.
 *
 * (How) do we want to implement this: A meta data block contains some
 * reference to the physical device it belongs. Refuse to attach not
 * corresponding meta data.
 *
 * THINK: put a checksum within the on-disk meta data block, too?
 *
 * When asked to create a new meta data block, the bsrmeta command
 * warns loudly if either the data device or the meta data device seem
 * to contain some data, and requires explicit confirmation anyways.
 *
 * See current implementation in check_for_existing_data below.
 *
 * XXX should also be done for meta-data != internal, i.e.  refuse to
 * create meta data blocks on a device that seems to be in use for
 * something else.
 *
 * Maybe with an external meta data device, we want to require a "meta
 * data device super block", which could also serve as TOC to the meta
 * data, once we have variable size meta data.  Other option could be a
 * /var/lib/bsr/md-toc plain file, and some magic block on every device
 * that serves as md storage.
 *
 * For certain content on the lower level device, we should refuse
 * always.  e.g. refuse to be created on top of a LVM2 physical volume,
 * or on top of swap space. This would require people to do an dd
 * if=/dev/zero of=device.  Protects them from shooting themselves,
 * and blaming us...
 */

/* reiserfs sb offset is 64k plus
 * align it to 4k, in case someone has unusual hard sect size (!= 512),
 * otherwise direct io will fail with EINVAL */
#define SO_MUCH (68*1024)

/*
 * I think this block of declarations and definitions should be
 * in some common.h, too.
 * {
 */

#ifndef ALIGN
# define ALIGN(x,a) ( ((x) + (a)-1) &~ ((a)-1) )
#endif

#define MD_AL_OFFSET_07        8
#define MD_AL_MAX_SECT_07     64
#define MD_BM_OFFSET_07        (MD_AL_OFFSET_07 + MD_AL_MAX_SECT_07)
// DW-1335
#define MD_RESERVED_SECT_07    ( (uint64_t)(256ULL << 11) )

#define MD_BM_MAX_BYTE_07      ( (uint64_t)(MD_RESERVED_SECT_07 - MD_BM_OFFSET_07)*512 )
#if BITS_PER_LONG == 32
#define MD_BM_MAX_BYTE_FLEX    ( (uint64_t)(1ULL << (32-3)) )
#else
#define MD_BM_MAX_BYTE_FLEX    ( (uint64_t)(1ULL << (38-3)) )
#endif

#define DEFAULT_BM_BLOCK_SIZE  (1<<12)

#define BSR_MD_MAGIC_06   (BSR_MAGIC+2)
#define BSR_MD_MAGIC_07   (BSR_MAGIC+3)
#define BSR_MD_MAGIC_08   (BSR_MAGIC+4)
#define BSR_MD_MAGIC_84_UNCLEAN   (BSR_MAGIC+5)
#define BSR_MD_MAGIC_09   (BSR_MAGIC+6)

/*
 * }
 * end of should-be-shared
 */

/*
 * global variables and data types
 */

/* buffer_size has to be a multiple of 4096, and at least 32k.
 * Pending a "nice" implementation of replay_al_84 for striped activity log,
 * I chose a big buffer hopefully large enough to hold the whole activity log,
 * even with "large" number of stripes and stripe sizes.
 *
 * If you chose to change buffer_size, double check also fprintf_bm(),
 * and how it calculates its chunk size.
 */
const size_t buffer_size = 32 * 1024 * 1024;
size_t pagesize; /* = sysconf(_SC_PAGESIZE) */
int opened_odirect = 1;
void *on_disk_buffer = NULL;
int global_argc;
char **global_argv;

enum md_format {
	BSR_V06,
	BSR_V07,
	BSR_V08,
	BSR_V09,
	BSR_UNKNOWN,
};

/* let gcc help us get it right.
 * some explicit endian types */
typedef struct { uint64_t le; } le_u64;
typedef struct { uint64_t be; } be_u64;
typedef struct { uint32_t le; } le_u32;
typedef struct { uint32_t be; } be_u32;
typedef struct { int32_t be; } be_s32;
typedef struct { uint16_t be; } be_u16;
typedef struct { unsigned long le; } le_ulong;
typedef struct { unsigned long be; } be_ulong;

/* NOTE that this structure does not need to be packed,
 * aligned, nor does it need to be in the same order as the on_disk variants.
 */
struct peer_md_cpu {
	uint64_t bitmap_uuid;
	uint64_t bitmap_dagtag;
	uint32_t flags;
	int32_t bitmap_index;
};

struct md_cpu {
	uint64_t current_uuid;
	uint64_t history_uuids[HISTORY_UUIDS];
	/* present since bsr 0.6 */
	uint32_t gc[GEN_CNT_SIZE];	/* generation counter */
	uint32_t magic;
	/* added in bsr 0.7;
	 * 0.7 stores effevtive_size on disk as kb, 0.8 in units of sectors.
	 * we use sectors in our general working structure here */
	uint64_t effective_size;	/* last agreed size */
	uint32_t md_size_sect;
	int32_t al_offset;		/* signed sector offset to this block */
	uint32_t al_nr_extents;	/* important for restoring the AL */
	int32_t bm_offset;		/* signed sector offset to the bitmap, from here */
	/* Since BSR 0.8 we have uuid instead of gc */
	uint32_t flags;
	uint64_t device_uuid;
	uint32_t bm_bytes_per_bit;
	uint32_t la_peer_max_bio_size;
	/* Since BSR 9.0 the following new stuff: */
	uint32_t max_peers;
	int32_t node_id;
	struct peer_md_cpu peers[BSR_PEERS_MAX];
	uint32_t al_stripes;
	uint32_t al_stripe_size_4k;
};

/*
 * bsrmeta specific types
 */

struct format_ops;

struct format {
	const struct format_ops *ops;
	char *md_device_name;	/* well, in 06 it is file name */
	char *bsr_dev_name;
#ifdef _WIN_VHD_META_SUPPORT
	char *vhd_dev_path;
	int peer_count;
#endif
#ifdef _LIN_LOOP_META_SUPPORT
	char *loop_file_path;
#endif
	unsigned minor;		/* cache, determined from bsr_dev_name */
	int lock_fd;
	int bsr_fd;		/* no longer used!   */
	int ll_fd;		/* not yet used here */
	int md_fd;
	int md_hard_sect_size;
#ifdef _WIN_CLI_UPDATE
	HANDLE md_handle; 
#endif 
	/* unused in 06 */
	int md_index;
	unsigned int bm_bytes;
	unsigned int bits_set;	/* 32 bit should be enough. @4k ==> 16TB */
	int bits_counted:1;
	int update_lk_bdev:1;	/* need to update the last known bdev info? */

	struct md_cpu md;

	/* _byte_ offsets of our "super block" and other data, within fd */
	uint64_t md_offset;
	uint64_t al_offset;
	uint64_t bm_offset;

	/* if create_md actually does convert,
	 * we want to wipe the old meta data block _after_ convertion. */
	uint64_t wipe_fixed;
	uint64_t wipe_flex;
	uint64_t wipe_resize;

	/* convenience */
	uint64_t bd_size; /* size of block device for internal meta data */

	/* size limit due to available on-disk bitmap */
	uint64_t max_usable_sect;

	/* last-known bdev info,
	 * to increase the chance of finding internal meta data in case the
	 * lower level device has been resized without telling BSR.
	 * Loaded from file for internal metadata */
	struct bdev_info lk_bd;
};

/* - parse is expected to exit() if it does not work out.
 * - open is expected to read the respective on_disk members,
 *   and copy the "superblock" meta data into the struct mem_cpu
 * FIXME describe rest of them, and when they should exit,
 * return error or success.
 */
struct format_ops {
	const char *name;
	char **args;
	int (*parse) (struct format *, char **, int, int *);
	int (*open) (struct format *);
	int (*close) (struct format *);
	int (*md_initialize) (struct format *, int do_disk_writes, int max_peers);
	int (*md_disk_to_cpu) (struct format *);
	int (*md_cpu_to_disk) (struct format *);
	void (*get_gi) (struct md_cpu *md, int node_id);
	void (*show_gi) (struct md_cpu *md, int node_id);
	void (*set_gi) (struct md_cpu *md, int node_id, char **argv, int argc);
	int (*outdate_gi) (struct md_cpu *md);
	int (*invalidate_gi) (struct md_cpu *md);
};

struct format_ops f_ops[];
/*
 * -- BSR 0.6 --------------------------------------
 */

struct __packed md_on_disk_06 {
	be_u32 gc[GEN_CNT_SIZE];	/* generation counter */
	be_u32 magic;
};

void md_disk_06_to_cpu(struct md_cpu *cpu, const struct md_on_disk_06 *disk)
{
	int i;

	memset(cpu, 0, sizeof(*cpu));
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->max_peers = 1;
}

void md_cpu_to_disk_06(struct md_on_disk_06 *disk, struct md_cpu *cpu)
{
	int i;

	for (i = 0; i < GEN_CNT_SIZE; i++)
		disk->gc[i].be = cpu_to_be32(cpu->gc[i]);
	disk->magic.be = cpu_to_be32(cpu->magic);
}

int v06_validate_md(struct format *cfg)
{
	if (cfg->md.magic != BSR_MD_MAGIC_06) {
		CLI_ERRO_LOG_STDERR(false, "v06 Magic number not found");
		return -1;
	}
	return 0;
}

/*
 * -- BSR 0.7 --------------------------------------
 */
unsigned long bm_bytes(const struct md_cpu * const md, uint64_t sectors);

struct __packed md_on_disk_07 {
	be_u64 la_kb;		/* last agreed size. */
	be_u32 gc[GEN_CNT_SIZE];	/* generation counter */
	be_u32 magic;
	be_u32 md_size_kb;
	be_s32 al_offset;	/* signed sector offset to this block */
	be_u32 al_nr_extents;	/* important for restoring the AL */
	be_s32 bm_offset;	/* signed sector offset to the bitmap, from here */
	char reserved[8 * 512 - 48];
};

void md_disk_07_to_cpu(struct md_cpu *cpu, const struct md_on_disk_07 *disk)
{
	int i;

	memset(cpu, 0, sizeof(*cpu));
	cpu->effective_size = be64_to_cpu(disk->la_kb.be) << 1;
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->md_size_sect = be32_to_cpu(disk->md_size_kb.be) << 1;
	cpu->al_offset = be32_to_cpu(disk->al_offset.be);
	cpu->al_nr_extents = be32_to_cpu(disk->al_nr_extents.be);
	cpu->bm_offset = be32_to_cpu(disk->bm_offset.be);
	cpu->bm_bytes_per_bit = DEFAULT_BM_BLOCK_SIZE;
	cpu->max_peers = 1;
	cpu->al_stripes = 1;
	cpu->al_stripe_size_4k = 8;
}

void md_cpu_to_disk_07(struct md_on_disk_07 *disk, const struct md_cpu * const cpu)
{
	int i;

	disk->la_kb.be = cpu_to_be64(cpu->effective_size >> 1);
	for (i = 0; i < GEN_CNT_SIZE; i++)
		disk->gc[i].be = cpu_to_be32(cpu->gc[i]);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size_kb.be = cpu_to_be32(cpu->md_size_sect >> 1);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	memset(disk->reserved, 0, sizeof(disk->reserved));
}

int is_valid_md(enum md_format f,
	const struct md_cpu * const md, const int md_index, const uint64_t ll_size)
{
	uint64_t md_size_sect;
	const char *v = f_ops[f].name;
	int al_size_sect;
	int n;

	ASSERT(f == BSR_V07 || f == BSR_V08 || f == BSR_V09);

	if ((f == BSR_V07 && md->magic != BSR_MD_MAGIC_07) ||
	    (f == BSR_V08 && md->magic != BSR_MD_MAGIC_08
			  && md->magic != BSR_MD_MAGIC_84_UNCLEAN) ||
	    (f == BSR_V09 && md->magic != BSR_MD_MAGIC_09)) {
		if (verbose >= 1)
			CLI_ERRO_LOG_STDERR(false, "%s Magic number not found", v);
		return 0;
	}

	if (md->max_peers < 1 || md->max_peers > BSR_PEERS_MAX) {
		CLI_ERRO_LOG_STDERR(false, "%s max-peers value %d out of bounds",
			v, md->max_peers);
		return 0;
	}
	if (md->node_id < -1 || md->node_id > BSR_PEERS_MAX + 1) {
		CLI_ERRO_LOG_STDERR(false, "%s device node-id value %d out of bounds",
			v, md->node_id);
		return 0;
	}
	for (n = 0; n < md->max_peers; n++) {
		if (md->peers[n].bitmap_index < -1 || md->peers[n].bitmap_index > BSR_PEERS_MAX + 1) {
			CLI_ERRO_LOG_STDERR(false, "%s peer device %d node-id value %d out of bounds",
				v, n, md->peers[n].bitmap_index);
			return 0;
		}
	}

	al_size_sect = md->al_stripes * md->al_stripe_size_4k * 8;

	switch(md_index) {
	default:
	case BSR_MD_INDEX_INTERNAL:
	case BSR_MD_INDEX_FLEX_EXT:
		if (md->al_offset != MD_AL_OFFSET_07) {
			CLI_ERRO_LOG_STDERR(false, "%s Magic number (al_offset) not found", v);
			CLI_ERRO_LOG_STDERR(false, "\texpected: %d, found %d",
				MD_AL_OFFSET_07, md->al_offset);
			return 0;
		}
		if (md->bm_offset != MD_AL_OFFSET_07 + al_size_sect) {
			CLI_ERRO_LOG_STDERR(false, "%s bm_offset: expected %d, found %d", v,
				MD_AL_OFFSET_07 + al_size_sect, md->bm_offset);
			return 0;
		}
		break;
	case BSR_MD_INDEX_FLEX_INT:
		if (md->al_offset != -al_size_sect) {
			CLI_ERRO_LOG_STDERR(false, "%s al_offset: expected %d, found %d", v,
				-al_size_sect, md->al_offset);
			return 0;
		}

		md_size_sect = bm_bytes(md, ll_size >> 9) >> 9;
		md_size_sect = ALIGN(md_size_sect, 8);    /* align on 4K blocks */
		/* plus the "bsr meta data super block",
		 * and the activity log; unit still sectors */
		md_size_sect += MD_AL_OFFSET_07 + al_size_sect;

		if (md->bm_offset != -(int64_t)md_size_sect + MD_AL_OFFSET_07) {
			CLI_ERRO_LOG_STDERR(false, "strange bm_offset %d (expected: "D64")",
					md->bm_offset, -(int64_t)md_size_sect + MD_AL_OFFSET_07);
			return 0;
		};
		if (md->md_size_sect != md_size_sect) {
			CLI_ERRO_LOG_STDERR(false, "strange md_size_sect %u (expected: "U64")",
					md->md_size_sect, md_size_sect);
			if (f == BSR_V08) return 0;
			/* else not an error,
			 * was inconsistently implemented in v07 */
		}
		break;
	}

	/* FIXME consistency check, effevtive_size < ll_device_size,
	 * no overlap with internal meta data,
	 * no overlap of flexible meta data offsets/sizes
	 * ...
	 */

	return 1; /* VALID */
}

/*
 * these stay the same for 0.8, too:
 */

struct al_sector_cpu {
	uint32_t magic;
	uint32_t tr_number;
	struct {
		uint32_t pos;
		uint32_t extent;
	} updates[62];
	uint32_t xor_sum;
};

struct __packed al_sector_on_disk {
	be_u32 magic;
	be_u32 tr_number;
	struct __packed {
		be_u32 pos;
		be_u32 extent;
	} updates[62];
	be_u32 xor_sum;
	be_u32 pad;
};

int v07_al_disk_to_cpu(struct al_sector_cpu *al_cpu, struct al_sector_on_disk *al_disk)
{
	uint32_t xor_sum = 0;
	int i;
	al_cpu->magic = be32_to_cpu(al_disk->magic.be);
	al_cpu->tr_number = be32_to_cpu(al_disk->tr_number.be);
	for (i = 0; i < 62; i++) {
		al_cpu->updates[i].pos = be32_to_cpu(al_disk->updates[i].pos.be);
		al_cpu->updates[i].extent = be32_to_cpu(al_disk->updates[i].extent.be);
		xor_sum ^= al_cpu->updates[i].extent;
	}
	al_cpu->xor_sum = be32_to_cpu(al_disk->xor_sum.be);
	return al_cpu->magic == BSR_MAGIC &&
		al_cpu->xor_sum == xor_sum;
}

/*
 * -- BSR 8.0, 8.2, 8.3 --------------------------------------
 */

struct __packed md_on_disk_08 {
	be_u64 effective_size;	/* last agreed size. */
	be_u64 uuid[UI_SIZE];   // UUIDs.
	be_u64 device_uuid;
	be_u64 reserved_u64_1;
	be_u32 flags;
	be_u32 magic;
	be_u32 md_size_sect;
	be_s32 al_offset;	/* signed sector offset to this block */
	be_u32 al_nr_extents;	/* important for restoring the AL */
	be_s32 bm_offset;	/* signed sector offset to the bitmap, from here */
	be_u32 bm_bytes_per_bit;
	be_u32 la_peer_max_bio_size; /* last peer max_bio_size */

	/* see al_tr_number_to_on_disk_sector() */
	be_u32 al_stripes;
	be_u32 al_stripe_size_4k;

	be_u32 reserved_u32[1];

	char reserved[8 * 512 - (8*(UI_SIZE+3)+4*11)];
};

void md_disk_08_to_cpu(struct md_cpu *cpu, const struct md_on_disk_08 *disk)
{
	int i;

	memset(cpu, 0, sizeof(*cpu));
	cpu->effective_size = be64_to_cpu(disk->effective_size.be);
	cpu->current_uuid = be64_to_cpu(disk->uuid[UI_CURRENT].be);
	cpu->peers[0].bitmap_uuid = be64_to_cpu(disk->uuid[UI_BITMAP].be);
	for (i = 0; i < HISTORY_UUIDS_V08; i++)
		cpu->history_uuids[i] =
			be64_to_cpu(disk->uuid[UI_HISTORY_START + i].be);
	cpu->device_uuid = be64_to_cpu(disk->device_uuid.be);
	cpu->flags = be32_to_cpu(disk->flags.be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->md_size_sect = be32_to_cpu(disk->md_size_sect.be);
	cpu->al_offset = be32_to_cpu(disk->al_offset.be);
	cpu->al_nr_extents = be32_to_cpu(disk->al_nr_extents.be);
	cpu->bm_offset = be32_to_cpu(disk->bm_offset.be);
	cpu->bm_bytes_per_bit = be32_to_cpu(disk->bm_bytes_per_bit.be);
	cpu->la_peer_max_bio_size = be32_to_cpu(disk->la_peer_max_bio_size.be);
	cpu->max_peers = 1;
	cpu->al_stripes = be32_to_cpu(disk->al_stripes.be);
	cpu->al_stripe_size_4k = be32_to_cpu(disk->al_stripe_size_4k.be);

	/* not set? --> default to old fixed size activity log */
	if (cpu->al_stripes == 0 && cpu->al_stripe_size_4k == 0) {
		cpu->al_stripes = 1;
		cpu->al_stripe_size_4k = 8;
	}
}

void md_cpu_to_disk_08(struct md_on_disk_08 *disk, const struct md_cpu *cpu)
{
	int i;

	memset(disk, 0, sizeof(*disk));

	disk->effective_size.be = cpu_to_be64(cpu->effective_size);
	disk->uuid[UI_CURRENT].be = cpu_to_be64(cpu->current_uuid);
	disk->uuid[UI_BITMAP].be = cpu_to_be64(cpu->peers[0].bitmap_uuid);
	for (i = 0; i < HISTORY_UUIDS_V08; i++)
		disk->uuid[UI_HISTORY_START + i].be =
			cpu_to_be64(cpu->history_uuids[i]);
	disk->device_uuid.be = cpu_to_be64(cpu->device_uuid);
	disk->flags.be = cpu_to_be32(cpu->flags);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size_sect.be = cpu_to_be32(cpu->md_size_sect);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	disk->bm_bytes_per_bit.be = cpu_to_be32(cpu->bm_bytes_per_bit);
	disk->la_peer_max_bio_size.be = cpu_to_be32(cpu->la_peer_max_bio_size);
	disk->al_stripes.be = cpu_to_be32(cpu->al_stripes);
	disk->al_stripe_size_4k.be = cpu_to_be32(cpu->al_stripe_size_4k);
}

/*
 * -- BSR 8.4 --------------------------------------
 */

/* new in 8.4: 4k al transaction blocks */
#define AL_UPDATES_PER_TRANSACTION 64
#define AL_CONTEXT_PER_TRANSACTION 919
/* from BSR 8.4 linux/bsr/bsr_limits.h, BSR_AL_EXTENTS_MAX */
#define AL_EXTENTS_MAX  65534
enum al_transaction_types {
	AL_TR_UPDATE = 0,
	AL_TR_INITIALIZED = 0xffff
};
struct __packed al_4k_transaction_on_disk {
	/* don't we all like magic */
	be_u32	magic;

	/* to identify the most recent transaction block
	 * in the on disk ring buffer */
	be_u32	tr_number;

	/* checksum on the full 4k block, with this field set to 0. */
	be_u32	crc32c;

	/* type of transaction, special transaction types like:
	 * purge-all, set-all-idle, set-all-active, ... to-be-defined
	 * see also enum al_transaction_types */
	be_u16	transaction_type;

	/* we currently allow only a few thousand extents,
	 * so 16bit will be enough for the slot number. */

	/* how many updates in this transaction */
	be_u16	n_updates;

	/* maximum slot number, "al-extents" in bsr.conf speak.
	 * Having this in each transaction should make reconfiguration
	 * of that parameter easier. */
	be_u16	context_size;

	/* slot number the context starts with */
	be_u16	context_start_slot_nr;

	/* Some reserved bytes.  Expected usage is a 64bit counter of
	 * sectors-written since device creation, and other data generation tag
	 * supporting usage */
	be_u32	__reserved[4];

	/* --- 36 byte used --- */

	/* Reserve space for up to AL_UPDATES_PER_TRANSACTION changes
	 * in one transaction, then use the remaining byte in the 4k block for
	 * context information.  "Flexible" number of updates per transaction
	 * does not help, as we have to account for the case when all update
	 * slots are used anyways, so it would only complicate code without
	 * additional benefit.
	 */
	be_u16	update_slot_nr[AL_UPDATES_PER_TRANSACTION];

	/* but the extent number is 32bit, which at an extent size of 4 MiB
	 * allows to cover device sizes of up to 2**54 Byte (16 PiB) */
	be_u32	update_extent_nr[AL_UPDATES_PER_TRANSACTION];

	/* --- 420 bytes used (36 + 64*6) --- */

	/* 4096 - 420 = 3676 = 919 * 4 */
	be_u32	context[AL_CONTEXT_PER_TRANSACTION];
};

struct al_4k_cpu {
	uint32_t	magic;
	uint32_t	tr_number;
	uint32_t	crc32c;
	uint16_t	transaction_type;
	uint16_t	n_updates;
	uint16_t	context_size;
	uint16_t	context_start_slot_nr;
	uint32_t	__reserved[4];
	uint16_t	update_slot_nr[AL_UPDATES_PER_TRANSACTION];
	uint32_t	update_extent_nr[AL_UPDATES_PER_TRANSACTION];
	uint32_t	context[AL_CONTEXT_PER_TRANSACTION];
	uint32_t	is_valid;
};


/* --- */

int v84_al_disk_to_cpu(struct al_4k_cpu *al_cpu, struct al_4k_transaction_on_disk *al_disk)
{
	unsigned crc = 0;
	unsigned i;

	al_cpu->magic                 = be32_to_cpu(al_disk->magic.be);
	al_cpu->tr_number             = be32_to_cpu(al_disk->tr_number.be);
	al_cpu->crc32c                = be32_to_cpu(al_disk->crc32c.be);
	al_cpu->transaction_type      = be16_to_cpu(al_disk->transaction_type.be);
	al_cpu->n_updates             = be16_to_cpu(al_disk->n_updates.be);
	al_cpu->context_size          = be16_to_cpu(al_disk->context_size.be);
	al_cpu->context_start_slot_nr = be16_to_cpu(al_disk->context_start_slot_nr.be);

	/* reserverd al_disk->__reserved[4] */

	for (i=0; i < AL_UPDATES_PER_TRANSACTION; i++)
		al_cpu->update_slot_nr[i] = be16_to_cpu(al_disk->update_slot_nr[i].be);
	for (i=0; i < AL_UPDATES_PER_TRANSACTION; i++)
		al_cpu->update_extent_nr[i] = be32_to_cpu(al_disk->update_extent_nr[i].be);
	for (i=0; i < AL_CONTEXT_PER_TRANSACTION; i++)
		al_cpu->context[i] = be32_to_cpu(al_disk->context[i].be);

	al_disk->crc32c.be = 0;
	crc = crc32c(crc, (void*)al_disk, 4096);
	al_cpu->is_valid = (al_cpu->magic == BSR_AL_MAGIC && al_cpu->crc32c == crc);
	return al_cpu->is_valid;
}

/*
 * -- BSR 9.0 --------------------------------------
 */
/* struct meta_data_on_disk_9 is in bsr_meta_data.h */

void md_disk_09_to_cpu(struct md_cpu *cpu, const struct meta_data_on_disk_9 *disk)
{
	int p, i;

	memset(cpu, 0, sizeof(*cpu));
	cpu->effective_size = be64_to_cpu(disk->effective_size.be);
	cpu->device_uuid = be64_to_cpu(disk->device_uuid.be);
	cpu->flags = be32_to_cpu(disk->flags.be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->md_size_sect = be32_to_cpu(disk->md_size_sect.be);
	cpu->al_offset = be32_to_cpu(disk->al_offset.be);
	cpu->al_nr_extents = be32_to_cpu(disk->al_nr_extents.be);
	cpu->bm_offset = be32_to_cpu(disk->bm_offset.be);
	cpu->bm_bytes_per_bit = be32_to_cpu(disk->bm_bytes_per_bit.be);
	cpu->la_peer_max_bio_size = be32_to_cpu(disk->la_peer_max_bio_size.be);
	cpu->max_peers = be32_to_cpu(disk->bm_max_peers.be);
	cpu->node_id = be32_to_cpu(disk->node_id.be);
	cpu->al_stripes = be32_to_cpu(disk->al_stripes.be);
	cpu->al_stripe_size_4k = be32_to_cpu(disk->al_stripe_size_4k.be);

	if (cpu->max_peers > BSR_PEERS_MAX)
		cpu->max_peers = BSR_PEERS_MAX;

	cpu->current_uuid = be64_to_cpu(disk->current_uuid.be);
	for (p = 0; p < BSR_NODE_ID_MAX; p++) {
		cpu->peers[p].flags = be32_to_cpu(disk->peers[p].flags.be);
		cpu->peers[p].bitmap_index = be32_to_cpu(disk->peers[p].bitmap_index.be);
		cpu->peers[p].bitmap_uuid =
			be64_to_cpu(disk->peers[p].bitmap_uuid.be);
		cpu->peers[p].bitmap_dagtag =
			be64_to_cpu(disk->peers[p].bitmap_dagtag.be);

	}
	BUILD_BUG_ON(ARRAY_SIZE(cpu->history_uuids) != ARRAY_SIZE(disk->history_uuids));
	for (i = 0; i < ARRAY_SIZE(cpu->history_uuids); i++)
		cpu->history_uuids[i] = be64_to_cpu(disk->history_uuids[i].be);
}

void md_cpu_to_disk_09(struct meta_data_on_disk_9 *disk, const struct md_cpu *cpu)
{
	int p, i;

	memset(disk, 0, sizeof(*disk));
	disk->effective_size.be = cpu_to_be64(cpu->effective_size);
	disk->device_uuid.be = cpu_to_be64(cpu->device_uuid);
	disk->flags.be = cpu_to_be32(cpu->flags);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size_sect.be = cpu_to_be32(cpu->md_size_sect);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	disk->bm_bytes_per_bit.be = cpu_to_be32(cpu->bm_bytes_per_bit);
	disk->la_peer_max_bio_size.be = cpu_to_be32(cpu->la_peer_max_bio_size);
	disk->bm_max_peers.be = cpu_to_be32(cpu->max_peers);
	disk->node_id.be = cpu_to_be32(cpu->node_id);
	disk->al_stripes.be = cpu_to_be32(cpu->al_stripes);
	disk->al_stripe_size_4k.be = cpu_to_be32(cpu->al_stripe_size_4k);

	disk->current_uuid.be = cpu_to_be64(cpu->current_uuid);
	for (p = 0; p < BSR_NODE_ID_MAX; p++) {
		disk->peers[p].flags.be = cpu_to_be32(cpu->peers[p].flags);
		disk->peers[p].bitmap_index.be = cpu_to_be32(cpu->peers[p].bitmap_index);
		disk->peers[p].bitmap_uuid.be =
			cpu_to_be64(cpu->peers[p].bitmap_uuid);
		disk->peers[p].bitmap_dagtag.be =
			cpu_to_be64(cpu->peers[p].bitmap_dagtag);

	}
	BUILD_BUG_ON(ARRAY_SIZE(disk->history_uuids) != ARRAY_SIZE(cpu->history_uuids));
	for (i = 0; i < ARRAY_SIZE(disk->history_uuids); i++)
		disk->history_uuids[i].be = cpu_to_be64(cpu->history_uuids[i]);
}

/*
 * --------------------------------------------------
 */

/* pre declarations */
void m_get_gc(struct md_cpu *md, int node_id);
void m_show_gc(struct md_cpu *md, int node_id);
void m_set_gc(struct md_cpu *md, int node_id, char **argv, int argc);
int m_outdate_gc(struct md_cpu *md);
int m_invalidate_gc(struct md_cpu *md);
void m_get_uuid(struct md_cpu *md, int node_id);
void m_show_uuid(struct md_cpu *md, int node_id);
void m_set_uuid(struct md_cpu *md, int node_id, char **argv, int argc);
void m_get_v9_uuid(struct md_cpu *md, int node_id);
void m_show_v9_uuid(struct md_cpu *md, int node_id);
void m_set_v9_uuid(struct md_cpu *md, int node_id, char **argv, int argc);
int m_outdate_uuid(struct md_cpu *md);
int m_invalidate_uuid(struct md_cpu *md);
int m_invalidate_v9_uuid(struct md_cpu *md);

int generic_md_close(struct format *cfg);

int v06_md_cpu_to_disk(struct format *cfg);
int v06_md_disk_to_cpu(struct format *cfg);
int v06_parse(struct format *cfg, char **argv, int argc, int *ai);
int v06_md_open(struct format *cfg);
int v06_md_initialize(struct format *cfg, int do_disk_writes, int max_peers);

int v07_md_cpu_to_disk(struct format *cfg);
int v07_md_disk_to_cpu(struct format *cfg);
int v07_parse(struct format *cfg, char **argv, int argc, int *ai);
int v07_md_initialize(struct format *cfg, int do_disk_writes, int max_peers);

int v07_style_md_open(struct format *cfg);

int v08_md_open(struct format *cfg);
int v08_md_cpu_to_disk(struct format *cfg);
int v08_md_disk_to_cpu(struct format *cfg);
int v08_md_initialize(struct format *cfg, int do_disk_writes, int max_peers);
int v08_md_close(struct format *cfg);

int v09_md_disk_to_cpu(struct format *cfg);
int v09_md_cpu_to_disk(struct format *cfg);
int v09_md_initialize(struct format *cfg, int do_disk_writes, int max_peers);

/* return codes for md_open */
enum {
	VALID_MD_FOUND = 0,
	NO_VALID_MD_FOUND = -1,
	VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION = -2,
};

struct format_ops f_ops[] = {
	[BSR_V06] = {
		     .name = "v06",
		     .args = (char *[]){"minor", NULL},
		     .parse = v06_parse,
		     .open = v06_md_open,
		     .close = generic_md_close,
		     .md_initialize = v06_md_initialize,
		     .md_disk_to_cpu = v06_md_disk_to_cpu,
		     .md_cpu_to_disk = v06_md_cpu_to_disk,
		     .get_gi = m_get_gc,
		     .show_gi = m_show_gc,
		     .set_gi = m_set_gc,
		     .outdate_gi = m_outdate_gc,
		     .invalidate_gi = m_invalidate_gc,
		     },
	[BSR_V07] = {
		     .name = "v07",
		     .args = (char *[]){"device", "index", NULL},
		     .parse = v07_parse,
		     .open = v07_style_md_open,
		     .close = generic_md_close,
		     .md_initialize = v07_md_initialize,
		     .md_disk_to_cpu = v07_md_disk_to_cpu,
		     .md_cpu_to_disk = v07_md_cpu_to_disk,
		     .get_gi = m_get_gc,
		     .show_gi = m_show_gc,
		     .set_gi = m_set_gc,
		     .outdate_gi = m_outdate_gc,
		     .invalidate_gi = m_invalidate_gc,
		     },
	[BSR_V08] = {
		     .name = "v08",
		     .args = (char *[]){"device", "index", NULL},
		     .parse = v07_parse,
		     .open = v08_md_open,
		     .close = v08_md_close,
		     .md_initialize = v08_md_initialize,
		     .md_disk_to_cpu = v08_md_disk_to_cpu,
		     .md_cpu_to_disk = v08_md_cpu_to_disk,
		     .get_gi = m_get_uuid,
		     .show_gi = m_show_uuid,
		     .set_gi = m_set_uuid,
		     .outdate_gi = m_outdate_uuid,
		     .invalidate_gi = m_invalidate_uuid,
		     },
	[BSR_V09] = {
		     .name = "v09",
		     .args = (char *[]){"device", "index", NULL},
		     .parse = v07_parse,
		     .open = v08_md_open,
		     .close = v08_md_close,
		     .md_initialize = v09_md_initialize,
		     .md_disk_to_cpu = v09_md_disk_to_cpu,
		     .md_cpu_to_disk = v09_md_cpu_to_disk,
		     .get_gi = m_get_v9_uuid,
		     .show_gi = m_show_v9_uuid,
		     .set_gi = m_set_v9_uuid,
		     .outdate_gi = m_outdate_uuid,
		     .invalidate_gi = m_invalidate_v9_uuid,
		     },
};

static inline enum md_format format_version(struct format *cfg)
{
	return (cfg->ops - f_ops);
}
static inline int is_v06(struct format *cfg)
{
	return format_version(cfg) == BSR_V06;
}
static inline int is_v07(struct format *cfg)
{
	return format_version(cfg) == BSR_V07;
}
static inline int is_v08(struct format *cfg)
{
	return format_version(cfg) == BSR_V08;
}
static inline int is_v09(struct format *cfg)
{
	return format_version(cfg) == BSR_V09;
}

/******************************************
  Commands we know about:
 ******************************************/

struct meta_cmd {
	const char *name;
	const char *args;
	int (*function) (struct format *, char **argv, int argc);
	int show_in_usage:1;
	int node_id_required:1;
	int modifies_md:1;
	unsigned int is_status_cmd:1; // BSR-1031
};
/* Global command pointer, to be able to change behavior in helper functions
 * based on which top-level command is being processed. */
static struct meta_cmd *command;

/* pre declarations */
int meta_get_gi(struct format *cfg, char **argv, int argc);
int meta_show_gi(struct format *cfg, char **argv, int argc);
int meta_dump_md(struct format *cfg, char **argv, int argc);
int meta_apply_al(struct format *cfg, char **argv, int argc);
int meta_restore_md(struct format *cfg, char **argv, int argc);
int meta_verify_dump_file(struct format *cfg, char **argv, int argc);
int meta_create_md(struct format *cfg, char **argv, int argc);
int meta_wipe_md(struct format *cfg, char **argv, int argc);
int meta_outdate(struct format *cfg, char **argv, int argc);
int meta_invalidate(struct format *cfg, char **argv, int argc);
int meta_set_gi(struct format *cfg, char **argv, int argc);
int meta_read_dev_uuid(struct format *cfg, char **argv, int argc);
int meta_write_dev_uuid(struct format *cfg, char **argv, int argc);
int meta_dstate(struct format *cfg, char **argv, int argc);
int meta_chk_offline_resize(struct format *cfg, char **argv, int argc);
int meta_forget_peer(struct format *cfg, char **argv, int argc);

struct meta_cmd cmds[] = {
	{"get-gi", 0, meta_get_gi, 1, 1, 0, 1},
	{"show-gi", 0, meta_show_gi, 1, 1, 0, 1},
	{"dump-md", 0, meta_dump_md, 1, 0, 0, 0},
	{"restore-md", "file", meta_restore_md, 1, 0, 1, 0},
	{"verify-dump", "file", meta_verify_dump_file, 1, 0, 0, 0},
	{"apply-al", 0, meta_apply_al, 1, 0, 1, 0},
	{"wipe-md", 0, meta_wipe_md, 1, 0, 1, 0},
	{"outdate", 0, meta_outdate, 1, 0, 1, 0},
	{"invalidate", 0, meta_invalidate, 1, 0, 1, 0},
	{"dstate", 0, meta_dstate, 1, 0, 0, 1},
	{"read-dev-uuid", 0,  meta_read_dev_uuid, 0, 0, 0, 0},
	{"write-dev-uuid", "VAL", meta_write_dev_uuid, 0, 0, 1, 0},
	/* FIXME: Get and set node and peer ids */
	{"set-gi", ":::VAL:VAL:...", meta_set_gi, 0, 1, 1, 0},
	{"check-resize", 0, meta_chk_offline_resize, 1, 0, 1, 0},
	{"create-md",
		"[--peer-max-bio-size {val}] "
		"[--al-stripes {val}] "
		"[--al-stripe-size-kB {val}] "
		"{max_peers}",
		meta_create_md, 1, 0, 1, 0},
	{"forget-peer", 0, meta_forget_peer, 1, 1, 1, 0},
};

/*
 * generic helpers
 */

#define PREAD(cfg,b,c,d) pread_or_die((cfg),(b),(c),(d), __func__ )
#define PWRITE(cfg,b,c,d) pwrite_or_die((cfg),(b),(c),(d), __func__ )
/* Do we want to exit() right here,
 * or do we want to duplicate the error handling everywhere? */
void pread_or_die(struct format *cfg, void *buf, size_t count, off_t offset, const char* tag)
{
#ifdef _WIN_CLI_UPDATE
	if(cfg->md_handle == INVALID_HANDLE_VALUE){
		CLI_ERRO_LOG_STDERR(false, " pread_or_die : unable to use handle ");
		exit(10); 
	}
	HANDLE fd = cfg->md_handle; 
	BOOL err;
	OVERLAPPED ol = {0};
	ol.Offset = offset; 
	DWORD c; 
       	
	err = ReadFile(cfg->md_handle, buf, count, &c, &ol);
	
	if(err == FALSE){
		CLI_ERRO_LOG_STDERR(false, "Unable to read from file.\n GetLastError=%08x", GetLastError()); 
		CloseHandle(cfg->md_handle);
	}	
#else 	
	int fd = cfg->md_fd;
	ssize_t c = pread(fd, buf, count, offset);
#endif 
	if (verbose >= 2) {
		fflush(stdout);
		CLI_ERRO_LOG_STDERR(false, " %-26s: pread(%u, ...,%6lu,%12llu)", tag,
			fd, (unsigned long)count, (unsigned long long)offset);
		if (count & ((1<<12)-1))
			CLI_ERRO_LOG_STDERR(false, "\tcount will cause EINVAL on hard sect size != 512");
		if (offset & ((1<<12)-1))
			CLI_ERRO_LOG_STDERR(false, "\toffset will cause EINVAL on hard sect size != 512");
	}
	if (c < 0) {
		CLI_ERRO_LOG_STDERR(false, "pread(%u,...,%lu,%llu) in %s failed: %s",
			fd, (unsigned long)count, (unsigned long long)offset,
			tag, strerror(errno));
		exit(10);
	} else if ((size_t)c != count) {
		CLI_ERRO_LOG_STDERR(false, "confused in %s: expected to read %d bytes,"
			" actually read %d\n",
			tag, (int)count, (int)c);
		exit(10);
	}

	if (verbose > 10)
		fprintf_hex(stderr, offset, buf, count);
}

#define min(x,y) ((x) < (y) ? (x) : (y))
#define min3(x,y,z) (min(min(x,y),z))

void validate_offsets_or_die(struct format *cfg, size_t count, off_t offset, const char* tag)
{
	off_t al_offset = cfg->md_offset + cfg->md.al_offset * 512LL;
	off_t bm_offset = cfg->md_offset + cfg->md.bm_offset * 512LL;
	off_t min_offset;
	off_t max_offset;

	if (al_offset != cfg->al_offset)
		CLI_ERRO_LOG_STDERR(false, "%s: ambiguous al_offset: "U64" vs %llu",
			tag, cfg->al_offset, (unsigned long long)al_offset);
	if (bm_offset != cfg->bm_offset)
		CLI_ERRO_LOG_STDERR(false, "%s: ambiguous bm_offset: "U64" vs %llu",
			tag, cfg->bm_offset, (unsigned long long)bm_offset);
	min_offset = min3(cfg->md_offset, al_offset, bm_offset);
	max_offset = min_offset + cfg->md.md_size_sect * 512LL;
	if (min_offset < 0)
		CLI_ERRO_LOG_STDERR(false, "%s: negative minimum offset: %lld", tag, (long long)min_offset);

	/* If we wipe some old meta data block,
	 * that hopefully falls outside the range of the current meta data.
	 * Skip the range check below.  */
	if (offset != 0
	&&  (offset == cfg->wipe_fixed
	   ||offset == cfg->wipe_flex
	   ||offset == cfg->wipe_resize))
			return;

	if (offset < min_offset || (offset + count) > max_offset) {
		CLI_ERRO_LOG_STDERR(false, "%s: offset+count ("U64"+%zu) not in meta data area range ["U64"; "U64"], aborted",
			tag, offset, count, min_offset, max_offset);
		if (ignore_sanity_checks) {
			CLI_ERRO_LOG_STDERR(false, "Ignored due to --ignore-sanity-checks");
		} else {
			CLI_ERRO_LOG_STDERR(false, "If you want to force this, tell me to --ignore-sanity-checks");
			exit(10);
		}
	}
}

static unsigned n_writes = 0;
void pwrite_or_die(struct format *cfg, const void *buf, size_t count, off_t offset, const char* tag)
{
#ifdef _WIN_CLI_UPDATE
	HANDLE fd = cfg->md_handle; 
	DWORD c; 
	BOOL err; 
	OVERLAPPED ol = {0}; 
	ol.Offset = offset; 

	if(cfg->md_handle == INVALID_HANDLE_VALUE){
		CLI_ERRO_LOG_STDERR(false, " pwrite_or_die : unable to use handle "); 
		exit(10); 
	}
#else 	
	int fd = cfg->md_fd;
	ssize_t c;
#endif 
	validate_offsets_or_die(cfg, count, offset, tag);

	++n_writes;
	if (dry_run) {
		CLI_ERRO_LOG_STDERR(false, " %-26s: pwrite(%u, ...,%6lu,%12llu) SKIPPED DUE TO DRY-RUN",
			tag, fd, (unsigned long)count, (unsigned long long)offset);
		if (verbose > 10)
			fprintf_hex(stderr, offset, buf, count);
		return;
	}
#ifdef _WIN_CLI_UPDATE
	err = WriteFile(cfg->md_handle, buf, count, &c, &ol);
	
	if(err == FALSE){
		CLI_ERRO_LOG_STDERR(false, "Unable to write file. ");
		CloseHandle(cfg->md_handle);	
	}
#else 	
	c = pwrite(fd, buf, count, offset);
#endif 
	if (verbose >= 2) {
		fflush(stdout);
		CLI_ERRO_LOG_STDERR(false, " %-26s: pwrite(%u, ...,%6lu,%12llu)", tag,
			fd, (unsigned long)count, (unsigned long long)offset);
		if (count & ((1<<12)-1))
			CLI_ERRO_LOG_STDERR(false, "\tcount will cause EINVAL on hard sect size != 512");
		if (offset & ((1<<12)-1))
			CLI_ERRO_LOG_STDERR(false, "\toffset will cause EINVAL on hard sect size != 512");
	}
	if (c < 0) {
		CLI_ERRO_LOG_STDERR(false, "pwrite(%u,...,%lu,%llu) in %s failed: %s",
			fd, (unsigned long)count, (unsigned long long)offset,
			tag, strerror(errno));
		exit(10);
	} else if ((size_t)c != count) {
		/* FIXME we might just now have corrupted the on-disk data */
		CLI_ERRO_LOG_STDERR(false, "confused in %s: expected to write %d bytes,"
			" actually wrote %d\n", tag, (int)count, (int)c);
		exit(10);
	}
}

size_t pwrite_with_limit_or_die(struct format *cfg, const void *buf, size_t count, off_t offset, off_t limit, const char* tag)
{
	if (offset >= limit) {
		CLI_ERRO_LOG_STDERR(false, "confused in %s: offset (%llu) > limit (%llu)",
			tag, (unsigned long long)offset, (unsigned long long)limit);
		exit(10);
	}
	if (count > limit - offset) {
		CLI_ERRO_LOG_STDERR(false, "in %s: truncating byte count from %lu to %lu", tag,
				(unsigned long)count,
				(unsigned long)(limit -offset));
		count = limit - offset;
	}
	pwrite_or_die(cfg, buf, count, offset, tag);
	return count;
}

void m_get_gc(struct md_cpu *md, int node_id __attribute((unused)))
{
	dt_print_gc(md->gc);
}

void m_show_gc(struct md_cpu *md, int node_id __attribute((unused)))
{
	dt_pretty_print_gc(md->gc);
}

void m_get_uuid(struct md_cpu *md, int node_id)
{
	uint64_t uuids[] = {
		[UI_CURRENT] = md->current_uuid,
		[UI_BITMAP] = md->peers[node_id].bitmap_uuid,
		[UI_HISTORY_START] = md->history_uuids[0],
		[UI_HISTORY_END] = md->history_uuids[1],
	};

	dt_print_uuids(uuids, md->flags);
}

void m_show_uuid(struct md_cpu *md, int node_id)
{
	uint64_t uuids[] = {
		[UI_CURRENT] = md->current_uuid,
		[UI_BITMAP] = md->peers[node_id].bitmap_uuid,
		[UI_HISTORY_START] = md->history_uuids[0],
		[UI_HISTORY_END] = md->history_uuids[1],
	};

	dt_pretty_print_uuids(uuids, md->flags);
}

void m_get_v9_uuid(struct md_cpu *md, int node_id)
{
	uint64_t uuids[] = {
		[UI_CURRENT] = md->current_uuid,
		[UI_BITMAP] = md->peers[node_id].bitmap_uuid,
		[UI_HISTORY_START] = md->history_uuids[0],
		[UI_HISTORY_END] = md->history_uuids[1],
	};

	dt_print_v9_uuids(uuids, md->flags, md->peers[node_id].flags);
}

void m_show_v9_uuid(struct md_cpu *md, int node_id)
{
	uint64_t uuids[] = {
		[UI_CURRENT] = md->current_uuid,
		[UI_BITMAP] = md->peers[node_id].bitmap_uuid,
		[UI_HISTORY_START] = md->history_uuids[0],
		[UI_HISTORY_END] = md->history_uuids[1],
	};

	dt_pretty_print_v9_uuids(uuids, md->flags, md->peers[node_id].flags);
}

int m_strsep_u32(char **s, uint32_t *val)
{
	char *t, *e;
	unsigned long v;

	if ((t = strsep(s, ":"))) {
		if (strlen(t)) {
			e = t;
			errno = 0;
			v = strtoul(t, &e, 0);
			if (*e != 0) {
				CLI_ERRO_LOG_STDERR(false, "'%s' is not a number.", *s);
				exit(10);
			}
			if (errno) {
				CLI_ERRO_LOG_STDERR(false, "'%s': ", *s);
				perror(0);
				exit(10);
			}
			if (v > 0xFFffFFffUL) {
				CLI_ERRO_LOG_STDERR(false, 
					"'%s' is out of range (max 0xFFffFFff).\n",
					*s);
				exit(10);
			}
			*val = (uint32_t)v;
		}
		return 1;
	}
	return 0;
}

int m_strsep_u64(char **s, uint64_t *val)
{
	char *t, *e;
	uint64_t v;

	if ((t = strsep(s, ":"))) {
		if (strlen(t)) {
			e = t;
			errno = 0;
			v = strto_u64(t, &e, 16);
			if (*e != 0) {
				CLI_ERRO_LOG_STDERR(false, "'%s' is not a number.", *s);
				exit(10);
			}
			if (errno) {
				CLI_ERRO_LOG_STDERR(false, "'%s': ", *s);
				perror(0);
				exit(10);
			}
			*val = v;
		}
		return 1;
	}
	return 0;
}

int m_strsep_bit(char **s, uint32_t *val, int mask)
{
	uint32_t d;
	int rv;

	d = *val & mask ? 1 : 0;

	rv = m_strsep_u32(s, &d);

	if (d > 1) {
		CLI_ERRO_LOG_STDERR(false, "'%d' is not 0 or 1.", d);
		exit(10);
	}

	if (d)
		*val |= mask;
	else
		*val &= ~mask;

	return rv;
}

void m_set_gc(struct md_cpu *md, int node_id __attribute((unused)), char **argv, int argc __attribute((unused)))
{
	char **str;

	str = &argv[0];

	do {
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_CONSISTENT)) break;
		if (!m_strsep_u32(str, &md->gc[HumanCnt])) break;
		if (!m_strsep_u32(str, &md->gc[TimeoutCnt])) break;
		if (!m_strsep_u32(str, &md->gc[ConnectedCnt])) break;
		if (!m_strsep_u32(str, &md->gc[ArbitraryCnt])) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_PRIMARY_IND)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_CONNECTED_IND)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_FULL_SYNC)) break;
	} while (false);
}

void m_set_uuid(struct md_cpu *md, int node_id, char **argv, int argc __attribute((unused)))
{
	char **str;
	int i;

	str = &argv[0];

	do {
		if (!m_strsep_u64(str, &md->current_uuid)) break;
		if (!m_strsep_u64(str, &md->peers[node_id].bitmap_uuid)) break;
		for (i = 0; i < HISTORY_UUIDS_V08; i++)
			if (!m_strsep_u64(str, &md->history_uuids[i])) return;
		if (!m_strsep_bit(str, &md->flags, MDF_CONSISTENT)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_WAS_UP_TO_DATE)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_PRIMARY_IND)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_CONNECTED_IND)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_FULL_SYNC)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_PEER_OUT_DATED)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_CRASHED_PRIMARY)) break;
	} while (false);
}

void m_set_v9_uuid(struct md_cpu *md, int node_id, char **argv, int argc __attribute((unused)))
{
	char **str;
	int i;

	str = &argv[0];

	do {
		if (!m_strsep_u64(str, &md->current_uuid)) break;
		if (!m_strsep_u64(str, &md->peers[node_id].bitmap_uuid)) break;
		for (i = 0; i < HISTORY_UUIDS_V08; i++)
			if (!m_strsep_u64(str, &md->history_uuids[i])) return;
		if (!m_strsep_bit(str, &md->flags, MDF_CONSISTENT)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_WAS_UP_TO_DATE)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_PRIMARY_IND)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_CRASHED_PRIMARY)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_AL_CLEAN)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_AL_DISABLED)) break;
		if (!m_strsep_bit(str, &md->peers[node_id].flags, MDF_PEER_CONNECTED)) break;
		if (!m_strsep_bit(str, &md->peers[node_id].flags, MDF_PEER_OUTDATED)) break;
		if (!m_strsep_bit(str, &md->peers[node_id].flags, MDF_PEER_FENCING)) break;
		if (!m_strsep_bit(str, &md->peers[node_id].flags, MDF_PEER_FULL_SYNC)) break;
		if (!m_strsep_bit(str, &md->peers[node_id].flags, MDF_PEER_DEVICE_SEEN)) break;
	} while (false);
}

int m_outdate_gc(struct md_cpu *md __attribute((unused)))
{
	CLI_ERRO_LOG_STDERR(false, "Can not outdate GC based meta data!");

	return 5;
}

int m_outdate_uuid(struct md_cpu *md)
{
	if ( !(md->flags & MDF_CONSISTENT) ) {
		return 5;
	}

	md->flags &= ~MDF_WAS_UP_TO_DATE;

	return 0;
}

int m_invalidate_gc(struct md_cpu *md)
{
	md->gc[Flags] &= ~MDF_CONSISTENT;
	md->gc[Flags] |= MDF_FULL_SYNC;

	return 5;
}

int m_invalidate_uuid(struct md_cpu *md)
{
	md->flags &= ~MDF_CONSISTENT;
	md->flags &= ~MDF_WAS_UP_TO_DATE;
	md->flags |= MDF_FULL_SYNC;

	return 0;
}

int m_invalidate_v9_uuid(struct md_cpu *md)
{
	int node_id;

	md->flags &= ~MDF_CONSISTENT;
	md->flags &= ~MDF_WAS_UP_TO_DATE;

	for (node_id = 0; node_id < BSR_NODE_ID_MAX; node_id++) {
		md->peers[node_id].flags |= MDF_PEER_FULL_SYNC;
	}

	return 0;
}


/******************************************
 begin of v06 {{{
 ******************************************/

int v06_md_disk_to_cpu(struct format *cfg)
{
	PREAD(cfg, on_disk_buffer, sizeof(struct md_on_disk_06), cfg->md_offset);
	md_disk_06_to_cpu(&cfg->md, (struct md_on_disk_06*)on_disk_buffer);
	return v06_validate_md(cfg);
}

int v06_md_cpu_to_disk(struct format *cfg)
{
	if (v06_validate_md(cfg))
		return -1;
	md_cpu_to_disk_06(on_disk_buffer, &cfg->md);
	PWRITE(cfg, on_disk_buffer, sizeof(struct md_on_disk_06), cfg->md_offset);
	return 0;
}

int v06_parse(struct format *cfg, char **argv, int argc, int *ai)
{
	unsigned long minor;
	char *e;

	if (argc < 1) {
		CLI_ERRO_LOG_STDERR(false, "Too few arguments for format");
		exit(20);
	}

	e = argv[0];
	minor = strtol(argv[0], &e, 0);
	if (*e != 0 || minor > 255UL) {
		CLI_ERRO_LOG_STDERR(false, "'%s' is not a valid minor number.", argv[0]);
		exit(20);
	}
	if (asprintf(&e, "%s/bsr%lu", BSR_LIB_DIR, minor) <= 18) {
		CLI_ERRO_LOG_STDERR(false, "asprintf() failed.");
		exit(20);
	};
	cfg->md_device_name = e;

	*ai += 1;

	return 0;
}

int v06_md_open(struct format *cfg)
{
	struct stat sb;

	cfg->md_fd = open(cfg->md_device_name, O_RDWR);

	if (cfg->md_fd == -1) {
		PERROR("open(%s) failed", cfg->md_device_name);
		return NO_VALID_MD_FOUND;
	}

	if (fstat(cfg->md_fd, &sb)) {
		PERROR("fstat() failed");
		return NO_VALID_MD_FOUND;
	}

	if (!S_ISREG(sb.st_mode)) {
		CLI_ERRO_LOG_STDERR(false, "'%s' is not a plain file!",
			cfg->md_device_name);
		return NO_VALID_MD_FOUND;
	}

	if (cfg->ops->md_disk_to_cpu(cfg)) {
		return NO_VALID_MD_FOUND;
	}

	return VALID_MD_FOUND;
}

int generic_md_close(struct format *cfg)
{
#ifdef _WIN_CLI_UPDATE
	if(cfg->md_handle != INVALID_HANDLE_VALUE){
		CloseHandle(cfg->md_handle); 
	}
#else 	
	/* On /dev/ram0 we may not use O_SYNC for some kernels (eg. RHEL6 2.6.32),
	 * and fsync() returns EIO, too. So we don't do error checking here. */
	fsync(cfg->md_fd);
	if (close(cfg->md_fd)) {
		PERROR("close() failed");
		return -1;
	}
#endif 	
	return 0;
}

int v06_md_initialize(struct format *cfg,
		      int do_disk_writes __attribute((unused)),
		      int max_peers __attribute((unused)))
{
	cfg->md.gc[Flags] = 0;
	cfg->md.gc[HumanCnt] = 1;	/* THINK 0? 1? */
	cfg->md.gc[TimeoutCnt] = 1;
	cfg->md.gc[ConnectedCnt] = 1;
	cfg->md.gc[ArbitraryCnt] = 1;
	cfg->md.max_peers = 1;
	cfg->md.magic = BSR_MD_MAGIC_06;
	return 0;
}

/******************************************
  }}} end of v06
 ******************************************/

static uint64_t max_usable_sectors(struct format *cfg)
{
	/* We currently have two possible layouts:
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
	 * There also used to be the fixed size internal meta data,
	 * which covers the last 128 MB of the device,
	 * and has the same layout as the "external:" above.
	 */
	if(cfg->md_index == BSR_MD_INDEX_INTERNAL ||
	   cfg->md_index == BSR_MD_INDEX_FLEX_INT) {
		/* for internal meta data, the available storage is limitted by
		 * the first meta data sector, even if the available bitmap
		 * space would support more. */
		return	min3(cfg->md_offset,
			     cfg->al_offset,
			     cfg->bm_offset ) >> 9;
	} else {
		/* For external meta data,
		 * we are limited by available on-disk bitmap space.
		 * Ok, and by the lower level storage device;
		 * which we don't know about here :-( */
		ASSERT(cfg->md.bm_bytes_per_bit == 4096);

		return
			/* bitmap sectors */
			(uint64_t)(cfg->md.md_size_sect - cfg->md.bm_offset)
			* 512	/* sector size */
			* 8	/* bits per byte */
			/ 64	/* 64 bit words, for interoperability */
			/ cfg->md.max_peers
			* 64	/* back to bits, per bitmap slot */
				/* storage bytes per bitmap bit;
				 * currently always 4096 */
			* cfg->md.bm_bytes_per_bit
			/ 512;	/* and back to sectors */;
	}
#undef min
}

void re_initialize_md_offsets(struct format *cfg)
{
	uint64_t md_size_sect;
	int al_size_sect;

	/* These two are needed for bm_bytes()... Ensure sane defaults... */
	if (cfg->md.bm_bytes_per_bit == 0)
		cfg->md.bm_bytes_per_bit = DEFAULT_BM_BLOCK_SIZE;
	if (cfg->md.max_peers == 0)
		cfg->md.max_peers = 1;

	al_size_sect = cfg->md.al_stripes * cfg->md.al_stripe_size_4k * 8;
	switch(cfg->md_index) {
	default:
		cfg->md.md_size_sect = MD_RESERVED_SECT_07;
		cfg->md.al_offset = MD_AL_OFFSET_07;
		cfg->md.bm_offset = cfg->md.al_offset + al_size_sect;
		break;
	case BSR_MD_INDEX_FLEX_EXT:
		/* just occupy the full device; unit: sectors */
		cfg->md.md_size_sect = cfg->bd_size >> 9;
		cfg->md.al_offset = MD_AL_OFFSET_07;
		cfg->md.bm_offset = cfg->md.al_offset + al_size_sect;
		break;
	case BSR_MD_INDEX_INTERNAL: /* only v07 */
		cfg->md.md_size_sect = MD_RESERVED_SECT_07;
		cfg->md.al_offset = MD_AL_OFFSET_07;
		cfg->md.bm_offset = MD_BM_OFFSET_07;
		break;
	case BSR_MD_INDEX_FLEX_INT:
		/* al size is still fixed */
		cfg->md.al_offset = -al_size_sect;

		/* we need (slightly less than) ~ this much bitmap sectors: */
		md_size_sect = bm_bytes(&cfg->md, cfg->bd_size >> 9) >> 9;
		md_size_sect = ALIGN(md_size_sect, 8);    /* align on 4K blocks */
		if (md_size_sect > (MD_BM_MAX_BYTE_FLEX>>9)) {
			CLI_ERRO_LOG_STDERR(false, "Bitmap for that device got too large.");
			if (BITS_PER_LONG == 32)
				CLI_ERRO_LOG_STDERR(false, "Maybe try a 64bit arch?");
			exit(10);
		}
		/* plus the "bsr meta data super block",
		 * and the activity log; unit still sectors */
		md_size_sect += MD_AL_OFFSET_07 + al_size_sect;
		cfg->md.md_size_sect = md_size_sect;
		cfg->md.bm_offset = -md_size_sect + MD_AL_OFFSET_07;
		break;
	}
	cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512LL;
	cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512LL;
	cfg->max_usable_sect = max_usable_sectors(cfg);

	if (verbose >= 2) {
		CLI_ERRO_LOG_STDERR(false, "md_offset: "U64"", cfg->md_offset);
		CLI_ERRO_LOG_STDERR(false, "al_offset: "U64" (%d)", cfg->al_offset, cfg->md.al_offset);
		CLI_ERRO_LOG_STDERR(false, "bm_offset: "U64" (%d)", cfg->bm_offset, cfg->md.bm_offset);
		CLI_ERRO_LOG_STDERR(false, "md_size_sect: "U32"", cfg->md.md_size_sect);
		CLI_ERRO_LOG_STDERR(false, "max_usable_sect: "U64"", cfg->max_usable_sect);
	}
}

void initialize_al(struct format *cfg)
{
	unsigned int mx = cfg->md.al_stripes * cfg->md.al_stripe_size_4k;
	size_t al_size = mx * 4096;
	memset(on_disk_buffer, 0x00, al_size);
	if (format_version(cfg) >= BSR_V08) {
		/* BSR <= 8.3 does not care if it is all zero,
		 * or otherwise wrong magic.
		 *
		 * For 8.4 and 9.0, we initialize to something that is
		 * valid magic, valid crc, and transaction_type = 0xffff.
		 */
		struct al_4k_transaction_on_disk *al = on_disk_buffer;
		unsigned crc_be = 0;
		int i;
		for (i = 0; i < mx; i++, al++) {
			al->magic.be = cpu_to_be32(BSR_AL_MAGIC);
			al->transaction_type.be = cpu_to_be16(AL_TR_INITIALIZED);
			/* crc calculated once */
			if (i == 0)
				crc_be = cpu_to_be32(crc32c(0, (void*)al, 4096));
			al->crc32c.be = crc_be;
		}
	}
	pwrite_or_die(cfg, on_disk_buffer, al_size, cfg->al_offset,
		"md_initialize_common:AL");
}

void check_for_existing_data(struct format *cfg);

static void zeroout_bitmap(struct format *cfg)
{
	const size_t bitmap_bytes =
		ALIGN(bm_bytes(&cfg->md, cfg->bd_size >> 9), cfg->md_hard_sect_size);
	uint64_t range[2];
	int err;

	range[0] = cfg->bm_offset; /* start offset */
	range[1] = bitmap_bytes; /* len */

	CLI_ERRO_LOG_STDERR(false, "initializing bitmap (%u KB) to all zero",
		(unsigned int)(bitmap_bytes >> 10));

#ifdef _LIN
	// windwos not support. execute the fallback code.
	err = ioctl(cfg->md_fd, BLKZEROOUT, &range);
	if (!err)
		return;

	// BSR-715 change the error message
	CLI_ERRO_LOG_STDERR(false, "ioctl(%s, BLKZEROOUT, [%llu, %llu]) not support\n", cfg->md_device_name,
		(unsigned long long)range[0], (unsigned long long)range[1]);
#endif
	CLI_ERRO_LOG_STDERR(false, "Using slow(er) fallback.");;
	{
		/* need to sector-align this for O_DIRECT.
		 * "sector" here means hard-sect size, which may be != 512.
		 * Note that even though ALIGN does round up, for sector sizes
		 * of 512, 1024, 2048, 4096 Bytes, this will be fully within
		 * the claimed meta data area, since we already align all
		 * "interesting" parts of that to 4kB */
		size_t i = bitmap_bytes;
		off_t bm_on_disk_off = cfg->bm_offset;
		unsigned int percent_done = 0;
		unsigned int percent_last_report = 0;
		size_t chunk;

		memset(on_disk_buffer, 0x00, buffer_size);
		while (i) {
			chunk = buffer_size < i ? buffer_size : i;
			pwrite_or_die(cfg, on_disk_buffer,
				chunk, bm_on_disk_off,
				"md_initialize_common:BM");
			bm_on_disk_off += chunk;
			i -= chunk;
			percent_done = 100 * (bitmap_bytes - i) / bitmap_bytes;
			if (percent_done != percent_last_report) {
				CLI_ERRO_LOG_STDERR(false, "\r%u%%", percent_done);
				percent_last_report = percent_done;
			}
		}
		CLI_ERRO_LOG_STDERR(false, "\r100%%");	
	}

}

/* MAYBE DOES DISK WRITES!! */
int md_initialize_common(struct format *cfg, int do_disk_writes)
{
	cfg->md.al_nr_extents = 257;    /* arbitrary. */
	cfg->md.bm_bytes_per_bit = DEFAULT_BM_BLOCK_SIZE;

	re_initialize_md_offsets(cfg);

	if (!do_disk_writes)
		return 0;

	check_for_existing_data(cfg);

	/* do you want to initialize al to something more useful? */
	printf("initializing activity log\n");
	if (MD_AL_MAX_SECT_07 * 512 > buffer_size) {
		CLI_ERRO_LOG_STDERR(false, "%s:%u: LOGIC BUG", __FILE__, __LINE__);
		exit(111);
	}
	initialize_al(cfg);

	/* We initialize the bitmap to all 0 for the use case that someone
	* might use set-gi to pretend that the backend devices are completely
	* in sync. (I.e. thinly provisioned storage, all zeroes)
	*
	* In case it current UUID is left at UUID_JUST_CREATED the kernel
	* driver will set all bits to 1 when using it in a handshake...
	*/
	zeroout_bitmap(cfg);

	return 0;
}

/******************************************
 begin of v07 {{{
 ******************************************/

uint64_t v07_style_md_get_byte_offset(const int idx, const uint64_t bd_size)
{
	uint64_t offset;

	switch(idx) {
	default: /* external, some index */
		offset = MD_RESERVED_SECT_07 * idx * 512;
		break;
	case BSR_MD_INDEX_INTERNAL:
		offset = (bd_size & ~4095LLU)
		    - MD_RESERVED_SECT_07 * 512;
		break;
	case BSR_MD_INDEX_FLEX_INT:
		/* sizeof(struct md_on_disk_07) == 4k
		 * position: last 4k aligned block of 4k size */
		offset  = bd_size - 4096LLU;
		offset &= ~4095LLU;
		break;
	case BSR_MD_INDEX_FLEX_EXT:
		offset = 0;
		break;
	}
	return offset;
}

void printf_al_07(struct format *cfg, struct al_sector_on_disk *al_disk)
{
	struct al_sector_cpu al_cpu;
	unsigned s, i;
	unsigned max_slot_nr = 0;
	for (s = 0; s < MD_AL_MAX_SECT_07; s++) {
		int ok = v07_al_disk_to_cpu(&al_cpu, al_disk + s);
		printf("#     sector %2u { %s\n", s, ok ? "valid" : "invalid");
		printf("# \tmagic: 0x%08x\n", al_cpu.magic);
		printf("# \ttr: %10u\n", al_cpu.tr_number);
		for (i = 0; i < 62; i++) {
			printf("# \t%2u: %10u %10u\n", i,
				al_cpu.updates[i].pos,
				al_cpu.updates[i].extent);
			if (al_cpu.updates[i].pos > max_slot_nr &&
			    al_cpu.updates[i].pos != -1U)
				max_slot_nr = al_cpu.updates[i].pos;
		}
		printf("# \txor: 0x%08x\n", al_cpu.xor_sum);
		printf("#     }\n");
	}
	if (max_slot_nr >= cfg->md.al_nr_extents)
		printf(
		"### CAUTION: maximum slot number found in AL: %u\n"
		"### CAUTION: but 'super-block' al-extents is: %u\n",
		max_slot_nr, cfg->md.al_nr_extents);
}

void printf_al_84(struct format *cfg, struct al_4k_transaction_on_disk *al_disk,
	unsigned block_nr_offset, unsigned N)
{
	struct al_4k_cpu al_cpu;
	unsigned b, i;
	unsigned max_slot_nr = 0;
	for (b = 0; b < N; b++) {
		int ok = v84_al_disk_to_cpu(&al_cpu, al_disk + b);
		if (!ok) {
			printf("#     block %2u { INVALID }\n", b + block_nr_offset);
			continue;
		}
		if (al_cpu.transaction_type == 0xffff) {
			printf("#     block %2u { INITIALIZED }\n", b + block_nr_offset);
			continue;
		}
		printf("#     block %2u {\n", b + block_nr_offset);
		printf("# \tmagic: 0x%08x\n", al_cpu.magic);
		printf("# \ttype: 0x%04x\n", al_cpu.transaction_type);
		printf("# \ttr: %10u\n", al_cpu.tr_number);
		printf("# \tactive set size: %u\n", al_cpu.context_size);
		if (al_cpu.context_size -1 > max_slot_nr)
			max_slot_nr = al_cpu.context_size -1;
		for (i = 0; i < AL_CONTEXT_PER_TRANSACTION; i++) {
			unsigned slot = al_cpu.context_start_slot_nr + i;
			if (al_cpu.context[i] == ~0U && slot >= al_cpu.context_size)
				continue;
			if (slot > max_slot_nr)
				max_slot_nr = slot;
			printf("# \t%2u: %10u %10u\n", i, slot, al_cpu.context[i]);
		}
		printf("# \tupdates: %u\n", al_cpu.n_updates);
		for (i = 0; i < AL_UPDATES_PER_TRANSACTION; i++) {
			if (i >= al_cpu.n_updates &&
				al_cpu.update_slot_nr[i] == UINT16_MAX)
				continue;
			printf("# \t%2u: %10u %10u\n", i,
				al_cpu.update_slot_nr[i],
				al_cpu.update_extent_nr[i]);
			if (al_cpu.update_slot_nr[i] > max_slot_nr)
				max_slot_nr = al_cpu.update_slot_nr[i];
		}
		printf("# \tcrc32c: 0x%08x\n", al_cpu.crc32c);
		printf("#     }\n");
	}
	if (max_slot_nr >= cfg->md.al_nr_extents)
		printf(
		"### CAUTION: maximum slot number found in AL: %u\n"
		"### CAUTION: but 'super-block' al-extents is: %u\n",
		max_slot_nr, cfg->md.al_nr_extents);
}

void printf_al(struct format *cfg)
{
	off_t al_on_disk_off = cfg->al_offset;
	off_t al_size = cfg->md.al_stripes * cfg->md.al_stripe_size_4k * 4096;
	struct al_sector_on_disk *al_512_disk = on_disk_buffer;
	struct al_4k_transaction_on_disk *al_4k_disk = on_disk_buffer;
	unsigned block_nr_offset = 0;
	unsigned N;

	int is_al_84 = is_v09(cfg) ||
		(is_v08(cfg) &&
		(cfg->md.al_stripes != 1 || cfg->md.al_stripe_size_4k != 8));

	printf("# al {\n");

	while (al_size) {
		off_t chunk = al_size;
		if (chunk > buffer_size)
			chunk = buffer_size;
		ASSERT(chunk);
		pread_or_die(cfg, on_disk_buffer, chunk, al_on_disk_off, "printf_al");
		al_on_disk_off += chunk;
		al_size -= chunk;
		N = chunk/4096;

		/* FIXME
		 * we should introduce a new meta data "super block" magic, so we won't
		 * have the same super block with two different activity log
		 * transaction layouts */
		if (format_version(cfg) < BSR_V08)
			printf_al_07(cfg, al_512_disk);

		/* looks like we have the new al format */
		else if (is_al_84 ||
			 BSR_AL_MAGIC == be32_to_cpu(al_4k_disk[0].magic.be) ||
			 BSR_AL_MAGIC == be32_to_cpu(al_4k_disk[1].magic.be)) {
			is_al_84 = 1;
			printf_al_84(cfg, al_4k_disk, block_nr_offset, N);
		}

		/* try the old al format anyways */
		else
			printf_al_07(cfg, al_512_disk);

		block_nr_offset += N;
		if (al_size && !is_al_84) {
			printf("### UNEXPECTED ACTIVITY LOG SIZE!\n");
		}
	}
	printf("# }\n");
}

/* One activity log extent represents 4M of storage,
 * one bit corresponds to 4k.
 *                       4M / 4k / 8bit per byte */
#define BM_BYTES_PER_AL_EXT	(1UL << (22 - 12 - 3))

struct al_cursor {
	unsigned i;
	uint32_t tr_number;
};

static int replay_al_07(struct format *cfg, uint32_t *hot_extent)
{
	unsigned int mx;
	struct al_sector_cpu al_cpu[MD_AL_MAX_SECT_07];
	unsigned char valid[MD_AL_MAX_SECT_07];

	struct al_sector_on_disk *al_disk = on_disk_buffer;

	unsigned b, i;

	int found_valid = 0;
	struct al_cursor oldest = { 0, };
	struct al_cursor newest = { 0, };

	/* Endian convert, validate, and find oldest to newest log range.
	 * In contrast to the 8.4 log format, this log format does NOT
	 * use all log space, but only as many sectors as absolutely necessary.
	 *
	 * We need to trust the "al_nr_extents" setting in the "super block".
	 */
#define AL_EXTENTS_PT 61
	/* mx = 1 + div_ceil(al_nr_extents, AL_EXTENTS_PT); */
	mx = 1 + (cfg->md.al_nr_extents + AL_EXTENTS_PT -1) / AL_EXTENTS_PT;
	for (b = 0; b < mx; b++) {
		valid[b] = v07_al_disk_to_cpu(al_cpu + b, al_disk + b);
		if (!valid[b])
		       continue;
		if (++found_valid == 1) {
			oldest.i = b;
			oldest.tr_number = al_cpu[b].tr_number;
			newest = oldest;
			continue;
		}

		d_expect(al_cpu[b].tr_number != oldest.tr_number);
		d_expect(al_cpu[b].tr_number != newest.tr_number);
		if ((int)al_cpu[b].tr_number - (int)oldest.tr_number < 0) {
			d_expect(oldest.tr_number - al_cpu[b].tr_number + b - oldest.i == mx);
			oldest.i = b;
			oldest.tr_number = al_cpu[b].tr_number;
		}
		if ((int)al_cpu[b].tr_number - (int)newest.tr_number > 0) {
			d_expect(al_cpu[b].tr_number - newest.tr_number == b - newest.i);
			newest.i = b;
			newest.tr_number = al_cpu[b].tr_number;
		}
	}

	if (!found_valid) {
		/* not even one transaction was valid.
		 * Has this ever been initialized correctly? */
		CLI_ERRO_LOG_STDERR(false, "No usable activity log found.");
		/* with up to 8.3 style activity log, this is NOT an error. */
		return 0;
	}

	/* we do expect at most one corrupt transaction, and only in case
	 * things went wrong during transaction write. */
	if (found_valid != mx) {
		CLI_ERRO_LOG_STDERR(false, "%u corrupt or uninitialized AL transactions found", mx - found_valid);
		CLI_ERRO_LOG_STDERR(false, "You can safely ignore this if this node was cleanly stopped (no crash).");
	}

	/* Any other paranoia checks possible with this log format? */

	/* Ok, so we found valid update transactions.  Reconstruct the "active
	 * set" at the time of the newest transaction. */

	/* wrap around */
	if (newest.i < oldest.i)
		newest.i += mx;

	for (b = oldest.i; b <= newest.i; b++) {
		unsigned idx = b % mx;
		if (!valid[idx])
			continue;

		/* This loop processes both "context" and "update" information.
		 * There is only one update, on index 0,
		 * which is why this loop counts down. */
		for (i = AL_EXTENTS_PT; (int)i >= 0; i--) {
			unsigned slot = al_cpu[idx].updates[i].pos;
			if (al_cpu[idx].updates[i].extent == ~0U)
				continue;
			if (slot >= AL_EXTENTS_MAX) {
				CLI_ERRO_LOG_STDERR(false, "slot number out of range: tr:%u slot:%u",
						idx, slot);
				continue;
			}
			hot_extent[slot] = al_cpu[idx].updates[i].extent;
		}
	}
	return found_valid;
}

static unsigned int al_tr_number_to_on_disk_slot(struct format *cfg, unsigned int b, unsigned int mx)
{
	const unsigned int stripes = cfg->md.al_stripes;
	const unsigned int stripe_size_4kB = cfg->md.al_stripe_size_4k;

	/* transaction number, modulo on-disk ring buffer wrap around */
	unsigned int t = b % mx;

	/* ... to aligned 4k on disk block */
	t = ((t % stripes) * stripe_size_4kB) + t/stripes;

	return t;
}


/* Expects the AL to be read into on_disk_buffer already.
 * Returns negative error code for non-interpretable data,
 * 0 for "just mark me clean, nothing more to do",
 * and positive if we have to apply something. */
int replay_al_84(struct format *cfg, uint32_t *hot_extent)
{
	const unsigned int mx = cfg->md.al_stripes * cfg->md.al_stripe_size_4k;
	struct al_4k_transaction_on_disk *al_disk = on_disk_buffer;
	struct al_4k_cpu *al_cpu = NULL;
	unsigned b, o, i;

	int found_valid = 0;
	int found_valid_updates = 0;
	struct al_cursor oldest = { 0, };
	struct al_cursor newest = { 0, };

	al_cpu = calloc(mx, sizeof(*al_cpu));
	if (!al_cpu) {
		CLI_ERRO_LOG_STDERR(false, "Could not calloc(%u, sizeof(*al_cpu))", mx);
		exit(30); /* FIXME sane exit codes */
	}

	/* endian convert, validate, and find oldest to newest log range */
	for (b = 0; b < mx; b++) {
		o = al_tr_number_to_on_disk_slot(cfg, b, mx);
		if (!v84_al_disk_to_cpu(al_cpu + b, al_disk + o))
		       continue;
		++found_valid;
		if (al_cpu[b].transaction_type == AL_TR_INITIALIZED)
			continue;
		d_expect(al_cpu[b].transaction_type == AL_TR_UPDATE);
		if (++found_valid_updates == 1) {
			oldest.i = b;
			oldest.tr_number = al_cpu[b].tr_number;
			newest = oldest;
			continue;
		}
		d_expect(al_cpu[b].tr_number != oldest.tr_number);
		d_expect(al_cpu[b].tr_number != newest.tr_number);
		if ((int)al_cpu[b].tr_number - (int)oldest.tr_number < 0) {
			d_expect(oldest.tr_number - al_cpu[b].tr_number + b - oldest.i == mx);
			oldest.i = b;
			oldest.tr_number = al_cpu[b].tr_number;
		}
		if ((int)al_cpu[b].tr_number - (int)newest.tr_number > 0) {
			d_expect(al_cpu[b].tr_number - newest.tr_number == b - newest.i);
			newest.i = b;
			newest.tr_number = al_cpu[b].tr_number;
		}
	}

	if (!found_valid) {
		/* not even one transaction was valid.
		 * Has this ever been initialized correctly? */
		CLI_ERRO_LOG_STDERR(false, "No usable activity log found. Do you need to create-md?");
		free(al_cpu);
		return -ENODATA;
	}

	/* we do expect at most one corrupt transaction, and only in case
	 * things went wrong during transaction write. */
	if (found_valid != mx)
		CLI_ERRO_LOG_STDERR(false, "%u corrupt AL transactions found", mx - found_valid);

	if (!found_valid_updates) {
		if (found_valid == mx)
			/* nothing to do, all slots are valid AL_TR_INITIALIZED */
			return 0;

		/* this is only expected, in case the _first_ transaction
		 * somehow failed. */
		if (!al_cpu[0].is_valid && found_valid == mx - 1)
			return 0;

		/* Hmm. Some transactions are valid.
		 * Some are not.
		 * This is not expected. */
		/* FIXME how do we want to handle this? */
		CLI_ERRO_LOG_STDERR(false, "No valid AL update transaction found.");
		return -EINVAL;
	}

	/* FIXME what do we do
	 * about more than one corrupt transaction?
	 * about corrupt transaction in the middle of the oldest -> newest range? */

	/* Ok, so we found valid update transactions.  Reconstruct the "active
	 * set" at the time of the newest transaction. */

	/* wrap around */
	if (newest.i < oldest.i)
		newest.i += mx;

	for (b = oldest.i; b <= newest.i; b++) {
		unsigned idx = b % mx;
		if (!al_cpu[idx].is_valid || al_cpu[idx].transaction_type == AL_TR_INITIALIZED)
			continue;

		for (i = 0; i < AL_CONTEXT_PER_TRANSACTION; i++) {
			unsigned slot = al_cpu[idx].context_start_slot_nr + i;
			if (al_cpu[idx].context[i] == UINT32_MAX && slot >= al_cpu[idx].context_size)
				continue;
			if (slot >= AL_EXTENTS_MAX) {
				CLI_ERRO_LOG_STDERR(false, "slot number out of range: tr:%u slot:%u",
						idx, slot);
				continue;
			}
			hot_extent[slot] = al_cpu[idx].context[i];
		}
		for (i = 0; i < AL_UPDATES_PER_TRANSACTION; i++) {
			unsigned slot = al_cpu[idx].update_slot_nr[i];
			if (i >= al_cpu[idx].n_updates && slot == UINT16_MAX)
				continue;
			if (slot >= AL_EXTENTS_MAX) {
				CLI_ERRO_LOG_STDERR(false, "update slot number out of range: tr:%u slot:%u",
						idx, slot);
				continue;
			}
			hot_extent[slot] = al_cpu[idx].update_extent_nr[i];
		}
	}
	return found_valid_updates;
}

int cmp_u32(const void *p1, const void *p2)
{
	const unsigned a = *(unsigned *)p1;
	const unsigned b = *(unsigned *)p2;

	/* how best to deal with 32bit wrap? */
	return a < b ? -1 : a == b ? 0 : 1;
}

void apply_al(struct format *cfg, uint32_t *hot_extent)
{
	const unsigned int extents_size = BM_BYTES_PER_AL_EXT * cfg->md.max_peers;
	const size_t bm_bytes = ALIGN(cfg->bm_bytes, cfg->md_hard_sect_size);
	off_t bm_on_disk_off = cfg->bm_offset;
	size_t bm_on_disk_pos = 0;
	size_t chunk = 0;
	int i, j;

	/* can only be AL_EXTENTS_MAX * BM_BYTES_PER_AL_EXT * 8,
	 * which currently is 65534 * 128 * 8 == 67106816
	 * fits easily into 32bit. */
	unsigned additional_bits_set = 0;
	uint64_t *w;
	char ppb[10];

	/* Now, actually apply this stuff to the on-disk bitmap.
	 * Since one AL extent corresponds to 128 bytes of bitmap,
	 * we need to do some read/modify/write cycles here.
	 *
	 * Note that this can be slow due to the use of O_DIRECT,
	 * worst case it does 65534 (AL_EXTENTS_MAX) cycles of
	 *  - read 128 kByte (buffer_size)
	 *  - memset 128 Bytes (BM_BYTES_PER_AL_EXT) to 0xff
	 *  - write 128 kByte
	 * This implementation could optimized in various ways:
	 *  - don't use direct IO; has other drawbacks
	 *  - first scan hot_extents for extent ranges,
	 *    and optimize the IO size.
	 *  - use aio with multiple buffers
	 *  - ...
	 */
	for (i = 0; i < AL_EXTENTS_MAX; i++) {
		size_t bm_pos;
		unsigned bits_set = 0;
		if (hot_extent[i] == UINT32_MAX)
			break;

		ASSERT(cfg->md.bm_bytes_per_bit == 4096);
		ASSERT(BM_BYTES_PER_AL_EXT % 4 == 0);

		bm_pos = hot_extent[i] * extents_size;
		if (bm_pos >= bm_bytes) {
			CLI_ERRO_LOG_STDERR(false, "extent %u beyond end of bitmap!", hot_extent[i]);
			/* could break or return error here,
			 * but I'll just print a warning, and skip, each of them. */
			continue;
		}

		/* On first iteration, or when the current position in the bitmap
		 * exceeds the current buffer, write out the current buffer, if any,
		 * and read in the next (at most buffer_size) chunk of bitmap,
		 * containing the currently processed bitmap region.
		 */

		if (i == 0 ||
		    bm_pos + extents_size >= bm_on_disk_pos + chunk) {
			if (i != 0)
				pwrite_or_die(cfg, on_disk_buffer, chunk,
						bm_on_disk_off + bm_on_disk_pos,
						"apply_al");

			/* don't special case logical sector size != 512,
			 * operate in 4k always. */
			bm_on_disk_pos = bm_pos & ~(off_t)(4095);
			chunk = bm_bytes - bm_on_disk_pos;
			if (chunk > buffer_size)
				chunk = buffer_size;
			pread_or_die(cfg, on_disk_buffer, chunk,
					bm_on_disk_off + bm_on_disk_pos,
					"apply_al");
		}
		ASSERT(bm_pos - bm_on_disk_pos <= chunk - extents_size);
		ASSERT((bm_pos - bm_on_disk_pos) % sizeof(uint64_t) == 0);
		w = (uint64_t *)on_disk_buffer
			+ (bm_pos - bm_on_disk_pos)/sizeof(uint64_t);
		for (j = 0; j < extents_size/sizeof(uint64_t); j++)
			bits_set += generic_hweight64(w[j]);

		additional_bits_set += extents_size * 8 - bits_set;
		memset((char*)on_disk_buffer + (bm_pos - bm_on_disk_pos),
			0xff, extents_size);
	}
	/* we still need to write out the buffer of the last iteration */
	if (i != 0) {
		pwrite_or_die(cfg, on_disk_buffer, chunk,
				bm_on_disk_off + bm_on_disk_pos,
				"apply_al");
		CLI_ERRO_LOG_STDERR(false, "Marked additional %s as out-of-sync based on AL.",
			ppsize(ppb, additional_bits_set * 4));
	} else
		CLI_ERRO_LOG_STDERR(false, "Nothing to do.");
}

int need_to_apply_al(struct format *cfg)
{
	switch (format_version(cfg)) {
	case BSR_V06:
		return 0; /* there was no activity log in 0.6 */
	case BSR_V07:
		return cfg->md.gc[Flags] & MDF_PRIMARY_IND;
	case BSR_V08:
	case BSR_V09:
		return cfg->md.flags & MDF_PRIMARY_IND;
	case BSR_UNKNOWN:
		CLI_ERRO_LOG_STDERR(false, "BUG in %s().", __FUNCTION__);
	}
	return 0;
}

int v08_move_internal_md_after_resize(struct format *cfg);
int meta_apply_al(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	off_t al_size;
	struct al_4k_transaction_on_disk *al_4k_disk = on_disk_buffer;
	uint32_t hot_extent[AL_EXTENTS_MAX];
	int need_to_update_md_flags = 0;
	int re_initialize_anyways = 0;
	int err;

	if (argc > 0)
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");

	if (format_version(cfg) < BSR_V07) {
		CLI_ERRO_LOG_STDERR(false, "apply-al only implemented for BSR >= 0.7");
		return -1;
	}

	err = cfg->ops->open(cfg);
	if (err == VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION) {
		if (v08_move_internal_md_after_resize(cfg) == 0)
			err = cfg->ops->open(cfg);
	}
	if (err != VALID_MD_FOUND) {
		CLI_ERRO_LOG_STDERR(false, "No valid meta data found");
		return -1;
	}

	al_size = cfg->md.al_stripes * cfg->md.al_stripe_size_4k * 4096;

	/* read in first chunk (which is actually the whole AL
	 * for old fixed size 32k activity log */
	pread_or_die(cfg, on_disk_buffer,
		al_size < buffer_size ? al_size : buffer_size,
		cfg->al_offset, "apply_al");

	/* init all extent numbers to -1U aka "unused" */
	memset(hot_extent, 0xff, sizeof(hot_extent));

	/* replay al */
	if (is_v07(cfg))
		err = replay_al_07(cfg, hot_extent);

	/* FIXME
	 * we should introduce a new meta data "super block" magic, so we won't
	 * have the same super block with two different activity log
	 * transaction layouts */
	else if (BSR_MD_MAGIC_84_UNCLEAN == cfg->md.magic ||
		 BSR_MD_MAGIC_09 == cfg->md.magic ||
		 BSR_AL_MAGIC == be32_to_cpu(al_4k_disk[0].magic.be) ||
		 BSR_AL_MAGIC == be32_to_cpu(al_4k_disk[1].magic.be) ||
		 cfg->md.al_stripes != 1 || cfg->md.al_stripe_size_4k != 8) {
		err = replay_al_84(cfg, hot_extent);
	} else {
		/* try the old al format anyways, this may be the first time we
		* run after upgrading from < 8.4 to 8.4, and we need to
		* transparently "convert" the activity log format. */
		err = replay_al_07(cfg, hot_extent);
		re_initialize_anyways = 1;
	}

	if (err < 0) {
		/* ENODATA:
		 * most likely this is an uninitialized,
		 * or at least non-8.4-style activity log.
		 * Cannot do anything about that.
		 *
		 * EINVAL:
		 * Some valid 8.4 style INITIALIZED transactions found,
		 * but others have been corrupt, and no single "usable"
		 * update transaction was found.
		 * FIXME: what to do about that?
		 * We probably need some "FORCE" mode as well. */

		if (need_to_apply_al(cfg)) {
			/* 1, 2, 10, 20? FIXME sane exit codes! */
			if (err == -ENODATA)
				return 1;
			return 2;
		} else if (is_v08(cfg) || is_v09(cfg)) {
			CLI_ERRO_LOG_STDERR(false, "Error ignored, no need to apply the AL");
			re_initialize_anyways = 1;
		}
	}

	/* do we need to actually apply it? */
	if (err > 0 && need_to_apply_al(cfg)) {
		/* process hot extents in order, to reduce disk seeks. */
		qsort(hot_extent, ARRAY_SIZE(hot_extent), sizeof(hot_extent[0]), cmp_u32);
		apply_al(cfg, hot_extent);
		need_to_update_md_flags = 1;
	}

	/* (Re-)initialize the activity log.
	 * This is needed on 8.4, and does not hurt on < 8.4.
	 * It may cause a "No usable activity log found" kernel message
	 * if it is attached to < 8.4, but that is cosmetic.
	 * We can skip this, if it was clean anyways (err == 0),
	 * or if we know that this is for 0.7.
	 */
	if (re_initialize_anyways || (err > 0 && !is_v07(cfg)))
		initialize_al(cfg);

	if (format_version(cfg) >= BSR_V08 &&
	    ((cfg->md.flags & MDF_AL_CLEAN) == 0 ||
	     cfg->md.magic != BSR_MD_MAGIC_08))
		need_to_update_md_flags = 1;

	err = 0;
	if (need_to_update_md_flags) {
		/* Must not touch MDF_PRIMARY_IND.
		 * This flag is used in-kernel to determine which
		 * "wait-for-connection-timeout" is to be used.
		 * Maybe it is time to reconsider the concept or
		 * current implementation of "degr-wfc-timeout".
		 * RFC:
		 * If we set MDF_CRASHED_PRIMARY, in case MDF_PRIMARY_IND
		 * was set, and clear MDF_PRIMARY_IND here, we can then
		 * USE_DEGR_WFC_T as long as MDF_CRASHED_PRIMARY is set.
		 * Maybe that even results in better semantics.
		 */
		if (format_version(cfg) >= BSR_V08)
			cfg->md.flags |= MDF_AL_CLEAN;
		if (is_v08(cfg))
			cfg->md.magic = BSR_MD_MAGIC_08;

		err = cfg->ops->md_cpu_to_disk(cfg);
		err = cfg->ops->close(cfg) || err;
		if (err)
			CLI_ERRO_LOG_STDERR(false, "update of super block flags failed");
	}

	return err;
}

unsigned long bm_bytes(const struct md_cpu * const md, uint64_t sectors)
{
	unsigned long long bm_bits;
	unsigned long sectors_per_bit = md->bm_bytes_per_bit >> 9;

	/* we announced 1 PiB as "supported" iirc. */
	ASSERT(sectors <= (1ULL << (50-9)));
	/* sectors_per_bit == 0 would trigger a division by zero.
	 * At some point we will want to store sectors_per_bit directly,
	 * and not bytes_per_bit.
	 * To keep sanity, we limit ourselves to tracking only power-of-two
	 * multiples of 4k */
	ASSERT(md->bm_bytes_per_bit >= 4096);
	ASSERT((md->bm_bytes_per_bit & (md->bm_bytes_per_bit - 1)) == 0);

	/* round up storage sectors to full "bitmap sectors per bit", then
	 * convert to number of bits needed, and round that up to 64bit words
	 * to ease interoperability between 32bit and 64bit architectures.
	 */
	bm_bits = (sectors + sectors_per_bit -1)/sectors_per_bit;
	bm_bits = ALIGN(bm_bits, 64);

	/* convert to bytes, multiply by number of peers,
	 * and, because we do all our meta data IO in 4k blocks,
	 * round up to full 4k
	 */
	return ALIGN(bm_bits / 8 * md->max_peers, 4096);
}

static void fprintf_bm_eol(FILE *f, unsigned int i, int peer_nr, const char* indent)
{
	if ((i & 63) == peer_nr)
		fprintf(f, "\n%s   # at %llukB\n%s   ", indent, (128LLU * (i - peer_nr)), indent);
	else
		fprintf(f, "\n%s   ", indent);
}

static unsigned int round_down(unsigned int i, unsigned int g)
{
	return i / g * g;
	/* return i - i % g; */
}

/* le_u64, because we want to be able to hexdump it reliably
 * regardless of sizeof(long) */
static void fprintf_bm(FILE *f, struct format *cfg, int peer_nr, const char* indent)
{
	const int WPL = 8;
	off_t bm_on_disk_off = cfg->bm_offset;
	le_u32 const *bm = on_disk_buffer;
	le_u32 cw; /* current word for rl encoding */
	le_u32 lw = {0}; /* low word for 64 bit output */
	const unsigned int n = cfg->bm_bytes/sizeof(*bm);
	unsigned int max_peers = cfg->md.max_peers;
	unsigned int count = 0;
	unsigned int bits_set = 0;
	unsigned int n_buffer = 0;
	unsigned int r; /* real offset */
	unsigned int i; /* in-buffer offset */
	unsigned int j;

	/*
	* The code below is a bit "funky" (ugly, unreadable, not only) with
	* the modulos, and implicit offset modulo continuation on buffer wrap.
	* To work, it requires the "chunk size" that is read-in per iteration
	* to be a multiple of max_peer_size * 8 bytes, or it will be seriously
	* confused on buffer wrap.
	* IO-size should be a multiple of 4k anyways (because of O_DIRECT),
	* align on 4k * max_peers seems to be an easy enough fix for said confusion.
	* If you change buffer_size, double check this hackish reasoning as well. */
	const size_t max_chunk_size = round_down(buffer_size, 4096 * max_peers);

	ASSERT(buffer_size >= BSR_PEERS_MAX * 4096);
	ASSERT(max_chunk_size);

	i = peer_nr;
	r = peer_nr;
	cw.le = 0; /* silence compiler warning */
	fprintf(f, "{");

	if (r < n)
		goto start;

	while (r < n) {
		/* need to read on first iteration,
		 * and on buffer wrap */
		if (i * sizeof(*bm) >= max_chunk_size) {
			size_t chunk;
			i -= max_chunk_size / sizeof(*bm);
		start:
			chunk = ALIGN((n - round_down(r, max_peers)) * sizeof(*bm), cfg->md_hard_sect_size);
			if (chunk > max_chunk_size)
				chunk = max_chunk_size;
			ASSERT(chunk);
			pread_or_die(cfg, on_disk_buffer,
				chunk, bm_on_disk_off, "fprintf_bm");
			bm_on_disk_off += chunk;

			n_buffer = chunk / sizeof(*bm);
		}
next:
		ASSERT(i < n_buffer);
		if (count == 0) cw = bm[i];
		if (i % (WPL * max_peers) == peer_nr) {
			if (!count)
				fprintf_bm_eol(f, r, peer_nr, indent);

			/* j = i, because it may be continuation after buffer wrap */
			for (j = i; j < n_buffer && cw.le == bm[j].le; j += max_peers)
				;
			unsigned int tmp = round_down(j / max_peers - i / max_peers, WPL);
			if (tmp > WPL) {
				count += tmp;
				r += tmp * max_peers;
				i += tmp * max_peers;
				if (j >= n_buffer && r < n)
					continue;
			}
			if (count) {
				fprintf(f, " %u times 0x%08X%08X;",
					count / 2, le32_to_cpu(cw.le), le32_to_cpu(cw.le));
				bits_set += count * generic_hweight32(cw.le);
				count = 0;
				if (r >= n)
					break;
				/* don't "continue;", we may have not advanced i after buffer wrap,
				 * so that would be treated as an other buffer wrap */
				goto next;
			}
		}
		ASSERT(i < n_buffer);
		if (((i / max_peers) & 1) == 0)
			lw = bm[i];
		else
			fprintf(f, " 0x%08X%08X;", le32_to_cpu(bm[i].le), le32_to_cpu(lw.le));
		bits_set += generic_hweight32(bm[i].le);
		r += max_peers;
		i += max_peers;
	}
	fprintf(f, "\n%s}\n", indent);
	cfg->bits_set = bits_set;
}

void printf_bm(struct format *cfg)
{
	int i;

	switch (format_version(cfg)) {
	case BSR_V06:
		return;
	case BSR_V07:
	case BSR_V08:
		printf("bm ");
		fprintf_bm(stdout, cfg, 0, "");
		break;
	case BSR_V09:
		for (i = 0; i < cfg->md.max_peers; i++) {
			printf("bitmap[%d] ", i);
			fprintf_bm(stdout, cfg, i, "");
		}
		break;
	case BSR_UNKNOWN:
		CLI_ERRO_LOG_STDERR(false, "BUG in %s().", __FUNCTION__);
	}
}

static void clip_effective_size_and_bm_bytes(struct format *cfg)
{
	if (cfg->md.effective_size > cfg->max_usable_sect) {
		printf("# la-size-sect was too big (%llu), truncated (%llu)!\n",
			(unsigned long long)cfg->md.effective_size,
			(unsigned long long)cfg->max_usable_sect);
		cfg->md.effective_size = cfg->max_usable_sect;
	}
	cfg->bm_bytes = bm_bytes(&cfg->md, cfg->md.effective_size);
}
#ifdef _WIN_VHD_META_SUPPORT
#include <libgen.h>

/**
* @brief
*	To create the diskpart's script for VHD-Meta creation
*/
static int _create_vhd_script(char * vhd_path, uint64_t size_mb, char * mount_point)
{
	convert_win32_separator(vhd_path);
	convert_win32_separator(mount_point);

	FILE * fp = fopen("./"CREATE_VHD_SCRIPT, "w");
	if (!fp) {
		CLI_ERRO_LOG_PEEROR(false, "fopen failed [%m]");
		return 1;
	}

	// first, to create the directory, because diskpart cmd wouldn't make
	char * dir_name = strdup(vhd_path);
	struct stat st = {0};
	dirname(dir_name);
	if (stat(dir_name, &st) == -1) {
		mkdir(dir_name, 0777);
	}
	free(dir_name);

	char buf[512];
	char * assign_type = (1 == strlen(mount_point)) ? "letter" : "mount";
	// assign type refer
	// https://technet.microsoft.com/en-us/library/cc766465(WS.10).aspx
	sprintf(buf,
		"create vdisk file=\"%s\" maximum=%llu\n"
		"attach vdisk\n"
		"create partition primary\n"
		"assign %s=\"%s\"",			// DW-1423 need quotation to get path with blank.
		vhd_path, size_mb, assign_type, mount_point);

	fputs(buf, fp);
	fclose(fp);

	return 0;
}

/**
* @brief
*	To create the diskpart's script for VHD-Meta attach
*/
static int _attach_vhd_script(char * vhd_path)
{
	convert_win32_separator(vhd_path);

	FILE * fp = fopen("./"ATTACH_VHD_SCRIPT, "w");
	if (!fp) {
		CLI_ERRO_LOG_PEEROR(false, "fopen failed [%m]");
		return 1;
	}

	char buf[512];
	sprintf(buf,
		"select vdisk file=\"%s\"\n"
		"attach vdisk",
		vhd_path);
	fputs(buf, fp);
	fclose(fp);

	return 0;
}

static int _call_script(char **argv)
{
	pid_t   my_pid;
	int     status = 0;
	int		pipes[2];

	if (pipe(pipes))
		return -1;

	if (0 == (my_pid = fork())) {
		// child
		close(pipes[0]); // close reading end
		dup2(pipes[1], 1); // 1 = stdout
		close(pipes[1]);

		int ret = execvp(argv[0], argv);
		if (-1 == ret) {
			CLI_ERRO_LOG_PEEROR(false, "child process execve failed [%m]");
			return -2;
		}
	}
	waitpid(my_pid, &status, 0);

	return status;
}

static uint64_t _get_bdev_size_by_letter(const char letter)
{
	char dev_name_nt[32] = { 0, };
	sprintf(dev_name_nt, "\\\\.\\%c:", letter);
	return bdev_size(dev_name_nt);
}

/**
* @brief
*	To return a proper win32 device namespace
*	ex) "\\.\x:" or
*		"\\.\x:\test\"
*		"\\.\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" without a trailing backslash
*	This function returns the allocated buffer, in which the caller should free
*/
static char * _get_win32_device_ns(const char * device_name)
{
	if (!device_name) {
		return NULL;
	}

	char temp[256] = { 0, };	// after converting win-style's separator
	strcpy(temp, device_name);
	
	convert_win32_separator(temp);
	
	char * wdn = NULL;	// win32 device namespace

	// in case drive letter. ex) "d"
	if (1 == strlen(temp)) {
		wdn = strdup("\\\\.\\ :");
		*(wdn + 4) = *temp;
		return wdn;
	}

	const char token[] = "Volume{";
	char * t1 = strstr(temp, token);

	// in case mounted folder
	if (!t1) {

		if ('\\' != temp[strlen(temp) - 1]) {
			strcpy(temp + strlen(temp), "\\");	// added trailing backslash
		}

		BOOL ret = GetVolumeNameForVolumeMountPoint(temp, temp, sizeof(temp));
		if (!ret) {
			DWORD err = GetLastError();
			switch (err) {
				case ERROR_FILE_NOT_FOUND:
					mkdir(temp, 0777);
				case ERROR_NOT_A_REPARSE_POINT:	// pass through intentionally
					break;
				default:
					//CLI_ERRO_LOG_STDERR(false, "GetVolumeNameForVolumeMountPoint() failed err(%d)", err);
					return NULL;
			}
			// DW-1423 retrieve path.
			wdn = (char*)malloc(strlen(temp) + 5);
			if (!wdn) {
				CLI_ERRO_LOG_STDERR(false, "malloc failed while getting directory path for mounting point");
				return NULL;
			}
			strcpy(wdn, "\\\\.\\");
			strcat(wdn, temp);
			return wdn;
		}
	}

	// in case win32 file namespace
	t1 = strstr(temp, token);
	size_t token_len = strlen(token);
	char * t2 = strstr(temp, "}");
	if (t2) {
		wdn = strdup("\\\\.\\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}");
		char * t3 = strstr(wdn, token);
		memcpy(t3, t1, (int)(t2 - t1));
	}

	return wdn;
}
#endif

int v07_style_md_open(struct format *cfg)
{
	struct stat sb;
	unsigned int hard_sect_size = 0;
	int ioctl_err;
	int open_flags = O_RDWR | O_DIRECT;
#ifdef _WIN
	char * buf = _get_win32_device_ns(cfg->md_device_name);
	free(cfg->md_device_name);
	cfg->md_device_name = buf;
#endif
#ifdef _WIN_CLI_UPDATE
	cfg->md_handle = INVALID_HANDLE_VALUE; 
#endif 	
	/* For old-style fixed size indexed external meta data,
	 * we cannot really use O_EXCL, we have to trust the given minor.
	 *
	 * For internal, or "flexible" external meta data, we open O_EXCL to
	 * avoid accidentally damaging otherwise in-use data, just because
	 * someone had a typo in the command line.
	 */
	if (cfg->md_index < 0)
		open_flags |= O_EXCL;

 retry:
#ifdef _WIN_CLI_UPDATE
	 cfg->md_handle = CreateFileA(cfg->md_device_name,       // drive to open
                GENERIC_READ | GENERIC_WRITE,           // no access to the drive
                FILE_SHARE_READ | FILE_SHARE_WRITE,     // share mode
                NULL,                                   // default security attributes
                OPEN_EXISTING,                          // disposition
                0,                                      // file attributes
                NULL);  				 // do not copy file attributes

	if(cfg->md_handle == INVALID_HANDLE_VALUE){
#else 	
	cfg->md_fd = open(cfg->md_device_name, open_flags );

	if (cfg->md_fd == -1) {
#endif 		
		int save_errno = errno;
		PERROR("open(%s) failed", cfg->md_device_name);
#ifdef _WIN_VHD_META_SUPPORT
		// failed to access by drive letter
		if (save_errno == ENOENT && cfg->vhd_dev_path &&
			(F_OK == access(cfg->vhd_dev_path, R_OK))) {
			if (!_attach_vhd_script(cfg->vhd_dev_path)) {
				char * _argv[] = { "diskpart", "/s", "./"ATTACH_VHD_SCRIPT, (char *)0 };
				CLI_ERRO_LOG_STDERR(false, "Attaching %s for meta data", cfg->vhd_dev_path);
				if (_call_script(_argv)) {
					remove("./"ATTACH_VHD_SCRIPT);
					CLI_ERRO_LOG_STDERR(false, "diskpart attach failed.");
					exit(20);
				}
				remove("./"ATTACH_VHD_SCRIPT);
				goto retry;
			}
		}
#endif
#ifdef _LIN_LOOP_META_SUPPORT
#ifdef LOOP_CTL_ADD // support since Linux 3.1
		if (save_errno == ENOENT && cfg->loop_file_path) {
			int loopctlfd;
			int devnr;
			int err;

			CLI_ERRO_LOG_STDERR(false, "set up the loop device (%s)", cfg->md_device_name);
			loopctlfd = open("/dev/loop-control", O_RDWR);
			if (loopctlfd == -1) {
				CLI_ERRO_LOG_STDERR(false, "failed to open /dev/loop-control");
				exit(20);
			}
			devnr = atoi(strtok(cfg->md_device_name, "/dev/loop"));
			// add the new loop device.
			// on success, the device index is returned.
			err = ioctl(loopctlfd, LOOP_CTL_ADD, devnr);
			close(loopctlfd);
			if (err != devnr) {
				CLI_ERRO_LOG_STDERR(false, "failed to add the new loop device (%s)", cfg->md_device_name);
				exit(20);
			}
			goto retry;
		}
#endif
#endif

		if (save_errno == EBUSY && (open_flags & O_EXCL)) {
			if ((!force && command->function == &meta_apply_al) ||
			    !confirmed("Exclusive open failed. Do it anyways?"))
			{
				CLI_WRAN_LOG_PRINT(false, "Operation canceled.(20)\n");
				exit(20);
			}
			open_flags &= ~O_EXCL;
			goto retry;
		}
		if (save_errno == EINVAL && (open_flags & O_DIRECT)) {
			/* shoo. O_DIRECT is not supported?
			 * retry, but remember this, so we can
			 * BLKFLSBUF appropriately */
			CLI_ERRO_LOG_STDERR(false, "could not open with O_DIRECT, retrying without");
			open_flags &= ~O_DIRECT;
			opened_odirect = 0;
			goto retry;
		}
		exit(20);
	}

#ifdef _LIN_LOOP_META_SUPPORT
	if (cfg->loop_file_path) {
		struct loop_info info;
		if (ioctl(cfg->md_fd, LOOP_GET_STATUS, &info) != 0) {
			int file_fd;
			file_fd = open(cfg->loop_file_path, O_RDWR);
			if (file_fd < 0) {
				CLI_ERRO_LOG_STDERR(false, "failed to open mete file (%s)", cfg->loop_file_path);
				exit(20);
			}

			// associate the loop device with the open file.			
			if (ioctl(cfg->md_fd, LOOP_SET_FD, file_fd) != 0) {
				CLI_ERRO_LOG_STDERR(false, "failed to associate the loop device (%s) with the meta file (%s)", 
						cfg->md_device_name, cfg->loop_file_path);
				close(file_fd);
				exit(20);
			}
			close(file_fd);
		}
	}
#endif

#ifdef _LIN
	if (fstat(cfg->md_fd, &sb)) {
		PERROR("fstat(%s) failed", cfg->md_device_name);
		exit(20);
	}

	if (!S_ISBLK(sb.st_mode)) {
		if (!force) {
			CLI_ERRO_LOG_STDERR(false, "'%s' is not a block device!",
				cfg->md_device_name);
			exit(20);
		}
		cfg->bd_size = sb.st_size;
	}
#endif
	if (format_version(cfg) >= BSR_V08) {
		ASSERT(cfg->md_index != BSR_MD_INDEX_INTERNAL);
	}
#ifdef _WIN
	ioctl_err = bdev_sect_size_nt(cfg->md_device_name, &hard_sect_size);
#else // _LIN
	ioctl_err = ioctl(cfg->md_fd, BLKSSZGET, &hard_sect_size);
#endif
	if (ioctl_err) {
		CLI_ERRO_LOG_STDERR(false, "ioctl(md_fd, BLKSSZGET) returned %d, "
			"assuming hard_sect_size is 512 Byte\n", ioctl_err);
		cfg->md_hard_sect_size = 512;
	}
	else {
		cfg->md_hard_sect_size = hard_sect_size;
		if (verbose >= 2)
			CLI_ERRO_LOG_STDERR(false, "hard_sect_size is %d Byte",
			cfg->md_hard_sect_size);
	}
	
	if (!cfg->bd_size)
#ifdef _WIN
		cfg->bd_size = bdev_size(cfg->md_device_name);
#else // _LIN
		cfg->bd_size = bdev_size(cfg->md_fd);
#endif
	/* check_for_existing_data() wants to read that much,
	 * so having less than that doesn't make sense.
	 * It's only 68kB anyway! */
	if (cfg->bd_size < SO_MUCH) {
		CLI_ERRO_LOG_STDERR(false, "%s is only %llu bytes. That's not enough.",
			cfg->md_device_name, (long long unsigned)cfg->bd_size);
		exit(10);
	}
	cfg->md_offset =
		v07_style_md_get_byte_offset(cfg->md_index, cfg->bd_size);
	if (cfg->md_offset > cfg->bd_size - 4096) {
		CLI_ERRO_LOG_STDERR(false, 
			"Device too small: expecting meta data block at\n"
			"byte offset %lld, but %s is only %llu bytes.\n",
			(signed long long)cfg->md_offset,
			cfg->md_device_name,
			(long long unsigned)cfg->bd_size);
		exit(10);
	}
#ifdef _LIN
	if (!opened_odirect &&
	    (MAJOR(sb.st_rdev) != RAMDISK_MAJOR)) {
		ioctl_err = ioctl(cfg->md_fd, BLKFLSBUF);
		/* report error, but otherwise ignore.  we could not open
		 * O_DIRECT, it is a "strange" device anyways. */
		if (ioctl_err)
			CLI_ERRO_LOG_STDERR(false, "ioctl(md_fd, BLKFLSBUF) returned %d, "
					"we may read stale data\n", ioctl_err);
	}
#endif
	if (cfg->ops->md_disk_to_cpu(cfg)) {
		/* no valid meta data found.  but we want to initialize
		 * al_offset and bm_offset anyways, so check_for_existing_data
		 * has something to work with. */
		return NO_VALID_MD_FOUND;
	}

	cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512LL;
	cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512LL;
	cfg->max_usable_sect = max_usable_sectors(cfg);
	clip_effective_size_and_bm_bytes(cfg);

	cfg->bits_set = -1U;

	/* FIXME paranoia verify that unused bits and words are unset... */
	/* FIXME paranoia verify that unused bits and words are unset... */

	return VALID_MD_FOUND;
}

int v07_md_disk_to_cpu(struct format *cfg)
{
	struct md_cpu md;
	int ok;
	PREAD(cfg, on_disk_buffer, sizeof(struct md_on_disk_07), cfg->md_offset);
	md_disk_07_to_cpu(&md, (struct md_on_disk_07*)on_disk_buffer);
	ok = is_valid_md(BSR_V07, &md, cfg->md_index, cfg->bd_size);
	if (ok)
		cfg->md = md;
	return ok ? 0 : -1;
}

int v07_md_cpu_to_disk(struct format *cfg)
{
	if (!is_valid_md(BSR_V07, &cfg->md, cfg->md_index, cfg->bd_size))
		return -1;
	md_cpu_to_disk_07(on_disk_buffer, &cfg->md);
	PWRITE(cfg, on_disk_buffer, sizeof(struct md_on_disk_07), cfg->md_offset);
	return 0;
}

int v07_parse(struct format *cfg, char **argv, int argc, int *ai)
{
	long index;
	char *e;

	if (argc < 2) {
		CLI_ERRO_LOG_STDERR(false, "Too few arguments for format");
		return -1;
	}

	cfg->md_device_name = strdup(argv[0]);
	if (!strcmp(argv[1],"internal")) {
		index =
		  is_v07(cfg) ? BSR_MD_INDEX_INTERNAL
			      : BSR_MD_INDEX_FLEX_INT;
	} else if (!strcmp(argv[1],"flex-external")) {
		index = BSR_MD_INDEX_FLEX_EXT;
	} else if (!strcmp(argv[1],"flex-internal")) {
		index = BSR_MD_INDEX_FLEX_INT;
#ifdef _WIN_VHD_META_SUPPORT
	} else if (strstr(argv[1], ".vhd")) {
		cfg->vhd_dev_path = strdup(argv[1]);
		index = BSR_MD_INDEX_FLEX_EXT;
#endif
#ifdef _LIN_LOOP_META_SUPPORT
	} else if (strstr(cfg->md_device_name, "loop") && strstr(argv[1], "/")) {
		cfg->loop_file_path = strdup(argv[1]);
		index = BSR_MD_INDEX_FLEX_EXT;
#endif
	} else {
		e = argv[1];
		errno = 0;
		index = strtol(argv[1], &e, 0);
		if (*e != 0 || 0 > index || index > 255 || errno != 0) {
			CLI_ERRO_LOG_STDERR(false, "'%s' is not a valid index number.", argv[1]);
			return -1;
		}
	}
	cfg->md_index = index;

	*ai += 2;

	return 0;
}

int v07_md_initialize(struct format *cfg, int do_disk_writes,
		      int max_peers __attribute((unused)))
{
	memset(&cfg->md, 0, sizeof(cfg->md));

	cfg->md.effective_size = 0;
	cfg->md.gc[Flags] = 0;
	cfg->md.gc[HumanCnt] = 1;	/* THINK 0? 1? */
	cfg->md.gc[TimeoutCnt] = 1;
	cfg->md.gc[ConnectedCnt] = 1;
	cfg->md.gc[ArbitraryCnt] = 1;
	cfg->md.max_peers = 1;
	cfg->md.magic = BSR_MD_MAGIC_07;
	/* No striping in v07!
	 * But some parts of the common code expect these members to be properly initialized. */
	cfg->md.al_stripes = 1;
	cfg->md.al_stripe_size_4k = 8;

	return md_initialize_common(cfg, do_disk_writes);
}

/******************************************
  }}} end of v07
 ******************************************/
/******************************************
 begin of v08 {{{
 ******************************************/

/* if this returns with something != 0 in cfg->lk_bd.bd_size,
 * caller knows he must move the meta data to actually find it. */
void v08_check_for_resize(struct format *cfg)
{
	struct md_cpu md_test;
	off_t flex_offset;
	int found = 0;

	/* you should not call me if you already found something. */
	ASSERT(cfg->md.magic == 0);

	/* check for resized lower level device ... only check for bsr 8 */
	if (format_version(cfg) < BSR_V08)
		return;
	if (cfg->md_index != BSR_MD_INDEX_FLEX_INT)
		return;

	/* Do we know anything? Maybe it never was stored. */
	if (lk_bdev_load(cfg->minor, &cfg->lk_bd)) {
		if (verbose)
			CLI_ERRO_LOG_STDERR(false, "no last-known offset information available.");
		return;
	}

	if (verbose) {
		CLI_ERRO_LOG_STDERR(false, " last known info: %llu %s",
			(unsigned long long)cfg->lk_bd.bd_size,
			cfg->lk_bd.bd_name ?: "-unknown device name-");
		if (cfg->lk_bd.bd_uuid)
			CLI_ERRO_LOG_STDERR(false, " last known uuid: "X64(016)"",
				cfg->lk_bd.bd_uuid);
	}

	/* I just checked that offset, nothing to see there. */
	if (cfg->lk_bd.bd_size == cfg->bd_size)
		return;

	flex_offset = v07_style_md_get_byte_offset(
		BSR_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);

	/* actually check that offset, if it is accessible. */
	/* If someone shrunk that device, I won't be able to read it! */
	if (flex_offset < cfg->bd_size) {
		PREAD(cfg, on_disk_buffer, 4096, flex_offset);
		if (is_v08(cfg)) {
			md_disk_08_to_cpu(&md_test, (struct md_on_disk_08*)on_disk_buffer);
			found = is_valid_md(BSR_V08, &md_test, BSR_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);
		}
		else if (is_v09(cfg)) {
			md_disk_09_to_cpu(&md_test, (struct meta_data_on_disk_9*)on_disk_buffer);
			found = is_valid_md(BSR_V09, &md_test, BSR_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);
		}
	}

	if (verbose) {
		CLI_ERRO_LOG_STDERR(false, "While checking for internal meta data for bsr%u on %s,"
				"it appears that it may have been relocated.\n"
				"It used to be ", cfg->minor, cfg->md_device_name);
		if (cfg->lk_bd.bd_name &&
			strcmp(cfg->lk_bd.bd_name, cfg->md_device_name)) {
			CLI_ERRO_LOG_STDERR(false, "on %s ", cfg->lk_bd.bd_name);
		}
		CLI_ERRO_LOG_STDERR(false, "at byte offset %llu", (unsigned long long)flex_offset);

		if (!found) {
			CLI_ERRO_LOG_STDERR(false, ", but I cannot find it now.");
			if (flex_offset >= cfg->bd_size)
				CLI_ERRO_LOG_STDERR(false, "Device is too small now!");
		} else
			CLI_ERRO_LOG_STDERR(false, ", and seems to still be valid.");
	}

	if (found) {
		if (cfg->lk_bd.bd_uuid && md_test.device_uuid != cfg->lk_bd.bd_uuid) {
			CLI_ERRO_LOG_STDERR(false, "Last known and found uuid differ!?"
					X64(016)" != "X64(016)"\n",
					cfg->lk_bd.bd_uuid, cfg->md.device_uuid);
			if (!force) {
				found = 0;
				CLI_ERRO_LOG_STDERR(false, "You may --force me to ignore that.");
			} else
				CLI_ERRO_LOG_STDERR(false, "You --force'ed me to ignore that.");
		}
	}
	if (found)
		cfg->md = md_test;
	return;
}

int v08_md_open(struct format *cfg) {
	int r = v07_style_md_open(cfg);
	if (r == VALID_MD_FOUND)
		return r;

	v08_check_for_resize(cfg);
	if (!cfg->lk_bd.bd_size || !cfg->md.magic)
		return NO_VALID_MD_FOUND;
	else
		return VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION;
}

int v08_md_disk_to_cpu(struct format *cfg)
{
	struct md_cpu md;
	int ok;
	PREAD(cfg, on_disk_buffer, sizeof(struct md_on_disk_08), cfg->md_offset);
	md_disk_08_to_cpu(&md, (struct md_on_disk_08*)on_disk_buffer);
	ok = is_valid_md(BSR_V08, &md, cfg->md_index, cfg->bd_size);
	if (ok)
		cfg->md = md;
	if (verbose >= 3 + !!ok && verbose <= 10)
		fprintf_hex(stderr, cfg->md_offset, on_disk_buffer, 4096);
	return ok ? 0 : -1;
}

int v08_md_cpu_to_disk(struct format *cfg)
{
	if (!is_valid_md(BSR_V08, &cfg->md, cfg->md_index, cfg->bd_size))
		return -1;
	md_cpu_to_disk_08((struct md_on_disk_08 *)on_disk_buffer, &cfg->md);
	PWRITE(cfg, on_disk_buffer, sizeof(struct md_on_disk_08), cfg->md_offset);
	cfg->update_lk_bdev = 1;
	return 0;
}

int v08_md_initialize(struct format *cfg, int do_disk_writes,
		      int max_peers __attribute((unused)))
{
	size_t i;

	memset(&cfg->md, 0, sizeof(cfg->md));

	cfg->md.effective_size = 0;
	cfg->md.current_uuid = UUID_JUST_CREATED;
	cfg->md.peers[0].bitmap_uuid = 0;
	for (i = 0; i < ARRAY_SIZE(cfg->md.history_uuids); i++)
		cfg->md.history_uuids[i] = 0;
	cfg->md.flags = MDF_AL_CLEAN;
	cfg->md.max_peers = 1;
	cfg->md.magic = BSR_MD_MAGIC_08;
	cfg->md.al_stripes = option_al_stripes;
	cfg->md.al_stripe_size_4k = option_al_stripe_size_4k;

	return md_initialize_common(cfg, do_disk_writes);
}

int v08_md_close(struct format *cfg)
{
	/* update last known info, if we changed anything,
	 * or if explicitly requested. */
	if (cfg->update_lk_bdev && !dry_run) {
		if (cfg->md_index != BSR_MD_INDEX_FLEX_INT)
			lk_bdev_delete(cfg->minor);
		else {
			cfg->lk_bd.bd_size = cfg->bd_size;
			cfg->lk_bd.bd_uuid = cfg->md.device_uuid;
			cfg->lk_bd.bd_name = cfg->md_device_name;
			lk_bdev_save(cfg->minor, &cfg->lk_bd);
		}
	}
	return generic_md_close(cfg);
}

/******************************************
 begin of v09 {{{
 ******************************************/
int v09_md_disk_to_cpu(struct format *cfg)
{
	struct md_cpu md;
	int ok;
	PREAD(cfg, on_disk_buffer, sizeof(struct meta_data_on_disk_9), cfg->md_offset);
	md_disk_09_to_cpu(&md, (struct meta_data_on_disk_9*)on_disk_buffer);
	ok = is_valid_md(BSR_V09, &md, cfg->md_index, cfg->bd_size);
	if (ok)
		cfg->md = md;
	if (verbose >= 3 + !!ok && verbose <= 10)
		fprintf_hex(stderr, cfg->md_offset, on_disk_buffer, 4096);
	return ok ? 0 : -1;
}

int v09_md_cpu_to_disk(struct format *cfg)
{
	if (!is_valid_md(BSR_V09, &cfg->md, cfg->md_index, cfg->bd_size))
		return -1;
	md_cpu_to_disk_09((struct meta_data_on_disk_9 *)on_disk_buffer, &cfg->md);
	PWRITE(cfg, on_disk_buffer, sizeof(struct meta_data_on_disk_9), cfg->md_offset);
	cfg->update_lk_bdev = 1;
	return 0;
}

int v09_md_initialize(struct format *cfg, int do_disk_writes, int max_peers)
{
	int p, i;

	memset(&cfg->md, 0, sizeof(cfg->md));

	cfg->md.effective_size = 0;
	cfg->md.max_peers = max_peers;
	cfg->md.flags = MDF_AL_CLEAN;
	cfg->md.node_id = -1;
	cfg->md.magic = BSR_MD_MAGIC_09;
	cfg->md.al_stripes = option_al_stripes;
	cfg->md.al_stripe_size_4k = option_al_stripe_size_4k;

	cfg->md.current_uuid = UUID_JUST_CREATED;
	for (i = 0; i < ARRAY_SIZE(cfg->md.history_uuids); i++)
		cfg->md.history_uuids[i] = 0;

	for (p = 0; p < BSR_NODE_ID_MAX; p++) {
		cfg->md.peers[p].bitmap_uuid = 0;
		cfg->md.peers[p].flags = 0;
		cfg->md.peers[p].bitmap_index = -1;
	}

	return md_initialize_common(cfg, do_disk_writes);
}

/******************************************
  }}} end of v09
 ******************************************/

int meta_get_gi(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	if (argc > 0) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}

	if (cfg->ops->open(cfg))
		return -1;

	cfg->ops->get_gi(&cfg->md, option_node_id);

	return cfg->ops->close(cfg);
}

int meta_show_gi(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	char ppb[10];

	if (argc > 0) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}

	if (cfg->ops->open(cfg))
		return -1;

	// find the correct slot from node-id.

	cfg->ops->show_gi(&cfg->md, option_node_id);

	if (cfg->md.effective_size) {
		printf("last agreed size: %s (%llu sectors)\n",
			ppsize(ppb, cfg->md.effective_size >> 1),
		       (unsigned long long)cfg->md.effective_size);
		printf("last agreed max bio size: %u Byte\n",
			       cfg->md.la_peer_max_bio_size);
#if 0
		/* FIXME implement count_bits() */
		printf("%u bits set in the bitmap [ %s out of sync ]\n",
			cfg->bits_set, ppsize(ppb, cfg->bits_set * 4));
#endif
	} else {
		printf("zero size device -- never seen peer yet?\n");
	}

	return cfg->ops->close(cfg);
}

int meta_dstate(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	if (argc > 0) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}

	if (cfg->ops->open(cfg)) {
		CLI_ERRO_LOG_STDERR(false, "No valid meta data found");
		return -1;
	}

	if(cfg->md.flags & MDF_CONSISTENT) {
		if(cfg->md.flags & MDF_WAS_UP_TO_DATE) {
			if (cfg->md.flags & MDF_PEER_OUT_DATED)
				printf("UpToDate\n");
			else
				printf("Consistent\n");
		} else {
			printf("Outdated\n");
		}
	} else {
		printf("Inconsistent\n");
	}

	return cfg->ops->close(cfg);
}

int meta_set_gi(struct format *cfg, char **argv, int argc)
{
	struct md_cpu tmp;
	int err;

	if (argc > 1) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}
	if (argc < 1) {
		CLI_ERRO_LOG_STDERR(false, "Required Argument missing");
		exit(10);
	}

	if (cfg->ops->open(cfg))
		return -1;

	tmp = cfg->md;
	cfg->ops->set_gi(&tmp, option_node_id, argv, argc);
	printf("previously ");
	cfg->ops->get_gi(&cfg->md, option_node_id);
	printf("set GI to  ");
	cfg->ops->get_gi(&tmp, option_node_id);

	if (!confirmed("Write new GI to disk?")) {
		CLI_INFO_LOG_PRINT(false, "Operation canceled.(0)");
		exit(0);
	}

	cfg->md = tmp;

	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg) || err;
	if (err)
		CLI_ERRO_LOG_STDERR(false, "update failed");

	return err;
}

void print_dump_header()
{
	char time_str[60];
	time_t t = time(NULL);
	int i;

	strftime(time_str, sizeof(time_str), "%F %T %z [%s]", localtime(&t));
	printf("# BSR meta data dump\n# %s\n# %s>",
		time_str, get_hostname());

	for (i=0; i < global_argc; i++)
		printf(" %s",global_argv[i]);
	printf("\n#\n\n");
}

char *pretty_peer_md_flags(char *inbuf, unsigned int buf_size, unsigned int flags, const char *first_sep, const char *sep)
{
	static const char *flag_name[32] = {
		/* MDF_PEER_CONNECTED   */ [0] = "connected",
		/* MDF_PEER_OUTDATED    */[1] = "<=outdated",
		/* MDF_PEER_FENCING     */[2] = "fencing",
		/* MDF_PEER_FULL_SYNC   */[3] = "full-sync",
		/* MDF_PEER_DEVICE_SEEN */[4] = "seen",
		/* MDF_NODE_EXISTS      */[16] = "exists",
	};

	char *buf = inbuf;
	int n = buf_size;
	int c;
	int i;
	const char *cur_sep = first_sep;

	*buf = '\0';
	for (i = 0; i < 32; i++) {
		unsigned int f = 1U << i;
		if ((flags & f) == 0)
			continue;

		if (flag_name[i])
			c = snprintf(buf, n, "%s%s", cur_sep, flag_name[i]);
		else
			c = snprintf(buf, n, "%s0x%x=?", cur_sep, f);
		cur_sep = sep;
		if (c < 0 || c >= n)
			break;
		buf += c;
		n -= c;
	}
	return inbuf;
}

int meta_dump_md(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int al_is_clean;
	int i;

	if (argc > 0) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}

	i = cfg->ops->open(cfg);
	if (i == NO_VALID_MD_FOUND) {
		CLI_ERRO_LOG_STDERR(false, "No valid meta data found");
		return -1;
	}

	al_is_clean =
		BSR_MD_MAGIC_84_UNCLEAN != cfg->md.magic &&
		(cfg->md.flags & MDF_AL_CLEAN) != 0;

	if (!al_is_clean) {
		CLI_ERRO_LOG_STDERR(false, "Found meta data is \"unclean\", please apply-al first");
		if (!force)
			return -1;
	}

	print_dump_header();
	printf("version \"%s\";\n\n", cfg->ops->name);

	if (!al_is_clean)
		/* So we have been forced. Still cause a parse error for restore-md. */
		printf("This_is_an_unclean_meta_data_dump._Don't_trust_the_bitmap.\n"
			"# You should \"apply-al\" first, if you plan to restore this.\n\n");

	if (format_version(cfg) >= BSR_V09)
		printf("max-peers %d;\n", cfg->md.max_peers);
	printf("# md_size_sect %llu\n", (long long unsigned)cfg->md.md_size_sect);

	if (i == VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION) {
		printf("#\n"
		"### Device seems to have been resized!\n"
		"### dumping meta data from the last known position\n"
		"### current size of %s: %llu byte\n"
		"### expected position of meta data:\n",
		cfg->md_device_name, (unsigned long long)cfg->bd_size);

		printf("## md_offset %llu\n", (long long unsigned)cfg->md_offset);
		printf("## al_offset %llu\n", (long long unsigned)cfg->al_offset);
		printf("## bm_offset %llu\n", (long long unsigned)cfg->bm_offset);

		printf(
		"### last known size of %s: %llu byte\n"
		"### adjusted position of meta data:\n",
		cfg->lk_bd.bd_name ?: "-?-",
		(unsigned long long)cfg->lk_bd.bd_size);

		cfg->md_offset = v07_style_md_get_byte_offset(
			BSR_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);

		cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512LL;
		cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512LL;
		cfg->bm_bytes = bm_bytes(&cfg->md, cfg->md.effective_size);
	}
	printf("# md_offset %llu\n", (long long unsigned)cfg->md_offset);
	printf("# al_offset %llu\n", (long long unsigned)cfg->al_offset);
	printf("# bm_offset %llu\n", (long long unsigned)cfg->bm_offset);
	printf("\n");

	switch (format_version(cfg)) {
	case BSR_V06:
	case BSR_V07:
		printf("gc {\n   ");
		for (i = 0; i < GEN_CNT_SIZE; i++) {
			printf(" %d;", cfg->md.gc[i]);
		}
		printf("\n}\n");
		break;
	case BSR_V08:
		printf("uuid {\n");
		printf("    0x"X64(016)"; 0x"X64(016)"; 0x"X64(016)"; 0x"X64(016)";\n",
		       cfg->md.current_uuid,
		       cfg->md.peers[0].bitmap_uuid,
		       cfg->md.history_uuids[0],
		       cfg->md.history_uuids[1]);
		printf("    flags 0x"X32(08)";\n", cfg->md.peers[0].flags);
		printf("}\n");
		break;
	case BSR_V09:
		printf("node-id %d;\n"
		       "current-uuid 0x"X64(016)";\n"
		       "flags 0x"X32(08)";\n",
		       cfg->md.node_id,
		       cfg->md.current_uuid, cfg->md.flags);
		for (i = 0; i < BSR_NODE_ID_MAX; i++) {
			struct peer_md_cpu *peer = &cfg->md.peers[i];
			char flag_buf[80];

			printf("peer[%d] {\n", i);
			if (format_version(cfg) >= BSR_V09) {
				printf("    bitmap-index %d;\n",
				       peer->bitmap_index);
			}
			printf("    bitmap-uuid 0x"X64(016)";\n"
			       "    bitmap-dagtag 0x"X64(016)";\n"
				   "    flags 0x"X32(08)";%s\n",
			       peer->bitmap_uuid,
			       peer->bitmap_dagtag,
				   peer->flags,
				   pretty_peer_md_flags(flag_buf, sizeof(flag_buf),
				   peer->flags, " # ", " | "));
			printf("}\n");
		}
		printf("history-uuids {");
		for (i = 0; i < ARRAY_SIZE(cfg->md.history_uuids); i++)
			printf("%s0x"X64(016)";",
			       i % 4 ? " " : "\n        ",
			       cfg->md.history_uuids[i]);
		printf("\n}\n");
		break;
	case BSR_UNKNOWN:
		CLI_ERRO_LOG_STDERR(false, "BUG in %s().", __FUNCTION__);
	}

	if (format_version(cfg) >= BSR_V07) {
		printf("# al-extents %u;\n", cfg->md.al_nr_extents);
		printf("la-size-sect "U64";\n", cfg->md.effective_size);
		if (format_version(cfg) >= BSR_V08) {
			printf("bm-byte-per-bit "U32";\n",
			       cfg->md.bm_bytes_per_bit);
			printf("device-uuid 0x"X64(016)";\n",
			       cfg->md.device_uuid);
			printf("la-peer-max-bio-size %d;\n",
			       cfg->md.la_peer_max_bio_size);
			printf("al-stripes "U32";\n",
				cfg->md.al_stripes);
			printf("al-stripe-size-4k "U32";\n",
				cfg->md.al_stripe_size_4k);
		}
		printf("# bm-bytes %u;\n", cfg->bm_bytes);
		printf_bm(cfg); /* pretty prints the whole bitmap */
		printf("# bits-set %u;\n", cfg->bits_set);

		/* This is half assed, still. Hide it. */
		if (verbose >= 10)
			printf_al(cfg);
	}

	return cfg->ops->close(cfg);
}

void md_parse_error(int expected_token, int seen_token,const char *etext)
{
	char z[1] = { 0, };

	if (!etext) {
		switch(expected_token) {
		/* leading space indicates to strip off "expected" below */
		default : etext = " invalid/unexpected token!"; break;
		case 0  : etext = "end of file"; break;
		case ';': etext = "semicolon (;)"; break;
		case '{': etext = "opening brace ({)"; break;
		case '}': etext = "closing brace (})"; break;
		case '[': etext = "opening bracket ([)"; break;
		case ']': etext = "closing bracket (])"; break;
		case TK_BM:
			etext = "keyword 'bm'"; break;
		case TK_BITMAP:
			etext = "keyword 'bitmap'"; break;
		case TK_BM_BYTE_PER_BIT:
			etext = "keyword 'bm-byte-per-bit'"; break;
		case TK_DEVICE_UUID:
			etext = "keyword 'device-uuid'"; break;
		case TK_FLAGS:
			etext = "keyword 'flags'"; break;
		case TK_GC:
			etext = "keyword 'gc'"; break;
		case TK_LA_SIZE:
			etext = "keyword 'la-size-sect'"; break;
		case TK_TIMES:
			etext = "keyword 'times'"; break;
		case TK_UUID:
			etext = "keyword 'uuid'"; break;
		case TK_VERSION:
			etext = "keyword 'version'"; break;
		case TK_NODE_ID:
			etext = "keyword 'node-id'"; break;
		case TK_CURRENT_UUID:
			etext = "keyword 'current-uuid'"; break;
		case TK_BITMAP_UUID:
			etext = "keyword 'bitmap-uuid'"; break;
		case TK_BITMAP_DAGTAG:
			etext = "keyword 'bitmap-dagtag'"; break;
		case TK_PEER:
			etext = "keyword 'peer'"; break;
		case TK_HASH:
			etext = "keyword 'hash'"; break;
		case TK_MAX_PEERS:
			etext = "keyword 'max-peers'"; break;
		case TK_NUM:
			etext = "number ([0-9], up to 20 digits)"; break;
		case TK_STRING:
			etext = "short quoted string "
				"(\"..up to 20 characters, no newline..\")";
				break;
		case TK_U32:
			etext = "an 8-digit hex number"; break;
		case TK_U64:
			etext = "a 16-digit hex number"; break;
		}
	}
	fflush(stdout);
	CLI_ERRO_LOG_STDERR(false, "Parse error in line %u: %s%s",
		yylineno, etext,
		(etext[0] == ' ' ? ":" : " expected")
		);

	switch(seen_token) {
	case 0:
		CLI_ERRO_LOG_STDERR(false, ", but end of file encountered"); 
		break;
	case   1 ...  58: /* ord(';') == 58 */
	case  60 ... 122: /* ord('{') == 123 */
	case 124:         /* ord('}') == 125 */
	case 126 ... 257:
		/* oopsie. these should never be returned! */
		CLI_ERRO_LOG_STDERR(false, "; got token value %u (this should never happen!)", seen_token);
		break;

	case TK_INVALID_CHAR:
		CLI_ERRO_LOG_STDERR(false, "; got invalid input character '\\x%02x' [%c]",
			(unsigned char)yylval.txt[0], yylval.txt[0]);
		break;
	case ';': case '{': case '}':
		CLI_ERRO_LOG_STDERR(false, ", not '%c'", seen_token); 
		break;
	case TK_NUM:
	case TK_U32:
	case TK_U64:
		CLI_ERRO_LOG_STDERR(false, ", not some number"); 
		break;
	case TK_INVALID:
		/* already reported by scanner */
		CLI_ERRO_LOG_STDERR(false, "%s", z); 
		break;
	default:
		CLI_ERRO_LOG_STDERR(false, ", not '%s'", yylval.txt);
	}
	exit(10);
}

static void EXP(int expected_token) {
	int tok = yylex();
	if (tok != expected_token)
		md_parse_error(expected_token, tok, NULL);
}

static int assign_32_of_64bit(int i, uint64_t value, int max_peers)
{
	le_u32 *bm = on_disk_buffer;

	if (i >= buffer_size / sizeof(*bm))
		return i; // Do no advance i after leaving the window

	if (i >= 0) { // only assign data, while within the window
		if (((i / max_peers) & 1) == 0)
			bm[i].le = cpu_to_le32((uint32_t) value); // little endian low word => lower address
		else
			bm[i].le = cpu_to_le32((uint32_t) (value >> 32));
	}

	return i + max_peers;
}

int parse_bitmap_window_one_peer(struct format *cfg, int window, int peer_nr, int parse_only)
{
	unsigned int max_peers = cfg->md.max_peers;
	le_u32 *bm = on_disk_buffer;
	uint64_t value;
	int i, times;

	i = peer_nr - window * (buffer_size / sizeof(*bm));

	if (format_version(cfg) < BSR_V09)
		EXP(TK_BM);
	else {
		EXP(TK_BITMAP); EXP('[');
		EXP(TK_NUM); EXP(']');
		if (yylval.u64 != peer_nr) {
			CLI_ERRO_LOG_STDERR(false, "Parse error in line %u: "
				"Expected peer slot %d but found %d\n",
				yylineno, i, (int)yylval.u64);
			exit(10);
		}
	}
	EXP('{');

	while(1) {
		int tok = yylex();
		switch(tok) {
		case TK_U64:
			EXP(';');
			/* NOTE:
			 * even though this EXP(';'); already advanced
			 * to the next token, yylval will *not* be updated
			 * for * ';', so it is still valid.
			 *
			 * This seemed to be the least ugly way to implement a
			 * "parse_only" functionality without ugly if-branches
			 * or the maintenance nightmare of code duplication */
			if (parse_only) {
				i += max_peers * (sizeof(value) / sizeof(*bm));
				break;
			}
			value = yylval.u64;

			i = assign_32_of_64bit(i, value, max_peers);
			i = assign_32_of_64bit(i, value, max_peers);
			break;
		case TK_NUM:
			times = yylval.u64;
			EXP(TK_TIMES);
			EXP(TK_U64);
			EXP(';');
			if (parse_only) {
				i += times * max_peers * (sizeof(value) / sizeof(*bm));
				break;
			}
			value = yylval.u64;
			while(times--) {
				i = assign_32_of_64bit(i, value, max_peers);
				i = assign_32_of_64bit(i, value, max_peers);
			}
			break;
		case '}':
			goto break_loop;
		default:
			md_parse_error(0 /* ignored, since etext is set */,
				       tok, "repeat count, 16-digit hex number, or closing brace (})");
			goto break_loop;
		}
	}
break_loop:

	return i - peer_nr;
}

int parse_bitmap_window(struct format *cfg, int window, int parse_only)
{
	int words = 0, i;

	if (format_version(cfg) < BSR_V09) {
		return parse_bitmap_window_one_peer(cfg, window, 0, parse_only);
	} else /* >= BSR_V09 */ {
		for (i = 0; i < cfg->md.max_peers; i++) {
			words = parse_bitmap_window_one_peer(cfg, window, i, parse_only);
		}
	}
	return words;
}

void parse_bitmap(struct format *cfg, int parse_only)
{
	le_u32 *bm = on_disk_buffer;
	off_t bm_max_on_disk_off;
	long start_pos;
	int window = 0;
	int words;
	int truncated = 0;

	start_pos = ftell(yyin) - my_yy_unscaned_characters();

	bm_max_on_disk_off = cfg->bm_offset + ALIGN(cfg->bm_bytes, 4096);

	do {
		fseek(yyin, start_pos, SEEK_SET);
		yyrestart(yyin);

		words = parse_bitmap_window(cfg, window, parse_only);

		if (words > 0 && !truncated) {
			size_t s = words * sizeof(*bm);
			size_t c;

			memset(bm + words, 0x00, buffer_size - s);
			/* need to sector-align this for O_DIRECT. to be
			 * generic, maybe we even need to PAGE align it? */
			s = ALIGN(s, cfg->md_hard_sect_size);
			if (parse_only) {
				c = bm_max_on_disk_off -
					(cfg->bm_offset + window * buffer_size);
				if (c > s)
					c = s;
			} else
				c = pwrite_with_limit_or_die(cfg, on_disk_buffer,
				      s, cfg->bm_offset + window * buffer_size,
				      bm_max_on_disk_off,
				      "meta_restore_md");
			if (s != c) {
				CLI_ERRO_LOG_STDERR(false, "Bitmap info too large, truncated!");
				/* If the bitmap info was truncated, there will
				 * be garbage, still, and the EXP(0) below would
				 * crap out.  "Drain" that garbage here,
				 * while still checking for parse errors.
				 */
				truncated = 1;
			}
		}

		window++;
	} while (words == buffer_size / sizeof(*bm));
}

int verify_dumpfile_or_restore(struct format *cfg, char **argv, int argc, int parse_only)
{
	int old_max_peers = -1;
	int new_max_peers = 1;
	int i;
	int err;
	char slots_seen[BSR_NODE_ID_MAX] = { 0, };
	int cur_slot;

	if (argc > 0) {
		yyin = fopen(argv[0],"r");
		if(yyin == NULL) {
			CLI_ERRO_LOG_STDERR(false, "open of '%s' failed.",argv[0]);
			exit(20);
		}
	}

	if (!parse_only) {
		if (cfg->ops->open(cfg) != NO_VALID_MD_FOUND) {
			old_max_peers = cfg->md.max_peers;
			if (!confirmed("Valid meta-data in place, overwrite?"))
				return -1;
		} else {
			ASSERT(!is_v06(cfg));
		}
	}

	EXP(TK_VERSION); EXP(TK_STRING);
	if(strcmp(yylval.txt,cfg->ops->name)) {
		CLI_ERRO_LOG_STDERR(false, "dump is '%s' you requested '%s'.",
			yylval.txt,cfg->ops->name);
		exit(10);
	}
	EXP(';');
	if (is_v09(cfg)) {
		EXP(TK_MAX_PEERS);
		EXP(TK_NUM); EXP(';');
		new_max_peers = yylval.u64;
	}

	cfg->ops->md_initialize(cfg, 0, new_max_peers);
	if (!parse_only) {
		CLI_ERRO_LOG_STDERR(false, "reinitializing");
		if (old_max_peers < new_max_peers &&
		    cfg->md_index != BSR_MD_INDEX_FLEX_INT) {
			printf("Meta data needs more space now, since max_peers\n"
			       "is bigger than in existing meta_data. (%d -> %d)\n",
			       old_max_peers, new_max_peers);
		}

		check_for_existing_data(cfg);
	}


	if (format_version(cfg) < BSR_V08) {
		EXP(TK_GC); EXP('{');
		for (i = 0; i < GEN_CNT_SIZE; i++) {
			EXP(TK_NUM); EXP(';');
			cfg->md.gc[i] = yylval.u64;
		}
		EXP('}');
	} else { // >= 08
		if (is_v08(cfg)) {
			EXP(TK_UUID); EXP('{');
			EXP(TK_U64); EXP(';');
			cfg->md.current_uuid = yylval.u64;
			EXP(TK_U64); EXP(';');
			cfg->md.peers[0].bitmap_uuid = yylval.u64;
			for (i = 0; i < HISTORY_UUIDS_V08; i++) {
				EXP(TK_U64); EXP(';');
				cfg->md.history_uuids[i] = yylval.u64;
			}
			EXP(TK_FLAGS); EXP(TK_U32); EXP(';');
			cfg->md.flags = (uint32_t)yylval.u64;
			EXP('}');
	} else /* >= 09 */ {
			EXP(TK_NODE_ID);
			EXP(TK_NUM); EXP(';');
			cfg->md.node_id = yylval.u64;
			EXP(TK_CURRENT_UUID);
			EXP(TK_U64); EXP(';');
			cfg->md.current_uuid = yylval.u64;
			EXP(TK_FLAGS); EXP(TK_U32); EXP(';');
			cfg->md.flags = (uint32_t)yylval.u64;

			for (i = 0; i < BSR_NODE_ID_MAX; i++) {
				EXP(TK_PEER); EXP('[');
				EXP(TK_NUM); EXP(']');
				cur_slot = yylval.u64;
				if (cur_slot < 0 || cur_slot >= BSR_NODE_ID_MAX) {
					CLI_ERRO_LOG_STDERR(false, "Parse error in line %u: "
						"Slot %d out of range\n",
						yylineno, cur_slot);
					exit(10);
				}
				if (slots_seen[cur_slot]) {
					CLI_ERRO_LOG_STDERR(false, "Parse error in line %u: "
						"Peer slot %d defined multiple times\n",
						yylineno, cur_slot);
					exit(10);
				}
				slots_seen[cur_slot] = 1;

				EXP('{');
				EXP(TK_BITMAP_INDEX);
				EXP(TK_NUM); EXP(';');
				cfg->md.peers[cur_slot].bitmap_index = yylval.u64;
				EXP(TK_BITMAP_UUID); EXP(TK_U64); EXP(';');
				cfg->md.peers[cur_slot].bitmap_uuid = yylval.u64;
				EXP(TK_BITMAP_DAGTAG); EXP(TK_U64); EXP(';');
				cfg->md.peers[cur_slot].bitmap_dagtag = yylval.u64;
				EXP(TK_FLAGS); EXP(TK_U32); EXP(';');
				cfg->md.peers[cur_slot].flags = (uint32_t)yylval.u64;
				EXP('}');
			}
			EXP(TK_HISTORY_UUIDS); EXP('{');
			for (i = 0; i < ARRAY_SIZE(cfg->md.history_uuids); i++) {
				EXP(TK_U64); EXP(';');
				cfg->md.history_uuids[i] = yylval.u64;
			}
			EXP('}');
		}
	}
	EXP(TK_LA_SIZE); EXP(TK_NUM); EXP(';');
	cfg->md.effective_size = yylval.u64;
	if (format_version(cfg) >= BSR_V08) {
		EXP(TK_BM_BYTE_PER_BIT); EXP(TK_NUM); EXP(';');
		cfg->md.bm_bytes_per_bit = yylval.u64;
		/* Check whether the value of bm_bytes_per_bit is
		 * a power-of-two multiple of 4k. */
		if (yylval.u64 < 4096 || (yylval.u64 & (yylval.u64 -1)) != 0) {
			CLI_ERRO_LOG_STDERR(false, "Invalid value for bm-byte-per-bit: "
				"value must be a power-of-two multiple of 4096\n");
			exit(10);
		}
		EXP(TK_DEVICE_UUID); EXP(TK_U64); EXP(';');
		cfg->md.device_uuid = yylval.u64;
		EXP(TK_LA_BIO_SIZE); EXP(TK_NUM); EXP(';');
		cfg->md.la_peer_max_bio_size = yylval.u64;

		EXP(TK_AL_STRIPES); EXP(TK_NUM); EXP(';');
		cfg->md.al_stripes = yylval.u64;
		EXP(TK_AL_STRIPE_SIZE_4K); EXP(TK_NUM); EXP(';');
		cfg->md.al_stripe_size_4k = yylval.u64;
	} else {
		cfg->md.bm_bytes_per_bit = DEFAULT_BM_BLOCK_SIZE;
	}

	if (option_al_stripes != cfg->md.al_stripes ||
	    option_al_stripe_size_4k != cfg->md.al_stripe_size_4k) {
		if (option_al_stripes_used) {
			CLI_ERRO_LOG_STDERR(false, "override activity log striping from commandline");
			cfg->md.al_stripes = option_al_stripes;
			cfg->md.al_stripe_size_4k = option_al_stripe_size_4k;
		}
		if (verbose >= 2)
			CLI_ERRO_LOG_STDERR(false, "adjusting activity-log and bitmap offsets");
		re_initialize_md_offsets(cfg);
	}

	clip_effective_size_and_bm_bytes(cfg);
	parse_bitmap(cfg, parse_only);

	/* there should be no trailing garbage in the input file */
	EXP(0);

	if (parse_only) {
		printf("input file parsed ok\n");
		return 0;
	}

	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg) || err;
	if (err) {
		CLI_ERRO_LOG_STDERR(false, "Writing failed");
		return -1;
	}

	printf("Successfully restored meta data\n");

	return 0;
}

int meta_restore_md(struct format *cfg, char **argv, int argc)
{
	return verify_dumpfile_or_restore(cfg,argv,argc,0);
}

int meta_verify_dump_file(struct format *cfg, char **argv, int argc)
{
	return verify_dumpfile_or_restore(cfg,argv,argc,1);
}

void md_convert_07_to_08(struct format *cfg)
{
	int i,j;
	/*
	 * FIXME
	 * what about the UI_BITMAP, and the Activity Log?
	 * how to bring them over for internal meta data?
	 *
	 * maybe just refuse to convert anything that is not
	 * "clean"? how to detect that?
	 *
	 * FIXME: if I am a crashed R_PRIMARY, or D_INCONSISTENT,
	 * or Want-Full-Sync or the like,
	 * refuse, and indicate how to solve this */

	printf("Converting meta data...\n");

	//if (!cfg->bits_counted) count_bits(cfg);
	/* FIXME:
	 * if this is "internal" meta data, and I have bits set,
	 * either move the bitmap into the newly expected place,
	 * or refuse, and indicate how to solve this */

	/* KB <-> sectors is done in the md disk<->cpu functions.
	 * We only need to adjust the magic here. */
	cfg->md.magic = BSR_MD_MAGIC_08;

	// The MDF Flags are (nearly) the same in 07 and 08
	cfg->md.flags = cfg->md.gc[Flags];

	cfg->md.current_uuid =
		(uint64_t)(cfg->md.gc[HumanCnt] & 0xffff) << 48 |
		(uint64_t)(cfg->md.gc[TimeoutCnt] & 0xffff) << 32 |
		(uint64_t)((cfg->md.gc[ConnectedCnt]+cfg->md.gc[ArbitraryCnt])
		       & 0xffff) << 16 |
		(uint64_t)0xbabe;
	cfg->md.peers[0].bitmap_uuid = (uint64_t)0;

	for (i = cfg->bits_set ? UI_BITMAP : UI_HISTORY_START, j = 1;
		i <= UI_HISTORY_END ; i++, j++) {
		if (i == UI_BITMAP)
			cfg->md.peers[0].bitmap_uuid = cfg->md.current_uuid - j*0x10000;
		else
			cfg->md.history_uuids[i - UI_HISTORY_START] =
				cfg->md.current_uuid - j*0x10000;
	}

	/* unconditionally re-initialize offsets,
	 * not necessary if fixed size external,
	 * necessary if flex external or internal */
	re_initialize_md_offsets(cfg);

	if (!is_valid_md(BSR_V08, &cfg->md, cfg->md_index, cfg->bd_size)) {
		CLI_ERRO_LOG_STDERR(false, "Conversion failed.\nThis is a bug :(");
		exit(111);
	}
}

void md_convert_08_to_07(struct format *cfg)
{
	/*
	 * FIXME
	 * what about the UI_BITMAP, and the Activity Log?
	 * how to bring them over for internal meta data?
	 *
	 * maybe just refuse to convert anything that is not
	 * "clean"? how to detect that?
	 *
	 * FIXME: if I am a crashed R_PRIMARY, or D_INCONSISTENT,
	 * or Want-Full-Sync or the like,
	 * refuse, and indicate how to solve this */

	printf("Converting meta data...\n");
	//if (!cfg->bits_counted) count_bits(cfg);
	/* FIXME:
	 * if this is "internal" meta data, and I have bits set,
	 * either move the bitmap into the newly expected place,
	 * or refuse, and indicate how to solve this */

	/* KB <-> sectors is done in the md disk<->cpu functions.
	 * We only need to adjust the magic here. */
	cfg->md.magic = BSR_MD_MAGIC_07;

	/* FIXME somehow generate GCs in a sane way */
	/* FIXME convert the flags? */
	printf("Conversion v08 -> v07 is BROKEN!\n"
		"Be prepared to manually intervene!\n");
	/* FIXME put some more helpful text here, indicating what exactly is to
	 * be done to make this work as expected. */

	/* unconditionally re-initialize offsets,
	 * not necessary if fixed size external,
	 * necessary if flex external or internal */
	re_initialize_md_offsets(cfg);

	if (!is_valid_md(BSR_V07, &cfg->md, cfg->md_index, cfg->bd_size)) {
		CLI_ERRO_LOG_STDERR(false, "Conversion failed.\nThis is a bug :(");
		exit(111);
	}
}

void md_convert_08_to_09(struct format *cfg)
{
	int p;

	for (p = 0; p < BSR_NODE_ID_MAX; p++) {
		cfg->md.peers[p].bitmap_uuid = 0;
		cfg->md.peers[p].flags = 0;
		cfg->md.peers[p].bitmap_index = -1;
	}

	if (cfg->md.flags & MDF_CONNECTED_IND)
		cfg->md.peers[0].flags |= MDF_PEER_CONNECTED;

	if (cfg->md.flags & MDF_FULL_SYNC)
		cfg->md.peers[0].flags |= MDF_PEER_FULL_SYNC;

	if (cfg->md.flags & MDF_PEER_OUT_DATED)
		cfg->md.peers[0].flags |= MDF_PEER_OUTDATED;

	cfg->md.flags &= ~(MDF_CONNECTED_IND | MDF_FULL_SYNC | MDF_PEER_OUT_DATED);

	cfg->md.node_id = -1;
	cfg->md.magic = BSR_MD_MAGIC_09;
	re_initialize_md_offsets(cfg);

	if (!is_valid_md(BSR_V09, &cfg->md, cfg->md_index, cfg->bd_size)) {
		CLI_ERRO_LOG_STDERR(false, "Conversion failed.\nThis is a bug :(");
		exit(111);
	}
}

void md_convert_09_to_08(struct format *cfg)
{
	if (cfg->md.peers[0].flags & MDF_PEER_CONNECTED)
		cfg->md.flags |= MDF_CONNECTED_IND;

	if (cfg->md.peers[0].flags & MDF_PEER_FULL_SYNC)
		cfg->md.flags |= MDF_FULL_SYNC;

	if (cfg->md.peers[0].flags & MDF_PEER_OUTDATED)
		cfg->md.flags |= MDF_PEER_OUT_DATED;

	cfg->md.magic = BSR_MD_MAGIC_08;
	cfg->md.max_peers = 1;
	re_initialize_md_offsets(cfg);

	if (!is_valid_md(BSR_V08, &cfg->md, cfg->md_index, cfg->bd_size)) {
		CLI_ERRO_LOG_STDERR(false, "Conversion failed.\nThis is a bug :(");
		exit(111);
	}
}

void convert_md(struct format *cfg, enum md_format from)
{
	enum md_format to = format_version(cfg);

	switch(to) {
	default:
	case BSR_UNKNOWN:
	case BSR_V06:
		CLI_ERRO_LOG_STDERR(false, "BUG in %s() %d.", __FUNCTION__, __LINE__);
		exit(10);
	case BSR_V07:
		switch(from) {
		case BSR_V09:
			md_convert_09_to_08(cfg);
		case BSR_V08:
			md_convert_08_to_07(cfg);
		case BSR_V07:
			break;
		case BSR_V06:
		case BSR_UNKNOWN:
		default:
			CLI_ERRO_LOG_STDERR(false, "BUG in %s() %d.", __FUNCTION__, __LINE__);
			exit(10);
		}
		break;
	case BSR_V08:
		switch(from) {
		default:
		case BSR_UNKNOWN:
		case BSR_V06:
			CLI_ERRO_LOG_STDERR(false, "BUG in %s() %d.", __FUNCTION__, __LINE__);
			exit(10);
		case BSR_V07:
			md_convert_07_to_08(cfg);
		case BSR_V08:
			break;
		case BSR_V09:
			md_convert_09_to_08(cfg);
		}
		break;
	case BSR_V09:
		switch(from) {
		default:
		case BSR_UNKNOWN:
		case BSR_V06:
			CLI_ERRO_LOG_STDERR(false, "BUG in %s() %d.", __FUNCTION__, __LINE__);
			exit(10);
		case BSR_V07:
			md_convert_07_to_08(cfg);
		case BSR_V08:
			md_convert_08_to_09(cfg);
		case BSR_V09:
			;
		}
	}
}

/* if on the physical device we find some data we can interpret,
 * print some informational message about what we found,
 * and what we think how much room it needs.
 *
 * look into /usr/share/misc/magic for inspiration
 * also consider e.g. xfsprogs/libdisk/fstype.c,
 * and of course the linux kernel headers...
 */
struct fstype_s {
	const char * type;
	unsigned long long bnum, bsize;
};

int may_be_extX(const char *data, struct fstype_s *f)
{
	unsigned int size;
	if (le16_to_cpu(*(uint16_t*)(data+0x438)) == 0xEF53) {
		if ( (le32_to_cpu(*(data+0x45c)) & 4) == 4 )
			f->type = "ext3 filesystem";
		else
			f->type = "ext2 filesystem";
		f->bnum  = le32_to_cpu(*(uint32_t*)(data+0x404));
		size     = le32_to_cpu(*(uint32_t*)(data+0x418));
		f->bsize = size == 0 ? 1024 :
			size == 1 ? 2048 :
			size == 2 ? 4096 :
			4096; /* DEFAULT */
		return 1;
	}
	return 0;
}

int may_be_xfs(const char *data, struct fstype_s *f)
{
	if (be32_to_cpu(*(uint32_t*)(data+0)) == 0x58465342) {
		f->type = "xfs filesystem";
		f->bsize = be32_to_cpu(*(uint32_t*)(data+4));
		f->bnum  = be64_to_cpu(*(uint64_t*)(data+8));
		return 1;
	}
	return 0;
}

int may_be_reiserfs(const char *data, struct fstype_s *f)
{
	if (strncmp("ReIsErFs",data+0x10034,8) == 0 ||
	    strncmp("ReIsEr2Fs",data+0x10034,9) == 0) {
		f->type = "reiser filesystem";
		f->bnum  = le32_to_cpu(*(uint32_t*)(data+0x10000));
		f->bsize = le16_to_cpu(*(uint16_t*)(data+0x1002c));
		return 1;
	}
	return 0;
}

int may_be_jfs(const char *data, struct fstype_s *f)
{
	if (strncmp("JFS1",data+0x8000,4) == 0) {
		f->type = "JFS filesystem";
		f->bnum = le64_to_cpu(*(uint64_t*)(data+0x8008));
		f->bsize = le32_to_cpu(*(uint32_t*)(data+0x8018));
		return 1;
	}
	return 0;
}

/* really large block size,
 * will always refuse */
#define REFUSE_BSIZE	0xFFFFffffFFFF0000LLU
#define ERR_BSIZE	0xFFFFffffFFFF0001LLU
#define REFUSE_IT()	do { f->bnum = 1; f->bsize = REFUSE_BSIZE; } while(false)
#define REFUSE_IT_ERR()	do { f->bnum = 1; f->bsize = ERR_BSIZE; } while(false)
int may_be_swap(const char *data, struct fstype_s *f)
{
	int looks_like_swap =
		strncmp(data+(1<<12)-10, "SWAP-SPACE", 10) == 0 ||
		strncmp(data+(1<<12)-10, "SWAPSPACE2", 10) == 0 ||
		strncmp(data+(1<<13)-10, "SWAP-SPACE", 10) == 0 ||
		strncmp(data+(1<<13)-10, "SWAPSPACE2", 10) == 0;
	if (looks_like_swap) {
		f->type = "swap space signature";
		REFUSE_IT();
		return 1;
	}
	return 0;
}

#define N_ERR_LINES 4
#define MAX_ERR_LINE_LEN 1024
int guessed_size_from_pvs(struct fstype_s *f, char *dev_name)
{
	char buf_in[200];
	char *buf_err[N_ERR_LINES];
	size_t c;
	unsigned long long bnum;
	int pipes[3][2];
	int err_lines = 0;
	FILE *child_err = NULL;
	int i;
	int ret = 0;
	pid_t pid;

	buf_err[0] = calloc(N_ERR_LINES, MAX_ERR_LINE_LEN);
	if (!buf_err[0])
		return 0;
	for (i = 1; i < N_ERR_LINES; i++)
		buf_err[i] = buf_err[i-1] + MAX_ERR_LINE_LEN;

	for (i = 0; i < 3; i++) {
		if (pipe(pipes[i]))
			goto out;
	}

	pid = fork();
	if (pid < 0)
		goto out;

	setenv("dev_name", dev_name, 1);
	if (pid == 0) {
		/* child */
		char *argv[] = {
			"sh", "-vxc",
			"pvs -vvv --noheadings --nosuffix --units s -o pv_size"
			" --config \"devices { write_cache_state=0 filter = [ 'a|$dev_name|', 'r|.|' ] }\"",
			NULL,
		};
		close(pipes[0][1]); /* close unused pipe ends */
		close(pipes[1][0]);
		close(pipes[2][0]);

		dup2(pipes[0][0],0); /* map to expected stdin/out/err */
		dup2(pipes[1][1],1);
		dup2(pipes[2][1],2);

		close(0); /* we do not use stdin */
		execvp(argv[0], argv);
		bsr_terminate_log(0);
		_exit(0);
	}
	/* parent */
	close(pipes[0][0]); /* close unused pipe ends */
	close(pipes[1][1]);
	close(pipes[2][1]);

	close(pipes[0][1]); /* we do not use stdin in child */

	/* We use blocking IO on pipes. This could deadlock,
	 * If the child process would do something unexpected.
	 * We do know the behaviour of pvs, though,
	 * and expect only a few bytes on stdout,
	 * and quite a few debug messages on stderr.
	 *
	 * First drain stderr, keeping the last N_ERR_LINES,
	 * then read stdout. */
	child_err = fdopen(pipes[2][0], "r");
	if (child_err) {
		char *b;
		do {
			err_lines = (err_lines + 1) % N_ERR_LINES;
			b = fgets(buf_err[err_lines], MAX_ERR_LINE_LEN, child_err);
		} while (b);
	}

	c = read(pipes[1][0], buf_in, sizeof(buf_in)-1);
	if (c > 0) {
		buf_in[c] = 0;
		if (1 == sscanf(buf_in, " %llu\n", &bnum)) {
			f->bnum = bnum;
			f->bsize = 512;
			ret = 1;
		}
	}
	if (!ret) {
		char z[1] = { 0, };

		for (i = 0; i < N_ERR_LINES; i++) {
			char *b = buf_err[(err_lines + i) % N_ERR_LINES];
			if (b[0] == 0)
				continue;
			CLI_ERRO_LOG_STDERR(false, "pvs stderr:%s", b);
		}
		CLI_ERRO_LOG_STDERR(false, "%s", z);
	}

	i = 2;
out:
	for ( ; i >= 0; i--) {
		close(pipes[i][0]);
		close(pipes[i][1]);
	}
	if (child_err)
		fclose(child_err);
	free(buf_err[0]);
	return ret;
}

int may_be_LVM(const char *data, struct fstype_s *f, char *dev_name)
{
	if (strncmp("LVM2",data+0x218,4) == 0) {
		f->type = "LVM2 physical volume signature";
		if (!guessed_size_from_pvs(f, dev_name))
			REFUSE_IT_ERR();
		return 1;
	}
	return 0;
}

/* XXX should all this output go to stderr? */
void check_for_existing_data(struct format *cfg)
{
	struct fstype_s f;
	size_t i;
	uint64_t fs_kB;
	uint64_t max_usable_kB;

	PREAD(cfg, on_disk_buffer, SO_MUCH, 0);

	for (i = 0; i < SO_MUCH/sizeof(long); i++) {
		if (((long*)(on_disk_buffer))[i] != 0LU) break;
	}
	/* all zeros? no message */
	if (i == SO_MUCH/sizeof(long)) return;

	f.type = "some data";
	f.bnum = 0;
	f.bsize = 0;

/* FIXME add more detection magic.
 * Or, rather, use some lib.
 */

	(void)(
	may_be_swap     (on_disk_buffer,&f) ||
	may_be_LVM      (on_disk_buffer,&f, cfg->md_device_name) ||

	may_be_extX     (on_disk_buffer,&f) ||
	may_be_xfs      (on_disk_buffer,&f) ||
	may_be_jfs      (on_disk_buffer,&f) ||
	may_be_reiserfs (on_disk_buffer,&f)
	);

	/* FIXME
	 * some of the messages below only make sense for internal meta data.
	 * for external meta data, we now only checked the meta-disk.
	 * we should still check the actual lower level storage area for
	 * existing data, too, and give appropriate warnings when it would
	 * appear to be truncated by too small external meta data */

	printf("md_offset %llu\n", (long long unsigned)cfg->md_offset);
	printf("al_offset %llu\n", (long long unsigned)cfg->al_offset);
	printf("bm_offset %llu\n", (long long unsigned)cfg->bm_offset);

	printf("\nFound %s\n", f.type);

	/* FIXME overflow check missing!
	 * relevant for ln2(bsize) + ln2(bnum) >= 64, thus only for
	 * device sizes of more than several exa byte.
	 * seems irrelevant to me for now.
	 */
	fs_kB = ((f.bsize * f.bnum) + (1<<10)-1) >> 10;
	max_usable_kB = max_usable_sectors(cfg) >> 1;

	if (f.bnum) {
		if (cfg->md_index >= 0 ||
		    cfg->md_index == BSR_MD_INDEX_FLEX_EXT) {
			printf("\nThis would corrupt existing data.\n");
			if (ignore_sanity_checks) {
				printf("\nIgnoring sanity check on user request.\n\n");
				return;
			}
			CLI_WRAN_LOG_PRINT(false,
								"If you want me to do this, you need to zero out the first part\n"
								"of the device (destroy the content).\n"
								"You should be very sure that you mean it.\n"
								"Operation refused.(40)\n\n");
			exit(40); /* FIXME sane exit code! */
		}

		if (f.bsize < REFUSE_BSIZE)
			printf("%12llu kB data area apparently used\n", (unsigned long long)fs_kB);
		printf("%12llu kB left usable by current configuration\n", (unsigned long long)max_usable_kB);

		if (f.bsize == ERR_BSIZE)
			printf(
"Could not determine the size of the actually used data area.\n\n");
		if (f.bsize >= REFUSE_BSIZE) {
			printf(
"Device size would be truncated, which\n"
"would corrupt data and result in\n"
"'access beyond end of device' errors.\n");
			if (ignore_sanity_checks) {
				printf("\nIgnoring sanity check on user request.\n\n");
				return;
			}
			CLI_WRAN_LOG_PRINT(false, 
								"If you want me to do this, you need to zero out the first part\n"
								"of the device (destroy the content).\n"
								"You should be very sure that you mean it.\n"
								"Operation refused.(40)\n\n");

			exit(40); /* FIXME sane exit code! */
		}

		/* looks like file system data */
		if (fs_kB > max_usable_kB) {
			CLI_WRAN_LOG_PRINT(false,
								"\nDevice size would be truncated, which\n"
								"would corrupt data and result in\n"
								"'access beyond end of device' errors.\n"
								"You need to either\n"
								"   * use external meta data (recommended)\n"
								"   * shrink that filesystem first\n"
								"   * zero out the device (destroy the filesystem)\n"
								"Operation refused.(40)\n\n");

			exit(40); /* FIXME sane exit code! */
		} else {
			printf(
"\nEven though it looks like this would place the new meta data into\n"
"unused space, you still need to confirm, as this is only a guess.\n");
		}
	} else
		printf("\n ==> This might destroy existing data! <==\n");

	if (!confirmed("Do you want to proceed?")) {
		CLI_WRAN_LOG_PRINT(false, "Operation canceled.(1)\n");
		exit(1); // 1 to avoid online resource counting
	}
}

/* tries to guess what is in the on_disk_buffer */
enum md_format detect_md(struct md_cpu *md, const uint64_t ll_size, int index_format)
{
	struct md_cpu md_test;
	enum md_format have = BSR_UNKNOWN;

	md_disk_07_to_cpu(&md_test, (struct md_on_disk_07*)on_disk_buffer);
	if (is_valid_md(BSR_V07, &md_test, index_format, ll_size)) {
		have = BSR_V07;
		*md = md_test;
	}

	md_disk_08_to_cpu(&md_test, (struct md_on_disk_08*)on_disk_buffer);
	if (is_valid_md(BSR_V08, &md_test, index_format, ll_size)) {
		have = BSR_V08;
		*md = md_test;
	}

	md_disk_09_to_cpu(&md_test, (struct meta_data_on_disk_9*)on_disk_buffer);
	if (is_valid_md(BSR_V09, &md_test, index_format, ll_size)) {
		have = BSR_V09;
		*md = md_test;
	}

	return have;
}

void check_internal_md_flavours(struct format * cfg) {
	struct md_cpu md_now;
	off_t fixed_offset, flex_offset;
	enum md_format have = BSR_UNKNOWN;
	int fixed = 0; /* as opposed to flex */

	ASSERT( cfg->md_index == BSR_MD_INDEX_INTERNAL ||
		cfg->md_index == BSR_MD_INDEX_FLEX_INT );

	fixed_offset = v07_style_md_get_byte_offset(
		BSR_MD_INDEX_INTERNAL, cfg->bd_size);
	flex_offset = v07_style_md_get_byte_offset(
		BSR_MD_INDEX_FLEX_INT, cfg->bd_size);

	/* printf("%lld\n%lld\n%lld\n", (long long unsigned)cfg->bd_size,
	   (long long unsigned)fixed_offset, (long long unsigned)flex_offset); */
	if (0 <= fixed_offset && fixed_offset < (off_t)cfg->bd_size - 4096) {
		struct md_cpu md_test;
		/* ... v07 fixed-size internal meta data? */
		PREAD(cfg, on_disk_buffer, 4096, fixed_offset);

		md_disk_07_to_cpu(&md_test,
			(struct md_on_disk_07*)on_disk_buffer);
		if (is_valid_md(BSR_V07, &md_test, BSR_MD_INDEX_INTERNAL, cfg->bd_size)) {
			have = BSR_V07;
			fixed = 1;
			md_now = md_test;
		}
	}

	if (have == BSR_UNKNOWN) {
		PREAD(cfg, on_disk_buffer, 4096, flex_offset);
		have = detect_md(&md_now, cfg->bd_size, BSR_MD_INDEX_FLEX_INT);
	}

	if (have == BSR_UNKNOWN)
		return;

	CLI_ERRO_LOG_STDERR(false, "You want me to create a %s%s style %s internal meta data block.",
		cfg->ops->name,
		(is_v07(cfg) && cfg->md_index == BSR_MD_INDEX_FLEX_INT) ? "(plus)" : "",
		cfg->md_index == BSR_MD_INDEX_FLEX_INT ? "flexible-size" : "fixed-size");


	CLI_ERRO_LOG_STDERR(false, "There appears to be a %s %s internal meta data block"
		"already in place on %s at byte offset %llu\n",
		f_ops[have].name, fixed ? "fixed-size" : "flexible-size",
		cfg->md_device_name,
		fixed ? (long long unsigned)fixed_offset : (long long unsigned)flex_offset);

	if (format_version(cfg) == have) {
		if (have != BSR_V07
		&& (cfg->md.al_stripes != option_al_stripes
		||  cfg->md.al_stripe_size_4k != option_al_stripe_size_4k)) {
			if (confirmed("Do you want to change the activity log stripe settings *only*?")) {
				CLI_ERRO_LOG_STDERR(false, 
					"Sorry, not yet fully implemented\n"
					"Try dump-md > dump.txt; restore-md -s x -z y dump.txt\n");
				exit(30);
				/*
				 *  ???
				 * cfg->md.al_stripes = option_al_stripes;
				 * cfg->md.al_stripe_size_4k = option_al_stripe_size_4k;
				 * re_initialize_md_offsets(cfg);
				 * return;
				 *  ???
				 */
			}
		}
		if (!confirmed("Do you really want to overwrite the existing meta-data?")) {
			CLI_WRAN_LOG_PRINT(false, "Operation cancelled.(1)\n");
			exit(1); // 1 to avoid online resource counting
		}
		cfg->md.magic = 0;
	} else {
		char msg[160];

		snprintf(msg, 160, "Valid %s meta-data found, convert to %s?",
			 f_ops[have].name, cfg->ops->name);
		if (confirmed(msg)) {
			cfg->md = md_now;
			convert_md(cfg, have);
		} else {
			snprintf(msg, 160, "So you want me to replace the %s meta-data\n"
				 "with newly initialized %s meta-data?",
				 f_ops[have].name, cfg->ops->name);
			if (!confirmed(msg)) {
				CLI_WRAN_LOG_PRINT(false, "Operation cancelled.(1)\n");
				exit(1); // 1 to avoid online resource counting
			}
			cfg->md.magic = 0;
		}
	}

	/* we have two "internal" layouts:
	 * v07 "fixed" internal:
	 * | data .... |MD super block |AL | bitmap                      |
	 * v07 "plus", v08, v09 "flexible" internal:
	 * | data ....                  |    bitmap  |AL |MD super block |
	 * If we change from one layout to the other,
	 * we want to wipe the former MD super block
	 * after successful conversion.
	 */
	/* we convert from v07 "fixed" to flexible internal, we wipe the "fixed" offset */
	if (have == BSR_V07 && fixed && cfg->md_index == BSR_MD_INDEX_FLEX_INT)
		cfg->wipe_fixed = fixed_offset;
	/* we convert from "flexible" to v07 fixed, we wipe the "flexible" offset */
	else if ((have != BSR_V07 || fixed == 0) && (is_v07(cfg) && cfg->md_index == BSR_MD_INDEX_INTERNAL))
		cfg->wipe_flex = flex_offset;
}

void wipe_after_convert(struct format *cfg)
{
	memset(on_disk_buffer, 0x00, 4096);
	if (cfg->wipe_fixed)
		pwrite_or_die(cfg, on_disk_buffer, 4096, cfg->wipe_fixed,
			"wipe fixed-size v07 internal md");
	if (cfg->wipe_flex)
		pwrite_or_die(cfg, on_disk_buffer, 4096, cfg->wipe_flex,
			"wipe flexible-size internal md");
}

void check_external_md_flavours(struct format * cfg) {
	struct md_cpu md_now;
	enum md_format have = BSR_UNKNOWN;
	char msg[160];

	ASSERT( cfg->md_index >= 0 ||
		cfg->md_index == BSR_MD_INDEX_FLEX_EXT );

	if (cfg->md.magic) {
		if (!confirmed("Valid meta data seems to be in place.\n"
				"Do you really want to overwrite?")) {
			CLI_WRAN_LOG_PRINT(false, "Operation cancelled.(1)\n");
			exit(1);
		}
		cfg->md.magic = 0;
		return;
	}

	PREAD(cfg, on_disk_buffer, 4096, cfg->md_offset);
	have = detect_md(&md_now, cfg->bd_size, BSR_MD_INDEX_FLEX_EXT);

	if (have == BSR_UNKNOWN)
		return;

	snprintf(msg, 160, "Valid %s meta-data found, convert to %s?",
		 f_ops[have].name, cfg->ops->name);
	if (confirmed(msg)) {
		cfg->md = md_now;
		convert_md(cfg, have);
	} else {
		snprintf(msg, 160, "So you want me to replace the %s meta-data\n"
			 "with newly initialized %s meta-data?",
			 f_ops[have].name, cfg->ops->name);
		if (confirmed(msg)) {
			cfg->md.magic = 0;
			return;
		}

		CLI_WRAN_LOG_PRINT(false, "Operation cancelled.(1)\n");
		exit(1);
	}
}

/* ok, so there is no valid meta data at the end of the device,
 * but there is valid internal meta data at the "last known"
 * position.  Move the stuff.
 * Areas may overlap:
 * |--...~//~[BITMAP][AL][SB]|     <<- last known
 * |--.......~//~[BITMAP][AL][SB]| <<- what it should look like now
 * So we move it in chunks.
 */
int v08_move_internal_md_after_resize(struct format *cfg)
{
	struct md_cpu md_old;
	off_t old_offset;
	off_t old_bm_offset;
	off_t cur_offset;
	off_t last_chunk_size;
	int err;

	ASSERT(format_version(cfg) >= BSR_V08);
	ASSERT(cfg->md_index == BSR_MD_INDEX_FLEX_INT);
	ASSERT(cfg->lk_bd.bd_size <= cfg->bd_size);

	/* we just read it in v08_check_for_resize().
	 * no need to do it again, but ASSERT this. */
	md_old = cfg->md;
	ASSERT(is_valid_md(format_version(cfg), &md_old, BSR_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size));
	old_offset = v07_style_md_get_byte_offset(BSR_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);

	/* fix AL and bitmap offsets, populate byte offsets for the new location */
	re_initialize_md_offsets(cfg);

	CLI_ERRO_LOG_STDERR(false, "Moving the internal meta data to its proper location");

	if (verbose >= 2) {
		CLI_ERRO_LOG_STDERR(false, "old md_offset: "U64"", old_offset);
		CLI_ERRO_LOG_STDERR(false, "old al_offset: %llu (%d)", old_offset + md_old.al_offset * 512LL, md_old.al_offset);
		CLI_ERRO_LOG_STDERR(false, "old bm_offset: %llu (%d)", old_offset + md_old.bm_offset * 512LL, md_old.bm_offset);

		CLI_ERRO_LOG_STDERR(false, "new md_offset: "U64"", cfg->md_offset);
		CLI_ERRO_LOG_STDERR(false, "new al_offset: "U64" (%d)", cfg->al_offset, cfg->md.al_offset);
		CLI_ERRO_LOG_STDERR(false, "new bm_offset: "U64" (%d)", cfg->bm_offset, cfg->md.bm_offset);

		CLI_ERRO_LOG_STDERR(false, "md_size_sect: "U32"", cfg->md.md_size_sect);
		CLI_ERRO_LOG_STDERR(false, "max_usable_sect: "U64"", cfg->max_usable_sect);
	}

	/* FIXME
	 * If the new meta data area overlaps the old "super block",
	 * and we crash before we successfully wrote the new super block,
	 * but after we overwrote the old, we are out of luck!
	 * But I don't want to write the new superblock early, either.
	 */

	/* move activity log, fixed size immediately preceeding the "super block". */
	cur_offset = old_offset + md_old.al_offset * 512LL;
	PREAD(cfg, on_disk_buffer, old_offset - cur_offset, cur_offset);
	PWRITE(cfg, on_disk_buffer, old_offset - cur_offset, cfg->al_offset);

	/* The AL was of fixed size.
	 * Bitmap is of flexible size, new bitmap is likely larger.
	 * We do not initialize that part, we just leave "garbage" in there.
	 * Once BSR "agrees" on the new lower level device size, that part of
	 * the bitmap will be handled by the module, anyways. */
	old_bm_offset = old_offset + cfg->md.bm_offset * 512LL;

	/* move bitmap, in chunks, peel off from the end. */
	cur_offset = old_offset + cfg->md.al_offset * 512LL - buffer_size;
	while (cur_offset > old_bm_offset) {
		PREAD(cfg, on_disk_buffer, buffer_size, cur_offset);
		PWRITE(cfg, on_disk_buffer, buffer_size,
				cfg->bm_offset + (cur_offset - old_bm_offset));
		cur_offset -= buffer_size;
	}

	/* Adjust for last, possibly partial buffer. */
	last_chunk_size = buffer_size - (old_bm_offset - cur_offset);
	PREAD(cfg, on_disk_buffer, last_chunk_size, old_bm_offset);
	PWRITE(cfg, on_disk_buffer, last_chunk_size, cfg->bm_offset);

	/* fix bitmap offset in meta data,
	 * and rewrite the "super block" */
	re_initialize_md_offsets(cfg);

	err = cfg->ops->md_cpu_to_disk(cfg);

	if (!err)
		printf("Internal bsr meta data successfully moved.\n");

	if (!err && old_offset < cfg->bm_offset) {
		/* wipe out previous meta data block, it has been superseded. */
		cfg->wipe_resize = old_offset;
		memset(on_disk_buffer, 0, 4096);
		PWRITE(cfg, on_disk_buffer, 4096, old_offset);
	}

	err = cfg->ops->close(cfg) || err;
	if (err)
		CLI_ERRO_LOG_STDERR(false, "operation failed");

	return err;
}

int meta_create_md(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int err = 0;
	int max_peers = 1;

	if (is_v09(cfg)) {
		if (argc < 1) {
			CLI_ERRO_LOG_STDERR(false, "USAGE: %s MINOR v09 ... create-md MAX_PEERS"
				"\n"
				"  MAX_PEERS argument missing\n", progname);
			exit(20);
		} else if (argc > 1)
			CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");

		max_peers = m_strtoll(argv[0], 1);
	} else if (argc > 0)
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");

	if (max_peers < 1 || max_peers > BSR_PEERS_MAX) {
		CLI_ERRO_LOG_STDERR(false, "MAX_PEERS argument not in allowed range 1 .. %d.", BSR_PEERS_MAX);
		exit(20);
	}
#ifdef _WIN_VHD_META_SUPPORT
	char * meta_volume = _get_win32_device_ns(cfg->md_device_name);
	// DW-1423 directory has been created while opening, it must exist. need to see if this's still directory.
	int access_ret = access(meta_volume, R_OK);
	int opendir_ret = opendir(meta_volume);

	if (opendir_ret)
		closedir(meta_volume);
	// whether to need vhd type
	if (cfg->vhd_dev_path && (F_OK != access_ret || opendir_ret)) {
		
		uint64_t evsm;		// Estimated Vhd Size per MiB
		evsm = _get_bdev_size_by_letter('C' + cfg->minor); // per bytes
		evsm = ((evsm >> 20) / 32768) * max_peers
			+ 1		/* for bsr reservation */
			+ 7;	/* for vhd reservation */

		// check the pre-created vhd
		if (F_OK == access(cfg->vhd_dev_path, R_OK)) {
			struct stat st;
			stat(cfg->vhd_dev_path, &st);
			uint64_t rvsm = st.st_size;	// Real VHD Size(per MB)
			rvsm >>= 20;
			if (rvsm <= evsm) {	// Need to re-create?
				remove(cfg->vhd_dev_path);
			}
		}

		// Make temporarily creation_vhd_script and call diskpart command with script
		if (!_create_vhd_script(cfg->vhd_dev_path, evsm, cfg->md_device_name)) {
			char * _argv[] = { "diskpart", "/s", "./"CREATE_VHD_SCRIPT, (char *)0 };
			CLI_ERRO_LOG_STDERR(false, "Creating %s for meta data...", cfg->vhd_dev_path);
			if (_call_script(_argv)) {
				remove("./"CREATE_VHD_SCRIPT);
				CLI_ERRO_LOG_STDERR(false, "diskpart create failed.");
				exit(20);
			}
			remove("./"CREATE_VHD_SCRIPT);
		}
	}

	if (meta_volume) {
		free(meta_volume);
	}
#endif
	err = cfg->ops->open(cfg);

	/* Suggest to move existing meta data after offline resize.  Though, if
	 * you --force create-md, you probably mean it, so we don't even ask.
	 * If you want to automatically move it, use check-resize.
	 */
	if (err == VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION) {
		if (option_al_stripes_used) {
			if (option_al_stripes != cfg->md.al_stripes
			||  option_al_stripe_size_4k != cfg->md.al_stripe_size_4k) {
				CLI_ERRO_LOG_STDERR(false, "Cannot move after offline resize and change AL-striping at the same time, yet.");
				exit(20);
			}
		}
		if (!force &&
		    confirmed("Move internal meta data from last-known position?\n")) {
			/* Maybe we want to use some library that provides detection of
			 * fs/partition/usage types? */
			check_for_existing_data(cfg);
			return v08_move_internal_md_after_resize(cfg);
		}
		/* else: reset cfg->md, it needs to be re-initialized below */
		memset(&cfg->md, 0, sizeof(cfg->md));
	}

	/* the offset of v07 fixed-size internal meta data is different from
	 * the offset of the flexible-size v07 ("plus") and v08 (default)
	 * internal meta data.
	 * to avoid the situation where we would have "valid" meta data blocks
	 * of different versions at different offsets, we also need to check
	 * the other format, and the other offset.
	 *
	 * on a request to create v07 fixed-size internal meta data, we also
	 * check flex-internal v08 [and v07 (plus)] at the other offset.
	 *
	 * on a request to create v08 flex-internal meta data (or v07 plus, for
	 * that matter), we also check the same offset for the respective other
	 * flex-internal format version, as well as the v07 fixed-size internal
	 * meta data offset for its flavor of meta data.
	 */
	if (cfg->md_index == BSR_MD_INDEX_INTERNAL ||
	    cfg->md_index == BSR_MD_INDEX_FLEX_INT)
		check_internal_md_flavours(cfg);
	else
		check_external_md_flavours(cfg);

	if (!cfg->md.magic) /* not converted: initialize */
		/* calls check_for_existing_data() internally */
		err = cfg->ops->md_initialize(cfg, 1, max_peers); /* Clears on disk AL implicitly */
	else {
		if (format_version(cfg) >= BSR_V09 && max_peers != 1)
			printf("Warning: setting max_peers to 1 instead of %d\n\n",
			       max_peers);
		err = 0; /* we have sucessfully converted somthing */

		check_for_existing_data(cfg);
	}

	cfg->md.la_peer_max_bio_size = option_peer_max_bio_size;

	/* FIXME
	 * if this converted fixed-size 128MB internal meta data
	 * to flexible size, we'd need to move the AL and bitmap
	 * over to the new location!
	 * But the upgrade procedure in such case is documented to first get
	 * the previous BSR into "clean" L_ESTABLISHED R_SECONDARY/R_SECONDARY, so AL
	 * and bitmap should be empty anyways.
	 */
	printf("Writing meta data...\n");
	err = err || cfg->ops->md_cpu_to_disk(cfg); // <- short circuit
	if (!err)
		wipe_after_convert(cfg);
	err = cfg->ops->close(cfg)          || err; // <- close always
	if (err) {
		CLI_ERRO_LOG_STDERR(false, "operation failed");
	}
	else
		printf("New bsr meta data block successfully created.\n");

	return err;
}

int meta_wipe_md(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int virgin, err;
	if (argc > 0) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}

	virgin = cfg->ops->open(cfg);
	if (virgin) {
		CLI_ERRO_LOG_STDERR(false, "There appears to be no bsr meta data to wipe out?");
		return 0;
	}

	if (!confirmed("Do you really want to wipe out the BSR meta data?")) {
		CLI_WRAN_LOG_PRINT(false, "Operation cancelled.(1)\n");
		exit(1);
	}

	printf("Wiping meta data...\n");
	memset(on_disk_buffer, 0, 4096);
	PWRITE(cfg, on_disk_buffer, 4096, cfg->md_offset);

	err = cfg->ops->close(cfg);
	if (err) {
		CLI_ERRO_LOG_STDERR(false, "operation failed");
	}
	else
		printf("BSR meta data block successfully wiped out.\n");

	/* delete last-known bdev info, it is of no use now. */
	lk_bdev_delete(cfg->minor);

	return err;
}

int meta_outdate(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int err;

	if (argc > 0) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}

	if (cfg->ops->open(cfg))
		return -1;

	if (cfg->ops->outdate_gi(&cfg->md)) {
		CLI_ERRO_LOG_STDERR(false, "Device is inconsistent.");
		exit(5);
	}

	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg)          || err; // <- close always
	if (err)
		CLI_ERRO_LOG_STDERR(false, "update failed");

	return err;
}

int meta_invalidate(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int err;

	if (argc > 0) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}

	if (cfg->ops->open(cfg))
		return -1;

	cfg->ops->invalidate_gi(&cfg->md);
	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg)          || err; // <- close always
	if (err)
		CLI_ERRO_LOG_STDERR(false, "update failed");

	return err;
}

int meta_read_dev_uuid(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	if (argc > 0) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}

	if (cfg->ops->open(cfg))
		return -1;

	printf(X64(016)"\n",cfg->md.device_uuid);

	return cfg->ops->close(cfg);
}

int meta_write_dev_uuid(struct format *cfg, char **argv, int argc)
{
	int err;

	if (argc > 1) {
		CLI_ERRO_LOG_STDERR(false, "Ignoring additional arguments");
	}
	if (argc < 1) {
		CLI_ERRO_LOG_STDERR(false, "Required Argument missing");
		exit(10);
	}

	if (cfg->ops->open(cfg))
		return -1;

	cfg->md.device_uuid = strto_u64(argv[0],NULL,16);

	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg) || err;
	if (err)
		CLI_ERRO_LOG_STDERR(false, "update failed");

	return err;
}

void print_usage_and_exit()
{
	char **args;
	size_t i;

	printf
	    ("\nUSAGE: %s [--force] DEVICE FORMAT [FORMAT ARGS...] COMMAND [CMD ARGS...]\n",
	     progname);

	printf("\nFORMATS:\n");
	for (i = BSR_V06; i < BSR_UNKNOWN; i++) {
		printf("  %s", f_ops[i].name);
		if ((args = f_ops[i].args)) {
			while (*args) {
				printf(" %s", *args++);
			}
		}
		printf("\n");
	}

	printf("\nCOMMANDS:\n");
	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (!cmds[i].show_in_usage)
			continue;
		printf("  %s%s %s\n", cmds[i].name,
		       cmds[i].node_id_required ? " --node-id {val}" : "",
		       cmds[i].args ? cmds[i].args : "");
	}

	CLI_WRAN_LOG(false, "print usage and exit(20)\n");
	exit(20);
}

int parse_format(struct format *cfg, char **argv, int argc, int *ai)
{
	enum md_format f;

	if (argc < 1) {
		CLI_ERRO_LOG_STDERR(false, "Format identifier missing");
		return -1;
	}

	for (f = BSR_V06; f < BSR_UNKNOWN; f++) {
		if (!strcmp(f_ops[f].name, argv[0]))
			break;
	}
	if (f == BSR_UNKNOWN) {
		CLI_ERRO_LOG_STDERR(false, "Unknown format '%s'.", argv[0]);
		return -1;
	}

	(*ai)++;

	cfg->ops = f_ops + f;
	return cfg->ops->parse(cfg, argv + 1, argc - 1, ai);
}


static enum bsr_disk_state bsr_str_disk(const char *str)
{
	/* bsr 8.4 and earlier provide "Local/Remote"
	 * bsr 9. only "Local". */
	const char *slash = strchr(str, '/');
	size_t len;
	int n;

	if (slash)
		len = slash - str;
	else
		len = strlen(str);

	for (n = 0; n < bsr_disk_state_names.size; n++) {
		if (bsr_disk_state_names.names[n] &&
		    !strncmp(str, bsr_disk_state_names.names[n], len))
			return (enum bsr_disk_state)n;
	}
	if (!strcmp(str, "Unconfigured"))
		return D_DISKLESS;

	CLI_ERRO_LOG_STDERR(false, "Unexpected output from bsrsetup >%s<", str);
	exit(20);
}


int is_attached(int minor)
{
    char minor_string[7], result[40];
	char *argv[] = { "bsrsetup", minor_string, "dstate", NULL };
	int pipes[2];
	pid_t pid;
	int rr, exitcode;

	if (pipe(pipes)) {
		CLI_ERRO_LOG_PEEROR(false, "bsrsetup pipe");
		exit(20);
	}

	snprintf(minor_string, ARRAY_SIZE(minor_string), "%d", minor);

	pid = fork();
	if (pid == -1) {
		CLI_ERRO_LOG_PEEROR(false, "fork for bsrsetup");
		exit(20);
	}
	if (pid == 0) {
		FILE *f = freopen("/dev/null", "w", stderr);
		if (!f)
			// DW-1777 revert source and change error message
			CLI_ERRO_LOG_STDERR(false, "open null service failed");

		close(pipes[0]);
		dup2(pipes[1], 1);

		execvp(argv[0], argv);
		CLI_ERRO_LOG_STDERR(false, "Can not exec bsrsetup");
		exit(20);
	}
	close(pipes[1]);

	rr = read(pipes[0], result, ARRAY_SIZE(result));
	close(pipes[0]);
	waitpid(pid, &exitcode, 0);
	if (WEXITSTATUS(exitcode) == 20 || WEXITSTATUS(exitcode) == 10)
		return 0; /* 20 == no module; 10 == no minor */

	if (rr < 1) {
		CLI_ERRO_LOG_PEEROR(false, "read from bsrsetup");
		exit(20);
	}
	result[rr-1] = 0;

	return bsr_str_disk(result) > D_DISKLESS ? 1 : 0;
}

int meta_chk_offline_resize(struct format *cfg, char **argv, int argc)
{
	int err;

	err = cfg->ops->open(cfg);

	/* this is first, so that lk-bdev-info files are removed/updated
	 * if we find valid meta data in the expected place. */
	if (err == VALID_MD_FOUND) {
		/* Do not clutter the output of the init script
		printf("Found valid meta data in the expected location, %llu bytes into %s.\n",
		       (unsigned long long)cfg->md_offset, cfg->md_device_name);
		*/
		/* create, delete or update the last known info */
		if (lk_bdev_load(cfg->minor, &cfg->lk_bd) < 0)
				return -1;
		if (cfg->md_index != BSR_MD_INDEX_FLEX_INT)
			lk_bdev_delete(cfg->minor);
		else if (cfg->lk_bd.bd_size != cfg->bd_size ||
			 cfg->lk_bd.bd_uuid != cfg->md.device_uuid)
			cfg->update_lk_bdev = 1;
		return cfg->ops->close(cfg);
	} else if (err == NO_VALID_MD_FOUND) {
		if (format_version(cfg) < BSR_V08 || cfg->md_index != BSR_MD_INDEX_FLEX_INT) {
			CLI_ERRO_LOG_STDERR(false, "Operation only supported for >= v8 internal meta data");
			return -1;
		}
		CLI_ERRO_LOG_STDERR(false, "no suitable meta data found :(");
		return -1; /* sorry :( */
	}
	/* VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION */

	ASSERT(format_version(cfg) >= BSR_V08);
	ASSERT(cfg->md_index == BSR_MD_INDEX_FLEX_INT);
	ASSERT(cfg->lk_bd.bd_size);
	ASSERT(cfg->md.magic);

	return v08_move_internal_md_after_resize(cfg);
}

int meta_forget_peer(struct format *cfg, char **argv, int argc)
{
	int err;

	err = cfg->ops->open(cfg);
	if (err)
		return -1;

	cfg->md.peers[option_node_id].bitmap_index = -1;
	cfg->md.peers[option_node_id].bitmap_uuid = 0;
	cfg->md.peers[option_node_id].flags = 0;

	cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg) || err;
	if (err)
		CLI_ERRO_LOG_STDERR(false, "update failed");

	return err;
}

/* CALL ONLY ONCE as long as on_disk_buffer is global! */
struct format *new_cfg()
{
	int err;
	struct format *cfg;

	errno = 0;
	pagesize = sysconf(_SC_PAGESIZE);
	if (errno) {
		CLI_ERRO_LOG_PEEROR(false, "could not determine pagesize");
		exit(20);
	}
	cfg = calloc(1, sizeof(struct format));
	if (!cfg) {
		CLI_ERRO_LOG_STDERR(false, "could not calloc() cfg");
		exit(20);
	}
	err = posix_memalign(&on_disk_buffer, pagesize, ALIGN(buffer_size, pagesize));
	if (err) {
		CLI_ERRO_LOG_STDERR(false, "could not posix_memalign() on_disk_buffer");
		exit(20);
	}
	return cfg;
}

extern char *lprogram;
extern char *lcmd;
// BSR-614
extern int llevel;
// BSR-1031
extern int lstatus;
extern char execution_log[512];

int main(int argc, char **argv)
{
	struct format *cfg;
	size_t i;
	int ai, rv;
	bool minor_attached = false;

	if ((progname = strrchr(argv[0], '/'))) {
		lprogram = argv[0] = ++progname;
	}
	else {
		lprogram = progname = argv[0];
	}

	// BSR-1031 set execution_log, output on error
	set_exec_log(argc, argv);

#if 1
	if (sizeof(struct md_on_disk_07) != 4096) {
		CLI_ERRO_LOG_STDERR(false, "Where did you get this broken build!?"
				"sizeof(md_on_disk_07) == %lu, should be 4096\n",
				(unsigned long)sizeof(struct md_on_disk_07));
		exit(111);
	}
	if (sizeof(struct md_on_disk_08) != 4096) {
		CLI_ERRO_LOG_STDERR(false, "Where did you get this broken build!?"
				"sizeof(md_on_disk_08) == %lu, should be 4096\n",
				(unsigned long)sizeof(struct md_on_disk_08));
		exit(111);
	}
	if (sizeof(struct meta_data_on_disk_9) != 4096) {
		CLI_ERRO_LOG_STDERR(false, "Where did you get this broken build!?"
				"sizeof(meta_data_on_disk_9) == %lu, should be 4096\n",
				(unsigned long)sizeof(struct meta_data_on_disk_9));
		exit(111);
	}
#if 0
	printf("v07: al_offset: %u\n", (int)&(((struct md_on_disk_07*)0)->al_offset));
	printf("v07: bm_offset: %u\n", (int)&(((struct md_on_disk_07*)0)->bm_offset));
	printf("v08: al_offset: %u\n", (int)&(((struct md_on_disk_08*)0)->al_offset));
	printf("v08: bm_offset: %u\n", (int)&(((struct md_on_disk_08*)0)->bm_offset));
	exit(0);
#endif
#endif

	if (argc < 4)
		print_usage_and_exit();

	/* so dump_md can write a nice header */
	global_argc = argc;
	global_argv = argv;

	/* Check for options (e.g. --force) */
	while (1) {
	    int c = getopt_long(argc, argv, make_optstring(metaopt), metaopt, 0);

	    if (c == -1)
		break;

	    switch (c) {
	    case 0:
		break;
	    case 'f':
		force = 1;
		break;
	    case 'v':
		verbose++;
		break;
	    case 'p':
		    option_peer_max_bio_size = m_strtoll(optarg, 1);
		    if (option_peer_max_bio_size < 0 ||
			option_peer_max_bio_size > 1024 * 1024) {
				CLI_ERRO_LOG_STDERR(false, "peer-max-bio-size out of range (0...1M)");
			    exit(10);
		    }
		    break;
	    case 'i':
		    option_node_id = m_strtoll(optarg, 1);
		    if (option_node_id < 0 || option_node_id > (BSR_PEERS_MAX - 1)) {
				CLI_ERRO_LOG_STDERR(false, "node-id out of range (0...%d)", BSR_PEERS_MAX - 1);
			    exit(10);
		    }
		    break;
	    case 's':
		    option_al_stripes = m_strtoll(optarg, 1);
		    option_al_stripes_used = 1;
		    break;
	    case 'z':
		    option_al_stripe_size_4k = m_strtoll(optarg, 'k')/4;
		    option_al_stripes_used = 1;
		    break;
	    default:
		print_usage_and_exit();
		break;
	    }
	}

	// Next argument to process is specified by optind...
	ai = optind;

	cfg = new_cfg();
	cfg->bsr_dev_name = argv[ai++];

	if (parse_format(cfg, argv + ai, argc - ai, &ai)) {
		/* parse has already printed some error message */
		exit(20);
	}

	if (ai >= argc) {
		CLI_ERRO_LOG_STDERR(false, "command missing");
		exit(20);
	}

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (!strcmp(cmds[i].name, argv[ai])) {
			command = cmds + i;
			break;
		}
	}
	if (command == NULL) {
		CLI_ERRO_LOG_STDERR(false, "Unknown command '%s'.", argv[ai]);
		exit(20);
	}
	ai++;

	lcmd = (char *)command->name;
	// BSR-1031
	lstatus = command->is_status_cmd;
	// execution_log output
	bsr_exec_log();

	/* does exit() unless we acquired the lock.
	 * unlock happens implicitly when the process dies,
	 * but may be requested implicitly
	 */
	if (strcmp(cfg->bsr_dev_name, "-")) {
		cfg->minor = dt_minor_of_dev(cfg->bsr_dev_name);
		if (cfg->minor < 0) {
			CLI_ERRO_LOG_STDERR(false, "Cannot determine minor device number of "
					"bsr device '%s'",
				cfg->bsr_dev_name);
			exit(20);
		}
		cfg->lock_fd = dt_lock_bsr(cfg->minor);

		/* check whether this is in use */
		minor_attached = is_attached(cfg->minor);
		if (minor_attached && command->modifies_md) {
			CLI_ERRO_LOG_STDERR(false, "Device '%s' is configured!",
				cfg->bsr_dev_name);
			exit(20);
		}
	} else {
		cfg->minor = -1;
		cfg->lock_fd = -1;
	}

	if (option_peer_max_bio_size &&
	    command->function != &meta_create_md) {
		CLI_ERRO_LOG_STDERR(false, "The --peer-max-bio-size option is only allowed with create-md");
		exit(10);
	}
	if (option_al_stripes_used &&
	    command->function != &meta_create_md &&
	    command->function != &meta_restore_md) {
		CLI_ERRO_LOG_STDERR(false, "The --al-stripe* options are only allowed with create-md and restore-md");
		exit(10);
	}

	/* at some point I'd like to go for this: (16*1024*1024/4) */
	if ((uint64_t)option_al_stripes * option_al_stripe_size_4k > (buffer_size/4096)) {
		CLI_ERRO_LOG_STDERR(false, "invalid (too large) al-stripe* settings");
		exit(10);
	}
	if (option_al_stripes * option_al_stripe_size_4k < 32/4) {
		CLI_ERRO_LOG_STDERR(false, "invalid (too small) al-stripe* settings");
		exit(10);
	}

	if (option_node_id != -1 && !command->node_id_required) {
		CLI_ERRO_LOG_STDERR(false, "The %s command does not accept the --node-id option",
			command->name);
		exit(10);
	}

	/* Hope this is sufficcient for backward compat */
	if (!is_v09(cfg) && command->node_id_required) {
		if (option_node_id == -1)
			option_node_id = 0;
		else if (option_node_id != 0)
			CLI_ERRO_LOG_STDERR(false, "Not v09, implicitly set --node-id = 0");
	}

	if (option_node_id == -1 && command->node_id_required) {
		CLI_ERRO_LOG_STDERR(false, "The %s command requires the --node-id option",
			command->name);
		exit(10);
	}

	rv = command->function(cfg, argv + ai, argc - ai);
	if (minor_attached)
		CLI_ERRO_LOG_STDERR(false, "# Output might be stale, since minor %d is attached", cfg->minor);

	bsr_terminate_log(rv);

	return rv;
	/* and if we want an explicit free,
	 * this would be the place for it.
	 * free(cfg->md_device_name), free(cfg) ...
	 */
}
