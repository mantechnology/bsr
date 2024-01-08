#ifdef _LIN_FAST_SYNC

typedef uint32_t	prid_t;		/* project ID */

typedef uint32_t	xfs_agblock_t;	/* blockno in alloc. group */
typedef uint32_t	xfs_agino_t;	/* inode # within allocation grp */
typedef uint32_t	xfs_extlen_t;	/* extent length in blocks */
typedef uint32_t	xfs_agnumber_t;	/* allocation group number */
typedef int32_t		xfs_extnum_t;	/* # of extents in a file */
typedef int16_t		xfs_aextnum_t;	/* # extents in an attribute fork */
typedef int64_t		xfs_fsize_t;	/* bytes in a file */
typedef uint64_t	xfs_ufsize_t;	/* unsigned bytes in a file */

typedef int32_t		xfs_suminfo_t;	/* type of bitmap summary info */
typedef uint32_t	xfs_rtword_t;	/* word type for bitmap manipulations */

typedef int64_t		xfs_lsn_t;	/* log sequence number */

typedef uint32_t	xfs_dablk_t;	/* dir/attr block number (in file) */
typedef uint32_t	xfs_dahash_t;	/* dir/attr hash value */

typedef uint64_t	xfs_fsblock_t;	/* blockno in filesystem (agno|agbno) */
typedef uint64_t	xfs_rfsblock_t;	/* blockno in filesystem (raw) */
typedef uint64_t	xfs_rtblock_t;	/* extent (block) in realtime area */
typedef uint64_t	xfs_fileoff_t;	/* block number in a file */
typedef uint64_t	xfs_filblks_t;	/* number of blocks in a file */

typedef int64_t		xfs_srtblock_t;	/* signed version of xfs_rtblock_t */

#ifndef UUID_SIZE
#define UUID_SIZE 16
#endif

// BSR-1094 check the UUID_SIZE declaration and the uuid_t declaration separately.
#ifndef COMPAT_HAVE_UUID_T_TYPE
typedef struct {
	__u8 b[UUID_SIZE];
} uuid_t;
#endif

typedef __s64			xfs_off_t;	/* <file offset> type */
typedef unsigned long long	xfs_ino_t;	/* <inode> type */
typedef __s64			xfs_daddr_t;	/* <disk address> type */
typedef __u32			xfs_dev_t;
typedef __u32			xfs_nlink_t;

#define XFSLABEL_MAX			12

#define	XFS_SB_MAGIC		0x58465342	/* 'XFSB' */
#define	XFS_SB_VERSION_1	1		/* 5.3, 6.0.1, 6.1 */
#define	XFS_SB_VERSION_2	2		/* 6.2 - attributes */
#define	XFS_SB_VERSION_3	3		/* 6.2 - new inode version */
#define	XFS_SB_VERSION_4	4		/* 6.2+ - bitmask version */
#define	XFS_SB_VERSION_5	5		/* CRC enabled filesystem */
#define	XFS_SB_VERSION_NUMBITS		0x000f
#define	XFS_SB_VERSION_MOREBITSBIT	0x8000
#define XFS_SB_VERSION2_LAZYSBCOUNTBIT	0x00000002	/* Superblk counters */

#define	XFS_SB_VERSION_NUM(sbp)	((sbp)->sb_versionnum & be16_to_cpu(XFS_SB_VERSION_NUMBITS))

#define XFS_BTREE_SHDR_ADDITIONAL_SIZE_TO_VERSION_5 40
/*
 * Structure of the super block
 * 
 * from fs/xfs/libxfs/xfs_format.h
 */
typedef struct xfs_sb {
	uint32_t	sb_magicnum;	/* magic number == XFS_SB_MAGIC */
	uint32_t	sb_blocksize;	/* logical block size, bytes */
	xfs_rfsblock_t	sb_dblocks;	/* number of data blocks */
	xfs_rfsblock_t	sb_rblocks;	/* number of realtime blocks */
	xfs_rtblock_t	sb_rextents;	/* number of realtime extents */
	uuid_t		sb_uuid;	/* user-visible file system unique id */
	xfs_fsblock_t	sb_logstart;	/* starting block of log if internal */
	xfs_ino_t	sb_rootino;	/* root inode number */
	xfs_ino_t	sb_rbmino;	/* bitmap inode for realtime extents */
	xfs_ino_t	sb_rsumino;	/* summary inode for rt bitmap */
	xfs_agblock_t	sb_rextsize;	/* realtime extent size, blocks */
	xfs_agblock_t	sb_agblocks;	/* size of an allocation group */
	xfs_agnumber_t	sb_agcount;	/* number of allocation groups */
	xfs_extlen_t	sb_rbmblocks;	/* number of rt bitmap blocks */
	xfs_extlen_t	sb_logblocks;	/* number of log blocks */
	uint16_t	sb_versionnum;	/* header version == XFS_SB_VERSION */
	uint16_t	sb_sectsize;	/* volume sector size, bytes */
	uint16_t	sb_inodesize;	/* inode size, bytes */
	uint16_t	sb_inopblock;	/* inodes per block */
	char		sb_fname[XFSLABEL_MAX]; /* file system name */
	uint8_t		sb_blocklog;	/* log2 of sb_blocksize */
	uint8_t		sb_sectlog;	/* log2 of sb_sectsize */
	uint8_t		sb_inodelog;	/* log2 of sb_inodesize */
	uint8_t		sb_inopblog;	/* log2 of sb_inopblock */
	uint8_t		sb_agblklog;	/* log2 of sb_agblocks (rounded up) */
	uint8_t		sb_rextslog;	/* log2 of sb_rextents */
	uint8_t		sb_inprogress;	/* mkfs is in progress, don't mount */
	uint8_t		sb_imax_pct;	/* max % of fs for inode space */
					/* statistics */
	/*
	 * These fields must remain contiguous.  If you really
	 * want to change their layout, make sure you fix the
	 * code in xfs_trans_apply_sb_deltas().
	 */
	uint64_t	sb_icount;	/* allocated inodes */
	uint64_t	sb_ifree;	/* free inodes */
	uint64_t	sb_fdblocks;	/* free data blocks */
	uint64_t	sb_frextents;	/* free realtime extents */
	/*
	 * End contiguous fields.
	 */
	xfs_ino_t	sb_uquotino;	/* user quota inode */
	xfs_ino_t	sb_gquotino;	/* group quota inode */
	uint16_t	sb_qflags;	/* quota flags */
	uint8_t		sb_flags;	/* misc. flags */
	uint8_t		sb_shared_vn;	/* shared version number */
	xfs_extlen_t	sb_inoalignmt;	/* inode chunk alignment, fsblocks */
	uint32_t	sb_unit;	/* stripe or raid unit */
	uint32_t	sb_width;	/* stripe or raid width */
	uint8_t		sb_dirblklog;	/* log2 of dir block size (fsbs) */
	uint8_t		sb_logsectlog;	/* log2 of the log sector size */
	uint16_t	sb_logsectsize;	/* sector size for the log, bytes */
	uint32_t	sb_logsunit;	/* stripe unit size for the log */
	uint32_t	sb_features2;	/* additional feature bits */

	/*
	 * bad features2 field as a result of failing to pad the sb structure to
	 * 64 bits. Some machines will be using this field for features2 bits.
	 * Easiest just to mark it bad and not use it for anything else.
	 *
	 * This is not kept up to date in memory; it is always overwritten by
	 * the value in sb_features2 when formatting the incore superblock to
	 * the disk buffer.
	 */
	uint32_t	sb_bad_features2;

	/* version 5 superblock fields start here */

	/* feature masks */
	uint32_t	sb_features_compat;
	uint32_t	sb_features_ro_compat;
	uint32_t	sb_features_incompat;
	uint32_t	sb_features_log_incompat;

	uint32_t	sb_crc;		/* superblock crc */
	xfs_extlen_t	sb_spino_align;	/* sparse inode chunk alignment */

	xfs_ino_t	sb_pquotino;	/* project quota inode */
	xfs_lsn_t	sb_lsn;		/* last write sequence */
	uuid_t		sb_meta_uuid;	/* metadata file system unique id */

	/* must be padded to 64 bit alignment */
} xfs_sb_t;

/*
 * Allocation group header
 *
 * This is divided into three structures, placed in sequential 512-byte
 * buffers after a copy of the superblock (also in a 512-byte buffer).
 */
#define	XFS_AGF_MAGIC	0x58414746	/* 'XAGF' */
#define	XFS_AGI_MAGIC	0x58414749	/* 'XAGI' */
#define	XFS_AGFL_MAGIC	0x5841464c	/* 'XAFL' */
#define	XFS_AGF_VERSION	1
#define	XFS_AGI_VERSION	1

#define	XFS_AGF_GOOD_VERSION(v)	((v) == XFS_AGF_VERSION)
#define	XFS_AGI_GOOD_VERSION(v)	((v) == XFS_AGI_VERSION)

typedef enum {
	XFS_BTNUM_BNOi, XFS_BTNUM_CNTi, XFS_BTNUM_RMAPi, XFS_BTNUM_BMAPi,
	XFS_BTNUM_INOi, XFS_BTNUM_FINOi, XFS_BTNUM_REFCi, XFS_BTNUM_MAX
} xfs_btnum_t;

#define	XFS_BTNUM_AGF	((int)XFS_BTNUM_RMAPi + 1)

typedef struct xfs_agf {
	/*
	 * Common allocation group header information
	 */
	__be32		agf_magicnum;	/* magic number == XFS_AGF_MAGIC */
	__be32		agf_versionnum;	/* header version == XFS_AGF_VERSION */
	__be32		agf_seqno;	/* sequence # starting from 0 */
	__be32		agf_length;	/* size in blocks of a.g. */
	/*
	 * Freespace and rmap information
	 */
	__be32		agf_roots[XFS_BTNUM_AGF];	/* root blocks */
	__be32		agf_levels[XFS_BTNUM_AGF];	/* btree levels */

	__be32		agf_flfirst;	/* first freelist block's index */
	__be32		agf_fllast;	/* last freelist block's index */
	__be32		agf_flcount;	/* count of blocks in freelist */
	__be32		agf_freeblks;	/* total free blocks */

	__be32		agf_longest;	/* longest free space */
	__be32		agf_btreeblks;	/* # of blocks held in AGF btrees */
	uuid_t		agf_uuid;	/* uuid of filesystem */

	__be32		agf_rmap_blocks;	/* rmapbt blocks used */
	__be32		agf_refcount_blocks;	/* refcountbt blocks used */

	__be32		agf_refcount_root;	/* refcount tree root block */
	__be32		agf_refcount_level;	/* refcount btree levels */

	/*
	 * reserve some contiguous space for future logged fields before we add
	 * the unlogged fields. This makes the range logging via flags and
	 * structure offsets much simpler.
	 */
	__be64		agf_spare64[14];

	/* unlogged fields, written during buffer writeback. */
	__be64		agf_lsn;	/* last write sequence */
	__be32		agf_crc;	/* crc of agf sector */
	__be32		agf_spare2;

	/* structure must be padded to 64 bit alignment */
} xfs_agf_t;

#define	XFS_AGF_MAGICNUM	0x00000001
#define	XFS_AGF_VERSIONNUM	0x00000002
#define	XFS_AGF_SEQNO		0x00000004
#define	XFS_AGF_LENGTH		0x00000008
#define	XFS_AGF_ROOTS		0x00000010
#define	XFS_AGF_LEVELS		0x00000020
#define	XFS_AGF_FLFIRST		0x00000040
#define	XFS_AGF_FLLAST		0x00000080
#define	XFS_AGF_FLCOUNT		0x00000100
#define	XFS_AGF_FREEBLKS	0x00000200
#define	XFS_AGF_LONGEST		0x00000400
#define	XFS_AGF_BTREEBLKS	0x00000800
#define	XFS_AGF_UUID		0x00001000
#define	XFS_AGF_RMAP_BLOCKS	0x00002000
#define	XFS_AGF_REFCOUNT_BLOCKS	0x00004000
#define	XFS_AGF_REFCOUNT_ROOT	0x00008000
#define	XFS_AGF_REFCOUNT_LEVEL	0x00010000
#define	XFS_AGF_SPARE64		0x00020000
#define	XFS_AGF_NUM_BITS	18
#define	XFS_AGF_ALL_BITS	((1 << XFS_AGF_NUM_BITS) - 1)

/*
 * Allocation Btree format definitions
 *
 * There are two on-disk btrees, one sorted by blockno and one sorted
 * by blockcount and blockno.  All blocks look the same to make the code
 * simpler; if we have time later, we'll make the optimizations.
 */
#define	XFS_ABTB_MAGIC		0x41425442	/* 'ABTB' for bno tree */
#define	XFS_ABTB_CRC_MAGIC	0x41423342	/* 'AB3B' */
#define	XFS_ABTC_MAGIC		0x41425443	/* 'ABTC' for cnt tree */
#define	XFS_ABTC_CRC_MAGIC	0x41423343	/* 'AB3C' */

/*
 * Data record/key structure
 */
typedef struct xfs_alloc_rec {
	__be32		ar_startblock;	/* starting block number */
	__be32		ar_blockcount;	/* count of free blocks */
} xfs_alloc_rec_t, xfs_alloc_key_t;

typedef struct xfs_alloc_rec_incore {
	xfs_agblock_t	ar_startblock;	/* starting block number */
	xfs_extlen_t	ar_blockcount;	/* count of free blocks */
} xfs_alloc_rec_incore_t;

/* btree pointer type */
typedef __be32 xfs_alloc_ptr_t;

/*
 * Generic Btree block format definitions
 *
 * This is a combination of the actual format used on disk for short and long
 * format btrees.  The first three fields are shared by both format, but the
 * pointers are different and should be used with care.
 *
 * To get the size of the actual short or long form headers please use the size
 * macros below.  Never use sizeof(xfs_btree_block).
 *
 * The blkno, crc, lsn, owner and uuid fields are only available in filesystems
 * with the crc feature bit, and all accesses to them must be conditional on
 * that flag.
 */
/* short form block header */
struct xfs_btree_block_shdr {
	__be32		bb_leftsib;
	__be32		bb_rightsib;

	/* version 5 filesystem fields start here */
	__be64		bb_blkno;
	__be64		bb_lsn;
	uuid_t		bb_uuid;
	__be32		bb_owner;
	__le32		bb_crc;
};

/* long form block header */
struct xfs_btree_block_lhdr {
	__be64		bb_leftsib;
	__be64		bb_rightsib;

	/* version 5 filesystem fields start here */
	__be64		bb_blkno;
	__be64		bb_lsn;
	uuid_t		bb_uuid;
	__be64		bb_owner;
	__le32		bb_crc;
	__be32		bb_pad; /* padding for alignment */
};

struct xfs_btree_block {
	__be32		bb_magic;	/* magic number for block type */
	__be16		bb_level;	/* 0 is a leaf */
	__be16		bb_numrecs;	/* current # of data records */
	union {
		struct xfs_btree_block_shdr s;
		//struct xfs_btree_block_lhdr l;
	} bb_u;				/* rest */
};

/* size of a short form block */
#define XFS_BTREE_SBLOCK_LEN \
	(offsetof(struct xfs_btree_block, bb_u) + \
	 offsetof(struct xfs_btree_block_shdr, bb_blkno))
/* size of a long form block */
#define XFS_BTREE_LBLOCK_LEN \
	(offsetof(struct xfs_btree_block, bb_u) + \
	 offsetof(struct xfs_btree_block_lhdr, bb_blkno))

inline bool xfs_sb_version_hasmorebits(struct xfs_sb *sbp);
inline bool xfs_sb_version_haslazysbcount(struct xfs_sb *sbp);
inline bool xfs_sb_version_hascrc(struct xfs_sb *sbp);

PVOLUME_BITMAP_BUFFER read_xfs_bitmap(struct file *fd, struct xfs_sb *xfs_sb);
bool is_xfs_fs(struct xfs_sb *xfs_sb);

#endif