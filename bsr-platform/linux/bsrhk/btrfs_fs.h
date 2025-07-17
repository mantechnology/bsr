#ifdef _LIN_FAST_SYNC

#define BTRFS_MAGIC "_BHRfS_M" 
#define BTRFS_SUPER_BLOCK_OFFSET 0x10000
#define BTRFS_FIRST_COPY_SUPER_BLOCK_OFFSET 0x4000000 
#define BTRFS_SECOND_COPY_SUPER_BLOCK_OFFSET 0x4000000000 
#define BTRFS_SUPER_BLOCK_SIZE 4096

#define BTRFS_CSUM_SIZE 32
#define BTRFS_FSID_SIZE 16
#define BTRFS_UUID_SIZE 16

#define UL_SHA256LENGTH 32

#define BTRFS_CHUNK_ITEM_KEY 228

typedef uint64_t XXH64_hash_t;

union btrfs_super_block_csum {
	uint8_t bytes[32];
	uint32_t crc32c;
	XXH64_hash_t xxh64;
	uint8_t sha256[UL_SHA256LENGTH];
};

struct btrfs_super_block {
	union btrfs_super_block_csum csum;
	uint8_t fsid[16];
	uint64_t bytenr;
	uint64_t flags;
	uint8_t magic[8];
	uint64_t generation;
	uint64_t root;
	uint64_t chunk_root; // byte offset
	uint64_t log_root;
	uint64_t log_root_transid;
	uint64_t total_bytes;
	uint64_t bytes_used;
	uint64_t root_dir_objectid;
	uint64_t num_devices;
	uint32_t sectorsize;
	uint32_t nodesize;
	uint32_t leafsize;
	uint32_t stripesize;
	uint32_t sys_chunk_array_size;
	uint64_t chunk_root_generation;
	uint64_t compat_flags;
	uint64_t compat_ro_flags;
	uint64_t incompat_flags;
	uint16_t csum_type;
	uint8_t root_level;
	uint8_t chunk_root_level;
	uint8_t log_root_level;
	struct btrfs_dev_item {
		uint64_t devid;
		uint64_t total_bytes;
		uint64_t bytes_used;
		uint32_t io_align;
		uint32_t io_width;
		uint32_t sector_size;
		uint64_t type;
		uint64_t generation;
		uint64_t start_offset;
		uint32_t dev_group;
		uint8_t seek_speed;
		uint8_t bandwidth;
		uint8_t uuid[16];
		uint8_t fsid[16];
	} __attribute__ ((__packed__)) dev_item;
	uint8_t label[256];
	uint8_t padding[3541]; /* pad to BTRFS_SUPER_INFO_SIZE for csum calculation */
} __attribute__ ((__packed__));

struct btrfs_header {
	/* These first four must match the super block */
	__u8 csum[BTRFS_CSUM_SIZE];
	/* FS specific uuid */
	__u8 fsid[BTRFS_FSID_SIZE];
	/* Which block this node is supposed to live in */
	__le64 bytenr;
	__le64 flags;

	/* Allowed to be different from the super from here on down */
	__u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	__le64 generation;
	__le64 owner;
	__le32 nritems;
	__u8 level;
} __attribute__ ((__packed__));

struct btrfs_disk_key {
    uint64_t objectid;
    uint8_t type;
    uint64_t offset;
} __attribute__ ((__packed__));

struct btrfs_key_ptr {
	struct btrfs_disk_key key;
	__le64 blockptr;
	__le64 generation;
} __attribute__ ((__packed__));

struct btrfs_key {
	__u64 objectid;
	__u8 type;
	__u64 offset;
} __attribute__ ((__packed__));

struct btrfs_item {
	struct btrfs_disk_key key;
	__le32 offset;
	__le32 size;
} __attribute__ ((__packed__));

struct btrfs_node {
	struct btrfs_header header;
	struct btrfs_key_ptr ptrs[];
} __attribute__ ((__packed__));

struct btrfs_stripe {
	__le64 devid;
	__le64 offset;
	u8 dev_uuid[BTRFS_UUID_SIZE];
} __attribute__ ((__packed__));

struct btrfs_chunk {
	/* size of this chunk in bytes */
	__le64 length;

	/* objectid of the root referencing this chunk */
	__le64 owner;

	__le64 stripe_len;
	__le64 type;

	/* optimal io alignment for this chunk */
	__le32 io_align;

	/* optimal io width for this chunk */
	__le32 io_width;

	/* minimal io size for this chunk */
	__le32 sector_size;

	/* 2^16 stripes is quite a lot, a second limit is the size of a single
	 * item in the btree
	 */
	__le16 num_stripes;

	/* sub stripes only matter for raid10 */
	__le16 sub_stripes;
	struct btrfs_stripe stripe;
	/* additional stripes go here */
} __attribute__ ((__packed__));

bool is_btrfs_fs(struct btrfs_super_block *btrfs_sb);
PVOLUME_BITMAP_BUFFER read_btrfs_bitmap(struct file *fd, struct btrfs_super_block *btrfs_sb);
int bsr_read_data(struct file *fd, void *buf, size_t size, off_t offset);

#endif 