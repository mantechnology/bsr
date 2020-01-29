#ifndef BSR_GENL_STRUCT_H
#define BSR_GENL_STRUCT_H
#ifdef _WIN
#include "../windows/types.h"
#endif

/**
 * struct bsr_genlmsghdr - BSR specific header used in NETLINK_GENERIC requests
 * @minor:
 *     For admin requests (user -> kernel): which minor device to operate on.
 *     For (unicast) replies or informational (broadcast) messages
 *     (kernel -> user): which minor device the information is about.
 *     If we do not operate on minors, but on connections or resources,
 *     the minor value shall be (~0), and the attribute BSR_NLA_CFG_CONTEXT
 *     is used instead.
 * @flags: possible operation modifiers (relevant only for user->kernel):
 *     BSR_GENL_F_SET_DEFAULTS
 * @ret_code: kernel->userland unicast cfg reply return code (union with flags);
 */
struct bsr_genlmsghdr {
	__u32 minor;
	union {
	__u32 flags;
	__s32 ret_code;
	};
};

/* To be used in bsr_genlmsghdr.flags */
enum {
	BSR_GENL_F_SET_DEFAULTS = 1,
};

/* hack around predefined gcc/cpp "linux=1",
 * we cannot possibly include <1/bsr_genl.h> */
#undef linux

#include "../bsr.h"

#define GENL_MAGIC_VERSION	2
#define GENL_MAGIC_FAMILY	bsr
#define GENL_MAGIC_FAMILY_HDRSZ	sizeof(struct bsr_genlmsghdr)
#define GENL_MAGIC_INCLUDE_FILE "bsr_genl.h"
#include "genl_magic_struct.h"

#endif
