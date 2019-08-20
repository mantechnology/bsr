#ifndef DRBD_GENL_STRUCT_H
#define DRBD_GENL_STRUCT_H
#ifdef _WIN32
#include "../windows/types.h"
#endif

/**
 * struct drbd_genlmsghdr - DRBD specific header used in NETLINK_GENERIC requests
 * @minor:
 *     For admin requests (user -> kernel): which minor device to operate on.
 *     For (unicast) replies or informational (broadcast) messages
 *     (kernel -> user): which minor device the information is about.
 *     If we do not operate on minors, but on connections or resources,
 *     the minor value shall be (~0), and the attribute DRBD_NLA_CFG_CONTEXT
 *     is used instead.
 * @flags: possible operation modifiers (relevant only for user->kernel):
 *     DRBD_GENL_F_SET_DEFAULTS
 * @ret_code: kernel->userland unicast cfg reply return code (union with flags);
 */
struct drbd_genlmsghdr {
	__u32 minor;
	union {
	__u32 flags;
	__s32 ret_code;
	};
};

/* To be used in drbd_genlmsghdr.flags */
enum {
	DRBD_GENL_F_SET_DEFAULTS = 1,
};

/* hack around predefined gcc/cpp "linux=1",
 * we cannot possibly include <1/drbd_genl.h> */
#undef linux

#ifdef _WIN32
#include "../windows/bsr.h"
#else
#include <linux/bsr.h>
#endif

#define GENL_MAGIC_VERSION	2
#define GENL_MAGIC_FAMILY	drbd
#define GENL_MAGIC_FAMILY_HDRSZ	sizeof(struct drbd_genlmsghdr)
#ifdef _WIN32
#define GENL_MAGIC_INCLUDE_FILE "bsr_genl.h" // TODO: linux 경로 인식 문제로 컴파일을 위해 임시 경로로 대치: linux/drbd_genl.h -> drbd_genl.h
#include "genl_magic_struct.h"
#else
#define GENL_MAGIC_INCLUDE_FILE <linux/bsr_genl.h>
#include <linux/genl_magic_struct.h>
#endif

#endif
