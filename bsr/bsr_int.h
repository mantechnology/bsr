/*
  bsr_int.h

  This file is part of BSR by Man Technology inc.

  Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>.

  bsr is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  bsr is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with bsr; see the file COPYING.  If not, write to
  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#ifndef _BSR_INT_H
#define _BSR_INT_H

#ifdef _WIN
#include <ntifs.h>
#include "stddef.h"
#include "./bsr-kernel-compat/windows/list.h"
#include "./bsr-kernel-compat/windows/sched.h"
#include "./bsr-kernel-compat/windows/bitops.h"
#include "../bsr-headers/windows/types.h"
#else // _LIN
#include <crypto/hash.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/mutex.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>

#if defined(COMPAT_HAVE_REVALIDATE_DISK) || defined(COMPAT_HAVE_REVALIDATE_DISK_SIZE)
#include <linux/genhd.h>
#endif

#include <linux/idr.h>
#include <linux/prefetch.h>
#include <linux/time.h>
#include "compat.h"
#endif

#include "../bsr-headers/linux/bsr_genl_api.h"
#include "bsr_state.h"
#include "bsr_kref_debug.h"
#include "./linux/bsr_config.h"
#include "./linux/lru_cache.h"
#include "./bsr-kernel-compat/bsr_wrappers.h"
#include "../bsr-headers/bsr_protocol.h"
#include "../bsr-headers/bsr_transport.h"
#include "../bsr-headers/linux/bsr_limits.h"
#include "../bsr-headers/bsr_strings.h"
#include "../bsr-headers/bsr.h"
#include "../bsr-headers/bsr_log.h"
#include "../bsr-headers/bsr_ioctl.h"

#ifdef _SEND_BUF
#include "bsr_send_buf.h"
#endif

#include "./bsr_idx_ring.h"

#define kfree2(x) if((x)) {bsr_kfree((x)); (x)=NULL;}
#define kvfree2(x) if((x)) {kvfree((x)); (x)=NULL;}

#ifdef __CHECKER__
# define __protected_by(x)       __attribute__((require_context(x,1,999,"rdwr")))
# define __protected_read_by(x)  __attribute__((require_context(x,1,999,"read")))
# define __protected_write_by(x) __attribute__((require_context(x,1,999,"write")))
# define __must_hold(x)       __attribute__((context(x,1,1), require_context(x,1,999,"call")))
#else
# define __protected_by(x)
# define __protected_read_by(x)
# define __protected_write_by(x)
# define __must_hold(x)
#endif

/* Compatibility for older kernels */
#ifndef __acquires
# ifdef __CHECKER__
#  define __acquires(x)	__attribute__((context(x,0,1)))
#  define __releases(x)	__attribute__((context(x,1,0)))
#  define __acquire(x)	__context__(x,1)
#  define __release(x)	__context__(x,-1)
# else
#  define __acquires(x)
#  define __releases(x)
#  define __acquire(x)	(void)0
#  define __release(x)	(void)0
# endif
#endif

/* module parameter, defined in bsr_main.c */
extern unsigned int minor_count;
extern bool disable_sendpage;
extern bool allow_oos;
#ifdef _LIN_FAST_SYNC
extern bool debug_fast_sync; /* debugging log output to dmesg */
#endif
#ifdef CONFIG_BSR_FAULT_INJECTION
extern int enable_faults;
extern int fault_rate;
extern int fault_devs;
extern int two_phase_commit_fail;
#endif

extern int g_handler_use;
extern char usermode_helper[];

// BSR-740
extern atomic_t g_bsrmon_run;

// BSR-764
extern SIMULATION_PERF_DEGR g_simul_perf;

struct log_idx_ring_buffer_t {
	struct idx_ring_buffer h;
	char b[LOGBUF_MAXCNT][MAX_BSRLOG_BUF + IDX_OPTION_LENGTH];
	atomic_t64 missing_count;
	spinlock_t lock;
};

extern struct log_idx_ring_buffer_t gLogBuf;
extern atomic_t64 gLogCnt;

extern enum bsr_thread_state g_consumer_state;
#ifdef _WIN
extern PVOID g_consumer_thread;
#else // _LIN
extern struct task_struct *g_consumer_thread;
#endif

extern void init_logging(void);
extern void clean_logging(void);
#ifdef _WIN
extern void log_consumer_thread(PVOID param);
#else // _LIN
extern int log_consumer_thread(void *unused);
#endif

#ifndef BSR_MAJOR
# define BSR_MAJOR 147
#endif

/* This is used to stop/restart our threads.
 * Cannot use SIGTERM nor SIGKILL, since these
 * are sent out by init on runlevel changes
 * I choose SIGHUP for now.
 *
 * FIXME btw, we should register some reboot notifier.
 */
#define BSR_SIGKILL SIGHUP

#define ID_IN_SYNC      (4711ULL)
#define ID_OUT_OF_SYNC  (4712ULL)
#define ID_CSUM_SYNC_IO_ERROR		(4713ULL) // BSR-448 io-error of SyncTarget during checksum synchronization
#ifdef _WIN
#define ID_SYNCER (UINT64_MAX)
#else // _LIN
#define ID_SYNCER (-1ULL)
#endif

// BSR-842 when all out of snyc generated in L_AHEAD state is sended, the ID_OUT_OF_SYNC_FINISHED is sended.
#define ID_OUT_OF_SYNC_FINISHED ID_SYNCER

// DW-1601 Add define values for split peer request processing and already sync processing
#define ID_SYNCER_SPLIT_DONE ID_SYNCER
#define ID_SYNCER_SPLIT (ID_SYNCER - 1)

#define UUID_NEW_BM_OFFSET ((u64)0x0001000000000000ULL)

// DW-2124
#define B_COMPLETE 0x01

//DW-1927
#define CONTROL_BUFF_SIZE	1024 * 5120

// BSR-119
#define OV_REQUEST_NUM_BLOCK 10

// BSR-601
#define OV_LIST_COUNT_LIMIT 5000

struct bsr_device;
struct bsr_connection;

// BSR-577 Change to common method
#ifdef _WIN
// BSR-648
extern void __printk(const char * func, int index, int level, int category, const char * format, ...);
#else // _LIN
extern void __printk(const char * func, int index, const char * level, int category, const char * format, ...);
#endif 
extern void WriteOOSTraceLog(int bitmap_index, ULONG_PTR startBit, ULONG_PTR endBit, ULONG_PTR bitsCount, unsigned int mode);

// BSR-237
#ifdef _WIN
#define NO_OBJECT
#else  // _LIN
#define NO_OBJECT NULL

#define KERN_OOS				"<8>"	/* DW-1153: debug-oos */
#define KERN_LATENCY			"<9>"	/* DW-1961 feature log */
#endif
/* I want to be able to grep for "bsr $resource_name"
 * and get all relevant log lines. */
#ifdef _WIN
#define __bsr_printk_device(category, index, level, device, fmt, ...)		\
    do {								\
        const struct bsr_device *__d = (device);		\
        const struct bsr_resource *__r = __d->resource;	\
        __printk(__FUNCTION__, index, level, category, "<%d> bsr %s/%u minor %u, ds(%s), dvflag(0x%x): " fmt,			\
             level, __r->name, __d->vnr, __d->minor, bsr_disk_str(__d->disk_state[NOW]), __d->flags, __VA_ARGS__);	\
    } while (0)

// DW-1494 (peer_device)->uuid_flags has caused a problem with the 32-bit operating system and therefore removed
#define __bsr_printk_peer_device(category, index, level, peer_device, fmt, ...)	\
    do {								\
        const struct bsr_device *__d;				\
        const struct bsr_connection *__c;			\
        const struct bsr_resource *__r;			\
        int __cn;					\
        /*rcu_read_lock();		_WIN32 // DW-938	*/		\
        __d = (peer_device)->device;				\
        __c = (peer_device)->connection;			\
        __r = __d->resource;					\
        __cn = __c->peer_node_id;	\
        __printk(__FUNCTION__, index, level,  category, "<%d> bsr %s/%u minor %u pnode-id:%d, pdsk(%s), prpl(%s), pdvflag(0x%x): " fmt,		\
             level, __r->name, __d->vnr, __d->minor, __cn, bsr_disk_str((peer_device)->disk_state[NOW]), bsr_repl_str((peer_device)->repl_state[NOW]), (peer_device)->flags, __VA_ARGS__);\
        /*rcu_read_unlock();	_WIN32 // DW-938	*/		\
	    } while (0)

#define __bsr_printk_resource(category, index, level, resource, fmt, ...) \
	__printk(__FUNCTION__, index, level,  category, "<%d> bsr %s, r(%s), f(0x%x), scf(0x%x): " fmt, level,  (resource)->name, bsr_role_str((resource)->role[NOW]), (resource)->flags,(resource)->state_change_flags, __VA_ARGS__)

#define __bsr_printk_connection(category, index, level, connection, fmt, ...) \
    do {	                    \
        /*rcu_read_lock();	_WIN32 // DW-938 */ \
        __printk(__FUNCTION__, index, level,  category, "<%d> bsr %s pnode-id:%d, cs(%s), prole(%s), cflag(0x%x), scf(0x%x): " fmt, level, (connection)->resource->name,  \
        (connection)->peer_node_id, bsr_conn_str((connection)->cstate[NOW]), bsr_role_str((connection)->peer_role[NOW]), (connection)->flags,(connection)->resource->state_change_flags, __VA_ARGS__); \
        /*rcu_read_unlock(); _WIN32 // DW-938 */ \
	    } while (0)

// BSR-237 if object is empty (NO_OBJECT)
#define __bsr_printk_(category, index, level, obj, fmt, ...) \
	__printk(__FUNCTION__, index, level, category, "<%d> [0x%p] " fmt, level, KeGetCurrentThread(), __VA_ARGS__)

void bsr_printk_with_wrong_object_type(void);
 
#define __bsr_printk_if_same_type(obj, type, func, level, fmt, ...) 

#define bsr_printk(category, index, level, obj, fmt, ...)   \
    do {    \
        __bsr_printk_##obj(category, index, level, obj, fmt, __VA_ARGS__);  \
    } while(0)

#if defined(disk_to_dev)
#define bsr_dbg(obj, fmt, args...) \
	dev_dbg(disk_to_dev(obj->vdisk), fmt, ## args)
#elif defined(DBG)
#define bsr_dbg(obj, fmt, ...) \
	bsr_printk(KERN_DEBUG, obj, fmt, __VA_ARGS__)
#else
#define bsr_dbg(obj, fmt, ...) \
	do { if (false,false) bsr_printk(BSR_LC_ETC, -1, KERN_DEBUG_NUM, obj, fmt, __VA_ARGS__); } while(false)
#endif

#if defined(dynamic_dev_dbg) && defined(disk_to_dev)
#define dynamic_bsr_dbg(obj, fmt, args...) \
	dynamic_dev_dbg(disk_to_dev(obj->vdisk), fmt, ## args)
#elif defined(_WIN) && defined(DBG)
#define dynamic_bsr_dbg(obj, fmt, ...) \
	bsr_dbg(obj, fmt, __VA_ARGS__)
#else
#define dynamic_bsr_dbg(obj, fmt, ...)
#endif

#define bsr_debug_netlink
#define bsr_debug_tm					// about timer
#define bsr_debug_rcu					// about rcu
#define bsr_debug_req_lock			// for lock_all_resources(), unlock_all_resources()
#define bsr_debug_tr		
#define bsr_debug_wq
#define bsr_debug_rs
#define bsr_debug_sk					// about socket
#define bsr_debug_sem
#define bsr_debug_ip4					
#define bsr_debug_sb
#define bsr_debug_co		
#define bsr_debug_conn	
#define bsr_debug_al

#ifndef FEATURE_BSR_PRINT
#define bsr_err     __noop
#define bsr_warn      __noop
#define bsr_debug     __noop
#define bsr_info      __noop
#endif

// BSR-648
#define bsr_crit(index, category, obj, fmt, ...) \
	bsr_printk(category, index, KERN_CRIT_NUM, obj, fmt, __VA_ARGS__)
#define bsr_emerg(index, category, obj, fmt, ...) \
	bsr_printk(category, index, KERN_EMERG_NUM, obj, fmt, __VA_ARGS__)
#define bsr_alert(index, category, obj, fmt, ...) \
	bsr_printk(category, index, KERN_ALERT_NUM, obj, fmt, __VA_ARGS__)
#define bsr_err(index, category, obj, fmt, ...) \
	bsr_printk(category, index, KERN_ERR_NUM, obj, fmt, __VA_ARGS__)
#define bsr_warn(index, category, obj, fmt, ...) \
	bsr_printk(category, index, KERN_WARNING_NUM, obj, fmt, __VA_ARGS__)
#define bsr_noti(index, category, obj, fmt, ...) \
	bsr_printk(category, index, KERN_NOTICE_NUM, obj, fmt, __VA_ARGS__)
#define bsr_info(index, category, obj, fmt, ...) \
	bsr_printk(category, index, KERN_INFO_NUM, obj, fmt, __VA_ARGS__)
#if defined(DBG)
#define bsr_debug(BSR_LC_TEMP, obj, fmt, ...) \
	bsr_printk(KERN_DEBUG_NUM, obj, fmt, __VA_ARGS__)
#else
#define bsr_debug(index, category, obj, fmt, ...) bsr_printk(category, index, KERN_DEBUG_NUM, obj, fmt, __VA_ARGS__)
#endif
#else  // _LIN

#define __bsr_printk_device(category, index, level, device, fmt, args...)		\
	({								\
		const struct bsr_device *__d = (device);		\
		const struct bsr_resource *__r = __d->resource;	\
		__printk(__FUNCTION__, index, level, category, "<%c> bsr %s/%u bsr%u: " fmt,			\
			(level)[1], __r->name, __d->vnr, __d->minor, ## args);	\
	})

#define __bsr_printk_peer_device(category, index, level, peer_device, fmt, args...)	\
	({								\
		const struct bsr_device *__d;				\
		const struct bsr_connection *__c;			\
		const struct bsr_resource *__r;			\
		const char *__cn;					\
		rcu_read_lock();					\
		__d = (peer_device)->device;				\
		__c = (peer_device)->connection;			\
		__r = __d->resource;					\
		__cn = rcu_dereference(__c->transport.net_conf)->name;	\
		__printk(__FUNCTION__, index, level, category, "<%c> bsr %s/%u bsr%u %s: " fmt,		\
			(level)[1], __r->name, __d->vnr, __d->minor, __cn, ## args);\
		rcu_read_unlock();					\
	})

#define __bsr_printk_resource(category, index, level, resource, fmt, args...) \
	__printk(__FUNCTION__, index, level, category, "<%c> bsr %s: " fmt, level[1], (resource)->name, ## args)

#define __bsr_printk_connection(category, index, level, connection, fmt, args...) \
	({	rcu_read_lock(); \
		__printk(__FUNCTION__, index, level, category, "<%c> bsr %s %s: " fmt, (level)[1], (connection)->resource->name,  \
		       rcu_dereference((connection)->transport.net_conf)->name, ## args); \
		rcu_read_unlock(); \
	})

void bsr_printk_with_wrong_object_type(void);

// BSR-237 if object is empty or undefined (NO_OBJECT)
#define __bsr_printk(category, index, level, fmt, args...) \
	__printk(__FUNCTION__, index, level, category, "<%c> bsr " fmt, level[1], ## args)

#define __bsr_printk_if_same_type(obj, type, func, category, index, level, fmt, args...) \
	(__builtin_types_compatible_p(typeof(obj), type) || \
	 __builtin_types_compatible_p(typeof(obj), const type)), \
	func(category, index, level, (const type)(obj), fmt, ## args)

#define bsr_printk(category, index, level, obj, fmt, args...) \
	__builtin_choose_expr( \
	  __bsr_printk_if_same_type(obj, struct bsr_device *, \
			     __bsr_printk_device, category, index, level, fmt, ## args), \
	  __builtin_choose_expr( \
	    __bsr_printk_if_same_type(obj, struct bsr_resource *, \
			       __bsr_printk_resource, category, index, level, fmt, ## args), \
	    __builtin_choose_expr( \
	      __bsr_printk_if_same_type(obj, struct bsr_connection *, \
				 __bsr_printk_connection, category, index, level, fmt, ## args), \
	      __builtin_choose_expr( \
		__bsr_printk_if_same_type(obj, struct bsr_peer_device *, \
				 __bsr_printk_peer_device, category, index, level, fmt, ## args), \
	        __bsr_printk(category, index, level, fmt, ## args))))) 

#if defined(disk_to_dev)
#define bsr_dbg(obj, fmt, args...) \
	dev_dbg(disk_to_dev(obj->vdisk), fmt, ## args)
#elif defined(DEBUG)
#define bsr_dbg(obj, fmt, args...) \
	bsr_printk(BSR_LC_ETC, -1, KERN_DEBUG, obj, fmt, ## args)
#else
#define bsr_dbg(obj, fmt, args...) \
	do { if (0) bsr_printk(BSR_LC_ETC, -1, KERN_DEBUG, obj, fmt, ## args); } while (0)
#endif

#if defined(dynamic_dev_dbg) && defined(disk_to_dev)
#define dynamic_bsr_dbg(obj, fmt, args...) \
	dynamic_dev_dbg(disk_to_dev(obj->vdisk), fmt, ## args)
#else
#define dynamic_bsr_dbg(obj, fmt, args...) \
	bsr_dbg(obj, fmt, ## args)
#endif


#define bsr_debug_conn(fmt, args...) //bsr_info(0, BSR_LC_ETC, NO_OBJECT, fmt, ## args)
#define bsr_debug_rs(fmt, args...)
#define bsr_debug_al(fmt, args...)

// BSR-648
#define bsr_emerg(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_EMERG, obj, fmt, ## args)
#define bsr_alert(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_ALERT, obj, fmt, ## args)
#define bsr_crit(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_CRIT, obj, fmt, ## args)
#define bsr_err(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_ERR, obj, fmt, ## args)
#define bsr_warn(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_WARNING, obj, fmt, ## args)
#define bsr_noti(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_NOTICE, obj, fmt, ## args)
#define bsr_info(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_INFO, obj, fmt, ## args)
#define bsr_oos(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_OOS, obj, fmt, ## args)
#define bsr_latency(index, category, obj, fmt, args...) \
	bsr_printk(category, index, KERN_LATENCY, obj, fmt, ## args)

#if defined(DEBUG)
#define bsr_debug(category, obj, fmt, args...) \
	bsr_printk(BSR_LC_ETC, -1, KERN_DEBUG, obj, fmt, ## args)
#else
#define bsr_debug(index, category, obj, fmt, args...) bsr_printk(category, index, KERN_DEBUG, obj, fmt, ## args)
#endif
#endif

#ifdef _WIN
#define BUG()   bsr_crit(15, BSR_LC_ETC, NO_OBJECT,"warning: failure")
#define BUG_ON(_condition)	\
	do {		\
		if (_condition) {	\
			\
				bsr_crit(16, BSR_LC_ETC, NO_OBJECT,"BUG: failure [ %s ]", #_condition); \
						}	\
			} while (false)

#endif
#ifdef WIN_AL_BUG_ON
#define AL_BUG_ON(_condition, str_condition, lc, e)	\
    do {	\
        if(_condition) { \
            bsr_crit(37, BSR_LC_LRU, NO_OBJECT,"BUG: failure [ %s ]", str_condition); \
			if(lc || e){	\
				lc_printf_stats(lc, e);	\
										}\
					}\
		} while (false)
#endif

// DW-1918 add output at debug level
#define DEBUG_BUG_ON(_condition)	\
do {	\
		if (_condition) {\
				\
				bsr_debug(79, BSR_LC_ETC, NO_OBJECT,"BUG: failure [ %s ]", #_condition); \
				}	\
} while (false)

// BSR-577
extern atomic_t g_eventlog_lv_min;
extern atomic_t g_dbglog_lv_min;

// BSR-579
extern atomic_t g_log_file_max_count;

// DW-1961
extern atomic_t g_debug_output_category;

// BSR-648
static const char * const __log_category_names[] = {
	[BSR_LC_VOLUME] = "VOLUME",
	[BSR_LC_IO] = "I/O",
	[BSR_LC_IO_ERROR] = "I/O ERROR",
	[BSR_LC_BITMAP] = "BITMAP",
	[BSR_LC_LRU] = "LRU",
	[BSR_LC_REQUEST] = "REQUEST",
	[BSR_LC_PEER_REQUEST] = "PEER REQUEST",
	[BSR_LC_RESYNC_OV] = "RESYNC/OV",
	[BSR_LC_REPLICATION] = "REPLICATION",
	[BSR_LC_CONNECTION] = "CONNECTION",
	[BSR_LC_UUID] = "UUID",
	[BSR_LC_TWOPC] = "TWOPC",
	[BSR_LC_THREAD] = "THREAD",
	[BSR_LC_SEND_BUFFER] = "SEND BUFFER",
	[BSR_LC_STATE] = "STATE",
	[BSR_LC_SOCKET] = "SOCKET",
	[BSR_LC_DRIVER] = "DRIVER",
	[BSR_LC_NETLINK] = "NETLINK",
	[BSR_LC_GENL] = "GENL",
	[BSR_LC_PROTOCOL] = "PROTOCOL",
	[BSR_LC_MEMORY] = "MEMORY",
	[BSR_LC_LOG] = "LOG",
	[BSR_LC_LATENCY] = "LATENCY",
	[BSR_LC_VERIFY] = "VERIFY",
	[BSR_LC_OUT_OF_SYNC] = "OUT OF SYNC",
	[BSR_LC_ETC] = "ETC",
};


// BSR-649 Maximum index value being used for log values.
// As the index value used in the log increases, the same increase must be made.
#define BSR_LC_VOLUME_MAX_INDEX 101
#define BSR_LC_IO_MAX_INDEX 61
#define BSR_LC_IO_ERROR_MAX_INDEX 11
#define BSR_LC_BITMAP_MAX_INDEX 127
#define BSR_LC_LRU_MAX_INDEX 41
#define BSR_LC_REQUEST_MAX_INDEX 37
#define BSR_LC_PEER_REQUEST_MAX_INDEX 33
#define BSR_LC_RESYNC_OV_MAX_INDEX 227
#define BSR_LC_REPLICATION_MAX_INDEX 32
#define BSR_LC_CONNECTION_MAX_INDEX 33
#define BSR_LC_UUID_MAX_INDEX 40
#define BSR_LC_TWOPC_MAX_INDEX 59
#define BSR_LC_THREAD_MAX_INDEX 37
#define BSR_LC_SEND_BUFFER_MAX_INDEX 37
#define BSR_LC_STATE_MAX_INDEX 57
#define BSR_LC_SOCKET_MAX_INDEX 108
#define BSR_LC_DRIVER_MAX_INDEX 154
#define BSR_LC_NETLINK_MAX_INDEX 36
#define BSR_LC_GENL_MAX_INDEX 92
#define BSR_LC_PROTOCOL_MAX_INDEX 70
#define BSR_LC_MEMORY_MAX_INDEX 97
#define BSR_LC_LOG_MAX_INDEX 25
#define BSR_LC_LATENCY_MAX_INDEX 8
#define BSR_LC_VERIFY_MAX_INDEX 17
#define BSR_LC_OUT_OF_SYNC_MAX_INDEX 7
#define BSR_LC_ETC_MAX_INDEX 87


#define BUG_ON_INT16_OVER(_value) DEBUG_BUG_ON(INT16_MAX < _value)
#define BUG_ON_UINT16_OVER(_value) DEBUG_BUG_ON(UINT16_MAX < _value)

#define BUG_ON_INT32_OVER(_value) DEBUG_BUG_ON(INT32_MAX < _value)
#define BUG_ON_UINT32_OVER(_value) DEBUG_BUG_ON(UINT32_MAX < _value)

#define BUG_ON_INT64_OVER(_value) DEBUG_BUG_ON(INT64_MAX < _value)
#define BUG_ON_UINT64_OVER(_value) DEBUG_BUG_ON(UINT64_MAX < _value)


#ifdef _WIN
#define DEFAULT_RATELIMIT_INTERVAL      (5 * HZ)
#define DEFAULT_RATELIMIT_BURST         10

struct ratelimit_state {
	spinlock_t		lock;           /* protect the state */
	int             interval;
	int             burst;
	int             printed;
	int             missed;
	ULONG_PTR	    begin;
};
#endif

extern struct ratelimit_state bsr_ratelimit_state;

#ifdef _WIN
extern int _BSR_ratelimit(struct ratelimit_state *rs, const char * func, const char * __FILE, const int __LINE);
#define bsr_ratelimit() _BSR_ratelimit(&bsr_ratelimit_state, __FUNCTION__, __FILE__, __LINE__)
#else // _LIN
static inline int bsr_ratelimit(void)
{
	return __ratelimit(&bsr_ratelimit_state);
}
#endif

#ifdef _WIN
#define D_ASSERT(x, exp) \
		if (!(exp))	{ \
			DbgPrint("\n\nASSERTION %s FAILED in %s #########\n\n",	\
				 #exp, __func__); \
		} 
#else // _LIN
#define D_ASSERT(x, exp)							\
	do {									\
		if (!(exp))							\
			bsr_err(18, BSR_LC_ETC, x, "ASSERTION %s FAILED in %s",		\
				 #exp, __func__);				\
	} while (0)
#endif
/**
 * expect  -  Make an assertion
 *
 * Unlike the assert macro, this macro returns a boolean result.
 */
#ifdef _WIN
#define expect(x, exp) (exp)
#else // _LIN
#define expect(x, exp) ({							\
		bool _bool = (exp);						\
		if (!_bool)							\
			bsr_err(19, BSR_LC_ETC, x, "ASSERTION %s FAILED in %s",		\
			        #exp, __func__);				\
		_bool;								\
		})
#endif

/* Defines to control fault insertion */
#ifdef _WIN
enum _fault {
#else // _LIN
enum {
#endif
	BSR_FAULT_MD_WR = 0,	/* meta data write */
	BSR_FAULT_MD_RD = 1,	/*           read  */
	BSR_FAULT_RS_WR = 2,	/* resync          */
	BSR_FAULT_RS_RD = 3,
	BSR_FAULT_DT_WR = 4,	/* data            */
	BSR_FAULT_DT_RD = 5,
	BSR_FAULT_DT_RA = 6,	/* data read ahead */
	BSR_FAULT_BM_ALLOC = 7,	/* bitmap allocation */
	BSR_FAULT_AL_EE = 8,	/* alloc ee */
	BSR_FAULT_RECEIVE = 9, /* Changes some bytes upon receiving a [rs]data block */

	BSR_FAULT_MAX,
};

extern unsigned int
_bsr_insert_fault(struct bsr_device *device, unsigned int type);

static inline int
bsr_insert_fault(struct bsr_device *device, unsigned int type) {
#ifdef CONFIG_BSR_FAULT_INJECTION
#ifdef _WIN
	int ret = fault_rate &&
		(enable_faults & (1<<type)) &&
		_bsr_insert_fault(device, type);

    if (ret) {
        bsr_err(87, BSR_LC_ETC, NO_OBJECT,"Failed to test. type=0x%x fault=%d", type, ret);
    }
    return ret;
#else // _LIN
	return fault_rate &&
		(enable_faults & (1<<type)) &&
		_bsr_insert_fault(device, type);
#endif
#else
	return 0;
#endif
}

/*
 * our structs
 *************************/

#define SET_MDEV_MAGIC(x) \
	({ typecheck(struct bsr_device*, x); \
	  (x)->magic = (long)(x) ^ BSR_MAGIC; })
#define IS_VALID_MDEV(x)  \
	(typecheck(struct bsr_device*, x) && \
	  ((x) ? (((x)->magic ^ BSR_MAGIC) == (long)(x)) : 0))

extern struct idr bsr_devices; /* RCU, updates: genl_lock() */
extern struct list_head bsr_resources; /* RCU, updates: resources_mutex */
extern struct mutex resources_mutex;

/* for sending/receiving the bitmap,
 * possibly in some encoding scheme */
struct bm_xfer_ctx {
	/* "const"
	 * stores total bits and long words
	 * of the bitmap, so we don't need to
	 * call the accessor functions over and again. */
	ULONG_PTR bm_bits;
	ULONG_PTR bm_words;
	/* during xfer, current position within the bitmap */
	ULONG_PTR bit_offset;
	ULONG_PTR word_offset;

	/* statistics; index: (h->command == P_BITMAP) */
	unsigned packets[2];
	unsigned bytes[2];
	ULONG_PTR count;  // DW-1981
};

extern void INFO_bm_xfer_stats(struct bsr_peer_device *, const char *, struct bm_xfer_ctx *);

static inline void bm_xfer_ctx_bit_to_word_offset(struct bm_xfer_ctx *c)
{
	/* word_offset counts "native long words" (32 or 64 bit),
	 * aligned at 64 bit.
	 * Encoded packet may end at an unaligned bit offset.
	 * In case a fallback clear text packet is transmitted in
	 * between, we adjust this offset back to the last 64bit
	 * aligned "native long word", which makes coding and decoding
	 * the plain text bitmap much more convenient.  */
#if BITS_PER_LONG == 64
	c->word_offset = c->bit_offset >> 6;
#elif BITS_PER_LONG == 32
	c->word_offset = c->bit_offset >> 5;
	c->word_offset &= ~(1UL);
#else
# error "unsupported BITS_PER_LONG"
#endif
}

extern unsigned int bsr_header_size(struct bsr_connection *connection);

/**********************************************************************/
enum bsr_thread_state {
	NONE,
	RUNNING,
	EXITING,
	RESTARTING
};

struct bsr_thread {
#ifdef _WIN
    struct task_struct *nt;
    KEVENT start_event;
    KEVENT wait_event;
#endif
	spinlock_t t_lock;
	struct task_struct *task;
	struct completion stop;
	enum bsr_thread_state t_state;
	int (*function) (struct bsr_thread *);
	struct bsr_resource *resource;
	struct bsr_connection *connection;
	int reset_cpu_mask;
	const char *name;
};

static inline enum bsr_thread_state get_t_state(struct bsr_thread *thi)
{
	/* THINK testing the t_state seems to be uncritical in all cases
	 * (but thread_{start,stop}), so we can read it *without* the lock.
	 *	--lge */

	smp_rmb();
	return thi->t_state;
}

struct bsr_work {
	struct list_head list;
	int (*cb)(struct bsr_work *, int cancel);
};

// DW-1755
struct bsr_io_error_work {
	struct bsr_work w;
	struct bsr_device *device;
	struct bsr_io_error *io_error;
};

// BSR-676
struct bsr_updated_gi_work {
	struct bsr_work w;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device;
	int type;
};

struct bsr_peer_device_work {
	struct bsr_work w;
	struct bsr_peer_device *peer_device;
};

enum bsr_stream;

#include "bsr_interval.h"

extern int bsr_wait_misc(struct bsr_device *, struct bsr_peer_device *, struct bsr_interval *);

extern void lock_all_resources(void);
extern void unlock_all_resources(void);

extern enum bsr_disk_state disk_state_from_md(struct bsr_device *);
extern void device_to_info(struct device_info *, struct bsr_device *);
extern long twopc_timeout(struct bsr_resource *);
extern long twopc_retry_timeout(struct bsr_resource *, int);
extern void twopc_connection_down(struct bsr_connection *);
extern u64 directly_connected_nodes(struct bsr_resource *, enum which_state);
extern int w_notify_io_error(struct bsr_work *w, int cancel);
extern int w_notify_updated_gi(struct bsr_work *w, int cancel);
/* sequence arithmetic for dagtag (data generation tag) sector numbers.
 * dagtag_newer_eq: true, if a is newer than b */
#ifdef _WIN
#define dagtag_newer_eq(a,b)      \
	((s64)(a) - (s64)(b) >= 0)

#define dagtag_newer(a,b)      \
	((s64)(a) - (s64)(b) > 0)
#else // _LIN
#define dagtag_newer_eq(a,b)      \
	(typecheck(u64, a) && \
	 typecheck(u64, b) && \
	((s64)(a) - (s64)(b) >= 0))

#define dagtag_newer(a,b)      \
	(typecheck(u64, a) && \
	 typecheck(u64, b) && \
	((s64)(a) - (s64)(b) > 0))
#endif

struct bsr_request {
	struct bsr_device *device;

	/* if local IO is not allowed, will be NULL.
	 * if local IO _is_ allowed, holds the locally submitted bio clone,
	 * or, after local IO completion, the ERR_PTR(error).
	 * see bsr_request_endio(). */
	struct bio *private_bio;
#ifdef _WIN
	char*	req_databuf;
	// DW-1237 add request buffer reference count to free earlier when no longer need buf.
	atomic_t req_databuf_ref;
#endif
	struct bsr_interval i;

	/* epoch: used to check on "completion" whether this req was in
	 * the current epoch, and we therefore have to close it,
	 * causing a p_barrier packet to be send, starting a new epoch.
	 *
	 * This corresponds to "barrier" in struct p_barrier[_ack],
	 * and to "barrier_nr" in struct bsr_epoch (and various
	 * comments/function parameters/local variable names).
	 */
	// BSR-231 Since the epoch(barrier_nr) value is copied and used as an int variable and an unsigned int variable,
	// there is a problem that the type conversion must be performed when comparing.Therefore it is unified to type int.
	int epoch;

	/* Position of this request in the serialized per-resource change
	 * stream. Can be used to serialize with other events when
	 * communicating the change stream via multiple connections.
	 * Assigned from device->resource->dagtag_sector.
	 *
	 * Given that some IO backends write several GB per second meanwhile,
	 * lets just use a 64bit sequence space. */
	u64 dagtag_sector;

	struct list_head tl_requests; /* ring list in the transfer log */

#ifdef NETQUEUED_LOG
	struct list_head nq_requests; /* ring list in the net queued log */
	atomic_t nq_ref;
#endif
	
	struct bio *master_bio;       /* master bio pointer */

	/* see struct bsr_device */
	struct list_head req_pending_master_completion;
	struct list_head req_pending_local;

	/* for generic IO accounting; "immutable" */
	ULONG_PTR start_jif;

	/* for request_timer_fn() */
	ULONG_PTR pre_submit_jif;
	ULONG_PTR pre_send_jif[BSR_PEERS_MAX];

	/* for BSR internal statistics */
	ktime_t start_kt;

	/* before actual request processing */
	ktime_t in_actlog_kt;
	ktime_t before_queue_kt;
	ktime_t before_al_begin_io_kt;
	
	/* local disk */
	ktime_t submit_kt;
	ktime_t bio_endio_kt;
	
	/* per connection */
	ktime_t pre_send_kt[BSR_PEERS_MAX];
	ktime_t acked_kt[BSR_PEERS_MAX];
	ktime_t net_done_kt[BSR_PEERS_MAX];

	// DW-1961
	bool	 do_submit;				// Whether do_submit logic passed
	LONGLONG created_ts;			// req created
	LONGLONG io_request_ts;			// Before delivering an io request to disk
	LONGLONG io_complete_ts;		// Received io completion from disk
	LONGLONG net_sent_ts[BSR_PEERS_MAX];			// Send request to peer
	LONGLONG net_done_ts[BSR_PEERS_MAX];			// Received a response from peer

	/* Possibly even more detail to track each phase:
	 *  master_completion_jif
	 *      how long did it take to complete the master bio
	 *      (application visible latency)
	 *  allocated_jif
	 *      how long the master bio was blocked until we finally allocated
	 *      a tracking struct
	 *  in_actlog_jif
	 *      how long did we wait for activity log transactions
	 *
	 *  net_queued_jif
	 *      when did we finally queue it for sending
	 *  pre_send_jif
	 *      when did we start sending it
	 *  post_send_jif
	 *      how long did we block in the network stack trying to send it
	 *  acked_jif
	 *      when did we receive (or fake, in protocol A) a remote ACK
	 *  net_done_jif
	 *      when did we receive final acknowledgement (P_BARRIER_ACK),
	 *      or decide, e.g. on connection loss, that we do no longer expect
	 *      anything from this peer for this request.
	 *
	 *  pre_submit_jif
	 *  post_sub_jif
	 *      when did we start submiting to the lower level device,
	 *      and how long did we block in that submit function
	 *  local_completion_jif
	 *      how long did it take the lower level device to complete this request
	 */


	/* once it hits 0, we may complete the master_bio */
	atomic_t completion_ref;
	/* once it hits 0, we may destroy this bsr_request object */
	struct kref kref;

	/* If not NULL, destruction of this bsr_request will
	 * cause kref_put() on ->destroy_next. */
	struct bsr_request *destroy_next;

	/* rq_state[0] is for local disk,
	 * rest is indexed by peer_device->bitmap_index + 1 */
	unsigned rq_state[1 + BSR_NODE_ID_MAX];
};


// DW-1191 out-of-sync information that doesn't rely on bsr request.
struct bsr_oos_no_req{
	struct list_head oos_list_head;
	sector_t sector;
	unsigned int size;
};

struct bsr_epoch {
	struct bsr_connection *connection;
	struct list_head list;
	unsigned int barrier_nr;
	atomic_t epoch_size; /* increased on every request added. */
	atomic_t active;     /* increased on every req. added, and dec on every finished. */
	ULONG_PTR flags;
};

/* bsr_epoch flag bits */
enum {
	DE_BARRIER_IN_NEXT_EPOCH_ISSUED,
	DE_BARRIER_IN_NEXT_EPOCH_DONE,
	DE_CONTAINS_A_BARRIER,
	DE_HAVE_BARRIER_NUMBER,
	DE_IS_FINISHING,
};

enum epoch_event {
	EV_PUT,
	EV_GOT_BARRIER_NR,
	EV_BARRIER_DONE,
	EV_BECAME_LAST,
	EV_CLEANUP = 32, /* used as flag */
};

struct digest_info {
	int digest_size;
	void *digest;
};

struct bsr_peer_request {
	struct bsr_work w;
	struct bsr_peer_device *peer_device;
	struct list_head recv_order; /* writes only */
	/* writes only, blocked on activity log;
	* FIXME merge with rcv_order or w.list? */
	struct list_head wait_for_actlog;

	struct bsr_page_chain_head page_chain;
	unsigned int op_flags; /* to be used as bi_op_flags */
	atomic_t pending_bios;
	struct bsr_interval i;
	ULONG_PTR flags; /* see comments on ee flag bits below */
	// DW-1966 I/O error number
	int error;
	union {
		struct { /* regular peer_request */
			struct bsr_epoch *epoch; /* for writes */
			ULONG_PTR submit_jif;

			// DW-1961
			bool	 do_submit;				// Whether do_submit logic passed
			LONGLONG created_ts;			// req created
			LONGLONG io_request_ts;			// Before delivering an io request to disk
			LONGLONG io_complete_ts;		// Received io completion from disk

			union {
				u64 block_id;
				struct digest_info *digest;
			};
			u64 dagtag_sector;
		}; 
		struct { /* reused object to queue send OOS to other nodes */
			u64 sent_oos_nodes; /* Used to notify L_SYNC_TARGETs about new out_of_sync bits */
			struct bsr_peer_device *send_oos_peer_device;
			u64 send_oos_in_sync;
		};
	};

#ifdef _WIN
	void* peer_req_databuf;
#endif

	struct {
		ULONG_PTR s_bb;		// DW-1601 start bitmap bit of split data 
		ULONG_PTR e_next_bb;// DW-1601 end next bitmap bit of split data  
		atomic_t *count;	// DW-1601 total split request (bitmap bit) 		        
		atomic_t *unmarked_count;    // DW-1911 this is the count for the sector not written in the maked replication bit 
		atomic_t *failed_unmarked; // DW-1911 true, if unmarked writing fails 
	};

	
	// BSR-764
	/* peer request aggregation */
	ktime_t start_kt;
	ktime_t p_submit_kt;
	ktime_t p_bio_endio_kt;
	ktime_t p_destroy_kt;
	
};

// DW-1755 passthrough policy
// disk error structure to pass to events2
struct bsr_io_error {
	unsigned char	disk_type;
	unsigned char	io_type;
	long		error_code;
	sector_t		sector;
	unsigned int	size;
	bool			is_cleared;
};

/* ee flag bits.
 * While corresponding bios are in flight, the only modification will be
 * set_bit WAS_ERROR, which has to be atomic.
 * If no bios are in flight yet, or all have been completed,
 * non-atomic modification to ee->flags is ok.
 */
enum {
	__EE_MAY_SET_IN_SYNC,

	/* This peer request closes an epoch using a barrier.
	 * On successful completion, the epoch is released,
	 * and the P_BARRIER_ACK send. */
	__EE_IS_BARRIER,

	/* is this a TRIM aka REQ_DISCARD? */
	__EE_TRIM,
	/* explicit zero-out requested, or
	 * our lower level cannot handle trim,
	 * and we want to fall back to zeroout instead */
	__EE_ZEROOUT,

	/* In case a barrier failed,
	 * we need to resubmit without the barrier flag. */
	__EE_RESUBMITTED,

	/* we may have several bios per peer request.
	 * if any of those fail, we set this flag atomically
	 * from the endio callback */
	__EE_WAS_ERROR,

	/* This ee has a pointer to a digest instead of a block id */
	__EE_HAS_DIGEST,

	/* Conflicting local requests need to be restarted after this request */
	__EE_RESTART_REQUESTS,

	/* The peer wants a write ACK for this (wire proto C) */
	__EE_SEND_WRITE_ACK,

	/* Is set when net_conf had two_primaries set while creating this peer_req */
	__EE_IN_INTERVAL_TREE,

	/* for debugfs: */
	/* has this been submitted, or does it still wait for something else? */
	__EE_SUBMITTED,

	/* this is/was a write request */
	__EE_WRITE,

	/* this is/was a write same request */
	__EE_WRITE_SAME,

	/* this originates from application on peer
	 * (not some resync or verify or other BSR internal request) */
	__EE_APPLICATION,

	/* If it contains only 0 bytes, send back P_RS_DEALLOCATED */
	__EE_RS_THIN_REQ,

	/* Hold reference in activity log */
	__EE_IN_ACTLOG,

	// DW-1601
	/* this is/was a split request */
	__EE_SPLIT_REQ,

	// DW-1601
	/* this is/was a last split request */
	__EE_SPLIT_LAST_REQ,

	// BSR-438
	/* this is/was a inacitve request
	* request not completed until connection is closed */
	__EE_WAS_INACTIVE_REQ,

	// BSR-438
	/* this is/was a lost request
	* Request not completed until connection is destroyed */
	__EE_WAS_LOST_REQ,
};
#define EE_MAY_SET_IN_SYNC     		(1<<__EE_MAY_SET_IN_SYNC)			//LSB bit field:0
#define EE_IS_BARRIER          		(1<<__EE_IS_BARRIER)				//LSB bit field:1
#define EE_TRIM            		    (1<<__EE_TRIM)
#define EE_ZEROOUT         		    (1<<__EE_ZEROOUT)
#define EE_RESUBMITTED         		(1<<__EE_RESUBMITTED)				//LSB bit field:4
#define EE_WAS_ERROR           		(1<<__EE_WAS_ERROR)					//LSB bit field:5
#define EE_HAS_DIGEST          		(1<<__EE_HAS_DIGEST)				//LSB bit field:6
#define EE_RESTART_REQUESTS			(1<<__EE_RESTART_REQUESTS)			//LSB bit field:7
#define EE_SEND_WRITE_ACK			(1<<__EE_SEND_WRITE_ACK)			//LSB bit field:8
#define EE_IN_INTERVAL_TREE			(1<<__EE_IN_INTERVAL_TREE)			//LSB bit field:9
#define EE_SUBMITTED				(1<<__EE_SUBMITTED)					//LSB bit field:10
#define EE_WRITE					(1<<__EE_WRITE)						//LSB bit field:11
#define EE_WRITE_SAME				(1<<__EE_WRITE_SAME)				//LSB bit field:12
#define EE_APPLICATION				(1<<__EE_APPLICATION)				//LSB bit field:13
#define EE_RS_THIN_REQ				(1<<__EE_RS_THIN_REQ)				//LSB bit field:14
#define EE_IN_ACTLOG				(1<<__EE_IN_ACTLOG)					//LSB bit field:15
// DW-1601
#define EE_SPLIT_REQ			(1<<__EE_SPLIT_REQ)				//LSB bit field:16 
#define EE_SPLIT_LAST_REQ		(1<<__EE_SPLIT_LAST_REQ)				//LSB bit field:17

// BSR-438
#define EE_WAS_INACTIVE_REQ			(1<<__EE_WAS_INACTIVE_REQ)			//LSB bit field:18
#define EE_WAS_LOST_REQ				(1<<__EE_WAS_LOST_REQ)				//LSB bit field:19
/* flag bits per device */
enum {
	UNPLUG_QUEUED,		/* only relevant with kernel 2.4 */
	UNPLUG_REMOTE,		/* sending a "UnplugRemote" could help */
	MD_DIRTY,		/* current uuids and flags not yet on disk */
	CRASHED_PRIMARY,	/* This node was a crashed primary.
				 * Gets cleared when the state.conn
				 * goes into L_ESTABLISHED state. */
	MD_NO_FUA,		/* meta data device does not support barriers,
				   so don't even try */
	WAS_READ_ERROR,		/* Local disk READ failed, returned IO error */
	FORCE_DETACH,		/* Force-detach from local disk, aborting any pending local IO */
	NEW_CUR_UUID,		/* Create new current UUID when thawing IO or issuing local IO */
	__NEW_CUR_UUID,        /* Set NEW_CUR_UUID as soon as state change visible */
	AL_SUSPENDED,		/* Activity logging is currently suspended. */
	// DW-874 Since resync works per peer device and device flag is shared for all peers, it may get racy with more than one peer.
	// To support resync for more than one peer, this flag must be set as a peer device flag.
	//AHEAD_TO_SYNC_SOURCE,   /* Ahead -> SyncSource queued */
	UNREGISTERED,
	FLUSH_PENDING,		/* if set, device->flush_jif is when we submitted that flush
				 * from bsr_flush_after_epoch() */

	/* cleared only after backing device related structures have been destroyed. */
	GOING_DISKLESS,         /* Disk is being detached, because of io-error, or admin request. */

	/* to be used in bsr_device_post_work() */
	GO_DISKLESS,            /* tell worker to schedule cleanup before detach */
	DESTROY_DISK,           /* tell worker to close backing devices and destroy related structures. */
	MD_SYNC,		/* tell worker to call bsr_md_sync() */

	HAVE_LDEV,
	STABLE_RESYNC,		/* One peer_device finished the resync stable! */
	READ_BALANCE_RR,
	// BSR-904
	UUID_WERE_INITIAL_BEFORE_PROMOTION,
};

/* flag bits per peer device */
enum {
	CONSIDER_RESYNC,
	RESYNC_AFTER_NEG,       /* Resync after online grow after the attach&negotiate finished. */
	RESIZE_PENDING,		/* Size change detected locally, waiting for the response from
				 * the peer, if it changed there as well. */
	RS_START,		/* tell worker to start resync/OV */
	RS_PROGRESS,		/* tell worker that resync made significant progress */
	RS_DONE,		/* tell worker that resync is done */
	B_RS_H_DONE,		/* Before resync handler done (already executed) */
	DISCARD_MY_DATA,	/* discard_my_data flag per volume */
	USE_DEGR_WFC_T,		/* degr-wfc-timeout instead of wfc-timeout. */
	INITIAL_STATE_SENT,
	INITIAL_STATE_RECEIVED,
	RECONCILIATION_RESYNC,
	UNSTABLE_RESYNC,	/* Sync source went unstable during resync. */
	SEND_STATE_AFTER_AHEAD,
	GOT_NEG_ACK,        /* got a neg_ack while primary, wait until peer_disk is lower than
                    D_UP_TO_DATE before becoming secondary! */
	// DW-874 Moved from device flag. See device flag comment for detail.
	AHEAD_TO_SYNC_SOURCE,   /* Ahead -> SyncSource queued */

	// DW-955 add resync aborted flag to resume it later.
	RESYNC_ABORTED,			/* Resync has been aborted due to unsyncable (peer)disk state, need to resume it when it goes syncable. */

	UNSTABLE_TRIGGER_CP,	// DW-1341 Do Trigger when my stability is unstable for Crashed Primay wiered case
	SEND_BITMAP_WORK_PENDING, // DW-1447 Do not queue send_bitmap() until the peer's repl_state changes to WFBitmapT. Used when invalidate-remote/invalidate.

	// DW-1598
	CONNECTION_ALREADY_FREED,
	
	// DW-1799 use for disk size comparison and setup.
	INITIAL_SIZE_RECEIVED,

	// BSR-118
	OV_FAST_BM_SET_PENDING,

	// BSR-52
	USE_CURRENT_OOS_FOR_SYNC,

	// BSR-1019
	UUID_DELAY_SEND,

};

/* We could make these currently hardcoded constants configurable
 * variables at create-md time (or even re-configurable at runtime?).
 * Which will require some more changes to the BSR "super block"
 * and attach code.
 *
 * updates per transaction:
 *   This many changes to the active set can be logged with one transaction.
 *   This number is arbitrary.
 * context per transaction:
 *   This many context extent numbers are logged with each transaction.
 *   This number is resulting from the transaction block size (4k), the layout
 *   of the transaction header, and the number of updates per transaction.
 *   See bsr_actlog.c:struct al_transaction_on_disk
 * */
#define AL_UPDATES_PER_TRANSACTION	 64	// arbitrary
#define AL_CONTEXT_PER_TRANSACTION	919	// (4096 - 36 - 6*64)/4

/* definition of bits in bm_flags to be used in bsr_bm_lock
 * and bsr_bitmap_io and friends. */
enum bm_flag {
	/*
	 * The bitmap can be locked to prevent others from clearing, setting,
	 * and/or testing bits.  The following combinations of lock flags make
	 * sense:
	 *
	 *   BM_LOCK_CLEAR,
	 *   BM_LOCK_SET, | BM_LOCK_CLEAR,
	 *   BM_LOCK_TEST | BM_LOCK_SET | BM_LOCK_CLEAR.
	 */

	BM_LOCK_TEST = 0x1,
	BM_LOCK_SET = 0x2,
	BM_LOCK_CLEAR = 0x4,
	BM_LOCK_BULK = 0x8, /* locked for bulk operation, allow all non-bulk operations */

	BM_LOCK_ALL = BM_LOCK_TEST | BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,

	BM_LOCK_SINGLE_SLOT = 0x10,
	// DW-1979 used to avoid printing unnecessary FIXME logs by modifying issues (send, receive bitmap)
	BM_LOCK_POINTLESS = 0x20,
};

struct bsr_bitmap {
	struct page **bm_pages;
	spinlock_t bm_lock;

	ULONG_PTR bm_set[BSR_PEERS_MAX]; /* number of bits set */
	ULONG_PTR bm_bits;  /* bits per peer */
	size_t   bm_words;
	size_t   bm_number_of_pages;
	sector_t bm_dev_capacity;
	struct mutex bm_change; /* serializes resize operations */

	wait_queue_head_t bm_io_wait; /* used to serialize IO of single pages */

	enum bm_flag bm_flags;
	unsigned int bm_max_peers;

	/* exclusively to be used by __al_write_transaction(),
	 * and bsr_bm_write_hinted() -> bm_rw() called from there.
	 * One activity log extent represents 4MB of storage, which are 1024
	 * bits (at 4k per bit), times at most BSR_PEERS_MAX (currently 32).
	 * The bitmap is created interleaved, with a potentially odd number
	 * of peer slots determined at create-md time.  Which means that one
	 * AL-extent may be associated with one or two bitmap pages.
	 */
	unsigned int n_bitmap_hints;
	unsigned int al_bitmap_hints[2*AL_UPDATES_PER_TRANSACTION];

	/* debugging aid, in case we are still racy somewhere */
	char          *bm_why;
	struct task_struct *bm_task;
	struct bsr_peer_device *bm_locked_peer;
};

struct bsr_work_queue {
	struct list_head q;
	spinlock_t q_lock;  /* to protect the list. */
	wait_queue_head_t q_wait;
};

struct bsr_peer_md {
	u64 bitmap_uuid;
	u64 bitmap_dagtag;
	u32 flags;
	s32 bitmap_index;
};

struct bsr_md {
	u64 md_offset;		/* sector offset to 'super' block */

	u64 effective_size;	/* last agreed size (sectors) */
	spinlock_t uuid_lock;
	u64 current_uuid;
	u64 device_uuid;
	u32 flags;
	s32 node_id;
	u32 md_size_sect;

	s32 al_offset;	/* signed relative sector offset to activity log */
	s32 bm_offset;	/* signed relative sector offset to bitmap */

	struct bsr_peer_md peers[BSR_NODE_ID_MAX];
	u64 history_uuids[HISTORY_UUIDS];

	/* cached value of bdev->disk_conf->meta_dev_idx */
	s32 meta_dev_idx;

	/* see al_tr_number_to_on_disk_sector() */
	u32 al_stripes;
	u32 al_stripe_size_4k;
	u32 al_size_4k; /* cached product of the above */
};

struct bsr_backing_dev {
	struct block_device *backing_bdev;
	struct block_device *md_bdev;
	struct bsr_md md;
	struct disk_conf *disk_conf; /* RCU, for updates: resource->conf_update */
	sector_t known_size; /* last known size of that backing device */
};

struct bsr_md_io {
	struct page *page;
	ULONG_PTR start_jif;	/* last call to bsr_md_get_buffer */
	ULONG_PTR submit_jif;	/* last _bsr_md_sync_page_io() submit */

	// DW-1961
	LONGLONG prepare_ts;	// prepare md io request
	LONGLONG io_request_ts;		// before requesting md io to disk
	LONGLONG io_complete_ts;		// receive md io complete

	const char *current_use;
	atomic_t in_use;
	unsigned int done;
	int error;
};

struct bm_io_work {
	struct bsr_work w;
	struct bsr_device *device;
	struct bsr_peer_device *peer_device;
	char *why;
	enum bm_flag flags;
	int (*io_fn)(struct bsr_device *, struct bsr_peer_device *);
	void (*done)(struct bsr_device *device, struct bsr_peer_device *, int rv);
};

struct fifo_buffer {
	/* singly linked list to accumulate multiple such struct fifo_buffers,
	 * to be freed after a single syncronize_rcu(),
	 * outside a critical section. */
	struct fifo_buffer *next;
	unsigned int head_index;
	unsigned int size;
	int total; /* sum of all values */
	int values[0];
};
#ifdef _WIN
extern struct fifo_buffer *fifo_alloc(int fifo_size, ULONG Tag);
#else // _LIN
extern struct fifo_buffer *fifo_alloc(int fifo_size);
#endif

/* flag bits per connection */
enum {
	SEND_PING,
	GOT_PING_ACK,		/* set when we receive a ping_ack packet, ping_wait gets woken */
	TWOPC_PREPARED,
	TWOPC_YES,
	TWOPC_NO,
	TWOPC_RETRY,
	CONN_DRY_RUN,		/* Expect disconnect after resync handshake. */
	CREATE_BARRIER,		/* next P_DATA is preceded by a P_BARRIER */
	DISCONNECT_EXPECTED,
	BARRIER_ACK_PENDING,
	CORKED,
	DATA_CORKED = CORKED,
	CONTROL_CORKED,
	C_UNREGISTERED,
	RECONNECT,
	CONN_DISCARD_MY_DATA,
	SEND_STATE_AFTER_AHEAD_C,
	// DW-2035 set only when command down is in role secondary
	DISCONN_NO_WAIT_RESYNC,
	// BSR-863
	GOT_UUID_ACK,
	// BSR-894
	PRIMARY_DISCONNECT_EXPECTED,
};

/* flag bits per resource */
enum {
	EXPLICIT_PRIMARY,
	CALLBACK_PENDING,	/* Whether we have a call_usermodehelper(, UMH_WAIT_PROC)
				 * pending, from bsr worker context.
				 * If set, bdi_write_congested() returns true,
				 * so shrink_page_list() would not recurse into,
				 * and potentially deadlock on, this bsr worker.
				 */
	NEGOTIATION_RESULT_TOUCHED,
	TWOPC_ABORT_LOCAL,
	TWOPC_EXECUTED,         /* Commited or aborted */
	// BSR-937 fix avoid state change races between change_cluster_wide_state() and w_after_state_change()
	STATE_WORK_PENDING,		
	DEVICE_WORK_PENDING,	/* tell worker that some device has pending work */
	PEER_DEVICE_WORK_PENDING,/* tell worker that some peer_device has pending work */
	RESOURCE_WORK_PENDING,  /* tell worker that some peer_device has pending work */

        /* to be used in bsr_post_work() */
	TRY_BECOME_UP_TO_DATE,  /* try to become D_UP_TO_DATE */
};

enum which_state { NOW, OLD = NOW, NEW };

enum twopc_type {
	TWOPC_STATE_CHANGE,
	TWOPC_RESIZE,
};

struct twopc_reply {
	int vnr;
	unsigned int tid;  /* transaction identifier */
	int initiator_node_id;  /* initiator of the transaction */
	int target_node_id;  /* target of the transaction (or -1) */
	u64 target_reachable_nodes;  /* behind the target node */
	u64 reachable_nodes;  /* behind other nodes */
	union {
		struct { /* type == TWOPC_STATE_CHANGE */
			u64 primary_nodes;
			u64 weak_nodes;
		};
		struct { /* type == TWOPC_RESIZE */
			u64 diskful_primary_nodes;
			u64 max_possible_size;
		};
	};
	int is_disconnect:1;
	int is_aborted:1;
};

struct bsr_thread_timing_details
{
	ULONG_PTR start_jif;
	void *cb_addr;
	const char *caller_fn;
	unsigned int line;
	unsigned int cb_nr;
};
#define BSR_THREAD_DETAILS_HIST	16

struct bsr_send_buffer {
	struct page *page;  /* current buffer page for sending data */
	char *unsent;  /* start of unsent area != pos if corked... */
	char *pos; /* position within that page */
	int allocated_size; /* currently allocated space */
	int additional_size;  /* additional space to be added to next packet's size */
};
#ifdef _WIN
struct connect_work {
	struct bsr_work w;
	struct bsr_resource* resource;
	int(*func)(struct bsr_thread *thi);
	struct bsr_thread* receiver;
};

struct disconnect_work {
	struct bsr_work w;
	struct bsr_resource* resource;
};
#endif

struct flush_context_sync {
	atomic_t primary_node_id;
	atomic_t64 barrier_nr;
};

/* This is blkdev_issue_flush, but asynchronous.
 * We want to submit to all component volumes in parallel,
 * then wait for all completions.
 */
struct issue_flush_context {
	atomic_t pending;
	int error;
	struct completion done;
	struct flush_context_sync ctx_sync;
};
struct one_flush_context {
	struct bsr_device *device;
	struct issue_flush_context *ctx;
	struct flush_context_sync ctx_sync;
};

#ifdef _WIN
#define CONFIG_DEBUG_FS
#endif

struct bsr_resource {
	char *name;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_res;
	struct dentry *debugfs_res_volumes;
	struct dentry *debugfs_res_connections;
	struct dentry *debugfs_res_in_flight_summary;
	struct dentry *debugfs_res_state_twopc;
#endif
	struct kref kref;
	struct kref_debug_info kref_debug;
	struct idr devices;		/* volume number to device mapping */
	struct list_head connections;
	struct list_head resources;
	struct res_opts res_opts;
	struct node_opts node_opts;
	unsigned int max_node_id;
	struct mutex conf_update;	/* for ready-copy-update of net_conf and disk_conf
					   and devices, connection and peer_devices lists */
	struct mutex adm_mutex;		/* mutex to serialize administrative requests */
	struct mutex vol_ctl_mutex;	// DW-1317 chaning role involves the volume for device is (dis)mounted, use this when the role change needs to be waited. 
	spinlock_t req_lock;
	u64 dagtag_sector;		/* Protected by req_lock.
					 * See also dagtag_sector in
					 * &bsr_request */
	ULONG_PTR flags;
	struct list_head transfer_log;	/* all requests not yet fully processed */

#ifdef NETQUEUED_LOG
	struct list_head net_queued_log;	/* RQ_NET_QUEUED requests */
#endif

	struct list_head peer_ack_list;  /* requests to send peer acks for */
	u64 last_peer_acked_dagtag;  /* dagtag of last PEER_ACK'ed request */
	struct bsr_request *peer_ack_req;  /* last request not yet PEER_ACK'ed */

	struct semaphore state_sem;
	wait_queue_head_t state_wait;  /* upon each state change. */
	// BSR-937
	wait_queue_head_t state_work_wait;
	enum chg_state_flags state_change_flags;
	const char **state_change_err_str;
	bool remote_state_change;  /* remote state change in progress */
	enum twopc_type twopc_type; /* from prepare phase */
	enum bsr_packet twopc_prepare_reply_cmd; /* this node's answer to the prepare phase or 0 */
	struct list_head twopc_parents;  /* prepared on behalf of peer */
	u64 twopc_parent_nodes;
	struct twopc_reply twopc_reply;
	struct timer_list twopc_timer;
	struct bsr_work twopc_work;
	wait_queue_head_t twopc_wait;
	struct twopc_resize {
		int dds_flags;            /* from prepare phase */
		sector_t user_size;       /* from prepare phase */
		u64 diskful_primary_nodes;/* added in commit phase */
		u64 new_size;             /* added in commit phase */
	} twopc_resize;
	struct list_head queued_twopc;
	spinlock_t queued_twopc_lock;
	struct timer_list queued_twopc_timer;
	struct queued_twopc *starting_queued_twopc;

	enum bsr_role role[2];
	bool susp[2];			/* IO suspended by user */
	bool susp_nod[2];		/* IO suspended because no data */

	enum write_ordering_e write_ordering;
	atomic_t current_tle_nr;	/* transfer log epoch number */
	unsigned current_tle_writes;	/* writes seen within this tl epoch */

#ifdef _LIN
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30) && !defined(cpumask_bits)
	cpumask_t cpu_mask[1];
#else
	cpumask_var_t cpu_mask;
#endif
#endif

	struct bsr_work_queue work;
	struct bsr_thread worker;

	struct list_head listeners;
	spinlock_t listeners_lock;

	struct timer_list peer_ack_timer; /* send a P_PEER_ACK after last completion */
	struct timer_list repost_up_to_date_timer;

	unsigned int w_cb_nr; /* keeps counting up */
	struct bsr_thread_timing_details w_timing_details[BSR_THREAD_DETAILS_HIST];
	wait_queue_head_t barrier_wait;  /* upon each state change. */
	wait_queue_head_t resync_reply_wait;
#ifdef _WIN
	bool bPreSecondaryLock;
	bool bPreDismountLock; // DW-1286
#endif
	bool bTempAllowMount;  // DW-1317
	bool breqbuf_overflow_alarm; // DW-1539
#ifdef _WIN_MULTIVOL_THREAD
	MVOL_THREAD			WorkThreadInfo;
#endif
	struct issue_flush_context ctx_flush; // DW-1895

	atomic_t req_write_cnt;			// DW-1925
};

struct bsr_connection {
	struct list_head connections;
	struct bsr_resource *resource;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_conn;
	struct dentry *debugfs_conn_callback_history;
	struct dentry *debugfs_conn_oldest_requests;
	struct dentry *debugfs_conn_transport;
	struct dentry *debugfs_conn_transport_speed;
	struct dentry *debugfs_conn_debug;
	struct dentry *debugfs_conn_send_buf;
#endif
	struct kref kref;
	struct kref_debug_info kref_debug;
	struct idr peer_devices;	/* volume number to peer device mapping */
	enum bsr_conn_state cstate[2];
	enum bsr_role peer_role[2];
	bool susp_fen[2];		/* IO suspended because fence peer handler runs */
	ULONG_PTR flags;

	// DW-1977
	enum bsr_packet last_send_packet;

	enum bsr_fencing_policy fencing_policy;
	wait_queue_head_t ping_wait;	/* Woken upon reception of a ping, and a state change */
	// BSR-863
	wait_queue_head_t uuid_wait;	

	struct bsr_send_buffer send_buffer[2];
	struct mutex mutex[2]; /* Protect assembling of new packet until sending it (in send_buffer) */
	int agreed_pro_version;		/* actually used protocol version */
	u32 agreed_features;

	ULONG_PTR last_received;	/* in jiffies, either socket */

	atomic_t64 ap_in_flight; /* App bytes in flight (waiting for ack) */
	atomic_t64 rs_in_flight; /* resync-data bytes in flight*/

	// BSR-839 implement congestion-highwater
	atomic_t ap_in_flight_cnt; /* App cnt in flight (waiting for ack) */
	atomic_t rs_in_flight_cnt; /* resync-data cnt in flight*/

	struct bsr_work connect_timer_work;
	struct timer_list connect_timer;

	struct crypto_shash *cram_hmac_tfm;
	struct crypto_shash *integrity_tfm;  /* checksums we compute, updates protected by connection->mutex[DATA_STREAM] */
	struct crypto_shash *peer_integrity_tfm;  /* checksums we verify, only accessed from receiver thread  */
	struct crypto_shash *csums_tfm;
	struct crypto_shash *verify_tfm;
	void *int_dig_in;
	void *int_dig_vv;

	/* receiver side */
	struct bsr_epoch *current_epoch;
	spinlock_t epoch_lock;
	unsigned int epochs;

	ULONG_PTR last_reconnect_jif;

#ifdef _LIN
	/* empty member on older kernels without blk_start_plug() */
	struct blk_plug receiver_plug;
#endif
	struct bsr_thread receiver;
	struct bsr_thread sender;
	struct bsr_thread ack_receiver;
	struct workqueue_struct *ack_sender;
	struct work_struct peer_ack_work;

	struct list_head peer_requests; /* All peer requests in the order we received them.. */
	u64 last_dagtag_sector;

	struct list_head active_ee; /* IO in progress (P_DATA gets written to disk) */
	struct list_head sync_ee;   /* IO in progress (P_RS_DATA_REPLY gets written to disk) */
	struct list_head read_ee;   /* [RS]P_DATA_REQUEST being read */
	struct list_head net_ee;    /* zero-copy network send in progress */
	struct list_head done_ee;   /* need to send P_WRITE_ACK */

	// BSR-930 linux does not use inactive_ee, but only windows.
#ifdef _WIN 
	struct list_head inactive_ee;	// DW-1696 List of active_ee, sync_ee not processed at the end of the connection
	atomic_t inacitve_ee_cnt; // BSR-438 inactive_ee count not completed until connection destroy
#endif
	struct list_head unacked_peer_requests; // BSR-1036 List of unacked peer_reqeust at connection termination

	atomic_t done_ee_cnt;
	struct work_struct send_acks_work;
	wait_queue_head_t ee_wait;

	atomic_t pp_in_use;		/* allocated from page pool */
	atomic_t pp_in_use_by_net;	/* sendpage()d, still referenced by transport */
	/* sender side */
	struct bsr_work_queue sender_work;

	struct sender_todo {
		struct list_head work_list;
#ifdef _LIN
		/* If upper layers trigger an unplug on this side, we want to
		 * send and unplug hint over to the peer.  Sending it too
		 * early, or missing it completely, causes a potential latency
		 * penalty (requests idling too long in the remote queue).
		 * There is no harm done if we occasionally send one too many
		 * such unplug hints.
		 *
		 * We have two slots, which are used in an alternating fashion:
		 * If a new unplug event happens while the current pending one
		 * has not even been processed yet, we overwrite the next
		 * pending slot: there is not much point in unplugging on the
		 * remote side, if we have a full request queue to be send on
		 * this side still, and not even reached the position in the
		 * change stream when the previous local unplug happened.
		 */
		u64 unplug_dagtag_sector[2];
		unsigned int unplug_slot; /* 0 or 1 */
#endif
		/* the currently (or last) processed request,
		 * see process_sender_todo() */
		struct bsr_request *req;

		/* Points to the next request on the resource->transfer_log,
		 * which is RQ_NET_QUEUED for this connection, and so can
		 * safely be used as next starting point for the list walk
		 * in tl_next_request_for_connection().
		 *
		 * If it is NULL (we walked off the tail last time), it will be
		 * set by __req_mod( QUEUE_FOR.* ), so fast connections don't
		 * need to walk the full transfer_log list every time, even if
		 * the list is kept long by some slow connections.
		 *
		 * There is also a special value to reliably re-start
		 * the transfer log walk after having scheduled the requests
		 * for RESEND. */
#define TL_NEXT_REQUEST_RESEND	((void*)1)
		struct bsr_request *req_next;
	} todo;

	/* cached pointers,
	 * so we can look up the oldest pending requests more quickly.
	 * protected by resource->req_lock */
	struct bsr_request *req_ack_pending;
	struct bsr_request *req_not_net_done;

	unsigned int s_cb_nr; /* keeps counting up */
	unsigned int r_cb_nr; /* keeps counting up */
	struct bsr_thread_timing_details s_timing_details[BSR_THREAD_DETAILS_HIST];
	struct bsr_thread_timing_details r_timing_details[BSR_THREAD_DETAILS_HIST];

	struct {
		ULONG_PTR last_sent_barrier_jif;

		int last_sent_epoch_nr;

		/* whether this sender thread
		 * has processed a single write yet. */
		bool seen_any_write_yet;

		/* Which barrier number to send with the next P_BARRIER */
		int current_epoch_nr;

		/* how many write requests have been sent
		 * with req->epoch == current_epoch_nr.
		 * If none, no P_BARRIER will be sent. */
		unsigned current_epoch_writes;

		/* position in change stream */
		u64 current_dagtag_sector;
	} send;
#ifdef _SEND_BUF
	ring_buffer* ptxbab[2];
#endif	
	unsigned int peer_node_id;
	struct list_head twopc_parent_list;
	struct bsr_transport transport; /* The transport needs to be the last member. The acutal
					    implementation might have more members than the
					    abstract one. */
};

/* used to get the next lower or next higher peer_device depending on device node-id */
enum bsr_neighbor {
	NEXT_LOWER,
	NEXT_HIGHER
};

// BSR-450
#ifdef _LIN
typedef struct bitmap_buffer {
    long long int BitmapSize;
    unsigned char Buffer[1];

} VOLUME_BITMAP_BUFFER, *PVOLUME_BITMAP_BUFFER;
#endif

// BSR-118
struct ov_work {
	struct bsr_work w;
	struct completion done;
};

// BSR-52
struct ov_oos_info {
	struct list_head list;
	/* Start sector of out of sync range (to merge printk reporting). */
	sector_t ov_oos_start;
	/* size of out-of-sync range in sectors. */
	sector_t ov_oos_size;
};

struct ov_skipped_info {
	struct list_head list;
	/* Start sector of skipped range (to merge printk reporting). */
	sector_t ov_skipped_start;
	/* size of skipped range in sectors. */
	sector_t ov_skipped_size;
};

// BSR-687
struct timing_stat {
	ktime_t last_val;
	ktime_t total_val;
	ktime_t max_val;
	ktime_t min_val;
	atomic_t cnt;
};

struct bsr_peer_device {
	struct list_head peer_devices;
	struct bsr_device *device;
	struct bsr_connection *connection;

	// DW-1191 out-of-sync list and work that will be queued to send.
	struct list_head send_oos_list;
	struct work_struct send_oos_work;
	spinlock_t send_oos_lock;

	struct peer_device_conf *conf; /* RCU, for updates: resource->conf_update */
	enum bsr_disk_state disk_state[2];
	enum bsr_repl_state repl_state[2];
	bool resync_susp_user[2];
	bool resync_susp_peer[2];
	bool resync_susp_dependency[2];
	bool resync_susp_other_c[2];
	enum bsr_repl_state negotiation_result; /* To find disk state after attach */
	unsigned int send_cnt;
	unsigned int recv_cnt;
	atomic_t packet_seq;
	unsigned int peer_seq;
	spinlock_t peer_seq_lock;
	unsigned int max_bio_size;
	uint64_t d_size;  /* size of disk */
	uint64_t u_size;  /* user requested size */
	uint64_t c_size;  /* current exported size */
	uint64_t max_size;
	int bitmap_index;
	int node_id;
	ULONG_PTR flags;
	// DW-1806 set after initial send.
	wait_queue_head_t state_initial_send_wait;

	enum bsr_repl_state start_resync_side;
	enum bsr_repl_state last_repl_state; /* What we received from the peer */
	struct timer_list start_resync_timer;
	struct bsr_work resync_work;
	struct timer_list resync_timer;
	struct bsr_work propagate_uuids_work;
	struct ov_work fast_ov_work;

	/* Used to track operations of resync... */
	struct lru_cache *resync_lru;
	/* Number of locked elements in resync LRU */
	unsigned int resync_locked;
	/* resync extent number waiting for application requests */
	unsigned int resync_wenr;
	enum bsr_disk_state resync_finished_pdsk; /* Finished while starting resync */
	bool resync_again; /* decided to resync again while resync running */

	atomic_t ap_pending_cnt; /* AP data packets on the wire, ack expected */
	atomic_t unacked_cnt;	 /* Need to send replies for */
	atomic_t rs_pending_cnt; /* RS request/data packets on the wire */
	atomic_t wait_for_actlog;
	// DW-1979 the value used by the syncaget to match the "out of sync" with the sync source when exchanging the bitmap.
	// set to 1 when waiting for a response to a resync request.
	atomic_t wait_for_bitmp_exchange_complete;
	// DW-1979 used to determine whether the bitmap exchange is complete on the syncsource.
	// set to 1 to wait for bitmap exchange.
	atomic_t wait_for_recv_bitmap;

	// BSR-842 sart resync when 0 in L_BEHIND state. Set to 1 in L_BEHIND state and set to 0 when ID_OUT_OF_SYNC_FINISHED is received.
	atomic_t wait_for_out_of_sync;

	// DW-2058 number of incomplete write requests to send out of sync
	atomic_t rq_pending_oos_cnt;

	// DW-2119 this variables in the device were moved to the peer_device.
	// DW-1904 resync start bitmap offset
	atomic_t64 s_resync_bb;
	// DW-2065 resync end bitmap offset
	atomic_t64 e_resync_bb;

	/* use checksums for *this* resync */
	bool use_csums;
	/* blocks to resync in this run [unit BM_BLOCK_SIZE] */
	ULONG_PTR rs_total;
	/* number of resync blocks that failed in this run */
	ULONG_PTR rs_failed;
	/* Syncer's start time [unit jiffies] */
	ULONG_PTR rs_start;
	/* cumulated time in PausedSyncX state [unit jiffies] */
	ULONG_PTR rs_paused;
	/* skipped because csum was equal [unit BM_BLOCK_SIZE] */
	ULONG_PTR rs_same_csum;
	// DW-1886
	/* write completed size (failed and success) */
	atomic_t64 rs_written;
	// DW-1886 add a log for resync to check the data flow.
	/* size of send resync data request */
	ULONG_PTR rs_send_req;
	/* size of receive resync data */
	ULONG_PTR rs_recv_res;


#define BSR_SYNC_MARKS 8
#define BSR_SYNC_MARK_STEP (3*HZ)
	/* block not up-to-date at mark [unit BM_BLOCK_SIZE] */
	ULONG_PTR rs_mark_left[BSR_SYNC_MARKS];
	/* marks's time [unit jiffies] */
	ULONG_PTR rs_mark_time[BSR_SYNC_MARKS];
	/* current index into rs_mark_{left,time} */
	int rs_last_mark;
	ULONG_PTR rs_last_writeout;

	/* where does the admin want us to start? (sector) */
	sector_t ov_start_sector;
	/* BSR-835 sector of last received the ov result */
	sector_t ov_acked_sector;
	sector_t ov_stop_sector;
	ULONG_PTR ov_bm_position; /* bit offset for bsr_ov_bm_find_next */
	/* where are we now? (sector) */
	sector_t ov_position;
	/* Start sector of out of sync range (to merge printk reporting). */
	sector_t ov_last_oos_start;
	/* size of out-of-sync range in sectors. */
	sector_t ov_last_oos_size;
	/* Start sector of skipped range (to merge printk reporting). */
	sector_t ov_last_skipped_start;
	/* size of skipped range in sectors. */
	sector_t ov_last_skipped_size;

	// BSR-997 
	atomic_t64 ov_req_sector; // sector sent ov request
	atomic_t64 ov_reply_sector; // sector waiting for ov reply
	atomic_t64 ov_split_req_sector; // sector sent split ov request
	atomic_t64 ov_split_reply_sector; // sector wating for split ov reply
	sector_t ov_split_position; // sector to send split ov
	struct list_head ov_skip_sectors_list;	// list of ov sectors skipped due to replication
	spinlock_t ov_lock;

	// BSR-52 for report at ov done
	struct list_head ov_oos_info_list;
	int ov_oos_info_list_cnt;
	int ov_oos_info_report_num;
	struct list_head ov_skipped_info_list;
	int ov_skipped_info_list_cnt;
	int ov_skipped_info_report_num;

	int c_sync_rate; /* current resync rate after syncer throttle magic */
	struct fifo_buffer *rs_plan_s; /* correction values of resync planer (RCU, connection->conn_update) */
	atomic_t rs_sect_in; /* for incoming resync data rate, SyncTarget */
	int rs_last_sect_ev; /* counter to compare with */
	int rs_last_events;  /* counter of read or write "events" (unit sectors)
			      * on the lower level device when we last looked. */
	int rs_in_flight; /* resync sectors in flight (to proxy, in proxy and from proxy) */
	// BSR-838 save time every second to initialize rs_in_light to zero. 
	ULONG_PTR rs_in_flight_mark_time;

	ULONG_PTR ov_left; /* in bits */
	// BSR-997
	sector_t ov_left_sectors; /* in sector */
	sector_t ov_skipped; /* in sector */
	PVOLUME_BITMAP_BUFFER fast_ov_bitmap;

	// BSR-835 ov bitmap buffer reference count management
	struct kref ov_bm_ref;

	u64 current_uuid;
	u64 bitmap_uuids[BSR_PEERS_MAX];
	u64 history_uuids[HISTORY_UUIDS];
	u64 dirty_bits;
	u64 uuid_flags;
	u64 uuid_authoritative_nodes; /* when then UUID_FLAG_STABLE is cleared the peer thinks it is
					 not stable. It does that because it thinks these nodes
					 are authoritative */
	bool uuids_received;

	ULONG_PTR comm_bm_set; /* communicated number of set bits. */

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_peer_dev;
	struct dentry *debugfs_peer_dev_resync_extents;
	struct dentry *debugfs_peer_dev_proc_bsr;
	struct dentry *debugfs_peer_dev_resync_ratio;
#endif
	unsigned long reqs;
	struct timing_stat pre_send_kt;
	struct timing_stat acked_kt;
	struct timing_stat net_done_kt;

	/* peer request aggregation */
	spinlock_t timing_lock;
	unsigned long p_reqs;
	struct timing_stat p_submit_kt;
	struct timing_stat p_bio_endio_kt;
	struct timing_stat p_destroy_kt;

	struct {/* sender todo per peer_device */
		bool was_ahead;
	} todo;
	// DW-1981
	struct bm_xfer_ctx bm_ctx;

	// BSR-676
	atomic_t notify_flags;

	// BSR-838 be used to set replication and resync ratios
	atomic_t64 repl_ratio;
	atomic_t64 resync_ratio;
	atomic_t64 cur_resync_sended;
	atomic_t64 cur_repl_sended;
	atomic_t64 last_resync_sended;
	atomic_t64 last_repl_sended;

	atomic_t64 cur_resync_received;
	atomic_t64 last_resync_received;

	atomic_t64 resync_sended;
	atomic_t64 repl_sended;

	struct timer_list sended_timer;
};


// BSR-997
struct bsr_ov_skip_sectors {
	sector_t sst;	/* start sector number */
	sector_t est;	/* end sector number */
	struct list_head sector_list;
};


// DW-1911
struct bsr_marked_replicate {
	ULONG_PTR bb;	/* current bitmap bit */
	u8 marked_rl;    /* marks the sector as bit. (4k = 8sector = u8(8bit)) */
	struct list_head marked_rl_list;
	u16 end_unmarked_rl;
};

// DW-2042
struct bsr_resync_pending_sectors {
	sector_t sst;	/* start sector number */
	sector_t est;	/* end sector number */
	struct list_head pending_sectors;
};

struct submit_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;

	/* protected by ..->resource->req_lock */
	struct list_head writes;
	struct list_head peer_writes;
};

struct bsr_device {
#ifdef PARANOIA
	long magic;
#endif
	struct bsr_resource *resource;
	struct list_head peer_devices;
	struct list_head pending_bitmap_io;
	ULONG_PTR flush_jif;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_minor;
	struct dentry *debugfs_vol;
	struct dentry *debugfs_vol_oldest_requests;
	struct dentry *debugfs_vol_act_log_extents;
	struct dentry *debugfs_vol_act_log_stat; // BSR-765
	struct dentry *debugfs_vol_data_gen_id;
	struct dentry *debugfs_vol_io_frozen;
	struct dentry *debugfs_vol_ed_gen_id;
	struct dentry *debugfs_vol_io_stat;
	struct dentry *debugfs_vol_io_complete;
	struct dentry *debugfs_vol_io_pending; // BSR-1054
	struct dentry *debugfs_vol_req_timing;
	struct dentry *debugfs_vol_peer_req_timing;
#endif

	unsigned int vnr;	/* volume number within the connection */
	unsigned int minor;	/* device minor number */

	struct kref kref;
	struct kref_debug_info kref_debug;

	/* things that are stored as / read from meta data on disk */
	ULONG_PTR flags;

	/* configured by bsrsetup */
	struct bsr_backing_dev *ldev __protected_by(local);

	struct request_queue *rq_queue;
#ifdef _WIN
	struct block_device *this_bdev;
#endif
	struct gendisk	    *vdisk;

	ULONG_PTR last_reattach_jif;
	struct timer_list md_sync_timer;
	struct timer_list request_timer;
#ifdef BSR_DEBUG_MD_SYNC
	struct {
		unsigned int line;
		const char* func;
	} last_md_mark_dirty;
#endif

	enum bsr_disk_state disk_state[2];
	wait_queue_head_t misc_wait;
	
	unsigned int read_cnt; /*sectors*/
	unsigned int writ_cnt; /*sectors*/

	unsigned int al_writ_cnt;
	unsigned int bm_writ_cnt;
	atomic_t ap_bio_cnt[2];	 /* Requests we need to complete. [READ] and [WRITE] */
	atomic_t ap_actlog_cnt;  /* Requests waiting for activity log */
	atomic_t local_cnt;	 /* Waiting for local completion */
	atomic_t suspend_cnt;

	/* Interval trees of pending local requests */
	struct rb_root read_requests;
	struct rb_root write_requests;

	/* for statistics and timeouts */
	/* [0] read, [1] write */
	struct list_head pending_master_completion[2];
	struct list_head pending_completion[2];

	struct bsr_bitmap *bitmap;
	ULONG_PTR bm_resync_fo; /* bit offset for bsr_bm_find_next */
	// BSR-969 change the name above for use in resync timer settings as well (bm_resync_fo_mutex => bm_resync_and_resync_timer_fo_mutex)
	struct mutex bm_resync_and_resync_timer_fo_mutex;
#ifdef SPLIT_REQUEST_RESYNC
	// DW-2042
	struct list_head resync_pending_sectors;
	// DW-2058 mutex for resync pending list
	struct mutex resync_pending_fo_mutex;

	// DW-1911 marked replication list, used for resync
	//does not use lock because it guarantees synchronization for the use of marked_rl_list.
	//Use lock if you cannot guarantee future marked_rl_list synchronization
	struct list_head marked_rl_list;

	// DW-1904 range set from out of sync to in sync as replication data.
	//used to determine whether to replicate during resync.
	ULONG_PTR s_rl_bb;
	ULONG_PTR e_rl_bb;

	// DW-1911 hit resync in progress hit marked replicate,in sync count
	ULONG_PTR h_marked_bb;
	ULONG_PTR h_insync_bb;
#endif
	int open_rw_cnt, open_ro_cnt;
	/* FIXME clean comments, restructure so it is more obvious which
	 * members are protected by what */

	int next_barrier_nr;
	struct bsr_md_io md_io;
	spinlock_t al_lock;
	wait_queue_head_t al_wait;
	struct lru_cache *act_log;	/* activity log */
	unsigned int al_tr_number;
	unsigned int al_tr_cycle;
	wait_queue_head_t seq_wait;
	u64 exposed_data_uuid; /* UUID of the exposed data */
	u64 next_exposed_data_uuid;
	atomic_t rs_sect_ev; /* for submitted resync data rate, both */
	struct pending_bitmap_work_s {
		atomic_t n;		/* inc when queued here, */
		spinlock_t q_lock;	/* dec only once finished. */
		struct list_head q;	/* n > 0 even if q already empty */
	} pending_bitmap_work;
	struct device_conf device_conf;

	/* any requests that would block in bsr_make_request()
	 * are deferred to this single-threaded work queue */
	struct submit_worker submit;
	bool susp_quorum[2];		/* IO suspended quorum lost */

	// DW-1755 disk error information structure is managed as a list, 
	/* and the error count is stored separately for the status command.
	Disk errors rarely occur, and even if they occur, 
	the list counts will not increase in a large amount 
	because they will occur only in a specific sector. */
	atomic_t io_error_count;
	spinlock_t timing_lock;
	ktime_t aggregation_start_kt;

	/* request aggregation*/
	unsigned long reqs;
	struct timing_stat in_actlog_kt;
	struct timing_stat submit_kt; /* aggregate over all reqs */
	struct timing_stat bio_endio_kt;
	struct timing_stat before_queue_kt; /* aggregate over all al_misses */
	struct timing_stat before_al_begin_io_kt;
	struct timing_stat req_destroy_kt;
	atomic_t al_updates_cnt;
	struct timing_stat al_before_bm_write_hinted_kt; /* aggregate over all al_updates */
	struct timing_stat al_after_bm_write_hinted_kt;
	struct timing_stat al_after_sync_page_kt;

	// BSR-765 add AL performance aggregation
	unsigned e_al_starving, e_al_pending, e_al_used, e_al_busy, e_al_wouldblock;
	unsigned al_wait_retry_cnt, al_wait_retry_total, al_wait_retry_max;

	/* IO aggregation. [READ] and [WRITE] */
	atomic_t io_cnt[2];
	atomic_t io_size[2]; /* bytes */
	struct timing_stat local_complete_kt; /* bsr_request_endio time aggregation*/
	struct timing_stat master_complete_kt; /* complete_master_bio time aggregation*/
	// BSR-676
	atomic_t notify_flags;
	// BSR-904
#ifdef _LIN
	atomic_t mounted_cnt;
#endif
};

struct bsr_bm_aio_ctx {
	struct bsr_device *device;
	struct list_head list; /* on device->pending_bitmap_io */
	ULONG_PTR start_jif;
	atomic_t in_flight;
	unsigned int done;
	unsigned flags;
#define BM_AIO_COPY_PAGES	1
#define BM_AIO_WRITE_HINTED	2
#define BM_AIO_WRITE_ALL_PAGES	4
#define BM_AIO_READ	        8
#define BM_AIO_WRITE_LAZY      16
	int error;
	struct kref kref;
};

struct bsr_config_context {
	/* assigned from bsr_genlmsghdr */
	unsigned int minor;
	/* assigned from request attributes, if present */
	unsigned int volume;
#define VOLUME_UNSPECIFIED			UINT32_MAX	//volume type unsigned int
	unsigned int peer_node_id;
#define PEER_NODE_ID_UNSPECIFIED	UINT32_MAX	//peer_node_id type unsigned int
	/* pointer into the request skb,
	 * limited lifetime! */
	char *resource_name;
	struct nlattr *my_addr;
	struct nlattr *peer_addr;

	/* reply buffer */
	struct sk_buff *reply_skb;
	/* pointer into reply buffer */
	struct bsr_genlmsghdr *reply_dh;
	/* resolved from attributes, if possible */
	struct bsr_device *device;
	struct bsr_resource *resource;
	struct bsr_connection *connection;
	struct bsr_peer_device *peer_device;
};

static inline struct bsr_device *minor_to_device(unsigned int minor)
{
	return (struct bsr_device *)idr_find(&bsr_devices, minor);
}


static inline struct bsr_peer_device *
conn_peer_device(struct bsr_connection *connection, int volume_number)
{
	return (struct bsr_peer_device *)idr_find(&connection->peer_devices, volume_number);
}

static inline unsigned bsr_req_state_by_peer_device(struct bsr_request *req,
		struct bsr_peer_device *peer_device)
{
	int idx = peer_device->node_id;
	if (idx < 0 || idx >= BSR_NODE_ID_MAX) {
		bsr_warn(23, BSR_LC_REQUEST, peer_device, "FIXME: unexpected node id(%d)", idx);
		/* WARN(1, "bitmap_index: %d", idx); */
		return 0;
	}
	return req->rq_state[1 + idx];
}

#define for_each_resource(resource, _resources) \
	list_for_each_entry_ex(struct bsr_resource, resource, _resources, resources)

/* Each caller of for_each_connect() must hold req_lock or adm_mutex or conf_update.
   The update locations hold all three! */
#define for_each_connection(connection, resource) \
	list_for_each_entry_ex(struct bsr_connection, connection, &resource->connections, connections)

#define for_each_resource_rcu(resource, _resources) \
	list_for_each_entry_rcu_ex(struct bsr_resource, resource, _resources, resources)

#define for_each_connection_rcu(connection, resource) \
	list_for_each_entry_rcu_ex(struct bsr_connection, connection, &resource->connections, connections)

#define for_each_resource_safe(resource, tmp, _resources) \
	list_for_each_entry_safe_ex(struct bsr_resource, resource, tmp, _resources, resources)

#define for_each_connection_safe(connection, tmp, resource) \
	list_for_each_entry_safe_ex(struct bsr_connection, connection, tmp, &resource->connections, connections)

#define for_each_connection_ref(connection, m, resource)		\
	for (connection = __bsr_next_connection_ref(&m, NULL, resource); \
	     connection;						\
	     connection = __bsr_next_connection_ref(&m, connection, resource))

/* Each caller of for_each_peer_device() must hold req_lock or adm_mutex or conf_update.
   The update locations hold all three! */
#define for_each_peer_device(peer_device, device) \
	list_for_each_entry_ex(struct bsr_peer_device, peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_rcu(peer_device, device) \
 	list_for_each_entry_rcu_ex(struct bsr_peer_device, peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_safe(peer_device, tmp, device) \
	list_for_each_entry_safe_ex(struct bsr_peer_device, peer_device, tmp, &device->peer_devices, peer_devices)

#define for_each_peer_device_ref(peer_device, m, device)		\
	for (peer_device = __bsr_next_peer_device_ref(&m, NULL, device); \
	     peer_device;						\
	     peer_device = __bsr_next_peer_device_ref(&m, peer_device, device))

static inline unsigned int device_to_minor(struct bsr_device *device)
{
	return device->minor;
}

/*
 * function declarations
 *************************/

/* bsr_main.c */

enum dds_flags {
	/* This enum is part of the wire protocol!
	* See P_SIZES, struct p_sizes; */
	DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE = 1,
	DDSF_NO_RESYNC = 2, /* Do not run a resync for the new space */
	DDSF_IGNORE_PEER_CONSTRAINTS = 4,
	DDSF_2PC = 8, /* local only, not on the wire */
};

extern int  bsr_thread_start(struct bsr_thread *thi);
extern void _bsr_thread_stop(struct bsr_thread *thi, int restart, int wait);

#ifdef _WIN
#define bsr_thread_current_set_cpu(A)
#else // _LIN
#ifdef CONFIG_SMP
extern void bsr_thread_current_set_cpu(struct bsr_thread *thi);
#else
#define bsr_thread_current_set_cpu(A) ({})
#endif
#endif

extern void tl_release(struct bsr_connection *, int barrier_nr,
		       unsigned int set_size);
extern void tl_clear(struct bsr_connection *);
extern void bsr_free_sock(struct bsr_connection *connection);

extern int __bsr_send_protocol(struct bsr_connection *connection, enum bsr_packet cmd);
extern int bsr_send_protocol(struct bsr_connection *connection);
extern int bsr_send_uuids(struct bsr_peer_device *, u64 uuid_flags, u64 weak_nodes, enum which_state which);
extern void bsr_gen_and_send_sync_uuid(struct bsr_peer_device *);
extern int bsr_attach_peer_device(struct bsr_peer_device *);
extern int bsr_send_sizes(struct bsr_peer_device *, uint64_t u_size_diskless, enum dds_flags flags);
extern int conn_send_state(struct bsr_connection *, union bsr_state);
extern int bsr_send_state(struct bsr_peer_device *, union bsr_state);
extern int bsr_send_current_state(struct bsr_peer_device *);
extern int bsr_send_sync_param(struct bsr_peer_device *);
extern void bsr_send_b_ack(struct bsr_connection *connection, s32 barrier_nr, u32 set_size);
extern int bsr_send_out_of_sync(struct bsr_peer_device *, struct bsr_interval *);
extern int bsr_send_block(struct bsr_peer_device *, enum bsr_packet,
			   struct bsr_peer_request *);
extern int bsr_send_dblock(struct bsr_peer_device *, struct bsr_request *req);
extern int bsr_send_drequest(struct bsr_peer_device *, int cmd,
			      sector_t sector, int size, u64 block_id);

extern int _bsr_send_ack(struct bsr_peer_device *peer_device, enum bsr_packet cmd,
	u64 sector, u32 blksize, u64 block_id);

extern int _bsr_send_bitmap_exchange_state(struct bsr_peer_device *peer_device, enum bsr_packet cmd, u32 state);

extern void *bsr_prepare_drequest_csum(struct bsr_peer_request *peer_req, int digest_size);
extern int bsr_send_ov_request(struct bsr_peer_device *, sector_t sector, int size);

// DW-2037
extern void bsr_send_bitmap_source_complete(struct bsr_device *, struct bsr_peer_device *, int);

// DW-1979
extern void bsr_send_bitmap_target_complete(struct bsr_device *, struct bsr_peer_device *, int);
extern int bsr_send_bitmap(struct bsr_device *, struct bsr_peer_device *);
extern int bsr_send_dagtag(struct bsr_connection *connection, u64 dagtag);
extern void bsr_send_sr_reply(struct bsr_connection *connection, int vnr,
			       enum bsr_state_rv retcode);
extern int bsr_send_rs_deallocated(struct bsr_peer_device *, struct bsr_peer_request *);
extern void bsr_send_twopc_reply(struct bsr_connection *connection,
				  enum bsr_packet, struct twopc_reply *);
extern void bsr_send_peers_in_sync(struct bsr_peer_device *, u64, sector_t, int);
extern int bsr_send_peer_dagtag(struct bsr_connection *connection, struct bsr_connection *lost_peer);
extern int bsr_send_current_uuid(struct bsr_peer_device *peer_device, u64 current_uuid, u64 weak_nodes);
extern void bsr_backing_dev_free(struct bsr_device *device, struct bsr_backing_dev *ldev);
extern void bsr_cleanup_device(struct bsr_device *device);
extern void bsr_print_uuids(struct bsr_peer_device *peer_device, const char *text, const char *caller);
extern void bsr_queue_unplug(struct bsr_device *device);

extern u64 bsr_capacity_to_on_disk_bm_sect(u64 capacity_sect, unsigned int max_peers);
extern void bsr_md_set_sector_offsets(struct bsr_device *device,
				       struct bsr_backing_dev *bdev);
extern void bsr_md_write(struct bsr_device *device, void *buffer);
extern void bsr_md_sync(struct bsr_device *device);
extern void bsr_md_sync_if_dirty(struct bsr_device *device);
extern int  bsr_md_read(struct bsr_device *device, struct bsr_backing_dev *bdev);
// DW-1145
extern void bsr_propagate_uuids(struct bsr_device *device, u64 nodes) __must_hold(local);
extern void bsr_uuid_received_new_current(struct bsr_peer_device *, u64 , u64) __must_hold(local);
extern void bsr_uuid_set_bitmap(struct bsr_peer_device *peer_device, u64 val) __must_hold(local);
extern void _bsr_uuid_set_bitmap(struct bsr_peer_device *peer_device, u64 val) __must_hold(local);
extern void _bsr_uuid_set_current(struct bsr_device *device, u64 val) __must_hold(local);
// BSR-967 add arguments for younger primary
extern void bsr_uuid_new_current(struct bsr_device *device, bool forced, bool younger, const char* caller);
extern void bsr_uuid_new_current_by_user(struct bsr_device *device);
extern void _bsr_uuid_push_history(struct bsr_device *device, u64 val, u64 *old_val) __must_hold(local);
extern u64 _bsr_uuid_pull_history(struct bsr_peer_device *peer_device, u64 *val) __must_hold(local);
extern void __bsr_uuid_set_bitmap(struct bsr_peer_device *peer_device, u64 val) __must_hold(local);
extern u64 bsr_uuid_resync_finished(struct bsr_peer_device *peer_device, struct bsr_peer_md *old_peer_md, u64 *removed_history, u64 *before_uuid) __must_hold(local);
// BSR-863
u64 bsr_uuid_resync_finished_rollback(struct bsr_peer_device *peer_device, u64 do_nodes, u64 uuid, struct bsr_peer_md *peer_md, u64 history) __must_hold(local);

// DW-955
extern void forget_bitmap(struct bsr_device *device, int node_id) __must_hold(local);
extern void bsr_uuid_detect_finished_resyncs(struct bsr_peer_device *peer_device) __must_hold(local);
extern u64 bsr_weak_nodes_device(struct bsr_device *device);
extern void bsr_md_set_flag(struct bsr_device *device, enum mdf_flag) __must_hold(local);
extern void bsr_md_clear_flag(struct bsr_device *device, enum mdf_flag)__must_hold(local);
extern int bsr_md_test_flag(struct bsr_device *device, enum mdf_flag);
extern void bsr_md_set_peer_flag(struct bsr_peer_device *, enum mdf_peer_flag);
extern void bsr_md_clear_peer_flag(struct bsr_peer_device *, enum mdf_peer_flag);
extern bool bsr_md_test_peer_flag(struct bsr_peer_device *, enum mdf_peer_flag);
#ifdef BSR_DEBUG_MD_SYNC
#define bsr_md_mark_dirty(m)	bsr_md_mark_dirty_(m, __LINE__ , __func__ )
extern void bsr_md_mark_dirty_(struct bsr_device *device,
	unsigned int line, const char *func);
#else
extern void bsr_md_mark_dirty(struct bsr_device *device);
#endif
extern void bsr_queue_bitmap_io(struct bsr_device *,
				 int (*io_fn)(struct bsr_device *, struct bsr_peer_device *),
				 void (*done)(struct bsr_device *, struct bsr_peer_device *, int),
				 char *why, enum bm_flag flags,
				 struct bsr_peer_device *);
extern int bsr_bitmap_io(struct bsr_device *,
		int (*io_fn)(struct bsr_device *, struct bsr_peer_device *),
		char *why, enum bm_flag flags,
		struct bsr_peer_device *);
extern int bsr_bitmap_io_from_worker(struct bsr_device *,
		int (*io_fn)(struct bsr_device *, struct bsr_peer_device *),
		char *why, enum bm_flag flags,
		struct bsr_peer_device *);
extern int bsr_bmio_set_n_write(struct bsr_device *device, struct bsr_peer_device *) __must_hold(local);


// DW-844
extern bool SetOOSAllocatedCluster(struct bsr_device *device, struct bsr_peer_device *, enum bsr_repl_state side, bool bitmap_lock, bool *bSync) __must_hold(local);
extern bool isFastInitialSync(void);
extern PVOID GetVolumeBitmap(struct bsr_device *device, ULONGLONG * pullTotalCluster, ULONG * pulBytesPerCluster);
#ifdef _LIN
extern bool isDeviceMounted(struct bsr_device *device);

#endif
extern int bsr_bmio_clear_all_n_write(struct bsr_device *device, struct bsr_peer_device *) __must_hold(local);
extern int bsr_bmio_set_all_n_write(struct bsr_device *device, struct bsr_peer_device *) __must_hold(local);
// DW-1293
extern int bsr_bmio_set_all_or_fast(struct bsr_device *device, struct bsr_peer_device *peer_device) __must_hold(local);
extern bool bsr_device_stable(struct bsr_device *device, u64 *authoritative);


// DW-1315
extern bool bsr_device_stable_ex(struct bsr_device *device, u64 *authoritative, enum which_state which, bool locked);

extern void bsr_flush_peer_acks(struct bsr_resource *resource);
extern void bsr_drop_unsent(struct bsr_connection* connection);
extern void bsr_cork(struct bsr_connection *connection, enum bsr_stream stream);
extern void bsr_uncork(struct bsr_connection *connection, enum bsr_stream stream);

extern struct bsr_connection *
__bsr_next_connection_ref(u64 *, struct bsr_connection *, struct bsr_resource *);

extern struct bsr_peer_device *
__bsr_next_peer_device_ref(u64 *, struct bsr_peer_device *, struct bsr_device *);


/* Meta data layout
 *
 * We currently have two possible layouts.
 * Offsets in (512 byte) sectors.
 * external:
 *   |----------- md_size_sect ------------------|
 *   [ 4k superblock ][ activity log ][  Bitmap  ]
 *   | al_offset == 8 |
 *   | bm_offset = al_offset + X      |
 *  ==> bitmap sectors = md_size_sect - bm_offset
 *
 *  Variants:
 *     old, indexed fixed size meta data:
 *
 * internal:
 *            |----------- md_size_sect ------------------|
 * [data.....][  Bitmap  ][ activity log ][ 4k superblock ][padding*]
 *                        | al_offset < 0 |
 *            | bm_offset = al_offset - Y |
 *  ==> bitmap sectors = Y = al_offset - bm_offset
 *
 *  [padding*] are zero or up to 7 unused 512 Byte sectors to the
 *  end of the device, so that the [4k superblock] will be 4k aligned.
 *
 *  The activity log consists of 4k transaction blocks,
 *  which are written in a ring-buffer, or striped ring-buffer like fashion,
 *  which are writtensize used to be fixed 32kB,
 *  but is about to become configurable.
 */

/* One activity log extent represents 4M of storage */
#define AL_EXTENT_SHIFT 22
#define AL_EXTENT_SIZE (1<<AL_EXTENT_SHIFT)

/* bsr_bitmap.c */
/*
 * We need to store one bit for a block.
 * Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
 * Bit 0 ==> local node thinks this block is binary identical on both nodes
 * Bit 1 ==> local node thinks this block needs to be synced.
 */

#define SLEEP_TIME (HZ/10)

/* We do bitmap IO in units of 4k blocks.
 * We also still have a hardcoded 4k per bit relation. */
#define BM_BLOCK_SHIFT	12			 /* 4k per bit */
#define BM_BLOCK_SIZE	 (1<<BM_BLOCK_SHIFT)
/* mostly arbitrarily set the represented size of one bitmap extent,
 * aka resync extent, to 128 MiB (which is also 4096 Byte worth of bitmap
 * at 4k per bit resolution) */
#define BM_EXT_SHIFT	 27	/* 128 MiB per resync extent */
#define BM_EXT_SIZE	 (1<<BM_EXT_SHIFT)

#if (BM_BLOCK_SHIFT != 12)
#error "HAVE YOU FIXED bsrmeta AS WELL??"
#endif

/* thus many _storage_ sectors are described by one bit */
#define BM_SECT_TO_BIT(x)   ((x)>>(BM_BLOCK_SHIFT-9))
#define BM_BIT_TO_SECT(x)   ((sector_t)(x)<<(BM_BLOCK_SHIFT-9))
#define BM_SECT_PER_BIT     BM_BIT_TO_SECT(1)

/* bit to represented kilo byte conversion */
#define Bit2KB(bits) ((bits)<<(BM_BLOCK_SHIFT-10))

/* in which _bitmap_ extent (resp. sector) the bit for a certain
 * _storage_ sector is located in */
#define BM_SECT_TO_EXT(x)   ((x)>>(BM_EXT_SHIFT-9))
#define BM_BIT_TO_EXT(x)    ((x) >> (BM_EXT_SHIFT - BM_BLOCK_SHIFT))

/* first storage sector a bitmap extent corresponds to */
#define BM_EXT_TO_SECT(x)   ((sector_t)(x) << (BM_EXT_SHIFT-9))
/* how much _storage_ sectors we have per bitmap extent */
#define BM_SECT_PER_EXT     BM_EXT_TO_SECT(1)
/* how many bits are covered by one bitmap extent (resync extent) */
#define BM_BITS_PER_EXT     (1UL << (BM_EXT_SHIFT - BM_BLOCK_SHIFT))

#define BM_BLOCKS_PER_BM_EXT_MASK  (BM_BITS_PER_EXT - 1)


/* in one sector of the bitmap, we have this many activity_log extents. */
#define AL_EXT_PER_BM_SECT  (1 << (BM_EXT_SHIFT - AL_EXTENT_SHIFT))

/* the extent in "PER_EXTENT" below is an activity log extent
 * we need that many (long words/bytes) to store the bitmap
 *		     of one AL_EXTENT_SIZE chunk of storage.
 * we can store the bitmap for that many AL_EXTENTS within
 * one sector of the _on_disk_ bitmap:
 * bit	 0	  bit 37   bit 38	     bit (512*8)-1
 *	     ...|........|........|.. // ..|........|
 * sect. 0	 `296	  `304			   ^(512*8*8)-1
 *
#define BM_WORDS_PER_EXT    ( (AL_EXT_SIZE/BM_BLOCK_SIZE) / BITS_PER_LONG )
#define BM_BYTES_PER_EXT    ( (AL_EXT_SIZE/BM_BLOCK_SIZE) / 8 )  // 128
#define BM_EXT_PER_SECT	    ( 512 / BM_BYTES_PER_EXTENT )	 //   4
 */

#define BSR_MAX_SECTORS_32 (0xffffffffLU)
/* we have a certain meta data variant that has a fixed on-disk size of 128
 * MiB, of which 4k are our "superblock", and 32k are the fixed size activity
 * log, leaving this many sectors for the bitmap.
 */

// DW-1335 
#define BSR_MAX_SECTORS_FIXED_BM \
	  (((256 << 20 >> 9) - (32768 >> 9) - (4096 >> 9)) * (1LL<<(BM_EXT_SHIFT-9))) 
	  
#if !defined(CONFIG_LBDAF) && !defined(CONFIG_LBD) && BITS_PER_LONG == 32
#define BSR_MAX_SECTORS      BSR_MAX_SECTORS_32
#define BSR_MAX_SECTORS_FLEX BSR_MAX_SECTORS_32
#else
#define BSR_MAX_SECTORS      BSR_MAX_SECTORS_FIXED_BM
/* 16 TB in units of sectors */
#if BITS_PER_LONG == 32
/* adjust by one page worth of bitmap,
 * so we won't wrap around in bsr_bm_find_next_bit.
 * you should use 64bit OS for that much storage, anyways. */
#define BSR_MAX_SECTORS_FLEX BM_BIT_TO_SECT(0xffff7fff)
#else
/* we allow up to 1 PiB now on 64bit architecture with "flexible" meta data */
#ifdef _WIN
#define BSR_MAX_SECTORS_FLEX (1ULL << 51)
#else // _LIN
#define BSR_MAX_SECTORS_FLEX (1UL << 51)
#endif
/* corresponds to (1UL << 38) bits right now. */
#endif
#endif

/* Estimate max bio size as 256 * PAGE_CACHE_SIZE,
 * so for typical PAGE_CACHE_SIZE of 4k, that is (1<<20) Byte.
 * Since we may live in a mixed-platform cluster,
 * we limit us to a platform agnostic constant here for now.
 * A followup commit may allow even bigger BIO sizes,
 * once we thought that through. */
#ifdef _LIN
#define BSR_BIO_MAX_PAGES (BIO_MAX_VECS << PAGE_SHIFT)
#if BSR_MAX_BIO_SIZE > BSR_BIO_MAX_PAGES
#error Architecture not supported: BSR_MAX_BIO_SIZE > (BIO_MAX_VECS << PAGE_SHIFT)
#endif
#endif
#define BSR_MAX_SIZE_H80_PACKET (1U << 15) /* Header 80 only allows packets up to 32KiB data */
#define BSR_MAX_BIO_SIZE_P95    (1U << 17) /* Protocol 95 to 99 allows bios up to 128KiB */

/* For now, don't allow more than half of what we can "activate" in one
 * activity log transaction to be discarded in one go. We may need to rework
 * bsr_al_begin_io() to allow for even larger discard ranges */
#define BSR_MAX_BATCH_BIO_SIZE	 (AL_UPDATES_PER_TRANSACTION/2*AL_EXTENT_SIZE)
#define BSR_MAX_BBIO_SECTORS    (BSR_MAX_BATCH_BIO_SIZE >> 9)

extern struct bsr_bitmap *bsr_bm_alloc(void);
extern int  bsr_bm_resize(struct bsr_device *device, sector_t sectors, int set_new_bits);
void bsr_bm_free(struct bsr_bitmap *bitmap);
extern void bsr_bm_set_all(struct bsr_device *device);
extern void bsr_bm_clear_all(struct bsr_device *device);
/* set/clear/test only a few bits at a time */
extern ULONG_PTR bsr_bm_set_bits(struct bsr_device *, unsigned int, ULONG_PTR, ULONG_PTR);
extern ULONG_PTR bsr_bm_clear_bits(struct bsr_device *, unsigned int, ULONG_PTR, ULONG_PTR);
extern ULONG_PTR bsr_bm_count_bits(struct bsr_device *, unsigned int, ULONG_PTR, ULONG_PTR);
/* bm_set_bits variant for use while holding bsr_bm_lock,
* may process the whole bitmap in one go */
extern void bsr_bm_set_many_bits(struct bsr_peer_device *, ULONG_PTR, ULONG_PTR);
// DW-1996
extern void bsr_bm_clear_many_bits(struct bsr_device *, int, ULONG_PTR, ULONG_PTR);
extern ULONG_PTR bsr_bm_test_bit(struct bsr_peer_device *, const ULONG_PTR);

extern int  bsr_bm_read(struct bsr_device *, struct bsr_peer_device *) __must_hold(local);
extern void bsr_bm_reset_al_hints(struct bsr_device *device) __must_hold(local);
#ifdef _WIN
extern void bsr_bm_mark_range_for_writeout(struct bsr_device *, ULONG_PTR, ULONG_PTR);
#else // _LIN
extern void bsr_bm_mark_range_for_writeout(struct bsr_device *, unsigned long, unsigned long);
#endif
extern int  bsr_bm_write(struct bsr_device *, struct bsr_peer_device *) __must_hold(local);
extern int  bsr_bm_write_hinted(struct bsr_device *device) __must_hold(local);
extern int  bsr_bm_write_lazy(struct bsr_device *device, unsigned upper_idx) __must_hold(local);
extern int bsr_bm_write_all(struct bsr_device *, struct bsr_peer_device *) __must_hold(local);
extern int bsr_bm_write_copy_pages(struct bsr_device *, struct bsr_peer_device *) __must_hold(local);
extern size_t	     bsr_bm_words(struct bsr_device *device);
extern ULONG_PTR bsr_bm_bits(struct bsr_device *device);
extern sector_t      bsr_bm_capacity(struct bsr_device *device);

#define BSR_END_OF_BITMAP	UINTPTR_MAX

// DW-1979 25000000 is 100 Gbyte (1bit = 4k) 
#define RANGE_FIND_NEXT_BIT 25000000
extern ULONG_PTR bsr_bm_range_find_next_zero(struct bsr_peer_device *, ULONG_PTR, ULONG_PTR);

// BSR-835
extern void bsr_free_ov_bm(struct kref *kref);
// BSR-118
extern ULONG_PTR bsr_ov_bm_test_bit(struct bsr_peer_device *, const ULONG_PTR);
extern ULONG_PTR bsr_ov_bm_total_weight(struct bsr_peer_device *);
extern ULONG_PTR bsr_ov_bm_range_find_next(struct bsr_peer_device *, ULONG_PTR, ULONG_PTR);
extern ULONG_PTR bsr_ov_bm_find_abort_bit(struct bsr_peer_device *);
// DW-1978
extern ULONG_PTR bsr_bm_range_find_next(struct bsr_peer_device *, ULONG_PTR, ULONG_PTR);
extern ULONG_PTR bsr_bm_find_next(struct bsr_peer_device *, ULONG_PTR);
/* bm_find_next variants for use while you hold bsr_bm_lock() */
extern ULONG_PTR _bsr_bm_find_next(struct bsr_peer_device *, ULONG_PTR);
extern ULONG_PTR _bsr_bm_find_next_zero(struct bsr_peer_device *, ULONG_PTR);
extern ULONG_PTR _bsr_bm_total_weight(struct bsr_device *, int);
extern ULONG_PTR bsr_bm_total_weight(struct bsr_peer_device *);

// DW-1859
extern void check_and_clear_io_error_in_primary(struct bsr_device *);
extern void check_and_clear_io_error_in_secondary(struct bsr_peer_device *);

/* for receive_bitmap */
extern void bsr_bm_merge_lel(struct bsr_peer_device *peer_device, size_t offset,
    size_t number, ULONG_PTR *buffer);
/* for _bsr_send_bitmap */
extern void bsr_bm_get_lel(struct bsr_peer_device *peer_device, size_t offset,
    size_t number, ULONG_PTR *buffer);

extern void bsr_bm_lock(struct bsr_device *device, char *why, enum bm_flag flags);
extern void bsr_bm_unlock(struct bsr_device *device);
extern void bsr_bm_slot_lock(struct bsr_peer_device *peer_device, char *why, enum bm_flag flags);
extern void bsr_bm_slot_unlock(struct bsr_peer_device *peer_device);

#if 0
extern void bsr_bm_copy_slot(struct bsr_device *device, unsigned int from_index, unsigned int to_index);
#endif
/* bsr_main.c */

#ifdef _WIN
extern NPAGED_LOOKASIDE_LIST bsr_bm_ext_cache;		/* bitmap extents */
extern NPAGED_LOOKASIDE_LIST bsr_al_ext_cache;		/* activity log extents */
#else // _LIN
extern struct kmem_cache *bsr_request_cache;
extern struct kmem_cache *bsr_ee_cache;	/* peer requests */
extern struct kmem_cache *bsr_bm_ext_cache;	/* bitmap extents */
extern struct kmem_cache *bsr_al_ext_cache;	/* activity log extents */
#endif
extern mempool_t *bsr_request_mempool;
extern mempool_t *bsr_ee_mempool;

/* bsr's page pool, used to buffer data received from the peer,
 * or data requested by the peer.
 *
 * This does not have an emergency reserve.
 *
 * When allocating from this pool, it first takes pages from the pool.
 * Only if the pool is depleted will try to allocate from the system.
 *
 * The assumption is that pages taken from this pool will be processed,
 * and given back, "quickly", and then can be recycled, so we can avoid
 * frequent calls to alloc_page(), and still will be able to make progress even
 * under memory pressure.
 */
#ifdef _LIN
extern struct page *bsr_pp_pool;
#endif
extern spinlock_t   bsr_pp_lock;
extern int	    bsr_pp_vacant;
extern wait_queue_head_t bsr_pp_wait;

/* We also need a standard (emergency-reserve backed) page pool
 * for meta data IO (activity log, bitmap).
 * We can keep it global, as long as it is used as "N pages at a time".
 * 128 should be plenty, currently we probably can get away with as few as 1.
 */
#define BSR_MIN_POOL_PAGES	128
extern mempool_t *bsr_md_io_page_pool;

/* We also need to make sure we get a bio
 * when we need it for housekeeping purposes */
extern struct BSR_BIO_SET bsr_md_io_bio_set;

/* And a bio_set for cloning */
extern struct BSR_BIO_SET bsr_io_bio_set;

/* to allocate from that set */
#ifdef _WIN
extern struct bio *bio_alloc_bsr(gfp_t gfp_mask, ULONG Tag);
#else // _LIN
extern struct bio *bio_alloc_bsr(struct block_device *bdev, gfp_t gfp_mask, int op);
#endif

extern int conn_lowest_minor(struct bsr_connection *connection);
extern struct bsr_peer_device *create_peer_device(struct bsr_device *, struct bsr_connection *);
extern enum bsr_ret_code bsr_create_device(struct bsr_config_context *adm_ctx, unsigned int minor,
					     struct device_conf *device_conf, struct bsr_device **p_device);
extern void bsr_unregister_device(struct bsr_device *);
extern void bsr_put_device(struct bsr_device *);
extern void bsr_unregister_connection(struct bsr_connection *);
extern void bsr_put_connection(struct bsr_connection *);
void del_connect_timer(struct bsr_connection *connection);

extern struct bsr_resource *bsr_create_resource(const char *, struct res_opts *);
extern void bsr_free_resource(struct bsr_resource *resource);

extern void bsr_destroy_device(struct kref *kref);

extern int set_resource_options(struct bsr_resource *resource, struct res_opts *res_opts);
extern struct bsr_connection *bsr_create_connection(struct bsr_resource *resource,
						      struct bsr_transport_class *tc);
extern void bsr_transport_shutdown(struct bsr_connection *connection, enum bsr_tr_free_op op);
extern void bsr_destroy_connection(struct kref *kref);
extern struct bsr_resource *bsr_find_resource(const char *name);
extern void bsr_destroy_resource(struct kref *kref);
extern void conn_free_crypto(struct bsr_connection *connection);
// DW-1398
extern void dtt_put_listeners(struct bsr_transport *);

/* bsr_req */
extern void do_submit(struct work_struct *ws);
#ifdef _WIN
extern NTSTATUS __bsr_make_request(struct bsr_device *, struct bio *, ktime_t, ULONG_PTR);
#else // _LIN
extern void __bsr_make_request(struct bsr_device *, struct bio *, ktime_t, unsigned long);
#endif

#ifdef COMPAT_HAVE_SUBMIT_BIO
extern MAKE_REQUEST_TYPE bsr_submit_bio(struct bio *bio);
#else
extern MAKE_REQUEST_TYPE bsr_make_request(struct request_queue *q, struct bio *bio);
#endif
#ifdef COMPAT_HAVE_BLK_QUEUE_MERGE_BVEC
extern int bsr_merge_bvec(struct request_queue *, struct bvec_merge_data *, struct bio_vec *);
#endif
extern int is_valid_ar_handle(struct bsr_request *, sector_t);


/* bsr_nl.c */
enum suspend_scope {
	READ_AND_WRITE,
	WRITE_ONLY
};
extern void bsr_suspend_io(struct bsr_device *device, enum suspend_scope);
extern void bsr_resume_io(struct bsr_device *device);
extern char *ppsize(char *buf, size_t len, unsigned long long size);
extern sector_t bsr_new_dev_size(struct bsr_device *,
	sector_t current_size, /* need at least this much */
	sector_t user_capped_size, /* want (at most) this much */
	enum dds_flags flags) __must_hold(local);
enum determine_dev_size {
	DS_2PC_ERR = -5,
	DS_2PC_NOT_SUPPORTED = -4,
	DS_ERROR_SHRINK = -3,
	DS_ERROR_SPACE_MD = -2,
	DS_ERROR = -1,
	DS_UNCHANGED = 0,
	DS_SHRUNK = 1,
	DS_GREW = 2,
	DS_GREW_FROM_ZERO = 3,
};
extern enum determine_dev_size
bsr_determine_dev_size(struct bsr_device *, sector_t peer_current_size,
		enum dds_flags, struct resize_parms *) __must_hold(local);
extern void resync_after_online_grow(struct bsr_peer_device *);
extern void bsr_reconsider_queue_parameters(struct bsr_device *device,
			struct bsr_backing_dev *bdev, struct o_qlim *o);
extern enum bsr_state_rv bsr_set_role(struct bsr_resource *, enum bsr_role, bool, struct sk_buff *);

#ifdef _WIN
extern enum bsr_state_rv bsr_set_secondary_from_shutdown(struct bsr_resource *);
#endif
extern bool conn_try_outdate_peer(struct bsr_connection *connection);
extern void conn_try_outdate_peer_async(struct bsr_connection *connection);
extern int bsr_khelper(struct bsr_device *, struct bsr_connection *, char *);
extern int bsr_create_peer_device_default_config(struct bsr_peer_device *peer_device);

/* bsr_sender.c */
extern int bsr_sender(struct bsr_thread *thi);
extern int bsr_worker(struct bsr_thread *thi);
enum bsr_ret_code bsr_resync_after_valid(struct bsr_device *device, int o_minor);
void bsr_resync_after_changed(struct bsr_device *device);
extern bool bsr_stable_sync_source_present(struct bsr_peer_device *, enum which_state);
extern void bsr_start_resync(struct bsr_peer_device *, enum bsr_repl_state);

// DW-1314
// DW-1315
extern bool bsr_inspect_resync_side(struct bsr_peer_device *peer_device, enum bsr_repl_state side, enum which_state which, bool locked);

extern void resume_next_sg(struct bsr_device *device);
extern void suspend_other_sg(struct bsr_device *device);
extern int bsr_resync_finished(struct bsr_peer_device *, enum bsr_disk_state);
// BSR-595
extern void verify_progress(struct bsr_peer_device *peer_device,
        sector_t sector, int size, bool acked);
extern void verify_skipped_block(struct bsr_peer_device *peer_device,
        sector_t sector, int size, bool acked);
/* maybe rather bsr_main.c ? */
extern void *bsr_md_get_buffer(struct bsr_device *device, const char *intent);
extern void bsr_md_put_buffer(struct bsr_device *device);
extern int bsr_md_sync_page_io(struct bsr_device *device,
		struct bsr_backing_dev *bdev, sector_t sector, int op);
extern void bsr_ov_out_of_sync_found(struct bsr_peer_device *, sector_t, int);
extern void wait_until_done_or_force_detached(struct bsr_device *device,
		struct bsr_backing_dev *bdev, unsigned int *done);
extern void bsr_rs_controller_reset(struct bsr_peer_device *);
extern void bsr_ping_peer(struct bsr_connection *connection);
extern struct bsr_peer_device *peer_device_by_node_id(struct bsr_device *, int);
#ifdef _WIN
extern KDEFERRED_ROUTINE repost_up_to_date_fn;
#else  // _LIN
extern void repost_up_to_date_fn(BSR_TIMER_FN_ARG);
#endif 

#ifdef _LIN
// BSR-875
static inline void sub_kvmalloc_mem_usage(void * objp, size_t size)
{
	if (objp) {
		if (is_vmalloc_addr(objp))
			atomic_sub64(size, &mem_usage.vmalloc);
		else 
			atomic_sub64(ksize(objp), &mem_usage.kmalloc);
	}
}
#endif

#ifndef COMPAT_HAVE_BLK_ALLOC_DISK
static inline struct request_queue *bsr_blk_alloc_queue(void) 
{
#ifdef _WIN
	return kzalloc(sizeof(struct request_queue), 0, 'E5SB');
#else // _LIN
#if defined(COMPAT_HAVE_BLK_QUEUE_MAKE_REQUEST)
	return blk_alloc_queue(GFP_KERNEL);
#elif defined(COMPAT_BLK_ALLOC_QUEUE_HAS_2_PARAMS)
	return blk_alloc_queue(bsr_make_request, NUMA_NO_NODE);
#else
	return blk_alloc_queue(NUMA_NO_NODE);
#endif
#endif
}
#endif

static inline void ov_out_of_sync_print(struct bsr_peer_device *peer_device, bool ov_done)
{
	if (peer_device->ov_last_oos_size) {
		// BSR-52 add in the list for the report function.
		struct ov_oos_info *ov_oos = bsr_kzalloc(sizeof(struct ov_oos_info), GFP_KERNEL, '19SB');
		if(ov_oos) {
			INIT_LIST_HEAD(&ov_oos->list);
			ov_oos->ov_oos_start = peer_device->ov_last_oos_start;
			ov_oos->ov_oos_size = peer_device->ov_last_oos_size;

			list_add_tail(&ov_oos->list, &peer_device->ov_oos_info_list);
			peer_device->ov_oos_info_list_cnt++;
			if (peer_device->ov_oos_info_list_cnt >= OV_LIST_COUNT_LIMIT) {
				peer_device->ov_oos_info_list_cnt = 0;
				ov_done = true;
			}
		}
		else {
			bsr_err(52, BSR_LC_MEMORY, peer_device, "Failed to add in ov_oos report list due to memory allocation fail");
			bsr_err(5, BSR_LC_RESYNC_OV, peer_device, "Out of sync: start=%llu, size=%llu (sectors)",
				(unsigned long long)peer_device->ov_last_oos_start,
				(unsigned long long)peer_device->ov_last_oos_size);
		}
	}
	peer_device->ov_last_oos_size = 0;

	if(ov_done) {
		struct ov_oos_info *ov_oos, *tmp;
		list_for_each_entry_safe_ex(struct ov_oos_info, ov_oos, tmp, &peer_device->ov_oos_info_list, list) {
			bsr_err(6, BSR_LC_RESYNC_OV, peer_device, "Report(%d) out of sync: start=%llu, size=%llu (sectors)", peer_device->ov_oos_info_report_num,
				(unsigned long long)ov_oos->ov_oos_start,
				(unsigned long long)ov_oos->ov_oos_size);

			list_del(&ov_oos->list);
			bsr_kfree(ov_oos);
		}
		peer_device->ov_oos_info_report_num++;
	}
}

static inline void ov_skipped_print(struct bsr_peer_device *peer_device, bool ov_done)
{
    if (peer_device->ov_last_skipped_size) {
		// BSR-52 add in the list for the report function.
		struct ov_skipped_info *ov_skipped = bsr_kzalloc(sizeof(struct ov_skipped_info), GFP_KERNEL, '29SB');
		if(ov_skipped) {
			INIT_LIST_HEAD(&ov_skipped->list);
			ov_skipped->ov_skipped_start = peer_device->ov_last_skipped_start;
			ov_skipped->ov_skipped_size = peer_device->ov_last_skipped_size;

			list_add_tail(&ov_skipped->list, &peer_device->ov_skipped_info_list);
			peer_device->ov_skipped_info_list_cnt++;
			if (peer_device->ov_skipped_info_list_cnt >= OV_LIST_COUNT_LIMIT) {
				peer_device->ov_skipped_info_list_cnt = 0;
				ov_done = true;
			}
		}
		else {
			bsr_err(53, BSR_LC_MEMORY, peer_device, "Failed to add in ov_skipped report list due to memory allocation fail");
			bsr_err(8, BSR_LC_RESYNC_OV, peer_device, "Skipped verify, too busy. sector start(%llu), size(%llu)",
				(unsigned long long)peer_device->ov_last_skipped_start,
				(unsigned long long)peer_device->ov_last_skipped_size);
		}
    }
    peer_device->ov_last_skipped_size = 0;

	if(ov_done) {
		struct ov_skipped_info *ov_skipped, *tmp;
		list_for_each_entry_safe_ex(struct ov_skipped_info, ov_skipped, tmp, &peer_device->ov_skipped_info_list, list) {
			bsr_info(9, BSR_LC_RESYNC_OV, peer_device, "Report(%d) skipped verify, too busy. sectors start(%llu), size(%llu)", peer_device->ov_skipped_info_report_num,
				(unsigned long long)ov_skipped->ov_skipped_start,
				(unsigned long long)ov_skipped->ov_skipped_size);

			list_del(&ov_skipped->list);
			bsr_kfree(ov_skipped);
		}
		peer_device->ov_skipped_info_report_num++;
	}
}

extern void bsr_csum_bio(struct crypto_shash *, struct bsr_request *, void *);

extern void bsr_csum_pages(struct crypto_shash *, struct bsr_peer_request *, void *);

/* worker callbacks */
extern int w_e_end_data_req(struct bsr_work *, int);
extern int w_e_end_rsdata_req(struct bsr_work *, int);
extern int w_e_end_csum_rs_req(struct bsr_work *, int);
extern int w_e_end_ov_reply(struct bsr_work *, int);
extern int w_e_end_ov_req(struct bsr_work *, int);
extern int w_resync_timer(struct bsr_work *, int);
extern int w_send_dblock(struct bsr_work *, int);
extern int w_send_read_req(struct bsr_work *, int);
extern int w_e_reissue(struct bsr_work *, int);
extern int w_restart_disk_io(struct bsr_work *, int);
extern int w_start_resync(struct bsr_work *, int);
extern int w_send_uuids(struct bsr_work *, int);
// BSR-118
extern int w_fast_ov_get_bm(struct bsr_work *, int);

#ifdef _WIN
extern KDEFERRED_ROUTINE resync_timer_fn;
extern KDEFERRED_ROUTINE start_resync_timer_fn;
#else // _LIN
extern void resync_timer_fn(BSR_TIMER_FN_ARG);
extern void start_resync_timer_fn(BSR_TIMER_FN_ARG);
#endif

extern void bsr_endio_write_sec_final(struct bsr_peer_request *peer_req);

void __update_timing_details(
		struct bsr_thread_timing_details *tdp,
		unsigned int *cb_nr,
		void *cb,
		const char *fn, const unsigned int line);

#define update_sender_timing_details(c, cb) \
	__update_timing_details(c->s_timing_details, &c->s_cb_nr, cb, __func__ , __LINE__ )
#define update_receiver_timing_details(c, cb) \
	__update_timing_details(c->r_timing_details, &c->r_cb_nr, cb, __func__ , __LINE__ )
#define update_worker_timing_details(r, cb) \
	__update_timing_details(r->w_timing_details, &r->w_cb_nr, cb, __func__ , __LINE__ )

/* bsr_receiver.c */
struct packet_info {
	enum bsr_packet cmd;
	unsigned int size;
	int vnr;
	void *data;
};

/* packet_info->data is just a pointer into some temporary buffer
 * owned by the transport. As soon as we call into the transport for
 * any further receive operation, the data it points to is undefined.
 * The buffer may be freed/recycled/re-used already.
 * Convert and store the relevant information for any incoming data
 * in bsr_peer_request_detail.
 */

struct bsr_peer_request_details {
	uint64_t sector;	/* be64_to_cpu(p_data.sector) */
	uint64_t block_id;	/* unmodified p_data.block_id */
	uint32_t peer_seq;	/* be32_to_cpu(p_data.seq_num) */
	uint32_t dp_flags;	/* be32_to_cpu(p_data.dp_flags) */
	uint32_t length;	/* endian converted p_head*.length */
	uint32_t bi_size;	/* resulting bio size */
	/* for non-discards: bi_size = length - digest_size */
	uint32_t digest_size;
};

struct queued_twopc {
	struct bsr_work w;
	ULONG_PTR start_jif;
	struct bsr_connection *connection;
	struct twopc_reply reply;
	struct packet_info packet_info;
	struct p_twopc_request packet_data;
};

extern int bsr_issue_discard_or_zero_out(struct bsr_device *device,
		sector_t start, unsigned int nr_sectors, int flags);
extern int bsr_send_ack(struct bsr_peer_device *, enum bsr_packet,
			 struct bsr_peer_request *);
extern int bsr_send_ack_ex(struct bsr_peer_device *, enum bsr_packet,
			    sector_t sector, int blksize, u64 block_id);
extern int bsr_receiver(struct bsr_thread *thi);
extern int bsr_ack_receiver(struct bsr_thread *thi);
extern void bsr_send_ping_wf(struct work_struct *ws);
extern void bsr_send_acks_wf(struct work_struct *ws);
extern void bsr_send_peer_ack_wf(struct work_struct *ws);
// DW-1191
extern void bsr_send_out_of_sync_wf(struct work_struct *ws);
extern bool bsr_rs_c_min_rate_throttle(struct bsr_peer_device *);
extern bool bsr_rs_should_slow_down(struct bsr_peer_device *, sector_t,
				     bool throttle_if_app_is_waiting);
extern int bsr_submit_peer_request(struct bsr_device *,
				    struct bsr_peer_request *, const int,
				    const unsigned, const int);
extern void bsr_cleanup_after_failed_submit_peer_request(struct bsr_peer_request *peer_req);
extern int bsr_free_peer_reqs(struct bsr_resource *, struct list_head *, bool is_net_ee);
extern struct bsr_peer_request *bsr_alloc_peer_req(struct bsr_peer_device *, gfp_t) __must_hold(local);
extern void __bsr_free_peer_req(struct bsr_peer_request *, int);
#define bsr_free_peer_req(pr) __bsr_free_peer_req(pr, 0)
#define bsr_free_net_peer_req(pr) __bsr_free_peer_req(pr, 1)
extern void bsr_set_recv_tcq(struct bsr_device *device, int tcq_enabled);
extern void _bsr_clear_done_ee(struct bsr_device *device, struct list_head *to_be_freed);
extern int bsr_connected(struct bsr_peer_device *);
extern void apply_unacked_peer_requests(struct bsr_connection *connection);
extern struct bsr_connection *bsr_connection_by_node_id(struct bsr_resource *, int);
extern struct bsr_connection *bsr_get_connection_by_node_id(struct bsr_resource *, int);
#ifdef _WIN
extern void bsr_resync_after_unstable(struct bsr_peer_device *peer_device) __must_hold(local);
#endif
extern void queue_queued_twopc(struct bsr_resource *resource);
#ifdef _WIN
extern KDEFERRED_ROUTINE queued_twopc_timer_fn;
#else // _LIN
extern void queued_twopc_timer_fn(BSR_TIMER_FN_ARG);
#endif
extern bool bsr_have_local_disk(struct bsr_resource *resource);
extern enum bsr_state_rv bsr_support_2pc_resize(struct bsr_resource *resource);
extern enum determine_dev_size
bsr_commit_size_change(struct bsr_device *device, struct resize_parms *rs, u64 nodes_to_reach);

#ifdef _WIN // DW-1607 get the real size of the meta disk.
static __inline sector_t bsr_get_md_capacity(struct block_device *bdev)
{
	if (!bdev) {
		bsr_err(25, BSR_LC_IO, NO_OBJECT, "Failed to get meta disk capacity because meta block device is not set.");
		return 0;
	}

	PVOLUME_EXTENSION pvext = (bdev->bd_disk) ? bdev->bd_disk->pDeviceExtension : NULL;
	if (pvext && (KeGetCurrentIrql() < 2)) {
		bdev->d_size = get_targetdev_volsize(pvext);	// real size
		return bdev->d_size >> 9;
	}
	else {
		bsr_err(26, BSR_LC_IO, NO_OBJECT, "Failed to get meta disk capacity because volume extension is not set.");
		return 0;
	}
}
#endif

static __inline sector_t bsr_get_capacity(struct block_device *bdev)
{
#ifdef _WIN
	if (!bdev) {
		bsr_warn(44, BSR_LC_VOLUME, NO_OBJECT,"Failed to get capacity beacuse block device is not assigned.");
		return 0;
	}
	
	if (bdev->d_size) {
		return bdev->d_size >> 9;
	}

	// Maybe... need to recalculate volume size
	PVOLUME_EXTENSION pvext = (bdev->bd_disk) ? bdev->bd_disk->pDeviceExtension : NULL;
	if (pvext && (KeGetCurrentIrql() < 2)) {
		bdev->d_size = get_targetdev_volsize(pvext);	// real size
		return bdev->d_size >> 9;
	} 
	
	if (bdev->bd_contains) {	// not real device
		bdev = bdev->bd_contains;
		if (bdev->d_size) {
			return bdev->d_size >> 9;
		}
	}
	
	return bdev->d_size >> 9;
#else // _LIN
	/* return bdev ? get_capacity(bdev->bd_disk) : 0; */
	return bdev ? i_size_read(bdev->bd_inode) >> 9 : 0;
#endif
}

static __inline sector_t bsr_get_vdisk_capacity(struct bsr_device *device)
{
#ifdef _WIN
	return bsr_get_capacity(device->this_bdev);
#else // _LIN
	return get_capacity(device->vdisk);
#endif
}

/* sets the number of 512 byte sectors of our virtual device */
static inline void bsr_set_my_capacity(struct bsr_device *device,
					sector_t size)
{
#ifdef _WIN
	if (!device->this_bdev) {
		return;
	}

	device->this_bdev->d_size = size << 9;
#else // _LIN
#ifdef COMPAT_HAVE_SET_CAPACITY_AND_NOTIFY
	set_capacity_and_notify(device->vdisk, size);
#else
	set_capacity(device->vdisk, size);

#ifdef COMPAT_HAVE_REVALIDATE_DISK_SIZE
	revalidate_disk_size(device->vdisk, false);
#else
#ifdef COMPAT_HAVE_REVALIDATE_DISK
	revalidate_disk(device->vdisk);
#endif
#endif
#endif
#endif
}

static inline void bsr_kobject_uevent(struct bsr_device *device)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(device);
	// required refactring for debugfs
#else // _LIN
	kobject_uevent(disk_to_kobj(device->vdisk), KOBJ_CHANGE);
#endif
	/* rhel4 / sles9 and older don't have this at all,
	 * which means user space (udev) won't get events about possible changes of
	 * corresponding resource + disk names after the initial bsr minor creation.
	 */
}

/*
 * used to submit our private bio
 */
static inline void bsr_generic_make_request(struct bsr_device *device,
					     int fault_type, struct bio *bio)
{
	__release(local);

#if defined(_WIN) || defined(COMPAT_HAVE_BIO_BI_BDEV)
	if (!bio->bi_bdev) {
		bsr_err(6, BSR_LC_IO, device, "Failed to I/O request because block device is not set.");
		bsr_bio_endio(bio, -ENODEV);
		return;
	}
#endif

	if (bsr_insert_fault(device, fault_type))
		bsr_bio_endio(bio, -EIO);
#ifdef _WIN
	else {
		if (generic_make_request(bio)) {
			bio_endio(bio, -EIO);
		}
	}
#else // _LIN
	else
		generic_make_request(bio);
#endif
}

void bsr_bump_write_ordering(struct bsr_resource *resource, struct bsr_backing_dev *bdev,
			      enum write_ordering_e wo);
#ifdef _WIN
extern KDEFERRED_ROUTINE twopc_timer_fn;
extern KDEFERRED_ROUTINE connect_timer_fn;
#else // _LIN
extern void twopc_timer_fn(BSR_TIMER_FN_ARG);
extern void connect_timer_fn(BSR_TIMER_FN_ARG);

/* bsr_proc.c */
extern struct proc_dir_entry *bsr_proc;
extern const struct file_operations bsr_proc_fops;
int bsr_seq_show(struct seq_file *seq, void *v);
#endif

typedef enum { RECORD_RS_FAILED, SET_OUT_OF_SYNC, SET_IN_SYNC } update_sync_bits_mode;


/* bsr_actlog.c */
extern bool bsr_al_try_lock(struct bsr_device *device);
extern bool bsr_al_try_lock_for_transaction(struct bsr_device *device);
extern int bsr_al_begin_io_nonblock(struct bsr_device *device, struct bsr_interval *i);
extern void bsr_al_begin_io_commit(struct bsr_device *device);
extern bool bsr_al_begin_io_fastpath(struct bsr_device *device, struct bsr_interval *i);
extern int bsr_al_begin_io_for_peer(struct bsr_peer_device *peer_device, struct bsr_interval *i);
extern bool bsr_al_complete_io(struct bsr_device *device, struct bsr_interval *i);
extern void bsr_rs_complete_io(struct bsr_peer_device *, sector_t, const char *);
extern int bsr_rs_begin_io(struct bsr_peer_device *, sector_t);
extern int bsr_try_rs_begin_io(struct bsr_peer_device *, sector_t, bool);
extern void bsr_rs_cancel_all(struct bsr_peer_device *);
extern int bsr_rs_del_all(struct bsr_peer_device *);
extern void bsr_rs_failed_io(struct bsr_peer_device *, sector_t, int);
extern void bsr_advance_rs_marks(struct bsr_peer_device *, ULONG_PTR);
extern bool bsr_set_all_out_of_sync(struct bsr_device *, sector_t, int);
// DW-1191
extern unsigned long bsr_set_sync(struct bsr_device *, sector_t, int, ULONG_PTR, ULONG_PTR);

// BSR-444 add parameter locked(rcu_read_lock)
extern ULONG_PTR update_sync_bits(struct bsr_peer_device *peer_device,
	ULONG_PTR sbnr, ULONG_PTR ebnr, update_sync_bits_mode mode, bool locked);

extern ULONG_PTR __bsr_change_sync(struct bsr_peer_device *peer_device, sector_t sector, int size,
		update_sync_bits_mode mode, const char* caller);
#define bsr_set_in_sync(peer_device, sector, size) \
	__bsr_change_sync(peer_device, sector, size, SET_IN_SYNC, __FUNCTION__)
#define bsr_set_out_of_sync(peer_device, sector, size) \
	__bsr_change_sync(peer_device, sector, size, SET_OUT_OF_SYNC, __FUNCTION__)
#define bsr_rs_failed_io(peer_device, sector, size) \
	__bsr_change_sync(peer_device, sector, size, RECORD_RS_FAILED, __FUNCTION__)

extern void bsr_al_shrink(struct bsr_device *device);
extern bool bsr_sector_has_priority(struct bsr_peer_device *, sector_t);
extern int bsr_al_initialize(struct bsr_device *, void *);

// BSR-1001
extern void check_remaining_out_of_sync(struct bsr_device* device);
/* bsr_nl.c */

extern struct mutex notification_mutex;
extern atomic_t bsr_genl_seq;

extern void notify_resource_state(struct sk_buff *,
				  unsigned int,
				  struct bsr_resource *,
				  struct resource_info *,
				  enum bsr_notification_type);
extern void notify_device_state(struct sk_buff *,
				unsigned int,
				struct bsr_device *,
				struct device_info *,
				enum bsr_notification_type);
extern void notify_connection_state(struct sk_buff *,
				    unsigned int,
				    struct bsr_connection *,
				    struct connection_info *,
				    enum bsr_notification_type);
extern void notify_peer_device_state(struct sk_buff *,
				     unsigned int,
				     struct bsr_peer_device *,
				     struct peer_device_info *,
				     enum bsr_notification_type);
extern void notify_helper(enum bsr_notification_type, struct bsr_device *,
			  struct bsr_connection *, const char *, int);
extern void notify_path(struct bsr_connection *, struct bsr_path *,
			enum bsr_notification_type);

// BSR-859
extern void notify_node_info(struct sk_buff *skb, 
					 unsigned int,
					 struct bsr_resource *resource,
					 struct bsr_connection *connection, 
					 char * node_name,
					 __u8 cmd,
					 enum bsr_notification_type type);

// BSR-676
#define BSR_GI_NOTI_UUID 0x00
#define BSR_GI_NOTI_DEVICE_FLAG 0x01
#define BSR_GI_NOTI_PEER_DEVICE_FLAG 0x02

extern void notify_gi_uuid_state(struct sk_buff*, unsigned int, struct bsr_peer_device *, enum bsr_notification_type);
extern void notify_gi_device_mdf_flag_state(struct sk_buff*, unsigned int, struct bsr_device *, enum bsr_notification_type);
extern void notify_gi_peer_device_mdf_flag_state(struct sk_buff*, unsigned int, struct bsr_peer_device*, enum bsr_notification_type);

// BSR-734
extern void notify_split_brain(struct bsr_connection *, char * recover_type);

extern sector_t bsr_local_max_size(struct bsr_device *device) __must_hold(local);
extern int bsr_open_ro_count(struct bsr_resource *resource);

/*
 * inline helper functions
 *************************/

static inline int bsr_peer_req_has_active_page(struct bsr_peer_request *peer_req)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(peer_req);
	// not support.
#else	
	struct page *page = peer_req->page_chain.head;
	page_chain_for_each(page) {
		if (page_count(page) > 1)
			return 1;
	}
#endif
	return 0;
}

/*
 * When a device has a replication state above L_OFF, it must be
 * connected.  Otherwise, we report the connection state, which has values up
 * to C_CONNECTED == L_OFF.
 */
static inline int combined_conn_state(struct bsr_peer_device *peer_device, enum which_state which)
{
	enum bsr_repl_state repl_state = peer_device->repl_state[which];

	if (repl_state > L_OFF)
		return repl_state;
	else
		return peer_device->connection->cstate[which];
}

enum bsr_force_detach_flags {
	BSR_READ_ERROR,
	BSR_WRITE_ERROR,
	BSR_META_IO_ERROR,
	BSR_FORCE_DETACH,
};

#define __bsr_chk_io_error(m,f) __bsr_chk_io_error_(m,f, __func__)
static inline void __bsr_chk_io_error_(struct bsr_device *device,
					enum bsr_force_detach_flags df,
					const char *where)
{
	enum bsr_io_error_p ep;
	int max_passthrough_cnt = 0;
	bool do_detach = false;

	rcu_read_lock();
	ep = rcu_dereference(device->ldev->disk_conf)->on_io_error;
	max_passthrough_cnt = rcu_dereference(device->ldev->disk_conf)->max_passthrough_count;
	rcu_read_unlock();
	switch (ep) {
	case EP_PASS_ON: /* FIXME would this be better named "Ignore"? */
		if (df == BSR_READ_ERROR ||  df == BSR_WRITE_ERROR) {
			if (bsr_ratelimit())
				bsr_err(2, BSR_LC_IO_ERROR, device, "Failed to I/O local in %s.", where);
			if (device->disk_state[NOW] > D_INCONSISTENT) {
				begin_state_change_locked(device->resource, CS_HARD);
				__change_disk_state(device, D_INCONSISTENT, __FUNCTION__);
				end_state_change_locked(device->resource, false, __FUNCTION__);
			}
			break;
		}
		/* NOTE fall through for BSR_META_IO_ERROR or BSR_FORCE_DETACH */
		/* Fall through */
	case EP_DETACH:
	case EP_CALL_HELPER:
		/* Remember whether we saw a READ or WRITE error.
		 *
		 * Recovery of the affected area for WRITE failure is covered
		 * by the activity log.
		 * READ errors may fall outside that area though. Certain READ
		 * errors can be "healed" by writing good data to the affected
		 * blocks, which triggers block re-allocation in lower layers.
		 *
		 * If we can not write the bitmap after a READ error,
		 * we may need to trigger a full sync (see w_go_diskless()).
		 *
		 * Force-detach is not really an IO error, but rather a
		 * desperate measure to try to deal with a completely
		 * unresponsive lower level IO stack.
		 * Still it should be treated as a WRITE error.
		 *
		 * Meta IO error is always WRITE error:
		 * we read meta data only once during attach,
		 * which will fail in case of errors.
		 */
		if (df == BSR_FORCE_DETACH)
			set_bit(FORCE_DETACH, &device->flags);
		// DW-2033 Change to Failed even at Attaching
		if (device->disk_state[NOW] > D_FAILED || device->disk_state[NOW] == D_ATTACHING) {
			begin_state_change_locked(device->resource, CS_HARD);
			__change_disk_state(device, D_FAILED, __FUNCTION__);
			end_state_change_locked(device->resource, false, __FUNCTION__);
			bsr_err(3, BSR_LC_IO_ERROR, device, "Failed to I/O local in %s. Detaching...", where);
		}
		break;
	// DW-1755
	case EP_PASSTHROUGH:	
		// BSR-720 BSR-731 detach if io_error_count exceeds max_passthrough_count
		if (df == BSR_READ_ERROR ||  df == BSR_WRITE_ERROR) {
			if (max_passthrough_cnt && (atomic_read(&device->io_error_count) > max_passthrough_cnt))
				do_detach = true;
		}
		
		// DW-1814 
		// If an error occurs in the meta volume, disk consistency can not be guaranteed and replication must be stopped in any case. 
		if (df == BSR_FORCE_DETACH)
			set_bit(FORCE_DETACH, &device->flags);
		if (df == BSR_META_IO_ERROR || df == BSR_FORCE_DETACH || do_detach) {
			// DW-2033 Change to Failed even at Attaching
			if (device->disk_state[NOW] > D_FAILED || device->disk_state[NOW] == D_ATTACHING) {
				begin_state_change_locked(device->resource, CS_HARD);
				__change_disk_state(device, D_FAILED, __FUNCTION__);
				end_state_change_locked(device->resource, false, __FUNCTION__);
				if (df == BSR_META_IO_ERROR)
					bsr_err(8, BSR_LC_IO_ERROR, device, "PassThrough, Detaching due to I/O error occurred on meta-disk in %s.", where);
				else if (do_detach)
					bsr_err(11, BSR_LC_IO_ERROR, device, "PassThrough, Detaching due to I/O error occurred more than %d times. Detaching...", max_passthrough_cnt);
				else
					bsr_err(4, BSR_LC_IO_ERROR, device, "PassThrough, Force-detaching in %s", where);
			}
		}
		else {
		// DW-1814 
		// In the event of a write or read error on a clone volume, there is no action here to commit it to the failure handling mechanism.
		// When a write error occurs in the duplicate volume, P_NEG_ACK is transmitted and the OOS is recorded and synchronized.
		// When a read error occurs, P_NEG_RS_DREPLY is transmitted, and synchronization can be restarted for failed bits.
			if (atomic_read(&device->io_error_count) == 1)
				bsr_err(5, BSR_LC_IO_ERROR, device, "PassThrough, Failed to %s replication-disk", (df == BSR_READ_ERROR) ? "Read" : "Write");
		}

		break;
	}
}

/**
 * bsr_chk_io_error: Handle the on_io_error setting, should be called from all io completion handlers
 * @device:	 BSR device.
 * @error:	 Error code passed to the IO completion callback
 * @forcedetach: Force detach. I.e. the error happened while accessing the meta data
 *
 * See also bsr_main.c:after_state_ch() if (os.disk > D_FAILED && ns.disk == D_FAILED)
 */
#define bsr_chk_io_error(m,e,f) bsr_chk_io_error_(m,e,f, __func__)
static inline void bsr_chk_io_error_(struct bsr_device *device,
	int error, enum bsr_force_detach_flags forcedetach, const char *where)
{
	if (error) {
		unsigned long flags;
		spin_lock_irqsave(&device->resource->req_lock, flags);
		__bsr_chk_io_error_(device, forcedetach, where);
		spin_unlock_irqrestore(&device->resource->req_lock, flags);
	}
}


/**
 * bsr_md_first_sector() - Returns the first sector number of the meta data area
 * @bdev:	Meta data block device.
 *
 * BTW, for internal meta data, this happens to be the maximum capacity
 * we could agree upon with our peer node.
 */
static inline sector_t bsr_md_first_sector(struct bsr_backing_dev *bdev)
{
	switch (bdev->md.meta_dev_idx) {
	case BSR_MD_INDEX_INTERNAL:
	case BSR_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + bdev->md.bm_offset;
	case BSR_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset;
	}
}

/**
 * bsr_md_last_sector() - Return the last sector number of the meta data area
 * @bdev:	Meta data block device.
 */
static inline sector_t bsr_md_last_sector(struct bsr_backing_dev *bdev)
{
	switch (bdev->md.meta_dev_idx) {
	case BSR_MD_INDEX_INTERNAL:
	case BSR_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + (4096 >> 9) -1;
	case BSR_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset + bdev->md.md_size_sect -1;
	}
}

/**
 * bsr_get_max_capacity() - Returns the capacity we announce to out peer
 * @bdev:	Meta data block device.
 *
 * returns the capacity we announce to out peer.  we clip ourselves at the
 * various MAX_SECTORS, because if we don't, current implementation will
 * oops sooner or later
 */
static inline sector_t bsr_get_max_capacity(struct bsr_backing_dev *bdev)
{
	sector_t s;

	switch (bdev->md.meta_dev_idx) {
	case BSR_MD_INDEX_INTERNAL:
	case BSR_MD_INDEX_FLEX_INT:
#ifdef _WIN // DW-1469 get real size
		s = bsr_get_capacity(bdev->backing_bdev->bd_contains)
#else // _LIN
		s = bsr_get_capacity(bdev->backing_bdev)
#endif
			? min_t(sector_t, BSR_MAX_SECTORS_FLEX,
				bsr_md_first_sector(bdev))
			: 0;
		break;
	case BSR_MD_INDEX_FLEX_EXT:		
#ifdef _WIN // DW-1469
		s = min_t(sector_t, BSR_MAX_SECTORS_FLEX,
				bsr_get_capacity(bdev->backing_bdev->bd_contains));
#else // _LIN
		s = min_t(sector_t, BSR_MAX_SECTORS_FLEX,
				bsr_get_capacity(bdev->backing_bdev));
#endif
		/* clip at maximum size the meta device can support */
		s = min_t(sector_t, s,
			BM_EXT_TO_SECT(bdev->md.md_size_sect
				     - bdev->md.bm_offset));
		break;
	default:		
#ifdef _WIN // DW-1469
		s = min_t(sector_t, BSR_MAX_SECTORS,
				bsr_get_capacity(bdev->backing_bdev->bd_contains));
#else // _LIN
		s = min_t(sector_t, BSR_MAX_SECTORS,
				bsr_get_capacity(bdev->backing_bdev));
#endif
	}
	return s;
}

/**
 * bsr_md_ss() - Return the sector number of our meta data super block
 * @bdev:	Meta data block device.
 */
static inline sector_t bsr_md_ss(struct bsr_backing_dev *bdev)
{
	const int meta_dev_idx = bdev->md.meta_dev_idx;

	if (meta_dev_idx == BSR_MD_INDEX_FLEX_EXT)
		return 0;

	/* Since bsr08, internal meta data is always "flexible".
	 * position: last 4k aligned block of 4k size */
	if (meta_dev_idx == BSR_MD_INDEX_INTERNAL ||
	    meta_dev_idx == BSR_MD_INDEX_FLEX_INT)
		return (bsr_get_capacity(bdev->backing_bdev) & ~7ULL) - 8;

	/* external, some index; this is the old fixed size layout */
	// DW-1335
	return (256 << 20 >> 9) * bdev->md.meta_dev_idx;
}

void bsr_queue_work(struct bsr_work_queue *, struct bsr_work *);

static inline void
bsr_queue_work_if_unqueued(struct bsr_work_queue *q, struct bsr_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	if (list_empty_careful(&w->list))
		list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

static inline void
bsr_device_post_work(struct bsr_device *device, int work_bit)
{
	if (!test_and_set_bit(work_bit, &device->flags)) {
		struct bsr_resource *resource = device->resource;
		struct bsr_work_queue *q = &resource->work;
		if (!test_and_set_bit(DEVICE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}

static inline void
bsr_peer_device_post_work(struct bsr_peer_device *peer_device, int work_bit)
{
	if (!test_and_set_bit(work_bit, &peer_device->flags)) {
		struct bsr_resource *resource = peer_device->device->resource;
		struct bsr_work_queue *q = &resource->work;
		if (!test_and_set_bit(PEER_DEVICE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}

static inline void
bsr_post_work(struct bsr_resource *resource, int work_bit)
{
	if (!test_and_set_bit(work_bit, &resource->flags)) {
		struct bsr_work_queue *q = &resource->work;
		if (!test_and_set_bit(RESOURCE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}

// DW-1755 passthrough policy
 /* Synchronization objects used in the process of forwarding events to events2 
 * only work when irql is less than APC_LEVEL. 
 * However, because the completion routine can operate in DISPATCH_LEVEL, 
 * it must be handled through the work thread.*/

#define bsr_queue_notify_io_error_cleared(device) \
	bsr_queue_notify_io_error(device, 0, 0, 0, 0, 0, true)

#define bsr_queue_notify_io_error_occurred(device, disk_type, io_type, error_code, sector, size) \
	bsr_queue_notify_io_error(device, disk_type, io_type, error_code, sector, size, false)

static inline void
bsr_queue_notify_io_error(struct bsr_device *device, unsigned char disk_type, unsigned char io_type, long error_code, sector_t sector, unsigned int size, bool is_cleared)
{
	struct bsr_io_error_work *w;
	w = bsr_kmalloc(sizeof(*w), GFP_ATOMIC, 'W1SB');
	if (w) {
		w->io_error = bsr_kmalloc(sizeof(*(w->io_error)), GFP_ATOMIC, 'W2SB');
		if (w->io_error) {
			w->device = device;
			w->w.cb = w_notify_io_error;
			w->io_error->error_code = error_code;
			w->io_error->sector = sector;
			w->io_error->size = size;
			w->io_error->io_type = io_type;
			w->io_error->disk_type = disk_type;
			w->io_error->is_cleared = is_cleared;
			bsr_queue_work(&device->resource->work, &w->w);
		}
		else {
			bsr_err(13, BSR_LC_MEMORY, device, "Failed to notification I/O error event due to failure to allocated %d size memory in kmalloc", sizeof(*(w->io_error)));
		}
	}
}


// BSR-676
static inline void
bsr_queue_notify_update_gi(struct bsr_device *device, struct bsr_peer_device *peer_device, int type)
{
	if (device || peer_device) {
		struct bsr_updated_gi_work *w;
		w = bsr_kmalloc(sizeof(*w), GFP_ATOMIC, 'W1DW');
		if (w) {
			w->device = device;
			w->peer_device = peer_device;
			w->type = type;
			w->w.cb = w_notify_updated_gi;
			if (!device)
				device = peer_device->device;
			bsr_queue_work(&device->resource->work, &w->w);
		}
	}
}
extern void bsr_flush_workqueue(struct bsr_resource* resource, struct bsr_work_queue *work_queue);
extern void bsr_flush_workqueue_timeout(struct bsr_resource* resource, struct bsr_work_queue *work_queue);

// BSR-793
#ifdef _WIN
#define send_sig(sig, task, n) force_sig(sig, task)
#endif

#ifdef _LIN
#ifndef COMPAT_HAVE_ALLOW_KERNEL_SIGNAL
#define allow_kernel_signal(sig) allow_signal(sig)
#endif
#endif

/* To get the ack_receiver out of the blocking network stack,
 * so it can change its sk_rcvtimeo from idle- to ping-timeout,
 * and send a ping, we need to send a signal.
 * Which signal we send is irrelevant. */
static inline void wake_ack_receiver(struct bsr_connection *connection)
{
	struct task_struct *task = connection->ack_receiver.task;
	if (task && get_t_state(&connection->ack_receiver) == RUNNING)
		send_sig(SIGXCPU, task, 1); // BSR-793 use send_sig not force_sig
}

static inline void request_ping(struct bsr_connection *connection)
{
	set_bit(SEND_PING, &connection->flags);
	wake_ack_receiver(connection);
}

extern void *__conn_prepare_command(struct bsr_connection *, int, enum bsr_stream);
extern void *conn_prepare_command(struct bsr_connection *, int, enum bsr_stream);
extern void *bsr_prepare_command(struct bsr_peer_device *, int, enum bsr_stream);
extern int __send_command(struct bsr_connection *, int, enum bsr_packet, enum bsr_stream);
extern int send_command(struct bsr_connection *, int, enum bsr_packet, enum bsr_stream);
extern int bsr_send_command(struct bsr_peer_device *, enum bsr_packet, enum bsr_stream);

extern int bsr_send_ping(struct bsr_connection *connection);
extern int bsr_send_ping_ack(struct bsr_connection *connection);
// BSR-863
extern int bsr_send_uuid_ack(struct bsr_connection *connection);
extern int conn_send_state_req(struct bsr_connection *, int vnr, enum bsr_packet, union bsr_state, union bsr_state);
extern int conn_send_twopc_request(struct bsr_connection *, int vnr, enum bsr_packet, struct p_twopc_request *);
extern int bsr_send_peer_ack(struct bsr_connection *, struct bsr_request *);

static inline void bsr_thread_stop(struct bsr_thread *thi)
{
	_bsr_thread_stop(thi, false, true);
}

static inline void bsr_thread_stop_nowait(struct bsr_thread *thi)
{
	_bsr_thread_stop(thi, false, false);
}

static inline void bsr_thread_restart_nowait(struct bsr_thread *thi)
{
	_bsr_thread_stop(thi, true, false);
}

static inline void set_ap_in_flight(struct bsr_connection *connection, unsigned int i)
{
	atomic_set64(&connection->ap_in_flight, i);
	// BSR-839
	atomic_set(&connection->ap_in_flight_cnt, i);
}
static inline void add_ap_in_flight(unsigned int size, struct bsr_connection *connection)
{
	atomic_add64(size, &connection->ap_in_flight);
	// BSR-839
	atomic_inc(&connection->ap_in_flight_cnt);
}
static inline void sub_ap_in_flight(unsigned int size, struct bsr_connection *connection)
{
	if (atomic_sub_return64(size, &connection->ap_in_flight) < 0)
		atomic_set64(&connection->ap_in_flight, 0);
	
	if (atomic_dec_return(&connection->ap_in_flight_cnt) < 0)
		atomic_set(&connection->ap_in_flight_cnt, 0);
}
static inline void set_rs_in_flight(struct bsr_connection *connection, unsigned int i)
{
	atomic_set64(&connection->rs_in_flight, i);
	// BSR-839
	atomic_set(&connection->rs_in_flight_cnt, i);
}
static inline void add_rs_in_flight(unsigned int size, struct bsr_connection *connection)
{
	atomic_add64(size, &connection->rs_in_flight);
	// BSR-839
	atomic_inc(&connection->rs_in_flight_cnt);
}
static inline void sub_rs_in_flight(unsigned int size, struct bsr_connection *connection, bool sync_done)
{
	if (atomic_sub_return64(size, &connection->rs_in_flight) < 0)
		atomic_set64(&connection->rs_in_flight, 0);
	if (sync_done && (atomic_dec_return(&connection->rs_in_flight_cnt) < 0))
		atomic_set(&connection->rs_in_flight_cnt, 0);
}


/* counts how many answer packets packets we expect from our peer,
 * for either explicit application requests,
 * or implicit barrier packets as necessary.
 * increased:
 *  w_send_barrier
 *  _req_mod(req, QUEUE_FOR_NET_WRITE or QUEUE_FOR_NET_READ);
 *    it is much easier and equally valid to count what we queue for the
 *    sender, even before it actually was queued or sent.
 *    (bsr_make_request_common; recovery path on read io-error)
 * decreased:
 *  got_BarrierAck (respective tl_clear, tl_clear_barrier)
 *  _req_mod(req, DATA_RECEIVED)
 *     [from receive_DataReply]
 *  _req_mod(req, WRITE_ACKED_BY_PEER or RECV_ACKED_BY_PEER or NEG_ACKED)
 *     [from got_BlockAck (P_WRITE_ACK, P_RECV_ACK)]
 *     FIXME
 *     for some reason it is NOT decreased in got_NegAck,
 *     but in the resulting cleanup code from report_params.
 *     we should try to remember the reason for that...
 *  _req_mod(req, SEND_FAILED or SEND_CANCELED)
 *  _req_mod(req, CONNECTION_LOST_WHILE_PENDING)
 *     [from tl_clear_barrier]
 */
static inline void inc_ap_pending(struct bsr_peer_device *peer_device)
{
	atomic_inc(&peer_device->ap_pending_cnt);
}

#define dec_ap_pending(peer_device) \
	((void)expect((peer_device), __dec_ap_pending(peer_device) >= 0))
static inline int __dec_ap_pending(struct bsr_peer_device *peer_device)
{
	int ap_pending_cnt = atomic_dec_return(&peer_device->ap_pending_cnt);
	if (ap_pending_cnt == 0)
		wake_up(&peer_device->device->misc_wait);
	return ap_pending_cnt;
}

/* counts how many resync-related answers we still expect from the peer
 *		     increase			decrease
 * L_SYNC_TARGET sends P_RS_DATA_REQUEST (and expects P_RS_DATA_REPLY)
 * L_SYNC_SOURCE sends P_RS_DATA_REPLY   (and expects P_WRITE_ACK with ID_SYNCER)
 *					   (or P_NEG_ACK with ID_SYNCER)
 */
static inline void inc_rs_pending(struct bsr_peer_device *peer_device)
{
	atomic_inc(&peer_device->rs_pending_cnt);
}

#define dec_rs_pending(peer_device) \
	((void)expect((peer_device), __dec_rs_pending(peer_device, __FUNCTION__) >= 0))
static inline int __dec_rs_pending(struct bsr_peer_device *peer_device, const char* caller)
{
	if (atomic_read(&peer_device->rs_pending_cnt) == 0)
		bsr_warn(160, BSR_LC_RESYNC_OV, peer_device, "%s => %s,There are no incomplete resync requests, but completion of the request has been set.", caller, __FUNCTION__);
	return atomic_dec_return(&peer_device->rs_pending_cnt);
}

/* counts how many answers we still need to send to the peer.
 * increased on
 *  receive_Data	unless protocol A;
 *			we need to send a P_RECV_ACK (proto B)
 *			or P_WRITE_ACK (proto C)
 *  receive_RSDataReply (recv_resync_read) we need to send a P_WRITE_ACK
 *  receive_DataRequest (receive_RSDataRequest) we need to send back P_DATA
 *  receive_Barrier_*	we need to send a P_BARRIER_ACK
 */
static inline void inc_unacked(struct bsr_peer_device *peer_device)
{
	atomic_inc(&peer_device->unacked_cnt);
}

#define dec_unacked(peer_device) \
	((void)expect(peer_device, __dec_unacked(peer_device, __FUNCTION__) >= 0))
static inline int __dec_unacked(struct bsr_peer_device *peer_device, const char* caller)
{
	if (atomic_read(&peer_device->unacked_cnt) == 0)
		bsr_warn(61, BSR_LC_IO, peer_device, "%s => %s, There is no request being processed, but the request has been completed.", caller, __FUNCTION__);
	return atomic_dec_return(&peer_device->unacked_cnt);
}

#define sub_unacked(peer_device, n) \
	((void)expect(peer_device, __sub_unacked(peer_device) >= 0))
static inline int __sub_unacked(struct bsr_peer_device *peer_device, int n)
{
	return atomic_sub_return(n, &peer_device->unacked_cnt);
}

static inline bool is_sync_target_state(struct bsr_peer_device *peer_device,
					enum which_state which)
{
	enum bsr_repl_state repl_state = peer_device->repl_state[which];

	return repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T;
}

static inline bool is_sync_target(struct bsr_peer_device *peer_device)
{
	return is_sync_target_state(peer_device, NOW) ||
				peer_device->repl_state[NOW] == L_WF_BITMAP_T;
}

static inline bool is_sync_source_state(struct bsr_peer_device *peer_device,
					enum which_state which)
{
	enum bsr_repl_state repl_state = peer_device->repl_state[which];

	return repl_state == L_SYNC_SOURCE || repl_state == L_PAUSED_SYNC_S;
}

static inline bool is_sync_state(struct bsr_peer_device *peer_device,
				 enum which_state which)
{
	return is_sync_source_state(peer_device, which) ||
		is_sync_target_state(peer_device, which);
}

static inline bool is_verify_state(struct bsr_peer_device *peer_device,
				enum which_state which)
{
	enum bsr_repl_state repl_state = peer_device->repl_state[which];
	return repl_state == L_VERIFY_S || repl_state == L_VERIFY_T;
}

static inline bool is_sync_source(struct bsr_peer_device *peer_device)
{
	return is_sync_source_state(peer_device, NOW) ||
		peer_device->repl_state[NOW] == L_WF_BITMAP_S;
}
/**
 * get_ldev() - Increase the ref count on device->ldev. Returns 0 if there is no ldev
 * @_device:		BSR device.
 * @_min_state:		Minimum device state required for success.
 *
 * You have to call put_ldev() when finished working with device->ldev.
 */
#ifdef _WIN
#define get_ldev_if_state(_device, _min_state)				\
	(_get_ldev_if_state((_device), (_min_state)) ?			\
	true : false)
#else // _LIN
#define get_ldev_if_state(_device, _min_state)				\
	(_get_ldev_if_state((_device), (_min_state)) ?			\
	 ({ __acquire(x); true; }) : false)
#endif
#define get_ldev(_device) get_ldev_if_state(_device, D_INCONSISTENT)

static inline void put_ldev(struct bsr_device *device)
{
	enum bsr_disk_state disk_state = device->disk_state[NOW];
	/* We must check the state *before* the atomic_dec becomes visible,
	 * or we have a theoretical race where someone hitting zero,
	 * while state still D_FAILED, will then see D_DISKLESS in the
	 * condition below and calling into destroy, where he must not, yet. */
	int i = atomic_dec_return(&device->local_cnt);

	/* This may be called from some endio handler,
	 * so we must not sleep here. */

	__release(local);
	D_ASSERT(device, i >= 0);
	if (i == 0) {
		if (disk_state == D_DISKLESS)
			/* even internal references gone, safe to destroy */
			bsr_device_post_work(device, DESTROY_DISK);
		if (disk_state == D_FAILED || disk_state == D_DETACHING)
			/* all application IO references gone. */
			if (!test_and_set_bit(GOING_DISKLESS, &device->flags))
				bsr_device_post_work(device, GO_DISKLESS);
		wake_up(&device->misc_wait);
	}
}

#ifdef __CHECKER__
extern int _get_ldev_if_state(struct bsr_device *device, enum bsr_disk_state mins);
#else
static inline int _get_ldev_if_state(struct bsr_device *device, enum bsr_disk_state mins)
{
	int io_allowed;

	/* never get a reference while D_DISKLESS */
	if (device->disk_state[NOW] == D_DISKLESS)
		return 0;

	atomic_inc(&device->local_cnt);
	io_allowed = (device->disk_state[NOW] >= mins);
	if (!io_allowed)
		put_ldev(device);
	return io_allowed;
}
#endif

static inline bool bsr_state_is_stable(struct bsr_device *device)
{
	struct bsr_peer_device *peer_device;
	bool stable = true;

	/* DO NOT add a default clause, we want the compiler to warn us
	 * for any newly introduced state we may have forgotten to add here */

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		switch (peer_device->repl_state[NOW]) {
		/* New io is only accepted when the peer device is unknown or there is
		 * a well-established connection. */
		case L_OFF:
		case L_ESTABLISHED:
		case L_SYNC_SOURCE:
		case L_SYNC_TARGET:
		case L_VERIFY_S:
		case L_VERIFY_T:
		case L_PAUSED_SYNC_S:
		case L_PAUSED_SYNC_T:
		case L_AHEAD:
		case L_BEHIND:
		case L_STARTING_SYNC_S:
		case L_STARTING_SYNC_T:
			break;

			/* Allow IO in BM exchange states with new protocols */
		case L_WF_BITMAP_S:
			// DW-1979 remove the DW-1121, DW-1391 issue as I/O hang can occur 
			if (peer_device->connection->agreed_pro_version < 96)
				stable = false;
			break;

			/* no new io accepted in these states */
		case L_WF_BITMAP_T:
		case L_WF_SYNC_UUID:
			stable = false;
			break;
		}
		if (!stable)
			break;
	}
	rcu_read_unlock();

	switch (device->disk_state[NOW]) {
	case D_DISKLESS:
	case D_INCONSISTENT:
	case D_OUTDATED:
	case D_CONSISTENT:
	case D_UP_TO_DATE:
	case D_FAILED:
	case D_DETACHING:
		/* disk state is stable as well. */
		break;

	/* no new io accepted during transitional states */
	case D_ATTACHING:
	case D_NEGOTIATING:
	case D_UNKNOWN:
	case D_MASK:
		stable = false;
	}

	return stable;
}

extern void bsr_queue_pending_bitmap_work(struct bsr_device *);

/* rw = READ or WRITE (0 or 1); nothing else. */
static inline void dec_ap_bio(struct bsr_device *device, int rw)
{
	int nr_requests = device->resource->res_opts.nr_requests;
	int ap_bio = atomic_dec_return(&device->ap_bio_cnt[rw]);

	D_ASSERT(device, ap_bio >= 0);

	/* Check for list_empty outside the lock is ok.  Worst case it queues
	 * nothing because someone else just now did.  During list_add, both
	 * resource->req_lock *and* a refcount on ap_bio_cnt[WRITE] are held,
	 * a list_add cannot race with this code path.
	 * Checking pending_bitmap_work.n is not correct,
	 * it has a different lifetime. */
	if (ap_bio == 0 && rw == WRITE && !list_empty(&device->pending_bitmap_work.q))
		bsr_queue_pending_bitmap_work(device);

	if (ap_bio == 0 || ap_bio == nr_requests-1)
		wake_up(&device->misc_wait);
}


static inline bool bsr_suspended(struct bsr_device *device)
{
	return resource_is_suspended(device->resource, NOW, false);
}

static inline bool may_inc_ap_bio(struct bsr_device *device)
{
	if (bsr_suspended(device))
		return false;
	if (atomic_read(&device->suspend_cnt))
		return false;

	/* to avoid potential deadlock or bitmap corruption,
	 * in various places, we only allow new application io
	 * to start during "stable" states. */

	/* no new io accepted when attaching or detaching the disk */
	if (!bsr_state_is_stable(device))
		return false;

	if (atomic_read(&device->pending_bitmap_work.n))
		return false;
	return true;
}

static inline bool inc_ap_bio_cond(struct bsr_device *device, int rw)
{
	bool rv = false;
	int nr_requests;
	// DW-1925 DW-1200 request buffer maximum size.
	int max_req_write_cnt;

	spin_lock_irq(&device->resource->req_lock);
	nr_requests = device->resource->res_opts.nr_requests;
	rv = may_inc_ap_bio(device) && (atomic_read(&device->ap_bio_cnt[rw]) < nr_requests);

	// DW-1925 postpone I/O if current request count is too big.
	max_req_write_cnt = device->resource->res_opts.max_req_write_cnt;   
	if (max_req_write_cnt < BSR_MAX_REQ_WRITE_CNT_MIN ||
		max_req_write_cnt > BSR_MAX_REQ_WRITE_CNT_MAX)	{
		bsr_err(1, BSR_LC_REQUEST, device, "Set the default(%d) value because the max_req_write_cnt(%d) setting is incorrect.", max_req_write_cnt, (int)BSR_MAX_REQ_WRITE_CNT_DEF);
		max_req_write_cnt = (int)BSR_MAX_REQ_WRITE_CNT_DEF;    // use default if value is invalid.    
	}

	// DW-1925 postpone if only one of the number or size of req exceeds the maximum
	if (atomic_read(&device->resource->req_write_cnt) > max_req_write_cnt) {
		device->resource->breqbuf_overflow_alarm = true;
	
		if (bsr_ratelimit()) {
			bsr_warn(28, BSR_LC_REPLICATION, device, "request count exceeds maximum, postponing I/O until we get enough memory. req_write_cnt(%d), max cnt(%d)",
				atomic_read(&device->resource->req_write_cnt),
				max_req_write_cnt);
		}
		rv = false;
	} 
	else {
		device->resource->breqbuf_overflow_alarm = false;
	}

	if (rv)
		atomic_inc(&device->ap_bio_cnt[rw]);
	spin_unlock_irq(&device->resource->req_lock);

	return rv;
}

static inline void inc_ap_bio(struct bsr_device *device, int rw)
{
	/* we wait here
	 *    as long as the device is suspended
	 *    until the bitmap is no longer on the fly during connection
	 *    handshake as long as we would exceed the max_buffer limit.
	 *
	 * to avoid races with the reconnect code,
	 * we need to atomic_inc within the spinlock. */

	wait_event(device->misc_wait, inc_ap_bio_cond(device, rw));
}

static inline int bsr_set_exposed_data_uuid(struct bsr_device *device, u64 val)
{
	int changed = device->exposed_data_uuid != val;
	device->exposed_data_uuid = val;
	return changed;
}

static inline u64 bsr_current_uuid(struct bsr_device *device)
{
	if (!device->ldev)
		return 0;
	return device->ldev->md.current_uuid;
}

static inline bool verify_can_do_stop_sector(struct bsr_peer_device *peer_device)
{
	return peer_device->connection->agreed_pro_version >= 97 &&
		peer_device->connection->agreed_pro_version != 100;
}

static inline u64 bsr_bitmap_uuid(struct bsr_peer_device *peer_device)
{
	struct bsr_device *device = peer_device->device;
	struct bsr_peer_md *peer_md;

	if (!device->ldev)
		return 0;

	peer_md = &device->ldev->md.peers[peer_device->node_id];
	return peer_md->bitmap_uuid;
}

static inline u64 bsr_history_uuid(struct bsr_device *device, int i)
{
	if (!device->ldev || i >= ARRAY_SIZE(device->ldev->md.history_uuids))
		return 0;

	return device->ldev->md.history_uuids[i];
}

static inline int bsr_queue_order_type(struct bsr_device *device)
{
	UNREFERENCED_PARAMETER(device);

	/* sorry, we currently have no working implementation
	 * of distributed TCQ stuff */
#ifndef QUEUE_ORDERED_NONE
#define QUEUE_ORDERED_NONE 0
#endif
	return QUEUE_ORDERED_NONE;
}

#ifdef _WIN
extern struct genl_ops * get_bsr_genl_ops(u8 cmd);
#endif

#ifdef blk_queue_plugged
static inline void bsr_blk_run_queue(struct request_queue *q)
{
	if (q && q->unplug_fn)
		q->unplug_fn(q);
}

static inline void bsr_kick_lo(struct bsr_device *device)
{
	if (get_ldev(device)) {
		bsr_blk_run_queue(bdev_get_queue(device->ldev->backing_bdev));
		put_ldev(device);
	}
}
#else
static inline void bsr_blk_run_queue(struct request_queue *q)
{
	UNREFERENCED_PARAMETER(q);
}
static inline void bsr_kick_lo(struct bsr_device *device)
{
#ifdef _WIN
	UNREFERENCED_PARAMETER(device);
#endif
}
#endif

/* resync bitmap */
/* 128MB sized 'bitmap extent' to track syncer usage */
struct bm_extent {
	int rs_left; /* number of bits set (out of sync) in this extent. */
	int rs_failed; /* number of failed resync requests in this extent. */
	ULONG_PTR flags;
	struct lc_element lce;
};

#define BME_NO_WRITES  0  /* bm_extent.flags: no more requests on this one! */
#define BME_LOCKED     1  /* bm_extent.flags: syncer active on this one. */
#define BME_PRIORITY   2  /* finish resync IO on this extent ASAP! App IO waiting! */

/* should be moved to idr.h */
/**
 * idr_for_each_entry - iterate over an idr's elements of a given type
 * @idp:     idr handle
 * @entry:   the type * to use as cursor
 * @id:      id entry's key
 */
#ifdef idr_for_each_entry
#define idr_for_each_entry_ex(type, idp, entry, id)				\
		idr_for_each_entry(idp, entry, id)
#else
#define idr_for_each_entry_ex(type, idp, entry, id)				\
	for (id = 0, entry = (type)idr_get_next((idp), &(id)); \
	     entry != NULL;						\
	     ++id, entry = (type)idr_get_next((idp), &(id))) 
#endif

#ifdef idr_for_each_entry_continue
#define idr_for_each_entry_continue_ex(type, idp, entry, id)			\
		idr_for_each_entry_continue(idp, entry, id)
#else
#define idr_for_each_entry_continue_ex(type, idp, entry, id)			\
	for (entry = (type)idr_get_next((idp), &(id));		\
	     entry;							\
	     ++id, entry = (type)idr_get_next((idp), &(id)))
#endif

static inline struct bsr_connection *first_connection(struct bsr_resource *resource)
{
	return list_first_entry_or_null(&resource->connections,
				struct bsr_connection, connections);
}

#define NODE_MASK(id) ((u64)1 << (id))

#ifdef _WIN		
#define wait_event_timeout_ex(wq, condition, timeout, res) \
	wait_event_timeout(res, wq, condition, timeout);	
#else // _LIN	
#define wait_event_timeout_ex(wq, condition, timeout, res) \
	res = wait_event_timeout(wq, condition, timeout);	
#endif

#ifdef _WIN
#define wait_event_interruptible_timeout_ex(wq, condition, timeout, res)	\
	wait_event_interruptible_timeout(res, wq, condition, timeout);	
#else // _LIN
#define wait_event_interruptible_timeout_ex(wq, condition, timeout, res)	\
	res = wait_event_interruptible_timeout(wq, condition, timeout);	
#endif

#ifdef _WIN
#define wait_event_interruptible_ex(wq, condition, res)	\
	wait_event_interruptible(res, wq, condition);	
#else // _LIN
#define wait_event_interruptible_ex(wq, condition, res)	\
	res = wait_event_interruptible(wq, condition);
#endif

// DW-1480
static __inline bool list_add_valid(struct list_head *new, struct list_head *prev)
{
	if ((new == 0 || prev == 0 || prev->next == 0) ||
		(prev->next->prev != prev) || // list_add corruption.
		(new == prev || new == prev->next) //list_add double add.
#ifdef _WIN // TODO "twopc_parent_list already added" occurs on Linux. condition verification required. 
		|| (new->next != new->prev) // new is not initialized.
#endif
		) 
		return false;

	return true;
}

// DW-1961
static inline LONGLONG timestamp(void)
{
#ifdef _WIN
	LARGE_INTEGER time_stamp = KeQueryPerformanceCounter(NULL);
	return time_stamp.QuadPart;
#else // _LIN
	LONGLONG time_stamp;
	time_stamp = ktime_to_us(ktime_get());

	return time_stamp;
#endif
}


static inline LONGLONG timestamp_elapse(const char* caller, LONGLONG begin_ts, LONGLONG end_ts)
{
	LONGLONG microsec_elapse;

	if (begin_ts > end_ts || begin_ts <= 0 || end_ts <= 0) {
		bsr_info(20, BSR_LC_ETC, NO_OBJECT, "%s, The timestamp to compare is uncertain. begin(%lld), end(%lld)", caller, begin_ts, end_ts);
		return -1;
	}

	microsec_elapse = end_ts - begin_ts;

#ifdef _WIN
	microsec_elapse *= 1000000;
	microsec_elapse /= g_frequency.QuadPart;
#endif

	return microsec_elapse;
}

// BSR-764
static inline void force_delay(int t) 
{
#ifdef _WIN
	if (KeGetCurrentIrql() < DISPATCH_LEVEL)
		msleep(t);
#else // _LIN
	msleep(t);
#endif
		
}
#ifdef _LIN
extern long bsr_control_ioctl(struct file *filp, unsigned int cmd, unsigned long pram);
// BSR-597
extern int bsr_file_rename(const char *oldname, const char *newname);
extern int bsr_file_remove(const char *filename);
#ifdef COMPAT_HAVE_DIR_CONTEXT_PARAMS
extern int printdir(struct dir_context *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
#else
extern int printdir(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type);
#endif
extern int bsr_readdir(char * dir_path, struct log_rolling_file_list * rlist);
extern long bsr_mkdir(const char *pathname, umode_t mode);
extern long read_reg_file(char *file_path, long default_val);
#endif


#ifndef COMPAT_HAVE_KTIME_COMPARE
/**
* ktime_compare - Compares two ktime_t variables for less, greater or equal
* @cmp1:	comparable1
* @cmp2:	comparable2
*
* Return: ...
*   cmp1  < cmp2: return <0
*   cmp1 == cmp2: return 0
*   cmp1  > cmp2: return >0
*/
static inline int ktime_compare(const ktime_t cmp1, const ktime_t cmp2)
{
#ifdef _WIN
	if (cmp1 < cmp2)
		return -1;
	if (cmp1 > cmp2)
		return 1;
#else // _LIN
	if (cmp1.tv64 < cmp2.tv64)
		return -1;
	if (cmp1.tv64 > cmp2.tv64)
		return 1;
#endif
	return 0;
}
#endif
#ifndef COMPAT_HAVE_KTIME_AFTER
/**
* ktime_after - Compare if a ktime_t value is bigger than another one.
* @cmp1:	comparable1
* @cmp2:	comparable2
*
* Return: true if cmp1 happened after cmp2.
*/
static inline bool ktime_after(const ktime_t cmp1, const ktime_t cmp2)
{
	return ktime_compare(cmp1, cmp2) > 0;
}
#endif
#ifndef COMPAT_HAVE_KTIME_BEFORE
/**
* ktime_before - Compare if a ktime_t value is smaller than another one.
* @cmp1:	comparable1
* @cmp2:	comparable2
*
* Return: true if cmp1 happened before cmp2.
*/
static inline bool ktime_before(const ktime_t cmp1, const ktime_t cmp2)
{
	return ktime_compare(cmp1, cmp2) < 0;
}
#endif

#ifdef _WIN
// BSR-682
static inline ktime_t ktime_get(void)
{
	ktime_t t;
	LARGE_INTEGER p_counter = KeQueryPerformanceCounter(NULL);

	t = p_counter.QuadPart;
	return t;
}

static inline s64 ktime_to_us(const ktime_t kt)
{
	return kt * 1000000 / g_frequency.QuadPart;
}

static inline s64 ktime_to_ms(const ktime_t kt)
{
	return kt * 1000 / g_frequency.QuadPart;
}

static inline ktime_t ns_to_ktime(u64 ns)
{
	return ns;
}

/* Subtract two ktime_t variables. rem = lhs -rhs: */
static inline ktime_t ktime_sub(ktime_t lhs, ktime_t rhs)
{
	ktime_t t;
	t = lhs - rhs;
	return t;
}

/* Add two ktime_t variables. res = lhs + rhs: */
static inline ktime_t ktime_add(ktime_t lhs, ktime_t rhs)
{
	ktime_t t;
	t = lhs + rhs;
	return t;
}

#endif

#define ktime_min(D, M)	\
		if (ktime_to_us(D->M.min_val) == 0) \
			D->M.min_val = D->M.last_val;	\
		else if (ktime_before(D->M.last_val, D->M.min_val))	\
			D->M.min_val = D->M.last_val
#define ktime_max(D, M)	\
		if (ktime_to_us(D->M.max_val) == 0) \
			D->M.max_val = D->M.last_val;	\
		else if (ktime_after(D->M.last_val, D->M.max_val))	\
			D->M.max_val = D->M.last_val

#define _ktime_aggregate(D, M) \
	D->M.total_val = ktime_add(D->M.total_val, D->M.last_val);	\
	ktime_min(D, M);	\
	ktime_max(D, M);	\

#define ktime_aggregate_delta(D, ST, M) \
	D->M.last_val = ktime_sub(ktime_get(), ST);	\
	_ktime_aggregate(D, M)

#define ktime_aggregate(D, R, M) \
	D->M.last_val = ktime_after(R->M, R->start_kt) ? ktime_sub(R->M, R->start_kt) : ns_to_ktime(0); \
	_ktime_aggregate(D, M)

#define ktime_aggregate_st(D, ST, ED, M) \
	D->M.last_val = ktime_after(ED, ST) ? ktime_sub(ED, ST) : ns_to_ktime(0); \
	_ktime_aggregate(D, M)

#define ktime_aggregate_pd(P, N, R, M) 	\
	P->M.last_val = ktime_after(R->M[N], R->start_kt) ? ktime_sub(R->M[N], R->start_kt) : ns_to_ktime(0);	\
	_ktime_aggregate(P, M)

#define ktime_get_accounting(V) V = ktime_get()
#define ktime_get_accounting_assign(V, T) V = T
#define ktime_var_for_accounting(V) ktime_t V = ktime_get()

#endif
