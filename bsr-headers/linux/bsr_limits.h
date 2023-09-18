/*
  bsr_limits.h
  This file is part of BSR by Man Technology inc.
*/

/*
 * Our current limitations.
 * Some of them are hard limits,
 * some of them are arbitrary range limits, that make it easier to provide
 * feedback about nonsense settings for certain configurable values.
 */

#ifndef BSR_LIMITS_H
#define BSR_LIMITS_H 1

#define DEBUG_RANGE_CHECK 0

#define BSR_MINOR_COUNT_MIN 1
#define BSR_MINOR_COUNT_MAX 255
#define BSR_MINOR_COUNT_DEF 32
#define BSR_MINOR_COUNT_SCALE '1'

#define BSR_VOLUME_MAX 65535

#define BSR_DIALOG_REFRESH_MIN 0
#define BSR_DIALOG_REFRESH_MAX 600
#define BSR_DIALOG_REFRESH_SCALE '1'

/* valid port number */
#define BSR_PORT_MIN 1
#define BSR_PORT_MAX 0xffff
#define BSR_PORT_SCALE '1'

/* startup { */
  /* if you want more than 3.4 days, disable */
#define BSR_WFC_TIMEOUT_MIN 0
#define BSR_WFC_TIMEOUT_MAX 300000
#define BSR_WFC_TIMEOUT_DEF 0
#define BSR_WFC_TIMEOUT_SCALE '1'

#define BSR_DEGR_WFC_TIMEOUT_MIN 0
#define BSR_DEGR_WFC_TIMEOUT_MAX 300000
#define BSR_DEGR_WFC_TIMEOUT_DEF 0
#define BSR_DEGR_WFC_TIMEOUT_SCALE '1'

#define BSR_OUTDATED_WFC_TIMEOUT_MIN 0
#define BSR_OUTDATED_WFC_TIMEOUT_MAX 300000
#define BSR_OUTDATED_WFC_TIMEOUT_DEF 0
#define BSR_OUTDATED_WFC_TIMEOUT_SCALE '1'
/* }*/

/* net { */
  /* timeout, unit centi seconds
   * more than one minute timeout is not useful */
#define BSR_TIMEOUT_MIN 1
#define BSR_TIMEOUT_MAX 600
#ifdef _WIN
// TODO _WIN_SEND_BUF
// DW-1524 fix infinite send retry on low-bandwith
#define BSR_TIMEOUT_DEF (50)     /* 5 seconds */
#else // _LIN
#define BSR_TIMEOUT_DEF 60       /* 6 seconds */
#endif
#define BSR_TIMEOUT_SCALE '1'

 /* If backing disk takes longer than disk_timeout, mark the disk as failed */
#define BSR_DISK_TIMEOUT_MIN 0    /* 0 = disabled */
#define BSR_DISK_TIMEOUT_MAX 6000 /* 10 Minutes */
#define BSR_DISK_TIMEOUT_DEF 0    /* disabled */
#define BSR_DISK_TIMEOUT_SCALE '1'

  /* active connection retries when C_CONNECTING */
#define BSR_CONNECT_INT_MIN 1
#define BSR_CONNECT_INT_MAX 120
// DW-915
#define BSR_CONNECT_INT_DEF 3   /* seconds */
#define BSR_CONNECT_INT_SCALE '1'

  /* keep-alive probes when idle */
#define BSR_PING_INT_MIN 1
#define BSR_PING_INT_MAX 120
#define BSR_PING_INT_DEF 3
#define BSR_PING_INT_SCALE '1'

 /* timeout for the ping packets.*/
#define BSR_PING_TIMEO_MIN  1
#define BSR_PING_TIMEO_MAX  300
// DW-763
#define BSR_PING_TIMEO_DEF  30 /* 1/10 seconds */
#define BSR_PING_TIMEO_SCALE '1'

// BSR-838 
#define BSR_RATIO_LENGTH_MIN 3
#define BSR_RATIO_LENGTH_MAX 12

#define BSR_RATIO_MAX 10000
#define BSR_RATIO_MIN 1
#define BSR_RATIO_DEF 0

  /* max number of write requests between write barriers */
#define BSR_MAX_EPOCH_SIZE_MIN 1
#define BSR_MAX_EPOCH_SIZE_MAX 20000
// DW-1695 Increase a max-epoch-size's default value by increasing the max-buffers'.
#define BSR_MAX_EPOCH_SIZE_DEF 16000
#define BSR_MAX_EPOCH_SIZE_SCALE '1'


#if defined(_WIN64) || defined(_LIN)
// DW-1422 set limit send buffer max size to be within 32-bit variable, since config treats it as 32-bit var also.
// to have this over 32-bit, re-define this as '((unsigned long long)64 << 30) and modify all arguments(include read data from config) to 64-bit var. 
#define BSR_SNDBUF_SIZE_MAX  (0xFFFFFFFFFF)
// DW-1436 sndbuf-size default value is set to 0, minimum value is set to 10M when used 
#define BSR_SNDBUF_SIZE_DEF	0 
#define BSR_SNDBUF_SIZE_MIN  (1024*1024*10)
#else // _WIN32
#define BSR_SNDBUF_SIZE_MAX  (1024*1024*1024*2LLU)
#define BSR_SNDBUF_SIZE_DEF  0
/* I don't think that a tcp send buffer of more than 10M is useful */
#define BSR_SNDBUF_SIZE_MIN   (1024*1024*10)
#endif

// BSR-1116
#define BSR_ACCELBUF_SIZE_MAX  (0xFFFFFFFFFF)
#define BSR_ACCELBUF_SIZE_DEF	0 
#define BSR_ACCELBUF_SIZE_MIN  (1024*1024*10)

#define BSR_ACCELBUF_SIZE_SCALE '1'

#define MAX_ONETIME_SEND_BUF	(1024*1024*10) // 10MB

#define BSR_SNDBUF_SIZE_SCALE '1'

#define BSR_RCVBUF_SIZE_MIN  0
#define BSR_RCVBUF_SIZE_MAX  (10<<20)
#define BSR_RCVBUF_SIZE_DEF  0
#define BSR_RCVBUF_SIZE_SCALE '1'

  /* @4k PageSize -> 128kB - 512MB */
#define BSR_MAX_BUFFERS_MIN  32
#define BSR_MAX_BUFFERS_MAX  131072
// DW-1695 Takes the value of max-buffers sufficiently.
#define BSR_MAX_BUFFERS_DEF  16000
#define BSR_MAX_BUFFERS_SCALE '1'

  /* @4k PageSize -> 4kB - 512MB */
#define BSR_UNPLUG_WATERMARK_MIN  1
#define BSR_UNPLUG_WATERMARK_MAX  131072
#define BSR_UNPLUG_WATERMARK_DEF (BSR_MAX_BUFFERS_DEF/16)
#define BSR_UNPLUG_WATERMARK_SCALE '1'

  /* 0 is disabled.
   * 200 should be more than enough even for very short timeouts */
#define BSR_KO_COUNT_MIN  0
#define BSR_KO_COUNT_MAX  200
// DW-988 adjust default ko_count value, because connection timeout is so long for somecase. 
#define BSR_KO_COUNT_DEF  5 // DW-1208 3 -> 5 
#define BSR_KO_COUNT_SCALE '1'
/* } */

/* syncer { */
  /* FIXME allow rate to be zero? */
#define BSR_RESYNC_RATE_MIN 1
/* channel bonding 10 GbE, or other hardware */
#define BSR_RESYNC_RATE_MAX (4 << 20)

#define BSR_RESYNC_RATE_DEF 250
#define BSR_RESYNC_RATE_SCALE 'k'  /* kilobytes */

  /* less than 67 would hit performance unnecessarily. */
#define BSR_AL_EXTENTS_MIN  67
  /* we use u16 as "slot number", (u16)~0 is "FREE".
   * If you use >= 292 kB on-disk ring buffer,
   * this is the maximum you can use: */
#define BSR_AL_EXTENTS_MAX  0xfffe
// DW-1513
#define BSR_AL_EXTENTS_DEF  6001

#define BSR_AL_EXTENTS_SCALE '1'

#define BSR_MINOR_NUMBER_MIN  -1
#define BSR_MINOR_NUMBER_MAX  ((1 << 20) - 1)
#define BSR_MINOR_NUMBER_DEF  -1
#define BSR_MINOR_NUMBER_SCALE '1'

/* } */

/* bsrsetup XY resize -d Z
 * you are free to reduce the device size to nothing, if you want to.
 * the upper limit with 64bit kernel, enough ram and flexible meta data
 * is 1 PiB, currently. */
/* BSR_MAX_SECTORS */
#define BSR_DISK_SIZE_MIN  0
#define BSR_DISK_SIZE_MAX  (1 * (2LLU << 40))
#define BSR_DISK_SIZE_DEF  0 /* = disabled = no user size... */
#define BSR_DISK_SIZE_SCALE 's'  /* sectors */

// DW-1755
#define BSR_ON_IO_ERROR_DEF EP_PASSTHROUGH 
#define BSR_FENCING_DEF FP_DONT_CARE
#define BSR_AFTER_SB_0P_DEF ASB_DISCONNECT
#define BSR_AFTER_SB_1P_DEF ASB_DISCONNECT
#define BSR_AFTER_SB_2P_DEF ASB_DISCONNECT
#define BSR_RR_CONFLICT_DEF ASB_DISCONNECT
#define BSR_ON_NO_DATA_DEF OND_IO_ERROR
#define BSR_ON_CONGESTION_DEF OC_BLOCK
#define BSR_READ_BALANCING_DEF RB_PREFER_LOCAL
#define BSR_ON_REQ_WRITE_CONGESTION_DEF ORWC_DISCONNECT	// DW-1925

// BSR-720
#define BSR_MAX_PASSTHROUGH_COUNT_MIN 0 // disable
#define BSR_MAX_PASSTHROUGH_COUNT_MAX 100000
#ifdef _WIN
#define BSR_MAX_PASSTHROUGH_COUNT_DEF 0
#else // _LIN
#define BSR_MAX_PASSTHROUGH_COUNT_DEF 100
#endif
#define BSR_MAX_PASSTHROUGH_COUNT_SCALE '1'

#define BSR_MAX_BIO_BVECS_MIN 0
#define BSR_MAX_BIO_BVECS_MAX 128
#define BSR_MAX_BIO_BVECS_DEF 0
#define BSR_MAX_BIO_BVECS_SCALE '1'

#define BSR_C_PLAN_AHEAD_MIN  0
#define BSR_C_PLAN_AHEAD_MAX  300

#define BSR_C_PLAN_AHEAD_DEF  20
#define BSR_C_PLAN_AHEAD_SCALE '1'

#define BSR_C_DELAY_TARGET_MIN 1
#define BSR_C_DELAY_TARGET_MAX 100
#define BSR_C_DELAY_TARGET_DEF 10
#define BSR_C_DELAY_TARGET_SCALE '1'

#define BSR_C_FILL_TARGET_MIN 0
#define BSR_C_FILL_TARGET_MAX (1<<20) /* 500MByte in sec */
#define BSR_C_FILL_TARGET_DEF 100 /* Try to place 50KiB in socket send buffer during resync */
#define BSR_C_FILL_TARGET_SCALE 's'  /* sectors */

#define BSR_C_MAX_RATE_MIN     250
#define BSR_C_MAX_RATE_MAX     (4 << 20)
#define BSR_C_MAX_RATE_DEF     102400
#define BSR_C_MAX_RATE_SCALE	'k'  /* kilobytes */

#define BSR_C_MIN_RATE_MIN     0
#define BSR_C_MIN_RATE_MAX     (4 << 20)
#define BSR_C_MIN_RATE_DEF     250
#define BSR_C_MIN_RATE_SCALE	'k'  /* kilobytes */

// BSR-587
#define BSR_OV_REQ_NUM_MIN     1
#define BSR_OV_REQ_NUM_MAX     ((BSR_MAX_BIO_SIZE) >> 12)
#define BSR_OV_REQ_NUM_DEF     10
#define BSR_OV_REQ_NUM_SCALE	'1'  /* blocks */

#define BSR_OV_REQ_INTERVAL_MIN     1
#define BSR_OV_REQ_INTERVAL_MAX     5000
#define BSR_OV_REQ_INTERVAL_DEF     100
#define BSR_OV_REQ_INTERVAL_SCALE	'1'  /* milliseconds */

#define BSR_CONG_FILL_MIN	0
//#define BSR_CONG_FILL_MAX	(10<<21) /* 10GByte in sectors */
#define BSR_CONG_FILL_MAX 	(0xFFFFFFFFFF)
#define BSR_CONG_FILL_DEF	0
//#define BSR_CONG_FILL_SCALE	's'  /* sectors */
#define BSR_CONG_FILL_SCALE	'1'

#define BSR_CONG_EXTENTS_MIN	BSR_AL_EXTENTS_MIN
#define BSR_CONG_EXTENTS_MAX	BSR_AL_EXTENTS_MAX
#define BSR_CONG_EXTENTS_DEF	BSR_AL_EXTENTS_DEF
#define BSR_CONG_EXTENTS_SCALE BSR_AL_EXTENTS_SCALE

#define BSR_PROTOCOL_DEF BSR_PROT_C

#define BSR_DISK_BARRIER_DEF	0
#define BSR_DISK_FLUSHES_DEF	0		// DW-1967
#define BSR_DISK_DRAIN_DEF	1
#define BSR_DISK_DISKLESS_DEF    0
#define BSR_MD_FLUSHES_DEF	1
// DW-1652 change the default value of tcp-cork to no
#define BSR_TCP_CORK_DEF	0
#define BSR_AL_UPDATES_DEF     1
/* We used to ignore the discard_zeroes_data setting.
 * To not change established (and expected) behaviour,
 * by default assume that, for discard_zeroes_data=0,
 * we can make that an effective discard_zeroes_data=1,
 * if we only explicitly zero-out unaligned partial chunks. */
#define BSR_DISCARD_ZEROES_IF_ALIGNED_DEF 1

/* Some backends pretend to support WRITE SAME,
* but fail such requests when they are actually submitted.
* This is to tell BSR to not even try. */
 
// BSR-985 set the default value to disable write same 
#define BSR_DISABLE_WRITE_SAME_DEF 1

#define BSR_ALLOW_TWO_PRIMARIES_DEF	0
#define BSR_ALWAYS_ASBP_DEF	0
#define BSR_USE_RLE_DEF	1
#define BSR_CSUMS_AFTER_CRASH_ONLY_DEF 0
#define BSR_AUTO_PROMOTE_DEF	0 // BSR-465 auto-promote disable

// DW-1249 auto-start by svc
#define BSR_SVC_AUTO_UP_DEF 1
// BSR-593 auto-down by svc
#define BSR_SVC_AUTO_DOWN_DEF 1

#define BSR_NR_REQUESTS_MIN	4
// DW-836 
#define BSR_NR_REQUESTS_DEF	1000
#define BSR_NR_REQUESTS_MAX	INT32_MAX
#define BSR_NR_REQUESTS_SCALE	'1'

#define BSR_MAX_BIO_SIZE_DEF	BSR_MAX_BIO_SIZE
#define BSR_MAX_BIO_SIZE_MIN	(1 << 9)
#define BSR_MAX_BIO_SIZE_MAX	BSR_MAX_BIO_SIZE
#define BSR_MAX_BIO_SIZE_SCALE '1'

// DW-1200 DW-1539 DW-1925 request buffer maximum size, 10MB ~ 10GB, default : 100MB
#define BSR_MAX_REQ_WRITE_CNT_MIN        10000     
#define BSR_MAX_REQ_WRITE_CNT_DEF        100000
#define BSR_MAX_REQ_WRITE_CNT_MAX        1000000
#define BSR_MAX_REQ_WRITE_CNT_SCALE        '1'

#define BSR_MAX_REQ_WRITE_MB_MIN        10
#define BSR_MAX_REQ_WRITE_MB_DEF        100
#define BSR_MAX_REQ_WRITE_MB_MAX        10240
#define BSR_MAX_REQ_WRITE_MB_SCALE        '1'

// BSR-839 implement congestion-highwater
#define BSR_CONG_HIGHWATER_MIN	0
#define BSR_CONG_HIGHWATER_MAX	BSR_MAX_REQ_WRITE_CNT_MAX
#define BSR_CONG_HIGHWATER_DEF	20000
#define BSR_CONG_HIGHWATER_SCALE '1'


#define BSR_NODE_ID_DEF		0
#define BSR_NODE_ID_MIN		0
#ifndef BSR_NODE_ID_MAX /* Is also defined in bsr.h */
#define BSR_NODE_ID_MAX		BSR_PEERS_MAX
#endif
#define BSR_NODE_ID_SCALE		'1'

#define BSR_PEER_ACK_WINDOW_DEF	4096   /* 2 MiByte */
#define BSR_PEER_ACK_WINDOW_MIN	2048   /* 1 MiByte */
#define BSR_PEER_ACK_WINDOW_MAX	204800 /* 100 MiByte */
#define BSR_PEER_ACK_WINDOW_SCALE 's' /* sectors*/

#define BSR_PEER_ACK_DELAY_DEF	100    /* 100ms */
#define BSR_PEER_ACK_DELAY_MIN 1
#define BSR_PEER_ACK_DELAY_MAX 10000  /* 10 seconds */
#define BSR_PEER_ACK_DELAY_SCALE '1' /* milliseconds */

/* Two-phase commit timeout (1/10 seconds). */
#define BSR_TWOPC_TIMEOUT_MIN	50
#define BSR_TWOPC_TIMEOUT_MAX	600
// DW-1204 adjust 2pc timout default value
#define BSR_TWOPC_TIMEOUT_DEF	50
#define BSR_TWOPC_TIMEOUT_SCALE '1'

#define BSR_TWOPC_RETRY_TIMEOUT_MIN 1
#define BSR_TWOPC_RETRY_TIMEOUT_MAX 50
#define BSR_TWOPC_RETRY_TIMEOUT_DEF 1
#define BSR_TWOPC_RETRY_TIMEOUT_SCALE '1'

#define BSR_SYNC_FROM_NID_DEF -1
#define BSR_SYNC_FROM_NID_MIN -1
#define BSR_SYNC_FROM_NID_MAX BSR_PEERS_MAX
#define BSR_SYNC_FROM_NID_SCALE '1'

#define BSR_AL_STRIPES_MIN     1
#define BSR_AL_STRIPES_MAX     1024
#define BSR_AL_STRIPES_DEF     1
#define BSR_AL_STRIPES_SCALE   '1'

#define BSR_AL_STRIPE_SIZE_MIN   4
#define BSR_AL_STRIPE_SIZE_MAX   16777216
#define BSR_AL_STRIPE_SIZE_DEF   32
#define BSR_AL_STRIPE_SIZE_SCALE 'k' /* kilobytes */

#define BSR_SOCKET_CHECK_TIMEO_MIN 1
#define BSR_SOCKET_CHECK_TIMEO_MAX BSR_PING_TIMEO_MAX
#define BSR_SOCKET_CHECK_TIMEO_DEF 5
#define BSR_SOCKET_CHECK_TIMEO_SCALE '1'

/* Auto promote timeout (1/10 seconds). */
#define BSR_AUTO_PROMOTE_TIMEOUT_MIN 0
#define BSR_AUTO_PROMOTE_TIMEOUT_MAX 600
#define BSR_AUTO_PROMOTE_TIMEOUT_DEF 20
#define BSR_AUTO_PROMOTE_TIMEOUT_SCALE '1'

#define BSR_RS_DISCARD_GRANULARITY_MIN 0
#define BSR_RS_DISCARD_GRANULARITY_MAX (1<<20)  /* 1MiByte */
#define BSR_RS_DISCARD_GRANULARITY_DEF 0     /* disabled by default */
#define BSR_RS_DISCARD_GRANULARITY_SCALE '1' /* bytes */

#define BSR_QUORUM_MIN 0
#define BSR_QUORUM_MAX QOU_ALL /* Note: user visible min/max different */
#define BSR_QUORUM_DEF QOU_OFF /* kernel min/max includes symbolic values */
#define BSR_QUORUM_SCALE '1' /* nodes */

/* By default freeze IO, if set error all IOs as quick as possible */
#define BSR_ON_NO_QUORUM_DEF ONQ_SUSPEND_IO

#define AL_WAIT_TIMEOUT			10 * HZ // DW-1513 // DW-1761
#define EE_WAIT_TIMEOUT			10 * HZ // BSR-846

#endif
