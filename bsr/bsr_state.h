#ifndef BSR_STATE_H
#define BSR_STATE_H

#include "../bsr-headers/bsr_protocol.h"

struct bsr_resource;
struct bsr_device;
struct bsr_connection;
struct bsr_peer_device;
struct bsr_work;

/**
 * DOC: BSR State macros
 *
 * These macros are used to express state changes in easily readable form.
 */
#define role_MASK R_MASK
#define peer_MASK R_MASK
#define disk_MASK D_MASK
#define pdsk_MASK D_MASK
#define conn_MASK C_MASK
#define susp_MASK 1
#define user_isp_MASK 1
#define aftr_isp_MASK 1
#define susp_nod_MASK 1
#define susp_fen_MASK 1

enum chg_state_flags {
	CS_HARD          = 1 << 0, /* Forced state change, such as a connection loss */
	CS_VERBOSE       = 1 << 1,
	CS_WAIT_COMPLETE = 1 << 2,
	CS_SERIALIZE     = 1 << 3,
	CS_ALREADY_SERIALIZED = 1 << 4, /* resource->state_sem already taken */
	CS_LOCAL_ONLY    = 1 << 5, /* Do not consider a device pair wide state change */
	CS_PREPARE	 = 1 << 6,
	CS_PREPARED	 = 1 << 7,
	CS_ABORT	 = 1 << 8,
	CS_TWOPC	 = 1 << 9,
	CS_IGN_OUTD_FAIL = 1 << 10,
	CS_DONT_RETRY    = 1 << 11, /* Disable internal retry. Caller has a retry loop */
};

extern void bsr_resume_al(struct bsr_device *device);

enum bsr_disk_state conn_highest_disk(struct bsr_connection *connection);
enum bsr_disk_state conn_lowest_disk(struct bsr_connection *connection);
enum bsr_disk_state conn_highest_pdsk(struct bsr_connection *connection);

extern void state_change_lock(struct bsr_resource *, unsigned long *, enum chg_state_flags);
extern void state_change_unlock(struct bsr_resource *, unsigned long *);

extern void begin_state_change(struct bsr_resource *, unsigned long *, enum chg_state_flags);
extern enum bsr_state_rv end_state_change(struct bsr_resource *, unsigned long *, const char*);
extern void abort_state_change(struct bsr_resource *, unsigned long *, const char*);
extern void abort_state_change_locked(struct bsr_resource *resource, bool locked, const char* caller);

extern void begin_state_change_locked(struct bsr_resource *, enum chg_state_flags);
extern enum bsr_state_rv end_state_change_locked(struct bsr_resource *, bool locked, const char* caller);

extern void abort_prepared_state_change(struct bsr_resource *);
extern void clear_remote_state_change(struct bsr_resource *resource);
// DW-1894
extern void clear_remote_state_change_without_lock(struct bsr_resource *resource);

// DW-1073
// DW-1257
void twopc_end_nested(struct bsr_resource *resource, enum bsr_packet cmd, bool as_work);


enum which_state;
extern union bsr_state bsr_get_device_state(struct bsr_device *, enum which_state);
extern union bsr_state bsr_get_peer_device_state(struct bsr_peer_device *, enum which_state);
extern union bsr_state bsr_get_connection_state(struct bsr_connection *, enum which_state);

// DW-1605 try change_state again until timeout.
#ifdef _WIN
#define stable_state_change(rv, resource, change_state) do{				\
		int err = 0;							\
		wait_event_interruptible_timeout_ex((resource)->state_wait,		\
			(rv = (change_state)) != SS_IN_TRANSIENT_STATE, HZ, err);	\
		if (err == -ETIMEDOUT)				\
			rv = SS_TIMEOUT;				\
		else if (err == -BSR_SIGKILL)		\
			rv = SS_INTERRUPTED;			\
	}while(false)
#else // _LIN
#define stable_state_change(rv, resource, change_state) ({				\
		int err;							\
		wait_event_interruptible_timeout_ex((resource)->state_wait,		\
			(rv = (change_state)) != SS_IN_TRANSIENT_STATE, HZ, err);	\
		if (err == 0)						\
			rv = SS_TIMEOUT;				\
		else if (err < 0)					\
			rv = SS_UNKNOWN_ERROR;			\
	})
#endif

extern int nested_twopc_work(struct bsr_work *work, int cancel);
extern enum bsr_state_rv nested_twopc_request(struct bsr_resource *, int, enum bsr_packet, struct p_twopc_request *);
extern bool cluster_wide_reply_ready(struct bsr_resource *);

extern enum bsr_state_rv change_role(struct bsr_resource *, enum bsr_role, enum chg_state_flags, bool, const char **);
extern void __change_io_susp_user(struct bsr_resource *, bool);
extern enum bsr_state_rv change_io_susp_user(struct bsr_resource *, bool, enum chg_state_flags);
extern void __change_io_susp_no_data(struct bsr_resource *, bool);
extern void __change_io_susp_fencing(struct bsr_connection *, bool);
extern void __change_io_susp_quorum(struct bsr_device *, bool);

extern void __change_disk_states(struct bsr_resource *, enum bsr_disk_state);
extern enum bsr_state_rv change_disk_state(struct bsr_device *, enum bsr_disk_state, enum chg_state_flags, const char **);

extern void __change_cstate(struct bsr_connection *, enum bsr_conn_state);
// BSR-1190 
extern enum bsr_state_rv change_cstate_es(struct bsr_connection *, enum bsr_conn_state, enum chg_state_flags, const char **, bool, const char *);


#define change_cstate_ex(connection, cstate, flags) \
	change_cstate(connection, cstate, flags, false, __FUNCTION__)

// BSR-1190 the following definition does not get req_lock on call change_cstate().
#define change_cstate_locked_ex(connection, cstate, flags) \
	change_cstate(connection, cstate, flags, true, __FUNCTION__)

static inline enum bsr_state_rv change_cstate(struct bsr_connection *connection,
												enum bsr_conn_state cstate,
												enum chg_state_flags flags,
												bool locked,
												const char *caller)
{
	return change_cstate_es(connection, cstate, flags, NULL, locked, caller);
}


// DW-1892 
extern void __change_peer_role(struct bsr_connection *, enum bsr_role, const char*);
extern void __change_repl_state(struct bsr_peer_device *, enum bsr_repl_state, const char*);
extern void __change_repl_state_and_auto_cstate(struct bsr_peer_device *, enum bsr_repl_state, const char*);
extern void __change_peer_disk_state(struct bsr_peer_device *, enum bsr_disk_state, const char*);
extern void __change_disk_state(struct bsr_device *, enum bsr_disk_state, const char*);
extern void __change_cstate_state(struct bsr_connection *, enum bsr_conn_state, const char*);

extern enum bsr_state_rv change_repl_state(const char* caller, struct bsr_peer_device *, enum bsr_repl_state, enum chg_state_flags);
extern enum bsr_state_rv stable_change_repl_state(const char* caller, struct bsr_peer_device *, enum bsr_repl_state, enum chg_state_flags);

extern void __change_peer_disk_states(struct bsr_connection *, enum bsr_disk_state);
extern void __outdate_myself(struct bsr_resource *resource);
extern enum bsr_state_rv change_peer_disk_state(struct bsr_peer_device *, enum bsr_disk_state, enum chg_state_flags);

enum bsr_state_rv change_from_consistent(struct bsr_resource *, enum chg_state_flags);

extern void __change_resync_susp_user(struct bsr_peer_device *, bool, const char*);
extern enum bsr_state_rv change_resync_susp_user(struct bsr_peer_device *, bool, enum chg_state_flags, const char *);
extern void __change_resync_susp_peer(struct bsr_peer_device *, bool, const char*);
extern void __change_resync_susp_dependency(struct bsr_peer_device *, bool, const char*);
extern void __change_resync_susp_other_c(struct bsr_peer_device *, bool, const char*);

struct bsr_work;
extern int abort_nested_twopc_work(struct bsr_work *, int);

extern bool resource_is_suspended(struct bsr_resource *resource, enum which_state which, bool locked);
extern bool is_suspended_fen(struct bsr_resource *resource, enum which_state which, bool locked);
extern bool is_suspended_quorum(struct bsr_resource *resource, enum which_state which, bool locked);

enum dds_flags;
enum determine_dev_size;
struct resize_parms;

extern enum determine_dev_size
change_cluster_wide_device_size(struct bsr_device *, sector_t, uint64_t, enum dds_flags,
			struct resize_parms *);

#endif
