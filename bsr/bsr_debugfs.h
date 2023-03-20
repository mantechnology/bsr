#ifdef _WIN
#include "./bsr-kernel-compat/windows/kernel.h"
#else // _LIN
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#endif
#include "bsr_int.h"

#if defined(CONFIG_DEBUG_FS) && defined(_LIN)
int __init bsr_debugfs_init(void);
void bsr_debugfs_cleanup(void);

void bsr_debugfs_resource_add(struct bsr_resource *resource);
void bsr_debugfs_resource_cleanup(struct bsr_resource *resource);

void bsr_debugfs_connection_add(struct bsr_connection *connection);
void bsr_debugfs_connection_cleanup(struct bsr_connection *connection);

void bsr_debugfs_device_add(struct bsr_device *device);
void bsr_debugfs_device_cleanup(struct bsr_device *device);

void bsr_debugfs_peer_device_add(struct bsr_peer_device *peer_device);
void bsr_debugfs_peer_device_cleanup(struct bsr_peer_device *peer_device);
#else
#ifdef _WIN
static __inline int bsr_debugfs_init(void) { return -ENODEV; }
#else // _LIN
static inline int __init bsr_debugfs_init(void) { return -ENODEV; }
#endif
static inline void bsr_debugfs_cleanup(void) { }

static inline void bsr_debugfs_resource_add(struct bsr_resource *resource) {
	UNREFERENCED_PARAMETER(resource);
}
static inline void bsr_debugfs_resource_cleanup(struct bsr_resource *resource) {
	UNREFERENCED_PARAMETER(resource);
}

static inline void bsr_debugfs_connection_add(struct bsr_connection *connection) {
	UNREFERENCED_PARAMETER(connection);
}
static inline void bsr_debugfs_connection_cleanup(struct bsr_connection *connection) {
	UNREFERENCED_PARAMETER(connection);
}

static inline void bsr_debugfs_device_add(struct bsr_device *device) {
	UNREFERENCED_PARAMETER(device);
}
static inline void bsr_debugfs_device_cleanup(struct bsr_device *device) {
	UNREFERENCED_PARAMETER(device);
}

static inline void bsr_debugfs_peer_device_add(struct bsr_peer_device *peer_device) {
	UNREFERENCED_PARAMETER(peer_device);
}
static inline void bsr_debugfs_peer_device_cleanup(struct bsr_peer_device *peer_device) {
	UNREFERENCED_PARAMETER(peer_device);
}

#endif


int bsr_version_show(struct seq_file *m, void *ignored);
int resource_in_flight_summary_show(struct seq_file *m, void *pos);
int resource_state_twopc_show(struct seq_file *m, void *pos);
int connection_callback_history_show(struct seq_file *m, void *ignored);
int connection_debug_show(struct seq_file *m, void *ignored);
int connection_oldest_requests_show(struct seq_file *m, void *ignored);
int connection_transport_show(struct seq_file *m, void *ignored);
int connection_transport_speed_show(struct seq_file *m, void *ignored);
int connection_send_buf_show(struct seq_file *m, void *ignored);
int peer_device_resync_ratio_show(struct seq_file *m, void *ignored); // BSR-838
int peer_device_proc_bsr_show(struct seq_file *m, void *ignored);
int peer_device_resync_extents_show(struct seq_file *m, void *ignored);
int device_act_log_extents_show(struct seq_file *m, void *ignored);
int device_act_log_stat_show(struct seq_file *m, void *ignored); // BSR-765
int device_oldest_requests_show(struct seq_file *m, void *ignored);
int device_data_gen_id_show(struct seq_file *m, void *ignored);
int device_io_frozen_show(struct seq_file *m, void *ignored);
int device_ed_gen_id_show(struct seq_file *m, void *ignored);
int device_io_stat_show(struct seq_file *m, void *ignored);
int device_io_complete_show(struct seq_file *m, void *ignored);
int device_io_pending_show(struct seq_file *m, void *ignored); // BSR-1054
int device_req_timing_show(struct seq_file *m, void *ignored);
int device_peer_req_timing_show(struct seq_file *m, void *ignored);
int bsr_alloc_pages_show(struct seq_file *m, void *ignored); // BSR-875
