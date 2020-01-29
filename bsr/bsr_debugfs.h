#ifdef _WIN
#include "./bsr-kernel-compat/windows/kernel.h"
#else // _LIN
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#endif
#include "bsr_int.h"

#ifdef CONFIG_DEBUG_FS
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
