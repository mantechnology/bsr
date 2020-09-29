#ifndef BSR_STATE_CHANGE_H
#define BSR_STATE_CHANGE_H

struct bsr_resource_state_change {
	struct bsr_resource *resource;
	enum bsr_role role[2];
	bool susp[2];
	bool susp_nod[2];
};

struct bsr_device_state_change {
	struct bsr_device *device;
	enum bsr_disk_state disk_state[2];
	bool susp_quorum[2];
	bool have_ldev;
	// BSR-676
	int notify_flags;
};

struct bsr_connection_state_change {
	struct bsr_connection *connection;
	enum bsr_conn_state cstate[2];
	enum bsr_role peer_role[2];
	bool susp_fen[2];
};

struct bsr_peer_device_state_change {
	struct bsr_peer_device *peer_device;
	enum bsr_disk_state disk_state[2];
	enum bsr_repl_state repl_state[2];
	bool resync_susp_user[2];
	bool resync_susp_peer[2];
	bool resync_susp_dependency[2];
	bool resync_susp_other_c[2];
	// BSR-676
	int notify_flags;
};

struct bsr_state_change {
	struct list_head list;
	unsigned int n_devices;
	unsigned int n_connections;
	struct bsr_resource_state_change resource[1];
	struct bsr_device_state_change *devices;
	struct bsr_connection_state_change *connections;
	struct bsr_peer_device_state_change *peer_devices;
};

extern struct bsr_state_change *remember_state_change(struct bsr_resource *, gfp_t);
extern void copy_old_to_new_state_change(struct bsr_state_change *);
extern void forget_state_change(struct bsr_state_change *);

extern void notify_resource_state_change(struct sk_buff *,
					 unsigned int,
					 struct bsr_state_change *,
					 enum bsr_notification_type type);
extern void notify_connection_state_change(struct sk_buff *,
					   unsigned int,
					   struct bsr_connection_state_change *,
					   enum bsr_notification_type type);
extern void notify_device_state_change(struct sk_buff *,
				       unsigned int,
				       struct bsr_device_state_change *,
				       enum bsr_notification_type type);
extern void notify_peer_device_state_change(struct sk_buff *,
					    unsigned int,
					    struct bsr_peer_device_state_change *,
					    enum bsr_notification_type type);

#endif  /* BSR_STATE_CHANGE_H */
