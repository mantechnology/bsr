#ifndef __BSR_STRINGS_H
#define __BSR_STRINGS_H

struct state_names {
	const char * const *names;
	unsigned int size;
};

// BSR-892
extern struct state_names bsr_conn_error_names;
extern struct state_names bsr_conn_state_names;
extern struct state_names bsr_repl_state_names;
extern struct state_names bsr_role_state_names;
extern struct state_names bsr_disk_state_names;
extern struct state_names bsr_error_messages;

enum bsr_packet;

// BSR-892
extern const char *bsr_conn_err_str(enum bsr_conn_error);
extern const char *bsr_repl_str(enum bsr_repl_state);
extern const char *bsr_conn_str(enum bsr_conn_state);
extern const char *bsr_role_str(enum bsr_role);
extern const char *bsr_disk_str(enum bsr_disk_state);
extern const char *bsr_set_st_err_str(enum bsr_state_rv);
extern const char *bsr_packet_name(enum bsr_packet);

// DW-1755
extern const char *bsr_io_type_name(unsigned char type);
extern const char *bsr_disk_type_name(unsigned char type);
// BSR-859
extern const char *bsr_host_type_name(char * node_name);
#endif  /* __BSR_STRINGS_H */
