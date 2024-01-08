#ifndef BSRSETUP_COLORS_H
#define BSRSETUP_COLORS_H

#include <bsr.h>

enum when_color { NEVER_COLOR = -1, AUTO_COLOR = 0, ALWAYS_COLOR = 1 };
extern enum when_color opt_color;

extern const char *stop_color_code(void);
extern const char *role_color_start(enum bsr_role, bool);
extern const char *role_color_stop(enum bsr_role, bool);
extern const char *cstate_color_start(enum bsr_conn_state);
extern const char *cstate_color_stop(enum bsr_conn_state);
extern const char *repl_state_color_start(enum bsr_repl_state);
extern const char *repl_state_color_stop(enum bsr_repl_state);
extern const char *disk_state_color_start(enum bsr_disk_state, bool intentional, bool);
extern const char *disk_state_color_stop(enum bsr_disk_state, bool);
// BSR-892
extern const char *cerror_color_start(enum bsr_conn_error);
extern const char *cerror_color_stop(enum bsr_conn_error);

// DW-1755
extern const char *io_error_color_start();
extern const char *io_error_color_stop();

#define REPL_COLOR_STRING(__r)  \
	repl_state_color_start(__r), bsr_repl_str(__r), repl_state_color_stop(__r)

#define DISK_COLOR_STRING(__d, __intentional, __local) \
    disk_state_color_start(__d, __intentional, __local), bsr_disk_str(__d), disk_state_color_stop(__d, __local)

#define ROLE_COLOR_STRING(__r, __local) \
	role_color_start(__r, __local), bsr_role_str(__r), role_color_stop(__r, __local)

#define CONN_COLOR_STRING(__c) \
	cstate_color_start(__c), bsr_conn_str(__c), cstate_color_stop(__c)

// BSR-892
#define CONN_ERROR_COLOR_STRING(__c) \
	cerror_color_start(__c), bsr_conn_err_str(__c), cerror_color_stop(__c)


// BSR-1128
#define PRINT_JSON_STR(prefix, format, args...) do { \
	printf(",\"" prefix "\":\"" format "\"", ## args); \
} while(0)

#define PRINT_JSON_INT(prefix, format, args...) do { \
	printf(",\"" prefix "\":" format "", ## args); \
} while(0)


#define PRINT_EVT_INT(prefix, format, args...) do { \
	if (opt_json) \
		PRINT_JSON_INT(prefix, format, ## args); \
	else \
		printf(" " prefix ":" format "", ## args); \
} while(0)

#define PRINT_EVT_STR(prefix, format, args...) do { \
	if (opt_json) \
		PRINT_JSON_STR(prefix, format, ## args); \
	else \
		printf(" " prefix ":" format "", ## args); \
} while(0)

#define WRAP_PRINT_STR(indent, prefix, format, args...) do { \
	if (opt_json) \
		wrap_printf(indent, ",\"" prefix "\":\"" format "\"", ## args); \
	else \
		wrap_printf(indent, " " prefix ":" format "", ## args); \
} while(0)

#define WRAP_PRINT_INT(indent, prefix, format, args...) do { \
	if (opt_json) \
		wrap_printf(indent, ",\"" prefix "\":" format "", ## args); \
	else \
		wrap_printf(indent, " " prefix ":" format "", ## args); \
} while(0)



#define UNKNOWN_STRING "UNKNOWN"
#define UNKNOWN_COLOR_STRING "",UNKNOWN_STRING,""
// BSR-1124 output the old and new state
#define DIFF_COLOR(check, prefix, om, nm) do { \
	if (check) \
		PRINT_EVT_STR(prefix, "%s%s%s->%s%s%s", om, nm); \
	else \
		PRINT_EVT_STR(prefix, "%s%s%s->%s%s%s", UNKNOWN_COLOR_STRING, nm); \
} while(0)

#endif  /* BSRSETUP_COLORS_H */
