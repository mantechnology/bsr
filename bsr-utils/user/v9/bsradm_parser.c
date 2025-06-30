/*
 *
   bsradm_parser.c a hand crafted parser

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>

   bsr is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   bsr is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with bsr; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glob.h>
#include <search.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "bsradm.h"
#include "bsr.h"
#include "linux/bsr_limits.h"
#include "bsrtool_common.h"
#include "bsradm_parser.h"
#include "shared_parser.h"
#include <config_flags.h>

YYSTYPE yylval;

/////////////////////

static int c_section_start;
static int parse_proxy_options(struct options *, struct options *);
static void parse_skip(void);
static struct d_resource *template_file(const char *res_name);

struct d_name *names_from_str(char* str)
{
	struct d_name *names;

	names = malloc(sizeof(struct d_name));
	names->name = strdup(str);

	return names;
}

char *_names_to_str_c(char* buffer, struct names *names, char c)
{
	int n = 0;
	struct d_name *name;

	if (STAILQ_EMPTY(names)) {
		snprintf(buffer, NAMES_STR_SIZE, "UNKNOWN");
		return buffer;
	}

	name = STAILQ_FIRST(names);
	while (1) {
		n += snprintf(buffer + n, NAMES_STR_SIZE - n, "%s", name->name);
		name = STAILQ_NEXT(name, link);
		if (!name)
			return buffer;
		n += snprintf(buffer + n, NAMES_STR_SIZE - n, "%c", c);
	}
}

char *_names_to_str(char* buffer, struct names *names)
{
	return _names_to_str_c(buffer, names, ' ');
}

/*
 * Determine if two hostnames are either fully qualified and equal,
 * or one or both do not contain a domain name and the host names
 * are equal.  (Note that DNS names are not case sensitive.)
 */
bool hostnames_equal(const char *a, const char *b)
{
	const char *domain_a = strchrnul(a, '.');
	const char *domain_b = strchrnul(b, '.');

	if (*domain_a && *domain_b) {
		/* Both hostnames contain a domain part. */
		return !strcasecmp(a, b);
	} else {
		/* One or both hostnames are "short". */
		return domain_a - a == domain_b - b &&
		       !strncasecmp(a, b, domain_a - a);
	}
}

int hostname_in_list(const char *name, struct names *names)
{
	struct d_name *n;

	STAILQ_FOREACH(n, names, link)
		if (hostnames_equal(n->name, name))
			return 1;

	return 0;
}

void free_names(struct names *names)
{
	struct d_name *n, *nf;

	n = STAILQ_FIRST(names);
	while (n) {
		nf = STAILQ_NEXT(n, link);
		free(n->name);
		free(n);
		n = nf;
	}
}

void m_strtoll_range(const char *s, char def_unit,
		     const char *name,
		     unsigned long long min, unsigned long long max)
{
	unsigned long long r = m_strtoll(s, def_unit);
	char unit[] = { def_unit != '1' ? def_unit : 0, 0 };
	if (min > r || r > max) {
		err("%s:%d: %s %s => %llu%s out of range [%llu..%llu]%s.\n",
			config_file, fline, name, s, r, unit, min, max, unit);
		if (config_valid <= 1) {
			config_valid = 0;
			return;
		}
	}
	if (DEBUG_RANGE_CHECK) {
		err("%s:%d: %s %s => %llu%s in range [%llu..%llu]%s.\n",
			config_file, fline, name, s, r, unit, min, max, unit);
	}
}

void range_check(const enum range_checks what, const char *name,
		 char *value)
{
	/*
	 * FIXME: Handle signed/unsigned values correctly by checking the
	 * F_field_name_IS_SIGNED defines.
	 */

#define M_STRTOLL_RANGE(x) \
		m_strtoll_range(value, BSR_ ## x ## _SCALE, name, \
				BSR_ ## x ## _MIN, \
				BSR_ ## x ## _MAX)

	switch (what) {
	case R_MINOR_COUNT:
		M_STRTOLL_RANGE(MINOR_COUNT);
		break;
	case R_DIALOG_REFRESH:
		M_STRTOLL_RANGE(DIALOG_REFRESH);
		break;
	case R_PORT:
		M_STRTOLL_RANGE(PORT);
		break;
	/* FIXME not yet implemented!
	case R_META_IDX:
		M_STRTOLL_RANGE(META_IDX);
		break;
	*/
	case R_NODE_ID:
		M_STRTOLL_RANGE(NODE_ID);
		break;
	default:
		err("%s:%d: unknown range for %s => %s\n", config_file, fline, name, value);
		break;
	}
}

struct d_option *new_opt(char *name, char *value)
{
	struct d_option *cn = calloc(1, sizeof(struct d_option));

	/* err("%s:%d: %s = %s\n",config_file,line,name,value); */
	cn->name = name;
	cn->value = value;

	return cn;
}

void pdperror(char *text)
{
	config_valid = 0;
	err("%s:%d: in proxy plugin section: %s.\n", config_file, line, text);
	exit(E_CONFIG_INVALID);
}

static void pperror(struct d_proxy_info *proxy, char *text)
{
	config_valid = 0;
	err("%s:%d: in section: proxy on %s { ... } }: '%s' keyword missing.\n",
	    config_file, c_section_start, names_to_str(&proxy->on_hosts), text);
}

#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})

/*
 * for check_uniq: check uniqueness of
 * resource names, ip:port, node:disk and node:device combinations
 * as well as resource:section ...
 * binary tree to test for uniqueness of these values...
 *
 * Furthermore, the names of files that have been read are
 * registered here, to avoid reading the same file multiple times.
 * IMPORTANT:
 * It is fine to point key and value to the same object within one entry, that
 * is handled by free_bt_node, BUT DON'T point to the same objects from
 * multiple entries (double free).
 */

void *global_btree = NULL;
/* some settings need only be unique within one resource definition. */
void *per_resource_btree = NULL;

int btree_key_cmp(const void *a, const void *b)
{
	ENTRY *ka = (ENTRY*)a;
	ENTRY *kb = (ENTRY*)b;

	return strcmp((char*)ka->key, (char*)kb->key);
}

void free_bt_node(void *node)
{
	ENTRY *e = node;
	/* creative users of the tree might point key and data to the same object */
	if (e->key != e->data)
		free(e->key);
	free(e->data);
	free(e);
}

void free_btrees(void)
{
	tdestroy(per_resource_btree, free_bt_node);
	tdestroy(global_btree, free_bt_node);
}

void check_upr_init(void)
{
	static int created = 0;
	if (config_valid >= 2)
		return;	
	if (created) {
		tdestroy(per_resource_btree, free_bt_node);
	}
	per_resource_btree = NULL;

	created = 1;
}

int vcheck_uniq_file_line(
	const char *file, const int line,
	void **bt, const char *what, const char *fmt, va_list ap)
{
	int rv;
	ENTRY *e, *f;

	/* if we are done parsing the config file,
	 * switch off this paranoia */
	if (config_valid >= 2)
		return 1;

	e = calloc(1, sizeof *e);
	if (!e) {
		err("calloc: %m\n");
		exit(E_THINKO);
	}

	rv = vasprintf(&e->key, fmt, ap);

	if (rv < 0) {
		err("vasprintf: %m\n");
		exit(E_THINKO);
	}

	if (EXIT_ON_CONFLICT && !what) {
		err("Oops, unset argument in %s:%d.\n", __FILE__, __LINE__);
		exit(E_THINKO);
	}
	m_asprintf((char **)&e->data, "%s:%u", file, line);

	f = tfind(e, bt, btree_key_cmp);
	if (f) {
		if (what) {
			ENTRY *ep = *(ENTRY **)f;
			err("%s: conflicting use of %s '%s' ...\n%s: %s '%s' first used here.\n",
				(char *)e->data, what, ep->key, (char *)ep->data, what, ep->key);
		}
		free(e->key);
		free(e->data);
		free(e);
		config_valid = 0;
	} else {
		f = tsearch(e, bt, btree_key_cmp);
		if (!f) {
			err("tree entry (%s => %s) failed\n", e->key, (char *)e->data);
			exit(E_THINKO);
		}
		f = NULL;
	}
	if (EXIT_ON_CONFLICT && f) {
		CLI_ERRO_LOG(false, true, "invalid config");
		exit(E_CONFIG_INVALID);
	}
	return !f;
}

int vcheck_uniq(void **bt, const char *what, const char *fmt, va_list ap)
{
	return vcheck_uniq_file_line(config_file, fline, bt, what, fmt, ap);
}

static void pe_expected(const char *exp)
{
	const char *s = yytext;
	err("%s:%u: Parse error: '%s' expected,\n\tbut got '%.20s%s'\n",
	    config_file, line, exp, s, strlen(s) > 20 ? "..." : "");
	exit(E_CONFIG_INVALID);
}

static void check_string_error(int got)
{
	const char *msg;
	switch(got) {
	case TK_ERR_STRING_TOO_LONG:
		msg = "Token too long";
		break;
	case TK_ERR_DQSTRING_TOO_LONG:
		msg = "Double quoted string too long";
		break;
	case TK_ERR_DQSTRING:
		msg = "Unterminated double quoted string\n  we don't allow embedded newlines\n ";
		break;
	default:
		return;
	}
	err("%s:%u: %s >>>%.20s...<<<\n", config_file, line, msg, yytext);
	exit(E_CONFIG_INVALID);
}

static void pe_expected_got(const char *exp, int got)
{
	static char tmp[2] = "\0";
	const char *s = yytext;
	if (exp[0] == '\'' && exp[1] && exp[2] == '\'' && exp[3] == 0) {
		tmp[0] = exp[1];
	}
	err("%s:%u: Parse error: '%s' expected,\n\tbut got '%.20s%s' (TK %d)\n",
	    config_file, line, tmp[0] ? tmp : exp, s, strlen(s) > 20 ? "..." : "", got);
	exit(E_CONFIG_INVALID);
}

#define EXP(TOKEN1)						\
({								\
	int token;						\
	token = yylex();					\
	if (token != TOKEN1) {					\
		if (TOKEN1 == TK_STRING)			\
			check_string_error(token);		\
		pe_expected_got( #TOKEN1, token);		\
	}							\
	token;							\
})

static void parse_global(void)
{
	fline = line;
	check_uniq("global section", "global");
	if (!STAILQ_EMPTY(&config)) {
		err("%s:%u: You should put the global {} section\n\tin front of any resource {} section\n",
		    config_file, line);
	}
	EXP('{');
	while (1) {
		int token = yylex();
		fline = line;
		switch (token) {
		case TK_UDEV_ALWAYS_USE_VNR:
			global_options.udev_always_symlink_vnr = 1;
			break;
		case TK_DISABLE_IP_VERIFICATION:
			global_options.disable_ip_verification = 1;
			break;
		case TK_MINOR_COUNT:
			EXP(TK_INTEGER);
			range_check(R_MINOR_COUNT, "minor-count", yylval.txt);
			global_options.minor_count = atoi(yylval.txt);
			break;
		case TK_DIALOG_REFRESH:
			EXP(TK_INTEGER);
			range_check(R_DIALOG_REFRESH, "dialog-refresh",
				    yylval.txt);
			global_options.dialog_refresh = atoi(yylval.txt);
			break;
		case TK_CMD_TIMEOUT_SHORT:
			EXP(TK_INTEGER);
			m_strtoll_range(yylval.txt, '1', "cmd-timeout-short", 0, 900);
			global_options.cmd_timeout_short = atoi(yylval.txt);
			break;
		case TK_CMD_TIMEOUT_MEDIUM:
			EXP(TK_INTEGER);
			m_strtoll_range(yylval.txt, '1', "cmd-timeout-medium", 0, 900);
			global_options.cmd_timeout_medium = atoi(yylval.txt);
			break;
		case TK_CMD_TIMEOUT_LONG:
			EXP(TK_INTEGER);
			m_strtoll_range(yylval.txt, '1', "cmd-timeout-long", 0, 900);
			global_options.cmd_timeout_long = atoi(yylval.txt);
			break;
			// BSR-1387
		case TK_HOSTNAME:
			EXP(TK_STRING);
			global_options.hostname = yylval.txt;
			hostname = yylval.txt;
			break;
		case TK_USAGE_COUNT:
			switch (yylex()) {
			case TK_YES:
				global_options.usage_count = UC_YES;
				break;
			case TK_NO:
				global_options.usage_count = UC_NO;
				break;
			case TK_ASK:
				global_options.usage_count = UC_ASK;
				break;
			default:
				pe_expected("yes | no | ask");
			}
			break;
		case '}':
			return;
		default:
			pe_expected("dialog-refresh | minor-count | "
				    "disable-ip-verification | hostname");
		}
		EXP(';');
	}
}

static char *check_deprecated_alias(char *name)
{
	int i;
	static struct {
		char *old_name, *new_name;
	} table[] = {
		{ "outdate-peer", "fence-peer" },
		{ "rate", "resync-rate" },
		{ "after", "resync-after" },
	};

	for (i = 0; i < ARRAY_SIZE(table); i++) {
		if (!strcmp(table[i].old_name, name))
			return table[i].new_name;
	}
	return name;
}

static void pe_valid_enums(const char **map, int nr_enums)
{
	int i, size = 0;
	char *buffer, *p;

	for (i = 0; i < nr_enums; i++) {
		if (map[i])
			size += strlen(map[i]) + 3;
	}

	assert(size >= 3);

	buffer = alloca(size);
	p = buffer;
	for (i = 0; i < nr_enums; i++) {
		if (map[i])
			p += sprintf(p, "%s | ", map[i]);
	}

	buffer[size - 3] = 0; /* Eliminate last " | " */
	err("Allowed values are: %s\n", buffer);
}

static void pe_field(struct field_def *field, enum check_codes e, char *value)
{
	static const char *err_strings[] = {
		[CC_NOT_AN_ENUM] = "not valid",
		[CC_NOT_A_BOOL] = "not 'yes' or 'no'",
		[CC_NOT_A_NUMBER] = "not a number",
		[CC_TOO_SMALL] = "too small",
		[CC_TOO_BIG] = "too big",
		[CC_STR_TOO_LONG] = "too long",
		[CC_NOT_AN_ENUM_NUM] = "not valid",
	};
	err("%s:%u: Parse error: while parsing value ('%.20s%s')\nfor %s. Value is %s.\n",
		config_file, line,
		value, strlen(value) > 20 ? "..." : "",
		field->name, err_strings[e]);

	if (e == CC_NOT_AN_ENUM)
		pe_valid_enums(field->u.e.map, field->u.e.size);
	else if (e == CC_STR_TOO_LONG)
		err("max len: %u\n", field->u.s.max_len - 1);
	/* else if (e == CC_NOT_AN_ENUM_NUM)
		pe_valid_enum_num((field->u.en.map, field->u.en.map_size); */

	if (config_valid <= 1)
		config_valid = 0;
}

static void pe_options(struct context_def *options_def)
{
	struct field_def *field;
	char *buffer, *p;
	int size = 0;

	for (field = options_def->fields; field->name; field++)
		size += strlen(field->name) + 3;

	assert(size >= 3);

	buffer = alloca(size);
	p = buffer;
	for (field = options_def->fields; field->name; field++)
		p += sprintf(p, "%s | ", field->name);
	buffer[size - 3] = 0; /* Eliminate last " | " */
	pe_expected(buffer);
}

static struct field_def *find_field(bool *no_prefix, struct context_def *options_def,
				    const char *name)
{
	struct field_def *field;
	bool ignored_no_prefix;

	if (no_prefix == NULL)
		no_prefix = &ignored_no_prefix;

	if (!strncmp(name, "no-", 3)) {
		name += 3;
		*no_prefix = true;
	} else {
		*no_prefix = false;
	}

	for (field = options_def->fields; field->name; field++) {
		if (!strcmp(field->name, name))
			return field;
	}

	return NULL;
}

static char *parse_option_value(struct field_def *field_def, bool no_prefix)
{
	char *value;
	int token;
	enum check_codes e;

	// BSR-768 fix to not fill blank values with yes (or no)
	token = yylex();
	
	if (!field_def->checked_in_postparse) {
		e = field_def->ops->check(field_def, yytext);
		if (e != CC_OK)
			pe_field(field_def, e, yytext);
	}
	
	if (token == ';') {
		value = NULL;
	} else {
		value = strdup(yytext);
		EXP(';');
	}

	return value;
}


/* The syncer section is deprecated. Distribute the options to the disk or net options. */
void parse_options_syncer(struct d_resource *res)
{
	struct field_def *field_def;
	bool no_prefix;
	char *text, *value;
	int token;

	struct options *options = NULL;
	c_section_start = line;
	fline = line;

	while (1) {
		token = yylex();
		fline = line;

		if (token == '}')
			return;

		text = check_deprecated_alias(yytext);
		field_def = find_field(&no_prefix, &show_net_options_ctx, text);
		if (field_def) {
			options = &res->net_options;
		} else {
			field_def = find_field(&no_prefix, &attach_cmd_ctx, text);
			if (field_def) {
				options = &res->disk_options;
			} else {
				field_def = find_field(&no_prefix, &resource_options_ctx,
						       text);
				if (field_def)
					options = &res->res_options;
				else
					pe_expected("a syncer option keyword");
			}
		}

		value = parse_option_value(field_def, no_prefix);
		insert_tail(options, new_opt((char *)field_def->name, value));
	}
}

static struct options __parse_options(struct context_def *options_def,
				      void (*delegate)(void*),
				      void *delegate_context)
{
	struct options options = STAILQ_HEAD_INITIALIZER(options);
	struct field_def *field_def;
	char *value;
	bool no_prefix;
	int token;

	c_section_start = line;
	fline = line;

	while (1) {
		token = yylex();
		if (token == '}')
			return options;

		field_def = find_field(&no_prefix, options_def, yytext);
		if (!field_def) {
			if (delegate) {
				delegate(delegate_context);
				continue;
			} else {
				pe_options(options_def);
			}
		}

		value = parse_option_value(field_def, no_prefix);
		insert_tail(&options, new_opt((char *)field_def->name, value));
	}
}

static struct options parse_options(struct context_def *options_def)
{
	return __parse_options(options_def, NULL, NULL);
}

// BSR-718
static void insert_node_options_delegate(void *ctx)
{
	struct options *options = ctx;
	struct field_def *field_def;
	bool no_prefix;
	char *value;

	field_def = find_field(&no_prefix, &node_options_ctx, yytext);
	if (!field_def)
		pe_options(&node_options_ctx);
	value = parse_option_value(field_def, no_prefix);
	insert_tail(options, new_opt((char *)field_def->name, value));
}
// BSR-718
static void parse_res_options(struct options *res_options, struct options *node_options)
{
	*res_options = __parse_options(&resource_options_ctx, 
					insert_node_options_delegate, 
					node_options);
}

static void insert_pd_options_delegate(void *ctx)
{
	struct options *options = ctx;
	struct field_def *field_def;
	bool no_prefix;
	char *value;

	field_def = find_field(&no_prefix, &peer_device_options_ctx, yytext);
	if (!field_def)
		pe_options(&peer_device_options_ctx);
	value = parse_option_value(field_def, no_prefix);
	insert_tail(options, new_opt((char *)field_def->name, value));
}

static void parse_disk_options(struct options *disk_options, struct options *peer_device_options)
{
	*disk_options = __parse_options(&attach_cmd_ctx,
					insert_pd_options_delegate,
					peer_device_options);
}

static void __parse_address(struct d_address *a)
{
	switch(yylex()) {
	case TK_SCI:   /* 'ssocks' was names 'sci' before. */
		a->af = strdup("ssocks");
		EXP(TK_IPADDR);
		break;
	case TK_SSOCKS:
	case TK_SDP:
	case TK_IPV4:
		a->af = yylval.txt;
		EXP(TK_IPADDR);
		break;
	case TK_IPV6:
		a->af = yylval.txt;
		EXP('[');
		EXP(TK_IPADDR6);
		break;
	case TK_IPADDR:
		a->af = strdup("ipv4");
		break;
	/* case '[': // Do not foster people's laziness ;)
		EXP(TK_IPADDR6);
		*af = strdup("ipv6");
		break; */
	default:
		pe_expected("ssocks | sdp | ipv4 | ipv6 | <ipv4 address> ");
	}

	assert(a->af != NULL);

	a->addr = yylval.txt;
	if (!strcmp(a->af, "ipv6"))
		EXP(']');
	EXP(':');
	EXP(TK_INTEGER);
	a->port = yylval.txt;
	range_check(R_PORT, "port", yylval.txt);

	a->is_local_address = addr_scope_local(a->addr);
}

static void parse_address(struct names *on_hosts, struct d_address *address)
{
	__parse_address(address);
	EXP(';');
}

// BSR-1409
static void parse_groups(struct names *groups, char delimeter)
{
	char errstr[20];
	struct d_name *name;
	int nr_groups = 0;
	int token;

	while (1) {
		token = yylex();
		switch (token) {
		case TK_STRING:
			name = malloc(sizeof(struct d_name));
			name->name = yylval.txt;
			insert_tail(groups, name);
			nr_groups++;
			break;
		default:
			if (token == delimeter) {
				if (nr_groups == 0)
					pe_expected_got("TK_STRING", token);
				return;
			} else {
				sprintf(errstr, "TK_STRING | '%c'", delimeter);
				pe_expected_got(errstr, token);
			}
		}
	}
}

static void parse_hosts(struct names *hosts, char delimeter)
{
	char errstr[20];
	struct d_name *name;
	int nr_hosts = 0;
	int token;

	while (1) {
		token = yylex();
		switch (token) {
		case TK_STRING:
			name = malloc(sizeof(struct d_name));
			name->name = yylval.txt;
			insert_tail(hosts, name);
			nr_hosts++;
			break;
		default:
			if (token == delimeter) {
				if (nr_hosts == 0)
					pe_expected_got("TK_STRING", token);
				return;
			} else {
				sprintf(errstr, "TK_STRING | '%c'", delimeter);
				pe_expected_got(errstr, token);
			}
		}
	}
}

static struct d_proxy_info *parse_proxy_section(void)
{
	struct d_proxy_info *proxy;

	proxy = calloc(1, sizeof(struct d_proxy_info));
	STAILQ_INIT(&proxy->on_hosts);

	EXP(TK_ON);
	parse_hosts(&proxy->on_hosts, '{');
	while (1) {
		switch (yylex()) {
		case TK_INSIDE:
			parse_address(&proxy->on_hosts, &proxy->inside);
			break;
		case TK_OUTSIDE:
			parse_address(&proxy->on_hosts, &proxy->outside);
			break;
			// BSR-1514 
		case TK_PUBLIC_INSIDE:
			parse_address(&proxy->on_hosts, &proxy->public_inside);
			break;
		case TK_PUBLIC_OUTSIDE:
			parse_address(&proxy->on_hosts, &proxy->public_outside);
			break;
		case TK_OPTIONS:
			parse_proxy_options(&proxy->options, &proxy->plugins);
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("inside | outside | public-inside | public-outside | options");

		}
	}

 break_loop:
	if (!proxy->inside.addr)
		pperror(proxy, "inside");

	if (!proxy->outside.addr)
		pperror(proxy, "outside");

	return proxy;
}

void parse_meta_disk(struct d_volume *vol)
{
#ifdef _LIN
	// BSR-1055 do not remove '\' character if windows meta-disk
	if (strcmp(vol->platform, "windows") == 0)
		skip_unescape = 1;
#endif
	EXP(TK_STRING);
	vol->meta_disk = yylval.txt;
	if (strcmp("internal", yylval.txt) == 0) {
		/* internal, flexible size */
		vol->meta_index = strdup("internal");
		EXP(';');
	} else {
		switch(yylex()) {
#if defined(_WIN_VHD_META_SUPPORT) || defined(_LIN_LOOP_META_SUPPORT)
		case TK_STRING:
			/* external, static size */
			vol->meta_index = strdup(yylval.txt);
			EXP(';');
			break;
#endif
		case '[':
			EXP(TK_INTEGER);
			/* external, static size */
			vol->meta_index = yylval.txt;
			EXP(']');
			EXP(';');
			break;
		case ';':
			/* external, flexible size */
			vol->meta_index = strdup("flexible");
			break;
		default:
			pe_expected("[ | ;");
		}
	}
#ifdef _LIN
	// BSR-1055
	skip_unescape = 0;
#endif
}

static void check_minor_nonsense(const char *devname, const int explicit_minor, char * platform)
{
	if (!devname)
		return;
#ifdef CONFIG_MULTI_PLATFORM
	if (strcmp(platform, "linux") == 0) {
		/* if devname is set, it starts with /dev/bsr */
		// BSR-386 rename to be the same as name of major device due to pvcreate error
		if (only_digits(devname + 8)) {
			int m = strtol(devname + 8, NULL, 10);
			if (m == explicit_minor)
				return;

			err("%s:%d: Parse error: '%s', explicit minor number must match with device name\n"
				"\tTry \"device /dev/bsr%u minor %u;\",\n"
				"\tor leave off either device name or explicit minor.\n"
				"\tArbitrary device names must start with /dev/bsr_\n"
				"\tmind the '_'! (/dev/ is optional, but bsr_ is required)\n",
				config_file, fline, devname, explicit_minor, explicit_minor);
			config_valid = 0;
			return;
		} else if (devname[8] == '_')
			return;

		err("%s:%d: Parse error: '%s', arbitrary device name must start with /dev/bsr_\n"
			"\tmind the '_'! (/dev/ is optional, but bsr_ is required)\n",
			config_file, fline, devname);
		config_valid = 0;
	}
#else
#ifdef _LIN
	/* if devname is set, it starts with /dev/bsr */
	// BSR-386 rename to be the same as name of major device due to pvcreate error
	if (only_digits(devname + 8)) {
		int m = strtol(devname + 8, NULL, 10);
		if (m == explicit_minor)
			return;

		err("%s:%d: Parse error: '%s', explicit minor number must match with device name\n"
		    "\tTry \"device /dev/bsr%u minor %u;\",\n"
		    "\tor leave off either device name or explicit minor.\n"
		    "\tArbitrary device names must start with /dev/bsr_\n"
		    "\tmind the '_'! (/dev/ is optional, but bsr_ is required)\n",
		    config_file, fline, devname, explicit_minor, explicit_minor);
		config_valid = 0;
		return;
	} else if (devname[8] == '_')
		return;

	err("%s:%d: Parse error: '%s', arbitrary device name must start with /dev/bsr_\n"
	    "\tmind the '_'! (/dev/ is optional, but bsr_ is required)\n",
	    config_file, fline, devname);
	config_valid = 0;
#endif
#endif
	return;
}

static void parse_device(struct names* on_hosts, struct d_volume *vol)
{
	struct d_name *h;
	int m;

	switch (yylex()) {
	case TK_STRING:
		// BSR-386 rename to be the same as name of major device due to pvcreate error
		if (!strncmp("bsr", yylval.txt, 3)) {
			m_asprintf(&vol->device, "/dev/%s", yylval.txt);
			free(yylval.txt);
		} else
			vol->device = yylval.txt;
#ifdef CONFIG_MULTI_PLATFORM
		if (strcmp(vol->platform, "linux") == 0) {
			// BSR-386 rename to be the same as name of major device due to pvcreate error
			if (strncmp("/dev/bsr", vol->device, 8)) {
				err("%s:%d: Parse error: '%s', device name must start with /dev/bsr\n"
					"\t(/dev/ is optional, but bsr is required)\n",
					config_file, fline, vol->device);
				config_valid = 0;
				/* no goto out yet,
				* as that would additionally throw a parse error */
			}
		}
		else { // windows
			if (strncmp("/dev", vol->device, 4) == 0) {
				err("%s:%d: Parse error: '%s', device name must be a drive letter\n",
					config_file, fline, vol->device);
				config_valid = 0;
			}
		}
#else
#ifdef _LIN
		// BSR-386 rename to be the same as name of major device due to pvcreate error
		if (strncmp("/dev/bsr", vol->device, 8)) {
			err("%s:%d: Parse error: '%s', device name must start with /dev/bsr\n"
			    "\t(/dev/ is optional, but bsr is required)\n",
			    config_file, fline, vol->device);
			config_valid = 0;
			/* no goto out yet,
			 * as that would additionally throw a parse error */
		}
#endif
#endif
		switch (yylex()) {
		default:
			pe_expected("minor | ;");
			/* Fall through */
		case ';':
			m = dt_minor_of_dev(vol->device);
			if (m < 0) {
				err("%s:%d: Parse error: '%s', no minor given nor device name contains a minor number\n",
				    config_file, fline, vol->device);
				config_valid = 0;
			}
			vol->device_minor = m;
			goto out;
		case TK_MINOR:
			; /* double fall through */
		}
	case TK_MINOR:
		EXP(TK_INTEGER);
		vol->device_minor = atoi(yylval.txt);
		EXP(';');

		/* if both device name and minor number are explicitly given,
		 * force /dev/bsr<minor-number> or /dev/bsr_<arbitrary> */
		check_minor_nonsense(vol->device, vol->device_minor, vol->platform);
	}
out:
	if (!on_hosts)
		return;

	STAILQ_FOREACH(h, on_hosts, link) {
		check_uniq_file_line(vol->v_config_file, vol->v_device_line,
			"device-minor", "device-minor:%s:%u", h->name, vol->device_minor);
		if (vol->device)
			check_uniq_file_line(vol->v_config_file, vol->v_device_line,
			"device", "device:%s:%s", h->name, vol->device);
	}
}

struct d_volume *alloc_volume(void)
{
	struct d_volume *vol;

	vol = calloc(1, sizeof(struct d_volume));
	if (vol == NULL) {
		err("calloc: %m\n");
		exit(E_EXEC_ERROR);
	}

	STAILQ_INIT(&vol->disk_options);
	STAILQ_INIT(&vol->pd_options);
	STAILQ_INIT(&vol->peer_devices);

	return vol;
}

struct d_volume *volume0(struct volumes *volumes, char *platform)
{
	struct d_volume *vol = STAILQ_FIRST(volumes);

	if (!vol) {
		vol = alloc_volume();
		vol->device_minor = -1;
		vol->implicit = 1;
#ifdef CONFIG_MULTI_PLATFORM
		if (platform != NULL) {
			vol->platform = platform;
		} else {
#ifdef _WIN
			vol->platform = strdup("windows");
#else // _LIN
			vol->platform = strdup("linux");
#endif
		}
#endif
		insert_head(volumes, vol);
		return vol;
	} else {
		if (vol->vnr == 0 && STAILQ_NEXT(vol, link) == NULL && vol->implicit)
			return vol;

		config_valid = 0;
		err("%s:%d: mixing explicit and implicit volumes is not allowed\n",
		    config_file, line);
		return vol;
	}
}

int parse_volume_stmt(struct d_volume *vol, struct names* on_hosts, int token)
{
	if (!vol->v_config_file)
		vol->v_config_file = config_file;

	switch (token) {
	case TK_DISK:
		token = yylex();
		switch (token) {
		case TK_STRING:
			vol->disk = yylval.txt;
			// DW-1451 Device name and disk name must be the same in Windows.
#ifdef CONFIG_MULTI_PLATFORM
			if (strcmp(vol->platform, "windows") == 0) {
				if (vol->disk != NULL && vol->device != NULL && strcmp(vol->disk, vol->device) != 0){
					err("The device(%s) and disk(%s) letters must be the same. Please check again.\n", vol->device, vol->disk);
					exit(E_CONFIG_INVALID);
				}

				vol->device = strdup(yylval.txt);
				vol->device_minor = (yylval.txt[0] & ~0x20) - 'C';
			}
#else
#ifdef _WIN
			if (vol->disk != NULL && vol->device != NULL && strcmp(vol->disk, vol->device) != 0){
				err("The device(%s) and disk(%s) letters must be the same. Please check again.\n", vol->device, vol->disk);
				exit(E_CONFIG_INVALID);
			}

            vol->device = strdup(yylval.txt);
            vol->device_minor = (yylval.txt[0] & ~0x20) - 'C';
#endif
#endif
			EXP(';');
			break;
		case '{':
			parse_disk_options(&vol->disk_options, &vol->pd_options);
			break;
		default:
			check_string_error(token);
			pe_expected_got( "TK_STRING | {", token);
		}
		vol->parsed_disk = 1;
		vol->v_disk_line = fline;
		break;
	case TK_DEVICE:
		parse_device(on_hosts, vol);
		// DW-1451 Device name and disk name must be the same in Windows.
#ifdef CONFIG_MULTI_PLATFORM
		if (strcmp(vol->platform, "windows") == 0) {
			if (vol->disk != NULL && vol->device != NULL && strcmp(vol->disk, vol->device) != 0){
				err("The device(%s) and disk(%s) letters must be the same. Please check again.\n", vol->device, vol->disk);
				exit(E_CONFIG_INVALID);
			}
		}
#else
#ifdef _WIN
		if (vol->disk != NULL && vol->device != NULL && strcmp(vol->disk, vol->device) != 0){
			err("The device(%s) and disk(%s) letters must be the same. Please check again.\n", vol->device, vol->disk);
			exit(E_CONFIG_INVALID);
		}
#endif
#endif
		vol->parsed_device = 1;
		vol->v_device_line = fline;
		break;
	case TK_META_DISK:
		parse_meta_disk(vol);
		vol->parsed_meta_disk = 1;
		vol->v_meta_disk_line = fline;
		break;
	case TK_FLEX_META_DISK:
		EXP(TK_STRING);
		vol->meta_disk = yylval.txt;
		if (strcmp("internal", yylval.txt) != 0) {
			/* external, flexible ize */
			vol->meta_index = strdup("flexible");
		} else {
			/* internal, flexible size */
			vol->meta_index = strdup("internal");
		}
		EXP(';');
		vol->parsed_meta_disk = 1;
		vol->v_meta_disk_line = fline;
		break;
	case TK_SKIP:
		parse_skip();
		break;
	default:
		return 0;
	}
	return 1;
}

struct d_volume *parse_volume(int vnr, struct names* on_hosts, char * platform)
{
	struct d_volume *vol;
	int token;

	vol = alloc_volume();
	vol->device_minor = -1;
	vol->vnr = vnr;

#ifdef CONFIG_MULTI_PLATFORM
	if (platform != NULL) {
		vol->platform = platform;
	} else {
#ifdef _WIN
		vol->platform = strdup("windows");
#else // _LIN
		vol->platform = strdup("linux");
#endif
	}
#endif
	EXP('{');
	while (1) {
		token = yylex();
		if (token == '}')
			break;
		if (!parse_volume_stmt(vol, on_hosts, token))
			pe_expected_got("device | disk | meta-disk | flex-meta-disk | }",
					token);
	}

	return vol;
}

struct d_volume *parse_stacked_volume(int vnr)
{
	struct d_volume *vol;
	int token;

	vol = alloc_volume();
	vol->device_minor = -1;
	vol->vnr = vnr;

	EXP('{');
	while (1) {
		token = yylex();
		switch (token) {
		case TK_DEVICE:
			parse_device(NULL, vol);
			break;
		case TK_DISK:
			EXP('{');
			parse_disk_options(&vol->disk_options, &vol->pd_options);
			break;
		case '}':
			goto exit_loop;
		default:
			pe_expected_got("device | disk | }", token);
			break;
		}
	}
exit_loop:
	vol->meta_disk = strdup("internal");
	vol->meta_index = strdup("internal");

	return vol;
}

enum parse_host_section_flags {
	REQUIRE_MINOR = 1,
	BY_ADDRESS  = 2,
};

static void parse_host_section(struct d_resource *res,
			       struct names *on_hosts,
			       enum parse_host_section_flags flags,
				   char *platform)
{
	struct d_host_info *host;
	struct d_name *h;
	struct d_group_info *group;
	int in_braces = 1;
	char *address = NULL;

	c_section_start = line;
	fline = line;

	host = calloc(1,sizeof(struct d_host_info));
	// BSR-718
	STAILQ_INIT(&host->node_options);
	STAILQ_INIT(&host->volumes);
	host->on_hosts = *on_hosts;
	host->config_line = c_section_start;
	host->implicit = 0;
	host->require_minor = flags & REQUIRE_MINOR ? 1 : 0;

#ifdef CONFIG_MULTI_PLATFORM
	if (platform != NULL)
		host->platform = platform;
#endif
	if (flags & BY_ADDRESS) {
		/* floating <address> {} */
		char *fake_uname = NULL;
		int token;

		host->by_address = 1;
		__parse_address(&host->address);
		if (!strcmp(host->address.af, "ipv6"))
			m_asprintf(&fake_uname, "ipv6 [%s]:%s", host->address.addr, host->address.port);
		else
			m_asprintf(&fake_uname, "%s:%s", host->address.addr, host->address.port);

		insert_head(&host->on_hosts, names_from_str(fake_uname));
		CLI_TRAC_LOG(false, "BY_ADDRESS(TK_FLOATING), %s, %s", res->name, fake_uname);

		token = yylex();
		switch(token) {
		case '{':
			break;
		case ';':
			in_braces = 0;
			break;
		default:
			pe_expected_got("{ | ;", token);
		}
	}

	STAILQ_FOREACH(h, on_hosts, link)
		check_upr("host section", "%s: on %s", res->name, h->name);
	insert_tail(&res->all_hosts, host);

	while (in_braces) {
		int token = yylex();
		fline = line;
		switch (token) {
		case TK_DISK:
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("disk statement", "%s:%s:disk", res->name, h->name);
			goto vol0stmt;
			/* STAILQ_FOREACH(h, on_hosts)
			  check_uniq("disk", "disk:%s:%s", h->name, yylval.txt); */
		case TK_DEVICE:
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("device statement", "%s:%s:device", res->name, h->name);
			goto vol0stmt;
		case TK_META_DISK:
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("meta-disk statement", "%s:%s:meta-disk", res->name, h->name);
			goto vol0stmt;
		case TK_FLEX_META_DISK:
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("meta-disk statement", "%s:%s:meta-disk", res->name, h->name);
			goto vol0stmt;
			break;
			// BSR-1433
		case TK_PUBLIC_ADDRESS:
			parse_address(on_hosts, &host->public_address);
			range_check(R_PORT, "port", host->public_address.port);
			address = NULL;
			if (!strcmp(host->public_address.af, "ipv6"))
				m_asprintf(&address, "ipv6 [%s]:%s", host->public_address.addr, host->public_address.port);
			else
				m_asprintf(&address, "%s:%s", host->public_address.addr, host->public_address.port);
			CLI_TRAC_LOG(false, "%s, %s, public %s", host->require_minor ? "TK_ON" : "TK__THIS_HOST", res->name, address);
			break;
		case TK_ADDRESS:
			if (host->by_address) {
				err("%s:%d: address statement not allowed for floating {} host sections\n",
				    config_file, fline);
				config_valid = 0;
				exit(E_CONFIG_INVALID);
			}
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("address statement", "%s:%s:address", res->name, h->name);
			parse_address(on_hosts, &host->address);
			range_check(R_PORT, "port", host->address.port);

			address = NULL;
			if (!strcmp(host->address.af, "ipv6"))
				m_asprintf(&address, "ipv6 [%s]:%s", host->address.addr, host->address.port);
			else
				m_asprintf(&address, "%s:%s", host->address.addr, host->address.port);
			CLI_TRAC_LOG(false, "%s, %s, %s", host->require_minor ? "TK_ON" : "TK__THIS_HOST", res->name, address);
			break;
		case TK_PROXY:
			host->proxy_compat_only = parse_proxy_section();
			break;
		case TK_VOLUME:
			EXP(TK_INTEGER);
			insert_volume(&host->volumes, parse_volume(atoi(yylval.txt), on_hosts, platform));
			break;
		case TK_NODE_ID:
			EXP(TK_INTEGER);
			range_check(R_NODE_ID, "node-id", yylval.txt);
			host->node_id = yylval.txt;
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("node-id statement", "%s:%s:node-id", res->name, h->name);
			// BSR-1409 duplicate node ID comparisons are performed during post-parsing to handle exceptions within the same group.
#if 0 
			check_upr("node-id", "%s:%s", res->name, host->node_id);
#endif
			EXP(';');
			break;
		case TK_OPTIONS:
			EXP('{');
			// BSR-718
			host->node_options = parse_options(&node_options_ctx);
			break;
		case TK_SKIP:
			parse_skip();
			break;
		// BSR-859 parsing node name from show output, set to node_name of host.
		// this is necessary to know that the node name has changed.
		case TK_NODE_NAME:
			EXP(TK_STRING);
			host->node_name = yylval.txt;
			EXP(';');
			break;
		// BSR-1409 create a group and set up a host for the group
		case TK_GROUP:
			EXP(TK_STRING);
			bool already_group = false;
			struct d_host_info *host_info;

			host->group = yylval.txt;
			for_each_group(group, &res->all_groups) {
				if(group->name && !strcmp(group->name, host->group)) {
					insert_link_tail(&group->members, host, group_link);
					CLI_TRAC_LOG(false, "INSERT_TAIL, %s, already group %s, hosts %s", res->name, group->name, STAILQ_FIRST(&host->on_hosts)->name);
					already_group = true;
					break;
				}
			}
			if(!already_group) {
				group = calloc(1,sizeof(struct d_group_info));
				STAILQ_INIT(&group->members);
				group->name = host->group;
				insert_link_tail(&group->members, host, group_link);
				CLI_TRAC_LOG(false, "INSERT_TAIL, %s, new group %s, hosts %s", res->name, group->name, STAILQ_FIRST(&host->on_hosts)->name);
				
				insert_tail(&res->all_groups, group);
			}
			EXP(';');
			break;
		case '}':
			in_braces = 0;
			break;
		vol0stmt:
			if (parse_volume_stmt(volume0(&host->volumes, host->platform), on_hosts, token))
				break;
			/* else fall through */
		default:
			pe_expected("disk | device | address | meta-disk "
				    "| flexible-meta-disk | node-id | skip");
		}
	}
}

static void parse_skip()
{
	int level = 0;
	int token;
	fline = line;

	while ((token = yylex())) {
		switch(token) {
		case '{':
			level++;
			break;
		case '}':
			if (!--level)
				return;
			break;
		}
	}
	if (!token) {
		err("%s:%u: reached eof ""while parsing this skip block.\n",
		    config_file, fline);
		exit(E_CONFIG_INVALID);
	}
}

void parse_stacked_section(struct d_resource* res)
{
	struct d_host_info *host;
	struct d_name *h;

	c_section_start = line;
	fline = line;

	host = calloc(1, sizeof(struct d_host_info));
	// BSR-718
	STAILQ_INIT(&host->node_options);
	STAILQ_INIT(&host->on_hosts);
	STAILQ_INIT(&host->volumes);
	insert_tail(&res->all_hosts, host);
	EXP(TK_STRING);
	check_uniq("stacked-on-top-of", "stacked:%s", yylval.txt);
	host->lower_name = yylval.txt;

	EXP('{');
	while (1) {
		switch(yylex()) {
		case TK_DEVICE:
			/* STAILQ_FOREACH(h, host->on_hosts)
			  check_upr("device statement", "%s:%s:device", res->name, h->name); */
			parse_device(&host->on_hosts, volume0(&host->volumes, NULL));
			volume0(&host->volumes, NULL)->meta_disk = strdup("internal");
			volume0(&host->volumes, NULL)->meta_index = strdup("internal");
			break;
		case TK_ADDRESS:
			STAILQ_FOREACH(h, &host->on_hosts, link)
				check_upr("address statement", "%s:%s:address", res->name, h->name);
			parse_address(NULL, &host->address);
			range_check(R_PORT, "port", yylval.txt);
			break;
		case TK_PROXY:
			host->proxy_compat_only = parse_proxy_section();
			break;
		case TK_VOLUME:
			EXP(TK_INTEGER);
			insert_volume(&host->volumes, parse_stacked_volume(atoi(yylval.txt)));
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("device | address | proxy");
		}
	}
 break_loop:

	res->stacked_on_one = 1;
}

void startup_delegate(void *ctx)
{
	struct d_resource *res = (struct d_resource *)ctx;

	if (!strcmp(yytext, "become-primary-on")) {
		/* err("Warn: Ignoring deprecated become-primary-on. Use automatic-promote\n"); */
		int token;
		do {
			token = yylex();
		} while (token != ';');
	} else if (!strcmp(yytext, "stacked-timeouts")) {
		res->stacked_timeouts = 1;
		EXP(';');
	} else
		pe_expected("<an option keyword> | become-primary-on | stacked-timeouts");
}

void net_delegate(void *ctx)
{
	enum pr_flags flags = (enum pr_flags)ctx;

	if (!strcmp(yytext, "discard-my-data") && flags & PARSE_FOR_ADJUST) {
		switch(yylex()) {
		case TK_YES:
		case TK_NO:
			/* Ignore this option.  */
			EXP(';');
			break;
		case ';':
			/* Ignore this option.  */
			return;
		default:
			pe_expected("yes | no | ;");
		}
	} else
		pe_expected("an option keyword");
}

void proxy_delegate(void *ctx)
{
	struct options *proxy_plugins = (struct options *)ctx;
	int token;
	struct options options = STAILQ_HEAD_INITIALIZER(options);
	struct d_option *opt;
	struct names line;
	struct d_name *word;

	opt = NULL;
	token = yylex();
	if (token != '{') {
		err("%s:%d: expected \"{\" after \"proxy\" keyword\n",
		    config_file, fline);
		exit(E_CONFIG_INVALID);
	}

	while (1) {
		STAILQ_INIT(&line);
		while (1) {
			yylval.txt = NULL;
			token = yylex();
			if (token == ';')
				break;
			if (token == '}') {
				if (STAILQ_EMPTY(&line))
					goto out;

				err("%s:%d: Missing \";\" before  \"}\"\n",
				    config_file, fline);
				exit(E_CONFIG_INVALID);
			}

			word = malloc(sizeof(struct d_name));
			if (!word)
				pdperror("out of memory.");
			word->name = yylval.txt ? yylval.txt : strdup(yytext);
			insert_tail(&line, word);
		}

		opt = calloc(1, sizeof(struct d_option));
		if (!opt)
			pdperror("out of memory.");
		opt->name = strdup(names_to_str(&line));
		insert_tail(&options, opt);
		free_names(&line);
	}
out:
	if (proxy_plugins)
		*proxy_plugins = options;
}

static int parse_proxy_options(struct options *proxy_options, struct options *proxy_plugins)
{
	struct options opts;

	EXP('{');
	opts = __parse_options(&proxy_options_ctx,
			       proxy_delegate, proxy_plugins);

	if (proxy_options)
		*proxy_options = opts;

	return 0;
}

int parse_proxy_options_section(struct d_proxy_info **pp)
{
	int token;
	struct d_proxy_info *proxy;

	proxy = *pp ? *pp : calloc(1, sizeof(struct d_proxy_info));
	token = yylex();
	if (token != TK_PROXY) {
		yyrestart(yyin); /* flushes flex's buffers */
		return 1;
	}

	return parse_proxy_options(&proxy->options, &proxy->plugins);
}

static struct hname_address *parse_hname_address_pair(struct path *path, int prev_token)
{
	struct hname_address *ha;
	int token;

	ha = calloc(1, sizeof(struct hname_address));
	ha->config_line = line;

	switch (prev_token) {
	case TK_ADDRESS:
		ha->name = "UNKNOWN"; /* updated in set_host_info_in_host_address_pairs() */
		ha->by_address = 1;
		goto parse_address;
	case TK__THIS_HOST:
		ha->name = "_this_host";
		path->my_address = &ha->address;
		goto parse_address;
	case TK__REMOTE_HOST:
		ha->name = "_remote_host";
		path->connect_to = &ha->address;
		goto parse_address;
	// BSR-1409
	case TK_GROUP:
		break;
	default:
		assert(0);
	case TK_HOST:
		break;
	}

	EXP(TK_STRING);
	// BSR-1409
	if(prev_token == TK_GROUP)
		// BSR-1522
		ha->name = ha->group = yylval.txt;
	else 
		ha->name = yylval.txt;

	token = yylex();
	switch (token) {
	case TK_ADDRESS:
	parse_address:
		__parse_address(&ha->address);
		ha->parsed_address = 1;
		goto parse_optional_via;
	case TK_PORT:
		EXP(TK_INTEGER);
		ha->address.port = yylval.txt;
		ha->parsed_port = 1;

	parse_optional_via:
		token = yylex();
		if (token == TK_VIA) {
			EXP(TK_PROXY);
			ha->proxy = parse_proxy_section();
			// BSR-1409
			if(prev_token == TK_GROUP)
				ha->proxy->group = ha->group;
		} 
		// BSR-1433
		else if (token == TK_PUBLIC_ADDRESS) {
            __parse_address(&ha->public_address);
            path->connect_to = &ha->public_address;
            goto parse_optional_via;
		} else if (token != ';')
			pe_expected_got( "via | public-address | ; ", token);
		break;
	case TK_VIA:
		EXP(TK_PROXY);
		ha->proxy = parse_proxy_section();
		// BSR-1409
		if(prev_token == TK_GROUP)
			ha->proxy->group = ha->group;
		break;
	case ';':
		break;
	default:
		pe_expected_got( "address | port | ;", token);
	}

	return ha;
}

struct connection *alloc_connection()
{
	struct connection *conn;

	conn = calloc(1, sizeof(struct connection));
	if (conn == NULL) {
		err("calloc: %m\n");
		exit(E_EXEC_ERROR);
	}
	STAILQ_INIT(&conn->paths);
	STAILQ_INIT(&conn->net_options);
	STAILQ_INIT(&conn->peer_devices);
	STAILQ_INIT(&conn->pd_options);

	return conn;
}

void free_connection(struct connection *connection)
{
	free(connection);
}

struct peer_device *alloc_peer_device()
{
	struct peer_device *peer_device;

	peer_device = calloc(1, sizeof(*peer_device));
	if (!peer_device)  {
		err("calloc: %m\n");
		exit(E_EXEC_ERROR);
	}
	STAILQ_INIT(&peer_device->pd_options);

	return peer_device;
}

static struct peer_device *parse_peer_device(int vnr)
{
	struct peer_device *peer_device;

	peer_device = alloc_peer_device();
	peer_device->vnr = vnr;
	peer_device->config_line = line;

	EXP('{');
	EXP(TK_DISK);
	EXP('{');
	peer_device->pd_options = parse_options(&peer_device_options_ctx);
	EXP('}');

	return peer_device;
}

static struct d_host_info *parse_peer_node_id(void)
{
	struct d_host_info *host;

	host = calloc(1,sizeof(struct d_host_info));
	// BSR-718
	STAILQ_INIT(&host->node_options);
	STAILQ_INIT(&host->volumes);
	STAILQ_INIT(&host->on_hosts);

	host->config_line = c_section_start;
	host->implicit = 1;
	host->require_minor = 0;

	EXP(TK_INTEGER);
	range_check(R_NODE_ID, "node-id", yylval.txt);
	host->node_id = yylval.txt;
	EXP(';');

	return host;
}

struct path *alloc_path()
{
	struct path *path;

	path = calloc(1, sizeof(struct path));
	if (path == NULL) {
		err("calloc: %m\n");
		exit(E_EXEC_ERROR);
	}
	STAILQ_INIT(&path->hname_address_pairs);

	return path;
}

static struct path *path0(struct connection *conn)
{
	struct path *path = STAILQ_FIRST(&conn->paths);

	if (!path) {
		path = alloc_path();
		path->implicit = true;
		path->config_line = line;

		insert_tail(&conn->paths, path);
	} else {
		if (!path->implicit) {
			config_valid = 0;
			err("%s:%d: Explicit and implicit paths not allowed\n",
			    config_file, line);
		}
	}
	return path;
}

static struct path *parse_path()
{
	struct path *path;
	int hosts_or_group = 0, token;

	path = alloc_path();
	path->config_line = line;

	EXP('{');
	while (1) {
		token = yylex();
		switch(token) {
		case TK_ADDRESS:
		case TK_HOST:
		case TK__THIS_HOST:
		case TK__REMOTE_HOST:
			insert_tail(&path->hname_address_pairs, parse_hname_address_pair(path, token));
			if (++hosts_or_group >= 3) {
				err("%s:%d: only two 'host' or 'group' keywords per connection allowed\n",
				    config_file, fline);
				config_valid = 0;
			}
			break;
		// BSR-1409 
		case TK_GROUP:
			insert_tail(&path->hname_address_pairs, parse_hname_address_pair(path, token));
			if (++hosts_or_group >= 3) {
				err("%s:%d: only two 'host' or 'group' keywords per connection allowed\n",
				    config_file, fline);
				config_valid = 0;
			}
			break;
		case '}':
			return path;
		default:
			pe_expected_got( "host | }", token);
		}
	}
}

static struct connection *parse_connection(enum pr_flags flags)
{
	struct connection *conn;
	struct peer_device *peer_device;
	int hosts_or_group = 0, token;
	struct path *path;
	char *group;

	conn = alloc_connection();
	conn->config_line = line;

	token = yylex();
	switch (token) {
	case '{':
		break;
	case TK_STRING:
		conn->name = yylval.txt;
		EXP('{');
		break;
	default:
		pe_expected_got( "<connection name> | {", token);
	}
	while (1) {
		token = yylex();
		switch(token) {
		case TK_ADDRESS:
		case TK_HOST:
		case TK__THIS_HOST:
		case TK__REMOTE_HOST:
			path = path0(conn);
			insert_tail(&path->hname_address_pairs, parse_hname_address_pair(path, token));
			if (++hosts_or_group >= 3) {
				err("%s:%d: only two 'host' or 'group' keywords per connection allowed\n",
				    config_file, fline);
				config_valid = 0;
			}
			break;
			// BSR-1409
		case TK__PEER_NODE_GROUP:
			EXP(TK_STRING);
			group = yylval.txt;
			if(strcmp(group, "")) 
				conn->peer->group = group;
			EXP(';');
			break;
			// BSR-1409 if the address is not set in the connection section, it will be set later by parse_hname_address_from_group_pair().
		case TK_GROUP:
			path = path0(conn);
			insert_tail(&path->hname_address_pairs, parse_hname_address_pair(path, token));
			if (++hosts_or_group >= 3) {
				err("%s:%d: only two 'host' or 'group' keywords per connection allowed\n",
				    config_file, fline);
				config_valid = 0;
			}
			break;
		case TK__PEER_NODE_ID:
			conn->peer = parse_peer_node_id();
			break;
		// BSR-859 parsing peer node name from show output, set to node_name of peer host.
		// this is necessary to know that the peer node name has changed.
		case TK__PEER_NODE_NAME:
			EXP(TK_STRING);
			conn->peer->node_name = yylval.txt;
			EXP(';');
			break;
		case TK_NET:
			if (!STAILQ_EMPTY(&conn->net_options)) {
				err("%s:%d: only one 'net' section per connection allowed\n",
				    config_file, fline);
				config_valid = 0;
			}
			EXP('{');
			conn->net_options = __parse_options(&show_net_options_ctx,
							    &net_delegate, (void *)flags);
			break;
		case TK_SKIP:
			parse_skip();
			break;
		case TK_DISK:
			EXP('{');
			conn->pd_options = parse_options(&peer_device_options_ctx);
			break;
		case TK_VOLUME:
			EXP(TK_INTEGER);
			peer_device = parse_peer_device(atoi(yylval.txt));
			peer_device->connection = conn;
			CLI_TRAC_LOG(false, "INSERT_TAIL, peer_devcies, vnr : %d", peer_device->vnr);
			STAILQ_INSERT_TAIL(&conn->peer_devices, peer_device, connection_link);
			break;
		case TK__IS_STANDALONE:
			conn->is_standalone = 1;
			EXP(';');
			break;
		case TK_PATH:
			insert_tail(&conn->paths, parse_path());
			break;
		case '}':
			if (STAILQ_EMPTY(&conn->paths) && !(flags & PARSE_FOR_ADJUST)) {
				err("%s:%d: connection without a single path (maybe empty?) not allowed\n",
					config_file, fline);
				config_valid = 0;
			}
			return conn;
		default:
			pe_expected_got( "host | net | skip | }", token);
		}
	}
}

void parse_connection_mesh(struct d_resource *res, enum pr_flags flags)
{
	struct mesh *mesh;
	int token;

	EXP('{');
	mesh = calloc(1, sizeof(struct mesh));
	STAILQ_INIT(&mesh->hosts);
	STAILQ_INIT(&mesh->groups);
	STAILQ_INIT(&mesh->net_options);

	while (1) {
		token = yylex();
		switch(token) {
		case TK_HOSTS:
			parse_hosts(&mesh->hosts, ';');
			break;
		// BSR-1409
		case TK_GROUPS:
			parse_groups(&mesh->groups, ';');
			break;
		case TK_NET:
			if (!STAILQ_EMPTY(&mesh->net_options)) {
				err("%s:%d: only one 'net' section allowed\n",
				    config_file, fline);
				config_valid = 0;
			}
			EXP('{');
			mesh->net_options =
				__parse_options(&show_net_options_ctx,
						&net_delegate,
						(void *)flags);
			break;
		case '}':
			insert_tail(&res->meshes, mesh);
			return;
		default:
			pe_expected_got( "hosts | net | }", token);
		}
	}
}

struct d_resource* parse_resource(char* res_name, enum pr_flags flags)
{
	struct field_def *proto_f;
	char *proto_v;
	struct d_resource* res;
	struct names host_names;
	struct options options;
	int token;
	char *platform = NULL;

	check_upr_init();
	check_uniq("resource section", res_name);

	res = calloc(1, sizeof(struct d_resource));
	STAILQ_INIT(&res->volumes);
	STAILQ_INIT(&res->connections);
	STAILQ_INIT(&res->all_hosts);
	// BSR-1409
	STAILQ_INIT(&res->all_groups);
	STAILQ_INIT(&res->net_options);
	STAILQ_INIT(&res->disk_options);
	STAILQ_INIT(&res->pd_options);
	STAILQ_INIT(&res->res_options);
	// BSR-718
	STAILQ_INIT(&res->node_options);
	STAILQ_INIT(&res->startup_options);
	STAILQ_INIT(&res->handlers);
	STAILQ_INIT(&res->proxy_options);
	STAILQ_INIT(&res->proxy_plugins);
	STAILQ_INIT(&res->meshes);
	res->name = res_name;
	res->config_file = config_save;
	res->start_line = line;

	while(1) {
		token = yylex();
		fline = line;
		platform = NULL;
		switch (token) {
		case TK_STRING:
			if (strcmp(yylval.txt, "protocol"))
				goto goto_default;
			check_upr("protocol statement","%s: protocol",res->name);
			proto_f = find_field(NULL, &net_options_ctx, yylval.txt);
			proto_v = parse_option_value(proto_f, false);
			insert_tail(&res->net_options, new_opt((char *)proto_f->name, proto_v));
			break;
#ifdef CONFIG_MULTI_PLATFORM
		case TK_ON_WINDOWS:
			platform = strdup("windows");
			goto parse_on_hosts;
		case TK_ON_LINUX:
			platform = strdup("linux");
#endif
		case TK_ON:
		parse_on_hosts:
			STAILQ_INIT(&host_names);
			parse_hosts(&host_names, '{');
			parse_host_section(res, &host_names, REQUIRE_MINOR, platform);
			break;
		case TK_STACKED:
			parse_stacked_section(res);
			break;
		case TK__THIS_HOST:
			EXP('{');
			STAILQ_INIT(&host_names);
			insert_head(&host_names, names_from_str("_this_host"));
			parse_host_section(res, &host_names, 0, NULL);
			break;
#ifdef CONFIG_MULTI_PLATFORM
		case TK_FLOATING_WINDOWS:
			platform = strdup("windows");
			goto parse_floating_host;
		case TK_FLOATING_LINUX:
			platform = strdup("linux");
#endif
		case TK_FLOATING:
		parse_floating_host:
			STAILQ_INIT(&host_names);
			parse_host_section(res, &host_names, REQUIRE_MINOR + BY_ADDRESS, platform);
			break;
		case TK_DISK:
			switch (token=yylex()) {
			case TK_STRING:{
				/* open coded parse_volume_stmt() */
				struct d_volume *vol = volume0(&res->volumes, NULL);
				vol->disk = yylval.txt;
				vol->parsed_disk = 1;
#ifdef _WIN   // DW-1451 Device name and disk name must be the same in Windows. 			
				if (vol->disk != NULL && vol->device != NULL && strcmp(vol->disk, vol->device) != 0){
					err("The device(%s) and disk(%s) letters must be the same. Please check again.\n", vol->device, vol->disk);
					exit(E_CONFIG_INVALID);
				}
#endif 
				}
				EXP(';');				
				break;
			case '{':
				check_upr("disk section", "%s:disk", res->name);
				parse_disk_options(&options, &res->pd_options);
				STAILQ_CONCAT(&res->disk_options, &options);
				break;
			default:
				check_string_error(token);
				pe_expected_got("TK_STRING | {", token);
			}
			break;
		case TK_NET:
			check_upr("net section", "%s:net", res->name);
			EXP('{');
			options = __parse_options(&show_net_options_ctx,
						  &net_delegate, (void *)flags);

			STAILQ_CONCAT(&res->net_options, &options);
			break;
		case TK_SYNCER:
			check_upr("syncer section", "%s:syncer", res->name);
			EXP('{');
			parse_options_syncer(res);
			break;
		case TK_STARTUP:
			check_upr("startup section", "%s:startup", res->name);
			EXP('{');
			res->startup_options = __parse_options(&startup_options_ctx,
							       &startup_delegate,
							       res);
			break;
		case TK_HANDLER:
			check_upr("handlers section", "%s:handlers", res->name);
			EXP('{');
			res->handlers = parse_options(&handlers_ctx);
			break;
		case TK_PROXY:
			check_upr("proxy section", "%s:proxy", res->name);
			parse_proxy_options(&res->proxy_options, &res->proxy_plugins);
			break;
		case TK_DEVICE:
			check_upr("device statement", "%s:device", res->name);
		case TK_META_DISK:
		case TK_FLEX_META_DISK:
			parse_volume_stmt(volume0(&res->volumes, NULL), NULL, token);
			break;
		case TK_VOLUME:
			EXP(TK_INTEGER);
			insert_volume(&res->volumes, parse_volume(atoi(yylval.txt), NULL, NULL));
			break;
		case TK_OPTIONS:
			check_upr("resource options section", "%s:res_options", res->name);
			EXP('{');
			// BSR-718
			parse_res_options(&options, &res->node_options);
			STAILQ_CONCAT(&res->res_options, &options);
			break;
		case TK_CONNECTION:
			insert_tail(&res->connections, parse_connection(flags));
			break;
		case TK_CONNECTION_MESH:
			parse_connection_mesh(res, flags);
			break;
		case TK_TEMPLATE_FILE:
			res->template = template_file(res_name);
			break;
		case TK_SKIP:
			parse_skip();
			break;
		case '}':
		case 0:
			goto exit_loop;
		default:
		goto_default:
#ifdef CONFIG_MULTI_PLATFORM
			pe_expected_got("protocol | disk | net | syncer |"
					" on | on-windows | on-linux | floating | floating-on-windows | floating-on-linux |"
					" startup | handlers | connection |"
					" ignore-on | skip",token);
#else
			pe_expected_got("protocol | on | disk | net | syncer |"
					" startup | handlers | connection |"
					" ignore-on | stacked-on-top-of | skip",token);
#endif
		}
	}

 exit_loop:

	if (flags == NO_HOST_SECT_ALLOWED && !STAILQ_EMPTY(&res->all_hosts)) {
		config_valid = 0;

		err("%s:%d: in the %s section, there are no host sections allowed.\n",
		    config_file, c_section_start, res->name);
	}

	return res;
}

/* Returns the "previous" count, ie. 0 if this file wasn't seen before. */
int was_file_already_seen(char *fn)
{
	ENTRY *e;
	char *real_path;

	e = calloc(1, sizeof *e);
	if (!e) {
		err("calloc %m\n");
		exit(E_THINKO);
	}

	real_path = realpath(fn, NULL);
	if (!real_path) {
		real_path = strdup(fn);
		if (!real_path) {
			err("strdup %m");
			free(e);
			exit(E_THINKO);
		}
	}


	e->key = real_path;
	e->data = real_path;
	if (tfind(e, &global_btree, btree_key_cmp)) {
		/* Can be freed, it's just a queried key. */
		free(real_path);
		free(e);
		return 1;
	}

	if (!tsearch(e, &global_btree, btree_key_cmp)) {
		err("tree entry (%s => %s) failed\n", e->key, (char *)e->data);
		free(real_path);
		free(e);
		exit(E_THINKO);
	}

	/* Must not be freed, because it's still referenced by the binary tree. */
	/* free(real_path); */

	return 0;
}

/* In order to allow relative paths in include statements we change
 * directory to the location of the current configuration file.
 * Before we start parsing, we canonicalize the full path name stored in
 * config_save, which means config_save always contains at least one slash.
 * Unless we are currently parsing STDIN (then it is the fixed string STDIN).
 */
static int pushd_to_current_config_file_unless_stdin(void)
{
	char *last_slash, *tmp;

	/* config_save was canonicalized before, unless it is STDIN */
#ifdef _WIN
    tmp = strdupa(config_file);
    if (strncmp(tmp, "/", strlen("/")) == 0) {
        last_slash = strrchr(tmp, '/');
    }
    else {
        last_slash = strrchr(tmp, '\\');
    }
#else // _LIN
	tmp = strdupa(config_save);
	last_slash = strrchr(tmp, '/');
#endif
	if (!last_slash)
		/* Currently parsing stdin, stay where we are.
		 * FIXME introduce BSR_INCLUDE_PATH?
		 * I don't feel comfortable "trusting" the current directory
		 * for relative include file paths.
		 */
		return -1;

	/* If last_slash == tmp, config_save is in the top level directory. */
	if (last_slash == tmp)
		tmp = "/";
	else
		*last_slash = 0;

	return pushd(tmp);
}

static struct d_resource *template_file(const char *res_name)
{
	struct d_resource *template = NULL;
	char *file_name;
	FILE *f;
	int cwd;

	cwd = pushd_to_current_config_file_unless_stdin();

	EXP(TK_STRING);
	file_name = yylval.txt;
	EXP(';');

	f = fopen(file_name, "re");
	if (f) {
		struct include_file_buffer buffer;
		char *tn = ssprintf("template-%s", res_name);

		save_parse_context(&buffer, f, file_name);

		EXP(TK_COMMON);
		EXP('{');
		template = parse_resource(tn, NO_HOST_SECT_ALLOWED);

		restore_parse_context(&buffer);
		fclose(f);
	} else {
		err("%s:%d: Failed to open template file '%s'.\n",
		    config_save, line, file_name);
		config_valid = 0;
	}

	popd(cwd);

	return template;
}

void include_stmt(char *str)
{
	glob_t glob_buf;
	int cwd;
	FILE *f;
	size_t i;
	int r;

	cwd = pushd_to_current_config_file_unless_stdin();

	r = glob(str, 0, NULL, &glob_buf);
	if (r == 0) {
		for (i=0; i<glob_buf.gl_pathc; i++) {
			if (was_file_already_seen(glob_buf.gl_pathv[i]))
				continue;

			f = fopen(glob_buf.gl_pathv[i], "re");
			if (f) {
				include_file(f, strdup(glob_buf.gl_pathv[i]));
				fclose(f);
			} else {
                err("%s:%d: Failed to open include file 1 '%s'.\n",
					parse_file, line, glob_buf.gl_pathv[i]);
				config_valid = 0;
			}
		}
		globfree(&glob_buf);
	} else if (r == GLOB_NOMATCH) {
		if (!strchr(str, '?') && !strchr(str, '*') && !strchr(str, '[')) {
            err("%s:%d: Failed to open include file '%s'.\n",
                parse_file, line, str);
			config_valid = 0;
		}
	} else {
		err("glob() failed: %d\n", r);
		exit(E_USAGE);
	}

	popd(cwd);
}

void my_parse(void)
{
	/* Remember that we're reading that file. */
	was_file_already_seen(config_file);


	while (1) {
		int token = yylex();
		fline = line;
		switch (token) {
		case TK_GLOBAL:
			parse_global();
			break;
		case TK_COMMON:
			EXP('{');
			common = parse_resource("common",NO_HOST_SECT_ALLOWED);
			break;
		case TK_RESOURCE:
			EXP(TK_STRING);
			ensure_sanity_of_res_name(yylval.txt);
			EXP('{');
			insert_tail(&config, parse_resource(yylval.txt, 0));
			break;
		case TK_SKIP:
			parse_skip();
			break;
		case TK_INCLUDE:
			EXP(TK_STRING);
			EXP(';');
			include_stmt(yylval.txt);
			break;
		case 0:
			return;
		default:
			pe_expected("global | common | resource | skip | include");
		}
	}
}

int check_uniq(const char *what, const char *fmt, ...)
{
	int rv;
	va_list ap;

	va_start(ap, fmt);
	rv = vcheck_uniq(&global_btree, what, fmt, ap);
	va_end(ap);

	return rv;
}

int check_uniq_file_line(const char *file, const int line, const char *what, const char *fmt, ...)
{
	int rv;
	va_list ap;

	va_start(ap, fmt);
	rv = vcheck_uniq_file_line(file, line, &global_btree, what, fmt, ap);
	va_end(ap);

	return rv;
}

/* unique per resource */
int check_upr(const char *what, const char *fmt, ...)
{
	int rv;
	va_list ap;

	va_start(ap, fmt);
	rv = vcheck_uniq(&per_resource_btree, what, fmt, ap);
	va_end(ap);

	return rv;
}
