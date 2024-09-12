/*
   shared_main.c

   This file is part of BSR by Man Technology inc.

   Copyright (C) 2014, Man Technology inc.

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


#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <search.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef _LIN
#include <sys/prctl.h>
#include <linux/sockios.h>
#include <linux/netdevice.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>

#include "bsr_endian.h"
#include "shared_main.h"
#include "shared_tool.h"
#include "bsrtool_common.h"

struct d_globals global_options = {

	.cmd_timeout_short = CMD_TIMEOUT_SHORT_DEF,
	.cmd_timeout_medium = CMD_TIMEOUT_MEDIUM_DEF,
	.cmd_timeout_long = CMD_TIMEOUT_LONG_DEF, // DW-817 wrong initialization.
	.dialog_refresh = 1,
	.usage_count = UC_ASK,
	// BSR-1387
	.disable_ip_verification = 0,
	.hostname = NULL,
};

void chld_sig_hand(int __attribute((unused)) unused)
{
	// do nothing. But interrupt systemcalls :)
}

unsigned minor_by_id(const char *id)
{
	if (strncmp(id, "minor-", 6))
		return -1U;
	return m_strtoll(id + 6, 1);
}

/*
 * I'd really rather parse the output of
 *   ip -o a s
 * once, and be done.
 * But anyways....
 */

struct ifreq *get_ifreq(void) {
	int sockfd, num_ifaces;
	struct ifreq *ifr;
	struct ifconf ifc;
	size_t buf_size;

	if (0 > (sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))) {
		CLI_ERRO_LOG_PEEROR(false, "Cannot open socket");
		exit(EXIT_FAILURE);
	}

	num_ifaces = 0;
	ifc.ifc_req = NULL;

	/* realloc buffer size until no overflow occurs  */
	do {
		num_ifaces += 16;	/* initial guess and increment */
		buf_size = ++num_ifaces * sizeof(struct ifreq);
		ifc.ifc_len = buf_size;
		if (NULL == (ifc.ifc_req = realloc(ifc.ifc_req, ifc.ifc_len))) {
			CLI_ERRO_LOG_STDERR(false,  "Out of memory.");
			return NULL;
		}
		if (ioctl(sockfd, SIOCGIFCONF, &ifc)) {
			CLI_ERRO_LOG_PEEROR(false, "ioctl SIOCFIFCONF");
			free(ifc.ifc_req);
			return NULL;
		}
	} while (buf_size <= (size_t) ifc.ifc_len);

	num_ifaces = ifc.ifc_len / sizeof(struct ifreq);
	/* Since we allocated at least one more than necessary,
	 * this serves as a stop marker for the iteration in
	 * have_ip() */
	ifc.ifc_req[num_ifaces].ifr_name[0] = 0;
	for (ifr = ifc.ifc_req; ifr->ifr_name[0] != 0; ifr++) {
		/* we only want to look up the presence or absence of a certain address
		 * here. but we want to skip "down" interfaces.  if an interface is down,
		 * we store an invalid sa_family, so the lookup will skip it.
		 */
		struct ifreq ifr_for_flags = *ifr;	/* get a copy to work with */
		if (ioctl(sockfd, SIOCGIFFLAGS, &ifr_for_flags) < 0) {
			CLI_ERRO_LOG_PEEROR(false, "ioctl SIOCGIFFLAGS");
			ifr->ifr_addr.sa_family = -1;	/* what's wrong here? anyways: skip */
			continue;
		}
		if (!(ifr_for_flags.ifr_flags & IFF_UP)) {
			ifr->ifr_addr.sa_family = -1;	/* is not up: skip */
			continue;
		}

		struct sockaddr_in *list_addr =
			(struct sockaddr_in *)&ifr->ifr_addr;
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;

		CLI_TRAC_LOG(false, "ipv4 %s", inet_ntoa(list_addr->sin_addr));
	}
	close(sockfd);
	return ifc.ifc_req;
}

int have_ip_ipv4(const char *ip, struct ifreq *ifreq_list)
{
	struct ifreq *ifr;
	struct in_addr query_addr;

	query_addr.s_addr = inet_addr(ip);

	if (!ifreq_list)
		ifreq_list = get_ifreq();

	for (ifr = ifreq_list; ifr && ifr->ifr_name[0] != 0; ifr++) {
		/* SIOCGIFCONF only supports AF_INET */
		struct sockaddr_in *list_addr =
		    (struct sockaddr_in *)&ifr->ifr_addr;
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;
		if (query_addr.s_addr == list_addr->sin_addr.s_addr)
			return 1;
	}
	return 0;
}

int have_ip_ipv6(const char *ip)
{
	FILE *if_inet6;
	struct in6_addr addr6, query_addr;
	unsigned int b[4];
	char addr6_str[40];
	char tmp_ip[INET6_ADDRSTRLEN+1];
	char name[20]; /* IFNAMSIZ aka IF_NAMESIZE is 16 */
	int i;

	/* don't want to do getaddrinfo lookup, but inet_pton get's confused by
	 * %eth0 link local scope specifiers. So we have a temporary copy
	 * without that part. */
	for (i=0; ip[i] && ip[i] != '%' && i < INET6_ADDRSTRLEN; i++)
		tmp_ip[i] = ip[i];
	tmp_ip[i] = 0;

	if (inet_pton(AF_INET6, tmp_ip, &query_addr) <= 0)
		return 0;

#define PROC_IF_INET6 "/proc/net/if_inet6"
	if_inet6 = fopen(PROC_IF_INET6, "r");
	if (!if_inet6) {
		if (errno != ENOENT)
			CLI_ERRO_LOG_PEEROR(false, "open of " PROC_IF_INET6 " failed:");
#undef PROC_IF_INET6
		return 0;
	}

	while (fscanf
	       (if_inet6,
		X32(08) X32(08) X32(08) X32(08) " %*x %*x %*x %*x %s",
		b, b + 1, b + 2, b + 3, name) > 0) {
		for (i = 0; i < 4; i++)
			addr6.s6_addr32[i] = cpu_to_be32(b[i]);

		inet_ntop(AF_INET6, (void *)&addr6, addr6_str, sizeof(addr6_str));
		CLI_TRAC_LOG(false, "ipv6 %s", addr6_str);

		if (memcmp(&query_addr, &addr6, sizeof(struct in6_addr)) == 0) {
			fclose(if_inet6);
			return 1;
		}
	}
	fclose(if_inet6);
	return 0;
}

int have_ip(const char *af, const char *ip, struct ifreq *ifreq_list)
{
	CLI_TRAC_LOG(false, "af(%s), ip(%s)", af, ip);

	if (!strcmp(af, "ipv4"))
		return have_ip_ipv4(ip, ifreq_list);
	else if (!strcmp(af, "ipv6"))
		return have_ip_ipv6(ip);

	return 1;		/* SCI */
}

extern char *progname;
void substitute_deprecated_cmd(char **c, char *deprecated,
				      char *substitution)
{
	if (!strcmp(*c, deprecated)) {
		CLI_ERRO_LOG_STDERR(false,  "'%s %s' is deprecated, use '%s %s' instead.",
			progname, deprecated, progname, substitution);
		*c = substitution;
	}
}

pid_t my_fork(void)
{
	pid_t pid = -1;
	int try;
	for (try = 0; try < 10; try++) {
		errno = 0;
		pid = fork();
		if (pid != -1 || errno != EAGAIN)
			return pid;
		err("fork: retry: Resource temporarily unavailable\n");
		usleep(100 * 1000);
	}
	return pid;
}

void m__system(char **argv, int flags, const char *res_name, pid_t *kid, int *fd, int *ex, const char* sh_varname, int adjust_with_progress, int dry_run, int verbose)
{
	pid_t pid;
	int status, rv = -1;
	int timeout = 0;
	char **cmdline = argv;
	int pipe_fds[2];

	struct sigaction so;
	struct sigaction sa;

	if (flags & (RETURN_STDERR_FD | RETURN_STDOUT_FD))
		assert(fd);

	sa.sa_handler = &alarm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (dry_run || verbose) {
		if (sh_varname && *cmdline)
			printf("%s=%s\n", sh_varname,
					res_name ? shell_escape(res_name) : "");
		while (*cmdline) {
			printf("%s ", shell_escape(*cmdline++));
		}
		printf("\n");
		if (dry_run) {
			if (kid)
				*kid = -1;
			if (fd)
				*fd = -1;
			if (ex)
				*ex = 0;
			return;
		}
	}

	/* flush stdout and stderr, so output of bsradm
	 * and helper binaries is reported in order! */
	fflush(stdout);
	fflush(stderr);

	if (adjust_with_progress && !(flags & RETURN_STDERR_FD))
		flags |= SUPRESS_STDERR;

	/* create the pipe in any case:
	 * it helps the analyzer and later we have:
	 * '*fd = pipe_fds[0];' */
	if (pipe(pipe_fds) < 0) {
		perror("pipe");
		CLI_ERRO_LOG_STDERR(false,  "Error in pipe, giving up.");
		exit(E_EXEC_ERROR);
	}

	pid = my_fork();
	if (pid == -1) {
		CLI_ERRO_LOG_STDERR(false,  "Can not fork");
		exit(E_EXEC_ERROR);
	}
	if (pid == 0) {
#ifdef _LIN
		prctl(PR_SET_PDEATHSIG, SIGKILL);
#endif
		/* Child: close reading end. */
		close(pipe_fds[0]);
		if (flags & RETURN_STDOUT_FD) {
			dup2(pipe_fds[1], STDOUT_FILENO);
		}
		if (flags & RETURN_STDERR_FD) {
			dup2(pipe_fds[1], STDERR_FILENO);
		}
		close(pipe_fds[1]);

		if (flags & SUPRESS_STDERR) {
			FILE *f = freopen("/dev/null", "w", stderr);
			if (!f)
				// DW-1777 revert source and change error message
				CLI_ERRO_LOG_STDERR(false,  "reopen null service failed");
		}
		if (argv[0]) {
#ifdef _WIN
			// DW-1203 execvp() run with the full path.
			char path[256];
			char *temp = strdup(argv[0]);
			char *ptr, *name;
			// DW-1425 it's supposed to run any application that belongs to the paths have been set in 'path' env var as long as this is able to parse env vars. 
			// since cygwin is NOT, preferentially search full path that is gotton from env var of bsr and drx. 
#define BSRADM_MAX_ENV_LEN		64	
			char envs[][BSRADM_MAX_ENV_LEN] = { "BSR_PATH", "DRX_PATH", "" };
			int i = 0;
			// remove /usr/bin/
			name = ptr = strtok(temp, "/");
			while (ptr = strtok(NULL, "/")) {
				name = ptr;
			}
			
			for (i = 0; i < sizeof(envs) / BSRADM_MAX_ENV_LEN; i++) {
				if (i == (sizeof(envs) / BSRADM_MAX_ENV_LEN) - 1)
					strcpy(path, name);
				else
					sprintf(path, "%s\\%s", getenv(envs[i]), name);

				if (!execvp(path, argv))
					break;
			}
#else // _LIN
			execvp(argv[0], argv);
#endif
		}
#ifdef _WIN
		CLI_ERRO_LOG_STDERR(false,  "Can not exec %s", argv[0]);
		perror("Failed");
#else // _LIN
		CLI_ERRO_LOG_STDERR(false,  "Can not exec");
#endif
		exit(E_EXEC_ERROR);
	}

	/* Parent process: close writing end. */
	close(pipe_fds[1]);

	if (flags & SLEEPS_FINITE) {
		sigaction(SIGALRM, &sa, &so);
		alarm_raised = 0;
		switch (flags & SLEEPS_MASK) {
		case SLEEPS_SHORT:
			timeout = global_options.cmd_timeout_short;
			timeout = timeout * 2; // DW-1280 adjust alarm timeout.
			break;
		case SLEEPS_LONG:
			timeout = global_options.cmd_timeout_medium;
			break;
		case SLEEPS_VERY_LONG:
			timeout = global_options.cmd_timeout_long;
			break;
		default:
			CLI_ERRO_LOG_STDERR(false,  "logic bug in %s:%d", __FILE__,
				__LINE__);
			exit(E_THINKO);
		}
		alarm(timeout);
	}

	if (kid)
		*kid = pid;

	if (flags & (RETURN_STDOUT_FD | RETURN_STDERR_FD)
			||  flags == RETURN_PID) {
		if (fd)
			*fd = pipe_fds[0];

		return;
	}

	while (1) {
		if (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR)
				break;
			if (alarm_raised) {
				alarm(0);
				sigaction(SIGALRM, &so, NULL);
				rv = 0x100;
				break;
			} else {
				CLI_ERRO_LOG_STDERR(false,  "logic bug in %s:%d",
					__FILE__, __LINE__);
				exit(E_EXEC_ERROR);
			}
		} else {
			if (WIFEXITED(status)) {
				rv = WEXITSTATUS(status);
				break;
			}
		}
	}

	/* Do not close earlier, else the child gets EPIPE. */
	close(pipe_fds[0]);

	if (flags & SLEEPS_FINITE) {
		if (rv >= 10
			&& !(flags & (DONT_REPORT_FAILED | SUPRESS_STDERR))) {
			int chkdsk_timeout = 0;

			// BSR-823 added log output when filesystem check timeout occurs
#ifdef _WIN
			if ((alarm_raised || rv == 20) && !strcmp(argv[1], "check-fs")) {
#else //_LIN
			if (alarm_raised && !strcmp(argv[1], "check-fs")) {
#endif
				CLI_ERRO_LOG_STDERR(false, "Filesystem check takes a long time. Check it manually (see bsr log).");
				CLI_ERRO_LOG_STDERR(false, "If there is no problem, you can ignore it with --skip-check-fs.");
				chkdsk_timeout = 1;
			}
			CLI_ERRO_LOG_STDERR_NO_LINE_BREAK(false, "Command '");
			for (cmdline = argv; *cmdline; cmdline++) {
				CLI_ERRO_LOG_STDERR_NO_LINE_BREAK(true, "%s", *cmdline);
				if (cmdline[1])
					CLI_ERRO_LOG_STDERR_NO_LINE_BREAK(true, " ");
			}
			if (alarm_raised || chkdsk_timeout) {
				CLI_ERRO_LOG_STDERR(true, "' did not terminate within %u seconds", timeout);
				exit(E_EXEC_ERROR);
			}
			else {
				CLI_ERRO_LOG_STDERR(true, "' terminated with exit code %d", rv);
			}
		}
	}
	fflush(stdout);
	fflush(stderr);

	if (ex)
		*ex = rv;
}
