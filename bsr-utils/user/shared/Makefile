# Makefile for bsr.o
#
# This file is part of BSR by Philipp Reisner and Lars Ellenberg.
#
# bsr is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# bsr is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bsr; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#

# variables set by configure
DISTRO = 
prefix = /usr/local
exec_prefix = /usr/local
localstatedir = /usr/local/var
datarootdir = /usr/local/share
datadir = /usr/local/share
sbindir = /usr/local/sbin
sysconfdir = /usr/local/etc
BASH_COMPLETION_SUFFIX = 
UDEV_RULE_SUFFIX = .disabled
INITDIR = /usr/local/etc/init.d
LIBDIR = /usr/local/lib/bsr
CC = gcc
CFLAGS = -g -O2
LDFLAGS = 
LN_S = ln -s

BSR_LIB_DIR = /usr/local/var/lib/bsr
BSR_RUN_DIR = /usr/local/var/run/bsr
BSR_LOCK_DIR = /usr/local/var/lock
BSR_CONFIG_DIR = /usr/local/etc

# features enabled or disabled by configure
WITH_UDEV = yes
WITH_XEN = no
WITH_BASHCOMPLETION = yes

# for some reason some of the commands below only work correctly in bash,
# and not in e.g. dash. I'm too lazy to fix it to be compatible.
SHELL=/bin/bash

# variables meant to be overridden from the make command line
DESTDIR ?= /

CFLAGS += -Wall -I../../bsr-headers -I.. -I.
CFLAGS += $(EXTRA_CFLAGS)

.PHONY: bsr_buildtag.c

all: bsrmeta_scanner.c # bsr_buildtag.c

bsr_buildtag.c:
	@set -e; exec > $@.new;							\
	echo -e "/* automatically generated. DO NOT EDIT. */";			\
	echo -e "#include <linux/bsr.h>";					\
	echo -e "const char *bsr_buildtag(void)\n{";				\
	if test -e ../../.git && GITHEAD=$$(git rev-parse HEAD); then		\
		GITDIFF=$$(cd .. && git diff --name-only HEAD |			\
			tr -s '\t\n' '  ' |					\
			sed -e 's/^/ /;s/ *$$//');				\
		echo -e "\treturn \"GIT-hash: $$GITHEAD$$GITDIFF\"";		\
	elif ! test -e $@ ; then						\
		echo >&2 "$@ not found.";					\
		test -e ../../.git &&						\
		>&2 printf "%s\n"						\
			"git did not work, but this looks like a git checkout?"	\
			"Install git and try again." ||				\
		echo >&2 "Your BSR source tree is broken. Unpack again.";	\
		exit 1;								\
	else									\
		grep return $@ ;						\
	fi ;									\
	echo -e "\t\t\" build by $$USER@$$HOSTNAME, `date "+%F %T"`\";\n}";	\
	mv -f $@.new $@

bsrmeta_scanner.c: bsrmeta_scanner.fl bsrmeta_parser.h
	flex -s -obsrmeta_scanner.c bsrmeta_scanner.fl

# bsrmeta is in this directory; but some header files it depends on are in 
# v9, so that's where it gets built and installed.

clean:
	rm -f bsrmeta_scanner.c
	! test -e ../../.git || rm -f bsr_buildtag.c

distclean: clean

install: ; @true

uninstall: ; @true

.PHONY: install uninstall clean distclean
../../configure:
	@echo "please (re-)run ./autogen.sh with appropriate arguments"; exit 1
../../config.status: ../../configure
	@echo "please (re-)run ./configure with appropriate arguments"; exit 1
Makefile.in: ;
Makefile: Makefile.in ../../config.status
	cd ../.. && ./config.status user/shared/Makefile

