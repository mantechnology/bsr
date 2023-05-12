# Makefile for bsr
#
# This file is part of BSR by Man Technology inc.
#
# Copyright (C) 2007-2020, Man Technology inc <bsr@mantech.co.kr>.
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
# along with bsr
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#

GIT = git
LN_S = ln -s
RPMBUILD = rpmbuild
DEBBUILD = debuild

# default for KDIR/KVER
ifndef KVER
 ifndef KDIR
KVER = `uname -r`
KDIR = /lib/modules/$(KVER)/build
 else
KVER := $(shell make -s -C $(KDIR) kernelrelease)
 endif
endif
KDIR ?= /lib/modules/$(KVER)/build

# for some reason some of the commands below only work correctly in bash,
# and not in e.g. dash. I'm too lazy to fix it to be compatible.
SHELL=/bin/bash

SUBDIRS     = bsr

REL_VERSION := $(shell sed -ne '/^\#define REL_VERSION/{s/^[^"]*"\([^ "]*\).*/\1/;p;q;}' bsr/linux/bsr_config.h)
override GITHEAD := $(shell test -e .git && $(GIT) rev-parse HEAD)

ifdef FORCE
#
# NOTE to generate a tgz even if too lazy to update the changelogs,
# or to forcefully include the FIXME to be done: latest change date;
# for now, include the git hash of the latest commit
# in the tgz name:
#   make distclean tgz FORCE=1
#
REL_VERSION := $(REL_VERSION)-$(GITHEAD)
endif

DIST_VERSION := $(REL_VERSION)
# BSR-1079
# ifeq ($(subst -,_,$(DIST_VERSION)),$(DIST_VERSION))
#     DIST_VERSION := $(DIST_VERSION)-1
# endif
FDIST_VERSION := $(shell test -s .filelist && sed -ne 's,^bsr-\([^/]*\)/.*,\1,p;q' < .filelist)
ifeq ($(FDIST_VERSION),)
FDIST_VERSION := $(DIST_VERSION)
endif

all: module tools

.PHONY: all tools module
tools: | $(if $(filter module all,$(if $(MAKECMDGOALS),,all)),module)
	@cat README.bsr-utils
doc:
	@echo "Man page sources moved to http://git.linbit.com/bsr-utils.git"

# we cannot use 'git submodule foreach':
# foreach only works if submodule already checked out
.PHONY: check-submods
check-submods:
	@if test -d .git && test -s .gitmodules; then \
		for d in `grep "^\[submodule" .gitmodules | cut -f2 -d'"'`; do \
			if [ ! "`ls -A $$d`" ]; then \
				git submodule init; \
				git submodule update; \
				break; \
			fi; \
		done; \
	fi

.PHONY: check-kdir
check-kdir:
	@if ! test -e $(KDIR)/Makefile ; then \
		echo "    SORRY, kernel makefile not found." ;\
	        echo "    You need to tell me a correct KDIR," ;\
	        echo "    Or install the neccessary kernel source packages." ;\
	        echo "" ;\
		false;\
	fi

.PHONY: module
module: check-kdir check-submods
	@ $(MAKE) -C bsr KVER=$(KVER) KDIR=$(KDIR)
	@ echo -e "\n\tModule build was successful."

install:
	$(MAKE) -C bsr install


clean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	rm -f *~

distclean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i distclean; done
	rm -f *~ .filelist

uninstall:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i uninstall; done

.PHONY: check check_changelogs_up2date install uninstall distclean clean
check check_changelogs_up2date:
	@ up2date=true; dver_re=$(DIST_VERSION); dver_re=$${dver_re//./\\.};	\
	dver=$${dver_re%[-~]*}; 						\
	echo "checking for presence of $$dver_re in various changelog files"; 	\
	for f in bsr-kernel.spec ; do 						\
	v=$$(sed -ne 's/^Version: //p' $$f); 					\
	if ! printf "%s" "$$v" | grep -H --label $$f "$$dver_re\>"; then \
	   printf "\n\t%s Version: tags need update\n" $$f; 		\
	   grep -Hn "^Version: " $$f ; 						\
	   up2date=false; fi ; 							\
	in_changelog=$$(sed -n -e '0,/^%changelog/d' 			\
		     -e '/- '"$$dver_re"'\>/p' < $$f) ; 		\
	if test -z "$$in_changelog" ; then 					\
	   printf "\n\t%%changelog in %s needs update\n" $$f; 			\
	   grep -Hn "^%changelog" $$f ; 					\
	   up2date=false; fi; 							\
	done ; 									\
	if ! grep -H "^\($$dver_re\|$$dver\) (api:" ChangeLog; 			\
	then 									\
	   printf "\nChangeLog:3:\tneeds update\n"; 				\
	   up2date=false; fi ; 							\
	if test -e debian/changelog 						\
	&& ! grep -H "^bsr ($$dver\(+mantech\)\?" debian/changelog; \
	then 									\
	   printf "\n\tdebian/changelog:1: needs update\n"; 			\
	   up2date=false; fi ; 							\
	$$up2date

.PHONY: bsr/.bsr_git_revision
ifdef GITHEAD
bsr/.bsr_git_revision:
	@git_head=$(GITHEAD); \
	echo GIT-hash: $${git_head:0:7} > $@
else
bsr/.bsr_git_revision:
	@echo >&2 "Need a git checkout to regenerate $@"; test -s $@
endif

# update of .filelist is forced:
.PHONY: .filelist
.filelist:
	@set -e ; $(GIT) ls-files | \
	  sed '$(if $(PRESERVE_DEBIAN),,/^debian/d);s#^#bsr-$(DIST_VERSION)/#' | \
	  grep -v "gitignore\|gitmodules\|windows\|bsr-utils" > .filelist
	@[ -s .filelist ] # assert there is something in .filelist now
	@echo bsr-$(DIST_VERSION)/.filelist               >> .filelist ; \
	echo bsr-$(DIST_VERSION)/bsr/.bsr_git_revision >> .filelist ; \
	if test -d pki ; then \
		echo bsr-$(DIST_VERSION)/pki/bsr_signing_key.priv >> .filelist ; \
		echo bsr-$(DIST_VERSION)/pki/bsr_signing_key_pub.der >> .filelist ; fi ; \
	echo "./.filelist updated."

# tgz will no longer automatically update .filelist,
# so the tgz and therefore rpm target will work within
# an extracted tarball, too.
# to generate a distribution tarball, use make tarball,
# which will regenerate .filelist
tgz:
	test -s .filelist
	rm -f bsr-$(FDIST_VERSION)
	$(LN_S) . bsr-$(FDIST_VERSION)
	for f in $$(<.filelist) ; do [ -e $$f ] && continue ; echo missing: $$f ; exit 1; done
	grep debian .filelist >/dev/null 2>&1 && _DEB=-debian || _DEB="" ; \
	tar --owner=0 --group=0 -czf - -T .filelist > bsr-$(FDIST_VERSION)$$_DEB.tar.gz
	rm bsr-$(FDIST_VERSION)

ifeq ($(FORCE),)
tgz: check_changelogs_up2date
endif

check_all_committed:
	@$(if $(FORCE),-,)modified=`$(GIT) diff --name-status HEAD`; 	\
	if test -n "$$modified" ; then	\
		echo "$$modified";	\
	       	false;			\
	fi

prepare_release:
	$(MAKE) tarball
	$(MAKE) tarball PRESERVE_DEBIAN=1

tarball: check-submods check_all_committed distclean bsr/.bsr_git_revision .filelist
	$(MAKE) tgz

module .filelist: bsr/.bsr_git_revision

ifdef RPMBUILD

# kernel module package using the system macros.
# result is kABI aware and uses the weak-updates mechanism.
# Only define %kernel_version, it it was set outside of this file,
# i.e. was inherited from environment, or set explicitly on command line.
# If unset, the macro will figure it out internally, and not depend on
# uname -r, which may be wrong in a chroot build environment.
.PHONY: kmp-rpm
kmp-rpm: bsr/.bsr_git_revision .filelist tgz bsr-kernel.spec
	cp bsr-$(FDIST_VERSION).tar.gz `rpm -E "%_sourcedir"`
	$(RPMBUILD) -bb \
	    $(if $(filter file,$(origin KVER)), --define "kernel_version $(KVER)") \
	    $(RPMOPT) \
	    bsr-kernel.spec
	@echo "You have now:" ; find `rpm -E "%_rpmdir"` -name *.rpm

.PHONY: kmp-rpm-sign
kmp-rpm-sign: bsr/.bsr_git_revision .filelist tgz bsr-kernel.spec
	@if ! test -e pki/bsr_signing_key.priv  ; then \
		echo -e "    pki/bsr_signing_key.priv key required\n" ;\
		false;\
	fi
	@if ! test -e pki/bsr_signing_key_pub.der  ; then \
		echo -e "    pki/bsr_signing_key_pub.der key required\n" ;\
		false;\
	fi
	cp bsr-$(FDIST_VERSION).tar.gz `rpm -E "%_sourcedir"`
	$(RPMBUILD) -bb \
	    $(if $(filter file,$(origin KVER)), --define "kernel_version $(KVER)") \
	    $(RPMOPT) \
	    --with modsign \
	    bsr-kernel.spec
	@echo "You have now:" ; find `rpm -E "%_rpmdir"` -name *.rpm

.PHONY: srpm
srpm: tgz
	cp bsr-$(FDIST_VERSION).tar.gz `rpm -E "%_sourcedir"`
	$(RPMBUILD) -bs \
	    --define "kernelversion $(KVER)" \
	    --define "kernel_version $(KVER)" \
	    --define "kdir $(KDIR)" \
		$(RPMOPT) \
		bsr-kernel.spec
	@echo "You have now:" ; find `rpm -E "%_srcrpmdir"` -name *.src.rpm
endif

ifdef DEBBUILD
.PHONY: km-deb
km-deb: distclean bsr/.bsr_git_revision
	$(DEBBUILD) -i -us -uc -b
endif

modsign:
	$(MAKE) -C bsr modsign

Makefile: ;
