# makefile for bsr for linux 2.4 // 2.6
#
# By Man Technology inc.
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

# usage: make [ KDIR=/path/to/kernel/source ]
#
# this file is read twice:
# the first invocation calls out to the toplevel Makefile in the
# kernel source tree, which then in turn will call this file again
# as subdir Makefile, with all appropriate vars and macros set.
#
# note: if you get strange make errors when ARCH=um, you
# probably need to "make mrproper" in the KDIR first...

# The destination "root" directory. Meant to be overridden by
# packaging scripts.
DESTDIR ?= /

# Do not:
# o  use make's built-in rules and variables
#    (this increases performance and avoids hard-to-debug behaviour);
# o  print "Entering directory ...";
MAKEFLAGS += -rR --no-print-directory

# since 2.6.16, KERNELRELEASE may be empty,
# e.g. when building against some (broken?) linux-header package.
# Lets test on PATCHLEVEL, that won't change too soon...

ifneq ($(PATCHLEVEL),)
 ifneq ($(VERSION),3)
  ifneq ($(VERSION),2)
    $(error "won't compile with this kernel version")
  endif
  ifneq ($(PATCHLEVEL),6)
    $(error "won't compile with this kernel version")
  endif
 endif

  CONFIG_BLK_DEV_BSR := m

  include $(src)/Kbuild

else
  # called from command line in current directory

  # for some reason some of the commands below only work correctly in bash,
  # and not in e.g. dash. I'm too lazy to fix it to be compatible.
  SHELL=/bin/bash

  BSRSRC := $(shell pwd)

  # BSR-659 module sign for secure boot support
  PRIVKEY := bsr_signing_key.priv
  PUBKEY := bsr_signing_key_pub.der

  # to be overridden on command line:
  PREFIX := /
  ifneq ($(wildcard ../build-for-uml),)
    #### for Philipp's convenience :)
    ARCH_UM := "ARCH=um"
    KDIR := /usr/src/linux-um
  else
    ifeq ($(wildcard /lib/modules/$(shell uname -r)/source),)
      KDIR := /lib/modules/$(shell uname -r)/build
    else
      KDIR := /lib/modules/$(shell uname -r)/source
      ifneq ("$(origin KDIR)", "command line")
        ifneq ($(wildcard /lib/modules/$(shell uname -r)/build),)
          O := /lib/modules/$(shell uname -r)/build
        endif
      endif
    endif
  endif

  .PHONY: bsr.o default all greeting clean kbuild install dep tags

  bsr.o: greeting kbuild
  default: bsr.o
  all:     bsr.o

  greeting:
	@echo "" ;\
	echo "    Calling toplevel makefile of kernel source tree, which I believe is in" ;\
	echo "    KDIR=$(KDIR)" ; \
	echo "";
	@if ! test -e $(KDIR)/Makefile ; then \
		echo -e "    SORRY, kernel makefile not found. You need to tell me a correct KDIR!\n" ;\
		false;\
	fi

  kbuild:
	@rm -f .bsr_kernelrelease*
	$(MAKE) -C $(KDIR)  $(if $(O),O=$(O),) M=$(BSRSRC) $(ARCH_UM) modules
	-mv .bsr_kernelrelease.new .bsr_kernelrelease
	@echo -n "Memorizing module configuration ... "
	@config=$$( (for x in $(KDIR)/.config $(O)/.config ; do \
	       if test -e $$x ; then echo $$x ; exit 0; fi ; \
	       done; echo $(KDIR)/.config) | sed -e 's,//,/,g') ; \
	{ echo -e "#\n# bsr.o was compiled with"          ; \
	  echo "#  `gcc -v 2>&1 | tail -1`"                 ; \
	  echo "# against this kernelrelease:"              ; \
	  sed 's/^/#  /' .bsr_kernelrelease                ; \
	  echo    "# kernel .config from"                   ; \
	  echo -n "#  $$config"                      ; \
	  test -L "$${config%/.config}" && echo "	alias"   &&           \
	  echo "#  $$(readlink $${config%/.config})/.config" || echo "" ; \
	  echo -e "# follows\n#\n"                          ; \
	  cat $$config ; } | gzip > .kernel.config.gz
	@echo "done."

  clean:
	rm -rf .tmp_versions Module.markers Module.symvers modules.order
	rm -f *.[oas] *.ko *.ko.unsigned .*.cmd .*.d .*.tmp *.mod.c .*.flags .depend .kernel*
	rm -f bsr-kernel-compat/*.[oas] bsr-kernel-compat/.*.cmd ../bsr-platform/linux/bsrhk/*.[oas] ../bsr-headers/*.[oas]
	rm -f .compat_test.*

  distclean: clean
	@if git show HEAD:bsr/linux/bsr_config.h > linux/bsr_config.h.tmp \
	&& ! diff -s -U0 linux/bsr_config.h.tmp linux/bsr_config.h ; then \
		mv linux/bsr_config.h.tmp linux/bsr_config.h ; \
	else \
		rm -f linux/bsr_config.h.tmp ; \
	fi
	rm -f bsr_buildtag.c compat.h

  tags:
	( git ls-files ;						\
	  git submodule foreach -q --recursive				\
		'git ls-files | sed -e "s,^,$$displaypath/,"' ) |	\
		ctags -L -						\
		-I __initdata,__exitdata,__acquires,__releases		\
		-I __must_hold,__protected_by,__protected_read_by	\
		-I __protected_write_by,BIO_ENDIO_ARGS

  ifneq ($(wildcard .bsr_kernelrelease),)
    # for VERSION, PATCHLEVEL, SUBLEVEL, EXTRAVERSION, KERNELRELEASE
    include .bsr_kernelrelease
    MODOBJS := bsr.ko # bsr_transport_tcp.ko
    MODSUBDIR := updates
    LINUX := $(wildcard /lib/modules/$(KERNELRELEASE)/build)

    install:
	@if ! [ -e $(MODOBJ) ] ; then \
	  echo "No $(MODOBJ): nothing to install??"; false ; \
	fi
	install -d $(DESTDIR)/lib/modules/$(KERNELRELEASE)/$(MODSUBDIR)
	set -e ; for ko in $(MODOBJS); do \
		install -m 644 $$ko $(DESTDIR)/lib/modules/$(KERNELRELEASE)/$(MODSUBDIR); \
	done
    ifeq ($(DESTDIR),/)
      ifeq ($(shell uname -r),$(KERNELRELEASE))
		/sbin/depmod -a || :
      else
		@echo "Don't forget to depmod."
      endif
    endif
	install -d $(DESTDIR)/var/log/bsr
	install -d $(DESTDIR)/var/log/bsr/perfmon
  else
    install:
	@echo "No .bsr_kernelrelease found. Do you need to 'make' the module first?"
	@false
  endif
  
  # BSR-659 module sign for secure boot support
  modsign:
	@if ! test -e ../pki/$(PRIVKEY)  ; then \
		echo -e "    pki/bsr_signing_key.priv key required\n" ;\
		false;\
	fi
	@if ! test -e ../pki/$(PUBKEY)  ; then \
		echo -e "    pki/bsr_signing_key_pub.der key required\n" ;\
		false;\
	fi
	# BSR-1089
	@if test -e /usr/src/kernels/$(KERNELRELEASE)/scripts/sign-file; then \
		SIGN_FILE_PATH=/usr/src/kernels/$(KERNELRELEASE)/scripts;\
	else \
		SIGN_FILE_PATH=$(KDIR)/scripts;\
	fi ;\
	$$SIGN_FILE_PATH/sign-file sha256 ../pki/$(PRIVKEY) ../pki/$(PUBKEY) bsr.ko 

endif

uninstall:

spell:
	for f in $(wildcard *.c); do \
	 	aspell --save-repl --dont-backup --personal=./../documentation/aspell.en.per check $$f; \
	done

