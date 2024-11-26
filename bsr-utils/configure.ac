dnl
dnl autoconf for BSR
dnl
dnl License: GNU General Public License Version 2 (GPLv2)

dnl Minimum autoconf version we require
AC_PREREQ(2.53)

dnl Include cpp feature testing macro
dnl AC_CONFIG_MACRO_DIR([m4])
dnl Using AC_CONFIG_MACRO_DIR([m4]) would be the correct way, but RHEL6 ships a broken autoconf
m4_include([m4/AX_CXX_COMPILE_STDXX.m4])
m4_include([m4/AX_CXX_COMPILE_STDXX_11.m4])

dnl What we are, our version, who to bug in case of problems
AC_INIT(BSR, 1.7.3.3, [bsr@mantech.co.kr])

dnl Sanitize $prefix. Autoconf does this by itself, but so late in the
dnl generated configure script that the expansion does not occur until
dnl after our eval magic below.
if test "$prefix" = "NONE"; then
  prefix=$ac_default_prefix
fi
exec_prefix=$prefix

dnl Expand autoconf variables so that we dont end up with '${prefix}'
dnl in #defines
dnl Autoconf deliberately leaves them unexpanded to allow make
dnl exec_prefix=/foo install. BSR supports only DESTDIR, KDIR and
dnl KVER to be invoked with make.
prefix="`eval echo ${prefix}`"
exec_prefix="`eval echo ${exec_prefix}`"
bindir="`eval echo ${bindir}`"
sbindir="`eval echo ${sbindir}`"
libexecdir="`eval echo ${libexecdir}`"
datarootdir="`eval echo ${datarootdir}`"
datadir="`eval echo ${datadir}`"
sysconfdir="`eval echo ${sysconfdir}`"
sharedstatedir="`eval echo ${sharedstatedir}`"
localstatedir="`eval echo ${localstatedir}`"
libdir="`eval echo ${libdir}`"
includedir="`eval echo ${includedir}`"
oldincludedir="`eval echo ${oldincludedir}`"
infodir="`eval echo ${infodir}`"
mandir="`eval echo ${mandir}`"
docdir="`eval echo ${docdir}`"

dnl "--with-<foo>" options (all except rgm enabled by default, pass --without-<foo> to disable)
WITH_UDEV=yes
WITH_XEN=no
WITH_BASHCOMPLETION=yes
WITH_NOARCH_SUBPACKAGES=no
WITH_MANUAL=no
WITH_BSRMON=yes
WITH_BSRCON=yes

AC_ARG_WITH([udev],
	[AS_HELP_STRING([--with-udev],
			[Enable udev integration])],
	[WITH_UDEV=$withval])
AC_ARG_WITH([xen],
	[AS_HELP_STRING([--with-xen],
			[Enable Xen integration])],
	[WITH_XEN=$withval])

AC_ARG_WITH([bashcompletion],
	[AS_HELP_STRING([--with-bashcompletion],
			[Enable programmable bash completion])],
	[WITH_BASHCOMPLETION=$withval])
AC_ARG_WITH([distro],
	[AS_HELP_STRING([--with-distro],
			[Configure for a specific distribution (supported values: generic, redhat, suse, debian; default is to autodetect)])],
	[DISTRO=$withval])
AC_ARG_WITH([initdir],
	[AS_HELP_STRING([--with-initdir],
			[Override directory for init scripts (default is distribution-specific)])],
	[INITDIR=$withval])
AC_ARG_WITH([noarchsubpkg],
	[AS_HELP_STRING([--with-noarchsubpkg],
			[Build subpackages that support it for the "noarch" architecture (makes sense only with --enable-spec, supported by RPM from 4.6.0 forward)])],
	[WITH_NOARCH_SUBPACKAGES=$withval])
AC_ARG_ENABLE([spec],
	[AS_HELP_STRING([--enable-spec],
			[Rather than creating Makefiles, create an RPM spec file only])],
	[SPECMODE=$enableval],
	[SPECMODE=""])
AC_ARG_WITH([manual],
	[AS_HELP_STRING([--without-manual],
			[Do not include manual pages])],
	[WITH_MANUAL=$withval])
AC_SUBST(WITH_UDEV)
AC_SUBST(WITH_XEN)
AC_SUBST(WITH_BASHCOMPLETION)
AC_SUBST(WITH_MANUAL)

dnl Check for functions
AC_CHECK_FUNCS([getentropy])

dnl Do we know where systemd unit files go?
PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdunitdir],
	[AC_HELP_STRING([--with-systemdunitdir=DIR],
        	        [Directory for systemd service files [Auto]])],
	[WITH_SYSTEMD_UNIT_DIR=$withval])
if test x"$with_systemdunitdir" = x || \
   test x"$with_systemdunitdir" = xyes ; then
	if test x"$PKG_CONFIG" != x; then
		systemdunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
	fi
	if test x"$systemdunitdir" = x; then
		AC_MSG_NOTICE([Could not detect systemd unit directory])
	fi
else
	systemdunitdir=$with_systemdunitdir
fi
AC_SUBST(systemdunitdir)
AC_MSG_RESULT([Using systemd unit directory: $systemdunitdir])

AC_ARG_WITH(tmpfilesdir,
	AC_HELP_STRING([--with-tmpfilesdir=DIR],
		[install configuration files for management of volatile files and directories in DIR [[PREFIX/lib/tmpfiles.d]]]),
		tmpfilesdir=$withval, tmpfilesdir='${prefix}/lib/tmpfiles.d')
AC_SUBST(tmpfilesdir)

# set default early
default_udevdir=/lib/udev
if test x"$with_udev" = x || \
   test x"$with_udev" = xyes ; then
	if test x"$PKG_CONFIG" != x; then
		udevdir=$($PKG_CONFIG --variable=udevdir udev)
	fi
	if test x"$udevdir" = x; then
		AC_MSG_NOTICE([Could not detect udev rules directory, using default])
		udevdir=$default_udevdir
	fi
	AC_MSG_RESULT([Using udev rules directory: $udevdir])
else
	udevdir=$default_udevdir
fi
dnl always replace, even if not used
AC_SUBST(udevdir)
udevrulesdir=$udevdir/rules.d
AC_SUBST(udevrulesdir)

AC_ARG_WITH([initscripttype],
	    [AS_HELP_STRING([--with-initscripttype=INIT_SCRIPT_TYPE],
			    [Type of init script to install (sysv|systemd|both|none). [auto]])
	    ])
case "$with_initscripttype" in
	"")
		if grep -ql systemd /sbin/init ; then
			initscripttype=systemd
		else
			initscripttype=sysv
		fi ;;
	sysv|systemd|both|none)
		initscripttype=$with_initscripttype ;;
	*)
		AC_MSG_ERROR([Illegal value -$with_initscripttype- for option --with-initscripttype]) ;;
esac
AC_SUBST(initscripttype)

AC_ARG_WITH([bsrmon],
	[AS_HELP_STRING([--without-bsrmon],
			[Do not include the BSR resource reporting utility])],
	[WITH_BSRMON=$withval])
AC_SUBST(WITH_BSRMON)

AC_ARG_WITH([bsrcon],
	[AS_HELP_STRING([--without-bsrcon],
			[Do not include the bsrcon utility])],
	[WITH_BSRCON=$withval])
AC_SUBST(WITH_BSRCON)

dnl Checks for programs
AC_PROG_CC
AC_PROG_LN_S
AC_PATH_PROG(SED, sed)
AC_PATH_PROG(GREP, grep)
AC_PATH_PROG(FLEX, flex)
AC_PATH_PROG(RPMBUILD, rpmbuild)
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_PATH_PROG(TAR, tar)
AC_PATH_PROG(GIT, git)
AC_PATH_PROG(DPKG_BUILDPACKAGE, dpkg-buildpackage)
AC_PATH_PROG(UDEVADM, udevadm, [false], [/sbin$PATH_SEPARATOR$PATH])
AC_PATH_PROG(UDEVINFO, udevinfo, [false], [/sbin$PATH_SEPARATOR$PATH])

if test -z "$CC"; then
   AC_MSG_ERROR([Cannot build utils without a C compiler.])
fi

if test -z $FLEX; then
   AC_MSG_ERROR([Cannot build utils without flex.])
fi

if test -z $RPMBUILD; then
   AC_MSG_WARN([No rpmbuild found, building RPM packages is disabled.])
fi

if test -z $DPKG_BUILDPACKAGE; then
   AC_MSG_WARN([No dpkg-buildpackage found, building Debian packages is disabled.])
fi

if test -z $XSLTPROC; then
   AC_MSG_WARN([Cannot build man pages without xsltproc. You may safely ignore this warning when building from a tarball.])
   dnl default to some sane value at least,
   dnl so the error message about command not found makes sense
   dnl otherwise you get "--xinclude ... command not found" :-/
   XSLTPROC=xsltproc
fi

if test -z $GIT; then
   AC_MSG_WARN(Cannot update buildtag without git. You may safely ignore this warning when building from a tarball.)
fi

if test $UDEVADM = false && test $UDEVINFO = false; then
   if test "$WITH_UDEV" = "yes"; then
     AC_MSG_WARN([udev support enabled, but neither udevadm nor udevinfo found on this system.])
   fi
fi

dnl special header checks

AC_LANG(C)
AC_COMPILE_IFELSE([AC_LANG_SOURCE[
#include <linux/genetlink.h>
static unsigned int dummy = CTRL_CMD_DELMCAST_GRP;
]], [AC_DEFINE([HAVE_CTRL_CMD_DELMCAST_GRP],1,[Does genetlink provide CTRL_CMD_DELMCAST_GRP already])])

dnl Checks for system services

BASH_COMPLETION_SUFFIX=""
UDEV_RULE_SUFFIX=""
RPM_DIST_TAG=""
RPM_BUILDREQ_DEFAULT="gcc flex glibc-devel make"
RPM_REQ_BSRMON=""
RPM_SUBPACKAGE_NOARCH=""
RPM_REQ_BASH_COMPLETION=""
RPM_REQ_XEN=""
RPM_REQ_CHKCONFIG_POST=""
RPM_REQ_CHKCONFIG_PREUN=""
dnl figure out the distribution we're running on, and set some variables accordingly
if test -z $DISTRO; then
   AC_CHECK_FILE(/etc/redhat-release, [DISTRO="redhat"])
   AC_CHECK_FILE(/etc/debian_version, [DISTRO="debian"])
   AC_CHECK_FILE(/etc/SuSE-release, [DISTRO="suse"])
fi
case "$DISTRO" in
     redhat)
	test -z $INITDIR && INITDIR="$sysconfdir/rc.d/init.d"
	RPM_DIST_TAG="%{?dist}"
	dnl Fedora/Red Hat packaging guidelines mandate that packages
	dnl belonging to the "minimal build system" should not be
	dnl listed in BuildRequires
	RPM_BUILDREQ_DEFAULT="flex"
	RPM_REQ_CHKCONFIG_POST="Requires(post): chkconfig"
	RPM_REQ_CHKCONFIG_PREUN="Requires(preun): chkconfig"
	AC_MSG_NOTICE([configured for Red Hat (includes Fedora, RHEL, CentOS).])

	AC_CHECK_FILE(/etc/fedora-release, [SUB_DISTRO="fedora"], [SUB_DISTRO="RHEL"])
	if test "$SUB_DISTRO" = "fedora"; then
		# bash-completion are not available in RHEL
		# Xen: Be relaxed on RHEL (hassle free update). Be strict on Fedora
		RPM_REQ_BASH_COMPLETION="Requires: bash-completion"
		RPM_REQ_XEN="Requires: xen"
	fi
	;;
     debian)
	AC_MSG_NOTICE([configured for Debian (includes Ubuntu).])
        ;;
     suse)
	BASH_COMPLETION_SUFFIX=".sh"
	# RPM_REQ_CHKCONFIG_POST="" chkconfig is part of aaa_base on suse
	# RPM_REQ_CHKCONFIG_PREUN="" chkconfig is part of aaa_base on suse
	AC_MSG_NOTICE([configured for SUSE (includes openSUSE, SLES).])

	RPM_REQ_BASH_COMPLETION="Requires: bash"
	# The following are disabled for hassle free updates:
	# RPM_REQ_XEN="Requires: xen"

	# Unfortunately gcc on SLES9 is broken with -O2. Works with -O1
	if grep -q 'VERSION = 9' /etc/SuSE-release; then
		CFLAGS="-g -O1"
	fi
	;;
     "")
	AC_MSG_WARN([Unable to determine what distribution we are running on. Distribution-specific features will be disabled.])
	;;
esac
dnl INITDIR may be set with --with-initdir, or set in the distro
dnl detection magic above. If unset down to here, use a sensible
dnl default.
test -z $INITDIR && INITDIR="$sysconfdir/init.d"

dnl Our udev rules file is known to work only with udev >= 85
if test "$WITH_UDEV" = "yes"; then
   udev_version=`$UDEVADM version 2>/dev/null` || udev_version=`$UDEVINFO -V | cut -d " " -f 3`
   if test -z $udev_version || test $udev_version -lt 85; then
      UDEV_RULE_SUFFIX=".disabled"
      AC_MSG_WARN([Obsolete or unknown udev version. Installing disabled udev rules.])
   fi
fi

dnl Our sub-packages can be built for noarch, but RPM only supports
dnl this from version 4.6.0 forward
if test "$WITH_NOARCH_SUBPACKAGES" = "yes"; then
   RPM_SUBPACKAGE_NOARCH="BuildArch: noarch"
fi
AC_SUBST(DISTRO)
AC_SUBST(INITDIR)
AC_SUBST(BASH_COMPLETION_SUFFIX)
AC_SUBST(UDEV_RULE_SUFFIX)
AC_SUBST(RPM_DIST_TAG)
AC_SUBST(RPM_BUILDREQ_DEFAULT)
AC_SUBST(RPM_SUBPACKAGE_NOARCH)
AC_SUBST(RPM_REQ_BASH_COMPLETION)
AC_SUBST(RPM_REQ_XEN)
AC_SUBST(RPM_REQ_CHKCONFIG_POST)
AC_SUBST(RPM_REQ_CHKCONFIG_PREUN)

AH_TEMPLATE(BSR_LIB_DIR, [Local state directory. Commonly
			  /var/lib/bsr or /usr/local/var/lib/bsr])
AH_TEMPLATE(BSR_RUN_DIR, [Runtime state directory. Commonly
			  /var/run/bsr or /usr/local/var/run/bsr])
AH_TEMPLATE(BSR_LOCK_DIR, [Local lock directory. Commonly
			   /var/lock or
			   /usr/local/var/lock])
AH_TEMPLATE(BSR_CONFIG_DIR, [Local configuration directory. Commonly
			   /etc or
			   /usr/local/etc])

AC_SUBST(BSR_LIB_DIR, [$localstatedir/lib/$PACKAGE_TARNAME])
AC_SUBST(BSR_RUN_DIR, [$localstatedir/run/$PACKAGE_TARNAME])
AC_SUBST(BSR_LOCK_DIR, [$localstatedir/lock])
AC_SUBST(BSR_CONFIG_DIR, [$sysconfdir])

AC_DEFINE_UNQUOTED(BSR_LIB_DIR, ["$BSR_LIB_DIR"])
AC_DEFINE_UNQUOTED(BSR_RUN_DIR, ["$BSR_RUN_DIR"])
AC_DEFINE_UNQUOTED(BSR_LOCK_DIR, ["$BSR_LOCK_DIR"])
AC_DEFINE_UNQUOTED(BSR_CONFIG_DIR, ["$BSR_CONFIG_DIR"])

dnl The configuration files we create (from their .in template)
if test -z $SPECMODE; then
   AC_CONFIG_FILES(Makefile user/shared/Makefile user/v9/Makefile scripts/Makefile scripts/bsr.rules)
   if [[ $WITH_MANUAL == "yes" ]] ; then
      AC_CONFIG_FILES(documentation/v9/Makefile)
   fi
   if [[ $WITH_BSRMON == "yes" ]] ; then
      AC_CONFIG_FILES(user/bsrmon/Makefile)
   fi
   if [[ $WITH_BSRCON == "yes" ]] ; then
      AC_CONFIG_FILES(bsrcon/Makefile)
   fi
   
   AC_CONFIG_HEADERS(user/shared/config.h)
else
   AC_CONFIG_FILES(bsr.spec)
fi

dnl output
AC_OUTPUT
