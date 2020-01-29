#!/bin/bash
#
# notify.sh -- a notification handler for various BSR events.
# This is meant to be invoked via a symlink in /usr/lib/bsr,
# by bsradm's userspace callouts.

# try to get possible output on stdout/err to syslog
PROG=${0##*/}

# Funky redirection to avoid logger feeding its own output to itself accidentally.
# Funky double exec to avoid an intermediate sub-shell.
# Sometimes, the sub-shell lingers around, keeps file descriptors open,
# and logger then won't notice the main script has finished,
# forever waiting for further input.
# The second exec replaces the subshell, and logger will notice directly
# when its stdin is closed once the main script exits.
# This avoids the spurious logger processes.
exec > >( exec 1>&- 2>&- logger -t "$PROG[$$]" -p local5.info) 2>&1

if [[ $BSR_VOLUME ]]; then
	pretty_print="$BSR_RESOURCE/$BSR_VOLUME (bsr$BSR_MINOR)"
else
	pretty_print="$BSR_RESOURCE"
fi

echo "invoked for $pretty_print"

# Default to sending email to root, unless otherwise specified
RECIPIENT=${1:-root}

# check arguments specified on command line
if [ -z "$RECIPIENT" ]; then
	echo "You must specify a notification recipient when using this handler." >&2
	exit 1
fi

# check envars normally passed in by bsradm
for var in BSR_RESOURCE BSR_PEER; do
	if [ -z "${!var}" ]; then
		echo "Environment variable \$$var not found (this is normally passed in by bsradm)." >&2
		exit 1
	fi
done

: ${BSR_CONF:="usually /etc/bsr.conf"}

BSR_LOCAL_HOST=$(hostname)

case "$0" in
	*split-brain.sh)
		SUBJECT="BSR split brain on resource $pretty_print"
		BODY="
BSR has detected split brain on resource $pretty_print
between $BSR_LOCAL_HOST and $BSR_PEER.
Please rectify this immediately."
		;;
	*out-of-sync.sh)
		SUBJECT="BSR resource $pretty_print has out-of-sync blocks"
		BODY="
BSR has detected out-of-sync blocks on resource $pretty_print
between $BSR_LOCAL_HOST and $BSR_PEER.
Please see the system logs for details."
		;;
    *io-error.sh)
		SUBJECT="BSR resource $pretty_print detected a local I/O error"
		BODY="
BSR has detected an I/O error on resource $pretty_print
on $BSR_LOCAL_HOST.
Please see the system logs for details."
		;;
	*pri-lost.sh)
		SUBJECT="BSR resource $pretty_print is currently Primary, but is to become SyncTarget on $BSR_LOCAL_HOST"
		BODY="
The BSR resource $pretty_print is currently in the Primary
role on host $BSR_LOCAL_HOST, but lost the SyncSource election
process."
		;;
	*pri-lost-after-sb.sh)
		SUBJECT="BSR resource $pretty_print is currently Primary, but lost split brain auto recovery on $BSR_LOCAL_HOST"
		BODY="
The BSR resource $pretty_print is currently in the Primary
role on host $BSR_LOCAL_HOST, but was selected as the split
brain victim in a post split brain auto-recovery."
		;;
	*pri-on-incon-degr.sh)
		SUBJECT="BSR resource $pretty_print no longer has access to valid data on $BSR_LOCAL_HOST"
		BODY="
BSR has detected that the resource $pretty_print
on $BSR_LOCAL_HOST has lost access to its backing device,
and has also lost connection to its peer, $BSR_PEER.
This resource now no longer has access to valid data."
		;;
	*emergency-reboot.sh)
		SUBJECT="BSR initiating emergency reboot of node $BSR_LOCAL_HOST"
		BODY="
Due to an emergency condition, BSR is about to issue a reboot
of node $BSR_LOCAL_HOST. If this is unintended, please check
your BSR configuration file ($BSR_CONF)."
		;;
	*emergency-shutdown.sh)
		SUBJECT="BSR initiating emergency shutdown of node $BSR_LOCAL_HOST"
		BODY="
Due to an emergency condition, BSR is about to shut down
node $BSR_LOCAL_HOST. If this is unintended, please check
your BSR configuration file ($BSR_CONF)."
		;;
	*)
		SUBJECT="Unspecified BSR notification"
		BODY="
BSR on $BSR_LOCAL_HOST was configured to launch a notification handler
for resource $pretty_print,
but no specific notification event was set.
This is most likely due to BSR misconfiguration.
Please check your configuration file ($BSR_CONF)."
		;;
esac

echo "$BODY" | mail -s "$SUBJECT" $RECIPIENT
