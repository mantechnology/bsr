#!/bin/sh
#
# BSR fence-peer handler for Pacemaker 1.1 clusters
# (via stonith-ng).
#
# Requires that the cluster is running with STONITH
# enabled, and has configured and functional STONITH
# agents.
#
# Also requires that the BSR disk fencing policy
# is at least "resource-only", but "resource-and-stonith"
# is more likely to be useful as most people will
# use this in dual-Primary configurations.
#
# Returns 7 on on success (BSR fence-peer exit code
# for "yes, I've managed to fence this node").
# Returns 1 on any error (undefined generic error code,
# causes BSR devices with the "resource-and-stonith"
# fencing policy to remain suspended).

log() {
  local msg
  msg="$1"
  logger -i -t "`basename $0`" -s "$msg"
}

die() { log "$*"; exit 1; }

die_unless_all_minors_up_to_date()
{
	set -- $BSR_MINOR
	local n_minors=$#

	[ $n_minors != 0 ] ||
		die "Resource minor numbers unknown! Unable to proceed."

	# and build a "grep extended regex"
	local _OLDIFS=$IFS
	IFS="|"
	local minor_regex="^ *($*): cs:"
	IFS=$_OLDIFS

	# grep -c -Ee '^ *(m|i|n|o|r|s): cs:.* ds:UpToDate' /proc/bsr
	local proc_bsr=$(cat /proc/bsr)
	local minors_of_resource=$(echo "$proc_bsr" | grep -E -e "$minor_regex")
	local n_up_to_date=$(echo "$minors_of_resource" | grep -c -e "ds:UpToDate")

	log "n_minors: $n_minors; n_up_to_date: $n_up_to_date"
	[ "$n_up_to_date" = "$n_minors" ] ||
		die "$BSR_RESOURCE(minor $BSR_MINOR): some minor is not UpToDate, will not fence peer."
}

[ -n "$BSR_PEERS" ] || die "BSR_PEERS is empty or unset, cannot continue."
die_unless_all_minors_up_to_date

for p in $BSR_PEERS; do
  stonith_admin --tolerance 5s --tag bsr --fence $p
  rc=$?
  if [ $rc -eq 0 ]; then
    log "stonith_admin successfully fenced peer $p."
  else
    die "Failed to fence peer $p. stonith_admin returned $rc."
  fi
done

exit 7
