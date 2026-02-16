#!/usr/bin/env sh
# Find and connect to a known-good endpoint when needed. UCI only. No /tmp list.
# Uses a dedicated polling interface so health checks do not disrupt the active VPN.
set -u

DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
# LuCI: read all from UCI (fallback to env/defaults)
_u() { uci -q get vpn_watchdog.@watchdog[0]."$1" 2>/dev/null; }
[ "$(_u enabled)" = "0" ] && exit 0
SITES_FILE="${SITES_FILE:-$(_u sites_file)}"; [ -z "$SITES_FILE" ] && SITES_FILE="$DIR/sites.conf"
VPN_IFACE="${VPN_IFACE:-$(_u vpn_iface)}"
SLEEP="${SLEEP_AFTER_SWITCH:-$(_u sleep_after_switch)}"; [ -z "$SLEEP" ] && SLEEP=3
DRY_RUN="${VPN_DRY_RUN:-0}"
LOG_PATH="${LOG_PATH:-$(_u log_path)}"
export CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-$(_u curl_connect_timeout)}"; [ -z "$CURL_CONNECT_TIMEOUT" ] && export CURL_CONNECT_TIMEOUT=3
export CURL_MAX_TIME="${CURL_MAX_TIME:-$(_u curl_max_time)}"; [ -z "$CURL_MAX_TIME" ] && export CURL_MAX_TIME=8

log() { echo "[vpn] $(date '+%Y-%m-%dT%H:%M:%S') $*"; [ -n "$LOG_PATH" ] && echo "[vpn] $(date '+%Y-%m-%dT%H:%M:%S') $*" >> "$LOG_PATH" 2>/dev/null; }
err() { echo "[vpn] $*" >&2; [ -n "$LOG_PATH" ] && echo "[vpn] $*" >> "$LOG_PATH" 2>/dev/null; }

. "$DIR/lib_uci.sh"
. "$DIR/lib_sites.sh"
. "$DIR/lib_switch.sh"

# #region agent log
_dlog() { _dlog_dir="/home/brandon/repos/vpn-health/.cursor"; [ -d "$_dlog_dir" ] && echo "{\"id\":\"log_$(date +%s)_$$\",\"timestamp\":$(( $(date +%s) * 1000 )),\"location\":\"$1\",\"message\":\"$2\",\"data\":$3,\"hypothesisId\":\"$4\"}" >> "$_dlog_dir/debug.log" 2>/dev/null; true; }
_dlog "vpn-health-check.sh:after_sources" "script started" "{\"DIR\":\"$DIR\",\"VPN_DRY_RUN\":\"${VPN_DRY_RUN:-}\",\"VPN_IFACE_set\":\"${VPN_IFACE:+y}\"}" "A"
# #endregion

[ -z "$VPN_IFACE" ] && VPN_IFACE=$(detect_wg_iface)
# #region agent log
_dlog "vpn-health-check.sh:before_wgcheck" "after detect_wg_iface" "{\"VPN_IFACE\":\"${VPN_IFACE:-}\"}" "B"
# #endregion
if [ -z "$VPN_IFACE" ]; then
  has_peers=$(uci show wireguard 2>/dev/null | grep -c "=peers$" || echo 0)
  if [ "${has_peers:-0}" -gt 0 ]; then
    err "no WireGuard interface in network. Set vpn_iface in LuCI (Services → KGE VPN Watchdog) to the client interface name, or connect VPN once so the interface exists."
  else
    err "no WireGuard interface and no wireguard peers in UCI."
  fi
  _dlog "vpn-health-check.sh:exit_no_wg" "exiting 1 no wgclient" "{}" "B"
  exit 1
fi

ACTIVE_IFACE="$VPN_IFACE"
POLLING_IFACE="${POLLING_IFACE:-$(_u polling_iface)}"
[ -z "$POLLING_IFACE" ] && POLLING_IFACE=wgclient_poll
export CHECK_IFACE="$POLLING_IFACE"

ensure_polling_interface "$POLLING_IFACE" || { err "failed to ensure polling iface $POLLING_IFACE"; _dlog "vpn-health-check.sh:exit_polling_fail" "exit 1 ensure_polling_interface failed" "{\"POLLING_IFACE\":\"$POLLING_IFACE\"}" "D"; exit 1; }
trap 'teardown_polling_interface "$POLLING_IFACE"' EXIT INT TERM

cur=$(current)
wl=$(peers_list_filtered)
# #region agent log
_dlog "vpn-health-check.sh:after_peers" "current and peers" "{\"cur\":\"${cur:-}\",\"wl_count\":\"$(echo $wl | wc -w)\"}" "D"
# #endregion
[ -z "$wl" ] && { err "no peers (uci wireguard or whitelist empty)"; _dlog "vpn-health-check.sh:exit_no_peers" "exit 1 no peers" "{}" "D"; exit 1; }

if [ -z "$cur" ]; then
  [ -n "$DRY_RUN" ] && [ "$DRY_RUN" != "0" ] && { log "no current (dry run)"; _dlog "vpn-health-check.sh:exit_no_cur_dry" "exit 1 no current (dry run)" "{}" "E"; exit 1; }
  log "no current; find and connect (poll via $POLLING_IFACE)"
  for id in $wl; do
    log "try $id"
    if try_switch_polling "$id"; then
      log "KGE=$id; applying to active $ACTIVE_IFACE"
      switch_active_to "$id" && { log "OK connected=$id"; _dlog "vpn-health-check.sh:exit_connected" "exit 0 connected" "{\"id\":\"$id\"}" "E"; exit 0; }
    fi
    sleep 2
  done
  err "no endpoint passed"
  _dlog "vpn-health-check.sh:exit_no_endpoint_1" "exit 1 no endpoint (no cur)" "{}" "E"; exit 1
fi

log "poll current=$cur (active=$ACTIVE_IFACE poll=$POLLING_IFACE)"
do_switch_to "$POLLING_IFACE" "$cur" 2>/dev/null || true
sleep "$SLEEP"
# #region agent log
check_result=0; check_all || check_result=$?
_dlog "vpn-health-check.sh:after_check_all" "check_all result" "{\"check_ok\":\"$([ $check_result -eq 0 ] && echo y || echo n)\",\"cur\":\"${cur:-}\"}" "F"
# #endregion
if [ $check_result -eq 0 ]; then
  [ -n "$DRY_RUN" ] && [ "$DRY_RUN" != "0" ] && { log "OK (dry run)"; _dlog "vpn-health-check.sh:exit_dry_ok" "exit 0 dry run OK" "{}" "C"; exit 0; }
  _dlog "vpn-health-check.sh:exit_ok" "exit 0 check passed" "{}" "F"; exit 0
fi

[ -n "$DRY_RUN" ] && [ "$DRY_RUN" != "0" ] && { log "stale (dry run)"; _dlog "vpn-health-check.sh:exit_stale_dry" "exit 1 stale (dry run)" "{}" "F"; exit 1; }
log "current stale; find and connect (poll via $POLLING_IFACE)"
for id in $wl; do
  [ "$id" = "$cur" ] && continue
  log "try $id"
  if try_switch_polling "$id"; then
    log "KGE=$id; applying to active $ACTIVE_IFACE"
    switch_active_to "$id" && { log "OK connected=$id"; _dlog "vpn-health-check.sh:exit_connected" "exit 0 connected" "{\"id\":\"$id\"}" "G"; exit 0; }
  fi
  do_switch_to "$POLLING_IFACE" "$cur" 2>/dev/null || true
  sleep 2
done

err "no endpoint passed"
_dlog "vpn-health-check.sh:exit_no_endpoint_2" "exit 1 no endpoint (stale)" "{}" "G"; exit 1
