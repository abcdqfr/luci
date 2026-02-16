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

[ -z "$VPN_IFACE" ] && VPN_IFACE=$(detect_wg_iface)
[ -z "$VPN_IFACE" ] && { err "no wgclient (uci)"; exit 1; }

ACTIVE_IFACE="$VPN_IFACE"
POLLING_IFACE="${POLLING_IFACE:-$(_u polling_iface)}"
[ -z "$POLLING_IFACE" ] && POLLING_IFACE=wgclient_poll
export CHECK_IFACE="$POLLING_IFACE"

ensure_polling_interface "$POLLING_IFACE" || { err "failed to ensure polling iface $POLLING_IFACE"; exit 1; }
trap 'teardown_polling_interface "$POLLING_IFACE"' EXIT INT TERM

cur=$(current)
wl=$(peers_list_filtered)
[ -z "$wl" ] && { err "no peers (uci wireguard or whitelist empty)"; exit 1; }

if [ -z "$cur" ]; then
  [ -n "$DRY_RUN" ] && [ "$DRY_RUN" != "0" ] && { log "no current (dry run)"; exit 1; }
  log "no current; find and connect (poll via $POLLING_IFACE)"
  for id in $wl; do
    log "try $id"
    if try_switch_polling "$id"; then
      log "KGE=$id; applying to active $ACTIVE_IFACE"
      switch_active_to "$id" && { log "OK connected=$id"; exit 0; }
    fi
    sleep 2
  done
  err "no endpoint passed"
  exit 1
fi

log "poll current=$cur (active=$ACTIVE_IFACE poll=$POLLING_IFACE)"
do_switch_to "$POLLING_IFACE" "$cur" 2>/dev/null || true
sleep "$SLEEP"
if check_all; then
  [ -n "$DRY_RUN" ] && [ "$DRY_RUN" != "0" ] && { log "OK (dry run)"; exit 0; }
  exit 0
fi

[ -n "$DRY_RUN" ] && [ "$DRY_RUN" != "0" ] && { log "stale (dry run)"; exit 1; }
log "current stale; find and connect (poll via $POLLING_IFACE)"
for id in $wl; do
  [ "$id" = "$cur" ] && continue
  log "try $id"
  if try_switch_polling "$id"; then
    log "KGE=$id; applying to active $ACTIVE_IFACE"
    switch_active_to "$id" && { log "OK connected=$id"; exit 0; }
  fi
  do_switch_to "$POLLING_IFACE" "$cur" 2>/dev/null || true
  sleep 2
done

err "no endpoint passed"
exit 1
