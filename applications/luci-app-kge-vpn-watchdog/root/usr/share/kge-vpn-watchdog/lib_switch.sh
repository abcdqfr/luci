# Switch peer on an interface: uci set + ifup. Expects SLEEP for try_switch_polling.
# do_switch_to(iface, id) = set iface to peer id and ifup.
# do_switch(id) = switch active interface (ACTIVE_IFACE or VPN_IFACE) to id.
# try_switch_polling(id) = set POLLING_IFACE to id, sleep, check_all (uses CHECK_IFACE=POLLING_IFACE).
# switch_active_to(id) = set ACTIVE_IFACE to id (apply chosen KGE to user traffic).
do_switch_to() {
  local iface="$1" id="$2"
  uci get "wireguard.${id}.public_key" >/dev/null 2>&1 || return 1
  uci set "network.${iface}.config=$id" || return 1
  uci commit network || return 1
  ifup "$iface" 2>/dev/null || true
  return 0
}
do_switch() {
  local target="${ACTIVE_IFACE:-$VPN_IFACE}"
  [ -z "$target" ] && return 1
  do_switch_to "$target" "$1"
}
switch_active_to() {
  [ -z "${ACTIVE_IFACE}" ] && return 1
  do_switch_to "$ACTIVE_IFACE" "$1"
}
try_switch_polling() {
  [ -z "${POLLING_IFACE}" ] && return 1
  do_switch_to "$POLLING_IFACE" "$1" 2>/dev/null || return 1
  sleep "${SLEEP:-3}"
  check_all
}
try_switch() {
  try_switch_polling "$1"
}
