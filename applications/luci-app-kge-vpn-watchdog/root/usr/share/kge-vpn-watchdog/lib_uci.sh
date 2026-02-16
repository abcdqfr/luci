# UCI: wg iface, current peer, peer list. Expects VPN_IFACE.
# POLLING_IFACE_NAME: name of the dedicated polling interface (default wgclient_poll).
detect_wg_iface() { uci show network 2>/dev/null | grep "\.proto='wgclient'" | head -1 | sed "s/^network\.\([^.]*\)\..*/\1/"; }
current() { uci get "network.${VPN_IFACE}.config" 2>/dev/null; }
peers_list() {
  cur=$(uci get "network.${VPN_IFACE}.config" 2>/dev/null)
  [ -n "$cur" ] && gid=$(uci get "wireguard.${cur}.group_id" 2>/dev/null)
  [ -z "$gid" ] && gid=$(uci show wireguard 2>/dev/null | grep "\.group_id=" | head -1 | sed "s/.*'\(.*\)'/\1/")
  [ -z "$gid" ] && return
  uci show wireguard 2>/dev/null | grep "\.group_id='${gid}'" | sed "s/\.group_id=.*//;s/^wireguard\.//" | grep -E '^peer_[0-9]+$'
}

# If peer_whitelist is set in UCI, output only those peers (from peers_list) that are in the whitelist.
# If peer_whitelist is empty/unset, output full peers_list. Call after peers_list; uses same VPN_IFACE.
peers_list_filtered() {
  local wl raw_whitelist id out
  wl=$(peers_list)
  [ -z "$wl" ] && return
  raw_whitelist=$(uci -q get vpn_watchdog.@watchdog[0].peer_whitelist 2>/dev/null)
  if [ -z "$raw_whitelist" ]; then
    echo "$wl"
    return
  fi
  out=""
  for id in $wl; do
    case " ${raw_whitelist} " in *" ${id} "*) out="${out}${out:+ }${id}";; esac
  done
  echo "$out"
}

# Polling interface (PI): exists ONLY while the script is running. Uses same key/creds as primary
# (same wireguard group_id). Create at run start, teardown on exit so idle = no PI, no contention.
ensure_polling_interface() {
  local name="${1:-wgclient_poll}"
  local first_peer
  wl=$(peers_list_filtered)
  [ -z "$wl" ] && wl=$(peers_list)
  [ -z "$wl" ] && return 1
  first_peer="${wl%% *}"
  uci get "wireguard.${first_peer}.public_key" >/dev/null 2>&1 || return 1
  if ! uci get "network.${name}" >/dev/null 2>&1; then
    newsec=$(uci add network interface) || return 1
    uci rename "network.${newsec}=${name}" 2>/dev/null || return 1
  fi
  uci set "network.${name}.proto=wgclient"
  uci set "network.${name}.config=${first_peer}"
  uci commit network 2>/dev/null || return 1
  return 0
}

# Remove PI from network config so it does not exist when idle. Call on script exit.
teardown_polling_interface() {
  local name="${1:-wgclient_poll}"
  ifdown "$name" 2>/dev/null || true
  uci delete "network.${name}" 2>/dev/null || true
  uci commit network 2>/dev/null || true
}
