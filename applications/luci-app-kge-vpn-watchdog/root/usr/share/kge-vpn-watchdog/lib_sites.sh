# Site checks: one URL, or all from SITES_FILE. Expects SITES_FILE; uses CHECK_IFACE if set else VPN_IFACE; uses log/err.
# Normalize URL: if not http:// or https://, treat as domain and use https://domain/
normalize_url() {
  local u="$1"
  case "$u" in
    http://*)  echo "$u" ;;
    https://*) echo "$u" ;;
    *) echo "https://${u%/}/" ;;
  esac
}
check_site() {
  url="$1" block="$2" success="$3"
  url=$(normalize_url "$url")
  t="/tmp/vpn-check.$$"
  check_iface="${CHECK_IFACE:-$VPN_IFACE}"; extra=""; [ -n "$check_iface" ] && extra="--interface $check_iface"
  code=$(curl -sS -f -o "$t" -w "%{http_code}" --connect-timeout 3 --max-time 8 $extra "$url" 2>/dev/null)
  echo "$code" | grep -qE '^2[0-9][0-9]$' || { rm -f "$t"; return 1; }
  [ -f "$t" ] || return 1
  [ -n "$block" ] && [ "$block" != "-" ] && grep -qiE "$block" "$t" 2>/dev/null && { rm -f "$t"; return 1; }
  [ -n "$success" ] && [ "$success" != "-" ] && ! grep -qiE "$success" "$t" 2>/dev/null && { rm -f "$t"; return 1; }
  rm -f "$t"; return 0
}
check_all() {
  [ ! -r "$SITES_FILE" ] && err "sites missing: $SITES_FILE" && return 1
  while IFS="$(printf '\t')" read -r name url block success; do
    [ -z "$name" ] || [ "${name#\#}" != "$name" ] && continue
    [ -z "$url" ] && continue
    [ -n "$block" ] || block="-"; [ -n "$success" ] || success="-"
    check_site "$url" "$block" "$success" || { log "site FAIL: $name"; return 1; }
  done < "$SITES_FILE"
  return 0
}
