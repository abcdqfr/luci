# luci-app-kge-vpn-watchdog

LuCI UI for KGE VPN Watchdog: enable/disable, log path, Run now, log viewer. Engine is the bundled shell scripts.

## Install

**From OpenWrt build:** LuCI → Applications → luci-app-kge-vpn-watchdog, then `opkg install` the ipk.

**Manual deploy:** Copy `root/` and `htdocs/` onto the device so that:

- `root/etc/uci-defaults/80_vpn_watchdog` → `/etc/uci-defaults/80_vpn_watchdog`
- `root/usr/share/luci/menu.d/luci-app-kge-vpn-watchdog.json` → `/usr/share/luci/menu.d/`
- `root/usr/share/rpcd/acl.d/luci-app-kge-vpn-watchdog.json` → `/usr/share/rpcd/acl.d/`
- `root/usr/share/rpcd/ucode/vpn_watchdog.uc` → `/usr/share/rpcd/ucode/`
- `htdocs/luci-static/resources/view/kge_vpn_watchdog/overview.js` → `/www/luci-static/resources/view/kge_vpn_watchdog/`
- `root/usr/share/kge-vpn-watchdog/*` → `/usr/share/kge-vpn-watchdog/`
- `root/usr/bin/kge-vpn-watchdog` → `/usr/bin/kge-vpn-watchdog` (chmod +x)

Run once: `sh /etc/uci-defaults/80_vpn_watchdog`, then restart rpcd and reload LuCI.

## Engine

- **`/usr/share/kge-vpn-watchdog/`** — `vpn-health-check.sh`, `lib_uci.sh`, `lib_sites.sh`, `lib_switch.sh`, `sites.conf`
- **`/usr/bin/kge-vpn-watchdog`** — wrapper that runs the main script (cron and Run now use this)

## Cron

When installed from ipk, add to crontab: `*/5 * * * * /usr/bin/kge-vpn-watchdog` (example: every 5 minutes).

## UCI

Config: `/etc/config/vpn_watchdog`. Section type `watchdog`, options `enabled` (0/1), `log_path` (optional).

## Run now (LuCI)

The Run now button calls the RPC `run_now`. If that fails (e.g. no run helper), run the script via SSH: `VPN_DRY_RUN=1 /usr/bin/kge-vpn-watchdog`.
