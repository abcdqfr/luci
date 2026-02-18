#!/usr/bin/env ucode
'use strict';
// VPN health engine: UCI-only, polling interface for checks. Replaces shell engine (ADR-0005).
// Invoked by cron and by RPC run_now via /usr/bin/kge-vpn-watchdog.

let cursor = require('uci').cursor;
let fs = require('fs');
// run module is rpcd-only; use fs.popen for ifup/ifdown when running standalone (cron, CLI)

let default_sites_path = '/etc/kge-vpn-watchdog/sites.conf';
let watchdog_section = null;

function get_uci(key, default_val) {
	let u = cursor();
	u.load('vpn_watchdog');
	let sec = u.get_first('vpn_watchdog', 'watchdog');
	if (sec) watchdog_section = sec;
	let v = sec ? u.get('vpn_watchdog', sec, key) : null;
	u.unload();
	return v != null ? v : default_val;
}

function resolve_sites_file() {
	let p = get_uci('sites_file', '');
	if (p !== '') return p;
	if (fs.access('/etc/kge-vpn-watchdog/sites.conf')) return '/etc/kge-vpn-watchdog/sites.conf';
	return '/usr/share/kge-vpn-watchdog/sites.conf';
}

function detect_wg_iface() {
	let u = cursor();
	u.load('network');
	let nets = u.get('network') || {};
	for (let k in nets) {
		let v = nets[k];
		if (!v || v['.type'] !== 'interface') continue;
		if (v.proto === 'wgclient' || v.proto === 'wireguard') {
			u.unload();
			return k;
		}
		let cfg = v.config;
		if (cfg && match(cfg, /^peer_[0-9]+$/)) {
			u.load('wireguard');
			if (u.get('wireguard', cfg, 'public_key')) {
				u.unload();
				return k;
			}
			u.unload();
		}
	}
	u.unload();
	return '';
}

function current(vpn_iface) {
	let u = cursor();
	u.load('network');
	let c = u.get('network', vpn_iface, 'config');
	u.unload();
	return c != null ? c : '';
}

function peers_list(vpn_iface) {
	let cur = current(vpn_iface);
	let gid = null;
	let u = cursor();
	u.load('wireguard');
	if (cur) {
		gid = u.get('wireguard', cur, 'group_id');
	}
	let all = u.get_all('wireguard') || {};
	if (!gid) {
		for (let sid in all) {
			if (match(sid, /^peer_[0-9]+$/)) {
				gid = u.get('wireguard', sid, 'group_id');
				if (gid) break;
			}
		}
	}
	if (!gid) {
		u.unload();
		return [];
	}
	let out = [];
	for (let sid in all) {
		if (match(sid, /^peer_[0-9]+$/) && u.get('wireguard', sid, 'group_id') === gid) {
			out.push(sid);
		}
	}
	u.unload();
	return out;
}

function peers_list_filtered(vpn_iface) {
	let wl = peers_list(vpn_iface);
	if (wl.length === 0) return [];
	let raw = get_uci('peer_whitelist', '');
	if (raw === '' || raw == null) return wl;
	let list = ('' + raw).trim().split(/\s+/);
	let allow = {};
	for (let i = 0; i < list.length; i++) allow[list[i]] = true;
	let out = [];
	for (let i = 0; i < wl.length; i++) {
		if (allow[wl[i]]) out.push(wl[i]);
	}
	return out;
}

function ensure_polling_interface(name, vpn_iface) {
	let wl = peers_list_filtered(vpn_iface);
	if (wl.length === 0) wl = peers_list(vpn_iface);
	if (wl.length === 0) return false;
	let first_peer = wl[0];
	let u = cursor();
	u.load('wireguard');
	if (!u.get('wireguard', first_peer, 'public_key')) {
		u.unload();
		return false;
	}
	u.unload();
	u = cursor();
	u.load('network');
	if (!u.get('network', name)) {
		let newsec = u.add('network', 'interface');
		if (!newsec) { u.unload(); return false; }
		u.rename('network', newsec, name);
	}
	u.set('network', name, 'proto', 'wgclient');
	u.set('network', name, 'config', first_peer);
	u.commit('network');
	u.unload();
	return true;
}

function teardown_polling_interface(name) {
	try {
		let fp = fs.popen('ifdown ' + name + ' 2>/dev/null', 'r');
		if (fp) { fp.read('all'); fp.close(); }
	} catch (e) {}
	let u = cursor();
	u.load('network');
	u.delete('network', name);
	u.commit('network');
	u.unload();
}

function log(msg, log_path) {
	let ts = fs.popen('date +\'+%Y-%m-%dT%H:%M:%S\' 2>/dev/null', 'r');
	let line = ts ? (ts.read('all') || '').trim() : '';
	if (ts) ts.close();
	let s = '[vpn] ' + (line || '') + ' ' + msg;
	print(s, "\n");
	if (log_path && log_path !== '') {
		try {
			let f = fs.open(log_path, 'a');
			if (f) { f.write(s + '\n'); f.close(); }
		} catch (e) {}
	}
}

function err(msg, log_path) {
	let s = '[vpn] ' + msg;
	print(s, "\n");
	if (log_path && log_path !== '') {
		try {
			let f = fs.open(log_path, 'a');
			if (f) { f.write(s + '\n'); f.close(); }
		} catch (e) {}
	}
}

function normalize_url(u) {
	if (match(u, /^https?:\/\//)) return u;
	return 'https://' + u.replace(/\/+$/, '') + '/';
}

function check_site(url, block, success, check_iface, connect_to, max_time) {
	url = normalize_url(url);
	let tmpdir = fs.mkdtemp('/tmp/vpn-check.XXXXXX');
	if (!tmpdir) return false;
	let tmp = tmpdir + '/body';
	let extra = (check_iface && check_iface !== '') ? ('--interface ' + check_iface) : '';
	let cmd = 'curl -sS -f -o ' + tmp + ' -w "%{http_code}" --connect-timeout ' + (connect_to || 3) + ' --max-time ' + (max_time || 8) + ' ' + extra + ' ' + url + ' 2>/dev/null';
	let fp = fs.popen(cmd, 'r');
	let code = (fp.read('all') || '').trim();
	fp.close();
	let ok = match(code, /^2[0-9][0-9]$/);
	if (!ok) {
		try { fs.unlink(tmp); } catch (e) {}
		return false;
	}
	let body = '';
	try {
		if (fs.access(tmp)) body = fs.readfile(tmp) || '';
		fs.unlink(tmp);
	} catch (e) {}
	if (block && block !== '-') {
		let re = regexp(block, 'i');
		if (match(body, re)) return false;
	}
	if (success && success !== '-') {
		let re = regexp(success, 'i');
		if (!match(body, re)) return false;
	}
	return true;
}

function check_all(sites_file, check_iface, connect_to, max_time, log_path) {
	if (!fs.access(sites_file, 'r')) {
		err('sites missing: ' + sites_file, log_path);
		return false;
	}
	let data = fs.readfile(sites_file) || '';
	let lines = data.split(/\n/);
	for (let i = 0; i < lines.length; i++) {
		let parts = lines[i].split(/\t/);
		let name = parts[0] ? parts[0].trim() : '';
		let url = parts[1] ? parts[1].trim() : '';
		if (name === '' || name.indexOf('#') === 0 || url === '') continue;
		let block = (type(parts[2]) === 'string' && parts[2].trim() !== '') ? parts[2].trim() : '-';
		let success = (type(parts[3]) === 'string' && parts[3].trim() !== '') ? parts[3].trim() : '-';
		if (!check_site(url, block, success, check_iface, connect_to, max_time)) {
			log('site FAIL: ' + name, log_path);
			return false;
		}
	}
	return true;
}

function do_switch_to(iface, id) {
	let u = cursor();
	u.load('wireguard');
	if (!u.get('wireguard', id, 'public_key')) {
		u.unload();
		return false;
	}
	u.unload();
	u = cursor();
	u.load('network');
	u.set('network', iface, 'config', id);
	u.commit('network');
	u.unload();
	try {
		let fp = fs.popen('ifup ' + iface + ' 2>/dev/null', 'r');
		if (fp) { fp.read('all'); fp.close(); }
	} catch (e) {}
	return true;
}

function try_switch_polling(polling_iface, id, sleep_sec, sites_file, connect_to, max_time, log_path) {
	if (!do_switch_to(polling_iface, id)) return false;
	// sleep
	let fp = fs.popen('sleep ' + (sleep_sec || 3) + ' 2>/dev/null', 'r');
	if (fp) { fp.read('all'); fp.close(); }
	return check_all(sites_file, polling_iface, connect_to, max_time, log_path);
}

function switch_active_to(active_iface, id) {
	return do_switch_to(active_iface, id);
}

// --- main
function main() {
	if (get_uci('enabled', '1') === '0') return 0;

	let sites_file = resolve_sites_file();
	let vpn_iface = get_uci('vpn_iface', '') || '';
	if (vpn_iface === '') vpn_iface = detect_wg_iface();

	if (vpn_iface === '') {
		let u = cursor();
		u.load('wireguard');
		let all = u.get_all('wireguard') || {};
		let has_peers = false;
		for (let sid in all) { if (match(sid, /^peer_[0-9]+$/)) { has_peers = true; break; } }
		u.unload();
		if (has_peers) {
			err('no WireGuard interface in network. Set vpn_iface in LuCI (Services → KGE VPN Watchdog) to the client interface name, or connect VPN once so the interface exists.');
		} else {
			err('no WireGuard interface and no wireguard peers in UCI.');
		}
		return 1;
	}

	let active_iface = vpn_iface;
	let polling_iface = get_uci('polling_iface', '') || 'wgclient_poll';
	let sleep_sec = parseInt(get_uci('sleep_after_switch', '3'), 10) || 3;
	let dry_run = (getenv('VPN_DRY_RUN') || '0').trim();
	if (dry_run !== '0' && dry_run !== '') dry_run = '1';
	let log_path = get_uci('log_path', '') || '';
	let connect_to = get_uci('curl_connect_timeout', '3') || '3';
	let max_time = get_uci('curl_max_time', '8') || '8';

	if (!ensure_polling_interface(polling_iface, vpn_iface)) {
		err('failed to ensure polling iface ' + polling_iface, log_path);
		return 1;
	}
	// Teardown on exit
	let teardown = function() { teardown_polling_interface(polling_iface); };
	// ucode has no process.on('exit'); we teardown at end of main or on explicit exit paths

	let cur = current(vpn_iface);
	let wl = peers_list_filtered(vpn_iface);
	if (wl.length === 0) {
		err('no peers (uci wireguard or whitelist empty)', log_path);
		teardown();
		return 1;
	}

	if (cur === '') {
		if (dry_run === '1') {
			log('no current (dry run)', log_path);
			teardown();
			return 1;
		}
		log('no current; find and connect (poll via ' + polling_iface + ')', log_path);
		for (let i = 0; i < wl.length; i++) {
			let id = wl[i];
			log('try ' + id, log_path);
			if (try_switch_polling(polling_iface, id, sleep_sec, sites_file, connect_to, max_time, log_path)) {
				log('KGE=' + id + '; applying to active ' + active_iface, log_path);
				if (switch_active_to(active_iface, id)) {
					log('OK connected=' + id, log_path);
					teardown();
					return 0;
				}
			}
			// Restore polling to cur before next try (cur is empty here, restore to first or leave)
			do_switch_to(polling_iface, wl[0]);
			let fp = fs.popen('sleep 2 2>/dev/null', 'r');
			if (fp) { fp.read('all'); fp.close(); }
		}
		err('no endpoint passed', log_path);
		teardown();
		return 1;
	}

	log('poll current=' + cur + ' (active=' + active_iface + ' poll=' + polling_iface + ')', log_path);
	do_switch_to(polling_iface, cur);
	(function() {
		let fp = fs.popen('sleep ' + sleep_sec + ' 2>/dev/null', 'r');
		if (fp) { fp.read('all'); fp.close(); }
	})();
	let check_ok = check_all(sites_file, polling_iface, connect_to, max_time, log_path);
	if (check_ok) {
		if (dry_run === '1') {
			log('OK (dry run)', log_path);
			teardown();
			return 0;
		}
		teardown();
		return 0;
	}

	if (dry_run === '1') {
		log('stale (dry run)', log_path);
		teardown();
		return 1;
	}
	log('current stale; find and connect (poll via ' + polling_iface + ')', log_path);
	for (let i = 0; i < wl.length; i++) {
		let id = wl[i];
		if (id === cur) continue;
		log('try ' + id, log_path);
		if (try_switch_polling(polling_iface, id, sleep_sec, sites_file, connect_to, max_time, log_path)) {
			log('KGE=' + id + '; applying to active ' + active_iface, log_path);
			if (switch_active_to(active_iface, id)) {
				log('OK connected=' + id, log_path);
				teardown();
				return 0;
			}
		}
		do_switch_to(polling_iface, cur);
		(function() {
			let fp = fs.popen('sleep 2 2>/dev/null', 'r');
			if (fp) { fp.read('all'); fp.close(); }
		})();
	}
	err('no endpoint passed', log_path);
	teardown();
	return 1;
}

let code = main();
exit(code);
