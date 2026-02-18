#!/usr/bin/env ucode
'use strict';

let cursor = require('uci').cursor;
let fs = require('fs');
let script_path = '/usr/bin/kge-vpn-watchdog';
// Writable by default: /usr is read-only on OpenWrt; use overlay /etc (see docs/LUCI-LESSONS.md).
let default_sites_path = '/etc/kge-vpn-watchdog/sites.conf';

let uci_section = null;

function peer_id_ok(s) {
	// peer_<digits>: minimal check for rpcd ucode (no split/replace/string indexing)
	if (!s || type(s) !== 'string' || length(s) < 7) return false;
	return index(s, 'peer_') === 0;
}

function get_uci(key, default_val) {
	let u = cursor();
	u.load('vpn_watchdog');
	let sec = u.get_first('vpn_watchdog', 'watchdog');
	if (sec) uci_section = sec;
	let v = sec ? u.get('vpn_watchdog', sec, key) : null;
	u.unload();
	return v != null ? v : default_val;
}

function sites_path() {
	let p = get_uci('sites_file', '');
	return (p !== '') ? p : default_sites_path;
}

function get_wg_group_id() {
	let vpn_iface = get_uci('vpn_iface', '');
	if (vpn_iface === '') {
		// Detect only what exists in UCI. Contract: network.IFACE.proto=wgclient|wireguard, .config=peer id. See BE3600-LUCI-FILE-FACTS §8.
		let u = cursor();
		u.load('network');
		let nets = u.get_all('network') || {};
		for (let k in nets) {
			let v = nets[k];
			if (!v || v['.type'] !== 'interface') continue;
			if (v.proto === 'wgclient' || v.proto === 'wireguard') {
				vpn_iface = k;
				break;
			}
			let cfg = v.config;
			if (cfg && peer_id_ok(cfg)) {
				u.load('wireguard');
				if (u.get('wireguard', cfg, 'public_key')) {
					vpn_iface = k;
					u.unload();
					break;
				}
				u.unload();
			}
		}
		u.unload();
	}
	if (vpn_iface === '') return null;
	let u = cursor();
	u.load('network');
	let cur = u.get('network', vpn_iface, 'config');
	u.unload();
	if (!cur) {
		u = cursor();
		u.load('wireguard');
		let all = u.get_all('wireguard') || {};
		for (let k in all) {
			if (peer_id_ok(k)) {
				let gid = u.get('wireguard', k, 'group_id');
				if (gid) { u.unload(); return gid; }
			}
		}
		u.unload();
		return null;
	}
	u = cursor();
	u.load('wireguard');
	let gid = u.get('wireguard', cur, 'group_id');
	u.unload();
	return gid;
}

// Infer region/country from endpoint host or description. Use lc() and index() for rpcd ucode.
function infer_region(host, desc) {
	let t = lc((host || '') + ' ' + (desc || ''));
	let pairs = [
		['us', 'US'], ['usa', 'US'], ['united states', 'US'], ['.us', 'US'], ['us-', 'US'],
		['ca', 'CA'], ['canada', 'CA'], ['.ca', 'CA'], ['ca-', 'CA'],
		['uk', 'UK'], ['gb', 'UK'], ['united kingdom', 'UK'], ['.uk', 'UK'], ['uk-', 'UK'],
		['de', 'DE'], ['germany', 'DE'], ['.de', 'DE'], ['de-', 'DE'],
		['nl', 'NL'], ['netherlands', 'NL'], ['.nl', 'NL'], ['nl-', 'NL'],
		['fr', 'FR'], ['france', 'FR'], ['.fr', 'FR'], ['fr-', 'FR'],
		['sg', 'SG'], ['singapore', 'SG'], ['.sg', 'SG'], ['sg-', 'SG'],
		['au', 'AU'], ['australia', 'AU'], ['.au', 'AU'], ['au-', 'AU'],
		['jp', 'JP'], ['japan', 'JP'], ['.jp', 'JP'], ['jp-', 'JP'],
		['ch', 'CH'], ['switzerland', 'CH'], ['.ch', 'CH'], ['ch-', 'CH'],
		['se', 'SE'], ['sweden', 'SE'], ['.se', 'SE'], ['se-', 'SE'],
		['no', 'NO'], ['norway', 'NO'], ['.no', 'NO'], ['no-', 'NO'],
		['fi', 'FI'], ['finland', 'FI'], ['.fi', 'FI'], ['fi-', 'FI'],
		['pl', 'PL'], ['poland', 'PL'], ['.pl', 'PL'], ['pl-', 'PL'],
		['es', 'ES'], ['spain', 'ES'], ['.es', 'ES'], ['es-', 'ES'],
		['it', 'IT'], ['italy', 'IT'], ['.it', 'IT'], ['it-', 'IT'],
		['br', 'BR'], ['brazil', 'BR'], ['.br', 'BR'], ['br-', 'BR'],
		['in', 'IN'], ['india', 'IN'], ['.in', 'IN'], ['in-', 'IN'],
		['hk', 'HK'], ['hong kong', 'HK'], ['.hk', 'HK'], ['hk-', 'HK'],
		['kr', 'KR'], ['korea', 'KR'], ['.kr', 'KR'], ['kr-', 'KR']
	];
	for (let i = 0; i < pairs.length; i++) {
		if (index(t, pairs[i][0]) >= 0) return pairs[i][1];
	}
	return '';
}

// Wireguard UCI on device: section type "peers", options end_point (host:port), name, location, group_id, public_key.
// See: uci show wireguard (peer sections = wireguard.peer_XXXX=peers).
function collect_peers_from_wireguard(gid) {
	let peers = [];
	let u = cursor();
	u.load('wireguard');
	let all = u.get_all('wireguard') || {};
	for (let sid in all) {
		if (!peer_id_ok(sid)) continue;
		let pk = u.get('wireguard', sid, 'public_key');
		if (!pk) continue;
		if (gid != null) {
			let sgid = u.get('wireguard', sid, 'group_id');
			if (sgid !== gid) continue;
		}
		let endpoint = u.get('wireguard', sid, 'end_point') || u.get('wireguard', sid, 'endpoint_host') || '';
		if (!endpoint && (u.get('wireguard', sid, 'endpoint_host') || u.get('wireguard', sid, 'host')))
			endpoint = (u.get('wireguard', sid, 'endpoint_host') || u.get('wireguard', sid, 'host') || '') + ':' + (u.get('wireguard', sid, 'endpoint_port') || u.get('wireguard', sid, 'port') || '');
		let desc = u.get('wireguard', sid, 'name') || u.get('wireguard', sid, 'location') || u.get('wireguard', sid, 'description') || '';
		let region = infer_region(endpoint, desc);
		push(peers, { id: sid, endpoint: endpoint, description: desc, region: region });
	}
	u.unload();
	sort(peers, function(a, b) { return (a.id < b.id ? -1 : 1); });
	return peers;
}

let methods = {
	get_peers: {
		call: function() {
			let gid = get_wg_group_id();
			let whitelist_raw = get_uci('peer_whitelist', '') || '';
			let whitelist = (whitelist_raw === '') ? [] : split(ltrim(rtrim(whitelist_raw)), /\s+/);
			let peers = collect_peers_from_wireguard(gid);
			if (length(peers) === 0 && gid == null)
				peers = collect_peers_from_wireguard(null);
			return { peers: peers, whitelist: whitelist };
		}
	},
	set_peer_whitelist: {
		args: { peers: [] },
		call: function(req) {
			let list = req.args && Array.isArray(req.args.peers) ? req.args.peers : [];
			let val = list.map(p => String(p).trim()).filter(p => peer_id_ok(p)).join(' ');
			try {
				let u = cursor();
				u.load('vpn_watchdog');
				let name = u.get_first('vpn_watchdog', 'watchdog');
				if (name) {
					u.set('vpn_watchdog', name, 'peer_whitelist', val);
					u.save('vpn_watchdog');
					u.commit('vpn_watchdog');
				}
				u.unload();
				return { ok: true, whitelist: val ? val.split(' ') : [] };
			} catch (e) {
				return { ok: false, error: e.message || String(e) };
			}
		}
	},
	get_status: {
		call: function() {
			get_uci('enabled', '1');
			return {
				enabled: get_uci('enabled', '1') === '1',
				log_path: get_uci('log_path') || '',
				sites_file: get_uci('sites_file') || '',
				vpn_iface: get_uci('vpn_iface') || '',
				polling_iface: get_uci('polling_iface') || '',
				sleep_after_switch: get_uci('sleep_after_switch') || '3',
				curl_connect_timeout: get_uci('curl_connect_timeout') || '3',
				curl_max_time: get_uci('curl_max_time') || '8',
				cron_enabled: get_uci('cron_enabled', '1') === '1',
				cron_interval: get_uci('cron_interval') || '5',
				cron_schedule: get_uci('cron_schedule') || '',
				run_timeout: get_uci('run_timeout') || '120',
				log_tail_lines: get_uci('log_tail_lines') || '200',
				script_path: fs.access(script_path) ? script_path : '',
				peer_whitelist: get_uci('peer_whitelist') || '',
				section: uci_section || ''
			};
		}
	},
	get_log: {
		args: { lines: 64 },
		call: function(req) {
			let path = get_uci('log_path') || '';
			let n = req.args && req.args.lines ? parseInt(req.args.lines, 10) : parseInt(get_uci('log_tail_lines', '200'), 10);
			if (path === '' || !fs.access(path))
				return { lines: '', path: '' };
			let data = fs.readfile(path);
			if (data === null) return { lines: '', path: path };
			let arr = data.split("\n");
			let start = arr.length > n ? arr.length - n : 0;
			return { lines: arr.slice(start).join("\n"), path: path };
		}
	},
	get_sites: {
		call: function() {
			let path = sites_path();
			let default_content = 'google\tgoogle.com\t-\t-\nwikipedia\twikipedia.org\t-\t-\n';
			if (!fs.access(path)) return { content: default_content, path: path };
			let data = fs.readfile(path);
			let content = (data !== null && data !== '') ? data : default_content;
			return { content: content, path: path };
		}
	},
		set_sites: {
			args: { content: '' },
			call: function(req) {
				let path = sites_path();
				let content = (req.args && req.args.content != null) ? String(req.args.content) : '';
				let dir = fs.dirname(path);
				if (dir && !fs.access(dir, 'f')) {
					fs.mkdir(dir);
				}
				try {
					fs.writefile(path, content);
					return { ok: true, path: path };
				} catch (e) {
					let msg = fs.error() || (e && (e.message || e.code || String(e))) || 'Unknown error';
					if (msg === '[object Object]') msg = 'Write failed (permission or read-only?)';
					return { ok: false, error: msg };
				}
			}
		},
	apply_cron: {
		call: function() {
			let enabled = get_uci('cron_enabled', '1') === '1';
			let schedule = get_uci('cron_schedule', '');
			let interval = get_uci('cron_interval', '5');
			let cron_line = '';
			if (enabled) {
				if (schedule !== '') cron_line = schedule + ' ' + script_path;
				else cron_line = '*/' + interval + ' * * * * ' + script_path;
			}
			let crontab_path = '/etc/crontabs/root';
			let rest = '';
			if (fs.access(crontab_path)) {
				let data = fs.readfile(crontab_path);
				if (data !== null) rest = data.split("\n").filter(function(l) { return l.indexOf(script_path) < 0 && l.replace(/^\s*#?/, '').length > 0; }).join("\n");
			}
			let out = (cron_line !== '' ? cron_line + "\n" : '') + (rest !== '' ? rest + "\n" : '');
			try {
				fs.writefile(crontab_path, out);
				return { ok: true, cron_line: cron_line || '(disabled)' };
			} catch (e) {
				let msg = fs.error() || (e && (e.message || String(e))) || 'Cron write failed';
				return { ok: false, error: msg };
			}
		}
	},
	run_now: {
		args: { dry_run: true },
		call: function(req) {
			let dry = req.args && req.args.dry_run;
			let timeout = parseInt(get_uci('run_timeout', '120'), 10) || 120;
			let shCmd = dry ? ('VPN_DRY_RUN=1 ' + script_path + ' 2>&1') : (script_path + ' 2>&1');
			let out = '';
			let code = 255;
			try {
				let run = require('run');
				let result = run(shCmd, timeout);
				code = result && result.code != null ? result.code : 255;
				out = (result && result.stdout) ? result.stdout : '';
			} catch (e) {
				try {
					let fullCmd = "/bin/sh -c '" + shCmd + "'";
					let fp = fs.popen(fullCmd, 'r');
					out = fp.read('all') || '';
					code = fp.close();
					if (code == null || code < 0) code = 255;
				} catch (e2) {
					out = 'run_not_available: ' + (e.message || e) + '; popen: ' + (e2.message || e2);
				}
			}
			return { exitcode: code, output: out };
		}
	}
};

return { 'luci.vpn_watchdog': methods };
