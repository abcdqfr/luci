#!/usr/bin/env ucode
'use strict';
// LuCI RPC plugin: luci.vpn_watchdog (rpcd ucode). Status, peers, sites, cron, run_now.

let cursor = require('uci').cursor;
let fs = require('fs');
let script_path = '/usr/bin/kge-vpn-watchdog';
// Sites path: default /etc (writable overlay); /usr is read-only on OpenWrt.
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
		// Detect WireGuard/wgclient interface from UCI network + wireguard peer refs.
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
	// Generic fallback for provider descriptions like "Denmark_dk-cph-wg-001" => DK
	let d = lc('' + (desc || ''));
	let segs = split(d, '_');
	if (length(segs) > 1) {
		let region_part = split(segs[1], '-');
		if (length(region_part) > 0) {
			let cc = region_part[0];
			if (length(cc) === 2) return uc(cc);
		}
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
	sort(peers, function (a, b) { return (a.id < b.id ? -1 : 1); });
	return peers;
}

function trim_ws(s) {
	return ltrim(rtrim('' + s));
}

function split_ws(s) {
	let t = trim_ws(s);
	return (t === '') ? [] : split(t, /\s+/);
}

function join_lines(arr, start) {
	let out = '';
	for (let i = start; i < length(arr); i++) {
		out += arr[i];
		if (i + 1 < length(arr)) out += "\n";
	}
	return out;
}

function join_space(arr) {
	let out = '';
	for (let i = 0; i < length(arr); i++) {
		if (i > 0) out += ' ';
		out += arr[i];
	}
	return out;
}

function has_non_comment_text(line) {
	let t = ltrim('' + line);
	if (t === '') return false;
	if (index(t, '#') === 0) t = ltrim(substr(t, 1));
	return t !== '';
}

let methods = {
	get_peers: {
		call: function () {
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
		call: function (req) {
			let list = (req.args && type(req.args.peers) === 'array') ? req.args.peers : [];
			let selected = [];
			for (let i = 0; i < length(list); i++) {
				let p = trim_ws(list[i]);
				if (peer_id_ok(p)) push(selected, p);
			}
			let val = join_space(selected);
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
				return { ok: true, whitelist: selected };
			} catch (e) {
				return { ok: false, error: e.message || ('' + e) };
			}
		}
	},
	get_status: {
		call: function () {
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
		call: function (req) {
			let path = get_uci('log_path') || '';
			let n = req && req.args && req.args.lines ? int(req.args.lines, 10) : int(get_uci('log_tail_lines', '200'), 10);
			if (n < 1 || n > 10000) n = 200;
			try {
				if (path === '' || !fs.access(path))
					return { lines: '', path: path || '' };
				let data = fs.readfile(path);
				if (data === null) return { lines: '', path: path };
				let arr = split('' + data, "\n");
				let start = length(arr) > n ? length(arr) - n : 0;
				return { lines: join_lines(arr, start), path: path };
			} catch (e) {
				return { lines: '', path: path || '', error: (e && (e.message || String(e))) || 'read failed' };
			}
		}
	},
	get_sites: {
		call: function () {
			let default_content = 'reddit\treddit.com\tblocked|access.denied|captcha|cf-browser|challenge|verify\treddit\n'
				+ 'youtube\tyoutube.com\tblocked|access.denied|captcha|cf-browser|challenge|verify\tyoutube\n'
				+ 'wikipedia\twikipedia.org\tblocked|access.denied|captcha|cf-browser|challenge|verify\twikipedia\n';
			try {
				let path = sites_path();
				if (!path || !fs.access(path)) return { content: default_content, path: path || '' };
				let data = fs.readfile(path);
				let content = (data !== null && data !== '') ? data : default_content;
				return { content: content, path: path };
			} catch (e) {
				return { content: default_content, path: '', error: (e && (e.message || String(e))) || 'read failed' };
			}
		}
	},
	set_sites: {
		args: { content: '' },
		call: function (req) {
			let path = sites_path();
			let content = (req.args && req.args.content != null) ? ('' + req.args.content) : '';
			let dir = fs.dirname(path);
			if (dir && !fs.access(dir))
				fs.mkdir(dir);
			try {
				fs.writefile(path, content);
				return { ok: true, path: path };
			} catch (e) {
				let msg = fs.error() || (e && (e.message || e.code || ('' + e))) || 'Unknown error';
				if (msg === '[object Object]') msg = 'Write failed (permission or read-only?)';
				return { ok: false, error: msg };
			}
		}
	},
	apply_cron: {
		call: function () {
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
				if (data !== null) {
					let lines = split('' + data, "\n");
					let kept = [];
					for (let i = 0; i < length(lines); i++) {
						let l = lines[i];
						if (index(l, script_path) >= 0) continue;
						if (has_non_comment_text(l)) push(kept, l);
					}
					rest = join_lines(kept, 0);
				}
			}
			let out = (cron_line !== '' ? cron_line + "\n" : '') + (rest !== '' ? rest + "\n" : '');
			try {
				fs.writefile(crontab_path, out);
				return { ok: true, cron_line: cron_line || '(disabled)' };
			} catch (e) {
				let msg = fs.error() || (e && (e.message || ('' + e))) || 'Cron write failed';
				return { ok: false, error: msg };
			}
		}
	},
	run_now: {
		args: { dry_run: true },
		call: function (req) {
			let code = 255;
			let out = '';
			try {
				let dry = req && req.args && req.args.dry_run;
				let timeout = int(get_uci('run_timeout', '120'), 10) || 120;
				if (timeout < 1 || timeout > 600) timeout = 120;
				let shCmd = dry ? ('VPN_DRY_RUN=1 ' + script_path + ' 2>&1') : (script_path + ' 2>&1');
				try {
					let run = require('run');
					let result = run(shCmd, timeout);
					let c = (result && result.code != null) ? int(result.code, 10) : null;
					code = (c != null && c === c) ? c : 255;
					out = (result && result.stdout != null) ? String(result.stdout) : '';
				} catch (e) {
					try {
						let fullCmd = "/bin/sh -c '" + shCmd + "'";
						let fp = fs.popen(fullCmd, 'r');
						out = fp.read('all');
						out = (out != null) ? String(out) : '';
						let c = fp.close();
						let c2 = (c != null && c >= 0) ? int(c, 10) : null;
						code = (c2 != null && c2 === c2) ? c2 : 255;
					} catch (e2) {
						out = 'run_not_available: ' + (e && (e.message || e)) + '; popen: ' + (e2 && (e2.message || e2));
					}
				}
			} catch (e) {
				code = 255;
				out = 'error: ' + (e && (e.message || String(e)) || 'unknown');
			}
			return { exitcode: code, output: out };
		}
	}
};

return { 'luci.vpn_watchdog': methods };
