#!/usr/bin/env ucode
'use strict';

let cursor = require('uci').cursor;
let fs = require('fs');
let script_path = '/usr/bin/kge-vpn-watchdog';
let default_sites_path = '/usr/share/kge-vpn-watchdog/sites.conf';

let uci_section = null;

function get_uci(key, default_val) {
	let u = cursor();
	u.load('vpn_watchdog');
	let s = u.sections('vpn_watchdog', 'watchdog');
	if (s && s.length > 0) uci_section = s[0]['.name'];
	let v = uci_section ? u.get('vpn_watchdog', uci_section, key) : null;
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
		// detect first wgclient
		let u = cursor();
		u.load('network');
		let nets = u.get('network') || {};
		for (let k in nets) {
			let v = nets[k];
			if (v && v['.type'] === 'interface' && v.proto === 'wgclient') {
				vpn_iface = k;
				break;
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
		let wg = u.get('wireguard') || {};
		for (let k in wg) {
			let v = wg[k];
			if (v && v['.type'] !== 'wireguard' && v.group_id) return v.group_id;
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

// Infer region/country from endpoint host or description for quick toggles (US, CA, UK, etc.).
function infer_region(host, desc) {
	let t = ((host || '') + ' ' + (desc || '')).toLowerCase();
	let patterns = [
		[/\b(us|usa|united states|\.us\b|us-)/, 'US'],
		[/\b(ca|canada|\.ca\b|ca-)/, 'CA'],
		[/\b(uk|gb|united kingdom|\.uk\b|uk-)/, 'UK'],
		[/\b(de|germany|\.de\b|de-)/, 'DE'],
		[/\b(nl|netherlands|\.nl\b|nl-)/, 'NL'],
		[/\b(fr|france|\.fr\b|fr-)/, 'FR'],
		[/\b(sg|singapore|\.sg\b|sg-)/, 'SG'],
		[/\b(au|australia|\.au\b|au-)/, 'AU'],
		[/\b(jp|japan|\.jp\b|jp-)/, 'JP'],
		[/\b(ch|switzerland|\.ch\b|ch-)/, 'CH'],
		[/\b(se|sweden|\.se\b|se-)/, 'SE'],
		[/\b(no|norway|\.no\b|no-)/, 'NO'],
		[/\b(fi|finland|\.fi\b|fi-)/, 'FI'],
		[/\b(pl|poland|\.pl\b|pl-)/, 'PL'],
		[/\b(es|spain|\.es\b|es-)/, 'ES'],
		[/\b(it|italy|\.it\b|it-)/, 'IT'],
		[/\b(br|brazil|\.br\b|br-)/, 'BR'],
		[/\b(in|india|\.in\b|in-)/, 'IN'],
		[/\b(hk|hong kong|\.hk\b|hk-)/, 'HK'],
		[/\b(kr|korea|\.kr\b|kr-)/, 'KR']
	];
	for (let i = 0; i < patterns.length; i++) {
		if (patterns[i][0].test(t)) return patterns[i][1];
	}
	return '';
}

let methods = {
	get_peers: {
		call: function() {
			let gid = get_wg_group_id();
			let peers = [];
			let whitelist_raw = get_uci('peer_whitelist', '') || '';
			let whitelist = (whitelist_raw === '') ? [] : whitelist_raw.trim().split(/\s+/);
			if (!gid) return { peers: peers, whitelist: whitelist };
			let u = cursor();
			u.load('wireguard');
			let wg = u.get('wireguard') || {};
			for (let name in wg) {
				let s = wg[name];
				if (!s || (s['.type'] && s['.type'] === 'wireguard')) continue;
				if (s.group_id !== gid) continue;
				let peerId = (s['.name'] && /^peer_[0-9]+$/.test(s['.name'])) ? s['.name'] : name;
				if (!/^peer_[0-9]+$/.test(peerId)) continue;
				let host = s.endpoint_host || s.host || '';
				let port = s.endpoint_port || s.port || '';
				let endpoint = (host && port) ? (host + ':' + port) : (host || port || '');
				let desc = s.description || s.name || '';
				let region = infer_region(host, desc);
				peers.push({ id: peerId, endpoint: endpoint, description: desc, region: region });
			}
			u.unload();
			peers.sort((a, b) => (a.id < b.id ? -1 : 1));
			return { peers: peers, whitelist: whitelist };
		}
	},
	set_peer_whitelist: {
		args: { peers: [] },
		call: function(req) {
			let list = req.args && Array.isArray(req.args.peers) ? req.args.peers : [];
			let val = list.map(p => String(p).trim()).filter(p => /^peer_[0-9]+$/.test(p)).join(' ');
			try {
				let u = cursor();
				u.load('vpn_watchdog');
				let s = u.sections('vpn_watchdog', 'watchdog');
				if (s && s.length > 0) {
					let name = s[0]['.name'];
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
			try {
				fs.writefile(path, content);
				return { ok: true, path: path };
			} catch (e) {
				return { ok: false, error: e.message || String(e) };
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
				return { ok: false, error: e.message || String(e) };
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
