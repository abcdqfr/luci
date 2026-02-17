~~~'use strict';
// LuCI form sections: use s.option(FormClass, name, title), not s.add().
'require form';
'require view';
'require rpc';
'require ui';
'require uci';

const get_status = rpc.declare({
  object: 'luci.vpn_watchdog',
  method: 'get_status'
});
const get_log = rpc.declare({
  object: 'luci.vpn_watchdog',
  method: 'get_log',
  params: ['lines']
});
const get_sites = rpc.declare({
  object: 'luci.vpn_watchdog',
  method: 'get_sites'
});
const set_sites = rpc.declare({
  object: 'luci.vpn_watchdog',
  method: 'set_sites',
  params: ['content']
});
const apply_cron = rpc.declare({
  object: 'luci.vpn_watchdog',
  method: 'apply_cron'
});
const run_now = rpc.declare({
  object: 'luci.vpn_watchdog',
  method: 'run_now',
  params: ['dry_run']
});
const get_peers = rpc.declare({
  object: 'luci.vpn_watchdog',
  method: 'get_peers'
});
const set_peer_whitelist = rpc.declare({
  object: 'luci.vpn_watchdog',
  method: 'set_peer_whitelist',
  params: ['peers']
});

return view.extend({
  load: function () {
    return Promise.all([
      L.resolveDefault(get_status(), {}),
      L.resolveDefault(get_log({ lines: 200 }), { lines: '', path: '' }),
      L.resolveDefault(get_sites(), { content: '', path: '' }),
      L.resolveDefault(get_peers(), { peers: [], whitelist: [] }),
      (function () {
        const m = new form.Map('vpn_watchdog', _('KGE VPN Watchdog'),
          _('Monitor VPN connectivity and switch to a working peer when the current one fails. All settings below are persisted.'));
        // Basic
        const s1 = m.section(form.TypedSection, 'watchdog', _('Basic'));
        s1.anonymous = true;
        const o1 = s1.option(form.Flag, 'enabled', _('Enabled'));
        o1.rmempty = false;
        s1.option(form.Value, 'log_path', _('Log path')).placeholder = '/var/log/vpn-watchdog.log';
        s1.option(form.Flag, 'cron_enabled', _('Cron enabled'));
        const o_cron = s1.option(form.ListValue, 'cron_interval', _('Poll interval (minutes)'));
        o_cron.value('5', _('5'));
        o_cron.value('10', _('10'));
        o_cron.value('15', _('15'));
        o_cron.default = '5';
        // Expert
        const s2 = m.section(form.TypedSection, 'watchdog', _('Expert'));
        s2.anonymous = true;
        s2.option(form.Value, 'sites_file', _('Sites file path')).placeholder = '/etc/kge-vpn-watchdog/sites.conf';
        s2.option(form.Value, 'vpn_iface', _('VPN interface override')).placeholder = _('Leave empty to auto-detect');
        s2.option(form.Value, 'polling_iface', _('Polling interface')).placeholder = 'wgclient_poll';
        s2.option(form.Value, 'sleep_after_switch', _('Sleep after switch (s)')).placeholder = '3';
        s2.option(form.Value, 'curl_connect_timeout', _('Curl connect timeout (s)')).placeholder = '3';
        s2.option(form.Value, 'curl_max_time', _('Curl max time (s)')).placeholder = '8';
        s2.option(form.Value, 'cron_schedule', _('Custom cron schedule')).placeholder = '*/5 * * * *';
        s2.option(form.Value, 'run_timeout', _('Run now timeout (s)')).placeholder = '120';
        s2.option(form.Value, 'log_tail_lines', _('Log tail lines')).placeholder = '200';
        return m.render();
      })()
    ]);
  },
  render: function (data) {
    const status = data[0] || {};
    const log = data[1] || {};
    const sites = data[2] || {};
    const formNode = data[4];
    const peersData = data[3] || { peers: [], whitelist: [] };
    const scriptOk = status.script_path && status.script_path.length > 0;
    const logPath = (log.path != null && log.path !== '') ? log.path : (status.log_path || '');
    const logLines = (log.lines != null) ? String(log.lines) : '';
    const logTail = parseInt(status.log_tail_lines, 10) || 200;
    const sitesContent = (sites.content != null) ? String(sites.content) : '';
    const sitesPath = (sites.path != null) ? String(sites.path) : '';
    const peers = (peersData.peers != null) ? peersData.peers : [];
    const whitelist = (peersData.whitelist != null) ? peersData.whitelist : [];
    const whitelistSet = new Set(Array.isArray(whitelist) ? whitelist : (whitelist ? String(whitelist).trim().split(/\s+/) : []));
    const useAllWhenEmpty = (whitelistSet.size === 0);

    const runBtn = E('button', {
      class: 'btn cbi-button cbi-button-apply',
      click: function () {
        if (runBtn.disabled) return;
        runBtn.disabled = true;
        runBtn.textContent = _('Running…');
        run_now({ dry_run: false }).then(function (r) {
          runBtn.disabled = false;
          runBtn.textContent = _('Run now');
          const out = (r && r.output != null) ? String(r.output) : '';
          const el = document.getElementById('kge-vpn-watchdog-log');
          if (el) el.textContent = out || _('(No output)');
          return get_log({ lines: logTail });
        }).then(function (l) {
          const el = document.getElementById('kge-vpn-watchdog-log');
          if (el && l && l.lines != null) el.textContent = l.lines;
        }).catch(function (err) {
          runBtn.disabled = false;
          runBtn.textContent = _('Run now');
          const el = document.getElementById('kge-vpn-watchdog-log');
          if (el) el.textContent = _('Error: ') + (err && err.message ? err.message : String(err));
        });
      }
    }, _('Run now'));

    const dryRunBtn = E('button', {
      class: 'btn cbi-button cbi-button-action',
      click: function () {
        if (dryRunBtn.disabled) return;
        dryRunBtn.disabled = true;
        dryRunBtn.textContent = _('Running…');
        run_now({ dry_run: true }).then(function (r) {
          dryRunBtn.disabled = false;
          dryRunBtn.textContent = _('Dry run');
          const el = document.getElementById('kge-vpn-watchdog-log');
          const out = (r && r.output != null) ? String(r.output) : '';
          if (el) el.textContent = out || _('(No output)');
        }).catch(function (err) {
          dryRunBtn.disabled = false;
          dryRunBtn.textContent = _('Dry run');
          const el = document.getElementById('kge-vpn-watchdog-log');
          if (el) el.textContent = _('Error: ') + (err && err.message ? err.message : String(err));
        });
      }
    }, _('Dry run'));

    const applyCronBtn = E('button', {
      class: 'btn cbi-button',
      click: function () {
        if (applyCronBtn.disabled) return;
        applyCronBtn.disabled = true;
        apply_cron().then(function (r) {
          applyCronBtn.disabled = false;
          ui.addNotification(r && r.ok ? null : (r && r.error) || _('Failed'), r && r.ok ? _('Cron schedule applied.') : (r && r.error) || _('Failed'), r && r.ok ? 'info' : 'error');
        }).catch(function () { applyCronBtn.disabled = false; });
      }
    }, _('Apply cron schedule'));

    const sitesTextarea = E('textarea', {
      id: 'kge-vpn-watchdog-sites',
      class: 'cbi-input-textarea',
      rows: 10,
      style: 'width: 100%; font-family: monospace; font-size: 0.9em;'
    });
    sitesTextarea.value = sitesContent;

    const saveSitesBtn = E('button', {
      class: 'btn cbi-button cbi-button-apply',
      click: function () {
        saveSitesBtn.disabled = true;
        set_sites({ content: sitesTextarea.value || '' }).then(function (r) {
          saveSitesBtn.disabled = false;
          var msg = (r && r.ok) ? _('Sites saved.') : ((r && r.error) ? r.error : _('Save site list failed.'));
          ui.addNotification(r && r.ok ? null : msg, msg, r && r.ok ? 'info' : 'error');
        }).catch(function (err) {
          saveSitesBtn.disabled = false;
          var msg = (err && (err.message || err)) ? String(err.message || err) : _('Save site list failed (RPC error).');
          ui.addNotification(null, msg, 'error');
        });
      }
    }, _('Save site list'));

    const refreshLogBtn = E('button', {
      class: 'btn cbi-button',
      click: function () {
        get_log({ lines: logTail }).then(function (l) {
          const el = document.getElementById('kge-vpn-watchdog-log');
          if (el && l && l.lines != null) el.textContent = l.lines;
        });
      }
    }, _('Refresh log'));

    const logPre = E('pre', {
      id: 'kge-vpn-watchdog-log',
      class: 'cbi-section',
      style: 'white-space: pre-wrap; max-height: 20em; overflow: auto; font-size: 0.9em;'
    }, logPath ? (logLines.length ? logLines : _('(Empty)')) : _('Set a log path in Basic and run the watchdog to see output.'));

    const statusLine = E('p', { class: 'cbi-value-description' },
      scriptOk ? _('Script installed.') : _('Script not found at /usr/bin/kge-vpn-watchdog.'));

    const siteSection = E('div', { class: 'cbi-section' }, [
      E('h3', { class: 'cbi-section-title' }, _('Site list')),
      E('p', { class: 'cbi-value-description' }, _('One line per site: name TAB url_or_domain TAB block_pattern TAB success_pattern. Use domain (e.g. google.com, wikipedia.org) or full https://... ; http/https handled. Empty or # lines ignored. File: ') + (sitesPath || '—')),
      E('div', { class: 'cbi-section-node' }, [sitesTextarea]),
      E('div', { class: 'cbi-section-node' }, [saveSitesBtn])
    ]);

    const peerCheckboxes = {};
    const peerListEl = E('div', { class: 'cbi-section-node', id: 'kge-vpn-watchdog-peers' });
    const regionToIds = {};
    peers.forEach(function (p) {
      const id = p.id || p;
      const label = id + (p.endpoint ? ' — ' + p.endpoint : '') + (p.description ? ' (' + p.description + ')' : '');
      const checked = useAllWhenEmpty || whitelistSet.has(id);
      const cb = E('input', { type: 'checkbox', id: 'peer-' + id, 'data-peer-id': id, 'data-region': p.region || '', checked: checked });
      peerCheckboxes[id] = cb;
      peerListEl.appendChild(E('label', { class: 'cbi-input-checkbox', style: 'display: block; margin: 0.25em 0;' }, [cb, ' ', label]));
      const r = (p.region && p.region.trim()) ? p.region.trim() : '';
      if (r) {
        if (!regionToIds[r]) regionToIds[r] = [];
        regionToIds[r].push(id);
      }
    });
    const selectAllPeers = function (checked) {
      Object.keys(peerCheckboxes).forEach(function (id) { peerCheckboxes[id].checked = checked; });
    };
    const setRegion = function (region, checked) {
      (regionToIds[region] || []).forEach(function (id) {
        if (peerCheckboxes[id]) peerCheckboxes[id].checked = checked;
      });
    };
    const getSelectedPeers = function () {
      return Object.keys(peerCheckboxes).filter(function (id) { return peerCheckboxes[id].checked; });
    };
    const selectAllBtn = E('button', { class: 'btn cbi-button', click: function () { selectAllPeers(true); } }, _('Select all'));
    const deselectAllBtn = E('button', { class: 'btn cbi-button', click: function () { selectAllPeers(false); } }, _('Deselect all'));
    const savePeersBtn = E('button', {
      class: 'btn cbi-button cbi-button-apply', click: function () {
        savePeersBtn.disabled = true;
        const selected = getSelectedPeers();
        set_peer_whitelist({ peers: selected }).then(function (r) {
          savePeersBtn.disabled = false;
          ui.addNotification(r && r.ok ? null : (r && r.error) || _('Failed'), r && r.ok ? _('Endpoint selection saved. Empty = use all for polling.') : (r && r.error) || _('Failed'), r && r.ok ? 'info' : 'error');
        }).catch(function () { savePeersBtn.disabled = false; });
      }
    }, _('Save endpoint selection'));
    const refreshPeersBtn = E('button', {
      class: 'btn cbi-button', click: function () {
        refreshPeersBtn.disabled = true;
        refreshPeersBtn.textContent = _('Scanning…');
        get_peers().then(function () {
          ui.addNotification(null, _('Endpoints refreshed from device.'), 'info');
          location.reload();
        }).catch(function () {
          refreshPeersBtn.disabled = false;
          refreshPeersBtn.textContent = _('Refresh endpoints');
        });
      }
    }, _('Refresh endpoints'));
    const regionToggles = [];
    const regions = Object.keys(regionToIds).sort();
    regions.forEach(function (reg) {
      regionToggles.push(E('button', { class: 'btn cbi-button cbi-button-positive', style: 'margin: 0 0.2em 0.2em 0;', click: function () { setRegion(reg, true); } }, _('All %s').replace('%s', reg)));
      regionToggles.push(E('button', { class: 'btn cbi-button', style: 'margin: 0 0.2em 0.2em 0;', click: function () { setRegion(reg, false); } }, _('None %s').replace('%s', reg)));
    });
    const endpointsSection = E('div', { class: 'cbi-section' }, [
      E('h3', { class: 'cbi-section-title' }, _('VPN Endpoints')),
      E('p', { class: 'cbi-value-description' }, _('Choose which endpoints the watchdog may use when polling. Leave all selected to allow all. Use region toggles to enable/disable by country (US, CA, UK, etc.). Save to apply.')),
      E('div', { class: 'cbi-section-node', style: 'margin-bottom: 0.5em;' }, [selectAllBtn, ' ', deselectAllBtn, ' ', savePeersBtn, ' ', refreshPeersBtn]),
      (regions.length > 0 ? E('div', { class: 'cbi-section-node', style: 'margin-bottom: 0.5em;' }, [E('span', { style: 'margin-right: 0.5em;' }, _('Region:')), regionToggles]) : E('div')),
      peerListEl
    ]);

    const runSection = E('div', { class: 'cbi-section' }, [
      E('h3', { class: 'cbi-section-title' }, _('Run & logs')),
      E('p', { class: 'cbi-value-description' }, _('Run once or dry run (check only). After changing Basic/Expert, click Save above; then click Apply cron schedule to update the cron job.')),
      statusLine,
      E('div', { class: 'cbi-section-node', style: 'margin-bottom: 0.5em;' }, [runBtn, ' ', dryRunBtn, ' ', applyCronBtn]),
      E('h4', { class: 'cbi-section-title', style: 'margin-top: 1em;' }, _('Log output')),
      E('div', { class: 'cbi-section-node' }, [refreshLogBtn]),
      E('div', { class: 'cbi-section-node' }, [logPre])
    ]);

    return E('div', { class: 'cbi-map' }, [formNode, endpointsSection, siteSection, runSection]);
  },
  handleSaveApply: null,
  handleSave: null,
  handleReset: null
});
