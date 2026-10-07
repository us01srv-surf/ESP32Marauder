/* Marauder control UI — vanilla JS, hash views, /api/v1 polling with offline retry */
'use strict';

var $ = function (s) { return document.querySelector(s); };
var noop = function () {};

var S = {
  view: '', tab: 'aps', sortK: 'rssi', sortD: -1,
  offline: false, status: null, info: null,
  aps: [], sts: [], ble: [], bleOk: true,
  dead: {}, cmdBusy: false, active: null
};
var IV = 2000, del = IV, running = false, inflight = false, fast = false,
    soon = null, pollT = null, toastT = null, lastCode = '';

/* ---------- transport ---------- */
/* resolves parsed JSON; rejects with e.http (+ e.code from the error envelope)
   when the device answered, or a plain error when it was unreachable */
function api(p, o, t) {
  var ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
  var tid = ctl ? setTimeout(function () { ctl.abort(); }, t || 4500) : 0;
  var opt = o || {};
  if (ctl) opt.signal = ctl.signal;
  var done = function () { clearTimeout(tid); };
  return fetch(p, opt).then(function (r) {
    return r.json().catch(function () { return null; }).then(function (j) {
      done();
      if (!r.ok) {
        var e = new Error('HTTP ' + r.status);
        e.http = r.status;
        e.code = (j && j.code) || '';
        throw e;
      }
      return j;
    });
  }, function (e) { done(); throw e; });
}
/* protocol envelope {"protocol":1,"data":{...}} — flat payloads tolerated */
function un(j) { return (j && j.data && typeof j.data === 'object') ? j.data : (j || {}); }

function setLink(state) { /* null = unknown, true = ok, false = unreachable */
  S.offline = state === false;
  document.body.classList.toggle('off', S.offline);
  $('#link').className = 'pill ' + (state === true ? 'ok' : state === false ? 'bad' : 'warn');
  $('#linkT').textContent = state === true ? 'LIVE' : state === false ? 'RETRY' : 'LINK';
  $('#banner').hidden = state !== false;
}
function markUp() { del = IV; setLink(true); }
function markDown() { /* exponential-ish retry, capped at the 2 s cadence */
  del = S.offline ? Math.min(IV, del * 2) : 600;
  setLink(false);
  document.body.classList.remove('scan'); /* stop live affordances while unreachable */
  $('#dSub').textContent = 'offline · showing last known state';
}
function e503(e) { /* 503 envelope on a poll — retry fast, say it once per code */
  if (!e || e.http !== 503) return false;
  fast = true;
  if (e.code && e.code !== lastCode) { lastCode = e.code; toast(ECODE[e.code] || e.code); }
  return true;
}
function toast(m) {
  var t = $('#toast');
  t.textContent = m;
  t.classList.add('on');
  clearTimeout(toastT);
  toastT = setTimeout(function () { t.classList.remove('on'); }, 2400);
}
function log(t, cls) {
  var el = $('#log');
  if (!el.dataset.n) { el.textContent = ''; el.dataset.n = '1'; }
  String(t).replace(/\r/g, '').split('\n').forEach(function (l) {
    var d = document.createElement('div');
    d.className = 'ln ' + (cls || '');
    d.textContent = l;
    el.appendChild(d);
  });
  while (el.childElementCount > 160) el.firstElementChild.remove();
  el.scrollTop = el.scrollHeight;
}

/* ---------- commands ---------- */
/* actions mapped onto the documented v1 endpoints; anything else falls
   through to the CLI passthrough endpoint (degrades if firmware lacks it) */
var MAP = {
  'scan -a': ['/api/v1/scan?mode=ap_sta'],
  'scan -t': ['/api/v1/scan?mode=ap_sta'],
  'scanall': ['/api/v1/scan?mode=ap_sta'],
  'scan -b': ['/api/v1/recon?mode=ble'],
  'recon wifi': ['/api/v1/recon?mode=wifi'],
  'recon ble': ['/api/v1/recon?mode=ble'],
  'stopscan': ['/api/v1/scan?mode=off', '/api/v1/recon?mode=stop']
};
var ECODE = {
  LOW_HEAP: 'low heap · retry shortly',
  BUSY: 'device busy · retrying',
  STOPPING: 'device stopping · retrying',
  SNAPSHOT_PENDING: 'snapshot pending · retrying'
};
function errTxt(e) {
  if (!e) return 'request failed';
  if (e.code && ECODE[e.code]) return ECODE[e.code];
  if (e.fw || e.http === 404 || e.http === 405) return 'not available in this firmware';
  if (e.http) return 'http ' + e.http + ' · retrying';
  return 'device unreachable';
}
function postAll(ps) {
  var acc = { ok: 0, errs: [], j: null };
  var chain = Promise.resolve(acc);
  ps.forEach(function (p) {
    chain = chain.then(function (a) {
      return api(p, { method: 'POST' }, 9000).then(function (j) {
        a.ok++; a.j = j || a.j; return a;
      }, function (e) { a.errs.push(e); return a; });
    });
  });
  return chain.then(function (a) {
    if (a.ok) return a.j;
    var e = a.errs[0] || new Error('fail');
    if (a.errs.length && a.errs.every(function (x) { return x.http === 404 || x.http === 405; })) e.fw = 1;
    throw e;
  });
}
function postCmd(c) {
  return api('/api/v1/cmd', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'cmd=' + encodeURIComponent(c)
  }, 10000);
}
function run(c, btn) {
  if (S.cmdBusy) return;
  if (S.offline) { toast('device unreachable'); return; }
  S.cmdBusy = true;
  S.active = btn || null;
  refreshCmds();
  log('$ ' + c, 'in');
  var tries = 0, held = true;
  var fin = function () {
    if (!held) return;
    held = false;
    S.cmdBusy = false;
    S.active = null;
    refreshCmds();
    tickSoon();
  };
  var go = function () {
    (MAP[c] ? postAll(MAP[c]) : postCmd(c)).then(function (j) {
      var d = un(j), out = d.out || d.msg || d.message || d.output;
      if (out) log(String(out), 'out');
      toast(d.ok === false ? 'command rejected' : 'ok · ' + c);
      fin();
    }, function (e) {
      /* device answered 503 (BUSY/STOPPING/SNAPSHOT_PENDING) — retry once */
      if (e && e.http === 503 && e.code && e.code !== 'LOW_HEAP' && tries++ < 1) {
        log('! ' + String(e.code).toLowerCase() + ' · retrying', 'sys');
        setTimeout(go, 900);
        return;
      }
      if (e && !e.http) { log('! device unreachable', 'err'); markDown(); }
      else if (e && (e.http === 404 || e.http === 405)) log('! command endpoint not available in this firmware', 'err');
      else log('! ' + (e && e.code ? e.code : 'http ' + (e && e.http)), 'err');
      toast(errTxt(e));
      fin();
    });
  };
  go();
}

/* ---------- status / info ---------- */
var TYPES = { wifi: 'WIFI SCAN', ap: 'AP SCAN', ap_sta: 'AP+STA SCAN', ble: 'BLE SCAN',
  station: 'STATION SCAN', recon: 'RECON', recon_wifi: 'WIFI RECON', recon_ble: 'BLE RECON' };
function applyStatus(st, avail) {
  var has = avail !== false && !!st;
  S.status = has ? st : null;
  document.body.classList.toggle('scan', !!(has && st.scanning));
  if (!has) { /* endpoint missing (pre-P3 firmware) — degrade honestly */
    $('#dState').textContent = '—';
    $('#dState').classList.remove('run');
    $('#dSub').textContent = 'scan state unavailable';
    $('#dAp').textContent = '—';
    $('#dSt').textContent = '—';
    $('#bState').textContent = '—';
    $('#bType').textContent = 'type —';
    return;
  }
  var sc = !!st.scanning, ty = String(st.type || 'none');
  var lbl = TYPES[ty] || 'SCANNING';
  var ds = $('#dState');
  ds.textContent = sc ? lbl : 'IDLE';
  ds.classList.toggle('run', sc);
  $('#dSub').textContent = sc ? 'live · refreshing every 2 s' : 'no scan running';
  $('#dAp').textContent = st.ap_count == null ? '—' : st.ap_count;
  $('#dSt').textContent = st.st_count == null ? '—' : st.st_count;
  $('#bState').textContent = sc ? lbl : 'IDLE';
  $('#bType').textContent = 'type ' + ty;
}
function fmt(n) {
  return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1024).toFixed(1) + ' KB';
}
function set(id, v) { $(id).textContent = v == null || v === '' ? '—' : v; }
function paintInfo() {
  var i = S.info;
  if (!i) return;
  set('#iChip', i.chip); set('#iFw', i.fw); set('#iMac', i.mac);
  set('#iMode', i.mode); set('#iIp', i.ip);
  set('#iPsram', i.psram_free == null ? null : fmt(i.psram_free));
  set('#iHeap', i.heap_free == null ? null : fmt(i.heap_free));
  var mp = $('#mpill'), head = [i.mode, i.ip].filter(Boolean).join(' · ');
  if (head) { mp.hidden = false; mp.textContent = head; }
  /* heap meter: free heap against a 256 KB reference scale */
  var free = i.heap_free, N = 24, m = $('#heap');
  var on = free == null ? 0 : Math.round(Math.max(0, Math.min(1, free / 262144)) * N);
  m.classList.toggle('hot', free != null && free < 61440 && free >= 20480);
  m.classList.toggle('crit', free != null && free < 20480);
  for (var k = 0; k < m.childElementCount; k++) m.children[k].classList.toggle('on', k < on);
}
function fetchInfo() {
  if (S.dead.info) return Promise.resolve();
  return api('/api/v1/info', null, 5000).then(function (j) {
    var i = un(j);
    if (i.chip || i.fw || i.heap_free != null) { S.info = i; paintInfo(); }
  }, function (e) {
    if (e && e.http) { if (!e503(e)) S.dead.info = 1; }
  });
}

/* ---------- list rendering ---------- */
function elFrom(html) {
  var t = document.createElement('template');
  t.innerHTML = html;
  return t.content.firstElementChild;
}
function mkRow() {
  var r = elFrom('<div><div class="c-id"><span class="ssid"></span><span class="sub"></span></div>' +
    '<div class="c-meta"></div><div class="c-sig"><span class="sig"></span><b class="dbm"></b></div></div>');
  r._s = {
    sid: r.querySelector('.ssid'), sub: r.querySelector('.sub'),
    meta: r.querySelector('.c-meta'), sig: r.querySelector('.sig'),
    dbm: r.querySelector('.dbm')
  };
  return r;
}
function tag(p, t) {
  if (t == null || t === '') return;
  var s = document.createElement('span');
  s.className = 'tag';
  s.textContent = t;
  p.appendChild(s);
}
function sigSet(el, v) {
  var n = v == null ? 0 : v >= -50 ? 4 : v >= -60 ? 3 : v >= -70 ? 2 : v >= -80 ? 1 : 0;
  el.className = 'sig s' + n;
  el.setAttribute('aria-label', 'signal ' + n + ' of 4');
}
function dBm(el, v) { el.textContent = v == null ? '—' : Math.round(v); }
function apUpd(r, a) {
  var s = r._s;
  s.sid.textContent = a.ssid || '(hidden)';
  s.sub.textContent = a.bssid || '';
  s.meta.textContent = '';
  tag(s.meta, 'CH ' + (a.ch == null ? '—' : a.ch));
  tag(s.meta, String(a.sec || a.enc || 'OPEN').toUpperCase());
  var st = a.stas == null ? a.clients : a.stas;
  if (st != null) tag(s.meta, 'ST ' + st);
  sigSet(s.sig, a.rssi);
  dBm(s.dbm, a.rssi);
}
function stUpd(r, a) {
  var s = r._s, pr = a.probes || [];
  s.sid.textContent = a.mac || a.addr || '(unknown)';
  s.sid.classList.add('mm');
  s.sub.textContent = a.ap ? 'via ' + a.ap : 'no associated ap';
  s.meta.textContent = '';
  pr.slice(0, 4).forEach(function (p) { tag(s.meta, p); });
  if (pr.length > 4) tag(s.meta, '+' + (pr.length - 4));
  if (!pr.length && a.ch != null) tag(s.meta, 'CH ' + a.ch);
  sigSet(s.sig, a.rssi);
  dBm(s.dbm, a.rssi);
}
function bleUpd(r, a) {
  var s = r._s, mac = a.mac || a.addr || a.address || '';
  s.sid.textContent = a.name || a.dev || mac || 'Unknown device';
  s.sub.textContent = mac;
  s.meta.textContent = '';
  if (a.name && a.type) tag(s.meta, String(a.type).toUpperCase());
  var svc = a.svc || a.services;
  if (svc && svc.length) tag(s.meta, 'SVC ' + svc.length);
  if (a.manuf) tag(s.meta, String(a.manuf).toUpperCase());
  sigSet(s.sig, a.rssi);
  dBm(s.dbm, a.rssi);
}
function sorted(arr) {
  var k = S.sortK, d = S.sortD;
  return arr.slice().sort(function (x, y) {
    var p, q;
    if (k === 'rssi') { p = +(x.rssi == null ? -120 : x.rssi); q = +(y.rssi == null ? -120 : y.rssi); }
    else if (k === 'ch') { p = +(x.ch || 0); q = +(y.ch || 0); }
    else { p = String(x[k] == null ? '' : x[k]).toLowerCase(); q = String(y[k] == null ? '' : y[k]).toLowerCase(); }
    return (p < q ? -1 : p > q ? 1 : 0) * d;
  });
}
/* keyed sync: rows are stable DOM nodes, animated only on insert / reorder */
function syncList(el, items, key, up, emptyHTML) {
  if (!items.length) {
    /* keyed by content: switching tabs changes the empty state */
    var h = emptyHTML || '';
    if (el._e !== h) { el._e = h; el._m = {}; el._o = ''; el.innerHTML = h; }
    return;
  }
  if (el._e) { el._e = 0; el._m = {}; el._o = ''; el.innerHTML = ''; }
  var map = el._m || (el._m = {}), ks = [];
  items.forEach(function (it, i) {
    var k = String(key(it, i));
    ks.push(k);
    var r = map[k];
    if (!r) {
      r = mkRow();
      r.className = 'row fresh';
      r.addEventListener('animationend', function (e) {
        if (e.target === r) r.className = 'row';
      }, { once: true });
      map[k] = r;
    }
    up(r, it);
  });
  Object.keys(map).forEach(function (k) {
    if (ks.indexOf(k) < 0) { map[k].remove(); delete map[k]; }
  });
  var sig = ks.join('\u0001');
  if (el._o !== sig) {
    el._o = sig;
    ks.forEach(function (k, i) {
      if (el.children[i] !== map[k]) el.insertBefore(map[k], el.children[i] || null);
    });
  }
}
var DEAD = '<div class="empty"><span>List endpoint not available in this firmware.</span></div>';
function renderWifi() {
  var list = $('#wList');
  if (S.tab === 'aps') {
    $('#cAps').textContent = S.aps.length;
    if (S.dead['aps']) { syncList(list, [], null, null, DEAD); return; }
    syncList(list, sorted(S.aps),
      function (a, i) { return a.bssid || (a.ssid || '?') + '#' + i; }, apUpd,
      '<div class="empty"><b>No APs yet</b><span>Start a scan to populate this list.</span>' +
      '<button class="btn pri" data-cmd="scan -a" type="button">SCAN APS</button></div>');
  } else {
    $('#cSts').textContent = S.sts.length;
    if (S.dead['sts']) { syncList(list, [], null, null, DEAD); return; }
    syncList(list, sorted(S.sts),
      function (a, i) { return a.mac || '#' + i; }, stUpd,
      '<div class="empty"><b>No stations yet</b><span>Start a station scan to populate this list.</span>' +
      '<button class="btn pri" data-cmd="scan -t" type="button">SCAN STATIONS</button></div>');
  }
}
function renderBle() {
  $('#bNote').hidden = S.bleOk;
  if (!S.bleOk) { syncList($('#bList'), [], null, null, ''); return; }
  syncList($('#bList'), S.ble,
    function (a, i) { return a.mac || a.addr || a.address || '#' + i; }, bleUpd,
    '<div class="empty"><b>No BLE devices yet</b><span>Start a BLE recon to populate this list.</span>' +
    '<button class="btn pri" data-cmd="recon ble" type="button">RECON BLE</button></div>');
}

/* ---------- command button states ---------- */
function refreshCmds() {
  var st = S.status || {}, sc = !!st.scanning;
  var ty = String(st.type || 'none'), bleScan = sc && ty.indexOf('ble') >= 0;
  Array.prototype.forEach.call(document.querySelectorAll('[data-cmd]'), function (b) {
    var c = b.getAttribute('data-cmd');
    var cyc = /^(scan|recon)/.test(c);
    var dis = S.offline || S.cmdBusy || (cyc && sc);
    if (b === S.active) dis = false;
    b.disabled = dis;
    b.classList.toggle('busy', b === S.active ||
      (!S.offline && ((b.id === 'wGo' && sc && !bleScan) || (b.id === 'bGo' && bleScan))));
  });
}

/* ---------- polling ---------- */
function viewFetch() {
  if (S.view === 'dash') return fetchInfo();
  if (S.view === 'wifi') {
    var aps = S.tab === 'aps';
    var p = aps ? 'aps' : 'sts';
    var url = aps ? '/api/v1/aps?offset=0&limit=50' : '/api/v1/stations?offset=0&limit=50';
    if (S.dead[p]) return null;
    return api(url, null, 5000).then(function (j) {
      var d = un(j);
      if (aps) S.aps = d.aps || [];
      else S.sts = d.stations || d.list || [];
      renderWifi();
    }, function (e) {
      if (!e || !e.http) return;
      if (e503(e)) return;                               /* BUSY etc. — retry soon */
      S.dead[p] = 1;                                     /* pre-P4 firmware — stop probing */
      renderWifi();
    });
  }
  if (S.view === 'ble' && S.bleOk) {
    if (S.dead.ble) return null;
    return api('/api/v1/ble?offset=0&limit=50', null, 5000).then(function (j) {
      var d = un(j);
      S.ble = d.devices || d.ble || d.list || (Array.isArray(j) ? j : []);
      renderBle();
    }, function (e) {
      if (!e || !e.http) return;
      if (e503(e)) return;
      S.dead.ble = 1;
      S.bleOk = false;
      renderBle();
    });
  }
  return null;
}
function nextIn(ms) {
  clearTimeout(pollT);
  if (running && !document.hidden) pollT = setTimeout(tick, ms);
}
function tickSoon() { clearTimeout(soon); clearTimeout(pollT); soon = setTimeout(tick, 150); }
function tick() {
  clearTimeout(soon);
  if (!running || document.hidden) return;
  if (inflight) { nextIn(400); return; }
  inflight = true;
  var held = true;
  var release = function () {
    if (!held) return;
    held = false;
    inflight = false;
    var nxt = S.offline ? del : fast ? 800 : IV;
    if (!fast && !S.offline) lastCode = ''; /* clean cycle — allow the toast again later */
    fast = false;
    nextIn(nxt);
  };
  var chain = function () {
    var v = viewFetch();
    if (v) v.then(release, release);
    else release();
  };
  if (S.view !== 'dash' && !S.info) fetchInfo(); /* background fill; dash view re-fetches itself */
  api('/api/v1/status', null, 4500).then(function (j) {
    markUp();
    applyStatus(un(j), true);
    refreshCmds();
    chain();
  }, function (e) {
    if (e && e.http) {          /* device answered — reachable even if degraded */
      markUp();
      if (e503(e)) { /* busy / snapshot pending — fast retry, stay live */ }
      else if (e.http === 404 || e.http === 405 || e.http === 501) applyStatus(null, false);
      refreshCmds();
      chain();
    } else {                    /* network failure — unreachable, back off */
      markDown();
      refreshCmds();
      release();
    }
  });
}
function startPoll() {
  if (running || document.hidden) return;
  running = true;
  tickSoon();
}
function stopPoll() {
  running = false;
  clearTimeout(soon);
  clearTimeout(pollT);
}

/* ---------- views ---------- */
var VIEWS = ['dash', 'wifi', 'ble', 'ctrl', 'cli'];
function show(v) {
  S.view = v;
  VIEWS.forEach(function (n) { $('#v-' + n).classList.toggle('on', n === v); });
  Array.prototype.forEach.call(document.querySelectorAll('.nav a'), function (a) {
    var on = a.getAttribute('data-v') === v;
    a.classList.toggle('on', on);
    if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  if (v === 'dash') paintInfo();
  if (v === 'wifi') renderWifi();
  if (v === 'ble') renderBle();
  refreshCmds();
  tickSoon();
}
function route() {
  var h = (location.hash || '').replace(/^#\/?/, '');
  var v = VIEWS.indexOf(h) >= 0 ? h : 'dash';
  if (v === S.view) return;
  show(v);
}
/* wifi tabs + sort */
var SORTLBL = { rssi: 'RSSI', ssid: 'SSID', ch: 'CH', ap: 'AP' };
function defDir(k) { return k === 'rssi' ? -1 : 1; }
function paintSort() { $('#wSort').textContent = SORTLBL[S.sortK] + (S.sortD < 0 ? ' ↓' : ' ↑'); }
function setTab(t) {
  S.tab = t;
  Array.prototype.forEach.call($('#wTabs').children, function (b) {
    b.classList.toggle('on', b.getAttribute('data-tab') === t);
  });
  var go = $('#wGo');
  go.setAttribute('data-cmd', t === 'aps' ? 'scan -a' : 'scan -t');
  go.textContent = t === 'aps' ? 'SCAN APS' : 'SCAN STATIONS';
  S.sortK = 'rssi';
  S.sortD = -1;
  paintSort();
  renderWifi();
  refreshCmds();
  tickSoon();
}
function cycleSort() {
  var keys = S.tab === 'aps' ? ['rssi', 'ssid', 'ch'] : ['rssi', 'ap'];
  var i = keys.indexOf(S.sortK);
  if (i < 0 || S.sortD === defDir(S.sortK)) S.sortD = -defDir(S.sortK);
  else { S.sortK = keys[(i + 1) % keys.length]; S.sortD = defDir(S.sortK); }
  paintSort();
  renderWifi();
}

/* ---------- boot ---------- */
function boot() {
  var m = $('#heap');
  for (var i = 0; i < 24; i++) m.appendChild(document.createElement('i'));
  paintSort();
  route();
  if (!S.view) show('dash');

  addEventListener('hashchange', route);
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stopPoll(); else startPoll();
  });
  document.addEventListener('click', function (e) {
    var b = e.target.closest ? e.target.closest('[data-cmd]') : null;
    if (b) run(b.getAttribute('data-cmd'), b);
  });
  $('#wTabs').addEventListener('click', function (e) {
    var b = e.target.closest('[data-tab]');
    if (b) setTab(b.getAttribute('data-tab'));
  });
  $('#wSort').addEventListener('click', cycleSort);
  $('#cmdForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var v = $('#cmdIn').value.trim();
    if (!v) return;
    $('#cmdIn').value = '';
    run(v, null);
  });
  $('#clearLog').addEventListener('click', function () {
    var el = $('#log');
    el.innerHTML = '';
    delete el.dataset.n;
    log('— log cleared —', 'sys');
  });

  if (location.protocol === 'file:') {
    /* no fetch possible from file:// — say so instead of hammering errors */
    $('#bannerT').textContent = 'FILE:// · SERVE FROM THE DEVICE OVER HTTP';
    log('file:// — serve this page from the device to connect', 'sys');
    setLink(false);
  } else {
    startPoll();
  }
}
document.addEventListener('DOMContentLoaded', boot);
