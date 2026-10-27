/* BREAK THE INTERNET — local simulation engine v2.
   No network calls, no libraries. Every metric is computed from
   requests and attacks that actually ran through the rules below.
   All attacks are SIMULATED inside this page: no real server,
   DNS service, or website is ever contacted.
   Simulated latency is a NUMBER the engine reports (ms). Packet
   animation speed is scaled for viewing and is not that number. */

'use strict';

/* ---------- Central state (single source of truth) ---------- */
const state = {
  running: true,
  simSeconds: 0,
  dnsFailed: false, dbFailed: false, primaryFailed: false, overload: false,
  backupEnabled: false, cacheEnabled: true,
  ddos: false, spoof: false, sqli: false,
  rateLimit: false, dnssec: false, waf: false,
  dbDegraded: false,
  attacksBlocked: 0, attacksHit: 0, floodCount: 0, attemptCount: 0,
  queue: 0, queueLimit: 12, warnAt: 8,
  queueWarnLogged: false, queueLimitLogged: false,
  total: 0, success: 0, failed: 0,
  latencySum: 0, latencyCount: 0,
  cacheHits: 0, cacheMisses: 0,
  recentOutcomes: [],
  requestCount: 0,
  scenario: 'normal',
  packetGen: 0,
  spawnIntervalMs: 1600,
  mix: 'balanced',
  lastRequest: null,
  mode: 'generic',
  cdnFailed: false, mediaFailed: false, feedFailed: false,
  gatewayFailed: false, queueBacklog: false, pushFailed: false, storeFailed: false,
  regionAFailed: false, regionBEnabled: false,
  scaleIndex: 2, autoscale: true,
  challengeBreak: '', challengeStart: 0,
  uptime: {
    browser: { ok: 0, total: 0 }, dns: { ok: 0, total: 0 }, primary: { ok: 0, total: 0 },
    backup: { ok: 0, total: 0 }, database: { ok: 0, total: 0 }, cache: { ok: 0, total: 0 },
  },
};

/* Deterministic request-type rotations per traffic mix. */
const MIX_PATTERNS = {
  balanced: ['db', 'cached', 'static', 'db', 'cached', 'db', 'static', 'cached'],
  'db-heavy': ['db', 'db', 'cached', 'db', 'static', 'db', 'db', 'cached'],
  'cache-heavy': ['cached', 'cached', 'static', 'cached', 'db', 'cached', 'static', 'cached'],
  'static-heavy': ['static', 'static', 'cached', 'static', 'db', 'static', 'cached', 'static'],
};
const TYPE_LABEL = { db: 'database-dependent', cached: 'cached content', static: 'static content' };
const BASE_LATENCY = { db: 110, cached: 58, static: 42 };

let spawnTimer = null, drainTicks = 0, toastTimer = null, tickerTimer = null;
let demoActive = false, demoTimer = null;
let replayActive = false, replayTimer = null, replayName = '';
let challengeActive = false, challengeTimer = null;
const prevMetric = { total: -1, success: -1, failed: -1 };

/* ---------- Small DOM helpers ---------- */
const $ = (id) => document.getElementById(id);
const els = {
  log: $('log'), emptyLog: $('emptyLog'), toast: $('toast'),
  total: $('mTotal'), success: $('mSuccess'), failed: $('mFailed'), rate: $('mRate'),
  latency: $('mLatency'), queue: $('mQueue'), queueHint: $('mQueueHint'),
  activeFailures: $('mActiveFailures'), activeHint: $('mActiveHint'),
  cacheRate: $('mCacheRate'), cacheHint: $('mCacheHint'),
  queueBar: $('queueBar'), queueText: $('queueText'), queueWarning: $('queueWarning'),
  queueBadge: $('queueBadge'), sparkLine: $('sparkLine'),
  sysDot: $('sysDot'), sysText: $('sysStatusText'), runIndicator: $('runIndicator'),
  simClock: $('simClock'), tickerText: $('tickerText'),
  attackStats: $('attackStats'), inspectorText: $('inspectorText'),
  demoBanner: $('demoBanner'), demoStep: $('demoStep'), btnDemo: $('btnDemo'),
  rateLabel: $('rateLabel'), queueLimitLabel: $('queueLimitLabel'),
  modeBanner: $('modeBanner'), replayBanner: $('replayBanner'), replayStep: $('replayStep'),
  challengeStatus: $('challengeStatus'), challengeTimer: $('challengeTimer'), challengeScore: $('challengeScore'),
  scaleUsersLabel: $('scaleUsersLabel'), scaleServersText: $('scaleServersText'), scaleShardsText: $('scaleShardsText'),
  regionCost: $('regionCost'), regionAvailability: $('regionAvailability'), regionStatus: $('regionStatus'),
  shareLink: $('shareLink'),
};

function showToast(msg) {
  els.toast.textContent = msg;
  els.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { els.toast.hidden = true; }, 3400);
}
function fmtClock() {
  const m = String(Math.floor(state.simSeconds / 60)).padStart(2, '0');
  const s = String(state.simSeconds % 60).padStart(2, '0');
  return 'T+' + m + ':' + s;
}
function highlightNode(key) {
  const g = $('node-' + key);
  if (!g) return;
  g.classList.add('active');
  setTimeout(() => g.classList.remove('active'), 900);
}

/* ---------- Event timeline + ticker ---------- */
function addLog(severity, text, component) {
  els.emptyLog.style.display = 'none';
  const li = document.createElement('li');
  const time = document.createElement('time'); time.textContent = fmtClock();
  const sev = document.createElement('span'); sev.className = 'sev ' + severity; sev.textContent = severity;
  const msg = document.createElement('span');
  msg.textContent = component ? text + ' [' + component + ']' : text;
  li.append(time, sev, msg);
  els.log.prepend(li);
  while (els.log.children.length > 60) els.log.lastChild.remove();
  els.tickerText.textContent = severity + ': ' + msg.textContent;
  els.tickerText.classList.remove('flash');
  void els.tickerText.offsetWidth;
  els.tickerText.classList.add('flash');
  clearTimeout(tickerTimer);
  tickerTimer = setTimeout(() => els.tickerText.classList.remove('flash'), 500);
}
function clearLog() {
  els.log.innerHTML = '';
  els.emptyLog.style.display = 'block';
}

/* ---------- Node rendering ---------- */
function nodeStatus(key) {
  if (key === 'browser') return ['HEALTHY', ''];
  if (key === 'dns') {
    if (state.dnsFailed) return ['FAILED', 'failed'];
    if (state.mode === 'instagram' && state.cdnFailed) return ['FAILED', 'failed'];
    if (state.mode === 'whatsapp' && state.gatewayFailed) return ['FAILED', 'failed'];
    return ['HEALTHY', ''];
  }
  if (key === 'primary') {
    if (state.primaryFailed || state.regionAFailed) return ['FAILED', 'failed'];
    if (state.mode === 'instagram' && state.feedFailed) return ['FAILED', 'failed'];
    if (state.overload || (state.ddos && !state.rateLimit)) return ['WARNING', 'warning'];
    return ['HEALTHY', ''];
  }
  if (key === 'backup') {
    if (!state.backupEnabled) return ['STANDBY', 'standby'];
    if (state.primaryFailed) return ['ACTIVE BACKUP', ''];
    return ['READY', ''];
  }
  if (key === 'database') {
    if (state.dbFailed) return ['FAILED', 'failed'];
    if (state.dbDegraded) return ['DEGRADED', 'warning'];
    if (state.mode === 'instagram' && state.mediaFailed) return ['DEGRADED', 'warning'];
    if (state.mode === 'whatsapp' && state.storeFailed) return ['DEGRADED', 'warning'];
    return ['HEALTHY', ''];
  }
  if (key === 'cache') {
    if (state.mode === 'whatsapp' && state.queueBacklog) return ['WARNING', 'warning'];
    return state.cacheEnabled ? ['HEALTHY', ''] : ['DISABLED', 'standby'];
  }
  if (key === 'attacker') {
    if (state.ddos || state.spoof || state.sqli) return ['ATTACKING', 'failed'];
    return ['IDLE', 'standby'];
  }
  if (key === 'fake') {
    if (state.spoof && !state.dnssec) return ['ACTIVE — FAKE', 'warning'];
    if (state.spoof) return ['BLOCKED', 'standby'];
    return ['DORMANT', 'standby'];
  }
  return ['HEALTHY', ''];
}
function anyAttack() { return state.ddos || state.spoof || state.sqli; }
function failoverAvailable() { return state.backupEnabled || state.regionBEnabled; }
function activeFailureCount() {
  return (state.dnsFailed ? 1 : 0) + ((state.dbFailed || state.dbDegraded) ? 1 : 0) +
         (state.primaryFailed ? 1 : 0) + (state.overload ? 1 : 0) +
         ((state.ddos && !state.rateLimit) ? 1 : 0) + ((state.spoof && !state.dnssec) ? 1 : 0) +
         ((state.mode === 'instagram' && state.cdnFailed) ? 1 : 0) +
         ((state.mode === 'instagram' && state.feedFailed) ? 1 : 0) +
         ((state.mode === 'instagram' && state.mediaFailed) ? 1 : 0) +
         ((state.mode === 'whatsapp' && state.gatewayFailed) ? 1 : 0) +
         ((state.mode === 'whatsapp' && state.storeFailed) ? 1 : 0) +
         ((state.regionAFailed && !failoverAvailable()) ? 1 : 0);
}
function activeFailureNames() {
  const names = [];
  if (state.dnsFailed) names.push('DNS');
  if (state.dbFailed) names.push('Database');
  else if (state.dbDegraded) names.push('Database degraded');
  if (state.primaryFailed) names.push('Primary server');
  if (state.overload) names.push('Overload');
  if (state.ddos && !state.rateLimit) names.push('DDoS');
  if (state.spoof && !state.dnssec) names.push('Spoofing');
  if (state.mode === 'instagram' && state.cdnFailed) names.push('CDN');
  if (state.mode === 'instagram' && state.feedFailed) names.push('Feed');
  if (state.mode === 'instagram' && state.mediaFailed) names.push('Media');
  if (state.mode === 'whatsapp' && state.gatewayFailed) names.push('Gateway');
  if (state.mode === 'whatsapp' && state.storeFailed) names.push('Message store');
  if (state.regionAFailed && !failoverAvailable()) names.push('Region A');
  return names;
}
function renderNodes() {
  ['browser', 'dns', 'primary', 'backup', 'database', 'cache', 'attacker', 'fake'].forEach((key) => {
    const g = $('node-' + key);
    if (!g) return;
    const [label, cls] = nodeStatus(key);
    g.classList.remove('failed', 'warning', 'standby');
    if (cls) g.classList.add(cls);
    const statusEl = g.querySelector('[data-status-for]');
    if (statusEl) statusEl.textContent = (cls === 'standby' ? '○ ' : '● ') + label;
    const nameEl = g.querySelector('.node-name');
    if (nameEl) g.setAttribute('aria-label', nameEl.textContent + ', ' + label.toLowerCase());
  });
  $('path-dns-backup').classList.toggle('active', state.backupEnabled && state.primaryFailed);
  $('path-dns-fake').classList.toggle('active', state.spoof && !state.dnssec);
  $('path-attacker-primary').classList.toggle('active', state.ddos);
  $('path-attacker-dns').classList.toggle('active', state.spoof);
  document.body.classList.toggle('attack-mode', anyAttack());
  const badgeText = els.queueBadge.querySelector('text');
  badgeText.textContent = 'Q ' + state.queue;
  els.queueBadge.style.display = state.queue > 0 ? 'block' : 'none';
  const n = activeFailureCount();
  if (n > 0) {
    els.sysDot.className = 'dot bad';
    els.sysText.textContent = 'Degraded — ' + n + ' active failure' + (n > 1 ? 's' : '');
  } else if (anyAttack()) {
    els.sysDot.className = 'dot warn';
    els.sysText.textContent = 'Attack active — mitigations holding';
  } else if (state.backupEnabled && state.primaryFailed) {
    els.sysDot.className = 'dot warn';
    els.sysText.textContent = 'Failover active — traffic on backup';
  } else {
    els.sysDot.className = 'dot ok';
    els.sysText.textContent = 'All systems operational';
  }
}

/* ---------- Metrics, inspector, attack stats, uptime ---------- */
function bump(el, key, value) {
  if (prevMetric[key] !== value) {
    prevMetric[key] = value;
    el.classList.remove('bump'); void el.offsetWidth; el.classList.add('bump');
    setTimeout(() => el.classList.remove('bump'), 380);
  }
}
function updateMetrics() {
  const completed = state.success + state.failed;
  els.total.textContent = state.total; bump(els.total, 'total', state.total);
  els.success.textContent = state.success; bump(els.success, 'success', state.success);
  els.failed.textContent = state.failed; bump(els.failed, 'failed', state.failed);
  els.rate.textContent = completed ? Math.round((state.success / completed) * 100) + '%' : '—';
  els.latency.textContent = state.latencyCount ? Math.round(state.latencySum / state.latencyCount) + ' ms' : '—';
  els.queue.textContent = state.queue;
  els.queueText.textContent = state.queue + ' / ' + state.queueLimit;
  els.queueBar.style.width = Math.round((state.queue / state.queueLimit) * 100) + '%';
  els.queueBar.className = state.queue >= state.queueLimit ? 'full' : state.queue >= state.warnAt ? 'warn' : '';
  els.queueWarning.hidden = state.queue < state.warnAt;
  els.activeFailures.textContent = activeFailureCount();
  const names = activeFailureNames();
  els.activeHint.textContent = names.length ? names.join(' · ') : 'none';
  const cacheTotal = state.cacheHits + state.cacheMisses;
  els.cacheRate.textContent = cacheTotal ? Math.round((state.cacheHits / cacheTotal) * 100) + '%' : '—';
  els.cacheHint.textContent = state.cacheHits + ' hits · ' + state.cacheMisses + ' misses';
  const pts = state.recentOutcomes.map((ok, i) => {
    const x = state.recentOutcomes.length === 1 ? 120 : Math.round((i / 23) * 240);
    return x + ',' + (ok ? 7 : 38);
  });
  els.sparkLine.setAttribute('points', pts.length ? pts.join(' ') : '0,40 240,40');
}
function updateAttackStats() {
  els.attackStats.textContent = 'Attacks blocked: ' + state.attacksBlocked + ' · Attacks that hit: ' + state.attacksHit;
}
function typeLabel(type) {
  if (state.mode === 'instagram') {
    return { db: 'feed / media upload', cached: 'photo / reel from CDN', static: 'profile / text post' }[type] || TYPE_LABEL[type];
  }
  if (state.mode === 'whatsapp') {
    return { db: 'chat history load', cached: 'queued message delivery', static: 'live message' }[type] || TYPE_LABEL[type];
  }
  return TYPE_LABEL[type];
}
function setInspector(id, type, pathParts, ok, latencyMs) {
  state.lastRequest = { id, type, path: pathParts.slice(), ok, latencyMs };
  els.inspectorText.textContent = '#' + id + ' · ' + typeLabel(type) + ' · ' +
    pathParts.join(' → ') + ' · ' + (ok ? 'SUCCESS' : 'FAILED') + ' · ' + latencyMs + ' ms';
}
function isUp(key) {
  if (key === 'browser') return true;
  if (key === 'dns') return !state.dnsFailed;
  if (key === 'primary') return !state.primaryFailed && !state.overload;
  if (key === 'backup') return true;
  if (key === 'database') return !state.dbFailed && !state.dbDegraded;
  if (key === 'cache') return state.cacheEnabled;
  return true;
}
function updateUptime() {
  Object.keys(state.uptime).forEach((key) => {
    const u = state.uptime[key];
    const pct = u.total ? Math.round((u.ok / u.total) * 100) + '%' : '—';
    const textEl = $('up-' + key), barEl = $('up-' + key + '-bar');
    if (textEl) textEl.textContent = pct;
    if (barEl) barEl.style.width = u.total ? Math.round((u.ok / u.total) * 100) + '%' : '0%';
  });
}
function recordOutcome(ok, latencyMs) {
  state.latencySum += latencyMs;
  state.latencyCount += 1;
  if (ok) state.success += 1; else state.failed += 1;
  state.recentOutcomes.push(ok);
  if (state.recentOutcomes.length > 24) state.recentOutcomes.shift();
  updateMetrics(); updateAttackStats(); renderNodes();
}
function finish(id, type, pathParts, ok, latencyMs) {
  setInspector(id, type, pathParts, ok, latencyMs);
  recordOutcome(ok, latencyMs);
}

/* ---------- Packet animation ---------- */
function animateLeg(pathId, opts) {
  const color = (opts && opts.color) || '#5ED3E8';
  const reverse = opts && opts.reverse;
  const duration = (opts && opts.duration) || 550;
  const gen = state.packetGen;
  return new Promise((resolve) => {
    const path = document.getElementById(pathId);
    if (!path) return resolve();
    const layer = $('packetLayer');
    const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dot.setAttribute('r', '5.5');
    dot.setAttribute('fill', color);
    dot.setAttribute('stroke', '#101114');
    dot.setAttribute('stroke-width', '1.5');
    layer.appendChild(dot);
    const len = path.getTotalLength();
    let progress = 0, last = null;
    function frame(now) {
      if (gen !== state.packetGen) { dot.remove(); return resolve(); }
      if (last === null) last = now;
      if (state.running) { progress += (now - last) / duration; last = now; }
      else { last = now; }
      const t = Math.min(progress, 1);
      const dist = reverse ? len * (1 - t) : len * t;
      const p = path.getPointAtLength(dist);
      dot.setAttribute('cx', p.x); dot.setAttribute('cy', p.y);
      if (t >= 1) setTimeout(() => { dot.remove(); resolve(); }, opts && opts.hold ? 320 : 40);
      else requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  });
}

/* ---------- Request lifecycle ---------- */
function latencyFor(type) {
  const jitter = (state.requestCount % 5) * 7;
  return BASE_LATENCY[type] + state.queue * 28 + (state.overload ? 120 : 0) +
         ((state.ddos && !state.rateLimit) ? 80 : 0) +
         ((state.mode === 'whatsapp' && state.queueBacklog) ? 600 : 0) + jitter;
}
function queueWarnAndCheck() {
  if (state.queue >= state.queueLimit && !state.queueLimitLogged) {
    state.queueLimitLogged = true;
    addLog('WARNING', 'Server queue exceeded the configured limit (' + state.queueLimit + ').', 'Primary Server');
  } else if (state.queue >= state.warnAt && !state.queueWarnLogged) {
    state.queueWarnLogged = true;
    addLog('WARNING', 'Server queue exceeded the warning threshold (' + state.warnAt + ').', 'Primary Server');
  }
  updateMetrics(); renderNodes();
}

async function runRequest() {
  const id = ++state.requestCount;
  const pattern = MIX_PATTERNS[state.mix] || MIX_PATTERNS.balanced;
  const type = pattern[(id - 1) % pattern.length];
  const pathParts = ['Browser'];
  state.total += 1;
  updateMetrics();
  addLog('INFO', 'Request #' + id + ' created (' + typeLabel(type) + ').', state.mode === 'generic' ? 'Browser Client' : state.mode);

  await animateLeg('path-browser-dns', { color: '#5ED3E8' });
  highlightNode('dns');
  if (state.dnsFailed) {
    pathParts.push('DNS');
    addLog('ERROR', 'Request #' + id + ' failed: DNS resolution failed — server address could not be resolved.', 'DNS Resolver');
    finish(id, type, pathParts, false, 38);
    return;
  }
  // Mode-specific failures at the CDN / gateway leg.
  if (state.mode === 'instagram' && state.cdnFailed && type === 'cached') {
    pathParts.push('CDN');
    addLog('ERROR', 'Request #' + id + ' failed: photos/reels could not load — CDN edge is down. Text still loads.', 'CDN Edge');
    finish(id, type, pathParts, false, 90);
    return;
  }
  if (state.mode === 'whatsapp' && state.gatewayFailed) {
    pathParts.push('Gateway');
    addLog('ERROR', 'Request #' + id + ' stuck: connection gateway is down — message stays at one tick (not sent).', 'Connection Gateway');
    finish(id, type, pathParts, false, 70);
    return;
  }
  if (state.mode === 'instagram' && state.feedFailed && type !== 'static') {
    pathParts.push('Feed');
    await animateLeg('path-dns-primary', { color: '#FF5A5A', hold: true });
    addLog('ERROR', 'Request #' + id + ' failed: feed service is down — feed is empty, but profile pages still load.', 'Feed Service');
    finish(id, type, pathParts, false, 80);
    return;
  }
  pathParts.push('DNS');
  addLog('INFO', 'DNS resolution completed for request #' + id + '.', 'DNS Resolver');

  // Spoofed DNS: diverted to the fake server unless DNSSEC rejects it.
  if (state.spoof && !state.dnssec) {
    pathParts.push('Fake Server');
    await animateLeg('path-dns-fake', { color: '#FF5A5A', hold: true });
    highlightNode('fake');
    state.attacksHit += 1;
    addLog('ERROR', 'Request #' + id + ' diverted to a fake server by a spoofed DNS answer.', 'Fake Server');
    finish(id, type, pathParts, false, 90);
    return;
  }

  let server, serverPath, toCachePath, toDbPath, serverLabel;
  const primaryDown = state.primaryFailed || state.regionAFailed;
  if (primaryDown && failoverAvailable()) {
    server = 'backup'; serverLabel = state.regionBEnabled && !state.backupEnabled ? 'Region B' : 'Backup Server';
    serverPath = 'path-dns-backup'; toCachePath = 'path-backup-cache'; toDbPath = 'path-backup-db';
    pathParts.push('Backup');
    addLog('WARNING', 'Traffic rerouted to ' + serverLabel + ' for request #' + id + '.', serverLabel);
    await animateLeg(serverPath, { color: '#5ED3E8' });
  } else if (primaryDown) {
    pathParts.push('Primary');
    await animateLeg('path-dns-primary', { color: '#FF5A5A', hold: true });
    highlightNode('primary');
    addLog('ERROR', 'Request #' + id + ' failed: ' + (state.regionAFailed ? 'Region A is down and no Region B / backup is active.' : 'primary server unavailable and no backup is active.'), 'Primary Server');
    finish(id, type, pathParts, false, 65);
    return;
  } else {
    server = 'primary'; serverLabel = 'Primary Server';
    serverPath = 'path-dns-primary'; toCachePath = 'path-primary-cache'; toDbPath = 'path-primary-db';
    pathParts.push('Primary');
    await animateLeg(serverPath, { color: '#5ED3E8' });
    highlightNode('primary');
    addLog('INFO', 'Request #' + id + ' forwarded to primary server.', 'Primary Server');
  }

  // Capacity / queue: overload, or an unmitigated DDoS, both fill the queue.
  const underPressure = state.overload || (state.ddos && !state.rateLimit);
  if (underPressure) {
    state.queue += 1;
    queueWarnAndCheck();
    if (state.queue >= state.queueLimit) {
      pathParts.push(server === 'backup' ? 'Backup' : 'Primary');
      addLog('ERROR', 'Request #' + id + ' timed out in the simulation (queue limit reached).', serverLabel);
      finish(id, type, pathParts, false, 1500);
      return;
    }
  }

  if (type === 'static') {
    addLog('SUCCESS', 'Static response returned successfully for request #' + id + ' (no database needed).', serverLabel);
  } else if (type === 'cached' && state.cacheEnabled) {
    state.cacheHits += 1;
    pathParts.push('Cache');
    await animateLeg(toCachePath, { color: '#5ED3E8' });
    highlightNode('cache');
    await animateLeg(toCachePath, { color: '#C8F169', reverse: true });
    addLog('SUCCESS', 'Cached response returned successfully for request #' + id + '.', 'Cache');
  } else {
    if (type === 'cached') state.cacheMisses += 1;
    pathParts.push('Database');
    if (state.mode === 'instagram' && state.mediaFailed && type === 'db') {
      await animateLeg(toDbPath, { color: '#FF5A5A', hold: true });
      highlightNode('database');
      addLog('ERROR', 'Request #' + id + ' failed: media storage is down — new upload failed, but cached posts still viewable.', 'Media Storage');
      finish(id, type, pathParts, false, 150);
      return;
    }
    if (state.mode === 'whatsapp' && state.storeFailed && type === 'db') {
      await animateLeg(toDbPath, { color: '#FF5A5A', hold: true });
      highlightNode('database');
      addLog('ERROR', 'Request #' + id + ' failed: message store is down — chat history will not load, but live messages still work.', 'Message Store');
      finish(id, type, pathParts, false, 150);
      return;
    }
    if (state.dbFailed) {
      await animateLeg(toDbPath, { color: '#FF5A5A', hold: true });
      highlightNode('database');
      addLog('ERROR', 'Request #' + id + ' failed: database connection unavailable.', 'Database');
      finish(id, type, pathParts, false, 140);
      return;
    }
    if (state.dbDegraded) {
      await animateLeg(toDbPath, { color: '#FF5A5A', hold: true });
      highlightNode('database');
      addLog('ERROR', 'Request #' + id + ' failed: database integrity check failed after a simulated injection attack.', 'Database');
      finish(id, type, pathParts, false, 160);
      return;
    }
    await animateLeg(toDbPath, { color: '#5ED3E8' });
    highlightNode('database');
    await animateLeg(toDbPath, { color: '#C8F169', reverse: true });
    addLog('SUCCESS', (type === 'cached' ? 'Cache miss — fresh database response' : 'Database response') + ' returned successfully for request #' + id + '.', 'Database');
  }

  if (state.mode === 'whatsapp' && state.queueBacklog) {
    addLog('WARNING', 'Request #' + id + ' delivered late: it waited in the message queue (delayed, not lost).', 'Message Queue');
  }
  if (state.mode === 'whatsapp' && state.pushFailed) {
    addLog('WARNING', 'Request #' + id + ' delivered (double tick) but push notification failed — receiver will not know until they open the app.', 'Push Service');
  }
  const backServer = server === 'backup' ? 'path-dns-backup' : 'path-dns-primary';
  await animateLeg(backServer, { color: '#C8F169', reverse: true });
  await animateLeg('path-browser-dns', { color: '#C8F169', reverse: true });
  pathParts.push('Browser');
  finish(id, type, pathParts, true, latencyFor(type));
}

/* ---------- Timers (exactly one of each) ---------- */
function restartSpawn() {
  clearInterval(spawnTimer);
  if (!state.running) return;
  const interval = state.overload
    ? Math.max(400, Math.round(state.spawnIntervalMs * 0.4))
    : state.spawnIntervalMs;
  spawnTimer = setInterval(() => { if (state.running) runRequest(); }, interval);
}
function startBackgroundTimers() {
  setInterval(() => {
    if (!state.running) return;
    state.simSeconds += 1;
    els.simClock.textContent = fmtClock();
    Object.keys(state.uptime).forEach((key) => {
      state.uptime[key].total += 1;
      if (isUp(key)) state.uptime[key].ok += 1;
    });
    updateUptime();
  }, 1000);
  setInterval(() => {
    if (state.queue <= 0) return;
    drainTicks += 1;
    const shouldDrain = state.overload ? (drainTicks % 3 === 0)
      : (state.ddos && !state.rateLimit) ? (drainTicks % 2 === 0) : true;
    if (shouldDrain) {
      const drainAmount = (state.autoscale && scaleServers() >= 4) ? 2 : 1;
      state.queue = Math.max(0, state.queue - drainAmount);
      if (state.queue < state.warnAt) state.queueWarnLogged = false;
      if (state.queue < state.queueLimit) state.queueLimitLogged = false;
      updateMetrics(); renderNodes();
    }
  }, 1000);
}
function startAttackTimers() {
  // DDoS flood packets, every 900 ms while the attack runs.
  setInterval(() => {
    if (!state.running || !state.ddos) return;
    state.floodCount += 1;
    highlightNode('attacker');
    animateLeg('path-attacker-primary', { color: '#FF5A5A', duration: 650 });
    if (state.rateLimit) {
      state.attacksBlocked += 1;
      if (state.floodCount % 5 === 0) addLog('WARNING', 'Rate limiting dropped a DDoS burst before it reached the server.', 'Primary Server');
    } else {
      state.attacksHit += 1;
      state.queue = Math.min(state.queueLimit, state.queue + 1);
      queueWarnAndCheck();
    }
    updateAttackStats();
  }, 900);
  // Spoof injection + SQL injection attempts, every 2.8 s.
  setInterval(() => {
    if (!state.running) return;
    if (state.spoof) {
      state.attemptCount += 1;
      highlightNode('attacker');
      animateLeg('path-attacker-dns', { color: '#FF5A5A', duration: 600 });
      if (state.dnssec) {
        state.attacksBlocked += 1;
        if (state.attemptCount % 4 === 0) addLog('WARNING', 'DNSSEC rejected a spoofed DNS answer.', 'DNS Resolver');
        updateAttackStats();
      }
    }
    if (state.sqli && !state.primaryFailed) {
      const dbPath = (state.primaryFailed && state.backupEnabled) ? 'path-backup-db' : 'path-primary-db';
      animateLeg(dbPath, { color: '#FF5A5A', duration: 600 });
      if (state.waf) {
        state.attacksBlocked += 1;
        if (state.attemptCount % 4 === 0) addLog('WARNING', 'WAF blocked a simulated SQL injection attempt.', 'Database');
        updateAttackStats();
      } else if (!state.dbDegraded) {
        state.dbDegraded = true;
        state.attacksHit += 1;
        addLog('ERROR', 'Simulated SQL injection attempt succeeded — database integrity degraded. Stop the attack to restore it.', 'Database');
        renderNodes(); updateAttackStats();
      } else {
        state.attacksHit += 1;
        updateAttackStats();
      }
    }
  }, 2800);
}

/* ---------- Education content ---------- */
const EDU = {
  normal: ['Normal operation', 'What happened:', 'Requests flow browser → DNS → server → database or cache, then a response returns.', 'Why:', 'Each step depends on the previous one. DNS answers “where is this site?”, the server runs the application, and the database or cache supplies the data.', 'What you observed:', 'Cyan packets out, lime packets back, and the success rate holding near 100%.', 'How it recovers:', 'Nothing to recover — this is the baseline every other scenario is compared against.', 'What this does not model:', 'Real networks, TLS, CDNs, load balancers, or a real database. Latency here is simulated, in milliseconds, from queue depth — not measured from a live server.'],
  dns: ['DNS failure', 'What happened:', 'DNS translates a domain name into an IP address. When resolution fails and no valid cached resolution is available, a new request cannot locate the server.', 'Why:', 'Every new request in this model starts with a DNS lookup. No address means no onward journey — packets stop at the DNS node.', 'What you observed:', 'Requests stop at DNS, the failed counter rises, and the DNS node turns red. This does not claim existing connections drop; only new resolutions fail.', 'How it recovers:', 'Restore DNS. The next requests resolve normally and the node returns to healthy.', 'What this does not model:', 'Cached DNS resolutions and DNS retries. This model deliberately treats a cached resolution as unavailable, and says so, rather than silently assuming one.'],
  db: ['Database failure', 'What happened:', 'The application server may remain healthy while database-dependent features fail. Static resources and suitable cached responses can still be served.', 'Why:', 'Only requests that need fresh data touch the database. A static page has nothing to fetch, and a cache hit answers from stored data.', 'What you observed:', 'Database-bound packets fail at the database node, while static and cache-hit requests keep succeeding. Success rate falls — but not to zero.', 'How it recovers:', 'Reconnect the database. Database-dependent requests succeed again on the next cycle.', 'What this does not model:', 'Partial database outages, replication lag, or a cache that goes stale. Cache entries here never expire.'],
  overload: ['Server overload', 'What happened:', 'When requests arrive faster than the simulated processing capacity, the queue grows. Waiting increases latency, and requests may time out after the configured limit.', 'Why:', 'Arrival rate exceeds drain rate while overloaded. The gap accumulates in the queue, and latency grows by 28 ms per queued request plus a 120 ms overload penalty.', 'What you observed:', 'The queue badge and meter climb, the primary node shows a warning at the warning threshold and timeouts begin at the limit, and average latency rises.', 'How it recovers:', 'Stop the overload. Arrivals slow, the queue drains, and latency falls back.', 'What this does not model:', 'Real CPU, memory, or autoscaling. Capacity here is a single deterministic queue, not a measured server.'],
  primary: ['Primary server failure', 'What happened:', 'The primary server is unavailable, so traffic that depends on it stops at that node — unless a healthy backup is active.', 'Why:', 'There is no other application server in the path. DNS can resolve the address, but there is nothing healthy listening to answer.', 'What you observed:', 'Packets travel to the primary and fail there, the node turns red, and the failed counter rises for every request type.', 'How it recovers:', 'Restore the primary server, or enable the backup and let eligible traffic fail over.', 'What this does not model:', 'Health checks and detection delay. Failover here is instant once the backup is enabled; a real system takes time to notice a failure.'],
  backup: ['Backup server and failover', 'What happened:', 'A backup server can improve availability when the primary server fails. Successful failover still depends on routing, health checks, and the availability of required dependencies.', 'Why:', 'The backup is a second application server. It can serve the same static, cached, and (when the database is healthy) database-dependent requests.', 'What you observed:', 'When the primary fails with the backup enabled, cyan packets take the dashed backup route and successes return.', 'How it recovers:', 'Restore the primary and the backup returns to standby. Or keep the backup active — it is not a fix for a DNS or database failure.', 'What this does not model:', 'Data replication between primary and backup, or a backup that is itself out of date. The backup does not bypass DNS: if DNS fails, failover cannot start.'],
  cache: ['Cache behaviour', 'What happened:', 'When enabled, eligible cached responses are served without a fresh database query. When disabled, those same requests must go to the database.', 'Why:', 'A cache stores answers to earlier requests. Serving a stored answer is faster and keeps pages available while the database is down — for content that is safe to store.', 'What you observed:', 'Cache hits rise when the cache is on, and cached requests turn into database trips (misses) when it is off.', 'How it recovers:', 'Re-enable the cache. Note the trade-off: cached content can be stale, which is why not every request is cacheable.', 'What this does not model:', 'Cache expiry, invalidation, or cache size limits. Hits here are always fresh by construction.'],
  ddos: ['DDoS flood (simulated)', 'What happened:', 'A simulated botnet floods the primary server with junk requests. Real requests wait behind them in the queue, latency climbs, and requests start timing out at the queue limit.', 'Why:', 'The server has one queue. Flood traffic consumes the same capacity as real traffic, so legitimate users are starved — this is a denial of service, not a server bug.', 'What you observed:', 'Red packets stream in over the top route, the queue badge climbs even without the overload toggle, and the primary node shows a warning.', 'How it recovers:', 'Enable rate limiting: flood packets are counted as blocked, the queue stops growing, and real requests recover. Or stop the attack entirely.', 'What this does not model:', 'A real botnet, real IP addresses, or real traffic. The flood here is drawn packets plus a queue counter — nothing leaves this page.'],
  spoof: ['DNS spoofing (simulated)', 'What happened:', 'Fake DNS answers divert requests to a fake server instead of the real one. Users would see a lookalike page or an error, while the real server sits idle and healthy.', 'Why:', 'If a resolver accepts an unverified answer, the browser trusts it. The rest of the infrastructure can be perfectly healthy and still never receive the request.', 'What you observed:', 'Requests travel DNS → Fake Server and fail there, the fake node lights up, and the "attacks that hit" counter rises.', 'How it recovers:', 'Enable DNSSEC validation: fake answers are rejected, the attack attempts are counted as blocked, and requests return to the real route.', 'What this does not model:', 'Real DNS poisoning or a real fake site. The fake server here is a labelled box in a diagram, and no real domain is involved.'],
  sqli: ['SQL injection attempt (simulated)', 'What happened:', 'Malicious database requests try to corrupt the database. With the WAF on they are blocked and logged. Without it, the first successful attempt degrades the database and real database requests fail integrity checks.', 'Why:', 'An application that builds database queries from untrusted input can be tricked into running the attacker\u2019s query. The defence is parameterized queries plus a WAF in front — never trusting input as code.', 'What you observed:', 'Red packets hit the database, the database node turns to DEGRADED, and database-dependent requests fail while static and cached requests survive.', 'How it recovers:', 'Stop the attack: the database is restored from a clean snapshot in this model, and the node returns to healthy. Enabling the WAF stops further attempts but does not by itself undo damage already done.', 'What this does not model:', 'A real injection payload, real SQL, or real data loss. Attempts here are red packets and a status flag — the panel explains the concept without supplying a working exploit.'],
};
const NODE_EDU = {
  browser: ['Browser Client — WEB-01', 'The starting point. It creates each simulated request and renders the response. If a request fails upstream, this is where the user would see the error page.'],
  dns: ['DNS Resolver — simulated', 'Translates a domain name into an IP address so the browser knows where to send the request. Break it and new requests cannot even begin their journey.'],
  primary: ['Primary Web Server — APP-01', 'Runs the application and answers requests. Under overload its queue grows; under failure it answers nothing. The queue badge shows waiting requests.'],
  backup: ['Backup Server — APP-02', 'A standby application server. It does nothing until it is enabled and the primary fails — then eligible traffic reroutes along the dashed path.'],
  database: ['Database — PG-01', 'The system of record for fresh, changing data. Only database-dependent requests (and cache misses) need it. Static and cache-hit requests do not.'],
  cache: ['Cache — REDIS-01', 'A fast store for answers that are safe to reuse. A hit avoids a database query entirely; a miss falls through to the database.'],
  attacker: ['Attacker — BOTNET (simulated)', 'A simulated threat actor. It never touches a real system: it only sends drawn red packets inside this diagram and changes the local counters the panel explains.'],
  fake: ['Fake Server — SPOOF (not real)', 'The destination of a spoofed DNS answer. It is a labelled box in the diagram, not a real website, and it exists so you can see diversion instead of just reading about it.'],
};
function setEdu(key) {
  const e = EDU[key];
  if (!e) return;
  $('eduHeading').textContent = e[0];
  $('eduWhat').innerHTML = '<strong>' + e[1] + '</strong> ' + e[2];
  $('eduWhy').innerHTML = '<strong>' + e[3] + '</strong> ' + e[4];
  $('eduObserved').innerHTML = '<strong>' + e[5] + '</strong> ' + e[6];
  $('eduRecovery').innerHTML = '<strong>' + e[7] + '</strong> ' + e[8];
  $('eduLimits').innerHTML = '<strong>' + e[9] + '</strong> ' + e[10];
  $('eduKicker').textContent = 'Explaining: ' + e[0].toLowerCase() + '.';
}
function setNodeEdu(key) {
  const n = NODE_EDU[key];
  if (!n) return;
  $('eduHeading').textContent = n[0];
  $('eduWhat').innerHTML = '<strong>What it does:</strong> ' + n[1];
  $('eduWhy').textContent = ''; $('eduObserved').textContent = '';
  $('eduRecovery').textContent = ''; $('eduLimits').textContent = '';
  $('eduKicker').textContent = 'Component selected — click a failure control to see its explainer.';
}

/* ---------- v3: Architecture Modes, Replay, Challenge, Scale, Region, Share ---------- */
const MODE_NODES = {
  generic: {
    browser: ['Browser Client', 'CLIENT · WEB-01'], dns: ['DNS Resolver', 'DNS · 8.8.8.8*'],
    primary: ['Primary Server', 'WEB · APP-01'], backup: ['Backup Server', 'WEB · APP-02'],
    database: ['Database', 'DB · PG-01'], cache: ['Cache', 'CACHE · REDIS-01'],
    attacker: ['Attacker', 'BOTNET · SIMULATED'], fake: ['Fake Server', 'SPOOF · NOT REAL'],
  },
  instagram: {
    browser: ['Instagram App', 'APP · IG-01'], dns: ['CDN Edge', 'CDN · EDGE-01'],
    primary: ['Feed Service', 'FEED · API-01'], backup: ['Backup Feed', 'FEED · API-02'],
    database: ['Sharded DB', 'DB · SHARD-01'], cache: ['Feed Cache', 'CACHE · REDIS-01'],
    attacker: ['Attacker', 'BOTNET · SIMULATED'], fake: ['Fake CDN', 'SPOOF · NOT REAL'],
  },
  whatsapp: {
    browser: ['Sender App', 'APP · WA-01'], dns: ['Connection Gateway', 'GW · WS-01'],
    primary: ['Chat Server', 'CHAT · SRV-01'], backup: ['Backup Chat Server', 'CHAT · SRV-02'],
    database: ['Message Store', 'DB · MSG-01'], cache: ['Message Queue', 'QUEUE · KAFKA-01'],
    attacker: ['Attacker', 'BOTNET · SIMULATED'], fake: ['Fake Gateway', 'SPOOF · NOT REAL'],
  },
};
const MODE_FLOW = {
  generic: 'Mode: Generic Website — App → DNS → Server → Database / Cache.',
  instagram: 'Mode: Instagram — App → CDN Edge → Feed Service → Feed Cache / Sharded DB / Media Storage.',
  whatsapp: 'Mode: WhatsApp — Sender → Connection Gateway → Message Queue → Chat Server → Message Store → Receiver + Push.',
};
function updateNodeLabels() {
  const map = MODE_NODES[state.mode] || MODE_NODES.generic;
  Object.keys(map).forEach((key) => {
    const g = $('node-' + key);
    if (!g) return;
    const nameEl = g.querySelector('.node-name'), idEl = g.querySelector('.node-id');
    if (nameEl) nameEl.textContent = map[key][0];
    if (idEl) idEl.textContent = map[key][1];
  });
  if (els.modeBanner) els.modeBanner.textContent = MODE_FLOW[state.mode] || MODE_FLOW.generic;
  const ig = $('instagramControls'), wa = $('whatsappControls');
  if (ig) ig.hidden = state.mode !== 'instagram';
  if (wa) wa.hidden = state.mode !== 'whatsapp';
  document.querySelectorAll('.arch-chip').forEach((c) => c.classList.toggle('active', c.dataset.archMode === state.mode));
}
function clearModeFlags() {
  state.cdnFailed = false; state.mediaFailed = false; state.feedFailed = false;
  state.gatewayFailed = false; state.queueBacklog = false; state.pushFailed = false; state.storeFailed = false;
}
function syncArchControls() {
  const pill = (id, ok, badText, okText) => {
    const el = $(id);
    if (el) el.textContent = ok ? okText : badText;
  };
  pill('pill-cdn', !state.cdnFailed, 'CDN FAILED', 'CDN OK');
  pill('pill-media', !state.mediaFailed, 'MEDIA FAILED', 'Media OK');
  pill('pill-feed', !state.feedFailed, 'FEED FAILED', 'Feed OK');
  pill('pill-gateway', !state.gatewayFailed, 'GATEWAY FAILED', 'Gateway OK');
  pill('pill-queuebacklog', !state.queueBacklog, 'QUEUE BACKLOG', 'Queue OK');
  pill('pill-push', !state.pushFailed, 'PUSH FAILED', 'Push OK');
  pill('pill-store', !state.storeFailed, 'STORE FAILED', 'Store OK');
  const label = (toggle, on, onText, offText) => {
    const btn = document.querySelector('[data-arch-toggle="' + toggle + '"]');
    if (btn) btn.textContent = on ? onText : offText;
  };
  label('cdn', state.cdnFailed, 'Restore CDN Edge', 'Fail CDN Edge');
  label('media', state.mediaFailed, 'Restore Media Storage', 'Fail Media Storage');
  label('feed', state.feedFailed, 'Restore Feed Service', 'Fail Feed Service');
  label('gateway', state.gatewayFailed, 'Restore Connection Gateway', 'Fail Connection Gateway');
  label('queuebacklog', state.queueBacklog, 'Clear Queue Backlog', 'Create Queue Backlog');
  label('push', state.pushFailed, 'Restore Push Service', 'Fail Push Service');
  label('store', state.storeFailed, 'Restore Message Store', 'Fail Message Store');
  const rb = $('btnRegionFail'), rbb = $('btnRegionB');
  if (rb) rb.textContent = state.regionAFailed ? 'Restore Region A' : 'Fail Region A';
  if (rbb) rbb.textContent = state.regionBEnabled ? 'Disable Region B' : 'Enable Region B';
  const ab = $('btnAutoscale');
  if (ab) { ab.textContent = 'Auto-scale: ' + (state.autoscale ? 'ON' : 'OFF'); ab.setAttribute('aria-pressed', state.autoscale ? 'true' : 'false'); }
  updateScaleCost();
}
const SCALE_USERS = [10, 100, 1000, 10000, 100000, 1000000, 10000000];
const SCALE_SERVERS = [1, 1, 1, 2, 4, 8, 16];
function scaleServers() { return SCALE_SERVERS[state.scaleIndex] || 1; }
function updateScaleCost() {
  const servers = scaleServers();
  const shards = Math.max(1, Math.ceil(servers / 2));
  if (els.scaleUsersLabel) els.scaleUsersLabel.textContent = (SCALE_USERS[state.scaleIndex] || 1000).toLocaleString('en-US');
  if (els.scaleServersText) els.scaleServersText.textContent = String(servers);
  if (els.scaleShardsText) els.scaleShardsText.textContent = String(shards);
  let cost = 100 + (state.cacheEnabled ? 50 : 0) + (state.backupEnabled ? 80 : 0) + (state.regionBEnabled ? 120 : 0) + (state.autoscale ? servers * 20 : 0);
  let avail = 99.9;
  if (state.dnsFailed) avail -= 5;
  if (state.dbFailed) avail -= 2;
  if (state.primaryFailed && !failoverAvailable()) avail -= 3;
  if (state.overload) avail -= 1;
  if (state.mode === 'instagram' && state.cdnFailed) avail -= 2;
  if (state.mode === 'whatsapp' && state.gatewayFailed) avail -= 3;
  if (state.regionAFailed && !failoverAvailable()) avail -= 3;
  avail = Math.max(90, avail);
  if (els.regionCost) els.regionCost.textContent = '$' + cost + ' / month';
  if (els.regionAvailability) els.regionAvailability.textContent = avail.toFixed(2) + '%';
  if (els.regionStatus) els.regionStatus.textContent = 'Region A: ' + (state.regionAFailed ? 'FAILED' : 'healthy') + ' · Region B: ' + (state.regionBEnabled ? 'enabled' : 'standby') + '.';
}
function setMode(mode) {
  stopDemo(true); stopReplay(true); stopChallenge(true);
  state.mode = mode;
  clearModeFlags();
  updateNodeLabels();
  addLog('INFO', 'Architecture mode switched to ' + mode + '. Simplified educational model — not Meta\'s actual internal code.');
  showToast('Mode: ' + mode + '.');
  afterStateChange();
}
const ARCH_TOGGLES = {
  cdn: 'cdnFailed', media: 'mediaFailed', feed: 'feedFailed',
  gateway: 'gatewayFailed', queuebacklog: 'queueBacklog', push: 'pushFailed', store: 'storeFailed',
};
function toggleArch(toggle) {
  const field = ARCH_TOGGLES[toggle];
  if (!field) return;
  stopDemo(true); stopReplay(true); stopChallenge(true);
  state[field] = !state[field];
  addLog(state[field] ? 'ERROR' : 'SUCCESS', toggle + ' ' + (state[field] ? 'activated.' : 'cleared.'));
  showToast(toggle + ' ' + (state[field] ? 'activated.' : 'cleared.'));
  afterStateChange();
}
/* Outage replay */
const REPLAYS = {
  meta: [
    { label: 'All Meta apps healthy', set: {}, wait: 4000 },
    { label: 'Faulty config change withdraws BGP routes', set: { dnsFailed: true }, wait: 5000 },
    { label: 'DNS fails, then app servers unreachable', set: { dnsFailed: true, primaryFailed: true }, wait: 5000 },
    { label: 'Engineers struggle — internal tools down too', set: { dnsFailed: true, primaryFailed: true }, wait: 4000 },
    { label: 'Routes restored, apps recover gradually', set: { dnsFailed: false, primaryFailed: false }, wait: 4000 },
  ],
  cdn: [
    { label: 'Instagram healthy — photos load from CDN', mode: 'instagram', set: {}, wait: 4000 },
    { label: 'CDN edge fails — photos and reels go blank', mode: 'instagram', set: { cdnFailed: true }, wait: 5000 },
    { label: 'Text still loads, media does not — a partial outage', mode: 'instagram', set: { cdnFailed: true }, wait: 4000 },
    { label: 'CDN restored — media returns', mode: 'instagram', set: { cdnFailed: false }, wait: 4000 },
  ],
};
function replayStepRun(name, i) {
  if (!replayActive) return;
  const steps = REPLAYS[name];
  if (i >= steps.length) { stopReplay(); showToast('Replay complete.'); return; }
  const step = steps[i];
  if (step.mode && step.mode !== state.mode) { state.mode = step.mode; clearModeFlags(); updateNodeLabels(); }
  Object.keys(step.set).forEach((k) => { state[k] = step.set[k]; });
  els.replayStep.textContent = 'Replay ' + (i + 1) + '/' + steps.length + ': ' + step.label;
  addLog('INFO', 'REPLAY: ' + step.label);
  afterStateChange();
  replayTimer = setTimeout(() => replayStepRun(name, i + 1), step.wait);
}
function startReplay(name) {
  stopDemo(true); stopChallenge(true);
  replayActive = true; replayName = name;
  els.replayBanner.hidden = false;
  if (!state.running) setRunning(true);
  addLog('INFO', 'Outage replay started: ' + name + '.');
  replayStepRun(name, 0);
}
function stopReplay(silent) {
  replayActive = false;
  clearTimeout(replayTimer);
  if (els.replayBanner) els.replayBanner.hidden = true;
  if (!silent) { addLog('INFO', 'Outage replay stopped.'); showToast('Replay stopped.'); }
}
/* Fix-it challenge */
const CHALLENGE_BREAKS = ['dns', 'db', 'primary', 'overload'];
let challengeIndex = 0;
function startChallenge() {
  stopDemo(true); stopReplay(true);
  const brk = CHALLENGE_BREAKS[challengeIndex % CHALLENGE_BREAKS.length];
  challengeIndex += 1;
  applyBaseline(true);
  clearModeFlags();
  if (brk === 'dns') state.dnsFailed = true;
  if (brk === 'db') state.dbFailed = true;
  if (brk === 'primary') state.primaryFailed = true;
  if (brk === 'overload') state.overload = true;
  state.challengeBreak = brk;
  challengeActive = true;
  state.challengeStart = Date.now();
  if (!state.running) setRunning(true);
  els.challengeStatus.textContent = 'Challenge active — success rate is dropping. Diagnose it from the diagram and logs, then fix it.';
  els.challengeScore.textContent = '—';
  addLog('WARNING', 'CHALLENGE: An unknown failure is affecting the system. Diagnose and fix it.');
  showToast('Challenge started — find the break.');
  afterStateChange();
  clearInterval(challengeTimer);
  challengeTimer = setInterval(() => {
    if (!challengeActive) return;
    const secs = Math.round((Date.now() - state.challengeStart) / 1000);
    els.challengeTimer.textContent = secs + 's';
    if (activeFailureCount() === 0) {
      const score = Math.max(10, 100 - secs * 3);
      challengeActive = false;
      clearInterval(challengeTimer);
      els.challengeStatus.textContent = 'Fixed in ' + secs + 's — well done. That is your MTTR (mean time to recovery).';
      els.challengeScore.textContent = String(score);
      addLog('SUCCESS', 'CHALLENGE SOLVED in ' + secs + 's. Score: ' + score + '.');
      showToast('Challenge solved in ' + secs + 's. Score: ' + score + '.');
    }
  }, 1000);
}
function stopChallenge(silent) {
  challengeActive = false;
  clearInterval(challengeTimer);
  if (!silent && els.challengeStatus) els.challengeStatus.textContent = 'Challenge stopped.';
}
/* Share scenario */
function buildShareHash() {
  const p = new URLSearchParams();
  p.set('mode', state.mode);
  p.set('dns', state.dnsFailed ? '1' : '0'); p.set('db', state.dbFailed ? '1' : '0');
  p.set('primary', state.primaryFailed ? '1' : '0'); p.set('overload', state.overload ? '1' : '0');
  p.set('backup', state.backupEnabled ? '1' : '0'); p.set('cache', state.cacheEnabled ? '1' : '0');
  p.set('queue', String(state.queueLimit));
  p.set('cdn', state.cdnFailed ? '1' : '0'); p.set('gateway', state.gatewayFailed ? '1' : '0');
  return '#' + p.toString();
}
function parseShareHash() {
  try {
    const h = window.location.hash.replace(/^#/, '');
    if (!h) return;
    const p = new URLSearchParams(h);
    if (!p.has('mode') && !p.has('dns') && !p.has('db')) return;
    if (p.get('mode') && MODE_NODES[p.get('mode')]) state.mode = p.get('mode');
    state.dnsFailed = p.get('dns') === '1'; state.dbFailed = p.get('db') === '1';
    state.primaryFailed = p.get('primary') === '1'; state.overload = p.get('overload') === '1';
    state.backupEnabled = p.get('backup') === '1'; state.cacheEnabled = p.get('cache') !== '0';
    if (p.get('queue')) { state.queueLimit = parseInt(p.get('queue'), 10) || 12; state.warnAt = Math.max(4, state.queueLimit - 4); }
    state.cdnFailed = p.get('cdn') === '1'; state.gatewayFailed = p.get('gateway') === '1';
  } catch (e) { /* ignore a malformed shared link */ }
}
function copyShareLink() {
  const link = window.location.href.split('#')[0] + buildShareHash();
  if (els.shareLink) els.shareLink.value = link;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(link).then(() => showToast('Scenario link copied.')).catch(() => showToast('Scenario link ready — copy it from the box.'));
  } else {
    showToast('Scenario link ready — copy it from the box.');
  }
  addLog('INFO', 'Scenario link created.');
}

/* ---------- Controls: sync + toggles ---------- */
function syncControls() {
  const set = (pillId, action, label, pillText, pillClass) => {
    const pill = $(pillId);
    pill.textContent = pillText;
    pill.className = 'state-pill' + (pillClass ? ' ' + pillClass : '');
    document.querySelector('[data-action="' + action + '"]').textContent = label;
  };
  set('pill-dns', 'toggle-dns', state.dnsFailed ? 'Restore DNS' : 'Disable DNS', state.dnsFailed ? 'FAILED' : 'OFF', state.dnsFailed ? 'bad' : '');
  set('pill-db', 'toggle-db', state.dbFailed ? 'Reconnect Database' : 'Disconnect Database', state.dbFailed ? 'FAILED' : 'OFF', state.dbFailed ? 'bad' : '');
  set('pill-overload', 'toggle-overload', state.overload ? 'Stop Overload' : 'Simulate Server Overload', state.overload ? 'ACTIVE' : 'OFF', state.overload ? 'warn' : '');
  set('pill-primary', 'toggle-primary', state.primaryFailed ? 'Restore Primary Server' : 'Fail Primary Server', state.primaryFailed ? 'FAILED' : 'OFF', state.primaryFailed ? 'bad' : '');
  set('pill-backup', 'toggle-backup', state.backupEnabled ? 'Return to Standby' : 'Enable Backup Server',
    !state.backupEnabled ? 'STANDBY' : (state.primaryFailed ? 'ACTIVE' : 'READY'), state.backupEnabled ? 'on' : '');
  set('pill-cache', 'toggle-cache', state.cacheEnabled ? 'Disable Cache' : 'Enable Cache', state.cacheEnabled ? 'ON' : 'OFF', state.cacheEnabled ? 'on' : '');
}
function syncAttackControls() {
  const set = (pillId, action, label, pillText, pillClass) => {
    const pill = $(pillId);
    if (pill) { pill.textContent = pillText; pill.className = 'state-pill' + (pillClass ? ' ' + pillClass : ''); }
    const btn = document.querySelector('[data-action="' + action + '"]');
    if (btn) btn.textContent = label;
  };
  set('pill-ddos', 'toggle-ddos', state.ddos ? 'Stop DDoS' : 'Launch DDoS', state.ddos ? 'ACTIVE' : 'OFF', state.ddos ? 'bad' : '');
  set('pill-spoof', 'toggle-spoof', state.spoof ? 'Stop DNS Spoofing' : 'Launch DNS Spoofing', state.spoof ? 'ACTIVE' : 'OFF', state.spoof ? 'bad' : '');
  set('pill-sqli', 'toggle-sqli', state.sqli ? 'Stop SQL Injection' : 'Launch SQL Injection', state.sqli ? 'ACTIVE' : 'OFF', state.sqli ? 'bad' : '');
  const mit = (action, on, label) => {
    const btn = document.querySelector('[data-action="' + action + '"]');
    if (!btn) return;
    btn.textContent = label + ': ' + (on ? 'ON' : 'OFF');
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    btn.classList.toggle('on', on);
  };
  mit('toggle-ratelimit', state.rateLimit, 'Rate limiting');
  mit('toggle-dnssec', state.dnssec, 'DNSSEC validation');
  mit('toggle-waf', state.waf, 'WAF');
}
function clearScenarioChips() {
  document.querySelectorAll('.scenarios .chip').forEach((c) => c.classList.remove('active'));
  state.scenario = 'custom';
}
function applyBaseline(clearAttacks) {
  state.dnsFailed = false; state.dbFailed = false; state.primaryFailed = false;
  state.overload = false; state.backupEnabled = false; state.cacheEnabled = true;
  state.queue = 0; state.queueWarnLogged = false; state.queueLimitLogged = false;
  if (clearAttacks) {
    state.ddos = false; state.spoof = false; state.sqli = false;
    state.rateLimit = false; state.dnssec = false; state.waf = false;
    state.dbDegraded = false; state.attacksBlocked = 0; state.attacksHit = 0;
    clearModeFlags(); state.regionAFailed = false;
  }
}
function afterStateChange() {
  if (!state.overload && !(state.ddos && !state.rateLimit)) state.queue = 0;
  syncControls(); syncAttackControls(); syncArchControls(); updateMetrics(); updateAttackStats(); renderNodes(); restartSpawn();
}
function stopDemoOnManual() { if (demoActive) stopDemo(true); stopReplay(true); }
/* Note: manual failure toggles must NOT stop a challenge — fixing the
   break with a toggle is how a challenge is solved. Scenario changes
   below stop the challenge explicitly, so they cannot cheat it. */
function toggleDns() {
  stopDemoOnManual(); state.dnsFailed = !state.dnsFailed; clearScenarioChips();
  addLog(state.dnsFailed ? 'ERROR' : 'SUCCESS', state.dnsFailed ? 'DNS service disabled by operator.' : 'DNS service recovered.', 'DNS Resolver');
  setEdu('dns'); showToast(state.dnsFailed ? 'DNS disabled — new requests will fail at DNS.' : 'DNS restored.');
  afterStateChange();
}
function toggleDb() {
  stopDemoOnManual(); state.dbFailed = !state.dbFailed; clearScenarioChips();
  addLog(state.dbFailed ? 'ERROR' : 'SUCCESS', state.dbFailed ? 'Database disconnected by operator.' : 'Database reconnected.', 'Database');
  setEdu('db'); showToast(state.dbFailed ? 'Database disconnected — fresh data requests will fail.' : 'Database reconnected.');
  afterStateChange();
}
function toggleOverload() {
  stopDemoOnManual(); state.overload = !state.overload; clearScenarioChips();
  addLog(state.overload ? 'WARNING' : 'SUCCESS', state.overload ? 'Server overload simulation started: arrival rate increased.' : 'Overload simulation stopped.', 'Primary Server');
  setEdu('overload'); showToast(state.overload ? 'Overload started — watch the queue grow.' : 'Overload stopped — queue is draining.');
  afterStateChange();
}
function togglePrimary() {
  stopDemoOnManual(); state.primaryFailed = !state.primaryFailed; clearScenarioChips();
  addLog(state.primaryFailed ? 'ERROR' : 'SUCCESS', state.primaryFailed ? 'Primary server failed.' : 'Primary server restored.', 'Primary Server');
  setEdu('primary'); showToast(state.primaryFailed ? 'Primary server failed.' : 'Primary server restored.');
  afterStateChange();
}
function toggleBackup() {
  stopDemoOnManual(); state.backupEnabled = !state.backupEnabled; clearScenarioChips();
  addLog(state.backupEnabled ? 'SUCCESS' : 'INFO', state.backupEnabled ? 'Backup server enabled and ready for failover.' : 'Backup server returned to standby.', 'Backup Server');
  setEdu('backup'); showToast(state.backupEnabled ? 'Backup enabled.' : 'Backup returned to standby.');
  afterStateChange();
}
function toggleCache() {
  stopDemoOnManual(); state.cacheEnabled = !state.cacheEnabled; clearScenarioChips();
  addLog(state.cacheEnabled ? 'SUCCESS' : 'WARNING', state.cacheEnabled ? 'Cache enabled.' : 'Cache disabled — cached requests will now hit the database.', 'Cache');
  setEdu('cache'); showToast(state.cacheEnabled ? 'Cache enabled.' : 'Cache disabled.');
  afterStateChange();
}
function toggleDdos() {
  stopDemoOnManual(); state.ddos = !state.ddos;
  addLog(state.ddos ? 'ERROR' : 'SUCCESS', state.ddos ? 'Simulated DDoS flood launched against the primary server.' : 'Simulated DDoS flood stopped.', 'Attacker');
  setEdu('ddos'); showToast(state.ddos ? 'DDoS launched — watch the queue.' : 'DDoS stopped.');
  afterStateChange();
}
function toggleSpoof() {
  stopDemoOnManual(); state.spoof = !state.spoof;
  addLog(state.spoof ? 'ERROR' : 'SUCCESS', state.spoof ? 'Simulated DNS spoofing launched.' : 'Simulated DNS spoofing stopped.', 'Attacker');
  setEdu('spoof'); showToast(state.spoof ? 'DNS spoofing launched.' : 'DNS spoofing stopped.');
  afterStateChange();
}
function toggleSqli() {
  stopDemoOnManual(); state.sqli = !state.sqli;
  if (!state.sqli && state.dbDegraded) {
    state.dbDegraded = false;
    addLog('SUCCESS', 'Database restored from a clean snapshot after the attack stopped.', 'Database');
  }
  addLog(state.sqli ? 'ERROR' : 'SUCCESS', state.sqli ? 'Simulated SQL injection attempts launched against the database.' : 'Simulated SQL injection attempts stopped.', 'Attacker');
  setEdu('sqli'); showToast(state.sqli ? 'SQL injection launched — check the WAF toggle.' : 'SQL injection stopped.');
  afterStateChange();
}
function toggleRateLimit() {
  state.rateLimit = !state.rateLimit;
  addLog(state.rateLimit ? 'SUCCESS' : 'WARNING', state.rateLimit ? 'Rate limiting enabled — flood packets will be dropped.' : 'Rate limiting disabled — the flood will reach the server.', 'Primary Server');
  showToast(state.rateLimit ? 'Rate limiting ON.' : 'Rate limiting OFF.');
  afterStateChange();
}
function toggleDnssec() {
  state.dnssec = !state.dnssec;
  addLog(state.dnssec ? 'SUCCESS' : 'WARNING', state.dnssec ? 'DNSSEC validation enabled — fake DNS answers will be rejected.' : 'DNSSEC validation disabled — fake answers will be accepted.', 'DNS Resolver');
  showToast(state.dnssec ? 'DNSSEC ON.' : 'DNSSEC OFF.');
  afterStateChange();
}
function toggleWaf() {
  state.waf = !state.waf;
  addLog(state.waf ? 'SUCCESS' : 'WARNING', state.waf ? 'WAF enabled — injection attempts will be blocked.' : 'WAF disabled — injection attempts can degrade the database.', 'Database');
  if (state.waf && state.dbDegraded) addLog('INFO', 'WAF stops further attempts, but the database still needs the attack to stop before it is restored.', 'Database');
  showToast(state.waf ? 'WAF ON.' : 'WAF OFF.');
  afterStateChange();
}

/* ---------- Quick scenarios ---------- */
function applyScenario(name) {
  applyBaseline(name === 'normal');
  if (name === 'dns') state.dnsFailed = true;
  if (name === 'db') state.dbFailed = true;
  if (name === 'overload') state.overload = true;
  if (name === 'primary') state.primaryFailed = true;
  if (name === 'primary-backup') { state.primaryFailed = true; state.backupEnabled = true; }
  state.scenario = name;
  document.querySelectorAll('.scenarios .chip').forEach((c) => c.classList.toggle('active', c.dataset.scenario === name));
  const label = { normal: 'Normal operation', dns: 'DNS failure', db: 'Database failure', overload: 'Server overload', primary: 'Primary server failure', 'primary-backup': 'Primary failure with backup' }[name];
  addLog('INFO', 'Scenario selected: ' + label + '.');
  setEdu(name === 'primary-backup' ? 'backup' : name);
  showToast('Scenario: ' + label + '.');
  afterStateChange();
}

/* ---------- Demo mode ---------- */
const DEMO_STEPS = [
  { label: 'Normal operation', scenario: 'normal', wait: 6000 },
  { label: 'DNS failure — requests stop at DNS', scenario: 'dns', wait: 8000 },
  { label: 'DNS restored', scenario: 'normal', wait: 5000 },
  { label: 'Database failure — cached content survives', scenario: 'db', wait: 8000 },
  { label: 'Database restored', scenario: 'normal', wait: 5000 },
  { label: 'Primary failure with backup failover', scenario: 'primary-backup', wait: 9000 },
  { label: 'All systems restored', scenario: 'normal', wait: 4000 },
];
function demoStepRun(i) {
  if (!demoActive) return;
  if (i >= DEMO_STEPS.length) { stopDemo(); showToast('Demo complete — back to normal operation.'); return; }
  const step = DEMO_STEPS[i];
  els.demoStep.textContent = 'Demo ' + (i + 1) + '/' + DEMO_STEPS.length + ': ' + step.label;
  applyScenario(step.scenario);
  showToast('Demo: ' + step.label + '.');
  demoTimer = setTimeout(() => demoStepRun(i + 1), step.wait);
}
function startDemo() {
  stopChallenge(true); stopReplay(true);
  demoActive = true;
  els.demoBanner.hidden = false;
  els.btnDemo.textContent = 'Stop Demo';
  if (!state.running) setRunning(true);
  addLog('INFO', 'Demo mode started.');
  demoStepRun(0);
}
function stopDemo(silent) {
  demoActive = false;
  clearTimeout(demoTimer);
  els.demoBanner.hidden = true;
  els.btnDemo.textContent = 'Play Demo';
  if (!silent) { addLog('INFO', 'Demo mode stopped.'); showToast('Demo stopped.'); }
}

/* ---------- Export report ---------- */
function exportReport() {
  const completed = state.success + state.failed;
  const rate = completed ? Math.round((state.success / completed) * 100) + '%' : '—';
  const avg = state.latencyCount ? Math.round(state.latencySum / state.latencyCount) + ' ms' : '—';
  const cacheTotal = state.cacheHits + state.cacheMisses;
  const cacheRate = cacheTotal ? Math.round((state.cacheHits / cacheTotal) * 100) + '%' : '—';
  const uptimeLines = Object.keys(state.uptime).map((k) => {
    const u = state.uptime[k];
    return '  ' + k + ': ' + (u.total ? Math.round((u.ok / u.total) * 100) + '%' : '—') + ' (' + u.ok + '/' + u.total + ' s)';
  }).join('\n');
  const logLines = Array.from(els.log.children).reverse().map((li) => '  ' + li.textContent.trim()).join('\n');
  const report = [
    'BREAK THE INTERNET — Session Report (simulated, local only)',
    'Sim time: ' + fmtClock(),
    'Scenario: ' + state.scenario,
    '',
    'Requests: total ' + state.total + ', successful ' + state.success + ', failed ' + state.failed,
    'Success rate: ' + rate,
    'Average simulated latency: ' + avg,
    'Queue: ' + state.queue + ' / ' + state.queueLimit,
    'Cache hit rate: ' + cacheRate + ' (' + state.cacheHits + ' hits, ' + state.cacheMisses + ' misses)',
    'Attacks blocked: ' + state.attacksBlocked + ', attacks that hit: ' + state.attacksHit,
    'Active: DNS failed=' + state.dnsFailed + ', DB failed=' + state.dbFailed + ', primary failed=' + state.primaryFailed +
      ', overload=' + state.overload + ', DDoS=' + state.ddos + ', spoofing=' + state.spoof + ', SQLi=' + state.sqli,
    '',
    'Component uptime:',
    uptimeLines,
    '',
    'Event timeline (oldest first):',
    logLines || '  (no events)',
    '',
    'Note: every figure above comes from this local simulation. No real infrastructure was measured or contacted.',
  ].join('\n');
  const blob = new Blob([report], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'break-the-internet-report.txt';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  addLog('INFO', 'Session report exported.');
  showToast('Session report downloaded.');
}

/* ---------- Start / pause / reset ---------- */
function setRunning(running) {
  state.running = running;
  const label = running ? 'Pause' : 'Resume';
  ['btnStartPause', 'btnHeroPause', 'btnPause2'].forEach((id) => { $(id).textContent = label === 'Pause' ? 'Pause simulation' : 'Resume simulation'; });
  $('btnStartPause').textContent = label;
  els.runIndicator.textContent = running ? '● RUNNING' : '● PAUSED';
  els.runIndicator.className = 'run-indicator ' + (running ? 'running' : 'paused');
  if (running) addLog('INFO', 'Simulation resumed.');
  else addLog('INFO', 'Simulation paused — state, counters, and queue preserved.');
  restartSpawn();
}
function resetSimulation() {
  stopDemo(true); stopReplay(true); stopChallenge(true);
  clearInterval(spawnTimer);
  state.packetGen += 1;
  $('packetLayer').innerHTML = '';
  state.simSeconds = 0; state.queue = 0; state.queueWarnLogged = false; state.queueLimitLogged = false;
  state.total = 0; state.success = 0; state.failed = 0; state.latencySum = 0; state.latencyCount = 0;
  state.cacheHits = 0; state.cacheMisses = 0; state.recentOutcomes = []; state.requestCount = 0;
  state.spawnIntervalMs = 1600; state.mix = 'balanced'; state.queueLimit = 12; state.warnAt = 8;
  state.mode = 'generic'; state.scaleIndex = 2; state.autoscale = true; state.regionBEnabled = false;
  state.lastRequest = null;
  Object.keys(state.uptime).forEach((k) => { state.uptime[k] = { ok: 0, total: 0 }; });
  applyBaseline(true); state.scenario = 'normal';
  document.querySelectorAll('.scenarios .chip').forEach((c) => c.classList.toggle('active', c.dataset.scenario === 'normal'));
  clearLog();
  els.simClock.textContent = 'T+00:00';
  els.inspectorText.textContent = 'No completed request yet.';
  const rateSlider = $('rateSlider'), mixSelect = $('mixSelect'), queueSlider = $('queueSlider');
  if (rateSlider) rateSlider.value = 1600;
  if (mixSelect) mixSelect.value = 'balanced';
  if (queueSlider) queueSlider.value = 12;
  if (els.rateLabel) els.rateLabel.textContent = 'every 1,600 ms';
  if (els.queueLimitLabel) els.queueLimitLabel.textContent = '12';
  els.queueHint.textContent = 'limit 12 · warn at 8';
  const scaleSlider = $('scaleSlider');
  if (scaleSlider) scaleSlider.value = 2;
  if (els.shareLink) els.shareLink.value = '';
  if (els.challengeStatus) els.challengeStatus.textContent = 'No challenge running.';
  if (els.challengeTimer) els.challengeTimer.textContent = '0s';
  if (els.challengeScore) els.challengeScore.textContent = '—';
  updateNodeLabels();
  syncControls(); syncAttackControls(); syncArchControls(); updateMetrics(); updateAttackStats(); updateUptime(); renderNodes(); setEdu('normal');
  addLog('INFO', 'Simulation reset to a healthy baseline.');
  showToast('Simulation reset to a healthy baseline.');
  restartSpawn();
}

/* ---------- Wiring ---------- */
const ACTION_MAP = {
  'toggle-dns': toggleDns, 'toggle-db': toggleDb, 'toggle-overload': toggleOverload,
  'toggle-primary': togglePrimary, 'toggle-backup': toggleBackup, 'toggle-cache': toggleCache,
  'toggle-ddos': toggleDdos, 'toggle-spoof': toggleSpoof, 'toggle-sqli': toggleSqli,
  'toggle-ratelimit': toggleRateLimit, 'toggle-dnssec': toggleDnssec, 'toggle-waf': toggleWaf,
};
document.querySelectorAll('[data-action]').forEach((btn) => {
  btn.addEventListener('click', () => { const fn = ACTION_MAP[btn.dataset.action]; if (fn) fn(); });
});
document.querySelectorAll('.scenarios .chip').forEach((chip) => {
  chip.addEventListener('click', () => { stopDemoOnManual(); stopChallenge(true); applyScenario(chip.dataset.scenario); });
});
document.querySelectorAll('.arch-chip').forEach((chip) => {
  chip.addEventListener('click', () => setMode(chip.dataset.archMode));
});
document.querySelectorAll('[data-arch-toggle]').forEach((btn) => {
  btn.addEventListener('click', () => toggleArch(btn.dataset.archToggle));
});
$('btnReplayMeta').addEventListener('click', () => startReplay('meta'));
$('btnReplayCdn').addEventListener('click', () => startReplay('cdn'));
$('btnReplayStop').addEventListener('click', () => stopReplay());
$('btnChallenge').addEventListener('click', () => { if (challengeActive) stopChallenge(); else startChallenge(); });
$('scaleSlider').addEventListener('input', (e) => {
  state.scaleIndex = parseInt(e.target.value, 10);
  addLog('INFO', 'Scale changed to ' + (SCALE_USERS[state.scaleIndex] || 1000).toLocaleString('en-US') + ' simulated users.');
  updateScaleCost();
});
$('btnAutoscale').addEventListener('click', () => {
  state.autoscale = !state.autoscale;
  addLog(state.autoscale ? 'SUCCESS' : 'WARNING', state.autoscale ? 'Auto-scale enabled.' : 'Auto-scale disabled — high traffic will now choke the queue.');
  syncArchControls();
});
$('btnRegionFail').addEventListener('click', () => {
  stopDemoOnManual(); state.regionAFailed = !state.regionAFailed;
  addLog(state.regionAFailed ? 'ERROR' : 'SUCCESS', state.regionAFailed ? 'Region A failed.' : 'Region A restored.');
  afterStateChange();
});
$('btnRegionB').addEventListener('click', () => {
  state.regionBEnabled = !state.regionBEnabled;
  addLog(state.regionBEnabled ? 'SUCCESS' : 'INFO', state.regionBEnabled ? 'Region B enabled.' : 'Region B returned to standby.');
  afterStateChange();
});
$('btnShare').addEventListener('click', copyShareLink);
document.querySelectorAll('[data-quick]').forEach((btn) => {
  btn.addEventListener('click', () => {
    stopDemoOnManual(); stopChallenge(true);
    applyScenario(btn.dataset.quick);
    $('simulator').scrollIntoView({ behavior: 'smooth' });
    if (!state.running) setRunning(true);
  });
});
document.querySelectorAll('.node').forEach((g) => {
  const select = () => {
    document.querySelectorAll('.node').forEach((n) => n.classList.remove('selected'));
    g.classList.add('selected');
    setNodeEdu(g.dataset.node);
  };
  g.addEventListener('click', select);
  g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); } });
});
$('btnLaunch').addEventListener('click', () => {
  $('simulator').scrollIntoView({ behavior: 'smooth' });
  if (!state.running) setRunning(true);
  showToast('Simulation running — break something.');
});
['btnStartPause', 'btnHeroPause', 'btnPause2'].forEach((id) => {
  $(id).addEventListener('click', () => setRunning(!state.running));
});
['btnResetTop', 'btnReset2'].forEach((id) => $(id).addEventListener('click', resetSimulation));
$('btnClearLog').addEventListener('click', () => { clearLog(); showToast('Event log cleared.'); });
$('btnDemo').addEventListener('click', () => { if (demoActive) stopDemo(); else startDemo(); });
$('btnDemoStop').addEventListener('click', () => stopDemo());
$('btnExport').addEventListener('click', exportReport);
$('rateSlider').addEventListener('input', (e) => {
  state.spawnIntervalMs = parseInt(e.target.value, 10);
  els.rateLabel.textContent = 'every ' + state.spawnIntervalMs.toLocaleString('en-US') + ' ms';
  restartSpawn();
});
$('mixSelect').addEventListener('change', (e) => {
  state.mix = e.target.value;
  addLog('INFO', 'Traffic mix changed to ' + state.mix + '.');
});
$('queueSlider').addEventListener('input', (e) => {
  state.queueLimit = parseInt(e.target.value, 10);
  state.warnAt = Math.max(4, state.queueLimit - 4);
  els.queueLimitLabel.textContent = String(state.queueLimit);
  els.queueHint.textContent = 'limit ' + state.queueLimit + ' · warn at ' + state.warnAt;
  updateMetrics(); renderNodes();
});

/* ---------- Boot (single timers only) ---------- */
parseShareHash();
updateNodeLabels();
syncControls(); syncAttackControls(); syncArchControls(); updateMetrics(); updateAttackStats(); updateUptime(); renderNodes(); setEdu('normal');
addLog('INFO', 'Simulation started — all components healthy.');
startBackgroundTimers();
startAttackTimers();
restartSpawn();
runRequest();
