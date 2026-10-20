/* One fingerprint per page; optional observations are never fabricated. */
(() => {
  const sessionToken = `web-${Date.now()}-${Array.from(crypto.getRandomValues(new Uint32Array(2))).join('-')}`;
  const ua = navigator.userAgent;
  const values = [ua, navigator.language, screen.width, screen.height, screen.colorDepth,
    Intl.DateTimeFormat().resolvedOptions().timeZone, navigator.platform];
  let hash = 2166136261;
  for (const char of values.join('|')) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  const payload = {sessionToken, fingerprint: `browser-${(hash >>> 0).toString(16)}`,
    path: location.href, userAgent: ua, language: navigator.language,
    browser: /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Unknown',
    os: /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown',
    screenPrint: `${screen.width}x${screen.height}`, platform: navigator.platform,
    collection_method: 'browser_js', webrtc_status: 'not_collected'};
  const post = (path, data) => fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data), keepalive: true}).then(r => {if (!r.ok) throw new Error(`telemetry HTTP ${r.status}`);});
  // The existing receiver merges HTTP and geo observations. An empty list means
  // no WebRTC addresses were observed, not that an address was inferred.
  post('/cdn/analytics', payload).then(() => post('/cdn/analytics/geo', {ips: []}))
    .catch(error => console.warn(error.message));
  const points = [], clicks = [];
  document.addEventListener('mousemove', e => {if (points.length < 100) points.push([e.clientX, e.clientY]);}, {passive: true});
  document.addEventListener('click', () => {if (clicks.length < 30) clicks.push(Date.now());}, {passive: true});
  let sent = false;
  function behavior() {
    if (sent) return;
    sent = true;
    const data = {sessionToken, userAgent: ua, mouseTrack: points,
      clickIntervals: clicks.slice(1).map((t, i) => t - clicks[i]), timestamp: Date.now()};
    post('/cdn/security/verify', data).catch(() => {sent = false;});
  }
  setTimeout(behavior, 4000);
  addEventListener('pagehide', behavior);
})();
