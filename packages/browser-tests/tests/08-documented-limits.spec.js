// Documented LIMITS of sandboxed-web-v1, made concrete in a real browser. These
// are not enforcement claims and never a reason to change production code:
//   * a PRE-EXISTING service worker on a reused origin intercepts navigation
//     before the protected network response arrives;
//   * ordinary user-activated navigation is not a network air gap;
//   * pre-existing request cookies are not stripped.
import { createServer, request as httpRequest } from 'node:http';
import { buildArtifact, htmlDocument } from '../lib/artifact.js';
import { nodeGet } from '../lib/servers.js';
import { expect, expectProfile, test } from '../lib/test.js';

/**
 * A disposable origin whose hostname is being REUSED: first it served an
 * unprotected bootstrap that registered a service worker; later the same
 * hostname fronts OWA content (modelled as a proxy to the real content listener,
 * relaying the exact protected response). The worker is what a browser already
 * holds for that origin.
 */
async function startReusedOrigin(topology, slug) {
  let mode = 'bootstrap';
  const counters = { target: 0 };
  const swScript = `self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (new URL(e.request.url).pathname === '/target') {
    e.respondWith(new Response('<!doctype html><meta charset="utf-8"><p id="sw-marker">served by the PRE-EXISTING service worker</p><script>document.documentElement.setAttribute("data-owa-sw-script-ran","yes")</script>', { headers: { 'content-type': 'text/html; charset=utf-8' } }));
  }
});`;
  const bootstrap = `<!doctype html><meta charset="utf-8"><p id="state">registering</p>
<script>
// Page-authored script on the UNPROTECTED bootstrap: this is the pre-existing
// deployment installing its worker, before the origin ever served OWA content.
(async () => {
  const state = document.getElementById('state');
  try {
    await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) await new Promise(r => navigator.serviceWorker.addEventListener('controllerchange', r, { once: true }));
    state.textContent = navigator.serviceWorker.controller ? 'controlling' : 'not-controlling';
  } catch (error) { state.textContent = 'failed:' + error.name; }
})();
</script>`;
  const server = createServer((req, res) => {
    const path = req.url.split('?')[0];
    if (path === '/') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); return res.end(bootstrap); }
    if (path === '/sw.js') { res.writeHead(200, { 'content-type': 'text/javascript', 'cache-control': 'no-store' }); return res.end(swScript); }
    if (path === '/target') {
      counters.target++;
      if (mode !== 'protected') { res.writeHead(503, { 'content-type': 'text/plain' }); return res.end('not yet fronting OWA content'); }
      // Relay the REAL content listener's response for site `slug`, headers and all.
      const upstream = httpRequest({ hostname: '127.0.0.1', port: topology.port, path: '/', method: req.method, headers: { host: `${slug}.localhost:${topology.port}` } }, up => {
        res.writeHead(up.statusCode, up.headers);
        up.pipe(res);
      });
      upstream.on('error', () => { res.writeHead(502); res.end(); });
      return upstream.end();
    }
    res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return {
    origin, counters,
    frontOwaContent() { mode = 'protected'; },
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(() => resolve()); })
  };
}

test('LIMIT: a pre-existing service worker on a reused origin intercepts navigation before the protected response arrives', async ({ browser, topology, evidence }) => {
  await topology.publish('site-a', buildArtifact([{ path: '/index.html', text: htmlDocument({ marker: 'protected-artifact-marker' }), mediaType: 'text/html' }]));
  const reused = await startReusedOrigin(topology, 'site-a');
  // Dedicated context: the point is state that ALREADY exists for the origin.
  const dirty = await browser.newContext();
  try {
    const page = await dirty.newPage();
    await page.route(url => !/^http:\/\/127\.0\.0\.1:\d+\//.test(url.href), route => route.abort());
    await page.goto(`${reused.origin}/`, { waitUntil: 'load' });
    await expect(page.locator('#state'), 'the worker installed, activated and controls the page').toHaveText('controlling', { timeout: 15_000 });

    // NETWORK SIDE: the origin now fronts OWA content. Verified from Node, outside any browser.
    reused.frontOwaContent();
    const direct = await nodeGet(`${reused.origin}/target`);
    expect(direct.status).toBe(200);
    expect(direct.headers['x-owa-security-profile']).toBe('sandboxed-web-v1');
    expect(direct.headers['content-security-policy']).toContain("script-src 'none'");
    expect(direct.body.toString()).toContain('protected-artifact-marker');
    const hitsBeforeNavigation = reused.counters.target;

    // The controlled context navigates to the same URL.
    const response = await page.goto(`${reused.origin}/target`, { waitUntil: 'load' });
    const state = await page.evaluate(() => ({
      swMarker: document.getElementById('sw-marker')?.textContent ?? null,
      artifactMarker: document.getElementById('marker')?.textContent ?? null,
      swScriptRan: document.documentElement.getAttribute('data-owa-sw-script-ran')
    }));
    expect(state.swMarker, 'the worker substituted its own document').toContain('PRE-EXISTING service worker');
    expect(state.artifactMarker, 'the protected artifact never became the document').toBeNull();
    expect(state.swScriptRan, 'page script in the worker response executed: no protected response governed this navigation').toBe('yes');
    expect(response.headers()['content-security-policy'], 'no CSP reached the document').toBeUndefined();
    expect(reused.counters.target, 'the network-side protected route was never even asked').toBe(hitsBeforeNavigation);
    evidence.limit('a service worker registered on the origin BEFORE it fronted OWA content served an unprotected document with executing script for the protected URL; the protected network response never governed the navigation');
    evidence.record('worker-provided response: fromServiceWorker()', typeof response.fromServiceWorker === 'function' ? await response.fromServiceWorker() : 'n/a');
    evidence.record('network hits for /target during the controlled navigation', reused.counters.target - hitsBeforeNavigation);

    // CONTROL: a fresh context with no worker gets the protected response for the same URL.
    const clean = await browser.newContext();
    try {
      const cleanPage = await clean.newPage();
      await cleanPage.route(url => !/^http:\/\/127\.0\.0\.1:\d+\//.test(url.href), route => route.abort());
      const protectedResponse = await cleanPage.goto(`${reused.origin}/target`, { waitUntil: 'load' });
      expectProfile(protectedResponse);
      const cleanState = await cleanPage.evaluate(() => ({ artifactMarker: document.getElementById('marker')?.textContent ?? null, swMarker: document.getElementById('sw-marker'), swScriptRan: document.documentElement.getAttribute('data-owa-sw-script-ran') }));
      expect(cleanState).toEqual({ artifactMarker: 'protected-artifact-marker', swMarker: null, swScriptRan: null });
      expect(reused.counters.target).toBe(hitsBeforeNavigation + 1);
      evidence.record('fresh context, same URL', 'exact sandboxed-web-v1 profile, artifact rendered, no worker marker');
    } finally { await clean.close(); }
  } finally {
    await dirty.close();
    await reused.close();
  }
});

test('LIMIT: an ordinary user-activated self-targeted link may leave the content origin (not a network air gap)', async ({ page, topology, capture, evidence }) => {
  await topology.publish('site-a', buildArtifact([{ path: '/index.html', text: htmlDocument({ body: `<a id="leave" href="${capture.url('/landing.txt')}">leave the gateway</a>` }), mediaType: 'text/html' }]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  const landing = capture.url('/landing.txt');
  const arrival = page.waitForResponse(landing, { timeout: 8000 }).then(response => response).catch(() => null);
  await page.locator('#leave').click();
  const response = await arrival;
  if (response === null) {
    // An engine that refuses this navigation under sandbox semantics is recorded, not corrected.
    expect(capture.count('/landing.txt')).toBe(0);
    expect(page.url()).toBe(topology.url('site-a'));
    evidence.limit('this engine did NOT follow the self-targeted link; the profile makes no claim either way');
    evidence.record('navigation outcome', 'blocked by the engine');
    return;
  }
  await page.waitForURL(landing);
  const requests = capture.requests.filter(r => r.path === '/landing.txt');
  expect(requests.length).toBeGreaterThan(0);
  expect(response.headers()['x-owa-security-profile'], 'the destination is outside the profile').toBeUndefined();
  expect(requests.every(r => r.hasReferer === false), 'Referrer-Policy: no-referrer — no Referer was sent').toBe(true);
  evidence.limit('an ordinary self-targeted link navigated the top-level document to the capture origin; sandboxed-web-v1 is not a navigation quarantine');
  evidence.record('navigation outcome', { arrivedAt: page.url(), refererSent: requests.some(r => r.hasReferer), destinationProfileHeader: response.headers()['x-owa-security-profile'] ?? null });
});

test('LIMIT: a pre-existing cookie for the content origin is not stripped from the top-level request', async ({ page, context, topology, evidence }) => {
  await topology.publish('site-a', buildArtifact([{ path: '/index.html', text: htmlDocument(), mediaType: 'text/html' }]));
  const url = topology.url('site-a');
  // Seeded by the harness BEFORE navigation: an obviously synthetic value, never a secret.
  await context.addCookies([{ name: 'owa_probe_cookie', value: 'synthetic-not-a-secret', url }]);
  const response = await page.goto(url, { waitUntil: 'load' });
  expectProfile(response);
  const topLevel = topology.seen(r => r.path === '/' && (r.host ?? '').startsWith('site-a.localhost'));
  expect(topLevel.length).toBeGreaterThan(0);
  const sent = topLevel.some(r => r.cookieNames.includes('owa_probe_cookie'));
  if (sent) evidence.limit('the browser sent the pre-existing cookie on the top-level request; the sandbox makes the document opaque but does not rewrite the request or strip cookies');
  else evidence.note('this engine did not attach the seeded cookie to the content-origin request in this harness; no stripping is claimed — cookieless content origins remain an operator requirement');
  evidence.record('cookie names seen by the content listener on the top-level request', topLevel.map(r => r.cookieNames));
  evidence.record('response still carried the exact profile', true);
});
