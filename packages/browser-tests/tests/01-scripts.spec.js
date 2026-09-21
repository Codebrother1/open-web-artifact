// Cases 0–6: the exact profile on the real top-level response, and every script
// path an artifact author controls — inline classic, inline module, inline event
// handlers, same-artifact external classic/module, and cross-origin scripts.
import { DATA_GIF, HANDLER_SIDE_EFFECT, SCRIPT_SIDE_EFFECTS, buildArtifact, htmlDocument } from '../lib/artifact.js';
import { expect, expectNoArtifactScriptRan, expectProfile, inspectMarkers, test } from '../lib/test.js';

const TITLE = 'OWA browser probe';
const html = (body, head = '', bodyAttributes = '') => ({ path: '/index.html', text: htmlDocument({ title: TITLE, head, body, bodyAttributes }), mediaType: 'text/html; charset=utf-8' });

test('0. protected top-level response carries the exact sandboxed-web-v1 headers', async ({ page, topology, evidence }) => {
  await topology.publish('site-a', buildArtifact([html('<p>static</p>')]));
  const response = await page.goto(topology.url('site-a'), { waitUntil: 'load' });
  expectProfile(response);
  expect(response.status()).toBe(200);
  expect(response.headers()['content-type']).toBe('text/html; charset=utf-8');
  expect(response.headers()['content-disposition']).toBe('inline');
  expect(await page.locator('#marker').textContent()).toBe('artifact-marker');
  evidence.record('CSP seen by the browser', response.headers()['content-security-policy']);
});

test('1. inline classic script does not execute', async ({ page, topology, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([html(`<script>${SCRIPT_SIDE_EFFECTS}</script>`)]));
  const response = await page.goto(topology.url('site-a'), { waitUntil: 'load' });
  expectProfile(response);
  const markers = await inspectMarkers(page);
  expectNoArtifactScriptRan(markers, TITLE);
  expect(markers.marker).toBe('artifact-marker');
  evidence.record('requests attempted', net.summary());
});

test('2. inline module script does not execute', async ({ page, topology, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([
    html(`<script type="module">${SCRIPT_SIDE_EFFECTS}</script><script type="module">import "./module.js";</script>`),
    { path: '/module.js', text: SCRIPT_SIDE_EFFECTS, mediaType: 'text/javascript' }
  ]));
  const response = await page.goto(topology.url('site-a'), { waitUntil: 'load' });
  expectProfile(response);
  expectNoArtifactScriptRan(await inspectMarkers(page), TITLE);
  // The import inside the blocked inline module never runs, so the module file
  // is never fetched either.
  expect(topology.seen(r => r.path === '/module.js')).toHaveLength(0);
  evidence.record('server hits for /module.js', 0);
  evidence.record('requests attempted', net.summary());
});

test('3. inline event handlers do not execute, even when the underlying allowed resource does load', async ({ page, topology, capture, evidence }) => {
  await topology.publish('site-a', buildArtifact([html(`
    <img id="allowed" alt="" src="${DATA_GIF}" onload="${HANDLER_SIDE_EFFECT}" onerror="${HANDLER_SIDE_EFFECT}">
    <img id="blocked" alt="" src="${capture.url('/handler.gif')}" onerror="${HANDLER_SIDE_EFFECT}" onload="${HANDLER_SIDE_EFFECT}">
    <button id="btn" onclick="${HANDLER_SIDE_EFFECT}">click</button>`,
  '', `onload="${HANDLER_SIDE_EFFECT}"`)]));
  const response = await page.goto(topology.url('site-a'), { waitUntil: 'load' });
  expectProfile(response);
  // The handler attributes parsed intact (so a syntax error is not what stopped them)...
  const attributes = await page.evaluate(() => ['allowed', 'blocked', 'btn'].map(id => document.getElementById(id).getAttribute(id === 'btn' ? 'onclick' : 'onload')).concat(document.body.getAttribute('onload')));
  for (const value of attributes) expect(value).toBe(HANDLER_SIDE_EFFECT);
  // ...and automation inspection shows the data: image genuinely loaded (its load event fired)...
  const allowed = await page.locator('#allowed').evaluate(img => ({ complete: img.complete, naturalWidth: img.naturalWidth }));
  expect(allowed).toEqual({ complete: true, naturalWidth: 1 });
  // ...so an onload handler HAD its event; the handler still did nothing.
  expectNoArtifactScriptRan(await inspectMarkers(page), TITLE);
  // A real user click on an element with an inline onclick handler.
  await page.locator('#btn').click();
  expectNoArtifactScriptRan(await inspectMarkers(page), TITLE);
  expect(capture.count('/handler.gif'), 'network image blocked before the network').toBe(0);
  evidence.record('data: image loaded (naturalWidth)', allowed.naturalWidth);
  evidence.record('onload/onerror/onclick/body-onload markers', 'none set');
});

test('4/6. same-artifact external classic and module scripts do not execute and are not fetched', async ({ page, topology, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([
    html(`<script src="/app.js"></script><script type="module" src="/module.js"></script><link rel="modulepreload" href="/module.js">`),
    { path: '/app.js', text: SCRIPT_SIDE_EFFECTS, mediaType: 'text/javascript' },
    { path: '/module.js', text: SCRIPT_SIDE_EFFECTS, mediaType: 'application/javascript' }
  ]));
  const response = await page.goto(topology.url('site-a'), { waitUntil: 'load' });
  expectProfile(response);
  expectNoArtifactScriptRan(await inspectMarkers(page), TITLE);
  const hits = topology.seen(r => r.path === '/app.js' || r.path === '/module.js');
  expect(hits, 'script-src none blocks before any fetch reaches the content listener').toHaveLength(0);
  evidence.record('server hits for /app.js and /module.js', hits.length);
  evidence.record('browser-side attempts', net.summary(/\/(app|module)\.js$/));
});

test('5. cross-origin script does not execute and never reaches the capture origin', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([html(`<script src="${capture.url('/evil.js')}"></script><script type="module" src="${capture.url('/evil-module.js')}"></script>`)]));
  const response = await page.goto(topology.url('site-a'), { waitUntil: 'load' });
  expectProfile(response);
  expectNoArtifactScriptRan(await inspectMarkers(page), TITLE);
  expect(capture.count(r => r.path.endsWith('.js')), 'capture origin received no script request').toBe(0);
  evidence.record('capture-origin script requests', 0);
  evidence.record('browser-side attempts', net.summary(/evil/));
});
