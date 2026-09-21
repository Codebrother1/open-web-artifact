// Cases 20–21: a direct SVG document with script/handlers/external references,
// and HTML-looking bytes under an unapproved media type (octet-stream attachment).
import { readFile } from 'node:fs/promises';
import { GIF_BYTES, HANDLER_SIDE_EFFECT, buildArtifact } from '../lib/artifact.js';
import { expect, expectProfile, test } from '../lib/test.js';

const SVG_SCRIPT = 'document.documentElement.setAttribute("data-owa-script-ran","yes");';

test('20. a direct SVG document executes no script or handler and loads no external subresource', async ({ page, topology, capture, net, evidence }) => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="120" height="120" onload="${HANDLER_SIDE_EFFECT}">
  <title>svg probe</title>
  <script>${SVG_SCRIPT}</script>
  <script href="${capture.url('/svg.js')}"></script>
  <rect id="marker" width="40" height="40" fill="rgb(9, 8, 7)" onclick="${HANDLER_SIDE_EFFECT}" onload="${HANDLER_SIDE_EFFECT}"/>
  <image href="${capture.url('/svg-image.png')}" x="50" width="20" height="20"/>
  <image xlink:href="/pixel.gif" y="50" width="20" height="20"/>
  <a href="${capture.url('/svg-link')}"><text x="10" y="100">link</text></a>
</svg>`;
  await topology.publish('site-a', buildArtifact([
    { path: '/index.html', text: '<!doctype html><p>entry</p>', mediaType: 'text/html' },
    { path: '/evil.svg', text: svg, mediaType: 'image/svg+xml' },
    { path: '/pixel.gif', bytes: GIF_BYTES, mediaType: 'image/gif' }
  ]));
  const response = await page.goto(topology.url('site-a', '/evil.svg'), { waitUntil: 'load' });
  expectProfile(response);
  expect(response.headers()['content-type']).toBe('image/svg+xml');
  const state = await page.evaluate(() => ({
    contentType: document.contentType,
    root: document.documentElement.localName,
    scriptRan: document.documentElement.getAttribute('data-owa-script-ran'),
    handlerRan: document.documentElement.getAttribute('data-owa-handler-ran'),
    rects: document.querySelectorAll('rect').length,
    rootOnload: document.documentElement.getAttribute('onload'),
    scripts: document.querySelectorAll('script').length
  }));
  expect(state.contentType).toBe('image/svg+xml');
  expect(state.root, 'parsed as an SVG document, not an XML parse error page').toBe('svg');
  expect(state.rects, 'static SVG content is present').toBe(1);
  expect(state.scripts, 'both script elements parsed intact').toBe(2);
  expect(state.rootOnload, 'the onload attribute parsed intact').toBe(HANDLER_SIDE_EFFECT);
  // A real click on the rect with an onclick handler.
  await page.locator('#marker').click();
  const after = await page.evaluate(() => document.documentElement.getAttribute('data-owa-handler-ran'));
  expect(state.scriptRan).toBeNull(); expect(state.handlerRan).toBeNull(); expect(after).toBeNull();
  expect(capture.count(r => r.path === '/svg.js' || r.path === '/svg-image.png')).toBe(0);
  expect(topology.seen(r => r.path === '/pixel.gif')).toHaveLength(0);
  evidence.record('SVG document markers (script/handler/onclick)', 'none set');
  evidence.record('SVG external subresource requests that reached a server', 0);
  evidence.record('browser-side attempts', net.summary(/svg\.js|svg-image|pixel\.gif/));
});

test('21. HTML-looking bytes under an unapproved media type are an octet-stream download, not an active document', async ({ page, topology, evidence }) => {
  const bytes = Buffer.from(`<!doctype html><html><head><title>MIME PROBE</title></head><body><h1 id="marker">should never render</h1><script>${SVG_SCRIPT}</script></body></html>`);
  await topology.publish('site-a', buildArtifact([
    { path: '/index.html', text: '<!doctype html><p>entry</p>', mediaType: 'text/html' },
    { path: '/unknown.html', bytes, mediaType: 'application/x-probe' },
    { path: '/plain.html', bytes, mediaType: 'text/plain; charset=utf-8' }
  ]));
  const url = topology.url('site-a', '/unknown.html');
  const responses = [];
  page.on('response', response => { if (response.url() === url) responses.push(response); });
  const [download, navigation] = await Promise.all([
    page.waitForEvent('download'),
    page.goto(url).catch(error => error)
  ]);
  const path = await download.path();
  const saved = await readFile(path);
  expect(saved.equals(bytes), 'downloaded bytes are the artifact bytes, unmodified').toBe(true);
  expect(page.url(), 'the page did not navigate to an HTML document').toBe('about:blank');
  expect(await page.evaluate(() => document.getElementById('marker') === null)).toBe(true);
  await download.delete();
  const headers = responses[0]?.headers() ?? null;
  if (headers) {
    expect(headers['content-type']).toBe('application/octet-stream');
    expect(headers['content-disposition']).toBe('attachment');
    expect(headers['x-owa-security-profile']).toBe('sandboxed-web-v1');
  }
  evidence.record('download event', { suggestedFilename: download.suggestedFilename(), bytes: saved.length, navigationOutcome: navigation instanceof Error ? 'goto rejected (download)' : `goto resolved ${navigation?.status?.() ?? ''}` });
  evidence.record('response headers observed by the browser', headers ? { 'content-type': headers['content-type'], 'content-disposition': headers['content-disposition'] } : 'not surfaced for the download by this engine');

  // The same bytes declared text/plain render as text, never as HTML.
  const plain = await page.goto(topology.url('site-a', '/plain.html'), { waitUntil: 'load' });
  expectProfile(plain);
  const state = await page.evaluate(() => ({ contentType: document.contentType, marker: document.getElementById('marker') === null, scriptRan: document.documentElement.getAttribute('data-owa-script-ran'), text: document.body.textContent.includes('<script>') }));
  expect(state).toEqual({ contentType: 'text/plain', marker: true, scriptRan: null, text: true });
  evidence.record('text/plain HTML-looking bytes', 'rendered as text (document.contentType text/plain), no element or script');
});
