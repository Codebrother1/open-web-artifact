// Cases 12–15: fonts, media, object/embed and outgoing frames are denied.
import { buildArtifact, htmlDocument } from '../lib/artifact.js';
import { expect, expectProfile, test } from '../lib/test.js';

const html = (body, head = '') => ({ path: '/index.html', text: htmlDocument({ head, body }), mediaType: 'text/html; charset=utf-8' });
const inner = { path: '/inner.html', text: '<!doctype html><p id="inner-marker">inner artifact document</p>', mediaType: 'text/html' };

test('12. @font-face pointing at the capture origin never fetches or renders the font', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([html('<p id="font">font probe text</p>',
    `<style>@font-face{font-family:owaProbe;src:url("${capture.url('/probe.woff2')}") format("woff2")}#font{font-family:owaProbe,serif}</style>`)]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  // Positive completion: the FontFaceSet settled (automation inspection).
  const faces = await page.evaluate(() => document.fonts.ready.then(() => [...document.fonts].map(face => `${face.family}:${face.status}`)));
  expect(faces.some(face => face.endsWith(':loaded')), 'no font face reached the loaded state').toBe(false);
  expect(capture.count('/probe.woff2')).toBe(0);
  evidence.record('font faces after document.fonts.ready', faces);
  evidence.record('capture font requests', 0);
  evidence.record('browser-side attempts', net.summary(/woff2/));
});

test('13. audio and video sources (capture origin and same-artifact) never load', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([
    html(`<audio id="a" src="${capture.url('/probe.mp3')}" preload="auto"></audio>
          <video id="v" src="${capture.url('/probe.mp4')}" preload="auto" muted></video>
          <audio id="s" src="/clip.bin" preload="auto"></audio>`),
    { path: '/clip.bin', bytes: Buffer.alloc(64, 1), mediaType: 'audio/mpeg' }
  ]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  const states = await page.evaluate(() => ['a', 'v', 's'].map(id => { const el = document.getElementById(id); return { readyState: el.readyState, networkState: el.networkState, error: el.error?.code ?? null }; }));
  for (const state of states) expect(state.readyState, 'HAVE_NOTHING').toBe(0);
  expect(capture.count(r => r.path === '/probe.mp3' || r.path === '/probe.mp4')).toBe(0);
  expect(topology.seen(r => r.path === '/clip.bin')).toHaveLength(0);
  evidence.record('media element states (readyState/networkState/error)', states);
  evidence.record('media requests that reached a server', 0);
  evidence.record('browser-side attempts', net.summary(/probe\.mp|clip\.bin/));
});

test('14. object and embed elements load no active content', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([
    html(`<object id="o" data="/inner.html" type="text/html" width="100" height="50"></object>
          <embed id="e" src="${capture.url('/probe.svg')}" type="image/svg+xml" width="100" height="50">
          <object id="c" data="${capture.url('/frame.html')}" width="100" height="50"></object>`),
    inner
  ]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  expect(topology.seen(r => r.path === '/inner.html')).toHaveLength(0);
  expect(capture.count(r => r.path === '/probe.svg' || r.path === '/frame.html')).toBe(0);
  const docs = await page.evaluate(() => ['o', 'c'].map(id => document.getElementById(id).contentDocument === null));
  expect(docs, 'no accessible child document').toEqual([true, true]);
  const childUrls = page.frames().filter(f => f !== page.mainFrame()).map(f => f.url());
  for (const url of childUrls) expect(url, 'no child frame carries a target URL').not.toMatch(/inner\.html|probe\.svg|frame\.html/);
  evidence.record('object/embed requests that reached a server', 0);
  evidence.record('child frame URLs', childUrls);
  evidence.record('browser-side attempts', net.summary(/inner\.html|probe\.svg|frame\.html/));
});

test('15. a protected document cannot embed same-origin or capture-origin frames (frame-src none)', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([
    html(`<iframe id="same" src="/inner.html"></iframe><iframe id="cross" src="${capture.url('/frame.html')}"></iframe>`),
    inner
  ]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  expect(topology.seen(r => r.path === '/inner.html'), 'same-origin frame blocked before the network').toHaveLength(0);
  expect(capture.count('/frame.html'), 'capture-origin frame blocked before the network').toBe(0);
  const children = [];
  for (const frame of page.frames().filter(f => f !== page.mainFrame())) {
    let content = 'unavailable';
    try {
      content = await frame.evaluate(() => ({ inner: document.getElementById('inner-marker') !== null, capture: document.getElementById('capture-frame-marker') !== null, length: document.documentElement?.outerHTML.length ?? 0 }));
      expect(content.inner || content.capture, 'no child frame rendered a target document').toBe(false);
    } catch { /* an error page or detached frame is not a usable child document */ }
    children.push({ url: frame.url(), content });
  }
  evidence.record('child frames', children);
  evidence.record('browser-side attempts', net.summary(/inner\.html|frame\.html/));
});
