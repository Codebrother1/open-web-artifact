// Cases 7–11: inline CSS is deliberately ALLOWED (style-src 'unsafe-inline') and
// must visibly apply; external stylesheets and @import are blocked; data: images
// are allowed; network images (same-artifact and cross-origin) are blocked.
import { DATA_GIF, GIF_BYTES, buildArtifact, htmlDocument } from '../lib/artifact.js';
import { expect, expectProfile, test } from '../lib/test.js';

const html = (body, head = '') => ({ path: '/index.html', text: htmlDocument({ head, body }), mediaType: 'text/html; charset=utf-8' });
const computed = (page, selector, property) => page.locator(selector).evaluate((el, prop) => getComputedStyle(el)[prop], property);

test('7. inline <style> and style attributes are allowed and actually applied', async ({ page, topology, evidence }) => {
  await topology.publish('site-a', buildArtifact([html(
    '<p id="styled" style="border:3px solid rgb(40, 50, 60)">styled</p>',
    '<style>#styled{color:rgb(10, 20, 30)}</style>'
  )]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  expect(await computed(page, '#styled', 'color')).toBe('rgb(10, 20, 30)');
  expect(await computed(page, '#styled', 'borderTopColor')).toBe('rgb(40, 50, 60)');
  expect(await computed(page, '#styled', 'borderTopWidth')).toBe('3px');
  evidence.record('computed color from <style>', 'rgb(10, 20, 30)');
  evidence.record('computed border from style attribute', '3px rgb(40, 50, 60)');
});

test('8. same-artifact and cross-origin external stylesheets are blocked', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([
    html('<p id="external-style-target">unstyled</p>',
      `<link rel="stylesheet" href="/style.css"><link rel="stylesheet" href="${capture.url('/evil.css')}">`),
    { path: '/style.css', text: '#external-style-target{color:rgb(200, 0, 0)!important}', mediaType: 'text/css' }
  ]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  expect(await computed(page, '#external-style-target', 'color'), 'default colour: no external rule applied').toBe('rgb(0, 0, 0)');
  expect(topology.seen(r => r.path === '/style.css')).toHaveLength(0);
  expect(capture.count('/evil.css')).toBe(0);
  evidence.record('server hits for /style.css, capture hits for /evil.css', [0, 0]);
  evidence.record('browser-side attempts', net.summary(/\.css$/));
});

test('9. CSS @import inside allowed inline CSS is blocked', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([
    html('<p id="external-style-target">unstyled</p><p id="inline">inline</p>',
      `<style>@import url("${capture.url('/import.css')}");@import url("/style.css");#inline{color:rgb(1, 2, 3)}</style>`),
    { path: '/style.css', text: '#external-style-target{color:rgb(200, 0, 0)!important}', mediaType: 'text/css' }
  ]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  expect(await computed(page, '#inline', 'color'), 'the inline rule beside the @import still applies').toBe('rgb(1, 2, 3)');
  expect(await computed(page, '#external-style-target', 'color'), 'imported rules did not apply').toBe('rgb(0, 0, 0)');
  expect(topology.seen(r => r.path === '/style.css')).toHaveLength(0);
  expect(capture.count('/import.css')).toBe(0);
  evidence.record('@import targets reached (same-artifact, capture)', [0, 0]);
  evidence.record('browser-side attempts', net.summary(/\.css$/));
});

test('10. data: image is allowed and renders', async ({ page, topology, evidence }) => {
  await topology.publish('site-a', buildArtifact([html(`<img id="data" alt="" src="${DATA_GIF}">`)]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  const state = await page.locator('#data').evaluate(img => ({ complete: img.complete, naturalWidth: img.naturalWidth, naturalHeight: img.naturalHeight }));
  expect(state).toEqual({ complete: true, naturalWidth: 1, naturalHeight: 1 });
  evidence.record('data: GIF decoded size', `${state.naturalWidth}x${state.naturalHeight}`);
});

test('11. same-artifact and cross-origin network images are blocked (img-src data: only)', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([
    html(`<img id="same" alt="" src="/pixel.gif"><img id="cross" alt="" src="${capture.url('/pixel.gif')}">
          <p id="bg" style="background-image:url('${capture.url('/bg.png')}')">bg</p>`),
    { path: '/pixel.gif', bytes: GIF_BYTES, mediaType: 'image/gif' }
  ]));
  expectProfile(await page.goto(topology.url('site-a'), { waitUntil: 'load' }));
  const states = await page.evaluate(() => ['same', 'cross'].map(id => { const img = document.getElementById(id); return { complete: img.complete, naturalWidth: img.naturalWidth }; }));
  for (const state of states) expect(state, 'image errored: complete without intrinsic size').toEqual({ complete: true, naturalWidth: 0 });
  expect(topology.seen(r => r.path === '/pixel.gif')).toHaveLength(0);
  expect(capture.count(r => r.path === '/pixel.gif' || r.path === '/bg.png')).toBe(0);
  evidence.record('image requests that reached a server (same-artifact, capture img, capture CSS background)', [0, 0, 0]);
  evidence.record('browser-side attempts', net.summary(/pixel\.gif|bg\.png/));
});
