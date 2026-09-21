// Case 19: an UNPROTECTED local parent tries to iframe the protected artifact.
// The request is allowed to reach the content listener; what must not happen is
// the artifact becoming an active child document (frame-ancestors 'none' and
// X-Frame-Options: DENY on the response).
import { buildArtifact, htmlDocument } from '../lib/artifact.js';
import { expect, test } from '../lib/test.js';

/** Inspect a (possibly blocked) child frame without ever hanging on it. */
async function inspectChild(frame, ms = 3000) {
  if (!frame) return 'no child frame object';
  const probe = frame.evaluate(() => ({
    marker: document.getElementById('marker')?.textContent ?? null,
    title: document.title,
    url: location.href,
    length: document.documentElement?.outerHTML.length ?? 0
  })).catch(error => `unavailable: ${String(error.message).split('\n')[0]}`);
  return Promise.race([probe, new Promise(resolve => setTimeout(() => resolve('unavailable: no document answered'), ms))]);
}

test('19. an unprotected parent page cannot render the protected artifact as a child frame', async ({ page, topology, capture, net, evidence }) => {
  await topology.publish('site-a', buildArtifact([{ path: '/index.html', text: htmlDocument({ marker: 'framed-artifact-marker' }), mediaType: 'text/html' }]));
  const target = topology.url('site-a');
  // Two frames: the protected artifact (must be refused) and an UNPROTECTED
  // control page from the capture origin (must render), so "no content seen" for
  // the artifact is discriminating rather than a harness blind spot.
  const control = capture.url('/control-frame.html');
  const parent = capture.serveParent('/parent.html', `<!doctype html><meta charset="utf-8"><p id="parent">unprotected parent on the capture origin</p>
<iframe id="child" src="${target}" width="300" height="150"></iframe><iframe id="control" src="${control}" width="300" height="150"></iframe>`);
  // A refused child frame may never fire the parent's load event in some engines,
  // so wait for the parent document itself, then for the positive network fact.
  await page.goto(parent, { waitUntil: 'domcontentloaded' });
  await expect(page.locator('#parent')).toHaveText(/unprotected parent/);
  const framedRequest = r => r.path === '/' && (r.host ?? '').startsWith('site-a.localhost');
  // Positive completion: the content listener saw the framed request...
  await expect.poll(() => topology.seen(framedRequest).length, { timeout: 10_000 }).toBeGreaterThan(0);
  const framed = topology.seen(framedRequest);
  // ...the browser finished with the framed response, and the control frame rendered.
  await expect.poll(() => net.completed(target).length + net.matching(target).filter(a => a.outcome === 'failed').length, { timeout: 10_000 }).toBeGreaterThan(0);
  const controlFrame = page.frames().find(frame => frame.url() === control);
  expect(controlFrame, 'the unprotected control frame exists').toBeTruthy();
  await expect(controlFrame.locator('#capture-frame-marker')).toHaveText(/served by capture origin/);

  const child = page.frames().find(frame => frame !== page.mainFrame() && frame !== controlFrame);
  const content = await inspectChild(child);
  if (typeof content === 'object') expect(content.marker, 'the artifact marker did not render inside the parent').toBeNull();
  // Also from the parent's side: no accessible child document (cross-origin OR refused).
  const parentView = await page.evaluate(() => { const f = document.getElementById('child'); let doc = 'inaccessible'; try { doc = f.contentDocument === null ? 'null' : 'accessible'; } catch { doc = 'threw'; } return doc; });
  expect(parentView).not.toBe('accessible');
  // The parent itself is untouched and still shows its own content.
  expect(await page.locator('#parent').textContent()).toContain('unprotected parent');

  evidence.record('request reached the content listener (sec-fetch-dest)', framed.map(r => r.dest ?? 'n/a'));
  evidence.record('browser-side outcome for the framed URL', net.summary(target));
  evidence.record('protected child frame URL / content', { url: child?.url() ?? null, content });
  evidence.record('unprotected control frame rendered its marker', true);
  evidence.note('class B: the request happened; the browser refused to make the response an active child document');
});
