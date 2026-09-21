// Cases 22–25: the content listener's route surface, the inert ?site= selector,
// Host-bound site isolation, and no-store / current-active-release behaviour —
// all observed through real browser navigation.
import { buildArtifact, htmlDocument } from '../lib/artifact.js';
import { expect, expectProfile, test } from '../lib/test.js';

const site = marker => buildArtifact([{ path: '/index.html', text: htmlDocument({ marker }), mediaType: 'text/html' }], { spaFallback: '/index.html' });

test('22. /health and /v1/* do not exist on the content listener, even with an SPA fallback', async ({ page, topology, evidence }) => {
  await topology.publish('site-a', site('site-a-marker'));
  const observed = {};
  for (const path of ['/health', '/v1/sites/site-a/releases', '/v1/sites/site-a/publish/plan', '/v1']) {
    const response = await page.goto(topology.url('site-a', path), { waitUntil: 'load' });
    expectProfile(response);
    expect(response.status(), `${path} is a fixed 404`).toBe(404);
    expect(await page.evaluate(() => document.getElementById('marker') === null), 'SPA fallback did not serve the artifact for a reserved path').toBe(true);
    observed[path] = response.status();
  }
  // A non-reserved unknown path still falls back to the SPA entrypoint — the 404s above are the boundary, not a broken site.
  const spa = await page.goto(topology.url('site-a', '/some/app/route'), { waitUntil: 'load' });
  expect(spa.status()).toBe(200);
  expect(await page.locator('#marker').textContent()).toBe('site-a-marker');
  evidence.record('reserved paths on the content listener', observed);
});

test('23. ?site= cannot select another site on the content listener', async ({ page, topology, evidence }) => {
  await topology.publish('site-a', site('site-a-marker'));
  await topology.publish('site-b', site('site-b-marker'));
  const response = await page.goto(topology.url('site-a', '/?site=site-b'), { waitUntil: 'load' });
  expectProfile(response);
  expect(await page.locator('#marker').textContent(), 'Host stays authoritative').toBe('site-a-marker');
  evidence.record('marker served for site-a.localhost/?site=site-b', 'site-a-marker');
});

test('24. Host-bound sites resolve their own artifacts on distinct content hostnames', async ({ page, context, topology, evidence }) => {
  await topology.publish('site-a', site('site-a-marker'));
  await topology.publish('site-b', site('site-b-marker'));
  const seen = {};
  for (const slug of ['site-a', 'site-b']) {
    const response = await page.goto(topology.url(slug), { waitUntil: 'load' });
    expectProfile(response);
    seen[slug] = await page.locator('#marker').textContent();
    expect(seen[slug]).toBe(`${slug}-marker`);
  }
  // An unbound hostname on the same listener is the ordinary 404, not a site.
  const unknown = await page.goto(`http://nosuchsite.localhost:${topology.port}/`, { waitUntil: 'load' });
  expectProfile(unknown);
  expect(unknown.status()).toBe(404);
  evidence.record('markers by hostname', seen);
  evidence.note('URL-origin / Host binding only; this does not demonstrate a registrable-domain cookie boundary');
  void context;
});

test('25. repeated navigation observes the current active release, not a stale protected page (no-store)', async ({ page, topology, evidence }) => {
  const v1 = await topology.publish('site-a', site('release-v1-marker'));
  const first = await page.goto(topology.url('site-a'), { waitUntil: 'load' });
  expectProfile(first);
  expect(first.headers()['cache-control']).toBe('no-store');
  expect(await page.locator('#marker').textContent()).toBe('release-v1-marker');
  const readsAfterFirst = topology.metadataReads.getSite;

  // Publish v2 without activating, then flip the active pointer through core.
  const v2 = await topology.publish('site-a', site('release-v2-marker'), { activate: false });
  expect(v2.release.id).not.toBe(v1.release.id);
  expect((await topology.metadata.getSite('site-a')).activeReleaseId, 'inactive publish left v1 active').toBe(v1.release.id);
  await topology.activate('site-a', v2.release.id);

  const second = await page.goto(topology.url('site-a'), { waitUntil: 'load' });
  expectProfile(second);
  expect(await page.locator('#marker').textContent(), 'a new navigation shows v2').toBe('release-v2-marker');
  const reloaded = await page.reload({ waitUntil: 'load' });
  expectProfile(reloaded);
  expect(await page.locator('#marker').textContent(), 'a reload shows v2').toBe('release-v2-marker');
  expect(topology.metadataReads.getSite, 'the server re-read the site record on every navigation').toBeGreaterThanOrEqual(readsAfterFirst + 2);
  evidence.record('markers (first, after activation, after reload)', ['release-v1-marker', 'release-v2-marker', 'release-v2-marker']);
  evidence.record('server getSite reads', topology.metadataReads.getSite);
});
