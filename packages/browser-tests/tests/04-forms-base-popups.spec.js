// Cases 16–18: form submission, author <base>, and popup creation through the
// markup/user-interaction paths an artifact author still has without script.
import { buildArtifact, htmlDocument } from '../lib/artifact.js';
import { awaitDiagnostic, expect, expectProfile, test } from '../lib/test.js';

const html = (body, head = '') => ({ path: '/index.html', text: htmlDocument({ head, body }), mediaType: 'text/html; charset=utf-8' });

test('16. a real click on a submit control produces no form request (form-action none + sandbox without allow-forms)', async ({ page, context, topology, capture, evidence }) => {
  await topology.publish('site-a', buildArtifact([html(`
    <form id="post" method="post" action="${capture.url('/submit')}"><input name="probe" value="not-a-secret"><button id="submit-post" type="submit">Submit POST</button></form>
    <form id="get" method="get" action="${capture.url('/submit-get')}"><input name="probe" value="not-a-secret"><button id="submit-get" type="submit">Submit GET</button></form>
    <form id="self" method="get" action="/self-target"><input name="probe" value="not-a-secret"><button id="submit-self" type="submit">Submit same-origin</button></form>`)]));
  const url = topology.url('site-a');
  expectProfile(await page.goto(url, { waitUntil: 'load' }));
  // Automation stamps the live document; if any submission navigated, the stamp is gone.
  await page.evaluate(() => { document.documentElement.setAttribute('data-owa-automation-stamp', 'present'); });
  const outcomes = {};
  for (const id of ['submit-post', 'submit-get', 'submit-self']) {
    outcomes[id] = await awaitDiagnostic({ page, context, captureOrigin: capture.origin, action: () => page.locator(`#${id}`).click() });
    expect(outcomes[id], 'no request left for the capture origin and no popup appeared').not.toMatch(/^(request:|popup)/);
  }
  expect(capture.count(r => r.path.startsWith('/submit'))).toBe(0);
  expect(topology.seen(r => r.path === '/self-target')).toHaveLength(0);
  expect(page.url()).toBe(url);
  expect(await page.getAttribute('html', 'data-owa-automation-stamp'), 'the same document is still live').toBe('present');
  evidence.record('form submission requests that reached a server', 0);
  evidence.record('browser diagnostic after each click (kind only)', outcomes);
});

test('17. an author <base href> to the capture origin is ignored (base-uri none)', async ({ page, topology, capture, evidence }) => {
  await topology.publish('site-a', buildArtifact([html(
    '<a id="rel" href="rel.txt">relative link</a>',
    `<base href="${capture.url('/base/')}" target="_blank">`
  )]));
  const url = topology.url('site-a');
  expectProfile(await page.goto(url, { waitUntil: 'load' }));
  const resolved = await page.evaluate(() => ({ baseURI: document.baseURI, href: document.getElementById('rel').href }));
  expect(resolved.baseURI, 'document base is the document URL, not the author base').toBe(url);
  expect(resolved.href, 'relative URLs resolve against the content origin').toBe(topology.url('site-a', '/rel.txt'));
  expect(capture.count(r => r.path.startsWith('/base/'))).toBe(0);
  evidence.record('document.baseURI', resolved.baseURI);
  evidence.record('relative link resolved to', resolved.href);
});

test('18. a user click on target=_blank cannot open a popup context (sandbox without allow-popups)', async ({ page, context, topology, capture, evidence }) => {
  await topology.publish('site-a', buildArtifact([html(`
    <a id="blank" href="${capture.url('/popup.html')}" target="_blank" rel="opener">open blank</a>
    <a id="named" href="${capture.url('/popup-named.html')}" target="owaPopupWindow">open named</a>`)]));
  const url = topology.url('site-a');
  expectProfile(await page.goto(url, { waitUntil: 'load' }));
  const outcomes = {};
  for (const id of ['blank', 'named']) {
    outcomes[id] = await awaitDiagnostic({ page, context, captureOrigin: capture.origin, action: () => page.locator(`#${id}`).click() });
    expect(outcomes[id]).not.toBe('popup');
    expect(outcomes[id]).not.toMatch(/^request:/);
  }
  expect(context.pages(), 'still exactly one page in the context').toHaveLength(1);
  expect(capture.count(r => r.path.startsWith('/popup'))).toBe(0);
  expect(page.url(), 'the protected document itself did not navigate either').toBe(url);
  evidence.record('pages in context after clicks', context.pages().length);
  evidence.record('popup requests that reached the capture origin', 0);
  evidence.record('browser diagnostic after each click (kind only)', outcomes);
});
