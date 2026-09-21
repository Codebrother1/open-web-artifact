// Shared Playwright fixtures for the sandboxed-web-v1 browser suite.
//
// Two kinds of code appear in these tests and must not be confused:
//   * ARTIFACT-AUTHORED code (scripts, handlers, CSS, markup inside the published
//     artifact) — the thing under test. It must not execute or load.
//   * AUTOMATION code (page.evaluate / locators) — how the test INSPECTS the
//     resulting DOM. Playwright can evaluate even where page scripts are blocked,
//     so its success is never used as evidence that artifact scripts can run.
import { test as base, expect } from '@playwright/test';
import { startCaptureServer, startContentTopology } from './servers.js';

export { expect };

/** Exact sandboxed-web-v1 contract, written out literally (never imported from the implementation). */
export const PROFILE_CSP = "sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
export const PROFILE_HEADERS = Object.freeze({
  'content-security-policy': PROFILE_CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex, nofollow, noarchive',
  'cache-control': 'no-store',
  'x-frame-options': 'DENY',
  'x-dns-prefetch-control': 'off',
  'x-owa-security-profile': 'sandboxed-web-v1'
});

/** Assert a Playwright Response carries the exact profile (header names are lowercase in Playwright). */
export function expectProfile(response) {
  expect(response, 'a response was received').not.toBeNull();
  const headers = response.headers();
  for (const [name, value] of Object.entries(PROFILE_HEADERS)) {
    expect(headers[name], `exact ${name}`).toBe(value);
  }
}

const LOOPBACK = /^https?:\/\/(?:127\.0\.0\.1|localhost|[a-z0-9_.-]+\.localhost)(?::\d+)?\//i;

/**
 * Per-page network observation: every request the browser ATTEMPTED (Playwright
 * sees CSP-blocked requests in Chromium as failed requests; other engines may not
 * emit them at all), what failed, and what completed. Server-side counters remain
 * the ground truth for "reached the network".
 */
function observe(page) {
  const attempts = [];
  page.on('request', request => {
    const entry = { url: request.url(), type: request.resourceType(), outcome: 'pending', status: null, failure: null };
    attempts.push(entry);
    request.response().then(response => { if (response) { entry.outcome = 'response'; entry.status = response.status(); } }).catch(() => {});
  });
  page.on('requestfailed', request => {
    const entry = attempts.find(a => a.url === request.url() && a.outcome === 'pending');
    if (entry) { entry.outcome = 'failed'; entry.failure = request.failure()?.errorText ?? null; }
  });
  page.on('requestfinished', request => {
    const entry = attempts.find(a => a.url === request.url() && a.outcome === 'pending');
    if (entry) entry.outcome = 'response';
  });
  return {
    attempts,
    /** Requests whose URL matches, regardless of outcome. */
    matching: pattern => attempts.filter(a => typeof pattern === 'string' ? a.url === pattern : pattern.test(a.url)),
    /** Requests that completed with an HTTP response (reached a server). */
    completed: pattern => attempts.filter(a => (typeof pattern === 'string' ? a.url === pattern : pattern.test(a.url)) && a.outcome === 'response'),
    summary: pattern => attempts.filter(a => !pattern || (typeof pattern === 'string' ? a.url === pattern : pattern.test(a.url)))
      .map(a => `${a.type} ${new URL(a.url).pathname} → ${a.outcome}${a.status ? ` ${a.status}` : ''}${a.failure ? ` (${a.failure})` : ''}`)
  };
}

export const test = base.extend({
  /** The real content-only listener over a fresh temporary store. */
  topology: async ({}, use) => {
    const topology = await startContentTopology();
    await use(topology);
    await topology.close();
  },
  /** A fresh loopback attacker/capture origin. */
  capture: async ({}, use) => {
    const capture = await startCaptureServer();
    await use(capture);
    await capture.close();
  },
  /**
   * Fresh page with (a) an egress guard — any URL outside loopback is aborted and
   * fails the test, so no test can ever reach the public network — and (b) the
   * request observer.
   */
  page: async ({ page }, use, testInfo) => {
    const escaped = [];
    await page.route(url => !LOOPBACK.test(url.href), route => { escaped.push(route.request().url()); route.abort(); });
    await use(page);
    expect(escaped, 'no request may leave loopback').toEqual([]);
    void testInfo;
  },
  net: async ({ page }, use) => { await use(observe(page)); },
  /**
   * Evidence recorder. Facts land in the test's annotations and are rendered by
   * lib/evidence-reporter.js into the per-engine matrix. `limit()` marks a test
   * that documents an expected limitation rather than an enforcement claim.
   */
  evidence: async ({ browserName, browser }, use, testInfo) => {
    testInfo.annotations.push({ type: 'engine', description: `${browserName} ${browser.version()}` });
    await use({
      record: (fact, value) => { testInfo.annotations.push({ type: 'evidence', description: `${fact}: ${typeof value === 'string' ? value : JSON.stringify(value)}` }); },
      limit: description => { testInfo.annotations.push({ type: 'expected-limit', description }); },
      note: description => { testInfo.annotations.push({ type: 'note', description }); }
    });
  }
});

/**
 * Automation inspection of the side effects artifact-authored code WOULD have left.
 * Runs in the page via Playwright; that this works is not evidence about scripts.
 */
export function inspectMarkers(page) {
  return page.evaluate(() => ({
    title: document.title,
    scriptRan: document.documentElement.getAttribute('data-owa-script-ran'),
    handlerRan: document.documentElement.getAttribute('data-owa-handler-ran'),
    captureScriptRan: document.documentElement.getAttribute('data-owa-capture-script-ran'),
    injected: document.getElementById('injected') !== null,
    marker: document.getElementById('marker')?.textContent ?? null,
    baseURI: document.baseURI,
    contentType: document.contentType,
    readyState: document.readyState
  }));
}

export function expectNoArtifactScriptRan(markers, expectedTitle) {
  expect(markers.scriptRan, 'artifact script did not set its marker attribute').toBeNull();
  expect(markers.handlerRan, 'artifact handler did not set its marker attribute').toBeNull();
  expect(markers.captureScriptRan, 'capture-origin script did not set its marker attribute').toBeNull();
  expect(markers.injected, 'artifact script did not inject an element').toBe(false);
  if (expectedTitle !== undefined) expect(markers.title, 'artifact script did not change the title').toBe(expectedTitle);
}

/**
 * Wait, boundedly, for a browser-side diagnostic after a user action that should
 * be refused: a console message (any wording; text is never asserted), a
 * SecurityPolicyViolation event observed by automation, a new page, or a request
 * to the capture origin. Returns which signal arrived first, or 'none'.
 */
export async function awaitDiagnostic({ page, context, captureOrigin, action, ms = 3000 }) {
  const violation = page.evaluate(() => new Promise(resolve => {
    // Automation-installed listener; the artifact cannot install one itself.
    document.addEventListener('securitypolicyviolation', event => resolve(`csp:${event.violatedDirective}`), { once: true });
  })).catch(() => new Promise(() => {}));
  const signals = [
    violation,
    page.waitForEvent('console', { timeout: ms }).then(message => `console:${message.type()}`).catch(() => null),
    context.waitForEvent('page', { timeout: ms }).then(() => 'popup').catch(() => null),
    page.waitForEvent('request', { predicate: request => request.url().startsWith(captureOrigin), timeout: ms }).then(request => `request:${new URL(request.url()).pathname}`).catch(() => null),
    new Promise(resolve => setTimeout(() => resolve('none'), ms))
  ];
  await action();
  const outcome = await Promise.race(signals.map(p => p.then(v => v ?? new Promise(() => {}))));
  return outcome;
}
