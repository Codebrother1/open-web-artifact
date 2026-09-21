# `@owa/browser-tests` — real-browser validation of `sandboxed-web-v1`

Optional, package-local Playwright suite that checks whether real browser engines
enforce the existing [`sandboxed-web-v1`](../../docs/sandboxed-web-v1.md) response
policy and the v0.4 [content-only origin topology](../../docs/origins.md) the way
the documentation says — and that makes the documented **limits** of the profile
concrete (pre-existing service worker, navigation, cookies).

It is **evidence for the existing contract, not part of it**. The deterministic
HTTP tests in `packages/conformance` remain authoritative for exact headers, MIME
grammar and byte preservation. Nothing here changes the profile, the server, or
artifact identity, and nothing in the runtime, CLI, storage, MCP or root
dependency graph depends on this package.

## Dependency boundary

- The only dependency is `@playwright/test`, pinned exactly in this package's own
  `package.json` / `package-lock.json`. The repository root has no dependencies
  and `npm test` neither installs nor needs a browser.
- Browser binaries are downloaded by Playwright into its own cache outside the
  repository. They are never committed; neither are traces, videos, screenshots
  or downloads (output goes to a temporary directory).

## Install and run

```sh
# 1. package-local dependencies (exact versions from the lockfile)
npm --prefix packages/browser-tests ci --ignore-scripts

# 2. the real engines (Playwright's pinned Chromium, Firefox and WebKit builds)
npm --prefix packages/browser-tests run install-browsers
#    On Linux the engines also need system libraries; Playwright prints exactly
#    which are missing. `npx playwright install-deps` covers Debian/Ubuntu hosts.

# 3. run
npm run test:browser                       # from the repository root, or
npm --prefix packages/browser-tests test
```

Useful variables:

| Variable | Effect |
| --- | --- |
| `OWA_BROWSERS=chromium,firefox` | Run only the listed engines. An engine that is not run is reported as **NOT RUN**, never as a pass. |
| `OWA_BROWSER_EVIDENCE_JSON=/path/out.json` | Also write the evidence matrix as JSON. |

`npm --prefix packages/browser-tests run versions` launches each engine and
prints the exact version it reports (or why it cannot start).

## What the suite does

Every test starts its own **real** `createContentServer()` over a fresh temporary
filesystem store, publishes adversarial artifacts through the ordinary core
commit path, and binds sites to `<site>.localhost` — the documented separated
development topology. Attacker/capture destinations are a second loopback server
that records only request metadata (method, path, `Sec-Fetch-Dest`, whether a
`Referer` was present, cookie names). No test contacts anything outside
`127.0.0.1` / `*.localhost`; a request to any other host is aborted and fails the
test.

Every positive enforcement test first verifies, through the browser's own
response object, that the top-level response carries the **exact**
`sandboxed-web-v1` headers. There is no test-only CSP.

Artifact-authored code (scripts, handlers, CSS) is written so that it would leave
visible side effects if it ran — attributes on the root element, a changed title,
an injected element, a request to the capture origin. Automation then *inspects*
the DOM with Playwright. Playwright's ability to evaluate is never used as
evidence that artifact scripts could run; the tests also assert the adversarial
attributes parsed intact so a syntax error can never masquerade as enforcement.

For each blocked resource class the evidence distinguishes:

- **A** — blocked before any request (server counter stays 0; Chromium and
  Firefox report the attempt as a CSP failure);
- **B** — the request reached a server but the browser refused to use the
  response (incoming framing under `frame-ancestors 'none'`);
- **C** — a top-level navigation, which is outside the subresource policy.

The final report prints a `Behavior | engine…` matrix with `PASS`, `FAIL`,
`SKIP (reason)`, `EXPECTED LIMIT` (a documented limitation that was demonstrated,
not an enforcement claim) or `NOT RUN`, followed by the recorded observations.

## What passing does not mean

Passing means the listed behaviors were observed under the listed engine versions
on the recorded date. It does **not** establish browser-engine vulnerability
resistance, malware safety, HTML sanitization, behavior of future browser
versions, private content, cookie stripping, service-worker cleanup, blocking of
all navigation, a network air gap, or any protection once downloaded content is
opened elsewhere. See the [threat model](../../docs/sandboxed-web-v1-threat-model.md).
