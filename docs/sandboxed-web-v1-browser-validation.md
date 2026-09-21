# `sandboxed-web-v1`: browser validation

Two kinds of browser evidence exist for this profile:

1. an **automated real-browser suite**, [`packages/browser-tests`](../packages/browser-tests/README.md)
   (optional, package-local Playwright; not required by `npm test` or any
   runtime package), whose dated record is in the next section;
2. the **manual procedure** below, for an operator who wants to repeat the
   observations by hand in a browser/version of their choosing.

Read the [profile](sandboxed-web-v1.md) and
[pre-implementation threat model](sandboxed-web-v1-threat-model.md) first.
Deterministic HTTP tests establish headers, MIME selection and byte preservation;
they do not prove browser enforcement. The probes contain real attempted
operations if served without policy. Do not open them as `file:` URLs or on an
unprotected static server, and do not enter real secrets into them.

## Automated real-browser evidence (recorded)

**Scope of the claim.** The behaviors listed below were *observed* under the
listed engine versions on the recorded date. This is evidence for the existing
`sandboxed-web-v1` contract in those engines, not a proof of browser-engine
vulnerability resistance, malware safety, HTML sanitization, universal
future-browser behavior, private content, cookie stripping, service-worker
cleanup, blocking of all navigation, a network air gap, or protection after
downloaded content is opened elsewhere. Do not read "browser sandbox proven
secure" into any row.

**Record — 2026-09-21.** Playwright 1.63.0 (package-local lockfile), Node
v24.14.1, Linux 6.18 x86_64 (Amazon Linux 2023, glibc 2.34), headless, run via
`OWA_BROWSERS=chromium,firefox npm run test:browser`; 28 tests per engine.

| Engine | Version actually executed | Result |
| --- | --- | --- |
| Chromium | 153.0.8010.12 (Playwright build v1243, headless shell) | 28/28 — 25 PASS, 3 EXPECTED LIMIT |
| Firefox | 155.0 (Playwright build v1543) | 28/28 — 25 PASS, 3 EXPECTED LIMIT |
| WebKit | 26.6 (Playwright build v2359) — **NOT RUN** | The engine binary requires `GLIBC_2.38` (and Ubuntu-24.04 runtime libraries) that this host's glibc 2.34 cannot provide; Playwright refused to start it. No result is claimed for WebKit; rerun on a supported host (`OWA_BROWSERS=webkit`). |

Every enforcement test first verified, through the browser's own response
object, that the top-level response carried the exact eight profile headers and
the exact CSP; no test-only policy was used. Observed behaviors, both engines
unless noted (A = blocked before any request reached a server; B = request
reached a server, browser refused the response; C = top-level navigation,
outside the subresource policy):

| Behavior | Chromium 153 | Firefox 155 |
| --- | --- | --- |
| Inline classic script; inline module script (+ its `import`) | no side effect; module file never fetched (A) | same |
| Inline event handlers (`onload` on a data: image that *did* load, `onerror`, `onclick` via real click, `<body onload>`), attributes verified parsed intact | none ran | same |
| Same-artifact external classic/module script, `modulepreload` | not executed, 0 server hits (A) | same |
| Cross-origin (capture-origin) script | not executed, 0 capture hits (A) | same |
| Inline `<style>` and `style=""` | applied (computed style) | same |
| External stylesheets (same-artifact, capture) and inline `@import` | not applied, 0 hits (A) | same |
| `data:` image | decoded 1×1 | same |
| Network images (same-artifact, capture, CSS background) | errored, 0 hits (A) | same |
| `@font-face` → capture | face status `error`, 0 hits (A) | same |
| `<audio>`/`<video>` (capture, same-artifact) | `readyState 0`, `MEDIA_ERR_SRC_NOT_SUPPORTED`, 0 hits (A) | same |
| `<object>`/`<embed>` | no request, no child document (A) | same |
| Outgoing `<iframe>` (same-origin, capture) | no request (A); child frames are error/blank documents | same (empty child frame URL) |
| Form submit via real click (POST/GET to capture, GET same-origin) | 0 requests; console diagnostic | 0 requests; no page-console diagnostic observed |
| Author `<base href>` | `document.baseURI` = document URL; relative link resolves on content origin | same |
| `target=_blank` / named-target link via real click | no new page, 0 requests; console diagnostic | no new page, 0 requests; diagnostic for `_blank` only |
| Incoming framing by an unprotected parent (`frame-ancestors 'none'` + XFO) | request reached listener (`Sec-Fetch-Dest: iframe`, 200) but the child is `chrome-error://` with no artifact content, while an unprotected control frame beside it rendered (B) | request reached listener; protected child never became an inspectable document, control frame rendered (B) |
| Direct SVG document (script, `onload`, `onclick`, external `<image>`s) | parsed as `<svg>` with attributes intact; no script/handler effect; 0 subresource hits (A) | same |
| HTML bytes under `application/x-probe` | `Content-Disposition: attachment` → download event; page stayed `about:blank`; bytes unmodified | same |
| HTML bytes under `text/plain` | `document.contentType text/plain`, rendered as text | same |
| `/health`, `/v1/...` on the content listener (site with SPA fallback) | fixed 404 with profile; non-reserved path still falls back | same |
| `?site=site-b` on `site-a.localhost` | site A served | same |
| `site-a.localhost` vs `site-b.localhost` | each its own artifact; unbound host 404 (URL-origin binding only) | same |
| Active release changed via core `activateRelease` | next navigation and reload showed the new release; server re-read the site record each time; `no-store` on every response | same |
| **LIMIT** pre-existing service worker on a reused origin | worker installed on an unprotected bootstrap (`clients.claim`), then the origin fronted the real protected response: the worker served its own document, its page script **executed**, 0 network hits for the URL (`fromServiceWorker: true`); fresh context → exact profile | same (worker substituted; script executed; 0 hits) |
| **LIMIT** ordinary self-targeted link (C) | navigated to the capture origin; no `Referer`; destination outside the profile | same |
| **LIMIT** pre-existing cookie for the content origin | sent on the top-level request; response still fully protected | same |

Engine differences observed: Firefox surfaces no page-console message when a
sandboxed form submission or a named-target popup is refused (Chromium does); the
outcomes — zero requests, same document still live, one page in the context —
were identical. Firefox represents the refused frames as empty-URL frames rather
than an error-page URL. Neither difference changes the policy or the profile.

To reproduce, see the package [README](../packages/browser-tests/README.md).
Rerun on each browser/version you intend to support; a result for one engine is
not evidence for another.

## Manual procedure

## 1. Isolate the environment and record it

Use a disposable browser profile with no extensions, stored credentials, cookies,
caches or service workers. Private/incognito mode alone is not evidence that the
origin and its history are clean. Use a fresh origin; inspect the browser's
storage/service-worker panels and record the starting state. Do not use a real
account, existing app origin or previously credentialed parent domain.

For production-like assessment, use a clean **content-only, one-site origin on a
cookieless domain**, with control/admin/API services on separate origins and no
parent-domain secrets. This topology is required by the full profile, but is
**not enforced by the reference server**. An operator-managed test deployment must
supply that separation; this guide adds no routing architecture.

The commands below use an isolated local prototype for response-policy
observation only. `npm run dev:server` explicitly selects `--dev` and binds
`127.0.0.1`, regardless of `HOST`. Keep it direct-loopback-only; never expose dev
mode through a proxy. Normal startup instead requires auth configuration; see
[auth startup and deployment](auth.md#startup-and-deployment). Neither mode
implements the content-only topology above.
Record browser name, full version/build, engine, OS, server revision, exact test
URL, origin setup, proxy settings and whether a controlled network endpoint was
used. Repeat at least once in each browser/version the operator intends to
support; do not infer cross-browser support from one result.

## 2. Materialize the repository fixtures without altering the corpus

Run from the repository root with Node.js 22+. The fixture source is
[`security-fixtures/sandboxed-web-v1.json`](security-fixtures/sandboxed-web-v1.json).
Its `samples` use literal UTF-8 `text` or explicit `base64`; `typeCases` bind those
bytes to exact paths and MIME metadata. Some intentionally contain mismatched
bytes and types. The helper below preserves those cases, rather than using the
directory packer's extension-based MIME inference.

This optional setup uses Node built-ins and existing repository publication/store
APIs only. It writes generated files and local store state **outside the
repository**, publishes through the existing local `commitManifest` operation,
and then uses the explicit local development server. Direct `commitManifest` and
store access are trusted-operator paths governed by filesystem permissions, not
HTTP bearer authorization. This setup does not create a new protocol, modify
fixtures/schema/code, or import the security-profile helper to generate expected
results. Run the shell commands in one terminal so the environment variables are
retained. The snippet itself has not been run as browser evidence.

```bash
export OWA_BROWSER_WORK="$(mktemp -d "${TMPDIR:-/tmp}/owa-browser-review.XXXXXX")"
export OWA_DATA_DIR="$OWA_BROWSER_WORK/store"
export OWA_STORAGE=filesystem
export PORT=7331

node --input-type=module <<'NODE'
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { createDefaultStores } from './packages/server/src/index.js';
import { commitManifest } from './packages/core/src/index.js';

const work = process.env.OWA_BROWSER_WORK;
if (!work) throw new Error('Set OWA_BROWSER_WORK to a new temporary directory');
const fixture = JSON.parse(await readFile('docs/security-fixtures/sandboxed-web-v1.json', 'utf8'));
const sources = fixture.typeCases.map(probe => ({
  ...fixture.samples[probe.sample], path: probe.path, mediaType: probe.mediaType
}));

// Derivatives are extra, explicitly local browser probes; original cases stay intact.
const inlineMarker = 'window.owaInlineRan=true;document.documentElement.dataset.owaInlineRan="yes";';
const externalMarker = 'window.owaExternalRan=true;document.documentElement.dataset.owaExternalRan="yes";';
const checks = fixture.samples.html.text
  .replace('</head>', `<link rel="stylesheet" href="/harmless.css"><link rel="stylesheet" href="/probe.css">
<style>@font-face{font-family:owaProbe;src:url('https://font.invalid/probe.woff2')}.font-probe{font-family:owaProbe}#inline-style{border:3px solid rgb(20,80,40)}</style></head>`)
  .replace('</body>', `<p id="inline-style" class="probe font-probe">Static marker; inline border should render.</p>
<script>${inlineMarker}</script><script src="/harmless.js"></script><script src="/probe.js"></script>
<a id="base-check" href="/plain.txt">Relative-URL/base check (self navigation)</a>
<a href="https://popup.invalid/" target="_blank">Popup probe</a>
<a href="https://top.invalid/" target="_top">Top-target probe; not a universal navigation-denial test</a>
<a href="/download.bin" download>Sandbox download probe</a>
<audio controls src="https://media.invalid/probe.mp3"></audio>
<video controls src="https://media.invalid/probe.mp4"></video></body>`);
sources.push(
  { path: '/browser-checks.html', mediaType: 'text/html; charset=utf-8', text: checks },
  { path: '/browser-checks.svg', mediaType: 'image/svg+xml', text: fixture.samples.svg.text.replace('<script>', '<script>window.owaSvgRan=true;document.documentElement.setAttribute("data-script-ran","yes");') },
  { path: '/harmless.js', mediaType: 'text/javascript', text: externalMarker },
  { path: '/harmless.css', mediaType: 'text/css', text: ':root{--owa-css-loaded:1}' },
  { path: '/harmless-js-as-text.txt', mediaType: 'text/plain', text: 'window.owaWrongMimeRan=true;' },
  { path: '/harmless-css-as-text.txt', mediaType: 'text/plain', text: ':root{--owa-wrong-css:1}' },
  { path: '/download.bin', mediaType: 'application/octet-stream', text: 'Harmless download marker\n' }
);
const stores = await createDefaultStores();
const files = [];
for (const source of sources) {
  const bytes = Object.hasOwn(source, 'text')
    ? Buffer.from(source.text, 'utf8') : Buffer.from(source.base64, 'base64');
  const digest = 'sha256:' + createHash('sha256').update(bytes).digest('hex');
  const filename = join(work, 'materialized', source.path.slice(1));
  await mkdir(dirname(filename), { recursive: true });
  await writeFile(filename, bytes);
  await stores.blobs.put(digest, bytes);
  files.push({ path: source.path, digest, size: bytes.length, mediaType: source.mediaType });
}
const manifest = {
  specVersion: 'owa.dev/v1', artifactType: 'application/vnd.openwebartifact.site.v1+json',
  entrypoint: '/index.html', files, access: { visibility: 'unlisted' },
  lifecycle: { expiresAt: null }
};
await writeFile(join(work, 'manifest.json'), JSON.stringify(manifest, null, 2));
const { release } = await commitManifest({ slug: 'security', manifest, ...stores });
console.log({ work, releaseId: release.id, artifactDigest: release.artifactDigest });
NODE

npm run dev:server
```

Visit `http://security.localhost:7331/` in the clean browser. If that hostname does
not resolve locally, configure a local loopback mapping; do not silently test a
public host. Changing `PORT` also changes all example URLs and the origin.

**Local URL footnote:** the prototype also supports
`http://localhost:7331/?site=security`, but it shares an origin across site
selectors and relative asset URLs need their own selector. Do not use it to
claim isolation. `a.localhost` and `b.localhost` are distinct URL origins, not an
automatic guarantee about all cookie/site boundaries. API routes remain reachable
on every prototype host, with the auth overlay's identifier and authorization
checks (or explicit direct-loopback dev checks), not content-only separation.
The local example is not a production-topology test.

## 3. Establish HTTP evidence first (not browser proof)

In another terminal, inspect responses independently of browser behavior.
Artifact GET/HEAD and GET `/health` below are public in both required and dev
modes; no auth tokens are needed. Successful protected control probes instead
need a valid bearer with the required site/capabilities or explicitly selected
direct-loopback dev mode; see the [capability matrix](auth.md#capability-matrix).
In required mode, a missing-bearer control response should retain the profile
headers, `no-store` and the 401 `WWW-Authenticate` challenge. Do not record or
paste bearer credentials into the report.

```bash
curl --noproxy '*' --resolve security.localhost:7331:127.0.0.1 -sS -D - -o /dev/null http://security.localhost:7331/
curl --noproxy '*' --resolve security.localhost:7331:127.0.0.1 -sS -I http://security.localhost:7331/
curl --noproxy '*' --resolve security.localhost:7331:127.0.0.1 -sS -I http://security.localhost:7331/probe.svg
curl --noproxy '*' --resolve security.localhost:7331:127.0.0.1 -sS -I http://security.localhost:7331/unknown.html
curl --noproxy '*' --resolve security.localhost:7331:127.0.0.1 -sS -I http://security.localhost:7331/no-such-file
curl --noproxy '*' -sS -D - http://127.0.0.1:7331/health
```

Compare against the **exact eight headers and CSP in the profile**, not an output
computed from the implementation helper. Compare GET and HEAD for representative
HTML, JS, CSS, JSON, SVG, images, WASM, attachments and artifact errors: HEAD must
have no body and the same representation/policy headers. GET `/health` is 200 JSON;
the local upload flow, not health, produces 204. This does not add HEAD control
routes. A direct HEAD inspection is HTTP evidence only.

For valid inline cases, confirm exact original MIME spelling/parameters and
`Content-Disposition: inline`; for invalid or unapproved cases confirm
`application/octet-stream` plus `attachment`, **without a filename**. Check
`/plain.html` (HTML-looking bytes declared plain text), `/html.bin` (HTML declared
HTML regardless of extension), `/crlf.html`, `/duplicate.html`, `/probe.pdf` and
`/probe.xhtml`. Also check `/charset-space-before.html` (`charset =utf-8`),
`/charset-space-after.html` (`charset= utf-8`), `/charset-spaces-quoted.html`
(`CHARSET = "Utf-8"`), and `/escaped.txt`: all must be attachments because spaces
surround a parameter `=`. The legacy `/escaped.txt` input is intentionally
unchanged even though its fixture ID is `valid-escaped-parameter`; its expected
disposition is now attachment. In contrast, `/escaped-strict.txt` must preserve
its exact valid MIME string and remain inline: spaces around semicolons and
spaces or `=` **inside** quoted values remain valid. These are metadata dispatch
tests, not byte sanitization tests or measured browser MIME-parser behavior.
Do not open downloaded adversarial files in another application.

Take the ETag from an asset GET and repeat GET/HEAD with `If-None-Match` containing
that exact quoted value. Expect current responses, not 304, and `no-store` in all
cases. `X-Robots-Tag` remains advisory even for this unlisted site. Deterministic
control/error/cache-state coverage is in `security-gateway.test.js`; the simple
curl list is not exhaustive and does not simulate authentication.

If testing raw traversal, use `curl --path-as-is` or Node `http.request`'s literal
`path` option, not `fetch` or a URL constructor. Example: `/assets/../index.html`
should produce artifact 404, not normalized entrypoint success. Conversely GET
`/discard/../health` retains the baseline control-route health alias. The 44
portable vectors test direct resolver arguments; do not turn them into normalized
browser URLs and claim equivalent coverage.

## 4. Observe document enforcement in DevTools

Open DevTools before navigating. Enable Network **Preserve log**, inspect the
main-document response headers, clear the log, and reload. Disabling the browser
cache can help isolate this pass but is not a test of cache semantics. Capture
Console CSP/sandbox violations, the Network blocked reason/initiator and relevant
DOM/computed-style observations. Do not remove headers, grant sandbox tokens or
paste active probe code into the console to make it run.

All network probe destinations embedded in the repository samples use
`*.invalid`. **A DNS failure, no successful request, or an empty remote log is
not proof of CSP enforcement.** Record positive browser diagnostics such as
"blocked by Content Security Policy" or sandbox violations. If stronger network
evidence is required, an operator may substitute only endpoints they control in
a temporary derivative, record every substitution, and collect endpoint logs
alongside browser diagnostics. Do not change the repository fixture. Distinguish
blocked attempts from successful traffic; lack of a log alone is inconclusive.
The reference server does not supply a browser/network observation harness.

### HTML, styles and images

1. Load `/index.html`, then `/browser-checks.html`. Verify the static content is
   present. On the derivative, the marker paragraph stays unchanged and its
   inline border renders; body text is `rgb(20, 80, 40)`. The 1×1 `data:` GIF is
   deliberately tiny: inspect its loaded dimensions (`naturalWidth`/`naturalHeight`
   equal to 1), rather than expecting a large visible picture.
2. Inspect inline/handler and external script violations. Read-only console
   inspection of `window.owaInlineRan`, `window.owaExternalRan` and
   `document.documentElement.dataset` should show no marker assignments from
   the artifact scripts. No `data-owa-inline-ran` or `data-owa-external-ran`
   attribute should have been set. The same-artifact `/harmless.js` and `/probe.js`
   and external `https://script.invalid/probe.js` must not execute. DevTools is a
   privileged diagnostic context: JavaScript typed there is not evidence that
   artifact scripts may run. If inspection is restricted, record that limitation
   and rely on DOM snapshots/diagnostics, not guessed values.
3. Verify external and same-artifact CSS, including `/harmless.css` and
   `/probe.css`, are blocked. The custom property `--owa-css-loaded` must not be
   set by the external stylesheet. Inline `@import`, CSS background-image, font,
   and network `<img>` requests should show CSP blocking. The derivative includes
   an actual `.probe`/`.font-probe` element so background/font rules are exercised.
   Inline CSS being allowed does not permit its network URLs.
4. Exercise audio/video play controls if needed to cause a request attempt;
   expect `media-src` blocking. Record if the browser never attempts a load rather
   than claiming that no attempted load proves enforcement. There should be no
   successful malicious subresource traffic in these no-navigation checks.
5. Inspect `document.baseURI` and the resolved URL of `#base-check`. The author
   `<base href="https://base.invalid/">` should be refused by `base-uri 'none'`;
   the link should resolve on the actual content URL's origin, not `base.invalid`.

### Forms, frames, popups, downloads and navigation

- Click **Submission probe**. Expect form submission to be blocked by sandbox and/or
  `form-action 'none'`, with no successful form request. The scripted submit
  attempts never run; the button provides a separate user-triggered check.
- Inspect the `<object>` and `<iframe>` blocked loads and associated CSP
  diagnostics. They should not display their remote content. The protected page
  itself cannot be an external-embedding test harness: its own `frame-src 'none'`
  would stop the request before testing the target's `frame-ancestors`.
- Click the derivative's **Popup probe** and record sandbox refusal/no popup.
  Absence of a popup from the blocked `window.open` script alone is only evidence
  that scripts did not run.
- Record that the inline `top.location` script is blocked. **Do not infer a
  universal navigation ban.** Testing ancestor/top navigation independently would
  require a suitable separate harness, but this profile also denies frame
  embedding. A `_top` link in a top-level document may target its own context;
  it is not independent proof of forbidden ancestor navigation.
- Ordinary self-targeted links may navigate, including leaving the gateway.
  Test `#base-check` only after saving logs; it may navigate to `/plain.txt`.
  The supplied external self-navigation link and top-target link may cause a
  navigation attempt and `.invalid` DNS failure. Do not classify this as a
  forbidden subresource escape, or require it to be blocked. Passive/navigation
  mechanisms such as meta refresh are not a promised network air gap either.
  No `navigate-to` guarantee is part of the profile.
- If desired, click **Sandbox download probe** and record the browser's sandbox
  download behavior. No `allow-downloads` permission is granted. Separately,
  navigating directly to `/download.bin` via browser UI may offer a user download;
  record the distinction and browser behavior. Use this harmless marker, never
  open a downloaded malicious fixture, and do not claim protections follow a
  downloaded file.

### Direct SVG and MIME handling

1. Navigate directly to `/probe.svg` and `/browser-checks.svg` in the address bar,
   not through an iframe blocked by the parent policy. Inspect their document
   headers, SVG script/handler violations and blocked remote image/frame attempts.
   On the derivative, `window.owaSvgRan` should not be assigned and the root
   `data-script-ran` attribute should remain absent. Static SVG text may render;
   script and foreign-content subresources are not thereby permitted. Record
   browser-specific SVG rendering rather than assuming identical output.
2. Navigate to `/plain.html`: HTML-looking source declared `text/plain` must not
   become an executing HTML document. Navigate to `/pixel.gif` for a valid direct
   raster image. Invalid image-byte fixtures may fail decoding; that is not
   sanitization. Direct JS/CSS/JSON/WASM viewing/downloading is browser-specific;
   it does not show that an artifact script ran.
3. Unknown types, PDF/XML/XHTML and malformed MIME fixtures should carry the
   octet-stream attachment response. Prefer header inspection rather than opening
   those files. `nosniff` has a more precise script/style consumption check below.

## 5. Separate controlled consumer harness (optional)

Document framing and subresource reuse need a **different, controlled origin and
an unprotected consumer page**. Do not use the protected fixture as the harness.
The following optional localhost server uses Node built-ins, is separate from
`artifactd`, and serves only a harmless consumer document. It does not execute the
adversarial `/probe.js` or `/probe.css` samples. Run it in a third terminal, then
visit `http://127.0.0.1:7442/` in the disposable browser. Adjust URLs if necessary
and record that change. This is manual operator setup, not implemented repository
browser automation or a recommended production server.

```bash
node --input-type=module <<'NODE'
import { createServer } from 'node:http';
const html = `<!doctype html><meta charset="utf-8"><title>Controlled OWA consumer</title>
<h1>Controlled external consumer</h1>
<iframe src="http://security.localhost:7331/index.html"></iframe>
<link rel="stylesheet" href="http://security.localhost:7331/harmless.css">
<link rel="stylesheet" href="http://security.localhost:7331/harmless-css-as-text.txt">
<script src="http://security.localhost:7331/harmless.js"></script>
<script src="http://security.localhost:7331/harmless-js-as-text.txt"></script>`;
createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(html);
}).listen(7442, '127.0.0.1', () => console.log('Controlled harness: http://127.0.0.1:7442/'));
NODE
```

Check and record separately:

- The iframe should be refused by the **target** `frame-ancestors 'none'` and/or
  `X-Frame-Options: DENY`. Confirm the reason in Console. A target HTTP request may
  still occur before framing is refused; framing protection is not no-network.
- The correctly typed harmless classic script may execute in this unprotected
  consumer (`window.owaExternalRan === true`, root marker attribute present), and
  the correctly typed CSS may set `--owa-css-loaded` to `1`. That is **not a profile
  bypass**: CSP on the JS/CSS response is not the consuming page's policy. Record
  other browser security rules if they block a load instead.
- The `text/plain` script/style controls should be refused for MIME/nosniff
  reasons: `window.owaWrongMimeRan` is not assigned and `--owa-wrong-css` is not
  set. Confirm MIME diagnostics; mere absence of a marker is inconclusive without
  confirming the load was attempted. These tests intentionally use harmless
  bytes so the external consumer never runs the adversarial probes.

Do not generalize this harness to a claim that gateway bytes are globally
non-executable or cannot be reused. The profile denies document embedding and
protects its own documents, not every external consumer.

## 6. Cache/history, evidence and cleanup

Inspect `no-store` on each response, including errors and HEAD, but do not equate
it with erased history. A manual fresh-load check does not prove eviction of
pre-existing caches or revocation of service workers. The automated cache-state
test is a small compliant-cache stub: public A → unlisted B (same blob/ETag,
different manifest/release) → new active release C → `getSite` null/404. It models
current metadata visibility to requests, not browser cache machinery,
authentication, private content or a revocation feature. Already loaded bodies,
service-worker caches and saved files are not erased by this profile.

After the assessment, stop both local servers, close the disposable browser and
remove only the temporary directory you recorded. Retain the report, browser
version, relevant screenshots/console diagnostics and sanitized network logs.
Do not publish credentials or unrelated browsing data. For rollout, fresh clean
content origins remain a mandatory operator assumption regardless of test results.

## Manual report template

Leave a row **not run** until actually observed. Use `pass`, `fail`, `inconclusive`
or `not run` with evidence and browser-specific notes; do not prefill success.
At minimum, record one complete browser/version result for any claimed manual
assessment. The template below is for *manual* runs and is intentionally left
blank; the automated record above is the only browser result this document
claims.

```text
Overall status: not run
Date/operator: not run
Server revision / profile: not run / sandboxed-web-v1
Browser name, full version/build, engine, OS: not run
Content origin and control/API topology: not run
Fresh origin/profile; cookies/cache/SW/extensions checked: not run
Fixture release ID / artifact digest / local modifications: not run
Controlled endpoint substitutions and logs (if any): not run
HTTP/header checks (not browser proof): not run
HTML inline/external/same-artifact script and handler denial: not run
DOM/global markers unchanged: not run
Inline CSS and data GIF rendered: not run
External CSS/import/image/font/media denial and diagnostics: not run
Base URL refusal: not run
Form submission refusal: not run
Object/frame resource denial: not run
Popup refusal: not run
Top/ancestor navigation evidence and limitations: not run
Self-navigation observation (not required to be blocked): not run
Sandbox download / optional direct-user-download distinction: not run
Direct SVG sandbox and marker results: not run
Direct MIME/attachment observations: not run
Separate-harness document-embedding refusal: not run
Separate-harness harmless JS/CSS reuse and MIME/nosniff controls: not run
Network evidence: not run (DNS absence alone is not proof)
Cache/history/SW limitations: not run
Evidence files and remaining gaps: not run
```
