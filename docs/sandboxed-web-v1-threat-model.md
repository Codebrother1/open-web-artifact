# sandboxed-web-v1: threat model before implementation

This threat model was recorded before the standalone profile implementation.
The target is an untrusted, agent-generated static HTML document and its stored
assets, not a server-side application or an authenticated private-content system.
The author can choose every byte, path and manifest media type, including
misleading types, malicious markup, CSS, JavaScript, SVG and links. The host
controls HTTP response policy and storage access; the browser is expected to
enforce CSP and sandboxing.

**Composition note (2026-09-20):** the profile is now composed onto merged auth
main (`a6cbc08`). The separate [HTTP capability auth overlay](auth.md) protects
control routes; artifact GET/HEAD and health remain public. This note updates the
current deployment assumptions, not the chronology of the initial threat model
or a claim that auth design preceded the standalone profile.

## Trust and deployment boundaries

- Trust the host, its metadata/storage, the TLS connection/edge, and a modern
  conforming browser. The artifact author is untrusted. This does not address
  browser parser/decoder vulnerabilities, malicious extensions or a compromised
  host. No attacker-supplied code is executed on the server. The composed control
  plane also relies on [auth's operator/key/clock assumptions](auth.md#limits-and-trust-boundary);
  identifier checks do not make pre-existing malicious metadata trustworthy.
- Use a fresh, cookieless content origin for each site and a separate
  control-plane/admin/API origin, preferably on a separate registrable domain.
  Do not set parent-domain credentials on content hosts. One site per hostname
  gives URL-origin separation, not automatically separate cookie/site boundaries.
- The current reference gateway does NOT enforce this deployment topology.
  `a.localhost` and `b.localhost` are distinct URL origins, but the `?site=` fallback
  multiplexes sites on one origin and control routes exist on every host. Those
  routes are now auth-protected and identifier-checked, not absent from content
  hosts. This is a prototype/development convenience, not an isolation guarantee.
- Bare CSP `sandbox` gives protected documents an opaque origin. It does not
  rewrite the request URL, strip incoming cookies, create cookie jars, make all
  requests credential-free, or remove APIs from an origin. Headers cannot repair
  a previously installed service worker intercepting navigation before the
  response arrives. Use a clean origin/browser state for rollout.

## Threats, intended controls, and honest limits

| Threat | Intended profile control | Residual risk / boundary |
| --- | --- | --- |
| Untrusted HTML | HTTP-enforced CSP with a bare sandbox and restrictive sources. Bytes remain untouched. | Static content can still deceive users, imitate trusted UI, consume resources or contain harmful links. This is not sanitization. |
| Untrusted JavaScript, inline handlers, external scripts and WASM use | No `allow-scripts`; `script-src 'none'`; no workers or connection APIs. No script executes in a compliant protected document. | Serving a JS file with CSP does not forbid a different, unprotected document from executing that file. No global execution quarantine is claimed. |
| Same-site and cross-site data access | Opaque document origin, no `allow-same-origin`, no scripts, frames or network subresources. | Not authentication, private storage or cookie isolation. Public artifact URLs remain public. Explicit content/control deployment separation is still required. |
| Top-level navigation / escape | No sandbox top-navigation permissions; no scripts; forms/popups blocked. | Do NOT claim all navigation is blocked. Ordinary self-targeted links may leave the gateway; policy does not follow the destination. No unsupported `navigate-to` promise. |
| Popup creation | No `allow-popups` or escape tokens; script execution denied. | Browser UI/manual navigation and implementation differences are outside this guarantee. |
| Form submission | `form-action 'none'` plus sandbox without `allow-forms`. | Users can still type into deceptive controls; do not enter secrets in untrusted documents. |
| Object/embed/plugin content | `object-src 'none'`, default deny, no sandbox permissions. | Not a guarantee against browser vulnerabilities. |
| Frames, embedding and clickjacking | `frame-src 'none'`; `frame-ancestors 'none'`; `X-Frame-Options: DENY`. | Image/stylesheet reuse by another page is different from frame embedding; CSP on a subresource is not the consuming document's policy. |
| Base-tag abuse | `base-uri 'none'`. | Literal absolute links can still exist. |
| Outbound network exfiltration | `default-src 'none'`, `connect-src 'none'`, no script/worker/media/font/frame sources; only inline CSS and `data:` images allowed. DNS prefetch disabled as defense in depth. | Not a network air gap: self-navigation, browser/network mechanisms, and nonconforming clients remain. No universal prohibition on all speculative browser traffic is claimed. |
| MIME confusion | Dispatch using validated manifest MIME metadata, not filename extension; unrecognized or unsafe values fall back to octet-stream attachment. SVG gets full document policy too. | No byte sniffing or content sanitization. Valid image/other decoders remain browser attack surface. Downloaded files opened elsewhere lose this response's protections. |
| MIME sniffing | `X-Content-Type-Options: nosniff` and deliberate Content-Type. | Nosniff is not an antivirus or a guarantee that every browser treats every MIME identically. |
| Path traversal / encoded traversal | Preserve received raw pathname for the existing decode-once resolver; reject malformed escapes and `..` before fallback. No filesystem path is constructed from an artifact path. | A client/proxy may normalize before transmission; the server cannot recover removed segments. The existing core routing/portable fixtures remain authoritative and unchanged. |
| Indexing/search exposure | HTTP `X-Robots-Tag: noindex, nofollow, noarchive` on every application response, including public artifacts. | Advisory only; malicious crawlers and already-indexed/saved material are not revoked. Unlisted is not authorization. |
| Stale cached authorization, visibility or activation state | `Cache-Control: no-store` on all application responses, including HTML/assets, HEAD, control responses and errors. Do not issue cacheable 304s. | Cannot erase pre-existing cache entries, already loaded documents, saved copies, service-worker caches or force noncompliant caches to obey. The profile does not add auth decisions. |

## Initial contract decision

`sandboxed-web-v1` is deliberately **script-disabled**. Inline styles and `data:`
images are the only subresource allowances; even same-artifact external scripts,
stylesheets and network image URLs are blocked from a protected document. This
is a static-preview policy, not a fully functional web-app profile. Assets can
still be fetched directly with correct MIME/security headers; their bytes and
artifact identity are unchanged. A future interactive profile needs a separate
review, not silent additions to this profile's allow tokens or source lists.

No `allow-same-origin`, `allow-scripts`, `allow-forms`, `allow-popups`,
`allow-top-navigation`, or `allow-downloads` token is added. Every response uses
the same conservative no-store/indexing baseline; mutable active-site URLs do not
become immutable cache keys merely because their underlying blobs are hashed.

The minimum future architectural change for stronger isolation is a content-only
listener/origin with an explicit host-to-site binding and no shared-origin query
selector, separate from control/admin APIs. This profile documents that proposal;
it does not implement origin management or a new routing model. The separately
merged auth overlay protects the existing control plane, not private artifact
retrieval or this proposed content-only topology.

## Evidence requirements

Deterministic tests can establish exact response headers, type dispatch,
GET/HEAD parity, raw-path handling, cache directives and byte/digest preservation.
They cannot prove browser enforcement by inspecting header strings. Optional
browser validation must be reported separately with browser/version and observed
results; absent such execution, the PR must say it was not performed. No browser
dependency is required in the normal suite.

Standards: [CSP Level 3](https://www.w3.org/TR/CSP3/),
[HTML sandboxing](https://html.spec.whatwg.org/multipage/browsers.html#sandboxing),
[MIME Sniffing](https://mimesniff.spec.whatwg.org/),
[HTTP caching](https://httpwg.org/specs/rfc9111.html#cache-response-directive.no-store),
[Service Workers](https://www.w3.org/TR/service-workers/).
