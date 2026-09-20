# `sandboxed-web-v1`: static-preview host policy

## Status and scope

This named host response policy is separate from the [OWA v0.2 artifact
contract](spec-v0.2.md). Its [threat model](sandboxed-web-v1-threat-model.md) was
written before the standalone profile implementation. As of the 2026-09-20
composition onto merged auth main (`a6cbc08`), the reference gateway combines
this response policy with the separate [HTTP capability auth overlay](auth.md).
The key words MUST, MUST NOT, SHOULD and MAY in this document describe this
profile, not new manifest fields or publishing operations.

The profile is **static, deny-by-default and script-disabled**. It intentionally
breaks interactive applications and even same-artifact external assets. Inline
CSS and `data:` images are the only subresource allowances, to permit useful
static previews without script execution or network subresources. A future
interactive profile requires separate review and a different contract; hosts
MUST NOT silently add sandbox allow tokens or source allowances to this one.

This is not sanitization, authentication, authorization, malware detection, a
private-content feature, or a claim that the platform is fully secure. Artifact
bytes and manifest metadata MUST remain unchanged. In particular, the core
`mediaType` constraint remains a nonempty string, not a MIME parser. The profile
MUST NOT change artifact paths, canonical encoding, numeric rules, digests,
release identity, publishing or storage semantics.

## Exact HTTP response contract

Every application-generated response MUST carry these eight fields with these
values. This includes every artifact asset type, control/API JSON, health
responses, empty 204 responses, and application-generated 4xx/5xx responses,
including responses to GET and HEAD. They are not an HTML-only policy.

| Header | Exact value |
| --- | --- |
| `Content-Security-Policy` | The single policy below |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `X-Robots-Tag` | `noindex, nofollow, noarchive` |
| `Cache-Control` | `no-store` |
| `X-Frame-Options` | `DENY` |
| `X-DNS-Prefetch-Control` | `off` |
| `X-OWA-Security-Profile` | `sandboxed-web-v1` |

```text
sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'
```

The sandbox is bare: **no allow tokens**. There is no `allow-scripts`,
`allow-same-origin`, `allow-forms`, `allow-popups`, `allow-popups-to-escape-sandbox`,
`allow-top-navigation`, `allow-top-navigation-by-user-activation` or
`allow-downloads`. There is no `'self'`, network scheme, wildcard or `blob:`
source allowance. CSP MUST be an enforced HTTP response header, not a report-only
policy or an author-controlled meta tag. Inline style permission is not inline
script permission.

The reference [`securityHeaders()`](../packages/server/src/security-profile.js)
returns a fresh plain object with exactly these eight lowercase keys.
`artifactHeaders(mediaType)` returns a fresh object containing those fields plus
`content-type` and `content-disposition`, selected below. Hosts in other languages
need not import JavaScript: this document is the independent wire contract.
HTTP header names are case-insensitive. Ordinary framing headers may be added;
they do not replace these policy fields.

The reference server installs the baseline before route dispatch, auth checks
and its error handler. Auth failures retain the profile headers, `no-store` and,
for 401, the existing `WWW-Authenticate: Bearer realm="owa"` challenge. Asset GET
and HEAD share status, type, disposition, length and ETag;
HEAD has no response body. Its current GET `/health` is **200 JSON**, while a
successful local signed PUT upload is **204**. This does not introduce a HEAD
health/control endpoint or change baseline method routing. Parser-level failures
before the application handler, proxy-generated responses and responses served
directly by an object store are not proven by application tests; operators must
assess those delivery paths separately and preserve policy on content delivery.

## MIME metadata and disposition

For an artifact response, the host MUST inspect only the complete manifest
`mediaType` string, not its filename extension or blob contents. This is response
selection, not additional manifest validation.

### Whole-string ASCII grammar

Accept syntax only when the entire string matches this grammar and the additional
conditions below. `SP` is U+0020, `DQUOTE` is U+0022, and `BACKSLASH` is U+005C.
`*` means zero or more repetitions and `1*` means one or more.

```text
media-type = token "/" token *( *SP ";" *SP token "=" value )
token      = 1*tchar
value      = token / DQUOTE *( qchar / quoted-pair ) DQUOTE
quoted-pair = BACKSLASH printable-ascii
printable-ascii = U+0020 through U+007E
qchar      = printable-ascii except DQUOTE and BACKSLASH
```

`tchar` is ASCII `A-Z`, `a-z`, `0-9`, or one of the following characters:

```text
! # $ % & ' * + - . ^ _ ` | ~
```

All of these conditions are mandatory:

1. The input is a nonempty string. Do not coerce other values to strings.
2. Every character is printable ASCII U+0020–U+007E. Reject all controls,
   including TAB, CR, LF, NUL and DEL, and all non-ASCII characters, including
   inside quoted strings or after a backslash.
3. Reject leading or trailing SP on the entire string. Do not trim or repair it.
   SP is allowed only at the grammar positions above or within quoted values;
   spaces MAY surround semicolons but MUST NOT surround the slash or the `=`
   separating a parameter name and value. Spaces and `=` inside quotes are literal
   value characters. A space immediately before a closing quote is valid quoted
   content, not trailing whitespace on the whole string.
4. Both type and subtype, all parameter names, and unquoted parameter values
   must be nonempty tokens. Empty quoted values (`note=""`) are allowed. A quoted
   backslash must escape exactly one printable ASCII character; it may escape
   a quote, backslash, space, semicolon, or any other printable ASCII character.
5. Parameter names MUST be unique under ASCII case-insensitive comparison.
   `charset=x; CHARSET=y` is invalid, even if values agree. Semicolons and apparent
   parameter names inside quotes are just value characters.
6. Consume the whole string. Reject missing `=`, dangling semicolons, unfinished
   quotes/escapes, comments, comma-separated MIME lists, or trailing junk. A valid
   prefix alone is insufficient.

Lowercase only the parsed `type/subtype` essence for allowlist comparison.
Parameter values are syntactically checked, not interpreted as permission or
content validation. If syntax is valid and the essence is approved, the response
MUST preserve the **entire original mediaType value**, including its case,
spacing, quotes and parameters, as `Content-Type`.

The **15 and only 15** approved essences are:

```text
text/html
text/plain
text/javascript
application/javascript
text/css
application/json
application/wasm
image/svg+xml
image/png
image/jpeg
image/gif
image/webp
image/avif
image/x-icon
image/vnd.microsoft.icon
```

For a valid approved essence, emit `Content-Disposition: inline`. Otherwise,
including invalid syntax or an unknown essence, emit exactly:

```text
Content-Type: application/octet-stream
Content-Disposition: attachment
```

No filename or `filename*` parameter is added. This fallback includes an explicit
`application/octet-stream`, PDF, XML (`application/xml` and `text/xml`), XHTML,
CSV, fonts, audio/video, archives, unlisted image formats and vendor `+json`
types. There are no wildcard, family or suffix allowances. An approved-looking
extension does not change the outcome. Do not sniff, sanitize, transcode or
rewrite bytes to fit the declared type.

For example, `Text/HTML; Charset="utf-8"` is preserved and inline;
`text/plain  ; note="a;b = c" ; charset=utf-8` is also preserved, including spaces
around semicolons and spaces/`=` inside the quoted value. In contrast,
`text/html; charset =utf-8`, `text/html; charset= utf-8`,
`text/html; CHARSET = "Utf-8"`, and the formerly accepted
`text/plain; note="a;b"; charset = utf-8` all fall back to octet-stream attachment.
This strict separator rule avoids accepting spacing that a browser MIME parser
may ignore rather than interpreting as the intended parameter; it is not a claim
of measured browser behavior. ` text/html`, `text/html; charset=`,
`text/html; charset=x; CHARSET=x`, a value containing TAB, and
`text/html; note="ok"junk` also fall back. A valid
`application/pdf; name="index.html"` still falls back with no filename.

### Resource behavior in a compliant browser

"Inline" is a disposition, not permission to execute. All rows receive the same
eight policy headers, including when fetched directly.

| Resource | Direct response | Use from a protected document |
| --- | --- | --- |
| HTML | Approved MIME, inline, sandboxed static document | No inline/external scripts or handlers; embedded HTML frames are blocked |
| JavaScript (both approved essences) | Original MIME and bytes, inline | All script execution is denied, including inline, external, modules and same-artifact scripts |
| CSS | Original MIME and bytes, inline | External stylesheets, including same-artifact CSS and `@import`, are blocked; inline `<style>` and style attributes are allowed |
| JSON / plain text | Original MIME and bytes, inline | Not executable HTML by permission of this profile; script-driven fetches are unavailable and `connect-src` denies connections |
| SVG | Original MIME and bytes, inline; direct SVG documents receive the full sandbox/CSP | SVG scripts, handlers and external subresources are denied; a network SVG image URL is also blocked by `img-src data:` |
| Approved raster images / icons | Original MIME and bytes, inline; decoder behavior is browser-specific | Network images, including same-artifact images, are blocked; `data:` images are allowed |
| WASM | `application/wasm` (with any accepted parameters), inline | No script execution or worker permission to fetch/instantiate it; this is not a WASM execution profile |
| Unknown, invalid or unapproved type | Octet-stream attachment, no filename | Not promoted to active content; sandbox-initiated downloads have no allowance |

A CSP header on a **JavaScript or CSS resource does not impose that policy on a
different consuming page**. An unprotected external consumer may execute a
correctly typed script or apply a stylesheet from this gateway according to its
own policy and browser rules. `frame-ancestors`/X-Frame-Options concern document
embedding, not a universal ban on image, script or stylesheet reuse. This profile
is not a global quarantine for the bytes.

`nosniff` and deliberate MIME dispatch mitigate MIME confusion; they are not
antivirus, byte validation or a guarantee of identical behavior in every browser.
An invalid image may fail to decode. A downloaded file opened elsewhere is outside
this response's protection. Initiating a download from the sandbox is not allowed
by the profile; a separate direct user navigation/download via browser UI may
still be possible, with browser-specific behavior.

## Browser capabilities and navigation limits

Protected documents have an **opaque origin** because there is no
`allow-same-origin`, and cannot execute scripts. Web Storage, cookie DOM access
and service-worker registration are not usable by artifact script under these
restrictions; the opaque origin is an additional barrier to origin-bound APIs.
This MUST NOT be described as removing incoming or outgoing HTTP cookies.
Sandboxing does not rewrite the URL, create isolated cookie jars, strip request
credentials or remove API routes. The prototype does not set response cookies or
add CORS permissions; that is not a cookie-stripping guarantee for the deployment.

External/network CSS, images, fonts, media, connections, workers, objects and
frames are denied. `form-action 'none'` and the lack of `allow-forms` prevent form
submission. Popups and top-navigation permissions are not granted. `base-uri
'none'` blocks author base URLs. Frame embedding is denied by `frame-ancestors
'none'` and `X-Frame-Options: DENY`.

This is **not a network air gap**. Ordinary self-targeted links/navigation may
leave the gateway, and the profile does not follow the destination. Passive or
navigation mechanisms, including meta refresh, are not comprehensively
quarantined by a subresource policy. No unsupported `navigate-to` directive is
claimed. DNS-prefetch disabling is defense in depth, not a universal guarantee
about speculative browser/network traffic. A blocked script containing
`top.location` is evidence of script blocking, not independent proof that every
possible navigation is blocked. Static content may still deceive users or consume
resources; users should not enter secrets into untrusted content.

## Indexing, caching and mutable state

`X-Robots-Tag: noindex, nofollow, noarchive` MUST be sent for **all** application
responses in both `public` and `unlisted` states. It is advisory crawler behavior,
not authorization, secret URLs, search-result removal or revocation of archived
copies. Unlisted artifacts remain accessible to anyone with their URLs.

`Cache-Control: no-store` MUST apply to all application responses: HTML, every
asset, HEAD, control JSON, health, 204 and errors. Hosts MUST NOT emit `immutable`
or a 304 shortcut for this profile. The reference gateway ignores conditional
cache validators for serving: it rechecks metadata and returns the current
representation or error. Successful assets retain an ETag of the quoted blob
digest (for example, `"sha256:..."`). That ETag is byte identity, **not cached
authorization or permission to reuse a prior response**.

An immutable blob hash or release does not make an active-site URL immutable.
That URL aliases a mutable active release. Different manifests/releases can share
the same bytes and ETag while differing in visibility or other metadata. A host
MUST NOT use shared blob identity to bypass current site/release decisions.

The cache regression uses a deliberately minimal compliant-cache stub, not a
browser or an authentication system. It observes public release A, then unlisted
release B with identical bytes/ETag but a different immutable manifest and
release, then a new active release C with different bytes, then `getSite` returning
null and a 404. Conditional GET/HEAD requests still reach current metadata; no
success/error is retained by the stub and no immutable release is rewritten.
Both public and unlisted remain readable. The final null lookup is a test
availability decision, not an implemented private/auth feature.

No-store cannot revoke pre-existing browser or service-worker caches, erase
already loaded bodies, retract downloaded copies or force noncompliant clients
to obey. A pre-existing service worker may intercept a navigation before the
new response policy arrives. **Clean, fresh content origins and browser state
are mandatory operator assumptions for rollout**, not a cleanup feature supplied
by these headers.

## Origin topology: required deployment versus prototype

A fully conformant production deployment of this profile **MUST use clean,
content-only, one-site origins on a cookieless domain**, separate from
control/admin/API origins. Use a separate registrable content domain from
credential-bearing services; do not put parent-domain secrets/cookies on content
hosts. Operators MUST ensure the edge preserves the response policy and that
older service workers/caches cannot substitute unprotected content. These are
deployment requirements, not capabilities enforced by the current prototype.

`http://a.localhost:7331` and `http://b.localhost:7331` have different URL origins
(the hostname differs). This alone does not establish independent cookie jars
or all browser "site" boundaries. The prototype also accepts `?site=a` and
`?site=b` on the **same** origin, and dispatches control/API routes on **every**
host before artifact routing. Those routes have the separate auth overlay's
capability and identifier checks; they are not removed from content hosts.
Artifact GET/HEAD and health remain public. `.localhost` host selection takes
precedence over the query selector. Neither the CSP nor the profile marker
disables those routes. Do not describe the reference development server as
enforcing content/control separation or production multi-tenant isolation.

The minimum future architectural work is explicit Host-to-site binding, a
content-only listener/origin separated from control/admin/API listeners, and
removal of the shared-origin `?site=` selector on content delivery. This profile
documents that requirement; composing it with the existing auth overlay does
**not** implement host management or a new routing architecture.

## Raw HTTP request targets and the unchanged resolver

For gateway artifact resolution, preserve the received request target before
WHATWG URL normalization. The reference HTTP adapter rejects a target not starting
with `/` (including absolute-form and asterisk-form targets), and rejects any
literal `#`, including after a query, with application JSON 400 and the baseline
headers. It splits at the first **literal** `?` to obtain the raw path. Encoded
`%3F` and `%23` remain path data until the resolver's decoding pass; they are not
query/fragment delimiters. Repeated leading slashes remain resolver input, not a
new artifact host selector.

Before an artifact-serving metadata lookup, the selected site value MUST satisfy
the existing auth `isSiteScope` grammar: 1–63 characters, starting with a lowercase
ASCII letter or digit, followed only by lowercase ASCII letters, digits, `_` or
`-` (`[a-z0-9][a-z0-9_-]{0,62}`, whole string). Uppercase, Unicode, separators,
controls and literal percent-looking names are rejected, not repaired. Invalid
selectors return 404 with the profile headers before the metadata store is called.
Apply this check to the selected Host/query value with no additional decoding:
query parameters have already been decoded once. Thus `?site=%61` selects `a`,
but `?site=%2561` is rejected rather than decoded a second time. This host scope
rule is distinct from the unchanged artifact-path grammar; it is not a new
manifest field or private-artifact access control.

The adapter passes the raw artifact path to the **unchanged** core `resolveRequestPath`.
The [v0.2 algorithm](spec-v0.2.md#safe-request-path-resolution) still performs one
strict UTF-8 percent-decoding pass, rejects backslash, NUL and `..` segments before
SPA fallback, and then performs its existing safe normalization and lookup.
Unsafe or malformed artifact paths return no file (HTTP 404), including with SPA
fallback. `/a%3Fb%23c.txt` can address literal artifact path `/a?b#c.txt`;
`/%252e%252e/secret` can address literal `/%2e%2e/secret`, not traverse a parent.

**Control routing retains the baseline WHATWG-parsed pathname.** For example,
GET `/discard/../health` still dispatches to GET `/health`. Publish, upload,
activate and release-list route dispatch is not replaced with a raw-path
publishing protocol. The raw-path hook applies to gateway artifact resolution;
it is not a claim that every control-route alias is newly rejected. The composed
control plane already validates decoded site scopes against `isSiteScope` and
activation release IDs against `r_` plus 20 lowercase hexadecimal digits, and
requires the [auth overlay's capabilities](auth.md#capability-matrix) before
protected storage work. Encoded slashes and percent-looking scopes fail the site
grammar, rather than reaching metadata as unconstrained selectors. Required auth
remains the default; tokenless control access is only explicit direct-loopback
dev mode. Content-only origin separation is still future architectural work.

Storage/metadata remains trusted. The composed gateway checks returned site
records for the requested slug and `s_` plus 20 lowercase hexadecimal digits,
and active release IDs before retrieval. These checks do not undo a malicious
index's internal lookup or validate all stored manifest/blob metadata; tampered
storage is not made safe. Valid manifest publication already rejects malformed
blob digests. No storage redesign is hidden in this profile.

The 44 published portable request vectors remain unchanged and are replayed as
**direct resolver arguments**, not as full HTTP targets. Direct arguments do not
strip query/fragment characters; the HTTP adapter's delimiter split is a separate
layer. A browser, client or upstream proxy may remove traversal segments before
transmitting the request. The gateway cannot reconstruct bytes it never received;
raw HTTP tests must avoid client-side URL normalization.

## Evidence and limitations

- [`security-profile.test.js`](../packages/conformance/src/security-profile.test.js)
  checks exact headers/CSP, fresh helper objects, all approved essences, complete
  ASCII grammar, rejection/fallback, and unchanged metadata/canonical/blob identity.
- [`security-gateway.test.js`](../packages/conformance/src/security-gateway.test.js)
  checks loopback raw HTTP, adversarial MIME and bytes, GET/HEAD asset/error parity,
  raw paths with/without SPA, the 44 direct resolver vectors, control/health/upload
  responses, no-store state transitions and stored-byte preservation. It does not
  evaluate fixture scripts, render documents or contact probe destinations.
- [`security-fixtures/sandboxed-web-v1.json`](security-fixtures/sandboxed-web-v1.json)
  is a separate security-probe format, not a replacement for the portable corpus.
- [Optional browser validation](sandboxed-web-v1-browser-validation.md) records
  browser/version and observations separately. Header assertions are not browser
  enforcement proof. No browser automation or mandatory Playwright dependency is
  implemented; the manual report starts **not run**.

The threat model's [standards references](sandboxed-web-v1-threat-model.md#evidence-requirements)
cover CSP, HTML sandboxing, MIME sniffing, HTTP no-store and service workers.
Browser vulnerabilities, extensions, compromised hosts, phishing, resource abuse,
previously stored content and deployment isolation need separate assessment.
