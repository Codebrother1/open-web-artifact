# Control and content origins

This document describes the v0.4 reference-server boundary: an authenticated
**control origin** and a public, content-only **content origin**.

Until v0.4 the reference server could serve control routes and public artifacts
on one HTTP origin, and could select an artifact with `?site=<slug>`. That was
always documented as a prototype convenience. It is now one explicitly named
topology among two, and it is no longer what a production deployment should run.

Nothing about the artifact model changes here. Manifest schema, canonical JSON,
artifact digests, release identity, activation, bearer tokens, capability names
and `sandboxed-web-v1` are all untouched.

## Why two origins

`sandboxed-web-v1` is a *response* policy. It sets CSP, `nosniff`, framing and
caching headers on artifact responses. It cannot, on its own, stop a hostile
artifact from sharing a browser origin with your control API, because the browser
decides what "same origin" means from the URL, not from your headers.

When a hostile artifact and the control plane share an origin, headers do not
prevent:

- cookies scoped to that origin (or its parent domain) being sent to both;
- a service worker registered by artifact content taking scope over control paths;
- `fetch()`/XHR from artifact content reaching control endpoints as same-origin;
- one artifact selecting another artifact through a query parameter.

Origin topology is the control for those. Headers remain necessary, but they are
not sufficient, and this repository should not imply otherwise.

## Architecture

```
                     ┌──────────────────────────────┐
  operator / CLI ───▶│  CONTROL ORIGIN              │
  (bearer token)     │  control.example.com         │
                     │                              │
                     │  GET  /health                │
                     │  POST /v1/sites/:s/publish/plan
                     │  PUT  /v1/uploads/:digest    │
                     │  POST /v1/sites/:s/publish/commit
                     │  POST /v1/sites/:s/activate/:r
                     │  GET  /v1/sites/:s/releases  │
                     └──────────────┬───────────────┘
                                    │
                        shared blob + metadata stores
                                    │
                     ┌──────────────┴───────────────┐
  public browser ───▶│  CONTENT ORIGIN              │
  (no credentials)   │  <site>.sites.example-user…  │
                     │                              │
                     │  GET  /<artifact path>       │
                     │  HEAD /<artifact path>       │
                     │  (nothing else exists here)  │
                     └──────────────────────────────┘
```

Both listeners run in one process by default and share the same storage objects.
The boundary that matters is the HTTP origin and the route surface, not process
count. There is no duplicated business logic: both listeners call the same
internal dispatchers.

## Route matrix

| Route | Method | Control origin | Content origin |
| --- | --- | --- | --- |
| `/health` | GET | 200 | **404** |
| `/v1/sites/:site/publish/plan` | POST | auth: `plan` (+`upload` per grant) | **404** |
| `/v1/uploads/:digest` | PUT | auth: `upload` + signature | **404** |
| `/v1/sites/:site/publish/commit` | POST | auth: `commit` (+`activate` by default) | **404** |
| `/v1/sites/:site/activate/:release` | POST | auth: `activate` | **404** |
| `/v1/sites/:site/releases` | GET | auth: `read` | **404** |
| Any artifact path | GET/HEAD | **404** (serves no bytes) | public, Host-bound |
| Anything else | any | 404 | 404 |

Notes on the content origin's 404s:

- The content listener **allowlists** content behavior. It does not dispatch a
  control route and then reject it; the route does not exist there at all.
- `/v1/...` and `/health` are reserved: they return 404 even when the site has an
  SPA fallback. Without that rule an SPA site would answer `200` for
  `/v1/sites/x/releases`, which would look like a working control route and would
  mask the boundary. An artifact therefore cannot publish a file at `/health` or
  under `/v1/` and have it served. This is a deliberate, documented trade-off.
- Non-GET/HEAD requests return the same fixed `404`, not `405`. A `405` would
  disclose which methods the control plane implements.

## Host-to-site binding

Production content serving binds one request `Host` to exactly one site.
`?site=` is **not** a production routing mechanism and is inert on the content
origin.

Two configuration models are supported; at least one is required.

1. **Base domain (wildcard).** `OWA_CONTENT_BASE_DOMAIN=sites.example.invalid`
   binds `<site>.sites.example.invalid` to `<site>`.
2. **Explicit map.** `OWA_CONTENT_HOST_MAP={"docs.example.invalid":"docs"}` pins
   individual hosts. Checked before the base domain.

### Validation rules

The `Host` header is parsed strictly before any metadata key is derived from it:

- only printable ASCII; no whitespace, control bytes, or NUL;
- no `@`, `/`, `\`, `?`, `#`, `[`, `]` — userinfo, path, query, fragment and
  address-literal confusion are all rejected;
- at most one `:` port separator; the port must be 1–65535 with no leading zeros;
- the port is normalized away before matching, so `a.example:8443` and
  `a.example` bind identically;
- ASCII-lowercased (normal DNS normalization), so `A.EXAMPLE` binds as
  `a.example` rather than being treated as a different site;
- no empty labels, no leading/trailing hyphen, no trailing dot (`a.example.` does
  not alias `a.example`), no label over 63 bytes;
- non-ASCII is rejected outright rather than guessed at via IDNA, which would
  introduce homograph ambiguity.

Under the base-domain model the prefix must be **exactly one label** that is also
a valid site slug. `a.b.sites.example.invalid` does not resolve to site `a.b`.

A malformed `Host` returns a fixed `400` with code `OWA_CONTENT_HOST_MALFORMED`.
A well-formed `Host` bound to no site returns the ordinary `404`
`site or active release not found`, identical to a missing site — so probing
cannot distinguish "no such site" from "not configured". The received `Host` is
never echoed in a response body.

Ambiguous configuration fails at startup, not at request time: the same host
mapped twice, a host that collides with the wildcard base domain, or an invalid
slug all throw `OWA_AUTH_CONFIG`.

### Forwarded headers are not trusted

`X-Forwarded-Host`, `Forwarded`, `X-Forwarded-Server` and similar headers are
**never read** for site selection. Only the direct `Host` header selects a site.
A reverse proxy must therefore rewrite `Host` to the public hostname it is
serving. If your proxy preserves the client `Host` (the common default), no
change is needed.

This also means a client that can reach the content listener directly cannot use
a forwarded header to reach a different site.

## Content domain assumptions

Prefer separating the content origin from the control origin **by registrable
domain**, not merely by subdomain:

```
control.example.com                 # control origin
*.sites.exampleusercontent.com      # content origin  (preferred)
```

rather than:

```
control.example.com                 # control origin
*.sites.example.com                 # content origin  (weaker)
```

The reason is cookie scope. A cookie set with `Domain=example.com` is sent to
every subdomain of `example.com`, including `*.sites.example.com`. Putting
artifact content on a separate registrable domain keeps it outside that cookie
scope and outside the same-site boundary used by `SameSite` cookies. The OWA
reference server sets no cookies at all, but the deployment around it may.

### What host separation does and does not give you

It does help with:

- same-origin `fetch`/XHR from artifact content to control APIs;
- service-worker scope over control paths;
- one artifact reading another artifact's responses via a query selector.

It does **not** give you:

- protection from a malicious or misconfigured reverse proxy in front of both
  origins — such a proxy can rewrite `Host` and defeat the binding entirely;
- protection from browser state that already exists (cookies, storage, service
  workers) from a previous deployment on the same hostname; changing topology
  does not unregister a service worker a browser already holds, and you may need
  a distinct hostname to escape it;
- custom-domain ownership verification — not implemented in this issue;
- private or per-tenant artifacts — artifact content served here is public;
- a claim that the browser sandbox is perfect.

### TLS and proxy requirements

- Terminate TLS for both origins. Serve the content origin over HTTPS with a
  certificate valid for the wildcard or each pinned host.
- The proxy must pass the public hostname through as `Host`.
- Do not expose the control listener's dev mode through any proxy: tokenless dev
  mode is loopback-only and checks the actual socket address.
- Set `OWA_CONTENT_SCHEME=https` (the default) so canonical URLs match reality.

## Canonical public URL

Clients used to synthesize `"<control-origin>/?site=<slug>"`. They no longer do.

A successful **commit** response may now carry a `contentUrl` field:

```json
{
  "slug": "demo",
  "releaseId": "r_...",
  "artifactDigest": "sha256:...",
  "activeReleaseId": "r_...",
  "contentUrl": "https://demo.sites.example.invalid/"
}
```

The contract:

- **Server-produced.** Built from validated server configuration plus the
  already-authorized slug. No part of it comes from client input, request
  headers, or the request URL.
- **Named `contentUrl`**, not `url`, so it cannot be confused with an upload
  grant URL or with the control origin the client dialed.
- **Omitted entirely when no content origin is configured.** The field is absent
  rather than null or guessed. No content base means no URL — the server never
  fabricates an address that would not resolve.
- **Omitted when there is no single canonical host**, e.g. a slug pinned to two
  hosts in an explicit map.
- **Not artifact state.** It is not in the manifest, not in canonical JSON, not
  in the artifact digest, and not in the release record. Two servers with
  different content origins produce byte-identical manifests and identical
  digests for the same content.
- It points at the site's **active** content, which after an activating commit is
  the release you just created. With `activate: false` the site's active release
  is unchanged and the URL still refers to whatever is active.

### CLI

`artifact publish --server ...` prints `Public URL: <contentUrl>` when the server
supplies one, and prints no URL otherwise. The CLI never reconstructs host
mapping locally. It validates the value as a credential-free absolute `http(s)`
URL and discards anything else, so a compromised or misconfigured server cannot
make the CLI print a `javascript:` URL or one carrying credentials.

### MCP

The MCP `publish` result's `url` field is now the server's canonical content URL.
The adapter no longer synthesizes `/?site=`, holds no content-domain policy of
its own, and **omits `url` entirely** when the server provided none. `url` is
therefore optional in the published `publish` output schema.

## Configuration

| Variable | Applies to | Default | Meaning |
| --- | --- | --- | --- |
| `OWA_CONTENT_BASE_DOMAIN` | both | unset | Wildcard content base; `<site>.<domain>` binds `<site>`. Setting this (or the map) selects the separated topology. |
| `OWA_CONTENT_HOST_MAP` | both | unset | JSON object of explicit `host` → `slug` bindings. |
| `OWA_CONTENT_SCHEME` | canonical URL | `https` | Scheme used in `contentUrl`. `http` only for local development. |
| `OWA_CONTENT_PUBLIC_PORT` | canonical URL | unset | Public port in `contentUrl`. Omitted when it is the scheme default. |
| `OWA_CONTENT_LISTEN_PORT` | content listener | `7332` | Content listener port. |
| `OWA_CONTENT_LISTEN_HOST` | content listener | `HOST` or `127.0.0.1` | Content listener bind address. |
| `OWA_CONTROL_PORT` | control listener | `PORT` or `7331` | Control listener port. |
| `OWA_CONTROL_HOST` | control listener | `HOST` or `127.0.0.1` | Control listener bind address. |
| `PORT` / `HOST` | control listener | `7331` / `127.0.0.1` | Pre-v0.4 names, still honored. |

Existing `OWA_AUTH_*`, `OWA_STORAGE`, `OWA_S3_*`, `OWA_DATA_DIR` and
`OWA_PUBLIC_BASE_URL` variables are unchanged. `OWA_PUBLIC_BASE_URL` still
describes the **control** origin used to build local upload grant URLs; it is not
the content origin.

### Production example

```sh
export OWA_AUTH_SECRET="$(openssl rand -hex 32)"     # >= 32 UTF-8 bytes
export OWA_CONTENT_BASE_DOMAIN=sites.exampleusercontent.com
export OWA_CONTENT_SCHEME=https
export OWA_CONTROL_PORT=7331
export OWA_CONTENT_LISTEN_PORT=7332
node packages/server/src/index.js
```

Point `control.example.com` at 7331 and `*.sites.exampleusercontent.com` at 7332,
terminating TLS for both.

## Development

Local development has two supported shapes.

**Separated (recommended, matches production):**

```sh
export OWA_AUTH_SECRET="$(openssl rand -hex 32)"
export OWA_CONTENT_BASE_DOMAIN=localhost
export OWA_CONTENT_SCHEME=http
export OWA_CONTENT_PUBLIC_PORT=7332
node packages/server/src/index.js
```

`http://demo.localhost:7332/` serves site `demo`; the control API is on 7331 and
serves no content. Most systems resolve `*.localhost` to loopback; if yours does
not, add a hosts-file entry.

**Shared-origin prototype (legacy):** running with no content configuration keeps
the pre-v0.4 behavior — one origin, control plus content, with the `?site=` and
`.localhost` selectors live. This is retained for compatibility and for the
existing test corpus. It is **not** a production topology, and the process prints
a fixed warning on stderr at startup saying so. Production auth defaults are
unaffected: auth is still required by default and tokenless dev mode is still
loopback-only.

Insecure behavior is never selected automatically by omission of the *auth*
configuration; the shared-origin topology is selected by omission of the
*content* configuration, and it announces itself.

## Server API

| Factory | Serves | Requires |
| --- | --- | --- |
| `createControlServer({ blobs, metadata, auth, content? })` | control routes only | auth config (fails closed) |
| `createContentServer({ blobs, metadata, content })` | artifact GET/HEAD only | content config |
| `createArtifactServer({ blobs, metadata, auth })` | both, shared origin (legacy) | auth config |

`createArtifactServer` is unchanged and remains exported for compatibility.
Passing `content` to a control server enables `contentUrl` on commit responses;
it does not make that listener serve content.

## Migrating from `?site=` prototype URLs

1. Choose a content domain, preferably on a separate registrable domain.
2. Set `OWA_CONTENT_BASE_DOMAIN` (and `OWA_CONTENT_SCHEME`).
3. Point DNS and TLS for `*.<content-domain>` at the content listener.
4. Replace any stored `https://control.example.com/?site=demo` link with the
   `contentUrl` returned by commit, or with `https://demo.<content-domain>/`.
5. Re-publish or re-read a commit response to obtain canonical URLs; no artifact
   re-packing is needed, because artifact identity did not change.

Old `?site=` URLs keep working **only** on the legacy shared-origin server. They
do not work against a content origin, by design: that selector is exactly the
shared-origin behavior this boundary removes.

## What this does not solve

- Custom-domain ownership verification, DNS automation and certificate issuance.
- Private, authenticated, or per-tenant artifact access; content served here is
  public to anyone who can reach the origin.
- Tenant-private content-addressed storage.
- A malicious reverse proxy, or any attacker who can rewrite `Host` in transit.
- Pre-existing browser state on a reused hostname.
- Browser sandbox perfection; `sandboxed-web-v1` remains a response policy, and
  this boundary does not make it a substitute for browser-level isolation.
- Account isolation beyond the existing per-site capability scopes.
