# Open Web Artifact (OWA)

An experimental open specification and reference implementation for **portable, immutable web artifacts**.

The thesis: an AI agent, CLI, CI job, or application should be able to produce one web artifact that can be stored, moved, signed, and served by different hosts without adopting each host's private deployment model.

## Status

| | |
| --- | --- |
| **Software / reference implementation** | **v0.4.0** — experimental; see [CHANGELOG](CHANGELOG.md) and the [release checklist](docs/release.md) |
| **Specification** | **v0.2 draft** ([docs/spec-v0.2.md](docs/spec-v0.2.md)); manifest `specVersion` **`owa.dev/v1`**, media type `application/vnd.openwebartifact.site.v1+json` |
| **Runtime** | Node.js **22+** |
| **CI** | **10 checks**, all secretless: Linux/macOS/Windows × Node 22/24, real MinIO, Chromium/Firefox/WebKit, real ORAS + Zot, and the independent Go conformance runner ([docs/ci.md](docs/ci.md)) |
| **Conformance** | portable corpus independently implemented in **JavaScript** (reference) and **Go** ([docs/independent-implementation.md](docs/independent-implementation.md)) |
| **Distribution** | source / reference implementation; every repository package is private, nothing is published to npm |

The software version and the protocol version are separate domains: v0.4.0
implements the v0.2 protocol draft, and the protocol itself is not "v0.4".
"v0.4" elsewhere in these docs (for example the content-only origin topology)
refers to the reference software. This is **not yet a production multi-tenant
hosting service** — see [Security / production status](#security--production-status).

## What the reference implementation proves

- content-addressed files using SHA-256 and deterministic canonical manifest identity, with an immutable published test vector, a portable multi-operation conformance corpus and a seeded property suite
- deterministic, locale-independent directory packing: `manifest.files` ordered by Unicode code-point order of complete artifact paths, proven on Linux, macOS and Windows
- immutable releases, blob deduplication, a mutable site -> active release pointer, and rollback without re-upload
- two-phase `plan -> direct upload -> commit` HTTP publishing with commit-boundary integrity: a release is persisted only after every unique blob is verified against its manifest SHA-256 **and** size
- local signed upload URLs for the filesystem backend; S3 Signature V4 presigned uploads for R2/S3-compatible storage with a mediated-by-default / explicitly-enforced direct-upload trust model
- filesystem and S3-compatible blob-store adapters; live Cloudflare R2 evidence (operator-run) and a real MinIO integration lane in CI
- conservative mark/sweep blob GC with publish leases protecting in-flight publishes
- required-by-default, site- and capability-scoped HTTP bearer authentication; the `sandboxed-web-v1` static-preview response profile; a content/control origin split
- real-browser enforcement evidence for `sandboxed-web-v1` in Chromium, Firefox and WebKit
- OCI image-layout export/import using the OWA manifest as artifact metadata, with the registry round-trip continuously verified with ORAS v1.3.4 against a real Zot v2.1.21 registry, including duplicate-content file entries
- an HTTP serving gateway, local and remote CLI workflows, and optional local stdio MCP tools as a thin client over the same HTTP protocol
- conformance tests including the published AWS SigV4 test vector, and ten secretless GitHub Actions checks
- portable conformance independently implemented in JavaScript and Go: a standard-library-only Go runner derives the same canonical bytes, digests, validation categories, request resolutions, pack results and OCI-layout results from the published spec and static corpus alone, with a shared static anchor and no call between the two implementations ([docs/independent-implementation.md](docs/independent-implementation.md))

The core, HTTP server, and CLI use Node.js built-ins and have **zero third-party
runtime dependencies**. The separately installed, optional MCP adapter adds three
third-party runtime packages: `@modelcontextprotocol/server@2.0.0`,
`@modelcontextprotocol/core@2.0.0`, and `zod@4.6.5`. Its official SDK client is a
dev-only test dependency. See the [MCP guide](docs/mcp.md) for the locked dependency
boundary and installation.

## Core architecture

```text
Agent / CLI / CI
       |
       |  canonical OWA manifest
       v
 +--------------------+
 |  artifact control  |
 |       plane        |
 |                    |
 | plan / commit      |
 | releases / activate|
 +---------+----------+
           |
           | presigned PUT instructions
           v
 +--------------------+
 | content-addressed  |
 |    blob storage    |
 |                    |
 | filesystem / S3    |
 +---------+----------+
           |
           v
      HTTP gateway

Same OWA artifact
       |
       +------> OCI image layout ------> ORAS ------> OCI registry
```

The important separation is that **file bytes do not need to pass through the artifact control plane**. With an S3-compatible backend, `artifactd` returns presigned PUT URLs and the publisher uploads directly to object storage.

## Quick start: local mode

Requires Node.js 22+. This is **explicit local development**, not a deployment
configuration. The local CLI uses host filesystem permissions, outside HTTP auth;
`npm run dev:server` opts into tokenless, direct-loopback-only HTTP operations.
It always binds `127.0.0.1`, regardless of `HOST`. Never expose dev mode through a
proxy or use it in production.

```bash
npm test

mkdir -p demo
printf '<h1>Hello OWA</h1>' > demo/index.html

npm run artifact -- publish demo --site hello
npm run dev:server
```

Open:

```text
http://hello.localhost:7331/
```

That single-origin server is the **prototype** topology: control routes and
artifact content share one origin and `?site=` selects a site. For the separated
production boundary, configure a content origin and the server runs a control
listener plus a content-only listener:

```bash
export OWA_AUTH_SECRET="$(openssl rand -hex 32)"
export OWA_CONTENT_BASE_DOMAIN=localhost
export OWA_CONTENT_SCHEME=http
export OWA_CONTENT_PUBLIC_PORT=7332
node packages/server/src/index.js
```

Artifacts are then served only from `http://hello.localhost:7332/`, bound to one
site per `Host`, with no control route and no `?site=` selector; the control API
stays on 7331 and serves no artifact bytes. A successful commit returns the
canonical `contentUrl`, which the CLI and MCP adapter surface instead of building
a URL themselves. See [control and content origins](docs/origins.md).

Publish another version and roll back without uploading the old version again:

```bash
printf '<h1>Version 2</h1>' > demo/index.html
npm run artifact -- publish demo --site hello
npm run artifact -- releases --site hello
npm run artifact -- activate <release-id> --site hello
```

## Remote two-phase publishing

For the local development server above:

```bash
npm run artifact -- publish demo \
  --site hello \
  --server http://localhost:7331
```

The client performs:

```text
1. pack directory + hash files
2. POST /v1/sites/<site>/publish/plan
3. upload only missing blobs using returned PUT URLs
4. POST /v1/sites/<site>/publish/commit with manifest/digest (not file bytes)
5. server verifies all blobs exist and creates an immutable release
```

Publishing the identical directory again should upload **zero** blobs. Commit
still activates by default. Remote `--no-activate` sends literal `activate: false`
and preserves the existing active pointer.

### Authenticated deployment workflow

`npm start` and `node packages/server/src/index.js` default to required auth, even
when no auth environment variables are set. Missing or short `OWA_AUTH_SECRET`
fails startup before storage/listening; it never silently enables dev mode.

Have your approved secret manager inject `OWA_AUTH_SECRET` into the server
process. It must be at least 32 UTF-8 bytes; use a high-entropy key generated from
at least 32 random bytes, unique to this deployment. Then, behind a trusted TLS
edge:

```bash
export OWA_AUTH_MODE=required
export OWA_PUBLIC_BASE_URL=https://artifacts.example.com
npm start
```

The listener defaults to `HOST=127.0.0.1` in required mode too. Set `HOST` only as
needed for a protected backend reachable by the trusted TLS edge. Set
`OWA_PUBLIC_BASE_URL` to that edge's public origin so filesystem upload grants
use the same HTTPS origin as the CLI; forwarding headers are not used to derive
it. TLS and secret-safe proxy logging are operator responsibilities.

Operators create short-lived tokens with the `createToken` library, not an HTTP
mint endpoint or CLI mint command. See [the auth guide](docs/auth.md) for an
in-memory creation example, exact wire format, capability matrix, and deployment
limits. Provision a token for site `hello` with `plan`, `upload`, and `commit`
through approved secret injection as `OWA_TOKEN` in the publisher process; do
not put tokens in command arguments, plaintext files, URLs, or terminal output.
Then run:

```bash
npm run artifact -- publish demo \
  --site hello \
  --server https://artifacts.example.com \
  --no-activate
```

Omit `--no-activate` only with an additional `activate` capability. A token with
literally only `commit` cannot run the CLI's plan/upload workflow. Release listing
requires `read`; explicit activation requires `activate`. The client sends OWA
credentials only to control requests and validated, marked same-origin filesystem
uploads, never to ordinary S3/R2 presigned uploads (even same-origin ones).

This auth layer adds HTTP authorization checks, local upload-grant fields, and
safe error codes. It does **not** change the manifest schema, artifact identity,
immutable release format, or direct-to-object-storage publishing model.

## Optional local MCP adapter

A local MCP client can use `publish`, `list_releases`, `activate`, and `rollback`
over stdio. The adapter uses the same HTTP plan/upload/commit lifecycle and bearer
authentication as the CLI; the HTTP server stays authoritative. It opens no HTTP
listener and introduces no OAuth flow or token minting. Rollback activates an
explicitly supplied release ID, without an implicit list/read request.

Requires Node.js 22+. Install separately from the repository root:

```bash
npm --prefix packages/mcp ci --ignore-scripts
```

For runtime-only installation, add `--omit=dev`. Configure the client to launch
`node /absolute/repo/packages/mcp/src/index.js` directly, not an npm script that
prints a banner to protocol stdout. Set `OWA_MCP_SERVER` to one trusted origin
and `OWA_MCP_ROOT` to an existing absolute, trusted read-only staging directory.
The client/launcher must explicitly forward `OWA_TOKEN` through approved secret
injection for required-auth servers; never put a token in tool arguments or
client config files, and never give the adapter the server's `OWA_AUTH_SECRET`.

Every tool call requires a `server` argument matching the pinned origin before
packing/network access. Publishing defaults to activation; `activate: false`
stages without changing the active pointer. MCP results contain validated
metadata, not file bytes, full manifests, or upload grants. The staging boundary
is not a race-proof filesystem sandbox, and origin pinning is not a DNS/egress
sandbox or per-site hosting isolation.

Read the [MCP setup, exact schemas, capability matrix, and security limits](docs/mcp.md)
and the [machine-readable tool schemas](packages/mcp/tool-schemas.json).
Run the optional suite with `npm run test:mcp` after the full MCP install; `npm test`
remains the independent root suite and does not require the SDK.

## S3 / Cloudflare R2 backend

Configure `artifactd` with environment variables. The following is a local dev
example; inject storage credentials using your secret manager. For a deployment,
use the required-auth/TLS setup above and `npm start`, not `dev:server`.

```bash
export OWA_STORAGE=s3
export OWA_S3_ENDPOINT='https://<account-id>.r2.cloudflarestorage.com'
export OWA_S3_BUCKET='owa-artifacts'
export OWA_S3_REGION='auto'
export OWA_S3_ACCESS_KEY_ID='...'
export OWA_S3_SECRET_ACCESS_KEY='...'
export OWA_S3_ADDRESSING_STYLE='path'

npm run dev:server
```

For AWS S3, virtual-host addressing is also supported:

```bash
export OWA_S3_ENDPOINT='https://s3.us-east-1.amazonaws.com'
export OWA_S3_BUCKET='my-bucket'
export OWA_S3_REGION='us-east-1'
export OWA_S3_ADDRESSING_STYLE='virtual'
```

Two independent provider capabilities decide how much `artifactd` trusts an
S3-compatible endpoint (details in [docs/integrity.md](docs/integrity.md)):

```bash
# May a HEAD-returned x-amz-checksum-sha256 replace a rehash at verification?
export OWA_S3_CHECKSUM_EVIDENCE='enforced'         # or 'advisory'
# May publishers hold direct presigned grants on final CAS keys?
export OWA_S3_DIRECT_UPLOAD_INTEGRITY='enforced'   # or 'mediated'
```

Cloudflare R2 (`*.r2.cloudflarestorage.com`) is live-proven and selects
`enforced` for both automatically. **Any other endpoint** — AWS S3, MinIO, another
compatible service — defaults to `advisory` + `mediated`: verification rehashes
the stored bytes, and uploads travel through `artifactd`, which checks the
SHA-256 before writing with its own storage credentials, so a publisher never
holds a storage credential that could corrupt a committed object later. Set
`enforced` only after verifying the provider (the MinIO tag recorded in
integrity.md qualifies). Any other value fails startup; no value skips
verification. The safe defaults cost bandwidth, never correctness.

The S3 signer is implemented directly with Node's cryptographic primitives and is checked against Amazon's published Signature V4 presign test vector.

### Live storage integration tests

`npm test` is the offline unit/conformance suite, including auth. Use
`npm run test:auth` for just auth coverage and `npm run test:integration:harness`
for offline live-harness checks. Run the separate live-service matrix with
`npm run test:integration`. Its loopback server explicitly selects dev auth; it
is storage interoperability coverage, not live auth/TLS validation. It covers
MinIO path-style, optional MinIO virtual-host addressing, and Cloudflare R2
path-style. Cases skip when their
explicit test endpoint or credentials are absent; configured service failures fail.

See [the integration test guide](docs/integration-tests.md) for exact environment
variables, local MinIO setup, CI examples, isolation/cleanup, and live-test limitations.

### Optional real-browser validation

`packages/browser-tests` is an isolated, package-local Playwright suite that runs
adversarial artifacts through the real content-only listener in actual browser
engines and records whether they enforce `sandboxed-web-v1` as documented — and
demonstrates the profile's documented limits (pre-existing service worker,
ordinary navigation, request cookies). It is optional: the root has no
dependencies, `npm test` needs no browser, and nothing in the runtime imports it.

```bash
npm --prefix packages/browser-tests ci --ignore-scripts        # Playwright, pinned
npm --prefix packages/browser-tests run install-browsers      # Chromium, Firefox, WebKit
npm run test:browser                                          # OWA_BROWSERS=chromium,firefox to subset
```

The dated evidence record — exact engines and versions actually executed, and
any engine not run — lives in [browser validation](docs/sandboxed-web-v1-browser-validation.md).

### Continuous integration

Four independent, **secretless** GitHub Actions workflows run on every pull
request, every push to `main`, and on demand (`pull_request`, never
`pull_request_target`; read-only token; no repository secrets):

| Workflow | What it proves |
| --- | --- |
| `CI` — `offline (<os>, node <22\|24>)` | every ordinary suite plus the package-local MCP suite on Ubuntu, macOS and Windows × Node 22 and 24; the live suites run unconfigured and must skip |
| `MinIO` — `minio (mediated + enforced, node 24)` | a real MinIO built from the pinned source commit of `RELEASE.2025-10-15T17-29-55Z`, disposable in-job credentials, the live suite in both default-mediated and explicitly-enforced modes, with skips turned into failures |
| `Browsers` — `browsers (chromium, firefox, webkit)` | the `packages/browser-tests` suite in all three real Playwright engines, including WebKit |
| `OCI` — `oci (oras + zot, node 24)` | the OCI layout pushed to and pulled from a real loopback Zot v2.1.21 registry with the pinned ORAS v1.3.4 CLI (checksum-verified official releases), by tag and by digest, then imported and served — with skips turned into failures |

Cloudflare R2 is intentionally **not** part of automatic CI: its credentials are
never exposed to pull-request code, and R2 remains operator-run evidence. Every
action is pinned to a commit SHA. Details, exact versions and how to reproduce
each lane locally: [docs/ci.md](docs/ci.md).

## OCI / ORAS transport

Export the exact same OWA artifact as an OCI image layout:

```bash
npm run artifact -- export-oci demo --out ./demo.oci --ref v1
```

Import it back into the local reference host:

```bash
npm run artifact -- import-oci ./demo.oci --ref v1 --site imported-demo
```

If ORAS is installed, the OCI layout can be copied to an OCI registry — and back
into a fresh layout — without OWA implementing a registry client:

```bash
oras cp --from-oci-layout ./demo.oci:v1 registry.example.com/team/site:v1
oras cp --to-oci-layout registry.example.com/team/site:v1 ./pulled.oci:v1
oras cp --to-oci-layout registry.example.com/team/site@sha256:<OCI manifest digest> ./pulled-by-digest.oci:v1
npm run artifact -- import-oci ./pulled.oci --ref v1 --site imported-demo
```

This is deliberate: OWA defines the web artifact semantics while OCI/ORAS handles
generic registry transport. That round trip is **observed continuously** with
ORAS v1.3.4 against a real Zot v2.1.21 registry (loopback, plain HTTP) in the
`OCI` GitHub Actions workflow: the registry stores exactly the OCI manifest OWA
wrote, tag and digest pulls recover the identical OWA artifact digest, canonical
manifest bytes and file bytes, and the imported release serves the original
bytes. Layer descriptors carry the RFC 6838 type/subtype of each file's media
type (`text/html` for `text/html; charset=utf-8`) because OCI descriptors cannot
carry parameters; the full OWA value stays in the config blob, which is the
canonical manifest. Several paths holding identical bytes stay distinct file
entries — one layer descriptor per entry, identified by `dev.openwebartifact.path`,
all referencing the one content-addressed blob (issue #9); the same live lane
proves those repeated descriptors survive the registry and that each path is
served with its own media type. Registry tags are mutable transport references —
neither OWA artifact identity nor OWA releases. Details, exact commands and
limitations (plain-HTTP loopback scope, no auth/TLS/signing claims):
[docs/oci.md](docs/oci.md).

## Artifact identity

The artifact digest is:

```text
sha256(UTF8(canonical-json(manifest)))
```

File bytes use their own SHA-256 digests. The OCI manifest has a separate OCI digest; the OWA manifest digest remains the portable web-artifact identity across filesystem, S3, and OCI transport.

See:

- `docs/spec-v0.2.md`
- `docs/manifest.schema.json`
- `docs/test-vectors/` (immutable published v0.2 vectors)
- [Portable conformance corpus and cross-language guide](docs/conformance/README.md)

`npm test` includes the portable corpus and deterministic property tests. To run
these separately, use `npm run test:conformance` and `npm run test:property`.
The property suite uses fixed seed `0x4f574132` and no third-party dependencies.

## Repository layout

```text
packages/
  spec/                canonicalization, validation, digest identity
  core/                packing, planning, commit, release activation
  storage-filesystem/  local blob + metadata reference backend
  storage-s3/          dependency-free S3/R2 SigV4 blob backend
  transport-oci/       OCI image-layout export/import
  server/              artifactd control listener + content listener
  gc/                  operational blob garbage collector (dry run by default)
  cli/                 local/remote publish + OCI commands
  mcp/                 optional SDK-based stdio client of the HTTP API
  conformance/         protocol and portability tests

implementations/
  go-conformance/      independent standard-library Go conformance implementation (not a server or SDK)

docs/
  spec-v0.1.md
  spec-v0.2.md
  manifest.schema.json
  auth.md
  origins.md
  sandboxed-web-v1.md          + threat model and browser validation record
  gc.md
  integrity.md
  oci.md
  mcp.md
  ci.md
  integration-tests.md
  release.md                   maintainer release checklist and readiness table
  release-notes-v0.4.0.md      release notes draft
  conformance/                 portable corpus and cross-language guide
  independent-implementation.md  the Go conformance implementation: scope, independence rules, ambiguities
  test-vectors/
```

## Security / production status

This is an experimental reference implementation, **not a production multi-tenant hosting service yet**.
The [HTTP auth overlay](docs/auth.md) enforces exact site/capability boundaries
for publishing, activation, and release inspection. It remains required by default;
only explicit direct-loopback dev mode is tokenless. Tokens do not provide full
tenant/storage isolation, per-token revocation, or replay prevention. Signing-key
rotation invalidates all tokens; deployment keys must not be reused.

The gateway also applies [`sandboxed-web-v1`](docs/sandboxed-web-v1.md), a
**script-disabled static-preview** response policy: bare CSP sandbox, deny-by-default
sources, inline CSS and data images only, no-store and advisory noindex headers.
All application responses receive the profile, including auth denials, control
JSON, health, uploads, errors and artifact GET/HEAD. Auth challenges and capabilities
are preserved; unknown/invalid artifact MIME is an octet-stream attachment without
rewriting bytes. The profile does not make interactive apps work or enable scripts.

Health and artifact GET/HEAD remain public; `read` protects control-plane metadata,
not public artifact access. Shared CAS deduplication is not tenant-private storage,
and commit verifies each blob's digest and size, not its ownership. Local operator CLI
access remains gated by filesystem permissions; storage and metadata are trusted.

A production deployment needs clean, cookieless, content-only per-site origins
separate from control/admin/API services. **The v0.4.0 reference server implements that topology**: see
[control and content origins](docs/origins.md). Configure a content origin
(`OWA_CONTENT_BASE_DOMAIN`) and the server runs a control listener plus a
content-only listener that binds one `Host` to one site, exposes no control
route, and drops the `?site=` selector. **With no content origin configured the
server still runs the legacy shared-origin prototype**, where `?site=` shares an
origin and protected APIs exist on all hosts; it prints a warning saying so.
No-store does not erase existing service workers, caches or saved copies. TLS,
secret custody, safe proxy logging, quotas and broader tenant isolation remain
operator responsibilities; blob garbage collection is provided (below) but release
retention is not.

Unreferenced blob objects (abandoned uploads and other true orphans) can be
reclaimed with the conservative mark/sweep collector. It is dry-run by default,
and **every stored release is a GC root** — active, inactive, rollback targets
and expired-lifecycle releases all keep their blobs, and no release record is
ever deleted:

```bash
npm run gc                 # preview what would be reclaimed
npm run gc -- --apply      # reclaim it
```

See [blob garbage collection](docs/gc.md). Release retention/pruning is
deliberately not implemented.

Commit is an **integrity gate**: a release is persisted only after every unique
referenced blob is strongly verified against its manifest SHA-256 **and** size —
provider-validated checksum evidence on S3/R2, a streaming rehash otherwise.
Direct-upload grants are checksum-bound and create-once, so a still-valid grant
cannot corrupt a committed object. See
[commit-boundary blob integrity](docs/integrity.md).

Read the [origin architecture](docs/origins.md),
[threat model](docs/sandboxed-web-v1-threat-model.md),
[profile contract](docs/sandboxed-web-v1.md), [auth guide](docs/auth.md),
[GC guide](docs/gc.md), [integrity guide](docs/integrity.md), and
[browser validation record](docs/sandboxed-web-v1-browser-validation.md).
Combined deterministic tests prove HTTP/auth policy and byte preservation, not
browser enforcement. Real-browser enforcement of `sandboxed-web-v1` was observed
with the optional `packages/browser-tests` suite in Chromium 153.0.8010.12,
Firefox 155.0 and WebKit 26.6 on 2026-09-21 (the `Browsers` GitHub Actions
workflow runs all three on every pull request — see the record and
[docs/ci.md](docs/ci.md)); that is dated evidence for those engines, not a proof
of universal browser security.

## Next milestones

Directions that remain open after the independent Go conformance proof (the portable corpus, origin split, GC,
integrity gate, MinIO/browser/ORAS+Zot lanes, Unicode pack ordering, cross-language conformance and the
portable pack media-type rule are done):

1. Decide the remaining portability interpretations recorded by the independent implementation ([docs/independent-implementation.md](docs/independent-implementation.md)), notably the pack-root and ancestor-symlink policy: both implementations currently follow a symbolic link supplied as the pack root, which issue #42 characterizes with tests in both implementations without making it normative. Non-regular directory entries are now specified in the v0.2 draft and pinned by implementation-local tests in both implementations (issue #40), deterministic pack-time media-type assignment is specified and corpus-pinned for the full fixed table (issue #33), and OCI index reference selection is exact, unique and fail-closed with a static multi-descriptor anchor (issue #36).
2. Broader operator-run live evidence where it adds information: additional S3-compatible providers, registries beyond the tested ORAS v1.3.4 / Zot v2.1.21 pair, authenticated/TLS registry transport (registry transport itself stays with ORAS).
3. Production and multi-tenant hardening beyond the documented prototype boundaries: tenant-private storage, token revocation/key rings, release retention, quotas.
4. Separately reviewed future interactive capabilities (data/forms/secret proxies) only after the static lifecycle is stable; `sandboxed-web-v1` stays script-disabled.

## License

MIT. See `LICENSE`.
