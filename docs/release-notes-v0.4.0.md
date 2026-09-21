# Open Web Artifact v0.4.0

Open Web Artifact (OWA) is an **experimental** open specification and reference
implementation for portable, immutable web artifacts: an agent, CLI, CI job or
application produces one content-addressed artifact that can be stored, moved
and served by different hosts without adopting each host's private deployment
model.

v0.4.0 is the first tagged release of the **reference implementation**. Three
version domains are deliberately distinct:

- **software / reference implementation:** v0.4.0 (this release);
- **protocol / specification:** still the **v0.2 draft** ([`docs/spec-v0.2.md`](spec-v0.2.md));
- **manifest `specVersion`:** still **`owa.dev/v1`**, media type
  `application/vnd.openwebartifact.site.v1+json`.

Nothing in this release changes canonical JSON, the artifact digest algorithm or
any published artifact identity. It is a **source / reference-implementation
release**: all repository packages are private, nothing is published to npm, and
there are no binaries or container images — GitHub's source archives are the
distribution. Runtime: **Node.js 22+**.

## What this release proves

- Deterministic canonical manifest identity (`sha256:` of canonical JSON) with a
  published, immutable test vector and a portable multi-operation conformance
  corpus plus a seeded property suite (424 scheduled iterations).
- **Locale-independent directory packing:** `manifest.files` is ordered by
  Unicode code-point order of complete artifact paths — the same relation
  canonical JSON uses for object keys — with portable Unicode vectors proven on
  Linux, macOS and Windows.
- Immutable releases, blob deduplication, a mutable active-release pointer, and
  rollback without re-upload.
- Two-phase HTTP publishing (`plan → direct upload → commit`) with
  **commit-boundary integrity**: a release is persisted only after every unique
  blob is verified against its manifest SHA-256 **and** size.
- Filesystem and S3-compatible storage (dependency-free SigV4 signer verified
  against Amazon's published test vector), with a **mediated-by-default /
  explicitly-enforced** direct-upload trust model and checksum-bound, create-once
  upload grants.
- Conservative mark/sweep blob garbage collection (dry-run by default, every
  stored release is a root) and publish leases that protect in-flight publishes.
- OCI image-layout export/import, a `sandboxed-web-v1` static-preview response
  profile, a content/control **origin split**, capability-scoped bearer
  authentication, a CLI, and an optional package-local MCP adapter.

## Interoperability

Enforced continuously by secretless GitHub Actions on every pull request and push:

- **Operating systems / runtimes:** Ubuntu, macOS and Windows × Node 22 and 24
  (six offline matrix cells).
- **S3-compatible storage:** a real **MinIO** built from the pinned source tag
  `RELEASE.2025-10-15T17-29-55Z`, running the live suite in default-mediated and
  explicitly-enforced modes; skips are failures. Cloudflare **R2** was proven
  live as operator-run evidence (recorded in [`docs/integrity.md`](integrity.md)),
  not in automatic CI.
- **Browsers:** `sandboxed-web-v1` enforcement observed in **Chromium
  153.0.8010.12**, **Firefox 155.0** and **WebKit 26.6** via **Playwright 1.63.0**,
  every engine required.
- **OCI registries:** OWA layouts pushed to and pulled from a real loopback
  **Zot v2.1.21** registry with the real **ORAS v1.3.4** CLI (checksum-verified
  official releases), by tag and by immutable digest, then imported and served
  byte-for-byte — including artifacts whose distinct paths share identical content.

## Security and integrity

- **Authentication:** capability-scoped HMAC bearer tokens, required by default;
  the only tokenless mode is explicit direct-loopback development mode.
- **Response policy:** `sandboxed-web-v1` — script-disabled static previews with
  a bare CSP sandbox, deny-by-default sources, no-store and advisory no-index
  headers on every application response.
- **Origins:** a configured content origin binds one `Host` to one site and
  exposes no control route or `?site=` selector; control/admin/API routes live on
  a separate listener.
- **Integrity:** commit verifies digest and size of every referenced blob;
  direct-upload grants cannot corrupt a committed object; GC never deletes a
  blob referenced by any stored release.

## Compatibility notes

**Unicode directory re-packing (issue #8).** Older reference builds ordered
`manifest.files` with locale-sensitive collation for arbitrary Unicode filenames,
so the same directory could pack differently on different hosts. v0.4.0 defines
Unicode **code-point** ordering of complete artifact paths. Existing manifests,
releases and artifacts do **not** change — a manifest's array order was always
fully specified once it existed. Re-packing the same Unicode directory with an
older reference build and with v0.4.0 **may** produce a different file-array
order and therefore a different artifact digest. All published pre-existing v0.2
corpus identities are unchanged, and there is no legacy-collation compatibility
mode because the old result depended on the host locale.

**OCI envelope (issues #23 and #9).** v0.4.0 corrected the OCI representation
without changing OWA identity: a parameterized OWA `mediaType` such as
`text/html; charset=utf-8` stays intact in the canonical config blob, while the
OCI layer descriptor carries the valid RFC 6838 type/subtype (`text/html`) or
`application/octet-stream` when the value is not representable. The OWA
artifact digest is unchanged; the **OCI manifest digest may differ** from older,
non-conformant exports. Duplicate-content paths now keep one distinct file-entry
descriptor per path (identified by `dev.openwebartifact.path`) while sharing one
content blob by digest; older readers collapsed them.

## Known limitations

- Experimental reference implementation — **not a production multi-tenant hosting
  service**.
- Bearer tokens are replayable until expiry; there is no per-token revocation,
  audience claim or key-ring/rotation overlap.
- The shared content-addressed store is not tenant-private storage.
- `sandboxed-web-v1` is a script-disabled static-preview profile, not an
  interactive web-app profile; it does not undo pre-existing service workers,
  caches or saved copies, and browser evidence is engine- and date-specific.
- Production content origins must be clean, cookieless and separate from control;
  without a configured content origin the server runs the legacy shared-origin
  prototype and warns.
- Registry authentication, TLS and signatures are outside the ORAS/Zot loopback
  proof; other registries are not claimed.
- R2 is operator-run evidence rather than automatic pull-request CI.
- Release retention/pruning is not implemented; GC reclaims only true orphans.

## Verification

Local (Node 22 or 24): `npm run test:gc`, `npm test`, `npm run test:auth`,
`npm run test:security`, `npm run test:conformance`, `npm run test:property`,
`npm run test:integrity`, `npm run test:integration:harness`,
`npm run test:integration` (provider cases skip without credentials),
`npm run test:oci` (live cases skip without a configured registry/ORAS),
`npm --prefix packages/mcp ci --ignore-scripts && npm run test:mcp`,
`git diff --check`. Continuous: nine GitHub Actions checks — six offline
OS × Node cells, MinIO, Browsers, OCI — described in [`docs/ci.md`](ci.md).
See [`CHANGELOG.md`](../CHANGELOG.md) for the full list of changes since 0.2.0.
