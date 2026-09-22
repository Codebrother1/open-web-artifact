# Changelog

Versions here are **software / reference-implementation** versions. The protocol
remains the v0.2 specification draft and every manifest keeps `specVersion`
`owa.dev/v1`; see [docs/release.md](docs/release.md) for the version domains.
There was no tagged 0.3.0 release; everything below was merged between 0.2.0 and
0.4.0.

## Unreleased

Protocol identity is unchanged (spec v0.2 draft, `owa.dev/v1`,
`application/vnd.openwebartifact.site.v1+json`, canonical JSON and artifact
digest algorithm); no package version, tag or release.

- specify pack-time media-type assignment as a portable producer rule (issue
  #33): the reference packer's existing fixed extension table plus a
  language-neutral extension rule — final path segment, suffix from the final
  dot, a leading dot alone is not an extension, ASCII-only folding of the
  lookup key, `application/octet-stream` fallback; no host MIME database, byte
  sniffing or compound extensions. Every table entry and the edge cases are
  pinned in the portable pack corpus, and the Go conformance implementation
  replaces its four-extension local interpretation with the same published
  rule. All previously published pack vectors keep their canonical JSON and
  artifact digests; manually authored `mediaType` values are unaffected.
- make OCI index reference selection exact, unique and fail-closed (issue
  #36): `readOciLayout` selects the `index.json` descriptor whose
  `org.opencontainers.image.ref.name` annotation is a string exactly equal to
  the requested ref and requires exactly one such descriptor — zero matches
  fail as not found, duplicates fail as ambiguous, descriptor order never
  decides. The undocumented `latest` → `manifests[0]` fallback is removed; the
  Go conformance implementation adopts the same rule and rejects duplicate
  matches. A new static multi-descriptor success vector
  (`blob-read-index-exact-ref-selection`) pins exact match over array position;
  failure behaviour is pinned by direct tests in both implementations because
  generic OCI layout failures have no portable OWA error category (the 18
  categories are unchanged). Writer output, config/manifest/layer/blob
  verification, duplicate-content handling, media-type mapping and all
  published artifact identities are unchanged.
- strengthen canonical binary64 conformance evidence at hard boundaries
  (issue #38): 79 new static `canonical-b64-*` vectors and one manifest
  vector (`manifest-binary64-boundary-annotations`) pin rule 5 — binary64
  parsing with ties to even, shortest round-tripping digits with closest-
  candidate and even-final-digit selection, the `1e-6`/`1e21` layout
  thresholds and their binary64 neighbours, the exponent and signed-zero
  grammar — at the smallest and largest subnormals, the smallest normal, the
  largest finite value and the overflow midpoint, `2^53`…`2^64`, exact parse
  midpoints and genuine shortest-digit ties. Expectations were authored by an
  independent standard-library exact-arithmetic verifier and frozen before
  either implementation ran; the JavaScript reference and the Go conformance
  implementation pass all of them unchanged, and each gains a local
  round-trip/grammar property suite. No canonicalization code, protocol
  identity, error category, package version or pre-existing vector changed.

## 0.4.0 - 2026-09-21

First tagged release of the reference implementation (source-only; repository
packages stay private). Protocol identity is unchanged: spec v0.2 draft,
`owa.dev/v1`, `application/vnd.openwebartifact.site.v1+json`, canonical JSON and
artifact digest algorithm.

Authentication, security profile and origins

- add required-by-default, site- and capability-scoped HMAC bearer authentication
  for the HTTP control plane, with safe error codes and audit hooks
- fail closed at startup when required auth has no usable secret; tokenless
  operation only in explicit direct-loopback dev mode
- add the `sandboxed-web-v1` script-disabled static-preview response profile on
  every application response, with its threat model and evidence record
- separate content and control origins: a configured content origin binds one
  `Host` to one site, exposes no control route and drops the `?site=` selector;
  the legacy shared-origin server remains available and warns

Publishing integrity and storage

- enforce commit-boundary blob integrity: a release is persisted only after every
  unique referenced blob is verified against its manifest SHA-256 and size
- add mediated (default) and explicitly enforced S3 direct-upload trust modes with
  checksum-bound, create-once upload grants and non-destructive repair
- add publish leases protecting the plan -> upload -> commit window
- add a conservative mark/sweep blob garbage collector (dry-run by default; every
  stored release is a root) with an operator CLI
- record live Cloudflare R2 evidence and add real MinIO (pinned source release
  `RELEASE.2025-10-15T17-29-55Z`) mediated + enforced integration in CI

Transport and packing

- make OCI layer descriptor media types conform to the OCI image-spec grammar
  (`text/html; charset=utf-8` -> `text/html`, `application/octet-stream` fallback);
  the canonical OWA manifest in the config blob keeps the full value and the OWA
  artifact digest is unchanged
- preserve duplicate-content file entries through OCI import: one descriptor per
  file entry selected by `dev.openwebartifact.path`, blobs deduplicated by digest
- prove OCI registry interoperability continuously with the real ORAS v1.3.4 CLI
  and a real Zot v2.1.21 registry (push, pull by tag and by digest, import, serve)
- define locale-independent directory packing: `manifest.files` is ordered by
  Unicode code-point order of complete artifact paths (previously
  locale-sensitive `localeCompare`); existing manifests and published corpus
  identities are unchanged, re-packing a Unicode directory may differ from older
  builds

Tooling, tests and CI

- add an optional package-local stdio MCP adapter over the same authenticated
  HTTP API (`@owa/mcp`)
- add real Chromium, Firefox and WebKit validation of `sandboxed-web-v1`
  (package-local Playwright 1.63.0 suite)
- add secretless GitHub Actions: Linux/macOS/Windows x Node 22/24 offline matrix,
  MinIO, Browsers and OCI lanes (nine checks), all actions pinned by commit SHA
- expand the portable conformance corpus (pack, blob, request, path, canonical,
  parse, manifest operations incl. Unicode pack ordering and duplicate-content
  OCI anchors) and the seeded property suite (424 scheduled iterations)
- align every repository package to version 0.4.0 with `engines.node >=22`; add
  the release checklist (`docs/release.md`) and release notes draft

## 0.2.0 - 2026-09-20

- add deterministic canonical manifest encoding and published test vector
- add two-phase HTTP publishing: plan, direct blob upload, commit
- add dependency-free S3 Signature V4 backend with path and virtual-host addressing
- verify S3 presigning against Amazon's published SigV4 test vector
- add OCI image-layout export/import compatible with ORAS workflows
- add manifest JSON Schema
- harden artifact path validation and reject symlinks while packing
- expand conformance suite and remote end-to-end coverage

## 0.1.0 - 2026-09-20

- initial content-addressed filesystem prototype
- immutable releases, deduplication, activation, rollback, gateway, and CLI
