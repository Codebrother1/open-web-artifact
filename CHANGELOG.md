# Changelog

Versions here are **software / reference-implementation** versions. The protocol
remains the v0.2 specification draft and every manifest keeps `specVersion`
`owa.dev/v1`; see [docs/release.md](docs/release.md) for the version domains.
There was no tagged 0.3.0 release; everything below was merged between 0.2.0 and
0.4.0.

## Unreleased

- protect the default branch with an active repository ruleset requiring pull
  requests, all ten GitHub Actions checks on an up-to-date branch, and blocking
  force pushes and deletion. Document the external setting and its no-bypass,
  zero-approval policy in the CI and release guides. No workflow or runtime code
  changed.

- reject duplicate decoded JSON member names in raw JSON at every object depth
  (issue #54) before assigning artifact identity, including escape-equivalent
  keys and discarded overflowing values. Both the JavaScript reference and the
  Go conformance parser now report `OWA_INVALID_JSON_VALUE`; eleven new static
  parse/manifest vectors pin the rule. This intentionally changes acceptance
  for callers relying on last-wins duplicates; duplicate-free canonical bytes,
  digests and the `owa.dev/v1` manifest shape are unchanged.

## 0.5.0 - 2026-09-22

Protocol identity is unchanged (spec v0.2 draft, `owa.dev/v1`,
`application/vnd.openwebartifact.site.v1+json`, canonical JSON and artifact
digest algorithm). Software metadata is 0.5.0; the annotated `v0.5.0` tag and
[GitHub Release](https://github.com/Codebrother1/open-web-artifact/releases/tag/v0.5.0)
were published on 2026-09-22 after all ten checks passed on the release commit.

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
- specify directory-packing behaviour for non-regular filesystem entries
  (issue #40): entries are classified without following links; symbolic links
  fail `OWA_SYMLINK`, directories recurse, regular files pack, and FIFOs,
  sockets, devices and any other entry type are skipped without being opened,
  read or connected to, contributing no entry or blob and leaving the identity
  of the regular files unchanged. The two failure cases are disjoint and
  ordered: zero regular-file entries → `OWA_INVALID_MANIFEST`; otherwise a
  requested entrypoint that is not among the regular-file entries →
  `OWA_MISSING_ENTRYPOINT`, which a skipped special entry never satisfies.
  This states existing JavaScript and Go behaviour; no production code
  changed. Both implementations gain implementation-local tests with real
  FIFOs and bound Unix-domain sockets (Linux/macOS; skipped on Windows) in
  which every pack operation that could meet a FIFO runs in a separate
  process under an external deadline with kill-and-reap, so a writer-less
  FIFO can never hang the suite. No corpus file, error category, protocol
  identity or package version changed.
- characterize pack-root and ancestor-symlink behaviour in both
  implementations (issue #42), as current behaviour rather than a normative
  rule: implementation-local tests record that a directory link supplied as
  the pack root (relative or absolute target) or in an ancestor component is
  followed and packs to the same identity as the direct path with no host
  spelling in artifact paths; that a link inside the tree still fails
  `OWA_SYMLINK` through every root spelling; and that a dangling root link or
  a root link to a regular file fails with the host filesystem error and no
  artifact. The root/ancestor-link policy stays unresolved and no confinement
  or race resistance is claimed. No production code, corpus file, error
  category, protocol identity or package version changed.
- add live evidence for authenticated HTTPS OCI transport (issue #46): the
  `oci (oras + zot, node 24)` lane now also runs
  `packages/integration/oci/authenticated-tls.test.js`, which starts a second,
  disposable Zot v2.1.21 with TLS (temporary test CA, `IP:127.0.0.1`/`DNS:localhost`
  SAN), htpasswd authentication required for every repository and a synthetic
  per-run password, then pushes and pulls the static duplicate-content anchor
  with the pinned ORAS v1.3.4 over verified HTTPS (isolated `--registry-config`,
  password on stdin, `--ca-file`) and proves the OWA artifact digest, canonical
  bytes, ordered entries, per-path media types, blob set and bytes and the OCI
  manifest digest survive, while missing credentials, wrong credentials and an
  untrusted CA each fail at their boundary (401s in the registry log; no request
  at all for the untrusted CA). The disposable registry's start waits for the
  exact challenge under a 60 s elapsed-time deadline that destroys in-flight
  probes regardless of incoming bytes and rejects a response completed after
  the budget, and cleans up its own failures — child stopped and reaped, state
  removed, probe and timers cleared — before rejecting with the original error.
  Test-only code; ORAS remains the transport. No production code, dependency,
  tool version, corpus file, protocol identity or package version changed.
- prepare the next software release (issue #48, documentation only): refresh
  `docs/release.md` into a reusable process covering the 10 CI checks
  (including Go conformance), the three live OCI tests, the authenticated HTTPS
  coverage and its limits, and exact-commit post-merge verification before
  tagging; record the v0.5.0 release-readiness review with its compatibility
  notes and open maintainer decisions; add `docs/release-notes-v0.5.0.md` as an
  UNRELEASED draft. No version bump, tag or release; the v0.4.0 record is kept.
- fix a test-harness hang in `auth-startup-listeners.test.js` (issue #44):
  the readiness wait for the spawned server polled with a self-rescheduling
  timer that was never stopped when its deadline won, so a failed readiness
  wait kept `npm run test:auth` alive until the workflow's 15-minute job
  limit cancelled the lane. The wait is now event-driven, fails as soon as
  the child exits without announcing readiness, and clears its timer and
  listener on every path; regression tests pin the bounded failure, the
  absence of leaked timers and the kill-and-reap of the child. Test code
  only; no timeout, gate, production code, corpus file or version changed.
- fix the authenticated-HTTPS OCI negative control's HTTP-status diagnostic
  check (issue #51): a bare `401` substring no longer counts as an HTTP
  authentication response, because an ephemeral registry port or repository
  path may contain those digits. The test now recognizes explicit
  `Unauthorized`, HTTP status-line and status-code wording, while the registry
  request log remains the primary proof that an untrusted-CA failure sends no
  HTTP request. Test-only code; no production behaviour, timeout, dependency,
  protocol identity or package version changed.

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
