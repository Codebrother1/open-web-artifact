# Open Web Artifact v0.5.0 — UNRELEASED DRAFT

> **Status: UNRELEASED.** This is a draft prepared by the release-readiness
> review (issue #48). No `v0.5.0` tag or GitHub Release exists, package
> versions are still `0.4.0`, and no release date has been set. The text is
> kept consistent with the `Unreleased` section of [`CHANGELOG.md`](../CHANGELOG.md)
> and must be re-read against the final changelog section before publication.

Open Web Artifact (OWA) is an **experimental** open specification and reference
implementation for portable, immutable web artifacts. v0.5.0 would be the second
tagged release of the **reference implementation**. The three version domains
stay distinct:

- **software / reference implementation:** v0.5.0 (this draft);
- **protocol / specification:** still the **v0.2 draft** ([`docs/spec-v0.2.md`](spec-v0.2.md)),
  which gained two normative producer subsections (below) without any change to
  canonical JSON, the artifact digest algorithm or the manifest grammar;
- **manifest `specVersion`:** still **`owa.dev/v1`**, media type
  `application/vnd.openwebartifact.site.v1+json`.

Every published artifact identity is unchanged: all 285 conformance vectors that
existed at v0.4.0 are byte-identical, and `docs/test-vectors/basic/*` is
untouched. Distribution stays **source-only** (all packages private, no npm,
no binaries, no container image); runtime **Node.js 22+**.

## What changed, and why it matters

### 1. OCI index reference selection is exact, unique and fail-closed (behaviour change)

`readOciLayout` — and therefore `artifact import-oci` — now selects the
`index.json` descriptor whose `org.opencontainers.image.ref.name` annotation is
a **string exactly equal** to the requested ref, and requires **exactly one**
such descriptor. Two behaviours of v0.4.0 are gone:

- the undocumented fallback that resolved `latest` to `index.manifests[0]` when
  no descriptor carried that annotation;
- silently taking the **first** of several descriptors that all claimed the
  requested ref.

Both cases now fail (`OCI reference not found: <ref>` /
`Ambiguous OCI index: <n> descriptors carry org.opencontainers.image.ref.name <ref>`).
Why it matters: descriptor order was never OWA identity, and a layout with a
decoy artifact listed first could previously be imported as the wrong artifact.
A static multi-descriptor success vector (`blob-read-index-exact-ref-selection`)
pins exact match over position. See [Compatibility](#compatibility-and-migration).

### 2. Pack-time media-type assignment is a portable rule (specification; implementation restated)

The spec now states the fixed extension table and the extension rule the
reference already used (final segment, suffix from the final `.`, a leading `.`
alone is not an extension, ASCII-only folding of the lookup key,
`application/octet-stream` for everything unlisted; no host MIME database, byte
sniffing or compound extensions). The reference packer's code was restated to
follow that rule literally; **no output changed for any input** the old table
handled, every table entry and edge case is now corpus-pinned, and the Go
implementation packs to the same digests. A second implementation can no longer
legitimately pack `photo.png` or `INDEX.HTML` to a different artifact digest.

### 3. Non-regular directory entries are specified (specification; behaviour unchanged)

Entries beneath the packed directory are classified without following links:
symbolic links fail `OWA_SYMLINK`, directories recurse, regular files pack, and
FIFOs, sockets, devices and anything else are skipped without being opened.
The two failure cases are disjoint and ordered — zero regular-file entries →
`OWA_INVALID_MANIFEST`; otherwise a requested entrypoint that is not a
regular-file entry → `OWA_MISSING_ENTRYPOINT`. This states what both
implementations already did; it is pinned by implementation-local tests with
real FIFOs and Unix-domain sockets (Linux/macOS) run in isolated child processes.

### 4. An independent Go implementation of the portable corpus

`implementations/go-conformance/` is a standard-library-only Go program written
from the published specification and corpus; it derives the same canonical
bytes, digests, validation categories, request resolutions, pack results and
OCI-layout results as the JavaScript reference, and runs as the tenth CI check
(`go-conformance (go 1.27, ubuntu)`). The two implementations never invoke each
other; `pack-cross-language-anchor` is their static rendezvous point. Every
ambiguity the port surfaced is recorded in
[`independent-implementation.md`](independent-implementation.md); three were
resolved by the spec (items 2 and 3 above and the ref-selection rule), the rest
remain listed as open interpretations (see limitations).

### 5. Stronger conformance evidence

79 new `canonical-b64-*` vectors and one manifest vector pin binary64 number
serialization at its hard boundaries (subnormals, the largest finite value and
overflow midpoint, `1e-6`/`1e21` layout thresholds, `2^53`…`2^64`, parse ties,
shortest-digit ties); their expectations were authored by an independent
exact-arithmetic verifier and frozen before either implementation ran. The
conformance suite grows from 297 to 384 tests; total pre-existing expectations
unchanged.

### 6. Authenticated HTTPS OCI transport, continuously verified (evidence for existing behaviour)

The `oci (oras + zot, node 24)` lane now also pushes and pulls the static
duplicate-content anchor through a second, disposable Zot v2.1.21 requiring
**TLS with certificate verification** (temporary test CA) and **htpasswd
authentication**, with the pinned ORAS v1.3.4 (`--ca-file`, isolated
`--registry-config`, password on stdin; never `--insecure`, never plain HTTP).
OWA artifact digest, canonical bytes, ordered entries, per-path media types,
blob set and bytes and the OCI manifest digest survive; missing credentials,
wrong credentials and an untrusted CA each fail at their boundary. No OWA
transport, credential or TLS code was added — ORAS remains the transport.

### 7. Test-harness reliability

A readiness poll in the auth startup tests could keep the test runner alive
after a failed wait until the CI job limit (observed once as a cancelled
post-merge lane); it is now event-driven with cleanup on every path. The
authenticated-registry harness owns cleanup for every failed start and bounds
readiness in elapsed time. Test code only.

## Compatibility and migration

- **OCI layouts imported with `import-oci` / `readOciLayout`.** Layouts pulled
  with ORAS are unaffected: ORAS writes the destination ref as `ref.name` on
  every pull, by tag and by digest. A hand-built or third-party layout whose
  `index.json` descriptors carry **no** `org.opencontainers.image.ref.name`
  annotation, and that was imported with the default `--ref latest` relying on
  the old first-descriptor fallback, now fails with `OCI reference not found:
  latest`. Migration: add the `org.opencontainers.image.ref.name` annotation to
  the intended descriptor, or pass `--ref` with the annotation value it does
  carry. A layout in which several descriptors carry the same ref now fails as
  ambiguous instead of importing the first; make the refs distinct. Writer
  output (`export-oci`) is unchanged.
- **Pack media types.** No change in produced `mediaType` values or artifact
  digests for any directory the v0.4.0 packer handled; the rule is now
  normative, so independent packers must produce the same values.
- **Non-regular entries.** No change in behaviour; now normative.
- **Manifests, canonical JSON, digests, stored releases, `specVersion`, the OWA
  media type and the 18 portable error categories** are unchanged. No manifest
  needs to be re-packed or re-published.
- **Pack roots that are symbolic links** (or have a link in an ancestor
  component) are followed by both implementations — current behaviour,
  characterized by tests, **not** a guarantee; the policy is still open.
- The Unicode re-packing note from v0.4.0 (locale-sensitive ordering in
  pre-0.4 packers) still applies to artifacts packed before v0.4.0.

## What was tested (at `main` `2e5f743a`, the review baseline)

Local, Node 24.14.1 on Linux: `npm test` 1105 pass · `test:conformance` 384 ·
`test:property` 6 suites / 424 seeded iterations · `test:auth` 249 ·
`test:security` 376 · `test:integrity` 62 · `test:gc` 51 ·
`test:integration:harness` 30 · `test:integration` 7 skipped (unconfigured) ·
`test:oci` 3 skipped (unconfigured) · `test:mcp` 167 · Go `go test ./...` 435
passing tests/subtests, `gofmt`/`go vet` clean, no non-standard-library import.

Continuously in GitHub Actions on the exact commit: **10 checks**, all
secretless — `offline (ubuntu|macos|windows-latest, node 22|24)` (6),
`minio (mediated + enforced, node 24)`, `browsers (chromium, firefox, webkit)`,
`oci (oras + zot, node 24)` (three live tests: plain-HTTP round trip,
duplicate-content, authenticated HTTPS; skips are failures), and
`go-conformance (go 1.27, ubuntu)`. Tool pins: ORAS v1.3.4, Zot v2.1.21,
Playwright 1.63.0, MinIO `RELEASE.2025-10-15T17-29-55Z`, Go 1.27.

## Remaining limitations

- **Experimental; not a production multi-tenant hosting service.** Shared CAS is
  not tenant-private; TLS termination, secret custody, proxy logging and quotas
  are operator responsibilities; bearer tokens are replayable until expiry with
  no per-token revocation, key ring or rotation overlap.
- **Pack-root / ancestor-link policy is unresolved.** Both implementations follow
  a link supplied as the root; nothing confines the root. Documented as current
  behaviour only.
- **Duplicate JSON member names** are outside the portable corpus; each
  implementation discloses its parser policy rather than the spec fixing one.
- **Authenticated HTTPS evidence is bounded**: basic auth over verified TLS on a
  loopback Zot with one allowed user. Token/bearer exchange, credential
  helpers, mutual TLS, authorization semantics beyond that user, multi-tenant
  isolation and other registries are not proven.
- **Provider coverage**: Cloudflare R2 remains operator-run evidence, not
  automatic CI; other S3-compatible providers and registries are untested.
- **Browser evidence** is engine- and date-specific (Chromium/Firefox/WebKit via
  Playwright 1.63.0), not proof against browser vulnerabilities.
- **Device nodes** are not exercised by the non-regular-entry tests (privileged
  to create); their handling rests on the shared classification branch.
- One original CI readiness miss (a spawned server not printing readiness within
  15 s on one Ubuntu runner) is **unexplained**; the harness hang it triggered is
  fixed and the failure message now records the child's state for the next
  occurrence.
- `sandboxed-web-v1` remains a script-disabled static-preview profile.

## Distribution (proposal)

Source / reference-implementation release only, exactly as v0.4.0: every
repository package stays `"private": true`; nothing is published to npm; no
binaries, installers or container images; GitHub's generated source archives for
tag `v0.5.0` are the distribution. GitHub's "Latest" label is a mechanical
marker, not a statement of production readiness.
