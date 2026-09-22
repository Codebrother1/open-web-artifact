# Release process

This is the maintainer checklist for tagging and publishing a software release of
the Open Web Artifact reference implementation. It is a checklist, not an
automation: no workflow creates tags or releases, and this document does not
authorize one. It has two parts — the **reusable process** (version domains,
evidence, pre-tag gates, tag and release policy) and a **per-version record**:
the v0.5.0 readiness review (UNRELEASED, under review) and the v0.4.0 release
record (released 2026-09-21, preserved with its dated evidence).

## Version domains

Three version numbers live in this repository and they do **not** move together:

| Domain | Current value | Where it lives | What moves it |
| --- | --- | --- | --- |
| **Software / reference implementation** | **v0.4.0** released (tag `v0.4.0` → `8a63b39a`); **v0.5.0 proposed, UNRELEASED** | every `package.json` `version`, the MCP server-info string, `CHANGELOG.md`, the Git tag, the GitHub Release title | a software release |
| **Protocol / specification draft** | **v0.2 (Draft)** | [`docs/spec-v0.2.md`](spec-v0.2.md), the conformance corpus under `docs/conformance/v0.2/` | a new spec draft, decided separately |
| **Manifest `specVersion`** | **`owa.dev/v1`** with media type `application/vnd.openwebartifact.site.v1+json` | `packages/spec/src/index.js`, every manifest | an incompatible manifest change, decided separately |

A software release never bumps `specVersion` or the media type and never
describes the protocol as "v0.4" or "v0.5". Normative additions to the v0.2
draft that only state producer behaviour the reference already had (pack
ordering, media types, entry types) stay inside the v0.2 draft; canonical JSON,
the artifact digest algorithm and every published artifact identity are
unchanged by any release to date.

## Distribution model

Every software release so far is a **source / reference-implementation
release**:

- every repository package stays `"private": true`; nothing is published to npm;
- no `publishConfig`, publish script, provenance attestation or release workflow;
- no container image, platform binary, installer or downloadable bundle;
- GitHub's ordinary auto-generated source archives (`.zip` / `.tar.gz`) for the
  tag are the distribution.

Anything beyond that is a separate, explicitly approved packaging issue.

## Continuous evidence: the 10 checks

Every pull request and every push to `main` runs **10 secretless GitHub Actions
checks** ([ci.md](ci.md)). A release relies on them, so the release process must
name all ten and read them **on the exact commit** being tagged:

| Check | What it proves for a release |
| --- | --- |
| `offline (ubuntu-latest, node 22)` · `offline (ubuntu-latest, node 24)` · `offline (macos-latest, node 22)` · `offline (macos-latest, node 24)` · `offline (windows-latest, node 22)` · `offline (windows-latest, node 24)` | every ordinary suite (`npm test`, auth, security, conformance, property, integrity, GC, integration harness, package-local MCP) on three operating systems × two Node lines; the live suites run unconfigured and must skip; the checkout is clean afterwards |
| `minio (mediated + enforced, node 24)` | the live S3 suite against a real MinIO built from the pinned source tag, in default-mediated and explicitly-enforced modes, skips turned into failures |
| `browsers (chromium, firefox, webkit)` | the `sandboxed-web-v1` browser-validation suite in all three real Playwright engines (dated, engine-specific evidence) |
| `oci (oras + zot, node 24)` | **three live OCI tests** with the pinned ORAS v1.3.4 and Zot v2.1.21, skips turned into failures: (1) layout → registry → fresh layout → import → serve, by tag and by digest, over plain HTTP; (2) duplicate-content file entries over one shared blob; (3) the same identity round trip through a second, disposable Zot requiring **TLS with certificate verification and htpasswd authentication**, with missing-credential, wrong-credential and untrusted-CA controls. Scope of (3): basic auth over verified TLS on a loopback registry with one allowed user — not token exchange, credential helpers, mutual TLS, authorization semantics beyond that user, other registries or production readiness ([oci.md](oci.md#authenticated-https-transport-issue-46)) |
| `go-conformance (go 1.27, ubuntu)` | the independent, standard-library-only Go implementation derives the same results from the published corpus, basic vectors and static anchors; `gofmt` and `go vet` clean; module proven stdlib-only |

**Exact-commit verification.** Pull-request checks prove the PR head; a squash
merge produces a *new* commit, whose `push` workflows must be read separately.
Before tagging, resolve the merge commit (`git rev-parse origin/main`) and
confirm, from the public check-runs API for **that** SHA
(`GET /repos/Codebrother1/open-web-artifact/commits/<sha>/check-runs`), that
`total_count` is 10, every run reports that single `head_sha`, and every
`conclusion` is `success`. Record the SHA and the ten run links in the release
PR. Job logs are login-gated; conclusions and the public `::notice` annotations
(runtime, tool versions, OCI digests) are readable without a login.

---

## Release-readiness review — v0.5.0 (UNRELEASED)

Prepared under issue #48 at `main` `2e5f743a9d066da028ea8c0a5164c3566d27c9b4`
(tree `77a40eda0e94c838fb873e728d9636633c3b9c4a`; 10/10 post-merge checks green
on that exact commit). Nine pull requests were merged after `v0.4.0`
(`8a63b39a`): #32, #34, #35, #37, #39, #41, #43, #45, #47 — 48 files,
+9311/−91. Companion draft: [`release-notes-v0.5.0.md`](release-notes-v0.5.0.md).

### Scope inventory (from the diff, not from titles)

| Category | Change | Kind |
| --- | --- | --- |
| **User-visible behaviour** | **OCI index reference selection** (#37, `packages/transport-oci/src/index.js`, +39/−2): `selectIndexDescriptor` requires exactly one descriptor whose `org.opencontainers.image.ref.name` is a string exactly equal to the requested ref. Removed: the undocumented `latest` → `manifests[0]` fallback; silently importing the first of several matching descriptors. Reaches users through `readOciLayout` and `artifact import-oci` (default `--ref latest`). | **implementation change — acceptance/rejection changed** (stricter) |
| **User-visible behaviour** | **Pack-time media type** (#35, `packages/core/src/index.js`, +61/−12): `path.extname(...).toLowerCase()` replaced by the spec's stated extension rule and a frozen table with identical entries. Same `mediaType` for every input the old code handled (same table; `extname` agrees on dotfiles, trailing dots and multiple dots; ASCII folding and `toLowerCase` differ only for non-ASCII candidates, unlisted in both → `application/octet-stream`). | implementation restated to the now-normative rule — **no output change demonstrated**; all pre-existing pack vectors byte-identical, all table entries now corpus-pinned |
| **Developer surface** | `package.json`: new script `test:go-conformance` (#32); `.github/scripts/oci-tools.mjs` also exports `OWA_TEST_ZOT_BIN` in CI (#47). No dependency, engine or package version change. | tooling |
| **Specification clarifications** (`docs/spec-v0.2.md`, +53) | "Media type assignment" (#35) and "Entry types" (#41) added under Directory packing as **normative producer rules stating existing behaviour**; the issue-5 limitations list updated. No `specVersion`, media type, canonical-JSON or digest change. | specification |
| **Independent Go implementation** | `implementations/go-conformance/` (#32; updated by #35, #37, #39, #41, #43): stdlib-only Go 1.27 program with its own lane; `docs/independent-implementation.md` records surfaced ambiguities (three resolved by spec, others open — see decisions). | new implementation + evidence |
| **Conformance corpus** | +87 vectors, none pre-existing modified: `canonical.json` 28 → 107 (#39), `manifest.json` 149 → 150 (#39), `pack.json` 11 → 17 (#32 anchor, #35 media types), `blob.json` 10 → 11 (#37); `parse`/`path`/`request` unchanged; corpus notes extended. Expectations authored independently of production code (#39: independent exact-arithmetic verifier). | evidence |
| **Test harness** | new JS suites (`canonical-number`, `oci-index-ref`, `pack-media-type`, `pack-nonregular`, `pack-root-symlink`); process-isolated FIFO/socket and root-symlink tests (#41, #43); auth-startup readiness wait made event-driven after a demonstrated hang (#45); OCI harness with required-mode prerequisites and stub-registry lifecycle checks (#47). | evidence / reliability |
| **Authenticated HTTPS OCI** (#47) | third live OCI test; `tls-registry.js` test-only lifecycle; docs. | **additional evidence for existing behaviour** (no OWA transport, credential or TLS code) |

### Compatibility review

- **Changed acceptance/rejection: OCI reference selection only.** A layout whose
  `index.json` descriptors carry no `org.opencontainers.image.ref.name`
  annotation, imported with the default `--ref latest`, resolved to
  `manifests[0]` in v0.4.0 and now fails `OCI reference not found: latest`; a
  layout with several descriptors carrying the requested ref imported the first
  in v0.4.0 and now fails as ambiguous. ORAS-pulled layouts are unaffected (ORAS
  writes `ref.name` on every pull). Migration: annotate the intended descriptor
  or pass the `--ref` it carries; make duplicate refs distinct. Writer output is
  unchanged. This is a deliberate fail-closed correction (descriptor order was
  never identity) — the release must say so; it is **not** a release with "no
  behaviour changes".
- **No other acceptance/rejection change.** The entry-type rule and the
  media-type rule state existing behaviour; the root/ancestor-symlink work is a
  characterization; `packages/spec`, `server`, `cli`, `storage-*`, `gc` and
  `mcp` are untouched since `v0.4.0`.
- **Identities unchanged, verified vector by vector**: every vector present at
  `v0.4.0` (285 across the seven corpus files) is byte-identical at `main`; only
  file-level `notes` grew and 87 vectors were added. `docs/test-vectors/basic/*`
  is untouched (pinned hashes in [conformance/README.md](conformance/README.md)).
  Canonical JSON, artifact digest, `specVersion`, media type and the 18 error
  categories are unchanged; no stored manifest or release changes.
- **Version assessment: `v0.5.0` is appropriate.** Pre-1.0 semver: a *minor*
  bump is warranted by a deliberate behaviour change (stricter OCI reference
  selection), two new normative spec subsections, a new independent
  implementation and CI lane, and a materially larger corpus; a *patch* would
  understate the reference-selection change, and 1.0 is out of the question
  while the protocol is a draft and the software is experimental. The merged
  PRs already carried the `v0.5` label. Versions are **not** changed by this
  review.

### Readiness table (v0.5.0)

State values: **READY** · **DOCUMENTED LIMITATION** (accepted and written down;
not a blocker, not "done") · **BLOCKER** (must be resolved before a release cut)
· **MAINTAINER DECISION** (a human choice this document does not make and does
not presume).

| Category | State | Evidence / note |
| --- | --- | --- |
| Protocol identity | READY | Spec v0.2 draft with two normative producer subsections added; `specVersion` `owa.dev/v1`; media type unchanged; canonical JSON and digest algorithm unchanged; 285/285 pre-existing vectors and `basic/*` byte-identical. |
| Behaviour change disclosure | READY | The OCI reference-selection change is stated in `CHANGELOG.md` (Unreleased), [oci.md](oci.md#index-reference-selection) and the draft release notes with a migration path. |
| Package metadata | READY for bump | 13 `package.json` at `0.4.0`, all private, `engines.node >=22`; both package-local lockfiles record `0.4.0`; dependency versions unchanged (`@modelcontextprotocol/server` 2.0.0, `@modelcontextprotocol/client` 2.0.0, `@playwright/test` 1.63.0). The bump touches these plus the MCP server-info string (see the version-bump checklist). |
| Changelog | READY | `Unreleased` section describes all nine merged PRs from history; converts to `## 0.5.0 - <date>` at the release cut. No invented date. |
| Conformance corpus | READY | 384 conformance tests (297 at v0.4.0); +87 independently authored vectors; static anchors shared by both implementations. |
| Property testing | READY | Seeded `0x4f574132`, 424 scheduled iterations, unchanged. |
| Independent Go implementation | READY | `go-conformance (go 1.27, ubuntu)`: 435 passing tests/subtests at `main`, `gofmt`/`vet` clean, `go.mod` without `require`, `go list -deps` stdlib-only. |
| Cross-platform CI | READY | 10 checks green on the exact merge commit `2e5f743a` (see the run links in the #48 PR). |
| OCI registry interoperability | READY (ORAS v1.3.4 + Zot v2.1.21) / DOCUMENTED LIMITATION (scope) | Three live tests incl. authenticated HTTPS; limits: basic auth over verified TLS on loopback with one user; no token exchange, credential helpers, mTLS, authz semantics, other registries or production readiness. |
| Test-harness reliability | READY / DOCUMENTED LIMITATION | The demonstrated hang after a failed readiness wait (#44/#45) is fixed with regression tests; the **original** readiness miss (a spawned server not printing readiness within 15 s on one `ubuntu-latest` runner, once) is **unexplained** — logs were login-gated. Not a blocker: it has not recurred across the 8 subsequent full CI rounds, and the failure message now records the child's state for a recurrence. |
| Pack-root / ancestor symbolic links | MAINTAINER DECISION (policy) · DOCUMENTED LIMITATION (behaviour) | Both implementations follow a link supplied as the root; characterized by tests in both (#43), recorded as current behaviour, not normative. The #43 recommendation (keep outside the portable contract; do not adopt rejection) awaits the maintainer; no release blocker. |
| Duplicate JSON member names | MAINTAINER DECISION (whether to specify) · DOCUMENTED LIMITATION | Outside the corpus by design; each implementation discloses its parser policy ([independent-implementation.md](independent-implementation.md), [conformance/README.md](conformance/README.md#explicitly-deferred-not-fixed-by-issue-5)). |
| Filesystem names that are not valid Unicode | DOCUMENTED LIMITATION | Out of scope by the spec's own statement; rejected rather than guessed. |
| Real-provider and registry coverage | DOCUMENTED LIMITATION | R2 is operator-run evidence, not automatic CI; other S3-compatible providers and registries beyond ORAS v1.3.4 / Zot v2.1.21 untested. |
| Browser validation | READY (dated) / DOCUMENTED LIMITATION | Unchanged since v0.4.0 (Playwright 1.63.0, three engines); engine- and date-specific. |
| Filesystem / S3 storage, commit integrity, GC, auth, security profile, origin topology | READY / DOCUMENTED LIMITATION as recorded for v0.4.0 | No production change in these packages since `v0.4.0`; the v0.4.0 rows below still describe them. |
| Multi-tenant production hosting | DOCUMENTED LIMITATION | Not a production multi-tenant hosting service: shared CAS not tenant-private; TLS, secret custody, proxy logging, quotas are operator responsibilities; tokens replayable until expiry, no revocation/key ring. |
| Documentation | READY | README status block, `oci.md`, `ci.md`, `conformance/README.md`, `independent-implementation.md` updated by the merged PRs; this review adds the draft notes. README still says v0.4.0 until the bump. |
| License | READY | MIT, unchanged since `v0.4.0` (`git diff v0.4.0..main -- LICENSE` empty). |
| Distribution model | READY | Source-only, as v0.4.0 (proposal in the draft notes). |
| Repository settings / branch protection | MAINTAINER DECISION | Observed read-only on **2026-09-22** via public endpoints: `main` reports `protected: false` and `protection.enabled: false`; the public branch-rules endpoint lists **no rulesets** for `main`; wiki enabled, discussions disabled, issues enabled. The authenticated branch-protection detail and the `security_and_analysis` settings are **unverified** (authentication required). Nothing requires the 10 checks before merge or prevents a direct push; whether to change that is a settings decision this document does not make. |
| Governance / community files | MAINTAINER DECISION | `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.github/dependabot.yml` absent (checked 2026-09-22). Adding any is a governance follow-up outside a release PR. |
| **Blockers** | **none found** | No failing invariant, stale published digest, runtime behaviour contradicting the spec, security-control bypass or falsely-green lane was found in this review. |

### Decisions still open (recorded, not resolved here)

1. Root/ancestor-link policy: keep outside the portable contract (recommended in #43) or specify.
2. Duplicate JSON member names: keep outside the corpus with per-implementation disclosure, or specify a policy.
3. Branch protection / required checks for `main`; community/governance files.
4. Whether to investigate the unexplained readiness miss further (the narrow next step is documented in #45) or accept the diagnostic message as sufficient.
5. Approve `v0.5.0` as the version and authorize a release-cut PR.

### From approval to publication (exact steps)

1. **Release-cut PR** (metadata/docs only, base `main`): bump the 13 `package.json`
   versions and the two package-local lockfiles to `0.5.0`; update the MCP
   server-info string in `packages/mcp/src/adapter.js` and the MCP initialize
   assertion in `packages/mcp/test/helpers.js`; replace `## Unreleased` with
   `## 0.5.0 - <release date>` in
   `CHANGELOG.md` (keep the protocol-identity paragraph); remove the UNRELEASED
   marker from `release-notes-v0.5.0.md` and re-read it against the final
   changelog section; update the README status row and the "Current value"
   column above; run the local verification below with `VERSION=0.5.0`.
2. All **10** PR checks green; maintainer review; merge.
3. Resolve the merge commit and confirm all 10 `push` checks green **on that SHA**
   (Exact-commit verification above).
4. Complete the pre-tag checklist; create the annotated tag `v0.5.0` at that
   commit; push it.
5. Create the GitHub Release "Open Web Artifact v0.5.0" from the tag with the
   final release notes; no assets.
6. Post-tag verification below.

---

## Pre-tag checklist (any version)

Every item must hold **before** the tag is created. Pull-request checks alone are
**not** sufficient.

- [ ] The release-cut PR has been reviewed and merged.
- [ ] The exact reviewed `main` commit is recorded, and all **10** `push` checks completed green **on that commit** (not merely on the PR head).
- [ ] Zero open issues or pull requests that are release blockers.
- [ ] Every `package.json` version is exactly the release version and every package is `private: true`; both package-local lockfiles agree; the MCP server-info string agrees (verification script below).
- [ ] `CHANGELOG.md` has the final `<version> - <date>` section and no `Unreleased` marker for this release.
- [ ] `docs/test-vectors/basic/*` are byte-identical to the pinned hashes (`sha256sum docs/test-vectors/basic/*`).
- [ ] No secrets, temporary files, logs or local configuration are tracked (`git ls-files | grep -iE '\.env|\.log$|secret|credential'` is empty).
- [ ] `git status --porcelain` is empty on the checkout being tagged.
- [ ] The release notes for the version have been reviewed against the final `CHANGELOG.md` section and carry no UNRELEASED marker.

## Local release verification (any version)

From a clean checkout of the commit to be tagged (Node 22 or 24; Go 1.27 for the
Go lane):

```sh
npm run test:gc
npm test
npm run test:auth
npm run test:security
npm run test:conformance
npm run test:property
npm run test:integrity
npm run test:integration:harness
npm run test:integration
npm run test:oci
npm --prefix packages/mcp ci --ignore-scripts
npm run test:mcp
npm run test:go-conformance        # or: go -C implementations/go-conformance test ./... -count=1
git diff --check
```

Expected unconfigured behaviour: `npm run test:integration` reports its 7
provider cases as **skipped** (no R2/MinIO credentials), and `npm run test:oci`
reports its **three** live cases as **skipped** (no `OWA_TEST_OCI_REGISTRY` /
`OWA_TEST_ORAS_BIN` / `OWA_TEST_ZOT_BIN`). Every other suite must pass with zero
failures. Counts at the v0.5.0 review baseline (`2e5f743a`): `npm test` 1105,
auth 249, security 376, conformance 384, property 6 suites (424 iterations),
integrity 62, GC 51, integration harness 30, MCP 167, Go 435 passing
tests/subtests. The real MinIO, browser, ORAS/Zot and Go evidence is enforced in
GitHub Actions with skips turned into failures; it need not be reproduced on
every workstation ([ci.md](ci.md) explains how when wanted).

Package metadata check (no helper is committed; run inline with the version
being verified):

```sh
VERSION=0.4.0   # current released version; use 0.5.0 in the release-cut PR
for f in package.json packages/*/package.json; do
  node -e 'const [file,v]=process.argv.slice(1); const p=require(file); if (p.version!==v||p.private!==true) { console.error("FAIL", file, p.version, p.private); process.exit(1);} console.log("ok", file, p.version)' "./$f" "$VERSION"
done
for l in packages/*/package-lock.json; do
  node -e 'const [file,v]=process.argv.slice(1); const l=require(file); if (l.version!==v||l.packages[""].version!==v) { console.error("FAIL", file); process.exit(1);} console.log("ok", file, l.version)' "./$l" "$VERSION"
done
grep -n "version: '$VERSION'" packages/mcp/src/adapter.js   # MCP server-info string
sha256sum docs/test-vectors/basic/*
```

## Version-bump checklist (release-cut PR)

The bump is metadata and documentation only. It touches: the 13 `package.json`
files (root, `@owa/spec`, `core`, `cli`, `server`, `storage-filesystem`,
`storage-s3`, `transport-oci`, `conformance`, `integration`, `gc`, `mcp`,
`browser-tests`); `packages/mcp/package-lock.json` and
`packages/browser-tests/package-lock.json` (package version entries only, no
dependency change); the MCP server-info string in `packages/mcp/src/adapter.js`
and the MCP initialize assertion in `packages/mcp/test/helpers.js`; `CHANGELOG.md` (section header and date); the
release notes marker; the README status row; the "Current value" cell above.
It must not touch runtime behaviour, dependencies, workflows, corpus files,
`LICENSE` or protocol identity.

## Tag policy

- Tag name `v<version>`, pointing exactly at the final reviewed `main` release
  commit selected after its post-merge push workflows are green — never at a PR
  head or a later commit.
- Prefer an **annotated** tag when creating it with git/CLI, e.g.
  `git tag -a v0.5.0 <commit> -m "Open Web Artifact v0.5.0"` followed by
  `git push origin v0.5.0`. The repository has adopted no tag-signing policy;
  this document does not introduce one.
- Nothing in the repository creates tags automatically.

## GitHub Release policy

- Title: **`Open Web Artifact v<version>`**, attached to the tag.
- Body: the version's release notes (`docs/release-notes-v<version>.md`) after
  review, consistent with the final `CHANGELOG.md` section.
- Source-only: no manually uploaded binaries, npm artifact, container image or
  installers. GitHub's generated source archives are the distribution.
- The wording must keep the project **experimental**. GitHub's own "Latest"
  label is a mechanical marker for the most recent release, not a statement of
  production-hosting readiness.

## Post-tag verification

- [ ] `git rev-parse v<version>^{commit}` equals the selected final reviewed `main` release commit.
- [ ] The GitHub Release points at that tag and therefore at that commit.
- [ ] The release title is exactly `Open Web Artifact v<version>`.
- [ ] The source `.zip` and `.tar.gz` archives are available; no unexpected uploaded assets.
- [ ] Every link in the release notes resolves against the tagged tree.
- [ ] README links resolve at the tag; the README status block shows the released software version, spec v0.2 draft and `owa.dev/v1`.
- [ ] `CHANGELOG.md` at the tag carries the version section with its release date and matches the release notes.
- [ ] The release wording remains experimental; nothing claims production or multi-tenant hosting readiness.

---

## Release record — v0.4.0 (released 2026-09-21)

Tag `v0.4.0` (annotated) → commit `8a63b39ad10cebd1906209a9dae39f8bfcf488cb`;
GitHub Release "Open Web Artifact v0.4.0" published 2026-09-21T19:58:33Z, source
archives only; notes: [`release-notes-v0.4.0.md`](release-notes-v0.4.0.md). At
that time the CI architecture had **nine** checks (the Go conformance lane was
added afterwards by #32) and `npm run test:oci` had **two** live cases. The
readiness table below is preserved exactly as reviewed on 2026-09-21; its
observations are dated and are **not** current statements (the v0.5.0 table
above supersedes them).

| Category | State (as of 2026-09-21) | Evidence / note (as of 2026-09-21) |
| --- | --- | --- |
| Protocol identity | READY | Spec remains v0.2 draft; `specVersion` `owa.dev/v1`; media type `application/vnd.openwebartifact.site.v1+json`; canonical JSON and artifact digest unchanged. `docs/test-vectors/basic/*` byte-identical (whole-file SHA-256 pinned in [conformance/README.md](conformance/README.md)). |
| Package metadata | READY | 13 `package.json` files all `0.4.0`, all `private: true`, all `engines.node >=22`; the two package-local lockfiles (`packages/mcp`, `packages/browser-tests`) record `0.4.0`; dependency versions unchanged (`@modelcontextprotocol/server` 2.0.0, `@modelcontextprotocol/client` 2.0.0, `@playwright/test` 1.63.0). No workspaces, no package manager tooling. |
| MCP server-info version string | READY | `packages/mcp/src/adapter.js` advertises `{ name: 'owa-mcp', version: '0.4.0' }` to MCP clients, and the official SDK initialize test asserts that version at the protocol boundary. This is software metadata only; it does not affect the OWA protocol. |
| Changelog | READY | `CHANGELOG.md` has the final `## 0.4.0 - 2026-09-21` section summarizing merged work since 0.2.0; no invented 0.3.0 release (none was ever tagged); older sections intact. |
| Conformance corpus | READY | Portable `owa-conformance-v1` corpus under `docs/conformance/v0.2/` (canonical, parse, manifest, path, request, pack, blob) incl. Unicode pack-ordering and duplicate-content OCI anchors; `npm run test:conformance` 297 tests; static expectations authored independently of production code. |
| Property testing | READY | Seeded (`0x4f574132`) deterministic properties, 424 scheduled iterations (`npm run test:property`); no wall-clock randomness. |
| Cross-platform CI | READY | `CI` workflow: `offline (ubuntu\|macos\|windows-latest, node 22\|24)` — 6 required cells, secretless, `pull_request` + `push: main`. See [ci.md](ci.md). |
| Filesystem storage | READY | Reference filesystem blob/metadata stores; commit-boundary integrity via streaming rehash; conservative GC; leases. |
| S3 storage | READY (mediated default) / DOCUMENTED LIMITATION (enforced mode) | Dependency-free SigV4 signer checked against Amazon's published test vector; default `checksumEvidence=advisory` + `directUploadIntegrity=mediated` is safe for any provider; `enforced` is only for providers verified to honour `x-amz-checksum-sha256` (MinIO at the pinned tag qualifies; AWS S3 documented but not live-verified). See [integrity.md](integrity.md). |
| R2 evidence | DOCUMENTED LIMITATION | Cloudflare R2 is **operator-run** evidence recorded in [integrity.md](integrity.md) and [integration-tests.md](integration-tests.md), intentionally **not** automatic pull-request CI (no hosted credentials in CI). |
| MinIO evidence | READY | `MinIO` workflow builds MinIO from the pinned source tag `RELEASE.2025-10-15T17-29-55Z` and runs the live suite in default-mediated and explicitly-enforced modes with skips turned into failures. |
| Browser validation | READY (dated evidence) / DOCUMENTED LIMITATION (scope) | `Browsers` workflow runs `packages/browser-tests` in Chromium 153.0.8010.12, Firefox 155.0 and WebKit 26.6 (Playwright 1.63.0) with every engine required. Evidence is engine- and date-specific for the documented static-preview contract; it is not proof against browser vulnerabilities or future-browser behaviour. See [sandboxed-web-v1-browser-validation.md](sandboxed-web-v1-browser-validation.md). |
| OCI registry interoperability | READY (ORAS v1.3.4 + Zot v2.1.21) / DOCUMENTED LIMITATION (scope) | `OCI` workflow: layout → real ORAS → real loopback Zot → real ORAS → import → serve, by tag and by digest, incl. duplicate-content entries; skips are failures. Plain-HTTP loopback only: registry auth, TLS, signatures, referrers and other registries are outside the proof. See [oci.md](oci.md). |
| Authentication | DOCUMENTED LIMITATION | Capability-scoped HMAC bearer tokens, required by default, explicit loopback-only dev mode. Tokens are replayable until expiry; no per-token revocation, audience claim, key ID/key ring or multi-key rotation overlap. See [auth.md](auth.md#limits-and-trust-boundary). |
| Security profile | DOCUMENTED LIMITATION | `sandboxed-web-v1` is a **script-disabled static-preview** profile on every application response; it does not make interactive apps work and does not undo pre-existing service workers, caches or saved copies. See [sandboxed-web-v1.md](sandboxed-web-v1.md) and its [threat model](sandboxed-web-v1-threat-model.md). |
| Origin topology | READY (content-only listener) / DOCUMENTED LIMITATION (legacy mode) | A configured content origin binds one `Host` to one site and exposes no control route; without it the server runs the legacy shared-origin prototype (`?site=`, control routes on every host) and warns. Production requires clean, cookieless content origins separate from control. See [origins.md](origins.md). |
| Commit-boundary integrity | READY | A release is persisted only after every unique blob is strongly verified against manifest SHA-256 **and** size (provider checksum evidence on S3/R2, streaming rehash otherwise); direct-upload grants are checksum-bound and create-once. See [integrity.md](integrity.md). |
| Direct-upload trust model | READY (defaults) / DOCUMENTED LIMITATION (operator choice) | Mediated by default; `enforced` only after provider verification; misconfiguration fails startup. |
| GC / leases | READY (conservative) / DOCUMENTED LIMITATION (no retention) | Mark/sweep collector, dry-run by default, every stored release is a root; publish leases protect plan → upload → commit. Release retention/pruning is deliberately not implemented. See [gc.md](gc.md). |
| CLI | READY | Local and remote publish, releases, activation/rollback, `export-oci` / `import-oci`; no registry push/pull/login commands (ORAS is the transport). |
| MCP | READY (optional) | Optional, package-local stdio adapter over the same authenticated HTTP API; server-info advertises software version `0.4.0`; three locked third-party runtime packages installed only with the adapter. See [mcp.md](mcp.md). |
| Documentation | READY | README status block distinguishes software v0.4.0 from spec v0.2; stale status statements corrected in the release-prep PR; limitations kept visible. |
| Multi-tenant production hosting | DOCUMENTED LIMITATION | The reference server is **not** a production multi-tenant hosting service: shared CAS is not tenant-private, TLS/secret custody/proxy logging/quotas are operator responsibilities. |
| License | READY | MIT (`LICENSE`), unchanged. |
| Distribution model | READY | Source-only release; all packages private; GitHub source archives only (see above). |
| Repository settings / branch protection | REQUIRES MAINTAINER DECISION | `main` has **no branch protection** (verified 2026-09-21 via the public API: `protected: false`). The nine CI checks exist and run on every PR and push, but nothing requires them before merge and nothing prevents a direct push or force-push to `main`. Deciding whether to protect `main` and require the nine checks is a repository-settings choice this document does not make. |
| Governance / community files | REQUIRES MAINTAINER DECISION | No `SECURITY.md`, `CONTRIBUTING.md` or `CODE_OF_CONDUCT.md` exists. Adding any of them is a maintainer/governance follow-up outside the release-prep PR. |
