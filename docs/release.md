# Release process

This is the maintainer checklist for tagging and publishing a software release of
the Open Web Artifact reference implementation. It is a checklist, not an
automation: no workflow creates tags or releases, and this document does not
authorize one. The first tagged release is **v0.4.0**.

## Version domains

Three version numbers live in this repository and they do **not** move together:

| Domain | Current value | Where it lives | What moves it |
| --- | --- | --- | --- |
| **Software / reference implementation** | **v0.4.0** (release candidate until tagged) | every `package.json` `version`, `CHANGELOG.md`, the Git tag, the GitHub Release title | a software release |
| **Protocol / specification draft** | **v0.2 (Draft)** | [`docs/spec-v0.2.md`](spec-v0.2.md), the conformance corpus under `docs/conformance/v0.2/` | a new spec draft, decided separately |
| **Manifest `specVersion`** | **`owa.dev/v1`** with media type `application/vnd.openwebartifact.site.v1+json` | `packages/spec/src/index.js`, every manifest | an incompatible manifest change, decided separately |

v0.4.0 is a software version. The protocol the software implements is still the
v0.2 draft and every manifest still says `owa.dev/v1`. Do not describe the
protocol as "v0.4", and do not bump `specVersion` or the media type as part of
a software release. Canonical JSON, the artifact digest algorithm and all
published artifact identities are unchanged by this release.

## Distribution model

v0.4.0 is a **source / reference-implementation release**:

- every repository package stays `"private": true`; nothing is published to npm;
- no `publishConfig`, publish script, provenance attestation or release workflow;
- no container image, platform binary, installer or downloadable bundle;
- GitHub's ordinary auto-generated source archives (`.zip` / `.tar.gz`) for the
  tag are the distribution.

Anything beyond that is a separate, explicitly approved packaging issue.

## Release-readiness table (v0.4.0)

State values: **READY** · **DOCUMENTED LIMITATION** (accepted and written down;
not a blocker, not "done") · **REQUIRES MAINTAINER DECISION** (a human choice
this checklist does not make).

| Category | State | Evidence / note |
| --- | --- | --- |
| Protocol identity | READY | Spec remains v0.2 draft; `specVersion` `owa.dev/v1`; media type `application/vnd.openwebartifact.site.v1+json`; canonical JSON and artifact digest unchanged. `docs/test-vectors/basic/*` byte-identical (whole-file SHA-256 pinned in [conformance/README.md](conformance/README.md)). |
| Package metadata | READY | 13 `package.json` files all `0.4.0`, all `private: true`, all `engines.node >=22`; the two package-local lockfiles (`packages/mcp`, `packages/browser-tests`) record `0.4.0`; dependency versions unchanged (`@modelcontextprotocol/server` 2.0.0, `@modelcontextprotocol/client` 2.0.0, `@playwright/test` 1.63.0). No workspaces, no package manager tooling. |
| MCP server-info version string | REQUIRES MAINTAINER DECISION | `packages/mcp/src/adapter.js` advertises `{ name: 'owa-mcp', version: '0.3.0' }` to MCP clients. Aligning it to `0.4.0` (or deriving it from `package.json`) is a one-line runtime-source change, deliberately **not** made in the metadata-only release-prep PR. Decide before or after the tag; it does not affect the OWA protocol. |
| Changelog | READY | `CHANGELOG.md` has `## 0.4.0 - Unreleased` summarizing merged work since 0.2.0; no invented 0.3.0 release (none was ever tagged); older sections intact. The date is filled in at tag time. |
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
| MCP | READY (optional) / see server-info row | Optional, package-local stdio adapter over the same authenticated HTTP API; three locked third-party runtime packages installed only with the adapter. See [mcp.md](mcp.md). |
| Documentation | READY | README status block distinguishes software v0.4.0 from spec v0.2; stale status statements corrected in the release-prep PR; limitations kept visible. |
| Multi-tenant production hosting | DOCUMENTED LIMITATION | The reference server is **not** a production multi-tenant hosting service: shared CAS is not tenant-private, TLS/secret custody/proxy logging/quotas are operator responsibilities. |
| License | READY | MIT (`LICENSE`), unchanged. |
| Distribution model | READY | Source-only release; all packages private; GitHub source archives only (see above). |
| Repository settings / branch protection | REQUIRES MAINTAINER DECISION | `main` has **no branch protection** (verified 2026-09-21 via the public API: `protected: false`). The nine CI checks exist and run on every PR and push, but nothing requires them before merge and nothing prevents a direct push or force-push to `main`. Deciding whether to protect `main` and require the nine checks is a repository-settings choice this document does not make. |
| Governance / community files | REQUIRES MAINTAINER DECISION | No `SECURITY.md`, `CONTRIBUTING.md` or `CODE_OF_CONDUCT.md` exists. Adding any of them is a maintainer/governance follow-up outside the release-prep PR. |

## Pre-tag checklist

Every item must hold **before** the tag is created. Pull-request checks alone are
**not** sufficient: after the release-prep PR merges, `main`'s own `push`
workflows must run and complete green on the exact merge commit.

- [ ] The release-prep PR (closes #27) has been reviewed and merged.
- [ ] The `main` commit to be tagged is recorded here: `__________`.
- [ ] Post-merge `main` GitHub Actions — `CI` (6 cells), `MinIO`, `Browsers`, `OCI` — have all **completed green on that commit** (not merely on the PR head).
- [ ] Zero unexpected open issues or pull requests that are release blockers.
- [ ] Every `package.json` version is exactly `0.4.0` and every package is `private: true` (see the verification script below).
- [ ] `CHANGELOG.md` has the `0.4.0` section; replace `Unreleased` with the tag date at tag time.
- [ ] `docs/test-vectors/basic/*` are byte-identical to the pinned hashes (`sha256sum docs/test-vectors/basic/*`).
- [ ] No secrets, temporary files, logs or local configuration are tracked (`git ls-files | grep -iE '\.env|\.log$|secret|credential'` is empty).
- [ ] `git status --porcelain` is empty on the checkout being tagged.
- [ ] [`release-notes-v0.4.0.md`](release-notes-v0.4.0.md) has been reviewed and reflects the final `CHANGELOG.md`.

## Local release verification

From a clean checkout of the commit to be tagged (Node 22 or 24):

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
git diff --check
```

Expected unconfigured behaviour: `npm run test:integration` reports its provider
cases as **skipped** (no R2/MinIO credentials or endpoints configured), and
`npm run test:oci` reports its two live cases as **skipped** (no
`OWA_TEST_OCI_REGISTRY` / `OWA_TEST_ORAS_BIN`). Every other suite must pass with
zero failures. The real MinIO, browser and ORAS/Zot evidence is enforced
continuously in GitHub Actions with skips turned into failures; it does not need
to be reproduced on every maintainer workstation (see [ci.md](ci.md) for how to
reproduce each lane locally when wanted).

Package metadata check (no helper is committed; run inline):

```sh
for f in package.json packages/*/package.json; do
  node -e 'const p=require(process.argv[1]); if (p.version!=="0.4.0"||p.private!==true) { console.error("FAIL", process.argv[1], p.version, p.private); process.exit(1);} console.log("ok", process.argv[1], p.version)' "./$f"
done
for l in packages/*/package-lock.json; do
  node -e 'const l=require(process.argv[1]); if (l.version!=="0.4.0"||l.packages[""].version!=="0.4.0") { console.error("FAIL", process.argv[1]); process.exit(1);} console.log("ok", process.argv[1], l.version)' "./$l"
done
sha256sum docs/test-vectors/basic/*
```

## Tag policy

- Proposed tag: **`v0.4.0`**.
- The tag MUST point exactly at the final reviewed `main` release commit recorded
  in the pre-tag checklist — never at a PR head or a later commit.
- Prefer an **annotated** tag when creating it with git/CLI, e.g.
  `git tag -a v0.4.0 <commit> -m "Open Web Artifact v0.4.0"` followed by
  `git push origin v0.4.0`. The repository has adopted no tag-signing policy;
  this document does not introduce one.
- Nothing in the repository creates tags automatically. No tag is created by the
  release-prep issue itself.

## GitHub Release policy

- Title: **`Open Web Artifact v0.4.0`**, attached to tag `v0.4.0`.
- Body: [`release-notes-v0.4.0.md`](release-notes-v0.4.0.md) (after review; keep
  it consistent with the final `CHANGELOG.md` section).
- Source-only: no manually uploaded binaries, no npm artifact, no container
  image, no platform installers. GitHub's generated source archives are the
  distribution.
- The wording must keep the project **experimental**. GitHub's own
  "Latest" label is a mechanical marker for the most recent release, not a
  statement of production-hosting readiness; the release text must not imply
  otherwise.

## Post-tag verification

- [ ] `git rev-parse v0.4.0^{commit}` equals the recorded `main` release commit.
- [ ] The GitHub Release points at tag `v0.4.0` and therefore at that commit.
- [ ] The release title is exactly `Open Web Artifact v0.4.0`.
- [ ] The source `.zip` and `.tar.gz` archives are available from the release page.
- [ ] No unexpected uploaded assets exist on the release.
- [ ] Every link in the release notes resolves (docs paths against the tagged tree).
- [ ] README links resolve at the tag; the README status block still says software v0.4.0 / spec v0.2 draft / `owa.dev/v1`.
- [ ] `CHANGELOG.md` at the tag carries the `0.4.0` section with the release date and matches the release notes.
- [ ] The release wording remains experimental; nothing claims production or multi-tenant hosting readiness.
