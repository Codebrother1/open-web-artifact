# Continuous integration

The repository runs five **independent** GitHub Actions workflows on every pull
request, on every push to `main`, and on demand (`workflow_dispatch`). They are
deliberately separate so that an offline failure never hides whether the MinIO,
browser, OCI or Go-conformance lanes are healthy, and vice versa.

Automatic CI is **secretless**: it uses ordinary `pull_request` events (never
`pull_request_target`), a read-only token (`permissions: contents: read`), no
repository secrets, and no hosted-storage credentials. Cloudflare R2 is
**intentionally excluded** from automatic CI; see [R2](#r2-is-not-in-automatic-ci).

| Workflow | File | Job / check name | Runner(s) | Timeout |
| --- | --- | --- | --- | --- |
| `CI` | `.github/workflows/ci.yml` | `offline (<os>, node <22\|24>)` — 6 cells | `ubuntu-latest`, `macos-latest`, `windows-latest` | 15 min |
| `MinIO` | `.github/workflows/minio.yml` | `minio (mediated + enforced, node 24)` | `ubuntu-latest` | 25 min |
| `Browsers` | `.github/workflows/browser.yml` | `browsers (chromium, firefox, webkit)` | `ubuntu-latest` | 25 min |
| `OCI` | `.github/workflows/oci.yml` | `oci (oras + zot, node 24)` | `ubuntu-latest` | 15 min |
| `Go conformance` | `.github/workflows/go-conformance.yml` | `go-conformance (go 1.27, ubuntu)` | `ubuntu-latest` | 10 min |

Each workflow has its own concurrency group (`ci-offline-*`, `ci-minio-*`,
`ci-browsers-*`, `ci-oci-*`, `ci-go-conformance-*`, keyed by PR number or ref)
with `cancel-in-progress: true`, so a newer push cancels only that workflow's
stale run for the same PR — one workflow never cancels another.

## Pinned actions and services

Every GitHub Action is referenced by an immutable commit SHA with the release it
corresponds to beside it. Only GitHub-maintained actions are used; everything
else is `node`, `npm`, `git` and shell.

| Action | Commit SHA | Release |
| --- | --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `v7.0.1` |
| `actions/setup-node` | `820762786026740c76f36085b0efc47a31fe5020` | `v7.0.0` |
| `actions/setup-go` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | `v7.0.0` |

Checkout is always used with `persist-credentials: false` so the job token is
not left in the checkout. No cache action is used: measured first-run times fit
the timeouts, and a cache can be added later without changing any test
(`setup-go` runs with `cache: false`; the Go module has no dependencies to
cache).

The MinIO service is pinned to a **source commit**, not a floating tag, and the
Playwright engines come from the exact package-local lockfile — see the lane
descriptions below.

## Job summaries

Every `node --test` script in the root `package.json` runs the ordinary `spec`
reporter on stdout **plus** `.github/scripts/test-summary-reporter.mjs`, which is
a no-op unless `GITHUB_STEP_SUMMARY` is set (only inside Actions). There it
appends, per script, the pass/fail/skip counts and each failing test's name,
location and full error to the job summary shown on the run page. The browser
suite's evidence reporter does the same with its engine versions, behaviour
matrix and any failing cell's diagnostics. Failures are therefore readable from
the public run page without downloading raw logs; the suites print no
credentials, signed URLs or provider bodies by construction, so nothing
sensitive can land in a summary.

## Lane 1 — `CI`: offline cross-platform correctness

Six matrix cells, none `continue-on-error`:

| | Node 22 | Node 24 |
| --- | --- | --- |
| `ubuntu-latest` | ✓ | ✓ |
| `macos-latest` | ✓ | ✓ |
| `windows-latest` | ✓ | ✓ |

Each cell runs, as separate steps for attribution: `npm test`, `test:auth`,
`test:security`, `test:conformance`, `test:property`, `test:integrity`,
`test:gc`, `test:integration:harness`, `test:integration`, then installs the
package-local MCP dependencies (`npm --prefix packages/mcp ci --ignore-scripts`)
and runs `test:mcp`, then `git diff --check` and a clean-working-tree check.
MCP therefore runs on **all six** OS × Node cells; its dependencies stay in
`packages/mcp`, and the repository root still has no dependencies to install.

Two portability details are handled in the workflow rather than in code:

- `git config --global core.autocrlf false` runs **before** checkout. Git for
  Windows would otherwise rewrite text files to CRLF, and fixture bytes, blob
  digests and canonical-JSON vectors must be byte-identical on every platform.
- Every step is a single portable `node`/`npm`/`git` command, so the default
  shell (bash on Linux/macOS, PowerShell on Windows) needs no shell-specific
  syntax. Checks that would need a shell (`test -z "$(git status …)"`) are small
  Node scripts under `.github/scripts/`.

`npm run test:integration` runs **unconfigured** in this lane. A preflight
(`assert-no-live-config.mjs`) fails the job if any `OWA_TEST_*` or `OWA_S3_*`
variable is present, so the live provider cases can only **skip** — they can
never reach R2, MinIO or any hosted service from the offline lane. Expected
result: 7 tests, 0 passed, 7 skipped (3 R2 cases, 3 MinIO cases, 1 MinIO
virtual-host case).

## Lane 2 — `MinIO`: real, secretless storage integration

A **real MinIO server** runs inside the job on `127.0.0.1:9000`.

**Version and immutability.** The release under test is
`RELEASE.2025-10-15T17-29-55Z`, the same release live-proven in the integrity
work (#10/#18). That release has **no published artifact left to pin** —
`dl.min.io` answers 410, the GitHub release has no assets, and neither Docker
Hub nor quay.io carries the tag — so the job builds MinIO from the official
source repository at the tag's commit and verifies the identity twice:

1. `git clone --branch RELEASE.2025-10-15T17-29-55Z` must resolve to commit
   **`9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`** (`git rev-parse HEAD` is
   compared; a mismatch fails the job);
2. the binary is built with MinIO's own Makefile recipe (`-tags kqueue
   -trimpath`, ldflags from `buildscripts/gen-ldflags.go` with
   `MINIO_RELEASE=RELEASE`) and `minio --version` must report
   `RELEASE.2025-10-15T17-29-55Z` together with commit
   `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`.

The Go toolchain is pinned too: `GOTOOLCHAIN=go1.24.8` (the `toolchain` line of
MinIO's `go.mod` at that commit), fetched through the Go module proxy and
verified against the Go checksum database; `go version` and the binary's SHA-256
are printed in the log. Build takes a few minutes; the job timeout allows for it.

**Credentials.** The root user and password are random values generated inside
the job with `node:crypto`, masked with `::add-mask::`, passed to later steps via
the runner-local `GITHUB_ENV` file, and destroyed with the runner. They are not
repository secrets, and MinIO's startup banner (which echoes them) is never
printed. Only the documented `OWA_TEST_MINIO_*` variables are set; a preflight
fails the job if any `OWA_TEST_R2_*` or `OWA_S3_*` variable exists.

**Startup and bucket.** `.github/scripts/minio-bucket.mjs` (Node, using the
repository's own `S3BlobStore` SigV4 signer — no `mc`, no vendor SDK) waits for
the real `/minio/health/ready` endpoint, creates the disposable bucket
`owa-ci-integration`, and fails the job if either does not succeed.

**Two runs of `npm run test:integration`:**

| Mode | Extra variables | Effective store capabilities | What the suite proves |
| --- | --- | --- | --- |
| **A — default safe** | none | `checksumEvidence=advisory`, `directUploadIntegrity=mediated` | publishers receive only artifactd's scoped grant (no presigned storage URL); wrong bytes are refused by artifactd and never reach MinIO; artifactd writes verified bytes; commit, repair and identical re-plan work; post-commit replay cannot corrupt CAS; zero OWA bearer reaches MinIO |
| **B — explicitly verified direct** | `OWA_TEST_MINIO_CHECKSUM_EVIDENCE=enforced`, `OWA_TEST_MINIO_DIRECT_UPLOAD_INTEGRITY=enforced` | `enforced` / `enforced` | direct checksum-bound (`x-amz-checksum-sha256`) create-once (`If-None-Match: *`) grants; wrong payload refused by MinIO; repair grants safe; post-commit replay refused (`412`/`400`); commit needs zero payload transfer; zero OWA bearer |

**Proof the MinIO cases ran, not skipped.** Both runs set
`OWA_TEST_REQUIRE_PROVIDERS=MINIO`. This **test-harness-only** switch
(`packages/integration/src/providers.js`) turns a would-be skip for the listed
provider into a **test failure** — so an exit code of 0 means the MinIO
publishing, integrity and GC cases actually executed. The virtual-host case has
its own token (`MINIO_VIRTUAL`) and keeps skipping cleanly; the R2 cases skip
because R2 is never configured. Expected result per mode: 7 tests, 3 passed,
4 skipped. Production code never reads this variable.

**Cleanup.** After each mode `minio-bucket.mjs assert-empty` lists the whole
bucket and fails if any object remains (the suites already assert their own
UUID-isolated prefixes are empty). A final step fails the job if MinIO exited
before shutdown, then stops it; data, source and binary are removed in
`if: always()` steps. Nothing from the service is uploaded as an artifact.

Virtual-host addressing is not exercised in CI: it would require making
`<bucket>.localhost` resolve on the runner and setting `MINIO_DOMAIN`, and the
issue asks not to make CI brittle for that optional case. Path-style mediated +
enforced coverage is the requirement and is what runs.

## Lane 3 — `Browsers`: Chromium, Firefox **and WebKit**

Runs the isolated [`packages/browser-tests`](../packages/browser-tests/README.md)
suite — the real content-only listener, adversarial artifacts, loopback-only —
in all three Playwright engines. The steps:

1. `npm --prefix packages/browser-tests ci --ignore-scripts` — exact versions
   from the package-local lockfile (Playwright **1.63.0**). The root and the
   runtime packages never depend on Playwright.
2. `npm --prefix packages/browser-tests run install-browsers:deps` — Playwright's
   own `install --with-deps chromium firefox webkit`, invoked through the
   package's pinned CLI, installing the Linux system libraries with the runner's
   `apt`. No other Playwright version is used anywhere.
3. `npm --prefix packages/browser-tests run versions -- --require chromium,firefox,webkit`
   — really launches each engine and prints the exact Playwright, Chromium,
   Firefox, WebKit, Node and OS versions; **an engine that cannot start fails the
   job**.
4. `OWA_BROWSERS=chromium,firefox,webkit npm run test:browser` — the full suite;
   any failing test, including in WebKit, fails the job.
5. `.github/scripts/assert-browser-evidence.mjs` — reads the suite's JSON
   evidence record and fails unless every one of the three engines reported a
   real version and every row is `PASS` or `EXPECTED LIMIT`. A `NOT RUN`, `SKIP`
   or `FAIL` cell for any engine fails the job even if Playwright's exit code was
   zero.

Nothing about WebKit is optional: no `continue-on-error`, no allowed failure,
no reduced engine list. This lane is what supplies the WebKit evidence that the
issue #19 development host could not (its glibc was too old to start WebKit).
Traces, videos, screenshots, downloaded fixtures and browser caches are not
uploaded; the tests' own egress guard keeps execution loopback-only.

## Lane 4 — `OCI`: live registry interoperability with ORAS and Zot

Proves `OWA directory → packDirectory → writeOciLayout → ORAS → Zot → ORAS →
fresh layout → readOciLayout → import-oci → serve` against a **real** registry;
see [oci.md](oci.md) for the representation, commands and claims.

- **Tools, pinned and verified before execution** by `.github/scripts/oci-tools.mjs`
  (plain Node; no `curl | sh`, no third-party action): ORAS **v1.3.4**
  (`oras_1.3.4_linux_amd64.tar.gz`, SHA-256
  `f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454`, listed in
  `oras_1.3.4_checksums.txt`, SHA-256
  `19d479e497fb5e30c7de3c621e3ed337e3857de0d96542021a73e2d8016dbe5a`) and Zot
  **v2.1.21** (`zot-linux-amd64`, SHA-256
  `8751cc0daf739634835a3bd8206e3094c84d552e2c462e4a4baf80f40dd92685`, listed in
  `checksums.sha256.txt`, SHA-256
  `dc91ac8283cc04f778d642aa4b51d46e6a1e4b05205825256291d05159cf4755`), both from
  their official GitHub releases. A hash mismatch fails the job; nothing is
  extracted or made executable before its hash matched. `oras version` and
  `zot --version` are printed and published as a `::notice`.
- **Registry**: `.github/scripts/zot.mjs start` writes a minimal config under
  `RUNNER_TEMP` (`distSpecVersion 1.1.1`, disposable storage, `gc: false`, no
  UI/search/sync/auth/metrics/remote storage), starts Zot on **127.0.0.1** with an
  **ephemeral port**, waits until `GET /v2/` answers 200 (bounded), and exports
  `OWA_TEST_OCI_REGISTRY`. Plain HTTP, unauthenticated, loopback only — this is
  an interoperability harness, not a deployment.
- **Authenticated HTTPS registry** (issue #46): `authenticated-tls.test.js`
  starts a *second* Zot from the same verified binary (`OWA_TEST_ZOT_BIN`, also
  exported by `oci-tools.mjs`) with TLS — a temporary test CA and a server
  certificate for `IP:127.0.0.1`/`DNS:localhost` generated by the runner's
  `openssl` — and htpasswd authentication required for every repository, using
  one synthetic user whose random password exists only for that run inside the
  test's temporary directory (bcrypt entry via the runner's `perl` and
  `crypt(3)`). The test stops the process and removes keys, certificate,
  htpasswd file, storage and log itself, on failure too.
- **Suite**: `OWA_TEST_OCI_REQUIRED=1 npm run test:oci` — with the required flag,
  a missing ORAS or Zot binary, a missing `openssl` or `perl`, a missing/unready
  registry or any failing ORAS command is a **failure**, never a skip. A
  postflight fails the job if the plain-HTTP Zot exited before shutdown;
  `if: always()` cleanup stops it and removes registry storage, config and the
  downloaded tools. Nothing from either registry is uploaded.
- Two preflights keep the lane secretless: `assert-no-live-config.mjs` rejects
  any `OWA_TEST_*`/`OWA_S3_*` configuration before the tools are installed, and no
  `secrets.*` reference exists. No hosted registry is contacted after the two
  release downloads. The only registry login anywhere is `oras login` against
  the disposable loopback HTTPS Zot, with the per-run synthetic password on
  stdin into an isolated `--registry-config` file — never the runner's or a
  user's Docker/ORAS configuration, never a hosted registry.

## Lane 5 — `Go conformance`: an independent implementation runs the same corpus

Proves that the published specification and static corpus are precise enough
for a **second implementation in another language** to derive the same results.
`implementations/go-conformance` is a standard-library-only Go implementation
written from [spec-v0.2.md](spec-v0.2.md), the [conformance guide](conformance/README.md),
[oci.md](oci.md) and the static vectors — never from the JavaScript packages
(see [independent-implementation.md](independent-implementation.md)).

- **Toolchain**: `actions/setup-go` pinned by commit SHA installs Go **1.27**
  (major/minor pinned, `check-latest: false`, no cache). The job prints
  `go version`.
- **Independence proof**: a step fails the job if `go.mod` acquires a `require`
  directive or if `go list -deps` reports any non-standard-library import. No
  Node, npm or repository JavaScript runs in this lane; the Go tests read only
  `docs/conformance/v0.2/*.json` and `docs/test-vectors/basic/*`.
- **Checks**: `gofmt -l` must be empty, `go vet ./...` clean, then
  `go test ./... -count=1 -v` — one subtest per corpus vector (286 vectors across
  the 7 corpus files, plus the immutable basic vectors and independent
  regression anchors), with `TestCorpusCoverage` failing if any corpus file has
  no Go harness. Skipping is not possible: the harness has no skip path.
- **Rendezvous with the JavaScript reference**: the static vector
  `pack-cross-language-anchor` is checked by this lane and by the offline lane's
  `npm run test:conformance` from the same checked-in bytes; the two
  implementations never call each other.

## R2 is not in automatic CI

The live Cloudflare R2 suites (`OWA_TEST_R2_*`) need real credentials. Giving
them to code that arrives in a pull request would hand a reusable hosted secret
to untrusted changes, so **no workflow sets any `OWA_TEST_R2_*` variable, no
repository secret exists for R2, and `pull_request_target` is not used**. Two
preflights enforce this: the offline lane rejects any live configuration, and
the MinIO lane rejects anything but its own disposable `OWA_TEST_MINIO_*`
variables. R2 remains operator-run evidence (see
[integration-tests.md](integration-tests.md) and the recorded runs in
[integrity.md](integrity.md)); a separately reviewed, trusted, manually
triggered R2 workflow can be added later. R2 is **not** continuously tested.

## Reproducing each lane locally

```sh
# Lane 1 — any OS, Node 22 or 24 (no live variables set)
node .github/scripts/assert-no-live-config.mjs
npm test && npm run test:auth && npm run test:security && npm run test:conformance
npm run test:property && npm run test:integrity && npm run test:gc
npm run test:integration:harness && npm run test:integration
npm --prefix packages/mcp ci --ignore-scripts && npm run test:mcp
git diff --check && node .github/scripts/assert-clean-tree.mjs

# Lane 2 — Linux/macOS with Go available (GOTOOLCHAIN fetches go1.24.8)
#   build MinIO exactly as the workflow does (see .github/workflows/minio.yml),
#   start it on 127.0.0.1:9000 with generated MINIO_ROOT_USER/PASSWORD, then:
export OWA_TEST_MINIO_ENDPOINT=http://127.0.0.1:9000 OWA_TEST_MINIO_BUCKET=owa-ci-integration OWA_TEST_MINIO_REGION=us-east-1
export OWA_TEST_MINIO_ACCESS_KEY_ID=... OWA_TEST_MINIO_SECRET_ACCESS_KEY=...   # the generated values
node .github/scripts/minio-bucket.mjs ready && node .github/scripts/minio-bucket.mjs create
OWA_TEST_REQUIRE_PROVIDERS=MINIO npm run test:integration                     # mode A
node .github/scripts/minio-bucket.mjs assert-empty
OWA_TEST_REQUIRE_PROVIDERS=MINIO OWA_TEST_MINIO_CHECKSUM_EVIDENCE=enforced \
  OWA_TEST_MINIO_DIRECT_UPLOAD_INTEGRITY=enforced npm run test:integration    # mode B
node .github/scripts/minio-bucket.mjs assert-empty

# Lane 3 — Ubuntu 22.04/24.04 (or another host Playwright 1.63.0 supports)
npm --prefix packages/browser-tests ci --ignore-scripts
npm --prefix packages/browser-tests run install-browsers:deps
npm --prefix packages/browser-tests run versions -- --require chromium,firefox,webkit
OWA_BROWSERS=chromium,firefox,webkit OWA_BROWSER_EVIDENCE_JSON=/tmp/evidence.json npm run test:browser
node .github/scripts/assert-browser-evidence.mjs /tmp/evidence.json chromium,firefox,webkit

# Lane 4 — Linux x86-64 (the pinned release assets are linux/amd64)
node .github/scripts/assert-no-live-config.mjs
node .github/scripts/oci-tools.mjs /tmp/oci-tools            # downloads + SHA-256-verifies ORAS v1.3.4 and Zot v2.1.21
node .github/scripts/zot.mjs start /tmp/oci-tools/zot-linux-amd64 /tmp/zot-state
export OWA_TEST_OCI_REGISTRY=http://127.0.0.1:<port printed by zot.mjs> OWA_TEST_ORAS_BIN=/tmp/oci-tools/oras/oras
OWA_TEST_OCI_REQUIRED=1 npm run test:oci
node .github/scripts/zot.mjs alive && node .github/scripts/zot.mjs stop /tmp/zot-state

# Lane 5 — any OS with Go 1.22+ installed (no Node required)
cd implementations/go-conformance && test -z "$(gofmt -l .)" && go vet ./... && go test ./... -count=1 -v
# or, from the repository root: npm run test:go-conformance
```

## What the first runs showed (2026-09-21)

Recorded from the pull request that introduced these workflows (#22); every
later run supersedes it.

- `offline (ubuntu-latest|macos-latest|windows-latest, node 22|24)`: all six
  cells green in 0.5–1.8 min each; every suite at its expected count, the live
  suite skipping all 7 provider cases, MCP 167/167 on every cell. The only
  portability issue found was in a **test**: the dev-mode "binds only
  127.0.0.1" probe connected to `127.0.0.2`, which macOS black-holes instead of
  refusing; it now probes a real non-internal address of the host.
- `minio (mediated + enforced, node 24)`: green in ~2 min including the source
  build; both modes ran with 3 MinIO cases passing and 4 skips (3 R2, 1
  virtual-host); both bucket-empty postflights passed; MinIO stayed alive.
- `browsers (chromium, firefox, webkit)`: green in ~2 min; Chromium
  153.0.8010.12, Firefox 155.0 and **WebKit 26.6** each executed all 28 rows
  (25 PASS, 3 EXPECTED LIMIT). Two harness bugs surfaced by WebKit were fixed
  (see [browser validation](sandboxed-web-v1-browser-validation.md)).

Job logs are only visible to signed-in users, so the suites also publish their
key facts as **annotations** (visible on the public run page and through the
check-runs API): each cell's exact Node/OS runtime, the MinIO executable's
`--version` line and SHA-256, the browser engines that really launched with
their row tallies, and — on failure — each failing test with its error.

## Branch protection

The job names above (`offline (<os>, node <n>)` × 6, `minio (mediated +
enforced, node 24)`, `browsers (chromium, firefox, webkit)`, `oci (oras + zot,
node 24)`, `go-conformance (go 1.27, ubuntu)`) are stable and intended to become
**required status checks**. Branch protection is a repository
setting configured by a maintainer outside these workflow files; this document
does not change it.
