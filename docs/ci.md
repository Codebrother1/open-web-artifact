# Continuous integration

The repository runs three **independent** GitHub Actions workflows on every pull
request, on every push to `main`, and on demand (`workflow_dispatch`). They are
deliberately separate so that an offline failure never hides whether the MinIO or
browser lanes are healthy, and vice versa.

Automatic CI is **secretless**: it uses ordinary `pull_request` events (never
`pull_request_target`), a read-only token (`permissions: contents: read`), no
repository secrets, and no hosted-storage credentials. Cloudflare R2 is
**intentionally excluded** from automatic CI; see [R2](#r2-is-not-in-automatic-ci).

| Workflow | File | Job / check name | Runner(s) | Timeout |
| --- | --- | --- | --- | --- |
| `CI` | `.github/workflows/ci.yml` | `offline (<os>, node <22\|24>)` — 6 cells | `ubuntu-latest`, `macos-latest`, `windows-latest` | 15 min |
| `MinIO` | `.github/workflows/minio.yml` | `minio (mediated + enforced, node 24)` | `ubuntu-latest` | 25 min |
| `Browsers` | `.github/workflows/browser.yml` | `browsers (chromium, firefox, webkit)` | `ubuntu-latest` | 25 min |

Each workflow has its own concurrency group (`ci-offline-*`, `ci-minio-*`,
`ci-browsers-*`, keyed by PR number or ref) with `cancel-in-progress: true`, so a
newer push cancels only that workflow's stale run for the same PR — one workflow
never cancels another.

## Pinned actions and services

Every GitHub Action is referenced by an immutable commit SHA with the release it
corresponds to beside it. Only GitHub-maintained actions are used; everything
else is `node`, `npm`, `git` and shell.

| Action | Commit SHA | Release |
| --- | --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `v7.0.1` |
| `actions/setup-node` | `820762786026740c76f36085b0efc47a31fe5020` | `v7.0.0` |

Both are used with `persist-credentials: false` so the job token is not left in
the checkout. No cache action is used yet: measured first-run times fit the
timeouts, and a cache can be added later without changing any test.

The MinIO service is pinned to a **source commit**, not a floating tag, and the
Playwright engines come from the exact package-local lockfile — see the lane
descriptions below.

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
2. the binary is built with MinIO's own Makefile recipe (`-tags kqueue,osusergo
   -trimpath`, ldflags from `buildscripts/gen-ldflags.go` with
   `MINIO_RELEASE=RELEASE`) and `minio --version` must print exactly
   `version RELEASE.2025-10-15T17-29-55Z (commit-id=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a)`.

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
```

## Branch protection

The job names above (`offline (<os>, node <n>)` × 6, `minio (mediated +
enforced, node 24)`, `browsers (chromium, firefox, webkit)`) are stable and
intended to become **required status checks**. Branch protection is a repository
setting configured by a maintainer outside these workflow files; this document
does not change it.
