# Live S3-compatible integration tests

These opt-in tests exercise the existing v0.2 implementation, not a replacement
storage client. They use Node.js built-ins and the existing `S3BlobStore`,
`FilesystemMetadataStore`, and `createArtifactServer`. No AWS/vendor SDK, npm
install, public artifact host, or production server is required. Node.js 22+ is
required, as for the rest of the repository.

```sh
npm test                          # offline unit/conformance suite, including auth
npm run test:auth                 # token, HTTP, CLI, executable-startup auth tests
npm run test:integration:harness  # offline request timeout/cancellation/cleanup checks
npm run test:integration          # real services; unconfigured cases explicitly skip
```

The live suite explicitly constructs `createArtifactServer` with
`auth: { mode: 'dev' }` and binds it to `127.0.0.1`. Its direct-loopback,
tokenless control requests are intentional storage interoperability coverage,
not required-auth deployment coverage. It does not need `OWA_AUTH_SECRET` or
`OWA_TOKEN`; it is not an invitation to expose a dev server through a proxy.
The pre-existing offline HTTP conformance fixture also explicitly selects dev
mode. Required-mode authorization, grant issuance, credential routing, and
executable fail-closed startup have separate offline auth tests.

Normal `npm start` / `node packages/server/src/index.js` now defaults to required
auth, with a minimum 32-UTF-8-byte `OWA_AUTH_SECRET`; absent auth configuration
fails startup, not open access. Only explicit `OWA_AUTH_MODE=dev`, `--dev`, or
`npm run dev:server` selects the executable's loopback dev mode. See
[the auth guide](auth.md) for token creation, capabilities, TLS/proxy setup,
`OWA_PUBLIC_BASE_URL`, and the boundary between auth and public artifact serving.

A skipped case is **not evidence of interoperability**. When all required
variables for a case are present, bad credentials, unreachable services, failed
assertions, and failed cleanup fail the suite rather than silently skipping.
Partially configured cases skip with the names of the missing variables.

## Matrix and assertions

| Case | Addressing | Enable with |
| --- | --- | --- |
| MinIO | Path-style | MinIO endpoint, bucket, access key, and secret below |
| MinIO | Virtual-host | MinIO bucket/credentials plus the separate virtual endpoint |
| Cloudflare R2 | Path-style | R2 endpoint, bucket, access key, and secret below |
| Cloudflare R2 GC | Path-style | Same R2 variables; runs the mark/sweep collector in a UUID-isolated `owa-gc-integration/<uuid>` prefix |
| Cloudflare R2 integrity | Path-style | Same R2 variables; proves checksum-bound create-once grants, provider-evidence verification, corrupt-object recovery and post-commit grant replay in a UUID-isolated `owa-integrity-integration/<uuid>` prefix |

Each enabled case starts an ephemeral artifactd on loopback with the real S3 blob
adapter and fresh local metadata, then tests:

1. Commit before upload returns HTTP 500 with the fixed `OWA_BLOB_MISSING` code,
   without creating a site/release or exposing provider error bodies.
2. HTTP plan returns three missing blobs for four files (two files share bytes).
3. The publisher follows the returned SigV4 PUT URLs **directly to storage**.
   Assertions check bucket placement in the path or hostname, signing parameters,
   and the actual upload count.
4. HTTP commit sends the manifest/digest only and activates an immutable release.
5. The gateway serves every file with exact bytes, content type, and digest ETag,
   including a binary asset and the entrypoint at `/`.
6. Identical republish completes plan/commit/serve with **zero uploads, three reused**.
7. Changing only `index.html` completes the flow with **one upload, two reused**;
   the requested digest must be exactly the changed blob's digest.
8. All three publishes are also performed using the filesystem backend. Their
   canonical manifests and artifact digests must match the remote releases.
   Earlier remote release records must remain unchanged after later commits.

OWA digest semantics are unchanged: the artifact identity is still
`sha256(UTF8(canonical-json(manifest)))`. This suite does not change manifest
schema, release records, canonicalization, or direct-to-storage publishing.
The separate [auth HTTP overlay](auth.md) does add bearer checks, scoped local
filesystem grant fields, and safe error codes; these are wire additions, not
artifact/spec changes. S3/R2 grants retain their storage-only SigV4 shape, without
an OWA bearer marker or forwarded OWA Authorization header. Storage services do
not interpret OWA capabilities. Provider setup stays here, outside the portable
OWA specification.

## Exact environment variables

Test configuration is deliberately separate from artifactd's `OWA_S3_*` variables
so normal server credentials do not accidentally opt a developer into live tests.
There is no fallback to production configuration.

| Variable | Requirement/default |
| --- | --- |
| `OWA_TEST_MINIO_ENDPOINT` | Required for MinIO path case, e.g. `http://127.0.0.1:9000` |
| `OWA_TEST_MINIO_VIRTUAL_ENDPOINT` | Required only for the optional virtual case, e.g. `http://localhost:9000`; omit the bucket from the hostname |
| `OWA_TEST_MINIO_BUCKET` | Required for either MinIO case; existing disposable test bucket |
| `OWA_TEST_MINIO_ACCESS_KEY_ID` | Required for either MinIO case |
| `OWA_TEST_MINIO_SECRET_ACCESS_KEY` | Required for either MinIO case |
| `OWA_TEST_MINIO_REGION` | Optional, defaults to `us-east-1` |
| `OWA_TEST_MINIO_SESSION_TOKEN` | Optional, only for temporary credentials |
| `OWA_TEST_MINIO_CHECKSUM_EVIDENCE` | Optional; `enforced` only after the probe proved the service validates `x-amz-checksum-sha256` against stored bytes. Default: the store's conservative `advisory` (rehash). |
| `OWA_TEST_MINIO_DIRECT_UPLOAD_INTEGRITY` | Optional; `enforced` only after the probe proved the complete direct final-CAS grant contract. Default: `mediated` — the live suites then route every upload through a real artifactd listener and assert no presigned request reaches the service. Run the suites both ways to cover both modes. |
| `OWA_TEST_R2_ENDPOINT` | Required for R2; account S3 API origin such as `https://<account-id>.r2.cloudflarestorage.com` |
| `OWA_TEST_R2_BUCKET` | Required for R2; existing disposable test bucket |
| `OWA_TEST_R2_ACCESS_KEY_ID` | Required for R2; S3 API access key ID |
| `OWA_TEST_R2_SECRET_ACCESS_KEY` | Required for R2; S3 API secret access key |
| `OWA_TEST_R2_REGION` | Optional, defaults to `auto` |
| `OWA_TEST_R2_SESSION_TOKEN` | Optional, only if supplied with temporary credentials |
| `OWA_TEST_R2_CHECKSUM_EVIDENCE`, `OWA_TEST_R2_DIRECT_UPLOAD_INTEGRITY` | Optional; R2 is live-proven and auto-selects `enforced` for both, so these are only needed to force the safe path (`advisory` / `mediated`) for comparison. |

Endpoints must be HTTP(S) origins with no embedded credentials, path, query, or
fragment. Bucket names must be DNS-compatible, especially for the virtual case.
Remote services should use HTTPS; HTTP examples below are loopback-only.

Each case gets a non-configurable, UUID-isolated object prefix:
`owa-integration/<minio-or-r2>/<path-or-virtual>/<uuid>/blobs/sha256/<digest>`.
The prefix is reported for operator cleanup; credentials and signed URLs are not
logged. Each request is bounded to 15 seconds and each case to 180 seconds.

## Local MinIO setup

Prerequisites: Node.js 22+ and a trusted, already-installed `minio` server binary
on `PATH`. The repository does not download or bundle service binaries. Obtain a
version approved for your environment (or use your organization's pinned MinIO
container and expose its API on loopback). Do not assume an old public download
URL or image tag remains available. Record `minio --version` with live test results.

Run the following from the repository root in one POSIX shell. The service data
and logs are placed outside the checkout; credentials are disposable and generated
locally. Port 9000 must be free.

```sh
minio --version
export MINIO_ROOT_USER=owa-integration-admin
export MINIO_ROOT_PASSWORD="$(node -e "process.stdout.write(require('node:crypto').randomBytes(24).toString('hex'))")"
export MINIO_DOMAIN=localhost
OWA_MINIO_TEST_DIR="$(mktemp -d)"
minio server "$OWA_MINIO_TEST_DIR/data" \
  --address 127.0.0.1:9000 --console-address 127.0.0.1:9001 \
  >"$OWA_MINIO_TEST_DIR/minio.log" 2>&1 &
OWA_MINIO_PID=$!
trap 'kill "$OWA_MINIO_PID" 2>/dev/null || true' EXIT

export OWA_TEST_MINIO_ENDPOINT=http://127.0.0.1:9000
export OWA_TEST_MINIO_BUCKET=owa-integration
export OWA_TEST_MINIO_REGION=us-east-1
export OWA_TEST_MINIO_ACCESS_KEY_ID="$MINIO_ROOT_USER"
export OWA_TEST_MINIO_SECRET_ACCESS_KEY="$MINIO_ROOT_PASSWORD"
```

Wait for readiness and create the bucket using the existing signer (no `mc` or SDK
required). This setup step is separate from the tests: the suite itself never
creates or deletes buckets.

```sh
node --input-type=module <<'NODE'
import { setTimeout } from 'node:timers/promises';
import { S3BlobStore } from './packages/storage-s3/src/index.js';
const endpoint = process.env.OWA_TEST_MINIO_ENDPOINT;
let ready = false;
for (let attempt = 0; attempt < 40; attempt++) {
  try {
    const res = await fetch(`${endpoint}/minio/health/ready`, { signal: AbortSignal.timeout(1000) });
    await res.arrayBuffer();
    if (res.ok) { ready = true; break; }
  } catch {}
  await setTimeout(250);
}
if (!ready) throw new Error('Local MinIO did not become ready; inspect its log');
const store = new S3BlobStore({
  endpoint,
  bucket: process.env.OWA_TEST_MINIO_BUCKET,
  region: process.env.OWA_TEST_MINIO_REGION,
  accessKeyId: process.env.OWA_TEST_MINIO_ACCESS_KEY_ID,
  secretAccessKey: process.env.OWA_TEST_MINIO_SECRET_ACCESS_KEY
});
const created = await fetch(store.presign('PUT', ''), {
  method: 'PUT', body: Buffer.alloc(0), signal: AbortSignal.timeout(15_000)
});
await created.arrayBuffer();
if (!created.ok) throw new Error(`Create fresh test bucket failed: HTTP ${created.status}`);
NODE

npm test
npm run test:integration
```

Without R2 configuration or a virtual endpoint, only the MinIO path-style case
runs; the other two explicitly skip. The generated local admin credential is for
a disposable loopback server only, not a recommendation for hosted services.

### Optional MinIO virtual-host case

The server above sets `MINIO_DOMAIN=localhost`. Configure local DNS or your hosts
file so `owa-integration.localhost` resolves to `127.0.0.1` (do not assume every
system resolves subdomains of localhost automatically):

```text
127.0.0.1 owa-integration.localhost
```

Then, in the same shell:

```sh
export OWA_TEST_MINIO_VIRTUAL_ENDPOINT=http://localhost:9000
node -e "require('node:dns').lookup('owa-integration.localhost', (err, address) => { if (err) throw err; console.log(address); })"
npm run test:integration
```

For a non-local MinIO endpoint, configure `MINIO_DOMAIN` and wildcard DNS/TLS for
`<bucket>.<endpoint-host>` instead. This is an explicit additional matrix case,
not a fallback: setting a virtual endpoint with broken DNS or TLS must fail.

After testing, stop the local service with `kill "$OWA_MINIO_PID"`, wait for it
with `wait "$OWA_MINIO_PID"` (termination may return nonzero), and remove only the
generated temporary data directory when you no longer need its logs. Clear the
test credential environment variables when finished. The exit trap also stops the
service if the shell exits early.

## Cloudflare R2 setup

1. Create a dedicated private R2 test bucket. Use the S3 API endpoint shown for its
   account/jurisdiction, not an `r2.dev` public URL or a custom serving domain.
2. Create bucket-scoped S3 API credentials with Object Read & Write access,
   including permission to delete test objects. Do not use a general Cloudflare
   bearer API token as the S3 secret. Keep credentials in a local secret manager
   or your CI secret store, never in committed files or shell tracing output.
3. Export `OWA_TEST_R2_ENDPOINT`, `OWA_TEST_R2_BUCKET`,
   `OWA_TEST_R2_ACCESS_KEY_ID`, and `OWA_TEST_R2_SECRET_ACCESS_KEY` through that
   secret mechanism. `OWA_TEST_R2_REGION=auto` is the default.
4. Run `npm run test:integration`. The R2 case uses path-style addressing against
   the account S3 endpoint. Virtual-host coverage is provided separately by
   MinIO; it is not assumed for R2 custom domains.

The service must allow HEAD on missing/existing objects, presigned PUT, GET, and
DELETE. For restricted MinIO/S3 policies, bucket-list permission can be necessary
for missing-object HEAD to return 404 rather than 403. The tests do not list
objects. Use a non-versioned MinIO test bucket; versioning can retain old versions
or delete markers beyond these targeted DELETE operations.

## CI invocation

Run the offline suite on every PR. Run live tests only in trusted, protected or
manually triggered jobs that can reach the configured storage endpoints. Never
provide live credentials to untrusted PR code. Configure the variables above from
CI secrets; the local artifactd process needs no externally exposed port.

For example, this GitHub Actions job can be placed in a trusted manual workflow
with `on: workflow_dispatch`. Supply all four R2 secrets before running it:

```yaml
jobs:
  r2-integration:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: npm test
      - name: Require R2 configuration and run the live suite
        env:
          OWA_TEST_R2_ENDPOINT: ${{ secrets.OWA_TEST_R2_ENDPOINT }}
          OWA_TEST_R2_BUCKET: ${{ secrets.OWA_TEST_R2_BUCKET }}
          OWA_TEST_R2_ACCESS_KEY_ID: ${{ secrets.OWA_TEST_R2_ACCESS_KEY_ID }}
          OWA_TEST_R2_SECRET_ACCESS_KEY: ${{ secrets.OWA_TEST_R2_SECRET_ACCESS_KEY }}
        run: |
          test -n "$OWA_TEST_R2_ENDPOINT"
          test -n "$OWA_TEST_R2_BUCKET"
          test -n "$OWA_TEST_R2_ACCESS_KEY_ID"
          test -n "$OWA_TEST_R2_SECRET_ACCESS_KEY"
          npm run test:integration
```

The explicit CI preflight prevents a missing required secret from producing an
all-skipped green live-validation job. Use the equivalent `OWA_TEST_MINIO_*`
variables for a MinIO CI job; provision the service/bucket first and require
`OWA_TEST_MINIO_VIRTUAL_ENDPOINT` as well when that job promises virtual coverage.
No dependency install step is needed.

## Cleanup and limitations

- A case records attempted upload digests before sending each PUT and deletes
  only those exact keys under its unique prefix, including when an assertion
  fails. Cleanup verifies absence with HEAD; cleanup failures fail the test.
- The suite never lists/empties/deletes a bucket or touches another run's prefix.
  Temporary fixture and metadata directories and local HTTP servers are cleaned up.
- Cancelling a PUT stops the client, but does not guarantee that storage stops
  processing it. A delayed PUT can persist after a cleanup DELETE/HEAD; forced
  process termination or unavailable storage can also leave a reported prefix
  behind. Cleanup is best-effort under these conditions, not transactional. An
  operator can remove that prefix after requests settle, or configure an expiry
  policy for `owa-integration/` on the dedicated test bucket. Live requests can
  incur charges.
- Metadata remains local by design. These tests do not claim distributed metadata,
  required-auth/TLS deployment validation, public/browser CORS behavior,
  production security hardening, multipart uploads, or compatibility with
  providers/addressing combinations not actually run. The auth layer does not
  implement issue 3 public-asset/service-worker isolation or tenant-private CAS.
- The offline `test:integration:harness` checks cancellation unwinding before
  cleanup, fresh cleanup deadlines, fetch restoration, and safe network errors.
  It needs no live endpoint and is separate from `npm test` and the live matrix.
- Record Node and MinIO versions, which matrix cases passed/skipped, which
  direct-upload mode (`direct` or `mediated`, printed in each case's diagnostics)
  each case ran in, and any inability to obtain service binaries or credentials
  with the test evidence.
  Passing conformance, auth, or test-harness checks alone is not live MinIO/R2 proof.
