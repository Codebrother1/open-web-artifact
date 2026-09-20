# Open Web Artifact (OWA)

An experimental open specification and zero-dependency reference implementation for **portable, immutable web artifacts**.

The thesis: an AI agent, CLI, CI job, or application should be able to produce one web artifact that can be stored, moved, signed, and served by different hosts without adopting each host's private deployment model.

## v0.2 status

The prototype now proves:

- content-addressed files using SHA-256
- deterministic canonical manifest identity
- immutable releases
- blob deduplication
- mutable site -> active release pointer
- rollback without re-upload
- two-phase `plan -> direct upload -> commit` HTTP publishing
- local signed upload URLs for the filesystem reference backend
- S3 Signature V4 presigned uploads for R2/S3-compatible storage
- filesystem and S3-compatible blob-store adapters
- OCI image-layout export/import using the OWA manifest as artifact metadata
- ORAS-compatible OCI layouts
- HTTP serving gateway
- local and remote CLI workflows
- required-by-default, site- and capability-scoped HTTP bearer authentication
- conformance tests, including the published AWS SigV4 test vector

Everything in the reference implementation currently uses Node.js built-ins. There are **zero third-party runtime dependencies**.

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

## OCI / ORAS transport

Export the exact same OWA artifact as an OCI image layout:

```bash
npm run artifact -- export-oci demo --out ./demo.oci --ref v1
```

Import it back into the local reference host:

```bash
npm run artifact -- import-oci ./demo.oci --ref v1 --site imported-demo
```

If ORAS is installed, the OCI layout can be copied to an OCI registry without OWA implementing a registry client:

```bash
oras cp --from-oci-layout ./demo.oci:v1 registry.example.com/team/site:v1
```

This is deliberate: OWA defines the web artifact semantics while OCI/ORAS handles generic registry transport.

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
  server/              artifactd HTTP control plane + gateway
  cli/                 local/remote publish + OCI commands
  conformance/         protocol and portability tests

docs/
  spec-v0.1.md
  spec-v0.2.md
  manifest.schema.json
  auth.md
  integration-tests.md
  test-vectors/
```

## Security / production status

This is a protocol prototype, **not a production multi-tenant hosting service yet**.
The [HTTP auth overlay](docs/auth.md) now enforces explicit site/capability
boundaries for publishing, activation, and release inspection. It is deliberately
minimal: no accounts database, individual token revocation/replay database, or
full tenant/storage isolation. Signing-key rotation invalidates all tokens;
keys must not be reused across deployments because tokens have no audience claim.

`GET /health` and artifact `GET`/`HEAD` remain public. This is not artifact access
control. Shared CAS deduplication is not tenant-private storage, and commit checks
blob existence rather than tenant ownership. Local operator CLI access is gated
by filesystem permissions, not HTTP tokens. Storage and metadata remain trusted.

Public-asset origin isolation, service-worker isolation, and hardened rendering
security profiles remain issue 3 work, **not implemented by this auth layer**.
Quotas, garbage collection, custom-domain verification, malware moderation, and a
finalized browser sandbox policy are also not provided. TLS, secret custody, and
proxy logging that excludes headers, full URLs/queries, and request bodies remain
operator responsibilities.

## Next milestones

1. Formal canonicalization compatibility suite across at least two languages.
2. Broader live integration evidence against R2 and MinIO/S3.
3. Hardened safe-rendering security profiles and public-asset isolation (issue 3).
4. Garbage collection and retention semantics for unreferenced blobs.
5. OCI registry import/export convenience commands on top of ORAS.
6. MCP adapter as a thin client over the HTTP protocol.
7. Optional static capabilities (data/forms/secret proxy) only after the base lifecycle is stable.

## License

MIT. See `LICENSE`.
