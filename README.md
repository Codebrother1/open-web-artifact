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

Requires Node.js 22+.

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

Start the server:

```bash
npm run dev:server
```

Then publish through its HTTP protocol:

```bash
npm run artifact -- publish demo \
  --site hello \
  --server http://localhost:7331
```

The client performs:

```text
1. pack directory + hash files
2. POST /publish/plan
3. upload only missing blobs using returned PUT URLs
4. POST /publish/commit with the manifest only
5. server verifies all blobs exist and creates an immutable release
```

Publishing the identical directory again should upload **zero** blobs.

## S3 / Cloudflare R2 backend

Configure `artifactd` with environment variables:

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

`npm test` remains the offline unit/conformance suite. Run the separate live-service
matrix with `npm run test:integration`. It covers MinIO path-style, optional MinIO
virtual-host addressing, and Cloudflare R2 path-style. Cases skip when their
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
  test-vectors/
```

## Security / production status

This is a protocol prototype, **not a production multi-tenant hosting service yet**. v0.2 intentionally does not include user authentication, tenant authorization, quotas, garbage collection, custom-domain verification, or malware moderation.

The gateway applies [`sandboxed-web-v1`](docs/sandboxed-web-v1.md), a deny-by-default **static-preview** response policy. It deliberately disables all JavaScript (inline, external and same-artifact), external stylesheets, and network images/fonts/media; only inline CSS and `data:` images are allowed. Existing interactive sites and remote-asset-dependent pages will not work as ordinary web apps. Artifact bytes and identity are unchanged; unknown or invalid MIME metadata is served as an octet-stream attachment. Every application response carries the profile's security, no-store and advisory noindex headers, including assets, control responses and errors. Public and unlisted URLs remain accessible; this is neither authentication nor sanitization.

A production deployment of this profile requires clean, cookieless, content-only one-site origins separate from control/admin/API services. **The prototype does not enforce that topology:** `.localhost` hostnames have distinct URL origins, but `?site=` can share an origin and API routes are exposed on every host. No-store does not erase existing browser caches, service workers or saved copies. This response policy is not a claim that the full platform is secure.

Read the [pre-implementation threat model](docs/sandboxed-web-v1-threat-model.md), the [exact profile and deployment contract](docs/sandboxed-web-v1.md), and the [optional manual browser-validation guide](docs/sandboxed-web-v1-browser-validation.md). The deterministic tests verify HTTP policy and byte preservation, not browser enforcement; no browser automation is implemented and the manual report is initially **not run**.

The remaining production controls should be added as explicit protocol/security layers rather than hidden assumptions in the storage implementation.

## Next milestones

1. Formal canonicalization compatibility suite across at least two languages.
2. Live integration tests against R2 and MinIO/S3.
3. Authentication and capability-scoped publish tokens.
4. Production content/control origin isolation and separately reviewed interactive security profiles.
5. Garbage collection and retention semantics for unreferenced blobs.
6. OCI registry import/export convenience commands on top of ORAS.
7. MCP adapter as a thin client over the HTTP protocol.
8. Optional static capabilities (data/forms/secret proxy) only after the base lifecycle is stable.

## License

MIT. See `LICENSE`.
