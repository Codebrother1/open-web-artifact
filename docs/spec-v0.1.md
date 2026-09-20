# Open Web Artifact Specification v0.1 (Draft)

## Status
Experimental. The purpose of v0.1 is to prove a provider-neutral representation for immutable static web releases.

## Core model
An **artifact** is an immutable manifest plus content-addressed blobs. A **release** binds an artifact digest to a site. A **site** owns a mutable `activeReleaseId` pointer. Activation and rollback change only that pointer.

## Manifest
Media type: `application/vnd.openwebartifact.site.v1+json`

Required fields:
- `specVersion`: `owa.dev/v1`
- `artifactType`
- `entrypoint`: absolute artifact path, normally `/index.html`
- `files[]`: path, SHA-256 digest, byte size, media type

Optional fields in v0.1:
- `routing.spaFallback`
- `access.visibility`: `public | unlisted`
- `lifecycle.expiresAt`
- `annotations`

## Invariants
1. Artifact identity is the SHA-256 digest of its canonical manifest representation.
2. File contents are addressed by SHA-256 digest.
3. Releases are immutable after creation.
4. Publishing MAY reuse blobs already present in storage.
5. Activating an existing release MUST NOT require uploading its blobs again.
6. A conforming gateway MUST NOT resolve paths outside the artifact namespace.
7. Hosts MAY impose stricter security policy than requested by the artifact.

## Lifecycle
`PACKED -> STORED -> RELEASED -> ACTIVE`

A site may have many RELEASED artifacts and exactly zero or one ACTIVE release. Rollback is activation of a previous release.

## Non-goals for v0.1
Build systems, arbitrary server-side compute, billing, custom domains, databases, forms, secret proxies, OCI transport, S3 presigned upload protocol, and authentication are deliberately deferred.
