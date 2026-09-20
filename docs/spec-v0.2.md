# Open Web Artifact Specification v0.2 (Draft)

## Status
Experimental. v0.2 adds transport-neutral publishing and deterministic manifest identity while preserving the v0.1 artifact model.

## Core model
An **artifact** is an immutable canonical manifest plus content-addressed blobs. A **release** binds an artifact digest to a site. A **site** owns a mutable `activeReleaseId` pointer. Activation and rollback change only that pointer.

## Manifest
Media type: `application/vnd.openwebartifact.site.v1+json`

Required fields:
- `specVersion`: `owa.dev/v1`
- `artifactType`: the media type above
- `entrypoint`: absolute normalized artifact path, normally `/index.html`
- `files[]`: normalized path, SHA-256 digest, byte size, media type

Optional fields:
- `routing.spaFallback`
- `access.visibility`: `public | unlisted`
- `lifecycle.expiresAt`
- `annotations`

## Canonical manifest encoding
Artifact identity is `sha256(UTF8(canonical-json(manifest)))`.

The v0.2 reference canonicalizer:
1. emits no insignificant whitespace;
2. sorts object keys by Unicode code point;
3. preserves array order;
4. uses normal JSON string escaping;
5. rejects non-finite numbers.

The current schema does not use floating-point fields. A later stable specification should either adopt RFC 8785/JCS explicitly or publish interoperable canonicalization vectors before declaring the digest format stable.

## Publishing protocol
A host exposes a two-phase upload flow.

### 1. Plan
`POST /v1/sites/{slug}/publish/plan`

Request:
```json
{
  "artifactDigest": "sha256:...",
  "manifest": {}
}
```

The host validates the manifest and returns upload instructions only for blobs it does not already possess:

```json
{
  "artifactDigest": "sha256:...",
  "reused": 4,
  "uploads": [
    {
      "digest": "sha256:...",
      "method": "PUT",
      "url": "https://object-store.example/...",
      "expiresIn": 900
    }
  ]
}
```

Upload URLs MAY point directly at object storage. File bytes therefore do not need to transit the artifact control plane.

### 2. Commit
`POST /v1/sites/{slug}/publish/commit`

Request:
```json
{
  "artifactDigest": "sha256:...",
  "manifest": {},
  "activate": true
}
```

Before creating a release, the host MUST verify the canonical artifact digest and MUST verify that every referenced blob exists. A release is immutable after creation.

## Storage adapters
Blob stores MUST implement logically equivalent operations for:
- `has(digest)`
- `get(digest)`
- `put(digest, bytes)` for trusted/local publication paths

A remote-capable store MAY additionally expose a direct-upload instruction such as a presigned S3 `PUT` URL.

The reference implementation includes filesystem and S3-compatible blob stores. The S3 adapter uses Signature V4 and is intended to support R2, AWS S3, MinIO, Backblaze B2, DigitalOcean Spaces, and compatible services subject to provider-specific validation.

## Invariants
1. File contents are addressed by SHA-256 digest.
2. Manifest identity is independent of JSON object insertion order.
3. Releases are immutable after creation.
4. Publishing SHOULD reuse blobs already present in storage.
5. Commit MUST fail if a referenced blob is absent.
6. Activation of an existing release MUST NOT require blob upload.
7. A conforming gateway MUST NOT resolve paths outside the artifact namespace.
8. Hosts MAY impose stricter security policy than requested by an artifact.

## Lifecycle
`PACKED -> PLANNED -> STORED -> RELEASED -> ACTIVE`

A site may have many RELEASED artifacts and exactly zero or one ACTIVE release. Rollback is activation of a previous release.

## Still deferred
Authentication, custom domains, OCI/ORAS transport, formal JCS test vectors, garbage collection, multi-tenant authorization, billing, forms/data/secret-proxy capabilities, and a stable security-profile vocabulary.
