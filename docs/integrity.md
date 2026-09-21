# Commit-boundary blob integrity

Issue #10. This document defines the **host integrity invariant** the reference
server enforces when it turns a manifest into an immutable release, how each
storage backend satisfies it, and — just as importantly — how a still-valid
direct-upload grant is prevented from corrupting a committed object afterwards.

This is a **host storage rule**. It changes no portable OWA semantics: manifest
schema, `specVersion`, media type, canonical JSON, artifact digest, release
identity, activation, auth, origin isolation, GC, MCP and OCI are untouched.

## The invariant

> A release MUST NOT be persisted or activated unless every unique blob it
> references has been strongly verified to match BOTH its manifest SHA-256
> digest AND its declared byte size.

Before this change, commit proved only that each blob **existed**. Existence
says nothing about content: an upload of the wrong bytes, a truncated write, or
a corrupt object already sitting at the content-addressed key would all have
been released and served as if correct.

### Normative language

- A host **MUST** establish strong digest **and** size integrity for every unique
  referenced blob before persisting a release.
- A host **MAY** satisfy that by any of: hashing the actual bytes during trusted
  ingestion; a storage-native cryptographic checksum that the storage service
  itself validated against the uploaded bytes; an explicit read/stream and
  SHA-256; or another backend-specific proof of equivalent strength.
- A host **SHOULD** prefer an equally strong proof that avoids re-transferring
  payload bytes when the backend offers one.
- A host **MUST NOT** treat any of the following as equivalent to payload
  SHA-256 verification: object existence; the content-addressed key name;
  caller-supplied metadata (including `x-amz-meta-*` digest claims); ETag alone;
  Last-Modified alone; size alone; a trusted-looking URL shape; a successful
  HEAD alone; a successful earlier plan alone.

### Digest and size, once per unique digest

Verification is keyed by **unique digest**, not by file path: a manifest with
five paths sharing one digest verifies that blob once. The declared size is
taken from the manifest entries. If the **same digest is declared with
conflicting sizes**, one stored object cannot satisfy both declarations, so
commit (and plan) fail closed with `OWA_BLOB_INTEGRITY` before anything is
minted or written. This is deliberately a commit-time integrity rule rather than
a change to the portable manifest grammar.

## Storage verification contract

Core asks one question and does not care how the backend answers it:

```
verifyBlob({ digest, size })  ->  { ok: true, method }   |   throws { code }
```

`method` is informational (`rehash`, `provider-checksum`, …). Failure is a
fixed code: `OWA_BLOB_MISSING`, `OWA_BLOB_INTEGRITY` (size or digest disagree),
or `OWA_BLOB_UNVERIFIED` (the store could not produce strong proof — a provider
error, a non-regular filesystem object, malformed input). Core normalises every
backend failure into an `IntegrityError` that carries the **digest only**: never
a storage key, filesystem path, provider body, signed URL or credential.

A store that lacks `verifyBlob` falls back to explicit `has()` + `get()` + SHA-256
in core. That is itself strong verification, so in-memory and test stores stay
correct; it just buffers, which the real backends avoid.

The contract is shaped to be hard to misuse: success is a positive `{ ok: true }`
with a named method, failure always throws, and an unknown code collapses to
`OWA_BLOB_UNVERIFIED`. A forgotten check cannot accidentally pass.

## Commit ordering

```
validate manifest
compute artifactDigest, compare to expectedArtifactDigest
derive digest -> size (conflicting sizes: fail)
for each unique digest: verifyBlob(digest, size)      <- INTEGRITY GATE
--- nothing above touched metadata ---
getSite / createSite
saveRelease
saveSite (activation)
```

If the gate throws, **no site is created, no release is saved, and no
`activeReleaseId` moves** — for a brand-new slug and for an existing site alike.
Tests assert this for missing, wrong-size, same-size wrong-digest and
unverifiable blobs.

## Filesystem backend

`FilesystemBlobStore.verifyBlob` strongly verifies the **stored** bytes:

1. the digest and size are well-formed;
2. `blobs` and `blobs/sha256` are real directories — the no-follow ancestor
   guard from GC applies, so a symlinked namespace is never traversed;
3. the object is `lstat`ed and must be a **regular file**: a symlink (even one
   pointing at exactly the right bytes), a directory or any other object is
   `OWA_BLOB_UNVERIFIED`;
4. the `lstat` size must equal the declared size (`OWA_BLOB_INTEGRITY` otherwise);
5. the file is **streamed** through SHA-256 while counting bytes — never buffered
   whole — stopping early if it runs longer than declared;
6. count and digest must both match.

Bytes are re-read on every verification. The local upload route and
`publishDirectory` do hash bytes at ingestion, but the filesystem offers no
contract that nothing changed since, so an earlier hash is **not** treated as
proof of current bytes. Verification cost is one local streamed read per unique
blob per commit.

## S3 / R2 backend

### What the live probe established

Measured against the real Cloudflare R2 test bucket in a UUID-isolated prefix
(statuses and header names only; no URLs, signatures or credentials recorded):

| Probe | Result |
| --- | --- |
| Presigned PUT with signed `x-amz-checksum-sha256`, correct bytes | `200` |
| **Same still-valid grant, same-length WRONG bytes, header still claims the right checksum** | **`400 BadDigest`** — object unchanged |
| Same grant, signed checksum header omitted | `403 SignatureDoesNotMatch` |
| Same grant, checksum header changed to match the wrong bytes | `403 SignatureDoesNotMatch` |
| `HEAD` with signed `x-amz-checksum-mode: ENABLED` after a checksum-validated PUT | `200`, `x-amz-checksum-sha256` present and equal to the expected value, `Content-Length` present |
| `GetObjectAttributes` | `501 NotImplemented` on R2 |
| The **pre-change** host-only grant, wrong bytes | `200` — object **corrupted** (the hole this closes) |
| `HEAD` after any checksum-*less* write | only `x-amz-checksum-crc64nvme`; the SHA-256 evidence is gone |
| Presigned PUT with signed `If-None-Match: *`, first write | `200` |
| Same grant again, even with the right bytes | `412 PreconditionFailed` |
| Same grant, `If-None-Match` omitted | `403 SignatureDoesNotMatch` |

So on R2: the provider **enforces** the SHA-256 checksum against payload bytes,
the checksum is retrievable by `HEAD` without a download, a signed header cannot
be dropped or altered, and `If-None-Match: *` is honoured on presigned PUT.

**MinIO could not be tested in this environment** (no `minio` binary). Its
documented behavior matches, but that is not evidence. The design below is
arranged so that invariant A (commit integrity) never depends on the provider
enforcing anything; only the post-commit grant guarantee does — see the threat
model.

### Verification: `S3BlobStore.verifyBlob`

1. One `HEAD` with a signed `x-amz-checksum-mode: ENABLED`.
   - `404` → `OWA_BLOB_MISSING`.
   - `Content-Length` ≠ declared size → `OWA_BLOB_INTEGRITY`, with **no payload
     transfer**.
   - `x-amz-checksum-sha256` present **and equal** to the base64 SHA-256 the
     digest names → verified, method `provider-checksum`, **zero payload bytes**.
2. Otherwise — no evidence, a composite (multipart) value, or a mismatch — a
   **streaming `GET`** through SHA-256, bounded at the declared size, method
   `rehash`. The rehash is definitive, so an ambiguous header is never trusted
   *or* treated as proof of corruption; the bytes decide.

Provider error bodies never surface; every failure is a fixed code, and all
requests use storage credentials only — no OWA bearer is ever sent to storage.

### Direct upload: checksum-bound, create-once grants

`createUpload(digest)` presigns a PUT on the final content-addressed key whose
**SigV4 signed headers** are:

```
x-amz-checksum-sha256: <base64 SHA-256 the digest names>
if-none-match: *
```

and returns them to the client in an additive `headers` field:

```json
{ "digest": "sha256:…", "method": "PUT", "url": "…", "expiresIn": 900,
  "headers": { "x-amz-checksum-sha256": "…", "if-none-match": "*" } }
```

Because both headers are signed, a client cannot omit or change them without
invalidating the grant. Because the provider validates the checksum against the
actual body, the grant can write **only the one correct object**. Because of
create-once, once that object exists the grant cannot write **anything** — not
even the same bytes again.

Trusted writes (`put()`) also send `x-amz-checksum-sha256`, so every object OWA
writes is provider-validated and leaves evidence that later verification can
read with a single `HEAD`.

### The direct-upload TOCTOU, closed

The naive design — GET/hash at commit, then release — is insufficient: a grant
lives up to 900 s, so after commit the same grant could overwrite the key with
arbitrary bytes and the *verified* release would serve corrupt content. Here:

- during the grant's lifetime it can only create the correct object
  (checksum-bound), and only once (create-once);
- after commit, reuse fails with `412` before the checksum is even consulted;
- the committed object is therefore byte-identical to what commit verified.

This is proven offline against an enforcing mock and live against R2: after
commit, the still-valid grant is replayed with wrong bytes and with the right
bytes, both are refused, and the stored bytes are unchanged.

### Corrupt existing object: recovery

Plan used to report any existing key as reusable. That created a permanent loop
for a corrupt object: plan says reused → commit rejects → re-plan says reused.
Plan is now **integrity-aware**:

- exists and verifies → reused;
- exists but **proven** wrong (`OWA_BLOB_INTEGRITY`) → the object is **deleted**
  and an upload grant is issued, so the client's next create-once upload replaces
  it with correct bytes; commit then succeeds and later publishes reuse normally;
- exists but **unverifiable** (`OWA_BLOB_UNVERIFIED`: provider error, non-regular
  filesystem object) → the plan **fails**; a possibly-valid object is never
  deleted on a probe that proved nothing;
- missing → upload grant.

The delete happens under the publish lease plan already took for the digest, so
GC cannot race it. `publishDirectory` behaves the same way with the bytes it
just packed.

### Client behavior

The CLI accepts a grant's `headers` only if it is exactly the integrity-binding
set: `x-amz-checksum-sha256` **equal to the base64 SHA-256 of the digest being
uploaded** (re-derived locally, not trusted from the server) and
`if-none-match` exactly `*`. Anything else — a foreign header, a wrong checksum,
an empty object, headers on a local bearer grant — is `OWA_CLI_GRANT` and no
byte is sent. A `412` on a create-once upload is treated as "already present":
the object can only have been written through a checksum-bound grant for the
same digest, and commit verifies it regardless. Grants without `headers`
(older servers) still work. MCP inherits all of this through the CLI and gains
no integrity logic of its own.

## Cost

| | Filesystem | S3 / R2 with evidence | S3 / R2 without evidence |
| --- | --- | --- | --- |
| Plan, existing blob | 1 streamed local read | **1 HEAD, 0 bytes** | 1 HEAD + 1 streaming GET |
| Plan, missing blob | 1 `existsSync` | 1 HEAD (404) | 1 HEAD (404) |
| Commit, per unique blob | 1 streamed local read | **1 HEAD, 0 bytes** | 1 HEAD + 1 streaming GET |
| Identical re-publish | reads, no writes | **HEADs only — no payload re-download** | GETs again |
| Payload through artifactd | read locally | **none** | streamed, never buffered whole |

"With evidence" means the object's last write was SHA-256-validated by the
provider — true for everything written by OWA after this change (grants and
`put()` both declare the checksum). Objects written **before** this change, or by
external tools without a checksum, carry no evidence and are re-hashed on each
plan and commit until they are re-written through a checksum-bound path. There
is no cheaper way to upgrade evidence in place: R2 does not support
`CopyObject` with a checksum algorithm. Measured live against Cloudflare R2 (single-blob integrity scenario, isolated
prefix): the whole corrupt → repair → commit → replay → re-plan sequence took
`PUT 7, HEAD 10, GET 4, DELETE 1`; **commit itself issued zero `GET`s**, and the
identical re-plan issued zero `GET`s. Of the four `GET`s, one was the legacy
no-evidence rehash and the rest were the test's own byte comparisons. Across the
full live run (publishing, GC and integrity suites, 114 provider requests) every
request used storage SigV4 or a presigned grant; **zero** carried an OWA bearer.

There is **no configuration switch to skip verification**. Production behavior
fails closed; test fixtures use purpose-built mocks.

## Relationship to other mechanisms

- **Publish leases (GC):** unchanged. Plan still leases every unique digest
  before probing; the lease is what makes plan's corrupt-object delete safe from
  a concurrent GC sweep.
- **GC:** unchanged. There is no staging namespace — grants still target the
  final CAS key — so GC's blob enumeration, retention and no-follow guards are
  unaffected.
- **OCI:** `transport-oci` already verified digest and size at its own boundary
  (`OWA_CONTENT_DIGEST_MISMATCH` / `OWA_CONTENT_SIZE_MISMATCH`) when writing and
  reading image layouts. This work brings the host commit boundary to the same
  standard; OCI identity and duplicate-path behavior (issue #9) are untouched.
- **Auth / origins / sandbox:** unchanged. The grant headers are storage grant
  material; they create no OWA capability and never carry a bearer.

## Threat model and residual limits

**Inside** the model, and enforced:

- a client that uploads wrong bytes, truncated bytes, or bytes for the wrong
  digest — rejected by the provider before storage, and by commit regardless;
- a still-valid grant replayed after commit — refused (`412`/`400`), object
  unchanged;
- a corrupt object already at a CAS key — never released, repaired by the next
  publish;
- a symlink or non-regular object where a blob should be — never verified,
  never followed;
- a control plane that hands the CLI a hostile `headers` object — refused
  client-side before any request.

**Outside** the model — stated so it is not overclaimed:

- **An operator or attacker with raw bucket or filesystem write access** can
  overwrite a committed object with storage credentials (or `put()`, or a plain
  `rm`/`cp`). Nothing here makes committed objects immutable against the storage
  administrator. On R2 such an overwrite at least drops the SHA-256 evidence, so
  the next verification falls back to a rehash and fails — but a release that is
  already active is served from storage without re-verification per request.
- **A provider that silently ignores `x-amz-checksum-sha256` or
  `If-None-Match`.** Invariant A still holds on such a provider (commit rehashes
  and refuses corrupt bytes), but the post-commit grant guarantee does not.
  R2 was proven to enforce both; AWS S3 documents both; MinIO could not be
  tested here and is unverified.
- **Serving-time integrity.** Verification happens at plan and commit, not on
  every public GET.
- **A concurrent local filesystem attacker** racing `lstat` against the
  following read is outside the model, as for GC.

Issues #8 (locale-independent pack ordering) and #9 (OCI duplicate-content path
semantics) remain out of scope.
