# Commit-boundary blob integrity

Issue #10. This document defines the **host integrity invariant** the reference
server enforces when it turns a manifest into an immutable release, how each
storage backend satisfies it, and — just as importantly — how an upload grant
still held by the publisher is prevented from corrupting a committed object
afterwards. For S3-compatible storage that rests on two **separate, explicit
provider capabilities**: whether a provider-returned checksum counts as proof
(`checksumEvidence`), and whether a publisher may hold a direct grant on a
final CAS key at all (`directUploadIntegrity`). Both default to the safe side
for any endpoint that has not been proven live.

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
4. the file is **streamed** through SHA-256 while counting bytes — never
   buffered whole — bounded by its real on-disk size;
5. bytes that do not hash to the key → `OWA_BLOB_INTEGRITY` attributed to the
   **object**; bytes that hash correctly but whose size differs from the
   declared size → `OWA_BLOB_INTEGRITY` attributed to the **manifest**;
6. otherwise verified.

A size disagreement alone is deliberately **not** treated as proof that the
object is corrupt: the whole object is hashed so plan can tell "corrupt object"
from "wrong manifest declaration" and never repairs a valid object.

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

**MinIO, measured live** — no prebuilt binary was obtainable, so MinIO was built
from source at tag `RELEASE.2025-10-15T17-29-55Z` (commit
`9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`) with `go1.27.1`, run per
[integration-tests.md](integration-tests.md) on `127.0.0.1:9000`, path-style,
region `us-east-1`, Node v24.14.1:

| Probe | MinIO result |
| --- | --- |
| Presigned PUT with signed `x-amz-checksum-sha256`, correct bytes | `200` |
| **Same grant, same-length WRONG bytes, header claims the right checksum** | **`400 XAmzContentChecksumMismatch`** — object unchanged |
| Same grant, signed checksum header omitted | `400 AccessDenied` (rejected; R2 answers `403`) |
| Same grant, checksum header changed | `403 SignatureDoesNotMatch` |
| `HEAD` + signed `x-amz-checksum-mode: ENABLED` after a validated PUT | `200`, `x-amz-checksum-sha256` present and equal |
| `GetObjectAttributes` | `200` with `ChecksumSHA256` (unlike R2) |
| Signed `If-None-Match: *`, first write / replay / header omitted | `200` / `412 PreconditionFailed` / `400 AccessDenied` |
| The pre-change host-only grant, wrong bytes | `200` — object corrupted (same hole as R2) |
| `HEAD` after a checksum-less write | no SHA-256 evidence |

So both tested providers enforce the checksum against payload bytes, honour
create-once, and return validated evidence on `HEAD`. Even so, **the reference
implementation does not assume this of an arbitrary endpoint** — see the two
capabilities below. Invariant A (commit integrity) never depends on provider
enforcement. The post-commit grant guarantee depends on it only where a direct
grant is issued at all, and a direct grant is issued only where the contract is
proven.

### Provider checksum trust boundary

A checksum returned by `HEAD` is strong proof **only** if the provider validated
it against the bytes it stored. A lax S3-compatible service could store a
caller-supplied `x-amz-checksum-sha256` unvalidated and echo it back; trusting
that would let corrupt bytes commit. `S3BlobStore` therefore carries an explicit
capability, `checksumEvidence`:

| Value | Meaning |
| --- | --- |
| `enforced` | The provider is known to validate the checksum against stored bytes. The zero-byte `HEAD` fast path is allowed. |
| `advisory` | The header is informational. Verification **always** streams and rehashes the object. |
| unset (default) | Automatic: only hosts proven live to enforce — currently `*.r2.cloudflarestorage.com` — are `enforced`; **every other endpoint is `advisory`**. |

Operators set `OWA_S3_CHECKSUM_EVIDENCE=enforced` after verifying their provider
(MinIO at the tag above qualifies; AWS S3 documents the behavior but was not
run here, so it defaults to `advisory`). Any other value is rejected. There is
**no** value that skips verification: the worst misconfiguration in the safe
direction costs bandwidth, never correctness. Asserting `enforced` for a
provider that does not actually validate is the one way to weaken this, and it
is an explicit operator claim, not a default.

### Direct-upload integrity capability

Checksum evidence answers "can a `HEAD` replace a rehash?". A different question
decides whether the publisher may **hold a presigned grant on a final CAS key at
all**. A grant lives up to 900 s, so it outlives commit. Commit can rehash the
object and be perfectly correct at time *T*; if the provider does not actually
enforce the signed checksum and `If-None-Match`, the same grant replayed at
*T+1* overwrites the key with arbitrary bytes and an **active release now serves
corrupt content**. The repair grant is the sharpest case: it intentionally omits
create-once, so its post-commit safety rests entirely on checksum enforcement —
and for an unknown provider that enforcement is precisely what has not been
established. `S3BlobStore` therefore carries a second capability,
`directUploadIntegrity`:

| Value | Meaning |
| --- | --- |
| `enforced` | The provider is known to enforce the **complete** direct-grant contract: the signed `x-amz-checksum-sha256` is validated against the payload; a signed header cannot be omitted or altered; `If-None-Match: *` refuses overwrite on a presigned PUT; a checksum-only repair grant still cannot write bytes that fail the checksum. Publishers receive direct presigned grants. |
| `mediated` | The publisher receives **no storage credential**. Plan issues artifactd's own scoped upload grant; the client sends the bytes to artifactd, which verifies `sha256(bytes) === digest` and only then writes them with its storage credentials through `put()`. |
| unset (default) | Automatic: only hosts proven live — currently `*.r2.cloudflarestorage.com` — are `enforced`; **every other endpoint is `mediated`**. |

`OWA_S3_DIRECT_UPLOAD_INTEGRITY=enforced` is the operator's explicit assertion
after verifying a provider. MinIO at the tag above qualifies, but an arbitrary
MinIO endpoint cannot be recognised from its hostname, so it is never assumed.
Any other value (`off`, `skip`, `unsafe`, `trust-all`, …) fails at
construction/startup; there is no value that weakens integrity. The two
capabilities are **independent**: asserting one never unlocks the other. A
`checksumEvidence: enforced` store on a mediated endpoint still relays bytes
through artifactd; a `directUploadIntegrity: enforced` store with advisory
evidence still rehashes at verification. Getting either wrong in the safe
direction costs bandwidth or control-plane transfer, never correctness.

The decision is **explicit, not inferred**. The server does not ask whether the
store *implements* `createUpload()` — an S3 store always does — but whether it
*declares* the capability: `blobs.canCreateSafeDirectUpload()`. A store without
that method is mediated. In mediated mode the store's `createUpload()` also
refuses to sign, so a publisher-held grant cannot escape through any caller.
Core (`planManifest`) is unaware of all of this: it calls the same
`uploadFactory` for a missing object and for a repair, and the server decides
what that factory returns.

#### The mediated path

```
publisher ──POST plan───▶ artifactd: authorize(plan); per missing/corrupt digest:
                                     authorize(plan, upload) → scoped local grant
publisher ──PUT bytes───▶ artifactd: local signature + site scope + `upload`;
                                     read body; re-check bearer and grant expiry;
                                     sha256(bytes) === digest, else 400;
                                     blobs.put(digest, bytes)   ← storage credentials
publisher ──POST commit─▶ artifactd: verifyBlob(digest, size) per unique digest
```

This is the filesystem backend's existing upload route, unchanged; it merely no
longer refuses S3 stores that run mediated. It already has the right shape: the
OWA `upload` capability is required at plan and again at upload; the grant is
scoped to the site and expires; the digest is verified before any backend
write; the publisher never sees a storage URL, header or credential; a replay
with wrong bytes fails the digest check before storage; a replay with the
correct bytes while still authorized can only restore identical content. That
artifactd then writes to S3 is fine — the publisher no longer owns a
post-commit storage credential. A repair uses the very same grant: `put()`
overwrites the corrupt key with the verified bytes.

The client sees exactly the local bearer grant shape it already knows
(`authorization: "bearer"`, same control origin,
`/v1/uploads/:digest?expires&sig&site`, no `headers`). The CLI gains no
S3-specific fallback logic, and MCP inherits CLI behavior unchanged.

### Verification: `S3BlobStore.verifyBlob`

1. One `HEAD` with a signed `x-amz-checksum-mode: ENABLED`.
   - `404` → `OWA_BLOB_MISSING`.
   - With `enforced` trust and `x-amz-checksum-sha256` **equal** to the expected
     value: the object matches its key. If `Content-Length` also equals the
     declared size → verified, method `provider-checksum`, **zero payload bytes**.
     If not → `OWA_BLOB_INTEGRITY` attributed to the **manifest** (`size`): the
     object is valid and is never touched.
2. Otherwise — advisory trust, no evidence, a composite (multipart) value, or a
   mismatch — a **streaming `GET`** through SHA-256 of the **whole actual
   object** (bounded by its real length), method `rehash`. Then:
   - bytes do not hash to the key → `OWA_BLOB_INTEGRITY` attributed to the
     **object** (`digest`);
   - bytes hash to the key but the declared size differs → attributed to the
     **manifest** (`size`);
   - both agree → verified.

The attribution (`reason`) is internal: HTTP clients see only
`OWA_BLOB_INTEGRITY`. Provider bodies never surface; every request uses storage
credentials only — no OWA bearer is ever sent to storage.

### Direct upload: checksum-bound, create-once grants

Where `directUploadIntegrity` is `enforced`, `createUpload(digest)` presigns a
PUT on the final content-addressed key whose **SigV4 signed headers** are:

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

This is proven offline against an enforcing mock and live against R2 and MinIO
(explicit `enforced`): after commit, the still-valid grant is replayed with
wrong bytes and with the right bytes, both are refused, and the stored bytes are
unchanged.

On a provider **not** proven to enforce those semantics none of this can be
relied upon — which is why such a provider never issues a direct grant in the
first place. The mediated path closes the same TOCTOU differently: the only
credential that can write the final key stays inside artifactd, and the
publisher's grant is honoured only for bytes that hash to the digest. An offline
regression models a provider that stores an unvalidated checksum, echoes it on
`HEAD` and ignores `If-None-Match`: a store *wrongly* asserted `enforced` lets a
replayed grant corrupt the committed object, while the default (mediated) flow
on the same provider keeps it byte-identical.

### Corrupt existing object: non-destructive repair

Plan used to report any existing key as reusable, which for a corrupt object was
a permanent loop: plan says reused → commit rejects → re-plan says reused. Plan is
now **integrity-aware and non-destructive** — it never deletes or overwrites CAS
state, because the CAS is global and an object may be serving other sites'
releases. The decision turns on *why* verification failed:

| Verification outcome | Meaning | Plan does |
| --- | --- | --- |
| verifies | reusable | reuse, no grant |
| `INTEGRITY` / `digest` | stored bytes do **not** hash to their own key: the **object** is corrupt and cannot serve any release naming it | mint a **repair upload**: a direct repair grant where `directUploadIntegrity` is `enforced`, artifactd's mediated grant otherwise |
| `INTEGRITY` / `size` | bytes hash to the key; the **submitted manifest** declared the wrong size; the object is valid | **fail the plan**; nothing minted, nothing touched |
| `UNVERIFIED` | no proof either way | fail the plan; nothing touched |
| `MISSING` | gone since `has()` | ordinary upload grant |

On an enforced provider a **repair grant** is a presigned PUT on the same key
with the signed `x-amz-checksum-sha256` header but **without** `If-None-Match: *`,
because replacement is the point. It remains bound to the digest exactly as
strongly as a normal grant: it can only ever write bytes whose SHA-256 is the
digest, wrong bytes are refused by the provider, and replaying it after commit —
even with the correct bytes — can only restore the identical content. Because it
is overwrite-capable by design, it is exactly the grant that must never reach a
publisher on an unproven provider: in mediated mode the repair is artifactd's own
scoped grant, the upload route hashes the bytes and `put()` overwrites the
corrupt key, and no overwrite-capable storage credential reaches the client.
Repair uploads of either kind are minted through the same `uploadFactory` as
normal ones, so the `upload` capability check precedes any CAS-affecting
instrument; a token holding only `plan` can neither delete, overwrite, nor
obtain a direct or mediated grant. On the filesystem backend — and on S3 in
mediated mode — the local upload route already writes only bytes that hash to
the digest and overwrites in place, so it is the repair path there.

The wrong-size case was a real bug in the first revision of this work: a
manifest that lied about the size of a valid, shared object caused plan to
*delete* it — before the upload capability was even checked. Regressions now
plant a valid object behind an active release on one site, submit a lying
manifest for another site, and assert zero deletes, zero writes, zero grants,
byte-identical content, unchanged release metadata, and that the first site
still serves the bytes — on the filesystem, on an S3-shaped store in both trust
modes, through the real control listener with a plan-only token, and live on
R2 and MinIO.

### Client behavior

The CLI accepts a grant's `headers` only if it is drawn from the integrity-binding
set: `x-amz-checksum-sha256` **equal to the base64 SHA-256 of the digest being
uploaded** (re-derived locally, not trusted from the server) and, when present,
`if-none-match` exactly `*`. A normal grant carries both; a repair grant carries
only the checksum. Anything else — a foreign header, a wrong checksum,
an empty object, headers on a local bearer grant — is `OWA_CLI_GRANT` and no
byte is sent. A `412` on a create-once upload is treated as "already present":
the object can only have been written through a checksum-bound grant for the
same digest, and commit verifies it regardless. Grants without `headers`
(older servers) still work. A mediated S3 backend returns the marked local
bearer grant, so the CLI's existing local-grant validation applies unchanged and
the CLI never learns which storage backend it is publishing to. MCP inherits all
of this through the CLI and gains no integrity or provider logic of its own.

## Cost

| | Filesystem | S3/R2, `enforced` trust + evidence | S3/R2, `advisory` trust or no evidence |
| --- | --- | --- | --- |
| Plan, existing blob | 1 streamed local read | **1 HEAD, 0 bytes** (plus `has()`'s HEAD) | 1 HEAD + 1 streaming GET |
| Plan, missing blob | 1 `existsSync` | 1 HEAD (404) | 1 HEAD (404) |
| Commit, per unique blob | 1 streamed local read | **1 HEAD, 0 bytes** | 1 HEAD + streaming GET |
| Identical re-publish | reads only | **HEADs only — no re-download** | GETs again |
| Payload through artifactd | local read | **none** | streamed, never buffered whole |
| Wrong-size manifest against a valid object | full local hash | **0 bytes** (evidence settles it) | full streaming hash to attribute the fault |

"Evidence" means the object's last write was SHA-256-validated by the provider —
true for everything OWA writes after this change (grants and `put()` both
declare the checksum). Objects written before it, or by external tools, carry no
evidence and are rehashed on each plan/commit until re-written through a
checksum-bound path; there is no in-place upgrade (R2 lacks `CopyObject` with a
checksum algorithm). A generic endpoint left at the default `advisory` trust pays
one streaming GET per unique blob per plan and per commit — the price of not
assuming what the provider has not proven.

Upload-path cost, by `directUploadIntegrity`:

| | `enforced` (direct) | `mediated` |
| --- | --- | --- |
| Payload bytes through artifactd | none | every uploaded blob, once (buffered, as the filesystem route already does) |
| Storage requests per uploaded blob | 1 presigned PUT by the publisher | 1 authenticated PUT by artifactd |
| Publisher-held storage credential | a checksum-bound presigned grant, ≤ 900 s | **none** |
| Wrong bytes | reach the provider and are refused there | refused by artifactd; never reach the provider |
| Post-commit replay of the grant | refused by the provider (`412`/`400`) | refused by artifactd's digest check |

Measured live (integrity scenario: wrong-size attack, corrupt → repair → commit →
replays, fresh grant, re-plan, legacy rehash), isolated prefixes:

| Provider / capabilities | PUT | HEAD | GET | Presigned | Bearer to storage |
| --- | --- | --- | --- | --- | --- |
| MinIO, default (`advisory` + `mediated`) | 6 | 15 | 15 | **0** | 0 |
| MinIO, explicit `enforced` + `enforced` | 11 | 15 | 10 | 8 | 0 |
| Cloudflare R2, auto (`enforced` + `enforced`) | 11 | 15 | 10 | 8 | 0 |

Under the defaults the five wrong-byte attempts of the scenario never reach the
provider (5 fewer PUTs, 0 presigned requests), while advisory trust rehashes at
each verification (the extra GETs). Under `enforced` the four fewer GETs are
exactly the fast-path verifications; commit issued zero GETs there. There is
**no configuration switch to skip verification**. Production behavior fails
closed; test fixtures use purpose-built mocks.

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
  material; they create no OWA capability and never carry a bearer. Mediated S3
  uploads reuse the existing `upload` capability, local grant signature and
  `PUT /v1/uploads/:digest` route: no new capability, token field or route.

## Threat model and residual limits

**Inside** the model, and enforced:

- a client that uploads wrong bytes, truncated bytes, or bytes for the wrong
  digest — rejected by the provider before storage, and by commit regardless;
- a still-valid direct grant replayed after commit — refused (`412`/`400`),
  object unchanged;
- a still-valid mediated grant replayed after commit with wrong bytes — refused
  by artifactd's digest check before any storage write; with the correct bytes it
  can only restore identical content;
- an S3-compatible endpoint whose direct-upload semantics are unknown — receives
  no direct final-CAS grant at all;
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
- **An operator asserting `enforced` for a provider that does not actually
  enforce.** Under the defaults a provider that silently ignores
  `x-amz-checksum-sha256` or `If-None-Match`, or echoes an unvalidated checksum,
  is `advisory` + `mediated`: commit rehashes and refuses corrupt bytes, and no
  publisher ever holds a grant on its final CAS keys, so there is nothing to
  replay — regressions prove both. What the model cannot protect is an explicit
  `enforced` claim for such a provider; a regression shows exactly what that
  misconfiguration costs. R2 and MinIO (tag above) are proven; AWS S3 documents
  the behavior but was not run here and therefore defaults to the safe path.
- **Serving-time integrity.** Verification happens at plan and commit, not on
  every public GET.
- **A concurrent local filesystem attacker** racing `lstat` against the
  following read is outside the model, as for GC.

Issues #8 (locale-independent pack ordering) and #9 (OCI duplicate-content path
semantics) were out of scope for this work; #9 has since been resolved in the OCI
transport (see [oci.md](oci.md)), #8 remains open.
