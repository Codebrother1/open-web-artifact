# Blob garbage collection

`owa-gc` reclaims blob objects that no stored release references and no
in-progress publish is relying on. It is a **storage operations** tool. It
changes no portable OWA semantics: manifest schema, canonical JSON, artifact
digests, release identity, activation, auth, origin isolation, MCP and OCI are
all untouched, and GC is never exposed over HTTP.

> **This version does not implement release retention or pruning.** No release
> record is ever deleted, no "keep last N", no age-based expiry, no retention
> tiers. Release-retention policy is a separate decision.

## What GC can and cannot delete

**It can delete** a blob object that is *all* of:

1. not referenced by **any** stored release manifest;
2. not covered by an unexpired publish lease;
3. older than the grace cutoff;
4. inside the configured OWA blob namespace;
5. still unreferenced and unleased at the final re-check immediately before deletion.

**It never deletes:**

| Never deleted | Why |
| --- | --- |
| Release records | GC only removes blob objects; metadata is read-only to it |
| Blobs of the **active** release | Release-referenced |
| Blobs of **inactive / superseded** releases | Every release is a root |
| Blobs of very old **rollback targets** | Every release is a root |
| Blobs of releases whose `lifecycle.expiresAt` has passed | An expired artifact is still a stored release; expiry is a serving decision, not a retention decision |
| Site records or `activeReleaseId` pointers | Not GC's concern |
| Objects outside the OWA blob prefix | Enumeration is prefix-confined |
| Anything at all, during a dry run | Dry run performs zero destructive mutation |

**Every stored release is a GC root.** That is the central retention rule: if a
digest appears in any release manifest, the blob survives. Rollback to any
historical release therefore keeps working after a collection.

## Mark/sweep algorithm

```
 1. record scan start time T0 and compute cutoff = T0 - grace
 2. MARK releases: every site -> every release -> every unique file digest
                   (validates ids, slugs, records, manifests; FAILS CLOSED)
 3. MARK leases:   every unexpired publish lease at T0  (FAILS CLOSED)
 4. ENUMERATE:     blob objects inside the OWA blob namespace only
 5. CANDIDATES:    unreferenced AND unleased AND lastModified <= cutoff
 6. dry run  -> report and stop. Nothing is mutated.
 7. apply    -> RE-MARK releases and leases (step 2 and 3 again)
 8.             for each candidate still unreferenced and unleased: delete
                anything newly protected is skipped and counted as a race skip
```

Steps 2–4 all complete before any deletion, so a run never deletes first and
discovers corrupt metadata afterwards.

### Race model

The window between "this is an orphan" (step 5) and "delete it" (step 8) is the
dangerous one: a publish can start, or a commit can land, inside it. The sweep
therefore recomputes both mark sets immediately before deleting and skips
anything that became protected. Two cases are covered and tested:

- an orphan becomes **leased** between scan and sweep → survives;
- an orphan becomes **release-referenced** between scan and sweep → survives.

The `beforeSweep` hook exists so those windows can be exercised deterministically
in tests instead of with sleeps.

**Residual limitations — read these.** This is a conservative collector, not a
transactional one:

- The re-check narrows the window; it does not eliminate it. A lease or commit
  landing in the microseconds between the final re-mark and an individual DELETE
  is still possible. Leases exist so that window is not the only protection.
- Protection is **bounded by lease lifetime**. A client that plans, then waits
  longer than the lease before committing, can have an otherwise-unreferenced
  blob collected and must re-plan. The lease is not permanent.
- GC and the artifactd process do not share a lock. Correctness rests on lease
  protection plus the grace period, not mutual exclusion.
- No claim is made about atomicity across arbitrary metadata/storage backends.

## Publish leases

"Not referenced by a release" is **not** sufficient to prove a blob is garbage:
direct uploads exist in storage before the commit that creates the release.

A successful publish **plan** creates or refreshes a lease for **every unique
digest in the validated manifest** — including digests that already exist in
storage. That last part matters: a digest can currently be an orphan and be
reused by a new plan. If the plan reports it reusable and GC deletes it before
commit, the client was told it need not upload and commit then fails. Leasing
only the missing uploads would leave exactly that hole.

Leases are taken **before** the existence probes, so a blob cannot be collected
between the `has()` that called it reusable and the lease that protects it.

- **Default lifetime: 24 hours** (`PUBLISH_LEASE_TTL_SECONDS`). Deliberately far
  longer than the 900-second direct-upload grant, because the lease must cover
  the whole plan → upload → commit window including retries and re-issued grants.
- **Refresh never shortens.** A repeated plan sets
  `expiry = max(existing, requested)`, so a slow publish is not weakened by a
  later quick re-plan.
- **The local publisher is protected too.** `publishDirectory` takes the same
  leases; protecting only the HTTP path would leave the trusted local path racing
  GC unprotected.
- **Commit needs no lease cleanup.** Once the release exists, release marking
  protects the blobs regardless of the lease, so the lease is simply allowed to
  expire. `--prune-expired-leases` removes expired records during an apply run.
- **The lease also covers integrity repair.** When plan finds an existing object
  whose bytes do not hash to its own key it mints a *repair* upload — a
  checksum-bound direct grant on a proven provider, artifactd's own mediated
  grant otherwise (see [integrity.md](integrity.md)) — it never deletes the object. The lease
  taken above keeps a concurrent GC sweep from collecting the digest while the
  replacement upload is in flight.

### Lease storage

Operational metadata beside the metadata root, never inside an artifact:

```
<metadata-root>/gc-leases/sha256/<hex>.json
{ "digest": "sha256:…", "expiresAt": "2026-06-02T12:00:00.000Z", "updatedAt": "…" }
```

Only those three fields are stored: no bearer token, storage credential,
presigned URL, request header, manifest or arbitrary client metadata. Lease
records are validated on read — a malformed record, or one whose digest
disagrees with its filename, **aborts the run** rather than being skipped. A
lease that cannot be read is a lease that cannot be proven expired.

The same applies to a `<hex>.json` entry that is not a real regular file — a
symlink, a directory, any other object. It is malformed lease state and aborts
the run; it is never followed or read. Silently skipping it would be the
*opposite* of fail-closed: the entry may represent an **active** lease, and
dropping it from the protection set could turn a protected blob into a deletion
candidate. Non-`.json` neighbours in the lease namespace are ignored.

Lease state is not part of artifact identity: it never appears in a manifest,
canonical JSON, artifact digest, release record, OCI image, MCP schema or any
public content response.

## Metadata enumeration

`FilesystemMetadataStore` gained `listSites()` and `listAllReleases(siteId)`.
Both **fail closed**: an unexpected entry, an unreadable or malformed record, a
bad id/slug, a manifest that no longer validates, or a release whose
`artifactDigest` disagrees with its own manifest all throw. Silently skipping an
unreadable release would silently drop its digests from the mark set and delete
live blobs.

`activeReleaseId` is deliberately **not** used to find referenced blobs — all
releases are roots. Duplicate digests across files and releases collapse
naturally into one mark.

That digest/manifest consistency check re-derives identity from metadata already
in hand. It does **not** read or rehash blob bytes; commit-boundary blob
integrity verification (issue #10) lives at commit time, see
[integrity.md](integrity.md), not in the collector.

## Filesystem blob operations

- `listBlobs()` recognizes only `<root>/blobs/sha256/<64 lowercase hex>`.
  Entries are inspected with `lstat`, so a symlink is reported as a link and
  skipped — it is never followed and can never make GC consider a file outside
  the blob root. Unrelated files, other algorithm directories, nested
  directories and non-hex names are ignored, not deleted.
- `delete(digest)` validates the digest, confirms the resolved path is inside the
  blob root, requires the target to be a regular file (never a symlink or a
  directory), and is idempotent: deleting a missing object is not an error.

### No-follow ancestor guard

`lstat` on the final entry is necessary but not sufficient. `readdir()` and
`rm()` follow a symlink at an **ancestor** position — `<root>/blobs`,
`<root>/blobs/sha256` — and a purely lexical containment check
(`resolve`/`relative`/`startsWith`) cannot see it: every child is still spelled
under `<root>/blobs/…` even though the filesystem resolved outside
`OWA_DATA_DIR`. Left unguarded, GC would enumerate an external tree as blobs and
`rm()` an external file through the link.

Every GC-owned directory chain below the configured data root is therefore
walked component by component and each component is `lstat`ed and required to
be a real directory before any enumeration or destructive mutation:

| Namespace | Chain verified | On a symlink |
| --- | --- | --- |
| Blobs | `blobs`, `blobs/sha256` | `OWA_GC_LIST_FAILED` / `OWA_GC_DELETE_FAILED` — fail closed |
| Leases | `gc-leases`, `gc-leases/sha256` | `OWA_GC_LEASE_UNREADABLE` on read/write, `OWA_GC_LEASE_PRUNE_FAILED` on prune — fail closed |
| Metadata | `sites`, `sites/<id>`, `sites/<id>/releases` | `OWA_GC_METADATA_MALFORMED` — fail closed |

The chosen contract for blobs is **fail closed**, not "enumerate nothing": a
symlink in an operational position is a misconfiguration signal, and an empty
enumeration could hide it. Because the listing throws, the collector aborts
before any deletion. A symlinked `releases` directory is malformed metadata, so
external JSON can never pose as the release roots that decide what survives. A
symlinked lease namespace is neither read as lease state nor written through,
and `--prune-expired-leases` re-verifies the chain immediately before its
destructive pass and requires each record to be a regular file.

The data root itself is operator configuration and is not inspected; pointing
`OWA_DATA_DIR` at a symlink is a legitimate deployment choice.

**Limitation — concurrent local mutation.** This guard defends against
*pre-existing* symlinks. Node exposes no `openat`/`unlinkat`-style API, so there
is a window between the `lstat` check and the following `readdir`/`rm` in which
a local attacker with write access to `OWA_DATA_DIR` could swap a directory for a
symlink. A concurrent privileged attacker on the same filesystem is outside the
reference threat model: `OWA_DATA_DIR` is assumed to be writable only by the
operator and artifactd.

## S3 / R2 blob operations

Implemented with the existing dependency-light SigV4 signer. No AWS SDK was
added.

- **`listBlobs()`** issues `ListObjectsV2` (`list-type=2`) scoped to
  `<prefix>/blobs/sha256/`, following `NextContinuationToken` until the listing
  is complete. Only keys matching the exact OWA grammar become results: a
  neighbouring object, a nested key, another algorithm, a malformed key or a
  different prefix is ignored, so GC can never offer unrelated bucket contents as
  a candidate. A truncated listing with no continuation token fails closed.
- **`delete(digest)`** deletes one exact validated key, signed with storage
  credentials only. 404 is accepted as idempotent success.

### Query signing: one serialization

`signedFetch` gained an optional `query` parameter. The default is no query
string, so every pre-existing caller signs byte-identically to before and the
publish presign path is untouched.

The canonical query string — sorted, RFC 3986 encoded by the signer's own
encoder — is **both what is signed and what is transmitted**, byte for byte.
The request URL is assembled from that exact string; the logical query is never
re-serialized through a second encoder. This matters because WHATWG
`URLSearchParams` uses form encoding, where a space becomes `+` while SigV4
canonicalization uses `%20`: two encoders would produce a valid signature for
a *different* request, and a continuation token containing a space would be
rejected by the provider. Continuation tokens are opaque and routinely contain
`/`, `+`, `=`, spaces and `&`; all are encoded as `%2F`, `%2B`, `%3D`, `%20`
and `%26` on the wire.

Tests assert this on the **raw** URL string handed to `fetch`, not via
`URL.searchParams` (which decodes `+` and `%20` to the same value and would hide
the mismatch), and pin the resulting `Authorization` header to the value an
independent implementation (botocore `S3SigV4Auth`) produced for the same
request. A session token, when configured, is signed and included in
`SignedHeaders` for both LIST and DELETE.

### XML response decoding

S3 XML escapes character data, so an opaque token `a&b` arrives as `a&amp;b`
and a key under a prefix containing `&` is escaped the same way. `<Key>` and
`<NextContinuationToken>` text is decoded with a small strict, dependency-free
decoder before use: the five named entities (`&amp; &lt; &gt; &quot; &apos;`)
and decimal/hexadecimal character references. Keys are decoded **before**
prefix/grammar validation, so a prefix containing XML-significant characters
still matches its real objects.

The decoder **fails closed**. A bare `&`, an unknown or unterminated reference,
a NUL/surrogate/out-of-range code point, or a `<` inside character data throws
`OWA_GC_LIST_FAILED`. Because the listing throws, no follow-up request is made
with a guessed token, pagination cannot loop, and the collector aborts before
any deletion rather than sweeping from an incomplete candidate set.

Provider error bodies, signed URLs, credentials and `Authorization` values are
never surfaced: storage failures become fixed `OWA_GC_*` codes.

## Operator interface

GC is local-only. There is no HTTP route and no new bearer capability.

```sh
npm run gc                              # dry run (the default)
npm run gc -- --apply                   # delete the reported candidates
npm run gc -- --grace-seconds=604800    # 7-day grace
npm run gc -- --json                    # structured report
npm run gc -- --prune-expired-leases    # also drop expired lease records (apply only)
node packages/gc/src/cli.js             # same, without npm
```

Storage and metadata come from the **same** environment artifactd uses
(`OWA_DATA_DIR`, `OWA_STORAGE`, `OWA_S3_*`), so GC always points at the namespace
the server writes to.

- **Dry run is the default.** You never have to type a flag to get preview
  behavior, and you cannot delete by accident.
- **Default grace: 24 hours** (`DEFAULT_GRACE_SECONDS`). An object must be idle
  this long to be collectible. Do not lower it to make a test convenient.
- An unrecognized flag or a non-canonical `--grace-seconds` value exits non-zero
  rather than silently running with a surprising grace.

### Report fields

| Field | Meaning |
| --- | --- |
| `mode` | `dry-run` or `apply` |
| `graceSeconds`, `graceCutoff` | Configured grace and the resulting cutoff |
| `sitesScanned`, `releasesScanned` | Metadata covered by the mark phase |
| `releaseDigestsMarked` | Unique digests protected by releases |
| `activeLeases` | Unexpired publish leases at scan time |
| `blobsScanned`, `bytesScanned` | Objects enumerated in the OWA namespace |
| `referencedSkipped` | Skipped because a release references them |
| `leasedSkipped` | Skipped because a publish lease protects them |
| `youngSkipped` | Skipped because they are newer than the cutoff |
| `candidates`, `candidateBytes` | Would be / were reclaimed |
| `deleted`, `deletedBytes` | Actually deleted (always 0 in dry run) |
| `raceSkipped` | Became protected between scan and sweep |
| `expiredLeasesCleaned` | Expired lease records removed |
| `candidateDigests` | The candidate digests themselves |

The report contains only counts, bytes and digests. It never contains storage
keys with query material, credentials, bearer tokens, `Authorization` headers,
presigned URLs, provider response bodies or environment dumps.

## Failure behavior

GC **fails closed**. No deletion occurs when metadata enumeration is incomplete,
a site or release cannot be parsed, a manifest fails validation, a release
contradicts its own digest, lease state cannot be trusted, blob listing fails, or
configuration is malformed. In dry run these conditions raise an error rather
than printing a misleading candidate set.

Errors are fixed codes: `OWA_GC_METADATA_UNREADABLE`, `OWA_GC_METADATA_MALFORMED`,
`OWA_GC_MANIFEST_INVALID`, `OWA_GC_LEASE_MALFORMED`, `OWA_GC_LEASE_UNREADABLE`,
`OWA_GC_LIST_FAILED`, `OWA_GC_DELETE_FAILED`, `OWA_GC_INVALID_DIGEST`,
`OWA_GC_INVALID_CONFIG`.

## Known limitations

- Bounded lease lifetime: a publish that stalls past 24 hours may need to re-plan.
- The final re-check narrows but does not eliminate the race window.
- No release retention/pruning; storage occupied by old releases is never
  reclaimed by this tool, by design.
- No scheduler or daemon: an operator runs it.
- Blob integrity is not verified (issue #10). GC trusts the digest-addressed
  path and metadata identity already present.
- `S3BlobStore.listBlobs()` holds the listing in memory; very large buckets would
  want a streaming variant.
- Filesystem enumeration reports `mtime`, which an operator or backup restore can
  move. The grace period assumes plausible modification times.
- The no-follow ancestor guard defends against pre-existing symlinks only. A
  concurrent local attacker able to mutate `OWA_DATA_DIR` between the `lstat`
  check and the following operation is outside the reference threat model.
