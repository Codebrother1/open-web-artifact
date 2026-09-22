# Open Web Artifact Specification v0.2 (Draft)

## Status
Experimental. v0.2 adds transport-neutral publishing and deterministic manifest identity while preserving the v0.1 artifact model.

## Core model
An **artifact** is an immutable canonical manifest plus content-addressed blobs. A **release** binds an artifact digest to a site. A **site** owns a mutable `activeReleaseId` pointer. Activation and rollback change only that pointer.

## Manifest
Media type: `application/vnd.openwebartifact.site.v1+json`

The [manifest schema](manifest.schema.json) and the following semantic constraints are normative. A manifest MUST be a JSON object with these required fields:
- `specVersion`: exactly `owa.dev/v1`;
- `artifactType`: exactly the media type above;
- `entrypoint`: an artifact path, normally `/index.html`;
- `files`: a nonempty array of objects, each containing exactly `path`, `digest`, `size`, and `mediaType`.

Each file's `path` MUST satisfy the artifact-path grammar below. Its `digest` MUST be exactly `sha256:` followed by 64 lowercase hexadecimal digits (71 characters total). Its `size` MUST be an integer number from 0 through 9007199254740991 (`2^53 - 1`), inclusive; strings and booleans are not numbers. Its `mediaType` MUST be a nonempty string. This is not a MIME syntax parser: even whitespace-only and non-MIME strings satisfy this field's structural constraint.

Optional root fields are:
- `routing`: an object allowing only optional `spaFallback`, an artifact path;
- `access`: an object allowing only optional `visibility`, exactly `public` or `unlisted`;
- `lifecycle`: an object allowing only optional `expiresAt`, either null or a date-time string as defined below;
- `annotations`: an object with arbitrary string keys and only string, finite number, boolean, or null values. Finite floating-point annotations are permitted; arrays and objects are not annotation values.

All four optional containers MAY be empty objects, but MUST NOT be null, arrays, or scalars. No additional properties are allowed on the manifest, file objects, `routing`, `access`, or `lifecycle`. Missing required fields and additional fields are errors, not defaults to insert or data to discard. Validation MUST NOT mutate the manifest. The reference validator now enforces these already-published schema constraints; this does not change successful canonical serialization.

File paths MUST be unique by exact string equality. `entrypoint` and any present `routing.spaFallback` MUST exactly match a file path. Distinct paths MAY share a content digest. Schema validation alone does not express these cross-field checks. Manifest validation checks metadata only: it does not read blobs, verify their existence, or verify their actual size or hash.

### Artifact paths
An artifact path consists of `/` followed by one or more nonempty segments separated by single `/` characters. A segment MUST NOT be exactly `.` or `..`; backslash and NUL are forbidden anywhere. Thus relative paths, `/` alone, repeated slashes, and a trailing slash are invalid. Validation MUST reject, not repair, such paths.

Paths are namespace strings, not URLs or native filesystem paths. Percent signs and percent-looking escapes are literal; no percent decoding, Unicode normalization, or case folding occurs. Composed and decomposed Unicode strings remain distinct. No other character restriction is implied by this grammar: spaces, `?`, `#`, and non-NUL control characters are not independently forbidden. Hosts MAY apply the stricter security policy allowed below.

### Expiry date-time
A non-null `lifecycle.expiresAt` MUST have the complete form `YYYY-MM-DDTHH:mm:ss[.fraction](Z|+HH:mm|-HH:mm)`, with ASCII decimal digits, exactly four year digits, and no surrounding whitespace. `T`/`t` and `Z`/`z` are accepted. Fractional seconds, when present, contain one or more digits. The month and day MUST form a valid Gregorian calendar date (leap years are divisible by 4, except centuries not divisible by 400). Hours are 00–23; minutes and seconds are 00–59; numeric offset hours are 00–23 and offset minutes 00–59. Leap seconds are not supported, matching the baseline implementation.

Validation MUST NOT depend on a runtime's permissive date parser or rewrite the timestamp string. Date-only, locale-specific, calendar-overflow, and timezone-less strings are invalid. The schema already specified `date-time`; prior reference acceptance of non-RFC3339 dates was an implementation/schema mismatch, not an alternative digest format. Enforcing these checks changes invalid-input acceptance, not canonical bytes.

## Canonical manifest encoding
Artifact identity is `sha256:` followed by the lowercase hexadecimal SHA-256 of the UTF-8 bytes of the canonical JSON string. The following rules describe the existing successful encoding; they do not introduce a new digest format or adopt RFC 8785/JCS.

1. Emit the JSON literals `null`, `true`, and `false`, and the usual JSON punctuation, with no insignificant whitespace. Encode the resulting string as UTF-8 without a byte-order mark or appended newline. Do not normalize Unicode.
2. At every object level, sort decoded keys lexicographically by their sequences of Unicode code-point values. Compare the first unequal value numerically; if one sequence is a prefix, put the shorter first (including the empty key). Do not use locale collation, UTF-16 code-unit order, numeric ordering of integer-looking names, or insertion order. For preserved unpaired surrogate escapes, use the surrogate's numeric value in this comparison.
3. Preserve every array's order, including `files`. Reordering object members does not affect identity; reordering array elements can. Canonicalization does not sort files or add optional fields.
4. Enclose strings and keys in double quotes. Escape `"` as `\"` and backslash as `\\`. Use the short escapes `\b`, `\t`, `\n`, `\f`, and `\r` for U+0008, U+0009, U+000A, U+000C, and U+000D respectively. Escape all other U+0000–U+001F characters as `\u00xx` using lowercase hexadecimal. Leave `/` unescaped. Other Unicode scalar values, including U+2028 and U+2029, remain literal. A paired high/low surrogate JSON escape represents one supplementary code point and is emitted as that character. Preserve an unpaired surrogate as a lowercase four-digit `\uxxxx` ASCII escape, never as a replacement character or invalid UTF-8. A parser unable to preserve such escapes must report that interoperability limitation rather than silently alter the value.
5. Interpret JSON numbers as IEEE 754 binary64, rounding the input decimal to nearest, ties to even. Reject non-finite results, including overflow from otherwise syntactically valid numbers. Serialize either signed zero as `0`; prefix negative nonzero values with `-`. For other values, select the shortest significant decimal digit sequence that rounds back to the same binary64 value; among equally short candidates choose the closest to the exact binary value, breaking a remaining tie with an even final digit. For magnitude `1e-6 <= abs(value) < 1e21`, use fixed notation; otherwise use scientific notation with one digit before the decimal point, lowercase `e`, an explicit `+` for a positive exponent, and no exponent zero padding. Omit an unnecessary decimal point and trailing fractional zeros; keep zeros needed for place value. Examples: `1e-6` becomes `0.000001`, `1e20` becomes `100000000000000000000`, and `1e21` becomes `1e+21`.

These number rules apply to finite floating-point annotations as well as integers. Arbitrary-precision parsing or a host language's default JSON encoder is not necessarily equivalent. Duplicate JSON member names are outside the portable corpus requirements; this specification does not silently choose first-wins or last-wins semantics.

The [language-neutral conformance corpus](conformance/README.md) contains exact canonical strings, static digests, and validation outcomes. The four published files in `docs/test-vectors/basic/` remain byte-for-byte immutable and independently hash-pinned.

## Safe request-path resolution
Request-path resolution is distinct from artifact-path validation. Given a valid manifest and a request-path string, the corpus specifies this algorithm on the direct argument, **not** on a full URL or a URL parser's output:

1. Percent-decode exactly once, interpreting escaped bytes as strict UTF-8. Malformed escapes, truncated or invalid UTF-8, overlong encodings, and UTF-8 encodings of surrogates return null. Do not convert `+` to a space or strip a query or fragment.
2. Reject any decoded backslash, NUL, or segment exactly `..`, returning null **before** considering SPA fallback. This includes encoded separators that reveal a `..` segment after decoding.
3. Make the path absolute with one leading `/`; collapse empty segments and remove `.` segments. Preserve a trailing slash if the decoded path ended in `/`, except that an all-empty/dot path remains `/`. Thus `/a/.` becomes `/a`, but `/a/./` becomes `/a/`. No Unicode normalization or case folding occurs.
4. Return the matching file metadata for an exact path match, or the entrypoint file when the normalized path is `/`. Only after a safe direct lookup miss, return the `spaFallback` file if configured; otherwise return null.

An empty request string therefore resolves the entrypoint. A file path with a trailing slash does not directly match the file. Percent-looking characters produced by the one decoding pass remain literal: `/%252e%252e/secret` may address the literal artifact path `/%2e%2e/secret`, while `/%2e%2e/secret` is rejected. The corpus does not redefine HTTP URL parsing; a host must not let earlier normalization conceal an unsafe path from its security checks.

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

## Directory packing (producer ordering)
Constructing a manifest from a directory is producer behaviour of the reference/conformance `pack` operation, not a property of manifests. When it builds `files`, the pack operation:

1. converts each discovered regular file to its complete OWA artifact path (`/` + the `/`-joined relative path), rejecting symbolic links;
2. does **not** Unicode-normalize, case-fold or otherwise alter that string — the exact name the host filesystem/runtime exposed is the path;
3. sorts the complete path strings with the **same Unicode code-point lexicographic relation** specified for canonical object keys in rule 2 above: compare the sequences of code-point values numerically at the first difference; a proper prefix sorts first; no locale collation, no UTF-16 code-unit order, no natural/numeric ordering, no case folding;
4. places the file entries into `manifest.files` in that order.

Traversal order of the filesystem is irrelevant: only the final sort of complete paths is normative (`/a.txt` sorts before `/a/x.txt` because U+002E precedes U+002F, whatever the directory walk did). Once a manifest exists, its `files` array order is fully specified and preserved by canonicalization; manually authored manifests are **not** required to be sorted, and `validateManifest` does not check ordering.

*Versioning and migration note.* Earlier v0.2 text left arbitrary-Unicode directory-pack ordering undefined (the reference used locale-sensitive collation). Defining it here closes an undefined producer behaviour inside the existing v0.2 draft: no new `specVersion`, media type or manifest field is introduced, canonical JSON and the artifact digest algorithm are unchanged, and every published v0.2 corpus and legacy artifact identity is preserved. Existing stored manifests and releases do not change. Re-packing a directory containing Unicode filenames with an older, locale-sensitive reference and with the corrected one MAY yield a different `files` order and therefore a different artifact digest; no legacy-collation compatibility mode exists because the old result depended on the host's locale/ICU and is not a portable algorithm. The packer operates on the Unicode filename strings the runtime exposes; a portable mapping for filesystem byte names that cannot be represented as such strings is out of scope.

### Entry types
Every entry discovered beneath the directory being packed is classified by inspecting it **without following symbolic links** (an `lstat`-style inspection), and then (issue #40):

1. a **symbolic link** — to a regular file, a directory, a special entry or a missing target — MUST fail with `OWA_SYMLINK`; it is neither followed nor skipped;
2. a **directory** MUST be traversed recursively;
3. a **regular file** MUST be packed under the rules above (artifact path, ordering, media type);
4. any **other** entry — a FIFO/named pipe, a filesystem socket, a character or block device, or anything classified as neither a directory nor a regular file — MUST be skipped: it contributes no `files` entry and no blob; its contents are never opened, read or connected to (only the metadata needed to classify it is inspected); and its presence MUST NOT change the canonical manifest bytes, artifact digest, file order, media types or blob contents produced for the same regular files.

Errors while enumerating a directory or inspecting an entry propagate as before; they are not permission to omit entries silently. Manifest validation then applies to the result unchanged: a tree whose regular files are exhausted by skipping yields `OWA_INVALID_MANIFEST`, and a tree whose only `index.html` (or other requested entrypoint) is a skipped special entry yields `OWA_MISSING_ENTRYPOINT` — a skipped entry never satisfies the entrypoint. This is producer behaviour of directory packing and states what the reference and the independent Go implementation already did; it does not restrict manually authored manifests. It concerns the types of entries observed during traversal only: the pack root itself, ancestor symbolic links, Windows reparse points, hard links and concurrent filesystem mutation during traversal are outside this rule, and no race-freedom is claimed.

### Media type assignment
The pack operation assigns each file entry's `mediaType` from the **complete artifact path alone**, using the extension rule and the fixed table below (issue #33). Like the ordering rule, this is producer behaviour of directory packing: it exists so that two independent packers derive the same `files` entries, canonical JSON and artifact digest from the same directory. It does **not** restrict manually authored manifests, whose `mediaType` remains any nonempty string as specified above.

Given the complete artifact path of a discovered regular file, the **extension lookup key** is derived as follows:

1. Take the final path segment — the text after the final `/`.
2. Find the final U+002E FULL STOP `.` in that segment. If there is none, the file has no extension.
3. If that final `.` is the first character of the segment, the file has no extension: `.env`, `.html` and `.gitignore` are dotfiles, not files with an extension.
4. Otherwise the candidate extension is the substring from that final `.` through the end of the segment: `index.html` → `.html`, `INDEX.HTML` → `.HTML`, `archive.tar.gz` → `.gz`, `archive.tar.JSON` → `.JSON`, `foo.` → `.`, `foo..txt` → `.txt`, `.foo.html` → `.html`.
5. Fold ASCII `A`–`Z` (U+0041–U+005A) to `a`–`z` (U+0061–U+007A) in the candidate, and nowhere else. This is a fixed ASCII mapping, not a locale-sensitive or Unicode-aware case conversion; non-ASCII characters are unchanged. Known extensions are therefore case-insensitive: `INDEX.HTML`, `App.MJS` and `IMAGE.PNG` map exactly as `index.html`, `app.mjs` and `image.png`.
6. Look the folded key up in the table below. A file with no extension, and every key not listed — including the bare `.` of a trailing-dot name and unlisted extensions such as `.gz`, `.zip` or `.md` — maps to `application/octet-stream`.

| Folded extension key | `mediaType` |
| --- | --- |
| `.html`, `.htm` | `text/html; charset=utf-8` |
| `.js`, `.mjs` | `text/javascript; charset=utf-8` |
| `.css` | `text/css; charset=utf-8` |
| `.json` | `application/json; charset=utf-8` |
| `.svg` | `image/svg+xml` |
| `.png` | `image/png` |
| `.jpg`, `.jpeg` | `image/jpeg` |
| `.webp` | `image/webp` |
| `.gif` | `image/gif` |
| `.txt` | `text/plain; charset=utf-8` |
| `.wasm` | `application/wasm` |
| `.ico` | `image/x-icon` |
| `.xml` | `application/xml; charset=utf-8` |
| `.pdf` | `application/pdf` |
| `.woff` | `font/woff` |
| `.woff2` | `font/woff2` |
| anything else, or no extension | `application/octet-stream` |

The table is fixed and closed by this specification. A packer MUST NOT consult a host or operating-system MIME database (`/etc/mime.types`, Windows or macOS type registries, a `mime` library), MUST NOT fetch an external MIME registry, MUST NOT inspect file bytes, and MUST NOT apply compound-extension rules: `archive.tar.gz` uses only `.gz` (unlisted, hence `application/octet-stream`) and `archive.tar.JSON` uses only `.json`. Only the final path segment is examined, so `vendor.json/LICENSE` has no extension. The path string itself is never Unicode-normalized, case-folded or otherwise modified (rule 2 of the ordering list above still holds); only the ASCII lookup key is folded. Charset parameters appear exactly where the table shows them and nowhere else.

*Versioning note.* Earlier v0.2 text did not define pack-time media-type assignment. The JavaScript reference already implemented exactly this table and rule, so every published pack vector, canonical string and artifact digest is unchanged, and defining it here closes an undefined producer behaviour inside the existing v0.2 draft: no new `specVersion`, media type, manifest field, canonical-JSON rule or digest algorithm. The [conformance corpus](conformance/README.md) pins every table entry and the edge cases (`pack-media-type-*`).

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

## Conformance scope and known limitations
The [conformance guide](conformance/README.md) defines operation-specific fixture inputs, success fields, and 18 stable error categories. Adapters in any language map local validation and parse errors to those categories; exception classes and human-readable text are not the contract. This is not an HTTP error-response redesign.

Issue 5 did not fix the following limitations at the time; their current status is noted:
- The reference directory packer then used locale-sensitive `localeCompare` for file ordering and pinned only lowercase ASCII expectations. Pack ordering is now defined above ([Directory packing](#directory-packing-producer-ordering), issue #8) as Unicode code-point order of complete artifact paths, with portable Unicode vectors; a manifest's array order was always fully specified once it existed and MUST be preserved.
- Pack-time media-type assignment was likewise undefined: the reference used a fixed table, but the corpus pinned only `.html`, `.css`, `.js` and `.txt`, so a second implementation could legitimately pack `photo.png` or `INDEX.HTML` to a different artifact digest (surfaced by the independent Go implementation). It is now defined above ([Media type assignment](#media-type-assignment), issue #33) with the reference's existing table and a portable extension rule, and every table entry is corpus-pinned; all previously published vectors are unchanged.
- OCI import at the time indexed layers by digest, collapsing entries with the same content digest and their distinct path annotations. Duplicate-content manifests were always valid; the OCI transport later resolved the round trip (issue #9) by selecting one layer descriptor per file entry through its `dev.openwebartifact.path` annotation while blob bytes stay deduplicated by digest — non-normative transport behaviour, see [oci.md](oci.md). Core manifest semantics did not change.
- *Non-normative OCI transport note:* an OCI layer descriptor `mediaType` must be an RFC 6838 type/subtype, so the OCI transport maps the OWA `mediaType` to that form (`text/html; charset=utf-8` → `text/html`; unrepresentable values → `application/octet-stream`) in descriptors only. The canonical OWA manifest — the OCI config blob — keeps the full value, so manifest validation, canonical JSON and artifact digests are unaffected. See [oci.md](oci.md).
- Commit then checked blob existence only. The reference host now verifies every unique referenced blob's SHA-256 digest **and** size at the commit boundary before a release is persisted (issue #10, see [integrity.md](integrity.md)); that is host behaviour, not a change to this specification. The content-mismatch conformance fixtures still exercise only the OCI read/write boundaries.
- Duplicate JSON member-name policy remains outside portable corpus requirements. Unpaired-surrogate fixtures pin preservation behavior, but implementations must disclose parser limitations rather than substitute characters.

## Named host security profile
The [`sandboxed-web-v1` host policy](sandboxed-web-v1.md) defines an exact, script-disabled static-preview response contract, including CSP/sandbox headers on every application response, whole-string MIME dispatch, indexing and no-store behavior, and required production origin separation. Hosts claiming this profile MUST follow that contract; it does not change the artifact model, manifest validation, canonical identity, publishing, storage or release semantics above. The reference gateway composes its response policy with the merged [HTTP capability auth overlay](auth.md): control routes are protected and identifier-checked, while artifact GET/HEAD and health remain public. It does not enforce the required content-only origin topology; protected control routes still exist on every host. See the [pre-implementation threat model and composition note](sandboxed-web-v1-threat-model.md) and [optional browser-validation guide](sandboxed-web-v1-browser-validation.md) for boundaries and evidence limitations.

## Still deferred
Identity/accounts and broader authentication work beyond the implemented host capability overlay, custom domains, broader OCI/ORAS transport semantics, adoption of RFC 8785/JCS, garbage collection, multi-tenant authorization, billing, forms/data/secret-proxy capabilities. The implemented auth overlay does not change the artifact format.
