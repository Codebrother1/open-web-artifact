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

Issue 5 does not fix the following existing limitations:
- The reference directory packer uses locale-sensitive `localeCompare` for file ordering. The pack fixtures pin explicit expected arrays for lowercase ASCII names, not universal cross-locale ordering of arbitrary Unicode filenames. Once a manifest exists, its array order is fully specified and MUST be preserved.
- OCI import indexes layers by digest, collapsing entries with the same content digest and potentially conflicting path annotations. Duplicate-content manifests are valid; supporting all such OCI round-trips is a separate transport issue.
- Commit checks blob existence, not stored bytes' hashes or lengths. Content-mismatch fixtures exercise existing OCI read/write verification only; they do not add commit-time or S3 verification.
- Duplicate JSON member-name policy remains outside portable corpus requirements. Unpaired-surrogate fixtures pin preservation behavior, but implementations must disclose parser limitations rather than substitute characters.

## Named host security profile
The [`sandboxed-web-v1` host policy](sandboxed-web-v1.md) defines an exact, script-disabled static-preview response contract, including CSP/sandbox headers on every application response, whole-string MIME dispatch, indexing and no-store behavior, and required production origin separation. Hosts claiming this profile MUST follow that contract; it does not change the artifact model, manifest validation, canonical identity, publishing, storage or release semantics above. The reference gateway composes its response policy with the merged [HTTP capability auth overlay](auth.md): control routes are protected and identifier-checked, while artifact GET/HEAD and health remain public. It does not enforce the required content-only origin topology; protected control routes still exist on every host. See the [pre-implementation threat model and composition note](sandboxed-web-v1-threat-model.md) and [optional browser-validation guide](sandboxed-web-v1-browser-validation.md) for boundaries and evidence limitations.

## Still deferred
Identity/accounts and broader authentication work beyond the implemented host capability overlay, custom domains, broader OCI/ORAS transport semantics, adoption of RFC 8785/JCS, garbage collection, multi-tenant authorization, billing, forms/data/secret-proxy capabilities. The implemented auth overlay does not change the artifact format.
