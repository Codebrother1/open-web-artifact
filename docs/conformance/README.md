# OWA v0.2 conformance corpus

The seven JSON files in [`v0.2/`](v0.2/) are the portable contract for issue 5. A runner in another language can consume them without importing or executing JavaScript. [`spec-v0.2.md`](../spec-v0.2.md) defines the encoding and validation rules; [`manifest.schema.json`](../manifest.schema.json) describes manifest structure. The Node tests are one adapter, not the definition of JSON, Unicode, numbers, dates, or paths.

This work preserves successful canonical bytes and artifact digests. It clarifies underspecified behavior, brings validation into line with published schema constraints, and assigns stable failure categories. It does not change the architecture, storage protocol, or HTTP error format.

## Corpus format

Each file contains:

- `format`: exactly `owa-conformance-v1`;
- `specVersion`: exactly `owa.dev/v1` (the manifest version, distinct from this corpus directory's v0.2 release label);
- `operation`: the filename without `.json`;
- `notes`: operation-specific setup and scope;
- `vectors`: independent cases, each with a globally unique `id`, `description`, exactly one of `input` or `inputJson`, and `expected`.

`input` is a JSON value. `inputJson` is a string containing a **second JSON document**: parse that text once before performing the operation. Do not trim it, remove a BOM, interpret it as a URL, apply hidden defaults, or merge it with another fixture. Normal JSON whitespace is allowed by the parser. Use strict JSON syntax and the specification's binary64 number semantics; a valid numeric token that overflows binary64 is an invalid JSON *value*, not a syntax error.

On failure, `expected` contains only `errorCategory`. Success must compare all fields listed below. An unrelated exception, a setup error, or an unexpected success MUST NOT pass a negative case. Request rejection is different: `resolvedPath: null` is a successful resolver result, not an exception.

`canonicalJson` is the exact canonical **string after parsing the outer fixture JSON**, not the outer file's quoted or escaped representation. Compare its UTF-8 bytes with no BOM, added newline, or Unicode normalization. Digests use `sha256:` plus 64 lowercase hexadecimal digits. Never regenerate expected strings or digests from the implementation under test.

## Operations and expected fields

| File / operation | Input and procedure | Successful `expected` fields |
| --- | --- | --- |
| [`canonical.json`](v0.2/canonical.json) / `canonical` | Parse `inputJson`, then canonicalize the resulting JSON value; no manifest validation. | `canonicalJson`, `digest` of its UTF-8 bytes. |
| [`manifest.json`](v0.2/manifest.json) / `manifest` | Parse the complete `inputJson`, validate structure and semantic references without reading blobs, then canonicalize without mutation. | `canonicalJson`, `artifactDigest`. |
| [`path.json`](v0.2/path.json) / `path` | Validate `input` as an artifact namespace path, without repairing it. | `validatedPath`, exactly the original string. |
| [`request.json`](v0.2/request.json) / `request` | Validate `input.manifest`, then resolve the direct `input.urlPath` string using the safe request algorithm. Do not first parse a URL. | `resolvedPath`: a manifest file path or null. On a match the resolver returns all metadata of that exact file, not merely a synthesized path. |
| [`parse.json`](v0.2/parse.json) / `parse` | Parse `inputJson` exactly, then canonicalize; no manifest validation. Parser syntax failures map to `OWA_INVALID_JSON`. | `canonicalJson`, `digest`. |
| [`pack.json`](v0.2/pack.json) / `pack` | Materialize `input.files`, then `input.symlinks`, under an isolated directory; pack with `input.entrypoint`. | `manifest` (structural equality, preserving arrays), `canonicalJson`, `artifactDigest`, `blobDigests` (the exact sorted unique digest list). Also compare every returned blob with independently hashed source bytes. |
| [`blob.json`](v0.2/blob.json) / `blob` | First validate `input.manifest` successfully, even in negative cases. Then exercise `input.boundary` as described below. | `canonicalJson`, `artifactDigest`, `blobs` (exact digest-to-bytes contents). The returned manifest must structurally equal `input.manifest`. |

### Filesystem and blob setup

A setup file is `{ "path": "relative/path", "contentBase64": "..." }`. Decode canonical base64 to exact bytes; do not treat it as text or translate line endings. Setup paths are relative, nonempty, contain no backslash or NUL, and have no empty, `.` or `..` segments. Create parent directories and reject duplicate setup paths. Always clean up the isolated directory, including on failure.

For `pack`, a symlink is `{ "path": "relative/link", "target": "relative/target" }`, optionally with `targetType: "directory"` as an OS setup hint. Its target is relative to the link. Symlinks must be rejected rather than followed, including safe-looking and dangling links. The expected manifest explicitly pins media types, pack defaults (`access.visibility: "unlisted"`, `lifecycle.expiresAt: null`), and file-array order for these inputs. Two paths with identical bytes remain two file entries but share one returned blob.

For `blob`:

- `boundary: "oci-write"`: decode `input.blobs`, an array of `{digest, contentBase64}`, into a source map keyed by the **declared** digest. Invoke OCI layout writing; after success, read it back and check the manifest, identity, and all `expected.blobs` bytes. Do not replace a declared digest with the actual hash before calling the writer; mismatch cases intentionally differ.
- `boundary: "oci-read"`: materialize `input.layoutFiles` verbatim and read the static OCI layout. Do not recreate or repair its descriptors, manifest, config, or content first.
- The existing write boundary checks size before digest; `blob-write-size-mismatch` deliberately has both wrong size and wrong hash. The reader verifies a blob's hash before its descriptor size, and separately checks layer size against manifest size. The read size cases isolate those checks with otherwise valid hashes. No general precedence for every possible combination of invalid inputs is implied.
- OCI layer descriptors carry the **transport** media type, not the OWA `mediaType` string: the RFC 6838 type/subtype before the first `;` (SP/HTAB trimmed) when it satisfies the OCI image-spec descriptor grammar, otherwise `application/octet-stream`. `text/html; charset=utf-8` in the OWA manifest is `text/html` in the layer descriptor; the full OWA value lives only in the config blob, which is the canonical manifest. The static `blob-read-*` layouts use that representation, and the reader rejects a layer whose descriptor media type is not the mapped value. This is OCI transport encoding ([docs/oci.md](../oci.md)); it does not change manifest validation, canonical JSON or artifact digests.

These cases test existing OCI boundaries. Manifest validation does not verify bytes, and neither commit-time rehashing nor S3 behavior is added by these fixtures.

## Language-neutral runner

The operation table is the adapter contract. A runner can use its own parser, validator, canonicalizer, resolver, packer, and OCI implementation:

```text
for each corpus JSON file:
    check format, version, operation, unique IDs, and expected-field shape
    for each vector:
        try:
            input = parse_exact_binary64_JSON(vector.inputJson) if present
                    else vector.input
            actual = adapter.execute(corpus.operation, input)
        catch local_error:
            require vector.expected has only errorCategory
            require adapter.category(local_error) == vector.expected.errorCategory
            continue
        require vector.expected has no errorCategory
        compare every operation-specific expected result, including exact bytes
        independently hash expected canonicalJson and returned blob bytes
```

Keep setup/assertion failures separate from classified operation failures. For diagnostics, print the corpus filename, vector ID, operation, expected and actual category or value, and the byte offset/hex bytes of a canonical mismatch. Do not depend on English exception messages.

A standard-library Python check can independently verify the **static golden hashes**, without a JavaScript import. Run from the repository root:

```python
import hashlib
import json
from pathlib import Path

for path in sorted(Path("docs/conformance/v0.2").glob("*.json")):
    corpus = json.loads(path.read_text(encoding="utf-8"))
    for vector in corpus["vectors"]:
        expected = vector["expected"]
        if "canonicalJson" not in expected:
            continue
        key = "digest" if corpus["operation"] in ("canonical", "parse") else "artifactDigest"
        data = expected["canonicalJson"].encode("utf-8")
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        assert actual == expected[key], (path.name, vector["id"], actual)
```

This is **not a full Python implementation or a conformance pass**: it checks only `canonicalJson → UTF-8 → SHA-256`. It intentionally does not use Python's default JSON encoder to canonicalize inputs; default key ordering, numeric parsing/printing, escaping, or surrogate handling may differ from the specified rules.

## Stable failure categories

The contract has 18 categories. The reference attaches codes to local errors; other languages may use enums, result types, or exceptions and map them in the adapter. Map a parser syntax failure to `OWA_INVALID_JSON` (the reference harness maps `SyntaxError`). Human-readable wording and exception class names are not portable requirements. These categories do not prescribe HTTP statuses or a new HTTP response body.

| Category | Meaning in this corpus |
| --- | --- |
| `OWA_INVALID_JSON` | Invalid JSON syntax, including a leading BOM. |
| `OWA_INVALID_JSON_VALUE` | Non-finite or otherwise unsupported canonical value; includes binary64 overflow. |
| `OWA_INVALID_MANIFEST` | Wrong object/container shape, missing required field, unknown property, or invalid/empty `files` array. |
| `OWA_UNSUPPORTED_SPEC_VERSION` | Present `specVersion` is not the supported constant. |
| `OWA_UNSUPPORTED_ARTIFACT_TYPE` | Present `artifactType` is not the supported constant. |
| `OWA_INVALID_PATH` | Invalid artifact path, including an entrypoint or fallback path. |
| `OWA_DUPLICATE_PATH` | Repeated exact file path, regardless of digest. |
| `OWA_INVALID_DIGEST` | Not exactly `sha256:` and 64 lowercase hexadecimal digits. |
| `OWA_INVALID_SIZE` | Not an integer number in `0..2^53-1`. |
| `OWA_INVALID_MEDIA_TYPE` | Empty or non-string `mediaType`. |
| `OWA_MISSING_ENTRYPOINT` | Valid entrypoint path absent from `files`. |
| `OWA_MISSING_SPA_FALLBACK` | Valid fallback path absent from `files`. |
| `OWA_INVALID_VISIBILITY` | Present visibility is neither `public` nor `unlisted`. |
| `OWA_INVALID_EXPIRY` | Present, non-null expiry violates the specified date-time rules. |
| `OWA_INVALID_ANNOTATIONS` | An annotation value is an array or object rather than a scalar. |
| `OWA_SYMLINK` | Directory packing encountered a symbolic link. |
| `OWA_CONTENT_DIGEST_MISMATCH` | Actual bytes fail an existing OCI boundary's digest check. |
| `OWA_CONTENT_SIZE_MISMATCH` | Bytes or descriptors fail an existing OCI boundary's size check. |

Missing required properties use `OWA_INVALID_MANIFEST`; invalid values of present properties use the applicable category. Even malformed objects with names such as `toString` must retain that category; diagnostic formatting must not introduce an unclassified coercion error. See `path-object-shadowed-coercion`, `path-array-shadowed-coercion`, and the `manifest-*-shadowed-coercion` regression vectors. Fixture outcomes, not a blanket "any error" test, are authoritative for the covered cases. This is not an exhaustive taxonomy of all I/O, transport, or host errors.

## Clarified ambiguities and regression anchors

Each linked JSON file contains the named vector IDs; IDs are stable lookup keys, not generated expectations.

| Ambiguity | Resolution / compatibility boundary | Fixture anchors |
| --- | --- | --- |
| Floating annotations and decimal formatting | Finite floating-point annotations are allowed. Input numbers round to binary64, nearest/ties-even; output uses shortest round-tripping digits (closest, then even on ties), `-0 → 0`, fixed notation for `1e-6 <= abs < 1e21`, otherwise lowercase `e` with a signed positive exponent and no zero padding. Successful serialization is unchanged. | [`manifest-number-annotations`](v0.2/manifest.json); [`canonical-negative-zero`, `canonical-small-fixed`, `canonical-small-exponent`, `canonical-large-fixed`, `canonical-large-exponent`, `canonical-binary64-rounding`, `canonical-binary64-integer-rounding`](v0.2/canonical.json). |
| Key sorting | Recursive Unicode code-point lexicographic order, shorter prefix first; neither UTF-16, locale, nor numeric-looking-key order. | [`canonical-numeric-keys`, `canonical-prefix-keys`, `canonical-supplementary-before-bmp-input`](v0.2/canonical.json). |
| Strings and hash bytes | UTF-8, no BOM/newline or Unicode normalization; exact short control escapes, lowercase other control escapes, unescaped `/`, literal U+2028/U+2029. Combine paired surrogates; preserve unpaired ones as lowercase ASCII escapes. | [`canonical-quotes-controls-slash`, `canonical-utf8-line-separators`, `canonical-unicode-no-normalization`, `canonical-surrogate-pair`, `canonical-unpaired-high-surrogate`, `canonical-unpaired-low-surrogate`, `canonical-unpaired-surrogate-key`](v0.2/canonical.json). |
| Schema versus permissive validation | Enforce already-published required/extra-field rules, optional-object shapes and scalar-only annotations. Empty optional objects are valid; no optional container may be null. Do not silently discard unknown fields. | [`manifest-empty-options`, `manifest-missing-files`, `manifest-file-missing-size`, `manifest-unknown-root`, `manifest-unknown-file`, `manifest-unknown-routing`, `manifest-unknown-access`, `manifest-unknown-lifecycle`, `manifest-routing-shape-null`, `manifest-annotation-array`, `manifest-annotation-object`](v0.2/manifest.json). |
| Size/path schema mismatch | Safe integer size is `0..2^53-1`; the schema's upper bound and path pattern align with validation. Reject terminal dot segments, backslash and NUL; do not repair paths. Exact digest length also rejects a trailing newline that a loose regex end anchor could miss. | [`manifest-maximum-size`, `manifest-size-unsafe`, `manifest-digest-newline`](v0.2/manifest.json); [`path-terminal-dot`, `path-terminal-dotdot`, `path-backslash`, `path-nul`, `path-newline-literal`](v0.2/path.json). |
| Date-time versus runtime date parsing | Enforce the schema's existing `date-time` requirement with four-digit year, calendar/leap-day checks, 00–23 hours, 00–59 minutes/seconds, optional fractional digits, `T`/`t`, `Z`/`z`, and offset hours 00–23/minutes 00–59. No leap seconds or date normalization. Previously accepted non-RFC3339 dates were an implementation/schema bug, not a digest rule. | [`manifest-expiry-lowercase`, `manifest-expiry-fraction`, `manifest-expiry-maximum-offset`, `manifest-expiry-date-only`, `manifest-expiry-missing-zone`, `manifest-expiry-impossible-february-day`, `manifest-expiry-century-leapday`, `manifest-expiry-century-non-leapday`, `manifest-expiry-second-60`, `manifest-expiry-trailing-lf`](v0.2/manifest.json). |
| `mediaType` permissiveness | Nonempty string only, not MIME parsing; do not tighten successful validation by adding a syntax rule. | [`manifest-whitespace-media`, `manifest-non-mime-media`, `manifest-media-empty`](v0.2/manifest.json). |
| Manifest paths versus request paths | Manifest paths are exact strings with literal `%` and no case/Unicode folding. Requests percent-decode once as strict UTF-8, reject backslash/NUL/`..` before fallback, normalize empty/`.` segments, preserve a decoded trailing slash, then try direct/root lookup before SPA. Full URL parsing is not part of the operation. | [`manifest-literal-percent-and-unicode`](v0.2/manifest.json); [`path-percent-literal`](v0.2/path.json); [`request-decode-once-percent`, `request-decode-slash`, `request-trailing-dot`, `request-trailing-dot-slash`, `request-query-not-url-parsed`, `request-spa-parent`, `request-spa-invalid-utf8`](v0.2/request.json). |
| File arrays versus input enumeration | Canonicalization preserves `files` order; reversal changes identity. Packing equal fixture trees is independent of creation order but pins only explicit lowercase ASCII expectations, not universal Unicode collation. | [`manifest-file-array-reversed`](v0.2/manifest.json); [`canonical-nested-array-order`](v0.2/canonical.json); [`pack-lower-ascii-order`](v0.2/pack.json). |
| Metadata validation versus content verification | Unique exact paths and entrypoint/fallback existence are semantic checks; matching content digests at different paths are valid. Blob mismatch cases have valid metadata and fail at existing OCI boundaries only. | [`manifest-duplicate-path-different-digest`, `manifest-same-content-different-paths`, `manifest-entrypoint-missing`, `manifest-fallback-missing`](v0.2/manifest.json); [`blob-write-digest-mismatch`, `blob-write-size-mismatch`, `blob-read-content-size-mismatch`](v0.2/blob.json). |

## Running the reference tests

From the repository root:

```sh
npm test                 # all default conformance tests, including properties
npm run test:conformance # portable corpus checks
npm run test:property    # deterministic property suite
```

The adapters are [`fixtures.test.js`](../../packages/conformance/src/fixtures.test.js) and [`property.test.js`](../../packages/conformance/src/property.test.js). [`schema.test.js`](../../packages/conformance/src/schema.test.js) independently checks the published scalar constraints and object declarations; it is not a complete JSON Schema engine. The default suite does not require a live object store or credentials. Live integration tests remain separate; passing this corpus does not claim live-provider validation.

### Deterministic property suite

Each property independently resets a 32-bit xorshift generator to seed **`0x4f574132`**. Each draw applies `state ^= state << 13`, `state ^= state >>> 17`, then `state ^= state << 5`, with 32-bit state and logical right shift; the result is unsigned. Bounded choices take the result modulo the bound. No wall-clock, network, or OS randomness generates test inputs. OS-random temporary directory names only isolate resources.

| Property | Iterations | Checks |
| --- | ---: | --- |
| Canonicalization | 128 | Object permutations, hand-ordered Unicode keys, scalar escaping, preserved arrays/file arrays, finite annotation values, independent hashes, and non-finite rejection. |
| Paths | 128 | Safe Unicode paths, encoded requests, invalid path mutations, and unsafe requests rejected even with SPA fallback. |
| Digests/sizes | 128 | Duplicate paths, valid duplicate content, malformed digests, and numeric size boundaries. |
| Filesystem enumeration | 16 | Equal lowercase ASCII trees created in different orders yield equal manifests/digests and exact source bytes. |
| Symlinks | 16 | File, directory, dangling, and external links are rejected. |
| OCI | 8 | Unique-content round-trips, original bytes/config identity, tampered layer/config/OCI-manifest hashes, and size mismatches. |
| **Total scheduled** | **424** | Multiple assertions and mutations run within each iteration. |

Failures include property name, seed, zero-based iteration, operation, detailed input, and the original cause. Resetting the seed per property means filtering tests does not change that property's input stream. The symlink property explicitly skips only for unsupported-operation errors (`ENOSYS`, `ENOTSUP`, `EOPNOTSUPP`) or Windows' unavailable symlink privilege (`EPERM`); other errors fail. Such a skip means not all 424 scheduled iterations ran. The static corpus's symlink cases require a capable setup and must not turn setup errors into `OWA_SYMLINK` passes.

### Immutable legacy vectors

The four files in [`../test-vectors/basic/`](../test-vectors/basic/) are unchanged. The fixture runner pins these independent SHA-256 hashes of **each whole file**, including any existing file terminator. These are not instructions to re-encode the files or regenerate goldens:

| File | Whole-file SHA-256 (hex) |
| --- | --- |
| `artifact-digest.txt` | `49d95b7b03b2eb1f367801d95c17a847a0b335653df0a7562ac3b09e537e5925` |
| `canonical.json` | `388a9912105ef49dab9d867b44c98f2c0cb2954139580bf56314b6818c206253` |
| `index.html` | `f6c64c97726aac94c47f997a6875c727f8a889043393bd398fe008e3edeb63b0` |
| `manifest.json` | `af31c7e942204c39a19fa04ff39976bf349328d1595c6bc680b8b7ab7c06bf29` |

New expectations are checked in as static data. The runner independently hashes expected canonical bytes and source/blob bytes, and guards against wrong-category errors and unexpected success. It does not manufacture expected values by calling production code.

## Explicitly deferred, not fixed by issue 5

- **Arbitrary Unicode directory-pack ordering:** the packer still uses locale-sensitive `localeCompare`. Lowercase ASCII pack fixtures and same-environment creation-order properties do not establish universal cross-locale ordering. Manifest array order itself is specified and unchanged.
- **Duplicate-content OCI import:** import indexes layers by digest, collapsing repeated-content layer entries that carry distinct path annotations. Such manifests remain valid; this suite does not introduce new OCI path/digest semantics (issue #9). The OCI property uses unique content, while manifest/pack cases still exercise deduplication; the live registry interoperability suite ([docs/oci.md](../oci.md)) also uses unique-content fixtures.
- **Commit-time content verification:** commit checks existence, not the stored bytes' hash or size. Content-mismatch vectors exercise only existing OCI verification, not a new commit or S3 guarantee.
- **Duplicate JSON member names:** not included in portable corpus requirements. No first-wins or last-wins policy is silently selected; a port must disclose its parser policy rather than infer one from these tests.
- **Unpaired-surrogate parser limitations:** the canonical cases pin exact preservation as escaped data. A port whose parser rejects those escapes must report the limitation, not replace characters or claim those cases passed.

Passing a finite corpus is regression evidence, not proof of every possible input, transport behavior, HTTP parsing path, or security policy. No unrelated host or protocol redesign is included.
