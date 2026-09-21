# Independent implementation: Go conformance runner

`implementations/go-conformance/` is a second, independent implementation of
the portable Open Web Artifact semantics, written in Go against the published
specification and the static conformance corpus — **not** against the
JavaScript reference packages. Its purpose is evidence: if a second language can
derive the same canonical bytes, digests, validation outcomes, request
resolutions, pack results and OCI-layout results from the written contract alone,
the contract is precise enough to be portable.

Portable conformance is therefore implemented independently in **JavaScript**
(the reference, `packages/*`) and **Go** (this implementation). Both consume the
same checked-in corpus; neither calls the other.

## Scope

| | |
| --- | --- |
| Target protocol | Specification **v0.2 draft** ([spec-v0.2.md](spec-v0.2.md)); manifest `specVersion` **`owa.dev/v1`**; media type `application/vnd.openwebartifact.site.v1+json` |
| Sources of truth | [spec-v0.2.md](spec-v0.2.md), [conformance/README.md](conformance/README.md), [oci.md](oci.md) (transport representation), [manifest.schema.json](manifest.schema.json), the static corpus `docs/conformance/v0.2/*.json`, the immutable `docs/test-vectors/basic/*` |
| Language / toolchain | Go, **standard library only** (`go.mod` has no `require`; verified in CI); developed and verified with `go1.27.1 linux/amd64`; `go.mod` declares `go 1.22` and uses no newer language features |
| Module | `github.com/Codebrother1/open-web-artifact/implementations/go-conformance`, package `owa` |
| Runtime dependencies on the reference | **none** — no Node, no npm, no repository JavaScript, no generated JS output, no reference CLI/server oracle |

### What it implements

- strict JSON parsing with binary64 numbers, exact unpaired-surrogate
  preservation, BOM/garbage/comment/trailing-comma rejection (`OWA_INVALID_JSON`)
  and binary64 overflow as `OWA_INVALID_JSON_VALUE`;
- canonical JSON (spec rules 1–5): code-point key ordering, preserved arrays,
  exact string escaping, `-0 → 0`, shortest round-trip digits with the specified
  fixed/scientific layout (`1e-6 → 0.000001`, `1e-7 → 1e-7`, `1e21 → 1e+21`);
- `sha256:<hex>` artifact identity;
- artifact-path validation and manifest validation with all 18 portable
  categories, including the cross-field entrypoint / `spaFallback` checks and
  the RFC 3339 expiry grammar with calendar validation;
- safe request-path resolution (decode once, strict UTF-8, reject `\`/NUL/`..`
  before SPA fallback, `/a/.` vs `/a/./`);
- directory packing with Unicode code-point ordering of complete artifact paths,
  symlink rejection, duplicate-content blob deduplication, and the fixed
  pack-time media-type table with its portable extension rule (issue #33);
- the OCI image-layout boundaries the corpus exercises: exact, unique
  `org.opencontainers.image.ref.name` index reference selection (issue #36),
  canonical config blob, one descriptor per file entry,
  `dev.openwebartifact.path` identity, descriptor media-type mapping with the
  `application/octet-stream` fallback, path-aware descriptor selection with the
  narrow legacy fallback, digest/size checks in the documented order.

### What it deliberately is not

Not a server, gateway, storage backend, CLI, SDK, registry client, ORAS/Zot
wrapper, GC, auth or MCP implementation. It does not publish, serve, sign, push
or pull anything; it reads and writes local files only inside the conformance
harness. Runtime/host behaviour (auth, origins, integrity gate at commit, leases,
S3, GC) is outside its scope and remains defined by the reference implementation
and its own suites.

## Running it

```sh
go -C implementations/go-conformance test ./... -count=1   # from repository root
# or, from the module directory:
cd implementations/go-conformance && go test ./... -count=1 -v
# or through the root npm script (orchestration only; it runs the same Go command):
npm run test:go-conformance
```

`go test -v` runs one subtest per corpus vector, named by its vector ID, so a
failure names the corpus file, the vector and the first differing byte.

## Corpus coverage

Every file under `docs/conformance/v0.2/` and every vector in it is executed —
`TestCorpusCoverage` fails if a corpus file has no harness. Nothing is skipped.

| Corpus file | Operation | Vectors | Harness |
| --- | --- | ---: | --- |
| `canonical.json` | canonical | 28 | parse → canonicalize; category check |
| `parse.json` | parse | 18 | parse → canonicalize; syntax → `OWA_INVALID_JSON` |
| `manifest.json` | manifest | 149 | parse → validate → canonicalize + artifact digest |
| `path.json` | path | 25 | validate; exact original string returned |
| `request.json` | request | 44 | validate manifest → resolve; exact file entry or null |
| `pack.json` | pack | 17 | materialize files/symlinks in a temp dir → pack (media types from the fixed table) → manifest, canonical, digest, sorted unique blob digests, blob bytes |
| `blob.json` | blob | 11 | validate manifest → OCI write + read-back, or OCI read of a static layout (index descriptor by exact, unique ref) → manifest, identity, blobs |

Plus the immutable basic vectors (`docs/test-vectors/basic/`: whole-file SHA-256
pins copied from the conformance guide, canonical bytes equal `canonical.json`,
digest equals `artifact-digest.txt`, `index.html` matches the file entry) and
independent regression anchors for the comparator, number and string
canonicalization, media-type mapping, expiry grammar and pack ordering.

## The cross-language static anchor

`pack-cross-language-anchor` in [`conformance/v0.2/pack.json`](conformance/v0.2/pack.json)
is the rendezvous point. Its seven files sort by code point across ASCII, Greek,
CJK, private-use (U+E000) and supplementary (U+10000, U+1F331) names, and four
entries — three `.txt` and one `.js` in three directories — hold identical bytes,
so one content digest appears under two OWA media types. Its expected canonical
JSON, artifact digest (`sha256:9a2bb62c7756c8f2b06cffce88985a00a32941b9440c53d1f5e833dd6e55c1b8`)
and blob digests were authored with an independent standard-library encoder and
re-verified with `sha256sum`; they were **not** produced by either implementation.
The JavaScript corpus runner (`npm run test:conformance`) and the Go harness
(`go test`) each check the same static bytes. There is no Go → Node or Node → Go
call anywhere.

## Independence rules

1. Semantics come from the documents listed under "Sources of truth" and from
   the static corpus. The corpus is the oracle; expected values are never
   regenerated from an implementation.
2. `packages/spec/src`, `packages/core/src` and `packages/transport-oci/src` are
   not consulted while implementing protocol semantics, and no JavaScript is
   translated. Disclosure: the same engineering session that produced this
   implementation had read parts of those files while working on earlier issues
   (#8, #9, #23); they were not opened during this work, and where the corpus
   pinned less than the reference did (the pack media-type case, since resolved
   — see "Resolved" below) this implementation deliberately followed only what
   was published.
3. No JavaScript runs at Go test time, and no Go runs inside the JavaScript
   suites. The only shared artifact is the static corpus.
4. If a corpus result cannot be derived from the written specification, the
   correct outcome is to report a specification ambiguity — not to
   reverse-engineer the reference or to change either implementation until they
   agree.

## Ambiguities and interpretations found

None of these blocked the corpus; each is recorded so the specification can
decide whether to pin it. Items the specification has since pinned move to
"Resolved" below with their history.

1. **Non-regular directory entries.** The packing rule speaks of "each
   discovered regular file". Symbolic links are rejected as specified; other
   non-regular entries (sockets, devices, FIFOs) are skipped here. The corpus
   does not cover them.
2. **Duplicate JSON member names** are explicitly outside the corpus. This
   parser keeps the last value at the first member's position and discloses
   that policy, as the conformance guide requires.
3. **Shortest-digit selection.** The specification's "shortest round-tripping
   digits, closest, ties to even" is realised with `strconv.FormatFloat(v, 'e',
   -1, 64)` for the digits and an explicit implementation of the layout rules.
   Every corpus number agrees; equivalence for all binary64 values is a property
   of Go's shortest-formatting algorithm that the corpus exercises but does not
   prove exhaustively.
4. **Filesystem names that are not valid Unicode** are out of scope by the
   specification's own statement; the packer rejects them rather than guessing.

### Resolved

- **Index reference selection** — surfaced by this implementation, resolved by
  issue #36. [oci.md](oci.md) said only that `index.json` lists the manifest
  with `org.opencontainers.image.ref.name` set to the requested ref; this
  implementation interpreted that as exact-match-only and failed when no
  descriptor matched, while the JavaScript reference additionally fell back to
  `index.manifests[0]` when `latest` was requested and unmatched, and both
  readers took the first of several descriptors claiming the requested ref — so
  two conforming readers could import different OCI manifests from one
  `index.json`. [oci.md](oci.md#index-reference-selection) now makes exact
  **and unique** matching normative: `manifests` must be an array; a descriptor
  matches only through a string `ref.name` annotation exactly equal to the
  requested ref; exactly one match is required; zero matches are *not found*
  and duplicates are *ambiguous*; descriptor order never breaks a tie; a
  missing, `null`, numeric, boolean, empty or different annotation never
  matches; nothing is selected by digest, artifact-digest annotation, media type
  or position. The JavaScript `latest → manifests[0]` fallback was removed, and
  this implementation replaced its first-match loop with `selectIndexDescriptor`,
  which counts all exact matches and reports `ErrRefNotFound` / `ErrRefAmbiguous`
  (transport-local; no portable category was added). The portable success anchor
  is `blob-read-index-exact-ref-selection` in `blob.json` (decoy `v1` first,
  `latest` second); failure behaviour is pinned by `oci_index_ref_test.go` and
  the JavaScript `oci-index-ref.test.js` because generic OCI layout failures have
  no portable OWA error category.

- **Pack media-type detection** — surfaced by this implementation, resolved by
  issue #33. The directory-packing rule originally defined paths and ordering
  but no rule for the `mediaType` a packer assigns, and the corpus pinned only
  `.html`, `.css`, `.js` and `.txt`; this implementation therefore mapped
  exactly those four (case-sensitively) and documented
  `application/octet-stream` for anything else as a local interpretation, so a
  second packer could legitimately have produced a different artifact digest for
  `photo.png` or `INDEX.HTML`. [spec-v0.2.md](spec-v0.2.md#media-type-assignment)
  now defines the fixed, closed 19-extension table (the JavaScript reference's
  existing table) and a portable extension rule: final path segment, suffix from
  the final `.`, a leading dot alone is not an extension, ASCII-only folding of
  the lookup key, `application/octet-stream` fallback, no host MIME database, no
  byte inspection, no compound extensions. The four-extension interpretation was
  deleted from `pack.go` and replaced by the full published rule, implemented
  from the specification text (not from the reference, which was not consulted);
  the corpus pins every table entry and the edge cases in the
  `pack-media-type-*` vectors of `pack.json`, checked by both runners from the
  same static bytes, and every previously published pack vector is unchanged.
  The one name shape the rule covers but the corpus does not materialize is a
  trailing dot (`file.`), because Windows removes it from file names; it is
  pinned by direct anchors (`pack_media_type_test.go`) instead.

## Adopting future corpus additions

When a vector is added to `docs/conformance/v0.2/`, the Go harness picks it up
automatically (files are discovered, vectors are iterated). A new corpus *file*
(a new operation) fails `TestCorpusCoverage` until a Go harness exists for it,
which is the intended signal. Expected values must continue to be authored
independently of both implementations; a disagreement between Go and the corpus
is investigated against the specification first and reported as an ambiguity if
the text does not decide it — never resolved by editing the reference so that
the two implementations merely agree.
