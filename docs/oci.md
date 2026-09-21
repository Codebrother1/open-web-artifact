# OCI registry transport

OWA artifacts travel through OCI registries as ordinary **OCI image layouts**.
OWA owns the layout encoding and decoding (`packages/transport-oci`) and the
artifact's identity; [ORAS](https://oras.land) owns registry transport; the
registry stores content-addressed blobs and manifests. OWA implements **no** OCI
Distribution client, registry authentication, signing, referrers or SBOM
semantics — those belong to ORAS and the operator.

Interoperability is enforced continuously against a real registry: the `OCI`
GitHub Actions workflow (check `oci (oras + zot, node 24)`) runs the flow below
on every pull request with **ORAS v1.3.4** and **Zot v2.1.21**. That is the
scope of the claim — *observed with ORAS v1.3.4 and Zot v2.1.21* — not "works
with every OCI registry".

## Four identities, deliberately distinct

| Identity | What it names | Mutable? | Where it lives |
| --- | --- | --- | --- |
| **OWA artifact digest** | SHA-256 of the canonical OWA manifest bytes | no | the OCI **config** descriptor digest and `dev.openwebartifact.artifact.digest` |
| **OCI manifest digest** | SHA-256 of one OCI *representation* of the artifact | no | the registry descriptor / `index.json` entry |
| **registry tag** (`:v1`, `:latest`) | a transport reference a registry maps to some OCI manifest digest | **yes** | the registry |
| **OWA release ID** (`r_…`) | a host lifecycle record for a site | no (the site's *active* pointer moves) | the reference host's metadata |

The OCI manifest digest is **not** the OWA artifact digest: the same artifact can
have several OCI representations (this document records one representation
change), while its OWA digest never changes. A registry tag is **not** OWA
identity and **not** an OWA release: moving `:latest` in a registry is transport
state, not activation; pulling an older manifest by digest is not rollback.
Activation and rollback remain site release-pointer operations on the host.

## The representation

`writeOciLayout({ manifest, blobs, output, ref })` writes an OCI image layout
(`oci-layout`, `index.json`, `blobs/sha256/…`) containing one OCI **image
manifest**:

| Field | Value |
| --- | --- |
| `mediaType` | `application/vnd.oci.image.manifest.v1+json` |
| `artifactType` | `application/vnd.openwebartifact.site.v1+json` |
| `config.mediaType` | `application/vnd.openwebartifact.site.v1+json` |
| `config` bytes | the **canonical OWA manifest** (UTF-8 canonical JSON) |
| `config.digest` | the **OWA artifact digest** |
| `layers[]` | one descriptor per OWA **file entry**, in `manifest.files` order: `digest` and `size` are the file's; `mediaType` is the *mapped* descriptor media type (next section). Several descriptors may reference the **same** blob digest (see [File entries vs blobs](#file-entries-vs-blobs-duplicate-content)) |
| layer annotations | `org.opencontainers.image.title` (path without the leading `/`) and `dev.openwebartifact.path` (the exact OWA path — the descriptor's identity) |
| manifest annotation | `dev.openwebartifact.artifact.digest` = OWA artifact digest |

`index.json` lists that manifest with `org.opencontainers.image.ref.name` set to
the requested `ref`. `readOciLayout({ input, ref })` re-verifies **everything**
on the way back in: layout version, the index descriptor selected by exact,
unique `ref.name` match ([next section](#index-reference-selection)), its
descriptor media type, OCI manifest digest and size, `artifactType`, config
media type, the config's canonical digest against `config.digest` and the
annotation, and for every OWA file entry the descriptor selected by its path
annotation — its digest, size, mapped media type and path — plus the actual blob
bytes' SHA-256 and length. The pulled layout is the local integrity boundary; a
registry is never trusted to have preserved bytes.

### Index reference selection

`index.json` may list several manifests (ORAS, other tools and hand-authored
layouts do). The requested `ref` is the **only** selector, and selection is
**exact, unique and fail-closed** (issue #36):

1. `index.manifests` MUST be an array; only its object entries are descriptors.
2. A descriptor **matches** when its `annotations` value is an object that has
   the key `org.opencontainers.image.ref.name` with a **string** value **exactly
   equal** to the requested `ref` (code point for code point — no case folding,
   trimming or normalization).
3. Exactly **one** descriptor MUST match. **Zero** matches fail as *reference not
   found*; **more than one** exact match fails as *ambiguous*.
4. A missing `annotations` object, a missing key, a `null`, number or boolean
   value, an empty string, or any different string **does not match**.
5. Descriptor **order carries no meaning** and never breaks a tie: requesting
   `latest` does **not** fall back to `index.manifests[0]`, duplicates are not
   resolved first-wins or last-wins, and there is no "first valid-looking
   descriptor".
6. Nothing else selects at this step — not the OCI manifest digest, not the
   `dev.openwebartifact.artifact.digest` annotation, not the media type, not the
   position.

Once the unique descriptor is selected, every verification listed above applies
to it unchanged. Both failures are **transport-local layout errors**: the
portable corpus defines no OWA error category for them (the 18 categories are
unchanged), so they are pinned by direct tests in both implementations
(`packages/conformance/src/oci-index-ref.test.js`,
`implementations/go-conformance/oci_index_ref_test.go`); the JavaScript reader
distinguishes them in its message text (`OCI reference not found: <ref>` vs
`Ambiguous OCI index: <n> descriptors carry org.opencontainers.image.ref.name
<ref>`) and the Go implementation through `ErrRefNotFound` / `ErrRefAmbiguous`.
The portable **success** anchor is
[`blob-read-index-exact-ref-selection`](conformance/v0.2/blob.json): its index
lists a complete decoy artifact under `v1` **first** and the expected artifact
under `latest` **second**, so a positional or first-descriptor reader imports the
wrong artifact and fails the vector.

*History.* Before issue #36 the JavaScript reference reader used
`exact match ?? (ref === "latest" ? manifests[0] : null)` — an undocumented,
descriptor-order-dependent compatibility fallback — and both readers accepted the
first of several descriptors claiming the requested ref. Neither behaviour was
required by any published corpus vector, by the v0.4.0 documentation, or by the
live ORAS/Zot flow (ORAS writes the destination ref as `ref.name` on every pull,
by tag and by digest), so the fallback was removed and duplicate matches are now
rejected. This is a v0.2-draft transport clarification: writer output, config
verification, OCI manifest digest verification, layer selection, duplicate-content
behaviour, media-type mapping, blob verification and all published artifact
identities are unchanged.

### File entries vs blobs (duplicate content)

An OWA manifest may list several **different paths with identical bytes**; they
share one SHA-256 digest and are all valid file entries. The OCI representation
keeps the two identities apart:

| Identity | Unit | Key |
| --- | --- | --- |
| **file entry** | one OCI layer descriptor | `dev.openwebartifact.path` |
| **blob** | one content-addressed object under `blobs/sha256/<digest>` (and once in a registry's CAS) | `sha256` digest |

So `/a.txt` and `/b.txt` with the same bytes produce **two** descriptors with the
**same** `digest` and distinct path annotations, both pointing at **one** stored
blob. Descriptor metadata belongs to the file entry: `/same.js` and `/same.txt`
with identical bytes carry `text/javascript` and `text/plain` descriptors over
one digest, and the config manifest keeps each entry's full OWA media type. The
writer has always emitted this shape; the import algorithm (`readOciLayout`)
treats `layers` as a descriptor **list**, never a digest-keyed set:

1. index descriptors by their exact `dev.openwebartifact.path`; two descriptors
   claiming the same path make the layout **ambiguous** — rejected, never
   "first wins" or "last wins";
2. for each config file entry select the unique descriptor whose path annotation
   equals `file.path`;
3. **legacy fallback** (annotation-less layouts) only when it is unambiguous:
   the file's digest occurs exactly once in the OWA manifest, exactly one layer
   carries that digest, and that layer has **no** `dev.openwebartifact.path`
   key at all. A present annotation — even `null`, `""` or a different path — is
   authoritative: the reader never falls back "through" it. Duplicate-digest
   entries therefore always need their own path-annotated descriptor;
4. a descriptor satisfies at most one file entry;
5. the selected descriptor must then carry the file's digest, size and mapped
   media type, and the blob bytes must hash to the digest with the declared
   length — checked for **every** entry even when the bytes were already read
   for another entry with the same digest.

The returned `blobs` map is keyed by digest, so three entries sharing one
digest yield one returned blob; `import-oci` stores it once. Layer **order** is
transport detail: the config manifest owns the file array order, and a layout
whose descriptors are shuffled imports the identical canonical manifest.

### Layer descriptor media types (the mapping)

Two different things are called "media type":

- **OWA `file.mediaType`** is artifact metadata. The OWA manifest contract only
  requires a nonempty string; typical values carry parameters —
  `text/html; charset=utf-8` — and any string is valid. It is preserved
  canonically in the config blob and is what the reference host serves.
- **OCI layer descriptor `mediaType`** is a transport field constrained by the
  OCI image spec to an RFC 6838 type/subtype
  (`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$`).
  Parameters are not allowed. Zot enforces this schema and rejects manifests
  that violate it — which is exactly how the first live run found that the
  previous representation (copying the OWA value verbatim) was non-conformant.

The transport therefore maps one to the other with one small rule
(`ociLayerMediaType`):

1. take the OWA value up to the first `;`;
2. trim ASCII SP/HTAB around it;
3. if the result satisfies the grammar above, use it **verbatim**;
4. otherwise use `application/octet-stream`.

| OWA `file.mediaType` | OCI layer descriptor `mediaType` |
| --- | --- |
| `text/html; charset=utf-8` | `text/html` |
| `text/javascript; charset=utf-8` | `text/javascript` |
| `text/css; charset=utf-8` | `text/css` |
| `application/json; charset=utf-8` | `application/json` |
| `image/png` | `image/png` |
| `application/vnd.example.foo+json` | `application/vnd.example.foo+json` |
| `not actually mime` | `application/octet-stream` |
| `   ` (whitespace, still a valid OWA string) | `application/octet-stream` |

The descriptor value is **never** the authoritative OWA media type and is never
copied into a second annotation: the full value is always recovered from the
config manifest, so an artifact whose files are `text/html; charset=utf-8` is
imported and served with exactly that value. The reader requires each layer's
descriptor to equal the mapped value for its file (a `text/html; charset=utf-8`
file whose layer says `application/octet-stream`, or still carries the
parameter, is rejected as a malformed representation). The mapping does not
narrow which OWA artifacts can be exported: every valid OWA manifest has a
conformant representation.

Consequence, accepted deliberately: OWA artifact digests, canonical manifest
bytes, file digests and bytes are **unchanged**; the **OCI manifest digest
changed** for artifacts whose files carry parameters, because the previous OCI
representation was invalid. Nothing treats an OCI manifest digest as stable
protocol identity.

## Commands

Export the artifact as a layout (any `--ref`; `v1` here):

```sh
npm run artifact -- export-oci ./site --out ./site.oci --ref v1
# Exported sha256:<OWA artifact digest>
# OCI manifest sha256:<OCI manifest digest>
```

Push the layout to a registry with **ORAS v1.3.4** (the layout is used exactly
as written; nothing rewrites it):

```sh
oras cp --from-oci-layout ./site.oci:v1 <registry-host>/<repository>:v1
```

The loopback test registry is plain HTTP, so the suite adds `--to-plain-http`;
a production registry uses TLS and whatever authentication ORAS is configured
with (`oras login`, credential helpers) — none of that is OWA's concern.

Read the registry descriptor (its `digest` is the OCI manifest digest and must
equal what `export-oci` printed):

```sh
oras manifest fetch --descriptor <registry-host>/<repository>:v1
oras resolve <registry-host>/<repository>:v1
```

Pull by **tag** into a **new, empty** layout directory, or by **immutable
digest**:

```sh
oras cp --to-oci-layout <registry-host>/<repository>:v1 ./pulled:v1
oras cp --to-oci-layout <registry-host>/<repository>@sha256:<OCI manifest digest> ./pulled-by-digest:by-digest
```

(`--from-plain-http` for the plain-HTTP test registry.) Import either layout
directly — no conversion step — into a reference host:

```sh
npm run artifact -- import-oci ./pulled --ref v1 --site my-site --data ./data
# Imported r_…
# Artifact sha256:<the same OWA artifact digest>
```

The imported release carries the original OWA artifact digest and the host
serves the original bytes with the original (full) media types.

## What the live suite proves

`packages/integration/oci/registry.test.js` (`npm run test:oci`) runs the whole
path against a real Zot with the real ORAS CLI in **both** directions; test-only
HTTP requests to `/v2/…` are supplemental inspection, never the transport. It
asserts, for a deterministic fixture whose five files have distinct digests
(`/index.html`, `/assets/app.js`, `/assets/style.css`, `/assets/blob.bin`,
`/empty.txt` — HTML/JS/CSS with `; charset=utf-8`, a binary, an empty file):

- `GET /v2/` answers 200; the pushed manifest's registry descriptor, `oras resolve`
  and `Docker-Content-Digest` all equal `writeOciLayout`'s OCI manifest digest,
  and the stored manifest bytes are byte-identical to the layout's;
- the stored manifest keeps `schemaVersion 2`, the image-manifest media type,
  the OWA `artifactType`, the OWA config media type, `config.digest` = OWA
  artifact digest, the digest annotation, and per layer the digest, size, mapped
  media type (`text/html`, `text/javascript`, `text/css`, `text/plain`,
  `application/octet-stream`) and `dev.openwebartifact.path`; each blob exists
  with the right `Content-Length`; the config blob equals the canonical manifest;
- pulling by tag and, independently, by digest into fresh layouts yields the
  same OWA artifact digest, identical canonical bytes, identical file bytes,
  digests, sizes and **full** media types, and the same OCI manifest digest;
- `import-oci` through the real CLI into a fresh data directory creates a release
  with the original artifact digest, and the real content listener serves `/`,
  the nested JS/CSS, the binary and the empty file byte-for-byte with the
  original `Content-Type` and `ETag`;
- nonexistent tag, nonexistent digest and never-created repository pulls
  **fail**; a pulled layout with a flipped, deleted or truncated blob is
  **rejected** by `readOciLayout`;
- moving `:latest` from v1 to a v2 artifact resolves to v2 while v1 stays
  addressable by digest and imports unchanged — tags are transport state;
- Zot is still answering afterwards.

`packages/integration/oci/duplicate-content.test.js` (same `npm run test:oci`
run, same real ORAS and Zot) adds the duplicate-content proof for a fixture with
`/shared.js`, `/shared.txt` and `/copy/shared.txt` holding **identical bytes**
(one digest, `text/javascript; charset=utf-8` vs `text/plain; charset=utf-8`)
next to a unique `/index.html`:

- the packer returns 4 file entries and 2 blobs; `writeOciLayout` emits 4
  descriptors — three with the shared digest, distinct path annotations and
  per-entry descriptor media types (`text/javascript`, `text/plain`) — and
  stores the shared blob once;
- ORAS pushes it; Zot's stored manifest is byte-identical, keeps all three
  repeated descriptors, and `HEAD /v2/<repo>/blobs/<shared digest>` answers 200
  once for the shared content (content-addressed identity — no claim about
  Zot's internal storage layout);
- pulls by tag and by digest both import the same OWA artifact digest, all four
  entries in config order, full media types, the same OCI manifest digest and a
  `blobs` map with **one** entry for the shared digest;
- `import-oci` stores 2 blobs for 4 entries; the content server serves
  `/shared.js` as `text/javascript; charset=utf-8` and `/shared.txt` and
  `/copy/shared.txt` as `text/plain; charset=utf-8` — the same bytes and the
  same `ETag`, each with its own entry's media type;
- copies of the real pull with one repeated descriptor stripped of its path
  annotation, two descriptors claiming one path, or the `.js`/`.txt` path
  annotations swapped are all **rejected** by `readOciLayout`, while an
  untouched copy still imports.

## Running it locally

```sh
# 1. pinned tools, verified against the official release checksums
node .github/scripts/oci-tools.mjs /tmp/oci-tools      # writes /tmp/oci-tools/oras/oras and /tmp/oci-tools/zot-linux-amd64
# 2. a disposable loopback Zot (ephemeral port, plain HTTP, storage under the state dir)
node .github/scripts/zot.mjs start /tmp/oci-tools/zot-linux-amd64 /tmp/zot-state
# 3. point the suite at them
export OWA_TEST_OCI_REGISTRY=http://127.0.0.1:<port printed above>
export OWA_TEST_ORAS_BIN=/tmp/oci-tools/oras/oras
npm run test:oci                                       # skips cleanly if either variable is unset
OWA_TEST_OCI_REQUIRED=1 npm run test:oci               # CI mode: any missing prerequisite FAILS
# 4. clean up
node .github/scripts/zot.mjs stop /tmp/zot-state
```

`OWA_TEST_OCI_REGISTRY` must be a bare `http://` loopback origin;
`OWA_TEST_ORAS_BIN` an absolute path to an executable. With
`OWA_TEST_OCI_REQUIRED=1` a missing ORAS binary, missing or unready registry, or
any failing ORAS command fails the run instead of skipping — the offline harness
checks (`npm run test:integration:harness`) pin that behaviour.

## Scope and limitations

- **Observed with ORAS v1.3.4 and Zot v2.1.21** on GitHub's `ubuntu-latest`.
  Other registries are not claimed; the representation follows the OCI image
  spec, so a spec-conformant registry should accept it, but that is inference
  until tested.
- The test registry is **loopback, plain HTTP, unauthenticated, disposable**.
  This proves content-addressed transport interoperability — not TLS, registry
  authentication or authorization, credential storage, token exchange,
  multi-tenant isolation, remote availability, or resistance to a malicious
  registry. OWA's reader digest checks are the local integrity boundary.
- **Signatures, provenance, cosign/Notary, referrers and SBOMs** are outside the
  OWA transport contract.
- **Duplicate content round-trips (issue #9, fixed):** distinct paths with
  identical bytes stay distinct file entries with one descriptor each over one
  shared blob. The only behaviour deliberately kept from the older reader is the
  unambiguous annotation-less legacy fallback described above; layouts with
  missing, conflicting or duplicated path annotations are rejected rather than
  guessed.
- **Extra, unrelated layer descriptors** are not a new error: the reader selects
  what the config manifest needs and ignores descriptors no file entry refers
  to, exactly as before — unless such a descriptor collides with a required path.
- **Extra index descriptors** under other refs are likewise ignored; only a
  missing or duplicated `org.opencontainers.image.ref.name` for the requested
  ref is an error ([Index reference selection](#index-reference-selection)).
  There is no `latest` or first-descriptor fallback.
- No `push-oci`/`pull-oci` commands exist; ORAS is the transport. `export-oci`
  and `import-oci` are the whole OWA surface.
