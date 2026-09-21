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
| `layers[]` | one descriptor per OWA file: `digest` and `size` are the file's; `mediaType` is the *mapped* descriptor media type (next section) |
| layer annotations | `org.opencontainers.image.title` (path without the leading `/`) and `dev.openwebartifact.path` (the exact OWA path) |
| manifest annotation | `dev.openwebartifact.artifact.digest` = OWA artifact digest |

`index.json` lists that manifest with `org.opencontainers.image.ref.name` set to
the requested `ref`. `readOciLayout({ input, ref })` re-verifies **everything**
on the way back in: layout version, descriptor media type, OCI manifest digest
and size, `artifactType`, config media type, the config's canonical digest
against `config.digest` and the annotation, and for every OWA file the layer's
existence, digest, size, mapped media type and path annotation, plus the actual
blob bytes' SHA-256 and length. The pulled layout is the local integrity
boundary; a registry is never trusted to have preserved bytes.

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
- **Issue #9 remains open:** the reader indexes layers by digest, so an OWA
  manifest in which two *different paths* share *identical content* does not yet
  round-trip through OCI. All live fixtures here use distinct digests; the
  deterministic suite pins the current behaviour without changing it.
- No `push-oci`/`pull-oci` commands exist; ORAS is the transport. `export-oci`
  and `import-oci` are the whole OWA surface.
