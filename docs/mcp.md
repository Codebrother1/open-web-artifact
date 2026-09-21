# Optional MCP adapter

`packages/mcp` exposes OWA publishing to a local Model Context Protocol (MCP)
client over **stdio**. It is a thin HTTP client, not another artifact host. The
existing HTTP server remains authoritative for authorization, plans, upload
grants, immutable releases, and the active pointer. The adapter opens **no HTTP
listener** and does not write directly to the server's storage.

Exactly four tools are available: `publish`, `list_releases`, `activate`, and
`rollback`. There are no adapter resources, prompts, sampling, or MCP logging
features. No OAuth flow, token minting, new rollback endpoint, or new artifact
format is introduced. The existing CLI interface, HTTP authentication, canonical
identity, CAS behavior, and gateway profile remain unchanged.

## Install and launch

Requires **Node.js 22 or newer**. From the repository root, install the optional
package separately:

```bash
npm --prefix packages/mcp ci --ignore-scripts
```

This includes the official SDK test client. For a runtime-only installation,
use this instead (the MCP test suite then needs a full install before running):

```bash
npm --prefix packages/mcp ci --ignore-scripts --omit=dev
```

Neither the root install nor the core/server/CLI runtime needs the MCP package.
The core, HTTP server, and CLI retain **zero third-party runtime dependencies**;
that statement does not apply to the optional MCP adapter. Its direct runtime
dependency is exactly `@modelcontextprotocol/server@2.0.0`. Its only direct dev
dependency is exactly `@modelcontextprotocol/client@2.0.0`, used by tests, not
loaded by the adapter runtime. Both direct versions and the transitive tree are
recorded in the package's own [package.json](../packages/mcp/package.json) and
[lockfile](../packages/mcp/package-lock.json).

The installed production tree, measured with
`npm --prefix packages/mcp ls --omit=dev --all`, contains **three distinct
third-party packages**:

```text
@modelcontextprotocol/server@2.0.0
  @modelcontextprotocol/core@2.0.0
  zod@4.6.5                 (also used by core, deduplicated)
```

Configure a local stdio-capable MCP client to start the actual entrypoint:

```text
node /absolute/repo/packages/mcp/src/index.js
```

Do not configure an ordinary `npm run start` command as the stdio transport:
npm's script banner can corrupt protocol stdout. Prefer `node` directly; an npm
wrapper would need `--silent` and no other stdout-producing wrapper behavior.
**Stdout is exclusively MCP protocol traffic.** Diagnostics go to stderr in the
fixed forms described below.

### Operator configuration

| Environment variable | Required | Meaning |
| --- | --- | --- |
| `OWA_MCP_SERVER` | Yes | One trusted HTTP(S) control-plane origin, at most 2048 characters; validated and normalized at startup. No path prefix, query, fragment, userinfo, whitespace, or backslash. An optional final `/` is accepted. |
| `OWA_MCP_ROOT` | Yes | An existing absolute operator-controlled staging directory, 1–4096 characters, not a URL or control-character-containing path. The selected directory must not be a symlink; its real path becomes the containment root. |
| `OWA_TOKEN` | For required-auth servers | An existing, appropriately site/capability-scoped OWA bearer token, supplied only through approved secret injection into the child process environment. It is never a tool argument. |

The bearer is optional only when using the server's **explicit direct-loopback
development mode**. Omitting it does not bypass a required-auth server; production
still requires the same HTTP bearer authentication. Use HTTPS for deployments.
The shared HTTP client rejects bearer transmission over non-loopback HTTP;
loopback HTTP is accepted for development. Tokenless configuration is not itself
a production security mode. See the [auth guide](auth.md) for server setup and
existing token provisioning.

Example client configuration, with **no secret value embedded**:

```json
{
  "mcpServers": {
    "owa": {
      "command": "node",
      "args": ["/absolute/repo/packages/mcp/src/index.js"],
      "env": {
        "OWA_MCP_SERVER": "https://artifacts.example.com",
        "OWA_MCP_ROOT": "/absolute/staging"
      }
    }
  }
}
```

Replace both paths with existing operator-selected paths. In addition to the
non-secret configuration above, the MCP client/launcher must **explicitly forward
`OWA_TOKEN` from your approved secret store into the adapter child's environment**.
Check that client's secure environment/secret-injection facility: clients do not
universally inherit every parent environment variable or interpolate environment
references in JSON. The example is not a promise of automatic token forwarding.
Do not put a bearer in config files, command arguments, URLs, prompts, tool
arguments, or transcripts. The adapter does not need `OWA_AUTH_SECRET`, the
server-side token signing key, and must not receive it or mint tokens. It also
does not need object-store credentials or an upload signing secret.

Prepare only publishable content under the staging root, including the normal
`index.html` entrypoint. Keep that tree trusted and immutable/read-only for the
duration of packing. Do not point the root at a home directory, repository with
secrets, or general-purpose working directory.

## Tool contract

The authoritative complete input and output JSON Schemas are
[`packages/mcp/tool-schemas.json`](../packages/mcp/tool-schemas.json). They match
runtime discovery in [`src/schemas.js`](../packages/mcp/src/schemas.js), checked
by [`test/schema.test.js`](../packages/mcp/test/schema.test.js). Every declared
object shape is closed (`additionalProperties: false`). Tool arguments must be
an object with exactly the permitted fields; there is no token, headers,
manifest, upload URL, or arbitrary options argument.

### Inputs

Fields in the required column must be present on **every** call to that tool.

| Tool | Required arguments | Optional arguments |
| --- | --- | --- |
| `publish` | `directory`, `site`, `server` | `activate`: boolean, default `true` |
| `list_releases` | `site`, `server` | None |
| `activate` | `site`, `server`, `releaseId` | None |
| `rollback` | `site`, `server`, `releaseId` | None |

| Value | Exact constraints and runtime interpretation |
| --- | --- |
| `site` | String, 1–63 ASCII characters. First character is lowercase `a`–`z` or `0`–`9`; remaining characters may additionally be `_` or `-`. No trailing newline or other suffix. |
| `server` | String, 1–2048 characters; a valid HTTP(S) origin with no credentials, path prefix, query, fragment, whitespace, or backslash; optional final `/` allowed. After the same normalization used by the CLI, it must equal the pinned `OWA_MCP_SERVER` origin exactly. |
| `directory` | String, 1–4096 characters; existing directory. No URL scheme or control characters U+0000–U+001F or U+007F–U+009F. Relative paths resolve against `OWA_MCP_ROOT`, **not the process working directory**. Absolute paths must resolve inside that root. Native Windows drive-absolute syntax is permitted on Windows; filesystem execution evidence here is Linux, not Windows verification. |
| `activate` | Literal JSON boolean. Only `false` stages without activating; omission means `true`. Strings such as `"false"`, numbers, and `null` are invalid. |
| `releaseId` | String consisting of `r_` followed by exactly 20 lowercase hexadecimal characters, with no trailing characters. Must identify an existing release for the specified site when activated. |

`server` is a required normal argument, not permission to select an arbitrary
host. Its normalized exact-origin comparison runs **before directory resolution,
packing, or any network request**. Scheme, hostname, and effective port must
match; a different hostname that happens to resolve to the same address is not a
match. Normal URL normalization, such as host case, the default port, and a final
slash, does not create a different origin.

### Results

A successful tool call returns `structuredContent` with `ok: true` and exactly
the fields below. A single text content block contains
`JSON.stringify(structuredContent)` for compatibility with text-only clients.
Success omits `isError`; tool failures set it to `true`. The output schemas
include both success and the error shape documented later.

| Tool | Exact success fields |
| --- | --- |
| `publish` | `{ ok, site, artifactDigest, releaseId, activeReleaseId, uploaded, reused, url }` |
| `list_releases` | `{ ok, site, activeReleaseId, releases }`, where each release is exactly `{ releaseId, artifactDigest, createdAt }` |
| `activate` | `{ ok, site, activeReleaseId }` |
| `rollback` | `{ ok, site, activeReleaseId }` |

| Result value | Constraint / meaning |
| --- | --- |
| `ok` | Literal `true` on success. |
| `site` | The validated input site, with the same constraints as above. |
| `artifactDigest` | `sha256:` followed by exactly 64 lowercase hexadecimal characters; canonical OWA manifest identity, not an OCI digest. |
| `releaseId` | `r_` plus exactly 20 lowercase hexadecimal characters. |
| `activeReleaseId` | A release ID or `null` for `publish` and `list_releases`. For `activate` and `rollback`, a non-null release ID equal to the explicitly requested ID. |
| `uploaded`, `reused` | Integers from 0 through 9007199254740991 inclusive, counting **unique blobs**, not filenames or bytes. Plan validation additionally checks their total against the packed unique-blob count. |
| `url` | **Optional.** The canonical public content URL exactly as returned by the server's commit response (`contentUrl`), never synthesized by the adapter. Absent when the server has no content origin configured; the adapter emits no URL rather than guessing one. A public content URL, **not a presigned upload URL**. It selects the site's active content, not necessarily the newly staged release. |
| `releases` | Array of all release metadata returned by the current HTTP listing, possibly empty; no adapter pagination or selection. Each item has only the three declared fields. |
| `createdAt` | A valid UTC timestamp of the exact form `YYYY-MM-DDTHH:mm:ss.sssZ`; runtime validation requires a finite date and an identical ISO round-trip. |

Results project validated metadata only. They do not include file bytes, full
manifests, local directory paths, upload grants, signed upload URLs, or provider
response bodies. This is not a promise that all client transcripts omit
user-supplied names: clients can record tool inputs and ordinary request IDs.
Keep secrets out of those inputs too. The output has no browser-validation or
security-profile status fields.

### HTTP operations and capabilities

All required-auth capabilities below must also cover the exact requested site.
The HTTP server makes the authorization decision; MCP does not weaken it.

| Tool / phase | Existing HTTP operation | Required capability |
| --- | --- | --- |
| `publish`: plan | `POST /v1/sites/<site>/publish/plan` | `plan` always; `upload` additionally when blobs are missing |
| `publish`: upload missing blobs | `PUT` to validated plan URLs | `upload` for missing blobs; marked filesystem PUTs also require their independent signed grant |
| `publish`: commit, `activate: false` | `POST /v1/sites/<site>/publish/commit` | `commit` |
| `publish`: commit, default / `activate: true` | Same commit route | `commit` **and** `activate` |
| `list_releases` | `GET /v1/sites/<site>/releases` | `read` |
| `activate` | `POST /v1/sites/<site>/activate/<releaseId>` | `activate` |
| `rollback` | Same activation route | `activate` |

A token with only `commit` cannot complete publishing, because planning is always
required. A staged publish with all blobs already present needs `plan` and
`commit`, but not `upload` or `activate`. `activate: false` preserves the previous
active pointer (which can be `null`); it does not make the new release active.

`rollback` is explicitly selected activation: the caller supplies the prior
release ID. It makes **no implicit listing/read request**, does not automatically
choose a release, and does not verify that the chosen release is actually older.
If the caller needs to inspect choices, that is a separate `list_releases` call
requiring `read`. Activation/rollback change only the active pointer, without
re-uploading bytes, creating another release, or modifying immutable releases.

For example, a `publish` call's arguments can be:

```json
{
  "directory": "site",
  "site": "hello",
  "server": "https://artifacts.example.com",
  "activate": false
}
```

Here the content is `/absolute/staging/site` under the example configuration.
Keep the returned `releaseId` for a later explicit `activate` or `rollback` call;
do not use an alias such as `latest`.

## Data path and trust boundaries

The adapter reuses the structured functions in
[`packages/cli/src/remote.js`](../packages/cli/src/remote.js). The narrow shared
extraction preserves existing CLI text formatting, validation, HTTP semantics,
and credential handling; it does not parse CLI stdout or create a second HTTP
implementation. Packing and canonical identity use the existing core packer.

Publishing packs and hashes locally, sends the manifest/digest for a plan,
uploads missing blobs directly, then commits the manifest/digest. File bytes do
not pass through MCP messages. **They are buffered in process memory by the
existing packer/upload path, just as in the CLI; this is not streaming or a
bounded-memory transfer implementation.** Large trees need appropriate memory
and operator limits.

Before any PUT, the shared client validates every upload instruction: known
packed digest, no duplicates, a valid HTTP(S) URL, no arbitrary headers, and PUT
semantics. Credential forwarding is deliberately narrower than URL acceptance:

- Control requests use `Authorization: Bearer` from `OWA_TOKEN` when present.
- Required-auth filesystem uploads require an explicit `authorization: "bearer"`
  plan marker and the exact configured origin. The URL path must identify the
  matching digest, and the query must contain only the matching site, a positive
  safe-integer expiry, and a 64-character lowercase-hex signature. The client
  checks this shape/scope; the HTTP server independently verifies the signed
  grant and the bearer. The adapter has no signing key.
- Unmarked uploads, including S3/R2 presigned URLs, receive **no OWA Authorization
  header even when their origin matches the control plane**. Matching an upload
  path/origin alone never authorizes bearer forwarding. Explicit loopback dev
  filesystem grants can also be unmarked and tokenless.
- Control requests and every upload use a no-redirect policy. Upload URLs remain
  internal and are never returned in MCP tool results.

Origin pinning is **not a network/DNS sandbox** and does not make a compromised
trusted server safe. Under existing shared-client semantics, that server can
request uploads of this artifact's packed bytes to arbitrary valid **unmarked**
HTTP(S) upload destinations. Those requests do not carry the OWA bearer, but they
do carry the intended artifact bytes. Trust the configured server and apply
operator-controlled egress restrictions where needed.

Directory selection uses `lstat`, then `realpath` and a path-component containment
check. The selected root and selected publish-directory leaf cannot be symlinks;
ancestor links are resolved and the selected target must remain inside the
canonical root. The unchanged packer rejects child symlinks. This is containment
checking, **not a race-proof filesystem sandbox**: it does not defend against
hard links, concurrent writers, or time-of-check/time-of-use changes. Supply a
trusted read-only staging tree, restrict the process's OS permissions, and keep
unpublishable secrets out of it. Do not assume shell working-directory isolation
or the MCP client's own resource-root feature replaces `OWA_MCP_ROOT`.

## Errors and protocol behavior

Tool errors use this exact closed shape in both `structuredContent` and the text
fallback, plus `isError: true` on the MCP result:

```json
{
  "ok": false,
  "error": {
    "code": "OWA_AUTH_CAPABILITY",
    "category": "capability",
    "message": "Authentication does not permit this operation",
    "status": 403
  }
}
```

`code`, `category`, and `message` are required and come from this fixed vocabulary.
`status` is optional, included only for a safe integer HTTP status from 100 through
599 when available. Local validation/network failures need not have a status.
Raw exception messages, stacks, causes, provider errors, and arbitrary response
fields are not exposed.

| Code | Category | Fixed message |
| --- | --- | --- |
| `OWA_MCP_CONFIG` | `configuration` | Invalid adapter configuration |
| `OWA_MCP_INVALID_INPUT` | `invalid_input` | Invalid input |
| `OWA_MCP_INVALID_RESPONSE` | `invalid_response` | Invalid control-plane response |
| `OWA_MCP_CONTROL_FAILED` | `control_plane` | Control-plane request failed |
| `OWA_MCP_UPLOAD_FAILED` | `upload` | Blob upload failed |
| `OWA_MCP_NETWORK_FAILED` | `network` | Network request failed |
| `OWA_MCP_FAILED` | `internal` | Operation failed |
| `OWA_AUTH_CONFIG` | `configuration` | Invalid authentication configuration |
| `OWA_AUTH_INVALID_TOKEN` | `authentication` | Invalid authentication token |
| `OWA_AUTH_INVALID_SIGNATURE` | `authentication` | Invalid authentication signature |
| `OWA_AUTH_EXPIRED` | `authentication` | Authentication token expired |
| `OWA_AUTH_MISSING` | `authentication` | Authentication required |
| `OWA_AUTH_SITE` | `site_scope` | Authentication does not permit this site |
| `OWA_AUTH_CAPABILITY` | `capability` | Authentication does not permit this operation |
| `OWA_AUTH_DEV_ONLY` | `authentication` | Development authentication requires a direct loopback connection |

These are all 15 adapter codes, including all eight existing safe HTTP auth
codes. See [`src/errors.js`](../packages/mcp/src/errors.js) for the fixed mapping.
Unknown HTTP failures become `OWA_MCP_CONTROL_FAILED`; bad upload grants become
`OWA_MCP_INVALID_RESPONSE`; unsuccessful PUTs become `OWA_MCP_UPLOAD_FAILED`.
Local packing/input failures map to a fixed input error where recognized and a
fixed internal error otherwise.

The official SDK owns initialization, protocol negotiation, JSON-RPC validation,
framing, and serialization. The runtime connects its `Server` directly through
`StdioServerTransport`; the tested integration uses the official client and
**classic `initialize` stdio negotiation**. Installing SDK v2 is not a claim that
the adapter wires every v2 modern-era mode or transport.

A small public `Transport` wrapper sanitizes diagnostics; it is not a new MCP
parser or protocol implementation. SDK wire errors lose diagnostic `data` and
provider/validation text. Only these fixed protocol messages are sent:

| JSON-RPC code | Message |
| --- | --- |
| `-32700` | Parse error |
| `-32600` | Invalid request |
| `-32601` | Method not found |
| `-32602` | Invalid parameters |
| `-32603` | Internal error |

Other outgoing error codes are mapped to the fixed internal error. Unknown tool
argument fields are rejected; unknown fields in the surrounding SDK request
`params` may instead be stripped by the SDK before the adapter sees them. Do not
rely on a particular error path for every malformed envelope.

Normal string/numeric request IDs are preserved for correlation. IDs containing
the current process bearer or a recognized complete `owa1` token pattern are
rejected with `id: null` before tool dispatch or mutation. Outgoing messages are
also scanned in memory for those token forms. This is not a general arbitrary
secret classifier; never submit credentials as request IDs or other input.

Malformed JSON can be dropped by the SDK; invalid wire envelopes can result in
fixed stderr diagnostics and/or sanitized protocol errors. Neither path echoes
raw SDK validation detail. The adapter does not promise one reply per malformed
frame. Its fixed stderr lines are:

```text
owa-mcp: OWA_MCP_CONFIG: Unable to start adapter
owa-mcp: OWA_MCP_FAILED: Protocol operation failed
```

Startup configuration/import failure exits nonzero without protocol stdout. A
normal initialized session does not print banners or routine diagnostics. The
client's own local validation, debug logging, and transcript handling are outside
this adapter boundary; configure those not to expose secrets either.

### Failure recovery and remaining limits

- A failed upload or denied/failed commit can leave already-uploaded immutable
  blobs behind. An invalid response can also occur after the server has acted.
  Failure does not imply that no state changed.
- There is no automatic rollback, hard operation timeout, or cancellation-driven
  transactional undo. An MCP cancellation or disconnect is not a guarantee that
  already-started HTTP work stops or that uploads/releases are removed. Inspect
  the authoritative state before deciding how to recover.
- Retrying can reuse existing blobs but can create a **new release**, even for an
  identical artifact. Blob deduplication is not release-level idempotency.
- Listing uses the current HTTP endpoint without pagination and excludes its
  full manifests from the MCP result. Large listings can still be large.
- Public artifact access, shared-CAS limitations and site/capability auth
  boundaries are unchanged. Content/control origin isolation is now provided by
  the server, not the adapter: see
  [control and content origins](origins.md). The adapter holds no
  content-domain policy, does not synthesize `/?site=`, and surfaces only the
  server's canonical URL. The
  [`sandboxed-web-v1` profile](sandboxed-web-v1.md) remains an independent
  script-disabled HTTP response policy, not an MCP/browser execution guarantee.
  A returned URL is not by itself proof that the deployment separated origins.
  See the [auth guide](auth.md) and
  [threat model](sandboxed-web-v1-threat-model.md).

## Tests and evidence

From the repository root:

```bash
npm test
npm --prefix packages/mcp ci --ignore-scripts
npm run test:mcp
```

The root offline suite remains separate and does not load the optional SDK. The
MCP suite can equivalently be run with `npm --prefix packages/mcp test` after its
full install. To target the shared-client extraction regression coverage:

```bash
node --test packages/conformance/src/http-client-results.test.js
```

The separate MCP tests start the actual stdio entrypoint with the pinned official
SDK client. They cover discovery/schema equality; real filesystem-backed HTTP
plan/PUT/commit in dev and required-auth modes; deduplication and a one-file
change; exact MCP-versus-HTTP-CLI identity; staged publish, listing, activation,
and explicit rollback; capability denials; directory containment; no-redirect
and upload credential rules; poisoned response projection; and safe SDK/wire
errors. Storage credential-isolation tests use local synthetic S3/R2-shaped
endpoints; they are not evidence of live cloud storage deployment.

The lifecycle test pins these **test-fixture-only** canonical identities:

```text
baseline: sha256:71e9c7a38c5d24bbd37f4cee787aba08f1bc428416e5eb3a02031142da16d660
changed:  sha256:86fc4e2f961313653b347c655812333b2795af33498af4695c4da576402b2600
```

The fixture proves equal canonical manifests/digests for actual MCP and CLI HTTP
publishes, unique-blob upload counts of 3 then 0 then 1, and immutable prior
releases. These are not production release IDs, deploy URLs, or live browser
validation. Execution evidence is Linux; Windows-native path syntax in the
schema is not an end-to-end Windows execution claim.

### SDK references

- [Official TypeScript SDK repository](https://github.com/modelcontextprotocol/typescript-sdk)
- [Official SDK releases](https://github.com/modelcontextprotocol/typescript-sdk/releases)
- [SDK v2 stdio serving documentation](https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio)

The checked-in lockfile and this adapter's tested entrypoint define the supported
integration here; upstream examples of other transports/features are not promises
that this adapter implements them.
