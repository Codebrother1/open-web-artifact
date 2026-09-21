# Minimal HTTP capability authentication

This is the reference host's issue 2 authentication overlay, not a new artifact
format or an accounts service. An operator grants a bearer token explicit site
scopes, capabilities, and an expiry. There is no accounts database, login flow,
HTTP token-mint endpoint, or CLI mint command.

The implementation is in `packages/server/src/auth.js`, the HTTP boundary in
`packages/server/src/index.js`, and the remote client in
`packages/cli/src/remote.js`.

## What changes, and what stays fixed

The overlay adds `Authorization: Bearer` handling and capability checks to the
control plane, scoped filesystem upload grants (`site` query parameter and
`authorization: 'bearer'` marker), and fixed authentication/error responses.
These **are HTTP wire additions**; this is not a claim of zero protocol changes.
They are documented here separately from the portable artifact specification.

The manifest schema, canonical manifest bytes, file digests, artifact digest
`sha256(UTF8(canonical-json(manifest)))`, immutable release records, and active
release pointer semantics are unchanged. No authentication claims are added to a
manifest or release. Publishing is still plan -> direct upload -> manifest-only
commit; S3/R2 bytes do not pass through the control plane. Commit still checks
that referenced blobs exist and activates by default. OCI transport and the
portable conformance corpus are unchanged.

The separately documented [`sandboxed-web-v1` response profile](sandboxed-web-v1.md)
is composed with this overlay. Its baseline is installed before route dispatch
and auth checks, including auth failures. The existing 401 `WWW-Authenticate:
Bearer realm="owa"` challenge and `Cache-Control: no-store` are preserved alongside
the profile headers. This composition does not change token format, capability
or expiry rules, or make public artifact GET/HEAD and health private.

## Startup and deployment

Requires Node.js 22+.

| Entry point/configuration | Behavior |
| --- | --- |
| `npm start` or `node packages/server/src/index.js` | Auth defaults to `required`, including when no auth environment variables are present. |
| `OWA_AUTH_MODE=required` | Requires `OWA_AUTH_SECRET`; missing or fewer than 32 UTF-8 bytes fails startup before storage or a listener opens. |
| `OWA_AUTH_MODE=dev` | Explicit tokenless, direct-loopback-only development mode. |
| `node packages/server/src/index.js --dev` or `npm run dev:server` | Explicit dev mode; `--dev` takes precedence over the environment mode. |
| Any other auth mode | Configuration error; no unauthenticated fallback. |

`NODE_ENV` does not select auth mode. Both modes default to port `7331` (`PORT`
overrides it). Required mode uses `HOST`, defaulting to `127.0.0.1`. The executable
in dev mode **always binds `127.0.0.1` regardless of `HOST`**.

Use an approved secret manager to inject `OWA_AUTH_SECRET` into the server
process. The minimum enforced size is not an entropy test: operators should use
keys generated from at least 32 cryptographically random bytes, unique to each
deployment/host. An environment string is used as UTF-8 bytes, not decoded as hex
or base64. When encoding a random key for environment injection, both minting and
verification must use the same encoded string as their key.

After secret injection, a required-auth deployment behind a trusted TLS edge can
start with:

```sh
export OWA_AUTH_MODE=required
export OWA_PUBLIC_BASE_URL=https://artifacts.example.com
npm start
```

The server is plain HTTP internally. **TLS is required for deployment**, via a
trusted TLS edge and a protected backend connection/network. Keep the default
loopback listener where possible; set `HOST` only when that trusted edge needs a
different backend binding. Auth does not make an exposed plaintext listener safe.

Set `OWA_PUBLIC_BASE_URL` to the public origin used by the publisher, with no
trailing slash, path, query, or fragment, for example `https://artifacts.example.com`. It is
used to construct local filesystem upload URLs behind a reverse proxy; without
it the server derives an HTTP base from the request Host header. Forwarding
headers are not used to infer the public base. The CLI requires marked local
uploads to match the configured control-plane origin, so an internal HTTP URL
or different public hostname will not work for authenticated uploads.

At the proxy, load balancer, tracing, and monitoring layers, do not log request
headers (especially Authorization), full URLs or query strings, or request
bodies. Response-body capture can also disclose upload grants. The reference
server does not log auth tokens; this does not sanitize infrastructure around it.
Disable shell tracing and prevent environment/diagnostic dumps in secret-bearing
processes. Keep secrets and complete bearer tokens out of plaintext files, source
control, command arguments, URLs, terminal output, and build logs.

### Dev mode is not a proxy deployment mode

The library authorizer checks the actual socket peer, not Host or a claimed
forwarded address. Supported loopback forms are IPv4 `127.0.0.0/8`, `::1`, and
IPv4-mapped `::ffff:127.x.x.x` addresses. It rejects a protected operation if any
`Forwarded` or `X-Forwarded-*` header is present, even if that header claims
loopback. These checks also apply to local upload PUTs.

**Never expose dev mode through a proxy, including a local proxy, or in
production.** A proxy can strip forwarding headers while making a remote request
appear to come from loopback. Public health and artifact serving are not made
private by dev checks.

Embedding applications must pass `auth: { mode: 'dev' }` explicitly to opt into
dev. `createArtifactServer({ blobs, metadata, auth: { secret } })` defaults to
required auth and does not read auth environment variables itself. Library users
control their listener binding and must keep dev listeners local too.

## Operator token creation and use

`createToken({ secret, jti, exp, sites, capabilities })` returns a token string in
memory; it does not print or persist it. Import it from
`packages/server/src/auth.js`. Only trusted operators should have the signing
key: possession permits minting any supported site/capability scope. Publishers
should normally receive only a short-lived scoped token, not that key.

Here is a minimal trusted-operator workflow from the repository root. First have
your secret manager inject the deployment's `OWA_AUTH_SECRET` into this process.
The example mints for `foo`, uses a non-secret audit label and a 15-minute expiry,
and publishes without activation. `remotePublish` uses the normal HTTP
plan/upload/commit flow and reads the in-process `OWA_TOKEN`; no token is printed,
passed as an argument, or written to a file. Replace the example origin and
prepare `./demo` before running.

```sh
node --input-type=module <<'NODE'
import { createToken } from './packages/server/src/auth.js';
import { remotePublish } from './packages/cli/src/remote.js';

try {
  const token = createToken({
    secret: process.env.OWA_AUTH_SECRET,
    jti: 'ci-publish-foo-001',
    exp: Math.floor(Date.now() / 1000) + 900,
    sites: ['foo'],
    capabilities: ['plan', 'upload', 'commit']
  });
  // Process-memory injection only; this is not a persisted shell export.
  process.env.OWA_TOKEN = token;
  await remotePublish('./demo', 'foo', 'https://artifacts.example.com', {
    activate: false
  });
} catch {
  console.error('Scoped publish failed');
  process.exitCode = 1;
} finally {
  delete process.env.OWA_TOKEN;
}
NODE
```

The fixed `jti` above is an illustrative audit label, not a credential or a nonce
that prevents replay. Choose a meaningful non-secret job/run label in practice.
The code does not imply secure memory erasure: use a short-lived trusted process
and restrict who can inspect its environment.

For ordinary CI, mint on the trusted operator side, then deliver the returned
token to the publisher as `OWA_TOKEN` through approved secret injection. Do not
use a console-printing mint script, shell command substitution that prints tokens,
a token CLI flag, or a plaintext token file. With `OWA_TOKEN` already injected:

```sh
npm run artifact -- publish demo --site foo \
  --server https://artifacts.example.com --no-activate
```

This publisher needs `plan`, `upload`, and `commit` when blobs are missing, but
not `activate`. A fully deduplicated publish needs no `upload` grant. A literally
commit-only token **cannot** run the CLI's plan/upload workflow; it can only send
a direct commit with `activate: false` once every referenced blob exists.
Default remote publishing also needs `activate`. `--no-activate` applies to the
remote publisher; the no-`--server` local operator path retains its existing
publish behavior.

For custom HTTP clients, keep the token in memory and send it only in a single
Authorization header. Do not embed it in JSON, a query, a grant URL, or another
header. Only literal JSON `false` in a commit's `activate` field disables
activation; omission, `null`, `0`, and the string `"false"` do not.

## Token wire format

The exact format is `owa1.payload.signature`, three dot-separated segments with
no surrounding whitespace. The token is at most 8192 characters. `payload` and
`signature` use canonical, **unpadded base64url**. The signature is the 32-byte
HMAC-SHA-256 of the ASCII bytes of `owa1.` followed by the encoded payload. It is
not a MAC over the decoded JSON and is not a JWT.

The payload is UTF-8 JSON generated with `JSON.stringify`, no whitespace, and
this exact field order:

1. `v`: integer `1`.
2. `jti`: operator-supplied audit identifier, 1–128 ASCII letters, digits, `_`, or
   `-` (`[A-Za-z0-9_-]`); it is required, not autogenerated.
3. `exp`: positive safe-integer Unix seconds, strictly greater than current Unix
   seconds. A token is expired at equality; there is no clock-skew grace period.
4. `sites`: 1–64 unique site scopes in ascending lexical order. Each is 1–63
   characters, starts with a lowercase ASCII letter or digit, and then contains
   only lowercase ASCII letters, digits, `_`, or `-` (`[a-z0-9][a-z0-9_-]{0,62}`).
   No wildcard, uppercase, hostname, slash, or Unicode scopes.
5. `capabilities`: 1–5 unique entries, sorted lexically, from exactly `plan`,
   `upload`, `commit`, `activate`, and `read`. No implied capabilities or wildcard.

`createToken` sorts copies of input arrays and rejects duplicates. Verification
requires already-sorted arrays and exact payload bytes; unknown fields,
duplicate JSON members, missing fields, different field order, whitespace,
alternate number/string encodings, unknown versions, invalid UTF-8, BOMs, base64
padding, non-URL-safe encodings, and noncanonical unused base64 bits are rejected.
This token JSON format is separate from artifact canonicalization.

The library key is either a UTF-8 string or a raw `Buffer`, at least 32 bytes.
Keys are copied for a running authorizer. Signature verification uses a
constant-time comparison for the fixed-length MAC before trusting JSON claims.
`verifyToken(token, { secret })` returns only the five validated claims. Library
`now` options, if supplied, are callbacks returning nonnegative safe-integer Unix
seconds; invalid clocks fail closed.

The HTTP scheme name `Bearer` is case-insensitive; exactly one space precedes
the token. Duplicate Authorization headers, extra whitespace, comma-separated
values, and other schemes are rejected. The implementation does not accept
credentials from query strings or cookies.

## Capability matrix

Every protected operation requires the token to include the exact requested site.
Capabilities are independent; `upload` does not imply `plan`, and `commit` does
not imply `activate` or `read`.

| HTTP operation | Required capability / additional condition |
| --- | --- |
| `POST /v1/sites/:site/publish/plan` | `plan` at admission, after the body, and before returning the completed plan. `plan` + `upload` are also rechecked **before each missing-blob grant is issued**, after asynchronous existence checks. A fully deduplicated plan succeeds with only `plan`, but not after expiry. |
| Filesystem `PUT /v1/uploads/:digest` | `upload` for the **signed `site` query scope**, plus an independently valid local upload signature and unexpired grant. Bearer and grant expiry are checked again after the body is received. |
| S3/R2 direct presigned PUT | No OWA bearer. OWA checks `upload` when issuing the grant; storage checks its own SigV4 authorization, not OWA capabilities. |
| `POST /v1/sites/:site/publish/commit` | `commit` + `activate` by default. Only literal `activate: false` reduces this to `commit`. |
| `POST /v1/sites/:site/activate/:releaseId` | `activate`. |
| `GET /v1/sites/:site/releases` | `read`. The existing response contains the site and full release records, including manifests for inspection; no individual-release inspection route is added. |
| `GET /health` | Public. |
| Artifact `GET` / `HEAD` | Public; the auth overlay is not artifact access control. |

For recognized control routes, auth runs before protected storage work; site
syntax is checked at the HTTP boundary. Activation release IDs must have the
existing `r_` plus 20 lowercase hexadecimal digits shape. Referenced metadata
site IDs/active release IDs are also checked before use. These checks do not
make a tampered store trustworthy.

Expiry is an authorization check, not transactional cancellation. Commit is
reauthorized after receiving its body and before entering the existing core
operation; activation/read are authorized before their metadata work. An admitted
core/storage operation can finish after expiry if backend I/O is slow. This
change does not add cancellation or partial-write rollback to those operations.
Plans recheck before returning results, and local PUTs recheck after their body,
so an attacker cannot extend those permissions by delaying body delivery.

### Filesystem upload grants

In required mode, a local grant has `method: 'PUT'`, a digest, `expiresIn`, its
URL, and `authorization: 'bearer'`. Its URL includes exactly the `expires`, `sig`,
and `site` fields generated by the server. `site` is a scope identifier, **not a
bearer secret**. The signature is lowercase hex HMAC-SHA-256 using an independent
upload-signing key over this UTF-8 input (newlines between lines, no trailing
newline):

```text
owa-upload-v1
<site>
<digest>
<expires>
```

Changing the site, digest, or expiry invalidates the grant. The bearer must allow
`upload` for that same site; a valid signature alone is insufficient. The URL is
still sensitive grant material and must not be logged.

`expiresIn` is the smaller of 900 seconds and the issuing bearer token's
remaining lifetime. Local `expires` is an absolute Unix timestamp. The server
checks both the bearer and grant before reading the body and again afterward,
then checks the bytes' digest before storing. A slow body cannot extend either
expiry.

By default the server generates a separate random upload key at construction.
An embedded server can supply `uploadSecret`; required mode enforces at least 32
bytes and rejects equality with the bearer-signing key. Reconstructing a server
with a fresh upload key invalidates its old local grants. Neither this key nor
the bearer-signing key is a token-persistence mechanism.

The legacy unscoped filesystem URL shape (only expiry/signature, signature input
`<digest>\n<expires>`, no bearer marker) exists **only in explicit dev mode** and
still requires a direct-loopback request. Required mode does not accept it.

### S3/R2 grants are storage credentials, not OWA tokens

S3/R2 grants keep the normal direct-storage SigV4 URL shape and have **no**
`authorization: 'bearer'` marker. No OWA token is embedded in their URLs, and the
publisher must not forward its OWA Authorization header to them. OWA bounds the
requested presign duration to 900 seconds or the issuing token's remaining
lifetime, whichever is smaller.

A presigned URL is delegatable until its storage expiry. The object store does
not understand OWA sites, capabilities, `jti`, or bearer-key rotation. Once the
grant has been issued, OWA cannot revoke it or recheck an OWA token mid-flight;
the storage provider's expiry and in-flight request semantics apply. OWA key
rotation alone does not cancel previously issued S3/R2 URLs.

## Remote client credential handling

The CLI's only remote credential source is `OWA_TOKEN` in its environment. It
keeps the token in memory, does not persist it, and does not add it to URLs or
request bodies. The server address must be an HTTP(S) **origin** with no embedded
credentials, path prefix, query, or fragment. Use HTTPS; token-bearing HTTP is
rejected except for loopback (`localhost`, `::1`, or IPv4 `127/8`). Tokenless HTTP
exists for local development, not as a secure deployment recommendation.

Control requests and all upload PUTs use `redirect: 'error'` and
`credentials: 'omit'`. No control or PUT redirects are followed. Upload headers
are constructed afresh, never copied wholesale from control-plane headers. An
ordinary presigned upload gets **no OWA bearer, even on the same origin**.

The client only adds the bearer to an upload that explicitly declares
`authorization: 'bearer'` and passes origin, exact local digest path, digest,
site, expiry, and signature-shape checks. It rejects unexpected grant headers,
unknown authorization markers, wrong methods, duplicate grants, and mismatched
sites. It validates all returned upload instructions before sending any bytes or
credentials. Custom clients should preserve this distinction rather than
blindly attaching control-plane headers to every PUT.

Untrusted error response bodies and nested network/provider causes are never
printed by the CLI. It reports fixed local codes/messages, recognized auth codes,
and bounded HTTP statuses. Successful terminal output is limited to validated
release/digest/count metadata, not full grants or tokens.

## Safe errors and audit hooks

Auth HTTP errors are JSON `{ error, code }` with fixed messages, `Cache-Control:
no-store`, and, for 401 only, `WWW-Authenticate: Bearer realm="owa"`. The exact
auth error vocabulary is:

| Code | HTTP status | Fixed message |
| --- | --- | --- |
| `OWA_AUTH_CONFIG` | 500 | Invalid authentication configuration |
| `OWA_AUTH_INVALID_TOKEN` | 401 | Invalid authentication token |
| `OWA_AUTH_INVALID_SIGNATURE` | 401 | Invalid authentication signature |
| `OWA_AUTH_EXPIRED` | 401 | Authentication token expired |
| `OWA_AUTH_MISSING` | 401 | Authentication required |
| `OWA_AUTH_SITE` | 403 | Authentication does not permit this site |
| `OWA_AUTH_CAPABILITY` | 403 | Authentication does not permit this operation |
| `OWA_AUTH_DEV_ONLY` | 403 | Development authentication requires a direct loopback connection |

Configuration errors normally stop construction/startup rather than producing an
HTTP response. Executable startup failures print only a fixed diagnostic and
exit nonzero. Tokens, keys, provider messages, and causes are not included.

Invalid/expired local grants return 403 with `OWA_UPLOAD_INVALID`; invalid site
or upload scope returns 400 with `OWA_INVALID_SITE`. A recognized missing-blob
commit failure returns 500 with `OWA_BLOB_MISSING` and `error: 'Missing blob'`,
without the digest/provider details. Other caught operation failures use 500,
`OWA_OPERATION_FAILED`, and `error: 'Operation failed'`. Existing explicit route
validation/status responses remain; this is not a new comprehensive error
architecture.

Embedded servers may supply `audit` to `createArtifactServer`. For successful
protected operations only, it receives a frozen `{ jti, site, operation }`, with
operation `plan`, `upload` (local filesystem PUT), `commit`, `activate`, or `read`.
It receives no request object, headers, URLs, full token, other claims, request
body, or error cause. No auth metadata is added to release records. A commit that
also activates emits a `commit` event, not a separate activation event. S3/R2
storage PUT completion has no server-side OWA audit callback.

The hook is optional and best-effort: synchronous throws and asynchronous
rejections are ignored, delivery is not awaited as a durability guarantee, and
there is no durable audit log or failed-operation audit stream. Dev requests have
no token `jti`, so do not emit these token audit events. If an operator records
hooks, keep only the safe fields and protect the resulting operational metadata.

## Limits and trust boundary

- Tokens are bearer credentials and can be replayed until expiry. There is no
  per-token revocation, replay database, one-time-use enforcement, or automatic
  refresh. `jti` is for audit correlation, not replay prevention.
- There is one signing key per running authorizer, no key ID/key ring or graceful
  multi-key overlap. Rotating the key and restarting/reconstructing all verifiers
  invalidates **all** old tokens. Changing a process environment variable alone
  does not rotate an already-constructed authorizer.
- Tokens have no audience claim. Reusing a key across hosts/deployments lets a
  matching site-scoped token verify there too. Use separate keys per deployment
  and restrict signer access; TLS, correct clocks, and secret custody are trusted
  operator responsibilities.
- Storage adapters, metadata files, and local operators remain trusted. Without
  `--server`, local CLI publish/release/activation and OCI import operations use
  filesystem permissions, outside this HTTP authorization scope. No HTTP token
  can compensate for unauthorized access to the data directory.
- The content-addressed blob store is globally shared, not tenant-private
  storage. Planning can reveal digest existence through reuse; commit checks
  existence, not site ownership. Capability scoping is not a storage ownership
  or confidential-blob isolation model.
- Health and served artifact bytes stay public, including artifacts whose
  manifest visibility is unlisted. `read` protects control-plane release and
  manifest inspection, not public artifact retrieval.
- The composed [`sandboxed-web-v1` profile](sandboxed-web-v1.md) supplies a
  script-disabled response policy, not service-worker isolation. Origin topology
  is supplied separately by the v0.4
  [control/content origin split](origins.md): a configured content origin serves
  artifact GET/HEAD only and exposes no bearer-protected route. This auth model
  is unchanged by that split — same token format, capabilities, scopes, errors
  and challenges — and the control listener keeps the entire authenticated
  surface. On the legacy shared-origin server, protected control routes still
  exist on every host and `?site=` still multiplexes sites on one origin. Fresh
  origins and browser state remain operator responsibilities. Do not treat this
  reference server as a full production multi-tenant hosting service.

## Tests

```sh
npm test                          # offline suite, including auth
npm run test:auth                 # token, HTTP, CLI, executable-startup auth tests
npm run test:conformance          # portable fixtures/schema
npm run test:property             # deterministic property tests
npm run test:integration:harness  # offline live-request timeout/cleanup checks
npm run test:integration          # opt-in live storage matrix; missing config skips
```

Auth tests exercise exact token bytes and rejection cases, capability/site
boundaries, grant issuance/expiry, required-mode filesystem and S3 grant behavior,
CLI credential routing/redaction, and real executable startup. Synthetic tokens
are created in memory; they are not checked-in bearer examples or production
credentials. The pre-existing HTTP conformance fixture and the live S3/MinIO/R2
suite now explicitly select loopback dev mode so their tokenless storage flows
remain valid. The live suite checks `OWA_BLOB_MISSING` for its pre-upload commit
failure; it is not live required-auth or TLS coverage. See
[integration-tests.md](integration-tests.md) for the live matrix, configuration,
cleanup, and evidence limitations. Do not equate skipped live cases or offline
success with tested provider interoperability.
