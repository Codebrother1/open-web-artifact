import { isIP } from 'node:net';
import { packDirectory } from '../../core/src/index.js';

const AUTH_CODES = new Set([
  'OWA_AUTH_CONFIG', 'OWA_AUTH_INVALID_TOKEN', 'OWA_AUTH_INVALID_SIGNATURE',
  'OWA_AUTH_EXPIRED', 'OWA_AUTH_MISSING', 'OWA_AUTH_SITE', 'OWA_AUTH_CAPABILITY', 'OWA_AUTH_DEV_ONLY'
]);
const MESSAGES = Object.freeze({
  OWA_CLI_CONFIG: 'Invalid remote configuration',
  OWA_CLI_INPUT: 'Invalid site or release identifier',
  OWA_CLI_RESPONSE: 'Invalid control-plane response',
  OWA_CLI_GRANT: 'Invalid upload grant',
  OWA_CLI_HTTP: 'Control-plane request failed',
  OWA_CLI_UPLOAD: 'Blob upload failed',
  OWA_CLI_NETWORK: 'Network request failed',
  OWA_CLI_FAILED: 'Operation failed'
});
const exact = (pattern, value) => typeof value === 'string' && pattern.test(value);
const isSite = value => exact(/^[a-z0-9][a-z0-9_-]{0,62}(?![\s\S])/, value);
const isRelease = value => exact(/^r_[0-9a-f]{20}(?![\s\S])/, value);
const isDigest = value => exact(/^sha256:[0-9a-f]{64}(?![\s\S])/, value);
const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const isStatus = value => Number.isInteger(value) && value >= 100 && value <= 599;
const isActiveRelease = value => value === null || isRelease(value);
function isTimestamp(value) {
  return exact(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z(?![\s\S])/, value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

// Only local codes and bounded numeric statuses can reach the terminal. Never
// retain or print provider messages, response errors, URLs, or nested causes.
export class CliError extends Error {
  constructor(code, status) {
    const safeCode = Object.hasOwn(MESSAGES, code) || AUTH_CODES.has(code) ? code : 'OWA_CLI_FAILED';
    super(MESSAGES[safeCode] ?? MESSAGES.OWA_CLI_HTTP);
    this.code = safeCode;
    if (isStatus(status)) this.status = status;
  }
}
export function cliErrorMessage(error) {
  const code = error instanceof CliError && (Object.hasOwn(MESSAGES, error.code) || AUTH_CODES.has(error.code))
    ? error.code : 'OWA_CLI_FAILED';
  const status = error instanceof CliError && isStatus(error.status) ? ` (HTTP ${error.status})` : '';
  return `artifact: ${code}: ${MESSAGES[code] ?? MESSAGES.OWA_CLI_HTTP}${status}`;
}
function requireSite(slug) {
  if (!isSite(slug)) throw new CliError('OWA_CLI_INPUT');
}
function httpUrl(value, code) {
  // Reject URL normalization tricks, embedded credentials (even empty ones),
  // fragments and non-HTTP schemes before any request can carry a credential.
  if (typeof value !== 'string' || /[\s\\\u0000-\u001f\u007f]/.test(value)
    || !/^https?:\/\//i.test(value) || value.includes('#')) throw new CliError(code);
  let url;
  try { url = new URL(value); } catch { throw new CliError(code); }
  const authority = value.match(/^https?:\/\/([^/?#]*)/i)?.[1];
  if (!authority || authority.includes('@') || url.username || url.password || url.hash
    || !['http:', 'https:'].includes(url.protocol)) throw new CliError(code);
  return url;
}
function controlClient(server) {
  const base = httpUrl(server, 'OWA_CLI_CONFIG');
  if (!/^https?:\/\/[^/?#]+\/?(?![\s\S])/i.test(server) || base.pathname !== '/' || base.search)
    throw new CliError('OWA_CLI_CONFIG');
  // OWA_TOKEN is the only credential source. It stays in memory and is never
  // added to a URL, persisted, or copied to ordinary object-store uploads.
  const token = process.env.OWA_TOKEN || null;
  if (token && !/^[A-Za-z0-9._-]{1,8192}(?![\s\S])/.test(token)) throw new CliError('OWA_CLI_CONFIG');
  const loopback = base.hostname === 'localhost' || base.hostname === '[::1]'
    || (isIP(base.hostname) === 4 && base.hostname.startsWith('127.'));
  if (token && base.protocol === 'http:' && !loopback) throw new CliError('OWA_CLI_CONFIG');
  return {
    origin: base.origin,
    token,
    async request(path, body, method = body === undefined ? 'GET' : 'POST') {
      const headers = {};
      if (token) headers.authorization = `Bearer ${token}`;
      if (body !== undefined) headers['content-type'] = 'application/json';
      const res = await safeFetch(`${base.origin}${path}`, {
        method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) })
      });
      let result;
      try { result = await res.json(); } catch {
        if (res.ok) throw new CliError('OWA_CLI_RESPONSE');
      }
      if (!res.ok) throw new CliError(AUTH_CODES.has(result?.code) ? result.code : 'OWA_CLI_HTTP', res.status);
      if (!isRecord(result)) throw new CliError('OWA_CLI_RESPONSE');
      return result;
    }
  };
}
export function validateRemoteServer(server) {
  return controlClient(server).origin;
}
async function safeFetch(url, options) {
  try { return await fetch(url, { ...options, redirect: 'error', credentials: 'omit' }); }
  catch { throw new CliError('OWA_CLI_NETWORK'); }
}
// The only storage headers a grant may instruct the client to send. Each value
// is re-derived or pinned locally, so a hostile control plane cannot turn the
// upload into a vehicle for arbitrary headers: the checksum MUST equal the
// digest being uploaded, and create-once MUST be exactly "*".
const STORAGE_HEADERS = Object.freeze(['x-amz-checksum-sha256', 'if-none-match']);
function storageHeaders(upload) {
  if (!Object.hasOwn(upload, 'headers')) return {};
  if (!isRecord(upload.headers)) throw new CliError('OWA_CLI_GRANT');
  const entries = Object.entries(upload.headers);
  if (entries.length === 0) throw new CliError('OWA_CLI_GRANT');
  const out = {};
  for (const [name, value] of entries) {
    const lower = name.toLowerCase();
    if (!STORAGE_HEADERS.includes(lower) || typeof value !== 'string' || Object.hasOwn(out, lower)) throw new CliError('OWA_CLI_GRANT');
    if (lower === 'x-amz-checksum-sha256' && value !== Buffer.from(upload.digest.slice('sha256:'.length), 'hex').toString('base64')) throw new CliError('OWA_CLI_GRANT');
    if (lower === 'if-none-match' && value !== '*') throw new CliError('OWA_CLI_GRANT');
    out[lower] = value;
  }
  return out;
}
function uploadRequest(upload, client, slug, blobs) {
  if (!isRecord(upload) || !isDigest(upload.digest) || !blobs.has(upload.digest)
    || (Object.hasOwn(upload, 'method') && upload.method !== 'PUT')
    || (Object.hasOwn(upload, 'authorization') && upload.authorization !== 'bearer')
    // A local bearer grant never carries storage headers; a storage grant never carries a bearer.
    || (upload.authorization === 'bearer' && Object.hasOwn(upload, 'headers')))
    throw new CliError('OWA_CLI_GRANT');
  const url = httpUrl(upload.url, 'OWA_CLI_GRANT');
  const headers = storageHeaders(upload);
  if (upload.authorization === 'bearer') {
    const rawPath = upload.url.match(/^https?:\/\/[^/?#]+([^?#]*)/i)?.[1];
    const query = url.searchParams;
    const expires = query.get('expires');
    if (url.origin !== client.origin || rawPath !== url.pathname
      || !/^\/v1\/uploads\/sha256(?::|%3[Aa])[0-9a-f]{64}(?![\s\S])/.test(url.pathname)
      || decodeURIComponent(url.pathname) !== `/v1/uploads/${upload.digest}`
      || query.size !== 3 || query.getAll('site').length !== 1 || query.get('site') !== slug
      || query.getAll('expires').length !== 1 || !/^[0-9]+(?![\s\S])/.test(expires ?? '')
      || !Number.isSafeInteger(Number(expires)) || Number(expires) <= 0
      || query.getAll('sig').length !== 1 || !exact(/^[0-9a-f]{64}(?![\s\S])/, query.get('sig')))
      throw new CliError('OWA_CLI_GRANT');
    if (client.token) headers.authorization = `Bearer ${client.token}`;
  }
  // Explicitly constructed upload headers, never the control-plane headers.
  return { url: url.href, createOnce: headers['if-none-match'] === '*', options: { method: 'PUT', headers, body: Buffer.from(blobs.get(upload.digest)) } };
}

export async function remotePublishResult(directory, slug, server, { activate = true } = {}) {
  requireSite(slug);
  const client = controlClient(server);
  const packed = await packDirectory(directory);
  const path = `/v1/sites/${slug}/publish`;
  const body = { manifest: packed.manifest, artifactDigest: packed.artifactDigest };
  const plan = await client.request(`${path}/plan`, body);
  if (plan.slug !== slug || plan.artifactDigest !== packed.artifactDigest || !Array.isArray(plan.uploads)
    || !Number.isSafeInteger(plan.reused) || plan.reused < 0 || plan.reused > packed.blobs.size
    || plan.uploads.length + plan.reused !== packed.blobs.size) throw new CliError('OWA_CLI_RESPONSE');
  // Validate every instruction before uploading any bytes or credentials.
  const uploads = plan.uploads.map(upload => uploadRequest(upload, client, slug, packed.blobs));
  if (new Set(plan.uploads.map(upload => upload.digest)).size !== uploads.length) throw new CliError('OWA_CLI_GRANT');
  for (const upload of uploads) {
    const res = await safeFetch(upload.url, upload.options);
    // A create-once grant answers 412 when the object already exists — e.g. a
    // retried upload whose first attempt did land, or a concurrent publisher of
    // the same content. That object can only have been written through a
    // checksum-bound grant for this digest, and commit verifies it regardless.
    if (res.status === 412 && upload.createOnce) continue;
    if (!res.ok) throw new CliError('OWA_CLI_UPLOAD', res.status);
  }
  const commit = await client.request(`${path}/commit`, { ...body, ...(activate === false ? { activate: false } : {}) });
  if (commit.slug !== slug || !isRelease(commit.releaseId) || !isDigest(commit.artifactDigest)
    || commit.artifactDigest !== packed.artifactDigest || !isActiveRelease(commit.activeReleaseId))
    throw new CliError('OWA_CLI_RESPONSE');
  // The canonical public URL is whatever the control plane returns; the CLI never
  // reconstructs host mapping locally. It is still validated as a credential-free
  // absolute http(s) URL so a control bearer can never ride along in a printed
  // address, and an absent or unusable value simply yields no URL at all.
  const contentUrl = publicContentUrl(commit.contentUrl);
  return {
    site: slug,
    artifactDigest: commit.artifactDigest,
    releaseId: commit.releaseId,
    activeReleaseId: commit.activeReleaseId,
    uploaded: uploads.length,
    reused: plan.reused,
    ...(contentUrl === null ? {} : { contentUrl })
  };
}

/** Accept only a credential-free absolute http(s) URL, else null. Never throws. */
export function publicContentUrl(value) {
  if (value === undefined || value === null) return null;
  let url;
  try { url = httpUrl(value, 'OWA_CLI_RESPONSE'); } catch { return null; }
  if (url.username || url.password || url.search || url.hash) return null;
  return url.href;
}

export async function remotePublish(directory, slug, server, { activate = true } = {}) {
  const result = await remotePublishResult(directory, slug, server, { activate });
  return `Published ${result.releaseId}\nArtifact ${result.artifactDigest}\nUploaded ${result.uploaded} blob(s), reused ${result.reused}`
    + (result.contentUrl ? `\nPublic URL: ${result.contentUrl}` : '');
}

export async function remoteReleasesResult(slug, server) {
  requireSite(slug);
  const body = await controlClient(server).request(`/v1/sites/${slug}/releases`);
  if (!isRecord(body.site) || body.site.slug !== slug || !isActiveRelease(body.site.activeReleaseId)
    || !Array.isArray(body.releases) || !body.releases.every(release => isRecord(release)
      && isRelease(release.id) && isDigest(release.artifactDigest) && isTimestamp(release.createdAt)))
    throw new CliError('OWA_CLI_RESPONSE');
  return {
    site: slug,
    activeReleaseId: body.site.activeReleaseId,
    releases: body.releases.map(release => ({
      releaseId: release.id,
      artifactDigest: release.artifactDigest,
      createdAt: release.createdAt
    }))
  };
}

export async function remoteReleases(slug, server) {
  const result = await remoteReleasesResult(slug, server);
  return result.releases.map(release => `${release.releaseId}${result.activeReleaseId === release.releaseId ? ' *' : ''}\t${release.artifactDigest}\t${release.createdAt}`).join('\n');
}

export async function remoteActivateResult(releaseId, slug, server) {
  requireSite(slug);
  if (!isRelease(releaseId)) throw new CliError('OWA_CLI_INPUT');
  const body = await controlClient(server).request(`/v1/sites/${slug}/activate/${releaseId}`, undefined, 'POST');
  if (body.slug !== slug || !isRelease(body.activeReleaseId) || body.activeReleaseId !== releaseId)
    throw new CliError('OWA_CLI_RESPONSE');
  return { site: slug, activeReleaseId: body.activeReleaseId };
}

export async function remoteActivate(releaseId, slug, server) {
  const result = await remoteActivateResult(releaseId, slug, server);
  return `Activated ${result.activeReleaseId} for ${slug}`;
}
