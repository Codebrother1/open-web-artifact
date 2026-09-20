import { createHash } from 'node:crypto';

export const OWA_SPEC_VERSION = 'owa.dev/v1';
export const OWA_MEDIA_TYPE = 'application/vnd.openwebartifact.site.v1+json';

// Stable conformance categories; retain ordinary errors and human-readable text.
export function owaError(code, message) {
  return Object.assign(new Error(message), { code });
}

export function sha256(data) {
  return `sha256:${createHash('sha256').update(data).digest('hex')}`;
}

function compareUnicodeCodePoints(a, b) {
  const aa = Array.from(a, c => c.codePointAt(0));
  const bb = Array.from(b, c => c.codePointAt(0));
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) {
    if (aa[i] !== bb[i]) return aa[i] - bb[i];
  }
  return aa.length - bb.length;
}

/**
 * Deterministic JSON encoding used for OWA artifact identity.
 * The v1 schema only permits finite JSON numbers. Object keys are ordered by
 * Unicode code point and insignificant whitespace is omitted.
 */
export function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw Object.assign(new TypeError('Canonical JSON forbids non-finite numbers'), { code: 'OWA_INVALID_JSON_VALUE' });
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort(compareUnicodeCodePoints);
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw Object.assign(new TypeError(`Unsupported canonical JSON value: ${typeof value}`), { code: 'OWA_INVALID_JSON_VALUE' });
}

export function artifactDigest(manifest) {
  return sha256(Buffer.from(canonicalJson(manifest), 'utf8'));
}

function isDigest(value) {
  return typeof value === 'string' && value.length === 71 && /^sha256:[0-9a-f]{64}$/.test(value);
}

export function validateArtifactPath(path) {
  if (typeof path !== 'string' || !path.startsWith('/')) throw owaError('OWA_INVALID_PATH', `Invalid artifact path: ${typeof path === 'string' ? path : typeof path}`);
  if (path.includes('\\') || path.includes('\0')) throw owaError('OWA_INVALID_PATH', `Invalid artifact path: ${path}`);
  if (path.length < 2 || path.endsWith('/') || path.includes('//')) throw owaError('OWA_INVALID_PATH', `Artifact path must name a file: ${path}`);
  const parts = path.split('/');
  if (parts.some(part => part === '..' || part === '.')) throw owaError('OWA_INVALID_PATH', `Artifact path must be normalized: ${path}`);
  return path;
}

function checkObject(value, name, allowed, required = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw owaError('OWA_INVALID_MANIFEST', `${name} must be an object`);
  if (required.some(key => !Object.hasOwn(value, key))) throw owaError('OWA_INVALID_MANIFEST', `${name} is missing a required field`);
  if (allowed && Object.keys(value).some(key => !allowed.includes(key))) throw owaError('OWA_INVALID_MANIFEST', `${name} contains an unknown field`);
}

function validExpiry(value) {
  // RFC 3339 calendar/time checks, without implementation-dependent date parsing.
  // Leap seconds remain unsupported, as in the existing reference validator.
  const match = /^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[zZ]|[+-](\d{2}):(\d{2}))(?![\s\S])/.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const offsetHour = Number(match[7] ?? 0), offsetMinute = Number(match[8] ?? 0);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]
    && hour < 24 && minute < 60 && second < 60
    && offsetHour < 24 && offsetMinute < 60;
}

export function validateManifest(manifest) {
  checkObject(manifest, 'Manifest', ['specVersion', 'artifactType', 'entrypoint', 'files', 'routing', 'access', 'lifecycle', 'annotations'], ['specVersion', 'artifactType', 'entrypoint', 'files']);
  if (manifest.specVersion !== OWA_SPEC_VERSION) throw owaError('OWA_UNSUPPORTED_SPEC_VERSION', `Unsupported specVersion: ${typeof manifest.specVersion === 'string' ? manifest.specVersion : typeof manifest.specVersion}`);
  if (manifest.artifactType !== OWA_MEDIA_TYPE) throw owaError('OWA_UNSUPPORTED_ARTIFACT_TYPE', `Unsupported artifactType: ${typeof manifest.artifactType === 'string' ? manifest.artifactType : typeof manifest.artifactType}`);
  validateArtifactPath(manifest.entrypoint);
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) throw owaError('OWA_INVALID_MANIFEST', 'Manifest files must be a non-empty array');

  const paths = new Set();
  for (const file of manifest.files) {
    checkObject(file, 'File', ['path', 'digest', 'size', 'mediaType'], ['path', 'digest', 'size', 'mediaType']);
    validateArtifactPath(file.path);
    if (paths.has(file.path)) throw owaError('OWA_DUPLICATE_PATH', `Duplicate artifact path: ${file.path}`);
    paths.add(file.path);
    if (!isDigest(file.digest)) throw owaError('OWA_INVALID_DIGEST', `Invalid SHA-256 digest for ${file.path}`);
    if (!Number.isSafeInteger(file.size) || file.size < 0) throw owaError('OWA_INVALID_SIZE', `Invalid size for ${file.path}`);
    if (typeof file.mediaType !== 'string' || !file.mediaType) throw owaError('OWA_INVALID_MEDIA_TYPE', `Invalid mediaType for ${file.path}`);
  }
  if (!paths.has(manifest.entrypoint)) throw owaError('OWA_MISSING_ENTRYPOINT', `Entrypoint ${manifest.entrypoint} is not present in files`);
  for (const [name, allowed] of [['routing', ['spaFallback']], ['access', ['visibility']], ['lifecycle', ['expiresAt']], ['annotations', null]]) {
    if (Object.hasOwn(manifest, name)) checkObject(manifest[name], name, allowed);
  }
  if (manifest.routing && Object.hasOwn(manifest.routing, 'spaFallback')) {
    validateArtifactPath(manifest.routing.spaFallback);
    if (!paths.has(manifest.routing.spaFallback)) throw owaError('OWA_MISSING_SPA_FALLBACK', 'spaFallback must reference a manifest file');
  }
  const visibility = manifest.access?.visibility;
  if (visibility !== undefined && !['public', 'unlisted'].includes(visibility)) throw owaError('OWA_INVALID_VISIBILITY', `Unsupported visibility: ${typeof visibility === 'string' ? visibility : typeof visibility}`);
  const expiresAt = manifest.lifecycle?.expiresAt;
  if (expiresAt != null && (typeof expiresAt !== 'string' || !validExpiry(expiresAt))) throw owaError('OWA_INVALID_EXPIRY', 'Invalid lifecycle.expiresAt');
  if (manifest.annotations) {
    for (const value of Object.values(manifest.annotations)) {
      if (value !== null && !['string', 'number', 'boolean'].includes(typeof value)) throw owaError('OWA_INVALID_ANNOTATIONS', 'Annotations must contain only string, number, boolean, or null values');
    }
  }
  canonicalJson(manifest);
  return manifest;
}
