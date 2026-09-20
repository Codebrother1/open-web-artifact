import { createHash } from 'node:crypto';

export const OWA_SPEC_VERSION = 'owa.dev/v1';
export const OWA_MEDIA_TYPE = 'application/vnd.openwebartifact.site.v1+json';

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
    if (!Number.isFinite(value)) throw new TypeError('Canonical JSON forbids non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort(compareUnicodeCodePoints);
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`Unsupported canonical JSON value: ${typeof value}`);
}

export function artifactDigest(manifest) {
  return sha256(Buffer.from(canonicalJson(manifest), 'utf8'));
}

function isDigest(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}

export function validateArtifactPath(path) {
  if (typeof path !== 'string' || !path.startsWith('/')) throw new Error(`Invalid artifact path: ${path}`);
  if (path.includes('\\') || path.includes('\0')) throw new Error(`Invalid artifact path: ${path}`);
  if (path.length < 2 || path.endsWith('/') || path.includes('//')) throw new Error(`Artifact path must name a file: ${path}`);
  const parts = path.split('/');
  if (parts.some(part => part === '..' || part === '.')) throw new Error(`Artifact path must be normalized: ${path}`);
  return path;
}

export function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('Manifest must be an object');
  if (manifest.specVersion !== OWA_SPEC_VERSION) throw new Error(`Unsupported specVersion: ${manifest.specVersion}`);
  if (manifest.artifactType !== OWA_MEDIA_TYPE) throw new Error(`Unsupported artifactType: ${manifest.artifactType}`);
  validateArtifactPath(manifest.entrypoint);
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) throw new Error('Manifest files must be a non-empty array');

  const paths = new Set();
  for (const file of manifest.files) {
    validateArtifactPath(file.path);
    if (paths.has(file.path)) throw new Error(`Duplicate artifact path: ${file.path}`);
    paths.add(file.path);
    if (!isDigest(file.digest)) throw new Error(`Invalid SHA-256 digest for ${file.path}`);
    if (!Number.isSafeInteger(file.size) || file.size < 0) throw new Error(`Invalid size for ${file.path}`);
    if (typeof file.mediaType !== 'string' || !file.mediaType) throw new Error(`Invalid mediaType for ${file.path}`);
  }
  if (!paths.has(manifest.entrypoint)) throw new Error(`Entrypoint ${manifest.entrypoint} is not present in files`);
  if (manifest.routing?.spaFallback) {
    validateArtifactPath(manifest.routing.spaFallback);
    if (!paths.has(manifest.routing.spaFallback)) throw new Error('spaFallback must reference a manifest file');
  }
  const visibility = manifest.access?.visibility;
  if (visibility !== undefined && !['public', 'unlisted'].includes(visibility)) throw new Error(`Unsupported visibility: ${visibility}`);
  if (manifest.lifecycle?.expiresAt != null && Number.isNaN(Date.parse(manifest.lifecycle.expiresAt))) throw new Error('Invalid lifecycle.expiresAt');
  canonicalJson(manifest);
  return manifest;
}
