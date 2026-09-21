import { ERRORS } from './errors.js';

export const SITE_PATTERN = '^[a-z0-9][a-z0-9_-]{0,62}(?![\\s\\S])';
export const RELEASE_PATTERN = '^r_[0-9a-f]{20}(?![\\s\\S])';
const site = { type: 'string', minLength: 1, maxLength: 63, pattern: SITE_PATTERN };
const releaseId = { type: 'string', pattern: RELEASE_PATTERN };
const activeReleaseId = { anyOf: [releaseId, { type: 'null' }] };
const artifactDigest = { type: 'string', pattern: '^sha256:[0-9a-f]{64}(?![\\s\\S])' };
const count = { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER };
const server = { type: 'string', minLength: 1, maxLength: 2048, description: 'The configured trusted HTTP(S) origin; no path, query, credentials, or fragment.' };
const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const error = object({
  ok: { const: false },
  error: object({
    code: { type: 'string', enum: Object.keys(ERRORS) },
    category: { type: 'string', enum: [...new Set(Object.values(ERRORS).map(([category]) => category))] },
    message: { type: 'string', enum: [...new Set(Object.values(ERRORS).map(([, message]) => message))] },
    status: { type: 'integer', minimum: 100, maximum: 599 }
  }, ['code', 'category', 'message'])
});
// required defaults to every property; pass an explicit list to make a field
// optional, as `url` is now that the server may legitimately supply no URL.
const output = (properties, required = null) => ({
  type: 'object',
  oneOf: [object({ ok: { const: true }, ...properties }, required === null ? undefined : ['ok', ...required]), error]
});
const mutation = { readOnlyHint: false, destructiveHint: true, openWorldHint: true };
const activationInput = object({ site, server, releaseId });
const activationOutput = output({ site, activeReleaseId: releaseId });

export const TOOLS = [
  {
    name: 'publish',
    description: 'Pack a directory under the operator staging root and publish using HTTP plan/upload/commit. Activates by default; false stages a release. Requires a trusted, read-only staging tree during packing; not a filesystem sandbox.',
    inputSchema: object({
      site, server,
      directory: {
        type: 'string', minLength: 1, maxLength: 4096,
        pattern: '^(?:(?=[A-Za-z]:[\\\\/])|(?![A-Za-z][A-Za-z0-9+.-]*:))[^\\u0000-\\u001f\\u007f-\\u009f]+(?![\\s\\S])',
        description: 'Existing directory, relative to the configured root or absolute inside it. No URL or control characters.'
      },
      activate: { type: 'boolean', default: true }
    }, ['site', 'server', 'directory']),
    outputSchema: output({
      site, artifactDigest, releaseId, activeReleaseId, uploaded: count, reused: count,
      url: { type: 'string', description: 'Canonical public content URL returned by the server. Absent when the server has no content origin configured. Not an upload grant.' }
    }, ['site', 'artifactDigest', 'releaseId', 'activeReleaseId', 'uploaded', 'reused']),
    annotations: mutation
  },
  {
    name: 'list_releases',
    description: 'List validated release metadata and the active pointer over HTTP. Requires read capability. Does not return manifests or file bytes.',
    inputSchema: object({ site, server }),
    outputSchema: output({
      site, activeReleaseId,
      releases: { type: 'array', items: object({
        releaseId, artifactDigest,
        createdAt: { type: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z(?![\\s\\S])' }
      }) }
    }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true }
  },
  {
    name: 'activate',
    description: 'Activate the explicitly named existing release over HTTP; changes only the active pointer. Requires activate capability, not read capability.',
    inputSchema: activationInput,
    outputSchema: activationOutput,
    annotations: mutation
  },
  {
    name: 'rollback',
    description: 'Activate an explicitly selected older release over HTTP. No automatic selection or release-list lookup; requires activate capability only.',
    inputSchema: activationInput,
    outputSchema: activationOutput,
    annotations: mutation
  }
];
