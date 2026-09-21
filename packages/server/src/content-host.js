// Host-to-site binding for the content origin. This module decides which single
// OWA site a public content request is allowed to reach. It reads ONLY the direct
// Host header: forwarded headers are never consulted, so a proxy that does not
// overwrite Host cannot be used to select another site. See docs/origins.md.
import { AuthError, isSiteScope } from './auth.js';

// A single DNS label: the site slug grammar already excludes dots and uppercase.
const LABEL = /^[a-z0-9][a-z0-9_-]{0,62}(?![\s\S])/;
const PORT = /^[0-9]{1,5}(?![\s\S])/;
// A registrable content base such as "sites.example.com". Labels are letters,
// digits and hyphens; no leading/trailing hyphen, no empty label, no trailing dot.
const DOMAIN_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)(?![\s\S])/;

export class ContentHostError extends Error {
  constructor(code) {
    const [status, message] = code === 'OWA_CONTENT_HOST_MALFORMED'
      ? [400, 'Malformed Host header']
      : [404, 'site or active release not found'];
    super(message);
    this.name = 'ContentHostError';
    this.code = code;
    this.status = status;
  }
}

/** Lowercase a base domain and reject anything that is not a plain DNS name. */
export function normalizeBaseDomain(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 253) throw new AuthError('OWA_AUTH_CONFIG');
  // Normal DNS normalization is ASCII-lowercasing only; reject non-ASCII outright
  // rather than guessing at IDNA, which would create homograph ambiguity here.
  if (/[^\x21-\x7e]/.test(value)) throw new AuthError('OWA_AUTH_CONFIG');
  const lowered = value.toLowerCase();
  if (lowered !== value && !/^[a-z0-9.\-]+(?![\s\S])/.test(lowered)) throw new AuthError('OWA_AUTH_CONFIG');
  // A single label is allowed so that `<site>.localhost` works for local
  // development; a public deployment should still use a registrable domain.
  const labels = lowered.split('.');
  if (!labels.every(label => DOMAIN_LABEL.test(label))) throw new AuthError('OWA_AUTH_CONFIG');
  return lowered;
}

/**
 * Validate and split a raw Host header value into { host, port }.
 * Rejects userinfo, path/query/fragment confusion, whitespace, control bytes,
 * NUL, backslashes, IPv6/address literals, empty labels and trailing dots.
 * Returns null for a malformed value; the caller maps that to a fixed 400.
 */
export function parseHostHeader(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 253 + 6) return null;
  // Everything outside printable ASCII, plus the delimiters that let a Host be
  // confused with an authority-with-credentials or a URL path, is rejected.
  if (/[^\x21-\x7e]/.test(value) || /[@/\\?#\[\]]/.test(value)) return null;

  let host = value;
  let port = null;
  const colon = value.indexOf(':');
  if (colon >= 0) {
    if (value.indexOf(':', colon + 1) >= 0) return null; // Only one port separator.
    host = value.slice(0, colon);
    const rawPort = value.slice(colon + 1);
    if (!PORT.test(rawPort)) return null;
    const parsed = Number(rawPort);
    // Reject 0, out-of-range values and noncanonical spellings such as "08080".
    if (parsed < 1 || parsed > 65535 || String(parsed) !== rawPort) return null;
    port = parsed;
  }
  if (host.length === 0 || host.length > 253) return null;
  if (host.endsWith('.')) return null; // Do not let "a.example.com." alias the site.
  // ASCII-lowercase is the normal DNS normalization; anything that is not a plain
  // name after it (including IPv4/IPv6 literals) cannot bind to a site.
  const lowered = host.toLowerCase();
  const labels = lowered.split('.');
  if (!labels.every(label => DOMAIN_LABEL.test(label))) return null;
  // An IPv4 literal parses as a syntactically valid authority. It is not treated
  // as malformed; it simply matches no binding and is reported as an unknown
  // host, so a probe cannot distinguish "bad syntax" from "no such site".
  return { host: lowered, port };
}

/**
 * Build a frozen content-origin binding.
 *
 * baseDomain: "<site>.<baseDomain>" selects that site. hosts: an explicit
 * host -> slug map, checked first, for deployments that do not use a wildcard.
 * At least one of the two must be supplied. Both are operator configuration and
 * are never derived from a request.
 */
export function createHostBinding({ baseDomain = null, hosts = null } = {}) {
  const explicit = new Map();
  if (hosts !== null) {
    if (typeof hosts !== 'object' || Array.isArray(hosts)) throw new AuthError('OWA_AUTH_CONFIG');
    for (const [rawHost, slug] of Object.entries(hosts)) {
      const parsed = parseHostHeader(rawHost);
      // A configured entry must be a bare name: the listener port is not part of
      // the identity, and a duplicate/ambiguous mapping is a configuration error.
      if (!parsed || parsed.port !== null || !isSiteScope(slug)) throw new AuthError('OWA_AUTH_CONFIG');
      if (explicit.has(parsed.host)) throw new AuthError('OWA_AUTH_CONFIG');
      explicit.set(parsed.host, slug);
    }
  }
  const base = baseDomain === null ? null : normalizeBaseDomain(baseDomain);
  if (base === null && explicit.size === 0) throw new AuthError('OWA_AUTH_CONFIG');
  // A wildcard child of the base domain must not also be pinned to another site.
  for (const host of explicit.keys()) {
    if (base !== null && host.endsWith(`.${base}`)) throw new AuthError('OWA_AUTH_CONFIG');
  }

  // Reverse map for canonical URLs. A slug pinned to several hosts has no single
  // canonical address, so it is recorded as ambiguous and yields no URL.
  const canonicalHost = new Map();
  for (const [host, slug] of explicit) {
    canonicalHost.set(slug, canonicalHost.has(slug) ? null : host);
  }

  return Object.freeze({
    baseDomain: base,
    /** The one canonical public host for a slug, or null when there isn't exactly one. */
    hostFor(slug) {
      if (!isSiteScope(slug)) return null;
      if (base !== null) return `${slug}.${base}`;
      return canonicalHost.get(slug) ?? null;
    },
    /**
     * Resolve a raw Host header to exactly one site slug.
     * Throws ContentHostError(400) for a malformed Host and (404) for a host that
     * is syntactically fine but bound to no site. Never returns an unvalidated slug.
     */
    resolve(rawHost) {
      const parsed = parseHostHeader(rawHost);
      if (!parsed) throw new ContentHostError('OWA_CONTENT_HOST_MALFORMED');
      const pinned = explicit.get(parsed.host);
      if (pinned !== undefined) return pinned;
      if (base !== null && parsed.host.endsWith(`.${base}`)) {
        const prefix = parsed.host.slice(0, -(base.length + 1));
        // Exactly one label: "a.b.sites.example.com" must not reach site "a.b",
        // and the slug grammar is the same one the control plane authorizes.
        if (LABEL.test(prefix) && isSiteScope(prefix)) return prefix;
      }
      throw new ContentHostError('OWA_CONTENT_HOST_UNKNOWN');
    }
  });
}

/**
 * Canonical public content URL for a site, from server configuration only.
 * Returns null when no content origin is configured, so a caller can omit the
 * field rather than fabricate an address that does not resolve.
 */
export function canonicalContentUrl(binding, slug, { scheme = 'https', port = null } = {}) {
  if (!binding || !isSiteScope(slug)) return null;
  if (scheme !== 'https' && scheme !== 'http') return null;
  const host = binding.hostFor(slug);
  if (host === null) return null;
  const defaultPort = scheme === 'https' ? 443 : 80;
  const suffix = port === null || port === defaultPort ? '' : `:${port}`;
  return `${scheme}://${host}${suffix}/`;
}
