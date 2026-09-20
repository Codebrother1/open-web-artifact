// Response policy only: see docs/sandboxed-web-v1-threat-model.md. This does not
// sanitize bytes, change artifact identity, add auth, or enforce origin topology.
export const PROFILE_NAME = 'sandboxed-web-v1';
export const PROFILE_CSP = "sandbox; default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

const INLINE_MEDIA_TYPES = new Set([
  'text/html',
  'text/plain',
  'text/javascript',
  'application/javascript',
  'text/css',
  'application/json',
  'application/wasm',
  'image/svg+xml',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/avif',
  'image/x-icon',
  'image/vnd.microsoft.icon'
]);
const TOKEN_CHARACTER = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]$/;

/** Return an independent plain object for every response, including errors. */
export function securityHeaders() {
  return {
    'content-security-policy': PROFILE_CSP,
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-robots-tag': 'noindex, nofollow, noarchive',
    'cache-control': 'no-store',
    'x-frame-options': 'DENY',
    'x-dns-prefetch-control': 'off',
    'x-owa-security-profile': PROFILE_NAME
  };
}

/**
 * Parse the entire metadata string, never a prefix or a trimmed/repaired value.
 * Grammar: token "/" token *(SP* ";" SP* token "=" value).
 * No spaces surround parameter "="; spaces/equals inside quotes remain literal.
 * token = 1*tchar, tchar = ASCII alphanumeric or !#$%&'*+-.^_`|~.
 * value = token or a double-quoted string (empty is allowed). Within quotes,
 * printable ASCII other than DQUOTE/backslash is literal; backslash must escape
 * exactly one printable ASCII character, including SP, DQUOTE or backslash.
 * Only U+0020 SP is whitespace; leading/trailing SP, all controls (including
 * TAB/CR/LF/DEL), and all non-ASCII are rejected, even inside quoted pairs.
 * Parameter names must be unique case-insensitively. The returned essence is
 * lowercased for matching; accepted metadata is returned unchanged by the caller.
 * This host response policy deliberately does not tighten manifest validation.
 */
function mediaTypeEssence(mediaType) {
  if (typeof mediaType !== 'string' || mediaType.length === 0
      || /[^\x20-\x7e]/.test(mediaType)
      || mediaType.startsWith(' ') || mediaType.endsWith(' ')) return null;

  let offset = 0;
  function token() {
    const start = offset;
    while (offset < mediaType.length && TOKEN_CHARACTER.test(mediaType[offset])) offset++;
    return mediaType.slice(start, offset);
  }
  function spaces() {
    while (mediaType[offset] === ' ') offset++;
  }

  const type = token();
  if (!type || mediaType[offset] !== '/') return null;
  offset++;
  const subtype = token();
  if (!subtype) return null;

  const parameters = new Set();
  while (offset < mediaType.length) {
    spaces();
    if (mediaType[offset] !== ';') return null;
    offset++;
    spaces();
    const name = token().toLowerCase();
    if (!name || parameters.has(name)) return null;
    parameters.add(name);
    if (mediaType[offset] !== '=') return null;
    offset++;

    if (mediaType[offset] === '"') {
      offset++;
      while (offset < mediaType.length && mediaType[offset] !== '"') {
        if (mediaType[offset] === '\\') {
          offset++;
          if (offset === mediaType.length) return null;
        }
        offset++;
      }
      if (mediaType[offset] !== '"') return null;
      offset++;
    } else if (!token()) {
      return null;
    }
  }
  return `${type}/${subtype}`.toLowerCase();
}

/**
 * Dispatch exclusively on complete manifest MIME metadata, never file extension
 * or byte sniffing. Unknown/invalid types, including octet-stream, are downloads
 * without a filename. No manifest, filename, or artifact bytes are accepted.
 */
export function artifactHeaders(mediaType) {
  const inline = INLINE_MEDIA_TYPES.has(mediaTypeEssence(mediaType));
  return {
    ...securityHeaders(),
    'content-type': inline ? mediaType : 'application/octet-stream',
    'content-disposition': inline ? 'inline' : 'attachment'
  };
}
