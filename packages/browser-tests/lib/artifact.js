// Adversarial static artifacts for the browser suite. Bytes are used exactly as
// written: nothing here sanitizes, rewrites or "fixes" markup. Media types follow
// the ordinary manifest `mediaType` rules; the server's own dispatch decides
// inline versus attachment.
import { artifactDigest, sha256, validateManifest } from '../../spec/src/index.js';

/** 1x1 transparent GIF — the same bytes the repository's security fixture uses. */
export const GIF_BASE64 = 'R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==';
export const GIF_BYTES = Buffer.from(GIF_BASE64, 'base64');
export const DATA_GIF = `data:image/gif;base64,${GIF_BASE64}`;

/**
 * Build a manifest + blob map from `[{ path, text | bytes, mediaType }]`.
 * The first file is the entrypoint. Validated with the unchanged spec validator;
 * the artifact digest is the ordinary canonical digest.
 */
export function buildArtifact(files, { visibility = 'public', spaFallback = null } = {}) {
  const blobs = new Map();
  const manifest = {
    specVersion: 'owa.dev/v1',
    artifactType: 'application/vnd.openwebartifact.site.v1+json',
    entrypoint: files[0].path,
    files: files.map(file => {
      const bytes = file.bytes ?? Buffer.from(file.text, 'utf8');
      const digest = sha256(bytes);
      blobs.set(digest, bytes);
      return { path: file.path, digest, size: bytes.length, mediaType: file.mediaType };
    }),
    access: { visibility },
    lifecycle: { expiresAt: null },
    ...(spaFallback ? { routing: { spaFallback } } : {})
  };
  validateManifest(manifest);
  return { manifest, blobs, artifactDigest: artifactDigest(manifest) };
}

/** A complete HTML document. `marker` is static text the tests look for. */
export function htmlDocument({ title = 'OWA browser probe', head = '', body = '', bodyAttributes = '', marker = 'artifact-marker' } = {}) {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title>${head}</head>
<body${bodyAttributes ? ` ${bodyAttributes}` : ''}><h1 id="marker">${marker}</h1>
${body}
</body></html>`;
}

/**
 * Artifact-authored code that would leave visible side effects if it ran. Every
 * probe below mutates state that automation can INSPECT afterwards; the
 * assertions never treat automation's own ability to evaluate as evidence.
 */
export const SCRIPT_SIDE_EFFECTS = [
  'document.documentElement.setAttribute("data-owa-script-ran","yes");',
  'document.title="SCRIPT RAN";',
  'var d=document.createElement("div");d.id="injected";d.textContent="injected by artifact script";document.body.appendChild(d);'
].join('');

/**
 * Inline handler body: same observable side effects under a different attribute.
 * Single quotes only, so it is a well-formed double-quoted attribute value in both
 * HTML and XML (SVG); tests assert the parsed attribute equals this string, so a
 * syntax error can never be mistaken for enforcement.
 */
export const HANDLER_SIDE_EFFECT = "document.documentElement.setAttribute('data-owa-handler-ran','yes');document.title='HANDLER RAN';";
