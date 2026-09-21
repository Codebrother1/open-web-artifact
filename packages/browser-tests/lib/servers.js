// Loopback servers for the browser suite: the REAL content-only listener over a
// temporary filesystem store, plus a local "attacker"/capture origin. Everything
// binds 127.0.0.1 on an ephemeral port; nothing here reaches the public network.
import { createServer, request as httpRequest } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';
import { activateRelease, commitManifest } from '../../core/src/index.js';
import { createContentServer } from '../../server/src/index.js';

const listen = server => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});
const close = server => new Promise(resolve => {
  if (!server.listening) return resolve();
  server.closeAllConnections?.();
  server.close(() => resolve());
});

/**
 * Record ONLY the request metadata the assertions need: method, raw target,
 * Host, Sec-Fetch-Dest/Mode, whether a Referer was present, and cookie NAMES.
 * No header values that could carry a credential are kept, no bodies are read.
 */
function describe(req) {
  const cookieNames = (req.headers.cookie ?? '').split(';').map(s => s.trim().split('=')[0]).filter(Boolean);
  return {
    method: req.method,
    target: req.url,
    path: req.url.split('?')[0],
    host: req.headers.host ?? null,
    dest: req.headers['sec-fetch-dest'] ?? null,
    mode: req.headers['sec-fetch-mode'] ?? null,
    hasReferer: 'referer' in req.headers,
    cookieNames
  };
}

/**
 * The real content-only topology: a temporary filesystem store, sites published
 * through the ordinary core commit path, and `createContentServer` bound to the
 * `<site>.localhost` base domain — the documented separated development topology.
 * `requests` is an append-only log of metadata for every request the listener saw.
 */
export async function startContentTopology() {
  const root = await mkdtemp(join(tmpdir(), 'owa-browser-topology-'));
  const blobs = new FilesystemBlobStore(root);
  const metadata = new FilesystemMetadataStore(root);
  // Count metadata reads so "the browser observed current state" can be tied to
  // the server re-reading the site record, not merely to the DOM changing.
  const metadataReads = { getSite: 0 };
  const originalGetSite = metadata.getSite.bind(metadata);
  metadata.getSite = async slug => { metadataReads.getSite++; return originalGetSite(slug); };

  const server = createContentServer({ blobs, metadata, content: { baseDomain: 'localhost', scheme: 'http' } });
  const requests = [];
  server.on('request', req => { requests.push(describe(req)); });
  const port = await listen(server);

  return {
    root, blobs, metadata, server, port, requests, metadataReads,
    origin: slug => `http://${slug}.localhost:${port}`,
    url: (slug, path = '/') => `http://${slug}.localhost:${port}${path}`,
    /** Publish through the normal core path (writes blobs, then commitManifest). */
    async publish(slug, artifact, { activate = true } = {}) {
      for (const [digest, bytes] of artifact.blobs) await blobs.put(digest, bytes);
      return commitManifest({ slug, manifest: artifact.manifest, blobs, metadata, activate });
    },
    /** Flip the active release through the normal core path. */
    activate: (slug, releaseId) => activateRelease(metadata, slug, releaseId),
    seen: predicate => requests.filter(predicate),
    async close() {
      await close(server);
      await rm(root, { recursive: true, force: true });
    }
  };
}

/**
 * Local attacker / capture origin on 127.0.0.1. Serves plausible responses for
 * every resource class an artifact might reference and counts what arrives.
 * A request that never reaches it was blocked before the network (class A).
 */
export async function startCaptureServer() {
  const requests = [];
  const parents = new Map(); // path -> html served as an UNPROTECTED parent page
  const server = createServer((req, res) => {
    const entry = describe(req);
    requests.push(entry); // Metadata only; request bodies are never read.
    const path = entry.path;
    const send = (status, type, body, extra = {}) => { res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'access-control-allow-origin': '*', ...extra }); res.end(body); };
    if (parents.has(path)) return send(200, 'text/html; charset=utf-8', parents.get(path));
    if (path.endsWith('.js')) return send(200, 'text/javascript', 'document.documentElement.setAttribute("data-owa-capture-script-ran","yes");');
    if (path.endsWith('.css')) return send(200, 'text/css', '#external-style-target{color:rgb(200,0,0)!important}');
    if (path.endsWith('.gif') || path.endsWith('.png')) return send(200, path.endsWith('.gif') ? 'image/gif' : 'image/png', Buffer.from('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==', 'base64'));
    if (path.endsWith('.woff2')) return send(200, 'font/woff2', Buffer.alloc(16));
    if (path.endsWith('.mp3') || path.endsWith('.mp4')) return send(200, path.endsWith('.mp3') ? 'audio/mpeg' : 'video/mp4', Buffer.alloc(64));
    if (path.endsWith('.svg')) return send(200, 'image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8"/></svg>');
    if (path.endsWith('.html')) return send(200, 'text/html; charset=utf-8', '<!doctype html><p id="capture-frame-marker">served by capture origin</p>');
    return send(200, 'text/plain; charset=utf-8', `capture ${req.method} ${path}`);
  });
  const port = await listen(server);
  return {
    server, port, requests,
    origin: `http://127.0.0.1:${port}`,
    url: path => `http://127.0.0.1:${port}${path}`,
    /** Register an unprotected parent page (e.g. to attempt framing the protected artifact). */
    serveParent(path, html) { parents.set(path, html); return `http://127.0.0.1:${port}${path}`; },
    count: predicate => requests.filter(typeof predicate === 'string' ? r => r.path === predicate : predicate).length,
    close: () => close(server)
  };
}

/** Plain Node GET used by tests to check a server from OUTSIDE any browser. */
export function nodeGet(url, { host } = {}) {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest({ hostname: '127.0.0.1', port: target.port, path: target.pathname + target.search, method: 'GET', agent: false, headers: { host: host ?? target.host, connection: 'close' } }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}
