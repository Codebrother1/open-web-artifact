import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { packDirectory } from '../../core/src/index.js';

// Pack-time media-type assignment (issue #33; spec-v0.2.md "Directory packing" →
// "Media type assignment"). Every expectation here is hand-written from the
// specification text, not derived from production code. The portable corpus
// (docs/conformance/v0.2/pack.json, pack-media-type-*) is the cross-language
// proof checked by both independent implementations; this file pins the rule on
// this host for name shapes and combinations the corpus does not materialize.

const OCTET = 'application/octet-stream';

// The complete published table, hand-copied from the specification.
const TABLE = Object.freeze({
  '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.webp': 'image/webp', '.gif': 'image/gif',
  '.txt': 'text/plain; charset=utf-8',
  '.wasm': 'application/wasm',
  '.ico': 'image/x-icon',
  '.xml': 'application/xml; charset=utf-8',
  '.pdf': 'application/pdf',
  '.woff': 'font/woff', '.woff2': 'font/woff2'
});

// Test-local ASCII-only case changes, so expectations do not lean on the folding
// under test (and never on toLowerCase/toUpperCase of non-ASCII text).
const asciiUpper = s => s.replace(/[a-z]/g, c => String.fromCharCode(c.charCodeAt(0) - 32));

// Materialize `entries` ({ 'relative/name': bytes }) under a fresh directory,
// pack it, and return { artifactPath: mediaType } plus the packed result.
async function packEntries(entries, entrypoint = '/index.html') {
  const root = await mkdtemp(join(tmpdir(), 'owa-pack-media-'));
  try {
    for (const [name, content] of Object.entries(entries)) {
      await mkdir(dirname(join(root, name)), { recursive: true });
      await writeFile(join(root, name), content);
    }
    const packed = await packDirectory(root, entrypoint);
    assert.equal(packed.manifest.files.length, Object.keys(entries).length, 'every fixture name materialized as a distinct file');
    return { packed, types: Object.fromEntries(packed.manifest.files.map(f => [f.path, f.mediaType])) };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('every table entry maps in lowercase, UPPERCASE and MiXeD case, at any depth, after any number of dots; the path keeps its exact case', async () => {
  assert.equal(Object.keys(TABLE).length, 19, 'the specification table has 19 extensions');
  const entries = { 'index.html': '<!doctype html>' };
  const expected = { '/index.html': TABLE['.html'] };
  for (const [ext, type] of Object.entries(TABLE)) {
    // Distinct basenames within each directory: no case-only pairs, so the tree
    // materializes on case-insensitive filesystems (APFS, NTFS) too.
    const shapes = {
      [`lower/file${ext}`]: type,
      [`upper/FILE${asciiUpper(ext)}`]: type,
      [`mixed/File${ext.slice(0, 2)}${asciiUpper(ext.slice(2))}`]: type,
      [`nested/deep/multi.part${ext}`]: type,
      [`dots/.hidden${ext}`]: type, // a dotfile WITH a later dot has an extension
      [`dots/double..${ext.slice(1)}`]: type // consecutive dots are ordinary characters
    };
    for (const [name, mediaType] of Object.entries(shapes)) { entries[name] = `${name}\n`; expected[`/${name}`] = mediaType; }
  }
  const { types } = await packEntries(entries);
  assert.deepEqual(types, expected);
  // Exact paths: nothing was case-folded or normalized; only the lookup key was.
  assert.ok(Object.hasOwn(types, '/upper/FILE.HTML') && Object.hasOwn(types, '/mixed/File.hTML') && Object.hasOwn(types, '/upper/FILE.WOFF2'));
});

test('no extension, dotfiles, unlisted extensions, unlisted FINAL extensions and non-final segments fall back to application/octet-stream — without a host MIME database', async () => {
  const names = [
    'README', 'Makefile', 'dir/LICENSE', // no dot at all
    '.env', '.html', '.gitignore', '.PNG', 'dir/.env', // the leading dot alone is never an extension, even when the name resembles one
    'file.xyz', 'x.unknown', // unlisted extension
    'archive.tar.gz', 'archive.json.gz', 'page.html.bak', 'image.png.orig', // unlisted FINAL extension: no compound-extension rules
    'vendor.json/LICENSE', 'assets.css/readme', // only the final path segment is examined
    'x.zip', 'x.mp4', 'x.csv', 'x.md', 'x.avif', 'x.mp3', 'x.ttf', 'x.otf', 'x.map', 'x.webmanifest', // every host MIME database knows these; the fixed table does not
    'page.ｈｔｍｌ', 'x.htmｌ' // non-ASCII letters are never folded onto ASCII keys (no compatibility/NFKC folding)
  ];
  const entries = { 'index.html': '<!doctype html>' };
  const expected = { '/index.html': TABLE['.html'] };
  for (const name of names) { entries[name] = `${name}\n`; expected[`/${name}`] = OCTET; }
  const { types } = await packEntries(entries);
  assert.deepEqual(types, expected);
});

test('only the suffix from the FINAL dot is the extension, and it is ASCII-folded', async () => {
  const entries = {
    'index.html': '<!doctype html>', 'archive.tar.JSON': '{}', 'jquery.min.js': ';', 'theme.dark.css': 'a{}',
    'chart.svg.PNG': 'not sniffed', '.hidden.html': '<p/>', 'foo..txt': 'x', 'INDEX.HTM': '<p/>', 'App.MJS': 'export {}', 'IMAGE.PNG': 'png?'
  };
  const { types } = await packEntries(entries);
  assert.deepEqual(types, {
    '/.hidden.html': TABLE['.html'],
    '/App.MJS': TABLE['.mjs'],
    '/IMAGE.PNG': TABLE['.png'],
    '/INDEX.HTM': TABLE['.htm'],
    '/archive.tar.JSON': TABLE['.json'],
    '/chart.svg.PNG': TABLE['.png'],
    '/foo..txt': TABLE['.txt'],
    '/index.html': TABLE['.html'],
    '/jquery.min.js': TABLE['.js'],
    '/theme.dark.css': TABLE['.css']
  });
});

test('a trailing-dot name has the extension "." and falls back to application/octet-stream', {
  // Win32 removes a trailing dot from a file name, so the fixture cannot be
  // materialized there; the string-level rule is pinned by the Go anchors and by
  // the specification examples. Everything else in this file runs on Windows.
  skip: process.platform === 'win32' ? 'Win32 strips trailing dots from file names' : false
}, async () => {
  const { types } = await packEntries({ 'index.html': '<!doctype html>', 'file.': 'x', 'dir/name.': 'y', 'x..': 'z', '.a.': 'w' });
  assert.deepEqual(types, { '/.a.': OCTET, '/dir/name.': OCTET, '/file.': OCTET, '/index.html': TABLE['.html'], '/x..': OCTET });
});

test('file bytes are never inspected: the name alone decides', async () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const { types, packed } = await packEntries({
    'index.html': png, // PNG signature under an .html name
    'logo.png': '<svg xmlns="http://www.w3.org/2000/svg"/>\n', // SVG text under a .png name
    'lib.wasm': '{"json":true}\n',
    'notes.txt': Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe]),
    'README': '<!doctype html><title>not sniffed</title>\n',
    'data.zip': 'PK'
  });
  assert.deepEqual(types, {
    '/README': OCTET, '/data.zip': OCTET, '/index.html': TABLE['.html'], '/lib.wasm': TABLE['.wasm'], '/logo.png': TABLE['.png'], '/notes.txt': TABLE['.txt']
  });
  // Determinism on this host: the same tree packs to the same identity.
  const again = await packEntries({ 'index.html': png, 'logo.png': '<svg xmlns="http://www.w3.org/2000/svg"/>\n', 'lib.wasm': '{"json":true}\n', 'notes.txt': Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe]), 'README': '<!doctype html><title>not sniffed</title>\n', 'data.zip': 'PK' });
  assert.equal(again.packed.artifactDigest, packed.artifactDigest);
});
