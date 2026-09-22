import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';
import { canonicalJson } from '../../spec/src/index.js';
import { packDirectory } from '../../core/src/index.js';

// Non-regular directory entries (issue #40; spec-v0.2.md "Directory packing" →
// "Entry types"). Every entry beneath the packed directory is classified without
// following links: symbolic links fail OWA_SYMLINK, directories recurse, regular
// files pack, and every other entry type (FIFO, socket, device, …) is skipped —
// never opened, read or connected to — without changing the manifest, canonical
// bytes, artifact digest, order, media types or blobs of the regular files. Such
// entries cannot be materialized uniformly by the portable JSON corpus, so this
// rule is pinned by implementation-local tests with REAL filesystem entries:
// a FIFO (`mkfifo`) and a bound Unix-domain socket in an isolated temporary
// directory, created without privileges. Device nodes are not exercised (they
// need privileges); they share the "neither directory nor regular file" branch.
// POSIX-specific cases skip on Windows with an explicit reason; on the supported
// Linux/macOS lanes a setup failure is a test FAILURE, never a skip.

const POSIX = process.platform !== 'win32';
const posixOnly = { skip: POSIX ? false : 'FIFOs and Unix-domain socket files are POSIX-specific (Linux/macOS lanes execute these cases)' };
const execFileAsync = promisify(execFile);
const b = text => Buffer.from(text, 'utf8');

// The regular-file baseline is the portable corpus anchor pack-cross-language-anchor
// (seven files, four with identical bytes across two media types, nested dirs), so
// the "before" state is checked against UNCHANGED static expectations, not
// against this implementation's own output.
const corpus = JSON.parse(await readFile(new URL('../../../docs/conformance/v0.2/pack.json', import.meta.url), 'utf8'));
const anchor = corpus.vectors.find(vector => vector.id === 'pack-cross-language-anchor');
assert.ok(anchor && !anchor.expected.errorCategory, 'the static anchor must exist');

/** Short temporary directory: Unix socket paths are limited (~104 bytes on macOS). */
async function shortTemp(t) {
  const root = await mkdtemp(join(tmpdir(), 'o-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
async function materializeAnchor(root) {
  for (const file of anchor.input.files) {
    await mkdir(dirname(join(root, file.path)), { recursive: true });
    await writeFile(join(root, file.path), Buffer.from(file.contentBase64, 'base64'));
  }
}
async function mkfifo(path) {
  // `mkfifo` is a standard POSIX utility; a failure on a supported platform is a failure.
  await execFileAsync('mkfifo', [path]);
}
/** Bind a Unix-domain socket at `path`; it stays listening until `close()` (which unlinks it). */
function bindSocket(path) {
  return new Promise((resolve, reject) => {
    const server = createServer();
    let connections = 0;
    server.on('connection', socket => { connections++; socket.destroy(); });
    server.once('error', reject);
    server.listen(path, () => resolve({
      get connections() { return connections; },
      close: () => new Promise(done => server.close(() => done()))
    }));
  });
}
/** Everything that identifies a packed artifact, in comparable form. */
function snapshot(packed) {
  return {
    manifest: structuredClone(packed.manifest),
    canonicalJson: canonicalJson(packed.manifest),
    artifactDigest: packed.artifactDigest,
    paths: packed.manifest.files.map(file => file.path),
    blobDigests: [...packed.blobs.keys()].sort(),
    blobBytes: Object.fromEntries([...packed.blobs].map(([digest, bytes]) => [digest, Buffer.from(bytes).toString('hex')]))
  };
}
function assertMatchesAnchor(packed) {
  assert.deepEqual(packed.manifest, anchor.expected.manifest, 'manifest equals the static anchor');
  assert.equal(canonicalJson(packed.manifest), anchor.expected.canonicalJson, 'canonical bytes equal the static anchor');
  assert.equal(packed.artifactDigest, anchor.expected.artifactDigest, 'artifact digest equals the static anchor');
  assert.deepEqual([...packed.blobs.keys()].sort(), anchor.expected.blobDigests, 'blob digest set equals the static anchor');
}

// Special entries placed at the root and inside nested directories; two of them
// carry names with known extensions to show that neither the name nor the
// media-type table matters once an entry is not a regular file.
const SPECIAL = {
  fifos: ['pipe.fifo', 'assets/queue.txt', 'Ω/notes.html'],
  sockets: ['s.sock', 'assets/n.sock']
};
async function addSpecialEntries(root) {
  const sockets = [];
  for (const rel of SPECIAL.fifos) { await mkdir(dirname(join(root, rel)), { recursive: true }); await mkfifo(join(root, rel)); }
  for (const rel of SPECIAL.sockets) { await mkdir(dirname(join(root, rel)), { recursive: true }); sockets.push(await bindSocket(join(root, rel))); }
  return sockets;
}
const SPECIAL_PATHS = [...SPECIAL.fifos, ...SPECIAL.sockets].map(rel => `/${rel}`);

test('regular-file baseline: the corpus anchor packs to its unchanged static expectations on this host', async t => {
  const root = await shortTemp(t);
  await materializeAnchor(root);
  assertMatchesAnchor(await packDirectory(root, anchor.input.entrypoint));
});

test('FIFOs and Unix-domain sockets beneath the tree are skipped: identical manifest, canonical bytes, digest, order, blob set and blob bytes; no connection is ever made', posixOnly, async t => {
  const root = await shortTemp(t);
  await materializeAnchor(root);
  const before = snapshot(await packDirectory(root, anchor.input.entrypoint));
  const sockets = await addSpecialEntries(root);
  try {
    const packed = await packDirectory(root, anchor.input.entrypoint);
    const after = snapshot(packed);
    assert.deepEqual(after, before, 'special entries change nothing about the regular files');
    assertMatchesAnchor(packed);
    for (const path of SPECIAL_PATHS) assert.ok(!after.paths.includes(path), `${path} is not a manifest entry`);
    assert.equal(after.paths.length, anchor.expected.manifest.files.length);
    for (const socket of sockets) assert.equal(socket.connections, 0, 'the packer never connected to a socket');
    // Twice more in the presence of the special entries: still deterministic.
    assert.deepEqual(snapshot(await packDirectory(root, anchor.input.entrypoint)), before);
  } finally {
    for (const socket of sockets) await socket.close();
  }
});

// A FIFO with no writer blocks any open(2) for reading indefinitely, so "the
// packer never opens it" is proven in a SEPARATE process under a real external
// deadline: on timeout the child is killed and reaped and the test fails. A
// Promise timeout around a blocked read would not free the blocked thread.
const coreModuleUrl = new URL('../../core/src/index.js', import.meta.url).href;
function runChild(script, args, deadlineMs) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', timedOut = false;
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, deadlineMs);
    // 'close' fires after the process has exited AND its stdio streams are closed: the child is reaped.
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr, timedOut }); });
  });
}
const PACK_SCRIPT = `import { packDirectory } from ${JSON.stringify(coreModuleUrl)};
const packed = await packDirectory(process.argv[1], process.argv[2]);
process.stdout.write(packed.artifactDigest);`;
const BLOCKING_SCRIPT = `import { readFileSync } from 'node:fs';
process.stdout.write('opening');
readFileSync(process.argv[1]); // blocks forever: no writer will ever open this FIFO
process.stdout.write('unexpectedly returned');`;

test('a FIFO with no writer does not hang packing (separate process, external deadline, kill-and-reap on timeout)', posixOnly, async t => {
  const root = await shortTemp(t);
  await materializeAnchor(root);
  await mkfifo(join(root, 'pipe.fifo'));
  await mkfifo(join(root, 'assets', 'index.html.fifo'));
  const result = await runChild(PACK_SCRIPT, [root, anchor.input.entrypoint], 30_000);
  assert.equal(result.timedOut, false, `packing blocked on the FIFO and was killed after the deadline: ${result.stderr}`);
  assert.equal(result.signal, null); assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, anchor.expected.artifactDigest, 'the child packed the regular files to the static anchor identity');
});

test('harness self-check: the external deadline really kills and reaps a process blocked on a writer-less FIFO', posixOnly, async t => {
  const root = await shortTemp(t);
  await mkfifo(join(root, 'blocked.fifo'));
  const started = Date.now();
  const result = await runChild(BLOCKING_SCRIPT, [join(root, 'blocked.fifo')], 2_000);
  assert.equal(result.timedOut, true, 'the blocked child hit the deadline');
  assert.equal(result.signal, 'SIGKILL', 'the child was killed, not left behind');
  assert.equal(result.code, null);
  assert.equal(result.stdout, 'opening', 'the child blocked inside the read and never continued');
  assert.ok(Date.now() - started < 25_000, 'the deadline fired promptly and the child was reaped');
});

test('a skipped special entry never satisfies the entrypoint, and a tree with only special entries has no regular files', posixOnly, async t => {
  // Regular assets present, but index.html exists only as a FIFO → OWA_MISSING_ENTRYPOINT.
  const missing = await shortTemp(t);
  await mkdir(join(missing, 'assets'));
  await writeFile(join(missing, 'assets', 'app.js'), b('console.log(1)\n'));
  await writeFile(join(missing, 'notes.txt'), b('notes\n'));
  await mkfifo(join(missing, 'index.html'));
  await assert.rejects(packDirectory(missing), { code: 'OWA_MISSING_ENTRYPOINT' });
  // The same with the entrypoint present only as a socket.
  const missingSocket = await shortTemp(t);
  await writeFile(join(missingSocket, 'a.txt'), b('a\n'));
  const socket = await bindSocket(join(missingSocket, 'index.html'));
  try { await assert.rejects(packDirectory(missingSocket), { code: 'OWA_MISSING_ENTRYPOINT' }); assert.equal(socket.connections, 0); }
  finally { await socket.close(); }
  // Only special entries (including one named index.html) → no regular files → OWA_INVALID_MANIFEST.
  const empty = await shortTemp(t);
  await mkdir(join(empty, 'nested'));
  await mkfifo(join(empty, 'index.html'));
  await mkfifo(join(empty, 'nested', 'pipe'));
  const only = await bindSocket(join(empty, 'nested', 's.sock'));
  try { await assert.rejects(packDirectory(empty), { code: 'OWA_INVALID_MANIFEST' }); assert.equal(only.connections, 0); }
  finally { await only.close(); }
});

// Symlink creation may be unavailable on a host (unsupported filesystem, or the
// Windows symlink privilege); that is the only permitted skip, per the existing
// property-suite convention. Every other error is a failure.
const unsupportedSymlink = error => ['ENOSYS', 'ENOTSUP', 'EOPNOTSUPP'].includes(error.code) || (process.platform === 'win32' && error.code === 'EPERM');

test('symbolic links to a regular file, a directory, a missing target and (where supported) a FIFO or socket all fail OWA_SYMLINK — they are neither followed nor skipped', async t => {
  const root = await shortTemp(t);
  await materializeAnchor(root);
  const outside = await shortTemp(t);
  await writeFile(join(outside, 'secret.txt'), b('secret\n'));
  const cases = [
    ['regular file', join(root, 'index.html'), 'file'],
    ['directory', join(root, 'assets'), 'dir'],
    ['missing target', join(root, 'does-not-exist'), 'file'],
    ['external file', join(outside, 'secret.txt'), 'file']
  ];
  if (POSIX) {
    await mkfifo(join(outside, 'pipe.fifo'));
    cases.push(['FIFO (special entry)', join(outside, 'pipe.fifo'), 'file']);
  }
  const socket = POSIX ? await bindSocket(join(outside, 's.sock')) : null;
  if (socket) cases.push(['Unix-domain socket (special entry)', join(outside, 's.sock'), 'file']);
  try {
    for (const [label, target, kind] of cases) {
      const link = join(root, 'link-under-test');
      try { await symlink(target, link, kind); }
      catch (error) {
        if (!unsupportedSymlink(error)) throw error;
        t.skip(`symlinks unsupported on this host: ${error.code}`);
        return;
      }
      await assert.rejects(packDirectory(root, anchor.input.entrypoint), { code: 'OWA_SYMLINK' }, `symlink to ${label} is rejected`);
      await rm(link);
    }
    if (socket) assert.equal(socket.connections, 0);
    // With every link removed the tree packs to the unchanged anchor identity again.
    assertMatchesAnchor(await packDirectory(root, anchor.input.entrypoint));
  } finally {
    if (socket) await socket.close();
  }
});
