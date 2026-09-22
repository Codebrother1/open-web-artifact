import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { connect, createServer } from 'node:net';
import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';
import { canonicalJson, sha256 } from '../../spec/src/index.js';
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
//
// Two harness rules hold throughout this file:
//
// 1. PROCESS ISOLATION. A FIFO with no writer blocks any open(2) for reading
//    indefinitely, and nothing in-process (Promise.race, a timer, an
//    AbortSignal) can cancel a read already blocked in the thread pool. So
//    EVERY pack operation that could meet a FIFO — directly, or through a
//    symbolic link should the link rule ever regress to following links —
//    runs in a CHILD PROCESS under an external deadline (`packInChild`). The
//    child returns one structured JSON result (the complete packed identity,
//    or the error category); the parent asserts on it. On deadline the parent
//    SIGKILLs the child, waits for `close` (exit AND stdio closed, so the child
//    is reaped), checks the pid is gone and fails. Only trees made of nothing
//    but regular files and directories are ever packed in-process, and each
//    such call is paired with a child pack of the same tree, which proves the
//    child's structured result is complete.
//
// 2. CLEANUP AT CREATION TIME. A listener's cleanup is registered with
//    `t.after()` the moment the bind succeeds — before anything else can fail —
//    so it runs whether the test passes, fails an assertion, or fails because a
//    child had to be killed. A setup that fails part-way additionally closes
//    every listener it already bound before rethrowing.

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

/**
 * Bind a Unix-domain socket at `path` and count connection attempts. Cleanup is
 * registered with `t.after()` immediately after the bind succeeds, so the
 * listener is closed (and its socket file unlinked) however the test ends —
 * pass, assertion failure or a child killed at its deadline. `close()` is
 * idempotent, so an early close on a setup failure and the registered cleanup
 * do not conflict.
 */
async function bindSocket(t, path) {
  const server = createServer();
  let connections = 0;
  let closed = false;
  server.on('connection', socket => { connections++; socket.destroy(); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
  const handle = {
    path,
    get connections() { return connections; },
    get listening() { return server.listening; },
    close() {
      if (closed) return Promise.resolve();
      closed = true;
      return new Promise(done => server.close(() => done()));
    }
  };
  t.after(() => handle.close());
  return handle;
}
/** The listener at `path` is gone: its socket file is unlinked and nothing accepts there. */
async function assertListenerClosed(handle) {
  assert.equal(handle.listening, false, `${handle.path} is no longer listening`);
  await assert.rejects(access(handle.path), { code: 'ENOENT' }, `${handle.path} was unlinked`);
  const error = await new Promise(resolve => { const socket = connect(handle.path); socket.once('error', resolve); socket.once('connect', () => { socket.destroy(); resolve(null); }); });
  assert.ok(error && ['ENOENT', 'ECONNREFUSED'].includes(error.code), `nothing accepts at ${handle.path}: ${error?.code ?? 'connected'}`);
}

// Special entries placed at the root and inside nested directories; two of them
// carry names with known extensions to show that neither the name nor the
// media-type table matters once an entry is not a regular file.
const SPECIAL = {
  fifos: ['pipe.fifo', 'assets/queue.txt', 'Ω/notes.html'],
  sockets: ['s.sock', 'assets/n.sock']
};
/**
 * Create the FIFOs and bind the sockets of `spec` beneath `root`. Every
 * successful bind registers its own cleanup at once (see `bindSocket`); should a
 * later step fail, every listener bound so far is closed before the failure is
 * rethrown, so a partial setup never leaks a listener. `bound` receives each
 * handle as it is created, so a caller can observe them even when setup fails.
 */
async function addSpecialEntries(t, root, spec = SPECIAL, bound = []) {
  try {
    for (const rel of spec.fifos) { await mkdir(dirname(join(root, rel)), { recursive: true }); await mkfifo(join(root, rel)); }
    for (const rel of spec.sockets) { await mkdir(dirname(join(root, rel)), { recursive: true }); bound.push(await bindSocket(t, join(root, rel))); }
    return bound;
  } catch (error) {
    for (const socket of bound) await socket.close();
    throw error;
  }
}
const SPECIAL_PATHS = [...SPECIAL.fifos, ...SPECIAL.sockets].map(rel => `/${rel}`);

/** Everything that identifies a packed artifact, in comparable (JSON-safe) form. */
const SNAPSHOT_KEYS = ['manifest', 'canonicalJson', 'artifactDigest', 'paths', 'blobDigests', 'blobBytes'];
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
function assertMatchesAnchor(snap) {
  assert.deepEqual(snap.manifest, anchor.expected.manifest, 'manifest equals the static anchor');
  assert.equal(snap.canonicalJson, anchor.expected.canonicalJson, 'canonical bytes equal the static anchor');
  assert.equal(canonicalJson(snap.manifest), anchor.expected.canonicalJson, 'the returned manifest re-canonicalizes to the static anchor');
  assert.equal(snap.artifactDigest, anchor.expected.artifactDigest, 'artifact digest equals the static anchor');
  assert.deepEqual(snap.paths, anchor.expected.manifest.files.map(file => file.path), 'file order equals the static anchor');
  assert.deepEqual(snap.blobDigests, anchor.expected.blobDigests, 'blob digest set equals the static anchor');
  // Blob bytes: every returned blob hashes to its digest, and the bytes of every
  // anchor input file are present under that file's digest.
  for (const [digest, hex] of Object.entries(snap.blobBytes)) assert.equal(sha256(Buffer.from(hex, 'hex')), digest, `blob ${digest} hashes to its digest`);
  for (const file of anchor.input.files) {
    const bytes = Buffer.from(file.contentBase64, 'base64');
    assert.equal(snap.blobBytes[sha256(bytes)], bytes.toString('hex'), `the bytes of ${file.path} are packed under their digest`);
  }
}

// ---------------------------------------------------------------------------
// Process isolation: every potentially blocking pack call runs in a child under
// an external deadline with kill-and-reap; the child returns a structured result.
// ---------------------------------------------------------------------------
const PACK_DEADLINE_MS = 30_000;
const coreModuleUrl = new URL('../../core/src/index.js', import.meta.url).href;
const specModuleUrl = new URL('../../spec/src/index.js', import.meta.url).href;

/** True once `pid` can no longer be signalled: the child has exited AND been reaped (a zombie still accepts signal 0). */
function processGone(pid) {
  try { process.kill(pid, 0); return false; } catch (error) { return error.code === 'ESRCH'; }
}
function runChild(script, args, deadlineMs) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '', timedOut = false;
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, deadlineMs);
    child.once('error', error => { clearTimeout(timer); resolve({ pid: child.pid, code: null, signal: null, stdout, stderr: `${stderr}\n${error.stack}`, timedOut, gone: true }); });
    // 'close' fires after the process has exited AND its stdio streams are closed: the child is reaped.
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ pid: child.pid, code, signal, stdout, stderr, timedOut, gone: processGone(child.pid) }); });
  });
}
// The child packs `dir` with the real packer and prints ONE JSON document: the
// complete packed identity, or the error category it failed with.
const PACK_SCRIPT = `import { packDirectory } from ${JSON.stringify(coreModuleUrl)};
import { canonicalJson } from ${JSON.stringify(specModuleUrl)};
const { dir, entrypoint } = JSON.parse(process.argv[1]);
let result;
try {
  const packed = entrypoint === undefined ? await packDirectory(dir) : await packDirectory(dir, entrypoint);
  result = {
    ok: true,
    manifest: packed.manifest,
    canonicalJson: canonicalJson(packed.manifest),
    artifactDigest: packed.artifactDigest,
    paths: packed.manifest.files.map(file => file.path),
    blobDigests: [...packed.blobs.keys()].sort(),
    blobBytes: Object.fromEntries([...packed.blobs].map(([digest, bytes]) => [digest, Buffer.from(bytes).toString('hex')]))
  };
} catch (error) {
  result = { ok: false, code: error?.code ?? null, message: String(error?.message ?? error) };
}
process.stdout.write(JSON.stringify(result));`;

/**
 * Pack `dir` in a child process under `deadlineMs`. Fails the test if the child
 * blocks (it is killed and reaped first), crashes, or returns no structured
 * result; otherwise returns the child's parsed result for `packedInChild` /
 * `failedInChild`. `entrypoint === undefined` uses the packer's default.
 */
async function packInChild(dir, entrypoint, deadlineMs = PACK_DEADLINE_MS) {
  const result = await runChild(PACK_SCRIPT, [JSON.stringify({ dir, entrypoint })], deadlineMs);
  assert.equal(result.timedOut, false, `packing ${dir} produced no result within ${deadlineMs} ms — a special entry was opened; the blocked child was killed (${result.signal}) and reaped (${result.gone}). stderr: ${result.stderr}`);
  assert.equal(result.signal, null, `pack child was signalled: ${result.signal}`);
  assert.equal(result.code, 0, `pack child exited ${result.code}: ${result.stderr}`);
  assert.equal(result.gone, true, `pack child ${result.pid} was reaped`);
  let parsed;
  try { parsed = JSON.parse(result.stdout); } catch { assert.fail(`pack child returned no structured result: ${JSON.stringify(result.stdout)} ${result.stderr}`); }
  return parsed;
}
function packedInChild(result) {
  assert.equal(result.ok, true, `packing failed in the child: ${result.code} ${result.message}`);
  return Object.fromEntries(SNAPSHOT_KEYS.map(key => [key, result[key]]));
}
function failedInChild(result, code) {
  assert.equal(result.ok, false, `packing unexpectedly succeeded in the child: ${result.artifactDigest}`);
  assert.equal(result.code, code, `expected ${code}, got ${result.code}: ${result.message}`);
}

// Negative controls for the harness. The first blocks inside a plain read of the
// FIFO; the second is a SIMULATED REGRESSED PACKER — a walker that treats every
// non-directory entry as a regular file and reads it — which blocks on a
// writer-less FIFO exactly where a regressed walk() would.
const BLOCKING_SCRIPT = `import { readFileSync } from 'node:fs';
process.stdout.write('opening');
readFileSync(process.argv[1]); // blocks forever: no writer will ever open this FIFO
process.stdout.write('unexpectedly returned');`;
const NAIVE_PACK_SCRIPT = `import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
process.stdout.write('walking');
const read = dir => {
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (lstatSync(full).isDirectory()) read(full);
    else try { readFileSync(full); } catch {} // a socket fails to open; a writer-less FIFO blocks
  }
};
read(process.argv[1]);
process.stdout.write('unexpectedly finished');`;

test('regular-file baseline: the corpus anchor packs to its unchanged static expectations, in-process and in the isolated child alike', async t => {
  const root = await shortTemp(t);
  await materializeAnchor(root);
  // Regular files and directories only: nothing here can block, so this is the one
  // kind of tree packed in-process — and it is paired with a child pack of the same
  // tree to prove the child's structured result is the complete packed identity.
  const inProcess = snapshot(await packDirectory(root, anchor.input.entrypoint));
  assertMatchesAnchor(inProcess);
  const child = packedInChild(await packInChild(root, anchor.input.entrypoint));
  assert.deepEqual(child, inProcess, 'the child returns the same manifest, canonical bytes, digest, order, blob digests and blob bytes as an in-process pack');
  assertMatchesAnchor(child);
});

test('FIFOs and Unix-domain sockets beneath the tree are skipped: identical manifest, canonical bytes, digest, order, blob set and blob bytes; no connection is ever made', posixOnly, async t => {
  const root = await shortTemp(t);
  await materializeAnchor(root);
  const before = snapshot(await packDirectory(root, anchor.input.entrypoint)); // regular files only: cannot meet a FIFO
  assertMatchesAnchor(before);
  const sockets = await addSpecialEntries(t, root);
  // From here on the tree holds writer-less FIFOs: every pack runs in a child under the deadline.
  const after = packedInChild(await packInChild(root, anchor.input.entrypoint));
  assert.deepEqual(after, before, 'special entries change nothing about the regular files');
  assertMatchesAnchor(after);
  for (const path of SPECIAL_PATHS) assert.ok(!after.paths.includes(path), `${path} is not a manifest entry`);
  assert.equal(after.paths.length, anchor.expected.manifest.files.length);
  for (const socket of sockets) assert.equal(socket.connections, 0, 'the packer never connected to a socket');
  // Once more in the presence of the special entries: still deterministic.
  assert.deepEqual(packedInChild(await packInChild(root, anchor.input.entrypoint)), before);
  for (const socket of sockets) assert.equal(socket.connections, 0);
});

test('a FIFO with no writer does not hang packing (separate process, external deadline, kill-and-reap on timeout)', posixOnly, async t => {
  const root = await shortTemp(t);
  await materializeAnchor(root);
  await mkfifo(join(root, 'pipe.fifo'));
  await mkfifo(join(root, 'assets', 'index.html.fifo'));
  const packed = packedInChild(await packInChild(root, anchor.input.entrypoint));
  assertMatchesAnchor(packed);
  assert.ok(!packed.paths.includes('/pipe.fifo') && !packed.paths.includes('/assets/index.html.fifo'));
});

test('harness self-check: the external deadline kills and reaps a child blocked on a writer-less FIFO, and a listener bound meanwhile is still cleaned up', posixOnly, async t => {
  const root = await shortTemp(t);
  await mkfifo(join(root, 'blocked.fifo'));
  let socket;
  // Negative control 1: a child blocked inside open(2) of the FIFO. The listener is
  // bound inside this subtest so that, once the subtest ends, the parent can observe
  // that cleanup registered at bind time ran even though a child had to be killed.
  await t.test('a child blocked inside the read is killed at the deadline and reaped', async st => {
    socket = await bindSocket(st, join(root, 's.sock'));
    const started = Date.now();
    const result = await runChild(BLOCKING_SCRIPT, [join(root, 'blocked.fifo')], 2_000);
    assert.equal(result.timedOut, true, 'the blocked child hit the deadline');
    assert.equal(result.signal, 'SIGKILL', 'the child was killed, not left behind');
    assert.equal(result.code, null);
    assert.equal(result.stdout, 'opening', 'the child blocked inside the read and never continued');
    assert.equal(result.gone, true, `pid ${result.pid} no longer exists: the child was reaped`);
    assert.ok(Date.now() - started < 25_000, 'the deadline fired promptly and the child was reaped');
    assert.equal(socket.listening, true, 'the listener stays bound while the child is blocked and killed');
  });
  await assertListenerClosed(socket);
  // Negative control 2: a SIMULATED REGRESSED PACKER over a real tree — regular files
  // plus a writer-less FIFO — blocks in its read of the FIFO and is killed at the
  // deadline; this is the failure the pack harness above would report.
  await materializeAnchor(root);
  const started = Date.now();
  const result = await runChild(NAIVE_PACK_SCRIPT, [root], 2_000);
  assert.equal(result.timedOut, true, 'the simulated regressed packer hit the deadline');
  assert.equal(result.signal, 'SIGKILL');
  assert.equal(result.code, null);
  assert.equal(result.stdout, 'walking', 'the simulated packer blocked inside its read of the FIFO');
  assert.equal(result.gone, true, `pid ${result.pid} no longer exists: the child was reaped`);
  assert.ok(Date.now() - started < 25_000);
});

test('the error cases are disjoint and ordered: zero regular files → OWA_INVALID_MANIFEST; otherwise an entrypoint present only as a skipped entry → OWA_MISSING_ENTRYPOINT', posixOnly, async t => {
  // Every tree below holds a writer-less FIFO or a socket named index.html, so every
  // pack runs in a child under the deadline.
  //
  // Second case: regular files exist, but index.html is only a FIFO → OWA_MISSING_ENTRYPOINT.
  const missing = await shortTemp(t);
  await mkdir(join(missing, 'assets'));
  await writeFile(join(missing, 'assets', 'app.js'), b('console.log(1)\n'));
  await writeFile(join(missing, 'notes.txt'), b('notes\n'));
  await mkfifo(join(missing, 'index.html'));
  failedInChild(await packInChild(missing, undefined), 'OWA_MISSING_ENTRYPOINT');
  // Second case with the entrypoint present only as a socket.
  const missingSocket = await shortTemp(t);
  await writeFile(join(missingSocket, 'a.txt'), b('a\n'));
  const socket = await bindSocket(t, join(missingSocket, 'index.html'));
  failedInChild(await packInChild(missingSocket, undefined), 'OWA_MISSING_ENTRYPOINT');
  assert.equal(socket.connections, 0);
  // First case: a directory containing ONLY a FIFO named index.html has zero
  // regular-file entries → OWA_INVALID_MANIFEST, unambiguously not OWA_MISSING_ENTRYPOINT.
  const onlyFifo = await shortTemp(t);
  await mkfifo(join(onlyFifo, 'index.html'));
  failedInChild(await packInChild(onlyFifo, undefined), 'OWA_INVALID_MANIFEST');
  // First case with several special entries (one named index.html) and a nested directory.
  const empty = await shortTemp(t);
  await mkdir(join(empty, 'nested'));
  await mkfifo(join(empty, 'index.html'));
  await mkfifo(join(empty, 'nested', 'pipe'));
  const only = await bindSocket(t, join(empty, 'nested', 's.sock'));
  failedInChild(await packInChild(empty, undefined), 'OWA_INVALID_MANIFEST');
  assert.equal(only.connections, 0);
});

test('partial special-entry setup never leaks a listener: when a later bind fails, the listener bound earlier is closed', posixOnly, async t => {
  const root = await shortTemp(t);
  // The second socket path is already occupied by a regular file, so its bind fails
  // deterministically with EADDRINUSE after the first socket has been bound.
  await writeFile(join(root, 'taken.sock'), b('a regular file occupies this path\n'));
  const bound = [];
  await assert.rejects(
    addSpecialEntries(t, root, { fifos: ['pipe.fifo'], sockets: ['first.sock', 'taken.sock'] }, bound),
    error => error.code === 'EADDRINUSE' && String(error.message).includes('taken.sock'),
    'the setup failure is a failure and names the bind that failed'
  );
  assert.equal(bound.length, 1, 'exactly the first socket was bound before the failure');
  assert.equal(bound[0].path, join(root, 'first.sock'));
  await assertListenerClosed(bound[0]);
  // The registered cleanup is still safe to run at the end of this test (idempotent close).
  await bound[0].close();
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
  const probe = join(root, 'probe-link');
  try { await symlink(join(root, 'index.html'), probe, 'file'); }
  catch (error) {
    if (!unsupportedSymlink(error)) throw error;
    t.skip(`symlinks unsupported on this host: ${error.code}`);
    return;
  }
  await rm(probe);
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
  const socket = POSIX ? await bindSocket(t, join(outside, 's.sock')) : null;
  if (socket) cases.push(['Unix-domain socket (special entry)', join(outside, 's.sock'), 'file']);
  // Each case is its own subtest with its own link, removed when the subtest ends,
  // so one failure cannot pollute the next. Every pack runs in a child under the
  // deadline: should the link rule ever regress to following links, the link to
  // the FIFO would block a regressed packer, and the deadline — not the CI job
  // timeout — is what fails the test.
  for (const [index, [label, target, kind]] of cases.entries()) {
    await t.test(`symlink to ${label} is rejected with OWA_SYMLINK`, async st => {
      const link = join(root, `link-under-test-${index}`);
      await symlink(target, link, kind);
      st.after(() => rm(link, { force: true }));
      failedInChild(await packInChild(root, anchor.input.entrypoint), 'OWA_SYMLINK');
    });
  }
  if (socket) assert.equal(socket.connections, 0);
  // With every link removed the tree packs to the unchanged anchor identity again.
  assertMatchesAnchor(packedInChild(await packInChild(root, anchor.input.entrypoint)));
});
