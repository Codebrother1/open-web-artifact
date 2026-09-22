import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { canonicalJson, sha256 } from '../../spec/src/index.js';
import { packDirectory } from '../../core/src/index.js';

// Pack-root and ancestor symbolic links (issue #42) — a CHARACTERIZATION of
// current behaviour, not a normative rule.
//
// spec-v0.2.md "Entry types" (issue #40) governs entries discovered BENEATH the
// directory being packed: a symbolic link found there fails OWA_SYMLINK. It says
// nothing about the pack root itself or about links in ancestor components of
// the supplied path, and the reference resolves the root with `resolve()` and
// never inspects it with `lstat`. This file records what the reference does
// today, so that the compatibility boundary is executable evidence rather than
// an assumption:
//
//   - a directory symlink supplied AS the root (relative or absolute target),
//     or a link in an ANCESTOR component with an ordinary directory as the final
//     component, is followed and packs to the same identity as the direct path,
//     with no host path spelling in the artifact paths;
//   - through every such root spelling, a link found INSIDE the tree still
//     fails OWA_SYMLINK — following the supplied path is distinct from following
//     discovered entries;
//   - a dangling root link, or a root link to a regular file, fails with the
//     host filesystem error (no artifact, no portable OWA category). The exact
//     code is asserted only where POSIX semantics fix it (Linux/macOS) and is
//     otherwise recorded in the test output.
//
// The policy for root and ancestor links remains UNRESOLVED; these tests prove
// neither confinement (nothing stops a root alias from pointing anywhere the
// caller may read) nor race resistance (no claim about concurrent mutation).
// Symlink creation may be unavailable on a host (unsupported filesystem, or the
// Windows symlink privilege, EPERM): that is the only permitted skip, per the
// existing property-suite convention; every other error is a failure. Every
// pack that involves a symbolic link runs in a CHILD PROCESS under an external
// deadline with kill-and-reap, mirroring pack-nonregular.test.js.

const POSIX = process.platform !== 'win32';
const b = text => Buffer.from(text, 'utf8');
const unsupportedSymlink = error => ['ENOSYS', 'ENOTSUP', 'EOPNOTSUPP'].includes(error.code) || (process.platform === 'win32' && error.code === 'EPERM');

// The regular-file fixture is the portable corpus anchor pack-cross-language-anchor,
// checked against UNCHANGED static expectations, never against this implementation.
const corpus = JSON.parse(await readFile(new URL('../../../docs/conformance/v0.2/pack.json', import.meta.url), 'utf8'));
const anchor = corpus.vectors.find(vector => vector.id === 'pack-cross-language-anchor');
assert.ok(anchor && !anchor.expected.errorCategory, 'the static anchor must exist');
const ANCHOR_PATHS = anchor.expected.manifest.files.map(file => file.path);

/** Short isolated temporary directory; removal is registered at creation. */
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
/**
 * Create a symbolic link, or skip the test when the host cannot create symlinks
 * at all (the only permitted skip). Returns false after skipping.
 */
async function linkOrSkip(t, target, link, kind) {
  try { await symlink(target, link, kind); return true; }
  catch (error) {
    if (!unsupportedSymlink(error)) throw error;
    t.skip(`symlinks unsupported on this host: ${error.code}`);
    return false;
  }
}

/**
 * The fixture and its root spellings. The anchor lives at base/parent/site; the
 * spellings below all denote that directory:
 *   direct    base/parent/site                       (no link anywhere in the spelling)
 *   relative  base/rel  -> parent/site               (relative-target link AS the root)
 *   absolute  base/abs  -> <absolute>/parent/site    (absolute-target link AS the root)
 *   ancestor  base/anc/site, base/anc -> parent      (link in an ANCESTOR component; `site` is an ordinary directory)
 * `mkdir` creates only ordinary directories, so no spelling contains a link the
 * test did not create; whether the temporary directory itself lies beneath a
 * host-level link (macOS: /var -> /private/var) is reported, not assumed.
 */
async function fixture(t) {
  const base = await shortTemp(t);
  const site = join(base, 'parent', 'site');
  await materializeAnchor(site);
  if (!await linkOrSkip(t, join('parent', 'site'), join(base, 'rel'), 'dir')) return null;
  await symlink(site, join(base, 'abs'), 'dir');
  await symlink('parent', join(base, 'anc'), 'dir');
  const real = await realpath(site);
  t.diagnostic(`direct root ${real === site ? 'has no' : 'already has a host-level'} symlinked ancestor on this host (${process.platform})`);
  return {
    base, site,
    spellings: [
      ['direct path', site],
      ['relative-target root link', join(base, 'rel')],
      ['absolute-target root link', join(base, 'abs')],
      ['ancestor link + ordinary final directory', join(base, 'anc', 'site')]
    ],
    // Every name the host spelling could leak into an artifact path.
    hostNames: [basename(base), 'parent', 'site', 'rel', 'abs', 'anc']
  };
}

/** Everything that identifies a packed artifact, in comparable JSON-safe form. */
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
  assert.deepEqual(snap.paths, ANCHOR_PATHS, 'file order equals the static anchor');
  assert.deepEqual(snap.blobDigests, anchor.expected.blobDigests, 'blob digest set equals the static anchor');
  for (const [digest, hex] of Object.entries(snap.blobBytes)) assert.equal(sha256(Buffer.from(hex, 'hex')), digest, `blob ${digest} hashes to its digest`);
  for (const file of anchor.input.files) {
    const bytes = Buffer.from(file.contentBase64, 'base64');
    assert.equal(snap.blobBytes[sha256(bytes)], bytes.toString('hex'), `the bytes of ${file.path} are packed under their digest`);
  }
}
/** No component of the host spelling — temp dir, link names, real directory names — appears in any artifact path. */
function assertNoHostSpelling(snap, hostNames) {
  for (const path of snap.paths) {
    assert.ok(path.startsWith('/'), `${path} is a complete artifact path`);
    for (const segment of path.split('/').slice(1)) assert.ok(!hostNames.includes(segment), `host name ${segment} leaked into artifact path ${path}`);
    assert.ok(!path.includes(tmpdir()), `temporary directory leaked into ${path}`);
  }
}

// ---------------------------------------------------------------------------
// Child-process harness (same protocol as pack-nonregular.test.js): the child
// runs the real packer and prints ONE JSON document — the complete packed
// identity, or the error it failed with; the parent asserts on it. On deadline
// the child is SIGKILLed, awaited to `close` (exit AND stdio closed) and checked
// gone (signal 0 → ESRCH), so it has been reaped.
// ---------------------------------------------------------------------------
const PACK_DEADLINE_MS = 30_000;
const coreModuleUrl = new URL('../../core/src/index.js', import.meta.url).href;
const specModuleUrl = new URL('../../spec/src/index.js', import.meta.url).href;
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
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ pid: child.pid, code, signal, stdout, stderr, timedOut, gone: processGone(child.pid) }); });
  });
}
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
  // Everything needed to characterize a failure: the portable category if any
  // (\`code\` OWA_*), or the host error's code/syscall/errno.
  result = { ok: false, name: error?.name ?? null, code: error?.code ?? null, syscall: error?.syscall ?? null, errno: error?.errno ?? null, message: String(error?.message ?? error) };
}
process.stdout.write(JSON.stringify(result));`;

async function packInChild(dir, entrypoint, deadlineMs = PACK_DEADLINE_MS) {
  const result = await runChild(PACK_SCRIPT, [JSON.stringify({ dir, entrypoint })], deadlineMs);
  assert.equal(result.timedOut, false, `packing ${dir} produced no result within ${deadlineMs} ms; the child was killed (${result.signal}) and reaped (${result.gone}). stderr: ${result.stderr}`);
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
/**
 * A failure that is a HOST filesystem error, not a portable OWA category: no
 * artifact was produced and `code` is a host code with a syscall. `posixCode` is
 * asserted only on POSIX hosts, where the semantics of a dangling directory
 * link (ENOENT) and of a file where a directory is required (ENOTDIR) are fixed;
 * elsewhere the observed code is recorded.
 */
function failedWithHostError(t, result, label, posixCode) {
  assert.equal(result.ok, false, `${label}: packing unexpectedly produced an artifact ${result.artifactDigest}`);
  assert.equal(typeof result.code, 'string', `${label}: the host error carries a code`);
  assert.ok(!result.code.startsWith('OWA_'), `${label}: the failure is a host filesystem error, not a portable OWA category (got ${result.code})`);
  assert.equal(typeof result.syscall, 'string', `${label}: the host error names the failing syscall`);
  t.diagnostic(`${label}: ${result.name} code=${result.code} syscall=${result.syscall} errno=${result.errno} (${process.platform})`);
  if (POSIX) assert.equal(result.code, posixCode, `${label}: POSIX code`);
  return result;
}

test('root aliases: a relative-target link, an absolute-target link and an ancestor link pack to the same identity as the direct path, equal to the static anchor, with no host spelling in artifact paths', async t => {
  const fx = await fixture(t);
  if (!fx) return;
  // The direct path contains no link the test created and its tree has none, so
  // it is packed in-process as the reference — and once more in a child, which
  // proves the child's structured result is the complete identity.
  const direct = snapshot(await packDirectory(fx.site, anchor.input.entrypoint));
  assertMatchesAnchor(direct);
  assertNoHostSpelling(direct, fx.hostNames);
  assert.deepEqual(packedInChild(await packInChild(fx.site, anchor.input.entrypoint)), direct, 'child and in-process packs of the direct path agree');
  for (const [label, root] of fx.spellings.slice(1)) {
    await t.test(`${label} (${root.slice(fx.base.length)}) packs identically`, async () => {
      const viaLink = packedInChild(await packInChild(root, anchor.input.entrypoint));
      assert.deepEqual(viaLink, direct, 'manifest, canonical bytes, digest, order, blob digests and blob bytes equal the direct baseline');
      assertMatchesAnchor(viaLink);
      assertNoHostSpelling(viaLink, fx.hostNames);
    });
  }
});

test('through every root spelling a symbolic link found INSIDE the tree still fails OWA_SYMLINK: following the supplied root is distinct from following discovered entries', async t => {
  const fx = await fixture(t);
  if (!fx) return;
  const outside = await shortTemp(t);
  await writeFile(join(outside, 'secret.txt'), b('secret\n'));
  const targets = [
    ['regular-file target', join(fx.site, 'index.html'), 'file'],
    ['dangling target', join(fx.site, 'does-not-exist'), 'file'],
    ['directory target', join(fx.site, 'assets'), 'dir'],
    ['external regular-file target', join(outside, 'secret.txt'), 'file']
  ];
  for (const [spelling, root] of fx.spellings) {
    for (const [targetLabel, target, kind] of targets) {
      await t.test(`${spelling}: link to ${targetLabel} inside the tree is rejected`, async st => {
        // The link is created in the real directory; every spelling sees it.
        const link = join(fx.site, 'link-under-test');
        await symlink(target, link, kind);
        st.after(() => rm(link, { force: true }));
        failedInChild(await packInChild(root, anchor.input.entrypoint), 'OWA_SYMLINK');
      });
    }
    // Every link removed: this spelling packs to the anchor again.
    assertMatchesAnchor(packedInChild(await packInChild(root, anchor.input.entrypoint)));
  }
});

test('a dangling root link fails with the host error and produces no artifact (relative and absolute targets)', async t => {
  const base = await shortTemp(t);
  await materializeAnchor(join(base, 'parent', 'site'));
  if (!await linkOrSkip(t, join('parent', 'nowhere'), join(base, 'dangling-rel'), 'dir')) return;
  await symlink(join(base, 'parent', 'nowhere'), join(base, 'dangling-abs'), 'dir');
  const rel = failedWithHostError(t, await packInChild(join(base, 'dangling-rel'), anchor.input.entrypoint), 'dangling root link (relative target)', 'ENOENT');
  const abs = failedWithHostError(t, await packInChild(join(base, 'dangling-abs'), anchor.input.entrypoint), 'dangling root link (absolute target)', 'ENOENT');
  assert.equal(rel.code, abs.code, 'relative and absolute dangling root links fail the same way');
  // The neighbouring real directory is untouched by the failed attempts.
  assertMatchesAnchor(snapshot(await packDirectory(join(base, 'parent', 'site'), anchor.input.entrypoint)));
});

test('a root link to a regular file fails with the host error and produces no artifact', async t => {
  const base = await shortTemp(t);
  const site = join(base, 'parent', 'site');
  await materializeAnchor(site);
  if (!await linkOrSkip(t, join('parent', 'site', 'index.html'), join(base, 'file-rel'), 'file')) return;
  await symlink(join(site, 'index.html'), join(base, 'file-abs'), 'file');
  const rel = failedWithHostError(t, await packInChild(join(base, 'file-rel'), anchor.input.entrypoint), 'root link to a regular file (relative target)', 'ENOTDIR');
  const abs = failedWithHostError(t, await packInChild(join(base, 'file-abs'), anchor.input.entrypoint), 'root link to a regular file (absolute target)', 'ENOTDIR');
  assert.equal(rel.code, abs.code, 'relative and absolute file-target root links fail the same way');
  // For contrast: the regular file itself, supplied directly as the root, fails the same way — the link adds nothing.
  const direct = failedWithHostError(t, await packInChild(join(site, 'index.html'), anchor.input.entrypoint), 'a regular file supplied directly as the root', 'ENOTDIR');
  assert.equal(direct.code, rel.code);
  assertMatchesAnchor(snapshot(await packDirectory(site, anchor.input.entrypoint)));
});
