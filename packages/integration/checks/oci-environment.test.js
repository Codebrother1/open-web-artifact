import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ociEnvironment } from '../oci/environment.js';

// Offline checks for the OCI registry suite's environment contract and its
// required mode. No registry, no ORAS: the suite must SKIP when unconfigured and
// FAIL (never skip) when OWA_TEST_OCI_REQUIRED=1 finds a prerequisite missing.

// Both live OCI test files (issue #23's registry proof and issue #9's duplicate-content proof) share the contract.
const SUITES = ['../oci/registry.test.js', '../oci/duplicate-content.test.js'].map(file => fileURLToPath(new URL(file, import.meta.url)));
const clean = { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR ?? '' };
const runSuite = env => new Promise(resolve => {
  execFile(process.execPath, ['--test', ...SUITES], { env: { ...clean, ...env }, timeout: 60_000 }, (error, stdout, stderr) => resolve({ code: error ? error.code ?? 1 : 0, out: `${stdout}\n${stderr}` }));
});

test('unconfigured → skip naming both variables; required → fail', async () => {
  assert.deepEqual(await ociEnvironment({}), { skip: 'set OWA_TEST_OCI_REGISTRY, OWA_TEST_ORAS_BIN' });
  assert.deepEqual(await ociEnvironment({ OWA_TEST_OCI_REGISTRY: 'http://127.0.0.1:5000' }), { skip: 'set OWA_TEST_ORAS_BIN' });
  const required = await ociEnvironment({ OWA_TEST_OCI_REQUIRED: '1' });
  assert.deepEqual(Object.keys(required), ['fail']);
  assert.match(required.fail, /^OWA_TEST_OCI_REQUIRED=1 but set OWA_TEST_OCI_REGISTRY, OWA_TEST_ORAS_BIN: the OCI registry suite must run, not skip$/);
});

test('registry must be a bare plain-HTTP loopback origin and ORAS an absolute executable', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'owa-oci-env-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const oras = join(dir, 'oras');
  await writeFile(oras, '#!/bin/sh\nexit 0\n');
  await chmod(oras, 0o755);
  const base = { OWA_TEST_ORAS_BIN: oras };
  for (const [registry, reason] of [
    ['https://127.0.0.1:5000', /plain http/],
    ['http://registry.example.com:5000', /loopback/],
    ['http://127.0.0.1:5000/v2/', /bare origin/],
    ['http://user:pw@127.0.0.1:5000', /bare origin/],
    ['not a url', /not a valid URL/]
  ]) {
    const relaxed = await ociEnvironment({ ...base, OWA_TEST_OCI_REGISTRY: registry });
    assert.match(relaxed.skip, reason, `${registry} skips when not required`);
    const strict = await ociEnvironment({ ...base, OWA_TEST_OCI_REGISTRY: registry, OWA_TEST_OCI_REQUIRED: '1' });
    assert.match(strict.fail, reason, `${registry} fails when required`);
  }
  assert.match((await ociEnvironment({ OWA_TEST_OCI_REGISTRY: 'http://127.0.0.1:5000', OWA_TEST_ORAS_BIN: 'oras' })).skip, /absolute path/);
  assert.match((await ociEnvironment({ OWA_TEST_OCI_REGISTRY: 'http://127.0.0.1:5000', OWA_TEST_ORAS_BIN: join(dir, 'missing') })).skip, /not an executable file/);
  assert.match((await ociEnvironment({ OWA_TEST_OCI_REGISTRY: 'http://127.0.0.1:5000', OWA_TEST_ORAS_BIN: join(dir, 'missing'), OWA_TEST_OCI_REQUIRED: '1' })).fail, /not an executable file/);
  const ok = await ociEnvironment({ ...base, OWA_TEST_OCI_REGISTRY: 'http://127.0.0.1:5000' });
  assert.deepEqual(ok, { required: false, registry: 'http://127.0.0.1:5000', registryHost: '127.0.0.1:5000', oras });
  assert.equal((await ociEnvironment({ ...base, OWA_TEST_OCI_REGISTRY: 'http://localhost:5000', OWA_TEST_OCI_REQUIRED: '1' })).required, true);
});

test('the live suite skips cleanly when unconfigured, and FAILS (exit 1) in required mode with ORAS/registry absent', async () => {
  const skipped = await runSuite({});
  assert.equal(skipped.code, 0, `unconfigured suite exits 0: ${skipped.out.slice(-400)}`);
  assert.match(skipped.out, /tests 2/);
  assert.match(skipped.out, /skipped 2/, 'both live OCI tests skip');
  assert.match(skipped.out, /pass 0/);
  const required = await runSuite({ OWA_TEST_OCI_REQUIRED: '1' });
  assert.equal(required.code, 1, 'required mode without prerequisites exits non-zero');
  assert.match(required.out, /fail 2/, 'both live OCI tests fail instead of skipping');
  assert.match(required.out, /must run, not skip/);
  assert.match(required.out, /skipped 0/);
  // Registry configured but ORAS missing, required: still a failure, not a skip.
  const half = await runSuite({ OWA_TEST_OCI_REQUIRED: '1', OWA_TEST_OCI_REGISTRY: 'http://127.0.0.1:1' });
  assert.equal(half.code, 1);
  assert.match(half.out, /set OWA_TEST_ORAS_BIN/);
});
