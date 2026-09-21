// Shared test-only helpers for the live OCI registry suites (issues #23 and #9).
// External commands always receive ARRAY arguments, never a shell string.
// Registry HTTP requests here are supplemental inspection; ORAS is the transport.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CLI = fileURLToPath(new URL('../../cli/src/index.js', import.meta.url));

/** Run an external command with array arguments; never a shell string. */
export function run(command, args, { timeout = 120_000 } = {}) {
  return new Promise(resolve => {
    execFile(command, args, { timeout, maxBuffer: 8 * 1024 * 1024, env: { ...process.env, ORAS_CACHE: undefined } }, (error, stdout, stderr) => {
      resolve({ code: error ? (error.code ?? 1) : 0, stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), signal: error?.signal ?? null });
    });
  });
}
export const tail = text => text.trim().split('\n').slice(-4).join(' | ').slice(0, 400);
/** ORAS must succeed; a non-zero exit is a failure with safe diagnostics (command, code, stderr tail). */
export async function oras(env, args, t) {
  t?.diagnostic(`oras ${args.join(' ')}`);
  const result = await run(env.oras, args);
  assert.equal(result.code, 0, `oras ${args[0]} exited ${result.code}${result.signal ? ` (${result.signal})` : ''}: ${tail(result.stderr || result.stdout)}`);
  return result;
}
/** ORAS must FAIL (non-zero exit); a zero exit is the failure. */
export async function orasMustFail(env, args, t) {
  t?.diagnostic(`oras ${args.join(' ')}   (expected to fail)`);
  const result = await run(env.oras, args);
  assert.notEqual(result.code, 0, `oras ${args[0]} unexpectedly succeeded: ${tail(result.stdout)}`);
  return result;
}
/** Test-only registry inspection over plain HTTP; returns status, headers and body bytes. */
export async function registryGet(url, { method = 'GET', accept } = {}) {
  const res = await fetch(url, { method, headers: accept ? { accept } : {}, signal: AbortSignal.timeout(15_000) });
  return { status: res.status, headers: Object.fromEntries(res.headers), body: Buffer.from(await res.arrayBuffer()) };
}
/** GET through the real content listener with an explicit Host (node:http, so Host is not rewritten). */
export function serve(port, host, path) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ hostname: '127.0.0.1', port, path, method: 'GET', headers: { host, connection: 'close' } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject); req.end();
  });
}
export async function ociManifestOf(layout) {
  const index = JSON.parse(await readFile(join(layout, 'index.json'), 'utf8'));
  return { index, descriptors: index.manifests ?? [] };
}
export const temp = async (t, name) => { const dir = await mkdtemp(join(tmpdir(), `owa-oci-${name}-`)); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };
export const record = (t, facts) => { for (const [k, v] of Object.entries(facts)) t.diagnostic(`${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`); };
/** GitHub Actions annotation (public evidence channel); a no-op elsewhere. */
export function notice(title, message) {
  if (process.env.GITHUB_ACTIONS !== 'true') return;
  const escape = value => String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  process.stdout.write(`::notice title=${escape(title)}::${escape(message)}\n`);
}
