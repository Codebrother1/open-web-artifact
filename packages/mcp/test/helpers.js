import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { createToken } from '../../server/src/auth.js';
import { createArtifactServer } from '../../server/src/index.js';
import { FilesystemBlobStore, FilesystemMetadataStore } from '../../storage-filesystem/src/index.js';

export const NOW = 2_000_000_000;
export const CAPS = ['plan', 'upload', 'commit', 'activate', 'read'];
export const SOURCE = Object.freeze({
  'index.html': '<!doctype html><title>MCP lifecycle fixture</title><h1>Deterministic artifact</h1>\n',
  'app.js': 'document.documentElement.dataset.fixture = "mcp-lifecycle-v1";\n',
  'style.css': 'body { color: #123456; background: #fafafa; }\n'
});
export const CHANGED_CSS = 'body { color: #654321; background: #fafafa; }\n';
const MCP = fileURLToPath(new URL('../src/index.js', import.meta.url));
const CLI = fileURLToPath(new URL('../../cli/src/index.js', import.meta.url));

// No inherited OWA operator credentials/configuration can reach either child.
// The one secret intentionally supplied to clients is the runtime-minted token.
export function childEnv(fields = {}) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('OWA_')) delete env[key];
  delete env.NODE_OPTIONS;
  return { ...env, ...fields };
}

export function assertSafe(text, secrets = [], { fileBytes = false } = {}) {
  for (const secret of secrets) {
    assert.ok(!secret || !text.includes(secret), 'no credential or operator key in output/storage');
  }
  assert.ok(!/owa1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(text), 'no complete bearer token');
  assert.ok(!/[?&](?:sig|expires|X-Amz-[^=\s]*)=/i.test(text), 'no signed upload URL');
  assert.ok(!/X-Amz-(?:Signature|Credential)/i.test(text), 'no object-store grant');
  if (fileBytes) {
    for (const bytes of [...Object.values(SOURCE), CHANGED_CSS]) {
      // Scan both wire JSON (escaped newlines) and decoded text.
      assert.ok(!text.includes(bytes.trim()) && !text.includes(JSON.stringify(bytes).slice(1, -1)),
        'no source-file bytes in tool output');
    }
  }
}

export function exactKeys(value, keys, label = 'exact result keys') {
  assert.ok(value !== null && typeof value === 'object' && !Array.isArray(value), label);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), label);
}

export function resultData(result, secrets = []) {
  assertSafe(JSON.stringify(result), secrets, { fileBytes: true });
  const data = result.structuredContent;
  assert.ok(data && typeof data === 'object' && typeof data.ok === 'boolean', 'primary structured content');
  exactKeys(result, data.ok ? ['content', 'structuredContent'] : ['content', 'structuredContent', 'isError']);
  assert.ok(Array.isArray(result.content) && result.content.length === 1, 'one text fallback');
  exactKeys(result.content[0], ['type', 'text']);
  assert.equal(result.content[0].type, 'text');
  assert.ok(result.content[0].text === JSON.stringify(data), 'text is exactly the same JSON as structured content');
  if (!data.ok) assert.equal(result.isError, true);
  return data;
}

export function expectError(result, code, status, secrets = []) {
  const data = resultData(result, secrets);
  assert.equal(data.ok, false);
  exactKeys(data, ['ok', 'error']);
  exactKeys(data.error, status === undefined ? ['code', 'category', 'message'] : ['code', 'category', 'message', 'status']);
  assert.equal(data.error.code, code);
  assert.equal(data.error.status, status);
  const expected = {
    OWA_AUTH_MISSING: ['authentication', 'Authentication required'],
    OWA_AUTH_SITE: ['site_scope', 'Authentication does not permit this site'],
    OWA_AUTH_EXPIRED: ['authentication', 'Authentication token expired'],
    OWA_AUTH_INVALID_SIGNATURE: ['authentication', 'Invalid authentication signature'],
    OWA_AUTH_CAPABILITY: ['capability', 'Authentication does not permit this operation'],
    OWA_MCP_INVALID_INPUT: ['invalid_input', 'Invalid input']
  }[code];
  assert.deepEqual([data.error.category, data.error.message], expected, 'fixed safe error vocabulary');
  return data;
}

async function scanStored(dir, secrets) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) await scanStored(path, secrets);
    else assertSafe((await readFile(path)).toString('utf8'), secrets);
  }
}

// Read-only fixture inspection is allowed; all lifecycle mutations below use
// the actual MCP stdio process or the actual CLI HTTP process, never core APIs.
export async function fixture(t, { mode = 'required', duplicate = false, content = null } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'owa-mcp-lifecycle-'));
  const staging = join(root, 'staging'), directory = join(staging, 'site'), data = join(root, 'data');
  const secret = randomBytes(32), uploadSecret = randomBytes(32);
  const tokens = [], children = [], exchanges = [];
  let server;
  const secrets = () => [...tokens, secret.toString('hex'), secret.toString('base64url'),
    uploadSecret.toString('hex'), uploadSecret.toString('base64url')];
  t.after(async () => {
    try {
      for (const child of [...children].reverse()) await child.close();
      if (server?.listening) await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
      for (const child of children) child.assertClean();
      await scanStored(data, secrets());
    } finally {
      // A failing credential assertion must not strand a child, socket, or file.
      for (const child of [...children].reverse()) await child.close().catch(() => {});
      if (server?.listening) await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
      await rm(root, { recursive: true, force: true });
    }
  });
  await mkdir(directory, { recursive: true });
  await mkdir(data);
  for (const [name, content] of Object.entries(SOURCE)) await writeFile(join(directory, name), content);
  if (duplicate) await writeFile(join(directory, 'duplicate.js'), SOURCE['app.js']);
  const blobs = new FilesystemBlobStore(data), metadata = new FilesystemMetadataStore(data);
  // `content` configures the server's content ORIGIN, which is what makes commit
  // return a canonical contentUrl. It does not change routing on this listener.
  server = createArtifactServer({ blobs, metadata, uploadSecret, content,
    auth: mode === 'dev' ? { mode, now: () => NOW } : { mode, secret, now: () => NOW } });
  // Observe the real server without changing routing, authorization, or storage.
  // Never retain headers, query values, request bodies, signatures, or tokens in
  // observations: they are reduced to booleans before assertions can print them.
  server.on('request', (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const authorization = req.headers.authorization;
    const record = {
      method: req.method, path: url.pathname, status: null,
      hasAuthorization: Object.hasOwn(req.headers, 'authorization'),
      bearerMatches: tokens.some(token => authorization === `Bearer ${token}`),
      hasSignature: /^[0-9a-f]{64}$/.test(url.searchParams.get('sig') ?? ''),
      validExpiry: url.searchParams.get('expires') === String(NOW + (mode === 'dev' ? 900 : 300)),
      localScope: url.searchParams.get('site') === 'demo',
      queryKeys: [...url.searchParams.keys()].sort(),
      hasContentType: Object.hasOwn(req.headers, 'content-type'),
      leakedOutsideHeader: tokens.some(token => req.url.includes(token) || Object.entries(req.headers)
        .some(([name, value]) => name !== 'authorization' && String(value).includes(token))),
      leakedInBody: false
    };
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      record.leakedInBody = tokens.some(token => body.includes(token));
      body = '';
    });
    res.on('finish', () => { record.status = res.statusCode; });
    exchanges.push(record);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;

  function mint(capabilities = CAPS, { sites = ['demo'], exp = NOW + 300, now = NOW } = {}) {
    const token = createToken({ secret, now: () => now, exp, jti: 'mcp-lifecycle-test', sites, capabilities });
    tokens.push(token);
    return token;
  }
  function tamper(token) {
    const parts = token.split('.');
    const signature = Buffer.from(parts[2], 'base64url');
    signature[0] ^= 1;
    parts[2] = signature.toString('base64url');
    const changed = parts.join('.');
    tokens.push(changed);
    return changed;
  }

  async function connect(token, { trustedServer = origin } = {}) {
    const transport = new StdioClientTransport({ command: process.execPath, args: [MCP], cwd: root,
      env: childEnv({ OWA_MCP_SERVER: trustedServer, OWA_MCP_ROOT: staging,
        ...(token === undefined ? {} : { OWA_TOKEN: token }) }), stderr: 'pipe' });
    const client = new Client({ name: 'owa-lifecycle-test', version: '1.0.0' });
    let stdout = '', stderr = '', protocolErrors = 0, closed = false;
    transport.stderr.on('data', chunk => { stderr += chunk; });
    client.onerror = () => { protocolErrors++; };
    // The pinned SDK exposes no public stdout getter. This read-only stream tap
    // is solely a leak detector; initialize/list/call/close are official public
    // Client APIs, not private adapter calls or hand-written protocol framing.
    const start = transport.start.bind(transport);
    transport.start = async () => {
      await start();
      transport._process.stdout.on('data', chunk => { stdout += chunk; });
    };
    const child = {
      client,
      async close() {
        if (closed) return;
        closed = true;
        await client.close();
      },
      assertClean() {
        assertSafe(stdout + stderr, secrets(), { fileBytes: true });
        assert.equal(protocolErrors, 0, 'official SDK observed no malformed stdout or protocol errors');
        assert.ok(stderr === '', 'normal MCP operations do not write diagnostics');
      },
      async call(name, args = {}) {
        let result;
        try { result = await client.callTool({ name, arguments: args }); }
        catch { throw new Error('Official MCP tools/call failed (diagnostics intentionally withheld)'); }
        assertSafe(JSON.stringify(result), secrets(), { fileBytes: true });
        return result;
      }
    };
    children.push(child);
    try { await client.connect(transport); }
    catch { throw new Error('Official MCP initialize failed (diagnostics intentionally withheld)'); }
    assert.ok(client.getServerCapabilities()?.tools, 'initialize advertises tools');
    assert.equal(client.getServerVersion()?.name, 'owa-mcp');
    assert.equal(client.getServerVersion()?.version, '0.5.0', 'initialize advertises the software release version');
    const discovered = await client.listTools();
    assertSafe(JSON.stringify(discovered), secrets(), { fileBytes: true });
    child.tools = discovered.tools;
    return child;
  }

  async function runCli(token) {
    const child = spawn(process.execPath, [CLI, 'publish', directory, '--site', 'demo', '--server', origin], {
      cwd: root, env: childEnv(token === undefined ? {} : { OWA_TOKEN: token }), stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 15_000);
    try {
      const [code, signal] = await once(child, 'close');
      assertSafe(stdout + stderr, secrets(), { fileBytes: true });
      assert.ok(code === 0 && signal === null, 'HTTP CLI publish exits successfully');
      assert.ok(stderr === '', 'HTTP CLI has no stderr');
      const digest = /^Artifact (sha256:[0-9a-f]{64})$/m.exec(stdout)?.[1];
      const releaseId = /^Published (r_[0-9a-f]{20})$/m.exec(stdout)?.[1];
      assert.ok(digest && releaseId, 'CLI output identifies digest and release');
      return { artifactDigest: digest, releaseId };
    } finally { clearTimeout(timer); }
  }

  return { root, staging, directory, data, blobs, metadata, origin, exchanges, mint, tamper, connect, runCli,
    secrets, args: extra => ({ site: 'demo', server: origin, ...extra }),
    async assertNoWrites() {
      assert.equal(await metadata.getSite('demo'), null, 'denial cannot create site metadata');
      assert.deepEqual(await readdir(data), [], 'denial has no downstream filesystem writes');
    },
    async fullReleases(token) {
      const response = await fetch(`${origin}/v1/sites/demo/releases`, {
        headers: token === undefined ? {} : { authorization: `Bearer ${token}` }
      });
      assert.equal(response.status, 200, 'fixture verification uses real HTTP release listing');
      const result = await response.json();
      assertSafe(JSON.stringify(result), secrets());
      return result;
    }
  };
}
