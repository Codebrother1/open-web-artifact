// CI helper for the local, disposable MinIO service. Uses ONLY the repository's
// own SigV4 signer (S3BlobStore); no `mc`, no vendor SDK. Reads the documented
// OWA_TEST_MINIO_* variables and never prints a credential, signed URL or
// Authorization header — only statuses, counts and key names.
//
//   node .github/scripts/minio-bucket.mjs ready          wait for /minio/health/ready (fail after ~60 s)
//   node .github/scripts/minio-bucket.mjs create         create the disposable bucket (fail unless 200/204)
//   node .github/scripts/minio-bucket.mjs assert-empty   fail if ANY object remains in the bucket
import { setTimeout as sleep } from 'node:timers/promises';
import { S3BlobStore, decodeXmlText } from '../../packages/storage-s3/src/index.js';

const command = process.argv[2];
const env = process.env;
for (const name of ['OWA_TEST_MINIO_ENDPOINT', 'OWA_TEST_MINIO_BUCKET', 'OWA_TEST_MINIO_ACCESS_KEY_ID', 'OWA_TEST_MINIO_SECRET_ACCESS_KEY']) {
  if (!env[name]) { console.error(`${name} is required`); process.exit(2); }
}
const endpoint = env.OWA_TEST_MINIO_ENDPOINT;
if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(endpoint)) { console.error('OWA_TEST_MINIO_ENDPOINT must be a loopback http origin in CI'); process.exit(2); }
const store = new S3BlobStore({
  endpoint, bucket: env.OWA_TEST_MINIO_BUCKET, region: env.OWA_TEST_MINIO_REGION || 'us-east-1',
  accessKeyId: env.OWA_TEST_MINIO_ACCESS_KEY_ID, secretAccessKey: env.OWA_TEST_MINIO_SECRET_ACCESS_KEY
});

async function ready() {
  for (let attempt = 0; attempt < 240; attempt++) {
    try {
      const res = await fetch(`${endpoint}/minio/health/ready`, { signal: AbortSignal.timeout(1000) });
      await res.arrayBuffer();
      if (res.ok) { console.log(`minio ready after ${attempt + 1} probe(s)`); await identity(); return; }
    } catch {}
    await sleep(250);
  }
  console.error('minio did not become ready within 60 s');
  process.exit(1);
}

/**
 * Inside Actions, record the identity of the MinIO that is actually serving:
 * the SHA-256 of the running executable (via /proc/<pid>/exe) and its
 * `--version` line, as a workflow-command notice. Annotations are visible on the
 * public run page, unlike the raw log. The version line names only the release
 * tag, commit and Go runtime; no credential is involved.
 */
async function identity() {
  if (process.env.GITHUB_ACTIONS !== 'true' || !process.env.MINIO_PID) return;
  try {
    const { createHash } = await import('node:crypto');
    const { readFile, readlink } = await import('node:fs/promises');
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const exe = await readlink(`/proc/${process.env.MINIO_PID}/exe`);
    const sha256 = createHash('sha256').update(await readFile(exe)).digest('hex');
    const { stdout } = await promisify(execFile)(exe, ['--version']);
    const version = stdout.split('\n').filter(Boolean).map(line => line.replace(/^\S+ version /, 'version ')).join('; ');
    const escape = value => String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
    console.log(`::notice title=minio identity::${escape(`${version}; executable sha256 ${sha256}`)}`);
  } catch (error) {
    console.log(`minio identity notice skipped: ${error.code ?? error.message}`);
  }
}

async function create() {
  // PUT on the bucket URL with the repo signer: the same mechanism integration-tests.md documents.
  const res = await store.signedFetch('PUT', null, { url: store.bucketUrl(), body: Buffer.alloc(0) });
  await res.arrayBuffer();
  if (res.status !== 200 && res.status !== 204) { console.error(`bucket creation failed: HTTP ${res.status}`); process.exit(1); }
  const head = await store.signedFetch('HEAD', null, { url: store.bucketUrl() });
  await head.arrayBuffer();
  if (!head.ok) { console.error(`bucket not visible after creation: HTTP ${head.status}`); process.exit(1); }
  console.log(`bucket created (HTTP ${res.status}); HEAD ${head.status}`);
}

async function assertEmpty() {
  // ListObjectsV2 over the WHOLE bucket, paginated. Keys are printed on failure so
  // a leak is attributable; they are content-addressed paths, never credentials.
  const keys = [];
  let token = null;
  do {
    const query = new URLSearchParams({ 'list-type': '2', 'max-keys': '1000' });
    if (token) query.set('continuation-token', token);
    const res = await store.signedFetch('GET', null, { url: store.bucketUrl(), query });
    const text = await res.text();
    if (!res.ok) { console.error(`list failed: HTTP ${res.status}`); process.exit(1); }
    for (const match of text.matchAll(/<Key>([^<]*)<\/Key>/g)) keys.push(decodeXmlText(match[1]));
    const next = /<NextContinuationToken>([^<]*)<\/NextContinuationToken>/.exec(text);
    token = /<IsTruncated>true<\/IsTruncated>/.test(text) && next ? decodeXmlText(next[1]) : null;
  } while (token);
  if (keys.length) {
    console.error(`bucket is not empty after the tests: ${keys.length} object(s) remain`);
    for (const key of keys.slice(0, 50)) console.error(`  ${key}`);
    process.exit(1);
  }
  console.log('bucket is empty: every isolated test prefix was cleaned up');
}

const commands = { ready, create, 'assert-empty': assertEmpty };
if (!commands[command]) { console.error(`usage: minio-bucket.mjs <ready|create|assert-empty>`); process.exit(2); }
await commands[command]();
