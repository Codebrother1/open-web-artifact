import test from 'node:test';
import assert from 'node:assert/strict';
import { REQUIREMENT_TOKENS, providerConfiguration, requiredProviders } from '../src/providers.js';

// Offline checks for the live-provider opt-in and the test-harness-only
// OWA_TEST_REQUIRE_PROVIDERS switch that CI uses to prove a provider case ran
// rather than skipped. No network, no real credentials: values are synthetic.

const MINIO = { name: 'MinIO path-style', provider: 'MINIO', endpoint: 'ENDPOINT', region: 'us-east-1', requirement: 'MINIO' };
const VIRTUAL = { name: 'MinIO virtual-host', provider: 'MINIO', endpoint: 'VIRTUAL_ENDPOINT', region: 'us-east-1', requirement: 'MINIO_VIRTUAL' };
const R2 = { name: 'Cloudflare R2', provider: 'R2', region: 'auto' };
const configured = {
  OWA_TEST_MINIO_ENDPOINT: 'http://127.0.0.1:9000', OWA_TEST_MINIO_BUCKET: 'owa-ci',
  OWA_TEST_MINIO_ACCESS_KEY_ID: 'SYNTHETIC_ACCESS_KEY_ID', OWA_TEST_MINIO_SECRET_ACCESS_KEY: 'synthetic-secret-never-real'
};

test('unconfigured provider skips, naming only the missing variable names', () => {
  const result = providerConfiguration(MINIO, {});
  assert.deepEqual(Object.keys(result), ['skip']);
  assert.equal(result.skip, 'set OWA_TEST_MINIO_ENDPOINT, OWA_TEST_MINIO_BUCKET, OWA_TEST_MINIO_ACCESS_KEY_ID, OWA_TEST_MINIO_SECRET_ACCESS_KEY');
  const partial = providerConfiguration(MINIO, { OWA_TEST_MINIO_ENDPOINT: 'http://127.0.0.1:9000', OWA_TEST_MINIO_BUCKET: 'b' });
  assert.equal(partial.skip, 'set OWA_TEST_MINIO_ACCESS_KEY_ID, OWA_TEST_MINIO_SECRET_ACCESS_KEY');
});

test('a required but unconfigured provider FAILS instead of skipping', () => {
  const result = providerConfiguration(MINIO, { OWA_TEST_REQUIRE_PROVIDERS: 'MINIO' });
  assert.deepEqual(Object.keys(result), ['fail']);
  assert.match(result.fail, /^OWA_TEST_REQUIRE_PROVIDERS lists MINIO but OWA_TEST_MINIO_ENDPOINT, .* are unset: this case must run, not skip$/);
  // Tokens are case-insensitive and may be listed together.
  assert.ok(providerConfiguration(R2, { OWA_TEST_REQUIRE_PROVIDERS: ' minio , r2 ' }).fail);
});

test('the virtual-host case has its own requirement token, so path-style-only CI still skips it cleanly', () => {
  const env = { ...configured, OWA_TEST_REQUIRE_PROVIDERS: 'MINIO' };
  assert.ok(providerConfiguration(MINIO, env).options, 'path-style runs');
  assert.equal(providerConfiguration(VIRTUAL, env).skip, 'set OWA_TEST_MINIO_VIRTUAL_ENDPOINT', 'virtual-host skips: not required');
  assert.ok(providerConfiguration(VIRTUAL, { ...env, OWA_TEST_REQUIRE_PROVIDERS: 'MINIO,MINIO_VIRTUAL' }).fail, 'unless explicitly required');
  assert.equal(providerConfiguration(R2, env).skip, 'set OWA_TEST_R2_ENDPOINT, OWA_TEST_R2_BUCKET, OWA_TEST_R2_ACCESS_KEY_ID, OWA_TEST_R2_SECRET_ACCESS_KEY', 'R2 keeps skipping in MinIO-only CI');
});

test('a configured provider yields store options with the trust overrides, and marks whether it was required', () => {
  const plain = providerConfiguration(MINIO, configured);
  assert.equal(plain.required, false);
  assert.deepEqual(plain.options, {
    endpoint: 'http://127.0.0.1:9000', bucket: 'owa-ci', region: 'us-east-1',
    accessKeyId: 'SYNTHETIC_ACCESS_KEY_ID', secretAccessKey: 'synthetic-secret-never-real', sessionToken: null,
    checksumEvidence: undefined, directUploadIntegrity: undefined
  });
  const asserted = providerConfiguration(MINIO, { ...configured, OWA_TEST_REQUIRE_PROVIDERS: 'MINIO', OWA_TEST_MINIO_REGION: 'eu-west-1', OWA_TEST_MINIO_CHECKSUM_EVIDENCE: 'enforced', OWA_TEST_MINIO_DIRECT_UPLOAD_INTEGRITY: 'enforced' });
  assert.equal(asserted.required, true);
  assert.equal(asserted.options.region, 'eu-west-1');
  assert.equal(asserted.options.checksumEvidence, 'enforced');
  assert.equal(asserted.options.directUploadIntegrity, 'enforced');
  assert.equal(providerConfiguration(VIRTUAL, { ...configured, OWA_TEST_MINIO_VIRTUAL_ENDPOINT: 'http://localhost:9000' }).options.endpoint, 'http://localhost:9000');
});

test('skip and fail messages never carry a configured value', () => {
  const env = { OWA_TEST_MINIO_ENDPOINT: 'http://127.0.0.1:9000', OWA_TEST_MINIO_ACCESS_KEY_ID: 'LEAKABLE_KEY_ID', OWA_TEST_REQUIRE_PROVIDERS: 'MINIO' };
  const { fail } = providerConfiguration(MINIO, env);
  assert.ok(!fail.includes('127.0.0.1') && !fail.includes('LEAKABLE_KEY_ID'));
  const { skip } = providerConfiguration(MINIO, { OWA_TEST_MINIO_ACCESS_KEY_ID: 'LEAKABLE_KEY_ID' });
  assert.ok(!skip.includes('LEAKABLE_KEY_ID'));
});

test('unknown requirement tokens are a configuration error, never a silent no-op', () => {
  assert.deepEqual([...requiredProviders({})], []);
  assert.deepEqual([...requiredProviders({ OWA_TEST_REQUIRE_PROVIDERS: '' })], []);
  assert.deepEqual([...requiredProviders({ OWA_TEST_REQUIRE_PROVIDERS: 'MINIO,MINIO_VIRTUAL,R2' })], REQUIREMENT_TOKENS);
  assert.throws(() => requiredProviders({ OWA_TEST_REQUIRE_PROVIDERS: 'S3' }), /unknown provider token "S3"/);
  assert.throws(() => providerConfiguration(MINIO, { OWA_TEST_REQUIRE_PROVIDERS: 'all' }), /unknown provider token "ALL"/);
});
