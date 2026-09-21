// Live-provider configuration shared by the S3-compatible integration suites.
//
// Every live case is opt-in through explicit OWA_TEST_<PROVIDER>_* variables and
// never falls back to artifactd's own OWA_S3_* settings. When a provider is not
// configured the case SKIPS — a skip is not evidence, but it keeps the ordinary
// offline lane green without contacting any hosted service.
//
// CI needs the opposite guarantee for the provider it provisioned: the intended
// cases must actually run. OWA_TEST_REQUIRE_PROVIDERS is a TEST-HARNESS-ONLY
// switch listing requirement tokens (e.g. "MINIO", "MINIO_VIRTUAL", "R2"). A case
// whose token is listed is never allowed to skip: with its variables missing the
// test FAILS with a clear message instead. Production code never reads it.

/** Requirement tokens a caller may list in OWA_TEST_REQUIRE_PROVIDERS. */
export const REQUIREMENT_TOKENS = Object.freeze(['MINIO', 'MINIO_VIRTUAL', 'R2']);

/** Parse the require list; unknown tokens are a configuration error, not a silent no-op. */
export function requiredProviders(env = process.env) {
  const raw = env.OWA_TEST_REQUIRE_PROVIDERS;
  if (raw === undefined || raw.trim() === '') return new Set();
  const tokens = raw.split(',').map(token => token.trim().toUpperCase()).filter(Boolean);
  for (const token of tokens) {
    if (!REQUIREMENT_TOKENS.includes(token)) throw new Error(`OWA_TEST_REQUIRE_PROVIDERS: unknown provider token "${token}" (known: ${REQUIREMENT_TOKENS.join(', ')})`);
  }
  return new Set(tokens);
}

/**
 * Resolve one live case.
 *
 *   entry.provider     "MINIO" | "R2"            → variable prefix OWA_TEST_<provider>_
 *   entry.endpoint     variable name for the endpoint (default "ENDPOINT";
 *                      the virtual-host case uses "VIRTUAL_ENDPOINT")
 *   entry.requirement  token this case is required under (default entry.provider)
 *   entry.region       default region when OWA_TEST_<provider>_REGION is unset
 *
 * Returns { skip } when unconfigured and not required, { fail } when unconfigured
 * but required, or { options } with the store options otherwise. Only variable
 * NAMES ever appear in messages — never their values.
 */
export function providerConfiguration(entry, env = process.env) {
  const prefix = `OWA_TEST_${entry.provider}_`;
  const endpointKey = entry.endpoint ?? 'ENDPOINT';
  const required = [endpointKey, 'BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY'];
  const missing = required.filter(key => !env[prefix + key]);
  const requirement = entry.requirement ?? entry.provider;
  const isRequired = requiredProviders(env).has(requirement);
  if (missing.length) {
    const names = missing.map(key => prefix + key).join(', ');
    if (isRequired) return { fail: `OWA_TEST_REQUIRE_PROVIDERS lists ${requirement} but ${names} ${missing.length === 1 ? 'is' : 'are'} unset: this case must run, not skip` };
    return { skip: `set ${names}` };
  }
  return {
    required: isRequired,
    options: {
      endpoint: env[prefix + endpointKey],
      bucket: env[prefix + 'BUCKET'],
      region: env[prefix + 'REGION'] || entry.region,
      accessKeyId: env[prefix + 'ACCESS_KEY_ID'],
      secretAccessKey: env[prefix + 'SECRET_ACCESS_KEY'],
      sessionToken: env[prefix + 'SESSION_TOKEN'] || null,
      checksumEvidence: env[prefix + 'CHECKSUM_EVIDENCE'] || undefined,
      directUploadIntegrity: env[prefix + 'DIRECT_UPLOAD_INTEGRITY'] || undefined
    }
  };
}
