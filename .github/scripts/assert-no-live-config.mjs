// CI preflight: the automatic lanes are SECRETLESS. No hosted-storage or R2
// configuration may be present, and the offline lane may carry no live-storage
// configuration at all, so `npm run test:integration` can only skip its provider
// cases — never reach a hosted service. Prints variable NAMES only.
//
//   node .github/scripts/assert-no-live-config.mjs                 offline lane: nothing allowed
//   node .github/scripts/assert-no-live-config.mjs --allow MINIO   MinIO lane: only OWA_TEST_MINIO_* and
//                                                                  OWA_TEST_REQUIRE_PROVIDERS may be set
const allowIndex = process.argv.indexOf('--allow');
const allowed = allowIndex === -1 ? [] : (process.argv[allowIndex + 1] ?? '').split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
const permitted = name => allowed.some(provider => name.startsWith(`OWA_TEST_${provider}_`)) || (allowed.length > 0 && name === 'OWA_TEST_REQUIRE_PROVIDERS');
const present = Object.keys(process.env).filter(name => (name.startsWith('OWA_TEST_') || name.startsWith('OWA_S3_')) && !permitted(name)).sort();
if (present.length) {
  console.error(`this lane must not carry live-storage configuration, but found: ${present.join(', ')}`);
  process.exit(1);
}
const r2 = Object.keys(process.env).filter(name => name.startsWith('OWA_TEST_R2_'));
if (r2.length) { console.error(`R2 is never configured in automatic CI, but found: ${r2.join(', ')}`); process.exit(1); }
console.log(allowed.length
  ? `lane carries only ${allowed.map(p => `OWA_TEST_${p}_*`).join(', ')} (disposable, runner-local); no R2 or hosted-storage configuration`
  : 'offline lane: no OWA_TEST_* / OWA_S3_* configuration present; provider cases will skip');
// Inside Actions, record the exact runtime this cell used as a public annotation
// (the raw log is only readable when signed in). Platform facts only.
if (process.env.GITHUB_ACTIONS === 'true') {
  const os = await import('node:os');
  const escape = value => String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  console.log(`::notice title=runtime::${escape(`node ${process.version}; ${process.platform} ${process.arch}; ${os.type()} ${os.release()}; ${process.env.RUNNER_OS ?? ''} ${process.env.ImageOS ?? ''} ${process.env.ImageVersion ? `image ${process.env.ImageVersion}` : ''}`.replace(/\s+/g, ' ').trim())}`);
}
