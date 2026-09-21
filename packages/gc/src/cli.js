// Thin local operator wrapper around the GC library. Dry run by default;
// deletion requires an explicit --apply. This is NOT an HTTP route and adds no
// auth capability: it is run by an operator with direct storage access.
//
//   npm run gc                               # dry run (default)
//   node packages/gc/src/cli.js              # same
//   npm run gc -- --apply                    # delete
//   npm run gc -- --grace-seconds=604800     # 7-day grace
//   npm run gc -- --json                     # machine-readable report
//
// Storage/metadata configuration is the SAME environment the server uses
// (OWA_DATA_DIR, OWA_STORAGE, OWA_S3_*), so GC always points at the same
// namespace artifactd writes to.

import { createDefaultStores } from '../../server/src/index.js';
import { DEFAULT_GRACE_SECONDS, GcError, collectGarbage, formatReport } from './index.js';

function parseArgs(argv) {
  const options = { apply: false, json: false, graceSeconds: DEFAULT_GRACE_SECONDS, pruneExpiredLeases: false };
  for (const arg of argv) {
    if (arg === '--apply') options.apply = true;
    else if (arg === '--json') options.json = true;
    else if (arg === '--prune-expired-leases') options.pruneExpiredLeases = true;
    else if (arg.startsWith('--grace-seconds=')) {
      const raw = arg.slice('--grace-seconds='.length);
      const value = Number(raw);
      // Canonical decimal only: a typo must not silently become grace 0.
      if (!Number.isSafeInteger(value) || value < 0 || String(value) !== raw) return null;
      options.graceSeconds = value;
    } else if (arg === '--help' || arg === '-h') return 'help';
    else return null;
  }
  return options;
}

const USAGE = `owa-gc — reclaim unreferenced OWA blob objects

  npm run gc -- [--apply] [--grace-seconds=N] [--json] [--prune-expired-leases]
  node packages/gc/src/cli.js [--apply] [--grace-seconds=N] [--json]

  (default)                dry run; reports what WOULD be reclaimed, deletes nothing
  --apply                  actually delete the reported candidates
  --grace-seconds=N        minimum object age to be collectible (default ${DEFAULT_GRACE_SECONDS})
  --json                   emit the structured report as JSON
  --prune-expired-leases   also remove expired lease records (apply only)

Every stored release is a GC root, active or not. Release records are never
deleted and no release pruning is performed. See docs/gc.md.`;

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options === 'help') { console.log(USAGE); return; }
  if (options === null) { console.error(USAGE); process.exitCode = 1; return; }

  const { blobs, metadata, leases, storageKind } = await createDefaultStores();
  const report = await collectGarbage({ blobs, metadata, leases, ...options });

  if (options.json) console.log(JSON.stringify(report, null, 2));
  else console.log(`storage: ${storageKind}\n${formatReport(report)}`);
}

try {
  await main();
} catch (error) {
  // Only a fixed code reaches the operator: never a provider body, signed URL,
  // credential, path or stack.
  console.error(error instanceof GcError ? `owa-gc: ${error.code}` : 'owa-gc: OWA_GC_FAILED');
  process.exitCode = 1;
}
