// Real-browser validation of sandboxed-web-v1 (issue #19). Optional, package-local.
// Nothing here is imported by the runtime, the CLI, storage, MCP or `npm test`.
import { defineConfig } from '@playwright/test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ENGINES = ['chromium', 'firefox', 'webkit'];
// OWA_BROWSERS=chromium,firefox limits the run to engines this host can start.
// An engine that is not run is reported as not run — never as a pass.
const selected = (process.env.OWA_BROWSERS ?? ENGINES.join(',')).split(',').map(s => s.trim()).filter(Boolean);
for (const name of selected) if (!ENGINES.includes(name)) throw new Error(`OWA_BROWSERS: unknown engine "${name}"`);

export default defineConfig({
  testDir: './tests',
  // Security tests: deterministic, sequential, no retries. Every test starts its
  // own loopback servers on ephemeral ports and its own temporary store, so the
  // serial run is a choice for reproducible evidence, not a shared-state need.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 60_000,
  expect: { timeout: 5_000 },
  reporter: [['list'], ['./lib/evidence-reporter.js']],
  // Ephemeral output only: nothing is written under the repository.
  outputDir: join(tmpdir(), 'owa-browser-tests-output'),
  use: {
    headless: true,
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    acceptDownloads: true,
    // Tests never contact anything but 127.0.0.1 / *.localhost. If a URL outside
    // loopback is ever requested, the request is aborted and recorded as a test
    // failure by the harness (see lib/test.js), so no telemetry can slip through.
  },
  projects: selected.map(name => ({ name, use: { browserName: name } }))
});
