// Print the exact engine versions this package would run, by launching each
// engine (an engine that cannot start is reported with its error, never guessed).
//
//   node lib/versions.js                         report every engine, exit 0
//   node lib/versions.js --require chromium,webkit
//       exit 1 unless every listed engine actually launched — CI uses this so a
//       missing browser prerequisite fails the job instead of becoming a skip.
import { createRequire } from 'node:module';
import { release, type as osType, arch } from 'node:os';
import { chromium, firefox, webkit } from '@playwright/test';

const ENGINES = { chromium, firefox, webkit };
const requireIndex = process.argv.indexOf('--require');
const required = requireIndex === -1 ? [] : (process.argv[requireIndex + 1] ?? '').split(',').map(s => s.trim()).filter(Boolean);
for (const name of required) if (!(name in ENGINES)) { console.error(`--require: unknown engine "${name}"`); process.exit(2); }

const require = createRequire(import.meta.url);
console.log(`Playwright ${require('@playwright/test/package.json').version}; Node ${process.version}; ${osType()} ${release()} ${arch()}`);
const launched = new Set();
for (const [name, type] of Object.entries(ENGINES)) {
  try {
    const browser = await type.launch();
    console.log(`${name}: ${browser.version()}`);
    launched.add(name);
    await browser.close();
  } catch (error) {
    console.log(`${name}: cannot start — ${String(error.message).split('\n').slice(0, 3).join(' ').trim()}`);
  }
}
const missing = required.filter(name => !launched.has(name));
if (missing.length) {
  console.error(`required engine(s) did not launch: ${missing.join(', ')}`);
  process.exit(1);
}
