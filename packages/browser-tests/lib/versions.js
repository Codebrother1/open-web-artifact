// Print the exact engine versions this package would run, by launching each
// engine (an engine that cannot start is reported with its error, never guessed).
import { createRequire } from 'node:module';
import { release, type as osType, arch } from 'node:os';
import { chromium, firefox, webkit } from '@playwright/test';

const require = createRequire(import.meta.url);
console.log(`Playwright ${require('@playwright/test/package.json').version}; Node ${process.version}; ${osType()} ${release()} ${arch()}`);
for (const [name, type] of [['chromium', chromium], ['firefox', firefox], ['webkit', webkit]]) {
  try {
    const browser = await type.launch();
    console.log(`${name}: ${browser.version()}`);
    await browser.close();
  } catch (error) {
    console.log(`${name}: cannot start — ${String(error.message).split('\n').slice(0, 3).join(' ').trim()}`);
  }
}
