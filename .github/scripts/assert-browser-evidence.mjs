// CI postflight for the browser lane: prove every required engine REALLY ran the
// whole suite. Reads the JSON the evidence reporter wrote (OWA_BROWSER_EVIDENCE_JSON)
// and fails unless each listed engine reports its real version and every row for
// it is PASS or EXPECTED LIMIT. A NOT RUN, SKIP or FAIL cell is a failure here even
// if Playwright's own exit code was 0.
//
//   node .github/scripts/assert-browser-evidence.mjs <evidence.json> chromium,firefox,webkit
import { readFileSync } from 'node:fs';

const [file, list] = process.argv.slice(2);
if (!file || !list) { console.error('usage: assert-browser-evidence.mjs <evidence.json> <engine,engine,...>'); process.exit(2); }
const required = list.split(',').map(s => s.trim()).filter(Boolean);
const evidence = JSON.parse(readFileSync(file, 'utf8'));
let failed = false;
console.log(`Playwright ${evidence.playwright}; Node ${evidence.node}; ${evidence.os}; ${evidence.date}`);
for (const engine of required) {
  const version = evidence.engines?.[engine];
  const cells = evidence.rows.map(row => ({ title: row.title, status: row.cells?.[engine]?.status ?? 'NOT RUN' }));
  const bad = cells.filter(cell => cell.status !== 'PASS' && cell.status !== 'EXPECTED LIMIT');
  const counts = cells.reduce((acc, cell) => { acc[cell.status] = (acc[cell.status] ?? 0) + 1; return acc; }, {});
  console.log(`${engine}: ${version ?? 'NO VERSION RECORDED'} — ${cells.length} rows: ${Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(', ')}`);
  if (!version || !version.startsWith(`${engine} `)) { console.error(`  ${engine}: no real engine version recorded (did the browser launch?)`); failed = true; }
  if (cells.length === 0) { console.error(`  ${engine}: no rows executed`); failed = true; }
  for (const cell of bad) { console.error(`  ${engine}: ${cell.status} — ${cell.title}`); failed = true; }
}
if (failed) process.exit(1);
console.log(`all required engines executed every row: ${required.join(', ')}`);
