// Prints the per-engine behavior matrix and the recorded evidence at the end of a
// run, and optionally writes the same data as JSON (OWA_BROWSER_EVIDENCE_JSON=path).
// Only engines that actually executed appear; a project that did not run is not
// a pass. Cells: PASS, FAIL, SKIP (+reason), EXPECTED LIMIT (a documented limit
// that was demonstrated, not an enforcement claim), or NOT RUN.
import { writeFileSync } from 'node:fs';
import { release, type as osType } from 'node:os';

export default class EvidenceReporter {
  constructor() { this.rows = new Map(); this.projects = []; this.engines = new Map(); }
  onBegin(config) {
    this.playwright = config.version;
    this.projects = config.projects.map(project => project.name);
  }
  onTestEnd(test, result) {
    const project = test.parent.project()?.name ?? 'default';
    const key = `${test.location.file.split('/').pop()} › ${test.title}`;
    if (!this.rows.has(key)) this.rows.set(key, { title: key, cells: {} });
    // Newer Playwright exposes runtime annotations on the result as well as the
    // test; take one source and de-duplicate identical entries.
    const seen = new Set();
    const annotations = (result.annotations?.length ? result.annotations : test.annotations)
      .filter(a => { const key = `${a.type}|${a.description ?? ''}`; if (seen.has(key)) return false; seen.add(key); return true; });
    const engine = annotations.find(a => a.type === 'engine')?.description;
    if (engine) this.engines.set(project, engine);
    const limit = annotations.filter(a => a.type === 'expected-limit').map(a => a.description);
    const status = result.status === 'skipped' ? `SKIP (${annotations.find(a => a.type === 'skip')?.description ?? 'skipped'})`
      : result.status === 'passed' ? (limit.length ? 'EXPECTED LIMIT' : 'PASS')
      : result.status === 'timedOut' ? 'FAIL (timeout)' : 'FAIL';
    this.rows.get(key).cells[project] = {
      status,
      evidence: annotations.filter(a => a.type === 'evidence').map(a => a.description),
      limits: limit,
      notes: annotations.filter(a => a.type === 'note').map(a => a.description),
      error: result.error?.message?.split('\n')[0] ?? null
    };
  }
  onEnd() {
    const lines = [];
    lines.push('');
    lines.push(`sandboxed-web-v1 real-browser evidence — Playwright ${this.playwright}, Node ${process.version}, ${osType()} ${release()}, ${new Date().toISOString().slice(0, 10)}`);
    for (const project of this.projects) lines.push(`  ${project}: ${this.engines.get(project) ?? 'NOT RUN (no test executed in this engine)'}`);
    lines.push('');
    const header = ['Behavior', ...this.projects];
    lines.push(`| ${header.join(' | ')} |`);
    lines.push(`| ${header.map(() => '---').join(' | ')} |`);
    for (const row of this.rows.values()) {
      lines.push(`| ${row.title} | ${this.projects.map(p => row.cells[p]?.status ?? 'NOT RUN').join(' | ')} |`);
    }
    lines.push('');
    for (const row of this.rows.values()) {
      for (const project of this.projects) {
        const cell = row.cells[project];
        if (!cell) continue;
        const facts = [...cell.limits.map(l => `LIMIT: ${l}`), ...cell.evidence, ...cell.notes.map(n => `note: ${n}`)];
        if (cell.error) facts.push(`error: ${cell.error}`);
        if (facts.length) { lines.push(`${row.title} [${project}]`); for (const fact of facts) lines.push(`    - ${fact}`); }
      }
    }
    const text = lines.join('\n');
    console.log(text);
    if (process.env.OWA_BROWSER_EVIDENCE_JSON) {
      writeFileSync(process.env.OWA_BROWSER_EVIDENCE_JSON, JSON.stringify({
        playwright: this.playwright, node: process.version, os: `${osType()} ${release()}`, date: new Date().toISOString(),
        engines: Object.fromEntries(this.engines), projects: this.projects, rows: [...this.rows.values()]
      }, null, 2));
    }
  }
  printsToStdio() { return true; }
}
