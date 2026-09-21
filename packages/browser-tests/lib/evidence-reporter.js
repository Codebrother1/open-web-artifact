// Prints the per-engine behavior matrix and the recorded evidence at the end of a
// run, and optionally writes the same data as JSON (OWA_BROWSER_EVIDENCE_JSON=path).
// Inside GitHub Actions (GITHUB_STEP_SUMMARY set) the matrix, the exact engine
// versions and every failing cell's full error are also appended to the job
// summary, so the result is readable from the run page.
// Only engines that actually executed appear; a project that did not run is not
// a pass. Cells: PASS, FAIL, SKIP (+reason), EXPECTED LIMIT (a documented limit
// that was demonstrated, not an enforcement claim), or NOT RUN.
import { appendFileSync, writeFileSync } from 'node:fs';
import { release, type as osType } from 'node:os';

const ANSI = /\x1b\[[0-9;]*m/g;

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
      error: result.error?.message?.split('\n')[0] ?? null,
      // Full diagnostics for a failing cell: every error's message, plus the
      // page/console context Playwright attaches, ANSI stripped.
      errors: (result.errors ?? []).map(error => String(error.message ?? error.value ?? error).replace(ANSI, '')),
      stdout: (result.stdout ?? []).map(chunk => String(chunk).replace(ANSI, '')).join('').slice(-2000)
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
    if (process.env.GITHUB_ACTIONS === 'true') {
      // Workflow-command annotations: readable on the run page and through the
      // public check-runs API without a sign-in. A notice records the engines that
      // really launched; one error per failing cell (GitHub shows at most 10).
      const escapeData = value => String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
      const escapeProperty = value => escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
      const engines = this.projects.map(project => `${project}: ${this.engines.get(project) ?? 'NOT RUN'}`).join('; ');
      const tally = {};
      for (const row of this.rows.values()) for (const project of this.projects) { const status = row.cells[project]?.status ?? 'NOT RUN'; tally[`${project} ${status}`] = (tally[`${project} ${status}`] ?? 0) + 1; }
      console.log(`::notice title=${escapeProperty('browser evidence')}::${escapeData(`Playwright ${this.playwright}; ${engines}; rows: ${Object.entries(tally).map(([k, v]) => `${k}=${v}`).join(', ')}`)}`);
      let emitted = 0, failing = 0;
      for (const row of this.rows.values()) {
        for (const project of this.projects) {
          const cell = row.cells[project];
          const status = cell?.status ?? 'NOT RUN';
          if (status === 'PASS' || status === 'EXPECTED LIMIT') continue;
          failing++;
          if (emitted >= 10) continue;
          emitted++;
          const detail = [...(cell?.errors ?? []), ...(cell?.evidence ?? []).map(fact => `evidence: ${fact}`)].join('\n');
          console.log(`::error title=${escapeProperty(`[${project}] ${status} — ${row.title}`)}::${escapeData(detail.slice(0, 1800) || status)}`);
        }
      }
      if (failing > emitted) console.log(`::error title=${escapeProperty('browser evidence')}::${failing - emitted} more failing cell(s); see the job log.`);
    }
    if (process.env.GITHUB_STEP_SUMMARY) {
      const md = [];
      md.push(`### sandboxed-web-v1 real-browser evidence — Playwright ${this.playwright}, Node ${process.version}, ${osType()} ${release()}`, '');
      for (const project of this.projects) md.push(`- **${project}**: ${this.engines.get(project) ?? 'NOT RUN (no test executed in this engine)'}`);
      md.push('', `| Behavior | ${this.projects.join(' | ')} |`, `| --- | ${this.projects.map(() => '---').join(' | ')} |`);
      for (const row of this.rows.values()) md.push(`| ${row.title.replace(/\|/g, '\\|')} | ${this.projects.map(p => row.cells[p]?.status ?? 'NOT RUN').join(' | ')} |`);
      md.push('');
      for (const row of this.rows.values()) {
        for (const project of this.projects) {
          const cell = row.cells[project];
          if (!cell || cell.status === 'PASS' || cell.status === 'EXPECTED LIMIT') continue;
          md.push(`<details><summary>${cell.status} — ${row.title} [${project}]</summary>`, '', '```text');
          for (const error of cell.errors ?? []) md.push(error.slice(0, 6000));
          for (const fact of cell.evidence) md.push(`evidence: ${fact}`);
          if (cell.stdout) md.push('', 'stdout (tail):', cell.stdout);
          md.push('```', '', '</details>', '');
        }
      }
      appendFileSync(process.env.GITHUB_STEP_SUMMARY, md.join('\n') + '\n');
    }
    if (process.env.OWA_BROWSER_EVIDENCE_JSON) {
      writeFileSync(process.env.OWA_BROWSER_EVIDENCE_JSON, JSON.stringify({
        playwright: this.playwright, node: process.version, os: `${osType()} ${release()}`, date: new Date().toISOString(),
        engines: Object.fromEntries(this.engines), projects: this.projects, rows: [...this.rows.values()]
      }, null, 2));
    }
  }
  printsToStdio() { return true; }
}
