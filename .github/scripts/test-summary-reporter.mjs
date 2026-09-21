// node --test reporter that mirrors failures into the GitHub Actions job summary.
//
// The spec reporter still prints everything to the job log. This reporter adds
// nothing to stdout; when GITHUB_STEP_SUMMARY is set (only inside Actions) it
// appends one section per npm script — pass/fail/skip counts and, for each
// failing test, its name, location and full error — so a failure is readable
// from the run page without downloading the raw log. Outside Actions it is a
// no-op. Test output can contain no credentials by construction: the suites
// never print tokens, signed URLs or provider bodies.
import { appendFileSync } from 'node:fs';

const ANSI = /\x1b\[[0-9;]*m/g;
const clean = value => String(value ?? '').replace(ANSI, '');

export default async function* summaryReporter(source) {
  const failures = [];
  let summary = null;
  for await (const event of source) {
    if (event.type === 'test:fail') {
      const { name, file, line, details } = event.data;
      const error = details?.error;
      failures.push({
        name, file, line,
        message: clean(error?.cause?.stack ?? error?.stack ?? error?.message ?? error)
      });
    } else if (event.type === 'test:summary') {
      summary = event.data.counts;
    }
  }
  const target = process.env.GITHUB_STEP_SUMMARY;
  if (!target) return;
  const script = process.env.npm_lifecycle_event ? `npm run ${process.env.npm_lifecycle_event}` : 'node --test';
  const counts = summary ?? {};
  const lines = [];
  lines.push(`### ${failures.length ? '❌' : '✅'} \`${script}\` — ${counts.passed ?? '?'} passed, ${counts.failed ?? failures.length} failed, ${counts.skipped ?? 0} skipped (${counts.tests ?? '?'} tests)`);
  for (const failure of failures.slice(0, 25)) {
    const where = failure.file ? ` — \`${failure.file.replace(process.cwd(), '.')}${failure.line ? `:${failure.line}` : ''}\`` : '';
    lines.push('', `<details><summary>✖ ${failure.name}${where}</summary>`, '', '```text', failure.message.slice(0, 6000), '```', '', '</details>');
  }
  if (failures.length > 25) lines.push('', `… ${failures.length - 25} more failure(s) in the job log.`);
  lines.push('');
  appendFileSync(target, lines.join('\n') + '\n');
}
