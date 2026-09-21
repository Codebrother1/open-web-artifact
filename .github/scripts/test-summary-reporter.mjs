// node --test reporter for GitHub Actions: mirrors failures into places readable
// from the run page without downloading raw logs.
//
//   * annotations — one `::error` workflow command per failing test (name,
//     location, first lines of the error). Annotations are shown on the run
//     page and returned by the public check-runs API, so they are readable by
//     anyone who can see the repository. GitHub renders at most 10 per step;
//     an 11th annotation summarises how many more failed.
//   * job summary — when GITHUB_STEP_SUMMARY is set, one section per npm script
//     with pass/fail/skip counts and each failing test's full error.
//
// The spec reporter still prints everything to stdout; this one adds only the
// workflow commands (inside Actions) and is a complete no-op elsewhere. Test
// output can contain no credentials by construction: the suites never print
// tokens, signed URLs or provider bodies.
import { appendFileSync } from 'node:fs';

const ANSI = /\x1b\[[0-9;]*m/g;
const clean = value => String(value ?? '').replace(ANSI, '');
// Workflow-command escaping (github.com/actions/toolkit core.ts).
const escapeData = value => String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escapeProperty = value => escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
const relative = file => file ? file.replace(process.cwd(), '.').replace(/\\/g, '/').replace(/^\.\//, '') : null;

export default async function* summaryReporter(source) {
  const inActions = process.env.GITHUB_ACTIONS === 'true';
  const script = process.env.npm_lifecycle_event ? `npm run ${process.env.npm_lifecycle_event}` : 'node --test';
  const failures = [];
  let summary = null;
  for await (const event of source) {
    if (event.type === 'test:fail') {
      const { name, file, line, details } = event.data;
      const error = details?.error;
      const failure = { name, file: relative(file), line, message: clean(error?.cause?.stack ?? error?.stack ?? error?.message ?? error) };
      failures.push(failure);
      if (inActions && failures.length <= 10) {
        const props = [`title=${escapeProperty(`${script}: ${name}`)}`];
        if (failure.file) props.push(`file=${escapeProperty(failure.file)}`);
        if (failure.line) props.push(`line=${escapeProperty(failure.line)}`);
        yield `::error ${props.join(',')}::${escapeData(failure.message.slice(0, 1800))}\n`;
      }
    } else if (event.type === 'test:summary') {
      summary = event.data.counts;
    }
  }
  if (inActions && failures.length > 10) yield `::error title=${escapeProperty(script)}::${failures.length - 10} more test(s) failed; see the job summary or log.\n`;
  const target = process.env.GITHUB_STEP_SUMMARY;
  if (!target) return;
  const counts = summary ?? {};
  const lines = [];
  lines.push(`### ${failures.length ? '❌' : '✅'} \`${script}\` — ${counts.passed ?? '?'} passed, ${counts.failed ?? failures.length} failed, ${counts.skipped ?? 0} skipped (${counts.tests ?? '?'} tests)`);
  for (const failure of failures.slice(0, 25)) {
    const where = failure.file ? ` — \`${failure.file}${failure.line ? `:${failure.line}` : ''}\`` : '';
    lines.push('', `<details><summary>✖ ${failure.name}${where}</summary>`, '', '```text', failure.message.slice(0, 6000), '```', '', '</details>');
  }
  if (failures.length > 25) lines.push('', `… ${failures.length - 25} more failure(s) in the job log.`);
  lines.push('');
  appendFileSync(target, lines.join('\n') + '\n');
}
