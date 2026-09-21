// CI postflight: the test suites must not modify or litter the checked-out tree.
// Portable replacement for a shell `test -z "$(git status --porcelain)"`.
import { execFileSync } from 'node:child_process';

const status = execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8' }).trim();
if (status) {
  console.error('the working tree is not clean after the tests:');
  console.error(status);
  process.exit(1);
}
console.log('working tree clean: the tests left no modified or untracked files');
