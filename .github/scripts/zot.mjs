// Lifecycle of the disposable, loopback-only, plain-HTTP Zot registry used by the
// OCI interoperability lane. Test-only: this is not a production registry setup.
//
//   node .github/scripts/zot.mjs start <zot-binary> <state-dir>
//       writes a minimal config under <state-dir>, starts Zot on 127.0.0.1 with a
//       free ephemeral port, waits until GET /v2/ answers 200, prints the origin,
//       and appends OWA_TEST_OCI_REGISTRY / OWA_CI_ZOT_PID to GITHUB_ENV when set.
//   node .github/scripts/zot.mjs alive
//       exit 1 unless the Zot process recorded in OWA_CI_ZOT_PID is still running.
//   node .github/scripts/zot.mjs stop <state-dir>
//       stops the process (if any) and removes <state-dir>.
//
// The config disables everything unrelated: no UI/search, no sync, no auth, no
// remote storage, no metrics. Nothing sensitive exists in this lane.
import { spawn } from 'node:child_process';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [command, ...rest] = process.argv.slice(2);
const fail = message => { console.error(`zot: ${message}`); process.exit(1); };

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); });
  });
}

async function start(binary, stateDir) {
  if (!binary || !stateDir) fail('usage: zot.mjs start <zot-binary> <state-dir>');
  await mkdir(join(stateDir, 'data'), { recursive: true });
  const port = await freePort();
  const config = {
    distSpecVersion: '1.1.1',
    storage: { rootDirectory: join(stateDir, 'data'), gc: false, dedupe: true },
    http: { address: '127.0.0.1', port: String(port) },
    log: { level: 'warn', output: join(stateDir, 'zot.log') }
  };
  await writeFile(join(stateDir, 'config.json'), JSON.stringify(config, null, 2));
  const child = spawn(binary, ['serve', join(stateDir, 'config.json')], { detached: true, stdio: ['ignore', 'ignore', 'ignore'] });
  child.unref();
  const origin = `http://127.0.0.1:${port}`;
  let exited = false;
  child.once('exit', () => { exited = true; });
  for (let attempt = 0; attempt < 240; attempt++) {
    if (exited) fail('zot exited before becoming ready');
    try {
      const res = await fetch(`${origin}/v2/`, { signal: AbortSignal.timeout(1000) });
      await res.arrayBuffer();
      if (res.status === 200) {
        console.log(`zot ready at ${origin}/v2/ after ${attempt + 1} probe(s); pid ${child.pid}; storage under ${stateDir}`);
        if (process.env.GITHUB_ENV) await writeFile(process.env.GITHUB_ENV, `OWA_TEST_OCI_REGISTRY=${origin}\nOWA_CI_ZOT_PID=${child.pid}\nOWA_CI_ZOT_STATE=${stateDir}\n`, { flag: 'a' });
        await writeFile(join(stateDir, 'registry.json'), JSON.stringify({ origin, pid: child.pid }));
        return;
      }
    } catch {}
    await sleep(250);
  }
  fail('zot did not answer GET /v2/ with 200 within 60 s');
}

function alive() {
  const pid = Number(process.env.OWA_CI_ZOT_PID);
  if (!pid) fail('OWA_CI_ZOT_PID is not set');
  try { process.kill(pid, 0); } catch { fail(`zot (pid ${pid}) exited before controlled shutdown`); }
  console.log(`zot (pid ${pid}) is still running`);
}

async function stop(stateDir) {
  const pid = Number(process.env.OWA_CI_ZOT_PID);
  if (pid) {
    try { process.kill(pid, 'SIGTERM'); } catch {}
    for (let i = 0; i < 40; i++) { try { process.kill(pid, 0); } catch { break; } await sleep(250); }
    try { process.kill(pid, 'SIGKILL'); } catch {}
    console.log(`zot (pid ${pid}) stopped`);
  }
  if (stateDir) { await rm(stateDir, { recursive: true, force: true }); console.log(`removed ${stateDir}`); }
}

if (command === 'start') await start(rest[0], rest[1]);
else if (command === 'alive') alive();
else if (command === 'stop') await stop(rest[0]);
else fail('usage: zot.mjs <start <zot-binary> <state-dir> | alive | stop <state-dir>>');
