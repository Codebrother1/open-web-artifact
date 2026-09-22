// Download the PINNED ORAS and Zot release assets from their official GitHub
// releases and verify each SHA-256 (asset AND the release's checksum file)
// BEFORE anything is extracted or made executable. Plain Node: no curl | sh, no
// third-party action, no package-manager channel.
//
//   node .github/scripts/oci-tools.mjs <dest-dir>
//
// Prints the versions each tool reports and, inside Actions, a `::notice` so the
// exact tool identities are readable on the public run page. Exit 1 on any
// mismatch or failure; nothing is run before its hash is verified.
import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);

export const ORAS = Object.freeze({
  version: 'v1.3.4',
  asset: 'oras_1.3.4_linux_amd64.tar.gz',
  assetSha256: 'f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454',
  checksums: 'oras_1.3.4_checksums.txt',
  checksumsSha256: '19d479e497fb5e30c7de3c621e3ed337e3857de0d96542021a73e2d8016dbe5a',
  base: 'https://github.com/oras-project/oras/releases/download/v1.3.4/'
});
export const ZOT = Object.freeze({
  version: 'v2.1.21',
  asset: 'zot-linux-amd64',
  assetSha256: '8751cc0daf739634835a3bd8206e3094c84d552e2c462e4a4baf80f40dd92685',
  checksums: 'checksums.sha256.txt',
  checksumsSha256: 'dc91ac8283cc04f778d642aa4b51d46e6a1e4b05205825256291d05159cf4755',
  base: 'https://github.com/project-zot/zot/releases/download/v2.1.21/'
});

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = message => { console.error(`oci-tools: ${message}`); process.exit(1); };

async function download(url) {
  const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(600_000) });
  if (!res.ok) fail(`download failed: HTTP ${res.status} for ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

/** Fetch asset + checksum file; verify both hashes and that the file lists the asset hash. */
async function fetchVerified(tool, dest) {
  const asset = await download(tool.base + tool.asset);
  const actual = sha256(asset);
  if (actual !== tool.assetSha256) fail(`${tool.asset}: sha256 ${actual} does not match the pinned ${tool.assetSha256}`);
  const checksums = await download(tool.base + tool.checksums);
  const checksumsActual = sha256(checksums);
  if (checksumsActual !== tool.checksumsSha256) fail(`${tool.checksums}: sha256 ${checksumsActual} does not match the pinned ${tool.checksumsSha256}`);
  const listed = checksums.toString('utf8').split('\n').some(line => {
    const [hash, name] = line.trim().split(/\s+\*?/);
    return hash === tool.assetSha256 && name === tool.asset;
  });
  if (!listed) fail(`${tool.checksums} does not list ${tool.assetSha256} for ${tool.asset}`);
  const path = join(dest, tool.asset);
  await writeFile(path, asset);
  console.log(`verified ${tool.asset} sha256 ${actual} (listed in ${tool.checksums} sha256 ${checksumsActual})`);
  return path;
}

async function main() {
  const dest = process.argv[2];
  if (!dest) fail('usage: oci-tools.mjs <dest-dir>');
  await mkdir(dest, { recursive: true });

  const orasArchive = await fetchVerified(ORAS, dest);
  const orasDir = join(dest, 'oras');
  await mkdir(orasDir, { recursive: true });
  await run('tar', ['-xzf', orasArchive, '-C', orasDir]);
  const orasBin = join(orasDir, 'oras');
  await chmod(orasBin, 0o755);
  const { stdout: orasVersion } = await run(orasBin, ['version']);
  const orasLine = orasVersion.split('\n').map(l => l.trim()).filter(Boolean).join('; ');
  if (!/Version:\s+1\.3\.4/.test(orasVersion)) fail(`oras reported an unexpected version: ${orasLine}`);

  const zotBin = await fetchVerified(ZOT, dest);
  await chmod(zotBin, 0o755); // only after the hash matched
  const { stdout: zotOut, stderr: zotErr } = await run(zotBin, ['--version']);
  const zotVersion = (zotOut + zotErr).split('\n').find(l => l.includes('"version"')) ?? (zotOut + zotErr).trim();
  let zotCommit = 'unknown';
  try { zotCommit = JSON.parse(zotVersion).commit ?? zotCommit; } catch {}
  if (!zotCommit.startsWith('v2.1.21')) fail(`zot reported an unexpected version: ${zotCommit}`);

  console.log(`oras: ${orasLine}`);
  console.log(`zot: commit ${zotCommit} (${zotBin})`);
  if (process.env.GITHUB_ENV) {
    // OWA_TEST_ZOT_BIN lets the authenticated HTTPS proof start its own disposable Zot (issue #46).
    await writeFile(process.env.GITHUB_ENV, `OWA_TEST_ORAS_BIN=${orasBin}\nOWA_CI_ZOT_BIN=${zotBin}\nOWA_TEST_ZOT_BIN=${zotBin}\n`, { flag: 'a' });
  }
  if (process.env.GITHUB_ACTIONS === 'true') {
    const escape = value => String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
    console.log(`::notice title=oci tools::${escape(`ORAS ${ORAS.version} (${ORAS.asset} sha256 ${ORAS.assetSha256}; ${orasLine}); Zot ${ZOT.version} (${ZOT.asset} sha256 ${ZOT.assetSha256}; ${zotCommit})`)}`);
  }
  // Make the verified paths available to a caller that sources them.
  await writeFile(join(dest, 'tools.json'), JSON.stringify({ oras: orasBin, zot: zotBin, orasVersion: orasLine, zotCommit }, null, 2));
}

await main();
