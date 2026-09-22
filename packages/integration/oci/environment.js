// Test-only environment contract for the live OCI registry suites (issues #23, #9, #46).
//
//   OWA_TEST_OCI_REGISTRY   plain-HTTP loopback registry origin, e.g. http://127.0.0.1:5000
//   OWA_TEST_ORAS_BIN       absolute path to the pinned ORAS CLI executable
//   OWA_TEST_ZOT_BIN        absolute path to the pinned Zot executable (the authenticated
//                           HTTPS proof starts its own disposable registry from it)
//   OWA_TEST_OCI_REQUIRED   "1" → every missing prerequisite is a FAILURE, never a skip
//
// Unconfigured local runs skip cleanly. CI sets OWA_TEST_OCI_REQUIRED=1 so a
// missing ORAS binary, a missing registry, an unready registry or any failing
// ORAS command fails the job instead of turning it green by skipping. This is
// deliberately NOT the S3 providerConfiguration() helper: an OCI registry is not
// an S3 provider, and the prerequisites (an external executable, a registry
// readiness probe) are different in kind.
import { access, constants } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { whichOnPath } from './tls-registry.js';

export const REQUIRED_ENV = 'OWA_TEST_OCI_REQUIRED';

export function isRequired(env = process.env) {
  return env[REQUIRED_ENV] === '1';
}

/**
 * Resolve the suite's prerequisites from the environment.
 * Returns { skip } when unconfigured and not required, { fail } when required
 * but unusable, or { registry, oras, required } when everything is present.
 * Messages carry variable NAMES and safe facts only.
 */
export async function ociEnvironment(env = process.env) {
  const required = isRequired(env);
  const problems = [];
  const missing = ['OWA_TEST_OCI_REGISTRY', 'OWA_TEST_ORAS_BIN'].filter(name => !env[name]);
  if (missing.length) {
    const message = `set ${missing.join(', ')}`;
    return required ? { fail: `${REQUIRED_ENV}=1 but ${message}: the OCI registry suite must run, not skip` } : { skip: message };
  }
  let registry;
  try {
    registry = new URL(env.OWA_TEST_OCI_REGISTRY);
    // Loopback, plain HTTP, origin only: this suite never talks to a hosted registry.
    if (registry.protocol !== 'http:') problems.push('OWA_TEST_OCI_REGISTRY must use plain http:// (loopback interoperability only)');
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(registry.hostname)) problems.push('OWA_TEST_OCI_REGISTRY must be a loopback host');
    if (registry.pathname !== '/' || registry.search || registry.hash || registry.username || registry.password) problems.push('OWA_TEST_OCI_REGISTRY must be a bare origin');
  } catch {
    problems.push('OWA_TEST_OCI_REGISTRY is not a valid URL');
  }
  const oras = env.OWA_TEST_ORAS_BIN;
  if (!isAbsolute(oras)) problems.push('OWA_TEST_ORAS_BIN must be an absolute path');
  else {
    try { await access(oras, constants.X_OK); } catch { problems.push('OWA_TEST_ORAS_BIN is not an executable file'); }
  }
  if (problems.length) {
    const message = problems.join('; ');
    return required ? { fail: `${REQUIRED_ENV}=1 but ${message}` } : { skip: message };
  }
  return { required, registry: registry.origin, registryHost: registry.host, oras };
}

/**
 * Prerequisites of the authenticated HTTPS proof (issue #46), which starts its
 * OWN disposable Zot: the pinned ORAS and Zot executables, plus `openssl` (test
 * CA and server certificate) and `perl` (bcrypt htpasswd entry through the
 * platform crypt(3)) on PATH. Same contract: skip when unconfigured, FAIL when
 * required. Messages carry variable/tool NAMES and safe facts only.
 */
export async function tlsEnvironment(env = process.env) {
  const required = isRequired(env);
  const missing = ['OWA_TEST_ORAS_BIN', 'OWA_TEST_ZOT_BIN'].filter(name => !env[name]);
  if (missing.length) {
    const message = `set ${missing.join(', ')}`;
    return required ? { fail: `${REQUIRED_ENV}=1 but ${message}: the authenticated HTTPS OCI suite must run, not skip` } : { skip: message };
  }
  const problems = [];
  for (const name of ['OWA_TEST_ORAS_BIN', 'OWA_TEST_ZOT_BIN']) {
    const path = env[name];
    if (!isAbsolute(path)) { problems.push(`${name} must be an absolute path`); continue; }
    try { await access(path, constants.X_OK); } catch { problems.push(`${name} is not an executable file`); }
  }
  const tools = {};
  for (const tool of ['openssl', 'perl']) {
    tools[tool] = await whichOnPath(tool, env);
    if (!tools[tool]) problems.push(`${tool} must be on PATH (${tool === 'openssl' ? 'test CA and server certificate' : 'bcrypt htpasswd entry through crypt(3)'})`);
  }
  if (problems.length) {
    const message = problems.join('; ');
    return required ? { fail: `${REQUIRED_ENV}=1 but ${message}` } : { skip: message };
  }
  return { required, oras: env.OWA_TEST_ORAS_BIN, zot: env.OWA_TEST_ZOT_BIN, openssl: tools.openssl, perl: tools.perl };
}
