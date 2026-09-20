import { lstat, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { Server } from '@modelcontextprotocol/server';
import {
  remotePublishResult, remoteReleasesResult, remoteActivateResult, validateRemoteServer
} from '../../cli/src/remote.js';
import { AdapterError, safeError, toolResult } from './errors.js';
import { TOOLS, SITE_PATTERN, RELEASE_PATTERN } from './schemas.js';
import { containsSensitiveText } from './transport.js';

const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const isSite = value => typeof value === 'string' && new RegExp(SITE_PATTERN).test(value);
const isRelease = value => typeof value === 'string' && new RegExp(RELEASE_PATTERN).test(value);
const isDirectoryInput = value => typeof value === 'string' && value.length >= 1 && value.length <= 4096
  && !/[\u0000-\u001f\u007f-\u009f]/.test(value)
  && (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(value) || (isAbsolute(value) && /^[A-Za-z]:[\\/]/.test(value)));
const inside = (root, path) => {
  const child = relative(root, path);
  return child === '' || (child !== '..' && !child.startsWith(`..${sep}`) && !isAbsolute(child));
};
const invalidInput = () => new AdapterError('OWA_MCP_INVALID_INPUT');

// env is an operator configuration source, not a tool argument. Authentication
// always stays in the shared client's process.env.OWA_TOKEN path.
export async function readConfig(env = process.env) {
  try {
    if (typeof env.OWA_MCP_SERVER !== 'string' || env.OWA_MCP_SERVER.length > 2048
      || !isDirectoryInput(env.OWA_MCP_ROOT) || !isAbsolute(env.OWA_MCP_ROOT)) {
      throw new AdapterError('OWA_MCP_CONFIG');
    }
    const server = validateRemoteServer(env.OWA_MCP_SERVER); // Network-free.
    const selected = resolve(env.OWA_MCP_ROOT);
    const info = await lstat(selected);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new AdapterError('OWA_MCP_CONFIG');
    const root = await realpath(selected);
    return Object.freeze({ server, root });
  } catch {
    throw new AdapterError('OWA_MCP_CONFIG');
  }
}

export async function resolveDirectory(directory, root) {
  try {
    if (!isDirectoryInput(directory)) throw invalidInput();
    const selected = resolve(root, directory);
    const info = await lstat(selected);
    if (info.isSymbolicLink() || !info.isDirectory()) throw invalidInput();
    const canonical = await realpath(selected);
    if (!inside(root, canonical)) throw invalidInput();
    return canonical;
  } catch {
    throw invalidInput();
  }
}

function validateArguments(tool, args, config) {
  if (!isRecord(args) || Object.keys(args).some(key => !Object.hasOwn(tool.inputSchema.properties, key))
    || tool.inputSchema.required.some(key => !Object.hasOwn(args, key)) || !isSite(args.site)
    || typeof args.server !== 'string' || args.server.length < 1 || args.server.length > 2048) throw invalidInput();
  if (tool.name === 'publish') {
    if (!isDirectoryInput(args.directory)
      || (Object.hasOwn(args, 'activate') && typeof args.activate !== 'boolean')) throw invalidInput();
  } else if (tool.name !== 'list_releases' && !isRelease(args.releaseId)) throw invalidInput();

  // Trust origin equality MUST precede filesystem packing and every HTTP call.
  // Canonicalization is the exact hardened CLI validator, not another client.
  let origin;
  try { origin = validateRemoteServer(args.server); } catch { throw invalidInput(); }
  if (origin !== config.server) throw invalidInput();
}

export async function createAdapter(env = process.env) {
  const config = await readConfig(env);
  const server = new Server({ name: 'owa-mcp', version: '0.3.0' }, { capabilities: { tools: {} } });
  const tools = new Map(TOOLS.map(tool => [tool.name, tool]));
  server.setRequestHandler('tools/list', () => ({ tools: structuredClone(TOOLS) }));
  server.setRequestHandler('tools/call', async request => {
    try {
      const params = request.params;
      const tool = tools.get(params?.name);
      if (!tool || !isRecord(params)
        || Object.keys(params).some(key => !['name', 'arguments', '_meta'].includes(key))) throw invalidInput();
      const args = params.arguments;
      validateArguments(tool, args, config);
      let fields;
      if (tool.name === 'publish') {
        // This is containment checking, NOT a race-proof sandbox. Operators must
        // stage a trusted read-only tree during packing. Hard links/concurrent
        // writers are not defended. The unchanged packer rejects child symlinks.
        const directory = await resolveDirectory(args.directory, config.root);
        fields = await remotePublishResult(directory, args.site, config.server, { activate: args.activate ?? true });
        fields = { ...fields, url: `${config.server}/?site=${args.site}` };
      } else if (tool.name === 'list_releases') {
        fields = await remoteReleasesResult(args.site, config.server);
      } else {
        // rollback is an alias with an EXPLICIT release, not a read/select flow.
        fields = await remoteActivateResult(args.releaseId, args.site, config.server);
      }
      const result = { ok: true, ...fields };
      if (containsSensitiveText(JSON.stringify(result))) throw new AdapterError('OWA_MCP_INVALID_RESPONSE');
      return server.projectCallToolResult(toolResult(result), tool.outputSchema);
    } catch (error) {
      return toolResult(safeError(error));
    }
  });
  return server;
}
