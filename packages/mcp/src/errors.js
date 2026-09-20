import { CliError } from '../../cli/src/remote.js';

// Only this vocabulary, never exception messages/causes, reaches a peer.
export const ERRORS = Object.freeze({
  OWA_MCP_CONFIG: ['configuration', 'Invalid adapter configuration'],
  OWA_MCP_INVALID_INPUT: ['invalid_input', 'Invalid input'],
  OWA_MCP_INVALID_RESPONSE: ['invalid_response', 'Invalid control-plane response'],
  OWA_MCP_CONTROL_FAILED: ['control_plane', 'Control-plane request failed'],
  OWA_MCP_UPLOAD_FAILED: ['upload', 'Blob upload failed'],
  OWA_MCP_NETWORK_FAILED: ['network', 'Network request failed'],
  OWA_MCP_FAILED: ['internal', 'Operation failed'],
  OWA_AUTH_CONFIG: ['configuration', 'Invalid authentication configuration'],
  OWA_AUTH_INVALID_TOKEN: ['authentication', 'Invalid authentication token'],
  OWA_AUTH_INVALID_SIGNATURE: ['authentication', 'Invalid authentication signature'],
  OWA_AUTH_EXPIRED: ['authentication', 'Authentication token expired'],
  OWA_AUTH_MISSING: ['authentication', 'Authentication required'],
  OWA_AUTH_SITE: ['site_scope', 'Authentication does not permit this site'],
  OWA_AUTH_CAPABILITY: ['capability', 'Authentication does not permit this operation'],
  OWA_AUTH_DEV_ONLY: ['authentication', 'Development authentication requires a direct loopback connection']
});
const CLI_CODES = Object.freeze({
  OWA_CLI_CONFIG: 'OWA_MCP_CONFIG',
  OWA_CLI_INPUT: 'OWA_MCP_INVALID_INPUT',
  OWA_CLI_RESPONSE: 'OWA_MCP_INVALID_RESPONSE',
  OWA_CLI_GRANT: 'OWA_MCP_INVALID_RESPONSE',
  OWA_CLI_HTTP: 'OWA_MCP_CONTROL_FAILED',
  OWA_CLI_UPLOAD: 'OWA_MCP_UPLOAD_FAILED',
  OWA_CLI_NETWORK: 'OWA_MCP_NETWORK_FAILED',
  OWA_CLI_FAILED: 'OWA_MCP_FAILED'
});
const INPUT_CODES = new Set([
  'OWA_SYMLINK', 'OWA_INVALID_PATH', 'OWA_DUPLICATE_PATH',
  'OWA_INVALID_MANIFEST', 'OWA_MISSING_ENTRYPOINT', 'OWA_INVALID_SIZE',
  'ENOENT', 'ENOTDIR', 'EACCES', 'EPERM', 'ELOOP', 'ENAMETOOLONG',
  'EISDIR', 'EINVAL', 'EIO', 'EMFILE', 'ENFILE', 'ERR_FS_FILE_TOO_LARGE'
]);

export class AdapterError extends Error {
  constructor(code) {
    const safeCode = Object.hasOwn(ERRORS, code) ? code : 'OWA_MCP_FAILED';
    super(ERRORS[safeCode][1]);
    this.code = safeCode;
  }
}

export function safeError(error) {
  let code = 'OWA_MCP_FAILED';
  let status;
  if (error instanceof CliError) {
    code = Object.hasOwn(CLI_CODES, error.code) ? CLI_CODES[error.code]
      : Object.hasOwn(ERRORS, error.code) ? error.code : code;
    if (Number.isInteger(error.status) && error.status >= 100 && error.status <= 599) status = error.status;
  } else if (error instanceof AdapterError) {
    if (Object.hasOwn(ERRORS, error.code)) code = error.code;
  } else if (INPUT_CODES.has(error?.code)) {
    code = 'OWA_MCP_INVALID_INPUT';
  }
  const [category, message] = ERRORS[code];
  return { ok: false, error: { code, category, message, ...(status === undefined ? {} : { status }) } };
}

export function toolResult(structuredContent) {
  return {
    structuredContent,
    content: [{ type: 'text', text: JSON.stringify(structuredContent) }],
    ...(structuredContent.ok ? {} : { isError: true })
  };
}
