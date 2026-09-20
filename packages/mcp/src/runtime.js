import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { createAdapter } from './adapter.js';
import { safeTransport } from './transport.js';

export async function startStdio() {
  const server = await createAdapter();
  const report = () => process.stderr.write('owa-mcp: OWA_MCP_FAILED: Protocol operation failed\n');
  server.onerror = report;
  const onEnd = () => { void server.close().catch(report); };
  server.onclose = () => process.stdin.off('end', onEnd);
  process.stdin.once('end', onEnd);
  // Direct official SDK connection negotiates initialize with deployed clients.
  // The public adapter strips diagnostics; the SDK owns all protocol framing.
  await server.connect(safeTransport(new StdioServerTransport()));
  if (process.stdin.readableEnded) onEnd();
  return server;
}
