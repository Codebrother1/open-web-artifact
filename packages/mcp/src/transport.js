// This is a public Transport adapter, not a framing/parser implementation.
// StdioServerTransport alone reads, validates and serializes JSON-RPC frames.
// Diagnostic detail is intentionally lost at this boundary.
export function containsSensitiveText(value) {
  const token = process.env.OWA_TOKEN;
  return typeof value === 'string' && ((Boolean(token) && value.includes(token))
    || /owa1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(value));
}

const PROTOCOL_MESSAGES = new Map([
  [-32700, 'Parse error'],
  [-32600, 'Invalid request'],
  [-32601, 'Method not found'],
  [-32602, 'Invalid parameters'],
  [-32603, 'Internal error']
]);
const protocolError = (id, code) => ({
  jsonrpc: '2.0', id,
  error: { code, message: PROTOCOL_MESSAGES.get(code) }
});

export function safeTransport(inner) {
  const transport = {
    onmessage: undefined,
    onerror: undefined,
    onclose: undefined,
    async start() {
      inner.onmessage = message => {
        // Secret-bearing ids cannot be echoed for correlation. Reject before
        // dispatch (and any mutation), using the JSON-RPC invalid-request id.
        if (containsSensitiveText(message.id)) {
          void transport.send(protocolError(null, -32600)).catch(() => {
            transport.onerror?.(new Error('MCP transport error'));
          });
          return;
        }
        transport.onmessage?.(message);
      };
      inner.onerror = () => transport.onerror?.(new Error('MCP transport error'));
      inner.onclose = () => transport.onclose?.();
      await inner.start();
    },
    async close() { await inner.close(); },
    async send(message) {
      const id = typeof message.id === 'string' || typeof message.id === 'number' ? message.id : null;
      let safe = message;
      if (containsSensitiveText(id)) {
        safe = protocolError(null, -32600);
      } else if (Object.hasOwn(message, 'error')) {
        const code = PROTOCOL_MESSAGES.has(message.error?.code) ? message.error.code : -32603;
        // Drop ALL SDK/provider text, data, and extra envelope members.
        safe = protocolError(id, code);
      }
      // Last defense for success/metadata paths as well as protocol errors.
      // This scan is only in memory, never logged or persisted.
      if (containsSensitiveText(JSON.stringify(safe))) {
        safe = protocolError(containsSensitiveText(id) ? null : id, -32603);
      }
      await inner.send(safe);
    }
  };
  return transport;
}
