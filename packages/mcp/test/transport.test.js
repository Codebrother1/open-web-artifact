import test from 'node:test';
import assert from 'node:assert/strict';
import { safeTransport } from '../src/transport.js';

function withToken(t) {
  const previous = process.env.OWA_TOKEN;
  // A process-injected opaque canary exercises exact-value screening separately
  // from the completed owa1 pattern. It is not a real credential.
  const token = Buffer.from('opaque-process-canary').toString('base64url');
  process.env.OWA_TOKEN = token;
  t.after(() => {
    if (previous === undefined) delete process.env.OWA_TOKEN;
    else process.env.OWA_TOKEN = previous;
  });
  return token;
}

function wire() {
  const messages = [];
  const inner = { async start() {}, async close() {}, async send(message) { messages.push(message); } };
  return { inner, messages, transport: safeTransport(inner) };
}

test('public transport boundary rejects a non-owa process-token ID before dispatch', async t => {
  const token = withToken(t);
  const { inner, messages, transport } = wire();
  let dispatched = 0;
  transport.onmessage = () => { dispatched++; };
  await transport.start();
  inner.onmessage({ jsonrpc: '2.0', id: token, method: 'tools/call', params: {} });
  await Promise.resolve();
  assert.equal(dispatched, 0);
  assert.ok(messages.length === 1 && messages[0].id === null && messages[0].error.code === -32600);
  assert.ok(!JSON.stringify(messages).includes(token), 'process credential must not be reflected');
  inner.onmessage({ jsonrpc: '2.0', id: 'ordinary-id', method: 'ping' });
  assert.equal(dispatched, 1, 'ordinary string IDs retain interoperability');
});

test('public transport boundary removes a process token from outgoing successful metadata', async t => {
  const token = withToken(t);
  const { messages, transport } = wire();
  await transport.send({ jsonrpc: '2.0', id: 42, result: { extra: token } });
  assert.ok(messages.length === 1 && messages[0].id === 42 && messages[0].error.code === -32603);
  assert.ok(!JSON.stringify(messages).includes(token), 'success metadata must not bypass screening');
  assert.ok(!Object.hasOwn(messages[0].error, 'data'));
});
