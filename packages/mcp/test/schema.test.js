import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { TOOLS } from '../src/schemas.js';

test('published tool schema snapshot matches the exact runtime discovery surface', async () => {
  const snapshot = JSON.parse(await readFile(new URL('../tool-schemas.json', import.meta.url), 'utf8'));
  assert.deepEqual(snapshot, { tools: TOOLS });
});

test('directory schema permits native path forms but rejects URL and control-character inputs', () => {
  const schema = TOOLS.find(tool => tool.name === 'publish').inputSchema.properties.directory;
  const pattern = new RegExp(schema.pattern);
  for (const input of ['site', '.', '/staging/site', 'C:\\staging\\site', 'C:/staging/site']) {
    assert.equal(pattern.test(input), true, 'native path spelling must not be mistaken for a URL');
  }
  for (const input of ['file:///staging/site', 'https://example.invalid/site', 'data:text/plain,a', 'site\0', 'site\n', 'site\t']) {
    assert.equal(pattern.test(input), false, 'URL/control-character input must be rejected');
  }
  // Syntax alone does not grant filesystem access. Realpath containment and
  // existence are separately tested through the running MCP server.
  assert.equal(schema.maxLength, 4096);
});
