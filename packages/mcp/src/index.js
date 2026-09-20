#!/usr/bin/env node

// Dynamic import keeps missing-SDK/import failures out of stderr stack traces.
try {
  const { startStdio } = await import('./runtime.js');
  await startStdio();
} catch {
  process.stderr.write('owa-mcp: OWA_MCP_CONFIG: Unable to start adapter\n');
  process.exitCode = 1;
}
