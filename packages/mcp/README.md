# Optional OWA MCP adapter

Local stdio tools over the authoritative OWA HTTP API: `publish`, `list_releases`,
`activate`, and explicit-release `rollback`. Requires Node.js 22+.

See the [MCP guide](../../docs/mcp.md) for installation, client configuration,
secret injection, exact inputs/results, capabilities, errors, and trust limits.
The [complete tool schemas](tool-schemas.json) are checked against runtime discovery.

From the repository root:

```bash
npm --prefix packages/mcp ci --ignore-scripts
npm run test:mcp
```

Use `--omit=dev` for runtime-only installation (not tests). The client launches
`node /absolute/repo/packages/mcp/src/index.js` directly; stdout is protocol-only.
Set `OWA_MCP_SERVER` and `OWA_MCP_ROOT`, and securely inject `OWA_TOKEN` for
required-auth servers. Never pass a token as a tool argument or supply the server
signing secret. Read the guide before choosing the staging root or trusted origin.
