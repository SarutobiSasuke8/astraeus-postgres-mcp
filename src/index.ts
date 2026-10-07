#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./server.js";
import { buildRuntime, StartupError } from "./startup.js";

async function main(): Promise<void> {
  const rt = buildRuntime({ env: process.env, argv: process.argv.slice(2) });
  const server = createServer(rt);
  await server.connect(new StdioServerTransport());
  // stdout carries the MCP protocol, so diagnostics go to stderr only.
  console.error(`astraeus-postgres-mcp ready (policy ${rt.policy.hash}, audit ${rt.audit.path})`);
  const shutdown = (): void => {
    void rt.db.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err: unknown) => {
  const message = err instanceof StartupError ? err.message : `fatal: ${(err as Error).message}`;
  console.error(`astraeus-postgres-mcp: ${message}`);
  process.exit(1);
});
