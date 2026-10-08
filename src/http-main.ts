#!/usr/bin/env node
// Opt-in Streamable HTTP entrypoint. The stdio entrypoint (index.ts) stays the default.
import { buildHttpConfig, startHttpServer } from "./http.js";
import { buildRuntime, StartupError } from "./startup.js";

async function main(): Promise<void> {
  // HTTP settings are checked first, so a missing token fails before any database work.
  const cfg = buildHttpConfig(process.env);
  const rt = buildRuntime({ env: process.env, argv: process.argv.slice(2) });
  const running = await startHttpServer(rt, cfg);
  console.error(
    `astraeus-postgres-mcp HTTP ready on ${running.url}/mcp (policy ${rt.policy.hash}, audit ${rt.audit.path})`,
  );
  const shutdown = (): void => {
    void running
      .close()
      .then(() => rt.db.close())
      .finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err: unknown) => {
  const message = err instanceof StartupError ? err.message : `fatal: ${(err as Error).message}`;
  console.error(`astraeus-postgres-mcp-http: ${message}`);
  process.exit(1);
});
