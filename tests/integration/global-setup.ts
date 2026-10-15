import type { TestProject } from "vitest/node";
import { startEmbeddedPostgres } from "../../scripts/embedded-pg.mjs";
import { prepareExternalPostgres } from "../../scripts/external-pg.mjs";

declare module "vitest" {
  export interface ProvidedContext {
    pg: { adminDsn: string; agentDsn: string; agentPassword: string; version: string };
  }
}

/**
 * One throwaway PostgreSQL for the whole integration run. By default an embedded one
 * (no Docker). With APM_TEST_PG_ADMIN_URL set (CI uses a Docker service container), an
 * external disposable server is seeded instead.
 */
export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const started = Date.now();
  const external = process.env.APM_TEST_PG_ADMIN_URL;
  const db = external
    ? await prepareExternalPostgres(external)
    : await startEmbeddedPostgres({ log: process.env.APM_PG_LOG === "1" });
  const kind = external ? "external" : "embedded";
  console.error(`${kind} PostgreSQL ${db.version} ready on port ${db.port} in ${Date.now() - started} ms`);
  project.provide("pg", { adminDsn: db.adminDsn, agentDsn: db.agentDsn, agentPassword: db.agentPassword, version: db.version });
  return async () => {
    await db.stop();
  };
}
