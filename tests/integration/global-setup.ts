import type { TestProject } from "vitest/node";
import { startEmbeddedPostgres } from "../../scripts/embedded-pg.mjs";

declare module "vitest" {
  export interface ProvidedContext {
    pg: { adminDsn: string; agentDsn: string; agentPassword: string; version: string };
  }
}

/** One throwaway embedded PostgreSQL for the whole integration run. No Docker. */
export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const started = Date.now();
  const db = await startEmbeddedPostgres({ log: process.env.APM_PG_LOG === "1" });
  console.error(`embedded PostgreSQL ${db.version} ready on 127.0.0.1:${db.port} in ${Date.now() - started} ms`);
  project.provide("pg", { adminDsn: db.adminDsn, agentDsn: db.agentDsn, agentPassword: db.agentPassword, version: db.version });
  return async () => {
    await db.stop();
  };
}
