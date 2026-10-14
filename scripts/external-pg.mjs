// Prepares an EXTERNAL, disposable PostgreSQL for the integration suite, for example the
// Docker service container in CI. The admin URL comes from APM_TEST_PG_ADMIN_URL and must
// point at an EMPTY database named appdb that nothing else uses: the seed creates tables
// and the astraeus_agent role there. Test harness only; the server never reads this.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { AGENT_ROLE, SEED_SQL_PATH } from "./embedded-pg.mjs";

/**
 * @param {string} adminUrl
 * @returns {Promise<{ adminDsn: string, agentDsn: string, agentPassword: string, port: number, version: string, stop: () => Promise<void> }>}
 */
export async function prepareExternalPostgres(adminUrl) {
  const url = new URL(adminUrl);
  if (url.pathname !== "/appdb") {
    throw new Error("APM_TEST_PG_ADMIN_URL must name the database appdb (the seed grants on it by name)");
  }
  const agentPassword = randomBytes(18).toString("base64url");
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    const existing = await admin.query("select 1 from pg_roles where rolname = $1", [AGENT_ROLE]);
    if (existing.rowCount !== 0) {
      throw new Error(`role ${AGENT_ROLE} already exists: point APM_TEST_PG_ADMIN_URL at a fresh, disposable server`);
    }
    await admin.query(readFileSync(SEED_SQL_PATH, "utf8"));
    await admin.query(`alter role ${AGENT_ROLE} password ${admin.escapeLiteral(agentPassword)}`);
    const version = (await admin.query("show server_version")).rows[0].server_version;
    const agent = new URL(adminUrl);
    agent.username = AGENT_ROLE;
    agent.password = agentPassword;
    return {
      adminDsn: adminUrl,
      agentDsn: agent.toString(),
      agentPassword,
      port: Number(url.port || 5432),
      version,
      // The container is thrown away with the job, so there is nothing to stop.
      stop: async () => undefined,
    };
  } finally {
    await admin.end();
  }
}
