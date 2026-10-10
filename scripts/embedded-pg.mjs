// Starts a throwaway real PostgreSQL from npm (embedded-postgres), seeds it with
// smoke/seed.sql and gives the agent role a random password. No Docker needed.
// Used by `npm run smoke` and by the integration suite (tests/integration).
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import EmbeddedPostgres from "embedded-postgres";
import pg from "pg";

const here = dirname(fileURLToPath(import.meta.url));
export const SEED_SQL_PATH = join(here, "..", "smoke", "seed.sql");
export const AGENT_ROLE = "astraeus_agent";

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const address = srv.address();
      srv.close(() => resolve(address.port));
    });
  });
}

function secret() {
  return randomBytes(18).toString("base64url");
}

/**
 * @param {{ log?: boolean }} [opts]
 * @returns {Promise<{ adminDsn: string, agentDsn: string, agentPassword: string, port: number, version: string, stop: () => Promise<void> }>}
 */
export async function startEmbeddedPostgres(opts = {}) {
  const port = await freePort();
  const adminPassword = secret();
  const agentPassword = secret();
  const workDir = mkdtempSync(join(tmpdir(), "apm-pg-"));
  const databaseDir = join(workDir, "data");
  const quiet = () => undefined;
  const server = new EmbeddedPostgres({
    databaseDir,
    port,
    user: "postgres",
    password: adminPassword,
    authMethod: "scram-sha-256",
    persistent: false,
    initdbFlags: ["--encoding=UTF8"],
    postgresFlags: ["-c", "listen_addresses=127.0.0.1"],
    onLog: opts.log ? console.error : quiet,
    onError: opts.log ? console.error : quiet,
  });
  await server.initialise();
  await server.start();
  const stop = async () => {
    await server.stop();
    try {
      rmSync(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      // Best effort: the data lives under the OS temp directory either way.
    }
  };
  try {
    await server.createDatabase("appdb");
    const adminDsn = `postgresql://postgres:${encodeURIComponent(adminPassword)}@127.0.0.1:${port}/appdb`;
    const admin = new pg.Client({ connectionString: adminDsn });
    await admin.connect();
    try {
      await admin.query(readFileSync(SEED_SQL_PATH, "utf8"));
      await admin.query(`alter role ${AGENT_ROLE} password ${admin.escapeLiteral(agentPassword)}`);
      const version = (await admin.query("show server_version")).rows[0].server_version;
      const agentDsn = `postgresql://${AGENT_ROLE}:${encodeURIComponent(agentPassword)}@127.0.0.1:${port}/appdb`;
      return { adminDsn, agentDsn, agentPassword, port, version, stop };
    } finally {
      await admin.end();
    }
  } catch (err) {
    await stop().catch(() => undefined);
    throw err;
  }
}
