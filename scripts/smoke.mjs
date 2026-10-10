// End-to-end smoke test. `npm run smoke` builds first, then:
//   default:            starts a throwaway embedded PostgreSQL from npm (no Docker), seeded from smoke/seed.sql
//   SMOKE_TARGET=docker: uses the docker-compose Postgres instead (needs SMOKE_PG_AGENT_PASSWORD)
// It proves the role's limits with a raw connection (no guard), then drives the real
// server over stdio and over the opt-in Streamable HTTP entrypoint.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import pg from "pg";

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : `  ${String(detail).slice(0, 400)}`}`);
  if (!ok) failures += 1;
}

let dsn;
let secretsToHide;
let stopDb = async () => undefined;
if (process.env.SMOKE_TARGET === "docker") {
  const password = process.env.SMOKE_PG_AGENT_PASSWORD;
  if (!password) {
    console.error("SMOKE_TARGET=docker needs SMOKE_PG_AGENT_PASSWORD (the value given to docker compose).");
    process.exit(2);
  }
  dsn = `postgresql://astraeus_agent:${encodeURIComponent(password)}@127.0.0.1:54329/appdb`;
  secretsToHide = [password];
  console.log("target: docker-compose PostgreSQL on 127.0.0.1:54329");
} else {
  const { startEmbeddedPostgres } = await import("./embedded-pg.mjs");
  const started = Date.now();
  const db = await startEmbeddedPostgres();
  dsn = db.agentDsn;
  secretsToHide = [db.agentPassword];
  stopDb = db.stop;
  console.log(`target: embedded PostgreSQL ${db.version} (npm embedded-postgres, no Docker), started in ${Date.now() - started} ms`);
}

const auditPath = join(mkdtempSync(join(tmpdir(), "apm-smoke-")), "audit.jsonl");
const POLICY = "smoke/policy.smoke.yaml";

try {
  // 1. Raw connection as the agent role. The guard is not involved at all.
  console.log("\n-- database role, guard bypassed --");
  const direct = new pg.Client({ connectionString: dsn });
  await direct.connect();
  const attempt = async (sql) => {
    try {
      await direct.query(sql);
      return "allowed";
    } catch (err) {
      return err.code;
    }
  };
  check("role cannot read customers.email (42501)", (await attempt("select email from customers")) === "42501");
  check("role cannot read secrets (42501)", (await attempt("select * from secrets")) === "42501");
  check("role is read-only by default (25006)", (await attempt("insert into orders (customer_id,total_cents,status,tenant_id) values (1,1,'x',1)")) === "25006");
  await direct.query("set default_transaction_read_only = off");
  const writes = [
    "insert into orders (customer_id,total_cents,status,tenant_id) values (1,1,'x',1)",
    "update customers set name = 'x'",
    "delete from orders",
    "truncate orders",
    "create temporary table t (x int)",
    "create table public.t (x int)",
  ];
  const writeCodes = [];
  for (const sql of writes) writeCodes.push(await attempt(sql));
  check("role has no write or create grants with read-only off (all 42501)", writeCodes.every((c) => c === "42501"), writeCodes.join(","));
  await direct.query("reset default_transaction_read_only");
  const rls = (await direct.query("select count(*)::int as n from orders")).rows[0].n;
  check("role-bound RLS limits orders to the agent tenant (7 of 10)", rls === 7, rls);
  check("role cannot switch role", (await attempt("set role postgres")) === "42501");
  await direct.end();

  // 2. The real server over stdio.
  console.log("\n-- MCP over stdio --");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["dist/index.js", "--policy", POLICY],
    env: { PATH: process.env.PATH ?? "", SYSTEMROOT: process.env.SYSTEMROOT ?? "", DATABASE_URL: dsn, ASTRAEUS_AUDIT_PATH: auditPath },
    stderr: "ignore",
  });
  const client = new Client({ name: "smoke", version: "0.0.0" });
  await client.connect(transport);
  const call = async (c, name, args = {}) => {
    const res = await c.callTool({ name, arguments: args });
    const text = res.content[0]?.text ?? "{}";
    return { error: res.isError === true, body: JSON.parse(text), text };
  };

  const tools = (await client.listTools()).tools.map((t) => t.name).sort();
  check("tools listed", tools.join(",") === "describe_table,list_tables,ping,policy_info,query,run_view", tools.join(","));
  check("ping ok", (await call(client, "ping")).body.status === "ok");
  const desc = await call(client, "describe_table", { table: "customers" });
  check("describe_table hides email", !desc.text.includes("email"));
  const all = await call(client, "query", { sql: "select id, name, billing_phone from customers order by id limit 1000" });
  check("row cap enforced (5)", all.body.row_count === 5 && all.body.limit_clamped === true, all.text);
  check("phone redacted", all.body.rows?.every((r) => r.billing_phone === "[REDACTED]") && !all.text.includes("555 01"));
  const count = await call(client, "query", { sql: "select count(*) as n from customers" });
  check("require_predicate hides soft-deleted row (7)", String(count.body.rows?.[0]?.n) === "7", count.text);
  check("email denied", (await call(client, "query", { sql: "select email from customers" })).body.error === "column_not_allowed");
  check("secrets table denied", (await call(client, "query", { sql: "select * from secrets" })).body.error === "table_not_allowed");
  check("multi-statement denied", (await call(client, "query", { sql: "select 1; select 2" })).body.error === "multi_statement");
  check("delete denied", (await call(client, "query", { sql: "delete from customers" })).body.error === "non_read_statement");
  const join = await call(client, "query", { sql: "select count(*) as n from customers c join orders o on o.customer_id = c.id" });
  check("join applies predicate per table plus RLS (6)", String(join.body.rows?.[0]?.n) === "6", join.text);
  const left = await call(client, "query", { sql: "select count(*) as n, count(c.name) as named from orders o left join customers c on c.id = o.customer_id" });
  check("left join keeps the predicate on its own table (7 rows, 6 named)", left.body.rows?.[0]?.n === "7" && left.body.rows?.[0]?.named === "6", left.text);
  const masked = await call(client, "query", { sql: "select c.billing_phone as contact, o.status from customers c join orders o on o.customer_id = c.id" });
  check("mask survives alias across a join", masked.body.rows?.every((r) => r.contact === "[REDACTED]") && !masked.text.includes("555 01"), masked.text);
  check(
    "cross-schema join denied",
    (await call(client, "query", { sql: "select c.id from customers c join internal.staff_notes n on n.customer_id = c.id" })).body.error === "cross_schema_join",
  );
  check(
    "non-allowlisted join denied",
    (await call(client, "query", { sql: "select c.id from customers c join secrets s on s.id = c.id" })).body.error === "table_not_allowed",
  );
  const view = await call(client, "run_view", { name: "revenue_by_status", params: { since: "2026-09-01" } });
  check("named view runs with a typed parameter", view.body.row_count === 3 && view.body.rows?.[1]?.total_cents === "27300", view.text);
  const badView = await call(client, "run_view", { name: "customer_orders", params: { customer_id: "1; drop table orders" } });
  check("named view rejects a mistyped parameter", badView.body.error === "invalid_params", badView.text);
  await client.close();

  // 3. The opt-in Streamable HTTP entrypoint as a real process.
  console.log("\n-- MCP over Streamable HTTP --");
  const baseEnv = { PATH: process.env.PATH ?? "", SYSTEMROOT: process.env.SYSTEMROOT ?? "", DATABASE_URL: dsn, ASTRAEUS_AUDIT_PATH: auditPath };
  const noToken = await runToExit(["dist/http-main.js", "--policy", POLICY], baseEnv);
  check("HTTP entrypoint refuses to start without a token", noToken.code === 1 && /ASTRAEUS_HTTP_TOKEN is not set/.test(noToken.stderr), noToken.stderr);
  const publicHost = await runToExit(["dist/http-main.js", "--policy", POLICY], {
    ...baseEnv,
    ASTRAEUS_HTTP_TOKEN: randomBytes(24).toString("hex"),
    ASTRAEUS_HTTP_HOST: "0.0.0.0",
  });
  check("HTTP entrypoint refuses a non-loopback bind without opt-in", publicHost.code === 1, publicHost.stderr);

  const token = randomBytes(24).toString("hex");
  secretsToHide.push(token);
  const port = await freePort();
  const child = spawn(process.execPath, ["dist/http-main.js", "--policy", POLICY], {
    env: { ...baseEnv, ASTRAEUS_HTTP_TOKEN: token, ASTRAEUS_HTTP_PORT: String(port) },
    stdio: ["ignore", "ignore", "pipe"],
  });
  try {
    await waitFor(child, /HTTP ready/);
    const base = `http://127.0.0.1:${port}`;
    const health = await fetch(`${base}/health`);
    check("GET /health is 200 without a token", health.status === 200);
    const anon = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    check("POST /mcp without a token is 401", anon.status === 401);
    const httpClient = new Client({ name: "smoke-http", version: "0.0.0" });
    await httpClient.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }),
    );
    const viaHttp = await call(httpClient, "query", { sql: "select count(*) as n from customers c join orders o on o.customer_id = c.id" });
    check("governed join over HTTP with the token (6)", String(viaHttp.body.rows?.[0]?.n) === "6", viaHttp.text);
    check("email denied over HTTP", (await call(httpClient, "query", { sql: "select email from customers" })).body.error === "column_not_allowed");
    await httpClient.close();
  } finally {
    child.kill();
  }

  // 4. Audit.
  console.log("\n-- audit --");
  const audit = readFileSync(auditPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  check("audit has allow and deny entries", audit.some((e) => e.decision === "allow") && audit.some((e) => e.decision === "deny"));
  check("audit marks HTTP calls", audit.some((e) => e.transport === "http"));
  const auditText = JSON.stringify(audit);
  check(
    "audit holds no phone numbers, passwords or tokens",
    !auditText.includes("555 01") && secretsToHide.every((s) => !auditText.includes(s)),
  );
} finally {
  await stopDb().catch(() => undefined);
}

console.log(failures === 0 ? "\nSmoke test passed." : `\nSmoke test failed (${failures}).`);
process.exit(failures === 0 ? 0 : 1);

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function runToExit(args, env) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, args, { env, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    p.stderr.on("data", (c) => (stderr += c.toString("utf8")));
    const timer = setTimeout(() => p.kill(), 15_000);
    p.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, stderr: stderr.trim() });
    });
  });
}

function waitFor(child, pattern) {
  return new Promise((resolve, reject) => {
    let stderr = "";
    const timer = setTimeout(() => reject(new Error(`HTTP entrypoint did not start: ${stderr}`)), 15_000);
    child.stderr.on("data", (c) => {
      stderr += c.toString("utf8");
      if (pattern.test(stderr)) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`HTTP entrypoint exited with ${code}: ${stderr}`));
    });
  });
}
