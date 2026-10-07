// End-to-end smoke test against the docker-compose Postgres. Run `npm run build` first.
// Requires SMOKE_PG_AGENT_PASSWORD (the same throwaway value given to docker compose).
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import pg from "pg";

const password = process.env.SMOKE_PG_AGENT_PASSWORD;
if (!password) {
  console.error("Set SMOKE_PG_AGENT_PASSWORD to the value used for docker compose.");
  process.exit(2);
}
const dsn = `postgresql://astraeus_agent:${encodeURIComponent(password)}@127.0.0.1:54329/appdb`;
const auditPath = join(mkdtempSync(join(tmpdir(), "apm-smoke-")), "audit.jsonl");

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : `  ${detail}`}`);
  if (!ok) failures += 1;
}

// 1. Prove the database role itself is least-privilege, independent of the guard.
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
check("role cannot read customers.email", (await attempt("select email from customers")) === "42501");
check("role cannot read secrets", (await attempt("select * from secrets")) === "42501");
check("role cannot write", (await attempt("insert into orders (customer_id,total_cents,status) values (1,1,'x')")) !== "allowed");
await direct.end();

// 2. Drive the real MCP server over stdio.
const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/index.js", "--policy", "smoke/policy.smoke.yaml"],
  env: { PATH: process.env.PATH ?? "", DATABASE_URL: dsn, ASTRAEUS_AUDIT_PATH: auditPath },
  stderr: "ignore",
});
const client = new Client({ name: "smoke", version: "0.0.0" });
await client.connect(transport);

const call = async (name, args = {}) => {
  const res = await client.callTool({ name, arguments: args });
  const text = res.content[0]?.text ?? "{}";
  return { error: res.isError === true, body: JSON.parse(text), text };
};

const tools = (await client.listTools()).tools.map((t) => t.name).sort();
check("tools listed", tools.join(",") === "describe_table,list_tables,ping,policy_info,query", tools.join(","));
check("ping ok", (await call("ping")).body.status === "ok");

const desc = await call("describe_table", { table: "customers" });
check("describe_table hides email", !desc.text.includes("email"));

const all = await call("query", { sql: "select id, name, billing_phone from customers order by id limit 1000" });
check("row cap enforced (5)", all.body.row_count === 5 && all.body.limit_clamped === true, all.text);
check("phone redacted", all.body.rows?.every((r) => r.billing_phone === "[REDACTED]") && !all.text.includes("555 01"));

const count = await call("query", { sql: "select count(*) as n from customers" });
check("require_predicate hides soft-deleted row", String(count.body.rows?.[0]?.n) === "7", count.text);

check("email denied", (await call("query", { sql: "select email from customers" })).body.error === "column_not_allowed");
check("secrets table denied", (await call("query", { sql: "select * from secrets" })).body.error === "table_not_allowed");
check("multi-statement denied", (await call("query", { sql: "select 1; select 2" })).body.error === "multi_statement");
check("delete denied", (await call("query", { sql: "delete from customers" })).body.error === "non_read_statement");
check("join denied (v0)", (await call("query", { sql: "select c.id from customers c join orders o on o.customer_id = c.id" })).body.error === "join_not_supported");

await client.close();

const audit = readFileSync(auditPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
check("audit has allow and deny entries", audit.some((e) => e.decision === "allow") && audit.some((e) => e.decision === "deny"));
check("audit holds no phone numbers or passwords", !JSON.stringify(audit).includes("555 01") && !JSON.stringify(audit).includes(password));

console.log(failures === 0 ? "\nSmoke test passed." : `\nSmoke test failed (${failures}).`);
process.exit(failures === 0 ? 0 : 1);
