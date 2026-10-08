// The real server stack (policy, guard, pg pool, masks, audit, MCP) against a real
// embedded PostgreSQL, connected as the least-privilege agent role.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, inject, it } from "vitest";
import { startHttpServer, type RunningHttpServer } from "../../src/http.js";
import { createServer } from "../../src/server.js";
import { buildRuntime } from "../../src/startup.js";
import type { Runtime } from "../../src/tools.js";

const { agentDsn, agentPassword } = inject("pg");
const POLICY = join(process.cwd(), "smoke", "policy.smoke.yaml");
const TOKEN = "integration-test-token-not-a-secret-000000";

let rt: Runtime;
let client: Client;
let auditPath: string;
let http: RunningHttpServer;

type Body = Record<string, unknown> & { rows?: Record<string, unknown>[]; error?: string };

async function call(
  c: Client,
  name: string,
  args: Record<string, unknown> = {},
): Promise<{ isError: boolean; body: Body; text: string }> {
  const res = await c.callTool({ name, arguments: args });
  const text = (res.content as { text: string }[])[0]?.text ?? "{}";
  return { isError: res.isError === true, body: JSON.parse(text) as Body, text };
}

const query = (sql: string) => call(client, "query", { sql });

beforeAll(async () => {
  auditPath = join(mkdtempSync(join(tmpdir(), "apm-int-")), "audit.jsonl");
  rt = buildRuntime({ env: { DATABASE_URL: agentDsn, ASTRAEUS_AUDIT_PATH: auditPath }, argv: ["--policy", POLICY] });
  const server = createServer(rt);
  client = new Client({ name: "integration", version: "0.0.0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  http = await startHttpServer(rt, { host: "127.0.0.1", port: 0, token: TOKEN, remote: false });
});

afterAll(async () => {
  await client?.close();
  await http?.close();
  await rt?.db.close();
});

describe("single-table reads on a real database", () => {
  it("pings and describes without revealing non-allowlisted columns", async () => {
    expect((await call(client, "ping")).body.status).toBe("ok");
    const desc = await call(client, "describe_table", { table: "customers" });
    expect(desc.isError).toBe(false);
    expect(desc.text).not.toContain("email");
  });

  it("enforces the row cap, the mask and require_predicate", async () => {
    const all = await query("select id, name, billing_phone from customers order by id limit 1000");
    expect(all.body).toMatchObject({ row_count: 5, limit_clamped: true });
    expect(all.body.rows?.every((r) => r.billing_phone === "[REDACTED]")).toBe(true);
    expect(all.text).not.toContain("555 01");
    const count = await query("select count(*) as n from customers");
    expect(String(count.body.rows?.[0]?.n)).toBe("7");
  });

  it("sees only the agent's tenant (RLS) through the server too", async () => {
    const r = await query("select count(*) as n, sum(total_cents) as total from orders");
    expect(r.body.rows?.[0]).toEqual({ n: "7", total: "30940" });
  });
});

describe("joins on a real database", () => {
  it("applies require_predicate per table and RLS together on an inner join", async () => {
    const r = await query("select count(*) as n from customers c join orders o on o.customer_id = c.id");
    // 10 orders exist; RLS leaves 7, and the deleted customer's order drops out of the inner join.
    expect(r.body.rows?.[0]).toEqual({ n: "6" });
  });

  it("keeps the predicate on its own table under a LEFT JOIN", async () => {
    const r = await query(
      "select count(*) as n, count(c.name) as named from orders o left join customers c on c.id = o.customer_id",
    );
    // All 7 visible orders survive; the soft-deleted customer is hidden, so one name is null.
    expect(r.body.rows?.[0]).toEqual({ n: "7", named: "6" });
  });

  it("masks survive aliases, qualified stars and expressions across a join", async () => {
    const r = await query(
      "select c.name, c.billing_phone as contact, lower(c.billing_phone) as lc, o.total_cents from customers c join orders o on o.customer_id = c.id order by o.id",
    );
    expect(r.isError).toBe(false);
    expect(r.body.masked_columns).toEqual(["contact", "lc"]);
    expect(r.text).not.toContain("555 01");
    const star = await query("select x.*, o.status from customers x join orders o on o.customer_id = x.id");
    expect(star.isError).toBe(false);
    expect(star.body.rows?.every((row) => row.billing_phone === "[REDACTED]")).toBe(true);
    expect(star.text).not.toContain("555 01");
    expect(star.text).not.toContain("example.test");
  });

  it("denies cross-schema, non-allowlisted and probing joins", async () => {
    const cases: [string, string][] = [
      ["select c.id from customers c join internal.staff_notes n on n.customer_id = c.id", "cross_schema_join"],
      ["select c.id from customers c join secrets s on s.id = c.id", "table_not_allowed"],
      ["select c.email from customers c join orders o on o.customer_id = c.id", "column_not_allowed"],
      ["select c.id from customers c join orders o on o.status = c.billing_phone", "masked_column_in_filter"],
      ["select id from customers c join orders o on o.customer_id = c.id", "ambiguous_column"],
      ["select c.id from customers c, orders o where o.customer_id = c.id", "join_not_supported"],
    ];
    for (const [sql, code] of cases) {
      const r = await query(sql);
      expect(r.body.error, sql).toBe(code);
    }
  });
});

describe("named views on a real database", () => {
  it("runs a view with a typed parameter", async () => {
    const r = await call(client, "run_view", { name: "revenue_by_status", params: { since: "2026-09-01" } });
    expect(r.isError).toBe(false);
    expect(r.body.rows).toEqual([
      { status: "open", orders: "2", total_cents: "3190" },
      { status: "paid", orders: "4", total_cents: "27300" },
      { status: "refunded", orders: "1", total_cents: "450" },
    ]);
  });

  it("applies masks, predicates and RLS inside a join view", async () => {
    const r = await call(client, "run_view", { name: "customer_orders", params: { customer_id: 1 } });
    expect(r.body.row_count).toBe(2);
    expect(r.body.rows?.every((row) => row.contact === "[REDACTED]")).toBe(true);
    const deleted = await call(client, "run_view", { name: "customer_orders", params: { customer_id: 8 } });
    expect(deleted.body.row_count).toBe(0);
  });

  it("refuses bad parameters and unknown views", async () => {
    const bad = await call(client, "run_view", { name: "customer_orders", params: { customer_id: "1; drop table orders" } });
    expect(bad.body.error).toBe("invalid_params");
    const extra = await call(client, "run_view", { name: "customer_orders", params: { customer_id: 1, sql: "x" } });
    expect(extra.body.error).toBe("invalid_params");
    const missing = await call(client, "run_view", { name: "revenue_by_status" });
    expect(missing.body.error).toBe("invalid_params");
    expect((await call(client, "run_view", { name: "drop_everything" })).body.error).toBe("view_not_found");
  });
});

describe("Streamable HTTP on a real database", () => {
  it("serves health without a token and refuses MCP calls without one", async () => {
    const health = await fetch(`${http.url}/health`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: "ok" });
    const noToken = await fetch(`${http.url}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(noToken.status).toBe(401);
  });

  it("runs a governed join over HTTP with the bearer token", async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`${http.url}/mcp`), {
      requestInit: { headers: { authorization: `Bearer ${TOKEN}` } },
    });
    const httpClient = new Client({ name: "integration-http", version: "0.0.0" });
    await httpClient.connect(transport);
    try {
      const r = await call(httpClient, "query", {
        sql: "select count(*) as n from customers c join orders o on o.customer_id = c.id",
      });
      expect(r.body.rows?.[0]).toEqual({ n: "6" });
      expect((await call(httpClient, "query", { sql: "select email from customers" })).body.error).toBe("column_not_allowed");
    } finally {
      await httpClient.close();
    }
  });
});

describe("audit on a real run", () => {
  it("has allow and deny entries, marks HTTP calls, and holds no PII or passwords", () => {
    const entries = readFileSync(auditPath, "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(entries.some((e) => e.decision === "allow")).toBe(true);
    expect(entries.some((e) => e.decision === "deny")).toBe(true);
    expect(entries.some((e) => e.tool === "run_view" && e.view === "customer_orders")).toBe(true);
    expect(entries.some((e) => e.transport === "http" && e.reason === "unauthorised")).toBe(true);
    expect(entries.some((e) => e.transport === "http" && e.decision === "allow")).toBe(true);
    const text = JSON.stringify(entries);
    expect(text).not.toContain("555 01");
    expect(text).not.toContain(agentPassword);
    expect(text).not.toContain(TOKEN);
    expect(text).not.toContain("drop table orders");
  });
});

describe("the database is the second line", () => {
  it("the agent role can read internal.staff_notes directly, so the cross-schema denial above is the guard's", async () => {
    const c = new pg.Client({ connectionString: agentDsn });
    await c.connect();
    try {
      expect((await c.query("select count(*)::int as n from internal.staff_notes")).rows[0]).toEqual({ n: 1 });
    } finally {
      await c.end();
    }
  });
});
