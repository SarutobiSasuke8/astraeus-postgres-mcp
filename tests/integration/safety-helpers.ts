// Shared plumbing for the safety and prompt-injection suites: a real server runtime on the
// safety policy, connected as the agent role, plus an MCP client over an in-memory transport.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import pg from "pg";
import { createServer } from "../../src/server.js";
import { buildRuntime } from "../../src/startup.js";
import type { Runtime } from "../../src/tools.js";

export const SAFETY_POLICY = join(process.cwd(), "tests", "integration", "fixtures", "policy.safety.yaml");

export type Body = Record<string, unknown> & { rows?: Record<string, unknown>[]; error?: string; message?: string };

export interface ToolCall {
  isError: boolean;
  body: Body;
  text: string;
}

export interface Harness {
  rt: Runtime;
  client: Client;
  auditPath: string;
  /** Every text block any tool returned through this harness, for leak checks. */
  outputs: string[];
  call(name: string, args?: Record<string, unknown>): Promise<ToolCall>;
  query(sql: string): Promise<ToolCall>;
  audit(): Record<string, unknown>[];
  close(): Promise<void>;
}

export async function startHarness(databaseUrl: string): Promise<Harness> {
  const auditPath = join(mkdtempSync(join(tmpdir(), "apm-safety-")), "audit.jsonl");
  const rt = buildRuntime({ env: { DATABASE_URL: databaseUrl, ASTRAEUS_AUDIT_PATH: auditPath }, argv: ["--policy", SAFETY_POLICY] });
  const server = createServer(rt);
  const client = new Client({ name: "safety", version: "0.0.0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  const outputs: string[] = [];
  const call = async (name: string, args: Record<string, unknown> = {}): Promise<ToolCall> => {
    const res = await client.callTool({ name, arguments: args });
    const text = (res.content as { text: string }[]).map((c) => c.text).join("\n");
    outputs.push(text);
    return { isError: res.isError === true, body: JSON.parse((res.content as { text: string }[])[0]?.text ?? "{}") as Body, text };
  };
  return {
    rt,
    client,
    auditPath,
    outputs,
    call,
    query: (sql: string) => call("query", { sql }),
    audit: () =>
      readFileSync(auditPath, "utf8")
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as Record<string, unknown>),
    close: async () => {
      await client.close();
      await rt.db.close();
    },
  };
}

/** Run statements as the superuser (fixture setup and after-the-fact checks only). */
export async function asAdmin<T>(adminDsn: string, fn: (c: pg.Client) => Promise<T>): Promise<T> {
  const c = new pg.Client({ connectionString: adminDsn });
  await c.connect();
  try {
    return await fn(c);
  } finally {
    await c.end();
  }
}

/** Row counts and object list the attacks must not change. */
export async function databaseFingerprint(adminDsn: string): Promise<Record<string, unknown>> {
  return asAdmin(adminDsn, async (c) => {
    const counts = await c.query(
      `select (select count(*) from customers)::int as customers,
              (select count(*) from orders)::int as orders,
              (select count(*) from secrets)::int as secrets,
              (select count(*) from customers where name = 'x')::int as renamed,
              (select coalesce(max(last_value), 0) from pg_sequences where sequencename = 'orders_id_seq')::int as orders_seq`,
    );
    const objects = await c.query(
      `select n.nspname || '.' || c.relname as name
         from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast') and n.nspname not like 'pg_temp%'
        order by 1`,
    );
    return { ...counts.rows[0], objects: objects.rows.map((r: { name: string }) => r.name) };
  });
}
