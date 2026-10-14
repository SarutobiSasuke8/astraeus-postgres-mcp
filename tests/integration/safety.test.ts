// Safety claims, end to end against a real disposable PostgreSQL:
//   1. writes, DDL, multi-statement tricks, COPY and function-based writes are refused,
//      by the guard AND (with the guard bypassed) by the READ ONLY transaction and the role;
//   2. row limits and statement timeouts hold;
//   3. tool output never leaks connection details (DSN, password, host and port).
import { createServer as createNetServer } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, inject, it } from "vitest";
import { PgDb } from "../../src/db.js";
import { asAdmin, databaseFingerprint, startHarness, type Harness } from "./safety-helpers.js";

const { adminDsn, agentDsn, agentPassword } = inject("pg");
const agentUrl = new URL(agentDsn);
const adminPassword = decodeURIComponent(new URL(adminDsn).password);

let h: Harness;
let before: Record<string, unknown>;

beforeAll(async () => {
  await asAdmin(adminDsn, async (c) => {
    // A table big enough that a three-way join runs far past the 1000 ms policy timeout.
    await c.query("create table numbers (n int not null)");
    await c.query("insert into numbers select generate_series(1, 2000)");
    await c.query("grant select on numbers to astraeus_agent");
    // A function that writes, to prove function-based writes fail inside the read-only transaction.
    await c.query("create table write_probe (at timestamptz not null default now())");
    await c.query(
      "create function public.apm_write_probe() returns int language plpgsql as $$ begin insert into write_probe default values; return 1; end $$",
    );
  });
  h = await startHarness(agentDsn);
  before = await databaseFingerprint(adminDsn);
});

afterAll(async () => {
  await h?.close();
  await asAdmin(adminDsn, async (c) => {
    await c.query("drop function if exists public.apm_write_probe()");
    await c.query("drop table if exists write_probe");
    await c.query("drop table if exists numbers");
  });
});

/** Attacks sent through the MCP query tool, with the guard error each must produce. */
const REFUSED: [string, string][] = [
  // Writes
  ["insert into orders (customer_id, total_cents, status, tenant_id) values (1, 1, 'x', 1)", "non_read_statement"],
  ["update customers set name = 'x'", "non_read_statement"],
  ["delete from orders", "non_read_statement"],
  ["merge into orders o using customers c on o.customer_id = c.id when matched then delete", "non_read_statement"],
  ["truncate orders", "non_read_statement"],
  ["with d as (delete from orders returning *) select * from d", "cte_not_supported"],
  ["select id into stolen from customers", "parse_error"],
  ["select id from customers for update", "unsupported_syntax"],
  // DDL and privilege changes
  ["create table agent_table (x int)", "non_read_statement"],
  ["drop table orders", "non_read_statement"],
  ["alter table orders add column z int", "non_read_statement"],
  ["grant select on secrets to public", "non_read_statement"],
  ["create function f() returns int language sql as 'select 1'", "non_read_statement"],
  ["do $$ begin delete from orders; end $$", "non_read_statement"],
  ["call some_procedure()", "non_read_statement"],
  ["vacuum orders", "non_read_statement"],
  ["lock table orders", "non_read_statement"],
  ["refresh materialized view anything", "non_read_statement"],
  // Session and transaction control
  ["set statement_timeout = 0", "non_read_statement"],
  ["set role postgres", "non_read_statement"],
  ["reset all", "non_read_statement"],
  ["prepare p as delete from orders", "non_read_statement"],
  ["execute p", "non_read_statement"],
  ["explain analyze delete from orders", "non_read_statement"],
  ["listen x", "non_read_statement"],
  ["notify x", "non_read_statement"],
  // Multi-statement tricks
  ["select id from customers; delete from orders", "multi_statement"],
  ["SeLeCt id FrOm customers; DeLeTe FrOm orders", "multi_statement"],
  ["select id from customers -- comment\n; drop table orders", "multi_statement"],
  ["select 'a'; drop table orders; --' as x from customers", "multi_statement"],
  ["begin; delete from orders; commit", "multi_statement"],
  ["commit; delete from orders", "multi_statement"],
  ["select $$; drop table orders; $$ as x from customers", "parse_error"],
  // COPY in every direction
  ["copy orders to stdout", "non_read_statement"],
  ["copy orders from stdin", "non_read_statement"],
  ["copy (select id from customers) to program 'id'", "non_read_statement"],
  ["copy (select id from customers) to '/tmp/apm-copy-out'", "non_read_statement"],
  ["copy orders from '/etc/passwd'", "non_read_statement"],
  // Function-based writes and side effects
  ["select apm_write_probe() from customers", "function_not_allowed"],
  ["select public.apm_write_probe() from customers", "function_not_allowed"],
  ["select nextval('orders_id_seq') from customers", "function_not_allowed"],
  ["select setval('orders_id_seq', 1) from customers", "function_not_allowed"],
  ["select set_config('default_transaction_read_only', 'off', false) from customers", "function_not_allowed"],
  ["select lo_import('/etc/passwd') from customers", "function_not_allowed"],
  ["select pg_read_file('/etc/passwd') from customers", "function_not_allowed"],
  ["select pg_terminate_backend(1) from customers", "function_not_allowed"],
  ["select query_to_xml('delete from orders', true, true, '') from customers", "function_not_allowed"],
  ["select id, pg_sleep(10) from customers", "function_not_allowed"],
  ["select id::regclass from customers", "unsupported_syntax"],
  ["select id from customers where id = (select 1)", "unsupported_syntax"],
];

describe("claim 1a: the guard refuses writes, DDL, multi-statement tricks, COPY and function writes", () => {
  it.each(REFUSED)("%s", async (sql, code) => {
    const r = await h.query(sql);
    expect(r.isError).toBe(true);
    expect(r.body.error).toBe(code);
  });

  it("logged every refusal as a deny in the audit", () => {
    const denies = h.audit().filter((e) => e.tool === "query" && e.decision === "deny");
    expect(denies.length).toBeGreaterThanOrEqual(REFUSED.length);
    expect(h.audit().some((e) => e.tool === "query" && e.decision === "allow")).toBe(false);
  });

  it("left the database exactly as it was", async () => {
    expect(await databaseFingerprint(adminDsn)).toEqual(before);
    const probes = await asAdmin(adminDsn, async (c) => (await c.query("select count(*)::int as n from write_probe")).rows[0]);
    expect(probes).toEqual({ n: 0 });
  });
});

describe("claim 1b: with the guard bypassed, the read-only transaction still refuses writes", () => {
  // PgDb.runReadOnly is the only path the server uses to run SQL. Here it gets SQL the guard
  // would never pass, on the SUPERUSER connection, so only BEGIN READ ONLY and the extended
  // protocol stand in the way.
  let adminDb: PgDb;
  let agentDb: PgDb;

  beforeAll(() => {
    adminDb = new PgDb(adminDsn);
    agentDb = new PgDb(agentDsn);
  });

  afterAll(async () => {
    await adminDb.close();
    await agentDb.close();
  });

  async function sqlState(db: PgDb, sql: string): Promise<string> {
    try {
      await db.runReadOnly(sql, 2000);
      return "allowed";
    } catch (err) {
      return String((err as { code?: string }).code);
    }
  }

  it("refuses DML, DDL, sequence and function writes even for a superuser", async () => {
    const cases = [
      "insert into orders (customer_id, total_cents, status, tenant_id) values (1, 1, 'x', 1)",
      "update customers set name = 'x'",
      "delete from orders",
      "truncate orders",
      "create table agent_table (x int)",
      "drop table orders",
      "select nextval('orders_id_seq')",
      "select public.apm_write_probe()",
    ];
    for (const sql of cases) {
      expect(await sqlState(adminDb, sql), sql).toBe("25006");
    }
  });

  it("refuses multi-statement strings at the protocol level, even with no parameters", async () => {
    for (const sql of [
      "select 1; delete from orders",
      "commit; delete from orders",
      "rollback; drop table orders",
      // A read-write switch on its own changes nothing (the transaction ends after one
      // statement), so the attack only works if a write can follow in the same string.
      "set transaction read write; insert into write_probe default values",
      "set transaction read write; select public.apm_write_probe()",
    ]) {
      expect(await sqlState(adminDb, sql), sql).toBe("42601");
    }
    const probes = await asAdmin(adminDsn, async (c) => (await c.query("select count(*)::int as n from write_probe")).rows[0]);
    expect(probes).toEqual({ n: 0 });
  });

  it("refuses a function write after a read-write switch inside one statement", async () => {
    expect(await sqlState(adminDb, "select set_config('transaction_read_only', 'off', true), public.apm_write_probe()")).not.toBe("allowed");
    const probes = await asAdmin(adminDsn, async (c) => (await c.query("select count(*)::int as n from write_probe")).rows[0]);
    expect(probes).toEqual({ n: 0 });
  });

  it("refuses COPY to or from files and programs for the agent role", async () => {
    for (const sql of [
      "copy (select 1) to '/tmp/apm-copy-out'",
      "copy (select 1) to program 'id'",
      "copy orders from '/etc/passwd'",
    ]) {
      expect(["42501", "25006"], sql).toContain(await sqlState(agentDb, sql));
    }
  });

  it("left the database exactly as it was", async () => {
    expect(await databaseFingerprint(adminDsn)).toEqual(before);
  });
});

describe("claim 2: row limits and statement timeouts hold", () => {
  it("clamps every way of asking for more rows to the table cap", async () => {
    for (const sql of [
      "select id from customers",
      "select id from customers limit 1000",
      "select id from customers fetch first 1000 rows only",
      "select id from customers order by id limit 1000 offset 1",
    ]) {
      const r = await h.query(sql);
      expect(r.isError, sql).toBe(false);
      expect(r.body.row_limit, sql).toBe(5);
      expect((r.body.rows ?? []).length, sql).toBeLessThanOrEqual(5);
      expect(r.body.limit_clamped, sql).toBe(true);
    }
  });

  it("refuses limits it cannot check", async () => {
    expect((await h.query("select id from customers limit all")).body.error).toBe("parse_error");
    expect((await h.query("select id from customers limit 1+1000")).body.error).toBe("unsupported_syntax");
  });

  it("caps a cartesian join at the smallest cap of the tables read", async () => {
    const r = await h.query("select a.n, b.n as m from numbers a join numbers b on true");
    expect(r.isError).toBe(false);
    expect(r.body.row_count).toBe(10);
    expect(r.body.may_have_more).toBe(true);
    const mixed = await h.query("select c.id, x.n from customers c join numbers x on true");
    expect(mixed.body.row_count).toBe(5);
  });

  it("cancels a slow query at the policy timeout and reports it without hanging", async () => {
    const started = Date.now();
    const r = await h.query("select count(*) as n from numbers a join numbers b on true join numbers c on true");
    const took = Date.now() - started;
    expect(r.isError).toBe(true);
    expect(r.body.error).toBe("db_error");
    expect(r.body.message).toContain("57014");
    expect(took).toBeLessThan(5000);
  });

  it("applies the timeout in the database layer too (pg_sleep with the guard bypassed)", async () => {
    const db = new PgDb(agentDsn);
    try {
      const started = Date.now();
      await expect(db.runReadOnly("select pg_sleep(5)", 300)).rejects.toMatchObject({ code: "57014" });
      expect(Date.now() - started).toBeLessThan(3000);
    } finally {
      await db.close();
    }
  });

  it("the agent role carries its own statement_timeout as a backstop", async () => {
    const c = new pg.Client({ connectionString: agentDsn });
    await c.connect();
    try {
      expect((await c.query("show statement_timeout")).rows[0]).toEqual({ statement_timeout: "5s" });
    } finally {
      await c.end();
    }
  });
});

describe("claim 3: tool output does not leak connection details", () => {
  const secretsOf = (password: string, url: URL): string[] => [
    password,
    encodeURIComponent(password),
    "postgres://",
    "postgresql://",
    `${url.hostname}:${url.port}`,
  ];

  it("keeps DSN, passwords, host and port out of every response from a healthy server", async () => {
    // Exercise every tool, including error paths, before scanning the collected output.
    await h.call("ping");
    await h.call("list_tables");
    await h.call("policy_info");
    await h.call("describe_table", { table: "customers" });
    await h.call("describe_table", { table: "secrets" });
    await h.query("select cast(name as integer) as n from customers");
    const all = h.outputs.join("\n");
    for (const s of [...secretsOf(agentPassword, agentUrl), adminPassword]) {
      expect(all.includes(s), `output contains ${s === agentPassword || s === adminPassword ? "a password" : s}`).toBe(false);
    }
    expect(JSON.stringify(h.audit()).includes(agentPassword)).toBe(false);
  });

  it("keeps the password out of errors when authentication fails", async () => {
    const wrong = new URL(agentDsn);
    const badPassword = `wrong-${Date.now()}-not-a-secret`;
    wrong.password = badPassword;
    const bad = await startHarness(wrong.toString());
    try {
      for (const r of [await bad.call("ping"), await bad.query("select id from customers")]) {
        expect(r.isError).toBe(true);
        expect(r.body.error).toBe("db_error");
        for (const s of secretsOf(badPassword, wrong)) expect(r.text.includes(s), s).toBe(false);
      }
    } finally {
      await bad.close();
    }
  });

  it("keeps host, port and password out of errors when the database is unreachable", async () => {
    const port = await new Promise<number>((resolve, reject) => {
      const srv = createNetServer();
      srv.on("error", reject);
      srv.listen(0, "127.0.0.1", () => {
        const address = srv.address();
        srv.close(() => resolve(typeof address === "object" && address ? address.port : 0));
      });
    });
    const down = new URL(agentDsn);
    down.port = String(port);
    const password = decodeURIComponent(down.password);
    const off = await startHarness(down.toString());
    try {
      for (const r of [await off.call("ping"), await off.query("select id from customers"), await off.call("describe_table", { table: "customers" })]) {
        expect(r.isError).toBe(true);
        expect(r.body.error).toBe("db_error");
        for (const s of secretsOf(password, down)) expect(r.text.includes(s), s).toBe(false);
        expect(r.text.includes(String(port)), "port").toBe(false);
      }
    } finally {
      await off.close();
    }
  });
});
