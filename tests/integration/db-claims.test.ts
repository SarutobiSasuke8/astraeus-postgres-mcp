// Proves the README's database-level claims WITHOUT the guard: these tests connect
// straight to Postgres as the agent role with the plain pg driver, so nothing in
// src/ is involved. If the guard had a bug, this is what an attacker would get.
import pg from "pg";
import { afterAll, beforeAll, describe, expect, inject, it } from "vitest";

const { agentDsn, adminDsn } = inject("pg");
let agent: pg.Client;

async function sqlState(client: pg.Client, sql: string): Promise<string> {
  try {
    await client.query(sql);
    return "allowed";
  } catch (err) {
    return String((err as { code?: string }).code);
  }
}

beforeAll(async () => {
  agent = new pg.Client({ connectionString: agentDsn });
  await agent.connect();
});

afterAll(async () => {
  await agent.end();
});

describe("agent role: identity", () => {
  it("is the least-privilege role, not a superuser and not able to bypass RLS", async () => {
    const r = await agent.query(
      "select current_user as u, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb from pg_roles r where r.rolname = current_user",
    );
    expect(r.rows[0]).toEqual({ u: "astraeus_agent", rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false });
  });

  it("cannot switch to another role", async () => {
    expect(await sqlState(agent, "set role postgres")).toBe("42501");
    expect(await sqlState(agent, "set session authorization postgres")).toBe("42501");
  });
});

describe("claim 1: column grants hold at the database", () => {
  it("denies a non-granted column", async () => {
    expect(await sqlState(agent, "select email from customers")).toBe("42501");
    expect(await sqlState(agent, "select id, email from customers where id = 1")).toBe("42501");
    expect(await sqlState(agent, "select * from customers")).toBe("42501");
    expect(await sqlState(agent, "select c.email from orders o join customers c on c.id = o.customer_id")).toBe("42501");
    expect(await sqlState(agent, "select tenant_id from orders")).toBe("42501");
  });

  it("denies a table with no grants at all", async () => {
    expect(await sqlState(agent, "select * from secrets")).toBe("42501");
    expect(await sqlState(agent, "select count(*) from secrets")).toBe("42501");
  });

  it("allows the granted columns", async () => {
    const r = await agent.query("select id, name, billing_phone from customers order by id limit 1");
    expect(r.rows[0]).toMatchObject({ id: 1, name: "Aoife Byrne" });
  });
});

describe("claim 2: the role cannot write, even outside a read-only transaction", () => {
  it("is read-only by default", async () => {
    expect(await sqlState(agent, "insert into orders (customer_id, total_cents, status, tenant_id) values (1, 1, 'x', 1)")).toBe("25006");
  });

  it("has no write grants once read-only mode is switched off", async () => {
    // The guard would refuse SET; here we bypass it and the read-only default too.
    await agent.query("set default_transaction_read_only = off");
    try {
      const writes = [
        "insert into orders (customer_id, total_cents, status, tenant_id) values (1, 1, 'x', 1)",
        "update customers set name = 'x'",
        "update customers set deleted_at = null",
        "delete from orders",
        "truncate orders",
        "insert into secrets (value) values ('x')",
        "create table public.agent_table (x int)",
        "create temporary table agent_tmp (x int)",
        "alter table customers add column z int",
        "drop table orders",
        "grant select on customers to public",
      ];
      for (const sql of writes) {
        expect(await sqlState(agent, sql), sql).toBe("42501");
      }
    } finally {
      await agent.query("reset default_transaction_read_only");
    }
  });

  it("left the data unchanged", async () => {
    const admin = new pg.Client({ connectionString: adminDsn });
    await admin.connect();
    try {
      const r = await admin.query("select (select count(*) from orders)::int as orders, (select count(*) from customers where name = 'x')::int as renamed");
      expect(r.rows[0]).toEqual({ orders: 10, renamed: 0 });
    } finally {
      await admin.end();
    }
  });
});

describe("claim 3: row-level security bounds rows", () => {
  it("role-bound RLS hides other tenants' rows from a raw connection", async () => {
    const r = await agent.query("select count(*)::int as n, sum(total_cents)::int as total from orders");
    expect(r.rows[0]).toEqual({ n: 7, total: 30_940 });
    // The admin sees all ten rows, so the bound is RLS, not missing data.
    const admin = new pg.Client({ connectionString: adminDsn });
    await admin.connect();
    try {
      expect((await admin.query("select count(*)::int as n from orders")).rows[0]).toEqual({ n: 10 });
    } finally {
      await admin.end();
    }
  });

  it("cannot be widened by the agent: it cannot change role, disable RLS or drop the policy", async () => {
    await agent.query("set default_transaction_read_only = off");
    try {
      expect(await sqlState(agent, "set row_security = off")).toBe("allowed");
      // With row_security off, a query that RLS would filter errors instead of leaking.
      expect(await sqlState(agent, "select count(*) from orders")).toBe("42501");
      await agent.query("reset row_security");
      expect(await sqlState(agent, "alter table orders disable row level security")).toBe("42501");
      expect(await sqlState(agent, "drop policy agent_tenant_orders on orders")).toBe("42501");
    } finally {
      await agent.query("reset default_transaction_read_only");
    }
    const r = await agent.query("select count(*)::int as n from orders");
    expect(r.rows[0]).toEqual({ n: 7 });
  });

  it("session-setting RLS is only as strong as the guard: a raw connection can change the setting", async () => {
    // Documented weakness, kept as a test so the README's advice stays honest.
    const before = await agent.query("select coalesce(sum(amount_cents), 0)::int as total from invoices");
    expect(before.rows[0]).toEqual({ total: 300 });
    await agent.query("set app.tenant_id = '2'");
    try {
      const after = await agent.query("select coalesce(sum(amount_cents), 0)::int as total from invoices");
      expect(after.rows[0]).toEqual({ total: 900_000 });
    } finally {
      await agent.query("reset app.tenant_id");
    }
  });
});
