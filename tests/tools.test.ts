import { describe, expect, it } from "vitest";
import {
  handleDescribeTable,
  handleListTables,
  handlePing,
  handlePolicyInfo,
  handleQuery,
} from "../src/tools.js";
import { makeRuntime, readAudit } from "./helpers.js";

describe("query: execution", () => {
  it("runs the regenerated SQL read-only with the policy timeout", async () => {
    const { rt, db } = makeRuntime();
    db.result = { fields: ["id"], rows: [[1], [2]] };
    const out = await handleQuery(rt, { sql: "select id from customers limit 2" });
    expect(out.ok).toBe(true);
    expect(db.executed).toHaveLength(1);
    expect(db.executed[0]?.timeoutMs).toBe(2000);
    expect(db.executed[0]?.sql).toContain("public.customers");
    expect(db.executed[0]?.sql).toMatch(/deleted_at IS NULL/i);
  });

  it("never reaches the database for denied SQL", async () => {
    const { rt, db } = makeRuntime();
    for (const sql of [
      "select 1; select 2",
      "delete from customers",
      "select email from customers",
      "select * from secrets",
    ]) {
      const out = await handleQuery(rt, { sql });
      expect(out.ok).toBe(false);
    }
    expect(db.executed).toHaveLength(0);
  });

  it("enforces max_rows even if the database returns more", async () => {
    const { rt, db } = makeRuntime();
    db.result = { fields: ["id"], rows: Array.from({ length: 50 }, (_, i) => [i]) };
    const out = await handleQuery(rt, { sql: "select id from customers limit 100000" });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.data.row_count).toBe(5);
    expect(out.data.row_limit).toBe(5);
    expect(out.data.limit_clamped).toBe(true);
    expect(out.data.may_have_more).toBe(true);
    expect(db.executed[0]?.sql).toMatch(/LIMIT\s+\(?5\)?/i);
  });

  it("refuses over-limit queries with a clear error in refuse mode", async () => {
    const { rt, db } = makeRuntime(
      (await import("./helpers.js")).testPolicy(
        `version: 1\nreadonly: true\ndefaults: { max_rows: 5, limit_mode: refuse }\nallow:\n  schemas: [public]\n  tables:\n    - { name: customers, columns: [id] }\n`,
      ),
    );
    const out = await handleQuery(rt, { sql: "select id from customers limit 6" });
    expect(out).toMatchObject({ ok: false, code: "row_limit_exceeded" });
    expect(db.executed).toHaveLength(0);
  });

  it("returns rows keyed by column name and reports a database error cleanly", async () => {
    const { rt, db } = makeRuntime();
    db.result = { fields: ["id", "name"], rows: [[7, "Ada"]] };
    const ok = await handleQuery(rt, { sql: "select id, name from customers" });
    expect(ok).toMatchObject({ ok: true, data: { rows: [{ id: 7, name: "Ada" }], row_count: 1 } });

    db.failWith = Object.assign(new Error("boom postgresql://user:pw@host/db"), { code: "57014" });
    const bad = await handleQuery(rt, { sql: "select id from customers" });
    expect(bad.ok).toBe(false);
    if (!bad.ok) {
      expect(bad.code).toBe("db_error");
      expect(bad.message).toContain("57014");
      expect(bad.message).not.toContain("pw@host");
    }
  });

  it("does not echo host or port from socket and DNS errors", async () => {
    const { rt, db } = makeRuntime();
    for (const [code, message] of [
      ["ECONNREFUSED", "connect ECONNREFUSED 10.1.2.3:6543"],
      ["ENOTFOUND", "getaddrinfo ENOTFOUND db.internal.example"],
      ["EPIPE", "write EPIPE 10.1.2.3:6543"],
      [undefined, "Connection terminated due to connection timeout to db.internal.example:6543"],
    ] as const) {
      db.failWith = Object.assign(new Error(message), code ? { code } : {});
      const out = await handleQuery(rt, { sql: "select id from customers" });
      expect(out).toMatchObject({ ok: false, code: "db_error" });
      if (!out.ok) {
        expect(out.message).not.toContain("10.1.2.3");
        expect(out.message).not.toContain("6543");
        expect(out.message).not.toContain("db.internal.example");
        expect(out.message).toContain("could not reach the database");
      }
    }
  });
});

describe("query: PII mask", () => {
  it("redacts masked columns, including aliased and derived ones", async () => {
    const { rt, db } = makeRuntime();
    db.result = {
      fields: ["id", "contact", "lower"],
      rows: [
        [1, "+353 1 555 0100", "+353 1 555 0100"],
        [2, null, null],
      ],
    };
    const out = await handleQuery(rt, {
      sql: "select id, billing_phone as contact, lower(billing_phone) from customers",
    });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.data.rows).toEqual([
      { id: 1, contact: "[REDACTED]", lower: "[REDACTED]" },
      { id: 2, contact: null, lower: null },
    ]);
    expect(out.data.masked_columns).toEqual(["contact", "lower"]);
    expect(JSON.stringify(out.data)).not.toContain("555");
  });

  it("redacts masked columns pulled in through *", async () => {
    const { rt, db } = makeRuntime();
    db.result = { fields: ["id", "name", "created_at", "billing_phone"], rows: [[1, "Ada", "2026-01-01", "0871234567"]] };
    const out = await handleQuery(rt, { sql: "select * from customers" });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(JSON.stringify(out.data)).not.toContain("0871234567");
    expect((out.data.rows as Record<string, unknown>[])[0]?.billing_phone).toBe("[REDACTED]");
  });

  it("supports null and hash strategies", async () => {
    const { testPolicy } = await import("./helpers.js");
    const policy = testPolicy(
      `version: 1\nreadonly: true\nallow:\n  schemas: [public]\n  tables:\n    - { name: t, columns: [id, iban, phone] }\npii_mask:\n  patterns:\n    - { column_regex: "iban", strategy: "null" }\n    - { column_regex: "phone", strategy: hash }\n`,
    );
    const { rt, db } = makeRuntime(policy);
    db.result = { fields: ["id", "iban", "phone"], rows: [[1, "IE00BANK", "0871234567"]] };
    const out = await handleQuery(rt, { sql: "select id, iban, phone from t" });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const row = (out.data.rows as Record<string, unknown>[])[0];
    expect(row?.iban).toBeNull();
    expect(String(row?.phone)).toMatch(/^sha256:[0-9a-f]{12}$/);
  });
});

describe("audit log", () => {
  it("writes an allow entry with normalised SQL and no literals", async () => {
    const { rt, db, auditPath } = makeRuntime();
    db.result = { fields: ["id"], rows: [[1]] };
    await handleQuery(rt, { sql: "select id from customers where name = 'Secret Person' and id = 42" });
    const [entry] = readAudit(auditPath);
    expect(entry).toMatchObject({ tool: "query", decision: "allow", reason: "ok", row_count: 1, table: "public.customers" });
    expect(entry?.policy_hash).toBe(rt.policy.hash);
    expect(typeof entry?.duration_ms).toBe("number");
    expect(typeof entry?.ts).toBe("string");
    expect(entry?.sql).toBe("select id from customers where name = ? and id = ?");
    expect(JSON.stringify(entry)).not.toContain("Secret Person");
  });

  it("writes a deny entry with the reason", async () => {
    const { rt, auditPath } = makeRuntime();
    await handleQuery(rt, { sql: "drop table customers" });
    await handleQuery(rt, { sql: "select email from customers" });
    await handleQuery(rt, { sql: "select 1; select 2" });
    const entries = readAudit(auditPath);
    expect(entries.map((e) => e.decision)).toEqual(["deny", "deny", "deny"]);
    expect(String(entries[0]?.reason)).toContain("non_read_statement");
    expect(String(entries[1]?.reason)).toContain("column_not_allowed");
    expect(String(entries[2]?.reason)).toContain("multi_statement");
  });

  it("audits the other tools too", async () => {
    const { rt, db, auditPath } = makeRuntime();
    db.columns = [{ name: "id", type: "integer", nullable: false }];
    handleListTables(rt);
    handlePolicyInfo(rt);
    await handleDescribeTable(rt, { table: "customers" });
    await handleDescribeTable(rt, { table: "secrets" });
    await handlePing(rt);
    const entries = readAudit(auditPath);
    expect(entries.map((e) => `${String(e.tool)}:${String(e.decision)}`)).toEqual([
      "list_tables:allow",
      "policy_info:allow",
      "describe_table:allow",
      "describe_table:deny",
      "ping:allow",
    ]);
  });

  it("returns no data when the audit log cannot be written", async () => {
    const { rt, db } = makeRuntime();
    db.result = { fields: ["id"], rows: [[1]] };
    rt.audit.write = () => {
      throw new Error("disk full");
    };
    await expect(handleQuery(rt, { sql: "select id from customers" })).rejects.toThrow("disk full");
  });
});

describe("metadata tools", () => {
  it("list_tables shows only policy tables and columns", () => {
    const { rt } = makeRuntime();
    const out = handleListTables(rt);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const tables = out.data.tables as { name: string; columns: string[] }[];
    expect(tables.map((t) => t.name)).toEqual(["customers", "orders"]);
    expect(tables[0]?.columns).not.toContain("email");
  });

  it("describe_table hides columns outside the policy and flags masked ones", async () => {
    const { rt, db } = makeRuntime();
    db.columns = [
      { name: "id", type: "integer", nullable: false },
      { name: "name", type: "text", nullable: true },
      { name: "email", type: "text", nullable: true },
      { name: "billing_phone", type: "text", nullable: true },
      { name: "created_at", type: "timestamp with time zone", nullable: false },
    ];
    const out = await handleDescribeTable(rt, { table: "customers" });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(JSON.stringify(out.data)).not.toContain("email");
    const cols = out.data.columns as { name: string; masked: boolean }[];
    expect(cols.find((c) => c.name === "billing_phone")?.masked).toBe(true);
    expect(await handleDescribeTable(rt, { table: "secrets" })).toMatchObject({ ok: false, code: "table_not_allowed" });
  });

  it("policy_info exposes no connection string", () => {
    const { rt } = makeRuntime();
    const out = handlePolicyInfo(rt);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const text = JSON.stringify(out.data);
    expect(text).not.toMatch(/postgres(ql)?:\/\//);
    expect(out.data.read_only).toBe(true);
    expect(out.data.pii_mask).toEqual([{ column_regex: "(?i)email|phone|iban", strategy: "redact" }]);
  });

  it("ping reports failure without data", async () => {
    const { rt, db } = makeRuntime();
    db.pingFails = true;
    expect(await handlePing(rt)).toMatchObject({ ok: false, code: "db_error" });
  });
});
