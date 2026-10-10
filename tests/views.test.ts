import { describe, expect, it } from "vitest";
import { PolicyError } from "../src/policy.js";
import { handleListTables, handlePolicyInfo, handleRunView } from "../src/tools.js";
import { makeRuntime, readAudit, testPolicy } from "./helpers.js";

const BASE = `
version: 1
readonly: true
defaults:
  max_rows: 5
allow:
  schemas: [public]
  tables:
    - name: customers
      columns: [id, name, billing_phone]
      require_predicate: "deleted_at IS NULL"
    - name: orders
      columns: [id, customer_id, total_cents, status, created_at]
      max_rows: 3
pii_mask:
  patterns:
    - column_regex: "(?i)phone"
      strategy: redact
`;

const VIEWS = `${BASE}
views:
  - name: orders_since
    description: Orders since a date with a minimum total.
    sql: "select id, status, total_cents from orders where created_at >= $1 and total_cents >= $2 order by id"
    params:
      - { name: since, type: timestamp }
      - { name: min_cents, type: integer, default: 0 }
  - name: contact_for
    sql: "select c.name, c.billing_phone as contact, o.status from customers c join orders o on o.customer_id = c.id where c.id = $1"
    params:
      - { name: customer_id, type: integer }
`;

describe("named views: validated at policy load", () => {
  it("compiles views through the guard with typed placeholders", () => {
    const p = testPolicy(VIEWS);
    const v = p.views.find((x) => x.name === "orders_since");
    expect(v?.guarded.sql).toMatch(/\(\$1\)::timestamptz/i);
    expect(v?.guarded.sql).toMatch(/\(\$2\)::bigint/i);
    expect(v?.guarded.limit).toBe(3);
    const c = p.views.find((x) => x.name === "contact_for");
    expect([...(c?.guarded.masked.keys() ?? [])]).toEqual([1]);
    expect(c?.guarded.sql).toMatch(/deleted_at IS NULL/i);
  });

  it.each([
    ["a non-allowlisted column", `select email from customers where id = $1`, "column_not_allowed"],
    ["a non-allowlisted table", `select id from secrets where id = $1`, "table_not_allowed"],
    ["a write", `delete from orders where id = $1`, "non_read_statement"],
    ["two statements", `select id from orders where id = $1; select 1`, "multi_statement"],
    ["an undeclared parameter", `select id from orders where id = $2`, "not declared"],
    ["a masked filter", `select id from customers where billing_phone = $1`, "masked_column_in_filter"],
  ])("rejects a view using %s", (_label, sql, fragment) => {
    const yaml = `${BASE}\nviews:\n  - name: bad\n    sql: "${sql}"\n    params:\n      - { name: p, type: text }\n`;
    expect(() => testPolicy(yaml)).toThrow(PolicyError);
    expect(() => testPolicy(yaml)).toThrow(fragment);
  });

  it("rejects declared but unused parameters, duplicates and bad defaults", () => {
    const unused = `${BASE}\nviews:\n  - name: v\n    sql: "select id from orders"\n    params:\n      - { name: p, type: text }\n`;
    expect(() => testPolicy(unused)).toThrow(/declared but not used/);
    const dupView = `${BASE}\nviews:\n  - { name: v, sql: "select id from orders" }\n  - { name: v, sql: "select id from orders" }\n`;
    expect(() => testPolicy(dupView)).toThrow(/listed twice/);
    const badDefault = `${BASE}\nviews:\n  - name: v\n    sql: "select id from orders where id = $1"\n    params:\n      - { name: p, type: integer, default: "x" }\n`;
    expect(() => testPolicy(badDefault)).toThrow(/default for p/);
    const badName = `${BASE}\nviews:\n  - { name: "Drop Table", sql: "select id from orders" }\n`;
    expect(() => testPolicy(badName)).toThrow(PolicyError);
  });
});

describe("named views: run_view", () => {
  it("binds parameters in declared order, applies defaults, caps rows and audits without values", async () => {
    const { rt, db, auditPath } = makeRuntime(testPolicy(VIEWS));
    db.result = { fields: ["id", "status", "total_cents"], rows: [[1, "paid", 10], [2, "open", 20], [3, "paid", 30], [4, "x", 40]] };
    const out = await handleRunView(rt, { name: "orders_since", params: { since: "2026-09-01T00:00:00Z" } });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.data.row_count).toBe(3);
    expect(db.executed).toHaveLength(1);
    expect(db.executed[0]?.params).toEqual(["2026-09-01T00:00:00Z", "0"]);
    const [entry] = readAudit(auditPath);
    expect(entry).toMatchObject({ tool: "run_view", decision: "allow", view: "orders_since", params: ["since"], row_count: 3 });
    expect(JSON.stringify(entry)).not.toContain("2026-09-01T00");
  });

  it("masks view output columns", async () => {
    const { rt, db } = makeRuntime(testPolicy(VIEWS));
    db.result = { fields: ["name", "contact", "status"], rows: [["Ada", "+353 1 555 0100", "paid"]] };
    const out = await handleRunView(rt, { name: "contact_for", params: { customer_id: 1 } });
    expect(out).toMatchObject({ ok: true, data: { rows: [{ name: "Ada", contact: "[REDACTED]", status: "paid" }] } });
  });

  it("denies unknown views and bad parameters without reaching the database", async () => {
    const { rt, db, auditPath } = makeRuntime(testPolicy(VIEWS));
    expect(await handleRunView(rt, { name: "nope" })).toMatchObject({ ok: false, code: "view_not_found" });
    expect(await handleRunView(rt, { name: "contact_for" })).toMatchObject({ ok: false, code: "invalid_params" });
    expect(await handleRunView(rt, { name: "contact_for", params: { customer_id: "1 or 1=1" } })).toMatchObject({
      ok: false,
      code: "invalid_params",
    });
    expect(await handleRunView(rt, { name: "contact_for", params: { customer_id: 1.5 } })).toMatchObject({ ok: false });
    expect(await handleRunView(rt, { name: "contact_for", params: { customer_id: 1, extra: 2 } })).toMatchObject({ ok: false });
    expect(await handleRunView(rt, { name: "orders_since", params: { since: "yesterday" } })).toMatchObject({ ok: false });
    expect(db.executed).toHaveLength(0);
    expect(readAudit(auditPath).every((e) => e.decision === "deny")).toBe(true);
    expect(JSON.stringify(readAudit(auditPath))).not.toContain("1 or 1=1");
  });

  it("lists views with their parameters in list_tables and policy_info", () => {
    const { rt } = makeRuntime(testPolicy(VIEWS));
    const lt = handleListTables(rt);
    expect(lt.ok).toBe(true);
    if (!lt.ok) return;
    const views = lt.data.views as { name: string; params: { name: string; required: boolean }[] }[];
    expect(views.map((v) => v.name)).toEqual(["orders_since", "contact_for"]);
    expect(views[0]?.params).toEqual([
      { name: "since", type: "timestamp", required: true },
      { name: "min_cents", type: "integer", required: false, default: 0 },
    ]);
    const pi = handlePolicyInfo(rt);
    expect(pi.ok && JSON.stringify(pi.data)).toContain("orders_since");
  });
});
