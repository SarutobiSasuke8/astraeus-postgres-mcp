import { describe, expect, it } from "vitest";
import { GuardError, guardQuery } from "../src/guard.js";
import { testPolicy } from "./helpers.js";

const policy = testPolicy();

function codeOf(sql: string, p = policy): string {
  try {
    guardQuery(sql, p);
  } catch (err) {
    if (err instanceof GuardError) return err.code;
    throw err;
  }
  return "allowed";
}

describe("guard: statement shape", () => {
  it("rejects multi-statement input", () => {
    expect(codeOf("select id from customers; select id from orders")).toBe("multi_statement");
    expect(codeOf("select id from customers; drop table customers")).toBe("multi_statement");
  });

  it("allows a trailing semicolon on a single statement", () => {
    expect(codeOf("select id from customers;")).toBe("allowed");
  });

  it.each([
    "insert into customers (name) values ('x')",
    "update customers set name = 'x'",
    "delete from customers",
    "drop table customers",
    "truncate customers",
    "create table x (a int)",
    "alter table customers add column z int",
    "grant select on customers to public",
    "copy customers to '/tmp/x'",
    "set role postgres",
    "set statement_timeout = 0",
    "do $$ begin end $$",
    "call do_thing()",
    "explain select 1",
  ])("rejects non-SELECT: %s", (sql) => {
    expect(codeOf(sql)).toBe("non_read_statement");
  });

  it("rejects CTEs, unions, joins, subqueries and locking reads in v0", () => {
    expect(codeOf("with a as (select id from customers) select * from a")).toBe("cte_not_supported");
    expect(codeOf("select id from customers union select id from orders")).toBe("set_operation_not_supported");
    expect(codeOf("select c.id from customers c join orders o on o.customer_id = c.id")).toBe("join_not_supported");
    expect(codeOf("select id from customers, orders")).toBe("join_not_supported");
    expect(codeOf("select id from (select id from customers) s")).toBe("subquery_not_supported");
    expect(codeOf("select (select count(*) from orders) from customers")).toBe("unsupported_syntax");
    expect(codeOf("select id from customers where id in (select customer_id from orders)")).toBe("unsupported_syntax");
    expect(codeOf("select id from customers for update")).toBe("unsupported_syntax");
  });

  it("rejects empty and unparseable input", () => {
    expect(codeOf("")).toBe("empty");
    expect(codeOf("   ")).toBe("empty");
    expect(codeOf("select from where")).toBe("parse_error");
  });

  it("rejects dangerous functions and casts", () => {
    expect(codeOf("select pg_sleep(10) from customers")).toBe("function_not_allowed");
    expect(codeOf("select pg_read_file('/etc/passwd') from customers")).toBe("function_not_allowed");
    expect(codeOf("select set_config('role','postgres',false) from customers")).toBe("function_not_allowed");
    expect(codeOf("select pg_catalog.lower(name) from customers")).toBe("function_not_allowed");
    expect(codeOf("select id::regclass from customers")).toBe("unsupported_syntax");
  });
});

describe("guard: allowlists", () => {
  it("denies a table that is not in the policy", () => {
    expect(codeOf("select * from secrets")).toBe("table_not_allowed");
    expect(codeOf("select * from pg_catalog.pg_user")).toBe("table_not_allowed");
    expect(codeOf("select * from information_schema.columns")).toBe("table_not_allowed");
    expect(codeOf("select * from other_schema.customers")).toBe("table_not_allowed");
  });

  it("denies a column that is not in the policy", () => {
    expect(codeOf("select email from customers")).toBe("column_not_allowed");
    expect(codeOf("select id from customers where email = 'a@b.c'")).toBe("column_not_allowed");
    expect(codeOf("select id from customers order by email")).toBe("column_not_allowed");
    expect(codeOf("select ctid from customers")).toBe("column_not_allowed");
    expect(codeOf("select lower(email) from customers")).toBe("column_not_allowed");
  });

  it("expands * to allowed columns only", () => {
    const r = guardQuery("select * from customers", policy);
    expect(r.columns).toEqual(["id", "name", "created_at", "billing_phone"]);
    expect(r.sql).not.toContain("*");
    expect(r.sql).not.toMatch(/\bemail\b/);
  });

  it("rejects wrong column qualifiers", () => {
    expect(codeOf("select orders.id from customers")).toBe("invalid_qualifier");
    expect(codeOf("select public.customers.id from customers")).toBe("invalid_qualifier");
    expect(codeOf("select c.id from customers c")).toBe("allowed");
  });

  it("resolves tables without relying on search_path", () => {
    const r = guardQuery("select id from customers", policy);
    expect(r.sql).toContain("public.customers");
  });
});

describe("guard: row limit", () => {
  it("applies the cap when no LIMIT is given", () => {
    const r = guardQuery("select id from customers", policy);
    expect(r.limit).toBe(5);
    expect(r.limitClamped).toBe(true);
    expect(r.sql).toMatch(/LIMIT\s+\(?5\)?/i);
  });

  it("clamps an over-large LIMIT", () => {
    const r = guardQuery("select id from customers limit 100000", policy);
    expect(r.limit).toBe(5);
    expect(r.limitClamped).toBe(true);
  });

  it("keeps a smaller LIMIT and an offset", () => {
    const r = guardQuery("select id from customers limit 2 offset 4", policy);
    expect(r.limit).toBe(2);
    expect(r.limitClamped).toBe(false);
    expect(r.sql).toMatch(/OFFSET\s+\(?4\)?/i);
  });

  it("uses the per-table cap", () => {
    expect(guardQuery("select id from orders limit 50", policy).limit).toBe(3);
  });

  it("refuses over-limit queries when limit_mode is refuse", () => {
    const strict = testPolicy(
      `version: 1\nreadonly: true\ndefaults: { max_rows: 5, limit_mode: refuse, require_limit: true }\nallow:\n  schemas: [public]\n  tables:\n    - { name: customers, columns: [id] }\n`,
    );
    expect(codeOf("select id from customers limit 6", strict)).toBe("row_limit_exceeded");
    expect(codeOf("select id from customers", strict)).toBe("limit_required");
    expect(codeOf("select id from customers limit 5", strict)).toBe("allowed");
  });

  it("rejects non-literal limits", () => {
    expect(codeOf("select id from customers limit (select 1)")).not.toBe("allowed");
    expect(codeOf("select id from customers limit 1 + 1")).toBe("unsupported_syntax");
  });
});

describe("guard: require_predicate", () => {
  it("ANDs the predicate into a query without WHERE", () => {
    const r = guardQuery("select id from customers", policy);
    expect(r.sql).toMatch(/WHERE\s*\(*\s*deleted_at IS NULL/i);
  });

  it("keeps a caller OR from bypassing the predicate", () => {
    const r = guardQuery("select id from customers where id = 1 or id = 2", policy);
    // The caller's OR must be grouped so the predicate applies to both branches.
    expect(r.sql.replace(/\s+/g, " ")).toMatch(/\(\(\(id = \(?1\)?\) OR \(id = \(?2\)?\)\) AND \(deleted_at IS NULL\)\)/i);
  });

  it("does not add a predicate to tables without one", () => {
    expect(guardQuery("select id from orders", policy).sql).not.toMatch(/deleted_at/);
  });

  it("rejects a malformed policy predicate at load time", () => {
    expect(() =>
      testPolicy(
        `version: 1\nreadonly: true\nallow:\n  schemas: [public]\n  tables:\n    - { name: t, columns: [id], require_predicate: "1=1) union select 1 from t where (1=1" }\n`,
      ),
    ).toThrow();
    expect(() =>
      testPolicy(
        `version: 1\nreadonly: true\nallow:\n  schemas: [public]\n  tables:\n    - { name: t, columns: [id], require_predicate: "id in (select 1)" }\n`,
      ),
    ).toThrow();
  });
});

describe("guard: PII mask planning", () => {
  it("marks masked output columns, including aliases and expressions", () => {
    const r = guardQuery("select id, billing_phone as contact, lower(billing_phone) from customers", policy);
    expect([...r.masked.keys()]).toEqual([1, 2]);
  });

  it("marks masked columns when expanded from *", () => {
    const r = guardQuery("select * from customers", policy);
    expect([...r.masked.keys()]).toEqual([3]);
  });

  it("does not allow masked columns to be used as filters or sort keys", () => {
    expect(codeOf("select id from customers where billing_phone = '123'")).toBe("masked_column_in_filter");
    expect(codeOf("select id from customers order by billing_phone")).toBe("masked_column_in_filter");
    expect(codeOf("select billing_phone, count(*) from customers group by billing_phone")).toBe("masked_column_in_filter");
    expect(codeOf("select billing_phone, id from customers order by 1")).toBe("masked_column_in_filter");
    expect(codeOf("select billing_phone as p from customers order by p")).toBe("masked_column_in_filter");
  });
});

describe("guard: supported reads still work", () => {
  it("accepts a typical analytical query", () => {
    const sql =
      "select status, count(*) as n, sum(total_cents) / 100 as total from orders where status in ('paid','open') and total_cents between 1 and 99999 group by status having count(*) > 1 order by n desc limit 3";
    expect(codeOf(sql)).toBe("allowed");
  });
});
