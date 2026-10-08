import { describe, expect, it } from "vitest";
import { GuardError, guardQuery } from "../src/guard.js";
import { testPolicy } from "./helpers.js";

const JOIN_POLICY = `
version: 1
readonly: true
defaults:
  max_rows: 50
allow:
  schemas: [public, internal]
  tables:
    - name: customers
      columns: [id, name, created_at, billing_phone]
      require_predicate: "deleted_at IS NULL"
      max_rows: 10
    - name: orders
      columns: [id, customer_id, total_cents, status]
    - name: notes
      schema: internal
      columns: [id, customer_id, body]
pii_mask:
  patterns:
    - column_regex: "(?i)phone"
      strategy: redact
`;

const policy = testPolicy(JOIN_POLICY);

function codeOf(sql: string, p = policy): string {
  try {
    guardQuery(sql, p);
  } catch (err) {
    if (err instanceof GuardError) return err.code;
    throw err;
  }
  return "allowed";
}

const flat = (sql: string): string => sql.replace(/\s+/g, " ");

describe("joins: allowed shapes", () => {
  it("accepts INNER, LEFT, RIGHT and FULL joins with ON", () => {
    for (const kind of ["join", "inner join", "left join", "left outer join", "right join", "full join"]) {
      expect(codeOf(`select c.id, o.total_cents from customers c ${kind} orders o on o.customer_id = c.id`), kind).toBe("allowed");
    }
  });

  it("qualifies every column and schema-qualifies every table", () => {
    const r = guardQuery("select name, total_cents from customers c join orders o on customer_id = c.id where status = 'paid'", policy);
    const sql = flat(r.sql);
    expect(sql).toMatch(/c\s*\.\s*name/);
    expect(sql).toMatch(/o\s*\.\s*total_cents/);
    expect(sql).toMatch(/o\s*\.\s*customer_id/);
    expect(sql).toMatch(/o\s*\.\s*status/);
    expect(sql).toContain("public.orders");
    expect(sql).toContain("public.customers");
    expect(r.tables.map((t) => t.name)).toEqual(["customers", "orders"]);
  });

  it("binds require_predicate to its own table as a derived table exposing only used columns", () => {
    const r = guardQuery("select c.name, o.status from orders o left join customers c on c.id = o.customer_id", policy);
    const sql = flat(r.sql);
    expect(sql).toMatch(/LEFT JOIN \(SELECT id , name FROM public\.customers WHERE \(?deleted_at IS NULL\)? \) AS c/i);
    // The predicate is not in the outer WHERE, so it cannot turn the LEFT JOIN into an inner join.
    expect(sql).not.toMatch(/\)\s*AS c\s.*WHERE/i);
    expect(sql).not.toMatch(/billing_phone|created_at/);
  });

  it("supports self joins with distinct aliases", () => {
    expect(codeOf("select a.id, b.id from orders a join orders b on a.customer_id = b.customer_id")).toBe("allowed");
  });

  it("uses the smallest row cap of the joined tables", () => {
    const r = guardQuery("select c.id, o.id from customers c join orders o on o.customer_id = c.id limit 1000", policy);
    expect(r.limit).toBe(10);
    expect(r.limitClamped).toBe(true);
  });

  it("expands * and alias.* to allowed columns only", () => {
    const all = guardQuery("select * from customers c join orders o on o.customer_id = c.id", policy);
    expect(all.columns).toEqual(["id", "name", "created_at", "billing_phone", "id", "customer_id", "total_cents", "status"]);
    const one = guardQuery("select o.*, c.name from customers c join orders o on o.customer_id = c.id", policy);
    expect(one.columns).toEqual(["id", "customer_id", "total_cents", "status", "name"]);
    expect(one.sql).not.toContain("*");
  });
});

describe("joins: masks survive aliases", () => {
  it("masks aliased, expression and starred columns from a joined table", () => {
    const r = guardQuery(
      "select c.billing_phone as contact, upper(c.billing_phone) as up, o.status from customers c join orders o on o.customer_id = c.id",
      policy,
    );
    expect([...r.masked.keys()]).toEqual([0, 1]);
    const star = guardQuery("select c.*, o.status from customers c join orders o on o.customer_id = c.id", policy);
    expect([...star.masked.keys()]).toEqual([3]);
  });

  it("refuses masked columns in ON, WHERE and ORDER BY of a join", () => {
    expect(codeOf("select c.id from customers c join orders o on o.status = c.billing_phone")).toBe("masked_column_in_filter");
    expect(codeOf("select c.id from customers c join orders o on o.customer_id = c.id where c.billing_phone like '+353%'")).toBe(
      "masked_column_in_filter",
    );
    expect(codeOf("select c.id from customers c join orders o on o.customer_id = c.id order by c.billing_phone")).toBe(
      "masked_column_in_filter",
    );
  });
});

describe("joins: deny paths", () => {
  it("denies non-allowlisted tables and columns anywhere in a join", () => {
    expect(codeOf("select c.id from customers c join secrets s on s.id = c.id")).toBe("table_not_allowed");
    expect(codeOf("select c.email from customers c join orders o on o.customer_id = c.id")).toBe("column_not_allowed");
    expect(codeOf("select c.id from customers c join orders o on o.secret = c.id")).toBe("column_not_allowed");
    expect(codeOf("select c.id from customers c join pg_catalog.pg_user u on true")).toBe("table_not_allowed");
  });

  it("denies cross-schema joins even when both tables are allowlisted", () => {
    expect(codeOf("select c.id from customers c join internal.notes n on n.customer_id = c.id")).toBe("cross_schema_join");
    expect(codeOf("select n.id from internal.notes n")).toBe("allowed");
  });

  it("denies ambiguous unqualified columns and unknown qualifiers", () => {
    expect(codeOf("select id from customers c join orders o on o.customer_id = c.id")).toBe("ambiguous_column");
    expect(codeOf("select x.id from customers c join orders o on o.customer_id = c.id")).toBe("invalid_qualifier");
    expect(codeOf("select customers.id from customers c join orders o on o.customer_id = c.id")).toBe("invalid_qualifier");
    expect(codeOf("select public.c.id from customers c join orders o on o.customer_id = c.id")).toBe("invalid_qualifier");
  });

  it("denies comma, CROSS, USING and LATERAL joins, duplicate aliases and subqueries", () => {
    expect(codeOf("select c.id from customers c, orders o where o.customer_id = c.id")).toBe("join_not_supported");
    expect(codeOf("select c.id from customers c cross join orders o")).toBe("join_not_supported");
    expect(codeOf("select c.id from customers c join orders o using (id)")).toBe("join_not_supported");
    expect(codeOf("select c.id from customers c join lateral (select 1) x on true")).toBe("subquery_not_supported");
    expect(codeOf("select c.id from customers c join (select id from orders) o on o.id = c.id")).toBe("subquery_not_supported");
    expect(codeOf("select orders.id from orders join orders on true")).toBe("duplicate_alias");
  });

  it("honours max_join_tables, including 1 to switch joins off", () => {
    const off = testPolicy(JOIN_POLICY.replace("max_rows: 50", "max_rows: 50\n  max_join_tables: 1"));
    expect(codeOf("select c.id from customers c join orders o on o.customer_id = c.id", off)).toBe("join_not_supported");
    expect(codeOf("select id from customers", off)).toBe("allowed");
    const two = testPolicy(JOIN_POLICY.replace("max_rows: 50", "max_rows: 50\n  max_join_tables: 2"));
    expect(
      codeOf("select a.id from orders a join orders b on a.id = b.id join orders c on c.id = a.id", two),
    ).toBe("join_not_supported");
  });

  it("refuses $n parameters outside named views", () => {
    expect(codeOf("select id from orders where id = $1")).toBe("unsupported_syntax");
  });
});
