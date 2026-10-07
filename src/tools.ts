import { GuardError, guardQuery } from "./guard.js";
import type { AuditSink } from "./audit.js";
import type { Db } from "./db.js";
import { maskRows } from "./mask.js";
import type { CompiledTable, Policy } from "./policy.js";

export interface Runtime {
  policy: Policy;
  db: Db;
  audit: AuditSink;
}

export type ToolOutcome =
  | { ok: true; data: Record<string, unknown> }
  | { ok: false; code: string; message: string };

function deny(code: string, message: string): ToolOutcome {
  return { ok: false, code, message };
}

function dedupe(names: string[]): string[] {
  const seen = new Map<string, number>();
  return names.map((n) => {
    const count = (seen.get(n) ?? 0) + 1;
    seen.set(n, count);
    return count === 1 ? n : `${n}_${count}`;
  });
}

function dbMessage(err: unknown): string {
  const e = err as { code?: unknown; message?: unknown };
  const code = typeof e.code === "string" ? e.code : "unknown";
  // pg errors can echo connection details, so keep only the code and a trimmed message.
  const message = typeof e.message === "string" ? e.message.replace(/postgres(ql)?:\/\/\S+/gi, "[dsn]").slice(0, 200) : "";
  return `database error (${code}): ${message}`;
}

export async function handleQuery(rt: Runtime, input: { sql: string }): Promise<ToolOutcome> {
  const started = Date.now();
  const elapsed = (): number => Date.now() - started;
  const sql = typeof input.sql === "string" ? input.sql : "";

  let guarded;
  try {
    guarded = guardQuery(sql, rt.policy);
  } catch (err) {
    if (err instanceof GuardError) {
      rt.audit.write({ tool: "query", decision: "deny", reason: `${err.code}: ${err.message}`, sql, duration_ms: elapsed() });
      return deny(err.code, err.message);
    }
    throw err;
  }

  const table = `${guarded.table.schema}.${guarded.table.name}`;
  let result;
  try {
    result = await rt.db.runReadOnly(guarded.sql, rt.policy.statementTimeoutMs);
  } catch (err) {
    const message = dbMessage(err);
    rt.audit.write({ tool: "query", decision: "deny", reason: "db_error", sql, table, duration_ms: elapsed() });
    return deny("db_error", message);
  }

  // Defence in depth: never return more than the cap even if the database did.
  const limited = result.rows.slice(0, guarded.limit);
  const rows = maskRows(limited, guarded.masked);
  const columns = dedupe(guarded.columns);
  rt.audit.write({ tool: "query", decision: "allow", reason: "ok", sql, table, row_count: rows.length, duration_ms: elapsed() });
  return {
    ok: true,
    data: {
      table,
      columns,
      rows: rows.map((r) => Object.fromEntries(columns.map((c, i) => [c, r[i]]))),
      row_count: rows.length,
      row_limit: guarded.limit,
      limit_clamped: guarded.limitClamped,
      may_have_more: guarded.limitClamped && rows.length >= guarded.limit,
      masked_columns: [...guarded.masked.keys()].map((i) => columns[i]),
    },
  };
}

function findTable(policy: Policy, name: string, schema?: string): CompiledTable | undefined {
  if (schema !== undefined) return policy.tables.find((t) => t.name === name && t.schema === schema);
  for (const s of policy.schemas) {
    const hit = policy.tables.find((t) => t.name === name && t.schema === s);
    if (hit) return hit;
  }
  return undefined;
}

export function handleListTables(rt: Runtime): ToolOutcome {
  const started = Date.now();
  const tables = rt.policy.tables.map((t) => ({
    schema: t.schema,
    name: t.name,
    columns: t.columns,
    max_rows: t.maxRows,
    filtered: t.requirePredicateSource !== undefined,
  }));
  rt.audit.write({ tool: "list_tables", decision: "allow", reason: "ok", row_count: tables.length, duration_ms: Date.now() - started });
  return { ok: true, data: { tables } };
}

export async function handleDescribeTable(
  rt: Runtime,
  input: { table: string; schema?: string | undefined },
): Promise<ToolOutcome> {
  const started = Date.now();
  const table = findTable(rt.policy, input.table, input.schema);
  if (!table) {
    const shown = input.schema ? `${input.schema}.${input.table}` : input.table;
    const message = `table "${shown}" is not in the policy`;
    rt.audit.write({ tool: "describe_table", decision: "deny", reason: `table_not_allowed: ${message}`, duration_ms: Date.now() - started });
    return deny("table_not_allowed", message);
  }
  const name = `${table.schema}.${table.name}`;
  let info;
  try {
    info = await rt.db.columnsOf(table.schema, table.name);
  } catch (err) {
    rt.audit.write({ tool: "describe_table", decision: "deny", reason: "db_error", table: name, duration_ms: Date.now() - started });
    return deny("db_error", dbMessage(err));
  }
  const byName = new Map(info.map((c) => [c.name, c]));
  // Only policy columns are ever reported. Columns outside the allowlist are not revealed.
  const columns = table.columns.map((c) => {
    const found = byName.get(c);
    return {
      name: c,
      type: found?.type ?? "unknown",
      nullable: found?.nullable ?? null,
      masked: rt.policy.masks.some((m) => m.regex.test(c)),
    };
  });
  rt.audit.write({ tool: "describe_table", decision: "allow", reason: "ok", table: name, row_count: columns.length, duration_ms: Date.now() - started });
  return {
    ok: true,
    data: { table: name, columns, max_rows: table.maxRows, require_predicate: table.requirePredicateSource ?? null },
  };
}

export function handlePolicyInfo(rt: Runtime): ToolOutcome {
  const started = Date.now();
  const p = rt.policy;
  rt.audit.write({ tool: "policy_info", decision: "allow", reason: "ok", duration_ms: Date.now() - started });
  return {
    ok: true,
    data: {
      version: p.version,
      policy_hash: p.hash,
      read_only: true,
      single_table_select_only: true,
      defaults: {
        max_rows: p.maxRows,
        statement_timeout_ms: p.statementTimeoutMs,
        limit_mode: p.limitMode,
        require_limit: p.requireLimit,
      },
      schemas: p.schemas,
      tables: p.tables.map((t) => ({
        schema: t.schema,
        name: t.name,
        columns: t.columns,
        max_rows: t.maxRows,
        require_predicate: t.requirePredicateSource ?? null,
      })),
      pii_mask: p.masks.map((m) => ({ column_regex: m.source, strategy: m.strategy })),
    },
  };
}

export async function handlePing(rt: Runtime): Promise<ToolOutcome> {
  const started = Date.now();
  try {
    await rt.db.ping();
  } catch (err) {
    rt.audit.write({ tool: "ping", decision: "deny", reason: "db_error", duration_ms: Date.now() - started });
    return deny("db_error", dbMessage(err));
  }
  const ms = Date.now() - started;
  rt.audit.write({ tool: "ping", decision: "allow", reason: "ok", duration_ms: ms });
  return { ok: true, data: { status: "ok", latency_ms: ms } };
}
