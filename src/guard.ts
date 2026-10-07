import { parse, toSql, type Statement } from "pgsql-ast-parser";
import type { CompiledTable, MaskStrategy, Policy } from "./policy.js";

export type ExprNode = Record<string, unknown>;

/** A denial raised by the SQL guard. `code` is stable and written to the audit log. */
export class GuardError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "GuardError";
  }
}

export interface GuardResult {
  /** SQL regenerated from the validated syntax tree. This, not the caller's text, is what runs. */
  sql: string;
  table: CompiledTable;
  /** Output column names, in order. */
  columns: string[];
  /** Output column index to mask strategy. */
  masked: Map<number, MaskStrategy>;
  /** The LIMIT that will be applied. */
  limit: number;
  /** True when the caller asked for more than the cap, or gave no limit. */
  limitClamped: boolean;
}

const MAX_SQL_LENGTH = 20_000;

/** Functions a caller may use. Everything else is denied, including pg_sleep, set_config and file access. */
const ALLOWED_FUNCTIONS = new Set([
  "count", "sum", "avg", "min", "max", "bool_and", "bool_or", "array_agg", "string_agg",
  "coalesce", "nullif", "greatest", "least", "any",
  "lower", "upper", "length", "char_length", "trim", "ltrim", "rtrim", "left", "right",
  "replace", "split_part", "concat", "to_char",
  "abs", "round", "ceil", "ceiling", "floor",
  "now", "date_trunc", "date_part", "age",
  "array_length", "cardinality",
]);

const ALLOWED_BINARY_OPS = new Set([
  "+", "-", "*", "/", "%", "^", "=", "!=", "<>", "<", ">", "<=", ">=",
  "AND", "OR", "LIKE", "ILIKE", "NOT LIKE", "NOT ILIKE", "IN", "NOT IN", "||", "~", "~*", "!~", "!~*",
]);

const ALLOWED_KEYWORDS = new Set([
  "current_date", "current_time", "current_timestamp", "localtime", "localtimestamp",
]);

const NODE_KEYS: Record<string, string[]> = {
  ref: ["type", "name", "table"],
  string: ["type", "value"],
  integer: ["type", "value"],
  numeric: ["type", "value"],
  boolean: ["type", "value"],
  null: ["type"],
  keyword: ["type", "keyword"],
  unary: ["type", "op", "operand"],
  binary: ["type", "op", "left", "right"],
  ternary: ["type", "op", "value", "lo", "hi"],
  list: ["type", "expressions"],
  array: ["type", "expressions"],
  call: ["type", "function", "args", "distinct"],
  cast: ["type", "operand", "to"],
  case: ["type", "value", "whens", "else"],
  extract: ["type", "field", "from"],
  member: ["type", "operand", "op", "member"],
  substring: ["type", "value", "from", "for"],
};

const STATEMENT_KEYS = new Set([
  "type", "columns", "from", "where", "groupBy", "having", "orderBy", "limit", "distinct",
]);

interface WalkCtx {
  table: CompiledTable | undefined;
  alias: string | undefined;
  /** Trusted mode is used for policy predicates: any column name is allowed. */
  trusted: boolean;
  refs: string[];
}

function isNode(v: unknown): v is ExprNode {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function checkKeys(node: ExprNode, kind: string): void {
  const allowed = NODE_KEYS[kind];
  if (!allowed) return;
  for (const key of Object.keys(node)) {
    if (!allowed.includes(key)) {
      throw new GuardError("unsupported_syntax", `unsupported ${kind} option: ${key}`);
    }
  }
}

function walkAll(nodes: unknown, ctx: WalkCtx): void {
  if (!Array.isArray(nodes)) throw new GuardError("unsupported_syntax", "malformed expression list");
  for (const n of nodes) walk(n, ctx);
}

function walkOptional(node: unknown, ctx: WalkCtx): void {
  if (node !== undefined && node !== null) walk(node, ctx);
}

function walk(node: unknown, ctx: WalkCtx): void {
  if (!isNode(node) || typeof node.type !== "string") {
    throw new GuardError("unsupported_syntax", "unsupported expression (subqueries are not allowed)");
  }
  const kind = node.type;
  if (!(kind in NODE_KEYS)) {
    throw new GuardError("unsupported_syntax", `unsupported expression type: ${kind}`);
  }
  checkKeys(node, kind);
  switch (kind) {
    case "ref": {
      const name = node.name;
      if (typeof name !== "string" || name === "*") {
        throw new GuardError("unsupported_syntax", "'*' is only allowed as a select item or inside count(*)");
      }
      const qualifier = node.table;
      if (qualifier !== undefined) {
        const q = qualifier as { name?: string; schema?: string };
        const expected = ctx.alias ?? ctx.table?.name;
        if (ctx.trusted || q.schema !== undefined || q.name !== expected) {
          throw new GuardError("invalid_qualifier", "column qualifier must be the queried table or its alias");
        }
      }
      if (!ctx.trusted && ctx.table && !ctx.table.columnSet.has(name)) {
        throw new GuardError(
          "column_not_allowed",
          `column "${name}" is not allowed on ${ctx.table.schema}.${ctx.table.name}`,
        );
      }
      ctx.refs.push(name);
      return;
    }
    case "keyword":
      if (!ALLOWED_KEYWORDS.has(String(node.keyword))) {
        throw new GuardError("unsupported_syntax", `keyword ${String(node.keyword)} is not allowed`);
      }
      return;
    case "unary":
      walk(node.operand, ctx);
      return;
    case "binary": {
      if (!ALLOWED_BINARY_OPS.has(String(node.op))) {
        throw new GuardError("unsupported_syntax", `operator ${String(node.op)} is not allowed`);
      }
      walk(node.left, ctx);
      walk(node.right, ctx);
      return;
    }
    case "ternary":
      walk(node.value, ctx);
      walk(node.lo, ctx);
      walk(node.hi, ctx);
      return;
    case "list":
    case "array":
      walkAll(node.expressions, ctx);
      return;
    case "call": {
      const fn = node.function as { name?: string; schema?: string } | undefined;
      const fname = fn?.name;
      if (!fname || fn?.schema !== undefined || !ALLOWED_FUNCTIONS.has(fname)) {
        throw new GuardError("function_not_allowed", `function ${fname ?? "(unknown)"} is not allowed`);
      }
      const args = node.args;
      if (!Array.isArray(args)) throw new GuardError("unsupported_syntax", "malformed function call");
      if (fname === "count" && args.length === 1 && isNode(args[0]) && args[0].type === "ref" && args[0].name === "*") {
        if (args[0].table !== undefined) throw new GuardError("unsupported_syntax", "count(t.*) is not supported");
        return;
      }
      walkAll(args, ctx);
      return;
    }
    case "cast": {
      const to = node.to as { name?: unknown; kind?: unknown; schema?: unknown } | undefined;
      const tname = typeof to?.name === "string" ? to.name.toLowerCase() : undefined;
      if (!tname || to?.schema !== undefined || tname.startsWith("reg") || tname === "oid") {
        throw new GuardError("unsupported_syntax", "this cast target is not allowed");
      }
      walk(node.operand, ctx);
      return;
    }
    case "case":
      walkOptional(node.value, ctx);
      if (!Array.isArray(node.whens)) throw new GuardError("unsupported_syntax", "malformed CASE");
      for (const w of node.whens) {
        if (!isNode(w)) throw new GuardError("unsupported_syntax", "malformed CASE");
        walk(w.when, ctx);
        walk(w.value, ctx);
      }
      walkOptional(node.else, ctx);
      return;
    case "extract":
      walk(node.from, ctx);
      return;
    case "member":
      walk(node.operand, ctx);
      return;
    case "substring":
      walk(node.value, ctx);
      walkOptional(node.from, ctx);
      walkOptional(node.for, ctx);
      return;
    default:
      return; // literals
  }
}

/** Validate and parse a policy require_predicate. Only used when loading a policy. */
export function compilePredicate(source: string): ExprNode {
  let stmts: Statement[];
  try {
    stmts = parse(`select 1 from t where (${source})`);
  } catch {
    throw new GuardError("policy_predicate", `require_predicate could not be parsed: ${source}`);
  }
  const stmt = stmts[0] as unknown as ExprNode | undefined;
  if (stmts.length !== 1 || !stmt || stmt.type !== "select") {
    throw new GuardError("policy_predicate", `require_predicate must be a single expression: ${source}`);
  }
  for (const key of Object.keys(stmt)) {
    if (!["type", "columns", "from", "where"].includes(key)) {
      throw new GuardError("policy_predicate", `require_predicate must be a single expression: ${source}`);
    }
  }
  const ctx: WalkCtx = { table: undefined, alias: undefined, trusted: true, refs: [] };
  walk(stmt.where, ctx);
  return stmt.where as ExprNode;
}

function firstWord(sql: string): string {
  const stripped = sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ").trim();
  return (stripped.match(/^[A-Za-z_]+/)?.[0] ?? "").toLowerCase();
}

function resolveTable(
  from: unknown,
  policy: Policy,
): { table: CompiledTable; alias: string | undefined; node: ExprNode } {
  if (!Array.isArray(from) || from.length === 0) {
    throw new GuardError("from_required", "a FROM clause with one allowed table is required");
  }
  if (from.length > 1) {
    throw new GuardError("join_not_supported", "v0 supports single-table SELECT only (no joins or multiple tables)");
  }
  const f = from[0] as ExprNode;
  if (f.type !== "table") {
    throw new GuardError("subquery_not_supported", "v0 supports a plain table in FROM only (no subqueries or functions)");
  }
  if ("join" in f) {
    throw new GuardError("join_not_supported", "v0 supports single-table SELECT only (no joins)");
  }
  const name = f.name as { name?: string; schema?: string; alias?: string; columnNames?: unknown } | undefined;
  if (!name?.name || name.columnNames !== undefined) {
    throw new GuardError("unsupported_syntax", "unsupported table reference");
  }
  for (const key of Object.keys(f)) {
    if (!["type", "name"].includes(key)) throw new GuardError("unsupported_syntax", `unsupported FROM option: ${key}`);
  }
  for (const key of Object.keys(name)) {
    if (!["name", "schema", "alias"].includes(key)) {
      throw new GuardError("unsupported_syntax", `unsupported table option: ${key}`);
    }
  }
  const candidates = policy.tables.filter((t) => t.name === name.name);
  let table: CompiledTable | undefined;
  if (name.schema !== undefined) {
    table = candidates.find((t) => t.schema === name.schema);
  } else {
    // Unqualified names resolve in allow.schemas order, never via the database search_path.
    for (const schema of policy.schemas) {
      table = candidates.find((t) => t.schema === schema);
      if (table) break;
    }
  }
  if (!table) {
    const shown = name.schema ? `${name.schema}.${name.name}` : name.name;
    throw new GuardError("table_not_allowed", `table "${shown}" is not in the policy`);
  }
  return { table, alias: name.alias, node: f };
}

function maskFor(policy: Policy, names: string[]): MaskStrategy | undefined {
  for (const rule of policy.masks) {
    if (names.some((n) => rule.regex.test(n))) return rule.strategy;
  }
  return undefined;
}

function outputName(expr: ExprNode, alias: string | undefined): string {
  if (alias) return alias;
  if (expr.type === "ref" && typeof expr.name === "string") return expr.name;
  if (expr.type === "call") return String((expr.function as { name?: string }).name ?? "?column?");
  return "?column?";
}

export function guardQuery(sql: string, policy: Policy): GuardResult {
  if (typeof sql !== "string" || sql.trim() === "") throw new GuardError("empty", "SQL is empty");
  if (sql.length > MAX_SQL_LENGTH) throw new GuardError("too_long", `SQL is longer than ${MAX_SQL_LENGTH} characters`);

  let stmts: Statement[];
  try {
    stmts = parse(sql);
  } catch {
    const word = firstWord(sql);
    if (word && word !== "select" && word !== "with") {
      throw new GuardError("non_read_statement", `only SELECT is allowed (found ${word.toUpperCase()})`);
    }
    throw new GuardError("parse_error", "SQL could not be parsed as a supported single-table SELECT");
  }
  if (stmts.length === 0) throw new GuardError("empty", "SQL is empty");
  if (stmts.length > 1) throw new GuardError("multi_statement", "exactly one statement is allowed");

  const stmt = stmts[0] as unknown as ExprNode;
  const stype = String(stmt.type);
  if (stype === "with" || stype === "with recursive") {
    throw new GuardError("cte_not_supported", "WITH queries are not supported in v0");
  }
  if (stype === "union" || stype === "union all") {
    throw new GuardError("set_operation_not_supported", "UNION is not supported in v0");
  }
  if (stype !== "select") {
    throw new GuardError("non_read_statement", `only SELECT is allowed (found ${stype.toUpperCase()})`);
  }
  for (const key of Object.keys(stmt)) {
    if (!STATEMENT_KEYS.has(key)) {
      throw new GuardError("unsupported_syntax", `unsupported SELECT clause: ${key}`);
    }
  }
  if (stmt.distinct !== undefined && stmt.distinct !== "distinct") {
    throw new GuardError("unsupported_syntax", "DISTINCT ON is not supported");
  }

  const { table, alias, node: fromNode } = resolveTable(stmt.from, policy);
  const ctx: WalkCtx = { table, alias, trusted: false, refs: [] };

  // Select list: expand '*' to the allowed columns, validate everything else.
  const rawCols = stmt.columns;
  if (!Array.isArray(rawCols) || rawCols.length === 0) {
    throw new GuardError("unsupported_syntax", "a select list is required");
  }
  const outCols: { expr: ExprNode; alias?: { name: string } }[] = [];
  const outNames: string[] = [];
  const masked = new Map<number, MaskStrategy>();
  for (const c of rawCols as ExprNode[]) {
    for (const key of Object.keys(c)) {
      if (!["expr", "alias"].includes(key)) {
        throw new GuardError("unsupported_syntax", `unsupported select item option: ${key}`);
      }
    }
    const expr = c.expr as ExprNode;
    const aliasName = (c.alias as { name?: string } | undefined)?.name;
    if (isNode(expr) && expr.type === "ref" && expr.name === "*") {
      const q = expr.table as { name?: string; schema?: string } | undefined;
      if (aliasName || (q && (q.schema !== undefined || q.name !== (alias ?? table.name)))) {
        throw new GuardError("invalid_qualifier", "invalid use of '*'");
      }
      for (const col of table.columns) {
        const idx = outCols.length;
        outCols.push({ expr: { type: "ref", name: col } });
        outNames.push(col);
        const strategy = maskFor(policy, [col]);
        if (strategy) masked.set(idx, strategy);
      }
      continue;
    }
    const local: WalkCtx = { ...ctx, refs: [] };
    walk(expr, local);
    const idx = outCols.length;
    outCols.push(aliasName ? { expr, alias: { name: aliasName } } : { expr });
    outNames.push(outputName(expr, aliasName));
    const strategy = maskFor(policy, [...local.refs, ...(aliasName ? [aliasName] : [])]);
    if (strategy) masked.set(idx, strategy);
  }

  // Filtering and ordering clauses. Masked columns may not be used here, otherwise
  // a caller could recover masked values by probing with predicates or sort order.
  const filterWalk = (node: unknown): void => {
    const local: WalkCtx = { ...ctx, refs: [] };
    walk(node, local);
    for (const ref of local.refs) {
      if (maskFor(policy, [ref]) !== undefined) {
        throw new GuardError("masked_column_in_filter", `masked column "${ref}" cannot be used to filter, group or sort`);
      }
    }
  };
  const sortWalk = (node: unknown, kind: "group" | "order"): void => {
    if (isNode(node) && node.type === "integer") {
      const n = Number(node.value);
      if (!Number.isInteger(n) || n < 1 || n > outCols.length) {
        throw new GuardError("unsupported_syntax", "ordinal position is out of range");
      }
      if (masked.has(n - 1)) {
        throw new GuardError("masked_column_in_filter", "a masked column cannot be used to group or sort");
      }
      return;
    }
    if (isNode(node) && node.type === "ref" && node.table === undefined && typeof node.name === "string") {
      const name = node.name;
      const aliasIdx = outNames.indexOf(name);
      const useAlias = kind === "order" ? aliasIdx >= 0 : aliasIdx >= 0 && !table.columnSet.has(name);
      if (useAlias) {
        if (masked.has(aliasIdx)) {
          throw new GuardError("masked_column_in_filter", `masked column "${name}" cannot be used to group or sort`);
        }
        return;
      }
    }
    filterWalk(node);
  };

  if (stmt.where !== undefined) filterWalk(stmt.where);
  const groupBy = stmt.groupBy as unknown[] | undefined;
  if (groupBy !== undefined) {
    if (!Array.isArray(groupBy)) throw new GuardError("unsupported_syntax", "malformed GROUP BY");
    for (const g of groupBy) sortWalk(g, "group");
  }
  if (stmt.having !== undefined) filterWalk(stmt.having);
  const orderBy = stmt.orderBy as ExprNode[] | undefined;
  if (orderBy !== undefined) {
    if (!Array.isArray(orderBy)) throw new GuardError("unsupported_syntax", "malformed ORDER BY");
    for (const o of orderBy) {
      for (const key of Object.keys(o)) {
        if (!["by", "order", "nulls"].includes(key)) {
          throw new GuardError("unsupported_syntax", `unsupported ORDER BY option: ${key}`);
        }
      }
      sortWalk(o.by, "order");
    }
  }

  // Row limit.
  const maxRows = table.maxRows;
  const limitNode = stmt.limit as { limit?: ExprNode; offset?: ExprNode } | undefined;
  let requested: number | undefined;
  let offset: ExprNode | undefined;
  if (limitNode) {
    for (const key of Object.keys(limitNode)) {
      if (!["limit", "offset"].includes(key)) throw new GuardError("unsupported_syntax", `unsupported LIMIT option: ${key}`);
    }
    if (limitNode.limit !== undefined) {
      if (!isNode(limitNode.limit) || limitNode.limit.type !== "integer") {
        throw new GuardError("unsupported_syntax", "LIMIT must be an integer literal");
      }
      requested = Number(limitNode.limit.value);
    }
    if (limitNode.offset !== undefined) {
      const o = limitNode.offset;
      if (!isNode(o) || o.type !== "integer") throw new GuardError("unsupported_syntax", "OFFSET must be an integer literal");
      offset = o;
    }
  }
  let limit = requested ?? maxRows;
  let limitClamped = requested === undefined;
  if (requested === undefined && policy.requireLimit) {
    throw new GuardError("limit_required", `a LIMIT of at most ${maxRows} is required`);
  }
  if (requested !== undefined && requested > maxRows) {
    if (policy.limitMode === "refuse") {
      throw new GuardError("row_limit_exceeded", `LIMIT ${requested} exceeds the policy maximum of ${maxRows}`);
    }
    limit = maxRows;
    limitClamped = true;
  }

  // Rewrite: expanded select list, schema-qualified table, predicate ANDed in, clamped limit.
  const rewritten: ExprNode = { ...stmt };
  rewritten.columns = outCols;
  const fromName = { ...(fromNode.name as ExprNode), schema: table.schema };
  rewritten.from = [{ ...fromNode, name: fromName }];
  if (table.requirePredicate) {
    const pred = structuredClone(table.requirePredicate);
    rewritten.where = stmt.where === undefined ? pred : { type: "binary", op: "AND", left: stmt.where, right: pred };
  }
  rewritten.limit = { limit: { type: "integer", value: limit }, ...(offset ? { offset } : {}) };

  const out = toSql.statement(rewritten as unknown as Statement);

  // Defence in depth: the regenerated text must itself be exactly one SELECT.
  let check: Statement[];
  try {
    check = parse(out);
  } catch {
    throw new GuardError("rewrite_failed", "could not safely rewrite the query");
  }
  if (check.length !== 1 || check[0]?.type !== "select") {
    throw new GuardError("rewrite_failed", "could not safely rewrite the query");
  }

  return { sql: out, table, columns: outNames, masked, limit, limitClamped };
}
