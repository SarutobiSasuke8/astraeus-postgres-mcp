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
  /** The first (or only) table in FROM. */
  table: CompiledTable;
  /** Every table the query reads, in FROM order. */
  tables: CompiledTable[];
  /** Output column names, in order. */
  columns: string[];
  /** Output column index to mask strategy. */
  masked: Map<number, MaskStrategy>;
  /** The LIMIT that will be applied. */
  limit: number;
  /** True when the caller asked for more than the cap, or gave no limit. */
  limitClamped: boolean;
  /** Number of positional parameters ($1..$n). Always 0 outside named views. */
  paramCount: number;
}

/** Parameter types a named view may declare, mapped to the Postgres cast applied to the placeholder. */
export const PARAM_CASTS = {
  text: "text",
  integer: "bigint",
  numeric: "numeric",
  boolean: "boolean",
  date: "date",
  timestamp: "timestamptz",
} as const;
export type ParamType = keyof typeof PARAM_CASTS;

export interface GuardOptions {
  /** Named-view mode: allow $1..$n placeholders, each cast to the declared type. */
  paramTypes?: ParamType[];
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

/** Join types that may be used. CROSS JOIN, comma joins, NATURAL, USING and LATERAL are refused. */
const ALLOWED_JOINS = new Set(["INNER JOIN", "LEFT JOIN", "RIGHT JOIN", "FULL JOIN"]);

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
  parameter: ["type", "name"],
};

const STATEMENT_KEYS = new Set([
  "type", "columns", "from", "where", "groupBy", "having", "orderBy", "limit", "distinct",
]);

/** One table in FROM, with the name it is referred to by (its alias, or its table name). */
interface Source {
  table: CompiledTable;
  alias: string | undefined;
  refName: string;
  node: ExprNode;
  /** Allowlisted columns of this table that the query touches. */
  used: Set<string>;
}

interface WalkCtx {
  sources: Source[];
  /** Trusted mode is used for policy predicates: any column name is allowed. */
  trusted: boolean;
  /** Join mode: every column reference is rewritten with its table qualifier. */
  qualify: boolean;
  refs: string[];
  paramTypes: ParamType[] | undefined;
  paramsSeen: Set<number>;
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

function label(t: CompiledTable): string {
  return `${t.schema}.${t.name}`;
}

/** Find the FROM source a column reference belongs to, or throw. */
function resolveRef(name: string, qualifier: { name?: string; schema?: string } | undefined, ctx: WalkCtx): Source {
  const { sources } = ctx;
  if (qualifier !== undefined) {
    const hit = qualifier.schema === undefined ? sources.find((s) => s.refName === qualifier.name) : undefined;
    if (!hit) {
      throw new GuardError(
        "invalid_qualifier",
        sources.length === 1
          ? "column qualifier must be the queried table or its alias"
          : "column qualifier must be one of the joined tables' aliases",
      );
    }
    if (!hit.table.columnSet.has(name)) {
      throw new GuardError("column_not_allowed", `column "${name}" is not allowed on ${label(hit.table)}`);
    }
    return hit;
  }
  if (sources.length === 1) {
    const only = sources[0] as Source;
    if (!only.table.columnSet.has(name)) {
      throw new GuardError("column_not_allowed", `column "${name}" is not allowed on ${label(only.table)}`);
    }
    return only;
  }
  const matches = sources.filter((s) => s.table.columnSet.has(name));
  if (matches.length === 0) {
    throw new GuardError("column_not_allowed", `column "${name}" is not allowed on any table in this query`);
  }
  if (matches.length > 1) {
    throw new GuardError("ambiguous_column", `column "${name}" is allowed on more than one joined table: qualify it with an alias`);
  }
  return matches[0] as Source;
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
      const qualifier = node.table as { name?: string; schema?: string } | undefined;
      if (ctx.trusted) {
        if (qualifier !== undefined) {
          throw new GuardError("invalid_qualifier", "policy predicates must use unqualified column names");
        }
        ctx.refs.push(name);
        return;
      }
      const source = resolveRef(name, qualifier, ctx);
      source.used.add(name);
      if (ctx.qualify) node.table = { name: source.refName };
      ctx.refs.push(name);
      return;
    }
    case "parameter": {
      const match = /^\$([1-9][0-9]{0,2})$/.exec(String(node.name));
      if (!ctx.paramTypes) {
        throw new GuardError("unsupported_syntax", "parameters are only allowed in named views defined in the policy");
      }
      const index = match ? Number(match[1]) : NaN;
      const type = ctx.paramTypes[index - 1];
      if (!type) {
        throw new GuardError("unsupported_syntax", `parameter ${String(node.name)} is not declared`);
      }
      ctx.paramsSeen.add(index);
      // Cast every placeholder to its declared type, so Postgres never has to guess.
      const placeholder = { type: "parameter", name: node.name };
      delete node.name;
      Object.assign(node, { type: "cast", operand: placeholder, to: { name: PARAM_CASTS[type] } });
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
  const ctx: WalkCtx = {
    sources: [],
    trusted: true,
    qualify: false,
    refs: [],
    paramTypes: undefined,
    paramsSeen: new Set(),
  };
  walk(stmt.where, ctx);
  return stmt.where as ExprNode;
}

function firstWord(sql: string): string {
  const stripped = sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ").trim();
  return (stripped.match(/^[A-Za-z_]+/)?.[0] ?? "").toLowerCase();
}

function lookupTable(policy: Policy, name: { name: string; schema?: string }): CompiledTable {
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
  return table;
}

function resolveFrom(from: unknown, policy: Policy): Source[] {
  if (!Array.isArray(from) || from.length === 0) {
    throw new GuardError("from_required", "a FROM clause with at least one allowed table is required");
  }
  if (from.length > policy.maxJoinTables) {
    throw new GuardError(
      "join_not_supported",
      policy.maxJoinTables === 1
        ? "joins are disabled by this policy (max_join_tables: 1)"
        : `at most ${policy.maxJoinTables} tables may be joined in one query`,
    );
  }
  const sources: Source[] = [];
  from.forEach((raw, i) => {
    const f = raw as ExprNode;
    if (f.type !== "table") {
      throw new GuardError("subquery_not_supported", "only plain allowlisted tables are allowed in FROM (no subqueries or functions)");
    }
    for (const key of Object.keys(f)) {
      if (!["type", "name", "join"].includes(key)) throw new GuardError("unsupported_syntax", `unsupported FROM option: ${key}`);
    }
    const join = f.join as { type?: string; on?: unknown; using?: unknown } | undefined;
    if (i > 0 && join === undefined) {
      throw new GuardError("join_not_supported", "comma joins are not supported: use JOIN ... ON");
    }
    if (join !== undefined) {
      for (const key of Object.keys(join)) {
        if (!["type", "on"].includes(key)) {
          throw new GuardError("join_not_supported", "JOIN ... USING is not supported: use JOIN ... ON");
        }
      }
      if (!ALLOWED_JOINS.has(String(join.type))) {
        throw new GuardError("join_not_supported", `${String(join.type)} is not supported: use INNER, LEFT, RIGHT or FULL JOIN ... ON`);
      }
      if (join.on === undefined) throw new GuardError("join_not_supported", "a join needs an ON condition");
    }
    const name = f.name as { name?: string; schema?: string; alias?: string; columnNames?: unknown } | undefined;
    if (!name?.name || name.columnNames !== undefined) {
      throw new GuardError("unsupported_syntax", "unsupported table reference");
    }
    for (const key of Object.keys(name)) {
      if (!["name", "schema", "alias"].includes(key)) {
        throw new GuardError("unsupported_syntax", `unsupported table option: ${key}`);
      }
    }
    const table = lookupTable(policy, { name: name.name, ...(name.schema !== undefined ? { schema: name.schema } : {}) });
    const refName = name.alias ?? table.name;
    if (sources.some((s) => s.refName === refName)) {
      throw new GuardError("duplicate_alias", `"${refName}" is used twice in FROM: give each table its own alias`);
    }
    sources.push({ table, alias: name.alias, refName, node: f, used: new Set() });
  });
  const schemas = new Set(sources.map((s) => s.table.schema));
  if (schemas.size > 1) {
    throw new GuardError("cross_schema_join", `joins across schemas are not allowed (${[...schemas].join(", ")})`);
  }
  return sources;
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

/**
 * The FROM item a source becomes after rewriting. In join mode a table with a
 * require_predicate is replaced by a derived table that already has the predicate
 * applied and exposes only the allowlisted columns the query uses. That keeps the
 * predicate bound to its own table under every join type, including outer joins.
 */
function rewriteSource(s: Source, joinMode: boolean): ExprNode {
  const join = s.node.join as ExprNode | undefined;
  const withJoin = (item: ExprNode): ExprNode => (join ? { ...item, join } : item);
  if (!joinMode || !s.table.requirePredicate) {
    const name: ExprNode = { name: s.table.name, schema: s.table.schema };
    if (s.alias !== undefined) name.alias = s.alias;
    return withJoin({ type: "table", name });
  }
  const inner: ExprNode = {
    type: "select",
    columns: s.table.columns.filter((c) => s.used.has(c)).map((c) => ({ expr: { type: "ref", name: c } })),
    from: [{ type: "table", name: { name: s.table.name, schema: s.table.schema } }],
    where: structuredClone(s.table.requirePredicate),
  };
  return withJoin({ type: "statement", statement: inner, alias: s.refName });
}

export function guardQuery(sql: string, policy: Policy, opts: GuardOptions = {}): GuardResult {
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
    throw new GuardError("parse_error", "SQL could not be parsed as a supported SELECT");
  }
  if (stmts.length === 0) throw new GuardError("empty", "SQL is empty");
  if (stmts.length > 1) throw new GuardError("multi_statement", "exactly one statement is allowed");

  const stmt = stmts[0] as unknown as ExprNode;
  const stype = String(stmt.type);
  if (stype === "with" || stype === "with recursive") {
    throw new GuardError("cte_not_supported", "WITH queries are not supported");
  }
  if (stype === "union" || stype === "union all") {
    throw new GuardError("set_operation_not_supported", "UNION is not supported");
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

  const sources = resolveFrom(stmt.from, policy);
  const joinMode = sources.length > 1;
  const ctx: WalkCtx = {
    sources,
    trusted: false,
    qualify: joinMode,
    refs: [],
    paramTypes: opts.paramTypes,
    paramsSeen: new Set(),
  };
  const anyAllows = (name: string): boolean => sources.some((s) => s.table.columnSet.has(name));

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
      let expand: Source[] = sources;
      if (q !== undefined) {
        const hit = q.schema === undefined ? sources.find((s) => s.refName === q.name) : undefined;
        if (!hit) throw new GuardError("invalid_qualifier", "invalid use of '*'");
        expand = [hit];
      }
      if (aliasName) throw new GuardError("invalid_qualifier", "invalid use of '*'");
      for (const s of expand) {
        for (const col of s.table.columns) {
          const idx = outCols.length;
          const ref: ExprNode = joinMode ? { type: "ref", name: col, table: { name: s.refName } } : { type: "ref", name: col };
          s.used.add(col);
          outCols.push({ expr: ref });
          outNames.push(col);
          const strategy = maskFor(policy, [col]);
          if (strategy) masked.set(idx, strategy);
        }
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

  // Filtering, joining and ordering clauses. Masked columns may not be used here,
  // otherwise a caller could recover masked values by probing with predicates,
  // join conditions or sort order.
  const filterWalk = (node: unknown): void => {
    const local: WalkCtx = { ...ctx, refs: [] };
    walk(node, local);
    for (const ref of local.refs) {
      if (maskFor(policy, [ref]) !== undefined) {
        throw new GuardError("masked_column_in_filter", `masked column "${ref}" cannot be used to filter, join, group or sort`);
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
      const useAlias = kind === "order" ? aliasIdx >= 0 : aliasIdx >= 0 && !anyAllows(name);
      if (useAlias) {
        if (masked.has(aliasIdx)) {
          throw new GuardError("masked_column_in_filter", `masked column "${name}" cannot be used to group or sort`);
        }
        return;
      }
    }
    filterWalk(node);
  };

  for (const s of sources) {
    const on = (s.node.join as { on?: unknown } | undefined)?.on;
    if (on !== undefined) filterWalk(on);
  }
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

  // Every declared view parameter must be used, so a view cannot silently ignore input.
  if (opts.paramTypes) {
    for (let i = 1; i <= opts.paramTypes.length; i += 1) {
      if (!ctx.paramsSeen.has(i)) throw new GuardError("unsupported_syntax", `parameter $${i} is declared but not used`);
    }
  }

  // Row limit: the smallest cap of any table read.
  const maxRows = Math.min(...sources.map((s) => s.table.maxRows));
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

  // Rewrite: expanded select list, schema-qualified tables, predicates applied, clamped limit.
  const rewritten: ExprNode = { ...stmt };
  rewritten.columns = outCols;
  rewritten.from = sources.map((s) => rewriteSource(s, joinMode));
  const only = sources[0] as Source;
  if (!joinMode && only.table.requirePredicate) {
    const pred = structuredClone(only.table.requirePredicate);
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

  return {
    sql: out,
    table: only.table,
    tables: sources.map((s) => s.table),
    columns: outNames,
    masked,
    limit,
    limitClamped,
    paramCount: opts.paramTypes?.length ?? 0,
  };
}
