import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { compilePredicate, GuardError, guardQuery, PARAM_CASTS, type ExprNode, type GuardResult, type ParamType } from "./guard.js";

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

const identifier = z.string().min(1).max(63);

const TableSchema = z
  .object({
    name: identifier,
    schema: identifier.optional(),
    columns: z.array(identifier).min(1),
    require_predicate: z.string().min(1).optional(),
    max_rows: z.number().int().positive().optional(),
  })
  .strict();

const MaskSchema = z
  .object({
    column_regex: z.string().min(1),
    strategy: z.enum(["redact", "null", "hash"]).default("redact"),
  })
  .strict();

const viewName = z.string().regex(/^[a-z][a-z0-9_]{0,62}$/, "view names are lower case letters, digits and underscores");

const ParamSchema = z
  .object({
    name: viewName,
    type: z.enum(Object.keys(PARAM_CASTS) as [ParamType, ...ParamType[]]),
    description: z.string().max(500).optional(),
    default: z.union([z.string(), z.number(), z.boolean()]).optional(),
  })
  .strict();

const ViewSchema = z
  .object({
    name: viewName,
    description: z.string().max(1000).optional(),
    sql: z.string().min(1).max(20_000),
    params: z.array(ParamSchema).max(20).default([]),
  })
  .strict();

const RotateSchema = z
  .object({
    max_bytes: z.number().int().min(1024).optional(),
    daily: z.boolean().default(false),
    keep: z.number().int().positive().optional(),
  })
  .strict();

const PolicySchema = z
  .object({
    version: z.literal(1),
    connection_env: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/).default("DATABASE_URL"),
    readonly: z.literal(true, { error: "v0 is read-only: set readonly: true" }),
    defaults: z
      .object({
        max_rows: z.number().int().positive().max(100_000).default(100),
        statement_timeout_ms: z.number().int().positive().max(600_000).default(5000),
        limit_mode: z.enum(["clamp", "refuse"]).default("clamp"),
        require_limit: z.boolean().default(false),
        max_join_tables: z.number().int().min(1).max(8).default(4),
      })
      .strict()
      .prefault({}),
    allow: z
      .object({
        schemas: z.array(identifier).min(1),
        tables: z.array(TableSchema).min(1),
      })
      .strict(),
    pii_mask: z
      .object({ patterns: z.array(MaskSchema).default([]) })
      .strict()
      .prefault({}),
    views: z.array(ViewSchema).max(100).default([]),
    deny_sql: z.array(z.string()).optional(),
    audit: z.object({ path: z.string().min(1).optional(), rotate: RotateSchema.optional() }).strict().optional(),
  })
  .strict();

export type MaskStrategy = "redact" | "null" | "hash";

export interface CompiledTable {
  schema: string;
  name: string;
  columns: string[];
  columnSet: ReadonlySet<string>;
  requirePredicateSource?: string;
  /** Parsed predicate expression, ANDed into every query for this table. */
  requirePredicate?: ExprNode;
  maxRows: number;
}

export interface MaskRule {
  source: string;
  regex: RegExp;
  strategy: MaskStrategy;
}

export interface ViewParam {
  name: string;
  type: ParamType;
  description?: string;
  default?: string | number | boolean;
}

export interface CompiledView {
  name: string;
  description?: string;
  /** The SQL as written in the policy. */
  source: string;
  params: ViewParam[];
  /** The guarded, regenerated statement with typed $n placeholders. */
  guarded: GuardResult;
}

export interface AuditRotation {
  maxBytes?: number;
  daily: boolean;
  keep?: number;
}

export interface Policy {
  version: 1;
  hash: string;
  connectionEnv: string;
  maxRows: number;
  statementTimeoutMs: number;
  limitMode: "clamp" | "refuse";
  requireLimit: boolean;
  maxJoinTables: number;
  schemas: string[];
  tables: CompiledTable[];
  masks: MaskRule[];
  views: CompiledView[];
  auditPath?: string;
  auditRotation?: AuditRotation;
}

function compileRegex(source: string): RegExp {
  let flags = "";
  let body = source;
  // JavaScript has no inline flags, so support the common (?i) prefix used in policy files.
  if (body.startsWith("(?i)")) {
    flags = "i";
    body = body.slice(4);
  }
  try {
    return new RegExp(body, flags);
  } catch {
    throw new PolicyError(`pii_mask column_regex is not a valid regular expression: ${source}`);
  }
}

export function parsePolicy(raw: string, format: "yaml" | "json"): Policy {
  let data: unknown;
  try {
    data = format === "json" ? JSON.parse(raw) : parseYaml(raw);
  } catch (err) {
    throw new PolicyError(`policy file could not be parsed: ${(err as Error).message}`);
  }
  const result = PolicySchema.safeParse(data);
  if (!result.success) {
    const detail = result.error.issues
      .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("; ");
    throw new PolicyError(`policy is invalid: ${detail}`);
  }
  const p = result.data;
  const schemaSet = new Set(p.allow.schemas);
  const tables: CompiledTable[] = p.allow.tables.map((t) => {
    const schema = t.schema ?? (schemaSet.has("public") ? "public" : (p.allow.schemas[0] as string));
    if (!schemaSet.has(schema)) {
      throw new PolicyError(`table ${t.name} uses schema ${schema}, which is not in allow.schemas`);
    }
    const compiled: CompiledTable = {
      schema,
      name: t.name,
      columns: [...new Set(t.columns)],
      columnSet: new Set(t.columns),
      maxRows: t.max_rows ?? p.defaults.max_rows,
    };
    if (t.require_predicate) {
      compiled.requirePredicateSource = t.require_predicate;
      try {
        compiled.requirePredicate = compilePredicate(t.require_predicate);
      } catch (err) {
        if (err instanceof GuardError) throw new PolicyError(`table ${t.name}: ${err.message}`);
        throw err;
      }
    }
    return compiled;
  });
  const seen = new Set<string>();
  for (const t of tables) {
    const key = `${t.schema}.${t.name}`;
    if (seen.has(key)) throw new PolicyError(`table ${key} is listed twice`);
    seen.add(key);
  }
  const policy: Policy = {
    version: 1,
    hash: createHash("sha256").update(raw).digest("hex").slice(0, 16),
    connectionEnv: p.connection_env,
    maxRows: p.defaults.max_rows,
    statementTimeoutMs: p.defaults.statement_timeout_ms,
    limitMode: p.defaults.limit_mode,
    requireLimit: p.defaults.require_limit,
    maxJoinTables: p.defaults.max_join_tables,
    schemas: p.allow.schemas,
    tables,
    masks: p.pii_mask.patterns.map((m) => ({
      source: m.column_regex,
      regex: compileRegex(m.column_regex),
      strategy: m.strategy,
    })),
    views: [],
  };
  policy.views = p.views.map((v) => compileView(v, policy));
  const viewNames = new Set<string>();
  for (const v of policy.views) {
    if (viewNames.has(v.name)) throw new PolicyError(`view ${v.name} is listed twice`);
    viewNames.add(v.name);
  }
  if (p.audit?.path) policy.auditPath = p.audit.path;
  if (p.audit?.rotate) {
    const r = p.audit.rotate;
    policy.auditRotation = {
      daily: r.daily,
      ...(r.max_bytes !== undefined ? { maxBytes: r.max_bytes } : {}),
      ...(r.keep !== undefined ? { keep: r.keep } : {}),
    };
  }
  return policy;
}

type RawView = z.infer<typeof ViewSchema>;

/**
 * Validate a named view at load time: its SQL must pass the same guard as an ad hoc
 * query (allowlists, predicates, masks, row cap), with $1..$n bound to the declared
 * parameters in order. A view that would be denied as a query makes the policy invalid.
 */
function compileView(v: RawView, policy: Policy): CompiledView {
  const paramNames = new Set<string>();
  for (const prm of v.params) {
    if (paramNames.has(prm.name)) throw new PolicyError(`view ${v.name}: parameter ${prm.name} is listed twice`);
    paramNames.add(prm.name);
    if (prm.default !== undefined) {
      const err = checkParamValue(prm.type, prm.default);
      if (err) throw new PolicyError(`view ${v.name}: default for ${prm.name} ${err}`);
    }
  }
  let guarded: GuardResult;
  try {
    guarded = guardQuery(v.sql, policy, { paramTypes: v.params.map((prm) => prm.type) });
  } catch (err) {
    if (err instanceof GuardError) throw new PolicyError(`view ${v.name} is not allowed by this policy: ${err.code}: ${err.message}`);
    throw err;
  }
  const view: CompiledView = {
    name: v.name,
    source: v.sql,
    params: v.params.map((prm) => ({
      name: prm.name,
      type: prm.type,
      ...(prm.description !== undefined ? { description: prm.description } : {}),
      ...(prm.default !== undefined ? { default: prm.default } : {}),
    })),
    guarded,
  };
  if (v.description !== undefined) view.description = v.description;
  return view;
}

const MAX_TEXT_PARAM = 1000;

/** Returns an error message, or undefined when the value is valid for the declared type. */
export function checkParamValue(type: ParamType, value: unknown): string | undefined {
  switch (type) {
    case "text":
      return typeof value === "string" && value.length <= MAX_TEXT_PARAM ? undefined : `must be a string of at most ${MAX_TEXT_PARAM} characters`;
    case "integer":
      return typeof value === "number" && Number.isSafeInteger(value) ? undefined : "must be an integer";
    case "numeric":
      return typeof value === "number" && Number.isFinite(value) ? undefined : "must be a finite number";
    case "boolean":
      return typeof value === "boolean" ? undefined : "must be true or false";
    case "date":
      return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value))
        ? undefined
        : "must be a date (YYYY-MM-DD)";
    case "timestamp":
      return typeof value === "string" &&
        /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:?\d{2})?)?$/.test(value) &&
        !Number.isNaN(Date.parse(value))
        ? undefined
        : "must be an ISO 8601 timestamp";
    default:
      return "has an unknown type";
  }
}

export function loadPolicy(path: string): Policy {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new PolicyError(`policy file could not be read at ${path}: ${(err as Error).message}`);
  }
  return parsePolicy(raw, extname(path).toLowerCase() === ".json" ? "json" : "yaml");
}
