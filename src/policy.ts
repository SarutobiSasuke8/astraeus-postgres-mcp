import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { compilePredicate, GuardError, type ExprNode } from "./guard.js";

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
    deny_sql: z.array(z.string()).optional(),
    audit: z.object({ path: z.string().min(1).optional() }).strict().optional(),
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

export interface Policy {
  version: 1;
  hash: string;
  connectionEnv: string;
  maxRows: number;
  statementTimeoutMs: number;
  limitMode: "clamp" | "refuse";
  requireLimit: boolean;
  schemas: string[];
  tables: CompiledTable[];
  masks: MaskRule[];
  auditPath?: string;
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
    schemas: p.allow.schemas,
    tables,
    masks: p.pii_mask.patterns.map((m) => ({
      source: m.column_regex,
      regex: compileRegex(m.column_regex),
      strategy: m.strategy,
    })),
  };
  if (p.audit?.path) policy.auditPath = p.audit.path;
  return policy;
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
