import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

export interface AuditEntry {
  tool: string;
  decision: "allow" | "deny";
  reason: string;
  sql?: string;
  table?: string;
  row_count?: number;
  duration_ms: number;
}

export interface AuditSink {
  readonly path: string;
  write(entry: AuditEntry): void;
}

/**
 * Strip literals so values (names, emails, tokens) do not reach the log, and
 * collapse whitespace. Applied to the caller's SQL on both allow and deny paths.
 */
export function normaliseSql(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\n]*/g, " ")
    .replace(/'(?:[^']|'')*'/g, "?")
    .replace(/\$([A-Za-z0-9_]*)\$[\s\S]*?\$\1\$/g, "?")
    .replace(/\b\d+(?:\.\d+)?\b/g, "?")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 2000);
}

/** Append-only JSONL audit log. A failed write throws, so no data is returned unaudited. */
export class JsonlAudit implements AuditSink {
  readonly path: string;

  constructor(
    path: string,
    private readonly policyHash: string,
  ) {
    this.path = resolve(path);
    mkdirSync(dirname(this.path), { recursive: true });
    appendFileSync(this.path, "");
  }

  write(entry: AuditEntry): void {
    const line = {
      ts: new Date().toISOString(),
      policy_hash: this.policyHash,
      ...entry,
      ...(entry.sql !== undefined ? { sql: normaliseSql(entry.sql) } : {}),
    };
    appendFileSync(this.path, JSON.stringify(line) + "\n", "utf8");
  }
}
