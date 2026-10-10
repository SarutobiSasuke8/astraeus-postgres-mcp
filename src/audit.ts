import { appendFileSync, mkdirSync, readdirSync, renameSync, statSync, unlinkSync } from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";

export interface AuditEntry {
  tool: string;
  decision: "allow" | "deny";
  reason: string;
  sql?: string;
  table?: string;
  view?: string;
  /** Names of the view parameters supplied. Values are never logged. */
  params?: string[];
  transport?: "stdio" | "http";
  row_count?: number;
  duration_ms: number;
}

export interface AuditSink {
  readonly path: string;
  write(entry: AuditEntry): void;
}

export interface RotationOptions {
  /** Rotate before a write that would take the live file past this many bytes. */
  maxBytes?: number;
  /** Rotate when the UTC date changes. */
  daily?: boolean;
  /** Keep at most this many rotated files (oldest are removed). Unset keeps all of them. */
  keep?: number;
}

export interface JsonlAuditOptions {
  rotation?: RotationOptions;
  /** Test seam for the clock. */
  now?: () => Date;
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

function utcDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/**
 * Append-only JSONL audit log with optional rotation by size and/or UTC date.
 * A failed write throws, so no data is returned unaudited.
 *
 * Rotation renames the live file to `<name>.<UTC timestamp>[.<n>]<ext>` and the next
 * line starts a new live file. A rename never splits or drops a line. Rotated files
 * are only deleted when `keep` is set. One process should own a given audit path.
 */
export class JsonlAudit implements AuditSink {
  readonly path: string;
  private readonly rotation: RotationOptions;
  private readonly now: () => Date;
  private size: number;
  private day: string;

  constructor(
    path: string,
    private readonly policyHash: string,
    opts: JsonlAuditOptions = {},
  ) {
    this.path = resolve(path);
    this.rotation = opts.rotation ?? {};
    this.now = opts.now ?? (() => new Date());
    mkdirSync(dirname(this.path), { recursive: true });
    appendFileSync(this.path, "");
    const st = statSync(this.path);
    this.size = st.size;
    // An existing file belongs to the day it was last written.
    this.day = st.size > 0 ? utcDay(st.mtime) : utcDay(this.now());
  }

  write(entry: AuditEntry): void {
    const now = this.now();
    const line =
      JSON.stringify({
        ts: now.toISOString(),
        policy_hash: this.policyHash,
        ...entry,
        ...(entry.sql !== undefined ? { sql: normaliseSql(entry.sql) } : {}),
      }) + "\n";
    const bytes = Buffer.byteLength(line, "utf8");
    const today = utcDay(now);
    if (this.size > 0) {
      const sizeDue = this.rotation.maxBytes !== undefined && this.size + bytes > this.rotation.maxBytes;
      const dayDue = this.rotation.daily === true && today !== this.day;
      if (sizeDue || dayDue) this.rotate(now);
    }
    appendFileSync(this.path, line, "utf8");
    this.size += bytes;
    this.day = today;
  }

  /** Rotated files for this log, oldest first. */
  rotatedFiles(): string[] {
    const ext = extname(this.path);
    const stem = basename(this.path, ext);
    const pattern = new RegExp(`^${escapeRegex(stem)}\\.(\\d{8}T\\d{9}Z)(?:\\.(\\d+))?${escapeRegex(ext)}$`);
    const found: { file: string; stamp: string; n: number }[] = [];
    for (const file of readdirSync(dirname(this.path))) {
      const m = pattern.exec(file);
      if (m) found.push({ file, stamp: m[1] ?? "", n: Number(m[2] ?? 0) });
    }
    found.sort((a, b) => (a.stamp === b.stamp ? a.n - b.n : a.stamp < b.stamp ? -1 : 1));
    return found.map((f) => join(dirname(this.path), f.file));
  }

  private rotate(now: Date): void {
    const ext = extname(this.path);
    const stem = basename(this.path, ext);
    const stamp = now.toISOString().replace(/[-:]/g, "").replace(".", "");
    let target = join(dirname(this.path), `${stem}.${stamp}${ext}`);
    for (let n = 1; existsQuiet(target); n += 1) {
      target = join(dirname(this.path), `${stem}.${stamp}.${n}${ext}`);
    }
    renameSync(this.path, target);
    appendFileSync(this.path, "");
    this.size = 0;
    if (this.rotation.keep !== undefined) {
      const rotated = this.rotatedFiles();
      for (const old of rotated.slice(0, Math.max(0, rotated.length - this.rotation.keep))) unlinkSync(old);
    }
  }
}

function existsQuiet(p: string): boolean {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
