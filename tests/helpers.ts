import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JsonlAudit } from "../src/audit.js";
import type { ColumnInfo, Db, QueryResult } from "../src/db.js";
import { parsePolicy, type Policy } from "../src/policy.js";
import type { Runtime } from "../src/tools.js";

export const POLICY_YAML = `
version: 1
connection_env: DATABASE_URL
readonly: true
defaults:
  max_rows: 5
  statement_timeout_ms: 2000
allow:
  schemas: [public]
  tables:
    - name: customers
      columns: [id, name, created_at, billing_phone]
      require_predicate: "deleted_at IS NULL"
    - name: orders
      columns: [id, customer_id, total_cents, status]
      max_rows: 3
pii_mask:
  patterns:
    - column_regex: "(?i)email|phone|iban"
      strategy: redact
`;

export function testPolicy(yaml: string = POLICY_YAML): Policy {
  return parsePolicy(yaml, "yaml");
}

export class MockDb implements Db {
  readonly executed: { sql: string; timeoutMs: number }[] = [];
  result: QueryResult = { fields: [], rows: [] };
  columns: ColumnInfo[] = [];
  failWith: Error | undefined;
  pingFails = false;

  runReadOnly(sql: string, timeoutMs: number): Promise<QueryResult> {
    this.executed.push({ sql, timeoutMs });
    if (this.failWith) return Promise.reject(this.failWith);
    return Promise.resolve(this.result);
  }
  columnsOf(): Promise<ColumnInfo[]> {
    return Promise.resolve(this.columns);
  }
  ping(): Promise<void> {
    return this.pingFails ? Promise.reject(new Error("down")) : Promise.resolve();
  }
  close(): Promise<void> {
    return Promise.resolve();
  }
}

export function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "apm-test-"));
}

export function makeRuntime(policy: Policy = testPolicy()): { rt: Runtime; db: MockDb; auditPath: string } {
  const auditPath = join(tempDir(), "audit.jsonl");
  const db = new MockDb();
  return { rt: { policy, db, audit: new JsonlAudit(auditPath, policy.hash) }, db, auditPath };
}

export function readAudit(path: string): Record<string, unknown>[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}
