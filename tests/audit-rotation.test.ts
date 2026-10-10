import { existsSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JsonlAudit, type AuditEntry } from "../src/audit.js";
import { parsePolicy } from "../src/policy.js";
import { buildRuntime } from "../src/startup.js";
import { MockDb, POLICY_YAML, tempDir } from "./helpers.js";

const entry = (i: number): AuditEntry => ({ tool: "query", decision: "allow", reason: `ok-${i}`, duration_ms: i });

function lines(paths: string[]): string[] {
  return paths.flatMap((p) => readFileSync(p, "utf8").split("\n").filter(Boolean));
}

function clock(start: string): { now: () => Date; set: (iso: string) => void } {
  let t = new Date(start);
  return { now: () => t, set: (iso: string) => (t = new Date(iso)) };
}

describe("audit rotation by size", () => {
  it("rotates before a write would exceed max_bytes and loses no lines", () => {
    const path = join(tempDir(), "audit.jsonl");
    const c = clock("2026-10-08T10:00:00.000Z");
    const audit = new JsonlAudit(path, "hash", { rotation: { maxBytes: 1024 }, now: c.now });
    for (let i = 0; i < 60; i += 1) {
      c.set(`2026-10-08T10:00:${String(i).padStart(2, "0")}.000Z`);
      audit.write(entry(i));
    }
    const rotated = audit.rotatedFiles();
    expect(rotated.length).toBeGreaterThan(2);
    for (const f of [...rotated, path]) expect(statSync(f).size).toBeLessThanOrEqual(1024);
    const all = lines([...rotated, path]).map((l) => (JSON.parse(l) as { reason: string }).reason);
    expect(all).toEqual(Array.from({ length: 60 }, (_, i) => `ok-${i}`));
    for (const f of rotated) expect(f).toMatch(/audit\.\d{8}T\d{9}Z(\.\d+)?\.jsonl$/);
  });

  it("never rotates an empty file, so one oversized line is still written", () => {
    const path = join(tempDir(), "a.jsonl");
    const audit = new JsonlAudit(path, "h", { rotation: { maxBytes: 1024 } });
    audit.write({ ...entry(1), sql: "x".repeat(1500) });
    expect(audit.rotatedFiles()).toHaveLength(0);
    expect(lines([path])).toHaveLength(1);
  });

  it("keeps only the newest rotated files when keep is set", () => {
    const path = join(tempDir(), "audit.jsonl");
    const c = clock("2026-10-08T10:00:00.000Z");
    const audit = new JsonlAudit(path, "hash", { rotation: { maxBytes: 1024, keep: 2 }, now: c.now });
    for (let i = 0; i < 80; i += 1) {
      c.set(new Date(Date.parse("2026-10-08T10:00:00.000Z") + i * 1000).toISOString());
      audit.write(entry(i));
    }
    const rotated = audit.rotatedFiles();
    expect(rotated).toHaveLength(2);
    // The newest lines are all still present: rotated files plus the live file end at the last write.
    const tail = lines([...rotated, path]).map((l) => (JSON.parse(l) as { reason: string }).reason);
    expect(tail.at(-1)).toBe("ok-79");
    expect(tail).toEqual(Array.from({ length: tail.length }, (_, i) => `ok-${80 - tail.length + i}`));
  });

  it("does not overwrite a rotated file when two rotations share a timestamp", () => {
    const path = join(tempDir(), "audit.jsonl");
    const c = clock("2026-10-08T10:00:00.000Z");
    const audit = new JsonlAudit(path, "hash", { rotation: { maxBytes: 1024 }, now: c.now });
    for (let i = 0; i < 40; i += 1) audit.write(entry(i));
    const rotated = audit.rotatedFiles();
    expect(rotated.length).toBeGreaterThan(1);
    expect(new Set(rotated).size).toBe(rotated.length);
    expect(lines([...rotated, path])).toHaveLength(40);
  });
});

describe("audit rotation by date", () => {
  it("rotates when the UTC day changes", () => {
    const path = join(tempDir(), "audit.jsonl");
    const c = clock("2026-10-08T23:59:58.000Z");
    const audit = new JsonlAudit(path, "hash", { rotation: { daily: true }, now: c.now });
    audit.write(entry(1));
    audit.write(entry(2));
    c.set("2026-10-09T00:00:01.000Z");
    audit.write(entry(3));
    const rotated = audit.rotatedFiles();
    expect(rotated).toHaveLength(1);
    expect(lines(rotated).map((l) => (JSON.parse(l) as { reason: string }).reason)).toEqual(["ok-1", "ok-2"]);
    expect(lines([path]).map((l) => (JSON.parse(l) as { reason: string }).reason)).toEqual(["ok-3"]);
  });

  it("rotates a pre-existing file from an earlier day on the first write", () => {
    const dir = tempDir();
    const path = join(dir, "audit.jsonl");
    writeFileSync(path, '{"old":true}\n');
    const old = new Date("2026-10-01T12:00:00Z");
    // Make the existing file look like it was last written a week ago.
    utimesSync(path, old, old);
    const audit = new JsonlAudit(path, "hash", { rotation: { daily: true }, now: () => new Date("2026-10-08T09:00:00Z") });
    audit.write(entry(1));
    expect(audit.rotatedFiles()).toHaveLength(1);
    expect(lines(audit.rotatedFiles())).toEqual(['{"old":true}']);
  });

  it("does not rotate without a rotation config", () => {
    const path = join(tempDir(), "audit.jsonl");
    const c = clock("2026-10-08T23:59:58.000Z");
    const audit = new JsonlAudit(path, "hash", { now: c.now });
    audit.write(entry(1));
    c.set("2026-10-10T00:00:00.000Z");
    audit.write(entry(2));
    expect(audit.rotatedFiles()).toHaveLength(0);
    expect(lines([path])).toHaveLength(2);
  });
});

describe("audit rotation from the policy", () => {
  it("parses audit.rotate and wires it into the runtime", () => {
    const yaml = `${POLICY_YAML}\naudit:\n  rotate:\n    max_bytes: 2048\n    daily: true\n    keep: 30\n`;
    const p = parsePolicy(yaml, "yaml");
    expect(p.auditRotation).toEqual({ maxBytes: 2048, daily: true, keep: 30 });
    const dir = tempDir();
    const policyPath = join(dir, "policy.yaml");
    writeFileSync(policyPath, yaml);
    const auditPath = join(dir, "audit.jsonl");
    const rt = buildRuntime({
      env: { DATABASE_URL: "postgresql://x", ASTRAEUS_AUDIT_PATH: auditPath },
      argv: ["--policy", policyPath],
      dbFactory: () => new MockDb(),
    });
    for (let i = 0; i < 40; i += 1) rt.audit.write(entry(i));
    expect((rt.audit as JsonlAudit).rotatedFiles().length).toBeGreaterThan(0);
    expect(existsSync(auditPath)).toBe(true);
  });

  it("rejects a max_bytes below 1024", () => {
    expect(() => parsePolicy(`${POLICY_YAML}\naudit:\n  rotate:\n    max_bytes: 10\n`, "yaml")).toThrow();
  });
});
