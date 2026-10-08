import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadPolicy, parsePolicy, PolicyError } from "../src/policy.js";
import { buildRuntime, StartupError } from "../src/startup.js";
import { MockDb, POLICY_YAML, tempDir } from "./helpers.js";

function policyFile(contents = POLICY_YAML): string {
  const path = join(tempDir(), "policy.yaml");
  writeFileSync(path, contents);
  return path;
}

const mockFactory = () => new MockDb();

describe("fail-closed startup", () => {
  it("refuses to start without a policy", () => {
    expect(() => buildRuntime({ env: { DATABASE_URL: "postgresql://x" }, argv: [], dbFactory: mockFactory })).toThrow(
      StartupError,
    );
    expect(() => buildRuntime({ env: { DATABASE_URL: "postgresql://x" }, argv: [], dbFactory: mockFactory })).toThrow(
      /no policy configured/,
    );
  });

  it("refuses to start when the policy file is missing or invalid", () => {
    const missing = join(tempDir(), "nope.yaml");
    expect(() => buildRuntime({ env: { DATABASE_URL: "x" }, argv: ["--policy", missing], dbFactory: mockFactory })).toThrow(
      StartupError,
    );
    expect(() =>
      buildRuntime({ env: { DATABASE_URL: "x" }, argv: ["--policy", policyFile("version: 2")], dbFactory: mockFactory }),
    ).toThrow(StartupError);
  });

  it("refuses to start without DATABASE_URL", () => {
    expect(() => buildRuntime({ env: {}, argv: ["--policy", policyFile()], dbFactory: mockFactory })).toThrow(
      /DATABASE_URL is not set/,
    );
    expect(() => buildRuntime({ env: { DATABASE_URL: "" }, argv: ["--policy", policyFile()], dbFactory: mockFactory })).toThrow(
      StartupError,
    );
  });

  it("honours connection_env from the policy", () => {
    const file = policyFile(POLICY_YAML.replace("DATABASE_URL", "CLIENT_DB_URL"));
    expect(() => buildRuntime({ env: { DATABASE_URL: "x" }, argv: ["--policy", file], dbFactory: mockFactory })).toThrow(
      /CLIENT_DB_URL is not set/,
    );
  });

  it("never echoes the connection string in errors", () => {
    const secret = "postgresql://user:hunter2@host/db";
    try {
      buildRuntime({ env: { DATABASE_URL: secret }, argv: [], dbFactory: mockFactory });
    } catch (err) {
      expect((err as Error).message).not.toContain("hunter2");
    }
  });

  it("starts when both are present, via flag or environment", () => {
    const file = policyFile();
    const dir = tempDir();
    const env = { DATABASE_URL: "postgresql://x", ASTRAEUS_AUDIT_PATH: join(dir, "a.jsonl") };
    expect(buildRuntime({ env, argv: ["--policy", file], dbFactory: mockFactory }).policy.tables).toHaveLength(2);
    expect(
      buildRuntime({ env: { ...env, ASTRAEUS_POLICY_PATH: file }, argv: [], dbFactory: mockFactory }).policy.version,
    ).toBe(1);
  });
});

describe("policy loading", () => {
  it("rejects a non-read-only policy and unknown keys", () => {
    expect(() => parsePolicy(POLICY_YAML.replace("readonly: true", "readonly: false"), "yaml")).toThrow(PolicyError);
    expect(() => parsePolicy(POLICY_YAML + "\nsurprise: true\n", "yaml")).toThrow(PolicyError);
  });

  it("rejects a table whose schema is not allowed", () => {
    const bad = POLICY_YAML.replace("- name: orders", "- name: orders\n      schema: private");
    expect(() => parsePolicy(bad, "yaml")).toThrow(/not in allow.schemas/);
  });

  it("rejects an invalid mask regex", () => {
    expect(() => parsePolicy(POLICY_YAML.replace("(?i)email|phone|iban", "(unclosed"), "yaml")).toThrow(PolicyError);
  });

  it("accepts JSON and produces a stable hash", () => {
    const json = JSON.stringify({
      version: 1,
      readonly: true,
      allow: { schemas: ["public"], tables: [{ name: "t", columns: ["id"] }] },
    });
    const a = parsePolicy(json, "json");
    expect(a.hash).toBe(parsePolicy(json, "json").hash);
    expect(a.maxRows).toBe(100);
  });
});

describe("shipped policies", () => {
  it("the example and smoke policies load, including their named views", () => {
    for (const file of ["examples/policy.example.yaml", "smoke/policy.smoke.yaml"]) {
      const p = loadPolicy(file);
      expect(p.views.length, file).toBeGreaterThan(0);
    }
  });
});
