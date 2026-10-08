#!/usr/bin/env node
// Stdio target for the mcp-eval contract suite (eval/mcp.suite.yaml).
//
// Starts a throwaway embedded PostgreSQL from npm (no Docker), seeded from smoke/seed.sql
// with random throwaway passwords on a random loopback port, then runs the built server
// (dist/index.js) with the smoke policy and relays MCP stdio to it. When the client closes
// stdin, or this process gets SIGTERM or SIGINT, the server is stopped and the database
// is shut down and deleted.
//
// stdout carries the MCP protocol only. Diagnostics go to stderr.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startEmbeddedPostgres } from "./embedded-pg.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const policyPath = join(root, "smoke", "policy.smoke.yaml");
const serverPath = join(root, "dist", "index.js");

// Hold client input until the server is up, so nothing is lost while the database starts.
process.stdin.pause();

const started = Date.now();
const db = await startEmbeddedPostgres({ log: process.env.APM_PG_LOG === "1" });
const auditDir = mkdtempSync(join(tmpdir(), "apm-eval-"));
console.error(`eval target: embedded PostgreSQL ${db.version} ready in ${Date.now() - started} ms`);

const child = spawn(process.execPath, [serverPath, "--policy", policyPath], {
  env: {
    PATH: process.env.PATH ?? "",
    SYSTEMROOT: process.env.SYSTEMROOT ?? "",
    DATABASE_URL: db.agentDsn,
    ASTRAEUS_AUDIT_PATH: join(auditDir, "audit.jsonl"),
  },
  stdio: ["pipe", "inherit", "inherit"],
});

let stopping;
function shutdown(code) {
  if (!stopping) {
    stopping = (async () => {
      const t0 = Date.now();
      if (child.exitCode === null) child.kill();
      await db.stop().catch(() => undefined);
      try {
        rmSync(auditDir, { recursive: true, force: true });
      } catch {
        // Best effort: the audit file lives under the OS temp directory either way.
      }
      console.error(`eval target: stopped in ${Date.now() - t0} ms`);
      process.exit(code);
    })();
  }
  return stopping;
}

process.stdin.pipe(child.stdin);
process.stdin.on("end", () => void shutdown(0));
child.stdin.on("error", () => undefined);
child.on("exit", (code) => void shutdown(code ?? 1));
process.on("SIGTERM", () => void shutdown(0));
process.on("SIGINT", () => void shutdown(0));
process.stdin.resume();
