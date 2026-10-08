import { request } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, describe, expect, it } from "vitest";
import { bearerMatches, buildHttpConfig, MIN_TOKEN_LENGTH, startHttpServer, type RunningHttpServer } from "../src/http.js";
import { StartupError } from "../src/startup.js";
import { makeRuntime, readAudit } from "./helpers.js";

const TOKEN = "unit-test-token-0123456789-abcdefghij";
let running: RunningHttpServer | undefined;

afterEach(async () => {
  await running?.close();
  running = undefined;
});

async function start() {
  const ctx = makeRuntime();
  running = await startHttpServer(ctx.rt, { host: "127.0.0.1", port: 0, token: TOKEN, remote: false });
  return { ...ctx, http: running };
}

function rawRequest(
  port: number,
  opts: { method?: string; path?: string; headers?: Record<string, string>; body?: string },
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, method: opts.method ?? "GET", path: opts.path ?? "/", headers: opts.headers ?? {} },
      (res) => {
        let body = "";
        res.on("data", (c: Buffer) => (body += c.toString("utf8")));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

const listTools = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
const mcpHeaders = { "content-type": "application/json", accept: "application/json, text/event-stream" };

describe("HTTP config: fails closed", () => {
  it("refuses to start without a token", () => {
    expect(() => buildHttpConfig({})).toThrow(StartupError);
    expect(() => buildHttpConfig({})).toThrow(/ASTRAEUS_HTTP_TOKEN is not set/);
    expect(() => buildHttpConfig({ ASTRAEUS_HTTP_TOKEN: "" })).toThrow(StartupError);
  });

  it("refuses a short or whitespace token and never echoes it", () => {
    const short = "short-secret-value";
    try {
      buildHttpConfig({ ASTRAEUS_HTTP_TOKEN: short });
      expect.unreachable();
    } catch (err) {
      expect((err as Error).message).toContain(String(MIN_TOKEN_LENGTH));
      expect((err as Error).message).not.toContain(short);
    }
    expect(() => buildHttpConfig({ ASTRAEUS_HTTP_TOKEN: `${"a".repeat(20)} ${"b".repeat(20)}` })).toThrow(StartupError);
  });

  it("binds loopback by default and refuses a public address without explicit opt-in", () => {
    expect(buildHttpConfig({ ASTRAEUS_HTTP_TOKEN: TOKEN })).toEqual({ host: "127.0.0.1", port: 8787, token: TOKEN, remote: false });
    expect(() => buildHttpConfig({ ASTRAEUS_HTTP_TOKEN: TOKEN, ASTRAEUS_HTTP_HOST: "0.0.0.0" })).toThrow(/not a loopback/);
    expect(buildHttpConfig({ ASTRAEUS_HTTP_TOKEN: TOKEN, ASTRAEUS_HTTP_HOST: "0.0.0.0", ASTRAEUS_HTTP_ALLOW_REMOTE: "1" }).remote).toBe(true);
    expect(buildHttpConfig({ ASTRAEUS_HTTP_TOKEN: TOKEN, ASTRAEUS_HTTP_HOST: "::1" }).host).toBe("::1");
  });

  it("refuses an invalid port", () => {
    for (const port of ["abc", "70000", "-1", "80.5"]) {
      expect(() => buildHttpConfig({ ASTRAEUS_HTTP_TOKEN: TOKEN, ASTRAEUS_HTTP_PORT: port }), port).toThrow(StartupError);
    }
  });

  it("compares bearer tokens exactly", () => {
    expect(bearerMatches(`Bearer ${TOKEN}`, TOKEN)).toBe(true);
    expect(bearerMatches(`Bearer ${TOKEN}x`, TOKEN)).toBe(false);
    expect(bearerMatches(`bearer ${TOKEN}`, TOKEN)).toBe(false);
    expect(bearerMatches(TOKEN, TOKEN)).toBe(false);
    expect(bearerMatches(undefined, TOKEN)).toBe(false);
    expect(bearerMatches(`Basic ${TOKEN}`, TOKEN)).toBe(false);
  });
});

describe("HTTP server", () => {
  it("serves /health without a token and without touching the database", async () => {
    const { http, db } = await start();
    const res = await fetch(`${http.url}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
    expect(db.executed).toHaveLength(0);
  });

  it("rejects /mcp without or with a wrong token, and audits the denial", async () => {
    const { http, auditPath } = await start();
    const none = await fetch(`${http.url}/mcp`, { method: "POST", headers: mcpHeaders, body: listTools });
    expect(none.status).toBe(401);
    expect(none.headers.get("www-authenticate")).toMatch(/^Bearer/);
    const wrong = await fetch(`${http.url}/mcp`, {
      method: "POST",
      headers: { ...mcpHeaders, authorization: "Bearer not-the-token-not-the-token-not-the-token" },
      body: listTools,
    });
    expect(wrong.status).toBe(401);
    const entries = readAudit(auditPath);
    expect(entries).toHaveLength(2);
    expect(entries.every((e) => e.reason === "unauthorised" && e.transport === "http")).toBe(true);
    expect(JSON.stringify(entries)).not.toContain("not-the-token");
  });

  it("rejects a foreign Host header on a loopback bind (DNS rebinding)", async () => {
    const { http } = await start();
    const res = await rawRequest(http.port, {
      method: "POST",
      path: "/mcp",
      headers: { ...mcpHeaders, host: "evil.example:80", authorization: `Bearer ${TOKEN}` },
      body: listTools,
    });
    expect(res.status).toBe(403);
  });

  it("returns 404 for unknown paths and 405 for GET /mcp", async () => {
    const { http } = await start();
    expect((await fetch(`${http.url}/`)).status).toBe(404);
    expect((await fetch(`${http.url}/mcp`, { headers: { authorization: `Bearer ${TOKEN}` } })).status).toBe(405);
  });

  it("refuses an oversized or invalid body", async () => {
    const { http } = await start();
    const bad = await fetch(`${http.url}/mcp`, {
      method: "POST",
      headers: { ...mcpHeaders, authorization: `Bearer ${TOKEN}` },
      body: "{not json",
    });
    expect(bad.status).toBe(400);
    const big = await fetch(`${http.url}/mcp`, {
      method: "POST",
      headers: { ...mcpHeaders, authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ pad: "x".repeat(1_100_000) }),
    }).catch(() => undefined);
    // The server answers 413 and closes; some clients surface the reset instead.
    if (big) expect(big.status).toBe(413);
  });

  it("serves the same governed tools over Streamable HTTP with the token", async () => {
    const { http, db, auditPath } = await start();
    db.result = { fields: ["id"], rows: [[1]] };
    const client = new Client({ name: "http-test", version: "0.0.0" });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${http.url}/mcp`), {
        requestInit: { headers: { authorization: `Bearer ${TOKEN}` } },
      }),
    );
    try {
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual(["describe_table", "list_tables", "ping", "policy_info", "query", "run_view"]);
      const ok = await client.callTool({ name: "query", arguments: { sql: "select id from customers" } });
      expect(ok.isError).toBeFalsy();
      const denied = await client.callTool({ name: "query", arguments: { sql: "delete from customers" } });
      expect(denied.isError).toBe(true);
    } finally {
      await client.close();
    }
    const entries = readAudit(auditPath).filter((e) => e.tool === "query");
    expect(entries.map((e) => `${String(e.decision)}:${String(e.transport)}`)).toEqual(["allow:http", "deny:http"]);
  });
});
