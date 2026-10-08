import { createHash, timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { AuditEntry, AuditSink } from "./audit.js";
import { createServer } from "./server.js";
import { StartupError } from "./startup.js";
import type { Runtime } from "./tools.js";

export const MCP_PATH = "/mcp";
export const HEALTH_PATH = "/health";
export const MIN_TOKEN_LENGTH = 32;
const MAX_BODY_BYTES = 1_000_000;
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

export interface HttpConfig {
  host: string;
  port: number;
  token: string;
  /** True when the operator explicitly allowed a non-loopback bind address. */
  remote: boolean;
}

/**
 * Read the HTTP settings from the environment, or throw StartupError. Fails closed:
 * no token, a short token, a bad port, or a non-loopback host without explicit opt-in
 * all refuse to start. The token is never included in an error message.
 */
export function buildHttpConfig(env: NodeJS.ProcessEnv): HttpConfig {
  const token = env.ASTRAEUS_HTTP_TOKEN;
  if (!token) {
    throw new StartupError("ASTRAEUS_HTTP_TOKEN is not set: refusing to start the HTTP transport without a bearer token");
  }
  if (token.length < MIN_TOKEN_LENGTH || /\s/.test(token)) {
    throw new StartupError(`ASTRAEUS_HTTP_TOKEN must be at least ${MIN_TOKEN_LENGTH} characters with no whitespace`);
  }
  const host = env.ASTRAEUS_HTTP_HOST ?? "127.0.0.1";
  const remote = env.ASTRAEUS_HTTP_ALLOW_REMOTE === "1";
  if (!LOOPBACK.has(host) && !remote) {
    throw new StartupError(
      `ASTRAEUS_HTTP_HOST=${host} is not a loopback address: set ASTRAEUS_HTTP_ALLOW_REMOTE=1 to bind it (and put TLS in front)`,
    );
  }
  const rawPort = env.ASTRAEUS_HTTP_PORT ?? "8787";
  const port = Number(rawPort);
  if (!/^\d{1,5}$/.test(rawPort) || !Number.isInteger(port) || port > 65535) {
    throw new StartupError(`ASTRAEUS_HTTP_PORT is not a valid port: ${rawPort.slice(0, 20)}`);
  }
  return { host, port, token, remote };
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/** Constant-time bearer check. Comparing digests keeps the comparison length fixed. */
export function bearerMatches(header: string | undefined, expected: string): boolean {
  const match = /^Bearer ([^\s]+)$/.exec(header ?? "");
  if (!match) return false;
  return timingSafeEqual(digest(match[1] as string), digest(expected));
}

function withTransport(audit: AuditSink): AuditSink {
  return {
    path: audit.path,
    write: (entry: AuditEntry) => audit.write({ ...entry, transport: "http" }),
  };
}

function send(res: ServerResponse, status: number, body: Record<string, unknown>, headers: Record<string, string> = {}): void {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("bad_json"));
      }
    });
    req.on("error", reject);
  });
}

/** Host header values accepted on a loopback bind. Blocks DNS rebinding from a browser. */
function hostAllowed(hostHeader: string | undefined, port: number): boolean {
  if (!hostHeader) return false;
  const allowed = [`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`];
  return allowed.includes(hostHeader.toLowerCase());
}

export interface RunningHttpServer {
  url: string;
  port: number;
  server: Server;
  close(): Promise<void>;
}

/**
 * Start the opt-in Streamable HTTP transport. Stateless: each POST to /mcp gets a fresh
 * MCP server bound to the shared runtime (policy, pool, audit). GET /health needs no
 * token and returns no data and touches no database.
 */
export async function startHttpServer(rt: Runtime, cfg: HttpConfig): Promise<RunningHttpServer> {
  const httpRt: Runtime = { ...rt, audit: withTransport(rt.audit) };
  let boundPort = cfg.port;

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = (req.url ?? "/").split("?")[0];
    if (path === HEALTH_PATH) {
      if (req.method !== "GET") return send(res, 405, { error: "method_not_allowed" }, { allow: "GET" });
      return send(res, 200, { status: "ok" });
    }
    if (path !== MCP_PATH) return send(res, 404, { error: "not_found" });
    if (!cfg.remote && !hostAllowed(req.headers.host, boundPort)) {
      return send(res, 403, { error: "forbidden_host" });
    }
    if (!bearerMatches(req.headers.authorization, cfg.token)) {
      httpRt.audit.write({ tool: "http", decision: "deny", reason: "unauthorised", duration_ms: 0 });
      return send(res, 401, { error: "unauthorised" }, { "www-authenticate": 'Bearer realm="astraeus-postgres-mcp"' });
    }
    if (req.method !== "POST") {
      return send(res, 405, { error: "method_not_allowed", message: "stateless server: use POST" }, { allow: "POST" });
    }
    let body: unknown;
    try {
      body = await readJson(req);
    } catch (err) {
      const tooLarge = (err as Error).message === "too_large";
      return send(res, tooLarge ? 413 : 400, { error: tooLarge ? "body_too_large" : "invalid_json" });
    }
    const server = createServer(httpRt);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  };

  const server = createHttpServer((req, res) => {
    handler(req, res).catch(() => send(res, 500, { error: "internal_error" }));
  });
  server.requestTimeout = 60_000;
  server.headersTimeout = 15_000;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(cfg.port, cfg.host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  boundPort = (server.address() as AddressInfo).port;
  const hostForUrl = cfg.host.includes(":") ? `[${cfg.host}]` : cfg.host;
  return {
    url: `http://${hostForUrl}:${boundPort}`,
    port: boundPort,
    server,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
