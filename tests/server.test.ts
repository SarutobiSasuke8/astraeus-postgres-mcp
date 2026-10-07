import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { createServer } from "../src/server.js";
import { makeRuntime, readAudit } from "./helpers.js";

async function connect() {
  const ctx = makeRuntime();
  const server = createServer(ctx.rt);
  const client = new Client({ name: "test", version: "0.0.0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { ...ctx, client };
}

function text(result: unknown): string {
  const content = (result as { content: { type: string; text: string }[] }).content;
  return content[0]?.text ?? "";
}

describe("MCP surface", () => {
  it("exposes exactly the v0 tools", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["describe_table", "list_tables", "ping", "policy_info", "query"]);
  });

  it("returns query results and flags denials with isError", async () => {
    const { client, db, auditPath } = await connect();
    db.result = { fields: ["id"], rows: [[1]] };
    const ok = await client.callTool({ name: "query", arguments: { sql: "select id from customers" } });
    expect(ok.isError).toBeFalsy();
    expect(JSON.parse(text(ok)).row_count).toBe(1);

    const denied = await client.callTool({ name: "query", arguments: { sql: "update customers set name = 'x'" } });
    expect(denied.isError).toBe(true);
    expect(JSON.parse(text(denied)).error).toBe("non_read_statement");
    expect(readAudit(auditPath).map((e) => e.decision)).toEqual(["allow", "deny"]);
  });

  it("returns an error and no data if auditing fails", async () => {
    const { client, db, rt } = await connect();
    db.result = { fields: ["id"], rows: [[1]] };
    rt.audit.write = () => {
      throw new Error("disk full");
    };
    const res = await client.callTool({ name: "query", arguments: { sql: "select id from customers" } });
    expect(res.isError).toBe(true);
    expect(text(res)).not.toContain('"rows"');
  });
});
