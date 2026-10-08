import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  handleDescribeTable,
  handleListTables,
  handlePing,
  handlePolicyInfo,
  handleQuery,
  handleRunView,
  type Runtime,
  type ToolOutcome,
} from "./tools.js";

function toResult(outcome: ToolOutcome) {
  if (outcome.ok) {
    return { content: [{ type: "text" as const, text: JSON.stringify(outcome.data, null, 2) }] };
  }
  return {
    isError: true,
    content: [{ type: "text" as const, text: JSON.stringify({ error: outcome.code, message: outcome.message }) }],
  };
}

/** Any unexpected failure, including an audit write failure, returns no data. */
async function safely(fn: () => ToolOutcome | Promise<ToolOutcome>) {
  try {
    return toResult(await fn());
  } catch {
    return toResult({ ok: false, code: "internal_error", message: "request failed and no data was returned (check the audit log path)" });
  }
}

export const SERVER_VERSION = "0.2.0";

export function createServer(rt: Runtime): McpServer {
  const server = new McpServer({ name: "astraeus-postgres-mcp", version: SERVER_VERSION });

  server.registerTool(
    "list_tables",
    { description: "List the schemas, tables and columns this policy allows. Does not touch the database." },
    () => safely(() => handleListTables(rt)),
  );

  server.registerTool(
    "describe_table",
    {
      description: "Describe an allowlisted table: column types and which columns are masked. Only policy columns are shown.",
      inputSchema: { table: z.string().min(1), schema: z.string().min(1).optional() },
    },
    (args) => safely(() => handleDescribeTable(rt, args)),
  );

  server.registerTool(
    "query",
    {
      description:
        "Run one read-only SELECT against allowlisted tables. INNER, LEFT, RIGHT and FULL JOIN ... ON across " +
        "allowlisted tables in one schema are allowed; subqueries, CTEs and UNION are not. Row limits are enforced, " +
        "masked columns are redacted, and every call is audited. Use list_tables first.",
      inputSchema: { sql: z.string().min(1).max(20_000) },
    },
    (args) => safely(() => handleQuery(rt, args)),
  );

  server.registerTool(
    "run_view",
    {
      description:
        "Run a named view defined in the policy: fixed, pre-approved SQL with typed parameters. " +
        "list_tables shows the available views and their parameters. Same row limits, masking and audit as query.",
      inputSchema: {
        name: z.string().min(1).max(64),
        params: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
      },
    },
    (args) => safely(() => handleRunView(rt, args)),
  );

  server.registerTool(
    "policy_info",
    { description: "Return the active policy summary: allowed tables and columns, limits, mask rules. Contains no secrets." },
    () => safely(() => handlePolicyInfo(rt)),
  );

  server.registerTool(
    "ping",
    { description: "Check database connectivity without reading any data." },
    () => safely(() => handlePing(rt)),
  );

  return server;
}
