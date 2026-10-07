# Astraeus Governed Postgres MCP

A local-first, read-only [Model Context Protocol](https://modelcontextprotocol.io) server that lets an AI agent query a Postgres database through a policy layer instead of a raw connection string.

Today an agent that needs business data either gets a full database password (too open) or nothing (too locked). This server is the locked door with a keyed hatch: scoped tools, table and column allowlists, row limits, PII masking and an audit log.

Built by [Astraeus Business Solutions](https://astraeus.ie) for Irish and UK SME installs. The product design lives in the Astraeus Agentic Satellite Vault at `Workspace/Grok/Astraeus/Astraeus Governed Postgres MCP Design.md` (private vault; the acceptance checklist it defines is what v0 implements).

Status: v0. Not yet published to npm; install from source.

## What v0 does

- Runs over stdio for Claude Code, Cursor, Codex and any other MCP host.
- Refuses to start without both a policy file and a database connection string (fail closed).
- Exposes five tools: `list_tables`, `describe_table`, `query`, `policy_info`, `ping`.
- `query` accepts one read-only, single-table `SELECT`. It is parsed with a real PostgreSQL parser (`pgsql-ast-parser`), validated against the policy, and then **regenerated from the validated syntax tree**. The text you send is never executed; the rewritten statement is.
- Enforces a table and column allowlist, a row cap, an optional per-table predicate, and PII masking.
- Runs every query inside a `READ ONLY` transaction with a statement timeout.
- Writes an append-only JSONL audit log for every allow and deny.

What v0 does not do: writes of any kind, joins, subqueries, CTEs, `UNION`, a semantic layer of named views, or hosted HTTP transport. Joins are planned after v0 (see [Roadmap](#roadmap)).

## Quick start

Requires Node 20 or later.

```bash
git clone https://github.com/SarutobiSasuke8/astraeus-postgres-mcp.git
cd astraeus-postgres-mcp
npm ci
npm run build
```

Copy `examples/policy.example.yaml`, edit it for your schema, and set the connection string in the environment:

```bash
export DATABASE_URL='postgresql://astraeus_agent:<password>@db-host:5432/appdb'
node dist/index.js --policy ./my-policy.yaml
```

Register it with Claude Code:

```bash
claude mcp add astraeus-postgres -e DATABASE_URL="$DATABASE_URL" -- node /absolute/path/to/dist/index.js --policy /absolute/path/to/my-policy.yaml
```

Or in any MCP host's JSON config:

```json
{
  "mcpServers": {
    "astraeus-postgres": {
      "command": "node",
      "args": ["/absolute/path/to/dist/index.js", "--policy", "/absolute/path/to/my-policy.yaml"],
      "env": { "DATABASE_URL": "set this from your secret store" }
    }
  }
}
```

Configuration:

| Setting | Where | Notes |
|---|---|---|
| Policy file | `--policy <file>` or `ASTRAEUS_POLICY_PATH` | Required. YAML or JSON. |
| Connection string | Environment variable named by `connection_env` in the policy (default `DATABASE_URL`) | Required. Never put it in the policy file. |
| Audit log path | `ASTRAEUS_AUDIT_PATH`, or `audit.path` in the policy | Defaults to `./astraeus-audit.jsonl`. |

Credentials are only ever read from the environment. `.env.example` lists the variable names with placeholder values.

## Tools

| Tool | What it does |
|---|---|
| `list_tables` | Lists the tables and columns the policy allows. Does not touch the database. |
| `describe_table` | Column types for an allowlisted table. Only policy columns are shown, and masked columns are flagged. |
| `query` | Runs one read-only single-table `SELECT` under the policy. |
| `policy_info` | Returns a summary of the active policy: tables, columns, limits, mask rules. Contains no secrets. |
| `ping` | Checks connectivity without reading data. |

Denied calls return `isError: true` with a stable code, for example `column_not_allowed`, `table_not_allowed`, `multi_statement`, `non_read_statement`, `join_not_supported`, `row_limit_exceeded`, `masked_column_in_filter`.

## Policy reference

The policy is default deny. See [`examples/policy.example.yaml`](examples/policy.example.yaml).

```yaml
version: 1
connection_env: DATABASE_URL
readonly: true                 # must be true in v0
defaults:
  max_rows: 100
  statement_timeout_ms: 5000
  limit_mode: clamp            # clamp or refuse
  require_limit: false
allow:
  schemas: [public]
  tables:
    - name: customers
      columns: [id, name, created_at, billing_phone]
      require_predicate: "deleted_at IS NULL"
    - name: orders
      columns: [id, customer_id, total_cents, status]
      max_rows: 50
pii_mask:
  patterns:
    - column_regex: "(?i)email|phone|iban"
      strategy: redact         # redact, null or hash
```

Rules:

1. **Allowlists.** Only listed schemas, tables and columns can be named anywhere in a query: select list, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`. `SELECT *` expands to the allowed columns only. Unqualified table names resolve in `allow.schemas` order, not through the database `search_path`.
2. **Row limit.** A missing `LIMIT` gets the cap. An over-large `LIMIT` is clamped (`limit_mode: clamp`, the default) or refused (`refuse`). `require_limit: true` refuses queries with no `LIMIT`. Responses report `row_limit`, `limit_clamped` and `may_have_more`. As a second layer, the server also truncates whatever the database returns to the cap.
3. **`require_predicate`.** The expression is ANDed into every query on that table. Caller conditions are grouped first, so a caller `OR` cannot escape it. Columns used in the predicate must be readable by the database role, but do not have to be in the `columns` list.
4. **PII mask.** Any output column that is, or is built from, a column whose name matches a `column_regex` is masked, as is any output alias that matches. This holds for `SELECT *`, aliases and expressions such as `lower(phone)`. Strategies: `redact` (replace with `[REDACTED]`), `null`, and `hash` (unsalted, truncated SHA-256; fine for de-duplication, weak for low-entropy values). Masked columns cannot be used in `WHERE`, `GROUP BY`, `HAVING` or `ORDER BY`, otherwise a caller could recover values by probing.
5. **Read only.** Anything other than a single `SELECT` is rejected by the guard, and queries run in a `READ ONLY` transaction. The database role must also lack write grants (below).
6. **`deny_sql`.** Documents what is refused. The guard enforces these unconditionally, so removing an entry does not relax anything.

Policy names must match the real catalogue names. Unquoted Postgres identifiers are lower case.

## What the guard refuses

Multi-statement input; everything that is not `SELECT` (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `TRUNCATE`, `COPY`, `SET`, `GRANT`, `DO`, `CALL`, `EXPLAIN`, and so on); `WITH`, `UNION`, subqueries and joins (v0); `FOR UPDATE`; `DISTINCT ON`; window functions; unlisted functions (`pg_sleep`, `pg_read_file`, `set_config`, `dblink` and the rest); schema-qualified function calls; casts to `reg*` types; and anything the parser cannot understand. Unknown syntax is denied, not guessed at.

The callable function list is a short allowlist of aggregates, string, maths and date helpers. It is in `src/guard.ts`.

## Audit log

One JSON object per line, written before any result is returned. If the log cannot be written the call fails and returns no data.

```json
{"ts":"2026-10-07T02:17:31.231Z","policy_hash":"ff64ed87efa29a22","tool":"query","decision":"deny","reason":"column_not_allowed: column \"email\" is not allowed on public.customers","sql":"select email from customers","duration_ms":2}
```

Fields: timestamp, tool, policy hash, decision, reason, normalised SQL, table, row count, duration. SQL is normalised before logging: string, dollar-quoted and numeric literals become `?`, comments are removed, and whitespace is collapsed. Passwords and connection strings are never logged. Rotation is left to your platform (logrotate or similar) in v0.

## Least-privilege role and RLS

The guard is the first line of defence. The database role is the second, and it should hold even if the guard has a bug. Create a dedicated role for the agent:

```sql
create role astraeus_agent login password '<set from your secret store>'
  nosuperuser nocreatedb nocreaterole noinherit connection limit 4;
grant connect on database appdb to astraeus_agent;
grant usage on schema public to astraeus_agent;

-- Column-level SELECT only, matching the policy (plus any column the predicate uses).
grant select (id, name, billing_phone, created_at, deleted_at) on public.customers to astraeus_agent;
grant select (id, customer_id, total_cents, status) on public.orders to astraeus_agent;

-- No INSERT, UPDATE, DELETE, TRUNCATE, or DDL grants. Belt and braces:
alter role astraeus_agent set default_transaction_read_only = on;
alter role astraeus_agent set statement_timeout = '5s';
```

Do not grant `pg_read_all_data`, ownership of any object, or membership of any other role.

For multi-tenant schemas, add row-level security so the boundary lives in the database, not only in a predicate:

```sql
alter table public.orders enable row level security;
alter table public.orders force row level security;   -- also binds the table owner

create policy agent_reads_own_tenant on public.orders
  for select to astraeus_agent
  using (tenant_id = current_setting('app.tenant_id')::int);

-- Pin the tenant for this role, so the agent cannot choose it.
alter role astraeus_agent set app.tenant_id = '42';
```

Recommendations for client installs:

- Keep the connection string in a secret store or the MCP host's environment configuration. Never commit it, paste it into chat, or write it to the policy file.
- Prefer a read replica DSN for agent traffic.
- Require TLS (`sslmode=verify-full`) when the database is not on the same host.
- One role and one policy file per client, so each audit log maps to one boundary.

## Smoke test

Unit tests need no database. For an end-to-end check against a real Postgres, use the ephemeral container in `docker-compose.yml`. Pick throwaway values for the two passwords; they are never written to disk (the data lives in `tmpfs`).

```bash
export SMOKE_PG_ADMIN_PASSWORD='any-throwaway-value'
export SMOKE_PG_AGENT_PASSWORD='another-throwaway-value'

docker compose up -d --wait
npm run build
npm run smoke
docker compose down
```

`npm run smoke` drives the real server over stdio and checks that:

- the role itself cannot read `customers.email` or `secrets`, and cannot write;
- the row cap, PII redaction and `require_predicate` hold;
- denied queries are denied (unlisted column, unlisted table, multiple statements, `DELETE`, joins);
- the audit log has allow and deny entries and contains no phone numbers or passwords.

The seed script is `smoke/init.sh` and the policy is `smoke/policy.smoke.yaml`.

## Development

```bash
npm ci
npm run lint
npm run typecheck
npm test
npm run build
```

Tests mock the `pg` layer (`Db` interface in `src/db.ts`), so they run without a database. They cover multi-statement and non-SELECT rejection, table and column denial, row-cap enforcement, PII masking, audit on allow and deny, fail-closed startup, and an in-memory MCP round trip.

Layout:

```text
src/policy.ts    policy schema, loader, hash
src/guard.ts     SQL parse, allowlist, rewrite
src/mask.ts      PII masking
src/audit.ts     JSONL audit log
src/db.ts        pg access (read-only transaction)
src/tools.ts     tool handlers
src/server.ts    MCP wiring
src/startup.ts   fail-closed startup
```

## Limits and honest caveats

- A guard is not a sandbox. Treat the database role and RLS as the real boundary and the guard as a strong filter in front of it.
- `hash` masking is weak for low-entropy values such as phone numbers. Prefer `redact` or `null`.
- Results can still be sensitive even when allowed. Keep column allowlists tight.
- Error messages from Postgres are returned to the caller after trimming and connection-string scrubbing. Keep the role's visible schema small.
- Audit rotation and shipping are not built in.

## Roadmap

Not in v0, in rough order:

1. Joins across allowlisted tables, with the predicate applied per table and masks that survive aliases.
2. Named views in the policy that map to fixed SQL (a small semantic layer).
3. `propose_write` with a human approval step. Never silent DML or DDL.
4. Audit rotation.
5. Hosted Streamable HTTP with per-client keys. Out of scope for the local-first design.

## Prior art

Studied for threat models and ergonomics, not copied: [gokiwitech/pgwarden-mcp](https://github.com/gokiwitech/pgwarden-mcp), [microsoft/postgres-mcp](https://github.com/microsoft/postgres-mcp), and the public postgres2mcp pattern.

## Licence

MIT. See [LICENSE](LICENSE).
