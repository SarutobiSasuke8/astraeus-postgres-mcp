# Astraeus Governed Postgres MCP

A local-first, read-only [Model Context Protocol](https://modelcontextprotocol.io) server that lets an AI agent query a Postgres database through a policy layer instead of a raw connection string.

Today an agent that needs business data either gets a full database password (too open) or nothing (too locked). This server is the locked door with a keyed hatch: scoped tools, table and column allowlists, row limits, PII masking and an audit log.

Built by [Astraeus Business Solutions](https://astraeus.ie) for Irish and UK SME installs. The product design lives in the Astraeus Agentic Satellite Vault at `Workspace/Grok/Astraeus/Astraeus Governed Postgres MCP Design.md` (private vault; v0 implements its acceptance checklist and v1 its "v1 scope (2026-10-08)" section).

Status: v1 (0.2.0). Not yet published to npm; install from source.

## What it does

- Runs over stdio for Claude Code, Cursor, Codex and any other MCP host. An opt-in [Streamable HTTP entrypoint](#streamable-http-opt-in) is available for local HTTP clients.
- Refuses to start without both a policy file and a database connection string (fail closed).
- Exposes six tools: `list_tables`, `describe_table`, `query`, `run_view`, `policy_info`, `ping`.
- `query` accepts one read-only `SELECT`, on one table or on several allowlisted tables joined with `JOIN ... ON`. It is parsed with a real PostgreSQL parser (`pgsql-ast-parser`), validated against the policy, and then **regenerated from the validated syntax tree**. The text you send is never executed; the rewritten statement is.
- `run_view` runs a **named view** from the policy: fixed SQL with typed parameters, checked by the same guard when the policy loads.
- Enforces a table and column allowlist, a row cap, an optional per-table predicate, and PII masking, for single tables, joins and views alike.
- Runs every query inside a `READ ONLY` transaction with a statement timeout.
- Writes an append-only JSONL audit log for every allow and deny, with optional rotation by size and by date.

What it does not do: writes of any kind (no `propose_write`), subqueries, CTEs, `UNION`, joins across schemas, comma, `CROSS`, `NATURAL`, `USING` or `LATERAL` joins, and hosted multi-tenant HTTP with per-client keys.

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
| Audit rotation | `audit.rotate` in the policy | Optional. See [Audit log](#audit-log). |
| HTTP settings | `ASTRAEUS_HTTP_*` | HTTP entrypoint only. See [Streamable HTTP](#streamable-http-opt-in). |

Credentials are only ever read from the environment. `.env.example` lists the variable names with placeholder values.

## Tools

| Tool | What it does |
|---|---|
| `list_tables` | Lists the tables, columns and named views the policy allows. Does not touch the database. |
| `describe_table` | Column types for an allowlisted table. Only policy columns are shown, and masked columns are flagged. |
| `query` | Runs one read-only `SELECT` under the policy: one table, or a join of allowlisted tables in one schema. |
| `run_view` | Runs a named view from the policy with typed parameters, for example `{"name": "revenue_by_status", "params": {"since": "2026-09-01"}}`. |
| `policy_info` | Returns a summary of the active policy: tables, columns, limits, join rules, views, mask rules, rotation. Contains no secrets. |
| `ping` | Checks connectivity without reading data. |

Denied calls return `isError: true` with a stable code, for example `column_not_allowed`, `table_not_allowed`, `multi_statement`, `non_read_statement`, `join_not_supported`, `cross_schema_join`, `ambiguous_column`, `duplicate_alias`, `row_limit_exceeded`, `masked_column_in_filter`, `view_not_found`, `invalid_params`.

## Policy reference

The policy is default deny. See [`examples/policy.example.yaml`](examples/policy.example.yaml).

```yaml
version: 1
connection_env: DATABASE_URL
readonly: true                 # must be true
defaults:
  max_rows: 100
  statement_timeout_ms: 5000
  limit_mode: clamp            # clamp or refuse
  require_limit: false
  max_join_tables: 4           # 1 switches joins off
allow:
  schemas: [public]
  tables:
    - name: customers
      columns: [id, name, created_at, billing_phone]
      require_predicate: "deleted_at IS NULL"
    - name: orders
      columns: [id, customer_id, total_cents, status, created_at]
      max_rows: 50
pii_mask:
  patterns:
    - column_regex: "(?i)email|phone|iban"
      strategy: redact         # redact, null or hash
views:
  - name: revenue_by_status
    description: Order count and total by status since a date.
    sql: >-
      select status, count(*) as orders, sum(total_cents) as total_cents
      from orders where created_at >= $1 group by status order by status
    params:
      - { name: since, type: date }
audit:
  path: ./astraeus-audit.jsonl
  rotate: { max_bytes: 10485760, daily: true, keep: 30 }
```

Rules:

1. **Allowlists.** Only listed schemas, tables and columns can be named anywhere in a query: select list, `ON`, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`. `SELECT *` and `alias.*` expand to the allowed columns only. Unqualified table names resolve in `allow.schemas` order, not through the database `search_path`.
2. **Row limit.** A missing `LIMIT` gets the cap. An over-large `LIMIT` is clamped (`limit_mode: clamp`, the default) or refused (`refuse`). `require_limit: true` refuses queries with no `LIMIT`. A join uses the smallest cap of the tables it reads. Responses report `row_limit`, `limit_clamped` and `may_have_more`. As a second layer, the server also truncates whatever the database returns to the cap.
3. **`require_predicate`.** On a single-table query the expression is ANDed into `WHERE`, with the caller's conditions grouped first so a caller `OR` cannot escape it. In a join, each table with a predicate is replaced by a derived table that already applies its own predicate and exposes only the allowlisted columns the query uses, so the predicate stays bound to its table under `INNER`, `LEFT`, `RIGHT` and `FULL` joins. Columns used in the predicate must be readable by the database role, but do not have to be in the `columns` list.
4. **Joins.** `INNER`, `LEFT`, `RIGHT` and `FULL JOIN ... ON` between allowlisted tables in the same schema, up to `max_join_tables` tables. Every column is rewritten with its table alias, an unqualified column allowed on more than one joined table is refused as ambiguous, and each alias may appear once. Cross-schema joins, comma joins, `CROSS JOIN`, `USING`, `NATURAL`, `LATERAL` and joined subqueries are refused.
5. **PII mask.** Any output column that is, or is built from, a column whose name matches a `column_regex` is masked, as is any output alias that matches. This holds for `SELECT *`, `alias.*`, aliases, expressions such as `lower(phone)`, joins and named views. Strategies: `redact` (replace with `[REDACTED]`), `null`, and `hash` (unsalted, truncated SHA-256; fine for de-duplication, weak for low-entropy values). Masked columns cannot be used in `ON`, `WHERE`, `GROUP BY`, `HAVING` or `ORDER BY`, otherwise a caller could recover values by probing.
6. **Named views.** Each view is fixed SQL with positional placeholders `$1..$n` that map, in order, to the declared `params`. At policy load the SQL is run through the same guard as an ad hoc query (allowlists, predicates, masks, row cap); a view that would be denied as a query makes the policy invalid and the server will not start. Every declared parameter must be used, and each placeholder is cast to its declared type: `text`, `integer`, `numeric`, `boolean`, `date` or `timestamp`. At call time values are type-checked and bound as query parameters, never spliced into SQL. Unknown or missing parameters are refused. A parameter may have a `default`.
7. **Read only.** Anything other than a single `SELECT` is rejected by the guard, and queries run in a `READ ONLY` transaction. The database role must also lack write grants (below).
8. **`deny_sql`.** Documents what is refused. The guard enforces these unconditionally, so removing an entry does not relax anything.

Policy names must match the real catalogue names. Unquoted Postgres identifiers are lower case.

## What the guard refuses

Multi-statement input; everything that is not `SELECT` (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `TRUNCATE`, `COPY`, `SET`, `GRANT`, `DO`, `CALL`, `EXPLAIN`, and so on); `WITH`, `UNION` and subqueries; the join forms listed above; `FOR UPDATE`; `DISTINCT ON`; window functions; unlisted functions (`pg_sleep`, `pg_read_file`, `set_config`, `dblink` and the rest); schema-qualified function calls; casts to `reg*` types; `$n` parameters outside named views; and anything the parser cannot understand. Unknown syntax is denied, not guessed at.

The callable function list is a short allowlist of aggregates, string, maths and date helpers. It is in `src/guard.ts`.

## Audit log

One JSON object per line, written before any result is returned. If the log cannot be written the call fails and returns no data.

```json
{"ts":"2026-10-07T02:17:31.231Z","policy_hash":"ff64ed87efa29a22","tool":"query","decision":"deny","reason":"column_not_allowed: column \"email\" is not allowed on public.customers","sql":"select email from customers","duration_ms":2}
```

Fields: timestamp, tool, policy hash, decision, reason, normalised SQL, table (comma-separated for joins), view name and parameter names for `run_view`, `transport: "http"` for calls over HTTP, row count, duration. SQL is normalised before logging: string, dollar-quoted and numeric literals become `?`, comments are removed, and whitespace is collapsed. View parameter values are never logged, only their names. Passwords, bearer tokens and connection strings are never logged.

Rotation is optional and set in the policy:

```yaml
audit:
  path: ./logs/astraeus-audit.jsonl
  rotate:
    max_bytes: 10485760   # rotate before a write would take the live file past 10 MiB (minimum 1024)
    daily: true           # rotate when the UTC date changes
    keep: 30              # keep the 30 newest rotated files; omit to keep all of them
```

On rotation the live file is renamed to `astraeus-audit.<UTC timestamp>.jsonl` (with a `.<n>` suffix if two rotations share a millisecond) and the next line starts a new live file. A rename never splits or drops a line, and rotated files are only deleted when `keep` is set. One server process should own a given audit path; give the stdio and HTTP entrypoints separate paths if both run.

## Streamable HTTP (opt-in)

stdio stays the default. For a local HTTP client, start the second entrypoint:

```bash
export DATABASE_URL='postgresql://astraeus_agent:<password>@db-host:5432/appdb'
export ASTRAEUS_HTTP_TOKEN="$(openssl rand -hex 32)"   # at least 32 characters
node dist/http-main.js --policy ./my-policy.yaml       # or: npm run start:http -- --policy ./my-policy.yaml
```

| Variable | Default | Notes |
|---|---|---|
| `ASTRAEUS_HTTP_TOKEN` | none | Required. One shared bearer token, at least 32 characters, no whitespace. |
| `ASTRAEUS_HTTP_HOST` | `127.0.0.1` | Loopback by default. Any other address needs `ASTRAEUS_HTTP_ALLOW_REMOTE=1`. |
| `ASTRAEUS_HTTP_PORT` | `8787` | |
| `ASTRAEUS_HTTP_ALLOW_REMOTE` | unset | Set to `1` only behind TLS you control. |

Behaviour:

- Fails closed: no token, a short token, a bad port, or a non-loopback host without the opt-in, and the process exits before it touches the database. The token never appears in errors or the audit log.
- `POST /mcp` is the MCP endpoint (stateless Streamable HTTP, JSON responses). It needs `Authorization: Bearer <token>`, compared in constant time. Missing or wrong tokens get `401` and an audit entry.
- On a loopback bind, requests whose `Host` header is not `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` get `403`, which blocks DNS rebinding from a browser.
- `GET /health` returns `{"status":"ok"}` with no token. It reads no data and does not touch the database.
- Request bodies over 1 MB get `413`.

Per-client keys and hosted multi-tenant HTTP are out of scope. One process serves one policy and one database role.

## Least-privilege role and RLS

The guard is the first line of defence. The database role is the second, and it should hold even if the guard has a bug. The integration suite proves the claims below by logging in as the agent role with a plain `pg` client, bypassing the server entirely (`tests/integration/db-claims.test.ts`). Create a dedicated role for the agent:

```sql
create role astraeus_agent login password '<set from your secret store>'
  nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls connection limit 4;
grant connect on database appdb to astraeus_agent;
grant usage on schema public to astraeus_agent;

-- PUBLIC gets TEMPORARY on every new database (and CREATE on schema public before PostgreSQL 15).
revoke temporary on database appdb from public;
revoke create on schema public from public;

-- Column-level SELECT only, matching the policy (plus any column the predicate uses).
grant select (id, name, billing_phone, created_at, deleted_at) on public.customers to astraeus_agent;
grant select (id, customer_id, total_cents, status, created_at) on public.orders to astraeus_agent;

-- No INSERT, UPDATE, DELETE, TRUNCATE, or DDL grants. Belt and braces:
alter role astraeus_agent set default_transaction_read_only = on;
alter role astraeus_agent set statement_timeout = '5s';
```

Do not grant `pg_read_all_data`, ownership of any object, or membership of any other role. Revoking `TEMPORARY` matters: without it, a raw connection can switch off read-only mode and create temporary tables, even with no other grants.

What the suite proves against a real PostgreSQL, as `astraeus_agent` with no guard in front:

- Selecting a non-granted column (`customers.email`), `SELECT *` on a partly granted table, or anything from a table with no grants fails with `42501`.
- Writes fail with `25006` in the default read-only mode, and with `42501` after the session switches read-only off: `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `CREATE TABLE`, `CREATE TEMPORARY TABLE`, `ALTER`, `DROP`, `GRANT`.
- The role cannot `SET ROLE` or `SET SESSION AUTHORIZATION`, cannot disable RLS or drop a policy, and `SET row_security = off` makes RLS-filtered reads fail rather than leak.
- Role-bound RLS limits rows: the agent sees 7 of the 10 seeded orders.

For multi-tenant schemas, add row-level security so the boundary lives in the database, not only in a predicate. **Bind the policy to the role**, with one role per tenant, so the agent cannot change it:

```sql
alter table public.orders enable row level security;
alter table public.orders force row level security;   -- also binds the table owner

create policy agent_tenant_orders on public.orders
  for select to astraeus_agent
  using (tenant_id = 42);
```

A policy keyed on a session setting, such as `current_setting('app.tenant_id')` pinned with `alter role ... set app.tenant_id`, is weaker: anyone holding the role's credentials can run `SET app.tenant_id = '<other>'` and read another tenant's rows. The guard refuses `SET` and `set_config`, so through this server the setting holds, but it is only as strong as the guard. The integration suite keeps a test that demonstrates this, so the advice here stays honest.

Recommendations for client installs:

- Keep the connection string in a secret store or the MCP host's environment configuration. Never commit it, paste it into chat, or write it to the policy file.
- Prefer a read replica DSN for agent traffic.
- Require TLS (`sslmode=verify-full`) when the database is not on the same host.
- One role and one policy file per client, so each audit log maps to one boundary.

## Smoke and integration tests

No Docker is needed. Both suites start a throwaway, real PostgreSQL server from npm with [`embedded-postgres`](https://www.npmjs.com/package/embedded-postgres) (PostgreSQL 18 binaries from zonky's embedded-postgres-binaries), on a random loopback port with random throwaway passwords, seed it from `smoke/seed.sql`, and delete it afterwards.

```bash
npm run smoke              # builds, then drives dist/ over stdio and HTTP
npm run test:integration   # vitest suite against the same embedded server
```

Why `embedded-postgres` and not PGlite: the claims under test are about what the agent role can do when it logs in on its own. `embedded-postgres` runs the real server binaries with password authentication, so the tests connect as `astraeus_agent` over the wire protocol, exactly like a client install, and grants, `default_transaction_read_only`, `SET ROLE` and RLS are enforced by an unmodified PostgreSQL. PGlite runs PostgreSQL in single-user mode inside the Node process and has no login roles over the network, so it could only imitate the agent with `SET ROLE` from a superuser session, which is a different thing from connecting as the agent.

The first start on Windows can take up to a minute (`initdb`); later starts are quicker. Set `APM_PG_LOG=1` to see the PostgreSQL log during the integration suite.

`npm run smoke` checks that:

- the role itself cannot read `customers.email` or `secrets`, cannot write or create anything even with read-only mode off, cannot switch role, and only sees its own tenant's orders;
- the row cap, PII redaction and `require_predicate` hold, on single tables and joins, including a `LEFT JOIN`;
- denied queries are denied (unlisted column, unlisted table, multiple statements, `DELETE`, cross-schema and non-allowlisted joins);
- a named view runs with a typed parameter and refuses a mistyped one;
- the HTTP entrypoint refuses to start without a token or on a public address, serves `/health`, returns `401` without the token, and serves governed queries with it;
- the audit log has allow and deny entries, marks HTTP calls, and contains no phone numbers, passwords or tokens.

The Docker alternative still works and uses the same seed:

```bash
export SMOKE_PG_ADMIN_PASSWORD='any-throwaway-value'
export SMOKE_PG_AGENT_PASSWORD='another-throwaway-value'
docker compose up -d --wait
SMOKE_TARGET=docker npm run smoke
docker compose down
```

The seed is `smoke/seed.sql` and the policy is `smoke/policy.smoke.yaml`.

### Safety suite and prompt-injection fixtures

`tests/integration/safety.test.ts` checks the read-only and output claims against a real database:

- writes, DDL, privilege changes, session and transaction control, multi-statement tricks (comments, string literals, `BEGIN`/`COMMIT` chains), `COPY` in every direction and function-based writes (a plpgsql function that inserts, `nextval`, `setval`, `set_config`, `lo_import`, `pg_read_file` and more) are refused by the guard, logged as denies, and leave the database unchanged;
- with the guard bypassed, `PgDb.runReadOnly` on a **superuser** connection still refuses DML, DDL, sequence and function writes (`25006`) and multi-statement strings (`42601`). For the agent role it also refuses `COPY` to or from files and programs;
- row caps hold for every way of asking for more rows (no limit, `LIMIT 1000`, `FETCH FIRST`, `OFFSET`, a cartesian join), and a slow join is cancelled at the policy `statement_timeout_ms`. The database layer applies the timeout too, and the role has its own `statement_timeout` as a backstop;
- no tool output contains the DSN, either password, or the host and port, on a healthy server, after a failed login, or when the database is unreachable.

`tests/integration/prompt-injection.test.ts` stores the fixtures in `tests/integration/fixtures/prompt-injection.ts` in a real table. The fixtures are hostile text such as instruction overrides, fake tool markup, JSON break-outs, stacked SQL, exfiltration requests, mask bait, image beacons, terminal escape codes, fake policy text and an oversized payload. The suite then reads them back through the server. The server never interprets result data, so the expected safe behaviour is: every payload comes back byte for byte as a JSON string value; the response keeps its own structure (no forged keys); masks and row caps still apply; control characters are escaped; the policy hash does not change; the audit log holds no row data; and if a model is tricked into sending the planted SQL, the guard refuses it. Whether a model obeys planted text is the client's concern. This suite proves that the server adds no path from data to action.

Locally the integration suite uses the embedded server. In CI (`.github/workflows/ci.yml`, job `integration`) it runs against a disposable Postgres service container (PostgreSQL 16 and 17). To use any other disposable server, set `APM_TEST_PG_ADMIN_URL` to a superuser URL for an **empty** database named `appdb`. The suite seeds it, creates the `astraeus_agent` role and refuses to run if that role already exists. This variable is read only by the test harness (`scripts/external-pg.mjs`), never by the server.

## Contract suite (mcp-eval)

`npm run eval:contract` builds the server and runs the [mcp-eval](https://github.com/SarutobiSasuke8/mcp-eval-harness) contract suite in `eval/mcp.suite.yaml`. The harness is a devDependency pinned to a commit SHA. The suite's stdio target is `scripts/eval-target.mjs`, which starts the same throwaway embedded PostgreSQL (seeded from `smoke/seed.sql`), runs `dist/index.js` with `smoke/policy.smoke.yaml`, and shuts the database down when the client disconnects. It needs no Docker, no network and no secrets.

The suite checks the exact tool list, the advertised input schema of every tool (`eval/fixtures/*.input.schema.json`), goldens for `list_tables`, `policy_info`, `describe_table`, a masked join and a named view against the seeded data, and the deny paths (`column_not_allowed`, `multi_statement`, `non_read_statement`, `table_not_allowed`, `cross_schema_join`, `invalid_params`, `view_not_found`, unknown tool). It exits 0 on pass, 1 on a broken contract and 2 if the target cannot start. Golden updates (`npx mcp-eval eval/mcp.suite.yaml --update-goldens`) are reviewed code changes and never run in CI. `.github/workflows/mcp-eval.yml` runs the suite on pull requests.

## Development

```bash
npm ci
npm run lint
npm run typecheck
npm test                   # unit tests, no database
npm run test:integration   # real embedded PostgreSQL, no Docker
npm run build
npm run eval:contract      # mcp-eval contract suite, real embedded PostgreSQL
```

Unit tests mock the `pg` layer (`Db` interface in `src/db.ts`), so they run without a database. They cover statement and join shapes, allowlist and mask deny paths, row caps, named-view validation and binding, audit on allow and deny, audit rotation, fail-closed stdio and HTTP startup, the HTTP auth and host checks, and MCP round trips in memory and over HTTP. The integration suite (`tests/integration`) runs the real stack and the guard-bypassing role checks against a real PostgreSQL.

Layout:

```text
src/policy.ts        policy schema, loader, hash, named views
src/guard.ts         SQL parse, allowlist, joins, rewrite
src/mask.ts          PII masking
src/audit.ts         JSONL audit log and rotation
src/db.ts            pg access (read-only transaction)
src/tools.ts         tool handlers
src/server.ts        MCP wiring
src/startup.ts       fail-closed startup
src/index.ts         stdio entrypoint
src/http.ts          Streamable HTTP transport, auth, health
src/http-main.ts     HTTP entrypoint
scripts/embedded-pg.mjs  throwaway embedded PostgreSQL for smoke and integration tests
scripts/external-pg.mjs  seeds an external disposable PostgreSQL (CI service container) for the integration suite
scripts/eval-target.mjs  stdio target for the contract suite (embedded PostgreSQL plus dist/index.js)
eval/                contract suite and fixtures
```

## Limits and honest caveats

- A guard is not a sandbox. Treat the database role and RLS as the real boundary and the guard as a strong filter in front of it.
- `hash` masking is weak for low-entropy values such as phone numbers. Prefer `redact` or `null`.
- Results can still be sensitive even when allowed. Keep column allowlists tight. A join can combine allowed columns in ways a single-table query cannot; set `max_join_tables: 1` if that matters for a client.
- Error messages from Postgres are returned to the caller after trimming and connection-string scrubbing. Keep the role's visible schema small.
- Audit rotation assumes one process per audit path. Shipping logs off the host is left to your platform.
- The HTTP entrypoint has one shared token and no per-client identity. Every HTTP caller acts as the same role under the same policy.

## Roadmap

In rough order:

1. `propose_write` with a human approval step. Never silent DML or DDL. Needs its own design first.
2. Hosted Streamable HTTP with per-client keys. Separate design; out of scope for the local-first server.

Done in v1: joins across allowlisted tables, named views, audit rotation, a local Streamable HTTP entrypoint, and Docker-free verification against a real PostgreSQL.

## Prior art

Studied for threat models and ergonomics, not copied: [gokiwitech/pgwarden-mcp](https://github.com/gokiwitech/pgwarden-mcp), [microsoft/postgres-mcp](https://github.com/microsoft/postgres-mcp), and the public postgres2mcp pattern.

## Licence

MIT. See [LICENSE](LICENSE).
