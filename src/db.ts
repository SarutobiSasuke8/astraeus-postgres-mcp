import pg from "pg";

export interface QueryResult {
  fields: string[];
  rows: unknown[][];
}

export interface ColumnInfo {
  name: string;
  type: string;
  nullable: boolean;
}

/** The only surface the server uses to reach Postgres. Tests replace it with a mock. */
export interface Db {
  /** Run one SELECT inside a READ ONLY transaction with a statement timeout. `params` bind $1..$n. */
  runReadOnly(sql: string, timeoutMs: number, params?: unknown[]): Promise<QueryResult>;
  columnsOf(schema: string, table: string): Promise<ColumnInfo[]>;
  ping(): Promise<void>;
  close(): Promise<void>;
}

export class PgDb implements Db {
  private readonly pool: pg.Pool;

  constructor(connectionString: string) {
    this.pool = new pg.Pool({
      connectionString,
      max: 2,
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 10_000,
      application_name: "astraeus-postgres-mcp",
    });
    // Idle client errors must not crash the stdio server or print the DSN.
    this.pool.on("error", () => undefined);
  }

  async runReadOnly(sql: string, timeoutMs: number, params: unknown[] = []): Promise<QueryResult> {
    const timeout = Math.floor(timeoutMs);
    if (!Number.isInteger(timeout) || timeout <= 0) throw new Error("invalid statement timeout");
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN READ ONLY");
      await client.query(`SET LOCAL statement_timeout = ${timeout}`);
      // queryMode "extended" forces the extended protocol even with no parameters, so the
      // server rejects a string holding more than one statement (42601). rowMode alone does
      // not: without values, pg falls back to the simple protocol, which runs every statement.
      // @types/pg does not declare queryMode yet, though pg itself reads it (lib/query.js).
      const config: pg.QueryArrayConfig & { queryMode: "extended" } = { text: sql, values: params, rowMode: "array", queryMode: "extended" };
      const res = await client.query(config);
      return { fields: res.fields.map((f) => f.name), rows: res.rows as unknown[][] };
    } finally {
      try {
        await client.query("ROLLBACK");
      } finally {
        client.release();
      }
    }
  }

  async columnsOf(schema: string, table: string): Promise<ColumnInfo[]> {
    const res = await this.pool.query(
      `select column_name, data_type, is_nullable
         from information_schema.columns
        where table_schema = $1 and table_name = $2
        order by ordinal_position`,
      [schema, table],
    );
    return res.rows.map((r: { column_name: string; data_type: string; is_nullable: string }) => ({
      name: r.column_name,
      type: r.data_type,
      nullable: r.is_nullable === "YES",
    }));
  }

  async ping(): Promise<void> {
    await this.pool.query("select 1");
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
