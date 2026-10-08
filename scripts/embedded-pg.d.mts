export declare const SEED_SQL_PATH: string;
export declare const AGENT_ROLE: string;

export interface EmbeddedPg {
  /** Superuser DSN for seeding and assertions. Throwaway random password. */
  adminDsn: string;
  /** DSN for the least-privilege agent role. Throwaway random password. */
  agentDsn: string;
  agentPassword: string;
  port: number;
  version: string;
  stop(): Promise<void>;
}

export declare function startEmbeddedPostgres(opts?: { log?: boolean }): Promise<EmbeddedPg>;
