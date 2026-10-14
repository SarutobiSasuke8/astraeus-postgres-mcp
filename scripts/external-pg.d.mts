import type { EmbeddedPg } from "./embedded-pg.mjs";

/** Seed an external, disposable PostgreSQL (empty database appdb) for the integration suite. */
export declare function prepareExternalPostgres(adminUrl: string): Promise<EmbeddedPg>;
