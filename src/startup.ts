import { PgDb, type Db } from "./db.js";
import { JsonlAudit } from "./audit.js";
import { loadPolicy, PolicyError } from "./policy.js";
import type { Runtime } from "./tools.js";

/** Raised when the server cannot start safely. The message never contains the connection string. */
export class StartupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StartupError";
  }
}

export interface StartupOptions {
  env: NodeJS.ProcessEnv;
  argv: string[];
  /** Test seam. Defaults to a real pg pool. */
  dbFactory?: (connectionString: string) => Db;
}

function policyPathFrom(argv: string[], env: NodeJS.ProcessEnv): string | undefined {
  const i = argv.indexOf("--policy");
  if (i >= 0) return argv[i + 1];
  return env.ASTRAEUS_POLICY_PATH;
}

/** Build the runtime or throw StartupError. Fails closed on a missing policy or connection string. */
export function buildRuntime(opts: StartupOptions): Runtime {
  const policyPath = policyPathFrom(opts.argv, opts.env);
  if (!policyPath) {
    throw new StartupError("no policy configured: pass --policy <file> or set ASTRAEUS_POLICY_PATH");
  }
  let policy;
  try {
    policy = loadPolicy(policyPath);
  } catch (err) {
    if (err instanceof PolicyError) throw new StartupError(err.message);
    throw new StartupError(`policy could not be loaded: ${(err as Error).message}`);
  }
  const dsn = opts.env[policy.connectionEnv];
  if (!dsn) {
    throw new StartupError(`${policy.connectionEnv} is not set: refusing to start without a database connection string`);
  }
  const auditPath = opts.env.ASTRAEUS_AUDIT_PATH ?? policy.auditPath ?? "astraeus-audit.jsonl";
  let audit;
  try {
    audit = new JsonlAudit(auditPath, policy.hash);
  } catch (err) {
    throw new StartupError(`audit log is not writable at ${auditPath}: ${(err as Error).message}`);
  }
  const db = (opts.dbFactory ?? ((s: string) => new PgDb(s)))(dsn);
  return { policy, db, audit };
}
