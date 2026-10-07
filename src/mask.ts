import { createHash } from "node:crypto";
import type { MaskStrategy } from "./policy.js";

export const REDACTED = "[REDACTED]";

export function maskValue(value: unknown, strategy: MaskStrategy): unknown {
  if (value === null || value === undefined) return null;
  switch (strategy) {
    case "null":
      return null;
    case "hash":
      // Unsalted and truncated. Fine for joining or de-duplicating, not secrecy for low-entropy values.
      return `sha256:${createHash("sha256").update(String(value)).digest("hex").slice(0, 12)}`;
    default:
      return REDACTED;
  }
}

/** Apply masks by output column position. Rows are arrays (pg rowMode: "array"). */
export function maskRows(rows: unknown[][], masked: Map<number, MaskStrategy>): unknown[][] {
  if (masked.size === 0) return rows;
  return rows.map((row) =>
    row.map((v, i) => {
      const strategy = masked.get(i);
      return strategy ? maskValue(v, strategy) : v;
    }),
  );
}
