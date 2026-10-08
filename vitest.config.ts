import { defineConfig } from "vitest/config";

// Unit tests only. The real-Postgres suite lives in tests/integration (npm run test:integration).
export default defineConfig({ test: { include: ["tests/**/*.test.ts"], exclude: ["tests/integration/**", "node_modules/**"] } });
