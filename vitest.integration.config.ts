import { defineConfig } from "vitest/config";

// Integration suite: one real embedded PostgreSQL (npm package embedded-postgres, no Docker)
// is started in globalSetup and shared by every file. First start on Windows can take a minute.
export default defineConfig({
  test: {
    include: ["tests/integration/**/*.test.ts"],
    globalSetup: ["tests/integration/global-setup.ts"],
    testTimeout: 30_000,
    hookTimeout: 240_000,
    fileParallelism: false,
  },
});
