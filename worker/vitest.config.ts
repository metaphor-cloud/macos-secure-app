import { defineConfig } from "vitest/config";
import { cloudflarePool, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import path from "node:path";

// The real migration files. test/setup.ts builds every test's DB from them,
// so a broken migration fails the suite rather than a fresh database.
const migrations = await readD1Migrations(path.resolve(import.meta.dirname, "migrations"));

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // The first Durable Object call in a file loads the whole Worker.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // The Worker logs every step it takes; show it for a failing test only.
    silent: "passed-only",
    setupFiles: ["./test/network-guard.ts"],
    pool: cloudflarePool({
      main: "./src/index.ts",
      remoteBindings: false,
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        kvNamespaces: ["KV"],
        bindings: {
          ENVIRONMENT: "test",
          TEST_MIGRATIONS: migrations,
        },
      },
    }),
  },
});
