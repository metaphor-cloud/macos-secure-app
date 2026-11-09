import { env } from "cloudflare:workers";
import type { Bindings } from "../src/types";

interface Migration {
  name: string;
  queries: string[];
}

/** The Worker's bindings as the tests see them. */
export function getEnv(): Bindings {
  return env as unknown as Bindings;
}

/**
 * Applies the real migrations once per test file: the first call builds the
 * schema and leaves a marker table, every later call finds it and returns.
 * One batch per file, as `wrangler d1 migrations apply` runs them.
 */
export async function setupDatabase(): Promise<void> {
  const db = getEnv().DB;
  const marker = await db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_test_schema_from_migrations'").first();
  if (marker) return;
  const { TEST_MIGRATIONS: migrations } = env as unknown as { TEST_MIGRATIONS: Migration[] };
  for (const migration of migrations) {
    try {
      await db.batch(migration.queries.map((query) => db.prepare(query)));
    } catch (error) {
      throw new Error(`test database: migration ${migration.name} failed: ${String(error)}`);
    }
  }
  await db.prepare("CREATE TABLE _test_schema_from_migrations (applied_at TEXT NOT NULL DEFAULT (datetime('now')))").run();
}

/** Empties every table between tests, children before parents: the schema is the real one, foreign keys and all. */
export async function cleanDatabase(): Promise<void> {
  const db = getEnv().DB;
  for (const table of ["push_tokens", "app_keys", "attest_challenges", "attest_events", "notes"]) {
    await db.prepare(`DELETE FROM ${table}`).run();
  }
  // Rate limits and the userinfo cache.
  const keys = await getEnv().KV.list();
  await Promise.all(keys.keys.map((k) => getEnv().KV.delete(k.name)));
}
