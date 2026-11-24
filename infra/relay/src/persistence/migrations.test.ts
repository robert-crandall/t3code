import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";
import * as NodeServices from "@effect/platform-node/NodeServices";
import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Path from "effect/Path";

describe("Postgres migrations", () => {
  it.effect("applies cleanly and idempotently against PGlite", () =>
    Effect.gen(function* () {
      const pg = yield* Effect.acquireRelease(
        Effect.promise(() => PGlite.create()),
        (client) => Effect.promise(() => client.close()),
      );
      const path = yield* Path.Path;
      const migrationsFolder = yield* path.fromFileUrl(
        new URL("../../migrations/postgres", import.meta.url),
      );
      const db = drizzle({ client: pg });

      yield* Effect.promise(() =>
        migrate(db, {
          migrationsFolder,
          migrationsTable: "relay_migrations",
          migrationsSchema: "public",
        }),
      );
      // Re-running must be a no-op rather than replaying statements or failing.
      yield* Effect.promise(() =>
        migrate(db, {
          migrationsFolder,
          migrationsTable: "relay_migrations",
          migrationsSchema: "public",
        }),
      );

      const applied = yield* Effect.promise(() =>
        pg.query<{ count: string }>("SELECT count(*)::text AS count FROM public.relay_migrations"),
      );
      expect(Number(applied.rows[0]?.count)).toBeGreaterThanOrEqual(16);

      const oauthTable = yield* Effect.promise(() =>
        pg.query<{ table_name: string | null }>(
          "SELECT to_regclass('public.relay_oauth_sessions')::text AS table_name",
        ),
      );
      expect(oauthTable.rows[0]?.table_name).toBe("relay_oauth_sessions");
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );
});
