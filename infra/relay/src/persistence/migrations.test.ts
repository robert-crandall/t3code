import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";
import * as NodeServices from "@effect/platform-node/NodeServices";
import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
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
      expect(Number(applied.rows[0]?.count)).toBeGreaterThanOrEqual(17);

      const oauthTable = yield* Effect.promise(() =>
        pg.query<{ table_name: string | null }>(
          "SELECT to_regclass('public.relay_oauth_sessions')::text AS table_name",
        ),
      );
      expect(oauthTable.rows[0]?.table_name).toBe("relay_oauth_sessions");

      const refreshCols = yield* Effect.promise(() =>
        pg.query<{ column_name: string; is_nullable: string }>(
          `SELECT column_name, is_nullable
             FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'relay_oauth_sessions'
              AND column_name IN ('encrypted_github_refresh_token', 'github_refresh_lease_until')
            ORDER BY column_name`,
        ),
      );
      expect(refreshCols.rows).toEqual([
        { column_name: "encrypted_github_refresh_token", is_nullable: "YES" },
        { column_name: "github_refresh_lease_until", is_nullable: "YES" },
      ]);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect(
    "preserves pre-existing relay_oauth_sessions rows across the github refresh migration",
    () =>
      Effect.gen(function* () {
        const pg = yield* Effect.acquireRelease(
          Effect.promise(() => PGlite.create()),
          (client) => Effect.promise(() => client.close()),
        );
        const path = yield* Path.Path;
        const migrationsFolder = yield* path.fromFileUrl(
          new URL("../../migrations/postgres", import.meta.url),
        );
        const fs = yield* FileSystem.FileSystem;
        const migrationDirs = (yield* fs.readDirectory(migrationsFolder)).toSorted();
        const targetIndex = migrationDirs.findIndex((dir) =>
          dir.endsWith("_relay_oauth_sessions_github_refresh"),
        );
        expect(targetIndex).toBeGreaterThan(0);

        for (const dir of migrationDirs.slice(0, targetIndex)) {
          const sql = yield* fs.readFileString(path.join(migrationsFolder, dir, "migration.sql"));
          yield* Effect.promise(() => pg.exec(sql));
        }

        yield* Effect.promise(() =>
          pg.query(
            `INSERT INTO public.relay_oauth_sessions (
            id, current_token_hash, user_id, github_login,
            encrypted_github_access_token, client_id,
            expires_at, absolute_expires_at, created_at, updated_at
          ) VALUES (
            'legacy-sess-1', 'hash-1', 'github:1', 'octocat',
            'v1.abc.def', 't3-mobile',
            '2026-12-01T00:00:00.000Z', '2027-02-01T00:00:00.000Z',
            '2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z'
          )`,
          ),
        );

        for (const dir of migrationDirs.slice(targetIndex)) {
          const sql = yield* fs.readFileString(path.join(migrationsFolder, dir, "migration.sql"));
          yield* Effect.promise(() => pg.exec(sql));
        }

        const existing = yield* Effect.promise(() =>
          pg.query<{
            id: string;
            encrypted_github_refresh_token: string | null;
            github_refresh_lease_until: string | null;
          }>(
            `SELECT id, encrypted_github_refresh_token, github_refresh_lease_until
             FROM public.relay_oauth_sessions
            WHERE id = 'legacy-sess-1'`,
          ),
        );
        expect(existing.rows).toEqual([
          {
            id: "legacy-sess-1",
            encrypted_github_refresh_token: null,
            github_refresh_lease_until: null,
          },
        ]);
      }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );
});
