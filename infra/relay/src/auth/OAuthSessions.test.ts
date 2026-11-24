import * as NodeServices from "@effect/platform-node/NodeServices";
import { PGlite } from "@electric-sql/pglite";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/pglite";
import { describe, expect, it } from "@effect/vitest";
import * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as TestClock from "effect/testing/TestClock";

import * as RelayDb from "../db.ts";
import { relayOauthSessions } from "../persistence/schema.ts";
import * as OAuthSessions from "./OAuthSessions.ts";

function makePgliteOAuthLayers(pg: PGlite) {
  const db = drizzle({ client: pg });

  const effectDb = {
    select: () => ({
      from: (table: typeof relayOauthSessions) => ({
        where: (condition: unknown) => ({
          for: () => ({
            limit: (n: number) =>
              Effect.promise(() =>
                db
                  .select()
                  .from(table)
                  .where(condition as never)
                  .limit(n),
              ),
          }),
        }),
      }),
    }),
    insert: (table: typeof relayOauthSessions) => ({
      values: (values: typeof relayOauthSessions.$inferInsert) =>
        Object.assign(
          Effect.promise(() => db.insert(table).values(values)),
          {
            onConflictDoNothing: (opts?: { target?: unknown }) => ({
              returning: (cols: Record<string, unknown>) =>
                Effect.promise(() =>
                  db
                    .insert(table)
                    .values(values)
                    .onConflictDoNothing(opts as never)
                    .returning(cols as never),
                ),
            }),
          },
        ),
    }),
    update: (table: typeof relayOauthSessions) => ({
      set: (values: Partial<typeof relayOauthSessions.$inferInsert>) => ({
        where: (condition: unknown) =>
          Effect.promise(() =>
            db
              .update(table)
              .set(values)
              .where(condition as never),
          ),
      }),
    }),
    delete: (table: typeof relayOauthSessions) => ({
      where: (condition: unknown) =>
        Effect.promise(() => db.delete(table).where(condition as never)),
    }),
  } as unknown as RelayDb.RelayDb["Service"];

  const transactions: RelayDb.RelayTransactions["Service"] = {
    withTransaction: (effect) =>
      Effect.acquireUseRelease(
        Effect.promise(() => pg.exec("BEGIN")),
        () => effect,
        (_, exit) =>
          Effect.promise(() => pg.exec(exit._tag === "Success" ? "COMMIT" : "ROLLBACK")).pipe(
            Effect.ignore,
          ),
      ),
  };

  return {
    db,
    layer: OAuthSessions.layer.pipe(
      Layer.provide(Layer.succeed(RelayDb.RelayDb, effectDb)),
      Layer.provide(Layer.succeed(RelayDb.RelayTransactions, transactions)),
      Layer.provide(SecureRandom.layerWebCrypto),
      Layer.provide(Digest.layerWebCrypto),
    ),
  };
}

const setupPglite = Effect.gen(function* () {
  const pg = yield* Effect.acquireRelease(
    Effect.promise(() => PGlite.create()),
    (client) => Effect.promise(() => client.close()),
  );
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const migrationsDir = yield* path.fromFileUrl(
    new URL("../../migrations/postgres/", import.meta.url),
  );
  for (const name of (yield* fs.readDirectory(migrationsDir)).toSorted()) {
    const migration = yield* fs.readFileString(`${migrationsDir}${name}/migration.sql`);
    yield* Effect.promise(() => pg.exec(migration));
  }
  return makePgliteOAuthLayers(pg);
});

describe("OAuthSessions", () => {
  it.effect("rejects duplicate authCodeJti so authorization codes are strictly one-time", () =>
    Effect.gen(function* () {
      const { layer } = yield* setupPglite;
      yield* TestClock.setTime(Date.parse("2026-11-24T12:00:00.000Z"));

      yield* Effect.gen(function* () {
        const sessions = yield* OAuthSessions.OAuthSessions;
        const first = yield* sessions.create({
          userId: "github:42",
          githubLogin: "octocat",
          email: "octocat@example.com",
          clientId: "t3-cli",
          authCodeJti: "code-jti-1",
          authCodeExpiresAt: "2026-11-24T12:05:00.000Z",
        });
        expect(first._tag).toBe("Created");

        const second = yield* sessions.create({
          userId: "github:42",
          githubLogin: "octocat",
          clientId: "t3-cli",
          authCodeJti: "code-jti-1",
          authCodeExpiresAt: "2026-11-24T12:05:00.000Z",
        });
        expect(second).toEqual({ _tag: "AuthCodeAlreadyUsed" });
      }).pipe(Effect.provide(layer));
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect("rotates refresh tokens atomically and commits revocation on replay", () =>
    Effect.gen(function* () {
      const { db, layer } = yield* setupPglite;
      const startMs = Date.parse("2026-11-24T12:00:00.000Z");
      yield* TestClock.setTime(startMs);

      yield* Effect.gen(function* () {
        const sessions = yield* OAuthSessions.OAuthSessions;
        const created = yield* sessions.create({
          userId: "github:42",
          githubLogin: "octocat",
          email: "octocat@example.com",
          clientId: "t3-cli",
        });
        if (created._tag !== "Created") {
          throw new Error("expected Created");
        }

        const rotated = yield* sessions.rotate({
          refreshToken: created.refreshToken,
          clientId: "t3-cli",
        });
        expect(rotated._tag).toBe("Rotated");
        if (rotated._tag !== "Rotated") {
          throw new Error("expected Rotated");
        }
        expect(rotated.refreshToken).not.toBe(created.refreshToken);
        expect(rotated.session).toMatchObject({
          userId: "github:42",
          githubLogin: "octocat",
          email: "octocat@example.com",
          clientId: "t3-cli",
        });

        // Replaying the prior refresh token must return InvalidGrant(replayed) AND commit revoked_at.
        const replay = yield* sessions.rotate({
          refreshToken: created.refreshToken,
          clientId: "t3-cli",
        });
        expect(replay).toEqual({ _tag: "InvalidGrant", reason: "replayed" });

        const rows = yield* Effect.promise(() =>
          db.select().from(relayOauthSessions).where(eq(relayOauthSessions.id, created.sessionId)),
        );
        expect(rows[0]?.revokedAt).not.toBeNull();

        // The previously valid rotated token is now also revoked.
        const afterRevoke = yield* sessions.rotate({
          refreshToken: rotated.refreshToken,
          clientId: "t3-cli",
        });
        expect(afterRevoke).toEqual({ _tag: "InvalidGrant", reason: "revoked" });
      }).pipe(Effect.provide(layer));
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect("enforces the 90-day absolute session cap across rolling rotations", () =>
    Effect.gen(function* () {
      const { layer } = yield* setupPglite;
      const startMs = Date.parse("2026-11-24T12:00:00.000Z");
      yield* TestClock.setTime(startMs);

      yield* Effect.gen(function* () {
        const sessions = yield* OAuthSessions.OAuthSessions;
        const created = yield* sessions.create({
          userId: "github:42",
          githubLogin: "octocat",
          clientId: "t3-cli",
        });
        if (created._tag !== "Created") {
          throw new Error("expected Created");
        }

        let token = created.refreshToken;
        // Rotate every 20 days up to day 80 (still within 90d cap).
        for (const day of [20, 40, 60, 80]) {
          yield* TestClock.setTime(startMs + day * 24 * 60 * 60 * 1_000);
          const next = yield* sessions.rotate({ refreshToken: token, clientId: "t3-cli" });
          expect(next._tag).toBe("Rotated");
          if (next._tag !== "Rotated") {
            throw new Error("expected Rotated");
          }
          token = next.refreshToken;
        }

        // At day 91 (> 90d absolute cap, even though only 11d since last rotation), must fail expired.
        yield* TestClock.setTime(startMs + 91 * 24 * 60 * 60 * 1_000);
        const expired = yield* sessions.rotate({ refreshToken: token, clientId: "t3-cli" });
        expect(expired).toEqual({ _tag: "InvalidGrant", reason: "expired" });
      }).pipe(Effect.provide(layer));
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect(
    "revokes explicitly and prunes only rows past both expires_at and auth_code_expires_at",
    () =>
      Effect.gen(function* () {
        const { db, layer } = yield* setupPglite;
        const startMs = Date.parse("2026-11-24T12:00:00.000Z");
        yield* TestClock.setTime(startMs);

        yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          const active = yield* sessions.create({
            userId: "github:1",
            githubLogin: "alice",
            clientId: "t3-cli",
          });
          const withLongAuthCode = yield* sessions.create({
            userId: "github:2",
            githubLogin: "bob",
            clientId: "t3-cli",
            authCodeJti: "long-code",
            authCodeExpiresAt: DateTime.formatIso(
              DateTime.makeUnsafe(startMs + 60 * 24 * 60 * 60 * 1_000),
            ),
          });
          if (active._tag !== "Created" || withLongAuthCode._tag !== "Created") {
            throw new Error("expected Created");
          }

          yield* sessions.revoke({ refreshToken: active.refreshToken, clientId: "t3-cli" });
          expect(
            yield* sessions.rotate({ refreshToken: active.refreshToken, clientId: "t3-cli" }),
          ).toEqual({ _tag: "InvalidGrant", reason: "revoked" });

          // At day 15, expires_at (30d) is still future: nothing is pruned.
          yield* TestClock.setTime(startMs + 15 * 24 * 60 * 60 * 1_000);
          yield* sessions.pruneExpired;
          expect(yield* Effect.promise(() => db.select().from(relayOauthSessions))).toHaveLength(2);

          // At day 35, expires_at is past for both, but bob's auth_code_expires_at is day 60:
          // only alice's row is pruned; bob's row stays to preserve one-time authCodeJti uniqueness.
          yield* TestClock.setTime(startMs + 35 * 24 * 60 * 60 * 1_000);
          yield* sessions.pruneExpired;
          const remaining = yield* Effect.promise(() => db.select().from(relayOauthSessions));
          expect(remaining.map((row) => row.id)).toEqual([withLongAuthCode.sessionId]);

          // At day 65, both timestamps are past: bob's row is pruned.
          yield* TestClock.setTime(startMs + 65 * 24 * 60 * 60 * 1_000);
          yield* sessions.pruneExpired;
          expect(yield* Effect.promise(() => db.select().from(relayOauthSessions))).toHaveLength(0);
        }).pipe(Effect.provide(layer));
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );
});
