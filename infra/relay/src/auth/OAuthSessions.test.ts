import * as NodeServices from "@effect/platform-node/NodeServices";
import { eq } from "drizzle-orm";
import { describe, expect, it } from "@effect/vitest";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as TestClock from "effect/testing/TestClock";

import { relayOauthSessions } from "../persistence/schema.ts";
import * as OAuthSessions from "./OAuthSessions.ts";
import { setupPgliteOAuthTest } from "./testSupport.ts";

describe("OAuthSessions", () => {
  it.effect("rejects duplicate authCodeJti so authorization codes are strictly one-time", () =>
    Effect.gen(function* () {
      const { layerAuth } = yield* setupPgliteOAuthTest();
      yield* TestClock.setTime(Date.parse("2026-11-24T12:00:00.000Z"));

      yield* Effect.gen(function* () {
        const sessions = yield* OAuthSessions.OAuthSessions;
        const first = yield* sessions.create({
          userId: "github:42",
          githubLogin: "octocat",
          email: "octocat@example.com",
          clientId: "t3-cli",
          githubAccessToken: "gho_secret_token",
          authCodeJti: "code-jti-1",
          authCodeExpiresAt: "2026-11-24T12:05:00.000Z",
        });
        expect(first._tag).toBe("Created");

        const second = yield* sessions.create({
          userId: "github:42",
          githubLogin: "octocat",
          clientId: "t3-cli",
          githubAccessToken: "gho_secret_token",
          authCodeJti: "code-jti-1",
          authCodeExpiresAt: "2026-11-24T12:05:00.000Z",
        });
        expect(second).toEqual({ _tag: "AuthCodeAlreadyUsed" });
      }).pipe(Effect.provide(layerAuth));
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect("detects replay across multiple rotations and commits session revocation", () =>
    Effect.gen(function* () {
      const { db, layerAuth } = yield* setupPgliteOAuthTest();
      const startMs = Date.parse("2026-11-24T12:00:00.000Z");
      yield* TestClock.setTime(startMs);

      yield* Effect.gen(function* () {
        const sessions = yield* OAuthSessions.OAuthSessions;
        const created = yield* sessions.create({
          userId: "github:42",
          githubLogin: "octocat",
          email: "octocat@example.com",
          clientId: "t3-cli",
          githubAccessToken: "gho_secret_token",
        });
        if (created._tag !== "Created") {
          throw new Error("expected Created");
        }

        // Stored GitHub access token must be encrypted at rest, never plaintext.
        const initialRows = yield* Effect.promise(() =>
          db.select().from(relayOauthSessions).where(eq(relayOauthSessions.id, created.sessionId)),
        );
        expect(initialRows[0]?.encryptedGithubAccessToken).not.toContain("gho_secret_token");

        const inspected = yield* sessions.inspectForRefresh({
          refreshToken: created.refreshToken,
          clientId: "t3-cli",
        });
        expect(inspected).toMatchObject({
          _tag: "Ready",
          githubAccessToken: "gho_secret_token",
        });

        // Rotate twice: R0 -> R1 -> R2.
        const r1 = yield* sessions.rotate({
          refreshToken: created.refreshToken,
          clientId: "t3-cli",
        });
        expect(r1._tag).toBe("Rotated");
        if (r1._tag !== "Rotated") {
          throw new Error("expected Rotated");
        }
        const r2 = yield* sessions.rotate({
          refreshToken: r1.refreshToken,
          clientId: "t3-cli",
        });
        expect(r2._tag).toBe("Rotated");
        if (r2._tag !== "Rotated") {
          throw new Error("expected Rotated");
        }
        expect(r2.refreshToken).not.toBe(r1.refreshToken);
        expect(r2.session).toMatchObject({
          userId: "github:42",
          githubLogin: "octocat",
          email: "octocat@example.com",
          clientId: "t3-cli",
        });

        // Replaying R0 (two rotations old!) must still detect replay AND revoke the whole session.
        const replay = yield* sessions.inspectForRefresh({
          refreshToken: created.refreshToken,
          clientId: "t3-cli",
        });
        expect(replay).toEqual({ _tag: "InvalidGrant", reason: "replayed" });

        const rows = yield* Effect.promise(() =>
          db.select().from(relayOauthSessions).where(eq(relayOauthSessions.id, created.sessionId)),
        );
        expect(rows[0]?.revokedAt).not.toBeNull();

        // The latest valid token R2 is now also rejected as revoked.
        const afterRevoke = yield* sessions.rotate({
          refreshToken: r2.refreshToken,
          clientId: "t3-cli",
        });
        expect(afterRevoke).toEqual({ _tag: "InvalidGrant", reason: "revoked" });
      }).pipe(Effect.provide(layerAuth));
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect("enforces the 90-day absolute session cap across rolling rotations", () =>
    Effect.gen(function* () {
      const { layerAuth } = yield* setupPgliteOAuthTest();
      const startMs = Date.parse("2026-11-24T12:00:00.000Z");
      yield* TestClock.setTime(startMs);

      yield* Effect.gen(function* () {
        const sessions = yield* OAuthSessions.OAuthSessions;
        const created = yield* sessions.create({
          userId: "github:42",
          githubLogin: "octocat",
          clientId: "t3-cli",
          githubAccessToken: "gho_secret_token",
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

        // At day 91 (> 90d absolute cap, even though only 11d since last rotation), must fail.
        yield* TestClock.setTime(startMs + 91 * 24 * 60 * 60 * 1_000);
        const expired = yield* sessions.rotate({ refreshToken: token, clientId: "t3-cli" });
        expect(expired._tag).toBe("InvalidGrant");
      }).pipe(Effect.provide(layerAuth));
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect(
    "revokes explicitly and prunes only rows past both expires_at and auth_code_expires_at",
    () =>
      Effect.gen(function* () {
        const { db, layerAuth } = yield* setupPgliteOAuthTest();
        const startMs = Date.parse("2026-11-24T12:00:00.000Z");
        yield* TestClock.setTime(startMs);

        yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          const active = yield* sessions.create({
            userId: "github:1",
            githubLogin: "alice",
            clientId: "t3-cli",
            githubAccessToken: "gho_alice",
          });
          const withLongAuthCode = yield* sessions.create({
            userId: "github:2",
            githubLogin: "bob",
            clientId: "t3-cli",
            githubAccessToken: "gho_bob",
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
        }).pipe(Effect.provide(layerAuth));
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect(
    "fails closed when sealed GitHub token is tampered, swapped across sessions, malformed, or opened with a different key",
    () =>
      Effect.gen(function* () {
        const { db, layerAuth, makeLayerAuth } = yield* setupPgliteOAuthTest();
        yield* TestClock.setTime(Date.parse("2026-11-24T12:00:00.000Z"));

        const created = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          const a = yield* sessions.create({
            userId: "github:1",
            githubLogin: "alice",
            clientId: "t3-cli",
            githubAccessToken: "gho_alice_secret",
          });
          const b = yield* sessions.create({
            userId: "github:2",
            githubLogin: "bob",
            clientId: "t3-cli",
            githubAccessToken: "gho_bob_secret",
          });
          if (a._tag !== "Created" || b._tag !== "Created") {
            throw new Error("expected Created");
          }
          return { a, b };
        }).pipe(Effect.provide(layerAuth));

        const [rowA] = yield* Effect.promise(() =>
          db
            .select()
            .from(relayOauthSessions)
            .where(eq(relayOauthSessions.id, created.a.sessionId)),
        );
        const [rowB] = yield* Effect.promise(() =>
          db
            .select()
            .from(relayOauthSessions)
            .where(eq(relayOauthSessions.id, created.b.sessionId)),
        );
        const originalEnvelopeA = rowA!.encryptedGithubAccessToken;
        const originalEnvelopeB = rowB!.encryptedGithubAccessToken;

        // 1. Different derived key (rotated GITHUB_OAUTH_CLIENT_SECRET) fails closed.
        const rotatedKeyResult = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions.inspectForRefresh({
            refreshToken: created.a.refreshToken,
            clientId: "t3-cli",
          });
        }).pipe(Effect.provide(makeLayerAuth("gh-rotated-secret")));
        expect(rotatedKeyResult).toEqual({ _tag: "InvalidGrant", reason: "revoked" });

        // 2. Swapped ciphertext between sessions fails AAD binding (session id mismatch).
        yield* Effect.promise(() =>
          db
            .update(relayOauthSessions)
            .set({ encryptedGithubAccessToken: originalEnvelopeB })
            .where(eq(relayOauthSessions.id, created.a.sessionId)),
        );
        const swappedResult = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions.inspectForRefresh({
            refreshToken: created.a.refreshToken,
            clientId: "t3-cli",
          });
        }).pipe(Effect.provide(layerAuth));
        expect(swappedResult).toEqual({ _tag: "InvalidGrant", reason: "revoked" });

        // 3. Tampered ciphertext/tag fails AES-GCM verification.
        // Mutate the first base64url character so byte 0 always changes (the last character
        // carries 2 unused padding bits for a 32-byte AES-GCM ciphertext+tag).
        const [version, nonce, ciphertext] = originalEnvelopeA.split(".");
        const tamperedCiphertext = (ciphertext!.startsWith("A") ? "B" : "A") + ciphertext!.slice(1);
        yield* Effect.promise(() =>
          db
            .update(relayOauthSessions)
            .set({ encryptedGithubAccessToken: `${version}.${nonce}.${tamperedCiphertext}` })
            .where(eq(relayOauthSessions.id, created.a.sessionId)),
        );
        const tamperedResult = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions.inspectForRefresh({
            refreshToken: created.a.refreshToken,
            clientId: "t3-cli",
          });
        }).pipe(Effect.provide(layerAuth));
        expect(tamperedResult).toEqual({ _tag: "InvalidGrant", reason: "revoked" });

        // 4. Malformed envelope fails closed.
        yield* Effect.promise(() =>
          db
            .update(relayOauthSessions)
            .set({ encryptedGithubAccessToken: "not-an-envelope" })
            .where(eq(relayOauthSessions.id, created.a.sessionId)),
        );
        const malformedResult = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions.inspectForRefresh({
            refreshToken: created.a.refreshToken,
            clientId: "t3-cli",
          });
        }).pipe(Effect.provide(layerAuth));
        expect(malformedResult).toEqual({ _tag: "InvalidGrant", reason: "revoked" });
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect(
    "serializes concurrent refresh rotations so replay revokes the whole session, and rolls back failed updates",
    () =>
      Effect.gen(function* () {
        let failUpdate = false;
        const { layerAuth, getForUpdateCount } = yield* setupPgliteOAuthTest({
          failUpdate: () => failUpdate,
        });

        const created = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions.create({
            userId: "github:42",
            githubLogin: "octocat",
            clientId: "t3-cli",
            githubAccessToken: "gho_concurrent_test",
          });
        }).pipe(Effect.provide(layerAuth));
        expect(created._tag).toBe("Created");
        if (created._tag !== "Created") return;

        // Failed update inside rotate rolls back cleanly and keeps the original refresh token usable.
        failUpdate = true;
        const failedRotate = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions
            .rotate({ refreshToken: created.refreshToken, clientId: "t3-cli" })
            .pipe(Effect.result);
        }).pipe(Effect.provide(layerAuth));
        expect(failedRotate._tag).toBe("Failure");
        failUpdate = false;

        // Two simultaneous rotations with the same token: one rotates, the second triggers replay revocation.
        const [first, second] = yield* Effect.all(
          [
            Effect.gen(function* () {
              const sessions = yield* OAuthSessions.OAuthSessions;
              return yield* sessions.rotate({
                refreshToken: created.refreshToken,
                clientId: "t3-cli",
              });
            }).pipe(Effect.provide(layerAuth)),
            Effect.gen(function* () {
              const sessions = yield* OAuthSessions.OAuthSessions;
              return yield* sessions.rotate({
                refreshToken: created.refreshToken,
                clientId: "t3-cli",
              });
            }).pipe(Effect.provide(layerAuth)),
          ],
          { concurrency: "unbounded" },
        );

        const outcomes = [first, second];
        const winner = outcomes.find((entry) => entry._tag === "Rotated");
        const loser = outcomes.find((entry) => entry._tag === "InvalidGrant");
        expect(winner?._tag).toBe("Rotated");
        expect(loser).toEqual({ _tag: "InvalidGrant", reason: "replayed" });
        expect(getForUpdateCount()).toBeGreaterThanOrEqual(3);
        if (!winner || winner._tag !== "Rotated") return;

        // The replay committed revocation, so the winner's new refresh token is also rejected.
        const postReplay = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions.inspectForRefresh({
            refreshToken: winner.refreshToken,
            clientId: "t3-cli",
          });
        }).pipe(Effect.provide(layerAuth));
        expect(postReplay).toEqual({ _tag: "InvalidGrant", reason: "revoked" });
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );
});
