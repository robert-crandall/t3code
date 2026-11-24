import { and, eq, isNull, lt, or } from "drizzle-orm";
import * as Context from "effect/Context";
import * as Digest from "effect/crypto/Digest";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";

import * as RelayDb from "../db.ts";
import { relayOauthSessions } from "../persistence/schema.ts";

export const REFRESH_TOKEN_ROLLING_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
export const REFRESH_TOKEN_ABSOLUTE_TTL_MS = 90 * 24 * 60 * 60 * 1_000;

export class OAuthSessionPersistenceError extends Schema.TaggedError<OAuthSessionPersistenceError>()(
  "OAuthSessionPersistenceError",
  {
    operation: Schema.Literals(["create", "rotate", "revoke", "prune-expired"]),
    cause: Schema.Defect(),
  },
) {
  override get message(): string {
    return `Failed to persist OAuth session state during '${this.operation}'`;
  }
}

export interface OAuthSessionIdentity {
  readonly id: string;
  readonly userId: string;
  readonly githubLogin: string;
  readonly email?: string;
  readonly clientId: string;
}

export type CreateOAuthSessionResult =
  | {
      readonly _tag: "Created";
      readonly sessionId: string;
      readonly refreshToken: string;
    }
  | {
      readonly _tag: "AuthCodeAlreadyUsed";
    };

export type RotateOAuthSessionResult =
  | {
      readonly _tag: "Rotated";
      readonly session: OAuthSessionIdentity;
      readonly refreshToken: string;
    }
  | {
      readonly _tag: "InvalidGrant";
      readonly reason: "not_found" | "client_mismatch" | "revoked" | "replayed" | "expired";
    };

export class OAuthSessions extends Context.Service<
  OAuthSessions,
  {
    readonly create: (input: {
      readonly userId: string;
      readonly githubLogin: string;
      readonly email?: string;
      readonly clientId: string;
      readonly authCodeJti?: string;
      readonly authCodeExpiresAt?: string;
    }) => Effect.Effect<CreateOAuthSessionResult, OAuthSessionPersistenceError>;
    readonly rotate: (input: {
      readonly refreshToken: string;
      readonly clientId: string;
    }) => Effect.Effect<RotateOAuthSessionResult, OAuthSessionPersistenceError>;
    readonly revoke: (input: {
      readonly refreshToken: string;
      readonly clientId?: string;
    }) => Effect.Effect<void, OAuthSessionPersistenceError>;
    readonly pruneExpired: Effect.Effect<void, OAuthSessionPersistenceError>;
  }
>()("t3code-relay/auth/OAuthSessions") {}

const make = Effect.gen(function* () {
  const db = yield* RelayDb.RelayDb;
  const transactions = yield* RelayDb.RelayTransactions;
  const random = yield* SecureRandom.SecureRandom;
  const digest = yield* Digest.Digest;

  const hashToken = (token: string) =>
    digest
      .digest(Digest.sha256, new TextEncoder().encode(token))
      .pipe(Effect.map(Base64Url.encode));

  const generateRefreshToken = Effect.fnUntraced(function* () {
    const bytes = yield* random.randomBytes(32);
    return `t3rt_${Base64Url.encode(bytes)}`;
  });

  const create: OAuthSessions["Service"]["create"] = Effect.fn("relay.oauth_sessions.create")(
    function* (input) {
      const now = yield* DateTime.now;
      const nowIso = DateTime.formatIso(now);
      const expiresAtIso = DateTime.formatIso(
        DateTime.makeUnsafe(now.epochMilliseconds + REFRESH_TOKEN_ROLLING_TTL_MS),
      );
      const absoluteExpiresAtIso = DateTime.formatIso(
        DateTime.makeUnsafe(now.epochMilliseconds + REFRESH_TOKEN_ABSOLUTE_TTL_MS),
      );
      const sessionId = yield* random
        .uuidV4()
        .pipe(
          Effect.mapError(
            (cause) => new OAuthSessionPersistenceError({ operation: "create", cause }),
          ),
        );
      const refreshToken = yield* generateRefreshToken().pipe(
        Effect.mapError(
          (cause) => new OAuthSessionPersistenceError({ operation: "create", cause }),
        ),
      );
      const currentTokenHash = yield* hashToken(refreshToken).pipe(
        Effect.mapError(
          (cause) => new OAuthSessionPersistenceError({ operation: "create", cause }),
        ),
      );

      const values = {
        id: sessionId,
        currentTokenHash,
        previousTokenHash: null,
        authCodeJti: input.authCodeJti ?? null,
        authCodeExpiresAt: input.authCodeExpiresAt ?? null,
        userId: input.userId,
        githubLogin: input.githubLogin,
        email: input.email ?? null,
        clientId: input.clientId,
        rotatedAt: null,
        revokedAt: null,
        expiresAt: expiresAtIso,
        absoluteExpiresAt: absoluteExpiresAtIso,
        createdAt: nowIso,
        updatedAt: nowIso,
      };

      if (input.authCodeJti !== undefined) {
        const inserted = yield* db
          .insert(relayOauthSessions)
          .values(values)
          .onConflictDoNothing({ target: relayOauthSessions.authCodeJti })
          .returning({ id: relayOauthSessions.id })
          .pipe(
            Effect.mapError(
              (cause) => new OAuthSessionPersistenceError({ operation: "create", cause }),
            ),
          );
        if (inserted.length === 0) {
          return { _tag: "AuthCodeAlreadyUsed" } as const;
        }
      } else {
        yield* db
          .insert(relayOauthSessions)
          .values(values)
          .pipe(
            Effect.mapError(
              (cause) => new OAuthSessionPersistenceError({ operation: "create", cause }),
            ),
          );
      }

      return { _tag: "Created", sessionId, refreshToken } as const;
    },
  );

  const rotate: OAuthSessions["Service"]["rotate"] = Effect.fn("relay.oauth_sessions.rotate")(
    function* (input) {
      const tokenHash = yield* hashToken(input.refreshToken);
      const nextRefreshToken = yield* generateRefreshToken();
      const nextTokenHash = yield* hashToken(nextRefreshToken);

      // Returns a tagged value instead of failing on replay so the transaction commits revocation.
      return yield* transactions.withTransaction(
        Effect.gen(function* () {
          const now = yield* DateTime.now;
          const nowMs = now.epochMilliseconds;
          const nowIso = DateTime.formatIso(now);

          const rows = yield* db
            .select()
            .from(relayOauthSessions)
            .where(
              or(
                eq(relayOauthSessions.currentTokenHash, tokenHash),
                eq(relayOauthSessions.previousTokenHash, tokenHash),
              ),
            )
            .for("update")
            .limit(1);

          const row = rows[0];
          if (!row) {
            return { _tag: "InvalidGrant", reason: "not_found" } as const;
          }
          if (row.clientId !== input.clientId) {
            return { _tag: "InvalidGrant", reason: "client_mismatch" } as const;
          }
          if (row.revokedAt !== null) {
            return { _tag: "InvalidGrant", reason: "revoked" } as const;
          }
          if (row.previousTokenHash === tokenHash) {
            yield* db
              .update(relayOauthSessions)
              .set({ revokedAt: nowIso, updatedAt: nowIso })
              .where(eq(relayOauthSessions.id, row.id));
            return { _tag: "InvalidGrant", reason: "replayed" } as const;
          }

          const expiresAtMs = Date.parse(row.expiresAt);
          const absoluteExpiresAtMs = Date.parse(row.absoluteExpiresAt);
          if (
            !Number.isFinite(expiresAtMs) ||
            !Number.isFinite(absoluteExpiresAtMs) ||
            expiresAtMs <= nowMs ||
            absoluteExpiresAtMs <= nowMs
          ) {
            return { _tag: "InvalidGrant", reason: "expired" } as const;
          }

          const nextExpiresAtMs = Math.min(
            nowMs + REFRESH_TOKEN_ROLLING_TTL_MS,
            absoluteExpiresAtMs,
          );
          const nextExpiresAtIso = DateTime.formatIso(DateTime.makeUnsafe(nextExpiresAtMs));

          yield* db
            .update(relayOauthSessions)
            .set({
              currentTokenHash: nextTokenHash,
              previousTokenHash: tokenHash,
              rotatedAt: nowIso,
              expiresAt: nextExpiresAtIso,
              updatedAt: nowIso,
            })
            .where(eq(relayOauthSessions.id, row.id));

          return {
            _tag: "Rotated",
            session: {
              id: row.id,
              userId: row.userId,
              githubLogin: row.githubLogin,
              ...(row.email !== null && row.email.length > 0 ? { email: row.email } : {}),
              clientId: row.clientId,
            },
            refreshToken: nextRefreshToken,
          } as const;
        }),
      );
    },
    Effect.mapError((cause) => new OAuthSessionPersistenceError({ operation: "rotate", cause })),
  );

  const revoke: OAuthSessions["Service"]["revoke"] = Effect.fn("relay.oauth_sessions.revoke")(
    function* (input) {
      const tokenHash = yield* hashToken(input.refreshToken).pipe(
        Effect.mapError(
          (cause) => new OAuthSessionPersistenceError({ operation: "revoke", cause }),
        ),
      );
      const nowIso = DateTime.formatIso(yield* DateTime.now);
      const tokenMatch = or(
        eq(relayOauthSessions.currentTokenHash, tokenHash),
        eq(relayOauthSessions.previousTokenHash, tokenHash),
      );
      const condition =
        input.clientId !== undefined
          ? and(
              tokenMatch,
              eq(relayOauthSessions.clientId, input.clientId),
              isNull(relayOauthSessions.revokedAt),
            )
          : and(tokenMatch, isNull(relayOauthSessions.revokedAt));

      yield* db
        .update(relayOauthSessions)
        .set({ revokedAt: nowIso, updatedAt: nowIso })
        .where(condition)
        .pipe(
          Effect.mapError(
            (cause) => new OAuthSessionPersistenceError({ operation: "revoke", cause }),
          ),
        );
    },
  );

  const pruneExpired: OAuthSessions["Service"]["pruneExpired"] = Effect.gen(function* () {
    const nowIso = DateTime.formatIso(yield* DateTime.now);
    // Keep rows while expiresAt >= now (preserves replay detection for revoked sessions)
    // and while authCodeExpiresAt >= now (preserves one-time authCodeJti uniqueness).
    yield* db
      .delete(relayOauthSessions)
      .where(
        and(
          lt(relayOauthSessions.expiresAt, nowIso),
          or(
            isNull(relayOauthSessions.authCodeExpiresAt),
            lt(relayOauthSessions.authCodeExpiresAt, nowIso),
          ),
        ),
      )
      .pipe(
        Effect.mapError(
          (cause) => new OAuthSessionPersistenceError({ operation: "prune-expired", cause }),
        ),
      );
  }).pipe(Effect.withSpan("relay.oauth_sessions.prune_expired"));

  return OAuthSessions.of({
    create,
    rotate,
    revoke,
    pruneExpired,
  });
});

export const layer = Layer.effect(OAuthSessions, make);
