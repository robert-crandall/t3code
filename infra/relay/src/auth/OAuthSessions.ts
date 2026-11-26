import { and, eq, isNotNull, isNull, lt, lte, or } from "drizzle-orm";
import * as Context from "effect/Context";
import * as Aead from "effect/crypto/Aead";
import * as Digest from "effect/crypto/Digest";
import * as Kdf from "effect/crypto/Kdf";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";

import * as RelayConfiguration from "../Config.ts";
import * as RelayDb from "../db.ts";
import { relayOauthSessions } from "../persistence/schema.ts";
import * as RelayTokens from "./RelayTokens.ts";

export const REFRESH_TOKEN_ROLLING_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
export const REFRESH_TOKEN_ABSOLUTE_TTL_MS = 90 * 24 * 60 * 60 * 1_000;
export const REFRESH_TOKEN_ROTATION_GRACE_WINDOW_MS = 60 * 1_000;
// Covers the 4s GitHub refresh POST, 1s body decode, and up to 3 bounded DB persist attempts
// (each up to 2s timeout + 5s @effect/sql-pg abort drain + backoff) so a worker is never
// preempted while persisting a consumed single-use GitHub refresh token.
export const GITHUB_REFRESH_LEASE_MS = 30 * 1_000;
const REFRESH_TOKEN_ABSOLUTE_TTL_SECONDS = Math.floor(REFRESH_TOKEN_ABSOLUTE_TTL_MS / 1_000);
const TOKEN_ENCRYPTION_SALT = new TextEncoder().encode("t3code-relay-oauth-github-token-v1");
const TOKEN_ENCRYPTION_INFO = new TextEncoder().encode("aes-256-gcm");

const REFRESH_ROTATION_CLOCK_SKEW_TOLERANCE_MS = 5_000;

function githubRefreshTokenAad(sessionId: string, clientId: string): string {
  return `${sessionId}:${clientId}:github-refresh`;
}

function formatUtcIso(epochMs: number): string {
  return DateTime.formatIso(DateTime.makeUnsafe(epochMs));
}

function revokedSessionValues(nowIso: string) {
  return {
    revokedAt: nowIso,
    encryptedCurrentRefreshToken: null,
    encryptedGithubRefreshToken: null,
    githubRefreshLeaseUntil: null,
    updatedAt: nowIso,
  } as const;
}

function isWithinRotationGraceWindow(
  row: { readonly previousTokenHash: string | null; readonly rotatedAt: string | null },
  tokenHash: string,
  nowMs: number,
): boolean {
  if (
    row.previousTokenHash === null ||
    row.previousTokenHash !== tokenHash ||
    row.rotatedAt === null
  ) {
    return false;
  }
  const rotatedAtMs = Date.parse(row.rotatedAt);
  if (!Number.isFinite(rotatedAtMs)) {
    return false;
  }
  const elapsedMs = nowMs - rotatedAtMs;
  return (
    elapsedMs >= -REFRESH_ROTATION_CLOCK_SKEW_TOLERANCE_MS &&
    elapsedMs <= REFRESH_TOKEN_ROTATION_GRACE_WINDOW_MS
  );
}

export class OAuthSessionPersistenceError extends Schema.TaggedError<OAuthSessionPersistenceError>()(
  "OAuthSessionPersistenceError",
  {
    operation: Schema.Literals([
      "create",
      "inspect",
      "rotate",
      "revoke",
      "prune-expired",
      "claim-github-refresh",
      "complete-github-refresh",
    ]),
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

export type InvalidGrantReason =
  | "not_found"
  | "client_mismatch"
  | "revoked"
  | "replayed"
  | "expired";

export type InspectOAuthSessionResult =
  | {
      readonly _tag: "Ready";
      readonly session: OAuthSessionIdentity;
      readonly githubAccessToken: string;
      readonly encryptedGithubAccessToken: string;
      readonly hasGithubRefreshToken: boolean;
    }
  | {
      readonly _tag: "InvalidGrant";
      readonly reason: InvalidGrantReason;
    };

export type ClaimGitHubRefreshResult =
  | {
      readonly _tag: "Claimed";
      readonly githubRefreshToken: string;
      readonly expectedEncryptedGithubRefreshToken: string;
      readonly claimedLeaseUntil: string;
    }
  | {
      readonly _tag: "AlreadyRefreshed";
      readonly githubAccessToken: string;
      readonly encryptedGithubAccessToken: string;
    }
  | { readonly _tag: "InFlight" }
  | { readonly _tag: "NoRefreshToken" }
  | { readonly _tag: "InvalidGrant"; readonly reason: InvalidGrantReason };

export type CompleteGitHubRefreshInput =
  | {
      readonly _tag: "Succeeded";
      readonly sessionId: string;
      readonly clientId: string;
      readonly expectedEncryptedGithubRefreshToken: string;
      readonly githubAccessToken: string;
      readonly githubRefreshToken?: string | null;
    }
  | {
      readonly _tag: "TransientFailure";
      readonly sessionId: string;
      readonly claimedLeaseUntil: string;
    }
  | {
      readonly _tag: "Rejected";
      readonly sessionId: string;
      readonly expectedEncryptedGithubRefreshToken: string;
      readonly claimedLeaseUntil: string;
    };

export type CompleteGitHubRefreshResult =
  | { readonly _tag: "Applied" }
  | { readonly _tag: "Superseded" };

export type RotateOAuthSessionResult =
  | {
      readonly _tag: "Rotated";
      readonly session: OAuthSessionIdentity;
      readonly refreshToken: string;
    }
  | {
      readonly _tag: "InvalidGrant";
      readonly reason: InvalidGrantReason;
    };

export class OAuthSessions extends Context.Service<
  OAuthSessions,
  {
    readonly sealSecret: (plaintext: string, aad: string) => Effect.Effect<string>;
    readonly openSecret: (sealed: string, aad: string) => Effect.Effect<Option.Option<string>>;
    readonly create: (input: {
      readonly userId: string;
      readonly githubLogin: string;
      readonly email?: string;
      readonly clientId: string;
      readonly githubAccessToken: string;
      readonly githubRefreshToken?: string | null;
      readonly authCodeJti?: string;
      readonly authCodeExpiresAt?: string;
    }) => Effect.Effect<CreateOAuthSessionResult, OAuthSessionPersistenceError>;
    readonly inspectForRefresh: (input: {
      readonly refreshToken: string;
      readonly clientId: string;
    }) => Effect.Effect<InspectOAuthSessionResult, OAuthSessionPersistenceError>;
    readonly claimGitHubRefresh: (input: {
      readonly sessionId: string;
      readonly clientId: string;
      readonly expectedEncryptedGithubAccessToken: string;
    }) => Effect.Effect<ClaimGitHubRefreshResult, OAuthSessionPersistenceError>;
    readonly completeGitHubRefresh: (
      input: CompleteGitHubRefreshInput,
    ) => Effect.Effect<CompleteGitHubRefreshResult, OAuthSessionPersistenceError>;
    readonly rotate: (input: {
      readonly refreshToken: string;
      readonly clientId: string;
    }) => Effect.Effect<RotateOAuthSessionResult, OAuthSessionPersistenceError>;
    readonly revoke: (input: {
      readonly refreshToken: string;
      readonly clientId?: string;
    }) => Effect.Effect<void, OAuthSessionPersistenceError>;
    readonly revokeById: (sessionId: string) => Effect.Effect<void, OAuthSessionPersistenceError>;
    readonly pruneExpired: Effect.Effect<void, OAuthSessionPersistenceError>;
  }
>()("t3code-relay/auth/OAuthSessions") {}

const make = Effect.gen(function* () {
  const db = yield* RelayDb.RelayDb;
  const transactions = yield* RelayDb.RelayTransactions;
  const config = yield* RelayConfiguration.RelayConfiguration;
  const relayTokens = yield* RelayTokens.RelayTokens;
  const aead = yield* Aead.Aead;
  const kdf = yield* Kdf.Kdf;
  const random = yield* SecureRandom.SecureRandom;
  const digest = yield* Digest.Digest;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const derivedKeyBytes = yield* kdf
    .derive(Kdf.hkdfSha256, encoder.encode(Redacted.value(config.githubOAuth.clientSecret)), {
      salt: TOKEN_ENCRYPTION_SALT,
      info: TOKEN_ENCRYPTION_INFO,
      length: Aead.aes256Gcm.keyLength,
    })
    .pipe(Effect.orDie);
  const tokenEncryptionKey = yield* Aead.key(Aead.aes256Gcm, derivedKeyBytes).pipe(Effect.orDie);

  const hashToken = (token: string) =>
    digest.digest(Digest.sha256, encoder.encode(token)).pipe(Effect.map(Base64Url.encode));

  const sealSecret: OAuthSessions["Service"]["sealSecret"] = Effect.fn(
    "relay.oauth_sessions.seal_secret",
  )(function* (plaintext, aad) {
    const nonce = yield* random.randomBytes(Aead.aes256Gcm.nonceLength);
    const ciphertext = yield* aead.encrypt(tokenEncryptionKey, encoder.encode(plaintext), {
      nonce,
      aad: encoder.encode(aad),
    });
    return `v1.${Base64Url.encode(nonce)}.${Base64Url.encode(ciphertext)}`;
  }, Effect.orDie);

  const openSecret: OAuthSessions["Service"]["openSecret"] = Effect.fn(
    "relay.oauth_sessions.open_secret",
  )(function* (sealed, aad) {
    const parts = sealed.split(".");
    if (parts.length !== 3 || parts[0] !== "v1") {
      return Option.none();
    }
    const nonce = Base64Url.decode(parts[1]!);
    const ciphertext = Base64Url.decode(parts[2]!);
    if (Result.isFailure(nonce) || Result.isFailure(ciphertext)) {
      return Option.none();
    }
    const decrypted = yield* aead
      .decrypt(tokenEncryptionKey, ciphertext.success, {
        nonce: nonce.success,
        aad: encoder.encode(aad),
      })
      .pipe(Effect.option);
    return Option.map(decrypted, (bytes) => decoder.decode(bytes));
  });

  const issueSignedRefreshToken = Effect.fnUntraced(function* (input: {
    readonly userId: string;
    readonly sessionId: string;
    readonly clientId: string;
    readonly issuedAtEpochSeconds: number;
    readonly absoluteExpiresAtMs: number;
  }) {
    const jti = yield* random.uuidV4();
    const expiresAtEpochSeconds = Math.max(
      input.issuedAtEpochSeconds + 1,
      Math.min(
        Math.floor(input.absoluteExpiresAtMs / 1_000),
        input.issuedAtEpochSeconds + REFRESH_TOKEN_ABSOLUTE_TTL_SECONDS,
      ),
    );
    return yield* relayTokens.issueOAuthRefreshToken({
      userId: input.userId,
      sessionId: input.sessionId,
      clientId: input.clientId,
      jti,
      issuedAtEpochSeconds: input.issuedAtEpochSeconds,
      expiresAtEpochSeconds,
    });
  });

  const create: OAuthSessions["Service"]["create"] = Effect.fn("relay.oauth_sessions.create")(
    function* (input) {
      const now = yield* DateTime.now;
      const nowIso = DateTime.formatIso(now);
      const issuedAtEpochSeconds = Math.floor(now.epochMilliseconds / 1_000);
      const absoluteExpiresAtMs = now.epochMilliseconds + REFRESH_TOKEN_ABSOLUTE_TTL_MS;
      const expiresAtIso = DateTime.formatIso(
        DateTime.makeUnsafe(now.epochMilliseconds + REFRESH_TOKEN_ROLLING_TTL_MS),
      );
      const absoluteExpiresAtIso = DateTime.formatIso(DateTime.makeUnsafe(absoluteExpiresAtMs));
      const sessionId = yield* random
        .uuidV4()
        .pipe(
          Effect.mapError(
            (cause) => new OAuthSessionPersistenceError({ operation: "create", cause }),
          ),
        );
      const refreshToken = yield* issueSignedRefreshToken({
        userId: input.userId,
        sessionId,
        clientId: input.clientId,
        issuedAtEpochSeconds,
        absoluteExpiresAtMs,
      }).pipe(
        Effect.mapError(
          (cause) => new OAuthSessionPersistenceError({ operation: "create", cause }),
        ),
      );
      const currentTokenHash = yield* hashToken(refreshToken).pipe(
        Effect.mapError(
          (cause) => new OAuthSessionPersistenceError({ operation: "create", cause }),
        ),
      );
      const encryptedGithubAccessToken = yield* sealSecret(
        input.githubAccessToken,
        `${sessionId}:${input.clientId}`,
      );
      const encryptedGithubRefreshToken =
        input.githubRefreshToken !== undefined &&
        input.githubRefreshToken !== null &&
        input.githubRefreshToken.length > 0
          ? yield* sealSecret(
              input.githubRefreshToken,
              githubRefreshTokenAad(sessionId, input.clientId),
            )
          : null;

      const values = {
        id: sessionId,
        currentTokenHash,
        previousTokenHash: null,
        encryptedCurrentRefreshToken: null,
        authCodeJti: input.authCodeJti ?? null,
        authCodeExpiresAt: input.authCodeExpiresAt ?? null,
        userId: input.userId,
        githubLogin: input.githubLogin,
        email: input.email ?? null,
        encryptedGithubAccessToken,
        encryptedGithubRefreshToken,
        githubRefreshLeaseUntil: null,
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

  const inspectForRefresh: OAuthSessions["Service"]["inspectForRefresh"] = Effect.fn(
    "relay.oauth_sessions.inspect_for_refresh",
  )(
    function* (input) {
      const claims = yield* relayTokens.verifyOAuthRefreshToken({ token: input.refreshToken });
      if (!claims) {
        return { _tag: "InvalidGrant", reason: "not_found" } as const;
      }
      if (claims.client_id !== input.clientId) {
        return { _tag: "InvalidGrant", reason: "client_mismatch" } as const;
      }

      const tokenHash = yield* hashToken(input.refreshToken);

      const rows = yield* db
        .select()
        .from(relayOauthSessions)
        .where(eq(relayOauthSessions.id, claims.sid))
        .limit(1);

      // Sample wall-clock time after reading the row so concurrent rotations do not appear in the future.
      const now = yield* DateTime.now;
      const nowMs = now.epochMilliseconds;
      const nowIso = DateTime.formatIso(now);

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
      if (
        row.currentTokenHash !== tokenHash &&
        !isWithinRotationGraceWindow(row, tokenHash, nowMs)
      ) {
        yield* db
          .update(relayOauthSessions)
          .set(revokedSessionValues(nowIso))
          .where(and(eq(relayOauthSessions.id, row.id), isNull(relayOauthSessions.revokedAt)));
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

      const githubAccessToken = yield* openSecret(
        row.encryptedGithubAccessToken,
        `${row.id}:${row.clientId}`,
      );
      if (Option.isNone(githubAccessToken)) {
        return { _tag: "InvalidGrant", reason: "revoked" } as const;
      }

      return {
        _tag: "Ready",
        session: {
          id: row.id,
          userId: row.userId,
          githubLogin: row.githubLogin,
          ...(row.email !== null && row.email.length > 0 ? { email: row.email } : {}),
          clientId: row.clientId,
        },
        githubAccessToken: githubAccessToken.value,
        encryptedGithubAccessToken: row.encryptedGithubAccessToken,
        hasGithubRefreshToken: row.encryptedGithubRefreshToken !== null,
      } as const;
    },
    Effect.mapError((cause) => new OAuthSessionPersistenceError({ operation: "inspect", cause })),
  );

  const claimGitHubRefresh: OAuthSessions["Service"]["claimGitHubRefresh"] = Effect.fn(
    "relay.oauth_sessions.claim_github_refresh",
  )(
    function* (input) {
      const now = yield* DateTime.now;
      const nowIso = DateTime.formatIso(now);
      const leaseUntilIso = formatUtcIso(now.epochMilliseconds + GITHUB_REFRESH_LEASE_MS);

      const claimed = yield* db
        .update(relayOauthSessions)
        .set({
          githubRefreshLeaseUntil: leaseUntilIso,
          updatedAt: nowIso,
        })
        .where(
          and(
            eq(relayOauthSessions.id, input.sessionId),
            eq(relayOauthSessions.clientId, input.clientId),
            isNull(relayOauthSessions.revokedAt),
            eq(
              relayOauthSessions.encryptedGithubAccessToken,
              input.expectedEncryptedGithubAccessToken,
            ),
            isNotNull(relayOauthSessions.encryptedGithubRefreshToken),
            or(
              isNull(relayOauthSessions.githubRefreshLeaseUntil),
              lte(relayOauthSessions.githubRefreshLeaseUntil, nowIso),
            ),
          ),
        )
        .returning({
          encryptedGithubRefreshToken: relayOauthSessions.encryptedGithubRefreshToken,
        });

      const claimedRow = claimed[0];
      if (claimedRow !== undefined) {
        if (claimedRow.encryptedGithubRefreshToken === null) {
          return { _tag: "NoRefreshToken" } as const;
        }
        const openedRefreshToken = yield* openSecret(
          claimedRow.encryptedGithubRefreshToken,
          githubRefreshTokenAad(input.sessionId, input.clientId),
        );
        if (Option.isNone(openedRefreshToken)) {
          return { _tag: "InvalidGrant", reason: "revoked" } as const;
        }
        return {
          _tag: "Claimed",
          githubRefreshToken: openedRefreshToken.value,
          expectedEncryptedGithubRefreshToken: claimedRow.encryptedGithubRefreshToken,
          claimedLeaseUntil: leaseUntilIso,
        } as const;
      }

      const rows = yield* db
        .select()
        .from(relayOauthSessions)
        .where(eq(relayOauthSessions.id, input.sessionId))
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
      if (row.encryptedGithubAccessToken !== input.expectedEncryptedGithubAccessToken) {
        const openedAccessToken = yield* openSecret(
          row.encryptedGithubAccessToken,
          `${row.id}:${row.clientId}`,
        );
        if (Option.isNone(openedAccessToken)) {
          return { _tag: "InvalidGrant", reason: "revoked" } as const;
        }
        return {
          _tag: "AlreadyRefreshed",
          githubAccessToken: openedAccessToken.value,
          encryptedGithubAccessToken: row.encryptedGithubAccessToken,
        } as const;
      }
      if (row.encryptedGithubRefreshToken === null) {
        return { _tag: "NoRefreshToken" } as const;
      }
      return { _tag: "InFlight" } as const;
    },
    Effect.mapError(
      (cause) => new OAuthSessionPersistenceError({ operation: "claim-github-refresh", cause }),
    ),
  );

  const completeGitHubRefresh: OAuthSessions["Service"]["completeGitHubRefresh"] = Effect.fn(
    "relay.oauth_sessions.complete_github_refresh",
  )(
    function* (input) {
      const nowIso = DateTime.formatIso(yield* DateTime.now);
      switch (input._tag) {
        case "Succeeded": {
          const encryptedGithubAccessToken = yield* sealSecret(
            input.githubAccessToken,
            `${input.sessionId}:${input.clientId}`,
          );
          const encryptedGithubRefreshToken =
            input.githubRefreshToken !== undefined &&
            input.githubRefreshToken !== null &&
            input.githubRefreshToken.length > 0
              ? yield* sealSecret(
                  input.githubRefreshToken,
                  githubRefreshTokenAad(input.sessionId, input.clientId),
                )
              : null;
          const updated = yield* db
            .update(relayOauthSessions)
            .set({
              encryptedGithubAccessToken,
              encryptedGithubRefreshToken,
              githubRefreshLeaseUntil: null,
              updatedAt: nowIso,
            })
            .where(
              and(
                eq(relayOauthSessions.id, input.sessionId),
                eq(relayOauthSessions.clientId, input.clientId),
                isNull(relayOauthSessions.revokedAt),
                eq(
                  relayOauthSessions.encryptedGithubRefreshToken,
                  input.expectedEncryptedGithubRefreshToken,
                ),
              ),
            )
            .returning({ id: relayOauthSessions.id });
          return updated.length > 0
            ? ({ _tag: "Applied" } as const)
            : ({ _tag: "Superseded" } as const);
        }
        case "TransientFailure": {
          const updated = yield* db
            .update(relayOauthSessions)
            .set({
              githubRefreshLeaseUntil: null,
              updatedAt: nowIso,
            })
            .where(
              and(
                eq(relayOauthSessions.id, input.sessionId),
                eq(relayOauthSessions.githubRefreshLeaseUntil, input.claimedLeaseUntil),
              ),
            )
            .returning({ id: relayOauthSessions.id });
          return updated.length > 0
            ? ({ _tag: "Applied" } as const)
            : ({ _tag: "Superseded" } as const);
        }
        case "Rejected": {
          const updated = yield* db
            .update(relayOauthSessions)
            .set(revokedSessionValues(nowIso))
            .where(
              and(
                eq(relayOauthSessions.id, input.sessionId),
                isNull(relayOauthSessions.revokedAt),
                eq(
                  relayOauthSessions.encryptedGithubRefreshToken,
                  input.expectedEncryptedGithubRefreshToken,
                ),
                eq(relayOauthSessions.githubRefreshLeaseUntil, input.claimedLeaseUntil),
              ),
            )
            .returning({ id: relayOauthSessions.id });
          return updated.length > 0
            ? ({ _tag: "Applied" } as const)
            : ({ _tag: "Superseded" } as const);
        }
      }
    },
    Effect.mapError(
      (cause) => new OAuthSessionPersistenceError({ operation: "complete-github-refresh", cause }),
    ),
  );

  const rotate: OAuthSessions["Service"]["rotate"] = Effect.fn("relay.oauth_sessions.rotate")(
    function* (input) {
      const claims = yield* relayTokens.verifyOAuthRefreshToken({ token: input.refreshToken });
      if (!claims) {
        return { _tag: "InvalidGrant", reason: "not_found" } as const;
      }
      if (claims.client_id !== input.clientId) {
        return { _tag: "InvalidGrant", reason: "client_mismatch" } as const;
      }

      const tokenHash = yield* hashToken(input.refreshToken);

      // Returns a tagged value instead of failing on replay so the transaction commits revocation.
      return yield* transactions.withTransaction(
        Effect.gen(function* () {
          const rows = yield* db
            .select()
            .from(relayOauthSessions)
            .where(eq(relayOauthSessions.id, claims.sid))
            .for("update")
            .limit(1);

          // Sample wall-clock time after acquiring the row lock so concurrent refreshes see a post-lock timestamp.
          const now = yield* DateTime.now;
          const nowMs = now.epochMilliseconds;
          const nowIso = DateTime.formatIso(now);

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
          const isCurrentToken = row.currentTokenHash === tokenHash;
          const isGraceRetry =
            !isCurrentToken && isWithinRotationGraceWindow(row, tokenHash, nowMs);
          if (!isCurrentToken && !isGraceRetry) {
            yield* db
              .update(relayOauthSessions)
              .set(revokedSessionValues(nowIso))
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

          const sessionIdentity: OAuthSessionIdentity = {
            id: row.id,
            userId: row.userId,
            githubLogin: row.githubLogin,
            ...(row.email !== null && row.email.length > 0 ? { email: row.email } : {}),
            clientId: row.clientId,
          };

          if (isGraceRetry) {
            const existingRefreshToken =
              row.encryptedCurrentRefreshToken !== null
                ? yield* openSecret(
                    row.encryptedCurrentRefreshToken,
                    `${row.id}:${row.clientId}:refresh`,
                  )
                : Option.none();
            if (Option.isSome(existingRefreshToken)) {
              return {
                _tag: "Rotated",
                session: sessionIdentity,
                refreshToken: existingRefreshToken.value,
              } as const;
            }
            yield* db
              .update(relayOauthSessions)
              .set(revokedSessionValues(nowIso))
              .where(eq(relayOauthSessions.id, row.id));
            return { _tag: "InvalidGrant", reason: "replayed" } as const;
          }

          const nextExpiresAtMs = Math.min(
            nowMs + REFRESH_TOKEN_ROLLING_TTL_MS,
            absoluteExpiresAtMs,
          );
          const nextExpiresAtIso = DateTime.formatIso(DateTime.makeUnsafe(nextExpiresAtMs));
          const nextRefreshToken = yield* issueSignedRefreshToken({
            userId: row.userId,
            sessionId: row.id,
            clientId: row.clientId,
            issuedAtEpochSeconds: Math.floor(nowMs / 1_000),
            absoluteExpiresAtMs,
          });
          const nextTokenHash = yield* hashToken(nextRefreshToken);
          const encryptedCurrentRefreshToken = yield* sealSecret(
            nextRefreshToken,
            `${row.id}:${row.clientId}:refresh`,
          );

          yield* db
            .update(relayOauthSessions)
            .set({
              currentTokenHash: nextTokenHash,
              previousTokenHash: row.currentTokenHash,
              encryptedCurrentRefreshToken,
              rotatedAt: nowIso,
              expiresAt: nextExpiresAtIso,
              updatedAt: nowIso,
            })
            .where(eq(relayOauthSessions.id, row.id));

          return {
            _tag: "Rotated",
            session: sessionIdentity,
            refreshToken: nextRefreshToken,
          } as const;
        }),
      );
    },
    Effect.mapError((cause) => new OAuthSessionPersistenceError({ operation: "rotate", cause })),
  );

  const revoke: OAuthSessions["Service"]["revoke"] = Effect.fn("relay.oauth_sessions.revoke")(
    function* (input) {
      const claims = yield* relayTokens.verifyOAuthRefreshToken({ token: input.refreshToken });
      if (!claims) {
        return;
      }
      if (input.clientId !== undefined && claims.client_id !== input.clientId) {
        return;
      }
      const nowIso = DateTime.formatIso(yield* DateTime.now);
      const condition =
        input.clientId !== undefined
          ? and(
              eq(relayOauthSessions.id, claims.sid),
              eq(relayOauthSessions.clientId, input.clientId),
              isNull(relayOauthSessions.revokedAt),
            )
          : and(eq(relayOauthSessions.id, claims.sid), isNull(relayOauthSessions.revokedAt));

      yield* db
        .update(relayOauthSessions)
        .set(revokedSessionValues(nowIso))
        .where(condition)
        .pipe(
          Effect.mapError(
            (cause) => new OAuthSessionPersistenceError({ operation: "revoke", cause }),
          ),
        );
    },
  );

  const revokeById: OAuthSessions["Service"]["revokeById"] = Effect.fn(
    "relay.oauth_sessions.revoke_by_id",
  )(function* (sessionId) {
    const nowIso = DateTime.formatIso(yield* DateTime.now);
    yield* db
      .update(relayOauthSessions)
      .set(revokedSessionValues(nowIso))
      .where(and(eq(relayOauthSessions.id, sessionId), isNull(relayOauthSessions.revokedAt)))
      .pipe(
        Effect.mapError(
          (cause) => new OAuthSessionPersistenceError({ operation: "revoke", cause }),
        ),
      );
  });

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
    sealSecret,
    openSecret,
    create,
    inspectForRefresh,
    claimGitHubRefresh,
    completeGitHubRefresh,
    rotate,
    revoke,
    revokeById,
    pruneExpired,
  });
});

export const layer = Layer.effect(OAuthSessions, make);
