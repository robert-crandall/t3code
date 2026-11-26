// @effect-diagnostics-next-line nodeBuiltinImport:off -- Effect's Crypto has no generateKeyPairSync.
import * as NodeCrypto from "node:crypto";

import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import * as Aead from "effect/crypto/Aead";
import * as Digest from "effect/crypto/Digest";
import * as Kdf from "effect/crypto/Kdf";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Signature from "effect/crypto/Signature";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Path from "effect/Path";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Semaphore from "effect/Semaphore";

import * as RelayConfiguration from "../Config.ts";
import * as RelayDb from "../db.ts";
import { relayOauthSessions } from "../persistence/schema.ts";
import * as CloudMintSigner from "./CloudMintSigner.ts";
import * as OAuthSessions from "./OAuthSessions.ts";
import * as RelayTokens from "./RelayTokens.ts";

const spkiPair = NodeCrypto.generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

class InjectedPersistenceError extends Schema.TaggedError<InjectedPersistenceError>()(
  "InjectedPersistenceError",
  {},
) {}

export const setupPgliteOAuthTest = Effect.fn("setupPgliteOAuthTest")(function* (options?: {
  readonly allowedOrgs?: ReadonlyArray<string>;
  readonly failUpdate?: () => boolean;
}) {
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

  const db = drizzle({ client: pg });
  let forUpdateCount = 0;
  let inTx = false;

  const effectDb = {
    select: () => ({
      from: (table: typeof relayOauthSessions) => ({
        where: (condition: unknown) => {
          const runLimit = (n: number, lockMode?: string) =>
            Effect.promise(() => {
              const query = db
                .select()
                .from(table)
                .where(condition as never);
              return (lockMode ? query.for(lockMode as never) : query).limit(n);
            });
          return {
            limit: (n: number) => runLimit(n),
            for: (mode: string) => ({
              limit: (n: number) => {
                if (mode === "update") forUpdateCount += 1;
                return runLimit(n, mode);
              },
            }),
          };
        },
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
        where: (condition: unknown) => {
          const runUpdate = (returningCols?: Record<string, unknown>) =>
            Effect.suspend(() => {
              const execute = () => {
                const query = db
                  .update(table)
                  .set(values)
                  .where(condition as never);
                return returningCols ? query.returning(returningCols as never) : query;
              };
              if (options?.failUpdate?.()) {
                // Inside a transaction, execute the write before failing so tests verify ROLLBACK reverts it.
                return inTx
                  ? Effect.promise(execute).pipe(
                      Effect.andThen(Effect.fail(new InjectedPersistenceError())),
                    )
                  : Effect.fail(new InjectedPersistenceError());
              }
              return Effect.promise(execute);
            });
          return Object.assign(runUpdate(), {
            returning: (cols: Record<string, unknown>) => runUpdate(cols),
          });
        },
      }),
    }),
    delete: (table: typeof relayOauthSessions) => ({
      where: (condition: unknown) =>
        Effect.promise(() => db.delete(table).where(condition as never)),
    }),
  } as unknown as RelayDb.RelayDb["Service"];

  const txLock = yield* Semaphore.make(1);
  const transactions: RelayDb.RelayTransactions["Service"] = {
    withTransaction: (effect) =>
      txLock.withPermits(1)(
        Effect.acquireUseRelease(
          Effect.promise(() => pg.exec("BEGIN")).pipe(
            Effect.tap(() =>
              Effect.sync(() => {
                inTx = true;
              }),
            ),
          ),
          () => effect,
          (_, exit) =>
            Effect.sync(() => {
              inTx = false;
            }).pipe(
              Effect.andThen(
                Effect.promise(() => pg.exec(exit._tag === "Success" ? "COMMIT" : "ROLLBACK")).pipe(
                  Effect.ignore,
                ),
              ),
            ),
        ),
      ),
  };

  const layerCrypto = Layer.mergeAll(
    Aead.layerWebCrypto,
    Digest.layerWebCrypto,
    Kdf.layerWebCrypto,
    Signature.layerWebCrypto,
  ).pipe(Layer.provideMerge(SecureRandom.layerWebCrypto));

  const makeLayerAuth = (clientSecret = "gh-secret-456") => {
    const configWithSecret = RelayConfiguration.RelayConfiguration.of({
      relayIssuer: "https://relay.crandalls.cloud",
      apns: null,
      apnsDeliveryJobSigningSecret: Redacted.make("job-secret"),
      githubOAuth: {
        clientId: "gh-client-123",
        clientSecret: Redacted.make(clientSecret),
        allowedOrgs: options?.allowedOrgs ?? ["robert-crandall-org"],
        oauthBaseUrl: "https://github.test",
        apiBaseUrl: "https://api.github.test",
      },
      cloudMintPrivateKey: Redacted.make(spkiPair.privateKey),
      cloudMintPublicKey: spkiPair.publicKey,
      managedEndpointBaseDomain: undefined,
      managedEndpointNamespace: undefined,
    });
    const layerBase = Layer.mergeAll(
      RelayConfiguration.layer(configWithSecret),
      Layer.succeed(RelayDb.RelayDb, effectDb),
      Layer.succeed(RelayDb.RelayTransactions, transactions),
      layerCrypto,
    );
    const layerRelayTokens = RelayTokens.layer.pipe(
      Layer.provideMerge(CloudMintSigner.layer),
      Layer.provideMerge(layerBase),
    );
    return OAuthSessions.layer.pipe(Layer.provideMerge(layerRelayTokens));
  };

  return { db, layerAuth: makeLayerAuth(), makeLayerAuth, getForUpdateCount: () => forUpdateCount };
});
