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
  const effectDb = {
    select: () => ({
      from: (table: typeof relayOauthSessions) => ({
        where: (condition: unknown) => {
          const runLimit = (n: number) =>
            Effect.promise(() =>
              db
                .select()
                .from(table)
                .where(condition as never)
                .limit(n),
            );
          return {
            limit: runLimit,
            for: () => ({
              limit: runLimit,
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
        where: (condition: unknown) =>
          options?.failUpdate?.()
            ? Effect.fail(new InjectedPersistenceError())
            : Effect.promise(() =>
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

  const config = RelayConfiguration.RelayConfiguration.of({
    relayIssuer: "https://relay.crandalls.cloud",
    apns: null,
    apnsDeliveryJobSigningSecret: Redacted.make("job-secret"),
    githubOAuth: {
      clientId: "gh-client-123",
      clientSecret: Redacted.make("gh-secret-456"),
      allowedOrgs: options?.allowedOrgs ?? ["robert-crandall-org"],
      oauthBaseUrl: "https://github.test",
      apiBaseUrl: "https://api.github.test",
    },
    cloudMintPrivateKey: Redacted.make(spkiPair.privateKey),
    cloudMintPublicKey: spkiPair.publicKey,
    managedEndpointBaseDomain: undefined,
    managedEndpointNamespace: undefined,
  });

  const layerCrypto = Layer.mergeAll(
    Aead.layerWebCrypto,
    Digest.layerWebCrypto,
    Kdf.layerWebCrypto,
    Signature.layerWebCrypto,
  ).pipe(Layer.provideMerge(SecureRandom.layerWebCrypto));

  const layerBase = Layer.mergeAll(
    RelayConfiguration.layer(config),
    Layer.succeed(RelayDb.RelayDb, effectDb),
    Layer.succeed(RelayDb.RelayTransactions, transactions),
    layerCrypto,
  );

  const layerRelayTokens = RelayTokens.layer.pipe(
    Layer.provideMerge(CloudMintSigner.layer),
    Layer.provideMerge(layerBase),
  );

  const layerAuth = OAuthSessions.layer.pipe(Layer.provideMerge(layerRelayTokens));

  return { db, layerAuth };
});
