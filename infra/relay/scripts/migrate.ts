// @effect-diagnostics nodeBuiltinImport:off - standalone Node CLI script for Postgres schema migrations.
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import type * as NodeTls from "node:tls";
import * as NodeURL from "node:url";

import * as NodeRuntime from "@effect/platform-node/NodeRuntime";
import * as PgClient from "@effect/sql-pg/PgClient";
import * as PgDrizzle from "drizzle-orm/effect-postgres";
import { migrate } from "drizzle-orm/effect-postgres/migrator";
import * as Config from "effect/Config";
import * as Console from "effect/Console";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Redacted from "effect/Redacted";

export const MIGRATIONS_TABLE = "relay_migrations";
export const MIGRATIONS_SCHEMA = "public";
export const MIGRATIONS_FOLDER = NodePath.resolve(
  NodePath.dirname(NodeURL.fileURLToPath(import.meta.url)),
  "../migrations/postgres",
);

const resolveMigrationConnection = (
  rawUrl: Redacted.Redacted<string>,
  caCertPath?: string,
): PgClient.PgPoolConfig => {
  const parsed = new URL(Redacted.value(rawUrl));
  const sslmode = parsed.searchParams.get("sslmode");
  const sslRootCert = caCertPath ?? parsed.searchParams.get("sslrootcert") ?? undefined;
  let ssl: boolean | NodeTls.ConnectionOptions | undefined;

  if (sslRootCert) {
    const ca = NodeFS.readFileSync(sslRootCert, "utf8");
    ssl = {
      ca,
      rejectUnauthorized: true,
      ...(sslmode === "verify-ca" ? { checkServerIdentity: () => undefined } : {}),
    };
    parsed.searchParams.delete("sslrootcert");
    if (sslmode === "verify-ca" || sslmode === "verify-full" || sslmode === "require") {
      parsed.searchParams.delete("sslmode");
    }
  } else if (sslmode === "no-verify") {
    ssl = { rejectUnauthorized: false };
    parsed.searchParams.set("sslmode", "require");
  }

  return {
    url: Redacted.make(parsed.toString()),
    ...(ssl !== undefined ? { ssl } : {}),
  };
};

const program = Effect.gen(function* () {
  const databaseUrl = yield* Config.Redacted("DATABASE_URL");
  const caCertPath = Option.getOrUndefined(
    Option.filter(
      yield* Config.option(Config.String("PGSSLROOTCERT")),
      (value) => value.trim().length > 0,
    ),
  );

  const clientLayer = PgClient.layer(resolveMigrationConnection(databaseUrl, caCertPath));
  yield* Effect.gen(function* () {
    const db = yield* PgDrizzle.makeWithDefaults();
    yield* migrate(db, {
      migrationsFolder: MIGRATIONS_FOLDER,
      migrationsTable: MIGRATIONS_TABLE,
      migrationsSchema: MIGRATIONS_SCHEMA,
    });
  }).pipe(Effect.provide(clientLayer));

  yield* Console.log(
    `Applied migrations from ${MIGRATIONS_FOLDER} (table: ${MIGRATIONS_SCHEMA}.${MIGRATIONS_TABLE}).`,
  );
});

NodeRuntime.runMain(program);
