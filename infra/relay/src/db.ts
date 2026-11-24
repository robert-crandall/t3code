import * as Alchemy from "alchemy";
import type { PgClient } from "@effect/sql-pg/PgClient";
import * as Cloudflare from "@alchemy.run/cloudflare";
import type { EffectPgDatabase } from "drizzle-orm/effect-postgres";
import * as Config from "effect/Config";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";

export class RelayDb extends Context.Service<
  RelayDb,
  EffectPgDatabase & {
    readonly $client: PgClient;
  }
>()("t3code-relay/db/RelayDb") {}

export class RelayTransactions extends Context.Service<
  RelayTransactions,
  {
    readonly withTransaction: RelayDb["Service"]["$client"]["withTransaction"];
  }
>()("t3code-relay/db/RelayTransactions") {
  static readonly layer = Layer.effect(
    RelayTransactions,
    Effect.gen(function* () {
      const db = yield* RelayDb;
      return RelayTransactions.of({
        withTransaction: db.$client.withTransaction,
      });
    }),
  );
}

export const RelayHyperdrive = Effect.gen(function* () {
  const { stage } = yield* Alchemy.Stack;
  const hyperdriveId = Option.getOrUndefined(
    Option.filter(
      yield* Config.option(Config.String("RELAY_HYPERDRIVE_ID")),
      (value) => value.trim().length > 0,
    ),
  );
  if (hyperdriveId) {
    return Cloudflare.Hyperdrive.lookup("RelayHyperdrive", {
      hyperdriveId: hyperdriveId.trim(),
    });
  }
  const defaultName = stage === "prod" ? "t3code-relay" : `t3code-relay-${stage}`;
  const name = (yield* Config.String("RELAY_HYPERDRIVE_NAME").pipe(
    Config.withDefault(defaultName),
  )).trim();
  return Cloudflare.Hyperdrive.lookup("RelayHyperdrive", { name });
});
