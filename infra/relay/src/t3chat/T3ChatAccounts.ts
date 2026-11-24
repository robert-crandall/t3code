import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import type { RelayT3ChatLink } from "@t3tools/contracts/relay";

export class T3ChatNotConfigured extends Schema.TaggedError<T3ChatNotConfigured>()(
  "T3ChatNotConfigured",
  {},
) {
  override get message(): string {
    return "T3 Chat linking is not configured on this relay";
  }
}

export class T3ChatRequestFailed extends Schema.TaggedError<T3ChatRequestFailed>()(
  "T3ChatRequestFailed",
  {
    operation: Schema.Literals(["get-link", "unlink"]),
    cause: Schema.Defect(),
  },
) {
  override get message(): string {
    return `T3 Chat '${this.operation}' request failed`;
  }
}

/**
 * T3 Chat linking requires Clerk-backed T3 Chat accounts and is disabled on
 * GitHub OAuth self-hosted relays.
 */
export class T3ChatAccounts extends Context.Service<
  T3ChatAccounts,
  {
    readonly available: boolean;
    readonly createLinkUrl: (input: {
      readonly userId: string;
    }) => Effect.Effect<string, T3ChatNotConfigured>;
    readonly getLink: (input: {
      readonly userId: string;
    }) => Effect.Effect<RelayT3ChatLink | null, T3ChatNotConfigured | T3ChatRequestFailed>;
    readonly unlink: (input: {
      readonly userId: string;
    }) => Effect.Effect<void, T3ChatNotConfigured | T3ChatRequestFailed>;
  }
>()("t3code-relay/t3chat/T3ChatAccounts") {}

export const layer = Layer.succeed(
  T3ChatAccounts,
  T3ChatAccounts.of({
    available: false,
    createLinkUrl: Effect.fn("T3ChatAccounts.createLinkUrl")(function* () {
      return yield* new T3ChatNotConfigured();
    }),
    getLink: Effect.fn("T3ChatAccounts.getLink")(function* () {
      return yield* new T3ChatNotConfigured();
    }),
    unlink: Effect.fn("T3ChatAccounts.unlink")(function* () {
      return yield* new T3ChatNotConfigured();
    }),
  }),
);
