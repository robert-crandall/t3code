import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";

import * as T3ChatAccounts from "./T3ChatAccounts.ts";

describe("T3ChatAccounts", () => {
  it.effect("reports itself unavailable and fails linking operations cleanly", () =>
    Effect.gen(function* () {
      const accounts = yield* T3ChatAccounts.T3ChatAccounts;
      expect(accounts.available).toBe(false);
      expect((yield* Effect.flip(accounts.getLink({ userId: "github:1" })))._tag).toBe(
        "T3ChatNotConfigured",
      );
      expect((yield* Effect.flip(accounts.createLinkUrl({ userId: "github:1" })))._tag).toBe(
        "T3ChatNotConfigured",
      );
      expect((yield* Effect.flip(accounts.unlink({ userId: "github:1" })))._tag).toBe(
        "T3ChatNotConfigured",
      );
    }).pipe(Effect.provide(T3ChatAccounts.layer)),
  );
});
