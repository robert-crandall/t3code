import * as NodeServices from "@effect/platform-node/NodeServices";
import { assert, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Path from "effect/Path";

import { acquireServiceSelectionLock } from "./serviceSelectionLock.ts";

it.layer(NodeServices.layer)("service selection lock", (it) => {
  it.effect("reclaims a lease from an earlier boot even when its PID is live again", () =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const root = yield* fs.makeTempDirectoryScoped({ prefix: "t3-service-selection-lock-" });
      const selectionPath = path.join(root, "service-state.json");
      const lock = `${selectionPath}.selection-lock`;
      const stale = `${process.pid}.1.00000000-0000-4000-8000-000000000000`;
      yield* fs.makeDirectory(lock, { recursive: true });
      yield* fs.writeFileString(path.join(lock, stale), "");

      const release = yield* Effect.promise(() => acquireServiceSelectionLock(selectionPath));
      const owners = yield* fs.readDirectory(lock);
      assert.equal(owners.length, 1);
      assert.notEqual(owners[0], stale);
      assert.isTrue(owners[0]!.startsWith(`${process.pid}.`));
      release();
      assert.isFalse(yield* fs.exists(lock));
    }),
  );

  it.effect("waits on a contended live lease until the first holder releases it", () =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const root = yield* fs.makeTempDirectoryScoped({ prefix: "t3-service-selection-lock-" });
      const selectionPath = path.join(root, "service-state.json");
      const lock = `${selectionPath}.selection-lock`;

      const releaseFirst = yield* Effect.promise(() => acquireServiceSelectionLock(selectionPath));
      let signalRetryStarted!: () => void;
      const retryStarted = new Promise<void>((resolve) => {
        signalRetryStarted = resolve;
      });
      let releaseRetryGate!: () => void;
      const retryGate = new Promise<void>((resolve) => {
        releaseRetryGate = resolve;
      });
      let secondAcquired = false;
      const second = acquireServiceSelectionLock(selectionPath, {
        waitForRetry: () => {
          signalRetryStarted();
          return retryGate;
        },
      }).then((release) => {
        secondAcquired = true;
        return release;
      });
      yield* Effect.promise(() => retryStarted);
      assert.isFalse(secondAcquired);
      releaseFirst();
      releaseRetryGate();
      const releaseSecond = yield* Effect.promise(() => second);
      assert.isTrue(secondAcquired);
      releaseSecond();
      assert.isFalse(yield* fs.exists(lock));
    }),
  );

  it.effect("rejects immediately when given an already-aborted signal", () =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const root = yield* fs.makeTempDirectoryScoped({ prefix: "t3-service-selection-lock-" });
      const selectionPath = path.join(root, "service-state.json");
      const lock = `${selectionPath}.selection-lock`;

      const errorMessage = yield* Effect.tryPromise({
        try: () => acquireServiceSelectionLock(selectionPath, { signal: AbortSignal.abort() }),
        catch: (cause) => String(cause),
      }).pipe(Effect.flip);
      assert.match(errorMessage, /Lock acquisition aborted/);
      assert.isFalse(yield* fs.exists(lock));
    }),
  );

  it.effect("aborts while waiting on a contended lease without disturbing the holder", () =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const root = yield* fs.makeTempDirectoryScoped({ prefix: "t3-service-selection-lock-" });
      const selectionPath = path.join(root, "service-state.json");
      const lock = `${selectionPath}.selection-lock`;

      const releaseFirst = yield* Effect.promise(() => acquireServiceSelectionLock(selectionPath));
      // @effect-diagnostics-next-line abortControllerInEffect:off -- Testing standalone AbortSignal cancellation.
      const controller = new AbortController();
      // Acquire runs synchronously until awaiting the default retry timer + abort listener.
      const pendingSecond = acquireServiceSelectionLock(selectionPath, {
        signal: controller.signal,
      });

      controller.abort();
      const errorMessage = yield* Effect.tryPromise({
        try: () => pendingSecond,
        catch: (cause) => String(cause),
      }).pipe(Effect.flip);
      assert.match(errorMessage, /Lock acquisition aborted/);
      assert.isTrue(yield* fs.exists(lock));

      releaseFirst();
      assert.isFalse(yield* fs.exists(lock));
    }),
  );
});
