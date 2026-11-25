// @effect-diagnostics nodeBuiltinImport:off globalFetchInEffect:off globalDateInEffect:off - Tests exercise the real loopback OAuth callback listener against a mocked relay fetch.
import * as NodeServices from "@effect/platform-node/NodeServices";
import * as HostProcess from "@t3tools/shared/HostProcess";
import type { DesktopCloudAuthState } from "@t3tools/contracts";
import { assert, describe, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import { vi } from "vite-plus/test";

import * as ElectronSafeStorage from "../electron/ElectronSafeStorage.ts";
import * as ElectronShell from "../electron/ElectronShell.ts";
import * as ElectronWindow from "../electron/ElectronWindow.ts";
import * as IpcChannels from "../ipc/channels.ts";
import * as DesktopCloudAuth from "./DesktopCloudAuth.ts";
import * as DesktopEnvironment from "./DesktopEnvironment.ts";

function makeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.sig`;
}

function makeFakeSafeStorage(available = true, backend: Option.Option<string> = Option.none()) {
  const isEncryptionAvailableCalls = { count: 0 };
  const service = ElectronSafeStorage.ElectronSafeStorage.of({
    isEncryptionAvailable: Effect.sync(() => {
      isEncryptionAvailableCalls.count += 1;
      return available;
    }),
    selectedStorageBackend: Effect.succeed(backend),
    encryptString: (plaintext) =>
      Effect.succeed(new Uint8Array(Buffer.from(`enc:${plaintext}`, "utf8"))),
    decryptString: (encrypted) => {
      const text = Buffer.from(encrypted).toString("utf8");
      if (!text.startsWith("enc:")) {
        return Effect.fail(
          new ElectronSafeStorage.ElectronSafeStorageDecryptError({
            cause: new Error("invalid ciphertext"),
          }),
        );
      }
      return Effect.succeed(text.slice(4));
    },
  });
  return { service, isEncryptionAvailableCalls };
}

describe("DesktopCloudAuth", () => {
  it.effect(
    "starts in loading without touching safeStorage, completes loopback PKCE sign-in, persists encrypted tokens, hydrates on restart, and revokes on sign-out",
    () =>
      Effect.gen(function* () {
        const fileSystem = yield* FileSystem.FileSystem;
        const path = yield* Path.Path;
        const stateDir = yield* fileSystem.makeTempDirectoryScoped();
        const { service: safeStorage, isEncryptionAvailableCalls } = makeFakeSafeStorage(true);

        const broadcasts: DesktopCloudAuthState[] = [];
        const revealMock = vi.fn();
        const mainWindow = { id: 1 };
        const electronWindow = {
          sendAll: (channel: string, payload: unknown) =>
            Effect.sync(() => {
              if (channel === IpcChannels.CLOUD_AUTH_STATE_CHANNEL) {
                broadcasts.push(payload as DesktopCloudAuthState);
              }
            }),
          currentMainOrFirst: Effect.succeedSome(mainWindow),
          reveal: (win: unknown) =>
            Effect.sync(() => {
              revealMock(win);
            }),
        } as unknown as ElectronWindow.ElectronWindow["Service"];

        const accessToken = makeJwt({
          sub: "gh_42",
          preferred_username: "robert-crandall",
          email: "robert@example.com",
          exp: 4_102_444_800,
        });
        const refreshToken = "rt_desktop_secret_token";

        const relayRequests: Array<{ url: string; body: Record<string, string> }> = [];
        const mockFetch: typeof fetch = async (input, init) => {
          const url = String(input);
          const rawBody = String(init?.body ?? "");
          const contentType =
            init?.headers instanceof Headers
              ? init.headers.get("content-type")
              : ((init?.headers as Record<string, string> | undefined)?.["content-type"] ??
                (init?.headers as Record<string, string> | undefined)?.["Content-Type"]);
          const body: Record<string, string> = contentType?.includes("application/json")
            ? (JSON.parse(rawBody || "{}") as Record<string, string>)
            : Object.fromEntries(new URLSearchParams(rawBody).entries());
          relayRequests.push({ url, body });
          if (url.endsWith("/v1/auth/token")) {
            assert.strictEqual(body.grant_type, "authorization_code");
            assert.strictEqual(body.client_id, "t3-desktop");
            assert.strictEqual(body.code, "gh-oauth-code-123");
            assert.isAbove((body.code_verifier ?? "").length, 20);
            return new Response(
              JSON.stringify({
                access_token: accessToken,
                refresh_token: refreshToken,
                token_type: "Bearer",
                expires_in: 900,
              }),
              { status: 200, headers: { "content-type": "application/json" } },
            );
          }
          if (url.endsWith("/v1/auth/revoke")) {
            return new Response(null, { status: 204 });
          }
          return new Response("not found", { status: 404 });
        };

        const openedUrls: string[] = [];
        const shell = ElectronShell.ElectronShell.of({
          openExternal: (value) =>
            Effect.promise(async () => {
              const authorizeUrl = new URL(String(value));
              openedUrls.push(authorizeUrl.toString());
              const redirectUri = authorizeUrl.searchParams.get("redirect_uri")!;
              const state = authorizeUrl.searchParams.get("state")!;

              // Mismatched state is rejected with 400 and does not complete the flow.
              const badStateUrl = new URL(redirectUri);
              badStateUrl.searchParams.set("state", "wrong-state");
              badStateUrl.searchParams.set("code", "bad-code");
              const badResponse = await fetch(badStateUrl);
              assert.strictEqual(badResponse.status, 400);

              // Valid callback completes sign-in.
              const goodUrl = new URL(redirectUri);
              goodUrl.searchParams.set("state", state);
              goodUrl.searchParams.set("code", "gh-oauth-code-123");
              const goodResponse = await fetch(goodUrl);
              assert.strictEqual(goodResponse.status, 200);
              assert.strictEqual(goodResponse.headers.get("cache-control"), "no-store");
              return true;
            }),
          openSystemSettings: () => Effect.succeed(false),
          copyText: () => Effect.void,
        });

        const baseLayer = Layer.mergeAll(
          NodeServices.layer,
          Layer.succeed(DesktopEnvironment.DesktopEnvironment, {
            stateDir,
          } as DesktopEnvironment.DesktopEnvironment["Service"]),
          Layer.succeed(HostProcess.Environment, {
            T3CODE_RELAY_URL: "https://relay.crandalls.cloud",
          }),
          Layer.succeed(ElectronSafeStorage.ElectronSafeStorage, safeStorage),
          Layer.succeed(ElectronShell.ElectronShell, shell),
          Layer.succeed(ElectronWindow.ElectronWindow, electronWindow),
        );

        const cloudAuthLayer = Layer.effect(
          DesktopCloudAuth.DesktopCloudAuth,
          DesktopCloudAuth.make({ fetch: mockFetch }),
        ).pipe(Layer.provide(baseLayer));

        // First instance: pre-start state is loading and safeStorage has not been queried.
        yield* Effect.gen(function* () {
          const auth = yield* DesktopCloudAuth.DesktopCloudAuth;
          const preStartState = yield* auth.getState;
          assert.deepStrictEqual(preStartState, { status: "loading", identity: null });
          assert.strictEqual(isEncryptionAvailableCalls.count, 0);

          yield* auth.start;
          assert.deepStrictEqual(yield* auth.getState, { status: "signedOut", identity: null });

          const signedIn = yield* auth.signIn;
          assert.deepStrictEqual(signedIn, {
            status: "signedIn",
            identity: {
              userId: "gh_42",
              login: "robert-crandall",
              email: "robert@example.com",
            },
          });
          assert.strictEqual(openedUrls.length, 1);
          const parsedOpen = new URL(openedUrls[0]!);
          assert.strictEqual(parsedOpen.origin, "https://relay.crandalls.cloud");
          assert.strictEqual(parsedOpen.pathname, "/v1/auth/authorize");
          assert.strictEqual(parsedOpen.searchParams.get("client_id"), "t3-desktop");
          assert.strictEqual(parsedOpen.searchParams.get("code_challenge_method"), "S256");
          const parsedRedirect = new URL(parsedOpen.searchParams.get("redirect_uri")!);
          assert.strictEqual(parsedRedirect.hostname, "127.0.0.1");
          assert.strictEqual(parsedRedirect.pathname, "/callback");

          assert.strictEqual(yield* auth.getAccessToken(), accessToken);
          assert.strictEqual(revealMock.mock.calls.length, 1);

          // Disk file exists and never stores plaintext refresh/access tokens.
          const sessionPath = path.join(stateDir, "cloud-auth", "session.json");
          const diskRaw = yield* fileSystem.readFileString(sessionPath);
          assert.notInclude(diskRaw, refreshToken);
          assert.notInclude(diskRaw, accessToken);
        }).pipe(Effect.scoped, Effect.provide(cloudAuthLayer));

        // Second instance (cold restart): hydrates persisted encrypted session without re-auth.
        yield* Effect.gen(function* () {
          const auth = yield* DesktopCloudAuth.DesktopCloudAuth;
          yield* auth.start;
          assert.deepStrictEqual(yield* auth.getState, {
            status: "signedIn",
            identity: {
              userId: "gh_42",
              login: "robert-crandall",
              email: "robert@example.com",
            },
          });
          assert.strictEqual(yield* auth.getAccessToken(), accessToken);

          const afterSignOut = yield* auth.signOut;
          assert.deepStrictEqual(afterSignOut, { status: "signedOut", identity: null });
          assert.isNull(yield* auth.getAccessToken());
          assert.isFalse(
            yield* fileSystem.exists(path.join(stateDir, "cloud-auth", "session.json")),
          );
        }).pipe(Effect.scoped, Effect.provide(cloudAuthLayer));

        assert.isTrue(
          relayRequests.some(
            (req) =>
              req.url === "https://relay.crandalls.cloud/v1/auth/revoke" &&
              req.body.token === refreshToken &&
              req.body.client_id === "t3-desktop",
          ),
        );
        assert.isTrue(broadcasts.some((b) => b.status === "signedIn"));
        assert.strictEqual(broadcasts.at(-1)?.status, "signedOut");
      }).pipe(Effect.provide(NodeServices.layer)),
  );

  it.effect("refuses to sign in when OS keychain encryption is unavailable", () =>
    Effect.gen(function* () {
      const fileSystem = yield* FileSystem.FileSystem;
      const stateDir = yield* fileSystem.makeTempDirectoryScoped();
      const { service: safeStorage } = makeFakeSafeStorage(false);
      const electronWindow = {
        sendAll: () => Effect.void,
        currentMainOrFirst: Effect.succeedNone,
        reveal: () => Effect.void,
      } as unknown as ElectronWindow.ElectronWindow["Service"];
      const shell = ElectronShell.ElectronShell.of({
        openExternal: () => Effect.succeed(true),
        openSystemSettings: () => Effect.succeed(false),
        copyText: () => Effect.void,
      });

      const layer = Layer.effect(
        DesktopCloudAuth.DesktopCloudAuth,
        DesktopCloudAuth.make({ relayUrl: "https://relay.crandalls.cloud" }),
      ).pipe(
        Layer.provide(
          Layer.mergeAll(
            NodeServices.layer,
            Layer.succeed(DesktopEnvironment.DesktopEnvironment, {
              stateDir,
            } as DesktopEnvironment.DesktopEnvironment["Service"]),
            Layer.succeed(HostProcess.Environment, {}),
            Layer.succeed(ElectronSafeStorage.ElectronSafeStorage, safeStorage),
            Layer.succeed(ElectronShell.ElectronShell, shell),
            Layer.succeed(ElectronWindow.ElectronWindow, electronWindow),
          ),
        ),
      );

      yield* Effect.gen(function* () {
        const auth = yield* DesktopCloudAuth.DesktopCloudAuth;
        yield* auth.start;
        const exit = yield* Effect.exit(auth.signIn);
        assert.isTrue(Exit.isFailure(exit));
      }).pipe(Effect.scoped, Effect.provide(layer));
    }).pipe(Effect.provide(NodeServices.layer)),
  );

  it.effect("refuses to sign in when Linux safeStorage falls back to basic_text", () =>
    Effect.gen(function* () {
      const fileSystem = yield* FileSystem.FileSystem;
      const stateDir = yield* fileSystem.makeTempDirectoryScoped();
      const { service: safeStorage } = makeFakeSafeStorage(true, Option.some("basic_text"));
      const electronWindow = {
        sendAll: () => Effect.void,
        currentMainOrFirst: Effect.succeedNone,
        reveal: () => Effect.void,
      } as unknown as ElectronWindow.ElectronWindow["Service"];
      const shell = ElectronShell.ElectronShell.of({
        openExternal: () => Effect.succeed(true),
        openSystemSettings: () => Effect.succeed(false),
        copyText: () => Effect.void,
      });

      const layer = Layer.effect(
        DesktopCloudAuth.DesktopCloudAuth,
        DesktopCloudAuth.make({ relayUrl: "https://relay.crandalls.cloud" }),
      ).pipe(
        Layer.provide(
          Layer.mergeAll(
            NodeServices.layer,
            Layer.succeed(DesktopEnvironment.DesktopEnvironment, {
              stateDir,
            } as DesktopEnvironment.DesktopEnvironment["Service"]),
            Layer.succeed(HostProcess.Environment, {}),
            Layer.succeed(ElectronSafeStorage.ElectronSafeStorage, safeStorage),
            Layer.succeed(ElectronShell.ElectronShell, shell),
            Layer.succeed(ElectronWindow.ElectronWindow, electronWindow),
          ),
        ),
      );

      yield* Effect.gen(function* () {
        const auth = yield* DesktopCloudAuth.DesktopCloudAuth;
        yield* auth.start;
        const exit = yield* Effect.exit(auth.signIn);
        assert.isTrue(Exit.isFailure(exit));
      }).pipe(Effect.scoped, Effect.provide(layer));
    }).pipe(Effect.provide(NodeServices.layer)),
  );

  it.effect("stays signedOut when no relay URL is configured", () =>
    Effect.gen(function* () {
      const fileSystem = yield* FileSystem.FileSystem;
      const stateDir = yield* fileSystem.makeTempDirectoryScoped();
      const { service: safeStorage } = makeFakeSafeStorage(true);
      const electronWindow = {
        sendAll: () => Effect.void,
        currentMainOrFirst: Effect.succeedNone,
        reveal: () => Effect.void,
      } as unknown as ElectronWindow.ElectronWindow["Service"];
      const shell = ElectronShell.ElectronShell.of({
        openExternal: () => Effect.succeed(true),
        openSystemSettings: () => Effect.succeed(false),
        copyText: () => Effect.void,
      });

      const layer = Layer.effect(
        DesktopCloudAuth.DesktopCloudAuth,
        DesktopCloudAuth.make({ relayUrl: null }),
      ).pipe(
        Layer.provide(
          Layer.mergeAll(
            NodeServices.layer,
            Layer.succeed(DesktopEnvironment.DesktopEnvironment, {
              stateDir,
            } as DesktopEnvironment.DesktopEnvironment["Service"]),
            Layer.succeed(HostProcess.Environment, {}),
            Layer.succeed(ElectronSafeStorage.ElectronSafeStorage, safeStorage),
            Layer.succeed(ElectronShell.ElectronShell, shell),
            Layer.succeed(ElectronWindow.ElectronWindow, electronWindow),
          ),
        ),
      );

      yield* Effect.gen(function* () {
        const auth = yield* DesktopCloudAuth.DesktopCloudAuth;
        yield* auth.start;
        assert.deepStrictEqual(yield* auth.getState, { status: "signedOut", identity: null });
        assert.isNull(yield* auth.getAccessToken());
      }).pipe(Effect.scoped, Effect.provide(layer));
    }).pipe(Effect.provide(NodeServices.layer)),
  );
});
