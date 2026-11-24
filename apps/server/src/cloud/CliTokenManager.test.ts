import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import * as NodeServices from "@effect/platform-node/NodeServices";
import { assert, it } from "@effect/vitest";
import * as Clock from "effect/Clock";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Deferred from "effect/Deferred";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Fiber from "effect/Fiber";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Queue from "effect/Queue";
import * as Schema from "effect/Schema";
import * as Terminal from "effect/Terminal";
import * as TestClock from "effect/testing/TestClock";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import type * as HttpBody from "effect/http/HttpBody";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";

import * as ServerSecretStore from "../auth/ServerSecretStore.ts";
import * as ServerConfig from "../config.ts";
import * as ExternalLauncher from "../process/externalLauncher.ts";
import * as CliTokenManager from "./CliTokenManager.ts";

const TEST_ENV = {
  T3CODE_RELAY_URL: "https://relay.example.test",
};

interface RecordedTokenRequest {
  readonly url: string;
  readonly params: URLSearchParams;
}

const TestIdTokenHeaderJson = Schema.fromJsonString(Schema.Struct({ alg: Schema.Literal("none") }));
const TestIdTokenPayloadJson = Schema.fromJsonString(Schema.Struct({ email: Schema.String }));
const encodeTestIdTokenHeader = Schema.encodeSync(TestIdTokenHeaderJson);
const encodeTestIdTokenPayload = Schema.encodeSync(TestIdTokenPayloadJson);
const idTokenWithEmail = (() => {
  const header = Base64Url.encode(encodeTestIdTokenHeader({ alg: "none" }));
  const payload = Base64Url.encode(encodeTestIdTokenPayload({ email: "theo@example.test" }));
  return `${header}.${payload}.`;
})();

const TestTokenResponseJson = Schema.fromJsonString(
  Schema.Struct({
    access_token: Schema.String,
    refresh_token: Schema.String,
    id_token: Schema.String,
    expires_in: Schema.Number,
    token_type: Schema.String,
  }),
);
const encodeTestTokenResponse = Schema.encodeSync(TestTokenResponseJson);

const provideTestEnv = Effect.provide(
  ConfigProvider.layer(ConfigProvider.fromEnv({ env: TEST_ENV })),
);

interface DeviceFlowServer {
  readonly requests: Array<RecordedTokenRequest>;
  readonly tokenReplies: Array<{ readonly status: number; readonly body: string } | "stall">;
}

const DEVICE_AUTHORIZATION_BODY = JSON.stringify({
  device_code: "device-code-1",
  user_code: "BCDF-GHJK",
  verification_uri: "https://accounts.example.test/device",
  verification_uri_complete: "https://accounts.example.test/device?user_code=BCDF-GHJK",
  expires_in: 600,
  interval: 5,
});

const oauthError = (error: string) => ({ status: 400, body: JSON.stringify({ error }) });
const tokenGranted = {
  status: 200,
  body: encodeTestTokenResponse({
    access_token: "access-token-1",
    refresh_token: "refresh-token-1",
    id_token: idTokenWithEmail,
    expires_in: 3600,
    token_type: "bearer",
  }),
};

const layerDeviceFlow = (server: DeviceFlowServer) =>
  Layer.succeed(
    HttpClient.HttpClient,
    HttpClient.make((request) =>
      Effect.suspend(() => {
        const body =
          request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "";
        server.requests.push({ url: request.url, params: new URLSearchParams(body) });
        const reply = request.url.endsWith("/v1/auth/device")
          ? { status: 200, body: DEVICE_AUTHORIZATION_BODY }
          : ((server.tokenReplies.length > 1
              ? server.tokenReplies.shift()
              : server.tokenReplies[0]) ?? oauthError("invalid_grant"));
        if (reply === "stall") return Effect.never;
        return Effect.succeed(
          HttpClientResponse.fromWeb(
            request,
            new Response(reply.body, {
              status: reply.status,
              headers: { "content-type": "application/json" },
            }),
          ),
        );
      }),
    ),
  );

const tokenRequests = (requests: ReadonlyArray<RecordedTokenRequest>) =>
  requests.filter((request) => request.url.endsWith("/v1/auth/token"));

const expiredStoredToken = new TextEncoder().encode(
  JSON.stringify({ accessToken: "expired", refreshToken: "refresh-token-1", expiresAtEpochMs: 0 }),
);

const provideRefreshManager = (
  httpClient: HttpClient.HttpClient,
  secrets = Layer.mock(ServerSecretStore.ServerSecretStore)({
    get: () => Effect.succeedSome(expiredStoredToken),
  }),
) =>
  Effect.provide(
    CliTokenManager.layer.pipe(
      Layer.provide(
        Layer.mergeAll(
          Layer.succeed(HttpClient.HttpClient, httpClient),
          secrets,
          Layer.mock(ExternalLauncher.ExternalLauncher)({}),
          NodeServices.layer,
          NodeCrypto.layer,
        ),
      ),
      Layer.provideMerge(ConfigProvider.layer(ConfigProvider.fromEnv({ env: TEST_ENV }))),
    ),
  );

it.effect(
  "persists rotated credentials under the lock despite shutdown, while queued callers can cancel",
  () =>
    Effect.gen(function* () {
      const requestStarted = yield* Deferred.make<void>();
      const releaseRequest = yield* Deferred.make<void>();
      const persistStarted = yield* Deferred.make<void>();
      const releasePersist = yield* Deferred.make<void>();
      let stored = expiredStoredToken;
      let reads = 0;
      const httpClient = HttpClient.make((request) =>
        Effect.gen(function* () {
          yield* Deferred.succeed(requestStarted, undefined);
          yield* Deferred.await(releaseRequest);
          return HttpClientResponse.fromWeb(
            request,
            Response.json({
              access_token: "rotated-access",
              refresh_token: "rotated-refresh",
              expires_in: 3600,
              token_type: "bearer",
            }),
          );
        }),
      );
      const secrets = Layer.mock(ServerSecretStore.ServerSecretStore)({
        get: () =>
          Effect.sync(() => {
            reads++;
            return Option.some(stored);
          }),
        set: (_name, value) =>
          Effect.gen(function* () {
            yield* Deferred.succeed(persistStarted, undefined);
            yield* Deferred.await(releasePersist);
            stored = new Uint8Array(value);
          }),
      });

      yield* Effect.gen(function* () {
        const manager = yield* CliTokenManager.CloudCliTokenManager;
        const refresh = yield* manager.getExisting.pipe(Effect.forkChild);
        assert.isTrue(
          yield* Effect.raceFirst(
            Deferred.await(requestStarted).pipe(Effect.as(true)),
            Fiber.await(refresh).pipe(Effect.as(false)),
          ),
          "refresh failed before reaching the endpoint",
        );
        const waiter = yield* manager.getExisting.pipe(
          Effect.forkChild({ startImmediately: true }),
        );
        yield* Fiber.interrupt(waiter);
        assert.equal(reads, 1, "queued caller must not read credentials during refresh");
        const interruption = yield* Fiber.interrupt(refresh).pipe(
          Effect.forkChild({ startImmediately: true }),
        );
        yield* Deferred.succeed(releaseRequest, undefined);
        const reachedPersist = yield* Effect.raceFirst(
          Deferred.await(persistStarted).pipe(Effect.as(true)),
          Fiber.await(refresh).pipe(Effect.as(false)),
        );
        assert.isTrue(reachedPersist, "shutdown discarded the rotated credential");
        const reader = yield* manager.getExisting.pipe(
          Effect.forkChild({ startImmediately: true }),
        );
        assert.equal(reads, 1, "credential lock must cover persistence");
        yield* Deferred.succeed(releasePersist, undefined);
        yield* Fiber.join(interruption);
        const token = Option.getOrThrow(yield* Fiber.join(reader));
        assert.equal(token.refreshToken, "rotated-refresh");
        assert.equal(token.accessToken, "rotated-access");
      }).pipe(
        Effect.ensuring(Deferred.succeed(releaseRequest, undefined)),
        Effect.ensuring(Deferred.succeed(releasePersist, undefined)),
        provideRefreshManager(httpClient, secrets),
      );
    }),
);

it.effect.each([
  { status: 400, code: "invalid_grant", requiresLogin: true, diagnostic: true },
  { status: 403, code: "private-provider-secret", requiresLogin: true, diagnostic: false },
  { status: 429, code: "invalid_grant", requiresLogin: false, diagnostic: false },
])(
  "refresh HTTP $status exposes only a safe login diagnostic",
  ({ status, code, requiresLogin, diagnostic }) =>
    Effect.gen(function* () {
      const manager = yield* CliTokenManager.CloudCliTokenManager;
      const error = yield* manager.getExisting.pipe(Effect.flip);
      assert.instanceOf(error, CliTokenManager.CloudCliCredentialRefreshError);
      assert.equal(error.requiresLogin, requiresLogin);
      assert.equal(error.message.includes("t3 connect login"), requiresLogin);
      assert.equal(error.message.includes("OAuth error: invalid_grant"), diagnostic);
      assert.notInclude(error.message, "private");
      assert.equal(error.message.includes("OAuth error:"), diagnostic);
      assert.isTrue(yield* manager.hasCredential);
    }).pipe(
      provideRefreshManager(
        HttpClient.make((request) =>
          Effect.succeed(
            HttpClientResponse.fromWeb(
              request,
              Response.json(
                {
                  error: code,
                  error_description: "private-description",
                  refresh_token: "private-refresh-token",
                },
                { status },
              ),
            ),
          ),
        ),
      ),
    ),
);

it.layer(Layer.mergeAll(NodeServices.layer, NodeCrypto.layer))(
  "CliTokenManager.deviceAuthorizationLogin",
  (it) => {
    it.effect("requests a device code, shows it, and polls until Clerk grants the token", () =>
      Effect.gen(function* () {
        const server: DeviceFlowServer = {
          requests: [],
          tokenReplies: [oauthError("authorization_pending"), tokenGranted],
        };
        const prompts: Array<CliTokenManager.DeviceAuthorizationPrompt> = [];

        const fiber = yield* CliTokenManager.deviceAuthorizationLogin((prompt) =>
          Effect.sync(() => {
            prompts.push(prompt);
          }),
        ).pipe(Effect.provide(layerDeviceFlow(server)), provideTestEnv, Effect.forkChild);

        yield* TestClock.adjust(Duration.seconds(10));
        const { token, identity } = yield* Fiber.join(fiber);

        assert.deepEqual(prompts, [
          {
            verificationUri: "https://accounts.example.test/device",
            verificationUriComplete: "https://accounts.example.test/device?user_code=BCDF-GHJK",
            userCode: "BCDF-GHJK",
            expiresIn: Duration.seconds(600),
          },
        ]);
        assert.equal(token.accessToken, "access-token-1");
        assert.equal(token.refreshToken, "refresh-token-1");
        assert.equal(token.identity, "theo@example.test");
        assert.equal(identity, "theo@example.test");

        const authorization = server.requests[0]!;
        assert.equal(authorization.url, "https://relay.example.test/v1/auth/device");
        assert.equal(authorization.params.get("client_id"), "t3-cli");
        assert.equal(authorization.params.get("scope"), "openid profile email offline_access");

        const polls = tokenRequests(server.requests);
        assert.lengthOf(polls, 2);
        for (const poll of polls) {
          assert.equal(poll.url, "https://relay.example.test/v1/auth/token");
          assert.equal(
            poll.params.get("grant_type"),
            "urn:ietf:params:oauth:grant-type:device_code",
          );
          assert.equal(poll.params.get("device_code"), "device-code-1");
          assert.equal(poll.params.get("client_id"), "t3-cli");
        }
      }),
    );

    it.effect("retries a poll that never answers instead of waiting out the device code", () =>
      Effect.gen(function* () {
        const server: DeviceFlowServer = { requests: [], tokenReplies: ["stall", tokenGranted] };

        const fiber = yield* CliTokenManager.deviceAuthorizationLogin(() => Effect.void).pipe(
          Effect.provide(layerDeviceFlow(server)),
          provideTestEnv,
          Effect.forkChild,
        );
        // 5 s interval, a 10 s request timeout, then the 10 s slowed-down interval.
        yield* TestClock.adjust(Duration.seconds(25));

        assert.lengthOf(tokenRequests(server.requests), 2);
        const { token } = yield* Fiber.join(fiber);
        assert.equal(token.accessToken, "access-token-1");
      }),
    );

    it.effect("fails with a denied error when the user rejects the request", () =>
      Effect.gen(function* () {
        const server: DeviceFlowServer = {
          requests: [],
          tokenReplies: [oauthError("access_denied")],
        };

        const fiber = yield* CliTokenManager.deviceAuthorizationLogin(() => Effect.void).pipe(
          Effect.provide(layerDeviceFlow(server)),
          provideTestEnv,
          Effect.flip,
          Effect.forkChild,
        );
        yield* TestClock.adjust(Duration.seconds(5));
        const result = yield* Fiber.join(fiber);

        assert.instanceOf(result, CliTokenManager.CloudCliAuthorizationDeniedError);
        assert.lengthOf(tokenRequests(server.requests), 1);
      }),
    );
  },
);

const readFormBody = (body: HttpBody.HttpBody) =>
  new URLSearchParams(body._tag === "Uint8Array" ? new TextDecoder().decode(body.body) : "");

it.live(
  "serializes concurrent refreshes across separate CliTokenManager instances via the secret-store lockfile",
  () =>
    Effect.scoped(
      Effect.gen(function* () {
        const fs = yield* FileSystem.FileSystem;
        const tempDir = yield* fs.makeTempDirectoryScoped({ prefix: "t3-cli-refresh-lock-" });
        const refreshStarted = yield* Deferred.make<void>();
        const releaseRefresh = yield* Deferred.make<void>();
        const requests: Array<RecordedTokenRequest> = [];

        const httpClient = HttpClient.make((request) =>
          Effect.gen(function* () {
            requests.push({
              url: request.url,
              params: readFormBody(request.body),
            });
            yield* Deferred.succeed(refreshStarted, undefined);
            yield* Deferred.await(releaseRefresh);
            return HttpClientResponse.fromWeb(
              request,
              new Response(
                JSON.stringify({
                  access_token: "access-rotated-cross-process",
                  refresh_token: "refresh-rotated-cross-process",
                  expires_in: 3600,
                  token_type: "bearer",
                  id_token: idTokenWithEmail,
                }),
                { status: 200, headers: { "content-type": "application/json" } },
              ),
            );
          }),
        );

        const sharedBaseLayer = Layer.mergeAll(
          NodeServices.layer,
          NodeCrypto.layer,
          ServerSecretStore.layer.pipe(
            Layer.provide(ServerConfig.layerTest(process.cwd(), tempDir)),
            Layer.provide(NodeServices.layer),
            Layer.provide(NodeCrypto.layer),
          ),
          Layer.succeed(HttpClient.HttpClient, httpClient),
          Layer.mock(ExternalLauncher.ExternalLauncher)({
            launchBrowser: () => Effect.void,
          }),
        );

        const secrets = yield* ServerSecretStore.ServerSecretStore.pipe(
          Effect.provide(sharedBaseLayer),
        );
        yield* secrets.set(
          "cloud-cli-oauth-token",
          new TextEncoder().encode(
            JSON.stringify({
              accessToken: "access-expired",
              refreshToken: "refresh-initial",
              expiresAtEpochMs: 1,
              identity: "theo@example.test",
            }),
          ),
        );

        const managerBReadExpired = yield* Deferred.make<void>();
        const managerBSecrets: typeof secrets = {
          ...secrets,
          get: (key) =>
            secrets
              .get(key)
              .pipe(Effect.tap(() => Deferred.succeed(managerBReadExpired, undefined))),
        };
        const managerBLayer = Layer.mergeAll(
          NodeServices.layer,
          NodeCrypto.layer,
          Layer.succeed(ServerSecretStore.ServerSecretStore, managerBSecrets),
          Layer.succeed(HttpClient.HttpClient, httpClient),
          Layer.mock(ExternalLauncher.ExternalLauncher)({
            launchBrowser: () => Effect.void,
          }),
        );

        const managerA = yield* CliTokenManager.CloudCliTokenManager.pipe(
          Effect.provide(CliTokenManager.layer.pipe(Layer.provide(sharedBaseLayer))),
        );
        const managerB = yield* CliTokenManager.CloudCliTokenManager.pipe(
          Effect.provide(CliTokenManager.layer.pipe(Layer.provide(managerBLayer))),
        );

        const fiberA = yield* Effect.forkChild(managerA.getExisting);
        const started = yield* Effect.raceFirst(
          Deferred.await(refreshStarted).pipe(Effect.as(true)),
          Fiber.await(fiberA).pipe(Effect.as(false)),
        );
        assert.isTrue(started, "managerA should reach the token refresh endpoint");
        const fiberB = yield* Effect.forkChild(managerB.getExisting);
        yield* Deferred.await(managerBReadExpired);
        yield* Deferred.succeed(releaseRefresh, undefined);

        const [tokenA, tokenB] = yield* Effect.all([Fiber.join(fiberA), Fiber.join(fiberB)]);

        assert.lengthOf(requests, 1);
        assert.equal(requests[0]!.url, "https://relay.example.test/v1/auth/token");
        assert.equal(requests[0]!.params.get("refresh_token"), "refresh-initial");
        assert.equal(Option.getOrUndefined(tokenA)?.accessToken, "access-rotated-cross-process");
        assert.equal(Option.getOrUndefined(tokenB)?.accessToken, "access-rotated-cross-process");
      }).pipe(Effect.provide(NodeServices.layer), provideTestEnv),
    ),
);

it.live(
  "fails fast with CloudCliAuthorizationDeniedError when loopback callback returns error=access_denied",
  () =>
    Effect.gen(function* () {
      const openedUrl = yield* Deferred.make<string>();
      const terminalQueue = yield* Queue.unbounded<Terminal.UserInput>();
      yield* Queue.offer(terminalQueue, {
        input: Option.none(),
        key: { name: "enter", ctrl: false, meta: false, shift: false },
      });
      const httpClient = HttpClient.make((request) =>
        Effect.succeed(
          HttpClientResponse.fromWeb(
            request,
            new Response(JSON.stringify({ error: "unexpected" }), { status: 500 }),
          ),
        ),
      );

      const layer = CliTokenManager.layer.pipe(
        Layer.provide(
          Layer.mergeAll(
            NodeServices.layer,
            NodeCrypto.layer,
            Layer.mock(ServerSecretStore.ServerSecretStore)({
              get: () => Effect.succeedNone,
              set: () => Effect.void,
              remove: () => Effect.void,
            }),
            Layer.mock(Terminal.Terminal)({
              "~effect/Terminal": "~effect/Terminal",
              readInput: Effect.succeed(terminalQueue),
            }),
            Layer.succeed(HttpClient.HttpClient, httpClient),
            Layer.mock(ExternalLauncher.ExternalLauncher)({
              launchBrowser: (url) => Deferred.succeed(openedUrl, url).pipe(Effect.asVoid),
            }),
          ),
        ),
      );

      const manager = yield* CliTokenManager.CloudCliTokenManager.pipe(Effect.provide(layer));
      const loopbackClient = yield* HttpClient.HttpClient.pipe(
        Effect.provide(FetchHttpClient.layer),
      );

      const loginFiber = yield* Effect.forkChild(Effect.flip(manager.get));
      const authorizeUrl = new URL(yield* Deferred.await(openedUrl));

      assert.equal(authorizeUrl.origin, "https://relay.example.test");
      assert.equal(authorizeUrl.pathname, "/v1/auth/authorize");
      assert.equal(authorizeUrl.searchParams.get("client_id"), "t3-cli");
      assert.equal(authorizeUrl.searchParams.get("code_challenge_method"), "S256");
      const redirectUri = authorizeUrl.searchParams.get("redirect_uri")!;
      const state = authorizeUrl.searchParams.get("state")!;
      assert.isNotEmpty(state);

      // Wrong state is rejected with 400 and does not abort the pending login.
      const badStateResponse = yield* loopbackClient.get(
        `${redirectUri}?state=wrong-state&error=access_denied`,
      );
      assert.equal(badStateResponse.status, 400);

      const deniedResponse = yield* loopbackClient.get(
        `${redirectUri}?state=${encodeURIComponent(state)}&error=access_denied&error_description=Not+in+org`,
      );
      assert.equal(deniedResponse.status, 400);

      const error = yield* Fiber.join(loginFiber);
      assert.instanceOf(error, CliTokenManager.CloudCliAuthorizationDeniedError);
    }).pipe(provideTestEnv),
);

it.effect(
  "revokes the refresh token on clear and still deletes local credentials if revoke fails",
  () =>
    Effect.gen(function* () {
      const now = yield* Clock.currentTimeMillis;
      let stored: Option.Option<Uint8Array> = Option.some(
        new TextEncoder().encode(
          JSON.stringify({
            accessToken: "access-live",
            refreshToken: "refresh-live",
            expiresAtEpochMs: now + 3600_000,
          }),
        ),
      );
      const revokeRequests: Array<RecordedTokenRequest> = [];
      let revokeStatus = 200;

      const httpClient = HttpClient.make((request) =>
        Effect.sync(() => {
          revokeRequests.push({
            url: request.url,
            params: readFormBody(request.body),
          });
          return HttpClientResponse.fromWeb(request, new Response(null, { status: revokeStatus }));
        }),
      );

      const manager = yield* CliTokenManager.CloudCliTokenManager.pipe(
        Effect.provide(
          CliTokenManager.layer.pipe(
            Layer.provide(
              Layer.mergeAll(
                NodeServices.layer,
                NodeCrypto.layer,
                Layer.mock(ServerSecretStore.ServerSecretStore)({
                  get: () => Effect.sync(() => stored),
                  set: (_name, value) =>
                    Effect.sync(() => {
                      stored = Option.some(new Uint8Array(value));
                    }),
                  remove: () =>
                    Effect.sync(() => {
                      stored = Option.none();
                    }),
                }),
                Layer.succeed(HttpClient.HttpClient, httpClient),
                Layer.mock(ExternalLauncher.ExternalLauncher)({
                  launchBrowser: () => Effect.void,
                }),
              ),
            ),
          ),
        ),
      );

      yield* manager.clear;
      assert.isTrue(Option.isNone(stored));
      assert.lengthOf(revokeRequests, 1);
      assert.equal(revokeRequests[0]!.url, "https://relay.example.test/v1/auth/revoke");
      assert.equal(revokeRequests[0]!.params.get("token"), "refresh-live");
      assert.equal(revokeRequests[0]!.params.get("token_type_hint"), "refresh_token");
      assert.equal(revokeRequests[0]!.params.get("client_id"), "t3-cli");

      // Local credentials are still removed when the relay is unreachable / returns 500.
      stored = Option.some(
        new TextEncoder().encode(
          JSON.stringify({
            accessToken: "access-live-2",
            refreshToken: "refresh-live-2",
            expiresAtEpochMs: now + 3600_000,
          }),
        ),
      );
      revokeStatus = 500;
      yield* manager.clear;
      assert.isTrue(Option.isNone(stored));
      assert.lengthOf(revokeRequests, 2);
    }).pipe(provideTestEnv),
);
