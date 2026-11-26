// @effect-diagnostics-next-line nodeBuiltinImport:off -- Effect's Crypto has no createHash sync helper.
import * as NodeCrypto from "node:crypto";

import * as NodeServices from "@effect/platform-node/NodeServices";
import { describe, expect, it } from "@effect/vitest";
import { eq } from "drizzle-orm";
import * as Cause from "effect/Cause";
import * as DateTime from "effect/DateTime";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as HttpRouter from "effect/http/HttpRouter";
import * as HttpServer from "effect/http/HttpServer";
import * as HttpServerRequest from "effect/http/HttpServerRequest";
import * as HttpServerResponse from "effect/http/HttpServerResponse";
import * as Layer from "effect/Layer";
import * as Queue from "effect/Queue";
import * as TestClock from "effect/testing/TestClock";

import { relayOauthSessions } from "../persistence/schema.ts";
import * as GitHubOAuth from "./GitHubOAuth.ts";
import * as OAuthSessions from "./OAuthSessions.ts";
import * as RelayTokens from "./RelayTokens.ts";
import { setupPgliteOAuthTest } from "./testSupport.ts";

function pkceChallenge(verifier: string): string {
  return NodeCrypto.createHash("sha256").update(verifier).digest("base64url");
}

function makeTestApp(options: {
  allowedOrgs?: ReadonlyArray<string>;
  failUpdate?: () => boolean;
  onGitHubRequest: (
    url: string,
    method: string,
    body: string,
    headers: Readonly<Record<string, string>>,
  ) => Response | Promise<Response>;
}) {
  return Effect.gen(function* () {
    const { layerAuth } = yield* setupPgliteOAuthTest({
      ...(options.allowedOrgs ? { allowedOrgs: options.allowedOrgs } : {}),
      ...(options.failUpdate ? { failUpdate: options.failUpdate } : {}),
    });

    const mockHttpClient = HttpClient.make((request) =>
      Effect.promise(async () => {
        const bodyText =
          request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "";
        const response = await options.onGitHubRequest(
          request.url,
          request.method,
          bodyText,
          request.headers,
        );
        return HttpClientResponse.fromWeb(request, response);
      }),
    );

    const app = yield* Effect.acquireRelease(
      Effect.sync(() =>
        HttpRouter.toWebHandler(
          GitHubOAuth.layerRoutes.pipe(
            Layer.provideMerge(layerAuth),
            Layer.provideMerge(Layer.succeed(HttpClient.HttpClient, mockHttpClient)),
            Layer.provide(HttpServer.layerServices),
          ),
          { disableLogger: true },
        ),
      ),
      (webApp) => Effect.promise(() => webApp.dispose()),
    );

    return { app, layerAuth };
  });
}

function defaultGitHubMock(overrides?: {
  orgStatus?: number;
  orgState?: string;
  devicePollResponse?: Record<string, unknown>;
}) {
  return (url: string): Response => {
    if (url.endsWith("/login/oauth/access_token")) {
      if (overrides?.devicePollResponse) {
        return Response.json(overrides.devicePollResponse);
      }
      return Response.json({ access_token: "gho_test_token", token_type: "bearer" });
    }
    if (url.endsWith("/login/device/code")) {
      return Response.json({
        device_code: "gh_dev_code_1",
        user_code: "ABCD-1234",
        verification_uri: "https://github.com/login/device",
        expires_in: 900,
        interval: 5,
      });
    }
    if (url.endsWith("/user")) {
      return Response.json({ id: 42, login: "robert-crandall", email: "rob@crandalls.cloud" });
    }
    if (url.includes("/user/memberships/orgs/")) {
      const status = overrides?.orgStatus ?? 200;
      if (status !== 200) {
        return new Response("Not Found", { status });
      }
      return Response.json({ state: overrides?.orgState ?? "active" });
    }
    return new Response(`Unexpected GitHub URL: ${url}`, { status: 500 });
  };
}

describe("GitHubOAuth", () => {
  it.effect("rejects non-loopback redirect_uri on /v1/auth/authorize", () =>
    Effect.gen(function* () {
      const { app } = yield* makeTestApp({ onGitHubRequest: defaultGitHubMock() });
      const response = yield* Effect.promise(() =>
        app.handler(
          new Request(
            `https://relay.crandalls.cloud/v1/auth/authorize?client_id=t3-cli&response_type=code&redirect_uri=${encodeURIComponent("https://evil.example/cb")}&state=s1&code_challenge=${pkceChallenge("verifier-1234567890123456789012345678901234567890")}&code_challenge_method=S256`,
          ),
        ),
      );
      expect(response.status).toBe(400);
      expect(yield* Effect.promise(() => response.json())).toMatchObject({
        error: "invalid_request",
      });
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.live(
    "completes PKCE authorize -> callback -> token, rejects verifier mismatch & code replay, and rotates/revokes refresh tokens",
    () =>
      Effect.gen(function* () {
        const { app, layerAuth } = yield* makeTestApp({ onGitHubRequest: defaultGitHubMock() });

        const verifier = "pkce-verifier-value-that-is-at-least-43-characters-long";
        const redirectUri = "http://127.0.0.1:43210/callback";

        // 1. /v1/auth/authorize redirects to GitHub with state + CSRF cookie.
        const authorizeRes = yield* Effect.promise(() =>
          app.handler(
            new Request(
              `https://relay.crandalls.cloud/v1/auth/authorize?client_id=t3-cli&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=cli-state-1&code_challenge=${pkceChallenge(verifier)}&code_challenge_method=S256`,
            ),
          ),
        );
        expect(authorizeRes.status).toBe(302);
        const ghRedirect = new URL(authorizeRes.headers.get("location")!);
        expect(ghRedirect.origin).toBe("https://github.test");
        expect(ghRedirect.pathname).toBe("/login/oauth/authorize");
        const relayState = ghRedirect.searchParams.get("state")!;
        const setCookie = authorizeRes.headers.get("set-cookie")!;
        const csrfCookie = setCookie.split(";")[0]!;

        // 2. Callback with missing/wrong CSRF cookie fails 400 and does NOT redirect.
        const badCsrfRes = yield* Effect.promise(() =>
          app.handler(
            new Request(
              `https://relay.crandalls.cloud/v1/auth/github/callback?code=gh_code_1&state=${encodeURIComponent(relayState)}`,
              { headers: { cookie: "__Host-t3_oauth_nonce=wrong-nonce" } },
            ),
          ),
        );
        expect(badCsrfRes.status).toBe(400);
        expect(badCsrfRes.headers.get("location")).toBeNull();

        // 3. Callback with matching CSRF cookie redirects to loopback with one-time relay auth code.
        const callbackRes = yield* Effect.promise(() =>
          app.handler(
            new Request(
              `https://relay.crandalls.cloud/v1/auth/github/callback?code=gh_code_1&state=${encodeURIComponent(relayState)}`,
              { headers: { cookie: csrfCookie } },
            ),
          ),
        );
        expect(callbackRes.status).toBe(302);
        const cliRedirect = new URL(callbackRes.headers.get("location")!);
        expect(`${cliRedirect.origin}${cliRedirect.pathname}`).toBe(redirectUri);
        expect(cliRedirect.searchParams.get("state")).toBe("cli-state-1");
        const relayCode = cliRedirect.searchParams.get("code")!;

        // 4. Token exchange with wrong PKCE verifier is rejected.
        const badPkceRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "t3-cli",
                code: relayCode,
                redirect_uri: redirectUri,
                code_verifier: "wrong-verifier-value-that-is-at-least-43-characters-long",
              }),
            }),
          ),
        );
        expect(badPkceRes.status).toBe(400);
        expect(yield* Effect.promise(() => badPkceRes.json())).toMatchObject({
          error: "invalid_grant",
        });

        // 5. Valid token exchange succeeds and returns verifiable access_token + refresh_token.
        const tokenRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "t3-cli",
                code: relayCode,
                redirect_uri: redirectUri,
                code_verifier: verifier,
              }),
            }),
          ),
        );
        expect(tokenRes.status).toBe(200);
        const tokenBody = (yield* Effect.promise(() => tokenRes.json())) as {
          access_token: string;
          refresh_token: string;
          id_token: string;
        };

        const verified = yield* Effect.gen(function* () {
          const relayTokens = yield* RelayTokens.RelayTokens;
          return yield* relayTokens.verifyClientAccessToken({ token: tokenBody.access_token });
        }).pipe(Effect.provide(layerAuth));
        expect(verified).toMatchObject({ sub: "github:42", preferred_username: "robert-crandall" });

        // 6. Replaying the same authorization code is rejected.
        const codeReplayRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "t3-cli",
                code: relayCode,
                redirect_uri: redirectUri,
                code_verifier: verifier,
              }),
            }),
          ),
        );
        expect(codeReplayRes.status).toBe(400);
        expect(yield* Effect.promise(() => codeReplayRes.json())).toMatchObject({
          error: "invalid_grant",
        });

        // 7. Refresh token rotates and revokes on /v1/auth/revoke.
        const refreshRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-cli",
                refresh_token: tokenBody.refresh_token,
              }),
            }),
          ),
        );
        expect(refreshRes.status).toBe(200);
        const refreshedBody = (yield* Effect.promise(() => refreshRes.json())) as {
          refresh_token: string;
        };
        expect(refreshedBody.refresh_token).not.toBe(tokenBody.refresh_token);

        const revokeRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/revoke", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                client_id: "t3-cli",
                token: refreshedBody.refresh_token,
              }),
            }),
          ),
        );
        expect(revokeRes.status).toBe(200);

        const postRevokeRefresh = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-cli",
                refresh_token: refreshedBody.refresh_token,
              }),
            }),
          ),
        );
        expect(postRevokeRefresh.status).toBe(400);
        expect(yield* Effect.promise(() => postRevokeRefresh.json())).toMatchObject({
          error: "invalid_grant",
        });
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.live("fails closed when user is not an active member of an allowlisted org", () =>
    Effect.gen(function* () {
      const verifier = "pkce-verifier-value-that-is-at-least-43-characters-long";
      const redirectUri = "http://127.0.0.1:43211/callback";

      for (const scenario of [
        { allowedOrgs: ["robert-crandall-org"], orgStatus: 404, orgState: "active" },
        { allowedOrgs: ["robert-crandall-org"], orgStatus: 200, orgState: "pending" },
        { allowedOrgs: [], orgStatus: 200, orgState: "active" },
      ]) {
        const { app } = yield* makeTestApp({
          allowedOrgs: scenario.allowedOrgs,
          onGitHubRequest: defaultGitHubMock({
            orgStatus: scenario.orgStatus,
            orgState: scenario.orgState,
          }),
        });
        const authRes = yield* Effect.promise(() =>
          app.handler(
            new Request(
              `https://relay.crandalls.cloud/v1/auth/authorize?client_id=t3-cli&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=s1&code_challenge=${pkceChallenge(verifier)}&code_challenge_method=S256`,
            ),
          ),
        );
        const state = new URL(authRes.headers.get("location")!).searchParams.get("state")!;
        const csrfCookie = authRes.headers.get("set-cookie")!.split(";")[0]!;

        const cbRes = yield* Effect.promise(() =>
          app.handler(
            new Request(
              `https://relay.crandalls.cloud/v1/auth/github/callback?code=gh_code&state=${encodeURIComponent(state)}`,
              { headers: { cookie: csrfCookie } },
            ),
          ),
        );
        expect(cbRes.status).toBe(302);
        const dest = new URL(cbRes.headers.get("location")!);
        expect(dest.searchParams.get("error")).toBe("access_denied");
        expect(dest.searchParams.get("code")).toBeNull();
      }
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.live("handles device flow polling states, org denial, and success", () =>
    Effect.gen(function* () {
      let pollResponse: Record<string, unknown> = { error: "authorization_pending" };
      let orgStatus = 200;

      const { app } = yield* makeTestApp({
        onGitHubRequest: (url) =>
          defaultGitHubMock({ devicePollResponse: pollResponse, orgStatus })(url),
      });

      const deviceRes = yield* Effect.promise(() =>
        app.handler(
          new Request("https://relay.crandalls.cloud/v1/auth/device", {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ client_id: "t3-cli" }),
          }),
        ),
      );
      expect(deviceRes.status).toBe(200);
      const deviceBody = (yield* Effect.promise(() => deviceRes.json())) as {
        device_code: string;
        user_code: string;
      };
      expect(deviceBody.user_code).toBe("ABCD-1234");

      const poll = () =>
        Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                client_id: "t3-cli",
                device_code: deviceBody.device_code,
              }),
            }),
          ),
        );

      for (const expectedError of [
        "authorization_pending",
        "slow_down",
        "expired_token",
        "access_denied",
      ]) {
        pollResponse = { error: expectedError };
        const res = yield* poll();
        expect(res.status).toBe(400);
        expect(yield* Effect.promise(() => res.json())).toMatchObject({ error: expectedError });
      }

      // GitHub succeeds, but org check denies -> access_denied.
      pollResponse = { access_token: "gho_device_token" };
      orgStatus = 404;
      const deniedRes = yield* poll();
      expect(deniedRes.status).toBe(400);
      expect(yield* Effect.promise(() => deniedRes.json())).toMatchObject({
        error: "access_denied",
      });

      // Org check passes -> 200 with tokens.
      orgStatus = 200;
      const okRes = yield* poll();
      expect(okRes.status).toBe(200);
      expect(yield* Effect.promise(() => okRes.json())).toMatchObject({
        token_type: "Bearer",
      });
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.live(
    "re-checks GitHub org membership on refresh: returns 503 on upstream failure and revokes session on denial",
    () =>
      Effect.gen(function* () {
        let orgStatus = 200;
        let orgRawBody: string | undefined;
        let failUpdate = false;
        const { app } = yield* makeTestApp({
          failUpdate: () => failUpdate,
          onGitHubRequest: (url) => {
            if (url.includes("/user/memberships/orgs/") && orgRawBody !== undefined) {
              return new Response(orgRawBody, { status: orgStatus });
            }
            return defaultGitHubMock({ orgStatus })(url);
          },
        });

        // Start a session via Device Flow.
        const deviceRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/device", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({ client_id: "t3-cli" }),
            }),
          ),
        );
        const { device_code: deviceCode } = (yield* Effect.promise(() => deviceRes.json())) as {
          device_code: string;
        };
        const loginRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                client_id: "t3-cli",
                device_code: deviceCode,
              }),
            }),
          ),
        );
        expect(loginRes.status).toBe(200);
        const { refresh_token: initialRefresh } = (yield* Effect.promise(() =>
          loginRes.json(),
        )) as { refresh_token: string };

        // Transient GitHub 500, 403 rate-limit, and malformed 200 JSON all return 503
        // temporarily_unavailable without revoking the session.
        for (const scenario of [
          { status: 500, rawBody: undefined },
          { status: 403, rawBody: undefined },
          { status: 200, rawBody: "{not-json" },
        ]) {
          orgStatus = scenario.status;
          orgRawBody = scenario.rawBody;
          const transientRes = yield* Effect.promise(() =>
            app.handler(
              new Request("https://relay.crandalls.cloud/v1/auth/token", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                  grant_type: "refresh_token",
                  client_id: "t3-cli",
                  refresh_token: initialRefresh,
                }),
              }),
            ),
          );
          expect(transientRes.status).toBe(503);
          expect(yield* Effect.promise(() => transientRes.json())).toMatchObject({
            error: "temporarily_unavailable",
          });
        }

        // Once GitHub recovers, the same refresh token still succeeds and rotates.
        orgStatus = 200;
        orgRawBody = undefined;
        const recoveredRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-cli",
                refresh_token: initialRefresh,
              }),
            }),
          ),
        );
        expect(recoveredRes.status).toBe(200);
        const { refresh_token: rotatedRefresh } = (yield* Effect.promise(() =>
          recoveredRes.json(),
        )) as { refresh_token: string };

        // Revoke persistence failure returns 503 instead of falsely claiming success.
        failUpdate = true;
        const revokeErrRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/revoke", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                client_id: "t3-cli",
                token: rotatedRefresh,
              }),
            }),
          ),
        );
        expect(revokeErrRes.status).toBe(503);
        expect(yield* Effect.promise(() => revokeErrRes.json())).toMatchObject({
          error: "temporarily_unavailable",
        });

        // Org denial (404) when revocation persistence fails returns 503 instead of claiming invalid_grant.
        orgStatus = 404;
        const deniedPersistErrRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-cli",
                refresh_token: rotatedRefresh,
              }),
            }),
          ),
        );
        expect(deniedPersistErrRes.status).toBe(503);
        expect(yield* Effect.promise(() => deniedPersistErrRes.json())).toMatchObject({
          error: "temporarily_unavailable",
        });
        failUpdate = false;

        // User removed from org (404) -> invalid_grant AND session revoked permanently.
        orgStatus = 404;
        const deniedRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-cli",
                refresh_token: rotatedRefresh,
              }),
            }),
          ),
        );
        expect(deniedRes.status).toBe(400);
        expect(yield* Effect.promise(() => deniedRes.json())).toMatchObject({
          error: "invalid_grant",
        });

        // Even if org membership is restored later, the revoked session cannot be reused.
        orgStatus = 200;
        const postRevokeRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-cli",
                refresh_token: rotatedRefresh,
              }),
            }),
          ),
        );
        expect(postRevokeRes.status).toBe(400);
        expect(yield* Effect.promise(() => postRevokeRes.json())).toMatchObject({
          error: "invalid_grant",
        });
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect(
    "rejects oversized OAuth POST bodies with 413 and falls through org 403 to a later allowed org",
    () =>
      Effect.gen(function* () {
        const { app } = yield* makeTestApp({
          allowedOrgs: ["sso-blocked-org", "robert-crandall-org"],
          onGitHubRequest: (url) => {
            if (url.endsWith("/user/memberships/orgs/sso-blocked-org")) {
              return Response.json({ message: "SSO" }, { status: 403 });
            }
            return defaultGitHubMock()(url);
          },
        });

        // Oversized POST body is rejected with 413 on unauthenticated OAuth POST routes.
        const oversizedRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: `client_id=t3-cli&pad=${"x".repeat(20_000)}`,
            }),
          ),
        );
        expect(oversizedRes.status).toBe(413);

        // Device auth + poll succeeds when org 1 returns 403 and org 2 returns 200 active.
        const startRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/device", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({ client_id: "t3-cli" }),
            }),
          ),
        );
        expect(startRes.status).toBe(200);
        const startJson = (yield* Effect.promise(() => startRes.json())) as { device_code: string };

        const pollRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                client_id: "t3-cli",
                device_code: startJson.device_code,
              }),
            }),
          ),
        );
        expect(pollRes.status).toBe(200);
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect(
    "captures runtime services at layer build time when wired through HttpRouter.toHttpEffect",
    () =>
      Effect.gen(function* () {
        const { layerAuth } = yield* setupPgliteOAuthTest();
        const mockHttpClient = HttpClient.make((request) =>
          Effect.sync(() => HttpClientResponse.fromWeb(request, defaultGitHubMock()(request.url))),
        );
        const httpEffect = yield* HttpRouter.toHttpEffect(
          GitHubOAuth.layerRoutes.pipe(
            Layer.provide(layerAuth),
            Layer.provide(Layer.succeed(HttpClient.HttpClient, mockHttpClient)),
          ),
        ).pipe(Effect.provide(HttpServer.layerServices));

        const authorizeResponse = yield* httpEffect.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromWeb(
              new Request("https://relay.crandalls.cloud/v1/auth/authorize"),
            ),
          ),
        );
        expect(authorizeResponse.status).toBe(400);

        const revokeResponse = yield* httpEffect.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromWeb(
              new Request("https://relay.crandalls.cloud/v1/auth/revoke", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: "",
              }),
            ),
          ),
        );
        expect(revokeResponse.status).toBe(200);

        const deviceResponse = yield* httpEffect.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromWeb(
              new Request("https://relay.crandalls.cloud/v1/auth/device", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({ client_id: "t3-cli" }),
              }),
            ),
          ),
        );
        expect(deviceResponse.status).toBe(200);

        const callbackResponse = yield* httpEffect.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromWeb(
              new Request("https://relay.crandalls.cloud/v1/auth/github/callback"),
            ),
          ),
        );
        expect(callbackResponse.status).toBe(400);

        const tokenResponse = yield* httpEffect.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromWeb(
              new Request("https://relay.crandalls.cloud/v1/auth/token", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: "",
              }),
            ),
          ),
        );
        expect(tokenResponse.status).toBe(400);
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.live(
    "supports t3-desktop loopback PKCE and t3-mobile custom-scheme PKCE while restricting device flow to t3-cli",
    () =>
      Effect.gen(function* () {
        expect(
          GitHubOAuth.isAllowedClientRedirectUri("t3-desktop", "http://127.0.0.1:43123/callback"),
        ).toBe(true);
        expect(
          GitHubOAuth.isAllowedClientRedirectUri("t3-desktop", "t3code-private://oauth/callback"),
        ).toBe(false);
        expect(
          GitHubOAuth.isAllowedClientRedirectUri("t3-mobile", "t3code-private://oauth/callback"),
        ).toBe(true);
        expect(
          GitHubOAuth.isAllowedClientRedirectUri("t3-mobile", "t3code-dev://oauth/callback"),
        ).toBe(true);
        expect(
          GitHubOAuth.isAllowedClientRedirectUri(
            "t3-mobile",
            "t3code-private://oauth/callback?x=1",
          ),
        ).toBe(false);
        expect(
          GitHubOAuth.isAllowedClientRedirectUri("t3-mobile", "http://127.0.0.1:43123/callback"),
        ).toBe(false);

        const { app, layerAuth } = yield* makeTestApp({ onGitHubRequest: defaultGitHubMock() });

        // Device endpoints stay restricted to t3-cli.
        for (const clientId of ["t3-desktop", "t3-mobile"]) {
          const deviceRes = yield* Effect.promise(() =>
            app.handler(
              new Request("https://relay.crandalls.cloud/v1/auth/device", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({ client_id: clientId }),
              }),
            ),
          );
          expect(deviceRes.status).toBe(400);
          expect(yield* Effect.promise(() => deviceRes.json())).toMatchObject({
            error: "invalid_client",
          });

          const deviceTokenRes = yield* Effect.promise(() =>
            app.handler(
              new Request("https://relay.crandalls.cloud/v1/auth/token", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                  grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                  client_id: clientId,
                  device_code: "unused",
                }),
              }),
            ),
          );
          expect(deviceTokenRes.status).toBe(400);
          expect(yield* Effect.promise(() => deviceTokenRes.json())).toMatchObject({
            error: "unauthorized_client",
          });
        }

        // Complete PKCE flow for t3-mobile using t3code-private://oauth/callback.
        const verifier = "mobile-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
        const redirectUri = "t3code-private://oauth/callback";
        const authUrl = new URL("https://relay.crandalls.cloud/v1/auth/authorize");
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("client_id", "t3-mobile");
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("code_challenge", pkceChallenge(verifier));
        authUrl.searchParams.set("code_challenge_method", "S256");
        authUrl.searchParams.set("state", "mobile-state-1");

        const authRes = yield* Effect.promise(() => app.handler(new Request(authUrl)));
        expect(authRes.status).toBe(302);
        const ghLocation = new URL(authRes.headers.get("location")!);
        const cookieHeader = authRes.headers.get("set-cookie")!.split(";")[0]!;

        const cbUrl = new URL("https://relay.crandalls.cloud/v1/auth/github/callback");
        cbUrl.searchParams.set("code", "gh-mobile-code");
        cbUrl.searchParams.set("state", ghLocation.searchParams.get("state")!);
        const cbRes = yield* Effect.promise(() =>
          app.handler(new Request(cbUrl, { headers: { cookie: cookieHeader } })),
        );
        expect(cbRes.status).toBe(302);
        const appCallback = new URL(cbRes.headers.get("location")!);
        expect(`${appCallback.protocol}//${appCallback.host}${appCallback.pathname}`).toBe(
          redirectUri,
        );
        expect(appCallback.searchParams.get("state")).toBe("mobile-state-1");
        const relayCode = appCallback.searchParams.get("code")!;

        const tokenRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "t3-mobile",
                code: relayCode,
                redirect_uri: redirectUri,
                code_verifier: verifier,
              }),
            }),
          ),
        );
        expect(tokenRes.status).toBe(200);
        const tokens = (yield* Effect.promise(() => tokenRes.json())) as {
          access_token: string;
          refresh_token: string;
        };
        const claims = yield* Effect.gen(function* () {
          const relayTokens = yield* RelayTokens.RelayTokens;
          return yield* relayTokens.verifyClientAccessToken({ token: tokens.access_token });
        }).pipe(Effect.provide(layerAuth));
        expect(claims?.client_id).toBe("t3-mobile");
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.live(
    "captures GitHub refresh tokens in PKCE login, transparently refreshes on 401 across rotations, and revokes on post-refresh org denial",
    () =>
      Effect.gen(function* () {
        let validAccessToken = "ghu_1";
        let expectedRefreshToken = "ghr_1";
        let nextPair = { access_token: "ghu_2", refresh_token: "ghr_2" };
        let denyOrgForToken: string | null = null;
        const refreshCalls: Array<URLSearchParams> = [];

        const { app } = yield* makeTestApp({
          onGitHubRequest: (url, _method, body, headers) => {
            if (url.endsWith("/login/oauth/access_token")) {
              const params = new URLSearchParams(body);
              if (params.get("grant_type") === "refresh_token") {
                refreshCalls.push(params);
                if (params.get("refresh_token") !== expectedRefreshToken) {
                  return Response.json({ error: "bad_refresh_token" });
                }
                validAccessToken = nextPair.access_token;
                expectedRefreshToken = nextPair.refresh_token;
                return Response.json({ ...nextPair, token_type: "bearer" });
              }
              return Response.json({
                access_token: "ghu_1",
                refresh_token: "ghr_1",
                token_type: "bearer",
              });
            }
            if (url.endsWith("/user")) {
              return Response.json({
                id: 42,
                login: "robert-crandall",
                email: "rob@crandalls.cloud",
              });
            }
            if (url.includes("/user/memberships/orgs/")) {
              const auth = headers.authorization ?? "";
              if (denyOrgForToken && auth === `Bearer ${denyOrgForToken}`) {
                return new Response("Not Found", { status: 404 });
              }
              if (auth !== `Bearer ${validAccessToken}`) {
                return new Response("Bad credentials", { status: 401 });
              }
              return Response.json({ state: "active" });
            }
            return new Response(`Unexpected URL: ${url}`, { status: 500 });
          },
        });

        const verifier = "pkce-refresh-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
        const redirectUri = "t3code-private://oauth/callback";
        const authRes = yield* Effect.promise(() =>
          app.handler(
            new Request(
              `https://relay.crandalls.cloud/v1/auth/authorize?client_id=t3-mobile&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&state=s1&code_challenge=${pkceChallenge(verifier)}&code_challenge_method=S256`,
            ),
          ),
        );
        const state = new URL(authRes.headers.get("location")!).searchParams.get("state")!;
        const cookie = authRes.headers.get("set-cookie")!.split(";")[0]!;
        const cbRes = yield* Effect.promise(() =>
          app.handler(
            new Request(
              `https://relay.crandalls.cloud/v1/auth/github/callback?code=gh_code&state=${encodeURIComponent(state)}`,
              { headers: { cookie } },
            ),
          ),
        );
        const relayCode = new URL(cbRes.headers.get("location")!).searchParams.get("code")!;

        const loginRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "t3-mobile",
                code: relayCode,
                redirect_uri: redirectUri,
                code_verifier: verifier,
              }),
            }),
          ),
        );
        expect(loginRes.status).toBe(200);
        const loginBody = (yield* Effect.promise(() => loginRes.json())) as {
          refresh_token: string;
        };

        // Expire ghu_1 -> reactive refresh exchanges ghr_1 for (ghu_2, ghr_2) and succeeds.
        validAccessToken = "expired";
        const refresh1 = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-mobile",
                refresh_token: loginBody.refresh_token,
              }),
            }),
          ),
        );
        expect(refresh1.status).toBe(200);
        expect(refreshCalls).toHaveLength(1);
        expect(refreshCalls[0]?.get("refresh_token")).toBe("ghr_1");
        expect(refreshCalls[0]?.get("client_id")).toBe("gh-client-123");
        expect(refreshCalls[0]?.get("client_secret")).toBe("gh-secret-456");
        const r1Body = (yield* Effect.promise(() => refresh1.json())) as {
          refresh_token: string;
        };

        // Expire ghu_2 -> uses newly rotated ghr_2 to mint (ghu_3, ghr_3).
        validAccessToken = "expired";
        nextPair = { access_token: "ghu_3", refresh_token: "ghr_3" };
        const refresh2 = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-mobile",
                refresh_token: r1Body.refresh_token,
              }),
            }),
          ),
        );
        expect(refresh2.status).toBe(200);
        expect(refreshCalls).toHaveLength(2);
        expect(refreshCalls[1]?.get("refresh_token")).toBe("ghr_2");
        const r2Body = (yield* Effect.promise(() => refresh2.json())) as {
          refresh_token: string;
        };

        // Expire ghu_3, refresh yields ghu_4, but user was removed from org (404) -> revokes.
        validAccessToken = "expired";
        nextPair = { access_token: "ghu_4", refresh_token: "ghr_4" };
        denyOrgForToken = "ghu_4";
        const deniedAfterRefresh = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-mobile",
                refresh_token: r2Body.refresh_token,
              }),
            }),
          ),
        );
        expect(deniedAfterRefresh.status).toBe(400);
        expect(yield* Effect.promise(() => deniedAfterRefresh.json())).toMatchObject({
          error: "invalid_grant",
        });

        // Session stays revoked even if org membership is restored.
        denyOrgForToken = null;
        const postRevoke = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-mobile",
                refresh_token: r2Body.refresh_token,
              }),
            }),
          ),
        );
        expect(postRevoke.status).toBe(400);
        expect(yield* Effect.promise(() => postRevoke.json())).toMatchObject({
          error: "invalid_grant",
        });
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.live(
    "handles device-flow refresh tokens: treats non-bad_refresh_token 200 errors as 503, preserves persisted tokens across post-refresh 500, revokes on bad_refresh_token, and revokes legacy sessions without a refresh token",
    () =>
      Effect.gen(function* () {
        let deviceLoginReturnsRefresh = true;
        let activeAccessToken = "ghu_dev_1";
        let refreshResponse: Record<string, unknown> = {
          error: "incorrect_client_credentials",
        };
        let postRefreshOrg500 = false;
        let refreshPostCount = 0;

        const { app } = yield* makeTestApp({
          onGitHubRequest: (url, _method, body, headers) => {
            if (url.endsWith("/login/device/code")) {
              return Response.json({
                device_code: "gh_dev_1",
                user_code: "ABCD-1234",
                verification_uri: "https://github.com/login/device",
                expires_in: 900,
                interval: 5,
              });
            }
            if (url.endsWith("/login/oauth/access_token")) {
              const params = new URLSearchParams(body);
              if (params.get("grant_type") === "refresh_token") {
                refreshPostCount += 1;
                return Response.json(refreshResponse);
              }
              return Response.json(
                deviceLoginReturnsRefresh
                  ? { access_token: "ghu_dev_1", refresh_token: "ghr_dev_1", token_type: "bearer" }
                  : { access_token: "gho_legacy_1", token_type: "bearer" },
              );
            }
            if (url.endsWith("/user")) {
              return Response.json({ id: 42, login: "robert-crandall", email: null });
            }
            if (url.includes("/user/memberships/orgs/")) {
              const auth = headers.authorization ?? "";
              if (auth === `Bearer ${activeAccessToken}`) {
                if (postRefreshOrg500) {
                  return new Response("Internal Server Error", { status: 500 });
                }
                return Response.json({ state: "active" });
              }
              return new Response("Unauthorized", { status: 401 });
            }
            return new Response(`Unexpected URL: ${url}`, { status: 500 });
          },
        });

        const startDeviceSession = () =>
          Effect.gen(function* () {
            const devRes = yield* Effect.promise(() =>
              app.handler(
                new Request("https://relay.crandalls.cloud/v1/auth/device", {
                  method: "POST",
                  headers: { "content-type": "application/x-www-form-urlencoded" },
                  body: new URLSearchParams({ client_id: "t3-cli" }),
                }),
              ),
            );
            const { device_code: deviceCode } = (yield* Effect.promise(() => devRes.json())) as {
              device_code: string;
            };
            const tokRes = yield* Effect.promise(() =>
              app.handler(
                new Request("https://relay.crandalls.cloud/v1/auth/token", {
                  method: "POST",
                  headers: { "content-type": "application/x-www-form-urlencoded" },
                  body: new URLSearchParams({
                    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                    client_id: "t3-cli",
                    device_code: deviceCode,
                  }),
                }),
              ),
            );
            expect(tokRes.status).toBe(200);
            const body = (yield* Effect.promise(() => tokRes.json())) as {
              refresh_token: string;
            };
            return body.refresh_token;
          });

        const refreshSession = (refreshToken: string) =>
          Effect.promise(() =>
            app.handler(
              new Request("https://relay.crandalls.cloud/v1/auth/token", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                  grant_type: "refresh_token",
                  client_id: "t3-cli",
                  refresh_token: refreshToken,
                }),
              }),
            ),
          );

        const refreshToken = yield* startDeviceSession();

        // 1. HTTP 200 { error: "incorrect_client_credentials" } -> 503, does NOT revoke, releases lease.
        activeAccessToken = "expired";
        refreshResponse = { error: "incorrect_client_credentials" };
        const badClientCredsRes = yield* refreshSession(refreshToken);
        expect(badClientCredsRes.status).toBe(503);
        expect(yield* Effect.promise(() => badClientCredsRes.json())).toMatchObject({
          error: "temporarily_unavailable",
        });

        // 2. Refresh succeeds with (ghu_dev_2, ghr_dev_2), then post-refresh org check hits 500.
        // Relay returns 503 AND has already persisted (ghu_dev_2, ghr_dev_2).
        refreshResponse = {
          access_token: "ghu_dev_2",
          refresh_token: "ghr_dev_2",
          token_type: "bearer",
        };
        activeAccessToken = "ghu_dev_2";
        postRefreshOrg500 = true;
        const postRefresh500Res = yield* refreshSession(refreshToken);
        expect(postRefresh500Res.status).toBe(503);
        expect(refreshPostCount).toBe(2);

        // 3. When org endpoint recovers, retry succeeds using persisted ghu_dev_2 with NO new refresh POST.
        postRefreshOrg500 = false;
        const recoveredRes = yield* refreshSession(refreshToken);
        expect(recoveredRes.status).toBe(200);
        expect(refreshPostCount).toBe(2);
        const { refresh_token: rotatedRefreshToken } = (yield* Effect.promise(() =>
          recoveredRes.json(),
        )) as { refresh_token: string };

        // 4. HTTP 200 { error: "bad_refresh_token" } revokes the session -> 400 invalid_grant.
        activeAccessToken = "expired";
        refreshResponse = { error: "bad_refresh_token" };
        const badRefreshRes = yield* refreshSession(rotatedRefreshToken);
        expect(badRefreshRes.status).toBe(400);
        expect(yield* Effect.promise(() => badRefreshRes.json())).toMatchObject({
          error: "invalid_grant",
        });

        // 5. Legacy session without a stored refresh token revokes immediately on 401 without calling refresh.
        deviceLoginReturnsRefresh = false;
        activeAccessToken = "gho_legacy_1";
        const legacyRefreshToken = yield* startDeviceSession();
        const countBeforeLegacy401 = refreshPostCount;
        activeAccessToken = "expired";
        const legacy401Res = yield* refreshSession(legacyRefreshToken);
        expect(legacy401Res.status).toBe(400);
        expect(yield* Effect.promise(() => legacy401Res.json())).toMatchObject({
          error: "invalid_grant",
        });
        expect(refreshPostCount).toBe(countBeforeLegacy401);
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.live(
    "serializes concurrent 401 refreshes via lease and serves grace-window and AlreadyRefreshed peers cleanly",
    () =>
      Effect.gen(function* () {
        let activeAccessToken = "ghu_race_1";
        let refreshPostCount = 0;
        let resolveRefreshBarrier!: () => void;
        let notifyRefreshStarted!: () => void;
        const refreshStarted = new Promise<void>((resolve) => {
          notifyRefreshStarted = resolve;
        });
        const refreshBarrier = new Promise<void>((resolve) => {
          resolveRefreshBarrier = resolve;
        });
        let holdSecondOrg401 = false;
        let releaseHeldOrg401!: () => void;
        let notifyOrg401Held!: () => void;
        const org401Held = new Promise<void>((resolve) => {
          notifyOrg401Held = resolve;
        });
        const org401Gate = new Promise<void>((resolve) => {
          releaseHeldOrg401 = resolve;
        });

        const { app } = yield* makeTestApp({
          onGitHubRequest: async (url, _method, body, headers) => {
            if (url.endsWith("/login/device/code")) {
              return Response.json({
                device_code: "gh_dev_race",
                user_code: "RACE-1234",
                verification_uri: "https://github.com/login/device",
                expires_in: 900,
                interval: 5,
              });
            }
            if (url.endsWith("/login/oauth/access_token")) {
              const params = new URLSearchParams(body);
              if (params.get("grant_type") === "refresh_token") {
                refreshPostCount += 1;
                notifyRefreshStarted();
                await refreshBarrier;
                activeAccessToken = "ghu_race_2";
                return Response.json({
                  access_token: "ghu_race_2",
                  refresh_token: "ghr_race_2",
                  token_type: "bearer",
                });
              }
              return Response.json({
                access_token: "ghu_race_1",
                refresh_token: "ghr_race_1",
                token_type: "bearer",
              });
            }
            if (url.endsWith("/user")) {
              return Response.json({ id: 42, login: "robert-crandall", email: null });
            }
            if (url.includes("/user/memberships/orgs/")) {
              if (headers.authorization === `Bearer ${activeAccessToken}`) {
                return Response.json({ state: "active" });
              }
              if (holdSecondOrg401) {
                holdSecondOrg401 = false;
                notifyOrg401Held();
                await org401Gate;
              }
              return new Response("Unauthorized", { status: 401 });
            }
            return new Response(`Unexpected URL: ${url}`, { status: 500 });
          },
        });

        // Create session with (ghu_race_1, ghr_race_1).
        const devRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/device", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({ client_id: "t3-cli" }),
            }),
          ),
        );
        const { device_code: deviceCode } = (yield* Effect.promise(() => devRes.json())) as {
          device_code: string;
        };
        const loginRes = yield* Effect.promise(() =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                client_id: "t3-cli",
                device_code: deviceCode,
              }),
            }),
          ),
        );
        const { refresh_token: rt1 } = (yield* Effect.promise(() => loginRes.json())) as {
          refresh_token: string;
        };

        const postRefresh = (token: string) =>
          app.handler(
            new Request("https://relay.crandalls.cloud/v1/auth/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "t3-cli",
                refresh_token: token,
              }),
            }),
          );

        // Expire ghu_race_1 and start Worker A + Worker C (held on initial 401 to hit AlreadyRefreshed).
        activeAccessToken = "expired";
        const workerAPromise = postRefresh(rt1);
        yield* Effect.promise(() => refreshStarted);

        // Worker B arrives while Worker A holds the lease -> 503 InFlight, no second refresh POST.
        const workerBRes = yield* Effect.promise(() => postRefresh(rt1));
        expect(workerBRes.status).toBe(503);
        expect(refreshPostCount).toBe(1);

        // Worker C starts and pauses right before receiving its initial 401.
        holdSecondOrg401 = true;
        const workerCPromise = postRefresh(rt1);
        yield* Effect.promise(() => org401Held);

        // Let Worker A complete refresh -> rotates rt1 -> rt2.
        resolveRefreshBarrier();
        const workerARes = yield* Effect.promise(() => workerAPromise);
        expect(workerARes.status).toBe(200);
        const { refresh_token: rt2 } = (yield* Effect.promise(() => workerARes.json())) as {
          refresh_token: string;
        };

        // Release Worker C -> hits AlreadyRefreshed(ghu_race_2), re-verifies org, returns grace-cached rt2.
        releaseHeldOrg401();
        const workerCRes = yield* Effect.promise(() => workerCPromise);
        expect(workerCRes.status).toBe(200);
        expect(yield* Effect.promise(() => workerCRes.json())).toMatchObject({
          refresh_token: rt2,
        });
        expect(refreshPostCount).toBe(1);

        // Worker B's grace-window retry with rt1 also succeeds with rt2 and no refresh POST.
        const workerBRetryRes = yield* Effect.promise(() => postRefresh(rt1));
        expect(workerBRetryRes.status).toBe(200);
        expect(yield* Effect.promise(() => workerBRetryRes.json())).toMatchObject({
          refresh_token: rt2,
        });
        expect(refreshPostCount).toBe(1);
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect(
    "skips refresh when initial org check consumes request budget and stays compatible with legacy raw enc_gh codes",
    () =>
      Effect.gen(function* () {
        const { layerAuth } = yield* setupPgliteOAuthTest();
        const startMs = Date.parse("2026-11-24T12:00:00.000Z");
        yield* TestClock.setTime(startMs);

        let slowInitial401 = true;
        let refreshPostCount = 0;
        const mockHttpClient = HttpClient.make((request) =>
          Effect.gen(function* () {
            if (request.url.endsWith("/login/oauth/access_token")) {
              refreshPostCount += 1;
              return HttpClientResponse.fromWeb(
                request,
                Response.json({
                  access_token: "ghu_budget_2",
                  refresh_token: "ghr_budget_2",
                  token_type: "bearer",
                }),
              );
            }
            if (request.url.includes("/user/memberships/orgs/")) {
              if (request.headers.authorization === "Bearer ghu_budget_2") {
                return HttpClientResponse.fromWeb(request, Response.json({ state: "active" }));
              }
              if (slowInitial401) {
                yield* TestClock.adjust("4500 millis");
              }
              return HttpClientResponse.fromWeb(
                request,
                new Response("Unauthorized", { status: 401 }),
              );
            }
            return HttpClientResponse.fromWeb(request, new Response("Not Found", { status: 404 }));
          }),
        );

        const httpEffect = yield* HttpRouter.toHttpEffect(
          GitHubOAuth.layerRoutes.pipe(
            Layer.provide(layerAuth),
            Layer.provide(Layer.succeed(HttpClient.HttpClient, mockHttpClient)),
          ),
        ).pipe(Effect.provide(HttpServer.layerServices));

        // 1. Seed a session with an expiring access token + refresh token.
        const created = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions.create({
            userId: "github:42",
            githubLogin: "robert-crandall",
            clientId: "t3-cli",
            githubAccessToken: "ghu_budget_1",
            githubRefreshToken: "ghr_budget_1",
          });
        }).pipe(Effect.provide(layerAuth));
        if (created._tag !== "Created") {
          throw new Error("expected Created");
        }

        // Slow initial 401 (>4s elapsed) returns 503 without claiming lease or calling GitHub refresh.
        const slowRes = yield* httpEffect.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromWeb(
              new Request("https://relay.crandalls.cloud/v1/auth/token", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                  grant_type: "refresh_token",
                  client_id: "t3-cli",
                  refresh_token: created.refreshToken,
                }),
              }),
            ),
          ),
        );
        expect(slowRes.status).toBe(503);
        expect(refreshPostCount).toBe(0);

        // Next fast 401 proceeds to refresh and succeeds.
        slowInitial401 = false;
        const fastRes = yield* httpEffect.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromWeb(
              new Request("https://relay.crandalls.cloud/v1/auth/token", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                  grant_type: "refresh_token",
                  client_id: "t3-cli",
                  refresh_token: created.refreshToken,
                }),
              }),
            ),
          ),
        );
        expect(fastRes.status).toBe(200);
        expect(refreshPostCount).toBe(1);

        // 2. Legacy pre-deploy raw-string enc_gh authorization code still exchanges cleanly.
        const verifier = "legacy-code-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
        const redirectUri = "http://127.0.0.1:43219/callback";
        const legacyCode = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          const relayTokens = yield* RelayTokens.RelayTokens;
          const now = yield* DateTime.now;
          const iat = Math.floor(now.epochMilliseconds / 1_000);
          const jti = "legacy-jti-1";
          const encGh = yield* sessions.sealSecret("gho_legacy_raw", `code:${jti}:t3-cli`);
          return yield* relayTokens.issueOAuthCodeToken({
            userId: "github:42",
            githubLogin: "robert-crandall",
            encryptedGithubAccessToken: encGh,
            clientId: "t3-cli",
            redirectUri,
            codeChallenge: pkceChallenge(verifier),
            jti,
            issuedAtEpochSeconds: iat,
            expiresAtEpochSeconds: iat + 60,
          });
        }).pipe(Effect.provide(layerAuth));

        const legacyExchangeRes = yield* httpEffect.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromWeb(
              new Request("https://relay.crandalls.cloud/v1/auth/token", {
                method: "POST",
                headers: { "content-type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                  grant_type: "authorization_code",
                  client_id: "t3-cli",
                  code: legacyCode,
                  redirect_uri: redirectUri,
                  code_verifier: verifier,
                }),
              }),
            ),
          ),
        );
        expect(legacyExchangeRes.status).toBe(200);
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );

  it.effect(
    "retries transient persistence errors with backoff, survives outer interruption during refresh, and releases lease on post-claim budget overrun",
    () =>
      Effect.gen(function* () {
        let failUpdateMode: "none" | "fail-once-after-claim" | "fail-all-after-claim" = "none";
        let updateCount = 0;
        let injectedFailures = 0;
        const { db, layerAuth } = yield* setupPgliteOAuthTest({
          failUpdate: () => {
            updateCount += 1;
            if (failUpdateMode === "fail-once-after-claim" && updateCount === 2) {
              injectedFailures += 1;
              return true;
            }
            if (failUpdateMode === "fail-all-after-claim" && updateCount >= 2) {
              injectedFailures += 1;
              return true;
            }
            return false;
          },
        });

        let refreshPostCount = 0;
        let refreshVersion = 1;
        let pauseRefreshStarted: Deferred.Deferred<void> | null = null;
        let releasePausedRefresh: Deferred.Deferred<void> | null = null;
        let refreshBehavior: "normal" | "hang" | "bad_refresh_token" = "normal";

        const mockHttpClient = HttpClient.make(
          Effect.fnUntraced(function* (request) {
            if (request.url.endsWith("/login/oauth/access_token")) {
              refreshPostCount += 1;
              if (pauseRefreshStarted && releasePausedRefresh) {
                yield* Deferred.succeed(pauseRefreshStarted, undefined);
                yield* Deferred.await(releasePausedRefresh);
              }
              if (refreshBehavior === "hang") {
                return yield* Effect.never;
              }
              if (refreshBehavior === "bad_refresh_token") {
                return HttpClientResponse.fromWeb(
                  request,
                  Response.json({
                    error: "bad_refresh_token",
                    error_description: "The refresh token passed is incorrect or expired.",
                  }),
                );
              }
              refreshVersion += 1;
              return HttpClientResponse.fromWeb(
                request,
                Response.json({
                  access_token: `ghu_fault_${refreshVersion}`,
                  refresh_token: `ghr_fault_${refreshVersion}`,
                }),
              );
            }
            if (request.url.includes("/user/memberships/orgs/")) {
              if (request.headers.authorization === `Bearer ghu_fault_${refreshVersion}`) {
                return HttpClientResponse.fromWeb(request, Response.json({ state: "active" }));
              }
              return HttpClientResponse.fromWeb(
                request,
                new Response("Unauthorized", { status: 401 }),
              );
            }
            return HttpClientResponse.fromWeb(request, new Response("Not Found", { status: 404 }));
          }),
        );

        let delayAfterClaim = false;
        let hangFirstComplete = false;
        let completeAttemptsStarted = 0;
        let trackCompleteAttempts = false;
        const completeAttemptDone = yield* Queue.unbounded<void>();
        const completeAttemptStarted = yield* Queue.unbounded<void>();
        const wrappedSessionsLayer = Layer.effect(
          OAuthSessions.OAuthSessions,
          Effect.gen(function* () {
            const base = yield* OAuthSessions.OAuthSessions;
            return OAuthSessions.OAuthSessions.of({
              ...base,
              claimGitHubRefresh: Effect.fnUntraced(function* (input) {
                const claimed = yield* base.claimGitHubRefresh(input);
                if (delayAfterClaim) {
                  yield* TestClock.adjust("3500 millis");
                }
                return claimed;
              }),
              completeGitHubRefresh: Effect.fnUntraced(function* (input) {
                completeAttemptsStarted += 1;
                if (trackCompleteAttempts) {
                  yield* Queue.offer(completeAttemptStarted, undefined);
                }
                if (hangFirstComplete && completeAttemptsStarted === 1) {
                  return yield* Effect.never.pipe(
                    Effect.onExit(() =>
                      trackCompleteAttempts
                        ? Queue.offer(completeAttemptDone, undefined)
                        : Effect.void,
                    ),
                  );
                }
                return yield* base
                  .completeGitHubRefresh(input)
                  .pipe(
                    Effect.onExit(() =>
                      trackCompleteAttempts
                        ? Queue.offer(completeAttemptDone, undefined)
                        : Effect.void,
                    ),
                  );
              }),
            });
          }),
        ).pipe(Layer.provide(layerAuth));

        const httpEffect = yield* HttpRouter.toHttpEffect(
          GitHubOAuth.layerRoutes.pipe(
            Layer.provide(wrappedSessionsLayer),
            Layer.provide(layerAuth),
            Layer.provide(Layer.succeed(HttpClient.HttpClient, mockHttpClient)),
          ),
        ).pipe(Effect.provide(HttpServer.layerServices));

        const created = yield* Effect.gen(function* () {
          const sessions = yield* OAuthSessions.OAuthSessions;
          return yield* sessions.create({
            userId: "github:42",
            githubLogin: "robert-crandall",
            clientId: "t3-cli",
            githubAccessToken: "ghu_fault_0",
            githubRefreshToken: "ghr_fault_0",
          });
        }).pipe(Effect.provide(layerAuth));
        if (created._tag !== "Created") {
          throw new Error("expected Created");
        }

        const postRefresh = (refreshToken: string) =>
          httpEffect.pipe(
            Effect.provideService(
              HttpServerRequest.HttpServerRequest,
              HttpServerRequest.fromWeb(
                new Request("https://relay.crandalls.cloud/v1/auth/token", {
                  method: "POST",
                  headers: { "content-type": "application/x-www-form-urlencoded" },
                  body: new URLSearchParams({
                    grant_type: "refresh_token",
                    client_id: "t3-cli",
                    refresh_token: refreshToken,
                  }),
                }),
              ),
            ),
          );

        const readRefreshToken = (res: HttpServerResponse.HttpServerResponse) =>
          Effect.promise(
            () => HttpServerResponse.toWeb(res).json() as Promise<{ refresh_token: string }>,
          );

        const loadSessionRow = () =>
          Effect.promise(() =>
            db
              .select({
                githubRefreshLeaseUntil: relayOauthSessions.githubRefreshLeaseUntil,
                revokedAt: relayOauthSessions.revokedAt,
              })
              .from(relayOauthSessions)
              .where(eq(relayOauthSessions.id, created.sessionId))
              .limit(1),
          );

        // 1. Post-claim budget overrun releases the lease without calling GitHub.
        delayAfterClaim = true;
        const overrunRes = yield* postRefresh(created.refreshToken);
        delayAfterClaim = false;
        expect(overrunRes.status).toBe(503);
        expect(refreshPostCount).toBe(0);
        const [rowAfterOverrun] = yield* loadSessionRow();
        expect(rowAfterOverrun?.githubRefreshLeaseUntil).toBeNull();

        const advanceToNextAttempt = (delay: "150 millis" | "350 millis") =>
          Effect.gen(function* () {
            yield* Queue.take(completeAttemptDone);
            // Drain the TestClock tracking scheduler so the retry fiber reaches Effect.sleep(delay).
            yield* TestClock.adjust("0 millis");
            yield* TestClock.adjust(delay);
            yield* Queue.take(completeAttemptStarted);
          });

        // 2. First persistence attempt fails -> backoff retry succeeds and persists rotated tokens.
        failUpdateMode = "fail-once-after-claim";
        updateCount = 0;
        injectedFailures = 0;
        completeAttemptsStarted = 0;
        trackCompleteAttempts = true;
        const retryFiber = yield* Effect.forkChild(postRefresh(created.refreshToken));
        yield* Queue.take(completeAttemptStarted);
        yield* advanceToNextAttempt("150 millis");
        yield* Queue.take(completeAttemptDone);
        const retryRes = yield* Fiber.join(retryFiber);
        trackCompleteAttempts = false;
        failUpdateMode = "none";
        expect(retryRes.status).toBe(200);
        expect(injectedFailures).toBe(1);
        expect(refreshPostCount).toBe(1);
        const retryBody = yield* readRefreshToken(retryRes);

        // Next refresh reuses persisted ghu_fault_2 without another GitHub refresh POST.
        const reuseRes = yield* postRefresh(retryBody.refresh_token);
        expect(reuseRes.status).toBe(200);
        expect(refreshPostCount).toBe(1);
        const reuseBody = yield* readRefreshToken(reuseRes);

        // 3. Outer interruption mid-refresh does not discard rotated tokens before persistence.
        refreshVersion += 1; // expire ghu_fault_2 so next call hits 401 -> refresh to ghu_fault_4
        pauseRefreshStarted = yield* Deferred.make<void>();
        releasePausedRefresh = yield* Deferred.make<void>();
        const interruptedFiber = yield* Effect.forkChild(postRefresh(reuseBody.refresh_token));
        yield* Deferred.await(pauseRefreshStarted);

        const interruptWaiter = yield* Effect.forkChild(Fiber.interrupt(interruptedFiber));
        yield* Effect.yieldNow;
        yield* Deferred.succeed(releasePausedRefresh, undefined);
        yield* Fiber.join(interruptWaiter);
        const interruptedExit = yield* Fiber.await(interruptedFiber);
        expect(Exit.isFailure(interruptedExit) && Cause.hasInterrupts(interruptedExit.cause)).toBe(
          true,
        );
        pauseRefreshStarted = null;
        releasePausedRefresh = null;

        expect(refreshPostCount).toBe(2);
        const [rowAfterInterrupt] = yield* loadSessionRow();
        expect(rowAfterInterrupt?.githubRefreshLeaseUntil).toBeNull();
        expect(rowAfterInterrupt?.revokedAt).toBeNull();

        // Subsequent refresh uses the persisted ghu_fault_4 with no additional GitHub refresh POST.
        const afterInterruptRes = yield* postRefresh(reuseBody.refresh_token);
        expect(afterInterruptRes.status).toBe(200);
        expect(refreshPostCount).toBe(2);
        const afterInterruptBody = yield* readRefreshToken(afterInterruptRes);

        // 4. Hung GitHub refresh POST times out at 4s inside Effect.uninterruptible and releases lease.
        refreshVersion += 1; // expire ghu_fault_4
        refreshBehavior = "hang";
        pauseRefreshStarted = yield* Deferred.make<void>();
        releasePausedRefresh = yield* Deferred.make<void>();
        yield* Deferred.succeed(releasePausedRefresh, undefined);
        const hungHttpFiber = yield* Effect.forkChild(
          postRefresh(afterInterruptBody.refresh_token),
        );
        yield* Deferred.await(pauseRefreshStarted);
        yield* TestClock.adjust("4 seconds");
        const hungHttpRes = yield* Fiber.join(hungHttpFiber);
        refreshBehavior = "normal";
        pauseRefreshStarted = null;
        releasePausedRefresh = null;
        expect(hungHttpRes.status).toBe(503);
        const [rowAfterHungHttp] = yield* loadSessionRow();
        expect(rowAfterHungHttp?.githubRefreshLeaseUntil).toBeNull();
        expect(rowAfterHungHttp?.revokedAt).toBeNull();

        // 5. Hung first completeGitHubRefresh attempt times out at 2s inside Effect.uninterruptible,
        // then retries after backoff and persists rotated tokens cleanly.
        hangFirstComplete = true;
        completeAttemptsStarted = 0;
        trackCompleteAttempts = true;
        const hungDbFiber = yield* Effect.forkChild(postRefresh(afterInterruptBody.refresh_token));
        yield* Queue.take(completeAttemptStarted);
        yield* TestClock.adjust("2 seconds");
        yield* advanceToNextAttempt("150 millis");
        yield* Queue.take(completeAttemptDone);
        const hungDbRes = yield* Fiber.join(hungDbFiber);
        hangFirstComplete = false;
        trackCompleteAttempts = false;
        expect(hungDbRes.status).toBe(200);
        const hungDbBody = yield* readRefreshToken(hungDbRes);

        // 6. Exhausting all persistence retries returns 503.
        refreshVersion += 1; // expire latest token
        failUpdateMode = "fail-all-after-claim";
        updateCount = 0;
        injectedFailures = 0;
        completeAttemptsStarted = 0;
        trackCompleteAttempts = true;
        const exhaustedFiber = yield* Effect.forkChild(postRefresh(hungDbBody.refresh_token));
        yield* Queue.take(completeAttemptStarted);
        yield* advanceToNextAttempt("150 millis");
        yield* advanceToNextAttempt("350 millis");
        yield* Queue.take(completeAttemptDone);
        const exhaustedRes = yield* Fiber.join(exhaustedFiber);
        trackCompleteAttempts = false;
        failUpdateMode = "none";
        expect(exhaustedRes.status).toBe(503);
        expect(injectedFailures).toBe(3);

        // 7. Persistence failure on Rejected returns 503 (not invalid_grant) without revoking.
        yield* TestClock.adjust(`${OAuthSessions.GITHUB_REFRESH_LEASE_MS + 1_000} millis`);
        refreshBehavior = "bad_refresh_token";
        failUpdateMode = "fail-all-after-claim";
        updateCount = 0;
        injectedFailures = 0;
        const failedRejectRes = yield* postRefresh(hungDbBody.refresh_token);
        refreshBehavior = "normal";
        failUpdateMode = "none";
        expect(failedRejectRes.status).toBe(503);
        const [rowAfterFailedReject] = yield* loadSessionRow();
        expect(rowAfterFailedReject?.revokedAt).toBeNull();
      }).pipe(Effect.provide(NodeServices.layer), Effect.scoped),
  );
});
