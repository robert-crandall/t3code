// @effect-diagnostics-next-line nodeBuiltinImport:off -- Effect's Crypto has no createHash sync helper.
import * as NodeCrypto from "node:crypto";

import * as NodeServices from "@effect/platform-node/NodeServices";
import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as HttpRouter from "effect/http/HttpRouter";
import * as HttpServer from "effect/http/HttpServer";
import * as Layer from "effect/Layer";

import * as GitHubOAuth from "./GitHubOAuth.ts";
import * as RelayTokens from "./RelayTokens.ts";
import { setupPgliteOAuthTest } from "./testSupport.ts";

function pkceChallenge(verifier: string): string {
  return NodeCrypto.createHash("sha256").update(verifier).digest("base64url");
}

function makeTestApp(options: {
  allowedOrgs?: ReadonlyArray<string>;
  failUpdate?: () => boolean;
  onGitHubRequest: (url: string, method: string, body: string) => Response;
}) {
  return Effect.gen(function* () {
    const { layerAuth } = yield* setupPgliteOAuthTest({
      ...(options.allowedOrgs ? { allowedOrgs: options.allowedOrgs } : {}),
      ...(options.failUpdate ? { failUpdate: options.failUpdate } : {}),
    });

    const mockHttpClient = HttpClient.make((request) =>
      Effect.sync(() => {
        const bodyText =
          request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "";
        const response = options.onGitHubRequest(request.url, request.method, bodyText);
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
});
