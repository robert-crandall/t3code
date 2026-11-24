// @effect-diagnostics-next-line nodeBuiltinImport:off -- Effect's Crypto has no generateKeyPairSync.
import * as NodeCrypto from "node:crypto";

import { describe, expect, it } from "@effect/vitest";
import { signRelayJwt } from "@t3tools/shared/relayJwt";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Signature from "effect/crypto/Signature";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as TestClock from "effect/testing/TestClock";

import * as CloudMintSigner from "./CloudMintSigner.ts";
import * as RelayConfiguration from "../Config.ts";
import * as RelayTokens from "./RelayTokens.ts";

const keyPair = NodeCrypto.generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});

const config = RelayConfiguration.RelayConfiguration.of({
  relayIssuer: "https://relay.example.test/",
  apns: {
    environment: "sandbox",
    teamId: "team-id",
    keyId: "key-id",
    privateKey: Redacted.make("private-key"),
    bundleId: "com.t3tools.t3code.dev",
  },
  apnsDeliveryJobSigningSecret: Redacted.make("job-secret"),
  githubOAuth: {
    clientId: "github-client-id",
    clientSecret: Redacted.make("github-client-secret"),
    allowedOrgs: ["robert-crandall-org"],
  },
  cloudMintPrivateKey: Redacted.make(keyPair.privateKey),
  cloudMintPublicKey: keyPair.publicKey,
  managedEndpointBaseDomain: undefined,
  managedEndpointNamespace: undefined,
});

const layer = RelayTokens.layer.pipe(
  Layer.provide(CloudMintSigner.layer),
  Layer.provide(RelayConfiguration.layer(config)),
  Layer.provideMerge(Signature.layerWebCrypto),
  Layer.provide(SecureRandom.layerWebCrypto),
);

describe("RelayTokens", () => {
  it.effect("issues a user-bound environment link challenge", () =>
    Effect.gen(function* () {
      const relayTokens = yield* RelayTokens.RelayTokens;
      const token = yield* relayTokens.issueLinkChallenge({
        userId: "user_123",
        request: {
          notificationsEnabled: true,
          liveActivitiesEnabled: true,
          managedTunnelsEnabled: true,
        },
        jti: "challenge-1",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 200,
      });
      yield* TestClock.setTime(150_000);

      expect(
        yield* relayTokens.verifyLinkChallenge({
          token,
          userId: "user_123",
          request: {
            notificationsEnabled: true,
            liveActivitiesEnabled: true,
            managedTunnelsEnabled: true,
          },
        }),
      ).toMatchObject({ sub: "user_123", jti: "challenge-1" });
      expect(
        yield* relayTokens.verifyLinkChallenge({
          token,
          userId: "attacker",
          request: {
            notificationsEnabled: true,
            liveActivitiesEnabled: true,
            managedTunnelsEnabled: true,
          },
        }),
      ).toBeNull();
    }).pipe(Effect.provide(layer)),
  );

  it.effect("issues and verifies DPoP access tokens bound to one proof-key thumbprint", () =>
    Effect.gen(function* () {
      const relayTokens = yield* RelayTokens.RelayTokens;
      const token = yield* relayTokens.issueDpopAccessToken({
        userId: "user_123",
        proofKeyThumbprint: "proof-key-thumbprint",
        jti: "access-token-1",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 1_900,
        clientId: "t3-mobile",
        scopes: ["environment:connect", "environment:status", "mobile:registration"],
      });

      yield* TestClock.setTime(700_000);
      expect(yield* relayTokens.verifyDpopAccessToken({ token })).toMatchObject({
        sub: "user_123",
        cnf: { jkt: "proof-key-thumbprint" },
        client_id: "t3-mobile",
        scope: ["environment:connect", "environment:status", "mobile:registration"],
      });
      yield* TestClock.setTime(1_961_000);
      expect(yield* relayTokens.verifyDpopAccessToken({ token })).toBeNull();
    }).pipe(Effect.provide(layer)),
  );

  it.effect("issues tunnel-only DPoP access tokens to web public clients", () =>
    Effect.gen(function* () {
      const relayTokens = yield* RelayTokens.RelayTokens;
      const token = yield* relayTokens.issueDpopAccessToken({
        userId: "user_123",
        proofKeyThumbprint: "web-proof-key-thumbprint",
        jti: "web-access-token-1",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 200,
        clientId: "t3-web",
        scopes: ["environment:connect", "environment:status"],
      });

      yield* TestClock.setTime(150_000);
      expect(yield* relayTokens.verifyDpopAccessToken({ token })).toMatchObject({
        client_id: "t3-web",
        scope: ["environment:connect", "environment:status"],
        cnf: { jkt: "web-proof-key-thumbprint" },
      });
    }).pipe(Effect.provide(layer)),
  );

  it.effect("rejects signed DPoP tokens whose scope is outside the relay policy", () =>
    Effect.gen(function* () {
      const relayTokens = yield* RelayTokens.RelayTokens;
      const token = yield* signRelayJwt({
        privateKey: keyPair.privateKey,
        typ: "t3-relay-dpop-access+jwt",
        payload: {
          iss: "https://relay.example.test",
          aud: "https://relay.example.test",
          sub: "user_123",
          jti: "access-token-invalid-scope",
          iat: 100,
          exp: 200,
          client_id: "t3-mobile",
          scope: "environment:admin",
          cnf: { jkt: "proof-key-thumbprint" },
        },
      });

      yield* TestClock.setTime(150_000);
      expect(yield* relayTokens.verifyDpopAccessToken({ token })).toBeNull();
    }).pipe(Effect.provide(layer)),
  );

  it.effect("rejects mobile registration scope on a web public client token", () =>
    Effect.gen(function* () {
      const relayTokens = yield* RelayTokens.RelayTokens;
      const token = yield* signRelayJwt({
        privateKey: keyPair.privateKey,
        typ: "t3-relay-dpop-access+jwt",
        payload: {
          iss: "https://relay.example.test",
          aud: "https://relay.example.test",
          sub: "user_123",
          jti: "web-token-invalid-mobile-scope",
          iat: 100,
          exp: 200,
          client_id: "t3-web",
          scope: "environment:connect mobile:registration",
          cnf: { jkt: "proof-key-thumbprint" },
        },
      });

      yield* TestClock.setTime(150_000);
      expect(yield* relayTokens.verifyDpopAccessToken({ token })).toBeNull();
    }).pipe(Effect.provide(layer)),
  );

  it.effect("issues and verifies client access tokens and enforces strict JWT typ isolation", () =>
    Effect.gen(function* () {
      const relayTokens = yield* RelayTokens.RelayTokens;
      const accessToken = yield* relayTokens.issueClientAccessToken({
        userId: "github:42",
        githubLogin: "octocat",
        clientId: "t3-cli",
        jti: "client-access-1",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 1_000,
      });
      const idToken = yield* relayTokens.issueClientIdToken({
        userId: "github:42",
        githubLogin: "octocat",
        email: "octocat@example.com",
        clientId: "t3-cli",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 1_000,
      });
      const stateToken = yield* relayTokens.issueOAuthStateToken({
        clientId: "t3-cli",
        redirectUri: "http://127.0.0.1:4321/callback",
        clientState: "client-state-1",
        codeChallenge: "challenge-1",
        nonce: "nonce-1",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 700,
      });
      const codeToken = yield* relayTokens.issueOAuthCodeToken({
        userId: "github:42",
        githubLogin: "octocat",
        email: "octocat@example.com",
        clientId: "t3-cli",
        redirectUri: "http://127.0.0.1:4321/callback",
        codeChallenge: "challenge-1",
        encryptedGithubAccessToken: "v1.nonce.cipher",
        jti: "code-jti-1",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 160,
      });
      const deviceToken = yield* relayTokens.issueOAuthDeviceToken({
        clientId: "t3-cli",
        githubDeviceCode: "gh-device-1",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 700,
      });
      const refreshToken = yield* relayTokens.issueOAuthRefreshToken({
        userId: "github:42",
        sessionId: "sess-1",
        clientId: "t3-cli",
        jti: "refresh-jti-1",
        issuedAtEpochSeconds: 100,
        expiresAtEpochSeconds: 1_000,
      });

      yield* TestClock.setTime(150_000);

      expect(yield* relayTokens.verifyClientAccessToken({ token: accessToken })).toMatchObject({
        sub: "github:42",
        preferred_username: "octocat",
        client_id: "t3-cli",
        jti: "client-access-1",
      });
      expect(yield* relayTokens.verifyOAuthStateToken({ token: stateToken })).toMatchObject({
        nonce: "nonce-1",
        client_state: "client-state-1",
      });
      expect(yield* relayTokens.verifyOAuthCodeToken({ token: codeToken })).toMatchObject({
        sub: "github:42",
        jti: "code-jti-1",
        enc_gh: "v1.nonce.cipher",
      });
      expect(yield* relayTokens.verifyOAuthDeviceToken({ token: deviceToken })).toMatchObject({
        github_device_code: "gh-device-1",
      });
      expect(yield* relayTokens.verifyOAuthRefreshToken({ token: refreshToken })).toMatchObject({
        sid: "sess-1",
        client_id: "t3-cli",
        jti: "refresh-jti-1",
      });

      // Cross-purpose tokens must never pass another verifier.
      for (const wrongToken of [idToken, stateToken, codeToken, deviceToken, refreshToken]) {
        expect(yield* relayTokens.verifyClientAccessToken({ token: wrongToken })).toBeNull();
      }
      expect(yield* relayTokens.verifyOAuthCodeToken({ token: accessToken })).toBeNull();
      expect(yield* relayTokens.verifyOAuthStateToken({ token: codeToken })).toBeNull();
      expect(yield* relayTokens.verifyOAuthDeviceToken({ token: stateToken })).toBeNull();
      expect(yield* relayTokens.verifyOAuthRefreshToken({ token: accessToken })).toBeNull();

      // Expired access token is rejected.
      yield* TestClock.setTime(1_061_000);
      expect(yield* relayTokens.verifyClientAccessToken({ token: accessToken })).toBeNull();
    }).pipe(Effect.provide(layer)),
  );
});
