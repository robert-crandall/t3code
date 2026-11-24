import {
  RelayDpopAccessTokenScope,
  RelayEnvironmentConnectScope,
  RelayEnvironmentStatusScope,
  RelayMobileClientId,
  RelayMobileRegistrationScope,
  RelayWebClientId,
  type RelayPublicClientId,
  type RelayEnvironmentLinkChallengeRequest,
} from "@t3tools/contracts/relay";
import { encodeOAuthScope, parseAllowedOAuthScope } from "@t3tools/shared/oauthScope";
import { normalizeRelayIssuer, RelayJwtError } from "@t3tools/shared/relayJwt";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";

import * as RelayConfiguration from "../Config.ts";
import * as CloudMintSigner from "./CloudMintSigner.ts";

const LINK_CHALLENGE_TYP = "t3-link-challenge+jwt";
const ACCESS_TOKEN_TYP = "t3-relay-dpop-access+jwt";
const CLIENT_ACCESS_TOKEN_TYP = "t3-relay-access+jwt";
const CLIENT_ID_TOKEN_TYP = "JWT";
const OAUTH_STATE_TYP = "t3-oauth-state+jwt";
const OAUTH_CODE_TYP = "t3-oauth-code+jwt";
const OAUTH_DEVICE_TYP = "t3-oauth-device+jwt";
const OAUTH_REFRESH_TYP = "t3-oauth-refresh+jwt";
const LINK_CHALLENGE_KIND = "environment_link_challenge";
export const RELAY_DPOP_ACCESS_TOKEN_TTL = "30 minutes";
export const RELAY_CLIENT_ACCESS_TOKEN_TTL = "15 minutes";
export const RELAY_CLIENT_ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
export const RELAY_OAUTH_STATE_TTL = "10 minutes";
export const RELAY_OAUTH_STATE_TTL_SECONDS = 10 * 60;
export const RELAY_OAUTH_CODE_TTL = "1 minute";
export const RELAY_OAUTH_CODE_TTL_SECONDS = 60;
export const RELAY_OAUTH_DEVICE_MAX_TTL = "20 minutes";
export const RELAY_OAUTH_DEVICE_MAX_TTL_SECONDS = 20 * 60;
export const RELAY_OAUTH_REFRESH_MAX_TTL = "90 days";

const LinkChallengeClaims = Schema.Struct({
  kind: Schema.Literal(LINK_CHALLENGE_KIND),
  iss: Schema.String,
  aud: Schema.String,
  sub: Schema.String,
  jti: Schema.String,
  iat: Schema.Int,
  exp: Schema.Int,
  notificationsEnabled: Schema.Boolean,
  liveActivitiesEnabled: Schema.Boolean,
  managedTunnelsEnabled: Schema.Boolean,
});
export type LinkChallengeClaims = typeof LinkChallengeClaims.Type;

const RelayDpopAccessTokenClaims = Schema.Struct({
  iss: Schema.String,
  aud: Schema.String,
  sub: Schema.String,
  jti: Schema.String,
  iat: Schema.Int,
  exp: Schema.Int,
  client_id: Schema.Literals([RelayMobileClientId, RelayWebClientId]),
  scope: Schema.String,
  cnf: Schema.Struct({ jkt: Schema.String }),
});
export type RelayDpopAccessTokenClaims = Omit<typeof RelayDpopAccessTokenClaims.Type, "scope"> & {
  readonly scope: ReadonlyArray<RelayDpopAccessTokenScope>;
};

const RelayClientAccessTokenClaims = Schema.Struct({
  iss: Schema.String,
  aud: Schema.String,
  sub: Schema.String,
  preferred_username: Schema.String,
  email: Schema.optional(Schema.String),
  client_id: Schema.String,
  jti: Schema.String,
  iat: Schema.Int,
  exp: Schema.Int,
});
export type RelayClientAccessTokenClaims = typeof RelayClientAccessTokenClaims.Type;

const OAuthStateTokenClaims = Schema.Struct({
  iss: Schema.String,
  aud: Schema.String,
  client_id: Schema.String,
  redirect_uri: Schema.String,
  code_challenge: Schema.String,
  client_state: Schema.String,
  nonce: Schema.String,
  iat: Schema.Int,
  exp: Schema.Int,
});
export type OAuthStateTokenClaims = typeof OAuthStateTokenClaims.Type;

const OAuthCodeTokenClaims = Schema.Struct({
  iss: Schema.String,
  aud: Schema.String,
  sub: Schema.String,
  preferred_username: Schema.String,
  email: Schema.optional(Schema.String),
  enc_gh: Schema.String,
  client_id: Schema.String,
  redirect_uri: Schema.String,
  code_challenge: Schema.String,
  jti: Schema.String,
  iat: Schema.Int,
  exp: Schema.Int,
});
export type OAuthCodeTokenClaims = typeof OAuthCodeTokenClaims.Type;

const OAuthDeviceTokenClaims = Schema.Struct({
  iss: Schema.String,
  aud: Schema.String,
  client_id: Schema.String,
  github_device_code: Schema.String,
  iat: Schema.Int,
  exp: Schema.Int,
});
export type OAuthDeviceTokenClaims = typeof OAuthDeviceTokenClaims.Type;

const OAuthRefreshTokenClaims = Schema.Struct({
  iss: Schema.String,
  aud: Schema.String,
  sub: Schema.String,
  sid: Schema.String,
  client_id: Schema.String,
  jti: Schema.String,
  iat: Schema.Int,
  exp: Schema.Int,
});
export type OAuthRefreshTokenClaims = typeof OAuthRefreshTokenClaims.Type;

const allowedScopesByClientId: Record<
  RelayPublicClientId,
  ReadonlySet<RelayDpopAccessTokenScope>
> = {
  [RelayMobileClientId]: new Set([
    RelayEnvironmentConnectScope,
    RelayEnvironmentStatusScope,
    RelayMobileRegistrationScope,
  ]),
  [RelayWebClientId]: new Set([RelayEnvironmentConnectScope, RelayEnvironmentStatusScope]),
};

function resolveDpopAccessTokenScopes(input: {
  readonly clientId: RelayPublicClientId;
  readonly scope: string;
}): ReadonlyArray<RelayDpopAccessTokenScope> | null {
  return parseAllowedOAuthScope({
    value: input.scope,
    allowedScopes: allowedScopesByClientId[input.clientId],
  });
}

export class RelayTokens extends Context.Service<
  RelayTokens,
  {
    readonly resolveDpopAccessTokenScopes: typeof resolveDpopAccessTokenScopes;
    readonly issueLinkChallenge: (input: {
      readonly userId: string;
      readonly request: RelayEnvironmentLinkChallengeRequest;
      readonly jti: string;
      readonly issuedAtEpochSeconds: number;
      readonly expiresAtEpochSeconds: number;
    }) => Effect.Effect<string, RelayJwtError>;
    readonly verifyLinkChallenge: (input: {
      readonly token: string;
      readonly userId: string;
      readonly request: RelayEnvironmentLinkChallengeRequest;
    }) => Effect.Effect<LinkChallengeClaims | null>;
    readonly issueDpopAccessToken: (input: {
      readonly userId: string;
      readonly proofKeyThumbprint: string;
      readonly jti: string;
      readonly issuedAtEpochSeconds: number;
      readonly expiresAtEpochSeconds: number;
      readonly clientId: RelayPublicClientId;
      readonly scopes: ReadonlyArray<RelayDpopAccessTokenScope>;
    }) => Effect.Effect<string, RelayJwtError>;
    readonly verifyDpopAccessToken: (input: {
      readonly token: string;
    }) => Effect.Effect<RelayDpopAccessTokenClaims | null>;
    readonly issueClientAccessToken: (input: {
      readonly userId: string;
      readonly githubLogin: string;
      readonly email?: string;
      readonly clientId: string;
      readonly jti: string;
      readonly issuedAtEpochSeconds: number;
      readonly expiresAtEpochSeconds: number;
    }) => Effect.Effect<string, RelayJwtError>;
    readonly verifyClientAccessToken: (input: {
      readonly token: string;
    }) => Effect.Effect<RelayClientAccessTokenClaims | null>;
    readonly issueClientIdToken: (input: {
      readonly userId: string;
      readonly githubLogin: string;
      readonly email?: string;
      readonly clientId: string;
      readonly issuedAtEpochSeconds: number;
      readonly expiresAtEpochSeconds: number;
    }) => Effect.Effect<string, RelayJwtError>;
    readonly issueOAuthStateToken: (input: {
      readonly clientId: string;
      readonly redirectUri: string;
      readonly codeChallenge: string;
      readonly clientState: string;
      readonly nonce: string;
      readonly issuedAtEpochSeconds: number;
      readonly expiresAtEpochSeconds: number;
    }) => Effect.Effect<string, RelayJwtError>;
    readonly verifyOAuthStateToken: (input: {
      readonly token: string;
    }) => Effect.Effect<OAuthStateTokenClaims | null>;
    readonly issueOAuthCodeToken: (input: {
      readonly userId: string;
      readonly githubLogin: string;
      readonly email?: string;
      readonly encryptedGithubAccessToken: string;
      readonly clientId: string;
      readonly redirectUri: string;
      readonly codeChallenge: string;
      readonly jti: string;
      readonly issuedAtEpochSeconds: number;
      readonly expiresAtEpochSeconds: number;
    }) => Effect.Effect<string, RelayJwtError>;
    readonly verifyOAuthCodeToken: (input: {
      readonly token: string;
    }) => Effect.Effect<OAuthCodeTokenClaims | null>;
    readonly issueOAuthDeviceToken: (input: {
      readonly clientId: string;
      readonly githubDeviceCode: string;
      readonly issuedAtEpochSeconds: number;
      readonly expiresAtEpochSeconds: number;
    }) => Effect.Effect<string, RelayJwtError>;
    readonly verifyOAuthDeviceToken: (input: {
      readonly token: string;
    }) => Effect.Effect<OAuthDeviceTokenClaims | null>;
    readonly issueOAuthRefreshToken: (input: {
      readonly userId: string;
      readonly sessionId: string;
      readonly clientId: string;
      readonly jti: string;
      readonly issuedAtEpochSeconds: number;
      readonly expiresAtEpochSeconds: number;
    }) => Effect.Effect<string, RelayJwtError>;
    readonly verifyOAuthRefreshToken: (input: {
      readonly token: string;
    }) => Effect.Effect<OAuthRefreshTokenClaims | null>;
  }
>()("t3code-relay/auth/RelayTokens") {}

const make = Effect.gen(function* () {
  const config = yield* RelayConfiguration.RelayConfiguration;
  const issuer = normalizeRelayIssuer(config.relayIssuer);
  const mint = yield* CloudMintSigner.CloudMintSigner;

  const issueLinkChallenge: RelayTokens["Service"]["issueLinkChallenge"] = Effect.fn(
    "relay.tokens.issue_link_challenge",
  )(function* (input) {
    return yield* mint.sign({
      typ: LINK_CHALLENGE_TYP,
      payload: {
        kind: LINK_CHALLENGE_KIND,
        iss: issuer,
        aud: issuer,
        sub: input.userId,
        jti: input.jti,
        iat: input.issuedAtEpochSeconds,
        exp: input.expiresAtEpochSeconds,
        ...input.request,
      },
    });
  });

  const verifyLinkChallenge: RelayTokens["Service"]["verifyLinkChallenge"] = Effect.fn(
    "relay.tokens.verify_link_challenge",
  )((input) =>
    mint
      .verify(LinkChallengeClaims, {
        token: input.token,
        typ: LINK_CHALLENGE_TYP,
        issuer,
        audience: issuer,
      })
      .pipe(
        Effect.map((claims) => {
          if (
            claims.sub !== input.userId ||
            (input.request.notificationsEnabled && claims.notificationsEnabled !== true) ||
            (input.request.liveActivitiesEnabled && claims.liveActivitiesEnabled !== true) ||
            (input.request.managedTunnelsEnabled && claims.managedTunnelsEnabled !== true)
          ) {
            return null;
          }
          return claims;
        }),
        Effect.orElseSucceed(() => null),
      ),
  );

  const issueDpopAccessToken: RelayTokens["Service"]["issueDpopAccessToken"] = Effect.fn(
    "relay.tokens.issue_dpop_access_token",
  )(function* (input) {
    return yield* mint.sign({
      typ: ACCESS_TOKEN_TYP,
      payload: {
        iss: issuer,
        aud: issuer,
        sub: input.userId,
        jti: input.jti,
        iat: input.issuedAtEpochSeconds,
        exp: input.expiresAtEpochSeconds,
        client_id: input.clientId,
        scope: encodeOAuthScope(input.scopes),
        cnf: { jkt: input.proofKeyThumbprint },
      },
    });
  });

  const verifyDpopAccessToken: RelayTokens["Service"]["verifyDpopAccessToken"] = Effect.fn(
    "relay.tokens.verify_dpop_access_token",
  )((input) =>
    mint
      .verify(RelayDpopAccessTokenClaims, {
        token: input.token,
        typ: ACCESS_TOKEN_TYP,
        issuer,
        audience: issuer,
        maxTokenAge: RELAY_DPOP_ACCESS_TOKEN_TTL,
      })
      .pipe(
        Effect.tapError((error) =>
          Effect.annotateCurrentSpan(
            "relay.tokens.verification_failure",
            RelayJwtError.diagnosticCode(error),
          ),
        ),
        Effect.map((claims): RelayDpopAccessTokenClaims | null => {
          const scopes = resolveDpopAccessTokenScopes({
            clientId: claims.client_id,
            scope: claims.scope,
          });
          return scopes === null ? null : { ...claims, scope: scopes };
        }),
        Effect.orElseSucceed(() => null),
      ),
  );

  const issueClientAccessToken: RelayTokens["Service"]["issueClientAccessToken"] = Effect.fn(
    "relay.tokens.issue_client_access_token",
  )(function* (input) {
    return yield* mint.sign({
      typ: CLIENT_ACCESS_TOKEN_TYP,
      payload: {
        iss: issuer,
        aud: issuer,
        sub: input.userId,
        preferred_username: input.githubLogin,
        ...(input.email ? { email: input.email } : {}),
        client_id: input.clientId,
        jti: input.jti,
        iat: input.issuedAtEpochSeconds,
        exp: input.expiresAtEpochSeconds,
      },
    });
  });

  const verifyClientAccessToken: RelayTokens["Service"]["verifyClientAccessToken"] = Effect.fn(
    "relay.tokens.verify_client_access_token",
  )((input) =>
    mint
      .verify(RelayClientAccessTokenClaims, {
        token: input.token,
        typ: CLIENT_ACCESS_TOKEN_TYP,
        issuer,
        audience: issuer,
        maxTokenAge: RELAY_CLIENT_ACCESS_TOKEN_TTL,
      })
      .pipe(
        Effect.tapError((error) =>
          Effect.annotateCurrentSpan(
            "relay.tokens.client_access_verification_failure",
            RelayJwtError.diagnosticCode(error),
          ),
        ),
        Effect.orElseSucceed(() => null),
      ),
  );

  const issueClientIdToken: RelayTokens["Service"]["issueClientIdToken"] = Effect.fn(
    "relay.tokens.issue_client_id_token",
  )(function* (input) {
    return yield* mint.sign({
      typ: CLIENT_ID_TOKEN_TYP,
      payload: {
        iss: issuer,
        aud: input.clientId,
        sub: input.userId,
        preferred_username: input.githubLogin,
        ...(input.email ? { email: input.email } : {}),
        iat: input.issuedAtEpochSeconds,
        exp: input.expiresAtEpochSeconds,
      },
    });
  });

  const issueOAuthStateToken: RelayTokens["Service"]["issueOAuthStateToken"] = Effect.fn(
    "relay.tokens.issue_oauth_state_token",
  )(function* (input) {
    return yield* mint.sign({
      typ: OAUTH_STATE_TYP,
      payload: {
        iss: issuer,
        aud: issuer,
        client_id: input.clientId,
        redirect_uri: input.redirectUri,
        code_challenge: input.codeChallenge,
        client_state: input.clientState,
        nonce: input.nonce,
        iat: input.issuedAtEpochSeconds,
        exp: input.expiresAtEpochSeconds,
      },
    });
  });

  const verifyOAuthStateToken: RelayTokens["Service"]["verifyOAuthStateToken"] = Effect.fn(
    "relay.tokens.verify_oauth_state_token",
  )((input) =>
    mint
      .verify(OAuthStateTokenClaims, {
        token: input.token,
        typ: OAUTH_STATE_TYP,
        issuer,
        audience: issuer,
        maxTokenAge: RELAY_OAUTH_STATE_TTL,
      })
      .pipe(Effect.orElseSucceed(() => null)),
  );

  const issueOAuthCodeToken: RelayTokens["Service"]["issueOAuthCodeToken"] = Effect.fn(
    "relay.tokens.issue_oauth_code_token",
  )(function* (input) {
    return yield* mint.sign({
      typ: OAUTH_CODE_TYP,
      payload: {
        iss: issuer,
        aud: issuer,
        sub: input.userId,
        preferred_username: input.githubLogin,
        ...(input.email ? { email: input.email } : {}),
        enc_gh: input.encryptedGithubAccessToken,
        client_id: input.clientId,
        redirect_uri: input.redirectUri,
        code_challenge: input.codeChallenge,
        jti: input.jti,
        iat: input.issuedAtEpochSeconds,
        exp: input.expiresAtEpochSeconds,
      },
    });
  });

  const verifyOAuthCodeToken: RelayTokens["Service"]["verifyOAuthCodeToken"] = Effect.fn(
    "relay.tokens.verify_oauth_code_token",
  )((input) =>
    mint
      .verify(OAuthCodeTokenClaims, {
        token: input.token,
        typ: OAUTH_CODE_TYP,
        issuer,
        audience: issuer,
        maxTokenAge: RELAY_OAUTH_CODE_TTL,
      })
      .pipe(Effect.orElseSucceed(() => null)),
  );

  const issueOAuthDeviceToken: RelayTokens["Service"]["issueOAuthDeviceToken"] = Effect.fn(
    "relay.tokens.issue_oauth_device_token",
  )(function* (input) {
    return yield* mint.sign({
      typ: OAUTH_DEVICE_TYP,
      payload: {
        iss: issuer,
        aud: issuer,
        client_id: input.clientId,
        github_device_code: input.githubDeviceCode,
        iat: input.issuedAtEpochSeconds,
        exp: input.expiresAtEpochSeconds,
      },
    });
  });

  const verifyOAuthDeviceToken: RelayTokens["Service"]["verifyOAuthDeviceToken"] = Effect.fn(
    "relay.tokens.verify_oauth_device_token",
  )((input) =>
    mint
      .verify(OAuthDeviceTokenClaims, {
        token: input.token,
        typ: OAUTH_DEVICE_TYP,
        issuer,
        audience: issuer,
        maxTokenAge: RELAY_OAUTH_DEVICE_MAX_TTL,
      })
      .pipe(Effect.orElseSucceed(() => null)),
  );

  const issueOAuthRefreshToken: RelayTokens["Service"]["issueOAuthRefreshToken"] = Effect.fn(
    "relay.tokens.issue_oauth_refresh_token",
  )(function* (input) {
    return yield* mint.sign({
      typ: OAUTH_REFRESH_TYP,
      payload: {
        iss: issuer,
        aud: issuer,
        sub: input.userId,
        sid: input.sessionId,
        client_id: input.clientId,
        jti: input.jti,
        iat: input.issuedAtEpochSeconds,
        exp: input.expiresAtEpochSeconds,
      },
    });
  });

  const verifyOAuthRefreshToken: RelayTokens["Service"]["verifyOAuthRefreshToken"] = Effect.fn(
    "relay.tokens.verify_oauth_refresh_token",
  )((input) =>
    mint
      .verify(OAuthRefreshTokenClaims, {
        token: input.token,
        typ: OAUTH_REFRESH_TYP,
        issuer,
        audience: issuer,
        maxTokenAge: RELAY_OAUTH_REFRESH_MAX_TTL,
      })
      .pipe(Effect.orElseSucceed(() => null)),
  );

  return RelayTokens.of({
    resolveDpopAccessTokenScopes,
    issueLinkChallenge,
    verifyLinkChallenge,
    issueDpopAccessToken,
    verifyDpopAccessToken,
    issueClientAccessToken,
    verifyClientAccessToken,
    issueClientIdToken,
    issueOAuthStateToken,
    verifyOAuthStateToken,
    issueOAuthCodeToken,
    verifyOAuthCodeToken,
    issueOAuthDeviceToken,
    verifyOAuthDeviceToken,
    issueOAuthRefreshToken,
    verifyOAuthRefreshToken,
  });
});

export const layer = Layer.effect(RelayTokens, make);
