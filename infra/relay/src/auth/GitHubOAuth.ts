import { normalizeRelayIssuer } from "@t3tools/shared/relayJwt";
import * as Digest from "effect/crypto/Digest";
import * as Mac from "effect/crypto/Mac";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import type * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as HttpRouter from "effect/http/HttpRouter";
import * as HttpServerRequest from "effect/http/HttpServerRequest";
import * as HttpServerResponse from "effect/http/HttpServerResponse";

import * as RelayConfiguration from "../Config.ts";
import * as OAuthSessions from "./OAuthSessions.ts";
import * as RelayTokens from "./RelayTokens.ts";

export const CLI_OAUTH_CLIENT_ID = "t3-cli";
export const DESKTOP_OAUTH_CLIENT_ID = "t3-desktop";
export const MOBILE_OAUTH_CLIENT_ID = "t3-mobile";
const SUPPORTED_OAUTH_CLIENT_IDS = new Set<string>([
  CLI_OAUTH_CLIENT_ID,
  DESKTOP_OAUTH_CLIENT_ID,
  MOBILE_OAUTH_CLIENT_ID,
]);
const ALLOWED_MOBILE_REDIRECT_URI_PATTERN =
  /^(t3code|t3code-dev|t3code-preview|t3code-private):\/\/oauth\/callback$/;
const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const OAUTH_NONCE_COOKIE = "__Host-t3_oauth_nonce";
const DEFAULT_GITHUB_OAUTH_BASE_URL = "https://github.com";
const DEFAULT_GITHUB_API_BASE_URL = "https://api.github.com";
const GITHUB_SCOPES = "read:org user:email";
// Stay under Api.ts's 9s RELAY_REQUEST_DEADLINE_MS with headroom for DB and signing.
const GITHUB_REQUEST_TIMEOUT = Duration.seconds(7);
const MAX_OAUTH_FORM_BODY_BYTES = 16_384;
const GITHUB_USER_AGENT = "t3code-relay";

const NO_STORE_HEADERS = {
  "cache-control": "no-store",
  pragma: "no-cache",
} as const;

const GitHubTokenExchangeResponse = Schema.Struct({
  access_token: Schema.optional(Schema.String),
  error: Schema.optional(Schema.String),
  error_description: Schema.optional(Schema.String),
});

const GitHubDeviceCodeResponse = Schema.Struct({
  device_code: Schema.String,
  user_code: Schema.String,
  verification_uri: Schema.String,
  verification_uri_complete: Schema.optional(Schema.String),
  expires_in: Schema.Number,
  interval: Schema.optional(Schema.Number),
});

const GitHubUserResponse = Schema.Struct({
  id: Schema.Number,
  login: Schema.String,
  email: Schema.NullOr(Schema.String),
});

const GitHubUserEmailsResponse = Schema.Array(
  Schema.Struct({
    email: Schema.String,
    primary: Schema.Boolean,
    verified: Schema.Boolean,
  }),
);

const GitHubOrgMembershipResponse = Schema.Struct({
  state: Schema.String,
});

const decodeGitHubTokenExchange = HttpClientResponse.schemaBodyJson(GitHubTokenExchangeResponse);
const decodeGitHubDeviceCode = HttpClientResponse.schemaBodyJson(GitHubDeviceCodeResponse);
const decodeGitHubUser = HttpClientResponse.schemaBodyJson(GitHubUserResponse);
const decodeGitHubUserEmails = HttpClientResponse.schemaBodyJson(GitHubUserEmailsResponse);
const decodeGitHubOrgMembership = HttpClientResponse.schemaBodyJson(GitHubOrgMembershipResponse);

const textEncoder = new TextEncoder();

function constantTimeEqual(left: string, right: string): boolean {
  return Mac.timingSafeEqual(textEncoder.encode(left), textEncoder.encode(right));
}

export function isSupportedOAuthClientId(clientId: string): boolean {
  return SUPPORTED_OAUTH_CLIENT_IDS.has(clientId);
}

export function isAllowedClientRedirectUri(clientId: string, redirectUri: string): boolean {
  if (clientId === MOBILE_OAUTH_CLIENT_ID) {
    return ALLOWED_MOBILE_REDIRECT_URI_PATTERN.test(redirectUri);
  }
  if (clientId !== CLI_OAUTH_CLIENT_ID && clientId !== DESKTOP_OAUTH_CLIENT_ID) {
    return false;
  }
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return false;
  }
  if (
    parsed.protocol !== "http:" ||
    parsed.hostname !== "127.0.0.1" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/callback" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    !/^\d+$/.test(parsed.port)
  ) {
    return false;
  }
  const port = Number(parsed.port);
  return Number.isInteger(port) && port >= 1 && port <= 65_535;
}

function isValidCodeChallenge(value: string): boolean {
  return value.length >= 43 && value.length <= 128 && /^[A-Za-z0-9_-]+$/.test(value);
}

function isValidCodeVerifier(value: string): boolean {
  return value.length >= 43 && value.length <= 128 && /^[A-Za-z0-9._~-]+$/.test(value);
}

function makeNonceCookieHeader(value: string, maxAgeSeconds: number): string {
  return `${OAUTH_NONCE_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

function oauthJsonResponse(
  body: unknown,
  status = 200,
  extraHeaders?: Readonly<Record<string, string>>,
) {
  return HttpServerResponse.jsonUnsafe(body, {
    status,
    headers: {
      ...NO_STORE_HEADERS,
      ...extraHeaders,
    },
  });
}

function oauthErrorResponse(error: string, errorDescription: string, status = 400) {
  return oauthJsonResponse(
    {
      error,
      error_description: errorDescription,
    },
    status,
  );
}

function redirectResponse(location: string, extraHeaders?: Readonly<Record<string, string>>) {
  return HttpServerResponse.empty({
    status: 302,
    headers: {
      ...NO_STORE_HEADERS,
      location,
      ...extraHeaders,
    },
  });
}

function appendRedirectParams(
  redirectUri: string,
  params: Readonly<Record<string, string>>,
): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

class OAuthBodyTooLarge extends Schema.TaggedError<OAuthBodyTooLarge>()("OAuthBodyTooLarge", {}) {}

const isOAuthBodyTooLarge = Schema.is(OAuthBodyTooLarge);
const textDecoder = new TextDecoder();

const parseFormParams = Effect.fn("relay.oauth.parse_body")(function* (
  request: HttpServerRequest.HttpServerRequest,
) {
  if (request.source instanceof Request && request.source.body === null) {
    return Result.succeed(new URLSearchParams());
  }
  const chunks: Array<Uint8Array> = [];
  let total = 0;
  const readResult = yield* request.stream.pipe(
    Stream.runForEach((chunk) => {
      total += chunk.length;
      if (total > MAX_OAUTH_FORM_BODY_BYTES) {
        return Effect.fail(new OAuthBodyTooLarge());
      }
      chunks.push(chunk);
      return Effect.void;
    }),
    Effect.result,
  );
  if (readResult._tag === "Failure") {
    return Result.fail(
      isOAuthBodyTooLarge(readResult.failure)
        ? oauthErrorResponse("invalid_request", "Request body is too large.", 413)
        : oauthErrorResponse("invalid_request", "Could not read request body.", 400),
    );
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return Result.succeed(new URLSearchParams(textDecoder.decode(body)));
});

function githubOAuthUrls(config: RelayConfiguration.GitHubOAuthSettings) {
  return {
    oauthBaseUrl: (config.oauthBaseUrl ?? DEFAULT_GITHUB_OAUTH_BASE_URL).replace(/\/+$/, ""),
    apiBaseUrl: (config.apiBaseUrl ?? DEFAULT_GITHUB_API_BASE_URL).replace(/\/+$/, ""),
  };
}

class GitHubOrgMembershipDenied extends Schema.TaggedError<GitHubOrgMembershipDenied>()(
  "GitHubOrgMembershipDenied",
  {},
) {}

class GitHubUpstreamError extends Schema.TaggedError<GitHubUpstreamError>()("GitHubUpstreamError", {
  stage: Schema.String,
  cause: Schema.Defect(),
}) {}

const makeGitHubApiHeaders = (githubAccessToken: string) =>
  ({
    accept: "application/vnd.github+json",
    authorization: `Bearer ${githubAccessToken}`,
    "x-github-api-version": "2022-11-28",
    "user-agent": GITHUB_USER_AGENT,
  }) as const;

const verifyGitHubOrgMembership = Effect.fn("relay.oauth.verify_github_org_membership")(
  function* (input: {
    readonly githubAccessToken: string;
    readonly githubOAuth: RelayConfiguration.GitHubOAuthSettings;
  }) {
    const allowedOrgs = input.githubOAuth.allowedOrgs
      .map((org) => org.trim())
      .filter((org) => org.length > 0);
    if (allowedOrgs.length === 0) {
      return yield* new GitHubOrgMembershipDenied();
    }

    const { apiBaseUrl } = githubOAuthUrls(input.githubOAuth);
    const httpClient = yield* HttpClient.HttpClient;
    const githubApiHeaders = makeGitHubApiHeaders(input.githubAccessToken);

    const checkOrgs = Effect.gen(function* () {
      let lastUpstreamError: GitHubUpstreamError | undefined;
      for (const org of allowedOrgs) {
        const membershipResponse = yield* HttpClientRequest.get(
          `${apiBaseUrl}/user/memberships/orgs/${encodeURIComponent(org)}`,
        ).pipe(
          HttpClientRequest.setHeaders(githubApiHeaders),
          httpClient.execute,
          Effect.mapError((cause) => new GitHubUpstreamError({ stage: "org-membership", cause })),
          Effect.result,
        );
        if (membershipResponse._tag === "Failure") {
          lastUpstreamError = membershipResponse.failure;
          continue;
        }
        if (membershipResponse.success.status === 200) {
          const membership = yield* decodeGitHubOrgMembership(membershipResponse.success).pipe(
            Effect.mapError(
              (cause) => new GitHubUpstreamError({ stage: "org-membership-decode", cause }),
            ),
            Effect.result,
          );
          if (membership._tag === "Failure") {
            lastUpstreamError = membership.failure;
            continue;
          }
          if (membership.success.state === "active") {
            return;
          }
        } else if (membershipResponse.success.status === 401) {
          return yield* new GitHubOrgMembershipDenied();
        } else if (
          membershipResponse.success.status === 403 ||
          membershipResponse.success.status === 429 ||
          membershipResponse.success.status >= 500
        ) {
          lastUpstreamError = new GitHubUpstreamError({
            stage: "org-membership",
            cause: `GitHub org membership check returned HTTP ${membershipResponse.success.status}`,
          });
        }
      }

      if (lastUpstreamError !== undefined) {
        return yield* lastUpstreamError;
      }
      return yield* new GitHubOrgMembershipDenied();
    });

    return yield* checkOrgs.pipe(
      Effect.timeout(GITHUB_REQUEST_TIMEOUT),
      Effect.catchTags({
        TimeoutError: (cause) =>
          Effect.fail(new GitHubUpstreamError({ stage: "org-membership-timeout", cause })),
      }),
    );
  },
);

const fetchGitHubIdentityAndAuthorizeOrg = Effect.fn("relay.oauth.verify_github_identity")(
  function* (input: {
    readonly githubAccessToken: string;
    readonly githubOAuth: RelayConfiguration.GitHubOAuthSettings;
  }) {
    yield* verifyGitHubOrgMembership(input);

    const { apiBaseUrl } = githubOAuthUrls(input.githubOAuth);
    const httpClient = yield* HttpClient.HttpClient;
    const githubApiHeaders = makeGitHubApiHeaders(input.githubAccessToken);

    const userResponse = yield* HttpClientRequest.get(`${apiBaseUrl}/user`).pipe(
      HttpClientRequest.setHeaders(githubApiHeaders),
      httpClient.execute,
      Effect.timeout(GITHUB_REQUEST_TIMEOUT),
      Effect.mapError((cause) => new GitHubUpstreamError({ stage: "user", cause })),
    );
    if (userResponse.status !== 200) {
      return yield* new GitHubUpstreamError({
        stage: "user",
        cause: `GitHub /user returned HTTP ${userResponse.status}`,
      });
    }
    const user = yield* decodeGitHubUser(userResponse).pipe(
      Effect.mapError((cause) => new GitHubUpstreamError({ stage: "user-decode", cause })),
    );

    let email: string | undefined =
      user.email && user.email.trim().length > 0 ? user.email.trim() : undefined;
    if (!email) {
      const emailsResponse = yield* HttpClientRequest.get(`${apiBaseUrl}/user/emails`).pipe(
        HttpClientRequest.setHeaders(githubApiHeaders),
        httpClient.execute,
        Effect.timeout(GITHUB_REQUEST_TIMEOUT),
        Effect.option,
      );
      if (Option.isSome(emailsResponse) && emailsResponse.value.status === 200) {
        const emails = yield* decodeGitHubUserEmails(emailsResponse.value).pipe(Effect.option);
        if (Option.isSome(emails)) {
          const preferred =
            emails.value.find((entry) => entry.primary && entry.verified) ??
            emails.value.find((entry) => entry.verified);
          if (preferred && preferred.email.trim().length > 0) {
            email = preferred.email.trim();
          }
        }
      }
    }

    return {
      userId: `github:${user.id}`,
      githubLogin: user.login,
      ...(email ? { email } : {}),
    };
  },
);

const issueTokenResponse = Effect.fn("relay.oauth.issue_token_response")(function* (input: {
  readonly userId: string;
  readonly githubLogin: string;
  readonly email?: string;
  readonly clientId: string;
  readonly refreshToken: string;
}) {
  const relayTokens = yield* RelayTokens.RelayTokens;
  const random = yield* SecureRandom.SecureRandom;
  const now = yield* DateTime.now;
  const issuedAtEpochSeconds = Math.floor(now.epochMilliseconds / 1_000);
  const expiresAtEpochSeconds =
    issuedAtEpochSeconds + RelayTokens.RELAY_CLIENT_ACCESS_TOKEN_TTL_SECONDS;
  const jti = yield* random.uuidV4();

  const accessToken = yield* relayTokens.issueClientAccessToken({
    userId: input.userId,
    githubLogin: input.githubLogin,
    ...(input.email ? { email: input.email } : {}),
    clientId: input.clientId,
    jti,
    issuedAtEpochSeconds,
    expiresAtEpochSeconds,
  });
  const idToken = yield* relayTokens.issueClientIdToken({
    userId: input.userId,
    githubLogin: input.githubLogin,
    ...(input.email ? { email: input.email } : {}),
    clientId: input.clientId,
    issuedAtEpochSeconds,
    expiresAtEpochSeconds,
  });

  return oauthJsonResponse({
    access_token: accessToken,
    id_token: idToken,
    refresh_token: input.refreshToken,
    token_type: "Bearer",
    expires_in: RelayTokens.RELAY_CLIENT_ACCESS_TOKEN_TTL_SECONDS,
  });
});

const handleAuthorize = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const config = yield* RelayConfiguration.RelayConfiguration;
  const relayTokens = yield* RelayTokens.RelayTokens;
  const random = yield* SecureRandom.SecureRandom;
  const now = yield* DateTime.now;

  const requestUrl = HttpServerRequest.toURL(request);
  if (Option.isNone(requestUrl)) {
    return oauthErrorResponse("invalid_request", "Invalid authorization request URL.");
  }
  const search = requestUrl.value.searchParams;
  const responseType = search.get("response_type") ?? "";
  const clientId = search.get("client_id") ?? "";
  const redirectUri = search.get("redirect_uri") ?? "";
  const codeChallenge = search.get("code_challenge") ?? "";
  const codeChallengeMethod = search.get("code_challenge_method") ?? "";
  const clientState = search.get("state") ?? "";

  if (!isSupportedOAuthClientId(clientId)) {
    return oauthErrorResponse("invalid_client", "Unsupported OAuth client_id.");
  }
  if (!isAllowedClientRedirectUri(clientId, redirectUri)) {
    return oauthErrorResponse("invalid_request", "redirect_uri is not allowed for this client_id.");
  }
  if (responseType !== "code") {
    return redirectResponse(
      appendRedirectParams(redirectUri, {
        error: "unsupported_response_type",
        ...(clientState ? { state: clientState } : {}),
      }),
    );
  }
  if (codeChallengeMethod !== "S256" || !isValidCodeChallenge(codeChallenge)) {
    return redirectResponse(
      appendRedirectParams(redirectUri, {
        error: "invalid_request",
        error_description: "PKCE S256 code_challenge is required.",
        ...(clientState ? { state: clientState } : {}),
      }),
    );
  }
  if (clientState.length === 0 || clientState.length > 512) {
    return redirectResponse(
      appendRedirectParams(redirectUri, {
        error: "invalid_request",
        error_description: "A non-empty state parameter is required.",
      }),
    );
  }

  const nonceBytes = yield* random.randomBytes(16);
  const nonce = Base64Url.encode(nonceBytes);
  const issuedAtEpochSeconds = Math.floor(now.epochMilliseconds / 1_000);
  const expiresAtEpochSeconds = issuedAtEpochSeconds + RelayTokens.RELAY_OAUTH_STATE_TTL_SECONDS;
  const stateToken = yield* relayTokens
    .issueOAuthStateToken({
      clientId,
      redirectUri,
      codeChallenge,
      clientState,
      nonce,
      issuedAtEpochSeconds,
      expiresAtEpochSeconds,
    })
    .pipe(Effect.orDie);

  const issuer = normalizeRelayIssuer(config.relayIssuer);
  const { oauthBaseUrl } = githubOAuthUrls(config.githubOAuth);
  const githubAuthorizeUrl = new URL(`${oauthBaseUrl}/login/oauth/authorize`);
  githubAuthorizeUrl.searchParams.set("client_id", config.githubOAuth.clientId);
  githubAuthorizeUrl.searchParams.set("redirect_uri", `${issuer}/v1/auth/github/callback`);
  githubAuthorizeUrl.searchParams.set("scope", GITHUB_SCOPES);
  githubAuthorizeUrl.searchParams.set("state", stateToken);

  return redirectResponse(githubAuthorizeUrl.toString(), {
    "set-cookie": makeNonceCookieHeader(nonce, RelayTokens.RELAY_OAUTH_STATE_TTL_SECONDS),
  });
}).pipe(Effect.withSpan("relay.oauth.authorize"));

const handleGitHubCallback = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const config = yield* RelayConfiguration.RelayConfiguration;
  const relayTokens = yield* RelayTokens.RelayTokens;
  const sessions = yield* OAuthSessions.OAuthSessions;
  const httpClient = yield* HttpClient.HttpClient;
  const random = yield* SecureRandom.SecureRandom;
  const now = yield* DateTime.now;
  const clearCookie = { "set-cookie": makeNonceCookieHeader("", 0) } as const;

  const requestUrl = HttpServerRequest.toURL(request);
  if (Option.isNone(requestUrl)) {
    return HttpServerResponse.text("Invalid callback request.", {
      status: 400,
      headers: { ...NO_STORE_HEADERS, ...clearCookie },
    });
  }
  const search = requestUrl.value.searchParams;
  const stateToken = search.get("state") ?? "";
  const githubCode = search.get("code") ?? "";
  const githubError = search.get("error") ?? "";
  const cookieNonce = request.cookies[OAUTH_NONCE_COOKIE];

  if (!stateToken || !cookieNonce) {
    return HttpServerResponse.text("Invalid or expired authorization session.", {
      status: 400,
      headers: { ...NO_STORE_HEADERS, ...clearCookie },
    });
  }

  const stateClaims = yield* relayTokens.verifyOAuthStateToken({ token: stateToken });
  if (
    !stateClaims ||
    !constantTimeEqual(stateClaims.nonce, cookieNonce) ||
    !isAllowedClientRedirectUri(stateClaims.client_id, stateClaims.redirect_uri)
  ) {
    return HttpServerResponse.text("Invalid or expired authorization session.", {
      status: 400,
      headers: { ...NO_STORE_HEADERS, ...clearCookie },
    });
  }

  if (githubError || !githubCode) {
    return redirectResponse(
      appendRedirectParams(stateClaims.redirect_uri, {
        error: "access_denied",
        error_description: githubError || "Authorization was cancelled.",
        state: stateClaims.client_state,
      }),
      clearCookie,
    );
  }

  const issuer = normalizeRelayIssuer(config.relayIssuer);
  const { oauthBaseUrl } = githubOAuthUrls(config.githubOAuth);
  const callbackUpstream = yield* Effect.gen(function* () {
    const tokenExchange = yield* HttpClientRequest.post(
      `${oauthBaseUrl}/login/oauth/access_token`,
    ).pipe(
      HttpClientRequest.setHeaders({
        accept: "application/json",
        "user-agent": GITHUB_USER_AGENT,
      }),
      HttpClientRequest.bodyUrlParams({
        client_id: config.githubOAuth.clientId,
        client_secret: Redacted.value(config.githubOAuth.clientSecret),
        code: githubCode,
        redirect_uri: `${issuer}/v1/auth/github/callback`,
      }),
      httpClient.execute,
      Effect.flatMap((response) =>
        response.status === 200
          ? decodeGitHubTokenExchange(response).pipe(Effect.mapError(() => "decode_error" as const))
          : Effect.fail("bad_status" as const),
      ),
      Effect.option,
    );

    if (Option.isNone(tokenExchange) || !tokenExchange.value.access_token) {
      return { _tag: "TokenExchangeFailed" as const };
    }

    const identityResult = yield* fetchGitHubIdentityAndAuthorizeOrg({
      githubAccessToken: tokenExchange.value.access_token,
      githubOAuth: config.githubOAuth,
    }).pipe(Effect.result);

    return {
      _tag: "IdentityChecked" as const,
      githubAccessToken: tokenExchange.value.access_token,
      identityResult,
    };
  }).pipe(Effect.timeoutOption(GITHUB_REQUEST_TIMEOUT));

  if (Option.isNone(callbackUpstream) || callbackUpstream.value._tag === "TokenExchangeFailed") {
    return redirectResponse(
      appendRedirectParams(stateClaims.redirect_uri, {
        error: "server_error",
        error_description: "Could not complete GitHub sign-in.",
        state: stateClaims.client_state,
      }),
      clearCookie,
    );
  }

  const { githubAccessToken, identityResult } = callbackUpstream.value;

  if (identityResult._tag === "Failure") {
    const error = identityResult.failure;
    if (error._tag === "GitHubOrgMembershipDenied") {
      return redirectResponse(
        appendRedirectParams(stateClaims.redirect_uri, {
          error: "access_denied",
          error_description: "GitHub organization membership required.",
          state: stateClaims.client_state,
        }),
        clearCookie,
      );
    }
    return redirectResponse(
      appendRedirectParams(stateClaims.redirect_uri, {
        error: "server_error",
        error_description: "Could not verify GitHub account.",
        state: stateClaims.client_state,
      }),
      clearCookie,
    );
  }

  const identity = identityResult.success;
  const issuedAtEpochSeconds = Math.floor(now.epochMilliseconds / 1_000);
  const expiresAtEpochSeconds = issuedAtEpochSeconds + RelayTokens.RELAY_OAUTH_CODE_TTL_SECONDS;
  const jti = yield* random.uuidV4();
  const encryptedGithubAccessToken = yield* sessions.sealSecret(
    githubAccessToken,
    `code:${jti}:${stateClaims.client_id}`,
  );
  const oauthCode = yield* relayTokens
    .issueOAuthCodeToken({
      userId: identity.userId,
      githubLogin: identity.githubLogin,
      ...(identity.email ? { email: identity.email } : {}),
      encryptedGithubAccessToken,
      clientId: stateClaims.client_id,
      redirectUri: stateClaims.redirect_uri,
      codeChallenge: stateClaims.code_challenge,
      jti,
      issuedAtEpochSeconds,
      expiresAtEpochSeconds,
    })
    .pipe(Effect.orDie);

  return redirectResponse(
    appendRedirectParams(stateClaims.redirect_uri, {
      code: oauthCode,
      state: stateClaims.client_state,
    }),
    clearCookie,
  );
}).pipe(Effect.withSpan("relay.oauth.github_callback"));

const handleDeviceAuthorization = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const config = yield* RelayConfiguration.RelayConfiguration;
  const relayTokens = yield* RelayTokens.RelayTokens;
  const httpClient = yield* HttpClient.HttpClient;
  const now = yield* DateTime.now;

  const parsedParams = yield* parseFormParams(request);
  if (parsedParams._tag === "Failure") {
    return parsedParams.failure;
  }
  const params = parsedParams.success;
  const clientId = params.get("client_id") ?? "";
  if (clientId !== CLI_OAUTH_CLIENT_ID) {
    return oauthErrorResponse("invalid_client", "Unsupported OAuth client_id.");
  }

  const { oauthBaseUrl } = githubOAuthUrls(config.githubOAuth);
  const githubDevice = yield* HttpClientRequest.post(`${oauthBaseUrl}/login/device/code`).pipe(
    HttpClientRequest.setHeaders({
      accept: "application/json",
      "user-agent": GITHUB_USER_AGENT,
    }),
    HttpClientRequest.bodyUrlParams({
      client_id: config.githubOAuth.clientId,
      scope: GITHUB_SCOPES,
    }),
    httpClient.execute,
    Effect.timeout(GITHUB_REQUEST_TIMEOUT),
    Effect.flatMap((response) =>
      response.status === 200
        ? decodeGitHubDeviceCode(response).pipe(Effect.mapError(() => "decode_error" as const))
        : Effect.fail("bad_status" as const),
    ),
    Effect.option,
  );

  if (Option.isNone(githubDevice)) {
    return oauthErrorResponse("server_error", "Could not start GitHub device authorization.", 502);
  }

  const ttlSeconds = Math.max(
    60,
    Math.min(
      Math.floor(githubDevice.value.expires_in),
      RelayTokens.RELAY_OAUTH_DEVICE_MAX_TTL_SECONDS,
    ),
  );
  const issuedAtEpochSeconds = Math.floor(now.epochMilliseconds / 1_000);
  const wrappedDeviceCode = yield* relayTokens
    .issueOAuthDeviceToken({
      clientId,
      githubDeviceCode: githubDevice.value.device_code,
      issuedAtEpochSeconds,
      expiresAtEpochSeconds: issuedAtEpochSeconds + ttlSeconds,
    })
    .pipe(Effect.orDie);

  return oauthJsonResponse({
    device_code: wrappedDeviceCode,
    user_code: githubDevice.value.user_code,
    verification_uri: githubDevice.value.verification_uri,
    ...(githubDevice.value.verification_uri_complete
      ? { verification_uri_complete: githubDevice.value.verification_uri_complete }
      : {}),
    expires_in: ttlSeconds,
    ...(githubDevice.value.interval !== undefined ? { interval: githubDevice.value.interval } : {}),
  });
}).pipe(Effect.withSpan("relay.oauth.device"));

const handleToken = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const config = yield* RelayConfiguration.RelayConfiguration;
  const relayTokens = yield* RelayTokens.RelayTokens;
  const sessions = yield* OAuthSessions.OAuthSessions;
  const httpClient = yield* HttpClient.HttpClient;
  const digest = yield* Digest.Digest;

  const parsedParams = yield* parseFormParams(request);
  if (parsedParams._tag === "Failure") {
    return parsedParams.failure;
  }
  const params = parsedParams.success;
  const grantType = params.get("grant_type") ?? "";
  const clientId = params.get("client_id") ?? "";

  if (!isSupportedOAuthClientId(clientId)) {
    return oauthErrorResponse("invalid_client", "Unsupported OAuth client_id.");
  }

  if (grantType === "authorization_code") {
    const code = params.get("code") ?? "";
    const redirectUri = params.get("redirect_uri") ?? "";
    const codeVerifier = params.get("code_verifier") ?? "";

    if (!code || !redirectUri || !isValidCodeVerifier(codeVerifier)) {
      return oauthErrorResponse("invalid_request", "Missing or invalid authorization_code inputs.");
    }

    const codeClaims = yield* relayTokens.verifyOAuthCodeToken({ token: code });
    if (
      !codeClaims ||
      codeClaims.client_id !== clientId ||
      codeClaims.redirect_uri !== redirectUri
    ) {
      return oauthErrorResponse("invalid_grant", "Authorization code is invalid or expired.");
    }

    const expectedChallenge = Base64Url.encode(
      yield* digest.digest(Digest.sha256, textEncoder.encode(codeVerifier)),
    );
    if (!constantTimeEqual(expectedChallenge, codeClaims.code_challenge)) {
      return oauthErrorResponse("invalid_grant", "PKCE code_verifier verification failed.");
    }

    const githubAccessToken = yield* sessions.openSecret(
      codeClaims.enc_gh,
      `code:${codeClaims.jti}:${clientId}`,
    );
    if (Option.isNone(githubAccessToken)) {
      return oauthErrorResponse("invalid_grant", "Authorization code is invalid or expired.");
    }

    const created = yield* sessions
      .create({
        userId: codeClaims.sub,
        githubLogin: codeClaims.preferred_username,
        ...(codeClaims.email ? { email: codeClaims.email } : {}),
        clientId,
        githubAccessToken: githubAccessToken.value,
        authCodeJti: codeClaims.jti,
        authCodeExpiresAt: DateTime.formatIso(DateTime.makeUnsafe(codeClaims.exp * 1_000)),
      })
      .pipe(Effect.result);

    if (created._tag === "Failure") {
      return oauthErrorResponse("server_error", "Could not persist OAuth session.", 500);
    }
    if (created.success._tag === "AuthCodeAlreadyUsed") {
      return oauthErrorResponse("invalid_grant", "Authorization code has already been used.");
    }

    return yield* issueTokenResponse({
      userId: codeClaims.sub,
      githubLogin: codeClaims.preferred_username,
      ...(codeClaims.email ? { email: codeClaims.email } : {}),
      clientId,
      refreshToken: created.success.refreshToken,
    }).pipe(Effect.orDie);
  }

  if (grantType === DEVICE_CODE_GRANT_TYPE) {
    if (clientId !== CLI_OAUTH_CLIENT_ID) {
      return oauthErrorResponse("unauthorized_client", "Device flow is only enabled for t3-cli.");
    }
    const wrappedDeviceCode = params.get("device_code") ?? "";
    if (!wrappedDeviceCode) {
      return oauthErrorResponse("invalid_request", "device_code is required.");
    }
    const deviceClaims = yield* relayTokens.verifyOAuthDeviceToken({ token: wrappedDeviceCode });
    if (!deviceClaims || deviceClaims.client_id !== clientId) {
      return oauthErrorResponse(
        "expired_token",
        "Device authorization code is invalid or expired.",
      );
    }

    const { oauthBaseUrl } = githubOAuthUrls(config.githubOAuth);
    const deviceUpstream = yield* Effect.gen(function* () {
      const poll = yield* HttpClientRequest.post(`${oauthBaseUrl}/login/oauth/access_token`).pipe(
        HttpClientRequest.setHeaders({
          accept: "application/json",
          "user-agent": GITHUB_USER_AGENT,
        }),
        HttpClientRequest.bodyUrlParams({
          client_id: config.githubOAuth.clientId,
          device_code: deviceClaims.github_device_code,
          grant_type: DEVICE_CODE_GRANT_TYPE,
        }),
        httpClient.execute,
        Effect.flatMap((response) =>
          response.status === 200
            ? decodeGitHubTokenExchange(response).pipe(
                Effect.mapError(() => "decode_error" as const),
              )
            : Effect.fail("bad_status" as const),
        ),
        Effect.option,
      );

      if (Option.isNone(poll)) {
        return { _tag: "PollFailed" as const };
      }
      if (poll.value.error) {
        return {
          _tag: "PollError" as const,
          error: poll.value.error,
          errorDescription: poll.value.error_description,
        };
      }
      if (!poll.value.access_token) {
        return { _tag: "EmptyAccessToken" as const };
      }

      const identityResult = yield* fetchGitHubIdentityAndAuthorizeOrg({
        githubAccessToken: poll.value.access_token,
        githubOAuth: config.githubOAuth,
      }).pipe(Effect.result);

      return {
        _tag: "IdentityChecked" as const,
        githubAccessToken: poll.value.access_token,
        identityResult,
      };
    }).pipe(Effect.timeoutOption(GITHUB_REQUEST_TIMEOUT));

    if (Option.isNone(deviceUpstream) || deviceUpstream.value._tag === "PollFailed") {
      return oauthErrorResponse("server_error", "Could not poll GitHub device authorization.", 502);
    }
    if (deviceUpstream.value._tag === "EmptyAccessToken") {
      return oauthErrorResponse("server_error", "GitHub returned an empty access token.", 502);
    }
    if (deviceUpstream.value._tag === "PollError") {
      switch (deviceUpstream.value.error) {
        case "authorization_pending":
        case "slow_down":
        case "expired_token":
        case "access_denied":
          return oauthErrorResponse(
            deviceUpstream.value.error,
            deviceUpstream.value.errorDescription ?? deviceUpstream.value.error,
          );
        default:
          return oauthErrorResponse(
            "invalid_grant",
            deviceUpstream.value.errorDescription ?? "Device authorization failed.",
          );
      }
    }

    const { githubAccessToken, identityResult } = deviceUpstream.value;
    if (identityResult._tag === "Failure") {
      if (identityResult.failure._tag === "GitHubOrgMembershipDenied") {
        return oauthErrorResponse("access_denied", "GitHub organization membership required.");
      }
      return oauthErrorResponse("server_error", "Could not verify GitHub account.", 502);
    }

    const identity = identityResult.success;
    const created = yield* sessions
      .create({
        userId: identity.userId,
        githubLogin: identity.githubLogin,
        ...(identity.email ? { email: identity.email } : {}),
        clientId,
        githubAccessToken,
      })
      .pipe(Effect.result);

    if (created._tag === "Failure" || created.success._tag !== "Created") {
      return oauthErrorResponse("server_error", "Could not persist OAuth session.", 500);
    }

    return yield* issueTokenResponse({
      userId: identity.userId,
      githubLogin: identity.githubLogin,
      ...(identity.email ? { email: identity.email } : {}),
      clientId,
      refreshToken: created.success.refreshToken,
    }).pipe(Effect.orDie);
  }

  if (grantType === "refresh_token") {
    const refreshToken = params.get("refresh_token") ?? "";
    if (!refreshToken) {
      return oauthErrorResponse("invalid_request", "refresh_token is required.");
    }

    const inspected = yield* sessions
      .inspectForRefresh({ refreshToken, clientId })
      .pipe(Effect.result);
    if (inspected._tag === "Failure") {
      return oauthErrorResponse("server_error", "Could not inspect OAuth session.", 500);
    }
    if (inspected.success._tag === "InvalidGrant") {
      return oauthErrorResponse(
        "invalid_grant",
        "Refresh token is invalid, expired, or has been revoked.",
      );
    }

    const hasConfiguredAllowedOrgs = config.githubOAuth.allowedOrgs.some(
      (org) => org.trim().length > 0,
    );
    if (!hasConfiguredAllowedOrgs) {
      return oauthErrorResponse(
        "temporarily_unavailable",
        "GitHub organization allowlist is not configured.",
        503,
      );
    }

    const membershipCheck = yield* verifyGitHubOrgMembership({
      githubAccessToken: inspected.success.githubAccessToken,
      githubOAuth: config.githubOAuth,
    }).pipe(Effect.result);
    if (membershipCheck._tag === "Failure") {
      if (membershipCheck.failure._tag === "GitHubOrgMembershipDenied") {
        const revoked = yield* sessions
          .revokeById(inspected.success.session.id)
          .pipe(Effect.result);
        if (revoked._tag === "Failure") {
          return oauthErrorResponse(
            "temporarily_unavailable",
            "Could not revoke OAuth session.",
            503,
          );
        }
        return oauthErrorResponse("invalid_grant", "GitHub organization membership required.");
      }
      return oauthErrorResponse(
        "temporarily_unavailable",
        "Could not verify GitHub organization membership.",
        503,
      );
    }

    const rotated = yield* sessions.rotate({ refreshToken, clientId }).pipe(Effect.result);
    if (rotated._tag === "Failure") {
      return oauthErrorResponse("server_error", "Could not rotate OAuth session.", 500);
    }
    if (rotated.success._tag === "InvalidGrant") {
      return oauthErrorResponse(
        "invalid_grant",
        "Refresh token is invalid, expired, or has been revoked.",
      );
    }

    return yield* issueTokenResponse({
      userId: rotated.success.session.userId,
      githubLogin: rotated.success.session.githubLogin,
      ...(rotated.success.session.email ? { email: rotated.success.session.email } : {}),
      clientId,
      refreshToken: rotated.success.refreshToken,
    }).pipe(Effect.orDie);
  }

  return oauthErrorResponse("unsupported_grant_type", "Unsupported grant_type.");
}).pipe(Effect.withSpan("relay.oauth.token"));

const handleRevoke = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest;
  const sessions = yield* OAuthSessions.OAuthSessions;
  const parsedParams = yield* parseFormParams(request);
  if (parsedParams._tag === "Failure") {
    return parsedParams.failure;
  }
  const params = parsedParams.success;
  const token = params.get("token") ?? "";
  const clientId = params.get("client_id") ?? undefined;

  if (token.length > 0) {
    const revoked = yield* sessions
      .revoke({
        refreshToken: token,
        ...(clientId ? { clientId } : {}),
      })
      .pipe(Effect.result);
    if (revoked._tag === "Failure") {
      return oauthErrorResponse("temporarily_unavailable", "Could not revoke OAuth session.", 503);
    }
  }

  return oauthJsonResponse({ ok: true });
}).pipe(Effect.withSpan("relay.oauth.revoke"));

export const layerRoutes: Layer.Layer<
  never,
  never,
  | HttpRouter.HttpRouter
  | RelayConfiguration.RelayConfiguration
  | RelayTokens.RelayTokens
  | OAuthSessions.OAuthSessions
  | HttpClient.HttpClient
  | SecureRandom.SecureRandom
  | Digest.Digest
> = HttpRouter.use(
  Effect.fnUntraced(function* (router) {
    const config = yield* RelayConfiguration.RelayConfiguration;
    const relayTokens = yield* RelayTokens.RelayTokens;
    const sessions = yield* OAuthSessions.OAuthSessions;
    const httpClient = yield* HttpClient.HttpClient;
    const random = yield* SecureRandom.SecureRandom;
    const digest = yield* Digest.Digest;

    // Bind services at router build time because HttpRouter.toHttpEffect does not forward layer outputs to requests.
    const bind = (
      handler: Effect.Effect<
        HttpServerResponse.HttpServerResponse,
        never,
        | HttpServerRequest.HttpServerRequest
        | RelayConfiguration.RelayConfiguration
        | RelayTokens.RelayTokens
        | OAuthSessions.OAuthSessions
        | HttpClient.HttpClient
        | SecureRandom.SecureRandom
        | Digest.Digest
      >,
    ): Effect.Effect<
      HttpServerResponse.HttpServerResponse,
      never,
      HttpServerRequest.HttpServerRequest
    > =>
      handler.pipe(
        Effect.provideService(RelayConfiguration.RelayConfiguration, config),
        Effect.provideService(RelayTokens.RelayTokens, relayTokens),
        Effect.provideService(OAuthSessions.OAuthSessions, sessions),
        Effect.provideService(HttpClient.HttpClient, httpClient),
        Effect.provideService(SecureRandom.SecureRandom, random),
        Effect.provideService(Digest.Digest, digest),
      );

    yield* router.add("GET", "/v1/auth/authorize", bind(handleAuthorize));
    yield* router.add("GET", "/v1/auth/github/callback", bind(handleGitHubCallback));
    yield* router.add("POST", "/v1/auth/device", bind(handleDeviceAuthorization));
    yield* router.add("POST", "/v1/auth/token", bind(handleToken));
    yield* router.add("POST", "/v1/auth/revoke", bind(handleRevoke));
  }),
);
