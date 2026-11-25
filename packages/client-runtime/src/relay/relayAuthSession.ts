import { normalizeSecureRelayUrl } from "@t3tools/shared/relayUrl";

export type RelayAuthClientId = "t3-desktop" | "t3-mobile";

export interface RelayAuthIdentity {
  readonly userId: string;
  readonly login: string;
  readonly email: string | null;
}

export interface RelayStoredSession {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAtMs: number;
  readonly identity: RelayAuthIdentity;
}

export type RelayAuthSnapshot =
  | { readonly status: "loading"; readonly identity: null }
  | { readonly status: "signedOut"; readonly identity: null }
  | { readonly status: "signedIn"; readonly identity: RelayAuthIdentity };

export interface RelayAuthTokenStore {
  readonly load: () => Promise<RelayStoredSession | null>;
  readonly save: (session: RelayStoredSession) => Promise<void>;
  readonly clear: () => Promise<void>;
}

export interface RelayAuthSessionOptions {
  readonly relayUrl: string;
  readonly clientId: RelayAuthClientId;
  readonly store: RelayAuthTokenStore;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly refreshMarginMs?: number;
  readonly withRefreshLock?: <T>(fn: () => Promise<T>) => Promise<T>;
}

export interface RelayAuthorizationCodeExchangeInput {
  readonly code: string;
  readonly redirectUri: string;
  readonly codeVerifier: string;
}

export interface RelayAuthSession {
  readonly initialize: () => Promise<RelayAuthSnapshot>;
  readonly getSnapshot: () => RelayAuthSnapshot;
  readonly subscribe: (listener: (snapshot: RelayAuthSnapshot) => void) => () => void;
  readonly exchangeAuthorizationCode: (
    input: RelayAuthorizationCodeExchangeInput,
  ) => Promise<RelayAuthIdentity>;
  readonly getAccessToken: (options?: {
    readonly forceRefresh?: boolean;
  }) => Promise<string | null>;
  readonly signOut: () => Promise<void>;
}

export interface RelayAccessTokenClaims {
  readonly userId: string;
  readonly login: string;
  readonly email: string | null;
  readonly expiresAtMs: number | null;
}

const DEFAULT_REFRESH_MARGIN_MS = 60_000;
const FALLBACK_ACCESS_TOKEN_TTL_MS = 15 * 60_000;

function decodeBase64UrlUtf8(segment: string): string | null {
  const normalized = segment.replace(/-/gu, "+").replace(/_/gu, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  try {
    const binary = globalThis.atob(`${normalized}${padding}`);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Decodes unverified JWT claims for client display and expiry scheduling.
 * Authorization is enforced server-side by the relay.
 */
export function parseRelayAccessTokenClaims(token: string): RelayAccessTokenClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[1]) return null;
  const decoded = decodeBase64UrlUtf8(parts[1]);
  if (decoded === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const record = parsed as Record<string, unknown>;
  const sub =
    typeof record.sub === "string" && record.sub.trim().length > 0 ? record.sub.trim() : null;
  if (sub === null) return null;
  const preferredUsername =
    typeof record.preferred_username === "string" && record.preferred_username.trim().length > 0
      ? record.preferred_username.trim()
      : sub;
  const email =
    typeof record.email === "string" && record.email.trim().length > 0 ? record.email.trim() : null;
  const exp =
    typeof record.exp === "number" && Number.isFinite(record.exp) ? record.exp * 1_000 : null;
  return {
    userId: sub,
    login: preferredUsername,
    email,
    expiresAtMs: exp,
  };
}

export function buildRelayAuthorizeUrl(input: {
  readonly relayUrl: string;
  readonly clientId: RelayAuthClientId;
  readonly redirectUri: string;
  readonly state: string;
  readonly codeChallenge: string;
}): string {
  const origin = normalizeSecureRelayUrl(input.relayUrl);
  if (origin === null) {
    throw new Error(`Invalid relay URL: ${input.relayUrl}`);
  }
  const url = new URL("/v1/auth/authorize", origin);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("code_challenge", input.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", input.state);
  return url.toString();
}

interface RelayTokenEndpointResponse {
  readonly access_token: string;
  readonly refresh_token: string;
  readonly expires_in?: number;
}

function parseTokenResponse(body: unknown): RelayTokenEndpointResponse {
  if (typeof body !== "object" || body === null) {
    throw new Error("Relay token response was not a JSON object.");
  }
  const record = body as Record<string, unknown>;
  if (typeof record.access_token !== "string" || record.access_token.length === 0) {
    throw new Error("Relay token response did not include access_token.");
  }
  if (typeof record.refresh_token !== "string" || record.refresh_token.length === 0) {
    throw new Error("Relay token response did not include refresh_token.");
  }
  const expiresIn =
    typeof record.expires_in === "number" &&
    Number.isFinite(record.expires_in) &&
    record.expires_in > 0
      ? record.expires_in
      : undefined;
  return {
    access_token: record.access_token,
    refresh_token: record.refresh_token,
    ...(expiresIn !== undefined ? { expires_in: expiresIn } : {}),
  };
}

function isPermanentRefreshRejection(status: number): boolean {
  return status >= 400 && status < 500 && status !== 408 && status !== 429;
}

function identityEquals(a: RelayAuthIdentity | null, b: RelayAuthIdentity | null): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  return a.userId === b.userId && a.login === b.login && a.email === b.email;
}

function snapshotEquals(a: RelayAuthSnapshot, b: RelayAuthSnapshot): boolean {
  return a.status === b.status && identityEquals(a.identity, b.identity);
}

function buildStoredSession(
  tokenResponse: RelayTokenEndpointResponse,
  nowMs: number,
  fallbackIdentity?: RelayAuthIdentity,
): RelayStoredSession {
  const claims = parseRelayAccessTokenClaims(tokenResponse.access_token);
  const identity: RelayAuthIdentity | null =
    claims !== null
      ? {
          userId: claims.userId,
          login: claims.login,
          email: claims.email,
        }
      : (fallbackIdentity ?? null);
  if (identity === null) {
    throw new Error("Relay access token did not contain a valid subject claim.");
  }
  const expiresAtMs =
    claims?.expiresAtMs ??
    nowMs +
      (tokenResponse.expires_in !== undefined
        ? tokenResponse.expires_in * 1_000
        : FALLBACK_ACCESS_TOKEN_TTL_MS);
  return {
    accessToken: tokenResponse.access_token,
    refreshToken: tokenResponse.refresh_token,
    expiresAtMs,
    identity,
  };
}

export function createRelayAuthSession(options: RelayAuthSessionOptions): RelayAuthSession {
  const origin = normalizeSecureRelayUrl(options.relayUrl);
  if (origin === null) {
    throw new Error(`Invalid relay URL: ${options.relayUrl}`);
  }
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const refreshMarginMs = options.refreshMarginMs ?? DEFAULT_REFRESH_MARGIN_MS;
  const withRefreshLock = options.withRefreshLock ?? (<T>(fn: () => Promise<T>) => fn());

  let snapshot: RelayAuthSnapshot = { status: "loading", identity: null };
  let cachedSession: RelayStoredSession | null = null;
  let initialized = false;
  let initPromise: Promise<RelayAuthSnapshot> | null = null;
  let refreshPromise: Promise<string | null> | null = null;
  // Incremented on every sign-in or sign-out so stale in-flight loads/refreshes cannot resurrect old sessions.
  let generation = 0;
  const listeners = new Set<(next: RelayAuthSnapshot) => void>();

  const setSnapshot = (next: RelayAuthSnapshot) => {
    if (snapshotEquals(snapshot, next)) return;
    snapshot = next;
    for (const listener of listeners) {
      listener(next);
    }
  };

  const initialize = async (): Promise<RelayAuthSnapshot> => {
    if (initialized) return snapshot;
    if (initPromise !== null) return initPromise;
    const initGeneration = generation;
    initPromise = (async () => {
      try {
        const stored = await options.store.load();
        if (generation !== initGeneration) {
          return snapshot;
        }
        initialized = true;
        cachedSession = stored;
        setSnapshot(
          stored !== null
            ? { status: "signedIn", identity: stored.identity }
            : { status: "signedOut", identity: null },
        );
        return snapshot;
      } finally {
        initPromise = null;
      }
    })();
    return initPromise;
  };

  const exchangeAuthorizationCode = async (
    input: RelayAuthorizationCodeExchangeInput,
  ): Promise<RelayAuthIdentity> => {
    const response = await fetchImpl(`${origin}/v1/auth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: options.clientId,
        code: input.code,
        redirect_uri: input.redirectUri,
        code_verifier: input.codeVerifier,
      }).toString(),
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      const description =
        typeof body === "object" &&
        body !== null &&
        typeof (body as Record<string, unknown>).error_description === "string"
          ? ((body as Record<string, unknown>).error_description as string)
          : `Relay token exchange failed with status ${response.status}.`;
      throw new Error(description);
    }
    const parsed = parseTokenResponse(body);
    const nextSession = buildStoredSession(parsed, now());
    generation += 1;
    initialized = true;
    await options.store.save(nextSession);
    cachedSession = nextSession;
    setSnapshot({ status: "signedIn", identity: nextSession.identity });
    return nextSession.identity;
  };

  const refreshUnderLock = async (forceRefresh: boolean): Promise<string | null> =>
    withRefreshLock(async () => {
      const attemptGeneration = generation;
      const stored = (await options.store.load()) ?? cachedSession;
      if (generation !== attemptGeneration) {
        return cachedSession?.accessToken ?? null;
      }
      if (stored === null) {
        cachedSession = null;
        setSnapshot({ status: "signedOut", identity: null });
        return null;
      }
      cachedSession = stored;
      if (!forceRefresh && stored.expiresAtMs - now() > refreshMarginMs) {
        setSnapshot({ status: "signedIn", identity: stored.identity });
        return stored.accessToken;
      }

      const attemptedRefreshToken = stored.refreshToken;
      let response: Response;
      try {
        response = await fetchImpl(`${origin}/v1/auth/token`, {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            accept: "application/json",
          },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: options.clientId,
            refresh_token: attemptedRefreshToken,
          }).toString(),
        });
      } catch {
        return stored.expiresAtMs > now() ? stored.accessToken : null;
      }

      if (response.ok) {
        let parsed: RelayTokenEndpointResponse;
        try {
          parsed = parseTokenResponse(await response.json());
        } catch {
          return stored.expiresAtMs > now() ? stored.accessToken : null;
        }
        if (generation !== attemptGeneration) {
          return null;
        }
        const nextSession = buildStoredSession(parsed, now(), stored.identity);
        await options.store.save(nextSession);
        if (generation !== attemptGeneration) {
          return null;
        }
        cachedSession = nextSession;
        setSnapshot({ status: "signedIn", identity: nextSession.identity });
        return nextSession.accessToken;
      }

      if (isPermanentRefreshRejection(response.status)) {
        if (generation !== attemptGeneration) {
          return null;
        }
        const latestStored = await options.store.load().catch(() => null);
        if (generation !== attemptGeneration) {
          return null;
        }
        // Only clear the session if nobody else rotated or replaced the refresh token while we were in flight.
        if (latestStored !== null && latestStored.refreshToken !== attemptedRefreshToken) {
          cachedSession = latestStored;
          setSnapshot({ status: "signedIn", identity: latestStored.identity });
          return latestStored.expiresAtMs > now() ? latestStored.accessToken : null;
        }
        cachedSession = null;
        await options.store.clear().catch(() => undefined);
        if (generation === attemptGeneration) {
          setSnapshot({ status: "signedOut", identity: null });
        }
        return null;
      }

      // Transient 408 / 429 / 5xx: preserve the stored session.
      return stored.expiresAtMs > now() ? stored.accessToken : null;
    });

  const getAccessToken = async (input?: {
    readonly forceRefresh?: boolean;
  }): Promise<string | null> => {
    if (!initialized) {
      await initialize();
    }
    const forceRefresh = input?.forceRefresh === true;
    const current = cachedSession;
    if (current === null) {
      return null;
    }
    if (!forceRefresh && current.expiresAtMs - now() > refreshMarginMs) {
      return current.accessToken;
    }
    if (refreshPromise !== null) {
      return refreshPromise;
    }
    const pending = refreshUnderLock(forceRefresh).finally(() => {
      if (refreshPromise === pending) {
        refreshPromise = null;
      }
    });
    refreshPromise = pending;
    return pending;
  };

  const signOut = async (): Promise<void> => {
    generation += 1;
    initialized = true;
    const previous = cachedSession ?? (await options.store.load().catch(() => null));
    cachedSession = null;
    await options.store.clear().catch(() => undefined);
    setSnapshot({ status: "signedOut", identity: null });

    if (previous?.refreshToken) {
      await fetchImpl(`${origin}/v1/auth/revoke`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: options.clientId,
          token: previous.refreshToken,
        }).toString(),
      }).catch(() => undefined);
    }
  };

  return {
    initialize,
    getSnapshot: () => snapshot,
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    exchangeAuthorizationCode,
    getAccessToken,
    signOut,
  };
}
