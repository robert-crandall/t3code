import {
  buildRelayAuthorizeUrl,
  createRelayAuthSession,
  type CloudAccountSource,
  type CloudAccountSourceSnapshot,
  type RelayAuthIdentity,
  type RelayAuthSession,
  type RelayAuthSnapshot,
  type RelayAuthTokenStore,
  type RelayStoredSession,
} from "@t3tools/client-runtime/relay";
import * as Base64Url from "effect/encoding/Base64Url";
import Constants from "expo-constants";
import * as ExpoCrypto from "expo-crypto";
import * as SecureStore from "expo-secure-store";
import * as WebBrowser from "expo-web-browser";

export const MOBILE_OAUTH_SESSION_STORAGE_KEY = "t3code.cloud.relay-oauth-session";
export const MOBILE_OAUTH_CLIENT_ID = "t3-mobile" as const;

export type MobileCloudSignInResult =
  | { readonly status: "signedIn"; readonly identity: RelayAuthIdentity }
  | { readonly status: "cancelled" };

export interface MobileCloudAuthAccountSource extends CloudAccountSource {
  readonly getAccessToken: (options?: {
    readonly forceRefresh?: boolean;
  }) => Promise<string | null>;
}

export interface MobileCloudAuthController {
  readonly initialize: () => Promise<RelayAuthSnapshot>;
  readonly getSnapshot: () => RelayAuthSnapshot;
  readonly subscribe: (listener: (snapshot: RelayAuthSnapshot) => void) => () => void;
  readonly getAccessToken: (options?: {
    readonly forceRefresh?: boolean;
  }) => Promise<string | null>;
  readonly signIn: () => Promise<MobileCloudSignInResult>;
  readonly signOut: () => Promise<void>;
  readonly accountSource: MobileCloudAuthAccountSource;
}

export interface MobileCloudAuthDependencies {
  readonly relayUrl: string;
  readonly store?: RelayAuthTokenStore;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly redirectUri?: string;
  readonly getRandomBytes?: (byteCount: number) => Uint8Array;
  readonly sha256?: (input: Uint8Array) => Promise<Uint8Array>;
  readonly openAuthSession?: (
    url: string,
    redirectUri: string,
  ) => Promise<{ readonly type: string; readonly url?: string }>;
  /**
   * Runs best-effort before local token clearing and relay refresh-token revocation
   * so push/agent-awareness device unregistration still has a valid bearer token.
   */
  readonly beforeSignOut?: (tokenProvider: () => Promise<string | null>) => Promise<void>;
}

function isStoredSession(value: unknown): value is RelayStoredSession {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  if (
    typeof record.accessToken !== "string" ||
    record.accessToken.length === 0 ||
    typeof record.refreshToken !== "string" ||
    record.refreshToken.length === 0 ||
    typeof record.expiresAtMs !== "number" ||
    !Number.isFinite(record.expiresAtMs) ||
    typeof record.identity !== "object" ||
    record.identity === null
  ) {
    return false;
  }
  const identity = record.identity as Record<string, unknown>;
  return (
    typeof identity.userId === "string" &&
    identity.userId.length > 0 &&
    typeof identity.login === "string" &&
    identity.login.length > 0 &&
    (identity.email === null || typeof identity.email === "string")
  );
}

export function createSecureStoreRelayTokenStore(
  storageKey = MOBILE_OAUTH_SESSION_STORAGE_KEY,
): RelayAuthTokenStore {
  const options: SecureStore.SecureStoreOptions = {
    keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
  };
  return {
    async load(): Promise<RelayStoredSession | null> {
      const raw = await SecureStore.getItemAsync(storageKey, options);
      if (!raw) return null;
      try {
        const parsed: unknown = JSON.parse(raw);
        return isStoredSession(parsed) ? parsed : null;
      } catch {
        return null;
      }
    },
    async save(session: RelayStoredSession): Promise<void> {
      await SecureStore.setItemAsync(storageKey, JSON.stringify(session), options);
    },
    async clear(): Promise<void> {
      await SecureStore.deleteItemAsync(storageKey, options);
    },
  };
}

export function resolveMobileOAuthRedirectUri(scheme?: string | ReadonlyArray<string>): string {
  const raw = scheme ?? Constants.expoConfig?.scheme;
  const candidate = Array.isArray(raw) ? raw[0] : raw;
  const resolved =
    typeof candidate === "string" && candidate.trim().length > 0 ? candidate.trim() : "t3code";
  return `${resolved}://oauth/callback`;
}

// Hermes has no SubtleCrypto, so compute PKCE S256 via expo-crypto.
async function defaultSha256(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data.length);
  copy.set(data);
  return new Uint8Array(await ExpoCrypto.digest(ExpoCrypto.CryptoDigestAlgorithm.SHA256, copy));
}

function toCloudAccountSourceSnapshot(snapshot: RelayAuthSnapshot): CloudAccountSourceSnapshot {
  switch (snapshot.status) {
    case "loading":
      return { status: "loading" };
    case "signedOut":
      return { status: "signedOut" };
    case "signedIn":
      return { status: "signedIn", accountId: snapshot.identity.userId };
  }
}

export function createMobileCloudAuth(
  dependencies: MobileCloudAuthDependencies,
): MobileCloudAuthController {
  let refreshLockTail: Promise<void> = Promise.resolve();
  const withRefreshLock = async <T>(fn: () => Promise<T>): Promise<T> => {
    const previous = refreshLockTail;
    let release!: () => void;
    refreshLockTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  };

  const session: RelayAuthSession = createRelayAuthSession({
    relayUrl: dependencies.relayUrl,
    clientId: MOBILE_OAUTH_CLIENT_ID,
    store: dependencies.store ?? createSecureStoreRelayTokenStore(),
    ...(dependencies.fetch ? { fetch: dependencies.fetch } : {}),
    ...(dependencies.now ? { now: dependencies.now } : {}),
    withRefreshLock,
  });

  const getRandomBytes = dependencies.getRandomBytes ?? ExpoCrypto.getRandomBytes;
  const sha256 = dependencies.sha256 ?? defaultSha256;
  const openAuthSession =
    dependencies.openAuthSession ??
    ((url: string, redirectUri: string) => WebBrowser.openAuthSessionAsync(url, redirectUri));

  let signInInFlight: Promise<MobileCloudSignInResult> | null = null;

  const signIn = async (): Promise<MobileCloudSignInResult> => {
    if (signInInFlight !== null) {
      return signInInFlight;
    }
    const pending = (async (): Promise<MobileCloudSignInResult> => {
      const redirectUri = dependencies.redirectUri ?? resolveMobileOAuthRedirectUri();
      const state = Base64Url.encode(getRandomBytes(24));
      const codeVerifier = Base64Url.encode(getRandomBytes(32));
      const codeChallenge = Base64Url.encode(await sha256(new TextEncoder().encode(codeVerifier)));
      const authorizeUrl = buildRelayAuthorizeUrl({
        relayUrl: dependencies.relayUrl,
        clientId: MOBILE_OAUTH_CLIENT_ID,
        redirectUri,
        state,
        codeChallenge,
      });

      const result = await openAuthSession(authorizeUrl, redirectUri);
      if (result.type !== "success" || !result.url) {
        return { status: "cancelled" };
      }

      const callbackUrl = new URL(result.url);
      const oauthError = callbackUrl.searchParams.get("error");
      if (oauthError) {
        const description = callbackUrl.searchParams.get("error_description");
        throw new Error(description ? `${oauthError}: ${description}` : oauthError);
      }

      const returnedState = callbackUrl.searchParams.get("state");
      if (returnedState !== state) {
        throw new Error("Sign-in verification failed (state mismatch). Please try again.");
      }

      const code = callbackUrl.searchParams.get("code");
      if (!code) {
        throw new Error("Sign-in callback did not include an authorization code.");
      }

      const identity = await session.exchangeAuthorizationCode({
        code,
        redirectUri,
        codeVerifier,
      });
      return { status: "signedIn", identity };
    })().finally(() => {
      if (signInInFlight === pending) {
        signInInFlight = null;
      }
    });
    signInInFlight = pending;
    return pending;
  };

  const signOut = async (): Promise<void> => {
    const current = session.getSnapshot();
    if (current.status === "signedIn" && dependencies.beforeSignOut) {
      await dependencies.beforeSignOut(() => session.getAccessToken()).catch(() => undefined);
    }
    await session.signOut();
  };

  const accountSource: MobileCloudAuthAccountSource = {
    getSnapshot: () => toCloudAccountSourceSnapshot(session.getSnapshot()),
    addListener(listener) {
      return session.subscribe((next) => listener(toCloudAccountSourceSnapshot(next)));
    },
    getAccessToken: (options) => session.getAccessToken(options),
  };

  return {
    initialize: () => session.initialize(),
    getSnapshot: () => session.getSnapshot(),
    subscribe: (listener) => session.subscribe(listener),
    getAccessToken: (options) => session.getAccessToken(options),
    signIn,
    signOut,
    accountSource,
  };
}
