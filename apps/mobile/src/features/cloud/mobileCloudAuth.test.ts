import * as NodeCrypto from "node:crypto";
import type { RelayAuthTokenStore, RelayStoredSession } from "@t3tools/client-runtime/relay";
import * as Base64Url from "effect/encoding/Base64Url";
import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const secureStoreState = new Map<string, { value: string; options: unknown }>();

vi.mock("expo-constants", () => ({
  default: {
    expoConfig: {
      scheme: "t3code-private",
    },
  },
}));

vi.mock("expo-crypto", () => ({
  CryptoDigestAlgorithm: { SHA256: "SHA-256" },
  getRandomBytes: (count: number) => Uint8Array.from({ length: count }, (_, i) => i + 1),
  digest: async (_alg: string, data: Uint8Array) =>
    new Uint8Array(NodeCrypto.createHash("sha256").update(data).digest()).buffer,
}));

vi.mock("expo-secure-store", () => ({
  AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: "AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY",
  getItemAsync: vi.fn(async (key: string) => secureStoreState.get(key)?.value ?? null),
  setItemAsync: vi.fn(async (key: string, value: string, options?: unknown) => {
    secureStoreState.set(key, { value, options });
  }),
  deleteItemAsync: vi.fn(async (key: string) => {
    secureStoreState.delete(key);
  }),
}));

vi.mock("expo-web-browser", () => ({
  openAuthSessionAsync: vi.fn(),
}));

import * as SecureStore from "expo-secure-store";
import {
  createMobileCloudAuth,
  createSecureStoreRelayTokenStore,
  MOBILE_OAUTH_SESSION_STORAGE_KEY,
  resolveMobileOAuthRedirectUri,
} from "./mobileCloudAuth";

function makeJwt(payload: Record<string, unknown>): string {
  const header = Base64Url.encode(new TextEncoder().encode(JSON.stringify({ alg: "HS256" })));
  const body = Base64Url.encode(new TextEncoder().encode(JSON.stringify(payload)));
  return `${header}.${body}.sig`;
}

function makeMemoryStore(initial: RelayStoredSession | null = null): RelayAuthTokenStore & {
  current: RelayStoredSession | null;
} {
  const store = {
    current: initial,
    async load() {
      return store.current;
    },
    async save(session: RelayStoredSession) {
      store.current = session;
    },
    async clear() {
      store.current = null;
    },
  };
  return store;
}

beforeEach(() => {
  secureStoreState.clear();
  vi.clearAllMocks();
});

describe("mobileCloudAuth", () => {
  it("resolves mobile redirect URI from Expo scheme config", () => {
    expect(resolveMobileOAuthRedirectUri()).toBe("t3code-private://oauth/callback");
    expect(resolveMobileOAuthRedirectUri(["t3code-dev", "other"])).toBe(
      "t3code-dev://oauth/callback",
    );
    expect(resolveMobileOAuthRedirectUri("  ")).toBe("t3code://oauth/callback");
  });

  it("persists sessions in SecureStore with AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY", async () => {
    const store = createSecureStoreRelayTokenStore();
    const stored: RelayStoredSession = {
      accessToken: "acc-1",
      refreshToken: "ref-1",
      expiresAtMs: 1_900_000_000_000,
      identity: { userId: "github:42", login: "octocat", email: "octocat@example.com" },
    };

    await store.save(stored);
    expect(SecureStore.setItemAsync).toHaveBeenCalledWith(
      MOBILE_OAUTH_SESSION_STORAGE_KEY,
      JSON.stringify(stored),
      { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY },
    );
    expect(await store.load()).toEqual(stored);

    await store.clear();
    expect(await store.load()).toBeNull();
  });

  it("completes PKCE GitHub sign-in via t3-mobile and validates callback state", async () => {
    const store = makeMemoryStore();
    const accessToken = makeJwt({
      sub: "github:7",
      preferred_username: "robert-crandall",
      email: "robert@example.com",
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe("https://relay.example.test/v1/auth/token");
      const body = new URLSearchParams(String(init?.body));
      expect(body.get("grant_type")).toBe("authorization_code");
      expect(body.get("client_id")).toBe("t3-mobile");
      expect(body.get("code")).toBe("oauth-code-123");
      expect(body.get("redirect_uri")).toBe("t3code-private://oauth/callback");
      expect(body.get("code_verifier")).toBeTruthy();
      return new Response(
        JSON.stringify({
          access_token: accessToken,
          refresh_token: "refresh-token-1",
          expires_in: 3600,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });

    const controller = createMobileCloudAuth({
      relayUrl: "https://relay.example.test",
      store,
      fetch: fetchMock as typeof fetch,
      now: () => 1_700_000_000_000,
      openAuthSession: async (url, redirectUri) => {
        const parsed = new URL(url);
        expect(parsed.origin + parsed.pathname).toBe(
          "https://relay.example.test/v1/auth/authorize",
        );
        expect(parsed.searchParams.get("client_id")).toBe("t3-mobile");
        expect(parsed.searchParams.get("redirect_uri")).toBe("t3code-private://oauth/callback");
        expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
        expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
        const state = parsed.searchParams.get("state")!;
        return {
          type: "success",
          url: `${redirectUri}?code=oauth-code-123&state=${encodeURIComponent(state)}`,
        };
      },
    });

    await controller.initialize();
    const result = await controller.signIn();
    expect(result).toEqual({
      status: "signedIn",
      identity: {
        userId: "github:7",
        login: "robert-crandall",
        email: "robert@example.com",
      },
    });
    expect(controller.getSnapshot()).toEqual({
      status: "signedIn",
      identity: {
        userId: "github:7",
        login: "robert-crandall",
        email: "robert@example.com",
      },
    });
    expect(await controller.getAccessToken()).toBe(accessToken);
  });

  it("rejects mismatched OAuth callback state and handles browser cancellation silently", async () => {
    const controller = createMobileCloudAuth({
      relayUrl: "https://relay.example.test",
      store: makeMemoryStore(),
      openAuthSession: async (_url, redirectUri) => ({
        type: "success",
        url: `${redirectUri}?code=abc&state=wrong-state`,
      }),
    });
    await expect(controller.signIn()).rejects.toThrow(/state mismatch/i);

    const cancelling = createMobileCloudAuth({
      relayUrl: "https://relay.example.test",
      store: makeMemoryStore(),
      openAuthSession: async () => ({ type: "cancel" }),
    });
    expect(await cancelling.signIn()).toEqual({ status: "cancelled" });
  });

  it("runs beforeSignOut with a live access token before clearing and revoking the session", async () => {
    const events: Array<string> = [];
    const store = makeMemoryStore({
      accessToken: "live-access-token",
      refreshToken: "live-refresh-token",
      expiresAtMs: 1_800_000_000_000,
      identity: { userId: "github:99", login: "octocat", email: null },
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      events.push(`revoke:${String(input)}:${String(init?.body)}`);
      return new Response(null, { status: 204 });
    });

    const controller = createMobileCloudAuth({
      relayUrl: "https://relay.example.test",
      store,
      fetch: fetchMock as typeof fetch,
      now: () => 1_700_000_000_000,
      beforeSignOut: async (tokenProvider) => {
        const token = await tokenProvider();
        events.push(`unregister:${token}`);
      },
    });

    await controller.initialize();
    expect(controller.getSnapshot().status).toBe("signedIn");

    await controller.signOut();

    expect(events[0]).toBe("unregister:live-access-token");
    expect(events[1]).toContain("revoke:https://relay.example.test/v1/auth/revoke:");
    expect(events[1]).toContain("live-refresh-token");
    expect(controller.getSnapshot()).toEqual({ status: "signedOut", identity: null });
    expect(store.current).toBeNull();
  });
});
