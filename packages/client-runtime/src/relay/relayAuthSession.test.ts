import { describe, expect, it } from "vite-plus/test";

import {
  buildRelayAuthorizeUrl,
  createRelayAuthSession,
  parseRelayAccessTokenClaims,
  type RelayAuthTokenStore,
  type RelayStoredSession,
} from "./relayAuthSession.ts";

function encodeBase64Url(value: string): string {
  return btoa(value).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

function makeFakeJwt(claims: Record<string, unknown>): string {
  return `${encodeBase64Url(JSON.stringify({ alg: "EdDSA", typ: "t3-relay-access+jwt" }))}.${encodeBase64Url(JSON.stringify(claims))}.sig`;
}

function makeMemoryStore(initial: RelayStoredSession | null = null) {
  let stored = initial;
  const store: RelayAuthTokenStore = {
    load: async () => stored,
    save: async (next) => {
      stored = next;
    },
    clear: async () => {
      stored = null;
    },
  };
  return {
    store,
    getStored: () => stored,
    setStored: (next: RelayStoredSession | null) => {
      stored = next;
    },
  };
}

describe("relayAuthSession", () => {
  it("parses relay JWT claims and builds authorize URLs", () => {
    const jwt = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      email: "robert@example.com",
      exp: 2_000_000,
    });
    expect(parseRelayAccessTokenClaims(jwt)).toEqual({
      userId: "github:42",
      login: "robert-crandall",
      email: "robert@example.com",
      expiresAtMs: 2_000_000_000,
    });
    expect(parseRelayAccessTokenClaims("not-a-jwt")).toBeNull();

    const url = new URL(
      buildRelayAuthorizeUrl({
        relayUrl: "https://relay.crandalls.cloud/",
        clientId: "t3-mobile",
        redirectUri: "t3code-private://oauth/callback",
        state: "st1",
        codeChallenge: "ch1",
      }),
    );
    expect(url.origin + url.pathname).toBe("https://relay.crandalls.cloud/v1/auth/authorize");
    expect(url.searchParams.get("client_id")).toBe("t3-mobile");
    expect(url.searchParams.get("redirect_uri")).toBe("t3code-private://oauth/callback");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("exchanges authorization code, deduplicates concurrent refreshes, and revokes on sign-out", async () => {
    let currentTime = 1_000_000_000;
    const { store, getStored } = makeMemoryStore();
    const requests: Array<{ url: string; body: string }> = [];
    let refreshCount = 0;

    const access1 = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      email: "robert@example.com",
      exp: Math.floor((currentTime + 120_000) / 1_000),
    });
    const access2 = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      email: "robert@example.com",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });

    const refreshGate = Promise.withResolvers<void>();
    const refreshStarted = Promise.withResolvers<void>();
    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store,
      now: () => currentTime,
      fetch: async (input, init) => {
        const url = String(input);
        const body = String(init?.body ?? "");
        requests.push({ url, body });
        if (url.endsWith("/v1/auth/token") && body.includes("grant_type=authorization_code")) {
          return new Response(
            JSON.stringify({ access_token: access1, refresh_token: "rt_1", expires_in: 120 }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (url.endsWith("/v1/auth/token") && body.includes("grant_type=refresh_token")) {
          refreshCount += 1;
          refreshStarted.resolve();
          await refreshGate.promise;
          return new Response(
            JSON.stringify({ access_token: access2, refresh_token: "rt_2", expires_in: 900 }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (url.endsWith("/v1/auth/revoke")) {
          return new Response(null, { status: 200 });
        }
        return new Response("unexpected", { status: 500 });
      },
    });

    await session.initialize();
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });

    const identity = await session.exchangeAuthorizationCode({
      code: "code_1",
      redirectUri: "http://127.0.0.1:43210/callback",
      codeVerifier: "verifier_12345",
    });
    expect(identity).toEqual({
      userId: "github:42",
      login: "robert-crandall",
      email: "robert@example.com",
    });
    expect(await session.getAccessToken()).toBe(access1);

    // Move within refresh margin and trigger 3 concurrent getAccessToken calls -> single refresh.
    currentTime += 70_000;
    const pending = Promise.all([
      session.getAccessToken(),
      session.getAccessToken(),
      session.getAccessToken(),
    ]);
    await refreshStarted.promise;
    refreshGate.resolve();
    const [t1, t2, t3] = await pending;
    expect([t1, t2, t3]).toEqual([access2, access2, access2]);
    expect(refreshCount).toBe(1);
    expect(getStored()?.refreshToken).toBe("rt_2");

    await session.signOut();
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });
    expect(getStored()).toBeNull();
    expect(requests.at(-1)).toEqual({
      url: "https://relay.crandalls.cloud/v1/auth/revoke",
      body: "client_id=t3-desktop&token=rt_2",
    });
  });

  it("preserves stored session on transient 5xx/429/network errors and clears on permanent 400", async () => {
    const currentTime = 1_000_000_000;
    const expiredAccess = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime - 10_000) / 1_000),
    });
    const { store, getStored } = makeMemoryStore({
      accessToken: expiredAccess,
      refreshToken: "rt_1",
      expiresAtMs: currentTime - 10_000,
      identity: { userId: "github:42", login: "robert-crandall", email: null },
    });

    let nextStatus: number | "network" = 503;
    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-mobile",
      store,
      now: () => currentTime,
      fetch: async () => {
        if (nextStatus === "network") {
          throw new Error("offline");
        }
        return new Response(JSON.stringify({ error: "invalid_grant" }), { status: nextStatus });
      },
    });

    await session.initialize();
    expect(session.getSnapshot().status).toBe("signedIn");

    // 503, 429, and network errors must NOT sign out.
    for (const status of [503, 429, "network"] as const) {
      nextStatus = status;
      expect(await session.getAccessToken()).toBeNull();
      expect(session.getSnapshot().status).toBe("signedIn");
      expect(getStored()?.refreshToken).toBe("rt_1");
    }

    // Permanent 400 clears stored session and signs out.
    nextStatus = 400;
    expect(await session.getAccessToken()).toBeNull();
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });
    expect(getStored()).toBeNull();
  });

  it("prevents an in-flight refresh from resurrecting a session after signOut", async () => {
    const currentTime = 1_000_000_000;
    const expiredAccess = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime - 10_000) / 1_000),
    });
    const freshAccess = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    const { store, getStored } = makeMemoryStore({
      accessToken: expiredAccess,
      refreshToken: "rt_1",
      expiresAtMs: currentTime - 10_000,
      identity: { userId: "github:42", login: "robert-crandall", email: null },
    });

    const refreshStarted = Promise.withResolvers<void>();
    const releaseRefresh = Promise.withResolvers<void>();

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store,
      now: () => currentTime,
      fetch: async (input) => {
        if (String(input).endsWith("/v1/auth/token")) {
          refreshStarted.resolve();
          await releaseRefresh.promise;
          return new Response(
            JSON.stringify({ access_token: freshAccess, refresh_token: "rt_2", expires_in: 900 }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        return new Response(null, { status: 200 });
      },
    });

    await session.initialize();
    const pendingRefresh = session.getAccessToken();
    await refreshStarted.promise;

    await session.signOut();
    releaseRefresh.resolve();
    expect(await pendingRefresh).toBeNull();
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });
    expect(getStored()).toBeNull();
  });

  it("serializes store.save and store.clear so signOut during refresh save or code exchange cannot resurrect credentials", async () => {
    const currentTime = 1_000_000_000;
    const expiredAccess = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime - 10_000) / 1_000),
    });
    const freshAccess = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    let stored: RelayStoredSession | null = {
      accessToken: expiredAccess,
      refreshToken: "rt_1",
      expiresAtMs: currentTime - 10_000,
      identity: { userId: "github:42", login: "robert-crandall", email: null },
    };
    const saveStarted = Promise.withResolvers<void>();
    const releaseSave = Promise.withResolvers<void>();
    const store: RelayAuthTokenStore = {
      load: async () => stored,
      save: async (next) => {
        saveStarted.resolve();
        await releaseSave.promise;
        stored = next;
      },
      clear: async () => {
        stored = null;
      },
    };

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store,
      now: () => currentTime,
      fetch: async (input) => {
        if (String(input).endsWith("/v1/auth/token")) {
          return new Response(
            JSON.stringify({ access_token: freshAccess, refresh_token: "rt_2", expires_in: 900 }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        return new Response(null, { status: 204 });
      },
    });

    await session.initialize();
    const pendingRefresh = session.getAccessToken();
    await saveStarted.promise;

    const pendingSignOut = session.signOut();
    releaseSave.resolve();
    expect(await pendingRefresh).toBeNull();
    await pendingSignOut;
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });
    expect(stored).toBeNull();

    // Sign-out racing with an in-flight authorization code exchange also rejects and never persists.
    const exchangeStarted = Promise.withResolvers<void>();
    const releaseExchange = Promise.withResolvers<void>();
    const session2Store = makeMemoryStore();
    const session2 = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store: session2Store.store,
      now: () => currentTime,
      fetch: async (input) => {
        if (String(input).endsWith("/v1/auth/token")) {
          exchangeStarted.resolve();
          await releaseExchange.promise;
          return new Response(
            JSON.stringify({ access_token: freshAccess, refresh_token: "rt_3", expires_in: 900 }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        return new Response(null, { status: 204 });
      },
    });
    const pendingExchange = session2.exchangeAuthorizationCode({
      code: "code-1",
      redirectUri: "http://127.0.0.1:4321/callback",
      codeVerifier: "verifier",
    });
    await exchangeStarted.promise;
    await session2.signOut();
    releaseExchange.resolve();
    await expect(pendingExchange).rejects.toThrow("Sign-in was superseded or signed out.");
    expect(session2.getSnapshot()).toEqual({ status: "signedOut", identity: null });
    expect(session2Store.getStored()).toBeNull();
  });

  it("notifies listeners on token refresh even when identity is unchanged and propagates signOut clear errors", async () => {
    const currentTime = 1_000_000_000;
    const access1 = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime - 10_000) / 1_000),
    });
    const access2 = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    let failClear = false;
    let stored: RelayStoredSession | null = {
      accessToken: access1,
      refreshToken: "rt_1",
      expiresAtMs: currentTime - 10_000,
      identity: { userId: "github:42", login: "robert-crandall", email: null },
    };
    const revokedTokens: string[] = [];
    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-mobile",
      store: {
        load: async () => stored,
        save: async (next) => {
          stored = next;
        },
        clear: async () => {
          if (failClear) throw new Error("keychain locked");
          stored = null;
        },
      },
      now: () => currentTime,
      fetch: async (input, init) => {
        if (String(input).endsWith("/v1/auth/token")) {
          return new Response(
            JSON.stringify({ access_token: access2, refresh_token: "rt_2", expires_in: 900 }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (String(input).endsWith("/v1/auth/revoke")) {
          const params = new URLSearchParams(String(init?.body ?? ""));
          revokedTokens.push(params.get("token") ?? "");
          return new Response(null, { status: 204 });
        }
        return new Response("unexpected", { status: 500 });
      },
    });

    await session.initialize();
    let notifications = 0;
    session.subscribe(() => {
      notifications += 1;
    });

    expect(await session.getAccessToken()).toBe(access2);
    expect(notifications).toBe(1);

    failClear = true;
    await expect(session.signOut()).rejects.toThrow("keychain locked");
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });
    expect(revokedTokens).toEqual(["rt_2"]);
  });

  it("keeps loading state on transient store.load failure and hydrates on retry", async () => {
    const currentTime = 1_000_000_000;
    const access = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    let attempts = 0;
    let cleared = false;
    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-mobile",
      store: {
        load: async () => {
          attempts += 1;
          if (attempts === 1) throw new Error("keychain temporarily locked");
          return {
            accessToken: access,
            refreshToken: "rt_1",
            expiresAtMs: currentTime + 900_000,
            identity: { userId: "github:42", login: "robert-crandall", email: null },
          };
        },
        save: async () => undefined,
        clear: async () => {
          cleared = true;
        },
      },
      now: () => currentTime,
      fetch: async () => new Response(null, { status: 204 }),
    });

    const snapshots: string[] = [];
    session.subscribe((next) => {
      snapshots.push(next.status);
    });

    await expect(session.initialize()).rejects.toThrow("keychain temporarily locked");
    expect(session.getSnapshot()).toEqual({ status: "loading", identity: null });
    expect(snapshots).toEqual([]);
    expect(cleared).toBe(false);

    const hydrated = await session.initialize();
    expect(hydrated).toEqual({
      status: "signedIn",
      identity: { userId: "github:42", login: "robert-crandall", email: null },
    });
    expect(snapshots).toEqual(["signedIn"]);
  });

  it("never returns a stale access token from a 5xx refresh fallback after signOut", async () => {
    const currentTime = 1_000_000_000;
    const nearExpiryAccess = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime + 30_000) / 1_000),
    });
    const refreshStarted = Promise.withResolvers<void>();
    const releaseRefresh = Promise.withResolvers<void>();
    const { store } = makeMemoryStore({
      accessToken: nearExpiryAccess,
      refreshToken: "rt_1",
      expiresAtMs: currentTime + 30_000,
      identity: { userId: "github:42", login: "robert-crandall", email: null },
    });
    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store,
      now: () => currentTime,
      fetch: async (input) => {
        if (String(input).endsWith("/v1/auth/token")) {
          refreshStarted.resolve();
          await releaseRefresh.promise;
          return new Response("upstream error", { status: 503 });
        }
        return new Response(null, { status: 204 });
      },
    });

    await session.initialize();
    const pendingToken = session.getAccessToken();
    await refreshStarted.promise;
    await session.signOut();
    releaseRefresh.resolve();
    expect(await pendingToken).toBeNull();
  });
});
