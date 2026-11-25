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
      relayOrigin: "https://relay.crandalls.cloud",
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
      relayOrigin: "https://relay.crandalls.cloud",
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
      relayOrigin: "https://relay.crandalls.cloud",
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
      relayOrigin: "https://relay.crandalls.cloud",
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
            relayOrigin: "https://relay.crandalls.cloud",
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
      relayOrigin: "https://relay.crandalls.cloud",
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

  it("ignores persisted sessions from a different relayOrigin without sending or deleting them", async () => {
    const currentTime = 1_000_000_000;
    const access = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    const otherOriginSession: RelayStoredSession = {
      accessToken: access,
      refreshToken: "rt_relay_a",
      expiresAtMs: currentTime + 900_000,
      identity: { userId: "github:42", login: "robert-crandall", email: null },
      relayOrigin: "https://relay-a.example.com",
    };
    const { store, getStored } = makeMemoryStore(otherOriginSession);
    const requestedUrls: string[] = [];
    const session = createRelayAuthSession({
      relayUrl: "https://relay-b.example.com",
      clientId: "t3-desktop",
      store,
      now: () => currentTime,
      fetch: async (input) => {
        requestedUrls.push(String(input));
        return new Response(null, { status: 500 });
      },
    });

    await session.initialize();
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });
    expect(await session.getAccessToken()).toBeNull();
    await session.signOut();
    expect(requestedUrls).toEqual([]);
    expect(getStored()).toEqual(otherOriginSession);
  });

  it("keeps rotated credentials authoritative in memory when store.save fails on refresh", async () => {
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
    const access3 = makeFakeJwt({
      sub: "github:42",
      preferred_username: "robert-crandall",
      exp: Math.floor((currentTime + 1_800_000) / 1_000),
    });
    let stored: RelayStoredSession | null = {
      accessToken: access1,
      refreshToken: "rt_1",
      expiresAtMs: currentTime - 10_000,
      identity: { userId: "github:42", login: "robert-crandall", email: null },
      relayOrigin: "https://relay.crandalls.cloud",
    };
    let failSave = true;
    const seenRefreshTokens: string[] = [];
    const seenSignals: boolean[] = [];

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store: {
        load: async () => stored,
        save: async (next) => {
          if (failSave) throw new Error("disk full");
          stored = next;
        },
        clear: async () => {
          stored = null;
        },
      },
      now: () => currentTime,
      fetch: async (_input, init) => {
        seenSignals.push(init?.signal !== undefined);
        const params = new URLSearchParams(String(init?.body ?? ""));
        const rt = params.get("refresh_token") ?? "";
        seenRefreshTokens.push(rt);
        if (rt === "rt_1") {
          return new Response(
            JSON.stringify({ access_token: access2, refresh_token: "rt_2", expires_in: 900 }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        if (rt === "rt_2") {
          return new Response(
            JSON.stringify({ access_token: access3, refresh_token: "rt_3", expires_in: 900 }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
      },
    });

    await session.initialize();
    // First refresh rotates rt_1 -> rt_2, but store.save throws so disk still holds rt_1.
    expect(await session.getAccessToken()).toBe(access2);
    expect(stored?.refreshToken).toBe("rt_1");

    // Next forced refresh MUST send rt_2 from memory, never regress to stale rt_1 on disk.
    failSave = false;
    expect(await session.getAccessToken({ forceRefresh: true })).toBe(access3);
    expect(seenRefreshTokens).toEqual(["rt_1", "rt_2"]);
    expect(seenSignals).toEqual([true, true]);
    expect(stored?.refreshToken).toBe("rt_3");
  });

  it("rolls back disk storage and revokes the minted token if code exchange is aborted during store.save", async () => {
    const currentTime = 1_000_000_000;
    const existingAccess = makeFakeJwt({
      sub: "github:1",
      preferred_username: "existing-user",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    const newAccess = makeFakeJwt({
      sub: "github:2",
      preferred_username: "new-user",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    const initialSession: RelayStoredSession = {
      accessToken: existingAccess,
      refreshToken: "rt_existing",
      expiresAtMs: currentTime + 900_000,
      identity: { userId: "github:1", login: "existing-user", email: null },
      relayOrigin: "https://relay.crandalls.cloud",
    };
    let stored: RelayStoredSession | null = initialSession;
    const saveStarted = Promise.withResolvers<void>();
    const releaseSave = Promise.withResolvers<void>();
    const revokedTokens: string[] = [];

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store: {
        load: async () => stored,
        save: async (next) => {
          if (next.refreshToken === "rt_aborted") {
            saveStarted.resolve();
            await releaseSave.promise;
          }
          stored = next;
        },
        clear: async () => {
          stored = null;
        },
      },
      now: () => currentTime,
      fetch: async (input, init) => {
        if (String(input).endsWith("/v1/auth/token")) {
          return new Response(
            JSON.stringify({
              access_token: newAccess,
              refresh_token: "rt_aborted",
              expires_in: 900,
            }),
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
    const abortController = new AbortController();
    const pendingExchange = session.exchangeAuthorizationCode({
      code: "code_abort",
      redirectUri: "http://127.0.0.1:43210/callback",
      codeVerifier: "verifier_abort",
      signal: abortController.signal,
    });

    await saveStarted.promise;
    abortController.abort();
    releaseSave.resolve();

    await expect(pendingExchange).rejects.toThrow("Sign-in was canceled.");
    expect(stored).toEqual(initialSession);
    expect(session.getSnapshot()).toEqual({
      status: "signedIn",
      identity: initialSession.identity,
    });
    expect(revokedTokens).toEqual(["rt_aborted"]);
  });

  it("replaces an unreadable stored session on sign-in, and revokes minted tokens without clearing when store.save fails", async () => {
    const currentTime = 1_000_000_000;
    const newAccess = makeFakeJwt({
      sub: "github:7",
      preferred_username: "octocat",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    const revokedTokens: string[] = [];
    let cleared = false;
    const savedSessions: RelayStoredSession[] = [];
    let failSave = true;
    let mintCounter = 0;

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store: {
        load: async () => {
          throw new Error("keychain read failed");
        },
        save: async (next) => {
          if (failSave) {
            throw new Error("keychain write failed");
          }
          savedSessions.push(next);
        },
        clear: async () => {
          cleared = true;
        },
      },
      now: () => currentTime,
      fetch: async (input, init) => {
        if (String(input).endsWith("/v1/auth/token")) {
          mintCounter += 1;
          return new Response(
            JSON.stringify({
              access_token: newAccess,
              refresh_token: `rt_minted_${mintCounter}`,
              expires_in: 900,
            }),
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

    // When both load and save fail, sign-in revokes the minted token and never clears storage.
    await expect(
      session.exchangeAuthorizationCode({
        code: "code_1",
        redirectUri: "http://127.0.0.1:43210/callback",
        codeVerifier: "verifier_1",
      }),
    ).rejects.toThrow("keychain write failed");
    expect(savedSessions).toEqual([]);
    expect(cleared).toBe(false);
    expect(revokedTokens).toEqual(["rt_minted_1"]);

    // When old storage is unreadable (e.g. reset keychain item) but save succeeds, explicit sign-in recovers.
    failSave = false;
    const identity = await session.exchangeAuthorizationCode({
      code: "code_2",
      redirectUri: "http://127.0.0.1:43210/callback",
      codeVerifier: "verifier_2",
    });
    expect(identity).toEqual({ userId: "github:7", login: "octocat", email: null });
    expect(savedSessions.map((entry) => entry.refreshToken)).toEqual(["rt_minted_2"]);
    expect(cleared).toBe(false);
    expect(revokedTokens).toEqual(["rt_minted_1"]);
  });

  it("clears cachedSession before awaiting storage on signOut so concurrent getAccessToken cannot resurrect the session", async () => {
    const currentTime = 1_000_000_000;
    const loadStarted = Promise.withResolvers<void>();
    const releaseLoad = Promise.withResolvers<void>();
    let stored: RelayStoredSession | null = {
      accessToken: "expiring-access",
      refreshToken: "rt_1",
      expiresAtMs: currentTime + 1_000,
      identity: { userId: "github:7", login: "octocat", email: null },
      relayOrigin: "https://relay.crandalls.cloud",
    };
    let loadCalls = 0;
    let refreshRequests = 0;

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store: {
        load: async () => {
          loadCalls += 1;
          if (loadCalls === 2) {
            loadStarted.resolve();
            await releaseLoad.promise;
          }
          return stored;
        },
        save: async (next) => {
          stored = next;
        },
        clear: async () => {
          stored = null;
        },
      },
      now: () => currentTime,
      fetch: async (input) => {
        if (String(input).endsWith("/v1/auth/token")) {
          refreshRequests += 1;
          return new Response(
            JSON.stringify({
              access_token: makeFakeJwt({
                sub: "github:7",
                preferred_username: "octocat",
                exp: Math.floor((currentTime + 900_000) / 1_000),
              }),
              refresh_token: "rt_resurrected",
              expires_in: 900,
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        return new Response(null, { status: 204 });
      },
    });

    await session.initialize();
    const pendingSignOut = session.signOut();
    await loadStarted.promise;

    expect(await session.getAccessToken()).toBeNull();
    releaseLoad.resolve();
    await pendingSignOut;

    expect(refreshRequests).toBe(0);
    expect(stored).toBeNull();
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });
  });

  it("retries persisting an unsaved refreshed session on subsequent getAccessToken reads", async () => {
    const currentTime = 1_000_000_000;
    const refreshedAccess = makeFakeJwt({
      sub: "github:7",
      preferred_username: "octocat",
      exp: Math.floor((currentTime + 900_000) / 1_000),
    });
    let stored: RelayStoredSession | null = {
      accessToken: "stale-access",
      refreshToken: "rt_1",
      expiresAtMs: currentTime + 1_000,
      identity: { userId: "github:7", login: "octocat", email: null },
      relayOrigin: "https://relay.crandalls.cloud",
    };
    let failSaves = true;
    const saved = Promise.withResolvers<void>();

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store: {
        load: async () => stored,
        save: async (next) => {
          if (failSaves) {
            throw new Error("disk temporarily full");
          }
          stored = next;
          saved.resolve();
        },
        clear: async () => {
          stored = null;
        },
      },
      now: () => currentTime,
      fetch: async () =>
        new Response(
          JSON.stringify({
            access_token: refreshedAccess,
            refresh_token: "rt_2",
            expires_in: 900,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });

    await session.initialize();
    expect(await session.getAccessToken()).toBe(refreshedAccess);
    expect(stored?.refreshToken).toBe("rt_1");

    failSaves = false;
    expect(await session.getAccessToken()).toBe(refreshedAccess);
    await saved.promise;
    expect(stored?.refreshToken).toBe("rt_2");
  });

  it("does not clear storage when signOut encounters a store.load failure", async () => {
    const currentTime = 1_000_000_000;
    let loadCalls = 0;
    let cleared = false;
    const stored: RelayStoredSession = {
      accessToken: "live-access",
      refreshToken: "rt_1",
      expiresAtMs: currentTime + 900_000,
      identity: { userId: "github:7", login: "octocat", email: null },
      relayOrigin: "https://relay.crandalls.cloud",
    };

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store: {
        load: async () => {
          loadCalls += 1;
          if (loadCalls === 2) {
            throw new Error("keychain locked during sign-out");
          }
          return stored;
        },
        save: async () => undefined,
        clear: async () => {
          cleared = true;
        },
      },
      now: () => currentTime,
      fetch: async () => new Response(null, { status: 204 }),
    });

    await session.initialize();
    await expect(session.signOut()).rejects.toThrow("keychain locked during sign-out");
    expect(cleared).toBe(false);
    expect(session.getSnapshot()).toEqual({ status: "signedOut", identity: null });
  });

  it("aborts exchangeAuthorizationCode after deferred store.load without calling store.save", async () => {
    const currentTime = 1_000_000_000;
    const loadStarted = Promise.withResolvers<void>();
    const releaseLoad = Promise.withResolvers<void>();
    const revokedTokens: string[] = [];
    let saveCalls = 0;

    const session = createRelayAuthSession({
      relayUrl: "https://relay.crandalls.cloud",
      clientId: "t3-desktop",
      store: {
        load: async () => {
          loadStarted.resolve();
          await releaseLoad.promise;
          return null;
        },
        save: async () => {
          saveCalls += 1;
        },
        clear: async () => undefined,
      },
      now: () => currentTime,
      fetch: async (input, init) => {
        if (String(input).endsWith("/v1/auth/token")) {
          return new Response(
            JSON.stringify({
              access_token: makeFakeJwt({
                sub: "github:7",
                preferred_username: "octocat",
                exp: Math.floor((currentTime + 900_000) / 1_000),
              }),
              refresh_token: "rt_abort_after_load",
              expires_in: 900,
            }),
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

    const abortController = new AbortController();
    const pendingExchange = session.exchangeAuthorizationCode({
      code: "code_abort_load",
      redirectUri: "http://127.0.0.1:43210/callback",
      codeVerifier: "verifier_abort_load",
      signal: abortController.signal,
    });

    await loadStarted.promise;
    abortController.abort();
    releaseLoad.resolve();

    await expect(pendingExchange).rejects.toThrow("Sign-in was canceled.");
    expect(saveCalls).toBe(0);
    expect(revokedTokens).toEqual(["rt_abort_after_load"]);
  });
});
