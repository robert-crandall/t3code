// @effect-diagnostics nodeBuiltinImport:off globalTimers:off - Loopback OAuth callback uses Node http.Server and crypto directly.
import * as NodeCrypto from "node:crypto";
import * as NodeHttp from "node:http";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import * as Schema from "effect/Schema";

import {
  buildRelayAuthorizeUrl,
  createRelayAuthSession,
  type RelayAuthSession,
  type RelayAuthTokenStore,
  type RelayStoredSession,
} from "@t3tools/client-runtime/relay";
import type { DesktopCloudAuthState } from "@t3tools/contracts";
import * as HostProcess from "@t3tools/shared/HostProcess";
import { normalizeSecureRelayUrl } from "@t3tools/shared/relayUrl";

import * as ElectronSafeStorage from "../electron/ElectronSafeStorage.ts";
import * as ElectronShell from "../electron/ElectronShell.ts";
import * as ElectronWindow from "../electron/ElectronWindow.ts";
import * as IpcChannels from "../ipc/channels.ts";
import * as DesktopEnvironment from "./DesktopEnvironment.ts";

declare const __T3CODE_BUILD_RELAY_URL__: string | undefined;

const OAUTH_CALLBACK_PATH = "/oauth/callback";
const OAUTH_SIGN_IN_TIMEOUT_MS = 5 * 60_000;
const ENCRYPTED_SESSION_VERSION = 1;

const EncryptedSessionDocumentSchema = Schema.Struct({
  version: Schema.Literal(ENCRYPTED_SESSION_VERSION),
  encryptedSession: Schema.String,
});
const decodeEncryptedSessionDocumentJson = Schema.decodeUnknownEffect(
  Schema.fromJsonString(EncryptedSessionDocumentSchema),
);
const encodeEncryptedSessionDocumentJson = Schema.encodeUnknownEffect(
  Schema.fromJsonString(EncryptedSessionDocumentSchema),
);

const StoredSessionSchema = Schema.Struct({
  accessToken: Schema.String,
  refreshToken: Schema.String,
  expiresAtMs: Schema.Number,
  identity: Schema.Struct({
    userId: Schema.String,
    login: Schema.String,
    email: Schema.NullOr(Schema.String),
  }),
});
const decodeStoredSessionJson = Schema.decodeUnknownEffect(
  Schema.fromJsonString(StoredSessionSchema),
);
const encodeStoredSessionJson = Schema.encodeUnknownEffect(
  Schema.fromJsonString(StoredSessionSchema),
);

export class DesktopCloudAuthError extends Schema.TaggedError<DesktopCloudAuthError>()(
  "DesktopCloudAuthError",
  {
    message: Schema.String,
  },
) {}

export interface DesktopCloudAuthOptions {
  readonly relayUrl?: string | null;
  readonly fetch?: typeof fetch;
  readonly signInTimeoutMs?: number;
}

export class DesktopCloudAuth extends Context.Service<
  DesktopCloudAuth,
  {
    readonly start: Effect.Effect<void>;
    readonly getState: Effect.Effect<DesktopCloudAuthState>;
    readonly getAccessToken: (options?: {
      readonly forceRefresh?: boolean | undefined;
    }) => Effect.Effect<string | null>;
    readonly signIn: Effect.Effect<DesktopCloudAuthState, DesktopCloudAuthError>;
    readonly signOut: Effect.Effect<DesktopCloudAuthState>;
  }
>()("@t3tools/desktop/app/DesktopCloudAuth") {}

function resolveDesktopRelayUrl(
  env: Readonly<Record<string, string | undefined>>,
  buildRelayUrl: string | undefined = typeof __T3CODE_BUILD_RELAY_URL__ === "undefined"
    ? undefined
    : __T3CODE_BUILD_RELAY_URL__,
): string | null {
  const configured = env.T3CODE_RELAY_URL ?? buildRelayUrl;
  return configured ? normalizeSecureRelayUrl(configured) : null;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderCallbackHtml(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #111318; color: #f5f7fa; display: grid; place-items: center; min-height: 100vh; margin: 0; padding: 24px; }
      main { max-width: 420px; text-align: center; }
      h1 { font-size: 20px; margin: 0 0 10px; }
      p { color: #a7b0be; line-height: 1.5; margin: 0; }
    </style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(body)}</p>
    </main>
  </body>
</html>`;
}

function writeCallbackResponse(
  response: NodeHttp.ServerResponse,
  statusCode: number,
  title: string,
  body: string,
): void {
  response.writeHead(statusCode, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  });
  response.end(renderCallbackHtml(title, body));
}

function createPkcePair(): {
  readonly codeVerifier: string;
  readonly codeChallenge: string;
  readonly state: string;
} {
  const codeVerifier = NodeCrypto.randomBytes(32).toString("base64url");
  const codeChallenge = NodeCrypto.createHash("sha256").update(codeVerifier).digest("base64url");
  const state = NodeCrypto.randomBytes(32).toString("base64url");
  return { codeVerifier, codeChallenge, state };
}

async function receiveLoopbackOAuthCode(input: {
  readonly expectedState: string;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
  readonly onListening: (redirectUri: string) => Promise<void>;
}): Promise<{ readonly code: string; readonly redirectUri: string }> {
  const server = NodeHttp.createServer();
  let settled = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  return new Promise((resolve, reject) => {
    const finish = (
      outcome:
        | { ok: true; value: { code: string; redirectUri: string } }
        | { ok: false; error: Error },
    ) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      input.signal.removeEventListener("abort", onAbort);
      server.closeAllConnections();
      server.close();
      if (outcome.ok) {
        resolve(outcome.value);
      } else {
        reject(outcome.error);
      }
    };

    const onAbort = () => {
      finish({ ok: false, error: new Error("Sign-in cancelled.") });
    };

    if (input.signal.aborted) {
      onAbort();
      return;
    }
    input.signal.addEventListener("abort", onAbort, { once: true });

    let redirectUri = "";
    server.on("request", (request, response) => {
      if (request.method !== "GET") {
        writeCallbackResponse(
          response,
          405,
          "Method not allowed",
          "Return to T3 Code to try again.",
        );
        return;
      }
      const parsed = URL.parse(request.url ?? "/", "http://127.0.0.1");
      if (!parsed || parsed.pathname !== OAUTH_CALLBACK_PATH) {
        writeCallbackResponse(response, 404, "Not found", "Return to T3 Code.");
        return;
      }

      const returnedState = parsed.searchParams.get("state");
      if (returnedState !== input.expectedState) {
        writeCallbackResponse(
          response,
          400,
          "Sign-in expired",
          "This sign-in attempt no longer matches the active T3 Code request. Return to T3 Code and try again.",
        );
        return;
      }

      const errorCode = parsed.searchParams.get("error");
      if (errorCode) {
        const description = parsed.searchParams.get("error_description") ?? errorCode;
        writeCallbackResponse(
          response,
          400,
          "Sign-in failed",
          `${description} You can close this tab and try again in T3 Code.`,
        );
        finish({ ok: false, error: new Error(description) });
        return;
      }

      const code = parsed.searchParams.get("code")?.trim();
      if (!code) {
        writeCallbackResponse(
          response,
          400,
          "Sign-in incomplete",
          "Missing authorization code. You can close this tab and try again in T3 Code.",
        );
        finish({ ok: false, error: new Error("Missing authorization code from relay callback.") });
        return;
      }

      writeCallbackResponse(
        response,
        200,
        "Signed in to T3 Code",
        "You can close this tab and return to T3 Code.",
      );
      finish({ ok: true, value: { code, redirectUri } });
    });

    server.once("error", (error) => {
      finish({
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      });
    });

    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        finish({ ok: false, error: new Error("Could not bind loopback callback listener.") });
        return;
      }
      redirectUri = `http://127.0.0.1:${address.port}${OAUTH_CALLBACK_PATH}`;
      timer = setTimeout(() => {
        finish({ ok: false, error: new Error("Timed out waiting for GitHub sign-in callback.") });
      }, input.timeoutMs);
      void input.onListening(redirectUri).catch((error) => {
        finish({
          ok: false,
          error: error instanceof Error ? error : new Error(String(error)),
        });
      });
    });
  });
}

function makeEncryptedTokenStore(input: {
  readonly fileSystem: FileSystem.FileSystem;
  readonly path: Path.Path;
  readonly safeStorage: ElectronSafeStorage.ElectronSafeStorage["Service"];
  readonly sessionFilePath: string;
  readonly runEffect: <A, E>(effect: Effect.Effect<A, E>) => Promise<A>;
}): RelayAuthTokenStore {
  const { fileSystem, path, safeStorage, sessionFilePath, runEffect } = input;
  const sessionDirectory = path.dirname(sessionFilePath);

  return {
    load: () =>
      runEffect(
        Effect.gen(function* () {
          const exists = yield* fileSystem.exists(sessionFilePath);
          if (!exists) return null;
          if (!(yield* safeStorage.isEncryptionAvailable)) {
            yield* Effect.logWarning(
              "OS secret storage is unavailable; cannot decrypt saved cloud auth session.",
            );
            return null;
          }
          const raw = yield* fileSystem.readFileString(sessionFilePath);
          const doc = yield* decodeEncryptedSessionDocumentJson(raw);
          const bytes = new Uint8Array(Buffer.from(doc.encryptedSession, "base64"));
          const plaintext = yield* safeStorage.decryptString(bytes);
          return yield* decodeStoredSessionJson(plaintext);
        }).pipe(
          Effect.catch((error) =>
            Effect.logWarning("Could not load persisted desktop cloud auth session.", {
              error,
            }).pipe(Effect.as(null)),
          ),
        ),
      ),

    save: (session: RelayStoredSession) =>
      runEffect(
        Effect.gen(function* () {
          if (!(yield* safeStorage.isEncryptionAvailable)) {
            return yield* new DesktopCloudAuthError({
              message:
                "OS keychain encryption is unavailable; refusing to persist cloud credentials in plaintext.",
            });
          }
          const serialized = yield* encodeStoredSessionJson(session);
          const encryptedBytes = yield* safeStorage.encryptString(serialized);
          const encoded = yield* encodeEncryptedSessionDocumentJson({
            version: ENCRYPTED_SESSION_VERSION,
            encryptedSession: Buffer.from(encryptedBytes).toString("base64"),
          });
          yield* fileSystem.makeDirectory(sessionDirectory, { recursive: true, mode: 0o700 });
          const tempPath = `${sessionFilePath}.${NodeCrypto.randomUUID()}.tmp`;
          yield* Effect.gen(function* () {
            yield* fileSystem.writeFileString(tempPath, `${encoded}\n`, { mode: 0o600 });
            yield* fileSystem.rename(tempPath, sessionFilePath);
          }).pipe(
            Effect.ensuring(fileSystem.remove(tempPath, { force: true }).pipe(Effect.ignore)),
          );
        }),
      ),

    clear: () =>
      runEffect(
        fileSystem.remove(sessionFilePath, { force: true }).pipe(
          Effect.catch((error) =>
            Effect.logWarning("Could not remove desktop cloud auth session file.", {
              error,
            }),
          ),
        ),
      ),
  };
}

/** @public */
export const make = Effect.fn("DesktopCloudAuth.make")(function* (
  options: DesktopCloudAuthOptions = {},
) {
  const environment = yield* DesktopEnvironment.DesktopEnvironment;
  const env = yield* HostProcess.Environment;
  const fileSystem = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const safeStorage = yield* ElectronSafeStorage.ElectronSafeStorage;
  const shell = yield* ElectronShell.ElectronShell;
  const electronWindow = yield* ElectronWindow.ElectronWindow;
  const services = yield* Effect.context<never>();
  const runEffect = Effect.runPromiseWith(services);

  const relayUrl =
    options.relayUrl !== undefined
      ? options.relayUrl
        ? normalizeSecureRelayUrl(options.relayUrl)
        : null
      : resolveDesktopRelayUrl(env);
  const sessionFilePath = path.join(environment.stateDir, "cloud-auth", "session.json");
  const signInTimeoutMs = options.signInTimeoutMs ?? OAUTH_SIGN_IN_TIMEOUT_MS;

  let currentState: DesktopCloudAuthState = { status: "loading", identity: null };
  let session: RelayAuthSession | null = null;
  let unsubscribeSession: (() => void) | null = null;
  let startPromise: Promise<void> | null = null;
  let activeSignInAbort: AbortController | null = null;

  const broadcastState = (next: DesktopCloudAuthState) => {
    currentState = next;
    void runEffect(
      electronWindow.sendAll(IpcChannels.CLOUD_AUTH_STATE_CHANNEL, next).pipe(Effect.ignore),
    );
  };

  const abortActiveSignIn = () => {
    if (activeSignInAbort !== null) {
      activeSignInAbort.abort();
      activeSignInAbort = null;
    }
  };

  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      abortActiveSignIn();
      unsubscribeSession?.();
      unsubscribeSession = null;
    }),
  );

  const ensureStarted = async (): Promise<void> => {
    if (startPromise !== null) {
      await startPromise;
      return;
    }
    startPromise = (async () => {
      if (relayUrl === null) {
        broadcastState({ status: "signedOut", identity: null });
        return;
      }
      const store = makeEncryptedTokenStore({
        fileSystem,
        path,
        safeStorage,
        sessionFilePath,
        runEffect,
      });
      const created = createRelayAuthSession({
        relayUrl,
        clientId: "t3-desktop",
        store,
        ...(options.fetch ? { fetch: options.fetch } : {}),
      });
      session = created;
      unsubscribeSession = created.subscribe((snapshot) => {
        broadcastState(snapshot);
      });
      const initialized = await created.initialize();
      broadcastState(initialized);
    })();
    await startPromise;
  };

  return DesktopCloudAuth.of({
    start: Effect.promise(() => ensureStarted()).pipe(Effect.withSpan("desktop.cloudAuth.start")),

    getState: Effect.sync(() => currentState),

    getAccessToken: Effect.fn("DesktopCloudAuth.getAccessToken")(function (tokenOptions) {
      return Effect.promise(async () => {
        await ensureStarted();
        if (session === null) return null;
        return session.getAccessToken(
          tokenOptions?.forceRefresh !== undefined
            ? { forceRefresh: tokenOptions.forceRefresh }
            : undefined,
        );
      });
    }),

    signIn: Effect.tryPromise({
      try: async () => {
        await ensureStarted();
        if (relayUrl === null || session === null) {
          throw new Error("T3 Connect relay URL is not configured in this build.");
        }
        const encryptionAvailable = await runEffect(safeStorage.isEncryptionAvailable);
        if (!encryptionAvailable) {
          throw new Error(
            "OS keychain encryption is unavailable; cannot sign in to T3 Connect safely.",
          );
        }

        // Cancel any abandoned sign-in attempt before opening a fresh loopback listener.
        abortActiveSignIn();
        const abortController = new AbortController();
        activeSignInAbort = abortController;

        try {
          const { codeVerifier, codeChallenge, state } = createPkcePair();
          const { code, redirectUri } = await receiveLoopbackOAuthCode({
            expectedState: state,
            timeoutMs: signInTimeoutMs,
            signal: abortController.signal,
            onListening: async (boundRedirectUri) => {
              const authorizeUrl = buildRelayAuthorizeUrl({
                relayUrl,
                clientId: "t3-desktop",
                redirectUri: boundRedirectUri,
                codeChallenge,
                state,
              });
              const opened = await runEffect(shell.openExternal(authorizeUrl));
              if (!opened) {
                throw new Error("Could not open system browser for GitHub sign-in.");
              }
            },
          });
          await session.exchangeAuthorizationCode({
            code,
            redirectUri,
            codeVerifier,
          });
          void runEffect(
            Effect.gen(function* () {
              const mainWindow = yield* electronWindow.currentMainOrFirst;
              if (Option.isSome(mainWindow)) {
                yield* electronWindow.reveal(mainWindow.value);
              }
            }).pipe(Effect.ignore),
          );
          return session.getSnapshot();
        } finally {
          if (activeSignInAbort === abortController) {
            activeSignInAbort = null;
          }
        }
      },
      catch: (error) =>
        new DesktopCloudAuthError({
          message: error instanceof Error ? error.message : String(error),
        }),
    }).pipe(Effect.withSpan("desktop.cloudAuth.signIn")),

    signOut: Effect.promise(async () => {
      abortActiveSignIn();
      await ensureStarted();
      if (session !== null) {
        await session.signOut();
        return session.getSnapshot();
      }
      broadcastState({ status: "signedOut", identity: null });
      return currentState;
    }).pipe(Effect.withSpan("desktop.cloudAuth.signOut")),
  });
});

export const layer = Layer.effect(DesktopCloudAuth, make());
