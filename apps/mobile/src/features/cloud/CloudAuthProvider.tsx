import type { RelayAuthIdentity, RelayAuthSnapshot } from "@t3tools/client-runtime/relay";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import { createContext, use, useSyncExternalStore, type ReactNode } from "react";
import { AppState } from "react-native";

import { runtime } from "../../lib/runtime";
import { unregisterAgentAwarenessDeviceForCurrentUser } from "../agent-awareness/remoteRegistration";
import { cloudAccountService, deactivateCloudRelayAccount } from "./cloudAccountService";
import {
  createMobileCloudAuth,
  type MobileCloudAuthController,
  type MobileCloudSignInResult,
} from "./mobileCloudAuth";
import { resolveCloudPublicConfig } from "./publicConfig";

export interface MobileCloudAuthState {
  readonly status: RelayAuthSnapshot["status"];
  readonly isLoaded: boolean;
  readonly isSignedIn: boolean;
  readonly initError: string | null;
  readonly userId: string | null;
  readonly identity: RelayAuthIdentity | null;
  readonly getToken: (options?: { readonly forceRefresh?: boolean }) => Promise<string | null>;
  readonly retryInitialize: () => Promise<void>;
  readonly signIn: () => Promise<MobileCloudSignInResult>;
  readonly signOut: () => Promise<void>;
}

const SIGNED_OUT_SNAPSHOT: RelayAuthSnapshot = { status: "signedOut", identity: null };
const UNCONFIGURED_AUTH_STATE: MobileCloudAuthState = {
  status: "signedOut",
  isLoaded: true,
  isSignedIn: false,
  initError: null,
  userId: null,
  identity: null,
  getToken: async () => null,
  retryInitialize: async () => undefined,
  signIn: async () => ({ status: "cancelled" }),
  signOut: async () => undefined,
};

const MobileCloudAuthContext = createContext<MobileCloudAuthState>(UNCONFIGURED_AUTH_STATE);

const cloudConfig = resolveCloudPublicConfig();
// Build-time constant: null when this build has no cloud config.
const relayUrl = cloudConfig.relay.url;

const mobileCloudAuth: MobileCloudAuthController | null = relayUrl
  ? createMobileCloudAuth({
      relayUrl,
      beforeSignOut: async (tokenProvider) => {
        await runtime.runPromiseExit(
          unregisterAgentAwarenessDeviceForCurrentUser(tokenProvider).pipe(
            Effect.timeoutOption(Duration.seconds(5)),
          ),
        );
      },
    })
  : null;

let retryInitializeSession: () => Promise<void> = async () => undefined;

if (mobileCloudAuth) {
  cloudAccountService.attach(mobileCloudAuth.accountSource);
  const controller = mobileCloudAuth;
  retryInitializeSession = async () => {
    try {
      await controller.initialize();
    } catch (error) {
      // Keep status in loading (accountSource stays Unobserved) so persisted cloud environments
      // are preserved while surfacing an explicit recovery path in the UI.
      console.warn("[t3-connect] Could not initialize mobile cloud auth session.", error);
    }
  };
  void retryInitializeSession();
  AppState.addEventListener("change", (nextState) => {
    if (nextState !== "active") return;
    if (controller.getInitError() !== null) {
      void retryInitializeSession();
    }
    cloudAccountService.retryIfFailed();
  });
} else {
  // Without cloud config no account can ever activate, so drop anything a
  // previous build with cloud enabled left registered.
  deactivateCloudRelayAccount();
}

function subscribeNoop(): () => void {
  return () => undefined;
}

function getUnconfiguredSnapshot(): RelayAuthSnapshot {
  return SIGNED_OUT_SNAPSHOT;
}

function getNoInitError(): string | null {
  return null;
}

export function CloudAuthProvider(props: { readonly children: ReactNode }) {
  const snapshot = useSyncExternalStore(
    mobileCloudAuth ? mobileCloudAuth.subscribe : subscribeNoop,
    mobileCloudAuth ? mobileCloudAuth.getSnapshot : getUnconfiguredSnapshot,
    mobileCloudAuth ? mobileCloudAuth.getSnapshot : getUnconfiguredSnapshot,
  );
  const initError = useSyncExternalStore(
    mobileCloudAuth ? mobileCloudAuth.subscribe : subscribeNoop,
    mobileCloudAuth ? mobileCloudAuth.getInitError : getNoInitError,
    mobileCloudAuth ? mobileCloudAuth.getInitError : getNoInitError,
  );

  const value: MobileCloudAuthState = mobileCloudAuth
    ? {
        status: snapshot.status,
        isLoaded: snapshot.status !== "loading",
        isSignedIn: snapshot.status === "signedIn",
        initError,
        userId: snapshot.identity?.userId ?? null,
        identity: snapshot.identity,
        getToken: mobileCloudAuth.getAccessToken,
        retryInitialize: retryInitializeSession,
        signIn: mobileCloudAuth.signIn,
        signOut: mobileCloudAuth.signOut,
      }
    : UNCONFIGURED_AUTH_STATE;

  return <MobileCloudAuthContext value={value}>{props.children}</MobileCloudAuthContext>;
}

export function useCloudAuth(): MobileCloudAuthState {
  return use(MobileCloudAuthContext);
}
