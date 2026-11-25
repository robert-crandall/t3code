import {
  type CloudAccountSource,
  type CloudAccountSourceSnapshot,
  createCloudAccountService,
  ManagedRelay,
  setManagedRelaySession,
} from "@t3tools/client-runtime/relay";
import {
  reportAtomCommandResult,
  runAtomCommand,
  settleAsyncResult,
  squashAtomCommandFailure,
} from "@t3tools/client-runtime/state/runtime";
import type {
  DesktopCloudAuthBridge,
  DesktopCloudAuthIdentity,
  DesktopCloudAuthState,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import { createContext, type ReactNode, use, useEffect, useState } from "react";

import { environmentCatalog } from "../connection/catalog";
import { runtime } from "../lib/runtime";
import { appAtomRegistry } from "../rpc/atomRegistry";

const SIGNED_OUT_STATE: DesktopCloudAuthState = {
  status: "signedOut",
  identity: null,
};

const LOADING_STATE: DesktopCloudAuthState = {
  status: "loading",
  identity: null,
};

export interface CloudAuthContextValue {
  readonly status: DesktopCloudAuthState["status"];
  readonly isLoaded: boolean;
  readonly isSignedIn: boolean | undefined;
  readonly userId: string | null;
  readonly identity: DesktopCloudAuthIdentity | null;
  readonly getToken: () => Promise<string | null>;
  readonly signIn: () => Promise<DesktopCloudAuthState>;
  readonly signOut: () => Promise<DesktopCloudAuthState>;
}

const DEFAULT_CLOUD_AUTH_CONTEXT: CloudAuthContextValue = {
  status: "signedOut",
  isLoaded: true,
  isSignedIn: false,
  userId: null,
  identity: null,
  getToken: async () => null,
  signIn: async () => SIGNED_OUT_STATE,
  signOut: async () => SIGNED_OUT_STATE,
};

const CloudAuthContext = createContext<CloudAuthContextValue>(DEFAULT_CLOUD_AUTH_CONTEXT);

export function useCloudAuth(): CloudAuthContextValue {
  return use(CloudAuthContext);
}

export function deactivateManagedRelayAuthentication(): void {
  setManagedRelaySession(appAtomRegistry, null);
}

export function activateManagedRelayAuthentication(
  accountId: string,
  readClerkToken: () => Promise<string | null>,
): void {
  setManagedRelaySession(appAtomRegistry, {
    accountId,
    readClerkToken,
  });
}

function toCloudAccountSnapshot(state: DesktopCloudAuthState): CloudAccountSourceSnapshot {
  // Keep saved relay environments intact when keychain storage is temporarily unavailable.
  if (state.status === "loading" || state.status === "unavailable") {
    return { status: "loading" };
  }
  if (state.status === "signedIn") {
    return { status: "signedIn", accountId: state.identity.userId };
  }
  return { status: "signedOut" };
}

interface DesktopCloudAuthAccountSource extends CloudAccountSource {
  readonly bridge: DesktopCloudAuthBridge;
}

function createDesktopCloudAuthAccountSource(
  bridge: DesktopCloudAuthBridge,
  onState: (state: DesktopCloudAuthState) => void,
): DesktopCloudAuthAccountSource {
  return {
    bridge,
    addListener(listener) {
      let active = true;
      let receivedChange = false;
      const emit = (next: DesktopCloudAuthState) => {
        if (!active) return;
        onState(next);
        listener(toCloudAccountSnapshot(next));
      };
      const unsubscribe = bridge.onStateChange((next) => {
        receivedChange = true;
        emit(next);
      });
      void bridge.getState().then(
        (initial) => {
          if (!receivedChange) {
            emit(initial);
          }
        },
        () => {
          if (!receivedChange) {
            emit(SIGNED_OUT_STATE);
          }
        },
      );
      return () => {
        active = false;
        unsubscribe();
      };
    },
  };
}

// A failed route removal fails the switch, so the next account never activates over the old routes.
async function cleanUpManagedRelayAccount(): Promise<void> {
  const [removal, tokenReset] = await Promise.all([
    runAtomCommand(appAtomRegistry, environmentCatalog.removeRelayEnvironments, undefined, {
      reportFailure: false,
      reportDefect: false,
    }),
    settleAsyncResult(() =>
      runtime.runPromiseExit(
        ManagedRelay.ManagedRelayClient.pipe(Effect.flatMap((client) => client.resetTokenCache)),
      ),
    ),
  ]);
  reportAtomCommandResult(tokenReset, { label: "cloud account cleanup" });
  if (removal._tag !== "Success") throw squashAtomCommandFailure(removal);
}

const managedRelayAccountService = createCloudAccountService<DesktopCloudAuthAccountSource>({
  deactivate: deactivateManagedRelayAuthentication,
  detach: deactivateManagedRelayAuthentication,
  cleanUp: cleanUpManagedRelayAccount,
  activate: ({ source, accountId }) =>
    activateManagedRelayAuthentication(accountId, () => source.bridge.getAccessToken()),
});

export function ManagedRelayAuthProvider({ children }: { readonly children: ReactNode }) {
  const bridge = typeof window === "undefined" ? undefined : window.desktopBridge?.cloudAuth;
  const [state, setState] = useState<DesktopCloudAuthState>(
    bridge ? LOADING_STATE : SIGNED_OUT_STATE,
  );

  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- subscribes the external managed relay account service to desktop IPC auth state changes
  useEffect(() => {
    if (!bridge) {
      deactivateManagedRelayAuthentication();
      return;
    }
    const source = createDesktopCloudAuthAccountSource(bridge, setState);
    return managedRelayAccountService.attach(source);
  }, [bridge]);

  const effectiveState = bridge ? state : SIGNED_OUT_STATE;
  const isLoaded = effectiveState.status !== "loading";
  const isSignedIn =
    effectiveState.status === "loading" ? undefined : effectiveState.status === "signedIn";
  const userId = effectiveState.status === "signedIn" ? effectiveState.identity.userId : null;
  const value: CloudAuthContextValue = {
    status: effectiveState.status,
    isLoaded,
    isSignedIn,
    userId,
    identity: effectiveState.identity,
    getToken: () => (bridge ? bridge.getAccessToken() : Promise.resolve(null)),
    signIn: async () => {
      if (!bridge) return SIGNED_OUT_STATE;
      const next = await bridge.signIn();
      setState(next);
      return next;
    },
    signOut: async () => {
      if (!bridge) return SIGNED_OUT_STATE;
      const next = await bridge.signOut();
      setState(next);
      return next;
    },
  };

  return <CloudAuthContext value={value}>{children}</CloudAuthContext>;
}
