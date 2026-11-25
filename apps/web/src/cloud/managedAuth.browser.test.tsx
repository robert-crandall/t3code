import { managedRelaySessionAtom } from "@t3tools/client-runtime/relay";
import type { DesktopCloudAuthBridge, DesktopCloudAuthState } from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import { describe, expect, it, vi } from "vite-plus/test";

import { act, render } from "../../test/render";
import { appAtomRegistry } from "../rpc/atomRegistry";
import {
  deactivateManagedRelayAuthentication,
  ManagedRelayAuthProvider,
  useCloudAuth,
} from "./managedAuth";

vi.mock("../lib/runtime", () => ({
  runtime: {
    runPromiseExit: vi.fn().mockResolvedValue({ _tag: "Success", value: undefined }),
  },
}));

vi.mock("../connection/catalog", () => ({
  environmentCatalog: {
    removeRelayEnvironments: {},
  },
}));

function AuthProbe() {
  const auth = useCloudAuth();
  return (
    <div
      data-testid="auth-state"
      data-status={auth.status}
      data-user-id={auth.userId ?? ""}
      data-login={auth.identity?.login ?? ""}
    />
  );
}

function stubDesktopCloudAuth(cloudAuth: DesktopCloudAuthBridge): Disposable {
  const originalDesktopBridge = window.desktopBridge;
  window.desktopBridge = {
    ...originalDesktopBridge,
    cloudAuth,
  } as NonNullable<typeof window.desktopBridge>;
  return {
    [Symbol.dispose]() {
      if (originalDesktopBridge === undefined) {
        delete window.desktopBridge;
      } else {
        window.desktopBridge = originalDesktopBridge;
      }
      deactivateManagedRelayAuthentication();
      vi.clearAllMocks();
    },
  };
}

describe("ManagedRelayAuthProvider", () => {
  it("hydrates from desktopBridge, prefers stateChange over stale getState, cleans up on signOut, and unsubscribes on unmount", async () => {
    const getStateDeferred = Promise.withResolvers<DesktopCloudAuthState>();
    let listener: ((next: DesktopCloudAuthState) => void) | null = null;
    const unsubscribe = vi.fn(() => {
      listener = null;
    });
    const getAccessToken = vi.fn(async () => "desktop-access-token");

    using _bridge = stubDesktopCloudAuth({
      getState: vi.fn(() => getStateDeferred.promise),
      onStateChange: vi.fn((cb) => {
        listener = cb;
        return unsubscribe;
      }),
      getAccessToken,
      signIn: vi.fn(async () => ({ status: "signedOut" as const, identity: null })),
      signOut: vi.fn(async () => ({ status: "signedOut" as const, identity: null })),
    });

    await using screen = await render(
      <ManagedRelayAuthProvider>
        <AuthProbe />
      </ManagedRelayAuthProvider>,
    );

    const probe = screen.getByTestId("auth-state");
    await expect.element(probe).toHaveAttribute("data-status", "loading");
    expect(appAtomRegistry.get(managedRelaySessionAtom)).toBeNull();

    // A stateChange event arriving before getState resolves must win over the stale getState result.
    await act(async () => {
      listener?.({
        status: "signedIn",
        identity: { userId: "github:42", login: "robert-crandall", email: "robert@example.com" },
      });
    });
    await act(async () => {
      getStateDeferred.resolve({ status: "signedOut", identity: null });
      await Promise.resolve();
    });

    await expect.element(probe).toHaveAttribute("data-status", "signedIn");
    await expect.element(probe).toHaveAttribute("data-user-id", "github:42");
    await expect.element(probe).toHaveAttribute("data-login", "robert-crandall");
    expect(appAtomRegistry.get(managedRelaySessionAtom)?.accountId).toBe("github:42");

    const token = await Effect.fromNullishOr(appAtomRegistry.get(managedRelaySessionAtom)).pipe(
      Effect.flatMap((session) => session.readClerkToken()),
      Effect.runPromise,
    );
    expect(token).toBe("desktop-access-token");

    // Sign-out clears the active managed relay session.
    await act(async () => {
      listener?.({ status: "signedOut", identity: null });
    });
    await expect.element(probe).toHaveAttribute("data-status", "signedOut");
    expect(appAtomRegistry.get(managedRelaySessionAtom)).toBeNull();

    // Unmounting disposes the desktop IPC listener.
    await screen.unmount();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
  });
});
