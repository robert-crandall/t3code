import { msg, useGT } from "gt-react";
import { useRef } from "react";

import { useCloudAuth } from "../../cloud/managedAuth";
import { toastManager } from "../ui/toast";

export function useT3ConnectAuthPrompt() {
  const { signIn } = useCloudAuth();
  const gt = useGT();
  const pendingRef = useRef(false);

  const openAuthPrompt = () => {
    if (pendingRef.current) return;
    pendingRef.current = true;
    void signIn()
      .catch((error: unknown) => {
        toastManager.add({
          type: "error",
          title: gt(msg("Could not sign in to T3 Connect")),
          description: error instanceof Error ? error.message : String(error),
        });
      })
      .finally(() => {
        pendingRef.current = false;
      });
  };
  return { openAuthPrompt };
}
