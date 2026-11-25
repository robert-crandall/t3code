import { T, useGT } from "gt-react";
import { LogInIcon, UserIcon } from "lucide-react";

import { useCloudAuth } from "../../cloud/managedAuth";
import { hasCloudPublicConfig } from "../../cloud/publicConfig";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "../ui/sidebar";
import { useT3ConnectAccountPage } from "./T3ConnectAccountPages";
import { useT3ConnectAuthPrompt } from "./useT3ConnectAuthPrompt";

export function T3ConnectSidebarSignIn() {
  if (!hasCloudPublicConfig()) return null;

  return <ConfiguredT3ConnectSidebarSignIn />;
}

export function T3ConnectSidebarAvatar() {
  if (!hasCloudPublicConfig()) return null;

  return <ConfiguredT3ConnectSidebarAvatar />;
}

function ConfiguredT3ConnectSidebarAvatar() {
  const { isLoaded, isSignedIn, identity } = useCloudAuth();
  const accountPage = useT3ConnectAccountPage();
  const gt = useGT();

  if (!isLoaded || !isSignedIn) return null;

  const label = identity?.login ? `@${identity.login}` : gt("T3 Connect account");
  const initial = identity?.login?.charAt(0).toUpperCase() ?? null;

  return (
    <>
      <button
        type="button"
        aria-label={label}
        onClick={() => accountPage.open?.("account")}
        className="mb-1 flex size-9 items-center justify-center rounded-lg p-1 text-xs font-medium text-foreground transition-colors hover:bg-sidebar-row-hover"
      >
        <span className="flex size-7 items-center justify-center rounded-full bg-accent text-accent-foreground">
          {initial ?? <UserIcon className="size-4" />}
        </span>
      </button>
      {accountPage.portals}
    </>
  );
}

function ConfiguredT3ConnectSidebarSignIn() {
  const { isLoaded, isSignedIn } = useCloudAuth();
  const { openAuthPrompt } = useT3ConnectAuthPrompt();

  if (!isLoaded || isSignedIn) return null;

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <SidebarMenuButton onClick={openAuthPrompt}>
          <LogInIcon />
          <span>
            <T>Sign in to T3 Connect</T>
          </span>
        </SidebarMenuButton>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
