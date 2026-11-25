import { LogOutIcon, MessageSquareIcon, ServerIcon, SmartphoneIcon, UserIcon } from "lucide-react";
import { msg, T, useGT, useMessages } from "gt-react";
import { type ReactNode, useState } from "react";

import { useCloudAuth } from "../../cloud/managedAuth";
import { cn } from "../../lib/utils";
import { Button } from "../ui/button";
import { Dialog, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "../ui/dialog";
import { MobileClientsUserProfilePage } from "./MobileClientsUserProfilePage";
import { T3ChatUserProfilePage } from "./T3ChatUserProfilePage";
import { T3ConnectUserProfilePage } from "./T3ConnectUserProfilePage";

function AccountOverviewPage({ onSignedOut }: { readonly onSignedOut: () => void }) {
  const { identity, signOut } = useCloudAuth();
  const [signingOut, setSigningOut] = useState(false);

  const handleSignOut = () => {
    if (signingOut) return;
    setSigningOut(true);
    void signOut()
      .then(
        () => {
          onSignedOut();
        },
        () => undefined,
      )
      .finally(() => {
        setSigningOut(false);
      });
  };

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border p-4">
        <p className="text-xs font-medium text-muted-foreground">
          <T>Signed in with GitHub</T>
        </p>
        <p className="mt-1 text-sm font-medium text-foreground">
          {identity?.login ? `@${identity.login}` : (identity?.userId ?? "")}
        </p>
        {identity?.email ? (
          <p className="mt-0.5 text-xs text-muted-foreground">{identity.email}</p>
        ) : null}
      </div>
      <div className="flex justify-end">
        <Button size="sm" variant="outline" disabled={signingOut} onClick={handleSignOut}>
          <LogOutIcon className="size-4" />
          <T>Sign out</T>
        </Button>
      </div>
    </div>
  );
}

const T3_CONNECT_ACCOUNT_PAGES = [
  {
    label: msg("Account"),
    url: "account",
    icon: <UserIcon className="size-4" />,
  },
  {
    label: msg("Mobile clients"),
    url: "mobile-clients",
    icon: <SmartphoneIcon className="size-4" />,
  },
  {
    label: "T3 Connect",
    url: "t3-connect",
    icon: <ServerIcon className="size-4" />,
  },
  {
    label: "T3 Chat",
    url: "t3-chat",
    icon: <MessageSquareIcon className="size-4" />,
  },
] as const;

export type T3ConnectAccountPageUrl = (typeof T3_CONNECT_ACCOUNT_PAGES)[number]["url"];

function renderAccountPageContent(page: T3ConnectAccountPageUrl, onClose: () => void): ReactNode {
  switch (page) {
    case "account":
      return <AccountOverviewPage onSignedOut={onClose} />;
    case "mobile-clients":
      return <MobileClientsUserProfilePage />;
    case "t3-connect":
      return <T3ConnectUserProfilePage />;
    case "t3-chat":
      return <T3ChatUserProfilePage />;
  }
}

export function useT3ConnectAccountPage(): {
  readonly open: ((page?: T3ConnectAccountPageUrl) => void) | null;
  readonly portals: ReactNode;
} {
  const { isSignedIn } = useCloudAuth();
  const gt = useGT();
  const m = useMessages();
  const [activePage, setActivePage] = useState<T3ConnectAccountPageUrl | null>(null);

  if (!isSignedIn && activePage !== null) {
    setActivePage(null);
  }

  const open = (page: T3ConnectAccountPageUrl = "t3-connect") => {
    setActivePage(page);
  };

  const close = () => setActivePage(null);

  const portals = (
    <Dialog
      open={isSignedIn === true && activePage !== null}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) close();
      }}
    >
      <DialogPopup className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{gt("T3 Connect account")}</DialogTitle>
          <div className="mt-2 flex flex-wrap gap-1 border-b border-border pb-2" role="tablist">
            {T3_CONNECT_ACCOUNT_PAGES.map((page) => {
              const selected = activePage === page.url;
              return (
                <button
                  key={page.url}
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  onClick={() => setActivePage(page.url)}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors",
                    selected
                      ? "bg-accent text-accent-foreground"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground",
                  )}
                >
                  {page.icon}
                  <span>{m(page.label)}</span>
                </button>
              );
            })}
          </div>
        </DialogHeader>
        <DialogPanel>{activePage ? renderAccountPageContent(activePage, close) : null}</DialogPanel>
      </DialogPopup>
    </Dialog>
  );

  return { open: isSignedIn ? open : null, portals };
}
