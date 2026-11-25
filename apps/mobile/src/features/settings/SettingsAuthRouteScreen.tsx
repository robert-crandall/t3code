import { useNavigation } from "@react-navigation/native";
import { useGT } from "gt-react-native";
import { useEffect, useState } from "react";
import { ScrollView, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { AppActivityIndicator } from "../../components/ui/AppActivityIndicator";
import { AppBar } from "../../components/ui/AppBar";
import { AppText as Text } from "../../components/ui/AppText";
import { Button } from "../../components/ui/Button";
import * as Dialog from "../../components/ui/Dialog";
import { useCloudAuth } from "../cloud/CloudAuthProvider";
import { hasCloudPublicConfig } from "../cloud/publicConfig";
import { T3ConnectProfilePage } from "../cloud/T3ConnectProfilePage";

// Without cloud config the app has no entry point here and appLinking drops the deep link.
export function SettingsAuthRouteScreen() {
  return hasCloudPublicConfig() ? <ConfiguredSettingsAuthRouteScreen /> : null;
}

function ConfiguredSettingsAuthRouteScreen() {
  const gt = useGT();
  const navigation = useNavigation();
  const insets = useSafeAreaInsets();
  const { isLoaded, isSignedIn, identity, signIn, signOut } = useCloudAuth();
  const handleHostBack = () => navigation.goBack();
  const [isSigningIn, setIsSigningIn] = useState(false);
  const [isSigningOut, setIsSigningOut] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  // Once signed in, stay on the account view so signing out pops back instead of
  // flashing the sign-in card.
  const [hasBeenSignedIn, setHasBeenSignedIn] = useState(isSignedIn);
  if (isSignedIn && !hasBeenSignedIn) setHasBeenSignedIn(true);

  // Follow the auth store so signing out pops the modal cleanly.
  // oxlint-disable-next-line t3code/no-unreasoned-state-sync -- pops the navigator when the cloud auth store reports a sign-out
  useEffect(() => {
    if (hasBeenSignedIn && isLoaded && !isSignedIn) {
      navigation.goBack();
    }
  }, [hasBeenSignedIn, isLoaded, isSignedIn, navigation]);

  const handleSignIn = () => {
    if (isSigningIn) return;
    setAuthError(null);
    setIsSigningIn(true);
    void signIn()
      .catch((error) => {
        setAuthError(error instanceof Error ? error.message : gt("Could not sign in with GitHub."));
      })
      .finally(() => {
        setIsSigningIn(false);
      });
  };

  const handleSignOut = () => {
    if (isSigningOut) return;
    Dialog.confirm({
      title: gt("Sign out?"),
      message: gt(
        "Cloud connections on this device will be disconnected until you sign in again. Local connections are not changed.",
      ),
      confirmText: gt("Sign out"),
      destructive: true,
      onConfirm: () => {
        setAuthError(null);
        setIsSigningOut(true);
        void signOut()
          .catch((error) => {
            setAuthError(error instanceof Error ? error.message : gt("Could not sign out."));
          })
          .finally(() => {
            setIsSigningOut(false);
          });
      },
    });
  };

  return (
    <View collapsable={false} className="flex-1 overflow-hidden bg-sheet">
      <AppBar title={hasBeenSignedIn ? gt("T3 Account") : gt("Sign in")} onClose={handleHostBack} />
      {!isLoaded ? (
        <View className="flex-1 items-center justify-center p-6">
          <AppActivityIndicator colorClassName="accent-foreground-muted" />
        </View>
      ) : hasBeenSignedIn ? (
        <T3ConnectProfilePage
          header={
            <View collapsable={false} className="border-b border-border px-6 py-5">
              <Text className="text-xs font-medium tracking-[0.3px] text-foreground-muted uppercase">
                {gt("GitHub account")}
              </Text>
              <Text className="mt-2 text-lg font-t3-bold text-foreground">
                {identity ? `@${identity.login}` : gt("Signed in")}
              </Text>
              {identity?.email ? (
                <Text className="mt-0.5 text-sm text-foreground-muted">{identity.email}</Text>
              ) : null}
            </View>
          }
          footer={
            <View
              collapsable={false}
              className="gap-3 px-6 pt-6"
              style={{ paddingBottom: Math.max(insets.bottom, 16) }}
            >
              {authError ? (
                <Text className="text-sm text-danger-foreground">{authError}</Text>
              ) : null}
              <Button
                label={gt("Sign out")}
                tone="danger"
                fullWidth
                loading={isSigningOut}
                onPress={handleSignOut}
              />
            </View>
          }
        />
      ) : (
        <ScrollView
          className="flex-1"
          contentInsetAdjustmentBehavior="automatic"
          contentContainerStyle={{
            paddingHorizontal: 20,
            paddingTop: 20,
            paddingBottom: Math.max(insets.bottom, 24) + 16,
            gap: 16,
          }}
        >
          <View collapsable={false} className="gap-4 rounded-[24px] bg-grouped-card p-5">
            <View collapsable={false} className="gap-1.5">
              <Text className="text-lg font-t3-bold text-foreground">
                {gt("Sign in to {product}", { product: "T3 Connect" })}
              </Text>
              <Text className="text-sm leading-normal text-foreground-muted">
                {gt(
                  "Sign in with GitHub to reach your servers through {product} and enable agent activity notifications.",
                  { product: "T3 Connect" },
                )}
              </Text>
            </View>
            {authError ? <Text className="text-sm text-danger-foreground">{authError}</Text> : null}
            <Button
              label={gt("Sign in with GitHub")}
              tone="primary"
              fullWidth
              loading={isSigningIn}
              onPress={handleSignIn}
            />
          </View>
        </ScrollView>
      )}
    </View>
  );
}
