import { DEFAULT_HOSTED_APP_URL } from "@t3tools/shared/connectAuth";
import { afterEach, expect, it, vi } from "vite-plus/test";

import appleAppSiteAssociation from "../web/public/.well-known/apple-app-site-association.json";
import assetLinks from "../web/public/.well-known/assetlinks.json";

// Keep config parsing independent of local env files and build credentials.
let mockRepoEnv: Record<string, string | undefined> = {};
let lastLoadRepoEnvOptions: { loadFiles?: boolean } | undefined;

vi.mock("../../scripts/lib/public-config.ts", () => ({
  loadRepoEnv: (options?: { loadFiles?: boolean }) => {
    lastLoadRepoEnvOptions = options;
    return { APP_VARIANT: process.env.APP_VARIANT, ...mockRepoEnv };
  },
}));

afterEach(() => {
  mockRepoEnv = {};
  lastLoadRepoEnvOptions = undefined;
  vi.unstubAllEnvs();
});

async function loadConfig(
  variant: string | undefined,
  env: Record<string, string | undefined> = {},
) {
  vi.resetModules();
  mockRepoEnv = env;
  vi.stubEnv("APP_VARIANT", variant);
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      vi.stubEnv(key, value);
    }
  }
  return (await import("./app.config.ts")).default;
}

it.each(["prod", ""])("rejects APP_VARIANT=%j before selecting production IDs", async (value) => {
  await expect(loadConfig(value)).rejects.toThrow(
    "APP_VARIANT must be development, preview, or production.",
  );
});

it.each([
  [undefined, "com.t3tools.t3code"],
  ["development", "com.t3tools.t3code.dev"],
  ["preview", "com.t3tools.t3code.preview"],
  ["production", "com.t3tools.t3code"],
])("keeps the iOS and Android identifiers for APP_VARIANT=%j", async (value, identifier) => {
  const config = await loadConfig(value);
  expect(lastLoadRepoEnvOptions).toEqual({ loadFiles: true });
  expect(config.ios?.bundleIdentifier).toBe(identifier);
  expect(config.ios?.appleTeamId).toBe("ARK85ZXQ4Z");
  expect(config.android?.package).toBe(identifier);
  expect(config.owner).toBe("pingdotgg");
  expect(config.extra?.eas?.projectId).toBe("d763fcb8-d37c-41ea-a773-b54a0ab4a454");
  expect(config.updates?.url).toBe("https://u.expo.dev/d763fcb8-d37c-41ea-a773-b54a0ab4a454");
  expect(config.extra?.observability?.tracesUrl).toBe("https://api.axiom.co/v1/traces");
  const clerkPlugin = (config.plugins ?? []).find(
    (entry) => Array.isArray(entry) && entry[0] === "@clerk/expo",
  ) as [string, { appleSignIn: boolean }] | undefined;
  expect(clerkPlugin?.[1].appleSignIn).toBe(true);
  // Copied thread links open this app only while app.t3.codes lists it.
  const host = new URL(DEFAULT_HOSTED_APP_URL).host;
  expect(config.ios?.associatedDomains).toContain(`applinks:${host}`);
  expect(appleAppSiteAssociation.applinks.details[0]?.appIDs).toContain(
    `${config.ios?.appleTeamId}.${identifier}`,
  );
  expect(config.android?.intentFilters?.[0]?.data).toEqual([
    { scheme: "https", host, pathPrefix: "/threads/" },
  ]);
  expect(assetLinks.map((link) => link.target.package_name)).toContain(identifier);
});

it("passes loadFiles=false when T3CODE_MOBILE_IGNORE_REPO_ENV=1", async () => {
  await loadConfig("production", { T3CODE_MOBILE_IGNORE_REPO_ENV: "1" });
  expect(lastLoadRepoEnvOptions).toEqual({ loadFiles: false });
});

it("supports custom paid-team iOS builds without upstream Ping defaults", async () => {
  const config = await loadConfig("production", {
    T3CODE_IOS_BUNDLE_ID: "cloud.crandalls.t3code",
    T3CODE_IOS_TEAM_ID: "7492ZAHAJV",
    T3CODE_MOBILE_APP_NAME: "T3 Code Private",
    T3CODE_MOBILE_SCHEME: "t3code-private",
    T3CODE_IOS_BUILD_NUMBER: "202604171200",
    T3CODE_RELAY_URL: "   ",
    EXPO_PUBLIC_OTLP_TRACES_URL: "   ",
  });

  expect(config.name).toBe("T3 Code Private");
  expect(config.scheme).toBe("t3code-private");
  expect(config.ios?.bundleIdentifier).toBe("cloud.crandalls.t3code");
  expect(config.ios?.buildNumber).toBe("202604171200");
  expect(config.ios?.appleTeamId).toBe("7492ZAHAJV");
  expect(config.ios?.associatedDomains).toBeUndefined();
  expect(config.ios?.entitlements?.["keychain-access-groups"]).toEqual([
    "$(AppIdentifierPrefix)cloud.crandalls.t3code",
  ]);
  expect(config.updates?.enabled).toBe(false);
  expect(config.updates?.url).toBeUndefined();
  expect(config.owner).toBeUndefined();
  expect(config.extra?.eas?.projectId).toBeUndefined();
  expect(config.extra?.relay?.url).toBeNull();
  expect(config.extra?.observability?.tracesUrl).toBeNull();

  const plugins = config.plugins ?? [];
  const clerkPlugin = plugins.find(
    (entry) => Array.isArray(entry) && entry[0] === "@clerk/expo",
  ) as [string, { appleSignIn: boolean }] | undefined;
  expect(clerkPlugin?.[1].appleSignIn).toBe(false);

  const widgetsPlugin = plugins.find(
    (entry) => Array.isArray(entry) && entry[0] === "expo-widgets",
  ) as [string, { bundleIdentifier: string; groupIdentifier: string }] | undefined;
  expect(widgetsPlugin?.[1].bundleIdentifier).toBe("cloud.crandalls.t3code.widgets");
  expect(widgetsPlugin?.[1].groupIdentifier).toBe("group.cloud.crandalls.t3code");

  const sharingPlugin = plugins.find(
    (entry) => Array.isArray(entry) && entry[0] === "expo-sharing",
  ) as
    | [string, { ios: { enabled: boolean; extensionBundleIdentifier: string; appGroupId: string } }]
    | undefined;
  expect(sharingPlugin?.[1].ios.enabled).toBe(true);
  expect(sharingPlugin?.[1].ios.extensionBundleIdentifier).toBe("cloud.crandalls.t3code.sharing");
  expect(sharingPlugin?.[1].ios.appGroupId).toBe("group.cloud.crandalls.t3code");
});

it("wires custom relying party and EAS project into custom iOS builds when configured", async () => {
  const config = await loadConfig("production", {
    T3CODE_IOS_BUNDLE_ID: "cloud.crandalls.t3code",
    T3CODE_IOS_TEAM_ID: "7492ZAHAJV",
    T3CODE_IOS_RELYING_PARTY: "clerk.crandalls.cloud",
    T3CODE_EAS_PROJECT_ID: "11111111-2222-3333-4444-555555555555",
    T3CODE_EXPO_OWNER: "robert-crandall",
    T3CODE_IOS_APPLE_SIGN_IN: "1",
  });

  expect(config.ios?.associatedDomains).toEqual([
    "applinks:clerk.crandalls.cloud",
    "webcredentials:clerk.crandalls.cloud",
  ]);
  expect(config.updates?.enabled).toBe(true);
  expect(config.updates?.url).toBe("https://u.expo.dev/11111111-2222-3333-4444-555555555555");
  expect(config.extra?.eas?.projectId).toBe("11111111-2222-3333-4444-555555555555");
  expect(config.owner).toBe("robert-crandall");

  const clerkPlugin = (config.plugins ?? []).find(
    (entry) => Array.isArray(entry) && entry[0] === "@clerk/expo",
  ) as [string, { appleSignIn: boolean }] | undefined;
  expect(clerkPlugin?.[1].appleSignIn).toBe(true);
});

it("preserves upstream defaults for upstream personal-team builds while omitting associatedDomains", async () => {
  const config = await loadConfig("development", {
    T3CODE_IOS_PERSONAL_TEAM: "1",
    T3CODE_IOS_PERSONAL_TEAM_BUNDLE_ID: "com.dev.t3code.personal",
  });

  expect(config.ios?.bundleIdentifier).toBe("com.dev.t3code.personal");
  expect(config.ios?.associatedDomains).toBeUndefined();
  expect(config.ios?.entitlements?.["keychain-access-groups"]).toEqual([
    "$(AppIdentifierPrefix)com.t3tools.t3code.dev",
  ]);
  expect(config.owner).toBe("pingdotgg");
  expect(config.extra?.eas?.projectId).toBe("d763fcb8-d37c-41ea-a773-b54a0ab4a454");
});

it("places withoutIosPersonalTeamCapabilities before expo-notifications and omits associatedDomains", async () => {
  const config = await loadConfig("production", {
    T3CODE_IOS_PERSONAL_TEAM: "1",
    T3CODE_IOS_BUNDLE_ID: "cloud.crandalls.t3code",
    T3CODE_IOS_TEAM_ID: "7492ZAHAJV",
    T3CODE_IOS_RELYING_PARTY: "clerk.crandalls.cloud",
  });

  expect(config.ios?.associatedDomains).toBeUndefined();
  const plugins = config.plugins ?? [];
  const stripIndex = plugins.findIndex(
    (entry) => entry === "./plugins/withoutIosPersonalTeamCapabilities.cjs",
  );
  const notificationsIndex = plugins.findIndex(
    (entry) => Array.isArray(entry) && entry[0] === "expo-notifications",
  );
  expect(stripIndex).toBeGreaterThanOrEqual(0);
  expect(notificationsIndex).toBeGreaterThan(stripIndex);
});

it("treats whitespace-only custom override env vars as unset", async () => {
  const config = await loadConfig("production", {
    T3CODE_MOBILE_APP_NAME: "   ",
    T3CODE_MOBILE_SCHEME: "  ",
    T3CODE_IOS_TEAM_ID: " ",
    T3CODE_IOS_BUNDLE_ID: " ",
    T3CODE_IOS_BUILD_NUMBER: " ",
  });

  expect(config.name).toBe("T3 Code");
  expect(config.scheme).toBe("t3code");
  expect(config.ios?.bundleIdentifier).toBe("com.t3tools.t3code");
  expect(config.ios?.appleTeamId).toBe("ARK85ZXQ4Z");
  expect(config.ios?.buildNumber).toBeUndefined();
});

it("rejects invalid custom iOS bundle IDs, team IDs, schemes, relying parties, and build numbers", async () => {
  await expect(
    loadConfig("production", { T3CODE_IOS_BUNDLE_ID: "not-reverse-dns" }),
  ).rejects.toThrow("T3CODE_IOS_BUNDLE_ID");
  await expect(loadConfig("production", { T3CODE_IOS_TEAM_ID: "bad-team" })).rejects.toThrow(
    "T3CODE_IOS_TEAM_ID",
  );
  await expect(loadConfig("production", { T3CODE_MOBILE_SCHEME: "Bad_Scheme" })).rejects.toThrow(
    "T3CODE_MOBILE_SCHEME",
  );
  await expect(
    loadConfig("production", { T3CODE_IOS_RELYING_PARTY: "https://clerk.example.com" }),
  ).rejects.toThrow("T3CODE_IOS_RELYING_PARTY");
  await expect(loadConfig("production", { T3CODE_IOS_BUILD_NUMBER: "1.0-beta" })).rejects.toThrow(
    "T3CODE_IOS_BUILD_NUMBER",
  );
});
