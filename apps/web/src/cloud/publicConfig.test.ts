import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { hasCloudPublicConfig } from "./publicConfig.ts";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("hasCloudPublicConfig", () => {
  it("rejects an insecure relay URL", () => {
    vi.stubEnv("VITE_T3CODE_RELAY_URL", "http://relay.example.test");
    vi.stubGlobal("window", { location: new URL("file:///app/index.html"), desktopBridge: {} });

    expect(hasCloudPublicConfig()).toBe(false);
  });

  it("disables cloud auth in plain browsers without desktopBridge", () => {
    vi.stubEnv("VITE_T3CODE_RELAY_URL", "https://relay.example.test");
    vi.stubGlobal("window", { location: new URL("https://example.com") });

    expect(hasCloudPublicConfig()).toBe(false);
  });

  it("enables cloud auth in Electron when an HTTPS relay URL is configured", () => {
    vi.stubEnv("VITE_T3CODE_RELAY_URL", "https://relay.example.test");
    vi.stubGlobal("window", { location: new URL("file:///app/index.html"), desktopBridge: {} });

    expect(hasCloudPublicConfig()).toBe(true);
  });

  it("disables cloud auth when no relay URL is configured", () => {
    vi.stubEnv("VITE_T3CODE_RELAY_URL", "");
    vi.stubGlobal("window", { location: new URL("file:///app/index.html"), desktopBridge: {} });

    expect(hasCloudPublicConfig()).toBe(false);
  });
});
