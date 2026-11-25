// @effect-diagnostics nodeBuiltinImport:off - Tests exercise root env file precedence directly.
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import { afterEach, describe, expect, it } from "vite-plus/test";

import { loadRepoEnv } from "./public-config.ts";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    NodeFS.rmSync(directory, { recursive: true, force: true });
  }
});

describe("loadRepoEnv", () => {
  it("applies process, root local, and root precedence in that order", () => {
    const repoRoot = makeTemporaryDirectory();
    NodeFS.writeFileSync(
      NodePath.join(repoRoot, ".env"),
      "T3CODE_RELAY_URL=https://root.example.test\n",
    );
    NodeFS.writeFileSync(
      NodePath.join(repoRoot, ".env.local"),
      "T3CODE_RELAY_URL=https://local.example.test\n",
    );

    expect(loadRepoEnv({ baseEnv: {}, repoRoot }).T3CODE_RELAY_URL).toBe(
      "https://local.example.test",
    );
    expect(
      loadRepoEnv({
        baseEnv: {
          T3CODE_RELAY_URL: "https://ci.example.test",
        },
        repoRoot,
      }),
    ).toMatchObject({
      T3CODE_RELAY_URL: "https://ci.example.test",
      VITE_T3CODE_RELAY_URL: "https://ci.example.test",
    });
  });

  it("ignores root env files when loadFiles is false while preserving alias expansion", () => {
    const repoRoot = makeTemporaryDirectory();
    NodeFS.writeFileSync(
      NodePath.join(repoRoot, ".env"),
      "T3CODE_RELAY_URL=https://relay.t3.codes\n",
    );
    NodeFS.writeFileSync(
      NodePath.join(repoRoot, ".env.local"),
      "T3CODE_RELAY_URL=https://relay-local.t3.codes\n",
    );

    const isolatedEmpty = loadRepoEnv({
      baseEnv: { T3CODE_RELAY_URL: "" },
      repoRoot,
      loadFiles: false,
    });
    expect(isolatedEmpty.T3CODE_RELAY_URL).toBe("");
    expect(isolatedEmpty.VITE_T3CODE_RELAY_URL).toBeUndefined();

    const isolatedCustom = loadRepoEnv({
      baseEnv: {
        T3CODE_RELAY_URL: "https://relay.example.test",
      },
      repoRoot,
      loadFiles: false,
    });
    expect(isolatedCustom.T3CODE_RELAY_URL).toBe("https://relay.example.test");
    expect(isolatedCustom.VITE_T3CODE_RELAY_URL).toBe("https://relay.example.test");
  });
});

function makeTemporaryDirectory() {
  const directory = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3code-public-config-"));
  temporaryDirectories.push(directory);
  return directory;
}
