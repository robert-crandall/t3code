#!/usr/bin/env node
import * as NodeChildProcess from "node:child_process";
import * as NodeFSP from "node:fs/promises";
import * as NodeModule from "node:module";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import * as NodeURL from "node:url";

const requireFromScripts = NodeModule.createRequire(
  new URL("../scripts/package.json", import.meta.url),
);
const Effect = await import(
  NodeURL.pathToFileURL(requireFromScripts.resolve("effect/Effect")).href
);
const NodeServices = await import(
  NodeURL.pathToFileURL(requireFromScripts.resolve("@effect/platform-node/NodeServices")).href
);
const Schema = await import(
  NodeURL.pathToFileURL(requireFromScripts.resolve("effect/Schema")).href
);
import { fromYaml } from "../packages/shared/src/schemaYaml.ts";

import rootPackageJson from "../package.json" with { type: "json" };
import desktopPackageJson from "../apps/desktop/package.json" with { type: "json" };
import serverPackageJson from "../apps/server/package.json" with { type: "json" };
import { resolveCatalogDependencies } from "../scripts/lib/resolve-catalog.ts";
import {
  STAGE_INSTALL_ARGS,
  createStagePatchedDependencies,
  createStageWorkspaceConfig,
  readWorkspaceConfig,
  resolveDesktopRuntimeDependencies,
  resolveMergedStageDependencies,
} from "../scripts/build-desktop-artifact.ts";

const repoRoot = NodePath.resolve(NodePath.dirname(NodeURL.fileURLToPath(import.meta.url)), "..");
const cliArgs = process.argv.slice(2);
const cacheRoot = NodePath.resolve(
  cliArgs[0] ?? NodePath.join(NodeOS.homedir(), ".cache/t3code-mac-pnpm"),
);
const appVersion = cliArgs[1] ?? serverPackageJson.version;

const cacheDir = NodePath.join(cacheRoot, "cache");
const storeDir = NodePath.join(cacheRoot, "store");

function runCmd(
  command: string,
  args: ReadonlyArray<string>,
  cwd: string,
  extraEnv: NodeJS.ProcessEnv,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = NodeChildProcess.spawn(command, args, {
      cwd,
      stdio: "inherit",
      env: {
        ...process.env,
        ...extraEnv,
      },
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${args.join(" ")} exited with code ${code}`));
    });
  });
}

async function main(): Promise<void> {
  const tmpParent = NodePath.join(cacheRoot, "_tmp");
  await NodeFSP.mkdir(cacheDir, { recursive: true });
  await NodeFSP.mkdir(storeDir, { recursive: true });
  await NodeFSP.mkdir(tmpParent, { recursive: true });

  const pnpmEnv: NodeJS.ProcessEnv = {
    pnpm_config_cache_dir: cacheDir,
    pnpm_config_store_dir: storeDir,
    CI: "true",
  };

  const wsTmp = await NodeFSP.mkdtemp(NodePath.join(tmpParent, "ws-"));
  const stageTmp = await NodeFSP.mkdtemp(NodePath.join(tmpParent, "stage-"));

  try {
    console.log(
      `[prewarm-mac-stage] 1/2 Prewarming darwin-arm64 workspace lockfile into ${cacheRoot}...`,
    );
    await runCmd("git", ["worktree", "add", "--detach", "--force", wsTmp, "HEAD"], repoRoot, {});
    const rawWs = await NodeFSP.readFile(NodePath.join(wsTmp, "pnpm-workspace.yaml"), "utf8");
    const darwinArchBlock = [
      "",
      "supportedArchitectures:",
      "  os:",
      "    - darwin",
      "  cpu:",
      "    - arm64",
      "",
    ].join("\n");
    await NodeFSP.writeFile(
      NodePath.join(wsTmp, "pnpm-workspace.yaml"),
      `${rawWs}\n${darwinArchBlock}`,
      "utf8",
    );
    await runCmd("vp", ["install", "--frozen-lockfile", "--ignore-scripts"], wsTmp, pnpmEnv);

    console.log(
      `[prewarm-mac-stage] 2/2 Prewarming darwin-arm64 desktop stage dependencies into ${cacheRoot}...`,
    );
    const workspaceConfig = await Effect.runPromise(
      readWorkspaceConfig().pipe(Effect.provide(NodeServices.layer)),
    );
    const workspaceCatalog = workspaceConfig.catalog ?? {};
    const workspaceOverrides = workspaceConfig.overrides ?? {};
    const workspacePatchedDependencies = workspaceConfig.patchedDependencies ?? {};
    const workspaceAllowBuilds = workspaceConfig.allowBuilds;

    const resolvedOverrides = resolveCatalogDependencies(
      workspaceOverrides,
      workspaceCatalog,
      "apps/desktop",
    );
    const resolvedServerDependencies = resolveCatalogDependencies(
      serverPackageJson.dependencies,
      workspaceCatalog,
      "apps/server",
    );
    const resolvedDesktopRuntimeDependencies = resolveDesktopRuntimeDependencies(
      desktopPackageJson.dependencies,
      workspaceCatalog,
    );
    const stageDependencies = resolveMergedStageDependencies({
      platform: "mac",
      serverDependencies: resolvedServerDependencies,
      desktopDependencies: resolvedDesktopRuntimeDependencies,
      arch: "arm64",
      fffNodeVersion: serverPackageJson.dependencies["@ff-labs/fff-node"],
    });
    const stagePatchedDependencies = createStagePatchedDependencies(
      workspacePatchedDependencies,
      stageDependencies,
    );
    const stageWorkspaceConfig = createStageWorkspaceConfig({
      platform: "mac",
      arch: "arm64",
      allowBuilds: workspaceAllowBuilds,
      patchedDependencies: stagePatchedDependencies,
      overrides: resolvedOverrides,
    });
    const encodeYaml = Schema.encodeSync(fromYaml(Schema.Unknown));
    const stageWorkspaceYaml = encodeYaml(stageWorkspaceConfig);

    const stagePackageJson = {
      name: "t3code",
      version: appVersion,
      private: true,
      packageManager: rootPackageJson.packageManager,
      dependencies: stageDependencies,
      devDependencies: {
        electron: desktopPackageJson.dependencies.electron,
      },
    };

    await NodeFSP.writeFile(
      NodePath.join(stageTmp, "package.json"),
      `${JSON.stringify(stagePackageJson, null, 2)}\n`,
      "utf8",
    );
    await NodeFSP.writeFile(
      NodePath.join(stageTmp, "pnpm-workspace.yaml"),
      stageWorkspaceYaml,
      "utf8",
    );
    if (Object.keys(stagePatchedDependencies).length > 0) {
      await NodeFSP.cp(NodePath.join(repoRoot, "patches"), NodePath.join(stageTmp, "patches"), {
        recursive: true,
      });
    }

    await runCmd("vp", [...STAGE_INSTALL_ARGS, "--ignore-scripts"], stageTmp, pnpmEnv);
    console.log(`[prewarm-mac-stage] Done. darwin-arm64 cache & store ready at ${cacheRoot}`);
  } finally {
    await runCmd("git", ["worktree", "remove", "--force", wsTmp], repoRoot, {}).catch(() => {});
    await NodeFSP.rm(wsTmp, { recursive: true, force: true }).catch(() => {});
    await NodeFSP.rm(stageTmp, { recursive: true, force: true }).catch(() => {});
  }
}

await main();
