#!/usr/bin/env node
import * as NodeChildProcess from "node:child_process";
import * as NodeFSP from "node:fs/promises";
import * as NodeModule from "node:module";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

const requireFromScripts = NodeModule.createRequire(
  new URL("../scripts/package.json", import.meta.url),
);
const { signAsync } = requireFromScripts("@electron/osx-sign");

const cliArgs = process.argv.slice(2);
const appPath = cliArgs[0];
if (!appPath) {
  console.error("Usage: node copilot-fork/sign-mac-app.mjs <path-to-.app> [signing-identity]");
  process.exit(1);
}

const resolvedAppPath = NodePath.resolve(appPath);

function resolveIdentity(explicitIdentity) {
  if (explicitIdentity) return explicitIdentity;
  const out = NodeChildProcess.execFileSync(
    "security",
    ["find-identity", "-v", "-p", "codesigning"],
    { encoding: "utf8" },
  );
  const devIdMatch = out.match(/"(Developer ID Application: [^"]+)"/);
  if (devIdMatch) return devIdMatch[1];
  const appleDevMatch = out.match(/"(Apple Development: [^"]+)"/);
  if (appleDevMatch) return appleDevMatch[1];
  throw new Error(`No Apple code-signing identity found in keychain:\n${out}`);
}

const ENTITLEMENTS_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.allow-jit</key>
  <true/>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
  <true/>
  <key>com.apple.security.cs.disable-library-validation</key>
  <true/>
  <key>com.apple.security.device.audio-input</key>
  <true/>
  <key>com.apple.security.device.camera</key>
  <true/>
</dict>
</plist>
`;

const identity = resolveIdentity(cliArgs[1]);
const tmpDir = await NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3code-mac-sign-"));
const entitlementsPath = NodePath.join(tmpDir, "entitlements.mac.plist");

try {
  await NodeFSP.writeFile(entitlementsPath, ENTITLEMENTS_PLIST, "utf8");
  NodeChildProcess.execFileSync("xattr", ["-cr", resolvedAppPath]);

  console.log(`[sign-mac-app] Signing ${resolvedAppPath} with "${identity}"...`);
  await signAsync({
    app: resolvedAppPath,
    identity,
    hardenedRuntime: true,
    entitlements: entitlementsPath,
    entitlementsInherit: entitlementsPath,
    platform: "darwin",
    batchCodesignCalls: true,
  });

  console.log("[sign-mac-app] Verifying deep strict code signature...");
  NodeChildProcess.execFileSync(
    "codesign",
    ["--verify", "--deep", "--strict", "--verbose=2", resolvedAppPath],
    { stdio: "inherit" },
  );

  const macosDir = NodePath.join(resolvedAppPath, "Contents", "MacOS");
  const entries = await NodeFSP.readdir(macosDir);
  const mainExecutable = NodePath.join(macosDir, entries[0]);
  console.log(`[sign-mac-app] Running AMFI execution check on ${mainExecutable}...`);
  const amfiOut = NodeChildProcess.execFileSync(mainExecutable, ["-e", "console.log('amfi-ok')"], {
    env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
    encoding: "utf8",
  }).trim();
  if (amfiOut !== "amfi-ok") {
    throw new Error(`Unexpected AMFI smoke output: ${amfiOut}`);
  }
  console.log("[sign-mac-app] Code signature and AMFI execution verified.");
} finally {
  await NodeFSP.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
}
