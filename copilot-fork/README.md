# T3 Code Copilot Custom Fork (`robert-crandall/t3code`)

This fork maintains a Copilot-optimized build of [pingdotgg/t3code](https://github.com/pingdotgg/t3code):

- **`main`** is the single fork branch (checked out at `~/repos/robert-crandall/t3code`). It merges `upstream/main` (`pingdotgg/t3code:main`) plus vetted open Copilot/ACP pull requests tracked in [`patches.json`](./patches.json) and custom fork patches.
- **Ubuntu (`whsfront` / `ubuntu`, `/home/robert/repos/robert-crandall/t3code`)** is the primary registered T3 Code project workspace and handles all npm/pnpm registry resolution, typechecks, tests, JS bundle builds (`apps/server/dist` + `apps/desktop/dist-electron`), Linux `t3` runtime deployment (`t3code.service`), and `darwin-arm64` pnpm cache/store prewarming (`copilot-fork/prewarm-mac-stage.ts`).
- **macOS (`darwin-arm64`)** syncs the prebuilt JS bundle and `darwin-arm64` pnpm cache/store over LAN from Ubuntu, builds `T3 Code (Beta).app` completely offline (`pnpm_config_offline=true`, bypassing local macOS npm/CFS restrictions), signs with `Apple Development` (`copilot-fork/sign-mac-app.mjs`), and atomically swaps `/Applications/T3 Code (Beta).app` once idle (`copilot-fork/swap-mac-app.sh`).
- **`~/.local/bin/update-t3code`** invokes [`copilot-fork/deploy-all.sh`](./deploy-all.sh) to build and deploy both Ubuntu and macOS in lockstep with matching exact SemVer (`0.1.12-copilot.YYYYMMDD.N`).
