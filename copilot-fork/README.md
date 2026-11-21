# T3 Code Copilot Custom Fork (`robert-crandall/t3code`)

This fork maintains a Copilot-optimized build of [pingdotgg/t3code](https://github.com/pingdotgg/t3code):

- **`main`** mirrors `pingdotgg/t3code:main` cleanly (`git merge --ff-only upstream/main`).
- **`copilot-custom`** carries `upstream/main` plus vetted open Copilot/ACP pull requests tracked in [`patches.json`](./patches.json).
- **`~/.local/bin/update-t3code`** syncs/builds/deploys `copilot-custom` to:
  - **macOS (`darwin-arm64`)**: code-signed `T3 Code (Beta).app` (`Apple Development: robert.crandall@outlook.com (3G2LN5PQZN)`), staged safely when T3 Code is running and atomically swapped into `/Applications/T3 Code (Beta).app` once idle/exited.
  - **Ubuntu (`ubuntu` / `192.168.16.15`, `linux-x64`)**: standalone `t3` runtime archive installed under `~/.t3/runtime/versions/<version>` with `t3 service install` updating `t3code.service` on port `3773`.
