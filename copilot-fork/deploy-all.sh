#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.vite-plus/bin:$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

MAC_WORKTREE="${T3CODE_MAC_WORKTREE:-$HOME/repos/robert-crandall/t3code}"
UBUNTU_HOST="${T3CODE_UBUNTU_HOST:-ubuntu}"
UBUNTU_REPO="${T3CODE_UBUNTU_REPO:-/home/robert/repos/robert-crandall/t3code}"
UBUNTU_MAC_PNPM_CACHE="${T3CODE_UBUNTU_MAC_PNPM_CACHE:-/home/robert/.cache/t3code-mac-pnpm}"
MAC_PNPM_CACHE="${T3CODE_MAC_PNPM_CACHE:-$HOME/.cache/t3code-mac-pnpm}"
STATE_DIR="$HOME/.local/state/t3code-custom"

mkdir -p "$STATE_DIR" "$MAC_PNPM_CACHE"

cd "$MAC_WORKTREE"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "[deploy-all] Refusing to run with dirty working tree in $MAC_WORKTREE" >&2
  git status -sb >&2
  exit 1
fi

HEAD_SHA="$(git rev-parse HEAD)"
BASE_VER="$(node -p 'require("./apps/server/package.json").version')"

compute_next_version() {
  local base="$1"
  local major minor patch next_patch today prefix seq candidate
  IFS='.' read -r major minor patch <<< "${base%%-*}"
  next_patch=$((patch + 1))
  today="$(date -u +%Y%m%d)"
  prefix="${major}.${minor}.${next_patch}-copilot.${today}."
  seq=1
  local existing_ubuntu
  existing_ubuntu="$(ssh "$UBUNTU_HOST" 'ls -1 ~/.t3/runtime/versions 2>/dev/null; cat ~/.t3/runtime/service-state.json 2>/dev/null || true')"
  while true; do
    candidate="${prefix}${seq}"
    if ! grep -Fxq "$candidate" <<<"$existing_ubuntu" &&
       [[ "$existing_ubuntu" != *"\"$candidate\""* ]] &&
       [[ "$(cat "$STATE_DIR/installed-mac-version" 2>/dev/null || true)" != "$candidate" ]] &&
       [[ "$(cat "$STATE_DIR/staged-version" 2>/dev/null || true)" != "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
    seq=$((seq + 1))
  done
}

VERSION="${1:-$(compute_next_version "$BASE_VER")}"
echo "[deploy-all] Building & deploying version $VERSION from commit $HEAD_SHA"

echo "[deploy-all] Step 1/4: Syncing commit $HEAD_SHA to $UBUNTU_HOST:$UBUNTU_REPO and building JS bundle + Linux CLI + Mac darwin-arm64 pnpm cache..."
ssh "$UBUNTU_HOST" bash -s -- "$UBUNTU_REPO" "$HEAD_SHA" "$VERSION" "$UBUNTU_MAC_PNPM_CACHE" <<'EOF_UBUNTU'
set -euo pipefail
export PATH="$HOME/.vite-plus/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

REPO_DIR="$1"
TARGET_SHA="$2"
VERSION="$3"
MAC_CACHE_DIR="$4"

cd "$REPO_DIR"
git checkout -- .
git fetch origin --prune
git checkout -B main "$TARGET_SHA"

cleanup() {
  git -C "$REPO_DIR" checkout -- . >/dev/null 2>&1 || true
  if [[ -n "${TMP_STAGE:-}" && -d "${TMP_STAGE:-}" ]]; then
    rm -rf "$TMP_STAGE"
  fi
}
trap cleanup EXIT

vp install --frozen-lockfile

node scripts/update-release-package-versions.ts "$VERSION"

export T3CODE_RELAY_URL="https://relay.crandalls.cloud"
export T3CODE_TELEMETRY_CHANNEL="dev"
export APP_VERSION="$VERSION"

rm -rf apps/server/dist apps/desktop/dist-electron
vp run --concurrency-limit 2 build:desktop:bundle
node scripts/apply-web-brand-assets.ts production apps/server/dist/client

cargo build --locked --release --manifest-path native/resource-monitor/Cargo.toml --target x86_64-unknown-linux-gnu

TMP_STAGE="$(mktemp -d /tmp/t3code-linux-cli-XXXXXX)"
mkdir -p "$TMP_STAGE/cli-resource-monitor/linux-x64" "$TMP_STAGE/release-cli"
cp native/resource-monitor/target/x86_64-unknown-linux-gnu/release/t3-resource-monitor \
  "$TMP_STAGE/cli-resource-monitor/linux-x64/t3-resource-monitor"

node apps/server/scripts/cli.ts build-exe
node scripts/build-cli-archive.ts \
  --platform linux \
  --arch x64 \
  --version "$VERSION" \
  --resource-monitor-dir "$TMP_STAGE/cli-resource-monitor" \
  --output-dir "$TMP_STAGE/release-cli"

ARCHIVE="$TMP_STAGE/release-cli/t3-${VERSION}-linux-x64.tar.gz"
node scripts/smoke-cli-archive.ts --archive "$ARCHIVE" --expect-version "$VERSION"

echo "[ubuntu] Prewarming darwin-arm64 pnpm cache/store for offline Mac packaging..."
node copilot-fork/prewarm-mac-stage.ts "$MAC_CACHE_DIR" "$VERSION"

echo "[ubuntu] Installing Linux runtime $VERSION and restarting t3code.service..."
VERSIONS_DIR="$HOME/.t3/runtime/versions"
DEST_DIR="$VERSIONS_DIR/$VERSION"
TMP_INSTALL="$VERSIONS_DIR/.tmp-${VERSION}-$$"
mkdir -p "$VERSIONS_DIR" "$HOME/.local/bin"
rm -rf "$TMP_INSTALL" "$DEST_DIR"
mkdir -p "$TMP_INSTALL"
tar -xzf "$ARCHIVE" -C "$TMP_INSTALL" --strip-components=1
printf '%s\n' "$VERSION" > "$TMP_INSTALL/.install-complete"
mv "$TMP_INSTALL" "$DEST_DIR"

printf '{"protocol":4,"activeVersion":"%s"}\n' "$VERSION" > "$HOME/.t3/runtime/service-state.json"

cat > "$HOME/.local/bin/t3" <<EOF_WRAPPER
#!/usr/bin/env sh
exec "$DEST_DIR/t3" "\$@"
EOF_WRAPPER
chmod +x "$HOME/.local/bin/t3"

if [[ -f "$HOME/.config/systemd/user/t3code.service" ]]; then
  sed -i -E "s|^ExecStart=.*|ExecStart=$DEST_DIR/t3 __service-launcher|" "$HOME/.config/systemd/user/t3code.service"
  systemctl --user daemon-reload
  systemctl --user reset-failed t3code.service || true
  systemctl --user restart t3code.service
  sleep 2
  systemctl --user is-active --quiet t3code.service
fi

echo "[ubuntu] Active t3 version: $($HOME/.local/bin/t3 --version)"
EOF_UBUNTU

echo "[deploy-all] Step 2/4: Syncing prebuilt JS bundle + darwin-arm64 pnpm cache from $UBUNTU_HOST to Mac..."
rsync -az --delete "${UBUNTU_HOST}:${UBUNTU_REPO}/apps/server/dist/" "$MAC_WORKTREE/apps/server/dist/"
rsync -az --delete "${UBUNTU_HOST}:${UBUNTU_REPO}/apps/desktop/dist-electron/" "$MAC_WORKTREE/apps/desktop/dist-electron/"
rsync -az --exclude='_tmp' "${UBUNTU_HOST}:${UBUNTU_MAC_PNPM_CACHE}/" "$MAC_PNPM_CACHE/"
mkdir -p "$HOME/Library/Caches/pnpm"
if [[ -f "$MAC_PNPM_CACHE/cache/lockfile-verified.jsonl" ]]; then
  cp "$MAC_PNPM_CACHE/cache/lockfile-verified.jsonl" "$HOME/Library/Caches/pnpm/lockfile-verified.jsonl"
fi

echo "[deploy-all] Step 3/4: Building & signing macOS arm64 T3 Code (Beta).app completely offline..."
cleanup_mac() {
  git -C "$MAC_WORKTREE" checkout -- . >/dev/null 2>&1 || true
  if [[ -n "${MAC_OUT_DIR:-}" && -d "${MAC_OUT_DIR:-}" ]]; then
    rm -rf "$MAC_OUT_DIR"
  fi
}
trap cleanup_mac EXIT

export pnpm_config_cache_dir="$MAC_PNPM_CACHE/cache"
export pnpm_config_store_dir="$MAC_PNPM_CACHE/store"
export pnpm_config_offline="true"

vp install --frozen-lockfile --offline --ignore-scripts

# Mac installs offline with --ignore-scripts, skipping react-native-enriched-markdown's
# postinstall (RaTeX iOS math + tree-sitter grammars). Mirror those vendored assets from
# Ubuntu's full install so copilot-fork/build-ios-app.sh stays ready after deploy-all.
if [[ -d "$MAC_WORKTREE/apps/mobile/node_modules/react-native-enriched-markdown" ]]; then
  MAC_ENRICHED_MD="$(cd "$MAC_WORKTREE/apps/mobile/node_modules/react-native-enriched-markdown" && pwd -P)"
  UBUNTU_ENRICHED_MD="${UBUNTU_REPO}/apps/mobile/node_modules/react-native-enriched-markdown"
  echo "[deploy-all] Syncing react-native-enriched-markdown vendored native assets from $UBUNTU_HOST..."
  mkdir -p "$MAC_ENRICHED_MD/ios/vendor" "$MAC_ENRICHED_MD/cpp/highlight/vendor"
  rsync -az --delete "${UBUNTU_HOST}:${UBUNTU_ENRICHED_MD}/ios/vendor/" "$MAC_ENRICHED_MD/ios/vendor/" || rm -f "$MAC_ENRICHED_MD/ios/vendor/.stamp"
  rsync -az --delete "${UBUNTU_HOST}:${UBUNTU_ENRICHED_MD}/cpp/highlight/vendor/" "$MAC_ENRICHED_MD/cpp/highlight/vendor/" || rm -f "$MAC_ENRICHED_MD/cpp/highlight/vendor/grammars/.stamp"
  if [[ ! -f "$MAC_ENRICHED_MD/ios/vendor/.stamp" || ! -f "$MAC_ENRICHED_MD/cpp/highlight/vendor/grammars/.stamp" ]]; then
    echo "[deploy-all] WARNING: react-native-enriched-markdown vendor assets are incomplete; copilot-fork/build-ios-app.sh may fail or omit syntax highlighting." >&2
  fi
fi

cargo build --locked --release --manifest-path native/resource-monitor/Cargo.toml --target aarch64-apple-darwin
export T3CODE_DESKTOP_REUSE_RESOURCE_MONITOR="true"

node scripts/update-release-package-versions.ts "$VERSION"

MAC_OUT_DIR="$(mktemp -d /tmp/t3code-mac-dist-XXXXXX)"
vp run dist:desktop:artifact \
  --platform mac \
  --target dir \
  --arch arm64 \
  --build-version "$VERSION" \
  --output-dir "$MAC_OUT_DIR" \
  --skip-build

BUILT_APP="$MAC_OUT_DIR/mac-arm64/T3 Code (Beta).app"
node copilot-fork/sign-mac-app.mjs "$BUILT_APP"

echo "[deploy-all] Step 4/4: Staging signed app for live-safe installation..."
STAGED_DIR="$STATE_DIR/staged"
STAGED_APP="$STAGED_DIR/T3 Code (Beta).app"
rm -rf "$STAGED_DIR"
mkdir -p "$STAGED_DIR"
ditto "$BUILT_APP" "$STAGED_APP"
printf '%s\n' "$VERSION" > "$STATE_DIR/staged-version"

git -C "$MAC_WORKTREE" checkout -- .

if "$MAC_WORKTREE/copilot-fork/swap-mac-app.sh" "$STAGED_APP" "$VERSION"; then
  echo "[deploy-all] Complete! Ubuntu and Mac are both updated to $VERSION."
else
  rc=$?
  if [[ "$rc" -eq 2 ]]; then
    echo "[deploy-all] Ubuntu updated to $VERSION; Mac build $VERSION is signed and staged at $STAGED_APP (waiting for T3 Code (Beta).app to exit)."
    exit 0
  fi
  exit "$rc"
fi
