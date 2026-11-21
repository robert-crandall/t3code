#!/usr/bin/env bash
set -euo pipefail

STAGED_APP="${1:-$HOME/.local/state/t3code-custom/staged/T3 Code (Beta).app}"
VERSION="${2:-}"
WAIT_MODE="${3:-}"
TARGET_APP="/Applications/T3 Code (Beta).app"
STATE_DIR="$HOME/.local/state/t3code-custom"
LOCK_DIR="$STATE_DIR/swap.lock"

mkdir -p "$STATE_DIR"

if [[ -z "$VERSION" && -f "$STATE_DIR/staged-version" ]]; then
  VERSION="$(cat "$STATE_DIR/staged-version")"
fi

if [[ ! -d "$STAGED_APP" ]]; then
  echo "[swap-mac-app] No staged app at $STAGED_APP; nothing to swap."
  exit 0
fi

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "[swap-mac-app] Another swapper is already waiting/running."
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

is_target_running() {
  ps -ax -o command= | grep -Fq "/Applications/T3 Code (Beta).app/Contents/"
}

if is_target_running; then
  if [[ "$WAIT_MODE" != "--wait" ]]; then
    echo "[swap-mac-app] $TARGET_APP is currently active; staged build ($VERSION) will swap once exited."
    exit 2
  fi
  echo "[swap-mac-app] Waiting for $TARGET_APP to exit before swapping to $VERSION..."
  while is_target_running; do
    sleep 10
  done
  sleep 2
fi

if [[ ! -d "$STAGED_APP" ]]; then
  echo "[swap-mac-app] Staged app already consumed."
  exit 0
fi

NEXT_APP="/Applications/.T3 Code (Beta).app.next"
PREV_APP="/Applications/.T3 Code (Beta).app.prev"

rm -rf "$NEXT_APP" "$PREV_APP"
ditto "$STAGED_APP" "$NEXT_APP"
xattr -cr "$NEXT_APP" || true
codesign --verify --deep --strict "$NEXT_APP"

if [[ -d "$TARGET_APP" ]]; then
  mv "$TARGET_APP" "$PREV_APP"
fi
if mv "$NEXT_APP" "$TARGET_APP"; then
  rm -rf "$PREV_APP" "$STAGED_APP"
  rm -f "$STATE_DIR/staged-version"
  if [[ -n "$VERSION" ]]; then
    printf '%s\n' "$VERSION" > "$STATE_DIR/installed-mac-version"
  fi
  echo "[swap-mac-app] Installed $TARGET_APP (${VERSION:-unknown})."
else
  if [[ -d "$PREV_APP" && ! -d "$TARGET_APP" ]]; then
    mv "$PREV_APP" "$TARGET_APP"
  fi
  echo "[swap-mac-app] Failed to move $NEXT_APP into $TARGET_APP; restored previous app." >&2
  exit 1
fi
