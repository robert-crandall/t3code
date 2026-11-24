#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.vite-plus/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MOBILE_DIR="$REPO_ROOT/apps/mobile"

MODE="simulator"
CONFIGURATION="Release"
PERSONAL_CAPABILITIES="0"
SKIP_PREBUILD="0"
ALLOW_PROVISIONING_UPDATES="0"
SIMULATOR_NAME=""
ARCHIVE_PATH=""

usage() {
  cat <<'EOF'
Usage: copilot-fork/build-ios-app.sh [options]

Builds a private-fork iOS app with your Apple Developer Team and bundle ID,
with upstream Ping EAS updates, associated domains, and Axiom defaults disabled.

Modes (pick one, default: --simulator):
  --prebuild                   Run Expo prebuild + CocoaPods install only
  --simulator                  Prebuild and compile for iOS Simulator
  --device                     Prebuild and build signed iOS device bundle
  --archive                    Prebuild and create an .xcarchive for TestFlight

Options:
  --configuration <Debug|Release>  Xcode configuration (default: Release)
  --personal-capabilities          Strip Push/Widgets/Sharing/App Groups so a
                                   wildcard provisioning profile can sign it
  --allow-provisioning-updates     Pass -allowProvisioningUpdates to xcodebuild
  --skip-prebuild                  Reuse existing apps/mobile/ios native project
  --simulator-name <name>          Simulator device name (default: iPhone 17)
  --archive-path <path>            Output .xcarchive path for --archive
  -h, --help                       Show this help

Environment overrides (also loaded from .env.ios.local if present):
  T3CODE_IOS_TEAM_ID               Apple Team ID (default: 7492ZAHAJV)
  T3CODE_IOS_BUNDLE_ID             iOS bundle ID (default: cloud.crandalls.t3code)
  T3CODE_IOS_BUILD_NUMBER          iOS CFBundleVersion (auto UTC timestamp on --archive)
  T3CODE_MOBILE_APP_NAME           Display name (default: T3 Code)
  T3CODE_MOBILE_SCHEME             URL scheme (default: t3code-private)
  T3CODE_RELAY_URL                 Optional self-hosted Cloudflare relay HTTPS URL
  T3CODE_CLERK_PUBLISHABLE_KEY     Optional custom Clerk publishable key
  T3CODE_CLERK_JWT_TEMPLATE        Optional custom Clerk JWT template
  T3CODE_IOS_RELYING_PARTY         Optional custom Clerk relying party domain
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prebuild) MODE="prebuild"; shift ;;
    --simulator) MODE="simulator"; shift ;;
    --device) MODE="device"; shift ;;
    --archive) MODE="archive"; shift ;;
    --configuration)
      [[ $# -ge 2 ]] || { echo "Missing value for --configuration" >&2; exit 1; }
      CONFIGURATION="$2"; shift 2 ;;
    --personal-capabilities) PERSONAL_CAPABILITIES="1"; shift ;;
    --allow-provisioning-updates) ALLOW_PROVISIONING_UPDATES="1"; shift ;;
    --skip-prebuild) SKIP_PREBUILD="1"; shift ;;
    --simulator-name)
      [[ $# -ge 2 ]] || { echo "Missing value for --simulator-name" >&2; exit 1; }
      SIMULATOR_NAME="$2"; shift 2 ;;
    --archive-path)
      [[ $# -ge 2 ]] || { echo "Missing value for --archive-path" >&2; exit 1; }
      ARCHIVE_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

USER_ARCHIVE_PATH="0"
if [[ -n "$ARCHIVE_PATH" ]]; then
  USER_ARCHIVE_PATH="1"
  if [[ "$ARCHIVE_PATH" != /* ]]; then
    ARCHIVE_PATH="$(pwd)/$ARCHIVE_PATH"
  fi
  if [[ -e "$ARCHIVE_PATH" || -L "$ARCHIVE_PATH" ]]; then
    echo "[build-ios] Refusing to overwrite existing --archive-path: $ARCHIVE_PATH" >&2
    exit 1
  fi
fi

ALIAS_GROUPS_JSON='[
  ["T3CODE_RELAY_URL","VITE_T3CODE_RELAY_URL"],
  ["T3CODE_CLERK_PUBLISHABLE_KEY","VITE_CLERK_PUBLISHABLE_KEY","EXPO_PUBLIC_CLERK_PUBLISHABLE_KEY"],
  ["T3CODE_CLERK_JWT_TEMPLATE","VITE_CLERK_JWT_TEMPLATE","EXPO_PUBLIC_CLERK_JWT_TEMPLATE"],
  ["T3CODE_MOBILE_OTLP_TRACES_URL","EXPO_PUBLIC_OTLP_TRACES_URL"],
  ["T3CODE_MOBILE_OTLP_TRACES_DATASET","EXPO_PUBLIC_OTLP_TRACES_DATASET"],
  ["T3CODE_MOBILE_OTLP_TRACES_TOKEN","EXPO_PUBLIC_OTLP_TRACES_TOKEN"]
]'

# Load optional local overrides without clobbering env vars already set by caller.
if [[ -f "$REPO_ROOT/.env.ios.local" ]]; then
  ENV_OVERRIDES_FILE="$(mktemp)"
  trap 'rm -f "${ENV_OVERRIDES_FILE:-}"' EXIT
  if ! node -e '
    const fs = require("node:fs");
    const { parseEnv } = require("node:util");
    const parsed = parseEnv(fs.readFileSync(process.argv[1], "utf8"));
    for (const group of JSON.parse(process.argv[2])) {
      if (group.some((k) => Object.hasOwn(process.env, k))) {
        for (const k of group) delete parsed[k];
      }
    }
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof v === "string") process.stdout.write(`${k}\0${v}\0`);
    }
  ' "$REPO_ROOT/.env.ios.local" "$ALIAS_GROUPS_JSON" > "$ENV_OVERRIDES_FILE"; then
    echo "[build-ios] Unable to load .env.ios.local; refusing build." >&2
    exit 1
  fi
  while IFS= read -r -d '' key && IFS= read -r -d '' val; do
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo "[build-ios] Ignoring invalid key in .env.ios.local: $key" >&2
      continue
    fi
    if [[ -z "${!key+x}" ]]; then
      export "$key=$val"
    fi
  done < "$ENV_OVERRIDES_FILE"
  rm -f "$ENV_OVERRIDES_FILE"
  ENV_OVERRIDES_FILE=""
fi

SIMULATOR_NAME="${SIMULATOR_NAME:-${T3CODE_IOS_SIMULATOR:-iPhone 17}}"

export APP_VARIANT="${APP_VARIANT:-production}"
export T3CODE_MOBILE_IGNORE_REPO_ENV=1
export EXPO_NO_DOTENV=1
export T3CODE_IOS_TEAM_ID="${T3CODE_IOS_TEAM_ID:-7492ZAHAJV}"
export T3CODE_IOS_BUNDLE_ID="${T3CODE_IOS_BUNDLE_ID:-cloud.crandalls.t3code}"
export T3CODE_MOBILE_APP_NAME="${T3CODE_MOBILE_APP_NAME:-T3 Code}"
export T3CODE_MOBILE_SCHEME="${T3CODE_MOBILE_SCHEME:-t3code-private}"
export T3CODE_MOBILE_UPDATES_ENABLED="${T3CODE_MOBILE_UPDATES_ENABLED:-0}"
export EXPO_NO_GIT_STATUS=1
export EXPO_NO_TELEMETRY=1

IOS_BUILD_NUMBER="${T3CODE_IOS_BUILD_NUMBER:-}"
if [[ "$MODE" == "archive" && -z "${IOS_BUILD_NUMBER//[[:space:]]/}" ]]; then
  if [[ "$SKIP_PREBUILD" == "1" ]]; then
    echo "[build-ios] Refusing --archive --skip-prebuild without T3CODE_IOS_BUILD_NUMBER: CFBundleVersion is baked during prebuild. Omit --skip-prebuild or pass T3CODE_IOS_BUILD_NUMBER matching the last prebuild." >&2
    exit 1
  fi
  export T3CODE_IOS_BUILD_NUMBER="$(date -u +%Y%m%d%H%M)"
fi

if [[ "$PERSONAL_CAPABILITIES" == "1" ]]; then
  export T3CODE_IOS_PERSONAL_TEAM=1
  export T3CODE_IOS_PERSONAL_TEAM_BUNDLE_ID="$T3CODE_IOS_BUNDLE_ID"
fi

if ! command -v pod >/dev/null 2>&1; then
  echo "[build-ios] CocoaPods (pod) not found. Install with: brew install cocoapods" >&2
  exit 1
fi

if [[ ! -x "$MOBILE_DIR/node_modules/.bin/expo" ]]; then
  echo "[build-ios] Missing $MOBILE_DIR/node_modules/.bin/expo. Run vp install first." >&2
  exit 1
fi

cd "$MOBILE_DIR"

# Evaluate resolved Expo config before prebuild/xcodebuild and fail closed on upstream leakage.
CONFIG_JSON="$(./node_modules/.bin/expo config --json)"
CONFIG_META="$(printf '%s' "$CONFIG_JSON" | node -e '
  const crypto = require("node:crypto");
  const fs = require("node:fs");
  const path = require("node:path");
  const raw = fs.readFileSync(0, "utf8");
  const forbidden = [
    "t3.codes",
    "pingdotgg",
    "ARK85ZXQ4Z",
    "d763fcb8-d37c-41ea-a773-b54a0ab4a454",
    "api.axiom.co",
  ];
  const parsed = JSON.parse(raw);
  const clerkKey = typeof parsed?.extra?.clerk?.publishableKey === "string"
    ? parsed.extra.clerk.publishableKey
    : "";
  let decodedClerk = "";
  const clerkMatch = clerkKey.match(/^pk_(?:live|test)_(.+)$/);
  if (clerkMatch) {
    decodedClerk = Buffer.from(clerkMatch[1], "base64").toString("utf8");
  }
  const haystack = `${raw}\n${decodedClerk}`.toLowerCase();
  const leaked = forbidden.filter((token) => haystack.includes(token.toLowerCase()));
  if (leaked.length > 0) {
    console.error(`[build-ios] Refusing build: resolved Expo config references upstream values: ${leaked.join(", ")}`);
    process.exit(1);
  }
  const hash = crypto.createHash("sha256").update(raw);
  const hashFile = (label, filePath) => {
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      hash.update(label).update("\0").update(fs.readFileSync(filePath)).update("\0");
    }
  };
  const hashDir = (label, dirPath) => {
    if (!fs.existsSync(dirPath)) return;
    const files = fs
      .readdirSync(dirPath, { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => path.join(entry.parentPath, entry.name))
      .sort();
    for (const file of files) {
      hashFile(`${label}/${path.relative(dirPath, file)}`, file);
    }
  };
  const repoRoot = path.resolve(process.cwd(), "../..");
  hashDir("plugins", path.join(process.cwd(), "plugins"));
  hashDir("mobile-assets", path.join(process.cwd(), "assets"));
  hashDir("brand-assets", path.join(repoRoot, "assets"));
  hashFile("mobile-package.json", path.join(process.cwd(), "package.json"));
  hashFile("pnpm-lock.yaml", path.join(repoRoot, "pnpm-lock.yaml"));
  hashDir("patches", path.join(repoRoot, "patches"));
  const marketingSiteUrl = process.env.EXPO_PUBLIC_MARKETING_SITE_URL;
  hash.update("EXPO_PUBLIC_MARKETING_SITE_URL\0").update(marketingSiteUrl === undefined ? "unset" : `set:${marketingSiteUrl}`).update("\0");
  const fingerprint = hash.digest("hex");
  const relay = typeof parsed?.extra?.relay?.url === "string" ? parsed.extra.relay.url : "";
  const teamId = typeof parsed?.ios?.appleTeamId === "string" ? parsed.ios.appleTeamId : "";
  process.stdout.write(`${fingerprint}\t${teamId}\t${relay}\n`);
')"
IFS=$'\t' read -r CONFIG_FINGERPRINT RESOLVED_TEAM_ID RESOLVED_RELAY <<< "$CONFIG_META"
if [[ -z "$RESOLVED_TEAM_ID" ]]; then
  echo "[build-ios] Resolved Expo config is missing ios.appleTeamId." >&2
  exit 1
fi

echo "[build-ios] mode=$MODE config=$CONFIGURATION team=$RESOLVED_TEAM_ID bundle=$T3CODE_IOS_BUNDLE_ID scheme=$T3CODE_MOBILE_SCHEME build=${T3CODE_IOS_BUILD_NUMBER:-default} personal_caps=$PERSONAL_CAPABILITIES"
if [[ -n "$RESOLVED_RELAY" ]]; then
  echo "[build-ios] relay=$RESOLVED_RELAY"
else
  echo "[build-ios] relay=(none - direct LAN/Tailscale pairing only; zero T3 Connect traffic)"
fi

FINGERPRINT_FILE="$MOBILE_DIR/ios/.t3code-build-fingerprint"
if [[ "$SKIP_PREBUILD" == "1" ]]; then
  if [[ ! -f "$FINGERPRINT_FILE" ]] || [[ "$(cat "$FINGERPRINT_FILE")" != "$CONFIG_FINGERPRINT" ]]; then
    echo "[build-ios] Refusing --skip-prebuild: existing apps/mobile/ios does not match current build configuration. Re-run without --skip-prebuild." >&2
    exit 1
  fi
else
  echo "[build-ios] Running expo prebuild --clean --platform ios..."
  ./node_modules/.bin/expo prebuild --clean --platform ios
  # Persist resolved fork isolation env into ios/.xcode.env.local (and unset omitted keys) so
  # direct Xcode GUI Run/Archive builds cannot inherit login-shell upstream vars or root .env.
  node -e '
    const fs = require("node:fs");
    const target = process.argv[1];
    const aliasGroups = JSON.parse(process.argv[2]);
    const quote = (value) => `\x27${value.replace(/\x27/g, "\x27\\\x27\x27")}\x27`;
    const directKeys = [
      "APP_VARIANT",
      "T3CODE_MOBILE_IGNORE_REPO_ENV",
      "EXPO_NO_DOTENV",
      "EXPO_NO_TELEMETRY",
      "T3CODE_IOS_TEAM_ID",
      "T3CODE_IOS_BUNDLE_ID",
      "T3CODE_IOS_BUILD_NUMBER",
      "T3CODE_MOBILE_APP_NAME",
      "T3CODE_MOBILE_SCHEME",
      "T3CODE_MOBILE_UPDATES_ENABLED",
      "T3CODE_MOBILE_VERSION",
      "MOBILE_VERSION_POLICY",
      "T3_SHOWCASE_CAPTURE_BUILD",
      "T3CODE_IOS_PERSONAL_TEAM",
      "T3CODE_IOS_PERSONAL_TEAM_BUNDLE_ID",
      "T3CODE_IOS_RELYING_PARTY",
      "T3CODE_EAS_PROJECT_ID",
      "T3CODE_EXPO_OWNER",
      "T3CODE_IOS_APPLE_SIGN_IN",
      "EXPO_PUBLIC_CLERK_GOOGLE_WEB_CLIENT_ID",
      "EXPO_PUBLIC_CLERK_GOOGLE_IOS_CLIENT_ID",
      "EXPO_PUBLIC_CLERK_GOOGLE_ANDROID_CLIENT_ID",
      "EXPO_PUBLIC_CLERK_GOOGLE_IOS_URL_SCHEME",
      "EXPO_PUBLIC_MARKETING_SITE_URL",
    ];
    const lines = ["", "# Private fork build isolation (written by copilot-fork/build-ios-app.sh)"];
    for (const key of directKeys) {
      const value = process.env[key];
      if (value !== undefined) {
        lines.push(`export ${key}=${quote(value)}`);
      } else {
        lines.push(`unset ${key}`);
      }
    }
    for (const group of aliasGroups) {
      const resolved = group.map((k) => process.env[k]?.trim()).find(Boolean);
      for (const key of group) {
        if (resolved !== undefined) {
          lines.push(`export ${key}=${quote(resolved)}`);
        } else {
          lines.push(`unset ${key}`);
        }
      }
    }
    fs.appendFileSync(target, `${lines.join("\n")}\n`, "utf8");
  ' "$MOBILE_DIR/ios/.xcode.env.local" "$ALIAS_GROUPS_JSON"
  printf '%s\n' "$CONFIG_FINGERPRINT" > "$FINGERPRINT_FILE"
fi

WORKSPACE="$(find "$MOBILE_DIR/ios" -maxdepth 1 -name '*.xcworkspace' | head -n 1)"
if [[ -z "$WORKSPACE" ]]; then
  echo "[build-ios] No .xcworkspace generated under $MOBILE_DIR/ios" >&2
  exit 1
fi
SCHEME="$(basename "$WORKSPACE" .xcworkspace)"
DERIVED_DATA="$MOBILE_DIR/ios/build/DerivedData"

if [[ "$MODE" == "prebuild" ]]; then
  echo "[build-ios] Prebuild complete: $WORKSPACE (scheme: $SCHEME)"
  exit 0
fi

XCODE_EXTRA_ARGS=()
if [[ "$ALLOW_PROVISIONING_UPDATES" == "1" ]]; then
  XCODE_EXTRA_ARGS+=(-allowProvisioningUpdates)
fi

case "$MODE" in
  simulator)
    echo "[build-ios] Building $SCHEME ($CONFIGURATION) for iOS Simulator ($SIMULATOR_NAME)..."
    xcodebuild \
      -workspace "$WORKSPACE" \
      -scheme "$SCHEME" \
      -configuration "$CONFIGURATION" \
      -sdk iphonesimulator \
      -destination "platform=iOS Simulator,name=$SIMULATOR_NAME" \
      -derivedDataPath "$DERIVED_DATA" \
      CODE_SIGNING_ALLOWED=NO \
      build
    APP_BUNDLE="$DERIVED_DATA/Build/Products/${CONFIGURATION}-iphonesimulator/${SCHEME}.app"
    echo "[build-ios] Simulator build succeeded: $APP_BUNDLE"
    ;;
  device)
    echo "[build-ios] Building signed $SCHEME ($CONFIGURATION) for generic iOS device..."
    xcodebuild \
      -workspace "$WORKSPACE" \
      -scheme "$SCHEME" \
      -configuration "$CONFIGURATION" \
      -sdk iphoneos \
      -destination "generic/platform=iOS" \
      -derivedDataPath "$DERIVED_DATA" \
      DEVELOPMENT_TEAM="$RESOLVED_TEAM_ID" \
      ${XCODE_EXTRA_ARGS[@]+"${XCODE_EXTRA_ARGS[@]}"} \
      build
    APP_BUNDLE="$DERIVED_DATA/Build/Products/${CONFIGURATION}-iphoneos/${SCHEME}.app"
    echo "[build-ios] Device build succeeded: $APP_BUNDLE"
    ;;
  archive)
    ARCHIVE_OUT="${ARCHIVE_PATH:-$MOBILE_DIR/ios/build/${SCHEME}.xcarchive}"
    if [[ "$USER_ARCHIVE_PATH" != "1" ]]; then
      rm -rf "$ARCHIVE_OUT"
    fi
    echo "[build-ios] Archiving $SCHEME ($CONFIGURATION) to $ARCHIVE_OUT..."
    xcodebuild \
      -workspace "$WORKSPACE" \
      -scheme "$SCHEME" \
      -configuration "$CONFIGURATION" \
      -sdk iphoneos \
      -destination "generic/platform=iOS" \
      -archivePath "$ARCHIVE_OUT" \
      DEVELOPMENT_TEAM="$RESOLVED_TEAM_ID" \
      ${XCODE_EXTRA_ARGS[@]+"${XCODE_EXTRA_ARGS[@]}"} \
      archive
    echo "[build-ios] Archive succeeded: $ARCHIVE_OUT"
    echo "[build-ios] Upload to TestFlight via Xcode Organizer: open \"$ARCHIVE_OUT\""
    ;;
esac
