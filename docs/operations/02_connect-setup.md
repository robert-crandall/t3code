# T3 Connect setup

Deployment and client configuration for T3 Connect. See [T3 Connect](../internals/06_t3-connect.md) for trust boundaries and [infra/relay/README.md](../../infra/relay/README.md#deployment) for relay provisioning.

## Public application configuration

T3 Connect is disabled in a fresh clone. Copy `.env.example` to `.env`, or set the relay URL in `.env` / `.env.local` (process env > `.env.local` > `.env`):

```dotenv
T3CODE_RELAY_URL=https://relay.example.com
```

Client and bundled-server builds embed `T3CODE_RELAY_URL` at build time; EAS preview/production environments only need `T3CODE_RELAY_URL`.

## GitHub OAuth setup (relay-hosted)

T3 Connect authenticates CLI, desktop, and mobile clients through the relay's built-in GitHub OAuth endpoints (`/v1/auth/authorize`, `/v1/auth/github/callback`, `/v1/auth/token`, `/v1/auth/device`, `/v1/auth/revoke`):

1. Create a GitHub OAuth App with callback URL `https://<your-relay-host>/v1/auth/github/callback`.
2. Configure `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, and `CloudMintKeyPair` (plus optional `GITHUB_OAUTH_ALLOWED_ORGS`) as relay secrets via Alchemy/Wrangler (never in client config).
3. Built-in client IDs and redirect URIs handled by the relay:
   - CLI (`t3-cli`): `http://127.0.0.1:<port>/callback` (PKCE) and `/v1/auth/device` (headless/SSH device flow)
   - Desktop (`t3-desktop`): `http://127.0.0.1:<port>/callback` (Electron main-process loopback PKCE; the desktop renderer signs in via Electron IPC)
   - Mobile (`t3-mobile`): `t3code://oauth/callback`, `t3code-dev://oauth/callback`, `t3code-preview://oauth/callback`, and `t3code-private://oauth/callback`
4. To restrict sign-ins to specific GitHub organizations, set `GITHUB_OAUTH_ALLOWED_ORGS` on the relay.

## Android FCM push setup

The relay sends Android push notifications directly via FCM HTTP v1 (no Expo Push account required):

1. Register each Android package (`com.t3tools.t3code.{dev,preview}` / `com.t3tools.t3code`) in Firebase and download `google-services.json`.
2. Pass `T3CODE_ANDROID_GOOGLE_SERVICES_FILE=/abs/path/google-services.json` when prebuilding/building locally or as an EAS file variable (available to fingerprint generation as well).
3. Enable the FCM API and store the Firebase service-account JSON only in the relay's `FCM_SERVICE_ACCOUNT` secret (never in EAS app env or the repo). Set `APNS_ENABLED=false` for an Android-only relay stage.
4. For local smoke/watch verification without deploying a relay, use `vp run push:android:smoke` and `vp run push:android:watch` from `infra/relay`.

## Desktop passkeys

For a signed macOS build (`com.t3tools.t3code`):

1. Create an explicit macOS App ID and a matching distribution provisioning profile.
2. Configure signing per [Apple signing and notarization](./03_release.md#apple-signing-and-notarization-macos). Local signed builds use `T3CODE_APPLE_TEAM_ID`, `T3CODE_MACOS_PROVISIONING_PROFILE`, and optionally `T3CODE_PASSKEY_RP_DOMAINS` if Associated Domains are needed. Bump the build version after changing Associated Domains so macOS refreshes cached Shared Web Credentials.

Unsigned `dev:desktop` cannot exercise passkeys. For renderer HMR with passkeys, launch an installed signed build against `vp run dev:web`:

```sh
VITE_DEV_SERVER_URL=http://127.0.0.1:5733 T3CODE_PORT=13773 \
  "/Applications/T3 Code (Alpha).app/Contents/MacOS/T3 Code (Alpha)"
```
