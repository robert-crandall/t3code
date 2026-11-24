# T3 Connect Relay

> [!NOTE]
> Sign in to T3 Connect from the app under Settings > Sharing & access.

The relay is the hosted control plane for T3 Connect. It helps clients discover and connect to
remote environments, manages the cloud-side records needed for those connections, and delivers
optional mobile notifications and Live Activities.

The relay is intentionally not in the hot path for normal T3 Code traffic. After a client connects,
regular API and WebSocket traffic goes directly between that client and the selected environment.
See the [T3 Connect architecture note](../../docs/internals/06_t3-connect.md) for the larger system
design.

## Responsibilities

The relay currently owns:

- Linking T3 Code environments to a cloud account.
- Provisioning and tracking managed environment endpoints.
- Issuing short-lived credentials used to connect clients to linked environments.
- Listing linked environments and registered mobile devices for an account.
- Registering mobile notification preferences and APNs or FCM tokens.
- Receiving published agent activity and delivering notifications or Live Activity updates.
- Persisting relay state and exposing relay-specific traces for diagnostics.

The environment server and relay have separate credentials and trust boundaries. Read
[Environment Authentication Profile](../../docs/internals/04_environment-auth.md) before changing token,
credential, or authorization behavior.

## Code Map

- [`alchemy.run.ts`](./alchemy.run.ts) defines the deployed Alchemy stack.
- [`src/worker.ts`](./src/worker.ts) wires Cloudflare bindings, runtime layers, queues, and HTTP APIs.
- [`src/http/Api.ts`](./src/http/Api.ts) contains the relay HTTP handlers and authentication
  boundaries.
- [`src/environments`](./src/environments) contains environment linking, credentials, endpoint
  provisioning, and connection flows.
- [`src/agentActivity`](./src/agentActivity) contains mobile device registration, activity state,
  APNs and FCM delivery, and queue processing.
- [`src/auth`](./src/auth) contains relay token and DPoP proof handling.
- [`src/persistence/schema.ts`](./src/persistence/schema.ts) defines persisted relay state. Keep
  schema and migration changes together.

Shared request and response schemas live in
[`packages/contracts/src/relay.ts`](../../packages/contracts/src/relay.ts). Shared client-side relay
calls live in
[`packages/client-runtime/src/relay/managedRelay.ts`](../../packages/client-runtime/src/relay/managedRelay.ts).

## Working Locally

Install dependencies from the repository root, then run relay-focused checks from this directory:

```sh
vp install
cd infra/relay
vp test run
vp run typecheck
```

To run a smaller test set while iterating:

```sh
vp test run src/environments/EnvironmentLinker.test.ts
```

Before considering a change complete, run the repository-wide checks from the root:

```sh
vp check
vp run typecheck
```

Backend changes should include tests. Prefer testing the real business logic with external
dependencies represented at their boundary rather than mocking internal behavior.

## Deployment

The relay deploys with the Alchemy CLI (`vp run --filter t3code-relay deploy` is `alchemy deploy`
in this directory):

```sh
vp run --filter t3code-relay deploy
```

The stack provisions the Cloudflare Worker, Durable Objects, managed endpoint resources, and binds
an existing Cloudflare Hyperdrive configuration by lookup (`RELAY_HYPERDRIVE_ID`, or
`RELAY_HYPERDRIVE_NAME` defaulting to `t3code-relay` on `prod` and `t3code-relay-<stage>` on
non-prod stages). Create the Hyperdrive config with `--caching-disabled true` so transactional
`SELECT ... FOR UPDATE` and read-after-write queries never hit cached results. Axiom, R2,
PlanetScale, and Clerk are not required.

This stack targets a fresh Alchemy stage. Because the legacy Axiom, PlanetScale, and Drizzle
Alchemy providers were removed, deploying directly over an existing upstream stage that still holds
those resources in Alchemy state will fail during planning with `MissingProviderError`. If migrating
an existing upstream stage rather than deploying to a new Cloudflare account or stage, destroy or
remove those legacy resources from Alchemy state before deploying this revision (back up or retain
your production database first).

Copy [`infra/relay/.env.example`](./.env.example) to `infra/relay/.env` and fill in the
deployment-specific values before deploying:

1. Run database migrations against your PostgreSQL database:

```sh
DATABASE_URL="postgresql://..." pnpm --dir infra/relay db:migrate
```

2. Deploy the `prod` stage with Alchemy (loads `infra/relay/.env`):

```sh
vp run --filter t3code-relay deploy -- --stage prod
```

Runtime secrets include `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`,
`GITHUB_OAUTH_ALLOWED_ORGS`, and optional APNs/FCM credentials (set `APNS_ENABLED=false` to disable
Apple push notifications). If the allowed GitHub organization enables OAuth App access restrictions,
own the OAuth App under that organization or approve it in org settings so org membership checks
succeed. Production adopts the configured API and tunnel DNS zones as retained Cloudflare resources;
personal stages reference the production-owned zones.

```sh
vp run --filter t3code-relay deploy -- --env-file .env.local
```

Alchemy defaults personal deployments to the `dev_$USER` stage. Relay custom domains apply the same
DNS-safe sanitization as Alchemy physical resource names, so `prod` uses
`relay.<RELAY_API_ZONE_NAME>` and `dev_julius` uses
`relay-dev-julius.<RELAY_API_ZONE_NAME>`. Managed environment endpoints are provisioned below
`RELAY_TUNNEL_ZONE_NAME`, which may be a different Cloudflare zone. Production tunnel hostnames use
`prod-<digest>.<RELAY_TUNNEL_ZONE_NAME>`; personal stages use
`<stage>-<digest>.<RELAY_TUNNEL_ZONE_NAME>`. `RELAY_DOMAIN` remains available as an explicit API
domain override.

The stack's `PublishClientConfig` action ([`src/clientConfig.ts`](./src/clientConfig.ts)) writes the
deployed relay URL into the repository-root `.env`, so subsequent source builds point at the relay
that was just deployed without copying values manually. It runs only when that output changed, and
`T3CODE_RELAY_CLIENT_CONFIG_ENV` redirects it to another file.

### Deployment CI

The relay is versioned separately from client releases. Automated GitHub Actions deployment
workflows (`deploy-relay.yml`, `relay-preview.yml`, and `release.yml`) are pending cutover from the
upstream PlanetScale/Axiom/Clerk configuration to the self-hosted Hyperdrive + GitHub OAuth stack;
deploy manually from `infra/relay` using the steps above until that cutover lands.

See:

- [T3 Connect architecture](../../docs/internals/06_t3-connect.md) for environment linking and trust boundaries.
