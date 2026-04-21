# mymcps-core

Shared core for **MyMCPs** — a personal ecosystem of provider-specific MCP servers
(`oura-mcp-server`, `withings-mcp-server`, …) running on AWS Lambda in `eu-west-2`.

Extracts the cross-provider concerns — auth (provider PATs + user OAuth2 with refresh-token
rotation), Streamable-HTTP MCP transport, DynamoDB + in-memory cache adapters, Secrets Manager
utilities, MCP-client auth (HS256 JWT + OAuth 2.1 + PKCE), and reusable SAM parameter fragments —
so each provider repo stays thin and only contains its API client + tools.

## Install (consumer)

Consumed by per-provider MCPs as a git-tag-pinned private dependency:

```json
{
  "dependencies": {
    "mymcps-core": "github:mattia-bugossi/mymcps-core#semver:^0.1.0"
  }
}
```

`npm ci` on Lambda build pulls it. No private registry needed at this scale.

## Scope

See the authoritative scope doc (`mymcps-core-scope.md`, Drive) for what lifts vs. what stays
per provider. Summary: anything that would be duplicated across Oura/Withings/Dexcom/Garmin
lives here; the provider API client, response types, tool handlers, and provider-specific
derivations stay in the provider repo.

## Surface

- `mymcps-core/auth` — `ProviderAuth` interface, `ServerSidePatAuth` (Oura-style PAT), and
  `UserOAuth2Auth` (Withings/Dexcom/Garmin-style with rotating refresh tokens). Plus
  `RefreshTokenStore` + AWS Secrets Manager implementation.
- `mymcps-core/auth/signing` — HMAC-SHA256 signing + nonce fetch (Withings `/v2/oauth2`).
- `mymcps-core/transport` — Streamable-HTTP MCP server bootstrap.
- `mymcps-core/cache` — `CacheAdapter` interface + `InMemoryCache` (local dev) +
  `DynamoCache` (Lambda).
- `mymcps-core/aws` — Secrets Manager fetch helper with in-process caching.
- `mymcps-core/tools` — tool registration helpers.
- `mymcps-core/errors` — provider error taxonomy + mapping to MCP error responses.
- `sam-fragments/` — reusable AWS SAM template fragments (Secrets Manager parameters, cache
  table, OAuth callback route).

## Development

```
nvm use              # Node 22
npm install
npm run typecheck
npm test
npm run build
```

## Conventions

- **ESM only.** `"type": "module"` + NodeNext module resolution. Explicit `.js` suffixes on
  relative imports so output runs as-is on Node without a bundler.
- **`// purpose:` header.** First line of every lead file in a new directory states what the
  directory is for.
- **One logical change per commit** — same convention as the provider repos.
- **No runtime deps on the provider repos.** Core must stay provider-agnostic.
