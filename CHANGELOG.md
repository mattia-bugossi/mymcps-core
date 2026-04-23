# Changelog

## [Unreleased]

### Added
- **`auth/mcp-client-auth`: RFC 7591 Dynamic Client Registration.** New
  `handleRegister(input, registry, now?)` mints a fresh `{client_id,
  client_secret}` for claude.ai-style connectors that self-register at
  `POST /register`. Persists through a new `ClientRegistry` interface
  (`get` / `put`) so consumers pick the storage backend (DynamoDB,
  Secrets Manager, in-memory for tests) — same injection pattern as
  `RefreshTokenStore`.
- **Discovery metadata gains `registration_endpoint`**
  (`${issuer}/register`).
- **New exports** from `mymcps-core/auth`:
  `handleRegister`, `RegisterInput`, `ClientRegistration`,
  `ClientRegistry`, `RegisteredClient`, `RegisteredClientMetadata`, the
  error class `ClientIdCollisionError`, and the narrowed
  `DiscoveryMetadataConfig`.

### Changed (breaking)
- **`handleAuthorize` and `handleToken` are now async.** Consumers
  upgrading from 0.2.x must add `await` at each call site — a one-line
  change with no behavior drift otherwise.
- **`ClientRegistry` is an optional fourth positional argument to both
  functions.** MCPs that do not use DCR pass nothing and get identical
  static-pair behavior; existing Oura and Withings deployments upgrade
  to 0.3.0 without wiring a registry.
- **`buildDiscoveryMetadata` now takes a narrowed `DiscoveryMetadataConfig`**
  instead of the full `OAuthServerConfig`. The new type exposes only
  RFC 8414-shaped fields and rejects unknown keys at compile time, so
  consumers stop passing `''` placeholders for `clientId`, `clientSecret`,
  `signingSecret` on the discovery path. Callers who pass an
  `OAuthServerConfig`-typed variable keep compiling via structural
  subtyping (the new field is optional); callers who pass inline object
  literals with non-RFC-8414 keys must drop them.
- **`OAuthServerConfig.defaultScope` (string) was previously reused by
  `buildDiscoveryMetadata` to populate the advertised scopes. Discovery
  now reads `DiscoveryMetadataConfig.scopes_supported` (string[], RFC 8414
  plural-array naming) instead. `OAuthServerConfig.defaultScope` stays,
  but its role is narrowed to the single-value fallback stamped on
  issued auth codes / access tokens when the client omits `scope` at
  /authorize or /token. Migration: consumers that previously relied on
  `defaultScope` to drive the advertised scopes list should set
  `scopes_supported: ['<scope>']` on the discovery call; everyone else
  gets `['mcp']` by default and can no-op.

### Validated at registration
- Only `token_endpoint_auth_method: "client_secret_post"` is accepted
  (the sole method `handleToken` verifies). Omitted → defaults to
  `client_secret_post`. Any other value → `400
  invalid_client_metadata` (RFC 7591 §3.2.2), so the client never
  discovers the mismatch as a mystery `401` two steps later at token
  exchange.

### Deployment guidance
- **`POST /register` is unauthenticated** (per RFC 7591 §2). If you
  deploy core `0.3.0` behind API Gateway, configure per-client-IP
  throttling on `POST /register` to mitigate the DoS surface. Core does
  not include rate-limiting — this is a deployment concern.
