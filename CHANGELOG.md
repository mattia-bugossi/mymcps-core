# Changelog

## [0.3.1] – 2026-05-08

### Added
- **`auth/mcp-client-auth`: refresh-token grant.** Standard OAuth 2.1
  refresh-token flow with rotation, 60s grace window, and reuse-detection-driven
  family revocation (RFC 6749 OAuth 2.1 §4.14). `handleToken` now accepts
  `grant_type=refresh_token` (body field `refresh_token`); the initial
  `authorization_code` response also returns a `refresh_token` alongside
  `access_token` when a store is wired. Closes the daily re-pair cliff
  in claude.ai. Discovery `grant_types_supported` advertises both grants
  when `DiscoveryMetadataConfig.refresh_token_supported: true`.
- **`auth/mcp-client-auth`: `IssuedRefreshTokenStore` interface.** New
  consumer-implemented persistence contract for refresh tokens that the
  MCP OAuth shell ISSUES to clients (claude.ai etc.) — distinct from
  `RefreshTokenStore` (in `src/auth/`), which holds tokens we RECEIVE
  from upstream providers under the OAuth2-delegation pattern. The
  `Issued` prefix and co-location with `mcp-client-auth/` keep them
  unconfusable. Storage backend is consumer-chosen — DynamoDB for prod,
  in-memory for tests — same injection pattern as `ClientRegistry`.

  **Rotation is atomic.** The store exposes `rotate(predecessorJti,
  newRecord)`, which MUST commit the supersede-mark on the predecessor
  AND the insert of the successor in one operation. Production
  consumers implement this via DynamoDB `TransactWriteItems`; in-memory
  test fakes do both writes synchronously. The atomic primitive closes
  the parallel-chain exploit window where a non-atomic
  put-then-mark-superseded sequence could let a leaked predecessor
  mint a second descendant chain inside the failure gap. Future-you
  grepping for "how does rotation handle network blips" should land
  here.
- **`errors`: `UpstreamAuthSeedError` error class.** Sibling to
  `UpstreamAuthRevoked`, distinct for diagnostic clarity. Thrown by
  `UserPreIssuedAuth` when the seeded Secrets Manager value's
  `expires_at` is at-or-before now at load time — meaning the very
  first call would force a refresh and risk burning the refresh token
  if another process (e.g., the SPA still running in another tab) has
  already rotated it. Maps via `classifyError` to HTTP `500` /
  JSON-RPC `-32603` (operator-config error, NOT 401 like
  `UpstreamAuthRevoked` — the user did nothing wrong; re-authorizing
  wouldn't help).
- **New exports** from `mymcps-core/auth`: `IssuedRefreshTokenRecord`,
  `IssuedRefreshTokenStore` (under the `mcpClientAuth` namespace), plus
  `UpstreamAuthSeedError` re-exported next to its `UserPreIssuedAuth`
  thrower for discoverability. New export from `mymcps-core/errors`:
  `UpstreamAuthSeedError`.

### Changed
- **MCP access-token TTL is now conditional on `refreshStore` presence.**
  When `handleToken` is wired with an `IssuedRefreshTokenStore`, access
  tokens default to **1h** (claude.ai refreshes natively via the new
  grant). When the store is absent, access tokens stay at **24h** —
  preserving v0.3.0 behavior for downstream MCPs that bump core but
  haven't migrated to refresh tokens yet. `OAuthServerConfig.accessTokenTtlSeconds`
  override still wins regardless of presence. **If you're debugging
  "why is my MCP re-pairing every hour" after the bump:** it's because
  you've wired `refreshStore` but your client doesn't implement the
  `refresh_token` grant — either wire the grant client-side or unwire
  the store to opt out of the new TTL.
- **`UserPreIssuedAuth` re-reads the secret before every refresh attempt.**
  Inside `doRefresh`, immediately before the upstream `/oauth/token`
  POST, a fresh `secretsClient.get` runs and the just-read access_token
  is compared to the in-memory cached one. If they differ, the upstream
  refresh is skipped and the rotator's value is surfaced to the caller.
  Closes the operator-rotates-via-`put-secret-value` cliff: warm Lambda
  instances now pick up manual rotations on the next request, without
  forcing a cold start. Single-flight `pendingRefresh` mutex semantics
  unchanged; cross-Lambda CAS contract on the write path unchanged.
- **`UserPreIssuedAuth` rejects `expires_at <= now` at secret-load time
  with `UpstreamAuthSeedError`** (see Added). Refresh path is NOT
  triggered when this error fires — abort before any network call,
  rather than racing an external rotator and burning the seeded
  refresh token. Only strict-past values rejected; `expires_at: now + 1`
  is fine.

### Storage
- **`RefreshTokensTable` schema** (consumer-provisioned DynamoDB table,
  one per MCP). Field names match `IssuedRefreshTokenRecord`:

  | Attribute | Type | Notes |
  | --- | --- | --- |
  | `jti` | String | HASH key. JWT `jti` claim. |
  | `family_id` | String | UUID assigned at initial code exchange, preserved through every rotation. GSI for `revokeFamily`. |
  | `client_id` | String | Static-pair or DCR client_id. Refresh-token grant verifies the presented `client_id` matches. |
  | `scope` | String | Single-value scope claim, copied verbatim from the originating authorization code. |
  | `created_at` | Number | Epoch seconds when this row (this rotation) was issued. Used to measure the 60s grace window. |
  | `exp` | Number | Epoch seconds when this row expires. **Anchored to family origin** (`family_origin_iat + familyTtl`) — rotations do NOT extend it. Set DDB TTL on this attribute for automatic cleanup. Matches the JWT's `exp` claim. |
  | `superseded_by_jti` | String (optional) | Set on rotation. Presence + re-presentation of the row's own `jti` is the trigger for either grace-window idempotent re-issue or family revocation. |
  | `revoked_at` | Number (optional) | Set when reuse detection (or any other revocation path) kills this row. Once set, all refresh attempts on this `jti` fail with 400 `invalid_grant`. |

  Recommended indexes: HASH on `jti`; GSI on `family_id` (projection
  `KEYS_ONLY`) for `revokeFamily`. DDB TTL: enable on `exp`. Family TTL
  default is 30 days (`OAuthServerConfig.refreshTokenFamilyTtlSeconds`
  override available); grace window default is 60 seconds
  (`OAuthServerConfig.refreshTokenGraceWindowSeconds`).

### Migration
- **No-op for downstream MCPs that bump core without wiring `refreshStore`.**
  Behavior is identical to v0.3.0 except the new
  `UpstreamAuthSeedError` (which only fires on a malformed seed
  anyway). Discovery still advertises only `authorization_code`;
  refresh-token grant returns `400 unsupported_grant_type`.
- **To enable refresh tokens for a downstream MCP:** (1) provision the
  `RefreshTokensTable` schema above; (2) implement `IssuedRefreshTokenStore`
  against it (the `rotate` method MUST use `TransactWriteItems`); (3)
  pass the store as the 5th positional argument to `handleToken`; (4)
  set `DiscoveryMetadataConfig.refresh_token_supported: true`. After
  this, access tokens drop to 1h and claude.ai refreshes natively.
- **Per-MCP bumps to v0.3.1 (Oura, Withings, Peloton) happen in their
  own sessions** — same pattern as v0.3.0 → v0.3.1.

## [0.3.0] – 2026-04-23

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
- **`auth`: `UserPreIssuedAuth` — pre-issued-token upstream auth with
  refresh rotation.** New pattern for upstream providers whose public
  SPA client ships no `client_secret` (Peloton-style), where the token
  pair must be seeded out-of-band into AWS Secrets Manager and refreshed
  from the server on expiry. Coexists with `UserOAuth2Auth` (the
  delegated-OAuth2 pattern used by Oura / Withings / Strava); the two
  modules must not cross-import. `createUserPreIssuedAuth(config)`
  returns `{ getAccessToken, fetch }` — `fetch` wraps upstream requests
  with `Authorization: Bearer`, refreshes proactively when the cached
  token is within `refreshMargin` seconds (default 60; pass 0 for
  pure-reactive) of `expires_at`, and retries once on a reactive 401.
- **`auth`: `VersionedSecretsClient` — versioned Secrets Manager client
  with optimistic concurrency.** Powers `UserPreIssuedAuth`'s refresh
  path. Atomic refresh via `PutSecretValue(AWSPENDING)` +
  `UpdateSecretVersionStage` with `RemoveFromVersionId` —
  `ConcurrentModificationError` on stale `VersionId`. Caller re-reads
  the secret and uses the winning writer's new `access_token` rather
  than triggering a second refresh (single-flight guarantee).
- **`errors`: `UpstreamAuthRevoked` error class.** Non-retryable; raised
  when the upstream refresh endpoint returns `4xx`, meaning the user's
  grant has been revoked and re-authorization is required. Maps to HTTP
  `401` / JSON-RPC `-32000` via `classifyError`, distinct from generic
  `AuthError` (which signals a server-side auth misconfiguration).
- **New exports** from `mymcps-core/auth`: `createUserPreIssuedAuth`,
  `PreIssuedAuth`, `UserPreIssuedAuthConfig`,
  `createVersionedSecretsClient`, `VersionedSecret`,
  `VersionedSecretsClient`, `ConcurrentModificationError`. New export
  from `mymcps-core/errors`: `UpstreamAuthRevoked`.

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
