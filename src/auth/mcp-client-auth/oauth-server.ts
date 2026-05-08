// purpose: Provider-agnostic OAuth 2.1 + PKCE authorization server, plus
// the RFC 7591 Dynamic Client Registration endpoint and the OAuth 2.1
// refresh-token grant. Pure async functions returning HttpResult;
// consumer wires them into express, lambda, or raw http.

import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import {
  ClientIdCollisionError,
  type ClientRegistry,
  type RegisteredClient,
  type RegisteredClientMetadata,
} from './client-registry.js';
import type {
  IssuedRefreshTokenRecord,
  IssuedRefreshTokenStore,
} from './issued-refresh-token-store.js';
import { sign, verify, type JwtClaims } from './jwt.js';

export interface OAuthServerConfig {
  // Static OAuth client credentials (verified in /token). Registered
  // clients (via handleRegister) are checked against the optional
  // ClientRegistry when the presented client_id does not match this
  // static pair; this lets existing connectors keep working as-is while
  // claude.ai-style DCR consumers self-register.
  clientId: string;
  clientSecret: string;
  // Shared HMAC secret used to sign & verify auth codes, access tokens,
  // and refresh tokens. The three carry distinct audiences so they
  // can't be cross-replayed.
  signingSecret: string;
  // JWT audiences. Refresh-token audience is computed by core as
  // `${accessAudience}${REFRESH_AUDIENCE_SUFFIX}` — not configurable, so
  // an operator can't accidentally set them equal.
  codeAudience: string;
  accessAudience: string;
  // Optional allow-list for the static client. Empty/unset means accept
  // any redirect_uri for the static client. Dynamically-registered
  // clients are validated against their own metadata.redirect_uris.
  allowedRedirectUris?: string[];
  // Scope claim stamped on issued auth codes / access tokens when the
  // client omits `scope` at /authorize or /token. Single string (the
  // scope claim is a single value per RFC 6749). Defaults to 'mcp'.
  // Semantically separate from DiscoveryMetadataConfig.scopes_supported,
  // which is the array advertised in discovery — typically defaultScope
  // should be a member of scopes_supported, but this is unenforced.
  defaultScope?: string;
  // Subject claim for the issued tokens. Single-user servers hard-code this
  // ('single-user'); multi-user servers derive it during a prior login step
  // and pass it in at authorize-time (not modeled here yet).
  subject?: string;
  // Code JWT TTL in seconds (default 60).
  codeTtlSeconds?: number;
  // Access token TTL in seconds. Default depends on whether a
  // refresh-token store is wired into handleToken: 1h when wired
  // (claude.ai will refresh natively), 24h when absent (zero-regression
  // fallback for downstream MCPs that haven't migrated yet). Setting
  // this override wins regardless of store presence.
  accessTokenTtlSeconds?: number;
  // Refresh-token family TTL in seconds (default 30 days). Anchored to
  // family origin — rotations do NOT extend it. Persisted as the row's
  // `exp` and stamped on the refresh JWT.
  refreshTokenFamilyTtlSeconds?: number;
  // Grace window in seconds for re-presenting a superseded refresh
  // token after a rotation (default 60). Inside the window returns the
  // SAME successor pair (idempotent retry); outside triggers reuse
  // detection per OAuth 2.1 §4.14, revoking the entire family.
  refreshTokenGraceWindowSeconds?: number;
}

export interface HttpResult {
  status: number;
  body?: unknown;
  // Present for 302 flows — caller sets Location + status.
  redirect?: string;
}

export interface AuthorizeInput {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  state?: string;
  scope?: string;
}

export interface TokenInput {
  grant_type?: string;
  // authorization_code grant
  code?: string;
  redirect_uri?: string;
  code_verifier?: string;
  // refresh_token grant
  refresh_token?: string;
  // both
  client_id?: string;
  client_secret?: string;
}

export interface TokenSuccess {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
  // Present when handleToken is wired with an IssuedRefreshTokenStore
  // (initial code-exchange and refresh-token grant both return one).
  // Omitted entirely when the store is absent.
  refresh_token?: string;
}

export interface DiscoveryInput {
  issuer: string;
}

// RFC 8414-aligned: keys match the discovery-metadata response shape so
// consumers don't have to carry OAuthServerConfig's authorize/token
// fields on the discovery path. Unknown keys are rejected at compile
// time. Expand this type as new advertised fields become configurable.
export interface DiscoveryMetadataConfig {
  // RFC 8414 `scopes_supported` — array of scope values the server
  // advertises as accepted. Defaults to ['mcp']. Semantically separate
  // from OAuthServerConfig.defaultScope (the single-value fallback
  // stamped on issued tokens when the client omits scope) — typically
  // defaultScope should be a member of scopes_supported, but this is
  // unenforced.
  scopes_supported?: string[];
  // Whether the server's /token endpoint accepts the refresh_token
  // grant. Set to true alongside wiring an IssuedRefreshTokenStore into
  // handleToken; false (default) means only authorization_code is
  // advertised. Discovery never advertises a feature handleToken can't
  // deliver.
  refresh_token_supported?: boolean;
}

// RFC 7591 §2 client metadata. All fields optional; `unknown` so we can
// type-check at the boundary without trusting the caller.
export interface RegisterInput {
  redirect_uris?: unknown;
  grant_types?: unknown;
  response_types?: unknown;
  client_name?: unknown;
  token_endpoint_auth_method?: unknown;
  scope?: unknown;
}

// RFC 7591 §3.2.1 client information response.
export interface ClientRegistration {
  client_id: string;
  client_secret: string;
  client_id_issued_at: number;
  // 0 = never expires (RFC 7591 §3.2.1).
  client_secret_expires_at: 0;
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  client_name?: string;
  token_endpoint_auth_method: 'client_secret_post';
  scope?: string;
}

const DEFAULT_CODE_TTL = 60;
const DEFAULT_ACCESS_TTL_WITH_REFRESH = 60 * 60;
const DEFAULT_ACCESS_TTL_WITHOUT_REFRESH = 24 * 60 * 60;
const DEFAULT_FAMILY_TTL_SEC = 30 * 24 * 60 * 60;
const DEFAULT_GRACE_WINDOW_SEC = 60;
const REFRESH_AUDIENCE_SUFFIX = '-refresh';
const DEFAULT_SCOPE = 'mcp';
const DEFAULT_SUBJECT = 'single-user';
const CLIENT_ID_BYTES = 32;
const CLIENT_SECRET_BYTES = 32;

function error(status: number, err: string, description: string): HttpResult {
  return { status, body: { error: err, error_description: description } };
}

function registrationError(description: string): HttpResult {
  return error(400, 'invalid_client_metadata', description);
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function constantTimeStringEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

function refreshAudience(accessAudience: string): string {
  return `${accessAudience}${REFRESH_AUDIENCE_SUFFIX}`;
}

// Builds the refresh-token JWT claims from a stored row. Property order
// here is load-bearing: byte-identical re-issue inside the grace window
// depends on JSON.stringify producing identical bytes across calls,
// which it does only when the object's insertion order is identical.
// Always assemble via this helper.
function buildRefreshClaims(
  row: IssuedRefreshTokenRecord,
  sub: string,
  accessAudience: string,
): JwtClaims {
  return {
    sub,
    aud: refreshAudience(accessAudience),
    iat: row.created_at,
    exp: row.exp,
    jti: row.jti,
    family_id: row.family_id,
    client_id: row.client_id,
    scope: row.scope,
  };
}

export function buildDiscoveryMetadata(
  config: DiscoveryMetadataConfig,
  { issuer }: DiscoveryInput,
): Record<string, unknown> {
  const scopes_supported = config.scopes_supported ?? [DEFAULT_SCOPE];
  const grant_types_supported = config.refresh_token_supported
    ? ['authorization_code', 'refresh_token']
    : ['authorization_code'];
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ['code'],
    grant_types_supported,
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    scopes_supported,
  };
}

export async function handleAuthorize(
  config: OAuthServerConfig,
  input: AuthorizeInput,
  now: () => number = () => Math.floor(Date.now() / 1000),
  registry?: ClientRegistry,
): Promise<HttpResult> {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope } = input;

  if (response_type !== 'code') {
    return error(400, 'unsupported_response_type', 'response_type must be "code"');
  }
  if (!client_id) return error(400, 'invalid_request', 'client_id required');
  if (!redirect_uri) return error(400, 'invalid_request', 'redirect_uri required');
  if (!code_challenge) return error(400, 'invalid_request', 'code_challenge required');
  if (code_challenge_method !== 'S256') {
    return error(400, 'invalid_request', 'code_challenge_method must be S256');
  }

  let registered: RegisteredClient | null = null;
  if (client_id !== config.clientId) {
    if (!registry) {
      return error(400, 'invalid_client', 'unknown client_id');
    }
    registered = await registry.get(client_id);
    if (!registered) {
      return error(400, 'invalid_client', 'unknown client_id');
    }
  }

  if (registered) {
    const uris = registered.metadata.redirect_uris;
    if (uris && uris.length > 0 && !uris.includes(redirect_uri)) {
      return error(400, 'invalid_request', 'redirect_uri not allowed for this client');
    }
  } else if (config.allowedRedirectUris && config.allowedRedirectUris.length > 0) {
    if (!config.allowedRedirectUris.includes(redirect_uri)) {
      return error(400, 'invalid_request', 'redirect_uri not allowed');
    }
  }

  const iat = now();
  const claims: JwtClaims = {
    sub: config.subject ?? DEFAULT_SUBJECT,
    aud: config.codeAudience,
    iat,
    exp: iat + (config.codeTtlSeconds ?? DEFAULT_CODE_TTL),
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    scope: scope ?? config.defaultScope ?? DEFAULT_SCOPE,
  };
  const code = sign(claims, config.signingSecret);

  let url: URL;
  try {
    url = new URL(redirect_uri);
  } catch {
    return error(400, 'invalid_request', 'redirect_uri is not a valid URL');
  }
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  return { status: 302, redirect: url.toString() };
}

export async function handleToken(
  config: OAuthServerConfig,
  input: TokenInput,
  now: () => number = () => Math.floor(Date.now() / 1000),
  registry?: ClientRegistry,
  refreshStore?: IssuedRefreshTokenStore,
): Promise<HttpResult> {
  const { grant_type } = input;

  if (grant_type === 'authorization_code') {
    return handleAuthorizationCodeGrant(config, input, now, registry, refreshStore);
  }
  if (grant_type === 'refresh_token') {
    if (!refreshStore) {
      return error(
        400,
        'unsupported_grant_type',
        'refresh_token grant is not enabled on this server',
      );
    }
    return handleRefreshTokenGrant(config, input, now, registry, refreshStore);
  }
  return error(400, 'unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
}

async function authenticateClient(
  config: OAuthServerConfig,
  client_id: string,
  client_secret: string,
  registry?: ClientRegistry,
): Promise<HttpResult | null> {
  if (constantTimeStringEqual(client_id, config.clientId)) {
    if (!constantTimeStringEqual(client_secret, config.clientSecret)) {
      return error(401, 'invalid_client', 'bad client_secret');
    }
    return null;
  }
  if (!registry) {
    return error(401, 'invalid_client', 'unknown client_id');
  }
  const registered = await registry.get(client_id);
  if (!registered) {
    return error(401, 'invalid_client', 'unknown client_id');
  }
  if (!constantTimeStringEqual(client_secret, registered.client_secret)) {
    return error(401, 'invalid_client', 'bad client_secret');
  }
  return null;
}

async function handleAuthorizationCodeGrant(
  config: OAuthServerConfig,
  input: TokenInput,
  now: () => number,
  registry: ClientRegistry | undefined,
  refreshStore: IssuedRefreshTokenStore | undefined,
): Promise<HttpResult> {
  const { code, redirect_uri, client_id, client_secret, code_verifier } = input;

  if (!code) return error(400, 'invalid_request', 'code required');
  if (!redirect_uri) return error(400, 'invalid_request', 'redirect_uri required');
  if (!client_id) return error(400, 'invalid_request', 'client_id required');
  if (!client_secret) return error(400, 'invalid_request', 'client_secret required');
  if (!code_verifier) return error(400, 'invalid_request', 'code_verifier required');

  const authFail = await authenticateClient(config, client_id, client_secret, registry);
  if (authFail) return authFail;

  let claims: JwtClaims;
  try {
    claims = verify(code, config.signingSecret, config.codeAudience, now());
  } catch (e) {
    return error(400, 'invalid_grant', (e as Error).message);
  }

  if (claims.client_id !== client_id) return error(400, 'invalid_grant', 'client_id mismatch');
  if (claims.redirect_uri !== redirect_uri) return error(400, 'invalid_grant', 'redirect_uri mismatch');

  const challenge = claims.code_challenge as string | undefined;
  if (!challenge) return error(400, 'invalid_grant', 'code missing challenge');
  const computed = b64url(createHash('sha256').update(code_verifier).digest());
  if (computed !== challenge) return error(400, 'invalid_grant', 'pkce verify failed');

  const iat = now();
  const accessTtl =
    config.accessTokenTtlSeconds ??
    (refreshStore ? DEFAULT_ACCESS_TTL_WITH_REFRESH : DEFAULT_ACCESS_TTL_WITHOUT_REFRESH);
  const scope = (claims.scope as string | undefined) ?? config.defaultScope ?? DEFAULT_SCOPE;
  const sub = claims.sub;
  const accessToken = sign(
    {
      sub,
      aud: config.accessAudience,
      iat,
      exp: iat + accessTtl,
      scope,
    },
    config.signingSecret,
  );

  const body: TokenSuccess = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTtl,
    scope,
  };

  if (refreshStore) {
    const familyTtl = config.refreshTokenFamilyTtlSeconds ?? DEFAULT_FAMILY_TTL_SEC;
    const row: IssuedRefreshTokenRecord = {
      jti: randomUUID(),
      family_id: randomUUID(),
      client_id,
      scope,
      created_at: iat,
      exp: iat + familyTtl,
    };
    await refreshStore.put(row);
    body.refresh_token = sign(buildRefreshClaims(row, sub, config.accessAudience), config.signingSecret);
  }

  return { status: 200, body };
}

async function handleRefreshTokenGrant(
  config: OAuthServerConfig,
  input: TokenInput,
  now: () => number,
  registry: ClientRegistry | undefined,
  refreshStore: IssuedRefreshTokenStore,
): Promise<HttpResult> {
  const { refresh_token, client_id, client_secret } = input;

  if (!refresh_token) return error(400, 'invalid_request', 'refresh_token required');
  if (!client_id) return error(400, 'invalid_request', 'client_id required');
  if (!client_secret) return error(400, 'invalid_request', 'client_secret required');

  const authFail = await authenticateClient(config, client_id, client_secret, registry);
  if (authFail) return authFail;

  // JWT verify covers signature, audience (refresh-only), and exp. A
  // forged or access-audience token is rejected here without a store
  // hit (cheap fast-path).
  let claims: JwtClaims;
  try {
    claims = verify(refresh_token, config.signingSecret, refreshAudience(config.accessAudience), now());
  } catch (e) {
    return error(400, 'invalid_grant', (e as Error).message);
  }

  if (claims.client_id !== client_id) return error(400, 'invalid_grant', 'client_id mismatch');
  const presentedJti = claims.jti as string | undefined;
  if (!presentedJti) return error(400, 'invalid_grant', 'refresh token missing jti');

  const row = await refreshStore.get(presentedJti);
  if (!row) return error(400, 'invalid_grant', 'refresh token not recognized');
  if (row.revoked_at !== undefined) return error(400, 'invalid_grant', 'refresh token revoked');

  const graceWindow = config.refreshTokenGraceWindowSeconds ?? DEFAULT_GRACE_WINDOW_SEC;
  const accessTtl =
    config.accessTokenTtlSeconds ??
    (refreshStore ? DEFAULT_ACCESS_TTL_WITH_REFRESH : DEFAULT_ACCESS_TTL_WITHOUT_REFRESH);
  const scope = row.scope;
  const sub = claims.sub;

  if (row.superseded_by_jti !== undefined) {
    // Already rotated. Either we're inside the grace window (return
    // the SAME successor pair, byte-identical refresh JWT) or this is
    // a reuse attack — revoke the family.
    const successor = await refreshStore.get(row.superseded_by_jti);
    if (!successor) {
      // Race against family TTL or another revocation path. Treat as
      // recognized-but-unusable: don't trigger reuse detection (we
      // can't verify a successor exists).
      return error(400, 'invalid_grant', 'refresh token superseded');
    }
    if (now() - successor.created_at > graceWindow) {
      await refreshStore.revokeFamily(row.family_id, now());
      return error(400, 'invalid_grant', 'refresh token reuse detected');
    }
    const accessToken = mintAccess(config, sub, scope, now(), accessTtl);
    const refreshToken = sign(
      buildRefreshClaims(successor, sub, config.accessAudience),
      config.signingSecret,
    );
    return {
      status: 200,
      body: {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: accessTtl,
        scope,
        refresh_token: refreshToken,
      } satisfies TokenSuccess,
    };
  }

  // Current valid refresh — rotate.
  const iat = now();
  const successor: IssuedRefreshTokenRecord = {
    jti: randomUUID(),
    family_id: row.family_id,
    client_id: row.client_id,
    scope,
    created_at: iat,
    // Anchored to family origin: preserve predecessor's exp.
    exp: row.exp,
  };
  await refreshStore.rotate(row.jti, successor);

  const accessToken = mintAccess(config, sub, scope, iat, accessTtl);
  const refreshToken = sign(
    buildRefreshClaims(successor, sub, config.accessAudience),
    config.signingSecret,
  );
  return {
    status: 200,
    body: {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: accessTtl,
      scope,
      refresh_token: refreshToken,
    } satisfies TokenSuccess,
  };
}

function mintAccess(
  config: OAuthServerConfig,
  sub: string,
  scope: string,
  iat: number,
  ttl: number,
): string {
  return sign(
    {
      sub,
      aud: config.accessAudience,
      iat,
      exp: iat + ttl,
      scope,
    },
    config.signingSecret,
  );
}

export async function handleRegister(
  input: RegisterInput,
  registry: ClientRegistry,
  now: () => number = () => Math.floor(Date.now() / 1000),
): Promise<HttpResult> {
  // Only 'client_secret_post' is supported today (handleToken requires
  // client_secret_post). Reject other values at registration time with
  // RFC 7591 §3.2.2 invalid_client_metadata rather than letting the
  // client discover the mismatch as a mystery 401 at token exchange.
  if (
    input.token_endpoint_auth_method !== undefined &&
    input.token_endpoint_auth_method !== 'client_secret_post'
  ) {
    return registrationError(
      'token_endpoint_auth_method must be "client_secret_post"',
    );
  }

  const metadata: RegisteredClientMetadata = {
    token_endpoint_auth_method: 'client_secret_post',
  };

  if (input.redirect_uris !== undefined) {
    if (!isStringArray(input.redirect_uris)) {
      return registrationError('redirect_uris must be an array of strings');
    }
    metadata.redirect_uris = input.redirect_uris;
  }
  if (input.grant_types !== undefined) {
    if (!isStringArray(input.grant_types)) {
      return registrationError('grant_types must be an array of strings');
    }
    metadata.grant_types = input.grant_types;
  }
  if (input.response_types !== undefined) {
    if (!isStringArray(input.response_types)) {
      return registrationError('response_types must be an array of strings');
    }
    metadata.response_types = input.response_types;
  }
  if (input.client_name !== undefined) {
    if (typeof input.client_name !== 'string') {
      return registrationError('client_name must be a string');
    }
    metadata.client_name = input.client_name;
  }
  if (input.scope !== undefined) {
    if (typeof input.scope !== 'string') {
      return registrationError('scope must be a string');
    }
    metadata.scope = input.scope;
  }

  // Mint random client_id + client_secret. Retry once on collision —
  // 32-byte base64url collisions are cryptographically negligible, but
  // ClientRegistry.put throws ClientIdCollisionError on collision rather
  // than overwrite, so we handle the (vanishingly unlikely) case.
  const issuedAt = now();
  let registered: RegisteredClient | null = null;
  let lastErr: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    const candidate: RegisteredClient = {
      client_id: b64url(randomBytes(CLIENT_ID_BYTES)),
      client_secret: b64url(randomBytes(CLIENT_SECRET_BYTES)),
      client_id_issued_at: issuedAt,
      metadata,
    };
    try {
      await registry.put(candidate);
      registered = candidate;
      break;
    } catch (err) {
      lastErr = err;
      if (err instanceof ClientIdCollisionError && attempt === 0) continue;
      throw err;
    }
  }
  if (!registered) {
    throw lastErr ?? new Error('handleRegister: failed to mint client_id');
  }

  const body: ClientRegistration = {
    client_id: registered.client_id,
    client_secret: registered.client_secret,
    client_id_issued_at: registered.client_id_issued_at,
    client_secret_expires_at: 0,
    token_endpoint_auth_method: 'client_secret_post',
    ...(metadata.redirect_uris ? { redirect_uris: metadata.redirect_uris } : {}),
    ...(metadata.grant_types ? { grant_types: metadata.grant_types } : {}),
    ...(metadata.response_types ? { response_types: metadata.response_types } : {}),
    ...(metadata.client_name ? { client_name: metadata.client_name } : {}),
    ...(metadata.scope ? { scope: metadata.scope } : {}),
  };
  return { status: 201, body };
}
