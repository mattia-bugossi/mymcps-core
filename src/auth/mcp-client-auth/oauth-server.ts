// purpose: Provider-agnostic OAuth 2.1 + PKCE authorization server. Pure
// functions returning HttpResult; consumer wires them into express, lambda,
// or raw http.

import { createHash, timingSafeEqual } from 'node:crypto';
import { sign, verify, type JwtClaims } from './jwt.js';

export interface OAuthServerConfig {
  // Expected OAuth client credentials (verified in /token).
  clientId: string;
  clientSecret: string;
  // Shared HMAC secret used to sign & verify both auth codes and access tokens.
  signingSecret: string;
  // JWT audiences — should differ so an access token can't be replayed as a code.
  codeAudience: string;
  accessAudience: string;
  // Optional allow-list; empty/unset means accept any redirect_uri.
  allowedRedirectUris?: string[];
  // Default scope when the client omits one. Defaults to 'mcp'.
  defaultScope?: string;
  // Subject claim for the issued tokens. Single-user servers hard-code this
  // ('single-user'); multi-user servers derive it during a prior login step
  // and pass it in at authorize-time (not modeled here yet).
  subject?: string;
  // Code JWT TTL in seconds (default 60).
  codeTtlSeconds?: number;
  // Access token TTL in seconds (default 24h).
  accessTokenTtlSeconds?: number;
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
  code?: string;
  redirect_uri?: string;
  client_id?: string;
  client_secret?: string;
  code_verifier?: string;
}

export interface TokenSuccess {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
}

export interface DiscoveryInput {
  issuer: string;
}

const DEFAULT_CODE_TTL = 60;
const DEFAULT_ACCESS_TTL = 24 * 60 * 60;
const DEFAULT_SCOPE = 'mcp';
const DEFAULT_SUBJECT = 'single-user';

function error(status: number, err: string, description: string): HttpResult {
  return { status, body: { error: err, error_description: description } };
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

export function buildDiscoveryMetadata(
  config: OAuthServerConfig,
  { issuer }: DiscoveryInput,
): Record<string, unknown> {
  const scope = config.defaultScope ?? DEFAULT_SCOPE;
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    scopes_supported: [scope],
  };
}

export function handleAuthorize(
  config: OAuthServerConfig,
  input: AuthorizeInput,
  now: () => number = () => Math.floor(Date.now() / 1000),
): HttpResult {
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
  if (client_id !== config.clientId) return error(400, 'invalid_client', 'unknown client_id');
  if (config.allowedRedirectUris && config.allowedRedirectUris.length > 0) {
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

export function handleToken(
  config: OAuthServerConfig,
  input: TokenInput,
  now: () => number = () => Math.floor(Date.now() / 1000),
): HttpResult {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = input;

  if (grant_type !== 'authorization_code') {
    return error(400, 'unsupported_grant_type', 'grant_type must be authorization_code');
  }
  if (!code) return error(400, 'invalid_request', 'code required');
  if (!redirect_uri) return error(400, 'invalid_request', 'redirect_uri required');
  if (!client_id) return error(400, 'invalid_request', 'client_id required');
  if (!client_secret) return error(400, 'invalid_request', 'client_secret required');
  if (!code_verifier) return error(400, 'invalid_request', 'code_verifier required');

  if (!constantTimeStringEqual(client_id, config.clientId)) {
    return error(401, 'invalid_client', 'unknown client_id');
  }
  if (!constantTimeStringEqual(client_secret, config.clientSecret)) {
    return error(401, 'invalid_client', 'bad client_secret');
  }

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
  const ttl = config.accessTokenTtlSeconds ?? DEFAULT_ACCESS_TTL;
  const scope = (claims.scope as string | undefined) ?? config.defaultScope ?? DEFAULT_SCOPE;
  const accessToken = sign(
    {
      sub: claims.sub,
      aud: config.accessAudience,
      iat,
      exp: iat + ttl,
      scope,
    },
    config.signingSecret,
  );

  const body: TokenSuccess = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ttl,
    scope,
  };
  return { status: 200, body };
}
