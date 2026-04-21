// purpose: Exchange a provider authorization code for tokens and persist them
// via a RefreshTokenStore. First write wins — subsequent getAccessToken calls
// then go through UserOAuth2Auth's cache-then-refresh flow.

import { AuthError, UpstreamError } from '../../errors/types.js';
import type { RefreshTokenStore } from '../RefreshTokenStore.js';
import type {
  ResponseErrorConvention,
  TokenRequestShape,
} from '../UserOAuth2Auth.js';

export interface ExchangeCodeConfig {
  provider: string;
  clientId: string;
  clientSecret: string;
  tokenEndpoint: string;
  redirectUri: string;
  tokenRequestShape: TokenRequestShape;
  responseErrorConvention: ResponseErrorConvention;
  authErrorStatusCodes?: number[];
  accessTokenTtlSec?: number;
  refreshTokenStore: RefreshTokenStore;
  now?: () => number;
  fetchFn?: typeof fetch;
}

export interface ExchangeCodeInput {
  // MCP-side user id the tokens will be stored under.
  userId: string;
  // Authorization code received at the callback.
  code: string;
}

export interface ExchangeCodeResult {
  accessToken: string;
  scope?: string;
  providerUserId?: string;
  expiresAt: number;
}

interface TokenEnvelope {
  status?: number;
  error?: string;
  body?: TokenBody;
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  userid?: string | number;
}

interface TokenBody {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  userid?: string | number;
}

const DEFAULT_AUTH_ERROR_STATUS_CODES = [100, 101, 102, 200, 401];

export async function exchangeAuthorizationCode(
  config: ExchangeCodeConfig,
  input: ExchangeCodeInput,
): Promise<ExchangeCodeResult> {
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  const fetchFn = config.fetchFn ?? fetch;
  const authErrorCodes = new Set(config.authErrorStatusCodes ?? DEFAULT_AUTH_ERROR_STATUS_CODES);

  const body = new URLSearchParams();
  if (config.tokenRequestShape === 'withings-action-param') {
    body.set('action', 'requesttoken');
  }
  body.set('grant_type', 'authorization_code');
  body.set('client_id', config.clientId);
  body.set('client_secret', config.clientSecret);
  body.set('code', input.code);
  body.set('redirect_uri', config.redirectUri);

  const res = await fetchFn(config.tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  let tokenBody: TokenBody | undefined;
  if (config.responseErrorConvention === 'http-status') {
    if (res.status === 401 || res.status === 400) {
      throw new AuthError(`${config.provider} code exchange rejected (http ${res.status})`);
    }
    if (!res.ok) {
      throw new UpstreamError(
        config.provider,
        `code exchange failed: http ${res.status}`,
        res.status,
      );
    }
    tokenBody = (await res.json()) as TokenBody;
  } else {
    if (!res.ok) {
      throw new UpstreamError(
        config.provider,
        `code exchange transport failed: http ${res.status}`,
        res.status,
      );
    }
    const env = (await res.json()) as TokenEnvelope;
    if (env.status === 0 && env.body) {
      tokenBody = env.body;
    } else if (typeof env.status === 'number' && authErrorCodes.has(env.status)) {
      throw new AuthError(
        `${config.provider} code exchange rejected: status=${env.status} error=${env.error ?? 'n/a'}`,
      );
    } else {
      throw new UpstreamError(
        config.provider,
        `code exchange failed: status=${env.status ?? 'missing'} error=${env.error ?? 'n/a'}`,
      );
    }
  }

  if (!tokenBody?.access_token || !tokenBody.refresh_token) {
    throw new UpstreamError(
      config.provider,
      'code exchange response missing access_token or refresh_token',
    );
  }
  const ttl = tokenBody.expires_in ?? config.accessTokenTtlSec;
  if (typeof ttl !== 'number') {
    throw new UpstreamError(
      config.provider,
      'code exchange response missing expires_in and no accessTokenTtlSec fallback',
    );
  }
  const ts = now();
  const record = {
    userId: input.userId,
    refreshToken: tokenBody.refresh_token,
    accessToken: tokenBody.access_token,
    accessTokenExpiresAt: ts + ttl,
    scope: tokenBody.scope,
    providerUserId: tokenBody.userid !== undefined ? String(tokenBody.userid) : undefined,
    updatedAt: ts,
  };
  await config.refreshTokenStore.put(record);
  return {
    accessToken: record.accessToken,
    scope: record.scope,
    providerUserId: record.providerUserId,
    expiresAt: record.accessTokenExpiresAt,
  };
}
