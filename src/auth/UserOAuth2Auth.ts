// purpose: Per-user OAuth2 refresh-token flow. Implements ProviderAuth for
// providers that hand out short-lived access tokens + long-lived rotating
// refresh tokens (Withings, Strava, …). Persists the rotated refresh token
// synchronously *before* returning the new access token so a crash between
// refresh and persist never loses the valid refresh token.

import { AuthError, UpstreamError } from '../errors/types.js';
import type { ProviderAuth } from './ProviderAuth.js';
import type { RefreshTokenRecord, RefreshTokenStore } from './RefreshTokenStore.js';

export type TokenRequestShape = 'standard' | 'withings-action-param';
export type ResponseErrorConvention = 'http-status' | 'status-in-body';

export interface UserOAuth2AuthConfig {
  // Provider identifier used in UpstreamError messages ('withings', 'strava', …).
  provider: string;
  clientId: string;
  clientSecret: string;
  // Fully-qualified token endpoint URL.
  tokenEndpoint: string;
  // How the request body is shaped. 'withings-action-param' adds the
  // Withings-specific `action=requesttoken` form field to the body. No HMAC
  // signature — Withings's /v2/oauth2 authenticates via client_secret in the
  // body; signing applies only to /v2/signature/* and admin endpoints.
  tokenRequestShape: TokenRequestShape;
  // How to detect an auth failure on the response. OAuth 2.1 uses HTTP
  // status codes (401 on bad refresh token); Withings tunnels errors through
  // the HTTP-200 body as a numeric `status` field.
  responseErrorConvention: ResponseErrorConvention;
  // Status values that mean "re-authorize required" for status-in-body mode.
  // Defaults to [100,101,102,200,401] — Withings's auth-failure bucket.
  authErrorStatusCodes?: number[];
  // Access token TTL fallback if the response omits expires_in.
  accessTokenTtlSec?: number;
  // Seconds of slack before expiry when cached access tokens are considered
  // stale. Defaults to 60.
  refreshMargin?: number;
  refreshTokenStore: RefreshTokenStore;
  now?: () => number;
  fetchFn?: typeof fetch;
}

interface TokenResponseEnvelope {
  // Present when responseErrorConvention === 'status-in-body'.
  status?: number;
  error?: string;
  body?: TokenResponseBody;
  // OAuth 2.1 standard fields — top-level when convention is 'http-status'.
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  userid?: string | number;
}

interface TokenResponseBody {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  userid?: string | number;
}

const DEFAULT_AUTH_ERROR_STATUS_CODES = [100, 101, 102, 200, 401];
const DEFAULT_REFRESH_MARGIN_SEC = 60;

export function createUserOAuth2Auth(config: UserOAuth2AuthConfig): ProviderAuth {
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  const fetchFn = config.fetchFn ?? fetch;
  const refreshMargin = config.refreshMargin ?? DEFAULT_REFRESH_MARGIN_SEC;
  const authErrorCodes = new Set(config.authErrorStatusCodes ?? DEFAULT_AUTH_ERROR_STATUS_CODES);

  function buildBody(refreshToken: string): URLSearchParams {
    const body = new URLSearchParams();
    if (config.tokenRequestShape === 'withings-action-param') {
      body.set('action', 'requesttoken');
    }
    body.set('grant_type', 'refresh_token');
    body.set('client_id', config.clientId);
    body.set('client_secret', config.clientSecret);
    body.set('refresh_token', refreshToken);
    return body;
  }

  async function refresh(record: RefreshTokenRecord): Promise<RefreshTokenRecord> {
    const res = await fetchFn(config.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: buildBody(record.refreshToken).toString(),
    });

    if (config.responseErrorConvention === 'http-status') {
      if (res.status === 401 || res.status === 400) {
        throw new AuthError(`${config.provider} refresh rejected (http ${res.status})`);
      }
      if (!res.ok) {
        throw new UpstreamError(config.provider, `refresh failed: http ${res.status}`, res.status);
      }
      const json = (await res.json()) as TokenResponseEnvelope;
      return extractRecord(record, json);
    }

    // status-in-body convention
    if (!res.ok) {
      throw new UpstreamError(config.provider, `refresh transport failed: http ${res.status}`, res.status);
    }
    const env = (await res.json()) as TokenResponseEnvelope;
    if (env.status === 0 && env.body) {
      return extractRecord(record, env.body);
    }
    if (typeof env.status === 'number' && authErrorCodes.has(env.status)) {
      throw new AuthError(
        `${config.provider} refresh rejected: status=${env.status} error=${env.error ?? 'n/a'}`,
      );
    }
    throw new UpstreamError(
      config.provider,
      `refresh failed: status=${env.status ?? 'missing'} error=${env.error ?? 'n/a'}`,
    );
  }

  function extractRecord(prev: RefreshTokenRecord, body: TokenResponseBody): RefreshTokenRecord {
    if (!body.access_token) {
      throw new UpstreamError(config.provider, 'refresh response missing access_token');
    }
    const ttl = body.expires_in ?? config.accessTokenTtlSec;
    if (typeof ttl !== 'number') {
      throw new UpstreamError(
        config.provider,
        'refresh response missing expires_in and no accessTokenTtlSec fallback',
      );
    }
    const ts = now();
    return {
      userId: prev.userId,
      refreshToken: body.refresh_token ?? prev.refreshToken,
      accessToken: body.access_token,
      accessTokenExpiresAt: ts + ttl,
      scope: body.scope ?? prev.scope,
      providerUserId: body.userid !== undefined ? String(body.userid) : prev.providerUserId,
      updatedAt: ts,
    };
  }

  return {
    async getAccessToken(userId: string): Promise<string> {
      const record = await config.refreshTokenStore.get(userId);
      if (!record) {
        throw new AuthError(`no ${config.provider} refresh token for user ${userId}`);
      }

      const ts = now();
      if (
        record.accessToken &&
        typeof record.accessTokenExpiresAt === 'number' &&
        record.accessTokenExpiresAt - refreshMargin > ts
      ) {
        return record.accessToken;
      }

      const refreshed = await refresh(record);
      // Persist BEFORE returning so a crash downstream can never lose
      // the rotated refresh token.
      await config.refreshTokenStore.put(refreshed);
      return refreshed.accessToken!;
    },
  };
}
