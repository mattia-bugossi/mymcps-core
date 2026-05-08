// purpose: Per-user upstream auth for providers that require a
// browser-issued token pair (access_token + refresh_token) to be
// pre-seeded out-of-band — the server side cannot initiate the OAuth
// dance because it does not hold a client_secret. Peloton-style public
// SPA clients live here. Coexists with UserOAuth2Auth (the delegated
// OAuth2 pattern used by Withings/Strava); the two must not cross-
// import — this module is the entry-point for the pre-issued pattern
// only.
//
// Storage layout: a single AWS Secrets Manager secret at secretArn with
// SecretString = JSON {access_token, refresh_token, expires_at} where
// expires_at is unix seconds. Seeded manually; rotated here on refresh.
//
// Refresh path: on upstream 401 (or proactively when the cached token
// is within refreshMargin of expiry), POST {authDomain}/oauth/token
// with JSON {grant_type: 'refresh_token', client_id, refresh_token}.
// New pair persisted via VersionedSecretsClient.put (CAS on prior
// VersionId). On ConcurrentModificationError, re-read the secret and
// use the winning writer's new access_token rather than refreshing
// again — per the spec's single-flight guarantee.
//
// Concurrency:
// - Per-Lambda-instance single-flight: one in-flight refresh Promise
//   per createUserPreIssuedAuth invocation, awaited by every concurrent
//   caller.
// - Cross-Lambda: handled by VersionedSecretsClient's CAS; the loser
//   re-reads and uses the winner's tokens, never triggering a second
//   refresh.

import {
  AuthError,
  UpstreamAuthRevoked,
  UpstreamAuthSeedError,
  UpstreamError,
} from '../errors/types.js';
import type { ProviderAuth } from './ProviderAuth.js';
import {
  ConcurrentModificationError,
  type VersionedSecret,
  type VersionedSecretsClient,
} from './VersionedSecretsClient.js';

export interface UserPreIssuedAuthConfig {
  // Provider identifier used in UpstreamError / UpstreamAuthRevoked
  // messages ('peloton', …).
  provider: string;
  // Fully-qualified base URL of the upstream auth domain (e.g.
  // 'https://auth.onepeloton.com'). The refresh POST is issued to
  // `${authDomain}/oauth/token`.
  authDomain: string;
  // Public SPA client_id. No client_secret — that's why we're in this
  // pattern rather than the delegated-OAuth2 pattern.
  clientId: string;
  // Access token audience (surfaced in the refresh request body for
  // providers that require it; harmless to include when they don't).
  audience: string;
  // ARN of the pre-seeded Secrets Manager secret holding the token pair.
  secretArn: string;
  // Versioned Secrets Manager client with CAS support.
  secretsClient: VersionedSecretsClient;
  now?: () => number;
  fetchFn?: typeof fetch;
  // Seconds of slack before expires_at when the cached access token is
  // considered stale enough to trigger a proactive refresh instead of
  // waiting for the upstream to 401. Defaults to 60. Pass 0 to force
  // pure-reactive behavior (refresh only on 401).
  refreshMargin?: number;
}

interface StoredTokenRecord {
  access_token: string;
  refresh_token: string;
  // Unix seconds.
  expires_at: number;
}

interface RefreshResponseBody {
  access_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
}

export interface PreIssuedAuth extends ProviderAuth {
  // Wraps fetch with Authorization: Bearer <access_token>. On upstream
  // 401, refreshes the token pair once and retries the original request
  // with the new access_token. Does not retry on other statuses —
  // caller maps to JSON-RPC. Any refresh 4xx propagates as
  // UpstreamAuthRevoked (user must re-authorize); refresh 5xx as
  // UpstreamError.
  fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
}

const DEFAULT_REFRESH_MARGIN_SEC = 60;

function parseStored(provider: string, raw: string): StoredTokenRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new AuthError(
      `${provider} stored token secret is not valid JSON: ${(err as Error).message}`,
    );
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new AuthError(`${provider} stored token secret is not an object`);
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.access_token !== 'string') {
    throw new AuthError(`${provider} stored token secret missing access_token`);
  }
  if (typeof record.refresh_token !== 'string') {
    throw new AuthError(`${provider} stored token secret missing refresh_token`);
  }
  if (typeof record.expires_at !== 'number') {
    throw new AuthError(`${provider} stored token secret missing expires_at`);
  }
  return {
    access_token: record.access_token,
    refresh_token: record.refresh_token,
    expires_at: record.expires_at,
  };
}

function withAuth(init: RequestInit | undefined, token: string): RequestInit {
  const headers = new Headers(init?.headers);
  headers.set('authorization', `Bearer ${token}`);
  return { ...(init ?? {}), headers };
}

export function createUserPreIssuedAuth(
  config: UserPreIssuedAuthConfig,
): PreIssuedAuth {
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  const fetchFn = config.fetchFn ?? fetch;
  const refreshMargin = config.refreshMargin ?? DEFAULT_REFRESH_MARGIN_SEC;

  // Module-scoped single-flight: only one refresh Promise in flight per
  // createUserPreIssuedAuth invocation. Cleared in finally() so later
  // callers trigger a fresh refresh on the next expiry.
  let pending: Promise<VersionedSecret> | null = null;

  async function loadCurrent(): Promise<{ secret: VersionedSecret; record: StoredTokenRecord }> {
    const secret = await config.secretsClient.get(config.secretArn);
    if (!secret) {
      throw new AuthError(
        `${config.provider} token seed missing at ${config.secretArn}`,
      );
    }
    const record = parseStored(config.provider, secret.value);
    // Strict-past check: a seed with expires_at at-or-before now would
    // force an immediate refresh on first call. If another process
    // (e.g., the SPA still running in another tab) has already rotated
    // the token pair upstream, that refresh would burn a refresh token
    // already consumed by the rotator. Abort before any network call.
    if (record.expires_at <= now()) {
      throw new UpstreamAuthSeedError(
        config.provider,
        'expires_at is in the past; this would force an immediate refresh on first call and may burn your refresh token if another process has already rotated it. Use the actual expiry from the source.',
      );
    }
    return { secret, record };
  }

  async function callRefresh(current: StoredTokenRecord): Promise<StoredTokenRecord> {
    const res = await fetchFn(`${config.authDomain}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        client_id: config.clientId,
        audience: config.audience,
        refresh_token: current.refresh_token,
      }),
    });

    if (res.status >= 400 && res.status < 500) {
      throw new UpstreamAuthRevoked(
        config.provider,
        `refresh rejected: http ${res.status}`,
        res.status,
      );
    }
    if (!res.ok) {
      throw new UpstreamError(
        config.provider,
        `refresh failed: http ${res.status}`,
        res.status,
      );
    }

    const body = (await res.json()) as RefreshResponseBody;
    if (typeof body.access_token !== 'string') {
      throw new UpstreamError(
        config.provider,
        'refresh response missing access_token',
      );
    }
    if (typeof body.expires_in !== 'number') {
      throw new UpstreamError(
        config.provider,
        'refresh response missing expires_in',
      );
    }
    const newRefresh =
      typeof body.refresh_token === 'string' ? body.refresh_token : current.refresh_token;
    return {
      access_token: body.access_token,
      refresh_token: newRefresh,
      expires_at: now() + body.expires_in,
    };
  }

  async function doRefresh(current: VersionedSecret): Promise<VersionedSecret> {
    const cachedRecord = parseStored(config.provider, current.value);

    // Re-read the secret immediately before refreshing. Catches manual
    // `put-secret-value` rotations (operator runbook) and same-Lambda
    // races where another path already rotated — without this, warm
    // instances would hold stale token pairs in module-scope memory
    // until cold start. Compare on access_token: the unambiguous
    // "did the secret change" signal (refresh_token may or may not
    // rotate; expires_at can drift from clock skew).
    const fresh = await config.secretsClient.get(config.secretArn);
    if (!fresh) {
      throw new AuthError(
        `${config.provider} token seed missing at ${config.secretArn}`,
      );
    }
    const freshRecord = parseStored(config.provider, fresh.value);
    if (freshRecord.access_token !== cachedRecord.access_token) {
      // Externally rotated. Skip the upstream POST (which would burn a
      // refresh token already consumed by the rotator) and surface the
      // fresh pair to the caller.
      return fresh;
    }

    const rotated = await callRefresh(cachedRecord);
    const newValue = JSON.stringify(rotated);
    try {
      const newVersionId = await config.secretsClient.put(
        config.secretArn,
        newValue,
        fresh.versionId,
      );
      return { value: newValue, versionId: newVersionId };
    } catch (err) {
      if (err instanceof ConcurrentModificationError) {
        // Another Lambda rotated the secret between our re-read and
        // put. Re-read and use the winner's access_token rather than
        // refreshing again.
        const winner = await config.secretsClient.get(config.secretArn);
        if (!winner) {
          throw new AuthError(
            `${config.provider} token seed disappeared during concurrent refresh`,
          );
        }
        return winner;
      }
      throw err;
    }
  }

  async function refreshOnce(current: VersionedSecret): Promise<VersionedSecret> {
    if (pending) return pending;
    pending = doRefresh(current).finally(() => {
      pending = null;
    });
    return pending;
  }

  async function getAccessToken(): Promise<string> {
    const { secret, record } = await loadCurrent();
    if (record.expires_at - refreshMargin > now()) {
      return record.access_token;
    }
    const refreshed = await refreshOnce(secret);
    return parseStored(config.provider, refreshed.value).access_token;
  }

  async function wrappedFetch(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    const token = await getAccessToken();
    const first = await fetchFn(input, withAuth(init, token));
    if (first.status !== 401) return first;

    // 401 — refresh once, retry with the new access_token.
    const current = await config.secretsClient.get(config.secretArn);
    if (!current) {
      throw new AuthError(
        `${config.provider} token seed missing at ${config.secretArn}`,
      );
    }
    const refreshed = await refreshOnce(current);
    const newAccess = parseStored(config.provider, refreshed.value).access_token;
    return fetchFn(input, withAuth(init, newAccess));
  }

  return {
    async getAccessToken() {
      return getAccessToken();
    },
    fetch: wrappedFetch,
  };
}
