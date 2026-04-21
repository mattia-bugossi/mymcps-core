import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createUserOAuth2Auth } from '../../src/auth/UserOAuth2Auth.js';
import type {
  RefreshTokenRecord,
  RefreshTokenStore,
} from '../../src/auth/RefreshTokenStore.js';
import { AuthError, UpstreamError } from '../../src/errors/types.js';

function makeStore(initial?: RefreshTokenRecord): {
  store: RefreshTokenStore;
  puts: RefreshTokenRecord[];
} {
  let current: RefreshTokenRecord | null = initial ?? null;
  const puts: RefreshTokenRecord[] = [];
  const store: RefreshTokenStore = {
    async get() {
      return current;
    },
    async put(r) {
      puts.push(r);
      current = r;
    },
    async delete() {
      current = null;
    },
  };
  return { store, puts };
}

const USER = 'user-42';
const NOW = 1_700_000_000;

const initialRecord: RefreshTokenRecord = {
  userId: USER,
  refreshToken: 'rt-old',
  accessToken: 'at-old',
  accessTokenExpiresAt: NOW + 1000,
  scope: 'user.metrics',
  providerUserId: '987',
  updatedAt: NOW - 500,
};

describe('UserOAuth2Auth.getAccessToken', () => {
  it('returns the cached access token when not near expiry', async () => {
    const { store, puts } = makeStore(initialRecord);
    let fetchCalls = 0;
    const fetchFn: typeof fetch = async () => {
      fetchCalls += 1;
      return new Response('{}', { status: 200 });
    };
    const auth = createUserOAuth2Auth({
      provider: 'withings',
      clientId: 'cid',
      clientSecret: 'csec',
      tokenEndpoint: 'https://example/token',
      tokenRequestShape: 'standard',
      responseErrorConvention: 'http-status',
      refreshTokenStore: store,
      now: () => NOW,
      fetchFn,
    });
    const token = await auth.getAccessToken(USER);
    assert.equal(token, 'at-old');
    assert.equal(fetchCalls, 0);
    assert.equal(puts.length, 0);
  });

  it('refreshes when the cached token is within the refreshMargin', async () => {
    const { store, puts } = makeStore({
      ...initialRecord,
      accessTokenExpiresAt: NOW + 30, // within 60s margin
    });
    const fetchFn: typeof fetch = async () =>
      new Response(
        JSON.stringify({
          access_token: 'at-new',
          refresh_token: 'rt-new',
          expires_in: 10_800,
          scope: 'user.metrics',
        }),
        { status: 200 },
      );
    const auth = createUserOAuth2Auth({
      provider: 'strava',
      clientId: 'cid',
      clientSecret: 'csec',
      tokenEndpoint: 'https://example/token',
      tokenRequestShape: 'standard',
      responseErrorConvention: 'http-status',
      refreshTokenStore: store,
      now: () => NOW,
      fetchFn,
    });
    const token = await auth.getAccessToken(USER);
    assert.equal(token, 'at-new');
    assert.equal(puts.length, 1);
    assert.equal(puts[0].refreshToken, 'rt-new');
    assert.equal(puts[0].accessTokenExpiresAt, NOW + 10_800);
  });

  it('throws AuthError when no record is stored for the user', async () => {
    const { store } = makeStore();
    const auth = createUserOAuth2Auth({
      provider: 'strava',
      clientId: 'cid',
      clientSecret: 'csec',
      tokenEndpoint: 'https://example/token',
      tokenRequestShape: 'standard',
      responseErrorConvention: 'http-status',
      refreshTokenStore: store,
      now: () => NOW,
      fetchFn: async () => new Response(''),
    });
    await assert.rejects(() => auth.getAccessToken(USER), (err) => err instanceof AuthError);
  });

  it('http-status convention: 401 surfaces as AuthError', async () => {
    const { store, puts } = makeStore({ ...initialRecord, accessTokenExpiresAt: NOW - 10 });
    const fetchFn: typeof fetch = async () =>
      new Response('{"error":"invalid_grant"}', { status: 401 });
    const auth = createUserOAuth2Auth({
      provider: 'strava',
      clientId: 'cid',
      clientSecret: 'csec',
      tokenEndpoint: 'https://example/token',
      tokenRequestShape: 'standard',
      responseErrorConvention: 'http-status',
      refreshTokenStore: store,
      now: () => NOW,
      fetchFn,
    });
    await assert.rejects(() => auth.getAccessToken(USER), (err) => err instanceof AuthError);
    assert.equal(puts.length, 0);
  });

  it('status-in-body convention: status=0 success unwraps the nested body', async () => {
    let captured: RequestInit | undefined;
    const { store, puts } = makeStore({ ...initialRecord, accessTokenExpiresAt: NOW - 10 });
    const fetchFn: typeof fetch = async (_url, init) => {
      captured = init;
      return new Response(
        JSON.stringify({
          status: 0,
          body: {
            access_token: 'at-w-new',
            refresh_token: 'rt-w-new',
            expires_in: 10_800,
            scope: 'user.metrics,user.info',
            userid: 987_654,
          },
        }),
        { status: 200 },
      );
    };
    const auth = createUserOAuth2Auth({
      provider: 'withings',
      clientId: 'cid',
      clientSecret: 'csec',
      tokenEndpoint: 'https://wbsapi.withings.net/v2/oauth2',
      tokenRequestShape: 'action-param',
      responseErrorConvention: 'status-in-body',
      refreshTokenStore: store,
      now: () => NOW,
      fetchFn,
    });
    const token = await auth.getAccessToken(USER);
    assert.equal(token, 'at-w-new');
    assert.equal(puts.length, 1);
    assert.equal(puts[0].refreshToken, 'rt-w-new');
    assert.equal(puts[0].providerUserId, '987654');

    const body = new URLSearchParams(captured?.body as string);
    assert.equal(body.get('action'), 'requesttoken');
    assert.equal(body.get('grant_type'), 'refresh_token');
    assert.equal(body.get('client_id'), 'cid');
    assert.equal(body.get('client_secret'), 'csec');
    assert.equal(body.get('refresh_token'), 'rt-old');
  });

  it('status-in-body convention: known auth status surfaces as AuthError', async () => {
    const { store, puts } = makeStore({ ...initialRecord, accessTokenExpiresAt: NOW - 10 });
    const fetchFn: typeof fetch = async () =>
      new Response(
        JSON.stringify({ status: 401, error: 'unauthorized: invalid refresh_token' }),
        { status: 200 },
      );
    const auth = createUserOAuth2Auth({
      provider: 'withings',
      clientId: 'cid',
      clientSecret: 'csec',
      tokenEndpoint: 'https://x/token',
      tokenRequestShape: 'action-param',
      responseErrorConvention: 'status-in-body',
      refreshTokenStore: store,
      now: () => NOW,
      fetchFn,
    });
    await assert.rejects(() => auth.getAccessToken(USER), (err) => err instanceof AuthError);
    assert.equal(puts.length, 0);
  });

  it('status-in-body convention: non-auth non-zero status surfaces as UpstreamError', async () => {
    const { store } = makeStore({ ...initialRecord, accessTokenExpiresAt: NOW - 10 });
    const fetchFn: typeof fetch = async () =>
      new Response(JSON.stringify({ status: 503, error: 'temporarily unavailable' }), { status: 200 });
    const auth = createUserOAuth2Auth({
      provider: 'withings',
      clientId: 'cid',
      clientSecret: 'csec',
      tokenEndpoint: 'https://x/token',
      tokenRequestShape: 'action-param',
      responseErrorConvention: 'status-in-body',
      refreshTokenStore: store,
      now: () => NOW,
      fetchFn,
    });
    await assert.rejects(() => auth.getAccessToken(USER), (err) => err instanceof UpstreamError);
  });

  it('persists the rotated refresh token BEFORE returning the new access token', async () => {
    const events: string[] = [];
    const current: RefreshTokenRecord = { ...initialRecord, accessTokenExpiresAt: NOW - 10 };
    const store: RefreshTokenStore = {
      async get() {
        return current;
      },
      async put(r) {
        events.push(`put:${r.refreshToken}`);
      },
      async delete() {},
    };
    const fetchFn: typeof fetch = async () => {
      events.push('refresh-response');
      return new Response(
        JSON.stringify({
          access_token: 'at-new',
          refresh_token: 'rt-rotated',
          expires_in: 3600,
        }),
        { status: 200 },
      );
    };
    const auth = createUserOAuth2Auth({
      provider: 'strava',
      clientId: 'cid',
      clientSecret: 'csec',
      tokenEndpoint: 'https://x/token',
      tokenRequestShape: 'standard',
      responseErrorConvention: 'http-status',
      refreshTokenStore: store,
      now: () => NOW,
      fetchFn,
    });
    const token = await auth.getAccessToken(USER);
    events.push(`returned:${token}`);
    assert.deepEqual(events, ['refresh-response', 'put:rt-rotated', 'returned:at-new']);
  });
});
