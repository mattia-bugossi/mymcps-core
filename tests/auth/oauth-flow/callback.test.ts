import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { exchangeAuthorizationCode } from '../../../src/auth/oauth-flow/callback.js';
import type {
  RefreshTokenRecord,
  RefreshTokenStore,
} from '../../../src/auth/RefreshTokenStore.js';
import { AuthError, UpstreamError } from '../../../src/errors/types.js';

function makeStore(): { store: RefreshTokenStore; puts: RefreshTokenRecord[] } {
  const puts: RefreshTokenRecord[] = [];
  const store: RefreshTokenStore = {
    async get() {
      return null;
    },
    async put(r) {
      puts.push(r);
    },
    async delete() {},
  };
  return { store, puts };
}

const NOW = 1_700_000_000;

describe('exchangeAuthorizationCode', () => {
  it('http-status success: persists record and returns access token', async () => {
    const { store, puts } = makeStore();
    const fetchFn: typeof fetch = async () =>
      new Response(
        JSON.stringify({
          access_token: 'at',
          refresh_token: 'rt',
          expires_in: 3600,
          scope: 'read write',
        }),
        { status: 200 },
      );
    const result = await exchangeAuthorizationCode(
      {
        provider: 'strava',
        clientId: 'cid',
        clientSecret: 'csec',
        tokenEndpoint: 'https://strava/token',
        redirectUri: 'https://mcp/cb',
        tokenRequestShape: 'standard',
        responseErrorConvention: 'http-status',
        refreshTokenStore: store,
        now: () => NOW,
        fetchFn,
      },
      { userId: 'u1', code: 'abc' },
    );
    assert.equal(result.accessToken, 'at');
    assert.equal(result.expiresAt, NOW + 3600);
    assert.equal(puts.length, 1);
    assert.equal(puts[0].userId, 'u1');
    assert.equal(puts[0].refreshToken, 'rt');
  });

  it('withings-action-param-signed shape: includes action=requesttoken in body', async () => {
    const { store } = makeStore();
    let capturedBody = '';
    const fetchFn: typeof fetch = async (_url, init) => {
      capturedBody = init?.body as string;
      return new Response(
        JSON.stringify({
          status: 0,
          body: {
            access_token: 'at',
            refresh_token: 'rt',
            expires_in: 10_800,
            scope: 'user.metrics',
            userid: '12345',
          },
        }),
        { status: 200 },
      );
    };
    const result = await exchangeAuthorizationCode(
      {
        provider: 'withings',
        clientId: 'cid',
        clientSecret: 'csec',
        tokenEndpoint: 'https://wbsapi.withings.net/v2/oauth2',
        redirectUri: 'https://mcp/cb',
        tokenRequestShape: 'withings-action-param-signed',
        responseErrorConvention: 'status-in-body',
        refreshTokenStore: store,
        now: () => NOW,
        fetchFn,
      },
      { userId: 'u1', code: 'abc' },
    );
    const body = new URLSearchParams(capturedBody);
    assert.equal(body.get('action'), 'requesttoken');
    assert.equal(body.get('grant_type'), 'authorization_code');
    assert.equal(body.get('code'), 'abc');
    assert.equal(result.providerUserId, '12345');
  });

  it('status-in-body known auth code surfaces as AuthError', async () => {
    const { store, puts } = makeStore();
    const fetchFn: typeof fetch = async () =>
      new Response(JSON.stringify({ status: 401, error: 'bad code' }), { status: 200 });
    await assert.rejects(
      () =>
        exchangeAuthorizationCode(
          {
            provider: 'withings',
            clientId: 'cid',
            clientSecret: 'csec',
            tokenEndpoint: 'https://x/token',
            redirectUri: 'https://mcp/cb',
            tokenRequestShape: 'withings-action-param-signed',
            responseErrorConvention: 'status-in-body',
            refreshTokenStore: store,
            now: () => NOW,
            fetchFn,
          },
          { userId: 'u1', code: 'abc' },
        ),
      (err) => err instanceof AuthError,
    );
    assert.equal(puts.length, 0);
  });

  it('status-in-body non-auth non-zero surfaces as UpstreamError', async () => {
    const { store } = makeStore();
    const fetchFn: typeof fetch = async () =>
      new Response(JSON.stringify({ status: 503, error: 'slow' }), { status: 200 });
    await assert.rejects(
      () =>
        exchangeAuthorizationCode(
          {
            provider: 'withings',
            clientId: 'cid',
            clientSecret: 'csec',
            tokenEndpoint: 'https://x/token',
            redirectUri: 'https://mcp/cb',
            tokenRequestShape: 'withings-action-param-signed',
            responseErrorConvention: 'status-in-body',
            refreshTokenStore: store,
            now: () => NOW,
            fetchFn,
          },
          { userId: 'u1', code: 'abc' },
        ),
      (err) => err instanceof UpstreamError,
    );
  });

  it('throws UpstreamError when refresh_token is missing from the response', async () => {
    const { store } = makeStore();
    const fetchFn: typeof fetch = async () =>
      new Response(JSON.stringify({ access_token: 'at', expires_in: 3600 }), { status: 200 });
    await assert.rejects(
      () =>
        exchangeAuthorizationCode(
          {
            provider: 'strava',
            clientId: 'cid',
            clientSecret: 'csec',
            tokenEndpoint: 'https://x/token',
            redirectUri: 'https://mcp/cb',
            tokenRequestShape: 'standard',
            responseErrorConvention: 'http-status',
            refreshTokenStore: store,
            now: () => NOW,
            fetchFn,
          },
          { userId: 'u1', code: 'abc' },
        ),
      (err) => err instanceof UpstreamError,
    );
  });
});
