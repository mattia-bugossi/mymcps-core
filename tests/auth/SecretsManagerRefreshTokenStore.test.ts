import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createSecretsManagerRefreshTokenStore,
  type TokenSecretsClient,
} from '../../src/auth/SecretsManagerRefreshTokenStore.js';
import type { RefreshTokenRecord } from '../../src/auth/RefreshTokenStore.js';

function makeFakeClient() {
  const map = new Map<string, string>();
  const client: TokenSecretsClient = {
    async getString(id) {
      return map.get(id) ?? null;
    },
    async putString(id, v) {
      map.set(id, v);
    },
    async deleteSecret(id) {
      map.delete(id);
    },
  };
  return { client, map };
}

const record: RefreshTokenRecord = {
  userId: 'user-123',
  refreshToken: 'rt-initial',
  accessToken: 'at-1',
  accessTokenExpiresAt: 1_700_000_100,
  scope: 'user.metrics,user.info',
  providerUserId: '987',
  updatedAt: 1_700_000_000,
};

describe('SecretsManagerRefreshTokenStore', () => {
  it('put stores under <prefix>/<userId> as JSON', async () => {
    const { client, map } = makeFakeClient();
    const store = createSecretsManagerRefreshTokenStore({
      client,
      secretPrefix: '/mymcps/withings/refresh-tokens',
    });
    await store.put(record);
    assert.deepEqual([...map.keys()], ['/mymcps/withings/refresh-tokens/user-123']);
    const stored = JSON.parse(map.get('/mymcps/withings/refresh-tokens/user-123')!) as RefreshTokenRecord;
    assert.deepEqual(stored, record);
  });

  it('get returns the parsed record', async () => {
    const { client } = makeFakeClient();
    const store = createSecretsManagerRefreshTokenStore({
      client,
      secretPrefix: '/mymcps/withings/refresh-tokens',
    });
    await store.put(record);
    const got = await store.get('user-123');
    assert.deepEqual(got, record);
  });

  it('get returns null when the secret is missing', async () => {
    const { client } = makeFakeClient();
    const store = createSecretsManagerRefreshTokenStore({
      client,
      secretPrefix: '/mymcps/withings/refresh-tokens',
    });
    assert.equal(await store.get('nobody'), null);
  });

  it('delete removes the secret', async () => {
    const { client, map } = makeFakeClient();
    const store = createSecretsManagerRefreshTokenStore({
      client,
      secretPrefix: '/mymcps/withings/refresh-tokens',
    });
    await store.put(record);
    await store.delete('user-123');
    assert.equal(map.size, 0);
  });
});
