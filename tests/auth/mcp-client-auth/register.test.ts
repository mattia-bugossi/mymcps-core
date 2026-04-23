import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  ClientIdCollisionError,
  type ClientRegistry,
  type RegisteredClient,
} from '../../../src/auth/mcp-client-auth/client-registry.js';
import {
  handleRegister,
  type ClientRegistration,
} from '../../../src/auth/mcp-client-auth/oauth-server.js';

const NOW = 1_700_000_000;
const now = () => NOW;

interface Store extends ClientRegistry {
  all(): RegisteredClient[];
  seed(client: RegisteredClient): void;
  putCalls(): number;
}

function mkStore(): Store {
  const map = new Map<string, RegisteredClient>();
  let puts = 0;
  return {
    all: () => Array.from(map.values()),
    seed: (c) => {
      map.set(c.client_id, c);
    },
    putCalls: () => puts,
    async get(clientId) {
      return map.get(clientId) ?? null;
    },
    async put(client) {
      puts++;
      if (map.has(client.client_id)) throw new ClientIdCollisionError(client.client_id);
      map.set(client.client_id, client);
    },
  };
}

describe('handleRegister', () => {
  it('mints and persists a fresh client on a minimal request', async () => {
    const store = mkStore();
    const result = await handleRegister(
      { redirect_uris: ['https://claude.ai/api/mcp/auth_callback'] },
      store,
      now,
    );

    assert.equal(result.status, 201);
    const body = result.body as ClientRegistration;
    assert.equal(typeof body.client_id, 'string');
    assert.equal(typeof body.client_secret, 'string');
    assert.ok(body.client_id.length >= 32);
    assert.ok(body.client_secret.length >= 32);
    assert.equal(body.client_id_issued_at, NOW);
    assert.equal(body.client_secret_expires_at, 0);
    assert.equal(body.token_endpoint_auth_method, 'client_secret_post');
    assert.deepEqual(body.redirect_uris, ['https://claude.ai/api/mcp/auth_callback']);

    assert.equal(store.all().length, 1);
    const stored = store.all()[0];
    assert.equal(stored.client_id, body.client_id);
    assert.equal(stored.client_secret, body.client_secret);
  });

  it('defaults token_endpoint_auth_method to client_secret_post when omitted', async () => {
    const store = mkStore();
    const result = await handleRegister({}, store, now);
    const body = result.body as ClientRegistration;
    assert.equal(body.token_endpoint_auth_method, 'client_secret_post');
  });

  it('mints unique client_ids across two registrations', async () => {
    const store = mkStore();
    const a = await handleRegister({}, store, now);
    const b = await handleRegister({}, store, now);
    const aBody = a.body as ClientRegistration;
    const bBody = b.body as ClientRegistration;
    assert.notEqual(aBody.client_id, bBody.client_id);
    assert.notEqual(aBody.client_secret, bBody.client_secret);
  });

  it('rejects token_endpoint_auth_method other than client_secret_post', async () => {
    const store = mkStore();
    const result = await handleRegister(
      { token_endpoint_auth_method: 'client_secret_basic' },
      store,
      now,
    );
    assert.equal(result.status, 400);
    assert.equal(
      (result.body as { error: string }).error,
      'invalid_client_metadata',
    );
    assert.equal(store.all().length, 0);
  });

  it('rejects malformed redirect_uris (must be array of strings)', async () => {
    const store = mkStore();
    const result = await handleRegister(
      { redirect_uris: 'https://single-string/cb' },
      store,
      now,
    );
    assert.equal(result.status, 400);
    assert.equal(
      (result.body as { error: string }).error,
      'invalid_client_metadata',
    );
  });

  it('echoes optional metadata (grant_types, response_types, client_name, scope)', async () => {
    const store = mkStore();
    const result = await handleRegister(
      {
        redirect_uris: ['https://cb/'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        client_name: 'claude.ai',
        scope: 'mcp',
      },
      store,
      now,
    );
    const body = result.body as ClientRegistration;
    assert.deepEqual(body.grant_types, ['authorization_code']);
    assert.deepEqual(body.response_types, ['code']);
    assert.equal(body.client_name, 'claude.ai');
    assert.equal(body.scope, 'mcp');
  });

  it('retries once on ClientIdCollisionError and succeeds on the second attempt', async () => {
    // Seed the store so that ANY client_id put() first throws. We need to
    // force a collision on attempt 0 only — use a registry that throws once.
    const real = mkStore();
    let thrown = false;
    const flaky: ClientRegistry = {
      async get(clientId) {
        return real.get(clientId);
      },
      async put(client) {
        if (!thrown) {
          thrown = true;
          throw new ClientIdCollisionError(client.client_id);
        }
        await real.put(client);
      },
    };
    const result = await handleRegister({}, flaky, now);
    assert.equal(result.status, 201);
    assert.equal(real.all().length, 1);
  });

  it('propagates non-collision errors from put() without retry', async () => {
    const broken: ClientRegistry = {
      async get() {
        return null;
      },
      async put() {
        throw new Error('disk full');
      },
    };
    await assert.rejects(() => handleRegister({}, broken, now), /disk full/);
  });
});
