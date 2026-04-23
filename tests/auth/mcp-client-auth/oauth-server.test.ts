import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  ClientIdCollisionError,
  type ClientRegistry,
  type RegisteredClient,
} from '../../../src/auth/mcp-client-auth/client-registry.js';
import {
  buildDiscoveryMetadata,
  handleAuthorize,
  handleToken,
  type OAuthServerConfig,
  type TokenSuccess,
} from '../../../src/auth/mcp-client-auth/oauth-server.js';

const config: OAuthServerConfig = {
  clientId: 'client-abc',
  clientSecret: 'shhh',
  signingSecret: 'sig-secret',
  codeAudience: 'test-code',
  accessAudience: 'test-access',
};

const NOW = 1_700_000_000;
const now = () => NOW;

function verifierAndChallenge() {
  const verifier = 'a'.repeat(64);
  const challenge = createHash('sha256')
    .update(verifier)
    .digest('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return { verifier, challenge };
}

describe('buildDiscoveryMetadata', () => {
  it('returns RFC 8414 fields with the correct issuer', () => {
    const md = buildDiscoveryMetadata(config, { issuer: 'https://x.example' });
    assert.equal(md.issuer, 'https://x.example');
    assert.equal(md.authorization_endpoint, 'https://x.example/oauth/authorize');
    assert.equal(md.token_endpoint, 'https://x.example/oauth/token');
    assert.equal(md.registration_endpoint, 'https://x.example/register');
    assert.deepEqual(md.response_types_supported, ['code']);
    assert.deepEqual(md.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(md.scopes_supported, ['mcp']);
  });
});

describe('handleAuthorize', () => {
  const { challenge } = verifierAndChallenge();

  it('redirects 302 with a signed code on valid input', async () => {
    const result = await handleAuthorize(
      config,
      {
        response_type: 'code',
        client_id: 'client-abc',
        redirect_uri: 'https://cb.example/cb',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'xyz',
      },
      now,
    );
    assert.equal(result.status, 302);
    assert.match(result.redirect ?? '', /^https:\/\/cb\.example\/cb\?code=.+&state=xyz$/);
  });

  it('rejects missing code_challenge', async () => {
    const result = await handleAuthorize(
      config,
      { response_type: 'code', client_id: 'client-abc', redirect_uri: 'https://cb/' },
      now,
    );
    assert.equal(result.status, 400);
    assert.deepEqual(result.body, { error: 'invalid_request', error_description: 'code_challenge required' });
  });

  it('rejects unknown client_id', async () => {
    const result = await handleAuthorize(
      config,
      {
        response_type: 'code',
        client_id: 'other',
        redirect_uri: 'https://cb/',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      now,
    );
    assert.equal(result.status, 400);
    assert.equal((result.body as { error: string }).error, 'invalid_client');
  });

  it('enforces allowedRedirectUris when configured', async () => {
    const restricted: OAuthServerConfig = { ...config, allowedRedirectUris: ['https://ok/cb'] };
    const result = await handleAuthorize(
      restricted,
      {
        response_type: 'code',
        client_id: 'client-abc',
        redirect_uri: 'https://evil/cb',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      now,
    );
    assert.equal(result.status, 400);
    assert.match((result.body as { error_description: string }).error_description, /not allowed/);
  });
});

describe('handleToken', () => {
  const { verifier, challenge } = verifierAndChallenge();
  const redirect_uri = 'https://cb.example/cb';

  async function issueCode(): Promise<string> {
    const result = await handleAuthorize(
      config,
      {
        response_type: 'code',
        client_id: 'client-abc',
        redirect_uri,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      now,
    );
    const url = new URL(result.redirect!);
    return url.searchParams.get('code')!;
  }

  it('exchanges a valid code for an access token', async () => {
    const code = await issueCode();
    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id: 'client-abc',
        client_secret: 'shhh',
        code_verifier: verifier,
      },
      now,
    );
    assert.equal(result.status, 200);
    const body = result.body as TokenSuccess;
    assert.equal(body.token_type, 'Bearer');
    assert.equal(body.expires_in, 24 * 60 * 60);
    assert.ok(body.access_token.split('.').length === 3);
    assert.equal(body.scope, 'mcp');
  });

  it('static-pair path works without a registry (zero-friction 0.2.x→0.3.0 upgrade)', async () => {
    const code = await issueCode();
    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id: 'client-abc',
        client_secret: 'shhh',
        code_verifier: verifier,
      },
      now,
      // registry deliberately omitted — identical behavior to 0.2.x except
      // the returned promise.
    );
    assert.equal(result.status, 200);
  });

  it('rejects pkce mismatch', async () => {
    const code = await issueCode();
    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id: 'client-abc',
        client_secret: 'shhh',
        code_verifier: 'wrong-verifier',
      },
      now,
    );
    assert.equal(result.status, 400);
    assert.match((result.body as { error_description: string }).error_description, /pkce/);
  });

  it('rejects wrong client_secret with 401', async () => {
    const code = await issueCode();
    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id: 'client-abc',
        client_secret: 'nope',
        code_verifier: verifier,
      },
      now,
    );
    assert.equal(result.status, 401);
    assert.equal((result.body as { error: string }).error, 'invalid_client');
  });

  it('rejects mismatched redirect_uri on exchange', async () => {
    const code = await issueCode();
    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://other/cb',
        client_id: 'client-abc',
        client_secret: 'shhh',
        code_verifier: verifier,
      },
      now,
    );
    assert.equal(result.status, 400);
    assert.match((result.body as { error_description: string }).error_description, /redirect_uri mismatch/);
  });

  it('rejects expired code', async () => {
    const code = await issueCode();
    const later = () => NOW + 120;
    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id: 'client-abc',
        client_secret: 'shhh',
        code_verifier: verifier,
      },
      later,
    );
    assert.equal(result.status, 400);
    assert.match((result.body as { error_description: string }).error_description, /expired/);
  });
});

function mkRegistry(clients: RegisteredClient[] = []): ClientRegistry & {
  all: () => RegisteredClient[];
} {
  const map = new Map<string, RegisteredClient>();
  for (const c of clients) map.set(c.client_id, c);
  return {
    all: () => Array.from(map.values()),
    async get(clientId) {
      return map.get(clientId) ?? null;
    },
    async put(client) {
      if (map.has(client.client_id)) throw new ClientIdCollisionError(client.client_id);
      map.set(client.client_id, client);
    },
  };
}

describe('handleAuthorize + handleToken with ClientRegistry (DCR client)', () => {
  const { verifier, challenge } = verifierAndChallenge();
  const redirect_uri = 'https://dcr.example/cb';
  const dcr: RegisteredClient = {
    client_id: 'dcr-abc',
    client_secret: 'dcr-shhh',
    client_id_issued_at: NOW,
    metadata: {
      token_endpoint_auth_method: 'client_secret_post',
      redirect_uris: [redirect_uri],
    },
  };

  it('accepts a registered client_id at /authorize and issues a code', async () => {
    const registry = mkRegistry([dcr]);
    const result = await handleAuthorize(
      config,
      {
        response_type: 'code',
        client_id: 'dcr-abc',
        redirect_uri,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      now,
      registry,
    );
    assert.equal(result.status, 302);
    assert.match(result.redirect ?? '', /code=/);
  });

  it('rejects redirect_uri not in the registered client metadata', async () => {
    const registry = mkRegistry([dcr]);
    const result = await handleAuthorize(
      config,
      {
        response_type: 'code',
        client_id: 'dcr-abc',
        redirect_uri: 'https://other.example/cb',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      now,
      registry,
    );
    assert.equal(result.status, 400);
    assert.match(
      (result.body as { error_description: string }).error_description,
      /not allowed/,
    );
  });

  it('rejects unknown client_id at /authorize even with a registry', async () => {
    const registry = mkRegistry([]);
    const result = await handleAuthorize(
      config,
      {
        response_type: 'code',
        client_id: 'unknown',
        redirect_uri,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      now,
      registry,
    );
    assert.equal(result.status, 400);
    assert.equal((result.body as { error: string }).error, 'invalid_client');
  });

  it('exchanges a code issued to a registered client for an access token', async () => {
    const registry = mkRegistry([dcr]);
    const authorized = await handleAuthorize(
      config,
      {
        response_type: 'code',
        client_id: 'dcr-abc',
        redirect_uri,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      now,
      registry,
    );
    const code = new URL(authorized.redirect!).searchParams.get('code')!;

    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id: 'dcr-abc',
        client_secret: 'dcr-shhh',
        code_verifier: verifier,
      },
      now,
      registry,
    );
    assert.equal(result.status, 200);
    const body = result.body as TokenSuccess;
    assert.equal(body.token_type, 'Bearer');
  });

  it('rejects a registered client with the wrong client_secret at /token', async () => {
    const registry = mkRegistry([dcr]);
    const authorized = await handleAuthorize(
      config,
      {
        response_type: 'code',
        client_id: 'dcr-abc',
        redirect_uri,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      },
      now,
      registry,
    );
    const code = new URL(authorized.redirect!).searchParams.get('code')!;

    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        client_id: 'dcr-abc',
        client_secret: 'nope',
        code_verifier: verifier,
      },
      now,
      registry,
    );
    assert.equal(result.status, 401);
    assert.equal((result.body as { error: string }).error, 'invalid_client');
  });

  it('rejects unknown client_id at /token with a registry present', async () => {
    const registry = mkRegistry([]);
    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code: 'whatever',
        redirect_uri,
        client_id: 'unknown',
        client_secret: 'x',
        code_verifier: verifier,
      },
      now,
      registry,
    );
    assert.equal(result.status, 401);
    assert.equal((result.body as { error: string }).error, 'invalid_client');
  });
});
