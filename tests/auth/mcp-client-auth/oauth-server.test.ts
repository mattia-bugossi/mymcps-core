import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
    assert.deepEqual(md.response_types_supported, ['code']);
    assert.deepEqual(md.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(md.scopes_supported, ['mcp']);
  });
});

describe('handleAuthorize', () => {
  const { challenge } = verifierAndChallenge();

  it('redirects 302 with a signed code on valid input', () => {
    const result = handleAuthorize(
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

  it('rejects missing code_challenge', () => {
    const result = handleAuthorize(
      config,
      { response_type: 'code', client_id: 'client-abc', redirect_uri: 'https://cb/' },
      now,
    );
    assert.equal(result.status, 400);
    assert.deepEqual(result.body, { error: 'invalid_request', error_description: 'code_challenge required' });
  });

  it('rejects unknown client_id', () => {
    const result = handleAuthorize(
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

  it('enforces allowedRedirectUris when configured', () => {
    const restricted: OAuthServerConfig = { ...config, allowedRedirectUris: ['https://ok/cb'] };
    const result = handleAuthorize(
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

  function issueCode(): string {
    const result = handleAuthorize(
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

  it('exchanges a valid code for an access token', () => {
    const code = issueCode();
    const result = handleToken(
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

  it('rejects pkce mismatch', () => {
    const code = issueCode();
    const result = handleToken(
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

  it('rejects wrong client_secret with 401', () => {
    const code = issueCode();
    const result = handleToken(
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

  it('rejects mismatched redirect_uri on exchange', () => {
    const code = issueCode();
    const result = handleToken(
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

  it('rejects expired code', () => {
    const code = issueCode();
    const later = () => NOW + 120;
    const result = handleToken(
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
