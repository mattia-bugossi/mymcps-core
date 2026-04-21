import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildAuthorizationUrl } from '../../../src/auth/oauth-flow/authorize.js';

describe('buildAuthorizationUrl', () => {
  it('builds an OAuth 2.0 standard space-joined scope URL', () => {
    const url = buildAuthorizationUrl({
      authorizationEndpoint: 'https://example/oauth/authorize',
      clientId: 'cid',
      redirectUri: 'https://mcp/callback',
      scopes: ['read', 'write'],
      state: 's1',
    });
    const u = new URL(url);
    assert.equal(u.origin + u.pathname, 'https://example/oauth/authorize');
    assert.equal(u.searchParams.get('response_type'), 'code');
    assert.equal(u.searchParams.get('client_id'), 'cid');
    assert.equal(u.searchParams.get('redirect_uri'), 'https://mcp/callback');
    assert.equal(u.searchParams.get('scope'), 'read write');
    assert.equal(u.searchParams.get('state'), 's1');
  });

  it('joins scopes with comma for providers that require it', () => {
    const url = buildAuthorizationUrl({
      authorizationEndpoint: 'https://account.withings.com/oauth2_user/authorize2',
      clientId: 'cid',
      redirectUri: 'https://mcp/callback',
      scopes: ['user.metrics', 'user.info'],
      scopeSeparator: 'comma',
    });
    assert.equal(new URL(url).searchParams.get('scope'), 'user.metrics,user.info');
  });

  it('appends extraParams without clobbering the standard ones', () => {
    const url = buildAuthorizationUrl({
      authorizationEndpoint: 'https://example/oauth/authorize',
      clientId: 'cid',
      redirectUri: 'https://mcp/callback',
      scopes: ['a'],
      extraParams: { code_challenge: 'XYZ', code_challenge_method: 'S256' },
    });
    const u = new URL(url);
    assert.equal(u.searchParams.get('code_challenge'), 'XYZ');
    assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(u.searchParams.get('response_type'), 'code');
  });
});
