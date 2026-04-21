import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { APIGatewayRequestAuthorizerEventV2 } from 'aws-lambda';
import { makeAuthorizer } from '../../../src/auth/mcp-client-auth/authorizer.js';
import { sign } from '../../../src/auth/mcp-client-auth/jwt.js';

const silentLogger = { warn: () => {} };

function event(rawPath: string, headers: Record<string, string> = {}): APIGatewayRequestAuthorizerEventV2 {
  return {
    version: '2.0',
    type: 'REQUEST',
    routeArn: '',
    identitySource: [],
    routeKey: '',
    rawPath,
    rawQueryString: '',
    headers,
    requestContext: {} as unknown as APIGatewayRequestAuthorizerEventV2['requestContext'],
  };
}

describe('makeAuthorizer', () => {
  it('bypasses public paths without inspecting headers', async () => {
    const auth = makeAuthorizer({
      accessAudience: 'aud-x',
      publicPaths: ['/healthz', '/oauth/token'],
      loadStaticToken: async () => {
        throw new Error('should not be called');
      },
      loadSigningSecret: async () => null,
      logger: silentLogger,
    });
    assert.deepEqual(await auth(event('/healthz')), { isAuthorized: true });
    assert.deepEqual(await auth(event('/oauth/token')), { isAuthorized: true });
  });

  it('accepts a matching static bearer token', async () => {
    const auth = makeAuthorizer({
      accessAudience: 'aud-x',
      publicPaths: [],
      loadStaticToken: async () => 'static-secret',
      loadSigningSecret: async () => null,
      logger: silentLogger,
    });
    assert.deepEqual(
      await auth(event('/mcp', { authorization: 'Bearer static-secret' })),
      { isAuthorized: true },
    );
  });

  it('denies when no Authorization header is present', async () => {
    const auth = makeAuthorizer({
      accessAudience: 'aud-x',
      publicPaths: [],
      loadStaticToken: async () => 's',
      loadSigningSecret: async () => null,
      logger: silentLogger,
    });
    assert.deepEqual(await auth(event('/mcp')), { isAuthorized: false });
  });

  it('accepts a signed JWT at the configured audience', async () => {
    const secret = 'sig-secret';
    const now = Math.floor(Date.now() / 1000);
    const jwt = sign({ sub: 'u', aud: 'aud-x', iat: now, exp: now + 60 }, secret);
    const auth = makeAuthorizer({
      accessAudience: 'aud-x',
      publicPaths: [],
      loadStaticToken: async () => 'mismatch-static',
      loadSigningSecret: async () => secret,
      logger: silentLogger,
    });
    assert.deepEqual(
      await auth(event('/mcp', { authorization: `Bearer ${jwt}` })),
      { isAuthorized: true },
    );
  });

  it('denies a JWT at the wrong audience', async () => {
    const secret = 'sig-secret';
    const now = Math.floor(Date.now() / 1000);
    const jwt = sign({ sub: 'u', aud: 'wrong', iat: now, exp: now + 60 }, secret);
    const auth = makeAuthorizer({
      accessAudience: 'aud-x',
      publicPaths: [],
      loadStaticToken: async () => 'static',
      loadSigningSecret: async () => secret,
      logger: silentLogger,
    });
    assert.deepEqual(
      await auth(event('/mcp', { authorization: `Bearer ${jwt}` })),
      { isAuthorized: false },
    );
  });

  it('denies (not 500s) when static-token load rejects', async () => {
    const auth = makeAuthorizer({
      accessAudience: 'aud-x',
      publicPaths: [],
      loadStaticToken: async () => {
        throw new Error('secrets manager unavailable');
      },
      loadSigningSecret: async () => null,
      logger: silentLogger,
    });
    assert.deepEqual(
      await auth(event('/mcp', { authorization: 'Bearer anything' })),
      { isAuthorized: false },
    );
  });
});
