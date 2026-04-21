import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sign, verify } from '../../../src/auth/mcp-client-auth/jwt.js';

const secret = 'test-secret-do-not-use';

describe('jwt.sign / verify', () => {
  it('round-trips valid claims', () => {
    const now = 1_000_000;
    const token = sign({ sub: 'u1', aud: 'aud-x', iat: now, exp: now + 60 }, secret);
    const claims = verify(token, secret, 'aud-x', now);
    assert.equal(claims.sub, 'u1');
    assert.equal(claims.aud, 'aud-x');
  });

  it('rejects bad signature', () => {
    const now = 1_000_000;
    const token = sign({ sub: 'u', aud: 'a', iat: now, exp: now + 60 }, secret);
    assert.throws(() => verify(token, 'wrong-secret', 'a', now), /invalid_signature/);
  });

  it('rejects wrong audience', () => {
    const now = 1_000_000;
    const token = sign({ sub: 'u', aud: 'a', iat: now, exp: now + 60 }, secret);
    assert.throws(() => verify(token, secret, 'other', now), /wrong_audience/);
  });

  it('rejects expired token', () => {
    const now = 1_000_000;
    const token = sign({ sub: 'u', aud: 'a', iat: now, exp: now + 60 }, secret);
    assert.throws(() => verify(token, secret, 'a', now + 120), /expired/);
  });

  it('rejects malformed token', () => {
    assert.throws(() => verify('not-a-jwt', secret, 'a'), /malformed_token/);
  });
});
