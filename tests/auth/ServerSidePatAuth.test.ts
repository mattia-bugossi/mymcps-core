import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createServerSidePatAuth } from '../../src/auth/ServerSidePatAuth.js';
import { clearSecretsCacheForTests, type SecretsClient } from '../../src/aws/secrets.js';
import { AuthError } from '../../src/errors/types.js';

describe('ServerSidePatAuth', () => {
  beforeEach(() => clearSecretsCacheForTests());

  it('returns the PAT from Secrets Manager regardless of userId', async () => {
    let calls = 0;
    const client: SecretsClient = {
      async getSecretString(arn) {
        calls += 1;
        return `pat-${arn}`;
      },
    };
    const auth = createServerSidePatAuth({ client, secretArn: 'arn:oura-pat' });
    assert.equal(await auth.getAccessToken('anyone'), 'pat-arn:oura-pat');
    assert.equal(await auth.getAccessToken('someone-else'), 'pat-arn:oura-pat');
    // fetchSecret memoises, so the SecretsClient is hit exactly once.
    assert.equal(calls, 1);
  });

  it('wraps Secrets Manager failures in AuthError', async () => {
    const client: SecretsClient = {
      async getSecretString() {
        throw new Error('access denied');
      },
    };
    const auth = createServerSidePatAuth({ client, secretArn: 'arn:missing' });
    await assert.rejects(
      () => auth.getAccessToken('u'),
      (err) => err instanceof AuthError && /access denied/.test((err as Error).message),
    );
  });
});
