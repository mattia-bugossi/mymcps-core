import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  fetchSecret,
  clearSecretsCacheForTests,
  type SecretsClient,
} from '../../src/aws/secrets.js';

describe('fetchSecret memoisation', () => {
  beforeEach(() => clearSecretsCacheForTests());

  it('caches a successful fetch so a second call does not hit the client', async () => {
    let calls = 0;
    const client: SecretsClient = {
      async getSecretString(arn) {
        calls += 1;
        return `value-for-${arn}`;
      },
    };
    assert.equal(await fetchSecret(client, 'arn:a'), 'value-for-arn:a');
    assert.equal(await fetchSecret(client, 'arn:a'), 'value-for-arn:a');
    assert.equal(calls, 1);
  });

  it('returns the same Promise for in-flight concurrent callers', async () => {
    let resolve!: (v: string) => void;
    let calls = 0;
    const client: SecretsClient = {
      getSecretString(arn) {
        calls += 1;
        return new Promise<string>((r) => {
          resolve = (v) => r(`${v}:${arn}`);
        });
      },
    };
    const p1 = fetchSecret(client, 'arn:a');
    const p2 = fetchSecret(client, 'arn:a');
    resolve('ok');
    assert.equal(await p1, 'ok:arn:a');
    assert.equal(await p2, 'ok:arn:a');
    assert.equal(calls, 1);
  });

  it('evicts a rejected fetch so the next caller retries', async () => {
    let calls = 0;
    const client: SecretsClient = {
      async getSecretString(arn) {
        calls += 1;
        if (calls === 1) throw new Error('transient');
        return `value-${arn}`;
      },
    };
    await assert.rejects(() => fetchSecret(client, 'arn:a'), /transient/);
    assert.equal(await fetchSecret(client, 'arn:a'), 'value-arn:a');
    assert.equal(calls, 2);
  });
});
