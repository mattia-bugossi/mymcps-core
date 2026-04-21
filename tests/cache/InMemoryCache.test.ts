import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryCache } from '../../src/cache/InMemoryCache.js';

describe('InMemoryCache', () => {
  it('returns null for a missing key', async () => {
    const c = new InMemoryCache();
    assert.equal(await c.get('missing'), null);
    c.stopSweep();
  });

  it('round-trips typed values', async () => {
    const c = new InMemoryCache();
    await c.set('k', { n: 7, s: 'x' }, 60);
    assert.deepEqual(await c.get<{ n: number; s: string }>('k'), { n: 7, s: 'x' });
    c.stopSweep();
  });

  it('expires entries after ttl elapses (lazy eviction on get)', async () => {
    mock.timers.enable({ apis: ['Date'] });
    const c = new InMemoryCache();
    await c.set('k', 'v', 10);
    mock.timers.tick(9_000);
    assert.equal(await c.get('k'), 'v');
    mock.timers.tick(2_000);
    assert.equal(await c.get('k'), null);
    c.stopSweep();
    mock.timers.reset();
  });

  it('delete removes the entry immediately', async () => {
    const c = new InMemoryCache();
    await c.set('k', 'v', 60);
    await c.delete('k');
    assert.equal(await c.get('k'), null);
    c.stopSweep();
  });
});
