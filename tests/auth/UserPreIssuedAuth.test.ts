import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuthError,
  UpstreamAuthRevoked,
  UpstreamAuthSeedError,
  UpstreamError,
} from '../../src/errors/types.js';
import {
  createUserPreIssuedAuth,
  type UserPreIssuedAuthConfig,
} from '../../src/auth/UserPreIssuedAuth.js';
import {
  ConcurrentModificationError,
  type VersionedSecret,
  type VersionedSecretsClient,
} from '../../src/auth/VersionedSecretsClient.js';

const NOW = 1_700_000_000;
const SECRET_ARN = 'arn:aws:secretsmanager:eu-west-2:111:secret:peloton/tokens';

interface StoredRec {
  access_token: string;
  refresh_token: string;
  expires_at: number;
}

interface FakeStore extends VersionedSecretsClient {
  stored: { value: string; versionId: string } | null;
  putCalls: number;
  getCalls: number;
  // Fires after each successful get(), AFTER the value has been
  // captured for return. Tests use this to mutate `stored` between
  // gets, simulating an external rotation that lands between the
  // caller's loadCurrent read and doRefresh's re-read.
  onGet?: (callIndex: number) => void;
  // Force the next put() to fail with ConcurrentModificationError, then
  // set `stored` to the winner's value so the caller's re-read picks it up.
  failNextPutWith(
    winner: { value: string; versionId: string },
  ): void;
}

function mkStore(initial: StoredRec, versionId = 'v1'): FakeStore {
  let stored: { value: string; versionId: string } | null = {
    value: JSON.stringify(initial),
    versionId,
  };
  let queuedWinner: { value: string; versionId: string } | null = null;
  let nextNewVersion = 2;

  const store: FakeStore = {
    get stored() {
      return stored;
    },
    set stored(v) {
      stored = v;
    },
    putCalls: 0,
    getCalls: 0,
    onGet: undefined,
    failNextPutWith(winner) {
      queuedWinner = winner;
    },
    async get() {
      const callIndex = store.getCalls++;
      const snapshot = stored ? { value: stored.value, versionId: stored.versionId } : null;
      if (store.onGet) store.onGet(callIndex);
      return snapshot;
    },
    async put(_arn, value, expectedVersionId) {
      store.putCalls++;
      if (queuedWinner) {
        // Simulate another writer having bumped the version first.
        stored = queuedWinner;
        queuedWinner = null;
        throw new ConcurrentModificationError(_arn, expectedVersionId);
      }
      if (!stored || stored.versionId !== expectedVersionId) {
        throw new ConcurrentModificationError(_arn, expectedVersionId);
      }
      const newVersionId = `v${nextNewVersion++}`;
      stored = { value, versionId: newVersionId };
      return newVersionId;
    },
  };
  return store;
}

interface FetchCall {
  url: string;
  init: RequestInit;
}

type Responder = (call: FetchCall) => Response | Promise<Response>;

function mkFetch(responder: Responder): {
  fetch: typeof fetch;
  calls: FetchCall[];
} {
  const calls: FetchCall[] = [];
  const fetchFn = (async (input, init) => {
    const call: FetchCall = { url: String(input), init: init ?? {} };
    calls.push(call);
    return responder(call);
  }) as typeof fetch;
  return { fetch: fetchFn, calls };
}

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  } as unknown as Response;
}

function mkConfig(overrides: Partial<UserPreIssuedAuthConfig> = {}): UserPreIssuedAuthConfig {
  return {
    provider: 'peloton',
    authDomain: 'https://auth.onepeloton.com',
    clientId: 'spa-client',
    audience: 'peloton-api',
    secretArn: SECRET_ARN,
    secretsClient: {
      async get() {
        return null;
      },
      async put() {
        return 'v-unused';
      },
    },
    now: () => NOW,
    ...overrides,
  };
}

describe('createUserPreIssuedAuth.getAccessToken — cached + proactive refresh', () => {
  it('returns the cached access_token when far from expiry', async () => {
    const store = mkStore({
      access_token: 'at-current',
      refresh_token: 'rt-current',
      expires_at: NOW + 3600,
    });
    const { fetch: fetchFn, calls } = mkFetch(() => jsonResponse(500, 'unused'));
    const auth = createUserPreIssuedAuth(
      mkConfig({ secretsClient: store, fetchFn }),
    );
    const token = await auth.getAccessToken('single-user');
    assert.equal(token, 'at-current');
    assert.equal(calls.length, 0, 'no refresh call expected');
    assert.equal(store.putCalls, 0);
  });

  it('rotates the pair when the cached token is within refreshMargin of expiry', async () => {
    const store = mkStore({
      access_token: 'at-old',
      refresh_token: 'rt-old',
      expires_at: NOW + 30, // inside default 60s margin
    });
    const { fetch: fetchFn, calls } = mkFetch(() =>
      jsonResponse(200, {
        access_token: 'at-new',
        refresh_token: 'rt-new',
        expires_in: 3600,
      }),
    );
    const auth = createUserPreIssuedAuth(
      mkConfig({ secretsClient: store, fetchFn }),
    );

    const token = await auth.getAccessToken('single-user');
    assert.equal(token, 'at-new');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://auth.onepeloton.com/oauth/token');

    // Old refresh_token invalidated in storage, new pair persisted.
    const persisted = JSON.parse(store.stored!.value) as StoredRec;
    assert.equal(persisted.access_token, 'at-new');
    assert.equal(persisted.refresh_token, 'rt-new');
    assert.equal(persisted.expires_at, NOW + 3600);
    assert.notEqual(persisted.refresh_token, 'rt-old');
  });
});

describe('createUserPreIssuedAuth.fetch — 401 → refresh → retry', () => {
  it('retries the original request once with the new access_token on 401', async () => {
    const store = mkStore({
      access_token: 'at-old',
      refresh_token: 'rt-old',
      expires_at: NOW + 3600, // cached, no proactive refresh
    });
    let call = 0;
    const { fetch: fetchFn, calls } = mkFetch((c) => {
      call++;
      if (c.url === 'https://auth.onepeloton.com/oauth/token') {
        return jsonResponse(200, {
          access_token: 'at-new',
          refresh_token: 'rt-new',
          expires_in: 3600,
        });
      }
      // Upstream: first attempt 401, retry 200.
      if (call === 1) return jsonResponse(401, { error: 'token_expired' });
      return jsonResponse(200, { ok: true });
    });

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    const res = await auth.fetch('https://api.onepeloton.com/me');
    assert.equal(res.status, 200);

    // Call sequence: upstream (401) → refresh (200) → upstream (200).
    assert.equal(calls.length, 3);
    assert.equal(calls[0].url, 'https://api.onepeloton.com/me');
    assert.equal(calls[1].url, 'https://auth.onepeloton.com/oauth/token');
    assert.equal(calls[2].url, 'https://api.onepeloton.com/me');

    const firstAuth = (calls[0].init.headers as Headers).get('authorization');
    const retryAuth = (calls[2].init.headers as Headers).get('authorization');
    assert.equal(firstAuth, 'Bearer at-old');
    assert.equal(retryAuth, 'Bearer at-new');
  });

  it('returns the second 401 as-is without a third attempt', async () => {
    const store = mkStore({
      access_token: 'at-old',
      refresh_token: 'rt-old',
      expires_at: NOW + 3600,
    });
    const { fetch: fetchFn, calls } = mkFetch((c) => {
      if (c.url === 'https://auth.onepeloton.com/oauth/token') {
        return jsonResponse(200, {
          access_token: 'at-new',
          refresh_token: 'rt-new',
          expires_in: 3600,
        });
      }
      return jsonResponse(401, { error: 'still_bad' });
    });

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    const res = await auth.fetch('https://api.onepeloton.com/me');
    assert.equal(res.status, 401);
    // upstream (401) → refresh → upstream (401); no third attempt.
    assert.equal(calls.length, 3);
  });
});

describe('createUserPreIssuedAuth — refresh error taxonomy', () => {
  it('throws UpstreamAuthRevoked on refresh 4xx (non-retryable)', async () => {
    const store = mkStore({
      access_token: 'at-old',
      refresh_token: 'rt-old',
      expires_at: NOW + 30, // within default 60s refreshMargin → forces refresh
    });
    const { fetch: fetchFn } = mkFetch(() =>
      jsonResponse(401, { error: 'invalid_grant' }),
    );
    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    await assert.rejects(
      () => auth.getAccessToken('single-user'),
      (err: unknown) =>
        err instanceof UpstreamAuthRevoked &&
        err.provider === 'peloton' &&
        err.upstreamStatus === 401,
    );
  });

  it('throws UpstreamError on refresh 5xx (distinct from revoked)', async () => {
    const store = mkStore({
      access_token: 'at-old',
      refresh_token: 'rt-old',
      expires_at: NOW + 30,
    });
    const { fetch: fetchFn } = mkFetch(() =>
      jsonResponse(503, { error: 'unavailable' }),
    );
    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    await assert.rejects(
      () => auth.getAccessToken('single-user'),
      (err: unknown) =>
        err instanceof UpstreamError &&
        !(err instanceof UpstreamAuthRevoked) &&
        err.upstreamStatus === 503,
    );
  });
});

describe('createUserPreIssuedAuth — single-flight mutex', () => {
  it('deduplicates concurrent refreshes into a single upstream /oauth/token call', async () => {
    const store = mkStore({
      access_token: 'at-old',
      refresh_token: 'rt-old',
      expires_at: NOW + 30,
    });
    let releaseRefresh: (value: Response) => void = () => {};
    const refreshPromise = new Promise<Response>((resolve) => {
      releaseRefresh = resolve;
    });
    let refreshCalls = 0;
    const { fetch: fetchFn } = mkFetch((c) => {
      if (c.url === 'https://auth.onepeloton.com/oauth/token') {
        refreshCalls++;
        return refreshPromise;
      }
      return jsonResponse(500, 'unused');
    });

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    const a = auth.getAccessToken('single-user');
    const b = auth.getAccessToken('single-user');
    const c = auth.getAccessToken('single-user');

    // Let the in-flight refresh resolve.
    releaseRefresh(
      jsonResponse(200, {
        access_token: 'at-new',
        refresh_token: 'rt-new',
        expires_in: 3600,
      }),
    );
    const [ta, tb, tc] = await Promise.all([a, b, c]);
    assert.equal(ta, 'at-new');
    assert.equal(tb, 'at-new');
    assert.equal(tc, 'at-new');
    assert.equal(refreshCalls, 1, 'single upstream /oauth/token call across 3 concurrent getters');
    assert.equal(store.putCalls, 1, 'single persist across concurrent callers');
  });
});

describe('createUserPreIssuedAuth — cross-Lambda CAS (ConcurrentModificationError)', () => {
  it('on stale VersionId, re-reads and uses the winning writer\'s access_token without a second refresh', async () => {
    const store = mkStore({
      access_token: 'at-old',
      refresh_token: 'rt-old',
      expires_at: NOW + 30,
    });
    // Simulate another Lambda having rotated first: the winning
    // writer's token pair sits at v2.
    const winnerRecord = {
      access_token: 'at-winner',
      refresh_token: 'rt-winner',
      expires_at: NOW + 3600,
    };
    store.failNextPutWith({ value: JSON.stringify(winnerRecord), versionId: 'v2' });

    let refreshCalls = 0;
    const { fetch: fetchFn } = mkFetch((c) => {
      if (c.url === 'https://auth.onepeloton.com/oauth/token') {
        refreshCalls++;
        return jsonResponse(200, {
          access_token: 'at-loser',
          refresh_token: 'rt-loser',
          expires_in: 3600,
        });
      }
      return jsonResponse(500, 'unused');
    });

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    const token = await auth.getAccessToken('single-user');
    assert.equal(token, 'at-winner', 'caller receives the winner\'s token, not its own refresh result');
    assert.equal(refreshCalls, 1, 'only one refresh attempt — no re-refresh after CAS failure');
    assert.equal(store.putCalls, 1);
  });
});

describe('createUserPreIssuedAuth — malformed stored secret', () => {
  it('throws AuthError with a pointed message when SecretString is not JSON', async () => {
    const store: VersionedSecretsClient = {
      async get() {
        return { value: 'not-json-at-all', versionId: 'v1' };
      },
      async put() {
        return 'v2';
      },
    };
    const { fetch: fetchFn } = mkFetch(() => jsonResponse(500, 'unused'));
    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    await assert.rejects(
      () => auth.getAccessToken('single-user'),
      (err: unknown) => err instanceof AuthError && /not valid JSON/.test(err.message),
    );
  });

  it('throws AuthError when a required field is missing', async () => {
    const store: VersionedSecretsClient = {
      async get() {
        return {
          value: JSON.stringify({ access_token: 'a', refresh_token: 'b' }), // no expires_at
          versionId: 'v1',
        };
      },
      async put() {
        return 'v2';
      },
    };
    const { fetch: fetchFn } = mkFetch(() => jsonResponse(500, 'unused'));
    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    await assert.rejects(
      () => auth.getAccessToken('single-user'),
      (err: unknown) => err instanceof AuthError && /missing expires_at/.test(err.message),
    );
  });
});

describe('createUserPreIssuedAuth — re-reads secret before refresh (external rotation)', () => {
  it('skips the upstream POST when the secret has been externally rotated since loadCurrent read it', async () => {
    // Setup: stored value is stale (expired access_token). An external
    // rotator (operator put-secret-value, or the SPA in another tab)
    // lands a fresh pair between loadCurrent's read and doRefresh's
    // re-read. Simulated via onGet: after the first get (loadCurrent),
    // mutate `stored` so the second get (doRefresh re-read) returns
    // the rotator's fresh value.
    const store = mkStore({
      access_token: 'at-stale',
      refresh_token: 'rt-stale',
      expires_at: NOW + 30, // within default 60s refreshMargin → forces refresh
    });
    store.onGet = (callIndex) => {
      if (callIndex === 0) {
        store.stored = {
          value: JSON.stringify({
            access_token: 'at-fresh-from-rotator',
            refresh_token: 'rt-fresh-from-rotator',
            expires_at: NOW + 3600,
          }),
          versionId: 'v-rotator',
        };
      }
    };

    let refreshCalls = 0;
    const { fetch: fetchFn } = mkFetch(() => {
      refreshCalls++;
      return jsonResponse(200, {
        access_token: 'at-from-our-refresh',
        refresh_token: 'rt-from-our-refresh',
        expires_in: 3600,
      });
    });

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    const token = await auth.getAccessToken('single-user');

    assert.equal(token, 'at-fresh-from-rotator', 'caller receives the rotator\'s token');
    assert.equal(refreshCalls, 0, 'no upstream /oauth/token POST — refresh skipped');
    assert.equal(store.putCalls, 0, 'no put — we did not refresh');
    // 2 gets: 1 loadCurrent + 1 doRefresh re-read.
    assert.equal(store.getCalls, 2);
  });

  it('combined with single-flight: 3 concurrent callers + external rotation → 1 doRefresh re-read, 0 refresh calls', async () => {
    const store = mkStore({
      access_token: 'at-stale',
      refresh_token: 'rt-stale',
      expires_at: NOW + 30,
    });
    store.onGet = (callIndex) => {
      // The single doRefresh re-read happens after the 3 loadCurrent
      // reads — at callIndex === 3.
      if (callIndex === 2) {
        store.stored = {
          value: JSON.stringify({
            access_token: 'at-fresh-from-rotator',
            refresh_token: 'rt-fresh-from-rotator',
            expires_at: NOW + 3600,
          }),
          versionId: 'v-rotator',
        };
      }
    };

    let refreshCalls = 0;
    const { fetch: fetchFn } = mkFetch(() => {
      refreshCalls++;
      return jsonResponse(200, {
        access_token: 'at-unused',
        refresh_token: 'rt-unused',
        expires_in: 3600,
      });
    });

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    const [a, b, c] = await Promise.all([
      auth.getAccessToken('single-user'),
      auth.getAccessToken('single-user'),
      auth.getAccessToken('single-user'),
    ]);
    assert.equal(a, 'at-fresh-from-rotator');
    assert.equal(b, 'at-fresh-from-rotator');
    assert.equal(c, 'at-fresh-from-rotator');
    assert.equal(refreshCalls, 0, 'single-flight + re-read-skip → no upstream POST at all');
    assert.equal(store.putCalls, 0);
    // 3 loadCurrent + 1 single-flighted doRefresh re-read = 4 gets.
    assert.equal(store.getCalls, 4);
  });

  it('routine call with fresh in-memory access token does not trigger the doRefresh re-read', async () => {
    const store = mkStore({
      access_token: 'at-fresh',
      refresh_token: 'rt-fresh',
      expires_at: NOW + 3600, // far past refreshMargin
    });
    const { fetch: fetchFn } = mkFetch(() => jsonResponse(500, 'unused'));

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    const token = await auth.getAccessToken('single-user');
    assert.equal(token, 'at-fresh');
    // Only the loadCurrent read; no refresh path entered, no re-read.
    assert.equal(store.getCalls, 1);
    assert.equal(store.putCalls, 0);
  });
});

describe('createUserPreIssuedAuth — UpstreamAuthSeedError on stale expires_at at load', () => {
  it('throws UpstreamAuthSeedError on expires_at: 0 — and does NOT trigger any refresh', async () => {
    const store = mkStore({
      access_token: 'at-seed',
      refresh_token: 'rt-seed',
      expires_at: 0,
    });
    let refreshCalls = 0;
    const { fetch: fetchFn } = mkFetch(() => {
      refreshCalls++;
      return jsonResponse(200, { access_token: 'unused', expires_in: 3600 });
    });

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    await assert.rejects(
      () => auth.getAccessToken('single-user'),
      (err: unknown) =>
        err instanceof UpstreamAuthSeedError &&
        err.provider === 'peloton' &&
        /expires_at is in the past/.test(err.message),
    );
    assert.equal(refreshCalls, 0, 'refresh path NOT triggered when seed error fires');
    assert.equal(store.putCalls, 0);
  });

  it('throws UpstreamAuthSeedError on expires_at one second in the past — same no-refresh guarantee', async () => {
    const store = mkStore({
      access_token: 'at-seed',
      refresh_token: 'rt-seed',
      expires_at: NOW - 1,
    });
    let refreshCalls = 0;
    const { fetch: fetchFn } = mkFetch(() => {
      refreshCalls++;
      return jsonResponse(200, { access_token: 'unused', expires_in: 3600 });
    });

    const auth = createUserPreIssuedAuth(mkConfig({ secretsClient: store, fetchFn }));
    await assert.rejects(
      () => auth.getAccessToken('single-user'),
      (err: unknown) => err instanceof UpstreamAuthSeedError,
    );
    assert.equal(refreshCalls, 0);
  });

  it('does NOT throw on expires_at exactly one second in the future (strict-past threshold)', async () => {
    // refreshMargin = 0 to avoid triggering a proactive refresh — we
    // only want to assert the seed check passes; what happens
    // afterward (route to cached token) is secondary.
    const store = mkStore({
      access_token: 'at-seed',
      refresh_token: 'rt-seed',
      expires_at: NOW + 1,
    });
    const { fetch: fetchFn } = mkFetch(() => jsonResponse(500, 'unused'));

    const auth = createUserPreIssuedAuth(
      mkConfig({ secretsClient: store, fetchFn, refreshMargin: 0 }),
    );
    const token = await auth.getAccessToken('single-user');
    assert.equal(token, 'at-seed');
  });
});

// Silence unused-import warning for VersionedSecret; it documents the
// contract the in-memory fake implements.
export type _Unused = VersionedSecret;
