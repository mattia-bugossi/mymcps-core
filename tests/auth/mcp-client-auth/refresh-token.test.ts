import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type {
  IssuedRefreshTokenRecord,
  IssuedRefreshTokenStore,
} from '../../../src/auth/mcp-client-auth/issued-refresh-token-store.js';
import { verify } from '../../../src/auth/mcp-client-auth/jwt.js';
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
const ONE_HOUR = 60 * 60;
const TWENTY_FOUR_HOURS = 24 * 60 * 60;
const THIRTY_DAYS = 30 * 24 * 60 * 60;

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

interface FakeStore extends IssuedRefreshTokenStore {
  rows: Map<string, IssuedRefreshTokenRecord>;
}

function mkStore(): FakeStore {
  const rows = new Map<string, IssuedRefreshTokenRecord>();
  return {
    rows,
    async get(jti) {
      return rows.get(jti) ?? null;
    },
    async put(record) {
      if (rows.has(record.jti)) throw new Error(`duplicate jti: ${record.jti}`);
      rows.set(record.jti, { ...record });
    },
    async rotate(predecessorJti, newRecord) {
      const predecessor = rows.get(predecessorJti);
      if (!predecessor) throw new Error(`unknown predecessor: ${predecessorJti}`);
      if (rows.has(newRecord.jti)) throw new Error(`duplicate jti: ${newRecord.jti}`);
      // Atomic: both writes commit together (simulating
      // TransactWriteItems). If either would fail, neither happens —
      // this is exactly the contract the production DDB store must
      // honor to close the parallel-chain exploit window.
      rows.set(predecessorJti, { ...predecessor, superseded_by_jti: newRecord.jti });
      rows.set(newRecord.jti, { ...newRecord });
    },
    async revokeFamily(familyId, revokedAt) {
      for (const [jti, row] of rows.entries()) {
        if (row.family_id === familyId) {
          rows.set(jti, { ...row, revoked_at: revokedAt });
        }
      }
    },
  };
}

async function issueCode(now: () => number): Promise<string> {
  const { challenge } = verifierAndChallenge();
  const result = await handleAuthorize(
    config,
    {
      response_type: 'code',
      client_id: 'client-abc',
      redirect_uri: 'https://cb.example/cb',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    },
    now,
  );
  return new URL(result.redirect!).searchParams.get('code')!;
}

async function exchangeCode(
  code: string,
  now: () => number,
  store?: IssuedRefreshTokenStore,
): Promise<TokenSuccess> {
  const { verifier } = verifierAndChallenge();
  const result = await handleToken(
    config,
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://cb.example/cb',
      client_id: 'client-abc',
      client_secret: 'shhh',
      code_verifier: verifier,
    },
    now,
    undefined,
    store,
  );
  assert.equal(result.status, 200, JSON.stringify(result.body));
  return result.body as TokenSuccess;
}

describe('discovery — refresh_token advertised conditionally on refresh_token_supported', () => {
  it('advertises ONLY authorization_code when refresh_token_supported is unset/false', () => {
    const md = buildDiscoveryMetadata({}, { issuer: 'https://x.example' });
    assert.deepEqual(md.grant_types_supported, ['authorization_code']);

    const md2 = buildDiscoveryMetadata(
      { refresh_token_supported: false },
      { issuer: 'https://x.example' },
    );
    assert.deepEqual(md2.grant_types_supported, ['authorization_code']);
  });

  it('advertises BOTH authorization_code AND refresh_token when refresh_token_supported is true', () => {
    const md = buildDiscoveryMetadata(
      { refresh_token_supported: true },
      { issuer: 'https://x.example' },
    );
    assert.deepEqual(md.grant_types_supported, ['authorization_code', 'refresh_token']);
  });
});

describe('access-token TTL conditional on refreshStore presence', () => {
  it('defaults to 24h when no refreshStore is wired (zero-regression for un-migrated MCPs)', async () => {
    const code = await issueCode(() => NOW);
    const body = await exchangeCode(code, () => NOW); // no store
    assert.equal(body.expires_in, TWENTY_FOUR_HOURS);
    assert.equal(body.refresh_token, undefined, 'no refresh_token issued without store');
  });

  it('defaults to 1h when refreshStore is wired (claude.ai will refresh natively)', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const body = await exchangeCode(code, () => NOW, store);
    assert.equal(body.expires_in, ONE_HOUR);
    assert.ok(body.refresh_token, 'refresh_token issued when store wired');
  });

  it('explicit accessTokenTtlSeconds override wins regardless of store presence', async () => {
    const overridden: OAuthServerConfig = { ...config, accessTokenTtlSeconds: 7200 };
    const code = await handleAuthorize(
      overridden,
      {
        response_type: 'code',
        client_id: 'client-abc',
        redirect_uri: 'https://cb.example/cb',
        code_challenge: verifierAndChallenge().challenge,
        code_challenge_method: 'S256',
      },
      () => NOW,
    ).then((r) => new URL(r.redirect!).searchParams.get('code')!);

    const result = await handleToken(
      overridden,
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://cb.example/cb',
        client_id: 'client-abc',
        client_secret: 'shhh',
        code_verifier: verifierAndChallenge().verifier,
      },
      () => NOW,
      undefined,
      mkStore(),
    );
    const body = result.body as TokenSuccess;
    assert.equal(body.expires_in, 7200);
  });
});

describe('refresh_token grant disabled when refreshStore absent (400)', () => {
  it('returns unsupported_grant_type when refresh_token grant is presented but no store wired', async () => {
    const result = await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: 'whatever',
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => NOW,
      // no registry, no refreshStore
    );
    assert.equal(result.status, 400);
    assert.equal((result.body as { error: string }).error, 'unsupported_grant_type');
  });
});

describe('initial code exchange returns refresh_token (signed at refresh-only audience)', () => {
  it('refresh JWT verifies at `${accessAudience}-refresh`, NOT at accessAudience', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const body = await exchangeCode(code, () => NOW, store);

    // Verifies at refresh audience.
    const claims = verify(body.refresh_token!, config.signingSecret, 'test-access-refresh', NOW);
    assert.equal(claims.aud, 'test-access-refresh');
    assert.equal(claims.client_id, 'client-abc');
    assert.equal(typeof claims.jti, 'string');
    assert.equal(typeof claims.family_id, 'string');

    // Cross-audience rejection: same token must NOT verify at accessAudience.
    assert.throws(() => verify(body.refresh_token!, config.signingSecret, 'test-access', NOW));

    // Row persisted; family TTL anchored to family origin.
    assert.equal(store.rows.size, 1);
    const row = store.rows.get(claims.jti as string)!;
    assert.equal(row.family_id, claims.family_id);
    assert.equal(row.exp, NOW + THIRTY_DAYS);
    assert.equal(row.created_at, NOW);
    assert.equal(row.superseded_by_jti, undefined);
    assert.equal(row.revoked_at, undefined);
  });
});

describe('refresh_token grant — happy-path rotation', () => {
  it('issues a new pair, marks predecessor superseded, both rows share family_id', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);
    const initialClaims = verify(
      initial.refresh_token!,
      config.signingSecret,
      'test-access-refresh',
      NOW,
    );

    const T1 = NOW + 100;
    const result = await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T1,
      undefined,
      store,
    );
    assert.equal(result.status, 200);
    const rotated = result.body as TokenSuccess;
    assert.notEqual(rotated.refresh_token, initial.refresh_token);
    assert.notEqual(rotated.access_token, initial.access_token);
    assert.equal(rotated.expires_in, ONE_HOUR);

    const newClaims = verify(
      rotated.refresh_token!,
      config.signingSecret,
      'test-access-refresh',
      T1,
    );
    assert.equal(newClaims.family_id, initialClaims.family_id, 'family preserved across rotation');
    assert.notEqual(newClaims.jti, initialClaims.jti);

    // Predecessor row marked superseded.
    const oldRow = store.rows.get(initialClaims.jti as string)!;
    assert.equal(oldRow.superseded_by_jti, newClaims.jti);

    // Successor row exists, same family, exp slides forward to T1 + 30d
    // (sliding TTL — each rotation extends the chain from now()).
    const newRow = store.rows.get(newClaims.jti as string)!;
    assert.equal(newRow.family_id, oldRow.family_id);
    assert.equal(newRow.created_at, T1);
    assert.equal(newRow.exp, T1 + THIRTY_DAYS, 'exp slides forward on rotation');
  });
});

describe('refresh_token grant — sliding TTL', () => {
  it('rotation at T2 (> T1) yields row2.exp = T2 + 30d, distinct from row1.exp', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);

    // Rotation 1 at T1.
    const T1 = NOW + 1000;
    const rotation1 = (await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T1,
      undefined,
      store,
    )).body as TokenSuccess;

    const claims1 = verify(
      rotation1.refresh_token!,
      config.signingSecret,
      'test-access-refresh',
      T1,
    );
    const row1 = store.rows.get(claims1.jti as string)!;
    assert.equal(row1.exp, T1 + THIRTY_DAYS);

    // Rotation 2 at T2 (1 hour later), well within the active window.
    const T2 = T1 + 3600;
    const rotation2 = (await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: rotation1.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T2,
      undefined,
      store,
    )).body as TokenSuccess;

    const claims2 = verify(
      rotation2.refresh_token!,
      config.signingSecret,
      'test-access-refresh',
      T2,
    );
    const row2 = store.rows.get(claims2.jti as string)!;
    assert.equal(row2.exp, T2 + THIRTY_DAYS, 'row2.exp slides to T2 + 30d');
    assert.notEqual(row2.exp, row1.exp, 'row2.exp is NOT anchored to row1.exp');
  });

  it('actively-used chain spanning > 30d total stays valid: rotate every 5d for 50d', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    let current = await exchangeCode(code, () => NOW, store);

    let lastT = NOW;
    for (let i = 1; i <= 10; i++) {
      const T = NOW + i * 5 * 24 * 60 * 60; // every 5 days
      const result = await handleToken(
        config,
        {
          grant_type: 'refresh_token',
          refresh_token: current.refresh_token!,
          client_id: 'client-abc',
          client_secret: 'shhh',
        },
        () => T,
        undefined,
        store,
      );
      assert.equal(result.status, 200, `rotation ${i} at T+${5 * i}d should succeed`);
      current = result.body as TokenSuccess;
      lastT = T;
    }

    // After 50 days of active use, the final row's exp is the LAST
    // rotation time + 30d — chain is still live, well past the original
    // 30d cliff that v0.3.1 would have imposed.
    const finalClaims = verify(
      current.refresh_token!,
      config.signingSecret,
      'test-access-refresh',
      lastT,
    );
    const finalRow = store.rows.get(finalClaims.jti as string)!;
    assert.equal(finalRow.exp, lastT + THIRTY_DAYS);
    assert.equal(lastT, NOW + 50 * 24 * 60 * 60);
    // Sanity: original-anchor world would have had final exp = NOW + 30d,
    // which is now in the past. We assert we're nowhere near that.
    assert.ok(finalRow.exp > NOW + THIRTY_DAYS, 'chain extended past origin+30d');
  });

  it('idle past the sliding window: rotation at T1, no use until T1 + 30d + 1s → 400 invalid_grant', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);

    const T1 = NOW + 1000;
    const rotation = (await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T1,
      undefined,
      store,
    )).body as TokenSuccess;

    // Idle from T1 through T1 + 30d + 1s — past the sliding window's
    // boundary anchored to the LAST rotation. JWT exp claim is
    // T1 + 30d, so verify rejects.
    const T2 = T1 + THIRTY_DAYS + 1;
    const result = await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: rotation.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T2,
      undefined,
      store,
    );
    assert.equal(result.status, 400);
    assert.equal((result.body as { error: string }).error, 'invalid_grant');
    assert.match(
      (result.body as { error_description: string }).error_description,
      /expired/,
    );
  });
});

describe('refresh_token grant — 60s grace window returns SAME successor pair (byte-identical refresh JWT)', () => {
  it('re-presenting the predecessor inside grace window returns byte-identical refresh JWT, fresh access token', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);

    // Rotation at T1.
    const T1 = NOW + 100;
    const firstRotation = (await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T1,
      undefined,
      store,
    )).body as TokenSuccess;

    // Re-present the OLD refresh token inside the grace window (T1 + 30 < T1 + 60).
    const T2 = T1 + 30;
    const graceRetry = (await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T2,
      undefined,
      store,
    )).body as TokenSuccess;

    // Refresh JWT MUST be byte-identical to the first rotation's response.
    assert.equal(
      graceRetry.refresh_token,
      firstRotation.refresh_token,
      'byte-identical successor refresh JWT across grace-window retries',
    );

    // Access token MUST be a fresh sign (different `iat`).
    assert.notEqual(graceRetry.access_token, firstRotation.access_token);

    // Re-present a THIRD time, still in grace.
    const T3 = T1 + 50;
    const graceRetry2 = (await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T3,
      undefined,
      store,
    )).body as TokenSuccess;
    assert.equal(graceRetry2.refresh_token, firstRotation.refresh_token);
  });
});

describe('refresh_token grant — reuse outside grace window revokes the family', () => {
  it('predecessor presented after 60s grace returns 400 AND revokes family — subsequent refresh on successor also fails', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);

    const T1 = NOW + 100;
    const rotated = (await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T1,
      undefined,
      store,
    )).body as TokenSuccess;

    // T1 + 61 > T1 + 60 — outside grace window.
    const T2 = T1 + 61;
    const reuseAttempt = await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T2,
      undefined,
      store,
    );
    assert.equal(reuseAttempt.status, 400);
    assert.equal((reuseAttempt.body as { error: string }).error, 'invalid_grant');

    // Family is revoked: every row sharing family_id has revoked_at set.
    for (const row of store.rows.values()) {
      assert.equal(row.revoked_at, T2, 'every family member revoked');
    }

    // Subsequent refresh on the SUCCESSOR (the legitimate post-rotation token) also fails.
    const T3 = T2 + 1;
    const successorAttempt = await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: rotated.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T3,
      undefined,
      store,
    );
    assert.equal(successorAttempt.status, 400);
    assert.equal((successorAttempt.body as { error: string }).error, 'invalid_grant');
    assert.match(
      (successorAttempt.body as { error_description: string }).error_description,
      /revoked/,
    );
  });
});

describe('refresh_token grant — rejections', () => {
  it('rejects refresh tokens past family TTL (30d) with 400 invalid_grant', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);

    // 30d + 1s after issuance — refresh JWT's exp claim has passed.
    const T1 = NOW + THIRTY_DAYS + 1;
    const result = await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => T1,
      undefined,
      store,
    );
    assert.equal(result.status, 400);
    assert.equal((result.body as { error: string }).error, 'invalid_grant');
  });

  it('rejects wrong client_id on refresh with 400 invalid_grant', async () => {
    const store = mkStore();
    // Need a registry so we can authenticate the wrong-client_id presenter.
    const dcr = {
      client_id: 'dcr-wrong',
      client_secret: 'dcr-secret',
      client_id_issued_at: NOW,
      metadata: { token_endpoint_auth_method: 'client_secret_post' as const },
    };
    const registry = {
      async get(id: string) {
        return id === dcr.client_id ? dcr : null;
      },
      async put() {
        // unused
      },
    };

    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);

    // Authenticate as a DIFFERENT client (passes auth) but present the
    // refresh token minted for the static client.
    const result = await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.refresh_token!,
        client_id: 'dcr-wrong',
        client_secret: 'dcr-secret',
      },
      () => NOW + 10,
      registry,
      store,
    );
    assert.equal(result.status, 400);
    assert.equal((result.body as { error: string }).error, 'invalid_grant');
    assert.match(
      (result.body as { error_description: string }).error_description,
      /client_id mismatch/,
    );
  });

  it('rejects an access token presented as a refresh token (cross-audience attack)', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);

    const result = await handleToken(
      config,
      {
        grant_type: 'refresh_token',
        refresh_token: initial.access_token, // cross-audience: access token at refresh slot
        client_id: 'client-abc',
        client_secret: 'shhh',
      },
      () => NOW + 10,
      undefined,
      store,
    );
    assert.equal(result.status, 400);
    assert.equal((result.body as { error: string }).error, 'invalid_grant');
    assert.match(
      (result.body as { error_description: string }).error_description,
      /wrong_audience/,
    );
  });

  it('rejects a refresh token presented as an authorization code (vice-versa cross-audience)', async () => {
    const store = mkStore();
    const code = await issueCode(() => NOW);
    const initial = await exchangeCode(code, () => NOW, store);

    // authorization_code grant verifies at codeAudience; the refresh
    // JWT is at `${accessAudience}-refresh` — verify must fail.
    const result = await handleToken(
      config,
      {
        grant_type: 'authorization_code',
        code: initial.refresh_token!,
        redirect_uri: 'https://cb.example/cb',
        client_id: 'client-abc',
        client_secret: 'shhh',
        code_verifier: verifierAndChallenge().verifier,
      },
      () => NOW + 10,
      undefined,
      store,
    );
    assert.equal(result.status, 400);
    assert.equal((result.body as { error: string }).error, 'invalid_grant');
    assert.match(
      (result.body as { error_description: string }).error_description,
      /wrong_audience/,
    );
  });
});
