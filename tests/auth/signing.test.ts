import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { makeWithingsSigner, DEFAULT_SIGNATURE_ENDPOINT } from '../../src/auth/signing.js';
import { UpstreamError } from '../../src/errors/types.js';

const SECRET = 'client-secret-xyz';

function expectedHex(data: string): string {
  return createHmac('sha256', SECRET).update(data).digest('hex');
}

describe('WithingsSigner.sign', () => {
  it('matches HMAC-SHA256 hex over action,client_id,nonce', () => {
    const signer = makeWithingsSigner();
    const sig = signer.sign(
      { action: 'requesttoken', client_id: 'cid', nonce: 'nnn' },
      SECRET,
    );
    assert.equal(sig, expectedHex('requesttoken,cid,nnn'));
  });

  it('is deterministic for identical inputs', () => {
    const s1 = makeWithingsSigner();
    const s2 = makeWithingsSigner();
    const a = s1.sign({ action: 'measure', client_id: 'c', nonce: 'n' }, SECRET);
    const b = s2.sign({ action: 'measure', client_id: 'c', nonce: 'n' }, SECRET);
    assert.equal(a, b);
  });
});

describe('WithingsSigner.getNonce', () => {
  it('posts form-urlencoded to the default endpoint with a timestamp-signed body', async () => {
    let captured: { url: string; init: RequestInit | undefined } = { url: '', init: undefined };
    const fakeFetch: typeof fetch = async (input, init) => {
      captured = { url: input as string, init };
      return new Response(JSON.stringify({ status: 0, body: { nonce: 'abc123' } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const signer = makeWithingsSigner({ fetchFn: fakeFetch, now: () => 1_700_000_000 });
    const nonce = await signer.getNonce('cid', SECRET);
    assert.equal(nonce, 'abc123');
    assert.equal(captured.url, DEFAULT_SIGNATURE_ENDPOINT);
    assert.equal(captured.init?.method, 'POST');
    const body = new URLSearchParams(captured.init?.body as string);
    assert.equal(body.get('action'), 'getnonce');
    assert.equal(body.get('client_id'), 'cid');
    assert.equal(body.get('timestamp'), '1700000000');
    assert.equal(body.get('signature'), expectedHex('getnonce,cid,1700000000'));
  });

  it('throws UpstreamError on non-zero Withings status', async () => {
    const fakeFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ status: 503, error: 'invalid signature' }), { status: 200 });
    const signer = makeWithingsSigner({ fetchFn: fakeFetch, now: () => 1 });
    await assert.rejects(
      () => signer.getNonce('cid', SECRET),
      (err) => err instanceof UpstreamError && /invalid signature/.test((err as Error).message),
    );
  });

  it('throws UpstreamError on transport HTTP failure', async () => {
    const fakeFetch: typeof fetch = async () =>
      new Response('gateway boom', { status: 502 });
    const signer = makeWithingsSigner({ fetchFn: fakeFetch, now: () => 1 });
    await assert.rejects(
      () => signer.getNonce('cid', SECRET),
      (err) => err instanceof UpstreamError && (err as UpstreamError).upstreamStatus === 502,
    );
  });

  it('honours a custom signatureEndpoint', async () => {
    let seenUrl = '';
    const fakeFetch: typeof fetch = async (url) => {
      seenUrl = url as string;
      return new Response(JSON.stringify({ status: 0, body: { nonce: 'x' } }), { status: 200 });
    };
    const signer = makeWithingsSigner({
      fetchFn: fakeFetch,
      now: () => 1,
      signatureEndpoint: 'https://example/sig',
    });
    await signer.getNonce('cid', SECRET);
    assert.equal(seenUrl, 'https://example/sig');
  });
});
