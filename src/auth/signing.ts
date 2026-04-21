// purpose: HMAC-SHA256 request signing for providers that require a signed
// action + short-lived nonce (Withings). Core primitive so any future provider
// following the same pattern can reuse it without copy-paste.
//
// Withings signature algorithm:
//   sig = hex(HMAC-SHA256(client_secret, `${action},${client_id},${extra}`))
// where `extra` is the nonce for normal endpoints, or the unix timestamp for
// the getnonce call itself. Params are comma-joined — not sorted alphabetically
// and not urlencoded.

import { createHmac } from 'node:crypto';
import { UpstreamError } from '../errors/types.js';

export const DEFAULT_SIGNATURE_ENDPOINT = 'https://wbsapi.withings.net/v2/signature';

export interface WithingsSignerConfig {
  // Endpoint for POST action=getnonce. Defaults to the prod Withings endpoint.
  signatureEndpoint?: string;
  // Injectable fetch so tests don't hit the network.
  fetchFn?: typeof fetch;
  // Injectable clock (seconds since epoch) for deterministic nonce timestamps.
  now?: () => number;
}

export interface SignParams {
  action: string;
  client_id: string;
  nonce: string;
}

export interface WithingsSigner {
  sign(params: SignParams, clientSecret: string): string;
  getNonce(clientId: string, clientSecret: string): Promise<string>;
}

interface WithingsEnvelope<T> {
  status: number;
  body?: T;
  error?: string;
}

function hmacHex(key: string, data: string): string {
  return createHmac('sha256', key).update(data).digest('hex');
}

export function makeWithingsSigner(config: WithingsSignerConfig = {}): WithingsSigner {
  const endpoint = config.signatureEndpoint ?? DEFAULT_SIGNATURE_ENDPOINT;
  const fetchFn = config.fetchFn ?? fetch;
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));

  async function getNonce(clientId: string, clientSecret: string): Promise<string> {
    const timestamp = String(now());
    const signature = hmacHex(clientSecret, `getnonce,${clientId},${timestamp}`);
    const form = new URLSearchParams({
      action: 'getnonce',
      client_id: clientId,
      timestamp,
      signature,
    });
    const res = await fetchFn(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    if (!res.ok) {
      throw new UpstreamError('withings', `getnonce http ${res.status}`, res.status);
    }
    const env = (await res.json()) as WithingsEnvelope<{ nonce: string }>;
    if (env.status !== 0 || !env.body?.nonce) {
      throw new UpstreamError(
        'withings',
        `getnonce failed: status=${env.status} error=${env.error ?? 'n/a'}`,
      );
    }
    return env.body.nonce;
  }

  function sign(params: SignParams, clientSecret: string): string {
    return hmacHex(clientSecret, `${params.action},${params.client_id},${params.nonce}`);
  }

  return { sign, getNonce };
}
