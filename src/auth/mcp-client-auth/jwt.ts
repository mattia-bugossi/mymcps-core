// purpose: zero-dep HS256 JWT sign/verify for OAuth authorization codes and access tokens.

import { createHmac, timingSafeEqual } from 'node:crypto';

export interface JwtClaims {
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  [key: string]: unknown;
}

function b64urlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(str: string): Buffer {
  const pad = str.length % 4 === 0 ? 0 : 4 - (str.length % 4);
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad);
  return Buffer.from(b64, 'base64');
}

export function sign(claims: JwtClaims, secret: string): string {
  const header = b64urlEncode(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = b64urlEncode(Buffer.from(JSON.stringify(claims)));
  const data = `${header}.${payload}`;
  const sig = createHmac('sha256', secret).update(data).digest();
  return `${data}.${b64urlEncode(sig)}`;
}

export function verify(
  token: string,
  secret: string,
  expectedAud: string,
  now: number = Math.floor(Date.now() / 1000),
): JwtClaims {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed_token');
  const [header, payload, signature] = parts;

  const data = `${header}.${payload}`;
  const expected = createHmac('sha256', secret).update(data).digest();
  const got = b64urlDecode(signature);
  if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
    throw new Error('invalid_signature');
  }

  let claims: JwtClaims;
  try {
    claims = JSON.parse(b64urlDecode(payload).toString('utf8')) as JwtClaims;
  } catch {
    throw new Error('malformed_payload');
  }

  if (typeof claims.exp !== 'number' || claims.exp <= now) throw new Error('expired');
  if (claims.aud !== expectedAud) throw new Error('wrong_audience');
  return claims;
}
