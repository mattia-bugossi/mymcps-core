// purpose: Transport-agnostic error classes that core and providers throw.
// errors/mapping.ts turns these into JSON-RPC / HTTP responses.

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class AuthError extends Error {
  constructor(message = 'Authentication required') {
    super(message);
    this.name = 'AuthError';
  }
}

export class RateLimitError extends Error {
  readonly retryAfterSeconds?: number;
  constructor(message = 'Rate limit exceeded', retryAfterSeconds?: number) {
    super(message);
    this.name = 'RateLimitError';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class UpstreamError extends Error {
  readonly provider: string;
  readonly upstreamStatus?: number;
  constructor(provider: string, message: string, upstreamStatus?: number) {
    super(message);
    this.name = 'UpstreamError';
    this.provider = provider;
    this.upstreamStatus = upstreamStatus;
  }
}

// Thrown by UserPreIssuedAuth when the upstream auth domain rejects a
// refresh call with a 4xx — the refresh token is no longer valid and
// the user must re-authorize. Non-retryable by design: callers should
// surface it as an auth error all the way to the MCP client rather
// than catching and retrying.
export class UpstreamAuthRevoked extends Error {
  readonly provider: string;
  readonly upstreamStatus?: number;
  constructor(provider: string, message: string, upstreamStatus?: number) {
    super(message);
    this.name = 'UpstreamAuthRevoked';
    this.provider = provider;
    this.upstreamStatus = upstreamStatus;
  }
}

// Thrown by UserPreIssuedAuth when the seeded Secrets Manager value's
// `expires_at` is at-or-before now at load time — meaning the very
// first call would force a refresh and risk burning the refresh token
// if another process (e.g., the SPA still running in another tab) has
// already rotated it. Sibling to UpstreamAuthRevoked: BOTH are
// upstream-auth-domain errors, but the remediation differs — Revoked
// means "user must re-authorize"; SeedError means "operator must
// re-seed the secret with the actual expiry from the source." Distinct
// telemetry buckets, distinct runbooks.
export class UpstreamAuthSeedError extends Error {
  readonly provider: string;
  constructor(provider: string, message: string) {
    super(message);
    this.name = 'UpstreamAuthSeedError';
    this.provider = provider;
  }
}

export class NotFoundError extends Error {
  constructor(message = 'Not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}
