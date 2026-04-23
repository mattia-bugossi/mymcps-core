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

export class NotFoundError extends Error {
  constructor(message = 'Not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}
