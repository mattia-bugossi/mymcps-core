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

export class NotFoundError extends Error {
  constructor(message = 'Not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}
