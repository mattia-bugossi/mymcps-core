// purpose: Map error classes to JSON-RPC error payloads + HTTP status codes.
// Replaces Oura's string-sniffing errorHandler with explicit class dispatch.

import {
  AuthError,
  NotFoundError,
  RateLimitError,
  UpstreamAuthRevoked,
  UpstreamAuthSeedError,
  UpstreamError,
  ValidationError,
} from './types.js';

export interface JsonRpcErrorPayload {
  jsonrpc: '2.0';
  id: string | number | null;
  error: {
    code: number;
    message: string;
    data?: { details?: string };
  };
}

export interface ErrorClassification {
  statusCode: number;
  jsonRpcCode: number;
  message: string;
}

export interface ToJsonRpcOptions {
  id?: string | number | null;
  // Hide raw message text from responses (production default). Falls back
  // to the high-level `message` per classification bucket.
  sanitizeDetails?: boolean;
}

export function classifyError(err: unknown): ErrorClassification {
  if (err instanceof ValidationError) {
    return { statusCode: 400, jsonRpcCode: -32602, message: 'Invalid parameters' };
  }
  if (err instanceof UpstreamAuthRevoked) {
    return {
      statusCode: 401,
      jsonRpcCode: -32000,
      message: `${err.provider} access revoked — re-authorization required`,
    };
  }
  if (err instanceof UpstreamAuthSeedError) {
    // Operator-config error, NOT a user-action-required auth error.
    // The user did nothing wrong; the seeded secret is malformed. 500
    // surfaces this as a server problem so the user isn't told to
    // re-authorize when the fix is on the operator's side.
    return {
      statusCode: 500,
      jsonRpcCode: -32603,
      message: `${err.provider} token seed misconfigured — operator must re-seed`,
    };
  }
  if (err instanceof AuthError) {
    return { statusCode: 401, jsonRpcCode: -32000, message: 'Authentication required' };
  }
  if (err instanceof RateLimitError) {
    return { statusCode: 429, jsonRpcCode: -32001, message: 'Rate limit exceeded' };
  }
  if (err instanceof UpstreamError) {
    return { statusCode: 502, jsonRpcCode: -32002, message: `${err.provider} API error` };
  }
  if (err instanceof NotFoundError) {
    return { statusCode: 404, jsonRpcCode: -32601, message: 'Not found' };
  }
  return { statusCode: 500, jsonRpcCode: -32603, message: 'Internal server error' };
}

export function toJsonRpcError(err: unknown, options: ToJsonRpcOptions = {}): JsonRpcErrorPayload {
  const { id = null, sanitizeDetails = false } = options;
  const { jsonRpcCode, message } = classifyError(err);
  const raw = err instanceof Error ? err.message : String(err);
  const details = sanitizeDetails ? message : raw;
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: jsonRpcCode,
      message,
      data: { details },
    },
  };
}
