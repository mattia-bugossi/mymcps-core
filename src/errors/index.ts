export {
  AuthError,
  NotFoundError,
  RateLimitError,
  UpstreamAuthRevoked,
  UpstreamError,
  ValidationError,
} from './types.js';
export {
  classifyError,
  toJsonRpcError,
  type ErrorClassification,
  type JsonRpcErrorPayload,
  type ToJsonRpcOptions,
} from './mapping.js';
