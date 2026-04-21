export {
  AuthError,
  NotFoundError,
  RateLimitError,
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
