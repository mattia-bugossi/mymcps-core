import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuthError,
  NotFoundError,
  RateLimitError,
  UpstreamError,
  ValidationError,
  classifyError,
  toJsonRpcError,
} from '../../src/errors/index.js';

describe('classifyError', () => {
  it('maps ValidationError to 400 / -32602', () => {
    assert.deepEqual(classifyError(new ValidationError('bad')), {
      statusCode: 400,
      jsonRpcCode: -32602,
      message: 'Invalid parameters',
    });
  });

  it('maps AuthError to 401 / -32000', () => {
    assert.equal(classifyError(new AuthError()).statusCode, 401);
    assert.equal(classifyError(new AuthError()).jsonRpcCode, -32000);
  });

  it('maps RateLimitError to 429 / -32001', () => {
    assert.equal(classifyError(new RateLimitError()).statusCode, 429);
  });

  it('maps UpstreamError to 502 with provider-aware message', () => {
    const c = classifyError(new UpstreamError('withings', 'boom', 500));
    assert.equal(c.statusCode, 502);
    assert.equal(c.message, 'withings API error');
  });

  it('maps NotFoundError to 404', () => {
    assert.equal(classifyError(new NotFoundError()).statusCode, 404);
  });

  it('maps unknown errors to 500 / -32603', () => {
    assert.equal(classifyError(new Error('??')).statusCode, 500);
    assert.equal(classifyError('string thrown').statusCode, 500);
  });
});

describe('toJsonRpcError', () => {
  it('surfaces raw details by default', () => {
    const payload = toJsonRpcError(new ValidationError('missing start_date'), { id: 7 });
    assert.deepEqual(payload, {
      jsonrpc: '2.0',
      id: 7,
      error: {
        code: -32602,
        message: 'Invalid parameters',
        data: { details: 'missing start_date' },
      },
    });
  });

  it('replaces details with classification message when sanitized', () => {
    const payload = toJsonRpcError(new Error('/absolute/path leaked'), { sanitizeDetails: true });
    assert.equal(payload.error.data?.details, 'Internal server error');
    assert.equal(payload.id, null);
  });
});
