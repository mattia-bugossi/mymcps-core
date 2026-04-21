// purpose: API Gateway HTTP API v2 request authorizer factory — allows a
// configurable set of public paths (OAuth endpoints, /healthz), otherwise
// accepts a static bearer token OR a JWT signed with the configured secret
// at the expected access audience.

import { timingSafeEqual } from 'node:crypto';
import type {
  APIGatewayRequestAuthorizerEventV2,
  APIGatewaySimpleAuthorizerResult,
} from 'aws-lambda';
import { verify } from './jwt.js';

export interface AuthorizerLogger {
  warn(message: string, meta?: Record<string, unknown>): void;
}

export interface AuthorizerConfig {
  // Access token audience ('oura-mcp', 'withings-mcp', …).
  accessAudience: string;
  // Paths that bypass auth — typically /.well-known/oauth-authorization-server,
  // /oauth/authorize, /oauth/token, /healthz, and any provider OAuth callback.
  publicPaths: Iterable<string>;
  // Resolves the static bearer token (single-client fallback). Throw to deny.
  loadStaticToken: () => Promise<string>;
  // Resolves the JWT-verify secret; return null to disable JWT verification.
  loadSigningSecret: () => Promise<string | null>;
  logger?: AuthorizerLogger;
}

const defaultLogger: AuthorizerLogger = {
  warn: (msg, meta) => console.warn(`[mymcps-core/authorizer] ${msg}`, meta ?? {}),
};

function extractBearer(event: APIGatewayRequestAuthorizerEventV2): string | null {
  const headers = event.headers ?? {};
  const raw = headers.authorization ?? headers.Authorization;
  if (!raw || typeof raw !== 'string') return null;
  const [scheme, token] = raw.split(' ');
  if (scheme !== 'Bearer' || !token) return null;
  return token;
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function makeAuthorizer(config: AuthorizerConfig) {
  const publicPaths = new Set<string>(config.publicPaths);
  const log = config.logger ?? defaultLogger;

  return async (
    event: APIGatewayRequestAuthorizerEventV2,
  ): Promise<APIGatewaySimpleAuthorizerResult> => {
    if (publicPaths.has(event.rawPath ?? '')) {
      return { isAuthorized: true };
    }

    const presented = extractBearer(event);
    if (!presented) return { isAuthorized: false };

    let staticToken: string;
    try {
      staticToken = await config.loadStaticToken();
    } catch (err) {
      log.warn('static token fetch failed — denying', {
        path: event.rawPath,
        reason: (err as Error)?.message ?? String(err),
      });
      return { isAuthorized: false };
    }

    if (constantTimeEqual(presented, staticToken)) {
      return { isAuthorized: true };
    }

    const signing = await config.loadSigningSecret();
    if (signing) {
      try {
        verify(presented, signing, config.accessAudience);
        return { isAuthorized: true };
      } catch (err) {
        log.warn('JWT verify failed', {
          path: event.rawPath,
          reason: (err as Error)?.message ?? String(err),
        });
      }
    }

    return { isAuthorized: false };
  };
}
