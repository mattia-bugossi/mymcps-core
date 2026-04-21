// purpose: ProviderAuth impl that returns the same server-side PAT for any
// userId. Fits single-user providers (Oura PAT) where the upstream credential
// is global, not per-MCP-client. The PAT is pulled from Secrets Manager once
// and memoised via the SecretsClient helper.

import { fetchSecret, type SecretsClient } from '../aws/secrets.js';
import { AuthError } from '../errors/types.js';
import type { ProviderAuth } from './ProviderAuth.js';

export interface ServerSidePatAuthConfig {
  client: SecretsClient;
  secretArn: string;
}

export function createServerSidePatAuth(config: ServerSidePatAuthConfig): ProviderAuth {
  return {
    async getAccessToken(): Promise<string> {
      try {
        return await fetchSecret(config.client, config.secretArn);
      } catch (err) {
        throw new AuthError(
          `failed to load server-side PAT: ${(err as Error)?.message ?? String(err)}`,
        );
      }
    },
  };
}
