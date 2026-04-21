// purpose: AWS Secrets Manager fetch helper with per-ARN in-process memoisation.

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

export interface SecretsClient {
  getSecretString(arn: string): Promise<string>;
}

export function createSecretsClient(region: string): SecretsClient {
  const sm = new SecretsManagerClient({ region });
  return {
    async getSecretString(arn: string): Promise<string> {
      const result = await sm.send(new GetSecretValueCommand({ SecretId: arn }));
      if (!result.SecretString) {
        throw new Error(`Secret ${arn} has no SecretString payload`);
      }
      return result.SecretString;
    },
  };
}

// Memoise by ARN so a second caller during the same warm Lambda invocation
// resolves with the same Promise reference — no duplicate Secrets Manager
// calls. On reject, the entry is evicted so the next caller can retry.
const cache = new Map<string, Promise<string>>();

export async function fetchSecret(client: SecretsClient, arn: string): Promise<string> {
  const existing = cache.get(arn);
  if (existing) return existing;
  const promise = client.getSecretString(arn);
  cache.set(arn, promise);
  try {
    return await promise;
  } catch (err) {
    cache.delete(arn);
    throw err;
  }
}

export function clearSecretsCacheForTests(): void {
  cache.clear();
}
