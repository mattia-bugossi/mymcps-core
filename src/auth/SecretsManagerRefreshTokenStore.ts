// purpose: AWS Secrets Manager backed RefreshTokenStore. One secret per user
// at '<prefix>/<userId>' (prefix defaults to '/mymcps/<provider>/refresh-tokens').
// Value is the JSON-serialised RefreshTokenRecord.
//
// Storing refresh tokens in Secrets Manager (rather than Dynamo) because they
// are long-lived, low-cardinality, and Secrets Manager gives free KMS-at-rest
// encryption + CloudTrail auditing out of the box.

import {
  CreateSecretCommand,
  DeleteSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  ResourceNotFoundException,
  SecretsManagerClient,
  type SecretsManagerClientConfig,
} from '@aws-sdk/client-secrets-manager';
import type { RefreshTokenRecord, RefreshTokenStore } from './RefreshTokenStore.js';

export interface TokenSecretsClient {
  // Returns null on ResourceNotFoundException. Throws on other errors.
  getString(secretId: string): Promise<string | null>;
  // Creates the secret if missing, otherwise puts a new version.
  putString(secretId: string, value: string): Promise<void>;
  // No-op if the secret doesn't exist.
  deleteSecret(secretId: string): Promise<void>;
}

export function createTokenSecretsClient(
  config: SecretsManagerClientConfig | { region: string },
): TokenSecretsClient {
  const sm = new SecretsManagerClient(config);
  return {
    async getString(secretId) {
      try {
        const r = await sm.send(new GetSecretValueCommand({ SecretId: secretId }));
        return r.SecretString ?? null;
      } catch (err) {
        if (err instanceof ResourceNotFoundException) return null;
        throw err;
      }
    },
    async putString(secretId, value) {
      try {
        await sm.send(new PutSecretValueCommand({ SecretId: secretId, SecretString: value }));
      } catch (err) {
        if (err instanceof ResourceNotFoundException) {
          await sm.send(new CreateSecretCommand({ Name: secretId, SecretString: value }));
          return;
        }
        throw err;
      }
    },
    async deleteSecret(secretId) {
      try {
        await sm.send(
          new DeleteSecretCommand({ SecretId: secretId, ForceDeleteWithoutRecovery: true }),
        );
      } catch (err) {
        if (err instanceof ResourceNotFoundException) return;
        throw err;
      }
    },
  };
}

export interface SecretsManagerRefreshTokenStoreConfig {
  client: TokenSecretsClient;
  // Prefix for per-user secret IDs. Example: '/mymcps/withings/refresh-tokens'.
  secretPrefix: string;
}

export function createSecretsManagerRefreshTokenStore(
  config: SecretsManagerRefreshTokenStoreConfig,
): RefreshTokenStore {
  const secretId = (userId: string) => `${config.secretPrefix}/${userId}`;

  return {
    async get(userId) {
      const raw = await config.client.getString(secretId(userId));
      if (!raw) return null;
      return JSON.parse(raw) as RefreshTokenRecord;
    },
    async put(record) {
      await config.client.putString(secretId(record.userId), JSON.stringify(record));
    },
    async delete(userId) {
      await config.client.deleteSecret(secretId(userId));
    },
  };
}
