// purpose: Versioned AWS Secrets Manager client with optimistic
// concurrency. Powers UserPreIssuedAuth's refresh path — reads the
// current secret + its VersionId, and on write refuses to overwrite a
// version newer than what was read (throws ConcurrentModificationError).
//
// Secrets Manager has no native conditional PutSecretValue, so `put`
// implements CAS via a two-phase dance: write the new value with
// `VersionStages: ['AWSPENDING']`, then promote it to `AWSCURRENT` via
// UpdateSecretVersionStage with `RemoveFromVersionId: expectedVersionId,
// MoveToVersionId: newVersionId`. If the AWSCURRENT stage isn't
// currently on expectedVersionId (another writer won the race), AWS
// rejects the Update with InvalidRequestException, which we translate
// to ConcurrentModificationError. On failure we best-effort drop the
// orphan AWSPENDING stage so secret history stays tidy.
//
// Kept separate from SecretsManagerRefreshTokenStore on purpose — that
// store is tied to the OAuth2-delegation pattern (UserOAuth2Auth,
// Withings/Strava-style); this client is tied to the pre-issued-token
// pattern (UserPreIssuedAuth, Peloton-style). The two must not cross-
// import.

import { randomUUID } from 'node:crypto';
import {
  GetSecretValueCommand,
  InvalidParameterException,
  InvalidRequestException,
  PutSecretValueCommand,
  ResourceNotFoundException,
  SecretsManagerClient,
  UpdateSecretVersionStageCommand,
  type SecretsManagerClientConfig,
} from '@aws-sdk/client-secrets-manager';

export interface VersionedSecret {
  value: string;
  versionId: string;
}

// Thrown by VersionedSecretsClient.put when the current AWSCURRENT
// version no longer matches the expectedVersionId passed by the caller
// — i.e. another writer rotated the secret in between the caller's
// get() and put(). UserPreIssuedAuth handles this by re-reading the
// secret and using the fresh value rather than triggering another
// refresh.
export class ConcurrentModificationError extends Error {
  readonly secretArn: string;
  readonly expectedVersionId: string;
  constructor(secretArn: string, expectedVersionId: string) {
    super(
      `concurrent modification for ${secretArn}: stale expectedVersionId=${expectedVersionId}`,
    );
    this.name = 'ConcurrentModificationError';
    this.secretArn = secretArn;
    this.expectedVersionId = expectedVersionId;
  }
}

export interface VersionedSecretsClient {
  // Returns null when the secret does not exist. Throws on other errors.
  get(secretArn: string): Promise<VersionedSecret | null>;
  // Atomic compare-and-swap write. Succeeds only if the AWSCURRENT
  // stage is currently on expectedVersionId. Returns the new VersionId
  // on success; throws ConcurrentModificationError on stale precondition.
  put(secretArn: string, value: string, expectedVersionId: string): Promise<string>;
}

export function createVersionedSecretsClient(
  config: SecretsManagerClientConfig | { region: string } | SecretsManagerClient,
): VersionedSecretsClient {
  const sm =
    config instanceof SecretsManagerClient ? config : new SecretsManagerClient(config);

  return {
    async get(secretArn) {
      try {
        const r = await sm.send(new GetSecretValueCommand({ SecretId: secretArn }));
        if (r.SecretString == null || r.VersionId == null) return null;
        return { value: r.SecretString, versionId: r.VersionId };
      } catch (err) {
        if (err instanceof ResourceNotFoundException) return null;
        throw err;
      }
    },

    async put(secretArn, value, expectedVersionId) {
      // Phase 1: write the new value under AWSPENDING. ClientRequestToken
      // must be unique — a fresh UUID per call prevents Secrets Manager
      // from treating this as a replay of a prior request.
      const clientRequestToken = randomUUID();
      const putRes = await sm.send(
        new PutSecretValueCommand({
          SecretId: secretArn,
          SecretString: value,
          VersionStages: ['AWSPENDING'],
          ClientRequestToken: clientRequestToken,
        }),
      );
      const newVersionId = putRes.VersionId;
      if (!newVersionId) {
        throw new Error('PutSecretValue returned no VersionId');
      }

      // Phase 2: promote AWSPENDING → AWSCURRENT atomically, only if
      // AWSCURRENT is still on expectedVersionId. AWS rejects the Update
      // with InvalidRequestException (or InvalidParameterException in
      // some shapes) if the stage isn't on expectedVersionId — that's
      // our CAS-failed signal.
      try {
        await sm.send(
          new UpdateSecretVersionStageCommand({
            SecretId: secretArn,
            VersionStage: 'AWSCURRENT',
            MoveToVersionId: newVersionId,
            RemoveFromVersionId: expectedVersionId,
          }),
        );
        return newVersionId;
      } catch (err) {
        if (
          err instanceof InvalidRequestException ||
          err instanceof InvalidParameterException
        ) {
          // Best-effort: strip AWSPENDING from the orphan version so it
          // doesn't clutter the secret's version history. Failure here
          // is not worth surfacing — the real signal is the CAS failure.
          try {
            await sm.send(
              new UpdateSecretVersionStageCommand({
                SecretId: secretArn,
                VersionStage: 'AWSPENDING',
                RemoveFromVersionId: newVersionId,
              }),
            );
          } catch {
            // swallow — cleanup is best-effort
          }
          throw new ConcurrentModificationError(secretArn, expectedVersionId);
        }
        throw err;
      }
    },
  };
}
