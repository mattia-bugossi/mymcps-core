// purpose: Persistence contract for refresh tokens that the MCP OAuth
// shell ISSUES to clients (claude.ai etc.) — distinct from
// `RefreshTokenStore` in `src/auth/`, which holds refresh tokens we
// RECEIVE from upstream providers (Withings, Strava, …) under the
// OAuth2-delegation pattern. Different lives, different schemas,
// different security properties — the `Issued` prefix makes confusion
// hard.
//
// Storage backend is consumer-chosen (DynamoDB in prod, in-memory for
// tests) — same injection pattern as `ClientRegistry`. Implementations
// MUST commit `rotate` atomically (DynamoDB `TransactWriteItems` for
// prod). See OAuth 2.1 §4.14 for the reuse-detection model the
// `revokeFamily` operation supports.

export interface IssuedRefreshTokenRecord {
  // The JWT `jti` claim. Primary key.
  jti: string;
  // UUID assigned at the initial code exchange and preserved through
  // every rotation. Used for reuse-detection-driven family revocation
  // (OAuth 2.1 §4.14).
  family_id: string;
  // Client that minted this family (static or DCR). Refresh-token grant
  // verifies the presented client_id matches.
  client_id: string;
  // Single-value scope claim, copied verbatim from the originating
  // authorization code.
  scope: string;
  // Epoch seconds when this row (this rotation) was issued. Used to
  // measure the 60-second grace window when a superseded token is
  // re-presented.
  created_at: number;
  // Epoch seconds when this row expires. Anchored to family origin
  // (`family_origin_iat + familyTtl`) — rotations do NOT extend it.
  // Implementations should set DDB TTL on this attribute for automatic
  // cleanup. Matches the JWT's `exp` claim.
  exp: number;
  // The successor's jti, set on rotation. Presence of this field plus
  // a re-presentation of the row's own jti is the trigger for either
  // the 60s grace-window idempotent re-issue or family revocation.
  superseded_by_jti?: string;
  // Epoch seconds when reuse detection (or any other revocation path)
  // killed this row. Once set, all refresh attempts on this jti fail
  // with 400 invalid_grant.
  revoked_at?: number;
}

export interface IssuedRefreshTokenStore {
  // Returns null when no row with the given jti exists. Implementations
  // SHOULD treat TTL-expired rows as absent.
  get(jti: string): Promise<IssuedRefreshTokenRecord | null>;

  // Persists a brand-new row at initial code exchange (no predecessor).
  // For rotation, use `rotate` instead — `put` is single-write and does
  // not touch any other row.
  put(record: IssuedRefreshTokenRecord): Promise<void>;

  // Atomic rotation: sets `superseded_by_jti = newRecord.jti` on the
  // row identified by `predecessorJti` AND inserts `newRecord`. MUST
  // commit both updates atomically — otherwise a leaked predecessor
  // could mint a parallel chain in the failure window. DynamoDB
  // implementations use `TransactWriteItems`; in-memory test fakes do
  // both ops in one synchronous block.
  rotate(predecessorJti: string, newRecord: IssuedRefreshTokenRecord): Promise<void>;

  // Sets `revoked_at = revokedAt` on every row sharing `family_id`.
  // Called by the refresh-token grant when reuse is detected on a
  // superseded jti outside the grace window. Implementations typically
  // require a GSI on `family_id`.
  revokeFamily(familyId: string, revokedAt: number): Promise<void>;
}
