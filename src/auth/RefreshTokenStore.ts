// purpose: Per-user refresh-token persistence contract. UserOAuth2Auth calls
// get() before a refresh and put() *synchronously* after a successful refresh,
// before returning the new access token, so a crash between the two never
// loses the new refresh token.

export interface RefreshTokenRecord {
  // Stable MCP-side user id (the 'sub' claim on the access token).
  userId: string;
  // Opaque refresh token from the provider.
  refreshToken: string;
  // Most-recent access token + its absolute expiry (epoch seconds). Optional
  // so put()-before-first-refresh (e.g. the callback-exchange write) can omit.
  accessToken?: string;
  accessTokenExpiresAt?: number;
  // Space- or comma-joined scope string, as returned by the provider.
  scope?: string;
  // Provider-side user identifier (Withings userid, etc.) when the provider
  // returns one alongside the tokens.
  providerUserId?: string;
  // Epoch seconds of last put().
  updatedAt: number;
}

export interface RefreshTokenStore {
  get(userId: string): Promise<RefreshTokenRecord | null>;
  put(record: RefreshTokenRecord): Promise<void>;
  delete(userId: string): Promise<void>;
}
