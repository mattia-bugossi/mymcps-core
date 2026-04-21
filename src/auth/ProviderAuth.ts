// purpose: Unified upstream-auth contract. Each provider implements this so
// tool handlers can ask for a ready-to-use access token without knowing
// whether it comes from a server-side PAT, an OAuth2 refresh flow, or a
// signed-request dance.

export interface ProviderAuth {
  // Returns a bearer access token ready to put in Authorization: Bearer <x>.
  // May perform a refresh, cache hit, or signed-request exchange internally.
  // Throws AuthError (from ../errors) on unrecoverable auth failures.
  getAccessToken(userId: string): Promise<string>;
}
