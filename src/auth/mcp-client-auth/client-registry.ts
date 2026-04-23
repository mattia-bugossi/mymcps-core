// purpose: Dynamic Client Registration (RFC 7591) storage contract.
// handleRegister persists new clients via put(); handleAuthorize and
// handleToken look them up via get() when the presented client_id does
// not match the static OAuthServerConfig.clientId. Storage backend is
// consumer-chosen (DynamoDB for prod, in-memory for tests) so core stays
// provider-agnostic — same pattern as RefreshTokenStore.

export interface RegisteredClientMetadata {
  redirect_uris?: string[];
  grant_types?: string[];
  response_types?: string[];
  client_name?: string;
  // Only 'client_secret_post' is supported today (handleToken requires
  // client_secret in the body). handleRegister rejects any other value
  // up front so the mismatch never surfaces as a mystery 401 two steps
  // later at token exchange.
  token_endpoint_auth_method?: 'client_secret_post';
  scope?: string;
}

export interface RegisteredClient {
  client_id: string;
  client_secret: string;
  // Epoch seconds at registration time.
  client_id_issued_at: number;
  metadata: RegisteredClientMetadata;
}

// Thrown by ClientRegistry.put when a client with the given client_id
// already exists. handleRegister catches this once and retries with a
// fresh client_id before giving up — 32-byte base64url collisions are
// cryptographically negligible, but the contract still needs a rule.
export class ClientIdCollisionError extends Error {
  readonly clientId: string;
  constructor(clientId: string) {
    super(`client_id already registered: ${clientId}`);
    this.name = 'ClientIdCollisionError';
    this.clientId = clientId;
  }
}

export interface ClientRegistry {
  // Returns null when no client with the given client_id exists.
  get(clientId: string): Promise<RegisteredClient | null>;
  // Persists a new client. Implementations MUST throw
  // ClientIdCollisionError on client_id collision rather than overwrite
  // an existing record — handleRegister depends on that signal to
  // retry. No update semantics today.
  put(client: RegisteredClient): Promise<void>;
}
