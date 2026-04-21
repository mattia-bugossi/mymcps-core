// purpose: Build the provider authorization URL that the MCP server redirects
// the user to when linking their account. Covers the authorization-code-with-
// PKCE-or-state flow for providers like Withings and Strava.

export interface BuildAuthorizationUrlConfig {
  // Provider's authorize endpoint, e.g. 'https://account.withings.com/oauth2_user/authorize2'.
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  // OAuth 2.0 specifies space-joined scopes; a few providers (notably Withings)
  // use comma-joined. Defaults to 'space'.
  scopeSeparator?: 'space' | 'comma';
  // State param tying the authorize request to the callback. Caller chooses
  // the shape (signed JWT, random nonce, …).
  state?: string;
  // Extra provider-specific query params (e.g. PKCE challenge, mode=demo).
  extraParams?: Record<string, string>;
}

export function buildAuthorizationUrl(config: BuildAuthorizationUrlConfig): string {
  const url = new URL(config.authorizationEndpoint);
  const separator = config.scopeSeparator === 'comma' ? ',' : ' ';
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.redirectUri);
  url.searchParams.set('scope', config.scopes.join(separator));
  if (config.state) url.searchParams.set('state', config.state);
  for (const [k, v] of Object.entries(config.extraParams ?? {})) {
    url.searchParams.set(k, v);
  }
  return url.toString();
}
