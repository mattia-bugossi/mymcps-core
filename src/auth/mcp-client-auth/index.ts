export { sign, verify, type JwtClaims } from './jwt.js';
export {
  buildDiscoveryMetadata,
  handleAuthorize,
  handleRegister,
  handleToken,
  type AuthorizeInput,
  type ClientRegistration,
  type DiscoveryInput,
  type DiscoveryMetadataConfig,
  type HttpResult,
  type OAuthServerConfig,
  type RegisterInput,
  type TokenInput,
  type TokenSuccess,
} from './oauth-server.js';
export {
  ClientIdCollisionError,
  type ClientRegistry,
  type RegisteredClient,
  type RegisteredClientMetadata,
} from './client-registry.js';
export {
  makeAuthorizer,
  type AuthorizerConfig,
  type AuthorizerLogger,
} from './authorizer.js';
