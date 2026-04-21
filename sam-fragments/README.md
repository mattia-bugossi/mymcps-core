# SAM fragments

Copy-paste building blocks for per-provider `template.yaml` files. CloudFormation
doesn't support `!Include`, so each provider repo keeps its own monolithic
template — these fragments exist to keep those templates *shaped* consistently.

## How to use

Each `.yaml` file below is a partial CFN Resources/Parameters/Outputs block.
When bootstrapping a new provider's `template.yaml`:

1. Start from an existing provider (e.g. `oura-mcp-server/template.yaml`) or a
   blank SAM template.
2. Paste the `Resources:` blocks from the fragments you need, renaming the
   logical IDs to match your provider (`WithingsRefreshTokens` instead of
   `ProviderRefreshTokens`, etc.).
3. Substitute `<provider>` placeholders with your provider slug (`withings`,
   `dexcom`, …).
4. Re-link any `!Ref` chains — fragments are written as if the blocks live in
   the same template.

## Fragments

| File | Purpose |
| --- | --- |
| `dynamo-cache-table.yaml` | DynamoDB on-demand table for the core CacheAdapter (`DynamoCache`). TTL attribute name matches the core default (`ttl`). |
| `secrets-manager-parameters.yaml` | Per-provider Secrets Manager entries: upstream PAT (optional), MCP-client bearer, OAuth client_id/secret, JWT signing secret, and the refresh-tokens prefix for `SecretsManagerRefreshTokenStore`. |
| `oauth-callback-route.yaml` | HttpApi routes and IAM policy adds for the provider-side OAuth callback (`/oauth/<provider>/callback`) used by `exchangeAuthorizationCode`. |
