-- name: ListAuthProviders :many
SELECT id, tenant_id, provider_type, provider_config_id, is_active, created_at, updated_at
FROM tenant_auth_providers
WHERE tenant_id = $1;
