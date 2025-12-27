-- name: ListOAuthIDPConfigs :many
SELECT tenant_id, provider, client_id, client_secret, redirect_uri, enabled, scopes, display_name, authorization_url
FROM oauth_idp_configs
WHERE tenant_id = $1;
