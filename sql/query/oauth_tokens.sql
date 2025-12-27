-- name: InsertOAuthToken :one
INSERT INTO oauth_tokens (
    id, tenant_id, client_id, user_id, access_token, refresh_token, scopes, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING id, tenant_id, client_id, user_id, access_token, refresh_token, scopes, expires_at, revoked, created_at;

-- name: GetOAuthTokenByRefresh :one
SELECT id, tenant_id, client_id, user_id, access_token, refresh_token, scopes, expires_at, revoked, created_at
FROM oauth_tokens
WHERE tenant_id = $1 AND refresh_token = $2
LIMIT 1;

-- name: GetOAuthTokenByRefreshValue :one
SELECT id, tenant_id, client_id, user_id, access_token, refresh_token, scopes, expires_at, revoked, created_at
FROM oauth_tokens
WHERE refresh_token = $1
LIMIT 1;

-- name: GetOAuthTokenByAccess :one
SELECT id, tenant_id, client_id, user_id, access_token, refresh_token, scopes, expires_at, revoked, created_at
FROM oauth_tokens
WHERE access_token = $1
LIMIT 1;

-- name: RotateRefreshToken :exec
UPDATE oauth_tokens
SET refresh_token = $2,
    expires_at = $3
WHERE id = $1;

-- name: RevokeOAuthToken :exec
UPDATE oauth_tokens
SET revoked = true
WHERE id = $1;
