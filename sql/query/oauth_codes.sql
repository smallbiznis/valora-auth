-- name: InsertOAuthCode :exec
INSERT INTO oauth_codes (
    id, tenant_id, client_id, user_id, code, redirect_uri, code_challenge, code_challenge_method, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
);

-- name: GetOAuthCode :one
SELECT id, tenant_id, client_id, user_id, code, redirect_uri, code_challenge, code_challenge_method, expires_at, revoked, created_at
FROM oauth_codes
WHERE tenant_id = $1 AND code = $2
LIMIT 1;

-- name: RevokeOAuthCode :exec
UPDATE oauth_codes
SET revoked = true
WHERE code = $1;
