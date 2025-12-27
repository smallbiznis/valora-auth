-- name: GetActiveOAuthKey :one
SELECT id, tenant_id, kid, secret, algorithm, active, created_at
FROM oauth_keys
WHERE tenant_id = $1 AND active = true
ORDER BY created_at DESC
LIMIT 1;

-- name: InsertOAuthKey :one
INSERT INTO oauth_keys (
    id, tenant_id, kid, secret, algorithm, active
) VALUES (
    $1, $2, $3, $4, $5, true
) RETURNING id, tenant_id, kid, secret, algorithm, active, created_at;
