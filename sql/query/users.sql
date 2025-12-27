-- name: GetUserByEmail :one
SELECT id, tenant_id, email, email_verified, password_hash, name, phone, phone_verified, avatar_url, status, created_at, updated_at
FROM users
WHERE tenant_id = $1 AND email = $2
LIMIT 1;

-- name: GetUserByID :one
SELECT id, tenant_id, email, email_verified, password_hash, name, phone, phone_verified, avatar_url, status, created_at, updated_at
FROM users
WHERE tenant_id = $1 AND id = $2
LIMIT 1;
