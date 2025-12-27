-- name: GetPasswordConfig :one
SELECT
    tenant_id,
    min_length,
    require_uppercase,
    require_number,
    require_symbol,
    allow_signup,
    allow_password_reset,
    lockout_attempts,
    lockout_duration_seconds,
    created_at,
    updated_at
FROM password_configs
WHERE tenant_id = $1
LIMIT 1;
