-- name: GetBranding :one
SELECT
    tenant_id,
    COALESCE(logo_url, '') AS logo_url,
    COALESCE(primary_color, '') AS primary_color
FROM brandings
WHERE tenant_id = $1
LIMIT 1;
