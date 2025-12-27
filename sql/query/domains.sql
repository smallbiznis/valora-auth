-- name: GetDomainByHost :one
-- name: GetDomainByHost :one
SELECT id, host, tenant_id
FROM domains
WHERE host = $1
LIMIT 1;

-- name: GetPrimaryDomain :one
SELECT id, host, tenant_id
FROM domains
WHERE tenant_id = $1
ORDER BY is_primary DESC, id ASC
LIMIT 1;
