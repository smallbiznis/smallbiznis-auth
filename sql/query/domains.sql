-- name: GetDomainByHost :one
SELECT id, host, tenant_id
FROM domains
WHERE host = $1
LIMIT 1;
