-- name: GetUserByEmail :one
SELECT id, tenant_id, email, password_hash, name, picture_url, blocked, failed_attempts, locked_until, created_at, updated_at
FROM users
WHERE tenant_id = $1 AND email = $2
LIMIT 1;

-- name: GetUserByID :one
SELECT id, tenant_id, email, password_hash, name, picture_url, blocked, failed_attempts, locked_until, created_at, updated_at
FROM users
WHERE tenant_id = $1 AND id = $2
LIMIT 1;

-- name: UpdateUserLoginStats :exec
UPDATE users
SET failed_attempts = $2,
    locked_until = $3,
    updated_at = NOW()
WHERE id = $1;
