-- name: InsertOAuthToken :one
INSERT INTO oauth_tokens (
    tenant_id, user_id, client_id, scope, refresh_token, access_token_id, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING id, tenant_id, user_id, client_id, scope, refresh_token, access_token_id, created_at, expires_at, rotated_at, revoked;

-- name: GetOAuthTokenByRefresh :one
SELECT id, tenant_id, user_id, client_id, scope, refresh_token, access_token_id, created_at, expires_at, rotated_at, revoked
FROM oauth_tokens
WHERE tenant_id = $1 AND refresh_token = $2
LIMIT 1;

-- name: RotateRefreshToken :exec
UPDATE oauth_tokens
SET refresh_token = $2,
    expires_at = $3,
    rotated_at = NOW()
WHERE id = $1;

-- name: RevokeOAuthToken :exec
UPDATE oauth_tokens
SET revoked = true
WHERE id = $1;
