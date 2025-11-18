-- name: InsertOAuthCode :exec
INSERT INTO oauth_codes (
    code, tenant_id, user_id, client_id, redirect_uri, scope, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
);

-- name: GetOAuthCode :one
SELECT code, tenant_id, user_id, client_id, redirect_uri, scope, expires_at, used
FROM oauth_codes
WHERE tenant_id = $1 AND code = $2
LIMIT 1;

-- name: MarkOAuthCodeUsed :exec
UPDATE oauth_codes
SET used = true
WHERE code = $1;
