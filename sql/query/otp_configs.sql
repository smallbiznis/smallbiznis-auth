-- name: GetOTPConfig :one
SELECT tenant_id, enabled, length, ttl
FROM otp_configs
WHERE tenant_id = $1
LIMIT 1;
