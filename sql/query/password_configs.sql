SELECT
    tenant_id,
    TRUE AS enabled,
    COALESCE(lockout_attempts, 5) AS max_attempts,
    make_interval(secs => COALESCE(lockout_duration_seconds, 300)) AS lockout_interval
FROM password_configs
WHERE tenant_id = $1
LIMIT 1;
