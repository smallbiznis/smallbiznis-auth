SELECT id,
       type,
       name,
       code,
       slug,
       country_code,
       timezone,
       is_default,
       status,
       created_at,
       updated_at
FROM tenants
WHERE id = $1
LIMIT 1;
