SELECT
    tenant_id,
    provider_type AS type,
    provider_type AS name,
    is_active AS enabled
FROM tenant_auth_providers
WHERE tenant_id = $1;
