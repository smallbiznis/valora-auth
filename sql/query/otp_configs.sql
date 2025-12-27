SELECT tenant_id, channel, provider, api_key, sender, template, expiry_seconds, created_at, updated_at
FROM otp_configs
WHERE tenant_id = $1
LIMIT 1;
