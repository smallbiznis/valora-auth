-- ==========================================================
-- EXTENSIONS
-- ==========================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ==========================================================
-- COUNTRIES & TIMEZONES
-- ==========================================================
CREATE TABLE countries(
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    locale TEXT NOT NULL,
    currency TEXT NOT NULL
);

CREATE TABLE timezones(
    tz TEXT PRIMARY KEY,
    country_code TEXT NOT NULL REFERENCES countries(code)
);

CREATE INDEX idx_timezones_country_code ON timezones(country_code);

-- ==========================================================
-- ENUM TYPES
-- ==========================================================
CREATE TYPE tenant_type AS ENUM ('platform', 'personal', 'company');
CREATE TYPE domain_verification_method AS ENUM ('dns', 'file', 'manual');
CREATE TYPE domain_certificate_status AS ENUM ('pending', 'active', 'failed');
CREATE TYPE domain_provisioning_status AS ENUM ('pending', 'provisioning', 'active', 'error');

-- ==========================================================
-- TENANTS
-- ==========================================================
CREATE TABLE tenants (
    id BIGINT PRIMARY KEY,
    type tenant_type NOT NULL,
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    country_code TEXT NOT NULL REFERENCES countries(code),
    timezone TEXT NOT NULL,
    is_default BOOLEAN NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_tenant_slug ON tenants(slug);
CREATE INDEX idx_tenant_code ON tenants(code);

-- ==========================================================
-- USERS
-- ==========================================================
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    email TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,

    password_hash TEXT,
    name TEXT,

    phone TEXT,
    phone_verified BOOLEAN DEFAULT FALSE,

    avatar_url TEXT,

    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);

-- ==========================================================
-- TENANT USERS (RBAC)
-- ==========================================================
CREATE TABLE tenant_users (
    tenant_user_id BIGINT PRIMARY KEY,

    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    role VARCHAR(20) NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'STAFF', 'VIEWER')),
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'INVITED', 'DISABLED')),
    is_default BOOLEAN DEFAULT FALSE,

    invited_email VARCHAR(255),
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (tenant_id, user_id)
);

CREATE INDEX idx_tenant_users_tenant ON tenant_users(tenant_id);
CREATE INDEX idx_tenant_users_user ON tenant_users(user_id);
CREATE INDEX idx_tenant_users_role ON tenant_users(role);
CREATE INDEX idx_tenant_users_status ON tenant_users(status);

-- ==========================================================
-- TENANT AUTH PROVIDERS (MASTER ENABLE/DISABLE)
-- ==========================================================
CREATE TABLE tenant_auth_providers (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    provider_type VARCHAR(30) NOT NULL
        CHECK (provider_type IN (
            'password',
            'otp',
            'google',
            'apple',
            'github',
            'microsoft',
            'oidc',
            'saml'
        )),

    provider_config_id BIGINT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (tenant_id, provider_type)
);

CREATE INDEX idx_tenant_auth_providers_tenant 
    ON tenant_auth_providers(tenant_id);

-- ==========================================================
-- PASSWORD AUTH CONFIG
-- ==========================================================
CREATE TABLE password_configs (
    tenant_id BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    min_length INT DEFAULT 8,
    require_uppercase BOOLEAN DEFAULT FALSE,
    require_number BOOLEAN DEFAULT FALSE,
    require_symbol BOOLEAN DEFAULT FALSE,

    allow_signup BOOLEAN DEFAULT TRUE,
    allow_password_reset BOOLEAN DEFAULT TRUE,

    lockout_attempts INT DEFAULT 5,
    lockout_duration_seconds INT DEFAULT 300,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==========================================================
-- OTP AUTH CONFIG
-- ==========================================================
CREATE TABLE otp_configs (
    tenant_id BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    channel VARCHAR(20) NOT NULL DEFAULT 'sms'
        CHECK (channel IN ('sms','whatsapp','email')),

    provider VARCHAR(50),
    api_key TEXT,
    sender TEXT,
    template TEXT,

    expiry_seconds INT DEFAULT 300,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==========================================================
-- TENANT DOMAINS
-- ==========================================================
CREATE TABLE domains (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    host TEXT NOT NULL UNIQUE,
    is_primary BOOLEAN DEFAULT FALSE,

    verification_method domain_verification_method DEFAULT 'dns',
    verification_code TEXT,
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,

    certificate_status domain_certificate_status DEFAULT 'pending',
    certificate_updated_at TIMESTAMPTZ,

    provisioning_status domain_provisioning_status DEFAULT 'pending',
    provisioned_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_domains_tenant_id ON domains(tenant_id);

CREATE UNIQUE INDEX uniq_primary_domain_per_tenant
    ON domains(tenant_id)
    WHERE is_primary = TRUE;

-- ==========================================================
-- BRANDING / THEME
-- ==========================================================
CREATE TABLE brandings (
    tenant_id BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    logo_url TEXT,
    favicon_url TEXT,

    primary_color TEXT,
    secondary_color TEXT,
    accent_color TEXT,
    background_color TEXT,
    text_color TEXT,

    dark_mode BOOLEAN DEFAULT TRUE,

    custom_css TEXT,
    custom_js TEXT,

    custom_html_header TEXT,
    custom_html_footer TEXT,

    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_branding_tenant_id ON brandings(tenant_id);

-- ==========================================================
-- OAUTH APPS
-- ==========================================================
CREATE TYPE oauth_app_type AS ENUM ('WEB', 'MOBILE', 'M2M');

CREATE TABLE oauth_apps (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    name TEXT NOT NULL,
    app_type oauth_app_type NOT NULL,
    description TEXT,
    icon_url TEXT,

    is_active BOOLEAN DEFAULT TRUE,
    is_first_party BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_oauth_apps_tenant_id ON oauth_apps(tenant_id);

-- ==========================================================
-- OAUTH CLIENTS
-- ==========================================================
CREATE TABLE oauth_clients (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id BIGINT REFERENCES oauth_apps(id) ON DELETE CASCADE,

    client_id TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,

    redirect_uris TEXT[] DEFAULT ARRAY[]::TEXT[],
    grants TEXT[] DEFAULT ARRAY[]::TEXT[],
    scopes TEXT[] DEFAULT ARRAY[]::TEXT[],
    token_endpoint_auth_methods TEXT[] DEFAULT ARRAY[]::TEXT[],
    require_consent BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_oauth_clients_tenant_id ON oauth_clients(tenant_id);
CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);

-- ==========================================================
-- OAUTH CODES
-- ==========================================================
CREATE TABLE oauth_codes (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    client_id TEXT NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id),

    code TEXT NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL,

    code_challenge TEXT,
    code_challenge_method TEXT,

    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_oauth_codes_tenant_id ON oauth_codes(tenant_id);
CREATE INDEX idx_oauth_codes_client_id ON oauth_codes(client_id);
CREATE INDEX idx_oauth_codes_code ON oauth_codes(code);

-- ==========================================================
-- OAUTH TOKENS
-- ==========================================================
CREATE TABLE oauth_tokens (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    client_id TEXT NOT NULL,
    user_id BIGINT REFERENCES users(id),

    access_token TEXT NOT NULL,
    refresh_token TEXT,

    scopes TEXT[] DEFAULT ARRAY[]::TEXT[],
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_oauth_tokens_tenant_id ON oauth_tokens(tenant_id);
CREATE INDEX idx_oauth_tokens_access_token ON oauth_tokens(access_token);
CREATE INDEX idx_oauth_tokens_refresh_token ON oauth_tokens(refresh_token);

-- ==========================================================
-- OAUTH SIGNING KEYS (PER TENANT)
-- ==========================================================
CREATE TABLE oauth_keys (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    kid TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL DEFAULT 'HS256',
    secret TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

CREATE INDEX idx_oauth_keys_tenant_id ON oauth_keys(tenant_id);

-- ==========================================================
-- IDENTITY PROVIDER CONFIGS (GOOGLE, APPLE, OIDC)
-- ==========================================================
CREATE TABLE oauth_idp_configs (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    provider VARCHAR(30) NOT NULL
        CHECK (provider IN ('google','apple','github','microsoft','oidc')),

    client_id TEXT NOT NULL,
    client_secret TEXT,

    issuer_url TEXT,
    authorization_url TEXT,
    token_url TEXT,
    userinfo_url TEXT,
    jwks_url TEXT,

    scopes TEXT[] DEFAULT ARRAY[]::TEXT[],
    extra JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_oauth_idp_configs_tenant ON oauth_idp_configs(tenant_id);

-- ==========================================================
-- SAML CONFIGS
-- ==========================================================
CREATE TABLE saml_idp_configs (
    id BIGINT PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    idp_entity_id TEXT NOT NULL,
    sso_url TEXT NOT NULL,
    certificate TEXT NOT NULL,

    acs_url TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,

    metadata_xml TEXT,
    extra JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_saml_idp_configs_tenant ON saml_idp_configs(tenant_id);

-- ==========================================================
-- USER IDENTITIES
-- ==========================================================
CREATE TABLE oauth_user_identities (
    id BIGINT PRIMARY KEY,

    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,

    email TEXT,
    raw_profile JSONB,

    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (provider, provider_user_id),
    UNIQUE (user_id, provider)
);

-- ==========================================================
-- INITIAL TENANT SEED (platform + Kopi Kenangan)
-- ==========================================================

INSERT INTO countries (code, name, locale, currency) VALUES
    ('ID', 'Indonesia', 'id-ID', 'IDR'),
    ('SG', 'Singapore', 'en-SG', 'SGD')
ON CONFLICT DO NOTHING;

INSERT INTO timezones(country_code, tz) VALUES
    ('ID', 'Asia/Jakarta'),
    ('ID', 'Asia/Makassar'),
    ('ID', 'Asia/Jayapura'),
    ('SG', 'Asia/Singapore')
ON CONFLICT DO NOTHING;

INSERT INTO tenants (id, type, name, code, slug, country_code, timezone, is_default, status)
VALUES
    (1000, 'platform', 'SmallBiznis', 'SB', 'smallbiznis', 'SG', 'Asia/Singapore', TRUE, 'active'),
    (2000, 'company', 'Kopi Kenangan', 'KK', 'kopikenangan', 'ID', 'Asia/Jakarta', FALSE, 'active')
ON CONFLICT DO NOTHING;

-- Branding defaults
INSERT INTO brandings (tenant_id, primary_color, secondary_color, accent_color, background_color, text_color, dark_mode)
VALUES
    (1000, '#5B3CF6', '#7E65FA', '#4A2ED9', '#111113', '#FFFFFF', TRUE),
    (2000, '#6A4C93', '#9D5CFF', '#FFAA00', '#ffffff', '#222222', FALSE)
ON CONFLICT DO NOTHING;

-- Primary domains
INSERT INTO domains (id, tenant_id, host, is_primary, verified)
VALUES
    (1001, 1000, 'smallbiznis.smallbiznisapp.io', TRUE, TRUE),
    (2001, 2000, 'kopikenangan.smallbiznisapp.io', TRUE, TRUE)
ON CONFLICT DO NOTHING;

-- OAuth apps & clients (Postman-friendly defaults)
INSERT INTO oauth_apps (id, tenant_id, name, app_type, description, icon_url, is_active, is_first_party)
VALUES
    (1100, 1000, 'SmallBiznis Console', 'WEB', 'First-party admin console', NULL, TRUE, TRUE),
    (2100, 2000, 'Kopi Kenangan POS', 'WEB', 'POS integration for Kopi Kenangan', NULL, TRUE, FALSE)
ON CONFLICT DO NOTHING;

INSERT INTO oauth_clients (id, tenant_id, app_id, client_id, client_secret, redirect_uris, grants, scopes, token_endpoint_auth_methods, require_consent)
VALUES
    (
        1200,
        1000,
        1100,
        'console-web',
        'console-web-secret',
        ARRAY['https://oauth.pstmn.io/v1/callback', 'http://localhost:3000/callback'],
        ARRAY['authorization_code', 'refresh_token', 'client_credentials'],
        ARRAY['openid', 'profile', 'email', 'offline_access'],
        ARRAY['client_secret_basic'],
        FALSE
    ),
    (
        2200,
        2000,
        2100,
        'kopi-pos',
        'kopi-pos-secret',
        ARRAY['https://oauth.pstmn.io/v1/callback', 'http://localhost:4000/callback'],
        ARRAY['authorization_code', 'refresh_token'],
        ARRAY['openid', 'profile'],
        ARRAY['client_secret_basic'],
        FALSE
    )
ON CONFLICT DO NOTHING;

INSERT INTO oauth_keys (id, tenant_id, kid, algorithm, secret, is_active)
VALUES
    (1300, 1000, 'sb-key-1', 'HS256', encode(gen_random_bytes(32), 'hex'), TRUE),
    (2300, 2000, 'kk-key-1', 'HS256', encode(gen_random_bytes(32), 'hex'), TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO oauth_idp_configs (
    id,
    tenant_id,
    provider,
    client_id,
    client_secret,
    issuer_url,
    authorization_url,
    token_url,
    userinfo_url,
    jwks_url,
    scopes
)
VALUES
    (
        1400,
        1000,
        'oidc',
        'dummy-client-id',
        'dummy-client-secret',
        'http://localhost:9000',
        'http://localhost:9000/oauth2/authorize',
        'http://localhost:9000/oauth2/token',
        'http://localhost:9000/oauth2/userinfo',
        'http://localhost:9000/oauth2/jwks',
        ARRAY['openid','email','profile']
    ),
    (
        2400,
        2000,
        'oidc',
        'dummy-client-id',
        'dummy-client-secret',
        'http://localhost:9000',
        'http://localhost:9000/oauth2/authorize',
        'http://localhost:9000/oauth2/token',
        'http://localhost:9000/oauth2/userinfo',
        'http://localhost:9000/oauth2/jwks',
        ARRAY['openid','email','profile']
    )
ON CONFLICT DO NOTHING;

INSERT INTO saml_idp_configs (id, tenant_id, idp_entity_id, sso_url, certificate, acs_url, sp_entity_id)
VALUES
    (
        1500, 2000,
        'kopi-kenangan-saml',
        'https://sso.kopikenangan.com/login',
        '-----BEGIN CERTIFICATE----- FAKE -----END CERTIFICATE-----',
        'https://kopikenangan.smallbiznisapp.local/saml/acs',
        'smallbiznis-sp'
    )
ON CONFLICT DO NOTHING;

-- Default auth providers
INSERT INTO tenant_auth_providers (id, tenant_id, provider_type, is_active)
VALUES
    (5001, 1000, 'password', TRUE),
    (5002, 1000, 'otp', TRUE),
    (5003, 2000, 'password', TRUE),
    (5004, 2000, 'otp', TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO password_configs (tenant_id, min_length, require_uppercase, require_number, require_symbol)
VALUES
    (1000, 8, FALSE, TRUE, FALSE),
    (2000, 8, TRUE, TRUE, FALSE)
ON CONFLICT DO NOTHING;

INSERT INTO otp_configs (tenant_id, channel, provider, api_key, sender, template, expiry_seconds)
VALUES
    (1000, 'sms', 'debug', 'local-dev', 'SMALLBIZNIS', 'Your OTP is {{code}}', 300),
    (2000, 'whatsapp', 'debug', 'local-dev', 'KOPIKENANGAN', 'OTP Anda: {{code}}', 300)
ON CONFLICT DO NOTHING;
