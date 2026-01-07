-- ALTER ROLE authenticator SET log_statement = 'all';
SELECT current_user, session_user;
SET ROLE postgres;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE visibility_mode AS ENUM ('PRIVATE', 'PUBLIC', 'CONTROLLED');

CREATE TABLE public.tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE public.roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    permissions TEXT[],
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE public.hierarchy (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    child_role_id UUID NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
    parent_role_id UUID NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES public.roles(id) ON DELETE RESTRICT,
    first_name TEXT,
    last_name TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE public.deals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    file_path TEXT UNIQUE,
    lead_owner_id UUID REFERENCES public.profiles(id),
    
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    owner_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    owner_ship visibility_mode NOT NULL DEFAULT 'PRIVATE',
    owner_role_id UUID REFERENCES public.roles(id) ON DELETE SET NULL,

    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX idx_roles_tenant_name ON public.roles(tenant_id, name);
CREATE INDEX idx_hierarchy_tenant ON public.hierarchy(tenant_id, parent_role_id);
CREATE UNIQUE INDEX idx_hierarchy_child_parent ON public.hierarchy(child_role_id, parent_role_id);
CREATE INDEX idx_profiles_tenant ON public.profiles(tenant_id);
CREATE INDEX idx_deals_tenant ON public.deals(tenant_id, owner_id);
CREATE INDEX idx_deals_files ON public.deals(file_path);

INSERT INTO storage.buckets (id, name, public) VALUES ('deals', 'deals', false) ON CONFLICT (id) DO NOTHING;