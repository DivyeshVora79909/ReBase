-- 1. populate tenant_id, owner_id, and owner_role_id if columns exist
CREATE OR REPLACE FUNCTION public.handle_security_mixin()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- Set tenant_id
    BEGIN
        IF NEW.tenant_id IS NULL THEN
            NEW.tenant_id := (auth.jwt()->'app_metadata'->>'tenant_id')::uuid;
        END IF;
    EXCEPTION
        WHEN undefined_column THEN
            NULL;
    END;

    -- Set owner_id
    BEGIN
        IF NEW.owner_id IS NULL THEN
            NEW.owner_id := auth.uid();
        END IF;
    EXCEPTION
        WHEN undefined_column THEN
            NULL;
    END;

    -- Set owner_role_id
    BEGIN
        IF NEW.owner_role_id IS NULL THEN
            NEW.owner_role_id := (auth.jwt()->'app_metadata'->>'role_id')::uuid;
        END IF;
    EXCEPTION
        WHEN undefined_column THEN
            NULL;
    END;

    -- Set tenant_id for Roles/Hierarchy if missing
    IF TG_TABLE_NAME = 'roles' AND NEW.tenant_id IS NULL THEN
        NEW.tenant_id := (auth.jwt()->'app_metadata'->>'tenant_id')::uuid;
    END IF;

    RETURN NEW;
END;
$$;

-- 2. Checks permission string in jwt
CREATE OR REPLACE FUNCTION public.has_permission(p_perm text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_perms jsonb;
BEGIN
    v_perms := COALESCE(
        auth.jwt()->'app_metadata'->'role'->'permissions',
        '[]'::jsonb
    );
    RETURN v_perms ? p_perm;
END;
$$;

-- 3. Checks target role in descendants list in jwt
CREATE OR REPLACE FUNCTION public.is_subordinate(p_target_role_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_descendants jsonb;
BEGIN
    v_descendants := COALESCE(
        auth.jwt()->'app_metadata'->'descendants',
        '[]'::jsonb
    );
    RETURN v_descendants ? p_target_role_id::text;
END;
$$;

-- 4. TENANT OWNER CHECK
CREATE OR REPLACE FUNCTION public.is_tenant_owner()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN (
        auth.jwt()->'app_metadata'->'role'->>'name'
    ) = 'Tenant Owner';
END;
$$;

-- APPLY MIXIN TRIGGER TO RESOURCE TABLES
DROP TRIGGER IF EXISTS set_security_fields ON public.deals;
CREATE TRIGGER set_security_fields BEFORE INSERT ON public.deals FOR EACH ROW EXECUTE FUNCTION public.handle_security_mixin();

DROP TRIGGER IF EXISTS set_security_fields ON public.profiles;
CREATE TRIGGER set_security_fields BEFORE INSERT ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.handle_security_mixin();

DROP TRIGGER IF EXISTS set_security_fields ON public.roles;
CREATE TRIGGER set_security_fields BEFORE INSERT ON public.roles FOR EACH ROW EXECUTE FUNCTION public.handle_security_mixin();

DROP TRIGGER IF EXISTS set_security_fields ON public.hierarchy;
CREATE TRIGGER set_security_fields BEFORE INSERT ON public.hierarchy FOR EACH ROW EXECUTE FUNCTION public.handle_security_mixin();