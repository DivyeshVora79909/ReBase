-- 0. ADMIN CHECKER
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$ BEGIN
    RETURN (
        (auth.jwt() ->> 'role') = 'service_role' OR
        (auth.uid() IS NULL AND session_user IN ('service_role', 'postgres', 'supabase_admin', 'supabase_auth_admin'))
    );
END;
 $$;

-- 1. SECURITY MIXIN: Forces Tenant Isolation and Sets Audit Fields
CREATE OR REPLACE FUNCTION public.handle_security_mixin()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$ DECLARE
    v_tenant_id uuid;
    v_role_id uuid;
    v_has_jwt boolean;
BEGIN
    IF public.is_admin() AND auth.uid() IS NULL THEN
        RETURN NEW;
    END IF;

    -- 1. ENFORCE TENANT ID
    v_has_jwt := (auth.jwt() IS NOT NULL);
    
    IF v_has_jwt THEN
        v_tenant_id := (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid;
        v_role_id := (auth.jwt() -> 'app_metadata' -> 'role' ->> 'id')::uuid;

        -- If tenant_id is provided, it MUST match the JWT
        IF NEW.tenant_id IS NOT NULL AND NEW.tenant_id != v_tenant_id THEN
            RAISE EXCEPTION 'Security Violation: Tenant ID mismatch.';
        END IF;

        -- Auto-populate tenant_id if missing
        IF NEW.tenant_id IS NULL THEN
            NEW.tenant_id := v_tenant_id;
        END IF;
    END IF;

    -- 2. ENFORCE AUDIT FIELDS
    IF v_has_jwt THEN
        NEW.owner_id := auth.uid();
        NEW.owner_role_id := v_role_id;
    END IF;

    RETURN NEW;
END;
 $$;

-- 2. INVITATION SPECIFIC TRIGGER
CREATE OR REPLACE FUNCTION public.handle_invitation_logic()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$ 
BEGIN
    IF public.is_admin() AND auth.uid() IS NULL THEN
        RETURN NEW;
    END IF;

    NEW.tenant_id := (auth.jwt()->'app_metadata'->>'tenant_id')::uuid;
    NEW.invited_by := auth.uid();
    NEW.status := 'pending';

    RETURN NEW;
END;
 $$;

-- 3. PERMISSION CHECKER
CREATE OR REPLACE FUNCTION public.has_permission(p_perm text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$ DECLARE
    v_perms jsonb;
BEGIN
    v_perms := COALESCE(
        auth.jwt()->'app_metadata'->'role'->'permissions',
        '[]'::jsonb
    );
    RETURN v_perms ? p_perm;
END;
 $$;

-- 4. SUBORDINATE CHECKER (Hierarchy)
CREATE OR REPLACE FUNCTION public.is_subordinate(p_target_role_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$ DECLARE
    v_descendants jsonb;
BEGIN
    v_descendants := COALESCE(
        auth.jwt()->'app_metadata'->'descendants',
        '[]'::jsonb
    );
    RETURN v_descendants ? p_target_role_id::text;
END;
 $$;

-- 5. TENANT OWNER CHECK
CREATE OR REPLACE FUNCTION public.is_tenant_owner()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$ BEGIN
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

DROP TRIGGER IF EXISTS set_invitation_audit ON public.invitations;
CREATE TRIGGER set_invitation_audit BEFORE INSERT ON public.invitations FOR EACH ROW EXECUTE FUNCTION public.handle_invitation_logic();