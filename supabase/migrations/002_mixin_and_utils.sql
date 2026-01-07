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
    IF (auth.jwt() ->> 'role') = 'service_role' THEN
        RETURN NEW;
    END IF;

    BEGIN
        v_tenant_id := (auth.jwt()->'app_metadata'->>'tenant_id')::uuid;
        v_role_id := (auth.jwt()->'app_metadata'->>'role_id')::uuid;
        v_has_jwt := (v_tenant_id IS NOT NULL);
    EXCEPTION
        WHEN OTHERS THEN
            v_has_jwt := FALSE;
    END;

    BEGIN
        IF v_has_jwt THEN
            NEW.tenant_id := v_tenant_id;
        END IF;
        IF NEW.tenant_id IS NULL THEN
            RAISE EXCEPTION 'Security Violation: Tenant ID is missing.';
        END IF;
    EXCEPTION
        WHEN undefined_column THEN NULL;
    END;

    BEGIN
        IF NEW.owner_id IS NULL THEN
            NEW.owner_id := auth.uid();
        END IF;
    EXCEPTION
        WHEN undefined_column THEN NULL;
    END;

    BEGIN
        IF NEW.owner_role_id IS NULL AND v_has_jwt THEN
            NEW.owner_role_id := v_role_id;
        END IF;
    EXCEPTION
        WHEN undefined_column THEN NULL;
    END;

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
    IF (auth.jwt() ->> 'role') = 'service_role' THEN
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