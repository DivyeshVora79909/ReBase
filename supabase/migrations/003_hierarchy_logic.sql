-- 1. HIERARCHY ENFORCEMENT (DAG, ROOT LOCK, & TENANT ISOLATION)
CREATE OR REPLACE FUNCTION public.enforce_hierarchy_rules()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$ DECLARE
    v_child_name TEXT;
    v_child_tenant_id uuid;
    v_parent_name TEXT;
    v_parent_tenant_id uuid;
    v_is_cycle BOOLEAN;
    v_my_role_id uuid;
BEGIN
    -- Fetch metadata for checks
    SELECT name, tenant_id INTO v_child_name, v_child_tenant_id FROM public.roles WHERE id = NEW.child_role_id;
    SELECT name, tenant_id INTO v_parent_name, v_parent_tenant_id FROM public.roles WHERE id = NEW.parent_role_id;

    -- RULE 1: Root Lock (Tenant Owner cannot be a child)
    IF v_child_name = 'Tenant Owner' THEN
        RAISE EXCEPTION 'Security Violation: Tenant Owner role cannot be a subordinate.';
    END IF;

    -- RULE 2: Tenant Isolation (Cross-tenant links forbidden)
    IF v_child_tenant_id IS DISTINCT FROM v_parent_tenant_id THEN
        RAISE EXCEPTION 'Security Violation: Cannot link roles from different tenants.';
    END IF;

    -- RULE 3: Prevent Cycles (DAG)
    IF NEW.parent_role_id = NEW.child_role_id THEN
        RAISE EXCEPTION 'Hierarchy Cycle Detected: A role cannot be its own parent.';
    END IF;

    IF EXISTS (
        WITH RECURSIVE hierarchy_tree AS (
            SELECT child_role_id as role_id
            FROM public.hierarchy
            WHERE parent_role_id = NEW.child_role_id AND tenant_id = v_child_tenant_id
            UNION ALL
            SELECT h.child_role_id
            FROM public.hierarchy h
            JOIN hierarchy_tree ht ON h.parent_role_id = ht.role_id
            WHERE h.tenant_id = v_child_tenant_id
        )
        SELECT 1 FROM hierarchy_tree WHERE role_id = NEW.parent_role_id
    ) THEN
        RAISE EXCEPTION 'Hierarchy Cycle Detected: Role % is already a descendant of %', NEW.child_role_id, NEW.parent_role_id;
    END IF;

    RETURN NEW;
END;
 $$;

DROP TRIGGER IF EXISTS check_hierarchy_integrity ON public.hierarchy;
CREATE TRIGGER check_hierarchy_integrity BEFORE INSERT OR UPDATE ON public.hierarchy FOR EACH ROW EXECUTE FUNCTION public.enforce_hierarchy_rules();

-- 2. ROLES ESCALATION PREVENTION
CREATE OR REPLACE FUNCTION public.protect_roles()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$ DECLARE
    v_my_perms text[];
BEGIN
    IF public.is_admin() THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' AND NOT public.is_subordinate(OLD.id) THEN
        RAISE EXCEPTION 'Security Violation: You can only manage roles that are subordinates of your role.';
    END IF;
    IF (TG_OP = 'INSERT') OR (NEW.permissions IS DISTINCT FROM OLD.permissions) THEN
        SELECT array_agg(x::text) INTO v_my_perms
        FROM jsonb_array_elements_text(auth.jwt() -> 'app_metadata' -> 'role' -> 'permissions') x;
        IF NOT (COALESCE(NEW.permissions, '{}') <@ COALESCE(v_my_perms, '{}')) THEN
            RAISE EXCEPTION 'Security Violation: You cannot grant permissions you do not possess.';
        END IF;
    END IF;
    RETURN NEW;
END;
 $$;

DROP TRIGGER IF EXISTS protect_roles_trigger ON public.roles;
CREATE TRIGGER protect_roles_trigger BEFORE INSERT OR UPDATE ON public.roles FOR EACH ROW EXECUTE FUNCTION public.protect_roles();

-- 3. PREVENT ROLE ASSIGNMENT ESCALATION
CREATE OR REPLACE FUNCTION public.protect_profile_role_assignment()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$ DECLARE
    v_target_perms text[];
    v_my_perms text[];
BEGIN
    IF public.is_admin() THEN
        RETURN NEW;
    END IF;

    IF NEW.role_id IS DISTINCT FROM OLD.role_id THEN
        IF NOT public.is_subordinate(NEW.role_id) THEN
            RAISE EXCEPTION 'Security Violation: You cannot assign a role that is not your subordinate.';
        END IF;
        SELECT permissions INTO v_target_perms FROM public.roles WHERE id = NEW.role_id;
        SELECT array_agg(x::text) INTO v_my_perms
        FROM jsonb_array_elements_text(auth.jwt() -> 'app_metadata' -> 'role' -> 'permissions') x;
        IF NOT (v_target_perms <@ v_my_perms) THEN
            RAISE EXCEPTION 'Security Violation: You cannot assign a role with permissions you do not possess.';
        END IF;
    END IF;
    RETURN NEW;
END;
 $$;

DROP TRIGGER IF EXISTS protect_profile_role_trigger ON public.profiles;
CREATE TRIGGER protect_profile_role_trigger BEFORE INSERT OR UPDATE OF role_id ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.protect_profile_role_assignment();

-- 4. PREVENT INVITATION ESCALATION
CREATE OR REPLACE FUNCTION public.protect_invitation_escalation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF public.is_admin() THEN
        RETURN NEW;
    END IF;

    IF NOT public.is_subordinate(NEW.target_role_id) THEN
        RAISE EXCEPTION 'Security Violation: You cannot invite a user to a role that is not your subordinate.';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS protect_invitation_trigger ON public.invitations;
CREATE TRIGGER protect_invitation_trigger BEFORE INSERT OR UPDATE ON public.invitations FOR EACH ROW EXECUTE FUNCTION public.protect_invitation_escalation();