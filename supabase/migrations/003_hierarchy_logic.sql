-- 1. HIERARCHY ENFORCEMENT (DAG & ROOT LOCK)
CREATE OR REPLACE FUNCTION public.enforce_hierarchy_rules()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$ DECLARE
    v_child_name TEXT;
    v_parent_name TEXT;
    v_is_cycle BOOLEAN;
    v_my_role_id uuid;
BEGIN
    SELECT name INTO v_child_name FROM public.roles WHERE id = NEW.child_role_id;
    SELECT name INTO v_parent_name FROM public.roles WHERE id = NEW.parent_role_id;

    IF v_child_name = 'Tenant Owner' THEN
        RAISE EXCEPTION 'Security Violation: Tenant Owner role cannot be a subordinate.';
    END IF;

    -- Cycle Detection using Recursive CTE
    WITH RECURSIVE path_check AS (
        SELECT parent_role_id, child_role_id, 1 as depth
        FROM public.hierarchy
        WHERE child_role_id = NEW.child_role_id AND tenant_id = NEW.tenant_id
        
        UNION ALL
        
        SELECT h.parent_role_id, h.child_role_id, pc.depth + 1
        FROM public.hierarchy h
        JOIN path_check pc ON h.child_role_id = pc.parent_role_id
        WHERE h.tenant_id = NEW.tenant_id AND pc.depth < 20
    )
    SELECT EXISTS(SELECT 1 FROM path_check WHERE parent_role_id = NEW.parent_role_id) INTO v_is_cycle;

    IF v_is_cycle THEN
        RAISE EXCEPTION 'Constraint Violation: Cycle detected in role hierarchy.';
    END IF;

    RETURN NEW;
END;
 $$;

DROP TRIGGER IF EXISTS check_hierarchy_integrity ON public.hierarchy;
CREATE TRIGGER check_hierarchy_integrity BEFORE INSERT OR UPDATE ON public.hierarchy FOR EACH ROW EXECUTE FUNCTION public.enforce_hierarchy_rules();

-- 2. ROLES ESCALATION PREVENTION (Refined)
CREATE OR REPLACE FUNCTION public.protect_roles()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$ DECLARE
    v_my_perms text[];
BEGIN
    IF NOT public.is_subordinate(OLD.id) THEN
        RAISE EXCEPTION 'Security Violation: You can only manage roles that are subordinates of your role.';
    END IF;

    IF NEW.permissions IS DISTINCT FROM OLD.permissions THEN
        SELECT array_agg(x::text) INTO v_my_perms
        FROM jsonb_array_elements_text(auth.jwt() -> 'app_metadata' -> 'role' -> 'permissions') x;
        IF NOT (NEW.permissions <@ v_my_perms) THEN
            RAISE EXCEPTION 'Security Violation: You cannot grant permissions you do not possess.';
        END IF;
    END IF;

    RETURN NEW;
END;
 $$;

DROP TRIGGER IF EXISTS protect_roles_trigger ON public.roles;
CREATE TRIGGER protect_roles_trigger BEFORE UPDATE ON public.roles FOR EACH ROW EXECUTE FUNCTION public.protect_roles();