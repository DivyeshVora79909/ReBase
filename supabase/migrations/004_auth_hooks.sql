-- 1. CUSTOM ACCESS TOKEN HOOK (Tenant Isolated)
CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$ DECLARE
    v_user_id uuid;
    v_tenant_id uuid;
    v_role_id uuid;
    v_role_name text;
    v_role_perms text[];
    v_claims jsonb;
    v_descendants jsonb;
BEGIN
    v_user_id := (event ->> 'user_id')::uuid;
    v_claims := COALESCE(event -> 'claims', '{}'::jsonb);

    -- Fetch Basic Role Info
    SELECT p.tenant_id, p.role_id, r.name, r.permissions
    INTO v_tenant_id, v_role_id, v_role_name, v_role_perms
    FROM public.profiles p
    JOIN public.roles r ON p.role_id = r.id
    WHERE p.id = v_user_id;

    IF v_tenant_id IS NULL THEN RETURN event; END IF;

    -- Fetch Descendants using Recursive CTE (Explicitly Tenant Scoped)
    SELECT jsonb_agg(id) INTO v_descendants
    FROM (
        WITH RECURSIVE subtree AS (
            SELECT r.id 
            FROM public.roles r
            JOIN public.hierarchy h ON r.id = h.child_role_id
            WHERE h.parent_role_id = v_role_id
            AND h.tenant_id = v_tenant_id
            UNION ALL
            SELECT r.id 
            FROM public.roles r
            JOIN public.hierarchy h ON r.id = h.child_role_id
            JOIN subtree s ON h.parent_role_id = s.id
            WHERE h.tenant_id = v_tenant_id
        )
        SELECT id FROM subtree
    ) sub;

    v_claims := jsonb_set(v_claims, '{app_metadata}', COALESCE(v_claims -> 'app_metadata', '{}'::jsonb));
    v_claims := jsonb_set(v_claims, '{app_metadata,role}', jsonb_build_object(
        'id', v_role_id,
        'name', v_role_name,
        'permissions', to_jsonb(v_role_perms)
    ));
    v_claims := jsonb_set(v_claims, '{app_metadata,descendants}', COALESCE(v_descendants, '[]'::jsonb));
    v_claims := jsonb_set(v_claims, '{app_metadata,tenant_id}', to_jsonb(v_tenant_id));

    return jsonb_set(event, '{claims}', v_claims);
END;
 $$;