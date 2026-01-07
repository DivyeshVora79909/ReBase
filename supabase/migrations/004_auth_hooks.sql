-- 1. HANDLE NEW USER (Stateless Token Onboarding)
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$ BEGIN
    IF NEW.raw_user_meta_data ? 'tenant_id' AND NEW.raw_user_meta_data ? 'role_id' THEN
        INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name)
        VALUES (
            NEW.id,
            (NEW.raw_user_meta_data ->> 'tenant_id')::uuid,
            (NEW.raw_user_meta_data ->> 'role_id')::uuid,
            NEW.raw_user_meta_data ->> 'first_name',
            NEW.raw_user_meta_data ->> 'last_name'
        );
    ELSE
        RAISE EXCEPTION 'Registration Failed: Missing tenant or role assignment metadata.';
    END IF;

    RETURN NEW;
END;
 $$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 2. CUSTOM ACCESS TOKEN HOOK
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

    -- Fetch Descendants using Recursive CTE
    SELECT jsonb_agg(id) INTO v_descendants
    FROM (
        WITH RECURSIVE subtree AS (
            SELECT id FROM public.roles WHERE id = v_role_id
            UNION
            SELECT r.id 
            FROM public.roles r
            JOIN public.hierarchy h ON r.id = h.child_role_id
            JOIN subtree s ON h.parent_role_id = s.id
            WHERE r.tenant_id = v_tenant_id
        )
        SELECT id FROM subtree
    ) sub;

    -- Construct App Metadata
    v_claims := jsonb_set(v_claims, '{app_metadata}', COALESCE(v_claims -> 'app_metadata', '{}'::jsonb));
    
    -- Role Object
    v_claims := jsonb_set(v_claims, '{app_metadata,role}', jsonb_build_object(
        'id', v_role_id,
        'name', v_role_name,
        'permissions', to_jsonb(v_role_perms)
    ));

    -- Arrays
    v_claims := jsonb_set(v_claims, '{app_metadata,descendants}', COALESCE(v_descendants, '[]'::jsonb));
    v_claims := jsonb_set(v_claims, '{app_metadata,tenant_id}', to_jsonb(v_tenant_id));

    return jsonb_set(event, '{claims}', v_claims);
END;
 $$;