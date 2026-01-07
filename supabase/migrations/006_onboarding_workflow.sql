-- 1. AUTOMATIC PROFILE CREATION TRIGGER
CREATE OR REPLACE FUNCTION public.handle_new_user_onboarding()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$ DECLARE
    v_invite_record public.invitations%ROWTYPE;
BEGIN
    IF public.is_admin() THEN
        RETURN NEW;
    END IF;

    SELECT * INTO v_invite_record
    FROM public.invitations
    WHERE email = NEW.email
    AND status = 'pending'
    LIMIT 1;

    IF v_invite_record IS NULL THEN
        RAISE EXCEPTION 'Signup Error: No pending invitation found for this email address.';
    END IF;

    -- 1. Create the Profile
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name)
    VALUES (
        NEW.id,
        v_invite_record.tenant_id,
        v_invite_record.target_role_id,
        (NEW.raw_user_meta_data->>'first_name'),
        (NEW.raw_user_meta_data->>'last_name')
    );

    -- 2. Mark Invitation as Accepted
    UPDATE public.invitations 
    SET status = 'accepted', updated_at = now()
    WHERE id = v_invite_record.id;

    RETURN NEW;
END;
 $$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.handle_new_user_onboarding();

-- 2. Provision Tenant
CREATE OR REPLACE FUNCTION public.provision_new_tenant(
    p_tenant_name text,
    p_tenant_slug text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_tenant_id uuid;
    v_role_id uuid;
    v_all_permissions text[];
BEGIN
    v_all_permissions := ARRAY[
        -- Tenants
        'public.tenants:select',
        'public.tenants:update',
        
        -- Roles
        'public.roles:select', 
        'public.roles:insert', 
        'public.roles:update', 
        'public.roles:delete',
        
        -- Profiles
        'public.profiles:select', 
        'public.profiles:insert', 
        'public.profiles:update',
        'public.profiles:delete',
        
        -- Hierarchy
        'public.hierarchy:select', 
        'public.hierarchy:manage', 
        
        -- Invitations
        'public.invitations:select', 
        'public.invitations:insert', 
        'public.invitations:update', 
        'public.invitations:delete',
        
        -- Deals
        'public.deals:select', 
        'public.deals:insert', 
        'public.deals:update', 
        'public.deals:delete'
    ];

    INSERT INTO public.tenants (name, slug)
    VALUES (p_tenant_name, p_tenant_slug)
    RETURNING id INTO v_tenant_id;

    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Tenant Owner', v_all_permissions)
    RETURNING id INTO v_role_id;

    RETURN jsonb_build_object(
        'tenant_id', v_tenant_id,
        'tenant_name', p_tenant_name,
        'owner_role_id', v_role_id,
        'message', 'Tenant and Owner Role provisioned successfully.'
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION public.provision_new_tenant(text, text) FROM public;
REVOKE EXECUTE ON FUNCTION public.provision_new_tenant(text, text) FROM anon;
REVOKE EXECUTE ON FUNCTION public.provision_new_tenant(text, text) FROM authenticated;

GRANT EXECUTE ON FUNCTION public.provision_new_tenant(text, text) TO service_role;