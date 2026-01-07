-- Phase 4: Role & Permission Management

BEGIN;

-- Setup: Create a Tenant and an Owner
SELECT tests.clear_mock_user();

DO $$
DECLARE
    v_tenant_info jsonb;
    v_tenant_id uuid;
    v_owner_role_id uuid;
    v_owner_id uuid := gen_random_uuid();
    v_manager_role_id uuid;
    v_tenant_b_info jsonb;
    v_tenant_b_id uuid;
    v_role_b_id uuid;
    v_staff_id uuid := gen_random_uuid();
    v_other_role_id uuid;
    v_row_count int;
BEGIN
    v_tenant_info := public.provision_new_tenant('Role Corp', 'role-corp');
    v_tenant_id := (v_tenant_info->>'tenant_id')::uuid;
    v_owner_role_id := (v_tenant_info->>'owner_role_id')::uuid;

    -- Create Owner in auth.users to satisfy FKs
    INSERT INTO auth.users (id, email, instance_id)
    VALUES (v_owner_id, 'owner@example.com', '00000000-0000-0000-0000-000000000000');

    RAISE NOTICE '--- Test 4.1: Permission Granting (Valid) ---';
    -- Mock Owner A
    PERFORM tests.set_mock_user(v_owner_id, v_tenant_id, v_owner_role_id, 'Tenant Owner', ARRAY[
        'public.tenants:select',
        'public.roles:select',
        'public.roles:insert',
        'public.roles:update',
        'public.roles:delete',
        'public.profiles:select',
        'public.profiles:insert',
        'public.profiles:update',
        'public.profiles:delete',
        'public.deals:select'
    ]);

    -- Create Manager Role with a subset of permissions
    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Manager', ARRAY['public.deals:select'])
    RETURNING id INTO v_manager_role_id;

    PERFORM tests.assert_true(v_manager_role_id IS NOT NULL, 'Owner should be able to create a role with their permissions');

    RAISE NOTICE '--- Test 4.1b: Permission Granting (Invalid - Escalation) ---';
    -- Owner tries to grant a permission they DON'T have (e.g., 'public.tenants:delete')
    BEGIN
        INSERT INTO public.roles (tenant_id, name, permissions)
        VALUES (v_tenant_id, 'Super Manager', ARRAY['public.tenants:delete']);
        RAISE EXCEPTION 'Should have failed: Cannot grant permissions you do not possess';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'Security Violation: You cannot grant permissions you do not possess', 'Escalation prevented: ' || SQLERRM);
    END;

    RAISE NOTICE '--- Test 4.2: Role Update Scope (Cross-Tenant) ---';
    PERFORM tests.clear_mock_user();
    v_tenant_b_info := public.provision_new_tenant('Tenant B', 'tenant-b');
    v_tenant_b_id := (v_tenant_b_info->>'tenant_id')::uuid;
    v_role_b_id := (v_tenant_b_info->>'owner_role_id')::uuid;

    -- Re-mock Owner A
    PERFORM tests.set_mock_user(v_owner_id, v_tenant_id, v_owner_role_id, 'Tenant Owner', ARRAY[
        'public.tenants:select',
        'public.roles:select',
        'public.roles:insert',
        'public.roles:update',
        'public.roles:delete',
        'public.profiles:select',
        'public.profiles:insert',
        'public.profiles:update',
        'public.profiles:delete',
        'public.deals:select'
    ]);

    -- Switch to authenticated role to test RLS
    SET ROLE authenticated;

    -- Owner A tries to update Role B
    UPDATE public.roles SET name = 'Hacked' WHERE id = v_role_b_id;
    
    -- Check if update was blocked (0 rows affected)
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    PERFORM tests.assert_equals(0::int, v_row_count, 'Cross-tenant role update should be prevented by RLS');

    -- Switch back to postgres for next steps
    RESET ROLE;

    RAISE NOTICE '--- Test 4.3: Assigning Roles (Valid Subordinate) ---';
    -- Link Owner -> Manager
    INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id)
    VALUES (v_tenant_id, v_owner_role_id, v_manager_role_id);

    -- Update mock user to include Manager as descendant
    PERFORM tests.set_mock_user(v_owner_id, v_tenant_id, v_owner_role_id, 'Tenant Owner', 
        ARRAY[
            'public.tenants:select',
            'public.roles:select',
            'public.roles:insert',
            'public.roles:update',
            'public.roles:delete',
            'public.profiles:select',
            'public.profiles:insert',
            'public.profiles:update',
            'public.profiles:delete',
            'public.deals:select'
        ], 
        ARRAY[v_manager_role_id]
    );

    -- Create a pending invitation (as postgres)
    INSERT INTO public.invitations (tenant_id, email, target_role_id, invited_by, status)
    VALUES (v_tenant_id, 'staff@example.com', v_manager_role_id, v_owner_id, 'pending');

    -- Create a dummy user in auth.users to satisfy FK (as postgres)
    -- This will trigger handle_new_user_onboarding and create the profile
    INSERT INTO auth.users (id, email, instance_id, raw_user_meta_data)
    VALUES (v_staff_id, 'staff@example.com', '00000000-0000-0000-0000-000000000000', '{"first_name": "Staff", "last_name": "User"}'::jsonb);

    -- Switch to authenticated role
    SET ROLE authenticated;

    -- Verify profile was created
    PERFORM tests.assert_true(EXISTS(
        SELECT 1 FROM public.profiles WHERE id = v_staff_id AND role_id = v_manager_role_id
    ), 'Profile should be created via onboarding trigger');

    -- Now test MANUAL update of role_id (Assignment)
    -- Create another subordinate role
    RESET ROLE;
    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Junior', ARRAY['public.deals:select'])
    RETURNING id INTO v_other_role_id;
    
    -- Link Manager -> Junior
    INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id)
    VALUES (v_tenant_id, v_manager_role_id, v_other_role_id);

    -- Update mock user to include Junior as descendant
    PERFORM tests.set_mock_user(v_owner_id, v_tenant_id, v_owner_role_id, 'Tenant Owner', 
        ARRAY[
            'public.tenants:select',
            'public.roles:select',
            'public.roles:insert',
            'public.roles:update',
            'public.roles:delete',
            'public.profiles:select',
            'public.profiles:insert',
            'public.profiles:update',
            'public.profiles:delete',
            'public.deals:select'
        ], 
        ARRAY[v_manager_role_id, v_other_role_id]
    );

    SET ROLE authenticated;
    UPDATE public.profiles SET role_id = v_other_role_id WHERE id = v_staff_id;

    PERFORM tests.assert_true(EXISTS(
        SELECT 1 FROM public.profiles WHERE id = v_staff_id AND role_id = v_other_role_id
    ), 'Owner should be able to update a subordinate role');

    RESET ROLE;

    RAISE NOTICE '--- Test 4.3b: Assigning Roles (Invalid - Non-Subordinate) ---';
    -- Create a role that is NOT a subordinate
    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Independent', ARRAY['public.deals:select'])
    RETURNING id INTO v_other_role_id;

    -- Switch to authenticated role
    SET ROLE authenticated;

    -- Try to assign Independent role
    BEGIN
        INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name)
        VALUES (gen_random_uuid(), v_tenant_id, v_other_role_id, 'Staff', 'User');
        RAISE EXCEPTION 'Should have failed: Cannot assign non-subordinate role';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'Security Violation: You cannot assign a role that is not your subordinate', 'Unauthorized role assignment prevented: ' || SQLERRM);
    END;

    RESET ROLE;

END $$;

ROLLBACK;
