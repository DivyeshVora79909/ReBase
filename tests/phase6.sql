-- Phase 6: Deal Visibility (Resource Access)

BEGIN;

-- Setup: Create Tenant, Roles, and Users
SELECT tests.clear_mock_user();

DO $$
DECLARE
    v_tenant_info jsonb;
    v_tenant_id uuid;
    v_owner_role_id uuid;
    v_manager_role_id uuid;
    v_staff_role_id uuid;
    
    v_owner_id uuid := gen_random_uuid();
    v_manager_id uuid := gen_random_uuid();
    v_staff_id uuid := gen_random_uuid();
    v_other_staff_id uuid := gen_random_uuid();
    
    v_deal_private_id uuid := gen_random_uuid();
    v_deal_controlled_id uuid := gen_random_uuid();
    v_deal_public_id uuid := gen_random_uuid();
BEGIN
    -- Provision Tenant
    v_tenant_info := public.provision_new_tenant('Visibility Corp', 'visibility');
    v_tenant_id := (v_tenant_info->>'tenant_id')::uuid;
    v_owner_role_id := (v_tenant_info->>'owner_role_id')::uuid;

    -- Create Roles
    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Manager', ARRAY['public.deals:select', 'public.deals:insert'])
    RETURNING id INTO v_manager_role_id;

    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Staff', ARRAY['public.deals:select'])
    RETURNING id INTO v_staff_role_id;

    -- Link Hierarchy: Owner -> Manager -> Staff
    INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id) VALUES (v_tenant_id, v_owner_role_id, v_manager_role_id);
    INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id) VALUES (v_tenant_id, v_manager_role_id, v_staff_role_id);

    -- Create Users & Profiles
    INSERT INTO auth.users (id, email, instance_id) VALUES (v_owner_id, 'owner@vis.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_owner_id, v_tenant_id, v_owner_role_id, 'Owner', 'User');

    INSERT INTO auth.users (id, email, instance_id) VALUES (v_manager_id, 'manager@vis.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_manager_id, v_tenant_id, v_manager_role_id, 'Manager', 'User');

    INSERT INTO auth.users (id, email, instance_id) VALUES (v_staff_id, 'staff@vis.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_staff_id, v_tenant_id, v_staff_role_id, 'Staff', 'User');

    INSERT INTO auth.users (id, email, instance_id) VALUES (v_other_staff_id, 'other@vis.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_other_staff_id, v_tenant_id, v_staff_role_id, 'Other', 'Staff');

    -- Create Deals with different visibility
    -- 1. Private Deal owned by Staff
    INSERT INTO public.deals (id, tenant_id, owner_id, owner_role_id, title, visibility)
    VALUES (v_deal_private_id, v_tenant_id, v_staff_id, v_staff_role_id, 'Private Staff Deal', 'PRIVATE');

    -- 2. Controlled Deal owned by Staff
    INSERT INTO public.deals (id, tenant_id, owner_id, owner_role_id, title, visibility)
    VALUES (v_deal_controlled_id, v_tenant_id, v_staff_id, v_staff_role_id, 'Controlled Staff Deal', 'CONTROLLED');

    -- 3. Public Deal owned by Staff
    INSERT INTO public.deals (id, tenant_id, owner_id, owner_role_id, title, visibility)
    VALUES (v_deal_public_id, v_tenant_id, v_staff_id, v_staff_role_id, 'Public Staff Deal', 'PUBLIC');

    RAISE NOTICE '--- Test 6.1: Private Own (Staff sees own private deal) ---';
    PERFORM tests.set_mock_user(v_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(EXISTS(SELECT 1 FROM public.deals WHERE id = v_deal_private_id), 'Staff should see their own private deal');
    RESET ROLE;

    RAISE NOTICE '--- Test 6.2: Private Peer (Staff cannot see peer private deal) ---';
    PERFORM tests.set_mock_user(v_other_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(NOT EXISTS(SELECT 1 FROM public.deals WHERE id = v_deal_private_id), 'Staff should NOT see peer private deal');
    RESET ROLE;

    RAISE NOTICE '--- Test 6.3: Private Manager (Manager sees subordinate private deal) ---';
    PERFORM tests.set_mock_user(v_manager_id, v_tenant_id, v_manager_role_id, 'Manager', ARRAY['public.deals:select'], ARRAY[v_staff_role_id]);
    SET ROLE authenticated;
    PERFORM tests.assert_true(EXISTS(SELECT 1 FROM public.deals WHERE id = v_deal_private_id), 'Manager should see subordinate private deal');
    RESET ROLE;

    RAISE NOTICE '--- Test 6.4: Private Reverse (Staff cannot see manager private deal) ---';
    -- Create private deal for manager
    INSERT INTO public.deals (tenant_id, owner_id, owner_role_id, title, visibility)
    VALUES (v_tenant_id, v_manager_id, v_manager_role_id, 'Manager Private Deal', 'PRIVATE');
    
    PERFORM tests.set_mock_user(v_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(NOT EXISTS(SELECT 1 FROM public.deals WHERE title = 'Manager Private Deal'), 'Staff should NOT see manager private deal');
    RESET ROLE;

    RAISE NOTICE '--- Test 6.5: Controlled Visibility (Peer sees controlled deal if they have permission) ---';
    PERFORM tests.set_mock_user(v_other_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(EXISTS(SELECT 1 FROM public.deals WHERE id = v_deal_controlled_id), 'Peer should see controlled deal with permission');
    RESET ROLE;

    RAISE NOTICE '--- Test 6.6: Public Visibility (Anyone in tenant sees public deal) ---';
    PERFORM tests.set_mock_user(v_other_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(EXISTS(SELECT 1 FROM public.deals WHERE id = v_deal_public_id), 'Peer should see public deal');
    RESET ROLE;

END $$;

ROLLBACK;
