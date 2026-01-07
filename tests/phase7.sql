-- Phase 7: Storage Security

BEGIN;

-- Setup: Create Tenant, Roles, Users, and Deals
SELECT tests.clear_mock_user();

DO $$
DECLARE
    v_tenant_info jsonb;
    v_tenant_id uuid;
    v_owner_role_id uuid;
    v_staff_role_id uuid;
    
    v_owner_id uuid := gen_random_uuid();
    v_staff_id uuid := gen_random_uuid();
    v_other_staff_id uuid := gen_random_uuid();
    
    v_deal_private_id uuid := gen_random_uuid();
    v_deal_public_id uuid := gen_random_uuid();
    
    v_file_private_path text := 'private_deal.pdf';
    v_file_public_path text := 'public_deal.pdf';
    v_file_zombie_path text := 'zombie.pdf';
BEGIN
    -- Provision Tenant
    v_tenant_info := public.provision_new_tenant('Storage Corp', 'storage');
    v_tenant_id := (v_tenant_info->>'tenant_id')::uuid;
    v_owner_role_id := (v_tenant_info->>'owner_role_id')::uuid;

    -- Create Staff Role
    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Staff', ARRAY['public.deals:select', 'public.deals:insert'])
    RETURNING id INTO v_staff_role_id;

    -- Link Hierarchy: Owner -> Staff
    INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id) VALUES (v_tenant_id, v_owner_role_id, v_staff_role_id);

    -- Create Users & Profiles
    INSERT INTO auth.users (id, email, instance_id) VALUES (v_owner_id, 'owner@storage.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_owner_id, v_tenant_id, v_owner_role_id, 'Owner', 'User');

    INSERT INTO auth.users (id, email, instance_id) VALUES (v_staff_id, 'staff@storage.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_staff_id, v_tenant_id, v_staff_role_id, 'Staff', 'User');

    INSERT INTO auth.users (id, email, instance_id) VALUES (v_other_staff_id, 'other@storage.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_other_staff_id, v_tenant_id, v_staff_role_id, 'Other', 'Staff');

    -- Create Deals with files
    INSERT INTO public.deals (id, tenant_id, owner_id, owner_role_id, title, visibility, file_path)
    VALUES (v_deal_private_id, v_tenant_id, v_staff_id, v_staff_role_id, 'Private Deal', 'PRIVATE', v_file_private_path);

    INSERT INTO public.deals (id, tenant_id, owner_id, owner_role_id, title, visibility, file_path)
    VALUES (v_deal_public_id, v_tenant_id, v_staff_id, v_staff_role_id, 'Public Deal', 'PUBLIC', v_file_public_path);

    -- Mock Storage Objects (in storage.objects table)
    -- Note: We can't easily mock the physical file, but we can mock the metadata that RLS checks.
    INSERT INTO storage.objects (bucket_id, name, owner, metadata)
    VALUES ('deals', v_file_private_path, v_staff_id, '{"mimetype": "application/pdf"}'::jsonb);

    INSERT INTO storage.objects (bucket_id, name, owner, metadata)
    VALUES ('deals', v_file_public_path, v_staff_id, '{"mimetype": "application/pdf"}'::jsonb);

    INSERT INTO storage.objects (bucket_id, name, owner, metadata)
    VALUES ('deals', v_file_zombie_path, v_staff_id, '{"mimetype": "application/pdf"}'::jsonb);

    RAISE NOTICE '--- Test 7.1: Private File Access (Owner) ---';
    PERFORM tests.set_mock_user(v_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(EXISTS(SELECT 1 FROM storage.objects WHERE name = v_file_private_path), 'Staff should see their own private deal file');
    RESET ROLE;

    RAISE NOTICE '--- Test 7.2: Private File Access (Peer - Denied) ---';
    PERFORM tests.set_mock_user(v_other_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(NOT EXISTS(SELECT 1 FROM storage.objects WHERE name = v_file_private_path), 'Peer should NOT see private deal file');
    RESET ROLE;

    RAISE NOTICE '--- Test 7.3: Public File Access (Peer - Allowed) ---';
    PERFORM tests.set_mock_user(v_other_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(EXISTS(SELECT 1 FROM storage.objects WHERE name = v_file_public_path), 'Peer should see public deal file');
    RESET ROLE;

    RAISE NOTICE '--- Test 7.4: Zombie File Prevention (Denied) ---';
    -- Zombie file exists in storage.objects but is NOT linked in public.deals
    PERFORM tests.set_mock_user(v_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    PERFORM tests.assert_true(NOT EXISTS(SELECT 1 FROM storage.objects WHERE name = v_file_zombie_path), 'Zombie file should be invisible even to owner if not linked to a resource');
    RESET ROLE;

    RAISE NOTICE '--- Test 7.5: Unauthorized Upload (Denied) ---';
    -- User without public.deals:insert permission tries to upload
    PERFORM tests.set_mock_user(v_other_staff_id, v_tenant_id, v_staff_role_id, 'Staff', ARRAY['public.deals:select']);
    SET ROLE authenticated;
    BEGIN
        INSERT INTO storage.objects (bucket_id, name, owner)
        VALUES ('deals', 'hack.pdf', v_other_staff_id);
        RAISE EXCEPTION 'Should have failed: Unauthorized upload';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'new row violates row-level security policy', 'Unauthorized upload prevented: ' || SQLERRM);
    END;
    RESET ROLE;

END $$;

ROLLBACK;
