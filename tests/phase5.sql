-- Phase 5: Data Isolation

BEGIN;

-- Setup: Create two tenants and users
SELECT tests.clear_mock_user();

DO $$
DECLARE
    v_tenant_a_info jsonb;
    v_tenant_a_id uuid;
    v_owner_a_role_id uuid;
    v_owner_a_id uuid := gen_random_uuid();
    
    v_tenant_b_info jsonb;
    v_tenant_b_id uuid;
    v_owner_b_role_id uuid;
    v_owner_b_id uuid := gen_random_uuid();
    
    v_deal_a_id uuid := gen_random_uuid();
    v_deal_b_id uuid := gen_random_uuid();
    v_row_count int;
BEGIN
    -- Provision Tenant A
    v_tenant_a_info := public.provision_new_tenant('Tenant A', 'tenant-a');
    v_tenant_a_id := (v_tenant_a_info->>'tenant_id')::uuid;
    v_owner_a_role_id := (v_tenant_a_info->>'owner_role_id')::uuid;
    INSERT INTO auth.users (id, email, instance_id) VALUES (v_owner_a_id, 'owner_a@example.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_owner_a_id, v_tenant_a_id, v_owner_a_role_id, 'Owner', 'A');

    -- Provision Tenant B
    v_tenant_b_info := public.provision_new_tenant('Tenant B', 'tenant-b');
    v_tenant_b_id := (v_tenant_b_info->>'tenant_id')::uuid;
    v_owner_b_role_id := (v_tenant_b_info->>'owner_role_id')::uuid;
    INSERT INTO auth.users (id, email, instance_id) VALUES (v_owner_b_id, 'owner_b@example.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_owner_b_id, v_tenant_b_id, v_owner_b_role_id, 'Owner', 'B');

    -- Create Deal in Tenant A
    INSERT INTO public.deals (id, tenant_id, owner_id, owner_role_id, title, visibility)
    VALUES (v_deal_a_id, v_tenant_a_id, v_owner_a_id, v_owner_a_role_id, 'Deal A', 'PRIVATE');

    -- Create Deal in Tenant B
    INSERT INTO public.deals (id, tenant_id, owner_id, owner_role_id, title, visibility)
    VALUES (v_deal_b_id, v_tenant_b_id, v_owner_b_id, v_owner_b_role_id, 'Deal B', 'PRIVATE');

    RAISE NOTICE '--- Test 5.1: Cross-Tenant Select (RLS) ---';
    -- Mock Owner A
    PERFORM tests.set_mock_user(v_owner_a_id, v_tenant_a_id, v_owner_a_role_id, 'Tenant Owner', ARRAY['public.deals:select']);
    SET ROLE authenticated;

    -- Should see Deal A
    PERFORM tests.assert_true(EXISTS(SELECT 1 FROM public.deals WHERE id = v_deal_a_id), 'Owner A should see their own deal');
    -- Should NOT see Deal B
    PERFORM tests.assert_true(NOT EXISTS(SELECT 1 FROM public.deals WHERE id = v_deal_b_id), 'Owner A should NOT see Deal B from Tenant B');

    RESET ROLE;

    RAISE NOTICE '--- Test 5.2: Cross-Tenant Insert (RLS/Trigger) ---';
    -- Owner A tries to insert into Tenant B
    SET ROLE authenticated;
    BEGIN
        INSERT INTO public.deals (tenant_id, owner_id, owner_role_id, title, visibility)
        VALUES (v_tenant_b_id, v_owner_a_id, v_owner_a_role_id, 'Hack Deal', 'PRIVATE');
        RAISE EXCEPTION 'Should have failed: Cross-tenant insert';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'Security Violation: Tenant ID mismatch', 'Cross-tenant insert prevented: ' || SQLERRM);
    END;
    RESET ROLE;

    RAISE NOTICE '--- Test 5.3: Cross-Tenant Update (RLS) ---';
    SET ROLE authenticated;
    UPDATE public.deals SET title = 'Hacked' WHERE id = v_deal_b_id;
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    PERFORM tests.assert_equals(0::int, v_row_count, 'Cross-tenant update should be prevented by RLS');
    RESET ROLE;

    RAISE NOTICE '--- Test 5.4: Cross-Tenant Delete (RLS) ---';
    SET ROLE authenticated;
    DELETE FROM public.deals WHERE id = v_deal_b_id;
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    PERFORM tests.assert_equals(0::int, v_row_count, 'Cross-tenant delete should be prevented by RLS');
    RESET ROLE;

END $$;

ROLLBACK;
