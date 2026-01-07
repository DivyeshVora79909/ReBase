-- Phase 3: Hierarchy Logic (The DAG)

BEGIN;

-- Setup: Create a Tenant and some roles
SELECT tests.clear_mock_user();

DO $$
DECLARE
    v_tenant_info jsonb;
    v_tenant_id uuid;
    v_owner_role_id uuid;
    v_manager_role_id uuid;
    v_staff_role_id uuid;
    v_tenant_b_info jsonb;
    v_tenant_b_id uuid;
    v_role_b_id uuid;
BEGIN
    v_tenant_info := public.provision_new_tenant('Hierarchy Corp', 'hierarchy');
    v_tenant_id := (v_tenant_info->>'tenant_id')::uuid;
    v_owner_role_id := (v_tenant_info->>'owner_role_id')::uuid;

    RAISE NOTICE '--- Test 3.1: Create Valid Link ---';
    -- Create Manager Role
    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Manager', ARRAY['public.deals:select'])
    RETURNING id INTO v_manager_role_id;

    -- Link Owner -> Manager
    INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id)
    VALUES (v_tenant_id, v_owner_role_id, v_manager_role_id);

    PERFORM tests.assert_true(EXISTS(
        SELECT 1 FROM public.hierarchy 
        WHERE parent_role_id = v_owner_role_id AND child_role_id = v_manager_role_id
    ), 'Valid link should be created');

    RAISE NOTICE '--- Test 3.2: Root Lock (Owner cannot have parent) ---';
    BEGIN
        INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id)
        VALUES (v_tenant_id, v_manager_role_id, v_owner_role_id);
        RAISE EXCEPTION 'Should have failed: Root role cannot have a parent';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'Tenant Owner role cannot be a subordinate', 'Root lock enforced: ' || SQLERRM);
    END;

    RAISE NOTICE '--- Test 3.3: Immediate Cycle ---';
    BEGIN
        INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id)
        VALUES (v_tenant_id, v_manager_role_id, v_manager_role_id);
        RAISE EXCEPTION 'Should have failed: Immediate cycle';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'Hierarchy Cycle Detected', 'Immediate cycle prevented: ' || SQLERRM);
    END;

    RAISE NOTICE '--- Test 3.4: Deep Cycle ---';
    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_id, 'Staff', ARRAY['public.deals:select'])
    RETURNING id INTO v_staff_role_id;

    -- Manager -> Staff
    INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id)
    VALUES (v_tenant_id, v_manager_role_id, v_staff_role_id);

    -- Try Staff -> Manager (Cycle)
    BEGIN
        INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id)
        VALUES (v_tenant_id, v_staff_role_id, v_manager_role_id);
        RAISE EXCEPTION 'Should have failed: Deep cycle';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'Hierarchy Cycle Detected', 'Deep cycle prevented: ' || SQLERRM);
    END;

    RAISE NOTICE '--- Test 3.5: Cross-Tenant Link ---';
    v_tenant_b_info := public.provision_new_tenant('Tenant B', 'tenant-b');
    v_tenant_b_id := (v_tenant_b_info->>'tenant_id')::uuid;
    
    -- Create a regular role in Tenant B
    INSERT INTO public.roles (tenant_id, name, permissions)
    VALUES (v_tenant_b_id, 'Manager B', ARRAY['public.deals:select'])
    RETURNING id INTO v_role_b_id;

    BEGIN
        INSERT INTO public.hierarchy (tenant_id, parent_role_id, child_role_id)
        VALUES (v_tenant_id, v_manager_role_id, v_role_b_id);
        RAISE EXCEPTION 'Should have failed: Cross-tenant link';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'Cannot link roles from different tenants', 'Cross-tenant link prevented: ' || SQLERRM);
    END;

END $$;

ROLLBACK;
