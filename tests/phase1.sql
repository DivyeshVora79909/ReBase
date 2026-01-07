-- Phase 1: Tenant Provisioning (Admin Scope)

DO $$
DECLARE
    v_result jsonb;
    v_tenant_id uuid;
    v_owner_role_id uuid;
    v_role_record record;
BEGIN
    -- 1.1 Admin Provisioning (Service Role)
    -- Simulate service_role
    SET ROLE service_role;
    v_result := public.provision_new_tenant('Acme', 'acme');
    v_tenant_id := (v_result->>'tenant_id')::uuid;
    v_owner_role_id := (v_result->>'owner_role_id')::uuid;
    
    PERFORM tests.assert_true(v_tenant_id IS NOT NULL, 'Tenant ID should not be null');
    PERFORM tests.assert_true(v_owner_role_id IS NOT NULL, 'Owner Role ID should not be null');
    RAISE NOTICE 'Test 1.1 Passed: Admin Provisioning Success';

    -- 1.4 Owner Role Integrity
    SELECT * INTO v_role_record FROM public.roles WHERE id = v_owner_role_id;
    PERFORM tests.assert_equals(v_role_record.name, 'Tenant Owner', 'Role name should be Tenant Owner');
    PERFORM tests.assert_equals(v_role_record.tenant_id, v_tenant_id, 'Role tenant_id should match');
    -- Check permissions (hardcoded list in migration 006)
    PERFORM tests.assert_true('public.deals:select' = ANY(v_role_record.permissions), 'Should have deals:select permission');
    RAISE NOTICE 'Test 1.4 Passed: Owner Role Integrity Success';

    -- 1.2 Unauthorized Provisioning (Authenticated User)
    SET ROLE authenticated;
    BEGIN
        PERFORM public.provision_new_tenant('Fail', 'fail');
        RAISE EXCEPTION 'Test 1.2 Failed: Authenticated user should not be able to provision tenant';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'Test 1.2 Passed: Unauthorized Provisioning (Authenticated) Denied';
    END;

    -- 1.3 Anon Provisioning (Anon Key)
    SET ROLE anon;
    BEGIN
        PERFORM public.provision_new_tenant('Fail', 'fail');
        RAISE EXCEPTION 'Test 1.3 Failed: Anon user should not be able to provision tenant';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'Test 1.3 Passed: Unauthorized Provisioning (Anon) Denied';
    END;

    -- Reset role
    RESET ROLE;
END;
$$;
