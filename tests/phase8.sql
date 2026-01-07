-- Phase 8: Data Integrity Triggers

BEGIN;

-- Setup: Create Tenant, Roles, Users
SELECT tests.clear_mock_user();

DO $$
DECLARE
    v_tenant_info jsonb;
    v_tenant_id uuid;
    v_owner_role_id uuid;
    v_owner_id uuid := gen_random_uuid();
    
    v_deal_id uuid := gen_random_uuid();
    v_deal_record record;
    v_old_updated_at timestamptz;
BEGIN
    -- Provision Tenant
    v_tenant_info := public.provision_new_tenant('Integrity Corp', 'integrity');
    v_tenant_id := (v_tenant_info->>'tenant_id')::uuid;
    v_owner_role_id := (v_tenant_info->>'owner_role_id')::uuid;

    -- Create Owner Profile
    INSERT INTO auth.users (id, email, instance_id) VALUES (v_owner_id, 'owner@integrity.com', '00000000-0000-0000-0000-000000000000');
    INSERT INTO public.profiles (id, tenant_id, role_id, first_name, last_name) VALUES (v_owner_id, v_tenant_id, v_owner_role_id, 'Owner', 'User');

    RAISE NOTICE '--- Test 8.1: Audit Fields (Created By) ---';
    PERFORM tests.set_mock_user(v_owner_id, v_tenant_id, v_owner_role_id, 'Tenant Owner', ARRAY['public.deals:insert', 'public.deals:select', 'public.deals:update']);
    SET ROLE authenticated;

    INSERT INTO public.deals (id, title, visibility)
    VALUES (v_deal_id, 'Audit Deal', 'PRIVATE');

    SELECT * INTO v_deal_record FROM public.deals WHERE id = v_deal_id;
    PERFORM tests.assert_equals(v_owner_id, v_deal_record.owner_id, 'owner_id should be auto-populated');
    PERFORM tests.assert_equals(v_owner_role_id, v_deal_record.owner_role_id, 'owner_role_id should be auto-populated');
    
    v_old_updated_at := v_deal_record.updated_at;

    RAISE NOTICE '--- Test 8.2: UpdatedAt Trigger ---';
    -- Wait a bit to ensure timestamp changes
    PERFORM pg_sleep(0.1);
    
    UPDATE public.deals SET title = 'Updated Deal' WHERE id = v_deal_id;
    
    SELECT * INTO v_deal_record FROM public.deals WHERE id = v_deal_id;
    PERFORM tests.assert_true(v_deal_record.updated_at > v_old_updated_at, 'updated_at should be updated on change');

    RESET ROLE;

    RAISE NOTICE '--- Test 8.3: Role Protection (Delete Linked Role) ---';
    -- Try to delete the Owner Role (which is linked to a profile)
    BEGIN
        DELETE FROM public.roles WHERE id = v_owner_role_id;
        RAISE EXCEPTION 'Should have failed: Cannot delete linked role';
    EXCEPTION WHEN OTHERS THEN
        PERFORM tests.assert_true(SQLERRM ~ 'violates foreign key constraint', 'Role deletion prevented due to profile link: ' || SQLERRM);
    END;

END $$;

ROLLBACK;
