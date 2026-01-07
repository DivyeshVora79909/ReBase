-- 1. AUTOMATIC PROFILE CREATION TRIGGER
CREATE OR REPLACE FUNCTION public.handle_new_user_onboarding()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$ DECLARE
    v_invite_record public.invitations%ROWTYPE;
BEGIN
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