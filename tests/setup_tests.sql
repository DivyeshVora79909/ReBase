-- Helper functions for testing ReBase security and logic

-- 1. Function to simulate a user session by setting JWT claims in the transaction local config
CREATE OR REPLACE FUNCTION tests.set_mock_user(
    p_user_id uuid,
    p_tenant_id uuid,
    p_role_id uuid,
    p_role_name text,
    p_permissions text[],
    p_descendants uuid[] DEFAULT '{}'
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_jwt jsonb;
BEGIN
    v_jwt := jsonb_build_object(
        'sub', p_user_id,
        'role', 'authenticated',
        'app_metadata', jsonb_build_object(
            'tenant_id', p_tenant_id,
            'role', jsonb_build_object(
                'id', p_role_id,
                'name', p_role_name,
                'permissions', to_jsonb(p_permissions)
            ),
            'descendants', to_jsonb(p_descendants)
        )
    );
    PERFORM set_config('request.jwt.claims', v_jwt::text, true);
END;
$$;

-- 2. Function to clear mock user session
CREATE OR REPLACE FUNCTION tests.clear_mock_user()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM set_config('request.jwt.claims', NULL, true);
END;
$$;

-- 3. Function to run a test and report result
CREATE OR REPLACE FUNCTION tests.assert_true(p_condition boolean, p_message text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT p_condition THEN
        RAISE EXCEPTION 'Assertion Failed: %', p_message;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION tests.assert_equals(p_actual anyelement, p_expected anyelement, p_message text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_actual IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'Assertion Failed: %. Expected %, got %', p_message, p_expected, p_actual;
    END IF;
END;
$$;

GRANT USAGE ON SCHEMA tests TO public;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA tests TO public;
