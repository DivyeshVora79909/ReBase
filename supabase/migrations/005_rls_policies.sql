-- 1. RESOURCE ACCESS FUNCTION
CREATE OR REPLACE FUNCTION public.check_resource_access(
    p_table_name text,
    p_op text,
    p_visibility visibility_mode,
    p_owner_id uuid,
    p_owner_role_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$ DECLARE
    v_perm_req text;
    v_my_uid uuid;
    v_is_owner boolean;
    v_is_ancestor boolean;
BEGIN
    v_my_uid := auth.uid();
    v_is_owner := (p_owner_id = v_my_uid);
    v_is_ancestor := public.is_subordinate(p_owner_role_id);
    v_perm_req := 'public.' || p_table_name || ':' || p_op;

    -- TIER 1: PUBLIC + PERMISSION
    IF p_visibility = 'PUBLIC' THEN
        RETURN public.has_permission(v_perm_req);
    END IF;

    -- TIER 2: PRIVATE / CONTROLLED (Ownership or Hierarchy)
    IF p_visibility IN ('PRIVATE', 'CONTROLLED') THEN
        IF v_is_owner THEN RETURN TRUE; END IF;
        IF v_is_ancestor THEN RETURN TRUE; END IF;
    END IF;

    -- TIER 3: CONTROLLED Select Ops Checks
    IF p_visibility = 'CONTROLLED' AND p_op = 'select' THEN
        IF public.has_permission(v_perm_req) THEN RETURN TRUE; END IF;
    END IF;

    RETURN FALSE;
END;
 $$;

-- ENABLE RLS
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hierarchy ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;

-- 1. TENANT POLICIES
CREATE POLICY "Tenants: Read Own" ON public.tenants FOR SELECT USING (id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);

-- 2. PROFILES POLICIES
CREATE POLICY "Profiles: Read Tenant" ON public.profiles FOR SELECT USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);
CREATE POLICY "Profiles: Update Self" ON public.profiles FOR UPDATE USING (id = auth.uid());

-- 3. ROLES POLICIES
CREATE POLICY "Roles: Read Tenant" ON public.roles FOR SELECT USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);
CREATE POLICY "Roles: Manage" ON public.roles FOR ALL USING (public.has_permission('public.roles:update'));

-- 4. HIERARCHY POLICIES
CREATE POLICY "Hierarchy: Read Tenant" ON public.hierarchy FOR SELECT USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);
CREATE POLICY "Hierarchy: Manage" ON public.hierarchy FOR ALL USING (public.has_permission('public.roles:update'));

-- 5. DEALS POLICIES
CREATE POLICY "Deals: Select" ON public.deals FOR SELECT USING (public.check_resource_access('deals', 'select', visibility, owner_id, owner_role_id));
CREATE POLICY "Deals: Insert" ON public.deals FOR INSERT WITH CHECK (public.check_resource_access('deals', 'insert', visibility, owner_id, owner_role_id));
CREATE POLICY "Deals: Update" ON public.deals FOR UPDATE USING (public.check_resource_access('deals', 'update', visibility, owner_id, owner_role_id));
CREATE POLICY "Deals: Delete" ON public.deals FOR DELETE USING (public.check_resource_access('deals', 'delete', visibility, owner_id, owner_role_id));

-- 6. STORAGE POLICIES
CREATE POLICY "Storage: Download" ON storage.objects FOR SELECT
USING (
    bucket_id = 'deals' 
    AND EXISTS (
        SELECT 1 FROM public.deals 
        WHERE file_path = storage.objects.name 
        AND public.check_resource_access('deals', 'select', visibility, owner_id, owner_role_id)
    )
);
CREATE POLICY "Storage: Upload" ON storage.objects FOR INSERT WITH CHECK (bucket_id = 'deals');