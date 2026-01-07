-- 1. RESOURCE ACCESS FUNCTION
CREATE OR REPLACE FUNCTION public.check_resource_access(
    p_table_name text,
    p_op text,
    p_visibility visibility_mode,
    p_owner_id uuid,
    p_owner_role_id uuid,
    p_tenant_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$ DECLARE
    v_perm_req text;
    v_my_uid uuid;
    v_my_tenant_id uuid;
    v_is_owner boolean;
    v_is_ancestor boolean;
BEGIN
    v_my_uid := auth.uid();
    v_my_tenant_id := (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid;

    IF p_tenant_id IS DISTINCT FROM v_my_tenant_id THEN
        RETURN FALSE;
    END IF;

    v_is_owner := (p_owner_id = v_my_uid);
    v_is_ancestor := public.is_subordinate(p_owner_role_id);
    v_perm_req := 'public.' || p_table_name || ':' || p_op;

    -- TIER 1: PUBLIC ACCESS (Permission Required)
    IF p_visibility = 'PUBLIC' THEN
        RETURN public.has_permission(v_perm_req);
    END IF;

    -- TIER 2: PRIVATE / CONTROLLED (Ownership or Hierarchy Required)
    IF p_visibility IN ('PRIVATE', 'CONTROLLED') THEN
        IF v_is_owner THEN RETURN TRUE; END IF;
        IF v_is_ancestor THEN RETURN TRUE; END IF;
    END IF;

    -- TIER 3: CONTROLLED FALLBACK (Read-only for generic permission holders)
    IF p_visibility = 'CONTROLLED' AND p_op = 'select' THEN
        IF public.has_permission(v_perm_req) THEN RETURN TRUE; END IF;
    END IF;

    RETURN FALSE;
END;
 $$;

-- 2. FILE INFRASTRUCTURE

-- A Polymorphic View that maps files to their owning resources.
-- SCALABILITY: To add support for 'invoices' or 'contracts', simply add a 
-- 'UNION ALL' block for that table here. No Policies need to change.
CREATE OR REPLACE VIEW public.v_file_resources AS
    SELECT 
        'deals'::text as resource_table,
        d.id as resource_id,
        d.tenant_id,
        d.owner_id,
        d.owner_role_id,
        d.visibility,
        d.file_path
    FROM public.deals d
    WHERE d.file_path IS NOT NULL
    
    -- EXAMPLE FOR FUTURE EXPANSION:
    -- UNION ALL
    -- SELECT 
    --     'invoices'::text,
    --     i.id, i.tenant_id, i.owner_id, i.owner_role_id, i.visibility, i.file_path
    -- FROM public.invoices i
    -- WHERE i.file_path IS NOT NULL
;

-- A generic checker that delegates to the main security function.
-- It looks up the file in the View, finds the table, and runs the security check.
CREATE OR REPLACE FUNCTION public.check_generic_file_access(p_path text, p_op text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$ DECLARE
    v_rec record;
BEGIN
    -- Find the resource owning this file
    SELECT * INTO v_rec 
    FROM public.v_file_resources 
    WHERE file_path = p_path;

    -- If no database record owns the file, access is DENIED (Prevents Zombie Files)
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- Delegate to the standard resource access logic
    RETURN public.check_resource_access(
        v_rec.resource_table,
        p_op,
        v_rec.visibility,
        v_rec.owner_id,
        v_rec.owner_role_id,
        v_rec.tenant_id
    );
END;
 $$;

-- 3. ENABLE RLS ON TABLES
ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hierarchy ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invitations ENABLE ROW LEVEL SECURITY;

-- 4. TABLE LEVEL POLICIES
-- TENANTS
CREATE POLICY "Tenants: Read Own" ON public.tenants 
FOR SELECT USING (id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);

-- PROFILES
CREATE POLICY "Profiles: Read Tenant" ON public.profiles FOR SELECT USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);
CREATE POLICY "Profiles: Insert" ON public.profiles FOR INSERT WITH CHECK (
    tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid 
    AND public.has_permission('public.profiles:insert')
);
CREATE POLICY "Profiles: Update Self" ON public.profiles FOR UPDATE USING (id = auth.uid());
CREATE POLICY "Profiles: Update Subordinate" ON public.profiles FOR UPDATE USING (
    tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid 
    AND public.has_permission('public.profiles:update')
    AND public.is_subordinate(role_id)
);
CREATE POLICY "Profiles: Delete" ON public.profiles FOR DELETE USING (
    tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid 
    AND public.has_permission('public.profiles:delete')
    AND public.is_subordinate(role_id)
);

-- ROLES
CREATE POLICY "Roles: Read Tenant" ON public.roles FOR SELECT USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);
CREATE POLICY "Roles: Manage" ON public.roles FOR ALL USING (
    tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid
    AND public.has_permission('public.roles:update')
);

-- HIERARCHY
CREATE POLICY "Hierarchy: Read Tenant" ON public.hierarchy FOR SELECT USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);
CREATE POLICY "Hierarchy: Owner Manage" ON public.hierarchy FOR ALL 
USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid AND public.is_tenant_owner()) 
WITH CHECK (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid AND public.is_tenant_owner());

-- DEALS
CREATE POLICY "Deals: Select" ON public.deals FOR SELECT USING (public.check_resource_access('deals', 'select', visibility, owner_id, owner_role_id, tenant_id));
CREATE POLICY "Deals: Insert" ON public.deals FOR INSERT WITH CHECK (public.check_resource_access('deals', 'insert', visibility, owner_id, owner_role_id, tenant_id));
CREATE POLICY "Deals: Update" ON public.deals FOR UPDATE USING (public.check_resource_access('deals', 'update', visibility, owner_id, owner_role_id, tenant_id));
CREATE POLICY "Deals: Delete" ON public.deals FOR DELETE USING (public.check_resource_access('deals', 'delete', visibility, owner_id, owner_role_id, tenant_id));

-- INVITATIONS
CREATE POLICY "Invitations: Select" ON public.invitations FOR SELECT 
USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid);

CREATE POLICY "Invitations: Insert" ON public.invitations FOR INSERT 
WITH CHECK (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid AND public.has_permission('public.invitations:insert'));

CREATE POLICY "Invitations: Update" ON public.invitations FOR UPDATE
USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid AND status = 'pending' AND public.has_permission('public.invitations:update'))
WITH CHECK (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid AND status = 'pending');

CREATE POLICY "Invitations: Delete" ON public.invitations FOR DELETE
USING (tenant_id = (auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid AND status = 'pending' AND public.has_permission('public.invitations:delete'));

-- 5. STORAGE BUCKET POLICIES (Scalable & Secure)
CREATE POLICY "Storage: Download" ON storage.objects FOR SELECT
USING (
    bucket_id = 'deals' 
    AND public.check_generic_file_access(storage.objects.name, 'select')
);

CREATE POLICY "Storage: Upload" ON storage.objects FOR INSERT
WITH CHECK (
    bucket_id = 'deals'
    AND public.has_permission('public.deals:insert')
);