# SupaMax – Supabase Backend

Production‑grade, multi‑tenant Supabase backend with strict RBAC, hierarchical roles, secure storage, and policy‑driven access control.

---

## 1. Overview

SupaMax implements:

- **Multi‑tenancy** (tenant‑isolated data)
- **Hierarchical RBAC** (DAG‑based role tree)
- **JWT‑embedded permissions** (computed at login)
- **Strict RLS everywhere** (Postgres‑first security)
- **Controlled file storage** (Supabase Storage + DB‑backed authorization)

Designed for SaaS systems where **roles, permissions, and ownership matter**.

---

## 2. Architecture

**Core Layers**

- PostgreSQL (schema, RLS, triggers, functions)
- Supabase Auth (email‑invite onboarding)
- Supabase Storage (DB‑verified access)
- JWT Custom Claims (permissions, hierarchy)

**Security Model**

- No trust in frontend
- All access enforced at DB level
- Service Role only for provisioning

---

## 3. Key Concepts

### Tenant

Logical organization boundary. All data is tenant‑scoped.

### Roles

- One **root role** per tenant
- Roles form a **DAG** (not a tree)
- Closure table used for fast hierarchy queries

### Permissions

- Flat permission codes (`dl:c`, `rl:u`, etc.)
- Assigned to roles
- Injected into JWT at login

### Visibility Modes

```text
PRIVATE     → Owner only
CONTROLLED → Owner + subordinate roles
PUBLIC      → Permission‑based
```

---

## 4. Database Schema

### Core Tables

- `tenants`
- `roles`
- `permissions`
- `role_permissions`
- `role_hierarchy`
- `role_closure`
- `profiles`
- `invitations`
- `deals`

### Why Closure Table?

- O(1) permission checks
- Efficient subordinate resolution
- Prevents recursive runtime queries

---

## 5. Authentication Flow

1. User is **invited** (`invitations` table)
2. User signs up via Supabase Auth
3. `handle_new_user` trigger:

   - Validates invitation
   - Creates profile
   - Assigns tenant + role

No invitation → no access.

---

## 6. JWT Custom Claims

Injected via `custom_access_token_hook`:

```json
{
  "tenant_id": "uuid",
  "role_id": "uuid",
  "subordinate_role_ids": ["uuid"],
  "permissions": ["dl:c", "rl:u"]
}
```

Used by:

- RLS policies
- Access control functions

---

## 7. Access Control Engine

Central function:

```sql
check_resource_access(
  tenant_id,
  visibility,
  owner_id,
  owner_role_id,
  prefix,
  operation
)
```

Controls:

- SELECT / INSERT / UPDATE / DELETE
- Ownership
- Role hierarchy
- Explicit permissions

No duplicated logic in policies.

---

## 8. Row Level Security (RLS)

Enabled on **all tables**.

Examples:

- Tenants → self only
- Profiles → self or tenant
- Roles → tenant‑scoped + permission‑gated
- Deals → delegated to access engine

Service Role bypasses all checks.

---

## 9. Storage Security

Bucket: `deals`

Rules:

- Upload allowed only to `deals`
- Download/update/delete only if:

  - Matching DB record exists
  - User has access to that deal

Storage access is **DB‑verified**, not public.

---

## 10. Provisioning APIs

### Provision Tenant (Service Role)

```sql
rpc('provision_tenant', {
  p_name: 'Acme Corp',
  p_slug: 'acme',
  p_admin_email: 'admin@acme.com',
  p_role_name: 'Admin',
  p_permissions: ['dl:c','dl:r','dl:u','dl:d']
})
```

Creates:

- Tenant
- Root role
- Permissions
- Admin invitation

Atomic and secure.

---

## 11. Safety Guarantees

Enforced via triggers:

- No permission escalation
- No role escalation
- Single root per tenant
- Root role immutable
- DAG cycle prevention

Impossible to break hierarchy accidentally.

---

## 12. Local Development

```bash
supabase start
supabase stop
supabase db reset
supabase status
```

Service Logs:

| Service | Container                |
| ------- | ------------------------ |
| API     | supabase_kong_SupaMax    |
| DB      | supabase_db_SupaMax      |
| Auth    | supabase_auth_SupaMax    |
| Storage | supabase_storage_SupaMax |

---

## 13. Configuration Notes

- SMTP via SendGrid
- Auth email‑only
- Anonymous auth disabled
- Storage S3‑compatible

All secrets via environment variables.

---

## 14. Intended Use

Ideal for:

- B2B SaaS
- Internal enterprise tools
- Role‑heavy platforms
- Compliance‑sensitive systems

---

## 15. Philosophy

- Database is the authority
- JWTs are derived, not trusted
- UI is disposable
- Security is structural, not conditional

---

## 16. Testing RLS

### Postgres default roles

- postgres authenticator anon authenticated service_role supabase_auth_admin dashboard_user

### supabase custom roles

- supabase_auth_admin supabase_admin supabase_read_only

```sql
SELECT current_user, session_user;  -- Both: postgres

-- Method 1: Test RLS as service_role
-- Now auth.role() returns 'service_role' for RLS checks
SET LOCAL request.jwt.claim.role = 'service_role';

-- Method 2: Temporarily become auth_admin
SET ROLE supabase_auth_admin;
SELECT current_user;  -- supabase_auth_admin
SELECT session_user;  -- postgres
RESET ROLE;  -- Back to postgres

-- Method 3: Full impersonation
SET SESSION AUTHORIZATION supabase_auth_admin;
SELECT current_user, session_user;  -- Both: supabase_auth_admin
RESET SESSION AUTHORIZATION;  -- Back to postgres
```

---

## 17. Example: End-to-End Tenant Bootstrap

### Provision tenant

```sql
-- 1. ELEVATE PRIVILEGES
SET LOCAL request.jwt.claim.role = 'service_role';
SET ROLE supabase_auth_admin;
SET SESSION AUTHORIZATION supabase_auth_admin;

DO $$ DECLARE
    v_tenant_name TEXT := 'Acme Corp';
    v_tenant_slug TEXT := 'acme';
    v_email TEXT := 'div@gmail.com';
    v_password TEXT := 'password';
    v_provision_result JSON;
    v_user_id UUID;
BEGIN
    -- A. CLEANUP (Reset for fresh seed)
    -- 1. Delete Auth User
    DELETE FROM auth.users WHERE email = v_email;

    -- 2. Delete Tenant (Cascades to Roles, Invitations, Profiles, Deals)
    DELETE FROM public.tenants WHERE slug = v_tenant_slug;

    -- B. PROVISION TENANT STRUCTURE
    -- This call assumes you applied the fix to 'provision_tenant' (Explicit UUIDs)
    -- It creates: Tenant, Root Role, Permissions, Invitation
    SELECT public.provision_tenant(
        p_name := v_tenant_name,
        p_slug := v_tenant_slug,
        p_admin_email := v_email,
        p_role_name := 'Owner'
    ) INTO v_provision_result;

    RAISE NOTICE 'Tenant Structure Provisioned: %', v_provision_result;

    -- C. CREATE AUTH USER
    -- Inserting into auth.users fires the 'handle_new_user' trigger.
    -- That trigger finds the invitation created in Step B and creates the profile.

    v_user_id := gen_random_uuid();

    INSERT INTO auth.users (
        instance_id,
        id,
        aud,
        role,
        email,
        encrypted_password,
        email_confirmed_at,
        raw_app_meta_data,
        raw_user_meta_data,
        created_at,
        updated_at,

        -- Supabase requires these to be strings, not NULL
        confirmation_token,
        recovery_token,
        email_change_token_new,
        email_change
    ) VALUES (
        '00000000-0000-0000-0000-000000000000', -- Standard Supabase Instance ID
        v_user_id,
        'authenticated',
        'authenticated',
        v_email,
        crypt(v_password, gen_salt('bf')),
        now(), -- Auto-confirm email
        '{"provider": "email", "providers": ["email"]}',
        '{"full_name": "Super Admin"}',
        now(),
        now(),

        -- Empty Strings (Supabase crashes on NULL here)
        '', '', '', ''
    );

    RAISE NOTICE 'SUCCESS: User created. Login with % / %', v_email, v_password;
END $$;

```
