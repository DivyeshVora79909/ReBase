import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';

const supabaseUrl = process.env.SUPABASE_URL || 'http://127.0.0.1:54321';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseServiceKey || !supabaseAnonKey) {
    console.error('Missing environment variables: SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ANON_KEY');
    process.exit(1);
}

const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
    auth: { autoRefreshToken: false, persistSession: false }
});

const authClient = createClient(supabaseUrl, supabaseAnonKey, {
    auth: { autoRefreshToken: false, persistSession: false }
});

async function runTests() {
    console.log('🚀 Starting Phase 2: Onboarding & Authentication Tests');

    try {
        const { data: currentRole } = await supabaseAdmin.rpc('get_my_role');
        console.log('--- Current Role (via service_role key):', currentRole);

        // 1. Provision Tenant A
        console.log('\n--- Step 1: Provisioning Tenant A ---');
        const suffix = Date.now();
        const { data: tenantA, error: tenantError } = await supabaseAdmin.rpc('provision_new_tenant', {
            p_tenant_name: `Acme Corp ${suffix}`,
            p_tenant_slug: `acme-${suffix}`
        });
        if (tenantError) throw tenantError;
        const { tenant_id: tenantAId, owner_role_id: ownerARoleId } = tenantA;
        console.log('✅ Tenant A provisioned:', tenantAId);

        // 2. Create Tenant Owner A
        console.log('\n--- Step 2: Creating Tenant Owner A ---');
        const ownerAEmail = `owner_a_${Date.now()}@example.com`;

        // We need an invitation for the owner because of the trigger
        const { error: inviteOwnerError } = await supabaseAdmin
            .from('invitations')
            .insert({
                email: ownerAEmail,
                tenant_id: tenantAId,
                target_role_id: ownerARoleId,
                status: 'pending'
            });
        if (inviteOwnerError) throw inviteOwnerError;

        const { data: ownerAAuth, error: ownerAAuthError } = await supabaseAdmin.auth.admin.createUser({
            email: ownerAEmail,
            password: 'password123',
            email_confirm: true,
            user_metadata: { first_name: 'Owner', last_name: 'A' }
        });
        if (ownerAAuthError) throw ownerAAuthError;
        const ownerAId = ownerAAuth.user.id;
        console.log('✅ Owner A created:', ownerAId);

        // 3. Login as Owner A to get JWT
        const { data: ownerASession, error: ownerALoginError } = await authClient.auth.signInWithPassword({
            email: ownerAEmail,
            password: 'password123'
        });
        if (ownerALoginError) throw ownerALoginError;
        const ownerAToken = ownerASession.session.access_token;
        const decodedOwnerA = jwt.decode(ownerAToken);
        console.log('Owner A JWT app_metadata:', JSON.stringify(decodedOwnerA.app_metadata, null, 2));

        // Check if profile exists
        const { data: ownerAProfile } = await supabaseAdmin.from('profiles').select().eq('id', ownerAId).single();
        console.log('Owner A Profile:', ownerAProfile);

        const ownerAClient = createClient(supabaseUrl, supabaseAnonKey, {
            global: { headers: { Authorization: `Bearer ${ownerAToken}` } }
        });

        // 2.1 Invite User
        console.log('\n--- Test 2.1: Invite User ---');

        // Create a subordinate role first
        const { data: managerRole, error: managerRoleError } = await ownerAClient
            .from('roles')
            .insert({
                name: 'Manager',
                permissions: ['public.deals:select']
            })
            .select()
            .single();
        if (managerRoleError) throw managerRoleError;
        console.log('✅ Manager role created:', managerRole.id);

        // Link Tenant Owner to Manager
        const { error: linkError } = await ownerAClient
            .from('hierarchy')
            .insert({
                parent_role_id: ownerARoleId,
                child_role_id: managerRole.id
            });
        // Wait, hierarchy management might require Tenant Owner role.
        // Let's check if Owner A has permission.
        if (linkError) {
            console.warn('⚠️ Hierarchy link failed (expected if not tenant owner):', linkError.message);
            // If it fails, we might need to use service_role to link them for the test
            await supabaseAdmin.from('hierarchy').insert({
                tenant_id: tenantAId,
                parent_role_id: ownerARoleId,
                child_role_id: managerRole.id
            });
            console.log('✅ Linked roles via service_role');
        } else {
            console.log('✅ Linked roles via Owner A');
        }

        // RE-LOGIN to refresh JWT claims (descendants)
        console.log('--- Refreshing Owner A Token ---');
        const { data: ownerASessionRefreshed, error: ownerALoginError2 } = await authClient.auth.signInWithPassword({
            email: ownerAEmail,
            password: 'password123'
        });
        if (ownerALoginError2) throw ownerALoginError2;
        const ownerATokenRefreshed = ownerASessionRefreshed.session.access_token;
        const decodedOwnerARefreshed = jwt.decode(ownerATokenRefreshed);
        console.log('Owner A Refreshed JWT app_metadata:', JSON.stringify(decodedOwnerARefreshed.app_metadata, null, 2));

        const ownerAClientRefreshed = createClient(supabaseUrl, supabaseAnonKey, {
            global: { headers: { Authorization: `Bearer ${ownerATokenRefreshed}` } }
        });

        const inviteeEmail = `invitee_${Date.now()}@example.com`;
        const { data: inviteData, error: inviteError } = await ownerAClientRefreshed
            .from('invitations')
            .insert({
                email: inviteeEmail,
                target_role_id: managerRole.id
            })
            .select()
            .single();

        if (inviteError) throw inviteError;
        console.log('✅ Invitation created. invited_by:', inviteData.invited_by);
        if (inviteData.invited_by !== ownerAId) throw new Error('invited_by not auto-filled correctly');
        if (inviteData.tenant_id !== tenantAId) throw new Error('tenant_id not auto-filled correctly');

        // 2.2 Cross-Tenant Invite
        console.log('\n--- Test 2.2: Cross-Tenant Invite ---');

        const { data: roleBeforeB } = await supabaseAdmin.rpc('get_my_role');
        console.log('--- Current Role before Tenant B (via service_role key):', roleBeforeB);

        // Provision Tenant B using ADMIN client
        const { data: tenantB, error: tenantBError } = await supabaseAdmin.rpc('provision_new_tenant', {
            p_tenant_name: `Beta Corp ${suffix}`,
            p_tenant_slug: `beta-${suffix}`
        });
        if (tenantBError) {
            console.error('❌ Failed to provision Tenant B:', tenantBError.message);
            throw tenantBError;
        }
        console.log('✅ Tenant B provisioned:', tenantB.tenant_id);

        // Owner A tries to invite to Tenant B
        const { error: crossInviteError } = await ownerAClientRefreshed
            .from('invitations')
            .insert({
                email: 'attacker@example.com',
                tenant_id: tenantB.tenant_id,
                target_role_id: tenantB.owner_role_id
            });

        if (crossInviteError) {
            console.log('✅ Cross-tenant invite failed as expected (RLS):', crossInviteError.message);
        } else {
            const { data: crossInviteCheck } = await supabaseAdmin
                .from('invitations')
                .select()
                .eq('email', 'attacker@example.com')
                .single();

            if (crossInviteCheck && crossInviteCheck.tenant_id === tenantAId) {
                console.log('✅ Cross-tenant invite prevented (tenant_id overwritten to Tenant A)');
            } else {
                throw new Error(`Cross-tenant invite check failed. tenant_id was ${crossInviteCheck?.tenant_id}`);
            }
        }

        // 2.3 Signup Flow
        console.log('\n--- Test 2.3: Signup Flow ---');
        const { data: inviteeAuth, error: inviteeSignupError } = await supabaseAdmin.auth.signUp({
            email: inviteeEmail,
            password: 'password123',
            options: { data: { first_name: 'Invitee', last_name: 'User' } }
        });
        if (inviteeSignupError) throw inviteeSignupError;

        // Confirm email via admin
        await supabaseAdmin.auth.admin.updateUserById(inviteeAuth.user.id, { email_confirm: true });

        // Check if profile was created
        const { data: inviteeProfile, error: profileError } = await supabaseAdmin
            .from('profiles')
            .select()
            .eq('id', inviteeAuth.user.id)
            .single();

        if (profileError) throw profileError;
        console.log('✅ Profile created automatically:', inviteeProfile.id);

        // Check invitation status
        const { data: acceptedInvite } = await supabaseAdmin
            .from('invitations')
            .select()
            .eq('email', inviteeEmail)
            .single();
        if (acceptedInvite.status !== 'accepted') throw new Error('Invitation status not updated to accepted');
        console.log('✅ Invitation status updated to accepted');

        // 2.4 Orphan Signup
        console.log('\n--- Test 2.4: Orphan Signup ---');
        const orphanEmail = `orphan_${Date.now()}@example.com`;
        const { error: orphanSignupError } = await supabaseAdmin.auth.signUp({
            email: orphanEmail,
            password: 'password123'
        });
        if (orphanSignupError && orphanSignupError.message.includes('No pending invitation found')) {
            console.log('✅ Orphan signup blocked as expected');
        } else {
            console.log('⚠️ Orphan signup behavior:', orphanSignupError ? orphanSignupError.message : 'Success (Check if profile exists)');
            const { data: orphanProfile } = await supabaseAdmin.from('profiles').select().eq('email', orphanEmail).single();
            if (orphanProfile) throw new Error('Profile created for orphan signup!');
        }

        // 2.5 JWT Claims Check
        console.log('\n--- Test 2.5: JWT Claims Check ---');
        const { data: inviteeSession } = await supabaseAdmin.auth.signInWithPassword({
            email: inviteeEmail,
            password: 'password123'
        });
        const inviteeToken = inviteeSession.session.access_token;
        const decoded = jwt.decode(inviteeToken);

        console.log('JWT app_metadata:', JSON.stringify(decoded.app_metadata, null, 2));
        if (!decoded.app_metadata.tenant_id) throw new Error('Missing tenant_id in JWT');
        if (!decoded.app_metadata.role) throw new Error('Missing role in JWT');
        if (!Array.isArray(decoded.app_metadata.descendants)) throw new Error('Missing descendants array in JWT');
        console.log('✅ JWT claims verified');

        console.log('\n🎉 Phase 2 Tests Completed Successfully!');

    } catch (err) {
        console.error('\n❌ Test failed:', err.message);
        if (err.details) console.error('Details:', err.details);
        process.exit(1);
    }
}

runTests();
