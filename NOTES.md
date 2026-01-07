Database Tables: Define your columns and data types (Schema).
RLS Policies: Write the security rules (Who can see/edit what).
SQL Functions/Triggers: Logic for internal automation (e.g., auto-creating profiles).
Edge Functions: Logic for external tasks (e.g., Emails, Stripe, 3rd party APIs).
Storage Buckets: Create the containers for your files.
Views: Define your read-only views (e.g., Student List).

supabase status
supabase stop
supabase start
supabase db reset

| Service              | Container name               | Command to view logs                        |
| -------------------- | ---------------------------- | ------------------------------------------- |
| API gateway (Kong)   | `supabase_kong_SupaMax`      | `docker logs -f supabase_kong_SupaMax`      |
| PostgREST (REST API) | `supabase_rest_SupaMax`      | `docker logs -f supabase_rest_SupaMax`      |
| Auth                 | `supabase_auth_SupaMax`      | `docker logs -f supabase_auth_SupaMax`      |
| Postgres DB          | `supabase_db_SupaMax`        | `docker logs -f supabase_db_SupaMax`        |
| Realtime             | `supabase_realtime_SupaMax`  | `docker logs -f supabase_realtime_SupaMax`  |
| Storage API          | `supabase_storage_SupaMax`   | `docker logs -f supabase_storage_SupaMax`   |
| Studio (web UI)      | `supabase_studio_SupaMax`    | `docker logs -f supabase_studio_SupaMax`    |
| Analytics / Logflare | `supabase_analytics_SupaMax` | `docker logs -f supabase_analytics_SupaMax` |
| Vector / search      | `supabase_vector_SupaMax`    | `docker logs -f supabase_vector_SupaMax`    |
| Mail / SMTP          | `supabase_inbucket_SupaMax`  | `docker logs -f supabase_inbucket_SupaMax`  |

so here my previous project was a big mess, it still has many bugs and isssues, now i have started a new project same idea but different enforcement, here there are many things easier and scalable, here i have only made the schema, you have to make a heirarchy recursive cte check for dag enforcement for a tenant's roles hierarchy, here there will not invitation or anything like that, here there will email authentication for user or whatever supabase gives the best, here for inviting a user i can simply generate a token and send it to the email of the user, anyone i mean even i can send it to the tenant admin user onboarding, or tenant admin can invite his own users using this, the token has the details for which tenant, role, random password.... here the token is a stateless thing simply send and register the user and profile by simply verifying and decoding the token thats it, here the jwt will be easy in nature it wont be confusing like inherited permissions and all, here simply in jwt put the heirarchy decendants, user id, tenant id, role whole object with permissions, here the role jsob permissions consists of the schema.table.select/insert/update/delete so basically the grant accordingly, basically the thing is softcoded that whatever ops the user is doing simply check the role with that meta data only

here major thing to note is that there should be no exceptional bypasses like service role bypass and all, here to make logic as fine and clear as possible also avoid hardcoding and conditionals, i am not telling completely avoid, i am telling to try avoiding it, the public, private and controlled will always have the conditionals

here the rls on a resource will be like this, there will three policies on any resource, 1) role permission + public check, 2) owner user id(light) or role name is tenant owner check or ancestor private controlled check(heavy for last), 3) controlled select ops check

here there will be security mixin trigger that rewrites or enforces the tenant id, role id, owner id from the token only, this trigger is such that it is softcoded, meaning if the column doesnot exist in the table then simply dont put it, meaning we can also use it in the role, heirarchy, where the role id or owner id is absent

here there will be role permission escalation too, as permission code and other things are shifted to meta data they are not needed, so here in the escalation it will be straight forward, during assignment, modifying a role, this checks the doer and user/role that is being modified

here the heirarchy permission will work like this, in the token only there will be is role record where its name if it is "Tenant Owner", then let him access his tenant's heirarchy

here the token generation will have whole role record, tenant id, user id, decendants

here there will be a rls or trigger in the role heirarchy for cte dag enforcement and for enforcing the tenant owner role to be always parent or non child only

here the self roles will be non editable too
