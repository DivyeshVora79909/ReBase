# Explicit cross-table analytics example

This deployable example uses the normal compiler and framework. It enrolls two
ordinary record types, `activity` and `annotation`, with comparable `points`.
Other tables are not automatically enrolled. The source files are
[roots.surql](roots.surql) and [records.surql](records.surql).

| Root | Owner | Key | Visibility |
| --- | --- | --- | --- |
| `z_created` | Tenant | creation datetime | System sessions |
| `z_effective` | Tenant | effective datetime | System sessions |
| `z_owner_created` | Tenant | owner RecordId, creation datetime | System sessions |
| `z_owned_created` | Tenant/user/group | creation datetime | System for tenant; authorized principal readers for user/group |
| `z_owned_effective` | Tenant/user/group | effective datetime | Same as owner creation tree |

All roots allow duplicate keys. Each also maintains count and point summaries.
An absent `effective_at` omits only the two effective-time memberships.
`include_analytics=false` omits all five. Moving ownership transfers the owner
trees and composite key atomically. Backdating retains `created_at`.

```bash
npm run build:index-analytics
npm run check:index-analytics
npm run probe:reader-index
```

Apply the generated `build/index-analytics/schema.surql` to a disposable design
database. Provision the tenant and user explicitly through a system connection:

```surql
CREATE rebase_tenant:demo SET name='Demo';
CREATE rebase_user:analyst SET name='Analyst',parents=[rebase_tenant:demo];
CREATE activity:one SET owned_by=rebase_user:analyst,title='First',points=3dec,
    effective_at=d'2027-01-01';
CREATE annotation:two SET owned_by=rebase_user:analyst,title='Second',points=5dec,
    effective_at=d'2027-01-02';
RETURN fn::tree::read(rebase_user:analyst,'z_owned_created','summary',[]);
RETURN fn::tree::read(rebase_tenant:demo,'z_effective','before',[d'2027-01-02']);
```

The first summary counts two records and eight points. The prefix counts one
record and three points. Use a record session for owner-scoped client reads;
tenant summaries are deliberately private. Every analytics slot declares
`@rebase-tree-no-reader`, so participation does not expand a source's `read_by`.

This is an example of explicit schema composition, not an automatic analytics
service or a workload benchmark. See the [developer blueprint](../rebase-system/developer-blueprint.md)
for extending it and the [verification](../rebase-system/reader-index-verification.md)
for current checks.
