📐 Reactive Graph Engine: Format Standard

1. File Structure

The architecture must be strictly split into these files. LLMs and developers
must append code to the correct file to prevent execution loop errors.

- 01_auth_rbac.surql: Users, groups, link relations, and database access
  definitions.
- 02_table_permissions.surql: Root table access control (FOR select, create,
  update, delete).
- 03_owned_by_fields.surql: Inheritance pointers mapping records to RBAC
  groups.
- 04_audit_meta_fields.surql: created_at, updated_at, created_by, updated_by
  (applied via loops).
- 05_system_flags.surql: System-level toggles (suspended, locked). Note: Do
  not use the generic word "state".
- 06_table_fields.surql: Standard inputs, hierarchical objects, and physics
  assertions.
- 07_views.surql: Stateless aggregations (GROUP BY). Always apply WHERE
  suspended = false.
- 08_events_upward.surql: View -> Parent pings (updated_at triggers and locked
  chokes).
- 09_events_downward_topology.surql: Parent -> Child DAG root checks.
- 10_events_downward_data.surql: Parent -> Child data pushes (The Zig-Zag
  variable hand-off).

2. Table Schema Standard

SurrealDB evaluates VALUE clauses sequentially in alphabetical order. To
guarantee fields resolve in the correct sequence, every table must nest its
computed fields strictly within these specific objects.

Rule: ASSERT clauses can be placed in z, zz, or zzz as needed.

1.  Normal Fields: Base inputs and relations (qty, cogs, invoice).
2.  parent{}: Variables pulled DOWN from a parent record. Evaluates 1st.
3.  view{}: Variables pulled UP from a view aggregation. Evaluates 2nd.
4.  z{}: Primary derived math. Evaluates 3rd.
5.  zz{}: Secondary derived math (depends on z). Evaluates 4th.
6.  zzz{}: (Rare) Final-stage derived math (depends on zz). Evaluates 5th.

Boilerplate Template (06_table_fields.surql)

DEFINE TABLE child_node SCHEMAFULL;

-- 1. NORMAL FIELDS
DEFINE FIELD qty ON child_node TYPE decimal ASSERT $value > 0dec;

-- 2. PARENT OBJECT (Push-down context)
DEFINE FIELD parent ON child_node TYPE object DEFAULT {};
DEFINE FIELD parent.locked ON child_node TYPE bool VALUE $this.parent_node.locked ?? false;

-- 3. VIEW OBJECT (Pull-up aggregations)
DEFINE FIELD view ON child_node TYPE object DEFAULT {};
DEFINE FIELD view.v_sl_totals ON child_node TYPE object DEFAULT {};
DEFINE FIELD view.v_sl_totals.delivered_qty ON child_node TYPE decimal DEFAULT 0dec;

-- 4. Z OBJECT (Primary Math & Asserts)
DEFINE FIELD z ON child_node TYPE object DEFAULT {};
DEFINE FIELD z.base_value ON child_node TYPE decimal
VALUE $this.qty \* 10dec
ASSERT $value >= 0dec;

-- 5. ZZ OBJECT (Secondary Math & Asserts)
DEFINE FIELD zz ON child_node TYPE object DEFAULT {};
DEFINE FIELD zz.qty_remaining ON child_node TYPE decimal
VALUE ($this.qty - $this.view.v_sl_totals.delivered_qty)
ASSERT $value >= 0dec;

3. Event Formatting Rules

Events must contain no procedural business logic. They are purely data-transport
mechanisms.

Upward Ping (08_events_upward.surql)

DEFINE EVENT ping_parent ON TABLE v_child_view WHEN $event != 'NONE' THEN {
LET $target_id = $after.parent_node ?? $before.parent_node;

    -- Choke point via O(1) graph traversal
    IF $target_id.locked = true { THROW "LOCKED"; };

    -- Sync aggregate & Spark evaluation
    UPDATE $target_id SET
        view.v_child_view.total = $after.total,
        updated_at = time::now();

};

Downward Topology (09_events_downward_topology.surql)

DEFINE EVENT ping_topology ON parent_node
WHEN $event = 'UPDATE' AND $before.org != $after.org THEN {
-- Forces child to re-evaluate DAG integrity
UPDATE (<~child_node) SET updated_at = time::now();
};

Downward Data (10_events_downward_data.surql)

DEFINE EVENT ping_data ON parent_node
WHEN $event = 'UPDATE' AND $before.z.total != $after.z.total THEN {
-- Pushes required context down to child
UPDATE child_node SET parent.total = $after.z.total WHERE parent_node = $after.id;
};
