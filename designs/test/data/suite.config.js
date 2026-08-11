module.exports = {
  cwd: "designs/test",
  seed: "bulk-insert-batch-number-1",
  anchors: { groups: ["groups:root"] },
  datasets: {
    groups: {
      schema: "data/groups.schema.json",
      count: 6,
      batchSize: 2,
    },
    user: {
      schema: "data/user.schema.json",
      count: 15,
      batchSize: 5,
      unique: ["email"],
    },
    test_primitive: {
      schema: "data/test_primitive.schema.json",
      count: 50,
      batchSize: 10,
    },
    test_relation: {
      schema: "data/test_relation.schema.json",
      count: 25,
      batchSize: 5,
    },
    test_multiref: {
      schema: "data/test_multiref.schema.json",
      count: 25,
      batchSize: 5,
    },
    test_tree: {
      schema: "data/test_tree.schema.json",
      count: 25,
      batchSize: 5,
    },
    setting: {
      schema: "data/setting.schema.json",
      count: 25,
      batchSize: 5,
    },
  },
  casts: [
    { path: "test_primitive[].a_datetime", type: "datetime" },
    { path: "test_primitive[].a_decimal", type: "decimal" },
  ],
  relations: [
    // AUTH GRAPH (Acyclic dataset wiring)
    {
      from: "groups.id",
      to: "groups.parents[]",
      cardinality: { min: 1, max: 2 },
    },
    {
      from: "user.id",
      to: "user.parents[]",
      cardinality: { min: 1, max: 2 },
    },
    {
      from: "groups.id",
      to: "user.parents[]",
      cardinality: { min: 1, max: 2 },
    },
    {
      from: "user.id",
      to: "user.a_friends[]",
      cardinality: { min: 0, max: 2 },
    },
    {
      from: "groups.id",
      to: "groups.a_partner_groups[]",
      cardinality: { min: 0, max: 2 },
    },

    // OPTIONAL CROSS-TABLE RELATIONS
    {
      from: "test_primitive.id",
      to: "groups.a_associated_primitive",
      cardinality: { min: 0, max: 1 },
    },
    {
      from: "test_primitive.id",
      to: "user.a_favorite_primitive",
      cardinality: { min: 0, max: 1 },
    },
    {
      from: "test_primitive.id",
      to: "user.a_watched_items[]",
      cardinality: { min: 0, max: 2 },
    },
    {
      from: "test_tree.id",
      to: "user.a_watched_items[]",
      cardinality: { min: 0, max: 2 },
    },

    // OWNERSHIP FAN-OUT
    { from: "user.id", to: "test_primitive.owned_by" },
    { from: "groups.id", to: "test_primitive.owned_by" },

    // TEST_RELATION
    { from: "test_primitive.id", to: "test_relation.a_primitive" },
    { from: "test_primitive.id", to: "test_relation.a_polymorphic" },
    { from: "user.id", to: "test_relation.a_polymorphic" },
    {
      from: "test_primitive.id",
      to: "test_relation.a_primitive_array[]",
      cardinality: { min: 0, max: 3 },
    },
    {
      from: "test_primitive.id",
      to: "test_relation.a_poly_array[]",
      cardinality: { min: 0, max: 3 },
    },
    {
      from: "groups.id",
      to: "test_relation.a_poly_array[]",
      cardinality: { min: 0, max: 3 },
    },
    { from: "user.id", to: "test_relation.owned_by" },
    { from: "groups.id", to: "test_relation.owned_by" },

    // TEST_MULTIREF
    { from: "user.id", to: "test_multiref.a_creator" },
    { from: "user.id", to: "test_multiref.a_reviewer" },
    { from: "user.id", to: "test_multiref.a_approver" },
    { from: "groups.id", to: "test_multiref.a_owning_group" },
    { from: "groups.id", to: "test_multiref.a_auditing_group" },
    { from: "user.id", to: "test_multiref.owned_by" },
    { from: "groups.id", to: "test_multiref.owned_by" },

    // TEST_TREE
    {
      from: "test_tree.id",
      to: "test_tree.a_parent",
      cardinality: { min: 0, max: 1 },
    },
    {
      from: "test_tree.id",
      to: "test_tree.a_related_nodes[]",
      cardinality: { min: 0, max: 2 },
    },
    { from: "user.id", to: "test_tree.owned_by" },
    { from: "groups.id", to: "test_tree.owned_by" },

    // SETTING (Polymorphic targets)
    { from: "test_primitive.id", to: "setting.target_record" },
    { from: "test_relation.id", to: "setting.target_record" },
    { from: "test_multiref.id", to: "setting.target_record" },
    { from: "test_tree.id", to: "setting.target_record" },
    { from: "setting.id", to: "setting.target_record" },

    // SETTING (Polymorphic secondary records)
    {
      from: "test_primitive.id",
      to: "setting.secondary_record",
      cardinality: { min: 0, max: 1 },
    },
    {
      from: "test_relation.id",
      to: "setting.secondary_record",
      cardinality: { min: 0, max: 1 },
    },
    {
      from: "test_multiref.id",
      to: "setting.secondary_record",
      cardinality: { min: 0, max: 1 },
    },
    {
      from: "test_tree.id",
      to: "setting.secondary_record",
      cardinality: { min: 0, max: 1 },
    },
    {
      from: "setting.id",
      to: "setting.secondary_record",
      cardinality: { min: 0, max: 1 },
    },

    { from: "user.id", to: "setting.dependency" },
    { from: "groups.id", to: "setting.dependency" },
    { from: "test_primitive.id", to: "setting.dependency" },
    { from: "setting.id", to: "setting.dependency" },

    { from: "user.id", to: "setting.owned_by" },
    { from: "groups.id", to: "setting.owned_by" },
  ],
};
