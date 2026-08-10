await tools.database.resetDatabase({
  db,
  namespace: "main",
  database: "main",
  confirm: true,
});
await tools.schema.loadSchema({ db, file: "build/test/schema.surql" });

// ADD ON EXISTING RECORDS
var seed = "bulk-insert-batch-number-1";

vars.config = require("./designs/test/data/suite.config.js");

vars.payload = tools.data.generateData({
  config: vars.config,
  seed,
  counts: {
    user: 20,
    test_primitive: 1000,
    groups: 5,
  },
});

tools.data.validateData({ data: vars.payload, config: vars.config });
vars.casted = tools.data.castData({
  data: vars.payload,
  rules: vars.config.casts,
});

await tools.materialize.materializeData({
  db,
  data: vars.casted,
  config: vars.config,
});
