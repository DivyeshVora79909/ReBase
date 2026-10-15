'use strict';
const path = require('node:path');
const root = process.cwd();
const { splitStatements } = require(path.join(root, 'dev-tools/compiler/surql'));
const acceptance = require(path.join(root, 'dev-tools/accounting/acceptance'));
const compile = acceptance.compile;
acceptance.compile = () => {
  const compiled = compile();
  compiled.bundle = splitStatements(compiled.bundle).map(statement =>
    statement.includes('DEFINE FUNCTION OVERWRITE fn::reads::settle_group(')
      ? 'DEFINE FUNCTION OVERWRITE fn::reads::settle_group($group: record) { UPDATE $group SET tree_changed=false RETURN NONE; } PERMISSIONS NONE;'
      : statement).join('\n');
  return compiled;
};
// All native mutation and oracle checks are unchanged; only the postorder
// repair is omitted in this disposable diagnostic bundle.
require(path.join(root, 'dev-tools/accounting/integrity-fx-probe')).main()
  .catch(error => { console.error(error.stack); process.exitCode = 1; });
