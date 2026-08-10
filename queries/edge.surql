-- @name Prepare email operation as record user
RETURN fn::edge_prepare(
  'email.send',
  NONE,
  <string>{ template: 'setting:replace_template', variables: { name: 'Workbench' } },
  'workbench-email-1'
);

-- @name Claim operation as administrator
RETURN fn::edge_claim('edge_operation:replace_me');

-- @name Complete operation as administrator
RETURN fn::edge_complete(
  'edge_operation:replace_me',
  <string>{ provider_id: 'manual-workbench-result' }
);

-- @name Fail operation as administrator
RETURN fn::edge_fail(
  'edge_operation:replace_me',
  <string>{ code: 'MANUAL_TEST' },
  'false'
);
