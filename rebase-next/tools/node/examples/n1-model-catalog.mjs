import { parseEnvironment, resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';

const config = resolveConfig({
  defaults: {
    native: {
      binary: '/absolute/path/to/rebase-next',
      environment: {},
    },
  },
  environment: parseEnvironment(process.env),
  overrides: {
    native: {
      configuration: {
        model: 'equipment',
        backend: { kind: 'redb', cluster_file: null },
        target: null,
        operator_methods: [],
      },
    },
  },
});

const native = await openNative(config);
try {
  const catalog = await native.catalog({ scope: 'public' });
  console.log(catalog);
} finally {
  await native.close();
}
