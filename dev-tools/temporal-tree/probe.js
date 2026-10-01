#!/usr/bin/env node
"use strict";
require('./reactivity-probe').main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
