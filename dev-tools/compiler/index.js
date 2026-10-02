'use strict';

const { loadMaterials, composeProfiles } = require('./materials');
const { emitModel, generateBundle, resolveModel, writeArtifacts } = require('./pipeline');
const { buildProject, compileFromArgs } = require('./project');

function compileMaterials(materials, options = {}) {
  return emitModel(resolveModel(materials, options));
}

function compileProject({ groups, print = false, ...options }) {
  const materials = loadMaterials({ groups, print });
  return compileMaterials(materials, options);
}

module.exports = {
  compileMaterials,
  buildProject,
  compileFromArgs,
  compileProject,
  composeProfiles,
  emitModel,
  generateBundle,
  loadMaterials,
  resolveModel,
  writeArtifacts,
};
