'use strict';

const { loadMaterials, composeProfiles } = require('./materials');
const { emitModel, generateBundle, resolveModel, writeArtifacts } = require('./pipeline');

function compileMaterials(materials, options = {}) {
  return emitModel(resolveModel(materials, options));
}

function compileProject({ groups, print = false, ...options }) {
  const materials = loadMaterials({ groups, print });
  return compileMaterials(materials, options);
}

module.exports = {
  compileMaterials,
  compileProject,
  composeProfiles,
  emitModel,
  generateBundle,
  loadMaterials,
  resolveModel,
  writeArtifacts,
};
