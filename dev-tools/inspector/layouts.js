"use strict";

require("cytoscape").use(require("cytoscape-dagre"));

function hierarchy(elements) {
  elements.layout({
    name: "dagre", rankDir: "TB", nodeSep: 28, rankSep: 75,
    acyclicer: "greedy", animate: false, fit: false,
    sort: (a, b) => a.id() < b.id() ? -1 : a.id() > b.id() ? 1 : 0,
  }).run();
}

function compactHierarchy(elements) {
  hierarchy(elements);
  // Keep Dagre's levels/order, but wrap wide levels using Cytoscape's grid.
  const cy = elements.cy(), levels = new Map(), nodes = elements.nodes();
  nodes.forEach(node => {
    const y = node.position("y");
    if (!levels.has(y)) levels.set(y, []);
    levels.get(y).push(node);
  });
  const ranks = [...levels].sort((a, b) => a[0] - b[0]).map(([, rank]) => cy.collection(rank));
  const cellWidth = nodes.reduce((size, node) => Math.max(size, node.outerWidth()), 0) + 28;
  const cellHeight = nodes.reduce((size, node) => Math.max(size, node.outerHeight()), 0) + 28;
  const width = Math.max(1, cy.width() - 70), height = Math.max(1, cy.height() - 70);
  const bounds = elements.boundingBox(), maxColumns = Math.max(...ranks.map(rank => rank.length));
  let columns = 0, scale = Math.min(width / bounds.w, height / bounds.h);
  // Choose the column count that gives the largest fitted nodes in this canvas.
  for (let count = 1; count < maxColumns; count++) {
    const rows = ranks.reduce((sum, rank) => sum + Math.ceil(rank.length / count), 0);
    const candidate = Math.min(width / (count * cellWidth), height / (rows * cellHeight + (ranks.length - 1) * 48));
    if (candidate > scale) { columns = count; scale = candidate; }
  }
  if (columns) {
    let top = 0;
    for (const rank of ranks) {
      const cols = Math.min(columns, rank.length), rows = Math.ceil(rank.length / cols);
      rank.layout({
        name: "grid", cols, rows, fit: false, animate: false, avoidOverlapPadding: 28,
        boundingBox: { x1: (columns - cols) * cellWidth / 2, y1: top, w: cols * cellWidth, h: rows * cellHeight },
        sort: (a, b) => a.position("x") - b.position("x"),
      }).run();
      top += rows * cellHeight + 48;
    }
  }
}

// The first choice is the default. Each function arranges the supplied elements;
// the caller owns visibility and fitting, independently of the chosen layout.
module.exports = {
  compact: { label: "Compact hierarchy", arrange: compactHierarchy },
  hierarchy: { label: "Standard hierarchy", arrange: hierarchy },
};
