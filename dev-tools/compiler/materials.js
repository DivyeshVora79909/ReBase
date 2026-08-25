const fs = require("node:fs");
const path = require("node:path");
const { splitStatements } = require("../../src/surql");

const SURREAL_EXTENSIONS = new Set([".surql", ".sql"]);
const SECTION_BEGIN = /^\s*--+\s*REBASE\s+SECTION\s+([A-Za-z][A-Za-z0-9_-]*)\s+BEGIN\s*$/gim;
const SECTION_END = /^\s*--+\s*REBASE\s+SECTION\s+([A-Za-z][A-Za-z0-9_-]*)\s+END\s*$/gim;
const USE_RE = /\bUSE\s+NS\s+([^\s;]+)\s+DB\s+([^\s;]+)\s*;/i;

function listFiles(root, extensions = SURREAL_EXTENSIONS) {
  const resolved = path.resolve(root);
  if (!fs.existsSync(resolved)) return [];
  const entries = fs.readdirSync(resolved, { withFileTypes: true });
  return entries
    .flatMap((entry) => {
      const file = path.join(resolved, entry.name);
      return entry.isDirectory() ? listFiles(file, extensions) : [file];
    })
    .filter((file) => extensions.has(path.extname(file).toLowerCase()))
    .sort((left, right) => left.localeCompare(right));
}

function readMaterialFiles(groups = []) {
  const files = [];
  const seen = new Set();
  for (const group of groups) {
    if (!group?.name) throw new Error("Every material group requires a name");
    for (const root of group.roots || []) {
      for (const file of listFiles(root)) {
        if (seen.has(file)) continue;
        seen.add(file);
        files.push({
          group: group.name || "source",
          path: file,
          relative: path.relative(path.resolve(root), file),
          source: fs.readFileSync(file, "utf8"),
        });
      }
    }
  }
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function combineMaterials(files) {
  return files
    .map((file) => `-- REBASE SOURCE ${file.group}:${file.relative}\n${file.source.trim()}\n`)
    .join("\n");
}

function extractMarkedSections(source) {
  const sections = new Map();
  const ranges = [];
  SECTION_BEGIN.lastIndex = 0;
  let start;
  while ((start = SECTION_BEGIN.exec(source))) {
    const name = start[1].toLowerCase();
    SECTION_END.lastIndex = SECTION_BEGIN.lastIndex;
    let end;
    while ((end = SECTION_END.exec(source))) {
      if (end[1].toLowerCase() === name) break;
    }
    if (!end) throw new Error(`Unclosed REBASE section: ${name}`);
    const bodyStart = start.index + start[0].length;
    const body = source.slice(bodyStart, end.index).trim();
    if (sections.has(name)) throw new Error(`Duplicate REBASE section: ${name}`);
    sections.set(name, body);
    ranges.push([start.index, end.index + end[0].length]);
    SECTION_BEGIN.lastIndex = end.index + end[0].length;
  }
  return { ranges, sections };
}

function removeMarkedSections(source, ranges) {
  let output = "";
  let cursor = 0;
  for (const [start, end] of ranges) {
    output += source.slice(cursor, start);
    cursor = end;
  }
  return output + source.slice(cursor);
}

function stripLeadingComments(statement) {
  return statement
    .replace(/^\s*(?:(?:--[^\n]*(?:\n|$))|(?:\/\*[\s\S]*?\*\/\s*))+/g, "")
    .trim();
}

function classifyStatement(statement) {
  const sql = stripLeadingComments(statement);
  if (/^USE\s+/i.test(sql)) return "context";
  if (/^DEFINE\s+TABLE\b[\s\S]*\bAS\s+SELECT\b/i.test(sql)) return "views";
  if (/^(?:CREATE|UPDATE|UPSERT|INSERT|RELATE|DELETE)\b/i.test(sql)) return "seed";
  if (/^(?:DEFINE|REMOVE|ALTER)\b/i.test(sql)) return "schema";
  return "raw";
}

function classifyMaterials(files) {
  const statements = [];
  for (const file of files) {
    const extracted = extractMarkedSections(file.source);
    const sections = extracted.sections;
    for (const [name, source] of sections) {
      const type = ["seed", "migration", "schema", "views", "framework"].includes(name)
        ? name
        : "raw";
      statements.push({ file, section: name, type, source, explicit: true });
    }
    const unmarked = removeMarkedSections(file.source, extracted.ranges);
    for (const statement of splitStatements(unmarked)) {
      statements.push({
        file,
        section: null,
        type: classifyStatement(statement),
        source: statement,
        explicit: false,
      });
    }
  }
  const partitions = new Map([
    ["context", []],
    ["schema", []],
    ["views", []],
    ["seed", []],
    ["migration", []],
    ["framework", []],
    ["raw", []],
  ]);
  for (const statement of statements) partitions.get(statement.type).push(statement);
  return { files, statements, partitions };
}

function materialSources(materials, group, type, { includeExplicit = true } = {}) {
  return materials.statements
    .filter((item) => item.file.group === group && item.type === type)
    .filter((item) => includeExplicit || !item.explicit)
    .map((item) => item.source.trim())
    .filter(Boolean)
    .join("\n\n");
}

function detectContext(materials) {
  const contexts = [];
  for (const item of materials.partitions.get("context") || []) {
    const match = USE_RE.exec(item.source);
    if (match) contexts.push({ namespace: match[1], database: match[2], file: item.file.path });
  }
  const unique = new Map(contexts.map((context) => [
    `${context.namespace}:${context.database}`,
    context,
  ]));
  if (unique.size > 1) {
    throw new Error(`Conflicting SurrealDB contexts: ${[...unique.keys()].join(", ")}`);
  }
  return [...unique.values()][0] || null;
}

function contextStatement(context) {
  if (!context?.namespace || !context?.database) return "";
  return `USE NS ${context.namespace} DB ${context.database};`;
}

function loadMaterials({ groups = [], print = false } = {}) {
  const files = readMaterialFiles(groups);
  if (!files.length) throw new Error("No SurrealQL material files found");
  const combined = combineMaterials(files);
  if (print) process.stdout.write(`${combined}\n`);
  const materials = classifyMaterials(files);
  return {
    ...materials,
    combined,
    context: detectContext(materials),
  };
}

function partitionSource(materials, name) {
  return (materials.partitions.get(name) || []).map((item) => item.source.trim()).filter(Boolean).join("\n\n");
}

module.exports = {
  classifyMaterials,
  classifyStatement,
  combineMaterials,
  contextStatement,
  detectContext,
  extractMarkedSections,
  listFiles,
  loadMaterials,
  materialSources,
  partitionSource,
  readMaterialFiles,
  removeMarkedSections,
  stripLeadingComments,
};
