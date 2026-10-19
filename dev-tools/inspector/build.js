"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { buildSync } = require("esbuild");

// A single local file, including pinned libraries and the selected catalog.
// Browser file:// loading needs neither a server nor cross-origin JSON fetches.
function buildInspector(catalog) {
  const script = buildSync({
    entryPoints: [path.join(__dirname, "app.js")], bundle: true, write: false,
    platform: "browser", format: "iife", target: "es2022", minify: true,
    legalComments: "inline", logLevel: "silent",
  }).outputFiles[0].text;
  const data = JSON.stringify(catalog).replace(/</g, "\\u003c");
  return fs.readFileSync(path.join(__dirname, "index.html"), "utf8")
    .replace("<!-- inspector-style -->", () => "<style>" + fs.readFileSync(path.join(__dirname, "inspector.css"), "utf8") + "</style>")
    .replace('<script id="rebase-catalog" type="application/json">null</script>',
      () => '<script id="rebase-catalog" type="application/json">' + data + "</script>")
    .replace("<!-- inspector-script -->", () => "<script>" + script.replace(/<\/script/gi, "<\\/script") + "</script>");
}

module.exports = { buildInspector };
