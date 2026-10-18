#!/usr/bin/env node
// Builds the inline crypto bundle of src/manager/manager.html.
//
//   cd tools/manager-crypto && npm ci          # once: installs the EXACT versions pinned in
//                                              # package.json / package-lock.json (noble + esbuild)
//   node scripts/build_manager_crypto.mjs          # rewrites the block between the markers
//   node scripts/build_manager_crypto.mjs --check  # exit 1 if manager.html differs from a fresh build
//
// The bundle (tools/manager-crypto/entry.js -> minified IIFE) is pasted between
//   /*EM-CRYPTO-BEGIN*/ ... /*EM-CRYPTO-END*/
// inside manager.html, so the manager stays a single self-contained file that works
// from plain-HTTP device origins (no crypto.subtle there).
//
// Reproducibility: dependency versions are pinned exactly and `npm ci` installs only what the
// lockfile says, so the same sources always yield the same bytes. Do NOT use `npm install` here.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const toolDir = path.join(root, "tools", "manager-crypto");
const htmlFile = path.join(root, "src", "manager", "manager.html");
const BEGIN = "/*EM-CRYPTO-BEGIN*/";
const END = "/*EM-CRYPTO-END*/";
const check = process.argv.includes("--check");

function fail(message) {
  console.error("build_manager_crypto: " + message);
  process.exit(1);
}

let esbuild;
try {
  esbuild = createRequire(path.join(toolDir, "package.json"))("esbuild");
} catch {
  fail("esbuild is not installed. Run:  cd tools/manager-crypto && npm ci");
}

const pkg = JSON.parse(fs.readFileSync(path.join(toolDir, "package.json"), "utf8"));
const installed = (name) => {
  try {
    return JSON.parse(fs.readFileSync(path.join(toolDir, "node_modules", name, "package.json"), "utf8")).version;
  } catch {
    return fail(`${name} is not installed. Run:  cd tools/manager-crypto && npm ci`);
  }
};
for (const [name, wanted] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
  if (installed(name) !== wanted) fail(`${name} ${installed(name)} installed but ${wanted} pinned. Run:  cd tools/manager-crypto && npm ci`);
}

const result = await esbuild.build({
  entryPoints: [path.join(toolDir, "entry.js")],
  bundle: true,
  write: false,
  format: "iife",
  target: "es2020",
  minify: true,
  charset: "ascii",
  legalComments: "inline",
  logLevel: "error",
  outfile: "bundle.js",
});
let code = result.outputFiles[0].text.trim();
if (/<\/script/i.test(code) || code.includes("<!--")) fail("bundle contains a sequence that is unsafe inside an inline <script>");
const banner = `/* @noble/hashes ${installed("@noble/hashes")}, @noble/ciphers ${installed("@noble/ciphers")}, esbuild ${installed("esbuild")}; source tools/manager-crypto/entry.js */`;
const block = `${BEGIN}${banner}\n${code}\n${END}`;

const html = fs.readFileSync(htmlFile, "utf8");
const start = html.indexOf(BEGIN);
const end = html.indexOf(END);
if (start < 0 || end < start || html.indexOf(BEGIN, start + 1) >= 0) fail(`manager.html must contain exactly one ${BEGIN} ... ${END} pair`);
const next = html.slice(0, start) + block + html.slice(end + END.length);

if (check) {
  if (next !== html) {
    console.error("build_manager_crypto: the inline crypto block of manager.html is stale. Run: node scripts/build_manager_crypto.mjs");
    process.exit(1);
  }
  console.log("manager crypto bundle is up to date (" + block.length + " bytes)");
} else if (next === html) {
  console.log("manager crypto bundle unchanged (" + block.length + " bytes)");
} else {
  fs.writeFileSync(htmlFile, next);
  console.log("wrote crypto bundle into manager.html (" + block.length + " bytes)");
}
