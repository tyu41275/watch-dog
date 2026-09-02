import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { API, SymbolFlags } from "typescript/unstable/sync";
import { isExportDeclaration, isImportDeclaration } from "typescript/unstable/ast/is";

const ROOT = process.cwd(), VERSION = "7.0.2", FETCH = "src/worker/fetch/fetch-machine.ts", SCAN = "src/shared/scan-machine.ts";
const OUT = "public/protocol", check = process.argv[2] === "--check" && process.argv.length === 3;
const fail = (family, subject) => { throw new Error(`${family} ${subject}`); };
if ((!check && process.argv.length !== 2) || ts.version !== VERSION) fail("RS-FC-TOOLCHAIN", "arguments/version");
const pkg = JSON.parse(fs.readFileSync("package.json", "utf8")), lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
if (pkg.devDependencies?.typescript !== VERSION || lock.packages?.["node_modules/typescript"]?.version !== VERSION) fail("RS-FC-TOOLCHAIN", "package-lock");
const api = new API({ cwd: ROOT }), snap = api.updateSnapshot({ openProjects: [path.join(ROOT, "tsconfig.json")] }), project = snap.getProjects()[0];
if (!project) fail("RS-FC-TOOLCHAIN", "tsconfig");
const diagnostics = [...project.program.getSyntacticDiagnostics(), ...project.program.getSemanticDiagnostics(), ...project.program.getProgramDiagnostics()];
if (diagnostics.length) fail("RS-FC-SOURCE-CLOSURE", "diagnostics");
const posix = (value) => path.relative(ROOT, value).split(path.sep).join("/"), order = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const sha = (value) => createHash("sha256").update(value).digest("hex"), raw = new Map(), edges = new Map();
function source(name) {
  if (raw.has(name)) return;
  const absolute = path.join(ROOT, name), stat = fs.lstatSync(absolute), bytes = fs.readFileSync(absolute);
  if (stat.isSymbolicLink() || bytes[0] === 0xef || bytes.includes(13) || bytes.at(-1) !== 10) fail("RS-FC-SOURCE-CLOSURE", name);
  const file = project.program.getSourceFile(absolute); if (!file || /\bimport\s*\(|\bimport\s+[^;]+\bwith\s*\{/su.test(bytes)) fail("RS-FC-SOURCE-CLOSURE", name);
  raw.set(name, bytes); const found = [];
  for (const node of file.statements) if ((isImportDeclaration(node) || isExportDeclaration(node)) && node.moduleSpecifier) {
    const spec = node.moduleSpecifier.text; if (!spec.startsWith(".")) fail("RS-FC-SOURCE-CLOSURE", name);
    const symbol = project.checker.getSymbolAtLocation(node.moduleSpecifier), resolved = symbol?.declarations[0]?.resolve()?.getSourceFile().fileName;
    if (!resolved || !path.resolve(resolved).startsWith(path.join(ROOT, "src") + path.sep)) fail("RS-FC-SOURCE-CLOSURE", name);
    const clause = node.importClause, runtime = isExportDeclaration(node) ? !node.isTypeOnly : !clause || (!clause.isTypeOnly && (!!clause.name || !clause.namedBindings?.elements || clause.namedBindings.elements.some((item) => !item.isTypeOnly)));
    found.push({ spec, target: posix(resolved), runtime });
  }
  edges.set(name, found); for (const edge of found) source(edge.target);
}
source(FETCH); source(SCAN);
const closure = (root, runtime = false, external = "") => { const seen = new Set(); const visit = (name) => { if (seen.has(name) || name === external) return; seen.add(name); for (const edge of edges.get(name)) if (!runtime || edge.runtime) visit(edge.target); }; visit(root); return [...seen].sort(order); };
const complete = new Map([[FETCH, closure(FETCH)], [SCAN, closure(SCAN)]]), runtime = new Map([[FETCH, closure(FETCH, true)], [SCAN, closure(SCAN, true, FETCH)]]);
const tree = (files) => sha(files.map((name) => `${name}\0${sha(raw.get(name))}\n`).join(""));
const exportsFor = (root) => { const file = project.program.getSourceFile(path.join(ROOT, root)), symbol = project.checker.getSymbolAtLocation(file); return project.checker.getExportsOfModule(symbol).filter((item) => item.flags & SymbolFlags.Value).map((item) => item.name).sort(order); };
const temp = path.join(process.env.TMPDIR || "/tmp", `sync-protocol-${process.pid}`); fs.mkdirSync(temp, { recursive: false }); process.on("exit", () => fs.rmSync(temp, { recursive: true, force: true }));
try { execFileSync(process.execPath, [fileURLToPath(new URL("../node_modules/typescript/lib/tsc.js", import.meta.url)), "--ignoreConfig", "--target", "es2022", "--module", "commonjs", "--moduleResolution", "bundler", "--removeComments", "--skipLibCheck", "--rootDir", ".", "--outDir", temp, FETCH, SCAN], { cwd: ROOT, stdio: "pipe" }); } catch { fail("RS-FC-SOURCE-CLOSURE", "emit"); }
const fold = (text) => { const lines = text.trim().split("\n"), out = []; for (let i = 0; i < lines.length; i += 3) out.push(lines.slice(i, i + 3).map((line) => line.trimEnd()).join(" ")); return out.join("\n"); };
function chunk(id, entry, dependency) {
  const files = runtime.get(entry), indexes = new Map(files.map((name, index) => [name, index]));
  const factories = files.map((name) => { let code = fs.readFileSync(path.join(temp, name.replace(/\.ts$/u, ".js")), "utf8").replace(/^"use strict";\n|^Object\.defineProperty\(exports, "__esModule", \{ value: true \}\);\n|^exports\.[^\n]+ = void 0;\n/gmu, ""); code = code.replace(/require\("([^"]+)"\)/gu, (_, spec) => { const edge = edges.get(name).find((item) => item.spec === spec && item.runtime); if (!edge) fail("RS-FC-SOURCE-CLOSURE", name); return edge.target === dependency ? "__fetch" : `__load(${indexes.get(edge.target)})`; }); if (/\brequire\s*\(/u.test(code)) fail("RS-FC-SOURCE-CLOSURE", name); return `(exports,__load)=>{\n${fold(code)}\n}`; });
  const names = exportsFor(entry), banner = `// Generated by scripts/sync-protocol.mjs. DO NOT EDIT.\n// chunk=${id}; target=ES2022; typescript=${VERSION}; source-tree-sha256=${tree(complete.get(entry))}\n`;
  return { names, text: banner + (dependency ? 'import * as __fetch from "./fetch-machine.generated.js";\n' : "") + `const __factories=[\n${factories.join(",\n")}\n];\nconst __cache=[];const __load=(id)=>{if(__cache[id])return __cache[id];const exports={};__cache[id]=exports;__factories[id](exports,__load);return exports;};\nconst __entry=__load(${indexes.get(entry)});\n${names.map((name) => `export const ${name}=__entry.${name};`).join("\n")}\n` };
}
const made = [["fetch-machine", FETCH, ""], ["scan-machine", SCAN, FETCH]].map(([id, entry, dependency]) => ({ id, entry, dependency, ...chunk(id, entry, dependency) }));
const sources = Object.fromEntries([...raw].sort(([a], [b]) => order(a, b)).map(([name, bytes]) => [name, sha(bytes)]));
const chunks = made.map(({ id, entry, dependency, names, text }) => ({ id, file: `${id}.generated.js`, entry, depends_on: dependency ? ["fetch-machine"] : [], exports: names, source_paths: complete.get(entry), source_tree_sha256: tree(complete.get(entry)), bytes: Buffer.byteLength(text), sha256: sha(text) }));
const artifacts = new Map(made.map(({ id, text }) => [`${OUT}/${id}.generated.js`, text])); artifacts.set(`${OUT}/manifest.json`, JSON.stringify({ schema_version: 1, generator: "scripts/sync-protocol.mjs", typescript_version: VERSION, target: "ES2022", sources, chunks }, null, 2) + "\n");
if (check) for (const [name, text] of artifacts) { let actual = ""; try { actual = fs.readFileSync(name, "utf8"); } catch {} if (actual !== text) { if (name === `${OUT}/manifest.json`) fail("RS-FC-ARTIFACT-TAMPER", name); let stale = false; try { const old = JSON.parse(fs.readFileSync(`${OUT}/manifest.json`, "utf8")); stale = Object.entries(sources).some(([key, value]) => old.sources?.[key] !== value); } catch {} fail(stale ? "RS-FC-ARTIFACT-STALE" : "RS-FC-ARTIFACT-TAMPER", name); } }
else { fs.mkdirSync(OUT, { recursive: true }); for (const [name, text] of artifacts) { const staged = `${name}.tmp-${process.pid}`; fs.writeFileSync(staged, text); fs.renameSync(staged, name); } }
fs.rmSync(temp, { recursive: true }); snap.dispose(); api.close();
