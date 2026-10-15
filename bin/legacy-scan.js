#!/usr/bin/env node
// legacy-scan: inventario de software heredado en una carpeta (o archivos sueltos).
// Detecta la tecnología de cada ejecutable/base de datos y estima si su código es recuperable.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { analyzeFile } from '../src/analyzer.js';

const pkg = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf-8'));
const EXTENSIONS = new Set(['exe', 'dll', 'ocx', 'mdb', 'accdb', 'mde', 'accde', 'jar', 'war', 'class', 'apk', 'dbf', 'db', 'sqlite']);
const SKIP_DIRS = new Set(['node_modules', '.git', '.svn', 'venv', '.venv', '__pycache__', '$RECYCLE.BIN', 'System Volume Information']);
const MAX_BYTES = 300 * 1024 * 1024;

const HELP = `legacy-scan ${pkg.version} · inventario de software heredado

Uso:
  legacy-scan <carpeta|archivo> [más rutas...] [opciones]

Opciones:
  --json          Salida en JSON (para guardar o procesar)
  --depth <n>     Profundidad máxima al recorrer carpetas (por defecto 6)
  --all           Mostrar también los archivos no reconocidos
  -h, --help      Esta ayuda
  -v, --version   Versión

Ejemplos:
  legacy-scan "C:\\Program Files (x86)\\MiAplicacion"
  legacy-scan .\\app.exe .\\datos.mdb --json > informe.json

Todo se analiza en local: los archivos no se envían a ningún sitio.
Versión web: https://www.stellariscode.com/analizar-exe`;

function parseArgs(argv) {
  const opts = { paths: [], json: false, depth: 6, all: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--all') opts.all = true;
    else if (a === '--depth') opts.depth = Math.max(0, parseInt(argv[++i], 10) || 0);
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else opts.paths.push(a);
  }
  return opts;
}

function* walk(target, depth) {
  let st;
  try {
    st = fs.statSync(target);
  } catch {
    return;
  }
  if (st.isFile()) {
    yield target;
    return;
  }
  if (!st.isDirectory() || depth < 0) return;
  let entries = [];
  try {
    entries = fs.readdirSync(target, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p = path.join(target, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(p, depth - 1);
    } else if (e.isFile()) {
      yield p;
    }
  }
}

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const COLORS = { ok: 32, warn: 33, bad: 31, info: 36 };
const pad = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s.padEnd(n));
// Para rutas: recorta por el principio, que es la parte menos útil.
const padPath = (s, n) => (s.length > n ? `…${s.slice(-(n - 1))}` : s.padEnd(n));

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.version) return console.log(pkg.version);
  if (opts.help || opts.paths.length === 0) return console.log(HELP);

  const results = [];
  for (const root of opts.paths) {
    const isFile = fs.existsSync(root) && fs.statSync(root).isFile();
    for (const file of walk(root, opts.depth)) {
      const ext = path.extname(file).slice(1).toLowerCase();
      if (!isFile && !EXTENSIONS.has(ext)) continue;
      let size = 0;
      try {
        size = fs.statSync(file).size;
      } catch {
        continue;
      }
      if (size > MAX_BYTES) {
        results.push({ path: file, root, ok: false, error: 'Archivo demasiado grande (más de 300 MB)' });
        continue;
      }
      try {
        const buf = fs.readFileSync(file);
        const r = analyzeFile(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength), path.basename(file));
        results.push({ path: file, root, ...r });
      } catch (e) {
        results.push({ path: file, root, ok: false, error: e.message });
      }
    }
  }

  if (opts.json) {
    const clean = results.map(({ root, ...rest }) => rest);
    console.log(JSON.stringify({ tool: 'legacy-scan', version: pkg.version, date: new Date().toISOString(), results: clean }, null, 2));
    return;
  }

  const shown = results.filter((r) => r.ok || opts.all);
  if (shown.length === 0) {
    console.log('No se han encontrado ejecutables ni bases de datos reconocibles.');
    return;
  }
  console.log(`\n${paint(1, 'legacy-scan')} · ${shown.length} archivo(s) analizado(s)\n`);
  console.log(paint(2, `${pad('Archivo', 34)} ${pad('Tecnología', 40)} Recuperación`));
  for (const r of shown) {
    const base = fs.statSync(r.root).isFile() ? path.dirname(r.root) : r.root;
    const name = path.relative(base, r.path) || path.basename(r.path);
    if (!r.ok) {
      console.log(`${padPath(name, 34)} ${paint(2, pad(r.error || 'No reconocido', 40))} -`);
      continue;
    }
    console.log(`${padPath(name, 34)} ${pad(r.tech, 40)} ${paint(COLORS[r.levelColor] || 0, r.levelLabel)}`);
    for (const w of r.warnings) console.log(paint(33, `  ⚠ ${w}`));
  }

  const byTech = {};
  for (const r of shown.filter((x) => x.ok)) byTech[r.tech] = (byTech[r.tech] || 0) + 1;
  console.log(`\n${paint(1, 'Resumen por tecnología')}`);
  for (const [t, n] of Object.entries(byTech).sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(3)}  ${t}`);
  console.log(paint(2, '\nEstimación automática a partir de la estructura de los archivos. No sustituye a un diagnóstico.'));
  console.log(paint(2, 'Más detalle: añade --json. ¿Necesitas ayuda para migrarlo? https://www.stellariscode.com/diagnostico\n'));
}

main();
