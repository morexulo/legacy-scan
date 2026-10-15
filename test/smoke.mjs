// Pruebas mínimas con cabeceras sintéticas (no incluye binarios de terceros).
import assert from 'assert';
import { analyzeFile } from '../src/analyzer.js';

const buf = (bytes, size = 4096) => {
  const b = new Uint8Array(size);
  b.set(bytes, 0);
  return b.buffer;
};
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

const cases = [
  ['datos.mdb', buf([0, 1, 0, 0, ...ascii('Standard Jet DB')]), 'Base de datos Access (.mdb / .mde)', 'alta'],
  ['datos.accdb', buf([0, 1, 0, 0, ...ascii('Standard ACE DB')]), 'Base de datos Access (.accdb / .accde)', 'alta'],
  ['clientes.dbf', buf([0x03, 0x7a, 1, 1]), 'Tabla dBase / FoxPro (.dbf)', 'alta'],
  ['app.db', buf(ascii('SQLite format 3\0')), 'Base de datos SQLite', 'alta'],
];

for (const [name, data, tech, level] of cases) {
  const r = analyzeFile(data, name);
  assert.ok(r.ok, `${name}: debería reconocerse`);
  assert.strictEqual(r.tech, tech, `${name}: tecnología`);
  assert.strictEqual(r.level, level, `${name}: nivel`);
}

const unknown = analyzeFile(buf(ascii('hola mundo')), 'notas.bin');
assert.strictEqual(unknown.ok, false, 'un archivo desconocido no debe reconocerse');

console.log(`OK · ${cases.length + 1} comprobaciones`);
