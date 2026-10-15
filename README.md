# legacy-scan

**Inventario de software heredado desde la línea de comandos.** Recorre una carpeta, detecta en qué tecnología está hecho cada ejecutable o base de datos (.NET, Visual Basic 6, Delphi, FoxPro, PowerBuilder, Access, Java…) y estima si su código es recuperable.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

> ¿Prefieres no instalar nada? Usa la versión web, que funciona igual y sin subir el archivo: **[stellariscode.com/analizar-exe](https://www.stellariscode.com/analizar-exe)**

---

## Para qué sirve

- Saber **qué tiene una empresa** antes de mantenerlo o migrarlo: qué aplicaciones hay, en qué están hechas y de qué dependen.
- Detectar **tecnologías sin soporte** (VB6, FoxPro, .NET Framework antiguo) antes de que den un susto.
- Estimar, antes de un presupuesto, **qué se puede recuperar** cuando se ha perdido el código fuente.

Todo se analiza **en local**: lee la estructura de los archivos (cabecera PE, tabla de importaciones, metadatos CLR, firmas conocidas). No ejecuta nada y no envía nada a ningún sitio.

## Uso

Sin instalar, con Node 18 o superior:

```bash
npx github:morexulo/legacy-scan "C:\Program Files (x86)\MiAplicacion"
```

O clonando el repositorio:

```bash
git clone https://github.com/morexulo/legacy-scan.git
cd legacy-scan
node bin/legacy-scan.js "C:\ruta\a\la\aplicacion"
```

### Opciones

| Opción | Qué hace |
|---|---|
| `--json` | Salida en JSON, para guardar el inventario o procesarlo |
| `--depth <n>` | Profundidad máxima al recorrer carpetas (por defecto 6) |
| `--all` | Muestra también los archivos no reconocidos |
| `-h`, `--help` | Ayuda |

### Ejemplo de salida

```text
legacy-scan · 309 archivo(s) analizado(s)

Archivo                            Tecnología                               Recuperación
Accessibility.dll                  Aplicación .NET Framework 4.x            Alta
AddInProcess.exe                   Aplicación .NET Framework 4.x            Alta
AdoNetDiag.dll                     Aplicación nativa                        Baja
aspnet_compiler.exe                Aplicación .NET Framework 4.x            Alta
…

Resumen por tecnología
  246  Aplicación .NET Framework 4.x
   55  Aplicación nativa
    5  Aplicación .NET Framework 4.5
    3  Aplicación nativa C / C++
```

*(Salida real al analizar la carpeta del .NET Framework de Windows.)*

## Qué detecta

| Tecnología | Cómo la reconoce | Recuperación típica |
|---|---|---|
| .NET Framework / .NET moderno | Cabecera CLR, versión del runtime, WinForms, WPF, ASP.NET, WCF, base de datos, ofuscadores | Alta |
| Java (`.jar`, `.class`, `.apk`) | Manifiesto y clases compiladas | Alta |
| Access (`.mdb`, `.accdb`) | Motor Jet o ACE | Alta (datos) |
| Visual Basic 5 / 6 | Runtime `MSVBVM` y firma `VB5!` | Media |
| Delphi / C++Builder | Marcas de Borland y Embarcadero | Media |
| Visual FoxPro | Runtime `VFP` | Media |
| PowerBuilder | Runtime `PBVM` | Media |
| C / C++ nativo, Go, Clarion | Librerías del compilador y del sistema | Baja |
| Comprimidos o protegidos | UPX, ASPack, Themida, VMProtect | Baja o variable |

**"Recuperación alta"** significa que, por la tecnología, es probable recuperar gran parte de la lógica a partir del ejecutable (por ejemplo, .NET o Java sin ofuscar). No es el código original idéntico: se pierden comentarios y algunos nombres.

## Como librería

```js
import fs from 'fs';
import { analyzeFile } from 'legacy-scan';

const buf = fs.readFileSync('app.exe');
const r = analyzeFile(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength), 'app.exe');
console.log(r.tech, r.levelLabel); // "Aplicación .NET Framework 4.x" "Alta"
```

El mismo motor funciona en el navegador: es el que usa la [versión web](https://www.stellariscode.com/analizar-exe).

## Limitaciones

- Es una **estimación heurística** a partir de la estructura del archivo. Puede equivocarse con tecnologías poco comunes y no sustituye a un diagnóstico.
- Úsalo solo con software del que seas titular o que tengas derecho a analizar. Recuperar o modificar código depende de la titularidad y de la licencia.

## Contribuir

Las propuestas son bienvenidas: nuevas firmas de tecnologías, correcciones o casos que detecte mal. Abre una *issue* con el resultado obtenido y la tecnología real (sin adjuntar binarios de terceros).

```bash
npm test
```

---

## English

`legacy-scan` is a zero-dependency CLI that inventories legacy software in a folder. It detects the technology behind executables and databases (.NET, VB6, Delphi, FoxPro, PowerBuilder, Access, Java…) by reading their headers locally, and estimates how much of their logic can be recovered. Run it with `npx github:morexulo/legacy-scan <folder>`. Output is in Spanish; `--json` gives a machine-readable report.

---

## Autor

Creado por **Jaime Salvador Moreno Villar** en **[Stellaris Code](https://www.stellariscode.com)**, donde me dedico al mantenimiento y la migración de software legado: recuperar la lógica de aplicaciones antiguas (aunque solo quede el ejecutable) y llevarlas a tecnología actual sin parar la operativa.

¿Tienes una aplicación así en tu empresa? [Primera consulta gratuita](https://www.stellariscode.com/diagnostico).

Licencia [MIT](LICENSE).
