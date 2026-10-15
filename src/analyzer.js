// Análisis heurístico de un ejecutable o archivo de datos (Node o navegador).
// Lee cabeceras (PE, CLR, imports, secciones) y busca marcas conocidas. No ejecuta nada ni envía el archivo a ningún sitio.
// Es una estimación orientativa: el diagnóstico real requiere revisar la aplicación completa.

const MAX_SCAN = 64 * 1024 * 1024; // bytes que se escanean buscando cadenas

const LEVELS = {
  alta: { label: 'Alta', color: 'ok' },
  media: { label: 'Media', color: 'warn' },
  baja: { label: 'Baja', color: 'bad' },
  info: { label: 'Necesita otro paso', color: 'info' },
};

function cstr(u8, off, max = 256) {
  let s = '';
  for (let i = 0; i < max && off + i < u8.length; i++) {
    const c = u8[off + i];
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function latin1(u8) {
  const view = u8.length > MAX_SCAN ? u8.subarray(0, MAX_SCAN) : u8;
  try {
    return new TextDecoder('latin1').decode(view);
  } catch {
    let s = '';
    for (let i = 0; i < view.length; i += 0x8000) s += String.fromCharCode.apply(null, view.subarray(i, i + 0x8000));
    return s;
  }
}

const fmtSize = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

function result(base, extra) {
  const level = LEVELS[extra.level] || LEVELS.info;
  return { ok: true, ...base, ...extra, levelLabel: level.label, levelColor: level.color };
}

// ───────────────────────── PE (exe, dll, ocx) ─────────────────────────
function parsePE(u8, dv) {
  if (u8.length < 0x40 || u8[0] !== 0x4d || u8[1] !== 0x5a) return null; // 'MZ'
  const pe = dv.getUint32(0x3c, true);
  if (pe + 24 > u8.length || dv.getUint32(pe, true) !== 0x00004550) return null; // 'PE\0\0'
  const machine = dv.getUint16(pe + 4, true);
  const nsec = dv.getUint16(pe + 6, true);
  const timestamp = dv.getUint32(pe + 8, true);
  const optSize = dv.getUint16(pe + 20, true);
  const characteristics = dv.getUint16(pe + 22, true);
  const opt = pe + 24;
  const magic = dv.getUint16(opt, true);
  const plus = magic === 0x20b;
  const nDirs = dv.getUint32(opt + (plus ? 108 : 92), true);
  const ddOff = opt + (plus ? 112 : 96);
  const dir = (i) => (i < nDirs && ddOff + i * 8 + 8 <= u8.length
    ? { rva: dv.getUint32(ddOff + i * 8, true), size: dv.getUint32(ddOff + i * 8 + 4, true) }
    : { rva: 0, size: 0 });

  const sections = [];
  const secOff = opt + optSize;
  for (let i = 0; i < Math.min(nsec, 96); i++) {
    const o = secOff + i * 40;
    if (o + 40 > u8.length) break;
    sections.push({
      name: cstr(u8, o, 8),
      vsize: dv.getUint32(o + 8, true),
      va: dv.getUint32(o + 12, true),
      rawSize: dv.getUint32(o + 16, true),
      rawPtr: dv.getUint32(o + 20, true),
    });
  }
  const rvaToOff = (rva) => {
    for (const s of sections) {
      if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) {
        const off = rva - s.va + s.rawPtr;
        return off < u8.length ? off : null;
      }
    }
    return null;
  };

  // Tabla de importaciones: nombres de DLL
  const imports = [];
  const imp = dir(1);
  if (imp.rva) {
    let o = rvaToOff(imp.rva);
    for (let i = 0; o !== null && i < 512 && o + 20 <= u8.length; i++, o += 20) {
      const nameRva = dv.getUint32(o + 12, true);
      if (!nameRva && !dv.getUint32(o, true) && !dv.getUint32(o + 16, true)) break;
      const no = rvaToOff(nameRva);
      if (no !== null) imports.push(cstr(u8, no, 128).toLowerCase());
    }
  }

  // Cabecera CLR (.NET)
  let clr = null;
  const com = dir(14);
  if (com.rva) {
    const o = rvaToOff(com.rva);
    if (o !== null && o + 24 <= u8.length) {
      const flags = dv.getUint32(o + 16, true);
      const metaOff = rvaToOff(dv.getUint32(o + 8, true));
      let version = '';
      if (metaOff !== null && metaOff + 16 <= u8.length && dv.getUint32(metaOff, true) === 0x424a5342) {
        const len = dv.getUint32(metaOff + 12, true);
        version = cstr(u8, metaOff + 16, Math.min(len, 64));
      }
      // ILONLY (0x1) o IL_LIBRARY (0x4, precompilado ReadyToRun): el IL sigue presente y es recuperable.
      clr = { flags, ilOnly: (flags & 1) === 1 || (flags & 4) === 4, readyToRun: (flags & 4) === 4, version };
    }
  }

  return {
    arch: { 0x14c: 'x86 (32 bits)', 0x8664: 'x64 (64 bits)', 0xaa64: 'ARM64', 0x1c0: 'ARM' }[machine] || `0x${machine.toString(16)}`,
    isDll: (characteristics & 0x2000) !== 0,
    timestamp,
    sections,
    imports,
    clr,
  };
}

function compileDate(ts) {
  const d = new Date(ts * 1000);
  const y = d.getUTCFullYear();
  if (!ts || y < 1993 || d.getTime() > Date.now() + 86400000) return null; // compilaciones reproducibles dan fechas sin sentido
  return d.toISOString().slice(0, 10);
}

const has = (txt, ...needles) => needles.some((n) => txt.includes(n));

function netFramework(txt, clr) {
  const core = txt.match(/\.NETCoreApp,Version=v(\d+\.\d+)/);
  if (core) return { label: `.NET ${core[1]} (moderno)`, modern: true };
  const fw = txt.match(/\.NETFramework,Version=v(\d+(?:\.\d+)*)/);
  if (fw) return { label: `.NET Framework ${fw[1]}`, modern: false };
  const std = txt.match(/\.NETStandard,Version=v(\d+\.\d+)/);
  if (std) return { label: `.NET Standard ${std[1]} (librería)`, modern: true };
  if (has(txt, 'System.Private.CoreLib')) return { label: '.NET moderno (Core / 5+)', modern: true };
  const v = clr?.version || '';
  if (v.startsWith('v1.0')) return { label: '.NET Framework 1.0', modern: false };
  if (v.startsWith('v1.1')) return { label: '.NET Framework 1.1', modern: false };
  if (v.startsWith('v2.0')) return { label: '.NET Framework 2.0 – 3.5', modern: false };
  if (v.startsWith('v4.0')) return { label: '.NET Framework 4.x', modern: false };
  return { label: '.NET (versión no identificada)', modern: false };
}

const NET_LIBS = [
  ['System.Windows.Forms', 'Interfaz de escritorio WinForms'],
  ['PresentationFramework', 'Interfaz de escritorio WPF'],
  ['System.ServiceModel', 'Servicios WCF'],
  ['System.Web.Mvc', 'ASP.NET MVC'],
  ['System.Web', 'ASP.NET (web clásica)'],
  ['Microsoft.AspNetCore', 'ASP.NET Core'],
  ['Microsoft.EntityFrameworkCore', 'Entity Framework Core'],
  ['EntityFramework', 'Entity Framework 6'],
  ['Microsoft.VisualBasic', 'Probablemente escrita en VB.NET'],
  ['System.Data.SqlClient', 'Base de datos SQL Server'],
  ['Microsoft.Data.SqlClient', 'Base de datos SQL Server'],
  ['MySql.Data', 'Base de datos MySQL'],
  ['Npgsql', 'Base de datos PostgreSQL'],
  ['Oracle.ManagedDataAccess', 'Base de datos Oracle'],
  ['Oracle.DataAccess', 'Base de datos Oracle'],
  ['System.Data.OleDb', 'Acceso OLE DB (a menudo Access o Excel)'],
  ['System.Data.SQLite', 'Base de datos SQLite'],
  ['CrystalDecisions', 'Informes Crystal Reports'],
  ['DevExpress', 'Componentes DevExpress (licencia de terceros)'],
  ['Telerik', 'Componentes Telerik (licencia de terceros)'],
  ['Infragistics', 'Componentes Infragistics (licencia de terceros)'],
];

const OBFUSCATORS = [
  ['ConfusedByAttribute', 'ConfuserEx'],
  ['DotfuscatorAttribute', 'Dotfuscator'],
  ['SmartAssembly', 'SmartAssembly'],
  ['Eazfuscator', 'Eazfuscator.NET'],
  ['BabelObfuscatorAttribute', 'Babel Obfuscator'],
  ['CryptoObfuscator', 'Crypto Obfuscator'],
  ['Xenocode', 'Xenocode'],
  ['AgileDotNet', 'Agile.NET'],
  ['dnGuard', 'DNGuard'],
];

const PACKERS = [
  [/^UPX\d?$/, 'UPX', 'comprimido'],
  [/^\.aspack$|^\.adata$/, 'ASPack', 'comprimido'],
  [/^MPRESS\d$/, 'MPRESS', 'comprimido'],
  [/^PEC2|^PECompact/, 'PECompact', 'comprimido'],
  [/^\.petite$/, 'Petite', 'comprimido'],
  [/^\.themida$|^\.winlice$/, 'Themida / WinLicense', 'protegido'],
  [/^\.vmp\d$/, 'VMProtect', 'protegido'],
  [/^\.enigma\d$/, 'Enigma Protector', 'protegido'],
];

function analyzePE(info, txt, base) {
  const details = [
    { label: 'Tipo', value: info.isDll ? 'Librería (DLL / OCX)' : 'Ejecutable (EXE)' },
    { label: 'Arquitectura', value: info.arch },
  ];
  const date = compileDate(info.timestamp);
  if (date) details.push({ label: 'Fecha de compilación (aprox.)', value: date });

  const findings = [];
  const warnings = [];
  const imports = info.imports;
  const imp = (re) => imports.find((d) => re.test(d));

  const packer = info.sections.map((s) => PACKERS.find(([re]) => re.test(s.name))).find(Boolean);

  // Instaladores
  if (has(txt, 'Inno Setup', 'NullsoftInst', 'Nullsoft Install System', 'InstallShield') && !info.clr) {
    return result(base, {
      tech: 'Instalador',
      level: 'info',
      summary: 'Esto parece un instalador, no la aplicación en sí. Instálala en un equipo de pruebas y analiza el ejecutable principal que queda en la carpeta del programa.',
      details,
      findings: [],
      nextSteps: ['Busca la carpeta de instalación (normalmente en Archivos de programa) y analiza el .exe principal.'],
      warnings,
    });
  }

  // ── .NET
  if (info.clr) {
    const fw = netFramework(txt, info.clr);
    details.push({ label: 'Plataforma', value: fw.label });
    if (info.clr.version) details.push({ label: 'Versión del runtime', value: info.clr.version });
    if (info.clr.readyToRun) details.push({ label: 'Compilación', value: 'Precompilada (ReadyToRun), conserva el código intermedio' });
    let libs = [...new Set(NET_LIBS.filter(([n]) => txt.includes(n)).map(([, l]) => l))];
    if (libs.includes('ASP.NET MVC') || fw.modern) libs = libs.filter((l) => l !== 'ASP.NET (web clásica)');
    findings.push(...libs);
    const obf = OBFUSCATORS.filter(([n]) => txt.includes(n)).map(([, l]) => l);
    if (packer?.[2] === 'protegido') obf.push(packer[1]);

    let level = 'alta';
    let summary = 'Las aplicaciones .NET conservan gran parte de su estructura al compilarse: clases, métodos, consultas y lógica de negocio suelen recuperarse con alta fidelidad, sin comentarios ni algunos nombres locales.';
    if (!info.clr.ilOnly) {
      level = 'media';
      summary = 'Es una aplicación .NET que mezcla código gestionado y nativo (C++/CLI). La parte .NET se recupera bien; la parte nativa requiere más trabajo.';
    }
    if (obf.length) {
      level = packer?.[2] === 'protegido' ? 'baja' : 'media';
      warnings.push(`Se han detectado marcas de ofuscación o protección: ${obf.join(', ')}. La recuperación es posible en muchos casos, pero más laboriosa.`);
    } else if (txt.includes('ObfuscationAttribute')) {
      warnings.push('Contiene atributos de configuración de ofuscación. Puede que parte del código esté ofuscado.');
    }
    if (!fw.modern) findings.push('Candidata a migración a .NET moderno');
    return result(base, {
      tech: `Aplicación ${fw.label}`,
      category: 'net',
      level,
      summary,
      details,
      findings,
      warnings,
      nextSteps: [
        'Conserva el .exe, todas las DLL de la carpeta y los archivos .config.',
        'Si puedes, guarda una copia de la base de datos que usa.',
        fw.modern ? 'Revisar si el código está documentado y versionado.' : 'Valorar la migración a .NET moderno una vez recuperado el código.',
      ],
    });
  }

  // ── Empaquetados / protegidos (nativos)
  if (packer) {
    details.push({ label: 'Empaquetado', value: packer[1] });
    const protegido = packer[2] === 'protegido';
    return result(base, {
      tech: protegido ? `Ejecutable protegido con ${packer[1]}` : `Ejecutable comprimido con ${packer[1]}`,
      category: 'packed',
      level: protegido ? 'baja' : 'info',
      summary: protegido
        ? 'El ejecutable está protegido contra el análisis. Recuperar su lógica es muy costoso; lo habitual es reconstruir la aplicación a partir de su comportamiento y de sus datos.'
        : 'El ejecutable está comprimido, lo que oculta la tecnología real. Se puede descomprimir para analizarlo; en el diagnóstico lo hacemos por ti.',
      details,
      findings,
      warnings,
      nextSteps: ['Envíanos más contexto: qué hace la aplicación, con qué base de datos trabaja y de qué año es.'],
    });
  }

  // ── Visual Basic 6 / 5
  const vb = imp(/^msvbvm(60|50)\.dll$/) || (txt.includes('VB5!') ? 'msvbvm60.dll' : null);
  if (vb) {
    const ver = vb.includes('50') ? '5' : '6';
    details.push({ label: 'Runtime', value: vb.toUpperCase() });
    return result(base, {
      tech: `Aplicación Visual Basic ${ver}`,
      category: 'vb6',
      level: 'media',
      summary: `En Visual Basic ${ver} se recuperan bien los formularios, controles y recursos. La lógica depende de cómo se compiló: en P-Code es bastante recuperable; en código nativo, solo parcialmente y hay que reconstruirla.`,
      details,
      findings: ['Tecnología sin soporte de Microsoft para su entorno de desarrollo', 'Candidata a migración a .NET o a web'],
      warnings,
      nextSteps: [
        'Conserva el .exe, los .ocx y .dll que lo acompañan y la base de datos.',
        'Anota qué procesos del negocio dependen de esta aplicación.',
      ],
    });
  }

  // ── Visual FoxPro
  const vfp = imp(/^vfp\d+[rt]\.dll$/);
  if (vfp) {
    details.push({ label: 'Runtime', value: vfp.toUpperCase() });
    return result(base, {
      tech: 'Aplicación Visual FoxPro',
      category: 'foxpro',
      level: 'media',
      summary: 'Visual FoxPro guarda el código compilado dentro del ejecutable. En muchos casos se puede recuperar una parte importante, salvo que se compilara con cifrado. Los datos (.dbf) suelen ser accesibles.',
      details,
      findings: ['Tecnología sin soporte desde hace años', 'Candidata a migración a web y a una base de datos actual'],
      warnings,
      nextSteps: ['Conserva el .exe y toda la carpeta de datos (.dbf, .cdx, .fpt).'],
    });
  }

  // ── PowerBuilder
  const pb = imp(/^pbvm\d+\.dll$/) || imp(/^pbdwe\d+\.dll$/);
  if (pb) {
    details.push({ label: 'Runtime', value: pb.toUpperCase() });
    return result(base, {
      tech: 'Aplicación PowerBuilder',
      category: 'powerbuilder',
      level: 'media',
      summary: 'Las aplicaciones PowerBuilder se distribuyen con librerías (.pbd) de las que a menudo se puede recuperar buena parte de la lógica y las ventanas.',
      details,
      findings: ['Candidata a migración a .NET o a web'],
      warnings,
      nextSteps: ['Conserva el .exe y todos los archivos .pbd y .dll de la carpeta.'],
    });
  }

  // ── Delphi / C++Builder
  const delphi = imp(/^borlndmm\.dll$|\.bpl$|^cc32\d+mt\.dll$/) || has(txt, 'PACKAGEINFO', 'DVCLAL', 'SOFTWARE\\Borland\\Delphi', 'Embarcadero Delphi', 'FastMM');
  if (delphi) {
    return result(base, {
      tech: 'Aplicación Delphi / C++Builder',
      category: 'delphi',
      level: 'media',
      summary: 'De Delphi se recuperan bien los formularios y su estructura. La lógica está compilada a código nativo: se puede analizar, pero normalmente hay que reconstruirla a partir de ese análisis, del comportamiento y de la base de datos.',
      details,
      findings: ['Candidata a migración a .NET o a web'],
      warnings,
      nextSteps: ['Conserva el .exe, las .bpl o .dll que lo acompañen y la base de datos.'],
    });
  }

  // ── Otros entornos reconocibles
  const others = [
    [() => has(txt, 'PyInstaller', '_MEIPASS', 'PYZ-00.pyz') || imp(/^python\d+\.dll$/), 'Aplicación Python empaquetada', 'media', 'El código Python suele poder extraerse del paquete; la calidad depende de la versión de Python usada.'],
    [() => has(txt, 'AU3!EA06', '>>>AUTOIT SCRIPT<<<'), 'Script AutoIt compilado', 'media', 'Los scripts AutoIt compilados suelen poder extraerse.'],
    [() => imp(/^clarun\.dll$/i), 'Aplicación Clarion', 'baja', 'Clarion compila a código nativo; lo habitual es reconstruir la lógica a partir del análisis y de los datos.'],
    [() => has(txt, 'Go build ID:'), 'Aplicación Go', 'baja', 'Go compila a código nativo. Se puede analizar, pero recuperar el código original no es viable; se reconstruye.'],
    [() => imp(/^jvm\.dll$/) || has(txt, 'Launch4j'), 'Lanzador de una aplicación Java', 'info', 'Es un envoltorio de una aplicación Java. Busca el archivo .jar en la carpeta del programa y analízalo: Java se recupera muy bien.'],
  ];
  for (const [test, tech, level, summary] of others) {
    if (test()) return result(base, { tech, category: 'other', level, summary, details, findings, warnings, nextSteps: ['Conserva toda la carpeta del programa y la base de datos.'] });
  }

  // ── Nativo C / C++
  const mfc = imp(/^mfc\d+u?d?\.dll$/);
  const qt = imp(/^qt\dcore\.dll$/);
  const vc = imp(/^(msvcr\d+|vcruntime\d+|msvcp\d+|msvcp_win|ucrtbase)\.dll$|^api-ms-win-crt-/);
  details.push({ label: 'Librerías principales', value: imports.slice(0, 6).join(', ') || 'no identificadas' });
  return result(base, {
    tech: mfc ? 'Aplicación C++ (MFC)' : qt ? 'Aplicación C++ (Qt)' : vc ? 'Aplicación nativa C / C++' : 'Aplicación nativa',
    category: 'native',
    level: 'baja',
    summary: 'Está compilada a código máquina. Se puede analizar su funcionamiento, pero el código original no se recupera: lo habitual es reconstruir la lógica a partir del análisis, del comportamiento y de su base de datos.',
    details,
    findings,
    warnings,
    nextSteps: ['Conserva la carpeta del programa, la base de datos y cualquier documentación o manual.', 'Anota qué hace la aplicación y qué procesos dependen de ella.'],
  });
}

// ───────────────────────── API pública ─────────────────────────
export function analyzeFile(buffer, fileName = '') {
  const u8 = new Uint8Array(buffer);
  const dv = new DataView(buffer);
  const ext = (fileName.split('.').pop() || '').toLowerCase();
  const base = { fileName, size: fmtSize(u8.length) };
  if (u8.length < 4) return { ok: false, error: 'El archivo está vacío o es demasiado pequeño.' };

  const head = cstr(u8, 0, 32);
  const at4 = cstr(u8, 4, 16);

  // Access
  if (at4.startsWith('Standard Jet DB') || at4.startsWith('Standard ACE DB')) {
    const ace = at4.startsWith('Standard ACE DB');
    return result(base, {
      tech: ace ? 'Base de datos Access (.accdb / .accde)' : 'Base de datos Access (.mdb / .mde)',
      category: 'access',
      level: 'alta',
      summary: 'Las tablas, consultas y datos de Access son accesibles y se pueden migrar a un motor actual como PostgreSQL o SQL Server. Los formularios y el código VBA se recuperan si el archivo no está compilado como .mde o .accde.',
      details: [{ label: 'Formato', value: ace ? 'Motor ACE (Access 2007 o posterior)' : 'Motor Jet (Access 97 – 2003)' }],
      findings: ['Candidata a migración a aplicación web con base de datos actual'],
      warnings: [],
      nextSteps: ['Haz una copia del archivo con todos los usuarios fuera de la aplicación.', 'Comprueba si hay otro archivo con los datos (aplicaciones divididas en "front-end" y "back-end").'],
    });
  }

  // SQLite
  if (head.startsWith('SQLite format 3')) {
    return result(base, {
      tech: 'Base de datos SQLite',
      category: 'data',
      level: 'alta',
      summary: 'Es una base de datos SQLite: los datos son accesibles y se pueden migrar sin problema. Para saber qué hace la aplicación, analiza también su ejecutable.',
      details: [],
      findings: [],
      warnings: [],
      nextSteps: ['Analiza el ejecutable principal de la aplicación que usa esta base de datos.'],
    });
  }

  // Java .class
  if (dv.getUint32(0, false) === 0xcafebabe && ext === 'class') {
    return result(base, {
      tech: 'Clase Java compilada',
      category: 'java',
      level: 'alta',
      summary: 'El código Java compilado se recupera con mucha fidelidad, salvo que esté ofuscado.',
      details: [],
      findings: [],
      warnings: [],
      nextSteps: ['Analiza el .jar completo de la aplicación si lo tienes.'],
    });
  }

  // ZIP / JAR / APK
  if (u8[0] === 0x50 && u8[1] === 0x4b && u8[2] === 0x03 && u8[3] === 0x04) {
    const txt = latin1(u8);
    if (txt.includes('AndroidManifest.xml')) {
      return result(base, { tech: 'Aplicación Android (APK)', category: 'java', level: 'alta', summary: 'Las aplicaciones Android se pueden descompilar con buena fidelidad, salvo ofuscación.', details: [], findings: [], warnings: [], nextSteps: [] });
    }
    if (txt.includes('META-INF/MANIFEST.MF') || ext === 'jar' || ext === 'war') {
      return result(base, {
        tech: 'Aplicación Java (.jar)',
        category: 'java',
        level: 'alta',
        summary: 'El código Java compilado se recupera con mucha fidelidad. Si está ofuscado (nombres como a, b, c), la lógica sigue siendo recuperable pero cuesta más entenderla.',
        details: [],
        findings: ['Candidata a modernización si usa versiones antiguas de Java'],
        warnings: [],
        nextSteps: ['Conserva el .jar, las librerías que lo acompañan y la configuración.'],
      });
    }
    return result(base, { tech: 'Archivo comprimido', category: 'zip', level: 'info', summary: 'Es un archivo comprimido. Descomprímelo y analiza el ejecutable principal que contenga.', details: [], findings: [], warnings: [], nextSteps: [] });
  }

  // DBF (dBase / FoxPro)
  if (ext === 'dbf' && [0x02, 0x03, 0x30, 0x31, 0x32, 0x43, 0x63, 0x83, 0x8b, 0xcb, 0xf5, 0xfb].includes(u8[0])) {
    return result(base, {
      tech: 'Tabla dBase / FoxPro (.dbf)',
      category: 'data',
      level: 'alta',
      summary: 'Es una tabla dBase o FoxPro: los datos son accesibles y se pueden migrar a una base de datos actual. Para recuperar la lógica, analiza también el ejecutable de la aplicación.',
      details: [],
      findings: [],
      warnings: [],
      nextSteps: ['Analiza el ejecutable principal y conserva toda la carpeta de datos.'],
    });
  }

  // Ejecutables Windows
  let info = null;
  try {
    info = parsePE(u8, dv);
  } catch {
    info = null;
  }
  if (info) {
    const r = analyzePE(info, latin1(u8), base);
    // Datos técnicos en bruto para la pestaña de detalles del informe.
    r.raw = {
      format: info.isDll ? 'PE (DLL)' : 'PE (EXE)',
      arch: info.arch,
      sections: info.sections.map((s) => ({ name: s.name || '(sin nombre)', size: s.rawSize })),
      imports: info.imports,
      clr: info.clr ? { version: info.clr.version, ilOnly: info.clr.ilOnly, readyToRun: !!info.clr.readyToRun } : null,
    };
    return r;
  }

  return {
    ok: false,
    error: 'No reconocemos este tipo de archivo. La herramienta analiza ejecutables de Windows (.exe, .dll, .ocx), bases de datos Access (.mdb, .accdb), archivos Java (.jar) y tablas .dbf.',
  };
}
