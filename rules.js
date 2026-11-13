
const JS = ['javascript', 'javascriptreact', 'typescript', 'typescriptreact', 'html', 'vue'];
const PY = ['python'];
const PHP = ['php'];
const JAVA = ['java'];

const RULES = [
  {
    id: 'secret-generic', severity: 'error', langs: null, cwe: 'CWE-798',
    pattern: /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/i,
    title: 'Posible credencial escrita directamente en el código',
    fix: 'Muévela a una variable de entorno (.env fuera de git) o a un gestor de secretos. Si ya se subió a git, revócala y genera una nueva.',
    example: 'const key = process.env.API_KEY;'
  },
  {
    id: 'secret-aws', severity: 'error', langs: null, cwe: 'CWE-798',
    pattern: /AKIA[0-9A-Z]{16}/,
    title: 'Posible Access Key de AWS expuesta',
    fix: 'Revócala en IAM ahora mismo, crea otra y cárgala por variables de entorno o roles de IAM.'
  },
  {
    id: 'secret-private-key', severity: 'error', langs: null, cwe: 'CWE-321',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    title: 'Clave privada dentro del repositorio',
    fix: 'Elimínala del código y del historial de git, rótala y guárdala fuera del proyecto.'
  },
  {
    id: 'secret-github', severity: 'error', langs: null, cwe: 'CWE-798',
    pattern: /gh[pousr]_[A-Za-z0-9]{36,}/,
    title: 'Posible token de GitHub expuesto',
    fix: 'Revócalo en GitHub > Settings > Developer settings y usa variables de entorno.'
  },
  {
    id: 'secret-google-key', severity: 'info', langs: null, cwe: 'CWE-798',
    pattern: /AIza[0-9A-Za-z_\-]{35}/,
    title: 'API key de Google/Firebase en el código',
    fix: 'Las keys web de Firebase son públicas por diseño, pero SOLO son seguras si tus reglas de Firestore/Storage están bien y la key tiene restricciones de dominio/API en Google Cloud.'
  },


  {
    id: 'js-eval', severity: 'error', langs: JS, cwe: 'CWE-95',
    pattern: /\beval\s*\(|\bnew\s+Function\s*\(/,
    title: 'Ejecución dinámica de código (eval / new Function)',
    fix: 'Evita eval. Para JSON usa JSON.parse; para lógica dinámica usa un mapa de funciones permitidas.',
    example: 'const data = JSON.parse(input);'
  },
  {
    id: 'js-xss-innerhtml', severity: 'warning', langs: JS, cwe: 'CWE-79',
    pattern: /\.(?:innerHTML|outerHTML)\s*(?:\+)?=(?!=)|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\(|dangerouslySetInnerHTML/,
    title: 'Posible XSS: se inserta HTML sin sanitizar',
    fix: 'Usa textContent para texto plano. Si necesitas HTML, sanitízalo con DOMPurify antes de insertarlo.',
    example: 'el.textContent = userInput;\n// o: el.innerHTML = DOMPurify.sanitize(userInput);'
  },
  {
    id: 'js-exec-injection', severity: 'error', langs: JS, cwe: 'CWE-78',
    pattern: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)/,
    title: 'Posible inyección de comandos (exec con datos concatenados)',
    fix: 'Usa execFile / spawn con un array de argumentos (sin shell) y valida la entrada contra una lista permitida.',
    example: "execFile('git', ['log', '-n', String(n)]);"
  },
  {
    id: 'js-path-traversal', severity: 'warning', langs: JS, cwe: 'CWE-22',
    pattern: /(?:readFile|readFileSync|createReadStream|sendFile)\s*\([^)]*req\.(?:query|params|body)/,
    title: 'Posible Path Traversal: ruta de archivo controlada por el usuario',
    fix: 'Normaliza con path.resolve y comprueba que el resultado siga dentro del directorio permitido; o usa IDs en lugar de nombres de archivo.',
    example: "const full = path.resolve(BASE, name);\nif (!full.startsWith(BASE + path.sep)) throw new Error('Ruta inválida');"
  },
  {
    id: 'js-math-random', severity: 'info', langs: JS, cwe: 'CWE-338',
    pattern: /Math\.random\s*\(\)/,
    title: 'Math.random no es criptográficamente seguro',
    fix: 'Si es para tokens, contraseñas o IDs secretos, usa crypto.randomBytes / crypto.randomUUID / crypto.getRandomValues.',
    example: "const token = require('crypto').randomBytes(32).toString('hex');"
  },
  {
    id: 'js-token-localstorage', severity: 'info', langs: JS, cwe: 'CWE-922',
    pattern: /localStorage\.setItem\(\s*["'][^"']*(?:token|jwt|session)[^"']*["']/i,
    title: 'Token guardado en localStorage (accesible por cualquier XSS)',
    fix: 'Prefiere cookies HttpOnly + Secure + SameSite para sesiones.'
  },
  {
    id: 'html-target-blank', severity: 'info', langs: JS, cwe: 'CWE-1022',
    pattern: /target=["']_blank["'](?![^>]*rel=)/,
    title: 'target="_blank" sin rel="noopener noreferrer"',
    fix: 'Añade rel="noopener noreferrer" para que la página abierta no controle window.opener.',
    example: '<a href="..." target="_blank" rel="noopener noreferrer">'
  },
  {
    id: 'cors-wildcard', severity: 'warning', langs: JS.concat(PY, PHP, JAVA), cwe: 'CWE-942',
    pattern: /Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|origin\s*:\s*["']\*["']|\bcors\(\s*\)/,
    title: 'CORS abierto a cualquier origen',
    fix: 'Permite solo los orígenes que necesitas. Nunca combines "*" con credenciales.',
    example: "app.use(cors({ origin: ['https://mi-sitio.com'] }));"
  },


  {
    id: 'electron-node-integration', severity: 'error', langs: JS, cwe: 'CWE-94',
    pattern: /nodeIntegration\s*:\s*true/,
    title: 'Electron: nodeIntegration activado',
    fix: 'Desactívalo y expón solo lo necesario con un preload + contextBridge. Un XSS con esto equivale a ejecución de código en el PC del usuario.',
    example: "webPreferences: { nodeIntegration: false, contextIsolation: true, preload: path.join(__dirname, 'preload.js') }"
  },
  {
    id: 'electron-context-isolation', severity: 'error', langs: JS, cwe: 'CWE-653',
    pattern: /contextIsolation\s*:\s*false/,
    title: 'Electron: contextIsolation desactivado',
    fix: 'Déjalo en true (es el valor por defecto) y usa contextBridge.exposeInMainWorld en el preload.'
  },
  {
    id: 'electron-web-security', severity: 'error', langs: JS, cwe: 'CWE-346',
    pattern: /webSecurity\s*:\s*false/,
    title: 'Electron: webSecurity desactivado',
    fix: 'Quita esta opción. Si tienes problemas de CORS, resuélvelos desde el proceso principal o el backend.'
  },


  {
    id: 'firebase-open-rules', severity: 'error', langs: null, cwe: 'CWE-284',
    pattern: /allow\s+(?:read|write|read\s*,\s*write|write\s*,\s*read)\s*:\s*if\s+true/,
    title: 'Reglas de Firebase abiertas a todo el mundo',
    fix: 'Exige autenticación y comprueba propiedad de los datos.',
    example: 'allow read, write: if request.auth != null && request.auth.uid == userId;'
  },


  {
    id: 'sql-injection', severity: 'error', langs: null, cwe: 'CWE-89',
    pattern: /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\n]*(?:["'`]\s*\+\s*\w|\$\{[^}]+\}|["']\s*%\s*\(?\w|\.format\()|\bf["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*\{/i,
    title: 'Posible inyección SQL (consulta construida con datos concatenados)',
    fix: 'Usa consultas parametrizadas / prepared statements; nunca concatenes entrada del usuario.',
    example: "db.query('SELECT * FROM users WHERE id = ?', [id]);"
  },

 
  {
    id: 'weak-hash', severity: 'warning', langs: null, cwe: 'CWE-327',
    pattern: /createHash\(\s*["'](?:md5|sha1)["']\s*\)|hashlib\.(?:md5|sha1)\(|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"/i,
    title: 'Algoritmo de hash débil (MD5/SHA-1)',
    fix: 'Para contraseñas usa bcrypt, scrypt o Argon2. Para integridad usa SHA-256 o superior.',
    example: "const hash = await bcrypt.hash(password, 12);"
  },
  {
    id: 'tls-disabled', severity: 'error', langs: null, cwe: 'CWE-295',
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/,
    title: 'Verificación de certificados TLS desactivada',
    fix: 'Quita la opción y arregla el certificado (o añade la CA correcta). Así evitas ataques man-in-the-middle.'
  },
  {
    id: 'insecure-http', severity: 'info', langs: null, cwe: 'CWE-319',
    pattern: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org)[^"'`\s]+/,
    title: 'URL sin cifrar (http://)',
    fix: 'Usa https:// para que los datos viajen cifrados.'
  },

 
  {
    id: 'py-pickle', severity: 'error', langs: PY, cwe: 'CWE-502',
    pattern: /\bpickle\.loads?\(|\byaml\.load\((?![^)]*Loader)/,
    title: 'Deserialización insegura (pickle / yaml.load)',
    fix: 'No deserialices datos no confiables con pickle. Para YAML usa yaml.safe_load; para datos usa JSON.',
    example: 'data = yaml.safe_load(text)'
  },
  {
    id: 'py-shell', severity: 'error', langs: PY, cwe: 'CWE-78',
    pattern: /shell\s*=\s*True|\bos\.system\(|\beval\(|\bexec\(/,
    title: 'Ejecución de comandos/código potencialmente peligrosa',
    fix: 'Usa subprocess.run([...lista de args...]) sin shell=True y valida la entrada.',
    example: "subprocess.run(['ls', '-l', folder], check=True)"
  },
  {
    id: 'py-debug', severity: 'warning', langs: PY, cwe: 'CWE-489',
    pattern: /\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True/,
    title: 'Modo debug activado',
    fix: 'Desactívalo en producción; el debugger expone ejecución de código y datos internos.'
  },

  
  {
    id: 'php-sqli', severity: 'error', langs: PHP, cwe: 'CWE-89',
    pattern: /\b(?:mysql_query|mysqli_query|->query)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/,
    title: 'Entrada del usuario dentro de una consulta SQL',
    fix: 'Usa PDO con prepared statements.',
    example: "$st = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$st->execute([$_GET['id']]);"
  },
  {
    id: 'php-include', severity: 'error', langs: PHP, cwe: 'CWE-98',
    pattern: /\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)/,
    title: 'Inclusión de archivos controlada por el usuario (LFI/RFI)',
    fix: 'Usa una lista blanca de archivos permitidos; nunca incluyas rutas que vengan de la petición.'
  },

 
  {
    id: 'java-deserialization', severity: 'warning', langs: JAVA, cwe: 'CWE-502',
    pattern: /new\s+ObjectInputStream\s*\(/,
    title: 'Deserialización Java nativa',
    fix: 'Evita ObjectInputStream con datos externos; usa JSON (Gson/Jackson) o un filtro de deserialización (ObjectInputFilter).'
  },
  {
    id: 'java-exec', severity: 'error', langs: JAVA, cwe: 'CWE-78',
    pattern: /Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+/,
    title: 'Posible inyección de comandos (Runtime.exec con concatenación)',
    fix: 'Usa ProcessBuilder con argumentos separados y valida la entrada.',
    example: 'new ProcessBuilder("git", "log", "-n", String.valueOf(n)).start();'
  }
];

module.exports = { RULES };