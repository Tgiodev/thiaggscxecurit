const vscode = require('vscode');
const { RULES } = require('./rules');

const SEV = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information
};

const COMPILED = RULES.map((r) => ({
  ...r,
  re: new RegExp(r.pattern.source, r.pattern.flags.includes('g') ? r.pattern.flags : r.pattern.flags + 'g')
}));
const BY_ID = new Map(RULES.map((r) => [r.id, r]));

let collection;


const SEV_META = {
  error: { label: 'Alta', icon: 'error', color: 'problemsErrorIcon.foreground' },
  warning: { label: 'Media', icon: 'warning', color: 'problemsWarningIcon.foreground' },
  info: { label: 'Baja', icon: 'info', color: 'problemsInfoIcon.foreground' }
};

function sevKey(s) {
  if (s === vscode.DiagnosticSeverity.Error) return 'error';
  if (s === vscode.DiagnosticSeverity.Warning) return 'warning';
  return 'info';
}

class FindingsProvider {
  constructor() {
    this._em = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._em.event;
    this.view = null;
  }

  collect() {
    const groups = { error: [], warning: [], info: [] };
    collection.forEach((uri, diags) => {
      for (const d of diags) groups[sevKey(d.severity)].push({ uri, d });
    });
    return groups;
  }

  refresh() {
    this._em.fire();
    if (this.view) {
      const g = this.collect();
      const total = g.error.length + g.warning.length + g.info.length;
      this.view.badge = total ? { value: total, tooltip: `${total} hallazgos de seguridad` } : undefined;
    }
  }

  getTreeItem(el) { return el; }

  getChildren(el) {
    const g = this.collect();
    if (!el) {
      const total = g.error.length + g.warning.length + g.info.length;
      if (!total) {
        const ok = new vscode.TreeItem('✅ Sin problemas detectados');
        ok.description = 'abre o guarda archivos para analizar';
        return [ok];
      }
      return ['error', 'warning', 'info'].map((k) => {
        const it = new vscode.TreeItem(
          `Severidad ${SEV_META[k].label}`,
          g[k].length ? (k === 'error' ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed)
                      : vscode.TreeItemCollapsibleState.None
        );
        it.description = String(g[k].length);
        it.iconPath = new vscode.ThemeIcon(SEV_META[k].icon, new vscode.ThemeColor(SEV_META[k].color));
        it.sevKey = k;
        return it;
      });
    }
    return g[el.sevKey]
      .sort((a, b) => a.uri.fsPath.localeCompare(b.uri.fsPath) || a.d.range.start.line - b.d.range.start.line)
      .map(({ uri, d }) => {
        const rule = BY_ID.get(d.code);
        const it = new vscode.TreeItem(rule ? rule.title : String(d.code), vscode.TreeItemCollapsibleState.None);
        it.description = `${uri.path.split('/').pop()}:${d.range.start.line + 1}`;
        it.tooltip = new vscode.MarkdownString(`**${rule ? rule.title : d.code}**\n\n${rule ? rule.fix : ''}`);
        it.iconPath = new vscode.ThemeIcon(SEV_META[el.sevKey].icon, new vscode.ThemeColor(SEV_META[el.sevKey].color));
        it.command = { command: 'vscode.open', title: 'Abrir', arguments: [uri, { selection: d.range }] };
        return it;
      });
  }
}

const findings = new FindingsProvider();

function scanDocument(doc) {
  const cfg = vscode.workspace.getConfiguration('thiaggscxecurit');
  if (!cfg.get('enable')) {
    collection.delete(doc.uri);
    return 0;
  }
  if (doc.uri.scheme !== 'file' && doc.uri.scheme !== 'untitled') return 0;

  const text = doc.getText();
  if (text.length > 500000) return 0;

  const disabled = new Set(cfg.get('disabledRules') || []);
  const diags = [];
  const lines = text.split(/\r?\n/);

  lines.forEach((line, i) => {
    if (line.includes('thiagg-ignore')) return;
    for (const rule of COMPILED) {
      if (disabled.has(rule.id)) continue;
      if (rule.langs && !rule.langs.includes(doc.languageId)) continue;
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(line))) {
        const range = new vscode.Range(i, m.index, i, m.index + Math.max(m[0].length, 1));
        const d = new vscode.Diagnostic(range, `${rule.title}\n→ ${rule.fix}`, SEV[rule.severity]);
        d.source = 'ThiaggScxecurit';
        d.code = rule.id;
        diags.push(d);
        if (m[0].length === 0) rule.re.lastIndex++;
      }
    }
  });

  collection.set(doc.uri, diags);
  findings.refresh();
  return diags.length;
}

async function scanWorkspace() {
  const files = await vscode.workspace.findFiles(
    '**/*.{js,jsx,ts,tsx,py,java,php,html,vue,cs,json,env,rules}',
    '**/{node_modules,.git,dist,build,out,target,.vscode-test}/**',
    3000
  );
  let total = 0;
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'ThiaggScxecurit: analizando proyecto…', cancellable: true },
    async (progress, token) => {
      for (let i = 0; i < files.length; i++) {
        if (token.isCancellationRequested) break;
        try {
          const doc = await vscode.workspace.openTextDocument(files[i]);
          total += scanDocument(doc);
        } catch (_) { /* binario o ilegible */ }
        if (i % 20 === 0) progress.report({ message: `${i}/${files.length}`, increment: (20 / files.length) * 100 });
      }
    }
  );
  const pick = await vscode.window.showInformationMessage(
    `ThiaggScxecurit: ${total} posibles problemas en ${files.length} archivos.`,
    'Ver problemas'
  );
  if (pick) vscode.commands.executeCommand('workbench.actions.view.problems');
}


async function explain(id) {
  const r = BY_ID.get(id);
  if (!r) return;
  const sev = { error: '🔴 Alta', warning: '🟠 Media', info: '🔵 Baja' }[r.severity];
  const md = [
    `# ${r.title}`,
    '',
    `**Severidad:** ${sev}  `,
    `**Referencia:** [${r.cwe}](https://cwe.mitre.org/data/definitions/${r.cwe.replace('CWE-', '')}.html)`,
    '',
    '## Cómo solucionarlo',
    r.fix,
    ...(r.example ? ['', '## Ejemplo seguro', '```', r.example, '```'] : []),
    '',
    '> Si es un falso positivo, añade `thiagg-ignore` en un comentario de esa línea.'
  ].join('\n');
  const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: md });
  await vscode.commands.executeCommand('markdown.showPreviewToSide', doc.uri).then(
    undefined,
    () => vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside)
  );
}


function ignoreComment(lang) {
  if (lang === 'python') return '  # thiagg-ignore';
  if (lang === 'html') return ' <!-- thiagg-ignore -->';
  return ' // thiagg-ignore';
}

const codeActions = {
  provideCodeActions(doc, _range, ctx) {
    const actions = [];
    for (const d of ctx.diagnostics) {
      if (d.source !== 'ThiaggScxecurit') continue;

      const how = new vscode.CodeAction('💡 Ver cómo solucionarlo', vscode.CodeActionKind.QuickFix);
      how.command = { command: 'thiaggscxecurit.explain', title: 'Explicar', arguments: [d.code] };
      how.diagnostics = [d];
      how.isPreferred = true;
      actions.push(how);

      const ign = new vscode.CodeAction('Ignorar esta línea (falso positivo)', vscode.CodeActionKind.QuickFix);
      ign.edit = new vscode.WorkspaceEdit();
      const line = doc.lineAt(d.range.start.line);
      ign.edit.insert(doc.uri, line.range.end, ignoreComment(doc.languageId));
      ign.diagnostics = [d];
      actions.push(ign);
    }
    return actions;
  }
};


async function analyzeUrl() {
  const input = await vscode.window.showInputBox({
    prompt: 'URL de TU sitio web (analiza solo sitios que te pertenezcan o tengas permiso para revisar)',
    placeHolder: 'https://mi-sitio.com'
  });
  if (!input) return;
  const url = /^https?:\/\//i.test(input) ? input : 'https://' + input;

  let res;
  try {
    res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(10000) });
  } catch (e) {
    vscode.window.showErrorMessage('No se pudo conectar: ' + e.message);
    return;
  }

  const h = res.headers;
  const csp = h.get('content-security-policy') || '';
  const checks = [
    {
      ok: res.url.startsWith('https://'), name: 'HTTPS',
      fix: 'Sirve el sitio por HTTPS y redirige todo el tráfico http → https.'
    },
    {
      ok: !!h.get('strict-transport-security'), name: 'Strict-Transport-Security (HSTS)',
      fix: 'Añade: Strict-Transport-Security: max-age=31536000; includeSubDomains'
    },
    {
      ok: !!csp, name: 'Content-Security-Policy',
      fix: "Añade una CSP que limite de dónde se cargan scripts, p. ej.: default-src 'self'. Mitiga XSS."
    },
    {
      ok: (h.get('x-content-type-options') || '').toLowerCase() === 'nosniff', name: 'X-Content-Type-Options',
      fix: 'Añade: X-Content-Type-Options: nosniff'
    },
    {
      ok: !!h.get('x-frame-options') || /frame-ancestors/i.test(csp), name: 'Protección contra clickjacking',
      fix: "Añade X-Frame-Options: DENY o CSP con frame-ancestors 'none'."
    },
    {
      ok: !!h.get('referrer-policy'), name: 'Referrer-Policy',
      fix: 'Añade: Referrer-Policy: strict-origin-when-cross-origin'
    },
    {
      ok: !!h.get('permissions-policy'), name: 'Permissions-Policy',
      fix: 'Añade Permissions-Policy para desactivar APIs que no usas (cámara, micrófono, geolocalización).'
    },
    {
      ok: !h.get('x-powered-by'), name: 'No revela tecnología (X-Powered-By)',
      fix: "Elimina la cabecera X-Powered-By (en Express: app.disable('x-powered-by') o usa helmet)."
    }
  ];

  const cookies = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
  const cookieIssues = cookies.flatMap((c) => {
    const name = c.split('=')[0];
    const out = [];
    if (!/;\s*secure/i.test(c)) out.push(`\`${name}\` sin **Secure**`);
    if (!/;\s*httponly/i.test(c)) out.push(`\`${name}\` sin **HttpOnly**`);
    if (!/;\s*samesite/i.test(c)) out.push(`\`${name}\` sin **SameSite**`);
    return out;
  });

  const score = checks.filter((c) => c.ok).length;
  const md = [
    `# Informe de seguridad web`,
    `**URL:** ${res.url}  `,
    `**Puntuación:** ${score}/${checks.length}`,
    '',
    '| Estado | Control |',
    '|---|---|',
    ...checks.map((c) => `| ${c.ok ? '✅' : '❌'} | ${c.name} |`),
    '',
    '## Qué arreglar',
    ...(checks.filter((c) => !c.ok).map((c) => `- **${c.name}:** ${c.fix}`) || []),
    ...(checks.every((c) => c.ok) ? ['Todo correcto en cabeceras 🎉'] : []),
    '',
    '## Cookies',
    ...(cookieIssues.length
      ? cookieIssues.map((i) => `- ${i}`).concat(['', 'Configura las cookies de sesión con `Secure; HttpOnly; SameSite=Lax` (o Strict).'])
      : [cookies.length ? 'Las cookies tienen buenas banderas ✅' : 'No se detectaron cookies en esta respuesta.'])
  ].join('\n');

  const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: md });
  await vscode.commands.executeCommand('markdown.showPreviewToSide', doc.uri).then(
    undefined,
    () => vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside)
  );
}


function activate(context) {
  collection = vscode.languages.createDiagnosticCollection('thiaggscxecurit');
  context.subscriptions.push(collection);
  findings.view = vscode.window.createTreeView('thiaggscxecurit.findings', { treeDataProvider: findings });
  context.subscriptions.push(findings.view);

  let timer;
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(scanDocument),
    vscode.workspace.onDidSaveTextDocument(scanDocument),
    vscode.workspace.onDidChangeTextDocument((e) => {
      clearTimeout(timer);
      timer = setTimeout(() => scanDocument(e.document), 500);
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('thiaggscxecurit')) vscode.workspace.textDocuments.forEach(scanDocument);
    }),
    vscode.languages.registerCodeActionsProvider({ scheme: '*' }, codeActions, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
    }),
    vscode.commands.registerCommand('thiaggscxecurit.scanFile', () => {
      const ed = vscode.window.activeTextEditor;
      if (ed) {
        const n = scanDocument(ed.document);
        vscode.window.showInformationMessage(`ThiaggScxecurit: ${n} posibles problemas en este archivo.`);
      }
    }),
    vscode.commands.registerCommand('thiaggscxecurit.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('thiaggscxecurit.analyzeUrl', analyzeUrl),
    vscode.commands.registerCommand('thiaggscxecurit.explain', explain)
  );

  vscode.workspace.textDocuments.forEach(scanDocument);
}

function deactivate() {}

module.exports = { activate, deactivate };