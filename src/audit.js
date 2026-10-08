// Find plugins under a path and audit each one.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { scanSource } from './scan-js.js';
import { scanShell } from './scan-shell.js';
import { rank, CLASSIC_EVENTS } from './rules.js';

const SKIP = new Set(['node_modules', '.git', 'dist', '.cache']);
const CODE_EXT = /\.(m?[jt]sx?|cjs|cts|mts)$/;
const SHELL_EXT = /\.(sh|bash|zsh)$/;
const TEST_FILE = /(^|\/)(tests?|__tests__|fixtures)\/|\.(test|spec)\.[a-z]+$/;

const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } };
const readText = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } };
const isFile = (p) => { try { return fs.statSync(p).isFile(); } catch { return false; } };

function walk(dir, depth, visit) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (SKIP.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (depth > 0) walk(p, depth - 1, visit); } else if (e.isFile()) visit(p);
  }
}

export function isPluginRoot(dir) {
  return isFile(path.join(dir, '.claude-plugin', 'plugin.json')) || isFile(path.join(dir, 'hooks', 'hooks.json'));
}

export function findPlugins(root, maxDepth = 7) {
  const found = [];
  const visit = (dir, depth) => {
    if (isPluginRoot(dir)) { found.push(dir); return; }
    if (depth <= 0) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) if (e.isDirectory() && !SKIP.has(e.name) && e.name !== '.claude-plugin') visit(path.join(dir, e.name), depth - 1);
  };
  visit(root, maxDepth);
  return found.sort();
}

function listFiles(root) {
  const files = [];
  walk(root, 8, (p) => files.push(p));
  return files.sort();
}

export function hashPlugin(root) {
  const h = crypto.createHash('sha256');
  for (const f of listFiles(root)) {
    if (f.includes(`${path.sep}.claude-plugin${path.sep}types${path.sep}`)) continue; // engine-written
    h.update(path.relative(root, f).split(path.sep).join('/'));
    h.update('\0');
    try { h.update(fs.readFileSync(f)); } catch { /* unreadable */ }
    h.update('\0');
  }
  return h.digest('hex');
}

const TRY_EXT = ['', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '/index.js', '/index.ts', '/index.mjs'];
function resolveLocal(spec, fromDir) {
  const base = path.resolve(fromDir, spec);
  for (const ext of TRY_EXT) if (isFile(base + ext)) return base + ext;
  const ts = base.replace(/\.(m?)js$/, '.$1ts'); // TS ESM: import './x.js' -> x.ts
  if (ts !== base && isFile(ts)) return ts;
  return null;
}

// Files a code/shell file pulls in: relative imports, requires, sourced scripts.
function dependenciesOf(file, root) {
  const src = readText(file);
  if (src == null) return [];
  const dir = path.dirname(file);
  const out = [];
  if (CODE_EXT.test(file)) {
    const re = /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s+)['"](\.{1,2}\/[^'"]+)['"]/g;
    for (let m; (m = re.exec(src));) { const p = resolveLocal(m[1], dir); if (p) out.push(p); }
  } else {
    const re = /([\w${}./-]*\/)?([\w.-]+\.(?:sh|bash|mjs|cjs|js|ts|py))\b/g;
    for (let m; (m = re.exec(src));) {
      for (const cand of [path.join(dir, m[2]), path.join(root, (m[1] || '').replace(/\$\{?[A-Z_]+\}?\/?/g, ''), m[2])]) {
        if (isFile(cand)) { out.push(cand); break; }
      }
    }
  }
  return out;
}

// Paths a hook command or MCP entry names inside the plugin.
function entriesIn(text, root) {
  const out = [];
  const re = /(?:\$\{?CLAUDE_PLUGIN_ROOT\}?\/|\.\/)?([\w./-]+\.(?:sh|bash|zsh|mjs|cjs|js|ts|py))\b/g;
  for (let m; (m = re.exec(text));) {
    const p = path.join(root, m[1]);
    if (isFile(p)) out.push(p);
  }
  return out;
}

export function auditPlugin(root) {
  const manifest = readJson(path.join(root, '.claude-plugin', 'plugin.json')) || {};
  const hooksJson = readJson(path.join(root, 'hooks', 'hooks.json')) || {};
  const rel = (p) => path.relative(root, p).split(path.sep).join('/');
  const findings = [];
  const domains = new Set();
  const events = [];

  // 1. Entry points: what Claude Code actually loads or runs.
  const modEntries = (hooksJson.modules || []).map((m) => path.resolve(root, 'hooks', m)).filter(isFile);
  const isMod = modEntries.length > 0;
  const classic = [];
  const entries = new Set(modEntries);
  const decisionEvents = new Map();
  for (const [event, groups] of Object.entries(hooksJson.hooks || {})) {
    for (const g of Array.isArray(groups) ? groups : []) {
      for (const h of g.hooks || []) {
        if (!h.command) continue;
        classic.push({ event, matcher: g.matcher || null, command: h.command });
        const inline = scanShell(h.command);
        for (const x of inline.findings) findings.push({ ...x, file: 'hooks/hooks.json', line: 0, reach: 'runtime' });
        inline.domains.forEach((d) => domains.add(d));
        for (const p of entriesIn(h.command, root)) { entries.add(p); if (!decisionEvents.has(p)) decisionEvents.set(p, new Set()); decisionEvents.get(p).add(event); }
      }
    }
    const ce = CLASSIC_EVENTS[event];
    if (ce) findings.push({ id: `classic:${event}`, severity: ce[0], text: `classic hook: ${ce[1]}`, file: 'hooks/hooks.json', line: 0, detail: event, reach: 'runtime' });
  }
  const mcpCfg = readJson(path.join(root, '.mcp.json')) || (manifest.mcpServers && typeof manifest.mcpServers === 'object' && { mcpServers: manifest.mcpServers }) || {};
  const mcp = [];
  for (const [name, s] of Object.entries(mcpCfg.mcpServers || {})) {
    if (!s || typeof s !== 'object') continue;
    if (s.command) {
      const target = [s.command, ...(s.args || [])].join(' ');
      mcp.push({ name, kind: 'process', target });
      for (const p of entriesIn(target, root)) entries.add(p);
      findings.push({ id: `mcp:${name}`, severity: 'medium', text: `starts MCP server "${name}" as a local process`, file: '.mcp.json', line: 0, detail: target.slice(0, 80), reach: 'runtime' });
    } else if (s.url) {
      mcp.push({ name, kind: 'remote', target: s.url });
      const host = (String(s.url).match(/^https?:\/\/([^/:]+)/) || [])[1];
      if (host) domains.add(host.toLowerCase());
      findings.push({ id: `mcp:${name}`, severity: 'medium', text: `connects to remote MCP server "${name}"`, file: '.mcp.json', line: 0, detail: s.url, reach: 'runtime' });
    }
  }

  // 2. Everything reachable from the entry points.
  const reachable = new Set();
  const queue = [...entries];
  while (queue.length) {
    const f = queue.pop();
    if (reachable.has(f)) continue;
    reachable.add(f);
    for (const d of dependenciesOf(f, root)) if (!reachable.has(d)) queue.push(d);
  }

  // 3. Scan every code and shell file; tag whether a hook/mod/MCP entry reaches it.
  const all = listFiles(root).filter((f) => (CODE_EXT.test(f) && !f.endsWith('.d.ts')) || SHELL_EXT.test(f));
  const modules = [];
  for (const f of all) {
    const r0 = rel(f);
    if (TEST_FILE.test(r0) || r0.startsWith('.claude-plugin/types/')) continue;
    const src = readText(f);
    if (src == null) continue;
    const reach = reachable.has(f) ? 'runtime' : 'other';
    const r = SHELL_EXT.test(f) ? scanShell(src) : scanSource(src);
    if (isMod && reach === 'runtime' && CODE_EXT.test(f)) modules.push(r0);
    if (reach === 'runtime') for (const e of r.events || []) events.push({ ...e, file: r0 });
    for (const x of r.findings) findings.push({ ...x, file: r0, reach });
    if (reach === 'runtime') r.domains.forEach((d) => domains.add(d));
    const evs = decisionEvents.get(f);
    if (evs) {
      for (const ev of evs) {
        if ((ev === 'PermissionRequest' || ev === 'PreToolUse') && /permissionDecision|"decision"|\\?"behavior\\?"\s*:/.test(src)) {
          findings.push({ id: `classic:${ev}:decides`, severity: 'high', text: `${ev} hook can answer permission/tool decisions itself`, file: r0, line: 0, detail: ev, reach: 'runtime' });
        }
      }
    }
  }

  // 4. Skills/commands/agents that tell the model to pipe downloads into a shell.
  for (const f of listFiles(root)) {
    if (!/SKILL\.md$|\/commands\/[^/]+\.md$|\/agents\/[^/]+\.md$/.test(f)) continue;
    const src = readText(f);
    if (src == null) continue;
    const m = src.match(/\b(curl|wget)\b[^\n|]*\|\s*(ba|z)?sh\b/);
    if (m) findings.push({ id: 'md:pipe-to-shell', severity: 'high', text: 'instructs the model to pipe a download into a shell', file: rel(f), line: src.slice(0, m.index).split('\n').length, detail: m[0].slice(0, 80), reach: 'runtime' });
  }

  // 5. Combinations, judged per reachable file (a mod's modules share one $, so they are one group).
  const groups = new Map();
  for (const f of findings) {
    if (f.reach !== 'runtime') continue;
    const g = isMod && modules.includes(f.file) ? '(mod)' : f.file;
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(f);
  }
  const READ = (f) => f.id === 'call:fs.read' || f.id.startsWith('path:') || f.id === 'call:session.messages' || f.id === 'call:session.turns' || f.id === 'call:env.get' || f.id === 'call:settings.read';
  const NET = (f) => f.id === 'call:http.fetch' || f.id === 'node:network' || f.id === 'sh:makes network connections' || f.id === 'sh:pipes a download straight into a shell';
  const DYN = (f) => f.id === 'dynamic-code' || f.id === 'sh:evaluates strings as shell code';
  const PROC = (f) => f.id === 'call:process.run' || f.id === 'call:process.spawn' || f.id === 'node:process';
  let exfil, fetchRun, procNet, phish;
  for (const list of groups.values()) {
    const r = list.find(READ), n = list.find(NET), d = list.find(DYN), p = list.find(PROC);
    const inp = list.find((f) => f.id === 'ui:input');
    if (inp && n && !phish) phish = inp;
    if (r && n && !exfil) exfil = { r, n };
    if (n && d && !fetchRun) fetchRun = d;
    if (p && n && !procNet) procNet = p;
  }
  if (exfil) findings.push({ id: 'combo:exfil', severity: 'critical', text: `can read local data (${exfil.r.text}) and send it over the network`, file: exfil.n.file, line: exfil.n.line, detail: 'read + network', reach: 'runtime' });
  if (fetchRun) findings.push({ id: 'combo:fetch-run', severity: 'critical', text: 'can download code and run it (fetch-then-run)', file: fetchRun.file, line: fetchRun.line, detail: 'network + dynamic code', reach: 'runtime' });
  if (phish) findings.push({ id: 'combo:input-net', severity: 'high', text: 'draws input fields and can send what is typed over the network (check it never asks for keys)', file: phish.file, line: phish.line, detail: 'input + network', reach: 'runtime' });
  if (procNet && !exfil) findings.push({ id: 'combo:proc-net', severity: 'high', text: 'runs host commands and talks to the network', file: procNet.file, line: procNet.line, detail: 'process + network', reach: 'runtime' });

  findings.sort((a, b) => (a.reach === b.reach ? 0 : a.reach === 'runtime' ? -1 : 1) || rank(b.severity) - rank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  const runtime = findings.filter((f) => f.reach === 'runtime');
  const worst = runtime.reduce((w, f) => (rank(f.severity) > rank(w) ? f.severity : w), 'info');
  return {
    name: manifest.name || path.basename(root),
    version: manifest.version || null,
    root,
    kind: [isMod && 'mod', classic.length && 'classic hooks', mcp.length && 'mcp'].filter(Boolean).join(' + ') || 'other',
    entries: [...entries].map(rel).sort(),
    reachable: [...reachable].map(rel).sort(),
    modules,
    events,
    classic,
    mcp,
    domains: [...domains].sort(),
    findings,
    worst,
    hash: hashPlugin(root),
  };
}
