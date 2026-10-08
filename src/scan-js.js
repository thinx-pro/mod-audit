// Static scan of one mod source file (JS/TS/TSX). Regex-based on a copy of the
// source with comments blanked out (newlines kept, so line numbers hold).
import { CALLS, EVENTS, SENSITIVE_COMPONENTS, SENSITIVE_PATHS } from './rules.js';

export function stripComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') { out += ' '; i++; }
    } else if (c === '/' && d === '*') {
      out += '  '; i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { out += src[i] === '\n' ? '\n' : ' '; i++; }
      if (i < n) { out += '  '; i += 2; }
    } else if (c === '"' || c === "'" || c === '`') {
      const q = c;
      out += c; i++;
      while (i < n && src[i] !== q) {
        if (src[i] === '\\' && i + 1 < n) { out += src[i] + src[i + 1]; i += 2; continue; }
        if (q !== '`' && src[i] === '\n') break; // unterminated: stop at line end
        out += src[i]; i++;
      }
      if (i < n && src[i] === q) { out += q; i++; }
    } else {
      out += c; i++;
    }
  }
  return out;
}

const lineAt = (text, idx) => {
  let line = 1;
  for (let k = 0; k < idx && k < text.length; k++) if (text.charCodeAt(k) === 10) line++;
  return line;
};

const KNOWN_NOUNS = new Set(Object.keys(CALLS).map((k) => k.split('.')[0]).concat(['ui', 'session', 'prompt', 'model', 'tool', 'agent', 'mcp', 'command', 'config', 'store', 'state', 'clock', 'audio', 'telemetry', 'turn', 'settings', 'env', 'http', 'process', 'fs', 'plugin']));

// Returns { events: [{event, matcher, line, rewrites}], findings: [{id, severity, text, line, detail}], domains: [] }
export function scanSource(src) {
  const code = stripComments(src);
  const findings = [];
  const add = (id, severity, text, idx, detail) => findings.push({ id, severity, text, line: lineAt(code, idx), detail });

  // 1. Hooked events: on('event', {matcher}?, hook)
  const events = [];
  const onRe = /\bon\s*\(\s*(['"`])([a-z]+\.[A-Za-z.]+)\1\s*(?:,\s*(\{[^{}]*\}))?/g;
  for (let m; (m = onRe.exec(code));) events.push({ event: m[2], matcher: m[3] || null, idx: m.index });
  events.sort((a, b) => a.idx - b.idx);

  // A rewrite is next({ ...e, ... }) or next(<something other than the bare event>).
  const rewrites = [];
  const nextRe = /\bnext\s*\(\s*([^)\s][^)]*)?\)/g;
  for (let m; (m = nextRe.exec(code));) {
    const arg = (m[1] || '').trim();
    if (arg && !/^[A-Za-z_$][\w$]*$/.test(arg)) rewrites.push(m.index);
  }
  const ownerOf = (idx) => {
    let owner = null;
    for (const ev of events) if (ev.idx < idx) owner = ev; else break;
    return owner;
  };
  for (const r of rewrites) { const o = ownerOf(r); if (o) o.rewrites = true; }

  for (const ev of events) {
    const line = lineAt(code, ev.idx);
    if (ev.event === 'ui.render') {
      const comp = ev.matcher && (ev.matcher.match(/component\s*:\s*['"`](\w+)['"`]/) || [])[1];
      if (comp && SENSITIVE_COMPONENTS[comp]) {
        add(`render:${comp}`, ev.rewrites ? 'critical' : 'high',
          ev.rewrites ? `rewrites ${SENSITIVE_COMPONENTS[comp]} as drawn` : `draws over ${SENSITIVE_COMPONENTS[comp]}`, ev.idx, `ui.render ${comp}`);
      } else if (!comp) {
        add('render:any', 'high', 'draws on every component (no component matcher)', ev.idx, 'ui.render');
      } else {
        add(`render:${comp}`, 'low', `draws ${comp}`, ev.idx, `ui.render ${comp}`);
      }
      continue;
    }
    const rule = EVENTS[ev.event];
    const tool = ev.matcher && (ev.matcher.match(/tool\s*:\s*['"`]([^'"`]+)['"`]/) || [])[1];
    const scope = tool ? ` (${tool})` : '';
    if (rule) {
      const [sev, plain, sevR, plainR] = rule;
      add(`on:${ev.event}${ev.rewrites ? ':rewrite' : ''}`, ev.rewrites ? sevR : sev, (ev.rewrites ? plainR : plain) + scope, ev.idx, `on('${ev.event}')`);
    } else {
      add(`on:${ev.event}`, 'info', `hooks ${ev.event}${scope}`, ev.idx, `on('${ev.event}')`);
    }
    void line;
  }

  // 2. Engine calls: any `<receiver>.<noun>.<method>(` with a known noun, plus
  //    destructured nouns (`const { http } = $` then `http.fetch(`).
  const seenCall = new Set();
  const callRe = /\.\s*([a-z]+)\s*\.\s*([a-zA-Z]+)\s*\(/g;
  const pushCall = (key, idx) => {
    if (seenCall.has(key)) return;
    seenCall.add(key);
    const rule = CALLS[key];
    if (rule) add(`call:${key}`, rule[0], rule[1], idx, `$.${key}()`);
  };
  for (let m; (m = callRe.exec(code));) {
    if (!KNOWN_NOUNS.has(m[1])) continue;
    pushCall(`${m[1]}.${m[2]}`, m.index);
  }
  const destructRe = /\{\s*([^{}]+?)\s*\}\s*=\s*(?:await\s+)?[A-Za-z_$][\w$]*\s*[;\n]/g;
  for (let m; (m = destructRe.exec(code));) {
    for (const part of m[1].split(',')) {
      const [name, alias] = part.split(':').map((s) => s && s.trim());
      if (!KNOWN_NOUNS.has(name)) continue;
      const local = (alias || name).replace(/[^\w$]/g, '');
      const re = new RegExp(`(?<![\\w$.])${local.replace(/\$/g, '\\$')}\\s*\\.\\s*([a-zA-Z]+)\\s*\\(`, 'g');
      for (let k; (k = re.exec(code));) pushCall(`${name}.${k[1]}`, k.index);
    }
  }
  // Computed access to a sensitive noun hides what is called.
  const computed = /\[\s*(['"`])(http|process|fs|env|session|prompt|tool|mcp)\1\s*\]|\$\s*\[\s*[A-Za-z_$]/g;
  for (let m; (m = computed.exec(code));) { add('dynamic-access', 'high', 'reaches engine nouns by computed name (hides which calls it makes)', m.index, m[0]); break; }

  const inputEl = /<Input\b|\bInput\s*\(\s*\{/.exec(code);
  if (inputEl) add('ui:input', 'low', 'draws text input fields', inputEl.index, 'Input');

  // 2b. Plain Node capabilities (classic hook scripts, MCP servers, helpers).
  const nodeRules = [
    [/\b(?:require\s*\(\s*|from\s+)['"](?:node:)?child_process['"]|\bexecSync\s*\(|\bspawnSync\s*\(/g, 'node:process', 'high', 'runs host commands (child_process)'],
    [/(?<![\w$.])fetch\s*\(|\b(?:require\s*\(\s*|from\s+)['"](?:node:)?(?:https?|net|tls|dgram)['"]|\baxios\b|\bundici\b/g, 'node:network', 'high', 'makes network requests'],
    [/\b(?:writeFileSync|writeFile|appendFileSync|appendFile|rmSync|unlinkSync|renameSync)\s*\(/g, 'node:write', 'medium', 'writes or deletes files'],
    [/\b(?:readFileSync|readFile|createReadStream)\s*\(/g, 'node:read', 'low', 'reads files'],
    [/\bprocess\.env\b/g, 'node:env', 'low', 'reads environment variables'],
  ];
  for (const [re, id, sev, text] of nodeRules) {
    const m = re.exec(code);
    if (m) add(id, sev, text, m.index, m[0].trim().slice(0, 40));
  }

  // 3. Dynamic code and obfuscation.
  const dyn = [
    [/\beval\s*\(/g, 'eval()'],
    [/\bnew\s+Function\s*\(/g, 'new Function()'],
    [/(?<![\w$.])Function\s*\(\s*['"`]/g, 'Function("...")'],
    [/\bimport\s*\(\s*(?!['"][^'"]+['"]\s*\))[^)]/g, 'import() of a computed specifier'],
  ];
  for (const [re, label] of dyn) {
    const m = re.exec(code);
    if (m) add('dynamic-code', 'high', `runs code built at runtime (${label})`, m.index, label);
  }
  const obf = [
    [/\batob\s*\(|Buffer\.from\([^)]*['"]base64['"]/g, 'decodes base64 at runtime'],
    [/String\.fromCharCode\s*\(/g, 'builds strings from char codes'],
    [/(['"`])[A-Za-z0-9+/=]{240,}\1/g, 'contains a long encoded string'],
    [/\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){15,}/g, 'contains a long hex-escaped string'],
  ];
  for (const [re, label] of obf) {
    const m = re.exec(code);
    if (m) add('obfuscation', 'medium', label, m.index, m[0].slice(0, 40));
  }

  // 4. Sensitive paths and remote hosts named in the source.
  for (const [re, label] of SENSITIVE_PATHS) {
    const m = new RegExp(re.source, 'g').exec(code);
    if (m) add(`path:${label}`, 'low', `mentions ${label}`, m.index, m[0]);
  }
  const domains = new Set();
  const urlRe = /\bhttps?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost|\d+\.\d+\.\d+\.\d+)(?::\d+)?/g;
  for (let m; (m = urlRe.exec(code));) domains.add(m[1].toLowerCase());

  return { events: events.map(({ event, matcher, idx, rewrites: r }) => ({ event, matcher, line: lineAt(code, idx), rewrites: !!r })), findings, domains: [...domains] };
}
