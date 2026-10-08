import os from 'node:os';
import { rank } from './rules.js';

const ICON = { critical: '■', high: '▲', medium: '●', low: '·', info: '·' };

export function colorer(on) {
  const c = (code) => (s) => (on ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return { bold: c('1'), dim: c('2'), red: c('31'), yellow: c('33'), green: c('32'), magenta: c('35'), cyan: c('36') };
}

const tidy = (p) => {
  const home = os.homedir();
  return p.startsWith(home) ? '~' + p.slice(home.length) : p;
};

function sevColor(col, s) {
  return { critical: col.magenta, high: col.red, medium: col.yellow, low: col.dim, info: col.dim }[s];
}

export function verdict(worst) {
  return { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'OK' }[worst];
}

// One line per finding id: the first location, then how many more files.
function printGrouped(out, col, list, min) {
  const groups = new Map();
  let hidden = 0;
  for (const f of list) {
    if (rank(f.severity) < min) { hidden++; continue; }
    const g = groups.get(f.id);
    if (g) { g.files.add(f.file); continue; }
    groups.set(f.id, { f, files: new Set([f.file]) });
  }
  for (const { f, files } of groups.values()) {
    const where = f.file + (f.line ? `:${f.line}` : '') + (files.size > 1 ? ` +${files.size - 1} more file${files.size > 2 ? 's' : ''}` : '');
    out.push(`  ${sevColor(col, f.severity)(`${ICON[f.severity]} ${f.severity.padEnd(8)}`)} ${f.text}  ${col.dim(where)}`);
  }
  return hidden;
}

export function textReport(results, opts = {}) {
  const col = colorer(opts.color);
  const min = rank(opts.minSeverity || 'low');
  const out = [];
  out.push(col.bold('mod-audit') + col.dim(` ${opts.version}`) + `  ${results.length} plugin${results.length === 1 ? '' : 's'} scanned`);
  out.push('');
  for (const r of results) {
    const v = verdict(r.worst);
    out.push(`${sevColor(col, r.worst)('●')} ${col.bold(r.name)}${r.version ? col.dim(' ' + r.version) : ''}  ${col.dim(r.kind)}  ${sevColor(col, r.worst)(v)}`);
    out.push(col.dim(`  ${tidy(r.root)}`));
    if (r.events.length) {
      const evs = [...new Set(r.events.map((e) => e.event + (e.rewrites ? '*' : '')))];
      out.push(`  hooks: ${evs.join(', ')}` + (evs.some((e) => e.endsWith('*')) ? col.dim('   (* = rewrites before passing on)') : ''));
    }
    if (r.classic.length) out.push(`  classic hooks: ${[...new Set(r.classic.map((c) => c.event))].join(', ')} ${col.dim(`(${r.classic.length} command${r.classic.length === 1 ? '' : 's'})`)}`);
    if (r.mcp.length) out.push(`  mcp: ${r.mcp.map((m) => `${m.name} (${m.kind})`).join(', ')}`);
    if (r.domains.length) out.push(`  hosts named: ${r.domains.join(', ')}`);
    const runtime = r.findings.filter((f) => f.reach === 'runtime');
    const other = r.findings.filter((f) => f.reach !== 'runtime');
    const hidden = printGrouped(out, col, runtime, min);
    if (!runtime.length) out.push(col.green('  nothing found in code that a hook, mod or MCP entry loads'));
    if (hidden) out.push(col.dim(`  + ${hidden} lower-severity finding${hidden === 1 ? '' : 's'} (use --all)`));
    if (other.length) {
      const files = new Set(other.map((f) => f.file)).size;
      if (opts.all) {
        out.push(col.dim(`  in ${files} file${files === 1 ? '' : 's'} no hook, mod or MCP entry loads (build/dev scripts):`));
        printGrouped(out, col, other, min);
      } else {
        out.push(col.dim(`  + ${other.length} finding${other.length === 1 ? '' : 's'} in ${files} file${files === 1 ? '' : 's'} no hook, mod or MCP entry loads (use --all)`));
      }
    }
    out.push('');
  }
  const counts = {};
  for (const r of results) counts[r.worst] = (counts[r.worst] || 0) + 1;
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  out.push(order.filter((s) => counts[s]).map((s) => sevColor(col, s)(`${counts[s]} ${verdict(s).toLowerCase()}`)).join(col.dim(' · ')));
  out.push(col.dim('Static analysis: it shows what the code can reach, not what it will do. Dynamic tricks can hide calls; treat "OK" as "nothing found", not "safe".'));
  return out.join('\n');
}

export function diffReport(diff, opts = {}) {
  const col = colorer(opts.color);
  const out = [col.bold('mod-audit diff') + col.dim(` against ${opts.lockPath}`), ''];
  let any = false;
  for (const d of diff) {
    if (d.status === 'same') continue;
    any = true;
    const tag = { new: col.cyan('NEW'), changed: col.yellow('CHANGED'), missing: col.dim('MISSING') }[d.status];
    out.push(`${tag} ${col.bold(d.name)}${d.note ? col.dim('  ' + d.note) : ''}`);
    for (const f of d.added) out.push(`  ${sevColor(col, f.severity)('+ ' + f.severity.padEnd(8))} ${f.text}  ${col.dim(f.file + (f.line ? ':' + f.line : ''))}`);
    for (const c of d.removed) out.push(col.dim(`  - ${c}`));
    for (const h of d.newDomains) out.push(`  ${col.red('+ host')}     ${h}`);
    if (d.status === 'changed' && !d.added.length && !d.newDomains.length) out.push(col.dim('  no new capabilities'));
    out.push('');
  }
  if (!any) out.push(col.green('No changes since the lockfile.'));
  return out.join('\n');
}
