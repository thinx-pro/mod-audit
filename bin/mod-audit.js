#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findPlugins, auditPlugin } from '../src/audit.js';
import { toLock, diffLock } from '../src/lock.js';
import { textReport, diffReport } from '../src/report.js';
import { SEVERITY, rank } from '../src/rules.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.join(here, '..', 'package.json'), 'utf8'));

const HELP = `mod-audit ${pkg.version}
See what a Claude Code plugin can do before you install or upgrade it: which
events its mods hook, which engine calls it makes (files, network, processes,
prompts, approval rows), what its classic hooks run, which hosts it names.

Usage
  mod-audit [paths...] [options]

  With no paths, scans ~/.claude/plugins/cache and ~/.claude/dev-mods.
  A path can be one plugin folder or any folder containing plugins.

Options
  --all                  show low and info findings too
  --json                 print results as JSON
  --write-lock [file]    pin hashes and capabilities (default: mod-audit.lock.json)
  --diff [file]          compare against a lockfile; shows only what is new
  --fail-on <severity>   exit 1 if a finding (in --diff: a new one) is at or above
                         this level: low | medium | high | critical
  --color / --no-color   force or disable ANSI colors
  -h, --help             show this help
  -v, --version          show version

Nothing is executed and nothing is sent anywhere: files are only read.`;

function parseArgs(argv) {
  const o = { paths: [], color: process.stdout.isTTY && !process.env.NO_COLOR };
  const optional = (i) => (i < argv.length && !argv[i].startsWith('-') ? argv[i] : null);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a === '--all') o.all = true;
    else if (a === '--json') o.json = true;
    else if (a === '--no-color') o.color = false;
    else if (a === '--color') o.color = true;
    else if (a === '--write-lock') { const v = optional(i + 1); o.writeLock = v && v.endsWith('.json') ? (i++, v) : 'mod-audit.lock.json'; }
    else if (a === '--diff') { const v = optional(i + 1); o.diff = v && v.endsWith('.json') ? (i++, v) : 'mod-audit.lock.json'; }
    else if (a === '--fail-on') {
      o.failOn = argv[++i];
      if (!SEVERITY.slice(1).includes(o.failOn)) throw new Error('--fail-on must be low, medium, high or critical');
    } else if (a.startsWith('-')) throw new Error(`unknown option ${a} (see --help)`);
    else o.paths.push(a);
  }
  return o;
}

function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error('mod-audit: ' + e.message); process.exit(2); }
  if (o.help) { console.log(HELP); return; }
  if (o.version) { console.log(pkg.version); return; }

  const roots = o.paths.length ? o.paths : [path.join(os.homedir(), '.claude', 'plugins', 'cache'), path.join(os.homedir(), '.claude', 'dev-mods')];
  const pluginDirs = [];
  for (const r of roots) {
    if (!fs.existsSync(r)) { if (o.paths.length) { console.error(`mod-audit: no such path ${r}`); process.exit(2); } continue; }
    for (const d of findPlugins(path.resolve(r))) if (!pluginDirs.includes(d)) pluginDirs.push(d);
  }
  if (!pluginDirs.length) {
    console.error('mod-audit: no plugins found (looked for .claude-plugin/plugin.json or hooks/hooks.json under ' + roots.join(', ') + ')');
    process.exit(1);
  }
  const results = pluginDirs.map(auditPlugin);

  if (o.writeLock) {
    fs.writeFileSync(o.writeLock, JSON.stringify(toLock(results), null, 2) + '\n');
  }

  let failed = false;
  const threshold = o.failOn ? rank(o.failOn) : Infinity;
  if (o.diff) {
    let lock;
    try { lock = JSON.parse(fs.readFileSync(o.diff, 'utf8')); } catch { console.error(`mod-audit: cannot read lockfile ${o.diff} (create one with --write-lock)`); process.exit(2); }
    const diff = diffLock(lock, results);
    failed = diff.some((d) => d.added.some((f) => rank(f.severity) >= threshold));
    if (o.json) console.log(JSON.stringify(diff, null, 2));
    else console.log(diffReport(diff, { color: o.color, lockPath: o.diff }));
  } else {
    failed = results.some((r) => r.findings.some((f) => rank(f.severity) >= threshold));
    if (o.json) console.log(JSON.stringify(results, null, 2));
    else console.log(textReport(results, { color: o.color, version: pkg.version, minSeverity: o.all ? 'info' : 'medium', all: o.all }));
  }
  if (o.writeLock && !o.json) console.log(`\nlockfile written: ${o.writeLock}`);
  if (failed) process.exit(1);
}

main();
