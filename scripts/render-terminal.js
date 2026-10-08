// Run mod-audit with colors and write its real output as a terminal-styled HTML
// page (for the README screenshot). Usage: node scripts/render-terminal.js out.html -- <mod-audit args>
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const [out, sep, ...args] = process.argv.slice(2);
if (!out || sep !== '--') { console.error('usage: render-terminal.js out.html -- <args>'); process.exit(2); }
const r = spawnSync('node', [path.join(here, '..', 'bin', 'mod-audit.js'), ...args, '--color'], { encoding: 'utf8' });
const text = r.stdout.replace(/(?:~|\/)[^\n]*?(test\/fixtures\/)/g, '$1'); // repo-relative paths in the picture

const COLORS = { 1: 'font-weight:700', 2: 'color:#8b8b8b', 31: 'color:#ff6b5f', 32: 'color:#5fd38d', 33: 'color:#f2c14e', 35: 'color:#e27cff', 36: 'color:#5fc8ff' };
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
let html = '';
let open = 0;
for (const part of text.split(/(\x1b\[[0-9;]*m)/)) {
  const m = part.match(/^\x1b\[([0-9;]*)m$/);
  if (!m) { html += esc(part); continue; }
  if (m[1] === '0' || m[1] === '') { html += '</span>'.repeat(open); open = 0; continue; }
  html += `<span style="${COLORS[m[1]] || ''}">`;
  open++;
}
html += '</span>'.repeat(open);

fs.writeFileSync(out, `<!doctype html><html><head><meta charset="utf-8"><title>mod-audit</title><style>
body{margin:0;background:#1b1d22;padding:28px}
.win{background:#0f1115;border-radius:10px;box-shadow:0 10px 40px rgba(0,0,0,.4);overflow:hidden;max-width:1040px}
.bar{height:30px;background:#23262d;display:flex;align-items:center;gap:8px;padding:0 12px}
.bar i{width:12px;height:12px;border-radius:50%;display:block}
pre{margin:0;padding:18px 20px 22px;color:#e6e6e6;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}
.cmd{color:#8b8b8b}
</style></head><body><div class="win"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i></div>
<pre><span class="cmd">$ npx github:thinx-pro/mod-audit ${esc(args.map((a) => a.replace(/^.*\/(test\/fixtures.*)$/, '$1')).join(' '))}</span>
${html}</pre></div></body></html>`);
console.log('wrote ' + out);
