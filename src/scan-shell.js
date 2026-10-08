// Scan a classic hook command or the shell script it runs.
import { SENSITIVE_PATHS } from './rules.js';

// A command word: at line start or after a separator/space, never after "-" (so `jq -nc` is not nc).
const CMD = (names) => new RegExp(`(?:^|[\\s;&|(\`])(?:${names})(?=\\s|$)`);

const RULES = [
  [/(?:^|[\s;&|(`])(curl|wget)\s[^\n|]*\|\s*(ba|z)?sh\b/, 'critical', 'pipes a download straight into a shell'],
  [CMD('curl|wget|nc|ncat|socat|telnet'), 'high', 'makes network connections'],
  [/(?:^|[\s;&|(`])base64\s+(-d|--decode|-D)\b|(?:^|[\s;&|(`])xxd\s+-r\b/, 'medium', 'decodes encoded data'],
  [/(?:^|[\s;&|(`])eval\s|(?:^|[\s;&|(`])source\s+<\(/, 'high', 'evaluates strings as shell code'],
  [/(?:^|[\s;&|(`])rm\s+-[a-zA-Z]*r[a-zA-Z]*f|(?:^|[\s;&|(`])rm\s+-[a-zA-Z]*f[a-zA-Z]*r/, 'high', 'deletes recursively (rm -rf)'],
  [CMD('osascript'), 'medium', 'runs AppleScript'],
  [CMD('sudo'), 'high', 'uses sudo'],
  [/\bcrontab\b|LaunchAgents|launchctl\s+load/, 'high', 'installs persistence (cron / launchd)'],
  [/\b(printenv|env)\s*(\||$)|\$\{?[A-Z_]*(TOKEN|SECRET|API_KEY|PASSWORD)[A-Z_]*\}?/, 'medium', 'reads secrets from the environment'],
];

export function scanShell(src) {
  const findings = [];
  const lines = src.split('\n');
  const seen = new Set();
  lines.forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*$/, '');
    if (!line.trim()) return;
    for (const [re, sev, text] of RULES) {
      if (seen.has(text) || !re.test(line)) continue;
      seen.add(text);
      findings.push({ id: `sh:${text}`, severity: sev, text, line: i + 1, detail: line.trim().slice(0, 80) });
    }
    for (const [re, label] of SENSITIVE_PATHS) {
      const key = 'path:' + label;
      if (seen.has(key) || !re.test(line)) continue;
      seen.add(key);
      findings.push({ id: key, severity: 'low', text: `mentions ${label}`, line: i + 1, detail: line.trim().slice(0, 80) });
    }
  });
  const domains = [...new Set([...src.matchAll(/\bhttps?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost)/g)].map((m) => m[1].toLowerCase()))];
  return { findings, domains };
}
