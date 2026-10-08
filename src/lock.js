// Lockfile: pin each plugin's content hash and capability set, then diff on upgrade.

export function toLock(results, date = new Date().toISOString().slice(0, 10)) {
  const plugins = {};
  for (const r of results) {
    plugins[r.name] = {
      version: r.version,
      hash: r.hash,
      capabilities: [...new Set(r.findings.map((f) => f.id))].sort(),
      domains: r.domains,
    };
  }
  return { lockfileVersion: 1, generated: date, plugins };
}

export function diffLock(lock, results) {
  const out = [];
  const seen = new Set();
  for (const r of results) {
    seen.add(r.name);
    const old = lock.plugins[r.name];
    if (!old) {
      out.push({ name: r.name, status: 'new', version: r.version, added: r.findings, removed: [], newDomains: r.domains, note: 'not in the lockfile' });
      continue;
    }
    const oldCaps = new Set(old.capabilities);
    const nowCaps = new Set(r.findings.map((f) => f.id));
    const added = [];
    const addedIds = new Set();
    for (const f of r.findings) if (!oldCaps.has(f.id) && !addedIds.has(f.id)) { added.push(f); addedIds.add(f.id); }
    const removed = old.capabilities.filter((c) => !nowCaps.has(c));
    const newDomains = r.domains.filter((d) => !(old.domains || []).includes(d));
    const changed = old.hash !== r.hash;
    let note = '';
    if (changed && old.version === r.version) note = `contents changed but version is still ${r.version}`;
    else if (changed) note = `${old.version} → ${r.version}`;
    out.push({ name: r.name, status: changed ? 'changed' : 'same', version: r.version, added, removed, newDomains, note });
  }
  for (const name of Object.keys(lock.plugins)) if (!seen.has(name)) out.push({ name, status: 'missing', added: [], removed: [], newDomains: [], note: 'in the lockfile but not found' });
  return out;
}
