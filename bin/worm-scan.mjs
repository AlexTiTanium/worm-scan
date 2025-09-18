#!/usr/bin/env node
// Node >=22, zero-deps CLI

import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { basename, resolve } from 'node:path';

const DEFAULT_DATA_URL = 'https://malware-list.aikido.dev/malware_predictions.json';

const colors = (() => {
  const noColor = !!process.env.NO_COLOR;
  const wrap = (codeStart, codeEnd = '\u001b[0m') => (s) => noColor ? String(s) : `\u001b[${codeStart}m${s}\u001b[0m`;
  return {
    red: wrap('31'),
    yellow: wrap('33'),
    green: wrap('32'),
    bold: wrap('1'),
  };
})();

function parseJSON(input, label) {
  try {
    return JSON.parse(input);
  } catch (e) {
    const where = label ? ` from ${label}` : '';
    throw new Error(`Failed to parse JSON${where}: ${e.message}`);
  }
}

async function fetchMalwareList() {
  const url = process.env.WORMSCAN_DATA_URL || DEFAULT_DATA_URL;
  try {
    if (url.startsWith('file://')) {
      const p = fileURLToPath(url);
      const text = await readFile(p, 'utf8');
      return parseJSON(text, `file ${p}`);
    }
    const res = await fetch(url, { headers: { 'user-agent': `worm-scan/0.1 (${process.platform}; Node ${process.versions.node})` } });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    const text = await res.text();
    return parseJSON(text, 'malware list');
  } catch (err) {
    throw new Error(`Failed to fetch malware data from ${url}: ${err.message}`);
  }
}

function normalizeMalwareList(data) {
  // Output: Map<string, Set<string>> of name -> versions
  const map = new Map();

  const add = (name, version) => {
    if (!name || !version) return;
    const n = String(name);
    const v = String(version);
    if (!map.has(n)) map.set(n, new Set());
    map.get(n).add(v);
  };

  const addMany = (name, arr) => {
    if (!name || !Array.isArray(arr)) return;
    for (const v of arr) add(name, v);
  };

  const isSemverish = (s) => typeof s === 'string' && /\d+\.\d+\.\d+/.test(s);

  const considerEntry = (entry) => {
    if (!entry || typeof entry !== 'object') return;
    // Optional ecosystem filter
    if ('ecosystem' in entry && String(entry.ecosystem).toLowerCase() !== 'npm') return;
    const name = entry.name || entry.package || entry.package_name || entry.pkg || entry.module || null;
    if (name) {
      if (Array.isArray(entry.versions)) addMany(name, entry.versions);
      if (Array.isArray(entry.affected_versions)) addMany(name, entry.affected_versions);
      if (Array.isArray(entry.affected)) addMany(name, entry.affected);
      if (typeof entry.version === 'string') add(name, entry.version);
      if (typeof entry.affected_version === 'string') add(name, entry.affected_version);
    }
  };

  const walkObject = (obj) => {
    for (const [k, v] of Object.entries(obj)) {
      if (Array.isArray(v)) {
        // Array of versions under a package key
        if (v.length && v.every(isSemverish)) {
          addMany(k, v);
          continue;
        }
        // Array of entries/objects
        for (const item of v) considerEntry(item);
      } else if (v && typeof v === 'object') {
        // Known container keys that may hold mappings
        if (['npm', 'packages', 'package', 'data', 'malware', 'malware_predictions'].includes(k)) {
          walkObject(v);
        } else {
          // Heuristic: nested mapping name -> versions[]
          for (const [nk, nv] of Object.entries(v)) {
            if (Array.isArray(nv) && nv.length && nv.every(isSemverish)) addMany(nk, nv);
          }
        }
      } else if (typeof v === 'string' && isSemverish(v)) {
        // Single version string under a package key
        add(k, v);
      }
    }
  };

  if (Array.isArray(data)) {
    for (const entry of data) considerEntry(entry);
  } else if (data && typeof data === 'object') {
    walkObject(data);
  }

  return map;
}

async function readNpmTree() {
  const overridePath = process.env.WORMSCAN_NPM_LS_JSON;
  if (overridePath) {
    const p = resolve(process.cwd(), overridePath);
    const text = await readFile(p, 'utf8');
    return parseJSON(text, `file ${p}`);
  }

  return new Promise((resolvePromise, reject) => {
    const child = spawn('npm', ['ls', '--all', '--json'], { cwd: process.cwd() });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', (e) => reject(new Error(`Failed to spawn npm ls: ${e.message}`)));
    child.on('close', (_code) => {
      if (!out.trim()) {
        const msg = err.trim() || 'npm ls produced no output';
        reject(new Error(`npm ls failed: ${msg}`));
        return;
      }
      try {
        const json = parseJSON(out, 'npm ls');
        resolvePromise(json);
      } catch (e) {
        reject(e);
      }
    });
  });
}

function flattenPackages(tree) {
  const seen = new Set();
  const results = [];

  const visit = (node, inferredName) => {
    if (!node || typeof node !== 'object') return;
    const name = node.name || inferredName;
    const version = node.version;
    if (name && version) {
      const key = `${name}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        results.push({ name, version });
      }
    }
    const deps = node.dependencies || {};
    if (deps && typeof deps === 'object') {
      for (const [depName, child] of Object.entries(deps)) visit(child, depName);
    }
  };

  visit(tree, tree?.name);
  // Deterministic order
  results.sort((a, b) => (a.name === b.name ? cmpVer(a.version, b.version) : a.name.localeCompare(b.name)));
  return results;
}

function parseSemver(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim().replace(/^v/, '');
  const [maj, min, rest] = s.split('.');
  if (maj === undefined || min === undefined || rest === undefined) return null;
  const patchStr = String(rest).split('-')[0];
  const M = Number(maj), m = Number(min), p = Number(patchStr);
  if (!Number.isInteger(M) || !Number.isInteger(m) || !Number.isInteger(p)) return null;
  return { major: M, minor: m, patch: p };
}

function cmpVer(a, b) {
  // best-effort sort; non-semver go lexical after semver
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (pa && pb) {
    if (pa.major !== pb.major) return pa.major - pb.major;
    if (pa.minor !== pb.minor) return pa.minor - pb.minor;
    return pa.patch - pb.patch;
  }
  if (pa && !pb) return -1;
  if (!pa && pb) return 1;
  return String(a).localeCompare(String(b));
}

function scan(installed, malwareMap, patchDistance = 1) {
  const findings = [];
  for (const { name, version } of installed) {
    const blocked = malwareMap.get(name);
    if (!blocked) continue;
    let isCritical = false;
    let warnedAgainst = null;
    if (blocked.has(version)) {
      isCritical = true;
    } else {
      const pv = parseSemver(version);
      if (pv) {
        for (const bver of blocked) {
          if (bver === version) { isCritical = true; break; }
          const bv = parseSemver(bver);
          if (!bv) continue;
          if (pv.major === bv.major && pv.minor === bv.minor) {
            const delta = Math.abs(pv.patch - bv.patch);
            if (delta <= patchDistance) {
              warnedAgainst = bver;
              break;
            }
          }
        }
      }
    }
    if (isCritical) {
      findings.push({ level: 'critical', name, version, against: version });
    } else if (warnedAgainst) {
      findings.push({ level: 'warning', name, version, against: warnedAgainst });
    }
  }
  // Deterministic output order
  findings.sort((a, b) => {
    if (a.level !== b.level) return a.level === 'critical' ? -1 : 1;
    if (a.name !== b.name) return a.name.localeCompare(b.name);
    return cmpVer(a.version, b.version);
  });
  return findings;
}

function printFindings(findings, patchDistance, stats) {
  let criticals = 0;
  let warnings = 0;
  for (const f of findings) {
    if (f.level === 'critical') {
      criticals++;
      console.log(colors.red(`CRITICAL`)+`: ${f.name}@${f.version} matches blocked ${f.against}`);
    } else {
      warnings++;
      console.log(colors.yellow(`WARNING`)+`: ${f.name}@${f.version} adjacent to blocked ${f.against} (patch distance ${patchDistance})`);
    }
  }
  if (criticals === 0 && warnings === 0) {
    console.log(colors.green('No critical or adjacent versions found.'));
  } else {
    const summary = `Summary: ${criticals} critical, ${warnings} warning${warnings === 1 ? '' : 's'}`;
    const colored = criticals > 0 ? colors.red(summary) : colors.yellow(summary);
    console.log(colored);
  }
  if (stats && typeof stats.totalPackages === 'number' && typeof stats.uniqueNames === 'number') {
    console.log(`Scanned ${stats.totalPackages} packages (${stats.uniqueNames} names).`);
  }
  if (stats && typeof stats.dbNames === 'number') {
    console.log(`DB package names: ${stats.dbNames}`);
  }
  if (stats && stats.present instanceof Map) {
    const presentNames = Array.from(stats.present.keys()).sort();
    console.log(`DB packages present: ${presentNames.length}`);
    for (const name of presentNames) {
      const info = stats.present.get(name);
      const installed = Array.from(info.installed);
      installed.sort(cmpVer);
      const affected = Array.from(info.affected);
      affected.sort(cmpVer);
      const installedStr = installed.join(', ');
      const affectedStr = affected.slice(0, 5).join(', ') + (affected.length > 5 ? ', …' : '');
      console.log(`INFO ${name} installed ${installedStr}; affected: ${affectedStr}`);
    }
  }
  return { criticals, warnings };
}

async function main() {
  const patchDistance = (() => {
    const raw = process.env.WORMSCAN_PATCH_DISTANCE;
    if (raw == null || raw === '') return 1;
    const n = Number(raw);
    return Number.isInteger(n) && n >= 0 ? n : 1;
  })();

  try {
    console.error('worm-scan: Fetching malware data...');
    const [malwareRaw, tree] = await Promise.all([
      fetchMalwareList(),
      (async () => { console.error('worm-scan: Reading npm tree...'); return readNpmTree(); })(),
    ]);
    const malwareMap = normalizeMalwareList(malwareRaw);
    const installed = flattenPackages(tree);
    const totalPackages = installed.length;
    const uniqueNames = new Set(installed.map(p => p.name)).size;
    console.error(`worm-scan: Scanning ${totalPackages} packages (${uniqueNames} names)...`);

    const findings = scan(installed, malwareMap, patchDistance);

    // Compute intersection between installed names and malware DB
    const present = new Map(); // name -> { installed:Set, affected:Set }
    for (const { name, version } of installed) {
      if (malwareMap.has(name)) {
        if (!present.has(name)) present.set(name, { installed: new Set(), affected: new Set(malwareMap.get(name)) });
        present.get(name).installed.add(version);
      }
    }

    const stats = { totalPackages, uniqueNames, present, dbNames: malwareMap.size };
    const { criticals } = printFindings(findings, patchDistance, stats);
    process.exit(criticals > 0 ? 2 : 0);
  } catch (err) {
    console.error(colors.red(`Error: ${err.message}`));
    process.exit(1);
  }
}

// Run the CLI unconditionally. When installed via npm bin shim, this module
// is imported rather than executed directly; we still want main() to run.
main();

export {
  // Export internals for potential future extension
  fetchMalwareList,
  normalizeMalwareList,
  readNpmTree,
  flattenPackages,
  parseSemver,
  scan,
  printFindings,
};
