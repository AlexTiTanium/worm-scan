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

  if (Array.isArray(data)) {
    for (const entry of data) {
      if (!entry || typeof entry !== 'object') continue;
      if ('name' in entry && 'version' in entry) {
        add(entry.name, entry.version);
      }
      if ('name' in entry && Array.isArray(entry.versions)) {
        for (const v of entry.versions) add(entry.name, v);
      }
    }
  } else if (data && typeof data === 'object') {
    for (const [name, versions] of Object.entries(data)) {
      if (Array.isArray(versions)) {
        for (const v of versions) add(name, v);
      } else if (typeof versions === 'string') {
        add(name, versions);
      }
    }
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

function printFindings(findings, patchDistance) {
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
    const [malwareRaw, tree] = await Promise.all([
      fetchMalwareList(),
      readNpmTree(),
    ]);
    const malwareMap = normalizeMalwareList(malwareRaw);
    const installed = flattenPackages(tree);
    const findings = scan(installed, malwareMap, patchDistance);
    const { criticals } = printFindings(findings, patchDistance);
    process.exit(criticals > 0 ? 2 : 0);
  } catch (err) {
    console.error(colors.red(`Error: ${err.message}`));
    process.exit(1);
  }
}

// Only run if invoked directly (not imported)
const isDirect = (() => {
  try {
    const entry = process.argv[1];
    const me = fileURLToPath(import.meta.url);
    return entry && basename(entry) === basename(me);
  } catch { return true; }
})();

if (isDirect) {
  main();
}

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
