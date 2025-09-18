import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { execFile } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, '..');
const binPath = resolve(repoRoot, 'bin', 'worm-scan.mjs');
const fixturesDir = resolve(__dirname, 'fixtures');

const fUrl = (file) => pathToFileURL(resolve(fixturesDir, file)).href;

function runScan(env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [binPath], { env: { ...process.env, ...env } }, (error, stdout, stderr) => {
      const code = error?.code ?? 0;
      resolve({ code, stdout: stdout.toString(), stderr: stderr.toString() });
    });
  });
}

test('Critical hit', async () => {
  const env = {
    WORMSCAN_DATA_URL: fUrl('malware-critical.json'),
    WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-evil-1.2.3.json'),
  };
  const { code, stdout } = await runScan(env);
  assert.equal(code, 2, 'exit code should be 2 for criticals');
  assert.match(stdout, /CRITICAL.*evil@1\.2\.3/i);
  assert.match(stdout, /Summary: 1 critical, 0 warnings/);
  assert.match(stdout, /Scanned \d+ packages \(\d+ names\)\./);
  assert.match(stdout, /DB package names: 1/);
  assert.match(stdout, /DB packages present: 1/);
  assert.match(stdout, /INFO evil installed 1\.2\.3; affected: 1\.2\.3/);
});

test('Warning below', async () => {
  const env = {
    WORMSCAN_DATA_URL: fUrl('malware-warning.json'),
    WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-pkg-2.5.6.json'),
  };
  const { code, stdout } = await runScan(env);
  assert.equal(code, 0, 'exit code should be 0 for warnings only');
  assert.match(stdout, /WARNING.*pkg@2\.5\.6.*2\.5\.7/);
  assert.match(stdout, /Scanned \d+ packages \(\d+ names\)\./);
  assert.match(stdout, /DB package names: 1/);
  assert.match(stdout, /DB packages present: 1/);
  assert.match(stdout, /INFO pkg installed 2\.5\.6; affected: 2\.5\.7/);
});

test('Warning above', async () => {
  const env = {
    WORMSCAN_DATA_URL: fUrl('malware-warning.json'),
    WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-pkg-2.5.8.json'),
  };
  const { code, stdout } = await runScan(env);
  assert.equal(code, 0);
  assert.match(stdout, /WARNING.*pkg@2\.5\.8.*2\.5\.7/);
  assert.match(stdout, /Scanned \d+ packages \(\d+ names\)\./);
  assert.match(stdout, /DB package names: 1/);
  assert.match(stdout, /DB packages present: 1/);
  assert.match(stdout, /INFO pkg installed 2\.5\.8; affected: 2\.5\.7/);
});

test('Clean project', async () => {
  const env = {
    WORMSCAN_DATA_URL: fUrl('malware-clean.json'),
    WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-clean.json'),
  };
  const { code, stdout } = await runScan(env);
  assert.equal(code, 0);
  assert.match(stdout, /No critical or adjacent versions found\./);
  assert.match(stdout, /Scanned \d+ packages \(\d+ names\)\./);
  assert.match(stdout, /DB package names: 1/);
  assert.match(stdout, /DB packages present: 0/);
});

test('npm ls noisy but parseable (via JSON override)', async () => {
  const env = {
    WORMSCAN_DATA_URL: fUrl('malware-critical.json'),
    WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-evil-1.2.3.json'),
  };
  const { code, stdout } = await runScan(env);
  assert.equal(code, 2);
  assert.match(stdout, /CRITICAL/);
  assert.match(stdout, /DB package names: 1/);
  assert.match(stdout, /DB packages present: 1/);
});

test('Network failure', async () => {
  const dead = 'http://127.0.0.1:65500/f/does-not-exist.json';
  const env = {
    WORMSCAN_DATA_URL: dead,
    WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-clean.json'),
  };
  const { code, stderr } = await runScan(env);
  assert.equal(code, 1, 'exit code should be 1 on tool error');
  assert.match(stderr, /Failed to fetch malware data/);
});

test('Schema quirks normalize identically', async (t) => {
  const shapes = ['malware-shape-1.json', 'malware-shape-2.json', 'malware-shape-3.json'];
  for (const f of shapes) {
    await t.test(`shape ${f}`, async () => {
      const env = {
        WORMSCAN_DATA_URL: fUrl(f),
        WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-abc-1.0.0.json'),
      };
      const { code, stdout } = await runScan(env);
      assert.equal(code, 2);
      assert.match(stdout, /CRITICAL.*abc@1\.0\.0/);
      assert.match(stdout, /DB package names: 1/);
      assert.match(stdout, /DB packages present: 1/);
      assert.match(stdout, /INFO abc installed 1\.0\.0; affected: 1\.0\.0/);
    });
  }
});

test('Schema with ecosystem/package/affected_versions', async (t) => {
  await t.test('abc via {package, versions, ecosystem:npm}', async () => {
    const env = {
      WORMSCAN_DATA_URL: fUrl('malware-shape-4.json'),
      WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-abc-1.0.0.json'),
    };
    const { code, stdout } = await runScan(env);
    assert.equal(code, 2);
    assert.match(stdout, /CRITICAL.*abc@1\.0\.0/);
    assert.match(stdout, /DB package names: 2/);
    assert.match(stdout, /DB packages present: 1/);
  });
  await t.test('pkg via {name, affected_versions}', async () => {
    const env = {
      WORMSCAN_DATA_URL: fUrl('malware-shape-4.json'),
      WORMSCAN_NPM_LS_JSON: join('tests', 'fixtures', 'npm-tree-pkg-2.5.6.json'),
    };
    const { code, stdout } = await runScan(env);
    assert.equal(code, 0);
    assert.match(stdout, /WARNING.*pkg@2\.5\.6.*2\.5\.7/);
    assert.match(stdout, /DB package names: 2/);
  });
});
