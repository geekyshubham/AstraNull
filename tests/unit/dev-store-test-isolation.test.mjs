import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { REPO_DEV_DATA_DIR, useIsolatedDevDataDir } from '../helpers/dev-data-dir.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const STORE_MODULE = path.join(ROOT, 'src/store.mjs');
const ISOLATION_MODULE = path.join(ROOT, 'tests/helpers/dev-data-dir.mjs');

const IMPORT_RE =
  /(?:^|\n)\s*(?:import|export)[^;'"]*?from\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)|(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g;

function collectTestFiles(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules') continue;
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) collectTestFiles(full, out);
    else if (/\.(test|spec)\.mjs$/.test(entry)) out.push(full);
  }
  return out;
}

const depCache = new Map();

function localDeps(file) {
  if (depCache.has(file)) return depCache.get(file);
  let source = '';
  try {
    source = readFileSync(file, 'utf8');
  } catch {
    depCache.set(file, []);
    return [];
  }
  const resolved = [];
  for (const match of source.matchAll(IMPORT_RE)) {
    const specifier = match[1] ?? match[2] ?? match[3];
    if (!specifier || !specifier.startsWith('.')) continue;
    let candidate = path.resolve(path.dirname(file), specifier);
    if (!existsSync(candidate)) {
      for (const ext of ['.mjs', '.js', '/index.mjs']) {
        if (existsSync(candidate + ext)) {
          candidate = candidate + ext;
          break;
        }
      }
    }
    if (existsSync(candidate) && statSync(candidate).isFile()) resolved.push(candidate);
  }
  depCache.set(file, resolved);
  return resolved;
}

function importClosure(entry) {
  const seen = new Set();
  const stack = [entry];
  while (stack.length) {
    for (const dep of localDeps(stack.pop())) {
      if (seen.has(dep)) continue;
      seen.add(dep);
      stack.push(dep);
    }
  }
  return seen;
}

describe('dev store test isolation', () => {
  it('points ASTRANULL_DEV_DATA_DIR at a temp dir outside the repo', () => {
    const dir = useIsolatedDevDataDir();
    assert.equal(process.env.ASTRANULL_DEV_DATA_DIR, dir);
    assert.ok(path.isAbsolute(dir));
    assert.notEqual(path.resolve(dir), path.resolve(REPO_DEV_DATA_DIR));
    assert.equal(dir.startsWith(ROOT), false, `isolated dir must not live in the repo: ${dir}`);
    assert.ok(existsSync(dir));
  });

  it('is idempotent and re-asserts the variable after a suite clears it', () => {
    const first = useIsolatedDevDataDir();
    delete process.env.ASTRANULL_DEV_DATA_DIR;
    assert.equal(useIsolatedDevDataDir(), first);
    assert.equal(process.env.ASTRANULL_DEV_DATA_DIR, first);
  });

  it('sends a persisting store write to the temp dir, leaving repo .data untouched', () => {
    const repoStoreFile = path.join(REPO_DEV_DATA_DIR, 'astranull-dev.json');
    const before = existsSync(repoStoreFile) ? readFileSync(repoStoreFile) : null;

    // Reproduces the pattern that clobbered the dev store: a suite that imports the shared
    // helper layer, then drops ASTRANULL_NO_PERSIST before writing.
    const script = `
      import { readFileSync } from 'node:fs';
      import path from 'node:path';
      import { freshStore } from ${JSON.stringify(path.join(ROOT, 'tests/helpers/reset.mjs'))};
      import { persistStore, getStore } from ${JSON.stringify(STORE_MODULE)};
      freshStore();
      delete process.env.ASTRANULL_NO_PERSIST;
      getStore().tenants.push({ id: 'ten_probe', name: 'probe' });
      persistStore();
      const dir = process.env.ASTRANULL_DEV_DATA_DIR;
      const written = JSON.parse(readFileSync(path.join(dir, 'astranull-dev.json'), 'utf8'));
      console.log(JSON.stringify({ dir, probed: written.tenants.some((t) => t.id === 'ten_probe') }));
    `;
    const out = execFileSync(process.execPath, ['--input-type=module', '--eval', script], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, ASTRANULL_DEV_DATA_DIR: '', ASTRANULL_NO_PERSIST: '' },
    });
    const result = JSON.parse(out.trim().split('\n').at(-1));

    assert.equal(result.probed, true);
    assert.equal(path.resolve(result.dir).startsWith(realpathSync(os.tmpdir())), true, result.dir);
    assert.equal(path.resolve(result.dir).startsWith(ROOT), false, result.dir);

    const after = existsSync(repoStoreFile) ? readFileSync(repoStoreFile) : null;
    if (before === null) {
      assert.equal(after, null, 'test run created a repo .data store');
    } else {
      assert.ok(after !== null && before.equals(after), 'test run rewrote repo .data store');
    }
  });

  it('cleans the temp dir up when the process exits', () => {
    const script = `
      import { useIsolatedDevDataDir } from ${JSON.stringify(ISOLATION_MODULE)};
      console.log(useIsolatedDevDataDir());
    `;
    const dir = execFileSync(process.execPath, ['--input-type=module', '--eval', script], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, ASTRANULL_DEV_DATA_DIR: '' },
    }).trim();
    assert.equal(existsSync(dir), false, `temp data dir survived process exit: ${dir}`);
  });

  it('every suite that can reach src/store.mjs also reaches the isolation helper', () => {
    const offenders = [];
    for (const file of collectTestFiles(path.join(ROOT, 'tests'))) {
      const closure = importClosure(file);
      if (!closure.has(STORE_MODULE)) continue;
      if (closure.has(ISOLATION_MODULE)) continue;
      // A suite may still opt out by owning the variable itself (dev-store-migrate does).
      if (/ASTRANULL_DEV_DATA_DIR/.test(readFileSync(file, 'utf8'))) continue;
      offenders.push(path.relative(ROOT, file));
    }
    assert.deepEqual(
      offenders,
      [],
      `these suites can read or clobber the developer's .data/astranull-dev.json:\n${offenders.join('\n')}`,
    );
  });
});
