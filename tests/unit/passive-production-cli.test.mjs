import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { it } from 'node:test';

const root = fileURLToPath(new URL('../..', import.meta.url));
for (const [script, manifestFlag] of [
  ['verify-external-production-readiness.mjs', '--manifest'],
  ['production-readiness-gap-audit.mjs', '--external-verification'],
]) {
  it(`${script} validate-only never creates missing manifest or reports`, () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'astranull-passive-cli-'));
    try {
      const evidence = path.join(dir, 'records.json');
      writeFileSync(evidence, JSON.stringify({ release_id: 'rel_current_candidate', records: [] }));
      const before = createHash('sha256').update(readFileSync(evidence)).digest('hex');
      const result = spawnSync(process.execPath, [path.join(root, 'scripts', script), '--evidence', evidence,
        '--release-id', 'rel_current_candidate', manifestFlag, path.join(dir, 'missing-manifest.json'),
        '--out', path.join(dir, 'report.json'), '--validate-only'], {
        cwd: dir, env: { ...process.env, ASTRANULL_RUN_PUBLIC_DNS: '0' }, encoding: 'utf8', timeout: 15_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stdout, /false|blocked|not ready/i);
      assert.deepEqual(readdirSync(dir), ['records.json']);
      assert.equal(createHash('sha256').update(readFileSync(evidence)).digest('hex'), before);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it(`${script} rejects relabelling a foreign evidence bundle before writing`, () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'astranull-passive-cli-'));
    try {
      const evidence = path.join(dir, 'records.json');
      writeFileSync(evidence, JSON.stringify({ release_id: 'rel_previous_candidate', records: [] }));
      const result = spawnSync(process.execPath, [path.join(root, 'scripts', script), '--evidence', evidence,
        '--release-id', 'rel_current_candidate', manifestFlag, path.join(dir, 'missing-manifest.json'),
        '--out', path.join(dir, 'report.json'), '--validate-only'], {
        cwd: dir, env: { ...process.env, ASTRANULL_RUN_PUBLIC_DNS: '0' }, encoding: 'utf8', timeout: 15_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /Evidence bundle release identity mismatch/);
      assert.deepEqual(readdirSync(dir), ['records.json']);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}
