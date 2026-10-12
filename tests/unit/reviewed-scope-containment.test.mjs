import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { listMigrationFiles } from '../../src/persistence/postgres/migrations.mjs';
import { isProbeWorkerRoute } from '../../src/context.mjs';

const targetDetail = readFileSync(new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url), 'utf8');

test('unfinished reviewed GET workflow is not imported or mounted in the customer target page', () => {
  assert.doesNotMatch(targetDetail, /import\s+.*\bReviewedSafeCheck\b/);
  assert.doesNotMatch(targetDetail, /<ReviewedSafeCheck\b/);
});

test('normal PostgreSQL runtime does not construct or expose the interrupted lifecycle', () => {
  const runtime = readFileSync(new URL('../../src/persistence/postgres/runtime.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(runtime, /reviewedSafeExecution|createReviewedExecutionGrantIssuance|ASTRANULL_REVIEWED_SAFE_EXECUTION_ENABLED/);
});

test('unaccepted lifecycle SQL is retained outside automatic migration discovery', () => {
  const files = listMigrationFiles(fileURLToPath(new URL('../../db/migrations', import.meta.url)));
  assert.equal(files.some((file) => file.version.startsWith('0079')), false);
  assert.equal(existsSync(new URL('../../docs/implementation/held-source/0079_reviewed_safe_execution_lifecycle.sql', import.meta.url)), true);
});

test('reviewed claim is not a worker HTTP route while existing bounded routes remain', () => {
  assert.equal(isProbeWorkerRoute('/internal/probe/jobs/job_test/reviewed-claim', 'POST'), false);
  for (const operation of ['execute', 'stop', 'activity', 'result']) {
    assert.equal(isProbeWorkerRoute(`/internal/probe/jobs/job_test/${operation}`, 'POST'), true);
  }
  const server = readFileSync(new URL('../../src/server.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(server, /reviewed-claim|consumeReviewedExecution/);
});
