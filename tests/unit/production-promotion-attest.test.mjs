import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { parseArgs, runProductionPromotionAttest, validatePromotionCandidateInputs } from '../../scripts/production-promotion-attest.mjs';

const dirs = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const binding = { candidate_sha: 'a'.repeat(40), image_digest: `sha256:${'b'.repeat(64)}`, schema_digest: 'c'.repeat(64) };
function fixture() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-promotion-contract-'));
  dirs.push(dir);
  const bundle = { release_id: 'rel_candidate_test', environment: 'staging', candidate_binding: { ...binding },
    records: [{ release_id: 'rel_candidate_test', kind: 'test-only-record', status: 'accepted', evidence: { environment: 'staging' } }] };
  const manifest = { release_id: bundle.release_id, candidate_binding: { ...binding } };
  const opts = { releaseId: bundle.release_id, profile: 'safe-validation-ga', candidateSha: binding.candidate_sha,
    imageDigest: binding.image_digest, schemaDigest: binding.schema_digest,
    evidence: path.join(dir, 'records.json'), manifest: path.join(dir, 'manifest.json') };
  function save() {
    for (const [key, value] of [['evidence', bundle], ['manifest', manifest]]) {
      const bytes = JSON.stringify(value);
      writeFileSync(opts[key], bytes);
      opts[`${key}Digest`] = createHash('sha256').update(bytes).digest('hex');
    }
  }
  save();
  return { opts, bundle, manifest, save };
}
const completeReport = (opts) => ({ release_id: opts.releaseId, profile: opts.profile,
  production_ready: true, customer_production_ready: true, external_verification: { complete: true } });

describe('read-only production promotion prerequisite verification', () => {
  it('parses explicit candidate flags and rejects unknown/missing arguments', () => {
    const opts = parseArgs(['--release-id', 'rel_current', '--profile', 'safe-validation-ga', '--candidate-sha', binding.candidate_sha,
      '--base-url', 'https://unused.example.test']);
    assert.equal(opts.releaseId, 'rel_current');
    assert.equal(opts.profile, 'safe-validation-ga');
    assert.equal(opts.baseUrl, 'https://unused.example.test');
    assert.equal(parseArgs(['-h']).help, true);
    assert.throws(() => parseArgs(['--release-id']), /Missing value/);
    assert.throws(() => parseArgs(['--unknown']), /Unknown argument/);
    assert.throws(() => parseArgs(['--release-id', 'a', '--release-id', 'b']), /Duplicate argument/);
    assert.throws(() => parseArgs(['--profile', 'full', '--profile', 'safe-validation-ga']), /Duplicate argument/);
  });

  it('requires pinned existing inputs before performing any orchestration', async () => {
    let calls = 0;
    await assert.rejects(() => runProductionPromotionAttest({}, { shell: () => calls++ }), /path and exact SHA-256/);
    assert.equal(calls, 0);
  });

  it('never chooses a historical or environment-provided release', () => {
    const { opts, bundle, manifest } = fixture();
    assert.throws(() => validatePromotionCandidateInputs({ ...opts, releaseId: undefined }, bundle, manifest), /explicit valid --release-id/);
    assert.throws(() => validatePromotionCandidateInputs({ ...opts, profile: 'hosted' }, bundle, manifest), /Unsupported promotion profile/);
  });

  for (const input of ['bundle', 'manifest']) {
    it(`rejects mismatched release and candidate in ${input}`, async () => {
      const world = fixture();
      world[input].release_id = 'rel_old';
      world.save();
      await assert.rejects(() => runProductionPromotionAttest(world.opts), /release identity mismatch/);
      world[input].release_id = world.opts.releaseId;
      world[input].candidate_binding.image_digest = `sha256:${'d'.repeat(64)}`;
      world.save();
      await assert.rejects(() => runProductionPromotionAttest(world.opts), /candidate binding mismatch/);
    });
  }

  it('rejects oversized and non-regular inputs before parsing or aggregation', async () => {
    const { opts } = fixture();
    let calls = 0;
    const deps = { aggregate: () => calls++ };
    truncateSync(opts.evidence, 16 * 1024 * 1024 + 1);
    await assert.rejects(() => runProductionPromotionAttest(opts, deps), /exceeds the 16 MiB input limit/);
    await assert.rejects(() => runProductionPromotionAttest({ ...opts, evidence: path.dirname(opts.evidence) }, deps), /must be a regular file/);
    assert.equal(calls, 0);
  });

  it('rejects changed exact bytes before evaluating metadata', async () => {
    const { opts } = fixture();
    writeFileSync(opts.evidence, '{}');
    let calls = 0;
    await assert.rejects(() => runProductionPromotionAttest(opts, { aggregate: () => calls++ }), /digest mismatch/);
    assert.equal(calls, 0);
  });

  for (const mutation of [
    (w) => { w.bundle.rehearsal_only = true; },
    (w) => { w.manifest.rehearsal_only = true; },
    (w) => { w.bundle.records[0].release_id = 'rel_old'; },
    (w) => { w.bundle.records[0].status = 'rejected'; },
    (w) => { w.bundle.records[0].evidence.rehearsal_only = true; },
    (w) => { w.bundle.records[0].evidence.environment = 'local-staging'; },
    (w) => { w.bundle.environment = 'dev'; },
    (w) => { w.bundle.records = []; },
  ]) {
    it('rejects rehearsal, mixed, missing, or non-operational records', async () => {
      const world = fixture();
      mutation(world);
      world.save();
      await assert.rejects(() => runProductionPromotionAttest(world.opts));
    });
  }

  for (const mutation of [
    (r) => { r.production_ready = false; },
    (r) => { r.customer_production_ready = false; },
    (r) => { r.external_verification.complete = false; },
    (r) => { delete r.external_verification; },
    (r) => { r.release_id = 'rel_old'; },
    (r) => { r.profile = 'full'; },
  ]) {
    it('propagates incomplete or wrongly scoped readiness rather than warning and succeeding', async () => {
      const { opts } = fixture();
      const report = completeReport(opts);
      mutation(report);
      await assert.rejects(() => runProductionPromotionAttest(opts, { aggregate: () => report }));
    });
  }

  it('propagates verification failures', async () => {
    const { opts } = fixture();
    await assert.rejects(() => runProductionPromotionAttest(opts, { aggregate() { throw new Error('verification failed'); } }), /verification failed/);
  });

  it('is passive even when an injected test prerequisite report is complete', async () => {
    const { opts } = fixture();
    const before = { evidence: readFileSync(opts.evidence), manifest: readFileSync(opts.manifest) };
    const oldEnv = { ...process.env };
    let shellCalls = 0;
    const result = await runProductionPromotionAttest(opts, {
      aggregate: () => completeReport(opts), shell: () => shellCalls++,
    });
    assert.equal(shellCalls, 0);
    assert.deepEqual({ ...process.env }, oldEnv);
    assert.deepEqual(readFileSync(opts.evidence), before.evidence);
    assert.deepEqual(readFileSync(opts.manifest), before.manifest);
    assert.deepEqual(result.candidate_binding, binding);
    assert.equal(result.passive, true);
    assert.equal(result.executes_drills, false);
    assert.equal(result.grants_deployment, false);
    assert.match(result.caveats[0], /does not authenticate a human approver/);
  });

  it('real readiness aggregation refuses the metadata-only test fixture', async () => {
    const { opts } = fixture();
    await assert.rejects(() => runProductionPromotionAttest(opts), /Promotion blocked/);
  });
});
